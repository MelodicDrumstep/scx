import argparse
import ctypes
import ctypes.util
import os
import signal
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from be_throughput_perf import parse_perf_stat_csv, throughput_monitor_worker

TailbenchDir = Path("/home/dell-07/wltu/Tailbench/tailbench")
SPEC_2006_BE_list = ["400.perlbench", "401.bzip2", "403.gcc", "429.mcf", "445.gobmk", "456.hmmer", "458.sjeng", "462.libquantum", "464.h264ref", "470.lbm", "473.astar", "483.xalancbmk"]
First_SMT_silibing_core_ID = 20 # Hard coded
Num_total_cores = 40 # with SMT counted

def generate_even_string(x):
    return ','.join(str(num) for num in range(0, x, 2))

def generate_odd_string(x):
    return ','.join(str(num) for num in range(1, x, 2))

NUMA0_cores = generate_even_string(Num_total_cores)
NUMA1_cores = generate_odd_string(Num_total_cores)

# BPF map constants
TASK_TYPE_RING_SIZE = 1024
TASK_TYPE_LC = 0
TASK_TYPE_BE = 1
BPF_ANY = 0

# Load libbpf
libbpf = None
libc = None

def init_libbpf():
    """Initialize libbpf and libc libraries"""
    global libbpf, libc
    if libbpf is None:
        libbpf_path = ctypes.util.find_library("bpf")
        if libbpf_path:
            libbpf = ctypes.CDLL(libbpf_path)
        else:
            # Try common paths
            for path in ["libbpf.so", "libbpf.so.1", "/usr/lib/x86_64-linux-gnu/libbpf.so"]:
                try:
                    libbpf = ctypes.CDLL(path)
                    break
                except OSError:
                    continue
        
        if libbpf is None:
            raise RuntimeError("Could not load libbpf library")
        
        # Set up function signatures
        libbpf.bpf_obj_get.argtypes = [ctypes.POINTER(ctypes.c_char)]
        libbpf.bpf_obj_get.restype = ctypes.c_int
        
        libbpf.bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        libbpf.bpf_map_lookup_elem.restype = ctypes.c_int
        
        libbpf.bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
        libbpf.bpf_map_update_elem.restype = ctypes.c_int
        
        libc = ctypes.CDLL(ctypes.util.find_library("c"))
        libc.close.argtypes = [ctypes.c_int]
        libc.close.restype = ctypes.c_int

def open_bpf_map_fd_by_path(map_path):
    """Open a BPF map by path and return its file descriptor"""
    init_libbpf()
    
    # Convert path to bytes
    path_bytes = map_path.encode('utf-8')
    path_cstr = ctypes.create_string_buffer(path_bytes)
    
    fd = libbpf.bpf_obj_get(ctypes.cast(path_cstr, ctypes.POINTER(ctypes.c_char)))
    if fd < 0:
        return None
    
    return fd

def find_bpf_map_fd(map_name):
    """Find a BPF map by name, searching common locations"""
    # Try common pinned paths
    common_paths = [
        f"/sys/fs/bpf/{map_name}",
        f"/sys/fs/bpf/scx_rusty/{map_name}",
        f"/sys/fs/bpf/rusty/{map_name}",
    ]
    
    for path in common_paths:
        fd = open_bpf_map_fd_by_path(path)
        if fd is not None:
            return fd
    
    # Try to find the map by iterating through /sys/fs/bpf
    try:
        if os.path.exists("/sys/fs/bpf"):
            for entry in os.listdir("/sys/fs/bpf"):
                entry_path = os.path.join("/sys/fs/bpf", entry)
                if os.path.isdir(entry_path):
                    map_path = os.path.join(entry_path, map_name)
                    if os.path.exists(map_path):
                        fd = open_bpf_map_fd_by_path(map_path)
                        if fd is not None:
                            return fd
                elif entry == map_name:
                    fd = open_bpf_map_fd_by_path(entry_path)
                    if fd is not None:
                        return fd
    except OSError:
        pass
    
    raise RuntimeError(
        f"Could not find BPF map '{map_name}'. "
        "Make sure the scheduler is running and the map is pinned."
    )

def write_task_type_update(map_fd, pid, task_type):
    """Write a task type update to the ring buffer"""
    init_libbpf()
    
    RING_KEY = 0
    key = struct.pack('<I', RING_KEY)
    
    # Ring buffer structure: lock (4) + producer (4) + consumer (4) + entries (TASK_TYPE_RING_SIZE * 8)
    value_size = 12 + (TASK_TYPE_RING_SIZE * 8)
    value = bytearray(value_size)
    
    # Lookup the ring buffer
    key_ptr = ctypes.cast(key, ctypes.c_void_p)
    value_ptr = ctypes.cast((ctypes.c_char * value_size).from_buffer(value), ctypes.c_void_p)
    
    ret = libbpf.bpf_map_lookup_elem(map_fd, key_ptr, value_ptr)
    if ret != 0:
        errno = ctypes.get_errno()
        raise RuntimeError(f"Failed to lookup task type ring buffer: errno {errno}")
    
    # Parse producer and consumer indices
    producer = struct.unpack('<I', bytes(value[4:8]))[0]
    consumer = struct.unpack('<I', bytes(value[8:12]))[0]
    
    # Check if ring buffer is full
    diff = (producer - consumer) & 0xFFFFFFFF
    if diff >= TASK_TYPE_RING_SIZE:
        return False
    
    # Calculate the index for the new entry
    idx = producer % TASK_TYPE_RING_SIZE
    entry_offset = 12 + (idx * 8)
    
    if entry_offset + 8 > len(value):
        raise RuntimeError("Ring buffer entry out of bounds")
    
    # Write the entry: pid (u32, 4 bytes) + task_type (u8, 1 byte) + padding (3 bytes)
    pid_bytes = struct.pack('<I', pid)
    value[entry_offset:entry_offset + 4] = pid_bytes
    value[entry_offset + 4] = task_type
    value[entry_offset + 5:entry_offset + 8] = b'\x00\x00\x00'
    
    # Update producer index
    new_producer = (producer + 1) & 0xFFFFFFFF
    producer_bytes = struct.pack('<I', new_producer)
    value[4:8] = producer_bytes
    
    # Write back to the map
    value_ptr = ctypes.cast((ctypes.c_char * len(value)).from_buffer(value), ctypes.c_void_p)
    ret = libbpf.bpf_map_update_elem(map_fd, key_ptr, value_ptr, BPF_ANY)
    if ret != 0:
        errno = ctypes.get_errno()
        raise RuntimeError(f"Failed to update task type ring buffer: errno {errno}")
    
    return True

def get_child_pids(pid):
    """Get all child PIDs of a process"""
    try:
        result = subprocess.run(
            ["pgrep", "-P", str(pid)],
            capture_output=True,
            text=True,
            check=True
        )
        pids = [int(p) for p in result.stdout.strip().split('\n') if p]
        return pids
    except (subprocess.CalledProcessError, ValueError):
        return []

def get_descendant_pids(pid, max_depth=3):
    """Get all descendant PIDs of a process (recursively)"""
    pids = []
    current_level = [pid]
    
    for depth in range(max_depth):
        next_level = []
        for parent_pid in current_level:
            children = get_child_pids(parent_pid)
            pids.extend(children)
            next_level.extend(children)
        current_level = next_level
        if not current_level:
            break
    
    return pids

def get_all_thread_ids(pid):
    """Get all thread IDs (TIDs) for a process, including the main thread"""
    thread_ids = []
    task_dir = f"/proc/{pid}/task"
    
    if not os.path.exists(task_dir):
        return thread_ids
    
    try:
        for tid_str in os.listdir(task_dir):
            try:
                tid = int(tid_str)
                thread_ids.append(tid)
            except ValueError:
                continue
    except (OSError, PermissionError):
        pass
    
    return thread_ids

def get_process_group_pids(pid):
    """Get all PIDs in the same process group as the given PID"""
    try:
        pgid = os.getpgid(pid)
        result = subprocess.run(
            ["pgrep", "-g", str(pgid)],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return [int(p) for p in result.stdout.strip().split('\n') if p]
    except (OSError, ValueError, subprocess.CalledProcessError):
        pass
    return []

def get_all_threads_for_processes(pids):
    """Get all thread IDs for a list of process PIDs"""
    all_threads = []
    for pid in pids:
        threads = get_all_thread_ids(pid)
        all_threads.extend(threads)
        # Also include the PID itself (main thread TID == PID)
        if pid not in all_threads:
            all_threads.append(pid)
    return all_threads

def collect_and_write_be_threads(map_fd, be_process_pid, BE_type, debug_mode=False):
    """One-time collect BE process threads and write them to the ring buffer (or print in debug mode)"""
    try:
        # Check if BE process is still running
        if be_process_pid and os.path.exists(f"/proc/{be_process_pid}"):
            be_pids = []
            be_pids.append(be_process_pid)
            
            pgid_pids = get_process_group_pids(be_process_pid)
            be_pids.extend(pgid_pids)

            # For SPEC benchmarks, get descendants and find by name
            descendant_pids = get_descendant_pids(be_process_pid, max_depth=5)
            be_pids.extend(descendant_pids)
            
            # Get all threads for all BE processes
            unique_be_pids = sorted(set(be_pids))
            be_threads = get_all_threads_for_processes(unique_be_pids)
            
            if debug_mode:
                # Debug mode: just print thread IDs with timestamp
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                print(f"[{timestamp}] DEBUG: BE Thread IDs ({len(be_threads)} total): {sorted(set(be_threads))}")
            else:
                # Normal mode: Write BE threads to ring buffer (one-time)
                written_count = 0
                failed_count = 0
                for tid in set(be_threads):
                    try:
                        if write_task_type_update(map_fd, tid, TASK_TYPE_BE):
                            written_count += 1
                        else:
                            failed_count += 1
                    except Exception as e:
                        failed_count += 1
                        print(f"  Error writing TID {tid} -> BE: {e}")
                
                if written_count > 0 or failed_count > 0:
                    print(f"Written BE task types: {written_count} written, {failed_count} failed (Total threads: {len(be_threads)})")
        else:
            # BE process no longer exists
            if debug_mode:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                print(f"[{timestamp}] DEBUG: BE process (PID {be_process_pid}) no longer exists")
            else:
                print(f"BE process (PID {be_process_pid}) no longer exists")
            
    except Exception as e:
        if debug_mode:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print(f"[{timestamp}] DEBUG: Error in BE thread collection: {e}")
        else:
            print(f"Error in BE thread collection: {e}")

def kill_all_spec_processes():
    """Kill all runspec and benchmark processes"""
    commands = [
        "sudo pkill -f runspec",
        "sudo pkill -f specinvoke", 
        "sudo pkill -f specmake",
        "sudo pkill -f run_base"
    ]
    
    for cmd in commands:
        try:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
    
    print("Killed all SPEC processes")

def collect_and_write_be_process_and_sub_process_pids(map_fd, be_process, debug_mode=False):
    # Recursively collect and write BE process PIDs and sub-process PIDs to ring buffer (one-time)
    if map_fd is not None or debug_mode:
        # Wait for processes to start
        time.sleep(1.5)
        
        if debug_mode:
            print(f"\n[DEBUG MODE] Collecting BE process and sub-process PIDs...")
        else:
            print(f"\nCollecting BE process and sub-process PIDs...")
        print(f"BE process PID: {be_process.pid}")
        
        # Collect BE PIDs recursively
        be_pids = []
        be_pids.append(be_process.pid)
        
        # Get process group PIDs
        pgid_pids = get_process_group_pids(be_process.pid)
        be_pids.extend(pgid_pids)
        
        # Get descendant PIDs recursively
        descendant_pids = get_descendant_pids(be_process.pid, max_depth=5)
        be_pids.extend(descendant_pids)
        
        # Get all unique BE PIDs
        unique_be_pids = sorted(set(be_pids))
        
        # Get all threads for all BE processes
        be_threads = get_all_threads_for_processes(unique_be_pids)
        
        if debug_mode:
            # Debug mode: just print thread IDs
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print(f"[{timestamp}] DEBUG: BE Process PIDs: {unique_be_pids}")
            print(f"[{timestamp}] DEBUG: BE Thread IDs ({len(be_threads)} total): {sorted(set(be_threads))}")
        else:
            # Normal mode: Write BE threads to ring buffer (one-time)
            written_count = 0
            failed_count = 0
            for tid in set(be_threads):
                try:
                    if write_task_type_update(map_fd, tid, TASK_TYPE_BE):
                        written_count += 1
                    else:
                        failed_count += 1
                except Exception as e:
                    failed_count += 1
                    print(f"  Error writing TID {tid} -> BE: {e}")
            
            print(f"Written BE task types: {written_count} written, {failed_count} failed (Total threads: {len(be_threads)})")
            print(f"BE Process PIDs: {unique_be_pids}")
            print(f"BE Thread IDs: {sorted(set(be_threads))}")

def read_thread_cpu_time(tid: int) -> int | None:
    stat_path = f"/proc/{tid}/stat"
    try:
        with open(stat_path, "r") as f:
            data = f.read().split()
        utime = int(data[13])
        stime = int(data[14])
        return utime + stime
    except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError, ValueError):
        return None


def run(LC_type, BE_type, num_cores, NUMA_unaware, pressure, task_type_shm=None, debug_mode=False):
    os.makedirs(LC_type, exist_ok=True)
    os.makedirs(f"{LC_type}/{pressure}", exist_ok=True)
    os.makedirs(f"{LC_type}/{pressure}/{BE_type}", exist_ok=True)

    # Pressure level to number
    if pressure == 'low':
        pressure_num = 0.3
    elif pressure == 'medium':
        pressure_num = 0.5
    elif pressure == 'high':
        pressure_num = 0.7
    else:
        raise Exception("Invalid pressure level, only [low / medium / high] are supported")

    # Build taskset command based on num_cores or NUMA_unaware
    taskset_cmd = ""
    if num_cores:
        # Use specified cores
        cpu_list = ','.join(map(str, range(num_cores)))
        taskset_cmd = f"taskset -c {cpu_list} "
    elif NUMA_unaware:
        # Use NUMA0 cores (even cores)
        taskset_cmd = f"taskset 0x1111111111 "
    else:
        # Use default CPU mask for even cores 0-38 (0x5555555555)
        taskset_cmd = "taskset 0x1111111111 "

    # Masstree configuration
    if LC_type == "masstree":
        lats_bin = TailbenchDir / "masstree" / "lats.bin"
        masstree_dir = TailbenchDir / "masstree"
        QPS = int(11700 * pressure_num)
        MAXREQS = QPS * 60
        WARMUPREQS = QPS
        MINSLEEPNS = 100
        NTHREADS = os.environ.get("NTHREADS", "10")
        
        # Construct masstree command with 10s sleep to allow scheduler to process ring buffer
        LC_cmd = (
            f"bash -c 'sleep 10 && cd {masstree_dir} && "
            f"TBENCH_QPS={QPS} TBENCH_MAXREQS={MAXREQS} TBENCH_WARMUPREQS={WARMUPREQS} "
            f"TBENCH_MINSLEEPNS={MINSLEEPNS} {taskset_cmd}"
            f"./mttest_integrated -j{NTHREADS} mycsba masstree'"
        )

    elif LC_type == "specjbb":
        lats_bin = TailbenchDir / "specjbb" / "lats.bin"
        SPECJBB_DIR = TailbenchDir / "specjbb"
        qps = int(15000 * pressure_num)
        run_sh = SPECJBB_DIR / "run.sh"
        if not run_sh.exists():
            print(f"ERROR: {run_sh} not found")
            return False

        # sleep 10s first
        LC_cmd = (
            f"bash -c 'sleep 10 && cd {SPECJBB_DIR} && sudo {taskset_cmd} {run_sh} {qps}'"
        )

        # DEBUG
        print(f"LC_cmd: {LC_cmd}")

    # delete lats.bin if it exists
    if lats_bin.exists():
        os.remove(str(lats_bin))

    # SPEC CPU environment - need to cd to directory and source shrc to set up Perl environment
    spec_dir = os.path.expanduser("/home/dell-07/wltu/speccpu2006-v1.0.1")
    
    if num_cores:
        # cd to spec directory, source shrc (sets up Perl @INC), then run runspec
        # Add 10s sleep to allow scheduler to process ring buffer
        BE_cmd = f"bash -c 'sleep 10 && cd {spec_dir} && . ./shrc && taskset -c {First_SMT_silibing_core_ID}-{First_SMT_silibing_core_ID + num_cores - 1} runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {num_cores} {BE_type}'"
    elif NUMA_unaware:
        # Add 10s sleep to allow scheduler to process ring buffer
        BE_cmd = f"bash -c 'sleep 10 && cd {spec_dir} && . ./shrc && taskset 0x1111111111 runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {int(Num_total_cores / 4)} {BE_type}'"
    else:
        # Add 10s sleep to allow scheduler to process ring buffer
        BE_cmd = f"bash -c 'sleep 10 && cd {spec_dir} && . ./shrc && runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {int(Num_total_cores)} {BE_type}'"
    # DEBUGING
    # BE_cmd = "sleep 10000"

    print(f"LC_cmd : {LC_cmd}, BE_cmd : {BE_cmd}")

    # Open BPF map if task_type_shm is provided (skip in debug mode)
    map_fd = None
    if debug_mode:
        print("DEBUG MODE: Skipping BPF map operations, will only print thread IDs")
    elif task_type_shm:
        try:
            if task_type_shm.startswith("/sys/fs/bpf/"):
                map_name = os.path.basename(task_type_shm)
                if not map_name:
                    map_name = "task_type_ring_buffer"
                print(f"Trying BPF map path: {task_type_shm}")
                map_fd = open_bpf_map_fd_by_path(task_type_shm)
                if map_fd is None:
                    print(f"Direct path failed, searching for BPF map: {map_name}")
                    map_fd = find_bpf_map_fd(map_name)
            else:
                map_name = os.path.basename(task_type_shm) if os.path.basename(task_type_shm) else task_type_shm
                if not map_name:
                    map_name = "task_type_ring_buffer"
                if map_name != "task_type_ring_buffer":
                    try:
                        map_fd = find_bpf_map_fd(map_name)
                    except:
                        pass
                if map_fd is None:
                    map_fd = find_bpf_map_fd("task_type_ring_buffer")
            
            if map_fd is None:
                raise RuntimeError("Could not find or open BPF map")
            print(f"Successfully opened BPF map (FD: {map_fd})")
        except Exception as e:
            print(f"Warning: Failed to find/open BPF map: {e}")
            print("Continuing without task type mapping...")

    # Start LC
    print("Starting LC process...")
    lc_process = None
    try:
        lc_process = subprocess.Popen(LC_cmd,
                                    shell=True,
                                    stdout=open(f"{LC_type}/{pressure}/{BE_type}/LC.log", "w"), 
                                    stderr=subprocess.STDOUT)
        print(f"LC process PID: {lc_process.pid}")
    except Exception as e:
        print(f"Error running LC process: {e}")

    # Collect LC tid and write to the ring buffer
    # Use grep 
    lc_tid = get_all_thread_ids(lc_process.pid)
    if map_fd is not None:
        for tid in lc_tid:
            write_task_type_update(map_fd, tid, TASK_TYPE_LC)
        print(f"Written LC TID: {lc_tid} to the ring buffer")
        print(f"LC TID: {lc_tid}")

    # Start BE
    print("Starting background processes (BE)...")
    be_process = subprocess.Popen(BE_cmd,
                                stdout=open(f"{LC_type}/{pressure}/{BE_type}/BE.log", "w"), 
                                stderr=subprocess.STDOUT,
                                shell=True,
                                preexec_fn=os.setsid)

    print(f"BE process PID: {be_process.pid}")

    be_wall_start = time.monotonic()
    mon_state: dict = {}
    mon_thread = threading.Thread(
        target=throughput_monitor_worker,
        args=(be_process.pid, mon_state),
        kwargs={"perf_csv": True},
        daemon=True,
    )
    mon_thread.start()

    # One-time: collect and write BE process and sub-process PIDs to ring buffer
    print("Collecting BE process and sub-process PIDs (one-time)...")
    collect_and_write_be_process_and_sub_process_pids(map_fd, be_process, debug_mode)
    
    # Wait for LC process to complete
    try:
        while True:
            if lc_process.poll() is not None:
                print("LC process completed...")
                break
            time.sleep(1)
        # Wait for LC process
        if lc_process:
            try:
                lc_process.wait()
                print("LC process completed")
            except Exception as e:
                print(f"Error waiting for LC process: {e}")
    except Exception as e:
        print(f"Error running LC process: {e}")
    
    print("All processes completed")
    
    # Cleanup - only terminate processes that are still running
    print("Cleaning up...")
    
    # Check if LC process is still running and terminate it
    if lc_process is not None:
        try:
            if lc_process.poll() is None:
                print("LC process still running, terminating...")
                lc_process.terminate()
                try:
                    lc_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    lc_process.kill()
                    lc_process.wait()
        except (ProcessLookupError, AttributeError):
            pass
    
    # Check if BE process is still running and terminate it
    try:
        be_status = be_process.poll()
        if be_status is None:
            print("BE process still running, terminating...")
            os.killpg(os.getpgid(be_process.pid), signal.SIGTERM)
            try:
                be_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(be_process.pid), signal.SIGKILL)
                be_process.wait()
        else:
            print(f"BE process already finished (status: {be_status})")
    except (ProcessLookupError, AttributeError) as e:
        print(f"Error checking BE process status: {e}")

    mon_thread.join(timeout=125)
    perf_proc = mon_state.get("perf_proc")
    be_start_time = mon_state.get("perf_start_time")
    if be_start_time is None:
        be_start_time = be_wall_start
    if mon_state.get("runspec_pid") is None:
        print(
            "Warning: runspec PID not found in BE subtree for perf stat.",
            file=sys.stderr,
        )

    # Stop perf monitor and report BE throughput.
    perf_stderr = ""
    if perf_proc is not None:
        try:
            if perf_proc.poll() is None:
                perf_proc.send_signal(signal.SIGINT)
            perf_stderr = perf_proc.communicate(timeout=10)[1] or ""
        except subprocess.TimeoutExpired:
            try:
                perf_proc.kill()
            except Exception:
                pass
            try:
                perf_stderr = perf_proc.communicate(timeout=2)[1] or ""
            except Exception:
                perf_stderr = ""
        except Exception as e:
            print(f"Warning: failed to stop/read perf output: {e}")

    be_end_time = time.monotonic()
    be_real_time = max(0.0, be_end_time - be_start_time)
    # used_time = perf_time if (perf_time is not None and perf_time > 0) else be_real_time
    used_time = be_real_time

    instructions, perf_time = (None, None)
    if perf_stderr:
        instructions, perf_time = parse_perf_stat_csv(perf_stderr)

        # Save raw perf output for debugging/repro (prepend wall-clock window used for throughput)
        try:
            perf_out_path = f"{LC_type}/{pressure}/{BE_type}/BE.perf.stat.csv"
            with open(perf_out_path, "w") as f:
                # f.write(f"# used_time_sec={used_time:.9f}\n")
                f.write(perf_stderr)
            print(f"[DEBUG] Saved perf output to: {perf_out_path}")
        except Exception as e:
            print(f"Warning: failed to write perf output file: {e}")
    if instructions is not None and used_time > 0:
        throughput = instructions / used_time
        print(
            f"BE throughput: instructions={instructions}, "
            f"real_time={used_time:.6f}s, "
            f"instructions/sec={throughput:.3f}"
        )
    else:
        print(
            "BE throughput: unavailable "
            f"(instructions={instructions}, time={used_time:.6f}s)"
        )
    
    print("Extract latency from the log file...")
    # Parse results
    results_file = f"{LC_type}/{pressure}/{BE_type}/latency.log"
    
    if not lats_bin.exists():
        print(f"WARNING: {lats_bin} not found after benchmark run")
        exit(1)
    
    print(f"\nParsing latency results...")
    parse_cmd = [
        "python3",
        str(TailbenchDir / "utilities" / "parselats.py"),
        str(lats_bin)
    ]
    
    try:
        with open(results_file, 'w') as f:
            parse_result = subprocess.run(
                parse_cmd,
                stdout=f,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )
        print(f"Results saved to: {results_file}")
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to parse results")
        print(f"Error: {e.stderr}")

    # Kill SPEC processes
    kill_all_spec_processes()

    print("Execution completed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(epilog = 'Usage : run_exp.py --LC <LC_type> [--BE <BE_type> / --run_all_SPEC] [-n <num_cores>]')
    parser.add_argument('--LC', choices = ['masstree', 'specjbb'], help = 'The LC type')
    parser.add_argument('--BE', choices = SPEC_2006_BE_list, help = 'The BE type')
    parser.add_argument('--run_all_SPEC', action = 'store_true', help = 'To run all of the BE inside SPEC2006 one by one')
    parser.add_argument('-n', '--num_cores', type = int, help = 'The number of cores to for LC and BE each. If not given, we won\'t bind cores.')
    parser.add_argument('--NUMA_unaware', action = 'store_true', help = 'To only set one NUMA node, only needed when \"num_cores\" is not given.')
    parser.add_argument('--task-type-shm', type = str, help = 'Path to the BPF map for task type ring buffer (e.g., /sys/fs/bpf/scx_rusty_task_types)')
    parser.add_argument('--debug', action = 'store_true', help = 'Debug mode: print BE thread IDs with timestamps instead of writing to BPF map')
    parser.add_argument('-p', '--pressure', type =str, choices = ['low', 'medium', 'high'], help = 'The pressure level to set for the LC process, [low / medium / high]')
    args = parser.parse_args()

    if args.pressure:
        if args.pressure not in ['low', 'medium', 'high']:
            raise Exception("Invalid pressure level, only [low / medium / high] are supported")
        pressure = args.pressure
    else:
        raise Exception("Pressure level is not given")
    
    # num_cores == None means we do not bind cores
    num_cores = None

    if args.num_cores:
        num_cores = args.num_cores
        if args.NUMA_unaware:
            raise Exception("\"NUMA_unaware\" is set but \"num_cores\" is also set, which is not valid")

    if not args.LC:
        raise Exception("No LC is given.")
    LC_type = args.LC

    if (not args.run_all_SPEC) and (not args.BE):
        raise Exception("No BE is given.")

    if args.run_all_SPEC:
        if args.BE:
            print("Warning : \"run all\" is set, ignoring given BE")
        for BE_type in SPEC_2006_BE_list:
            run(LC_type, BE_type, num_cores, args.NUMA_unaware, pressure, args.task_type_shm, args.debug)
        exit()

    run(LC_type, args.BE, num_cores, args.NUMA_unaware, pressure, args.task_type_shm, args.debug)
    