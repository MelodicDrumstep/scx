import os
import subprocess
import signal
import time
import argparse
import ctypes
import ctypes.util
import struct
import threading
from datetime import datetime
from pathlib import Path

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

def collect_and_write_be_threads(map_fd, be_process_pid, BE_type, stop_event, debug_mode=False):
    """Periodically collect BE process threads and write them to the ring buffer (or print in debug mode)"""
    update_interval = 0.02 # Update every 0.02 seconds
    next_update_time = None
    
    while not stop_event.is_set():
        try:
            # Check if BE process is still running
            if be_process_pid and os.path.exists(f"/proc/{be_process_pid}"):
                be_pids = []
                be_pids.append(be_process_pid)
                
                pgid_pids = get_process_group_pids(be_process_pid)
                be_pids.extend(pgid_pids)
                
                # # DEBUGING
                # print(f"BE PIDs: {be_pids}")
                # print(f"PGID PIDs: {pgid_pids}")

                # For SPEC benchmarks, get descendants and find by name
                descendant_pids = get_descendant_pids(be_process_pid, max_depth=5)
                be_pids.extend(descendant_pids)

                # # DEBUGING
                # print(f"DESCENDANT PIDs: {descendant_pids}")
                
                # Get all threads for all BE processes
                unique_be_pids = sorted(set(be_pids))

                # DEBUGING
                # print(f"UNIQUE BE PIDs: {unique_be_pids}")

                be_threads = get_all_threads_for_processes(unique_be_pids)

                # DEBUGING
                # print(f"BE THREADS: {be_threads}")
                
                if debug_mode:
                    # Debug mode: just print thread IDs with timestamp
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    print(f"[{timestamp}] DEBUG: BE Thread IDs ({len(be_threads)} total): {sorted(set(be_threads))}")
                else:
                    # Normal mode: Write BE threads to ring buffer (one pass)
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
                    
                    # if written_count > 0 or failed_count > 0:
                    #     print(f"Updated BE task types: {written_count} written, {failed_count} failed (Total threads: {len(be_threads)})")
            else:
                # BE process no longer exists
                if debug_mode:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    print(f"[{timestamp}] DEBUG: BE process (PID {be_process_pid}) no longer exists, stopping periodic updates")
                else:
                    print("BE process no longer exists, stopping periodic updates")
                break
                
        except Exception as e:
            if debug_mode:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                print(f"[{timestamp}] DEBUG: Error in periodic BE thread update: {e}")
            else:
                print(f"Error in periodic BE thread update: {e}")
        
        # Sleep until next update time (1 second from start of loop)
        # This ensures consistent 1-second intervals regardless of work time
        current_time = time.time()
        if next_update_time is None:
            next_update_time = current_time + update_interval
        if current_time < next_update_time:
            remaining_sleep = next_update_time - current_time
            # Sleep in small increments to check stop_event periodically
            sleep_end_time = current_time + remaining_sleep

            # # # DEBUGING
            # print(f"next_update_time: {next_update_time}")
            # print(f"Current time: {current_time}")
            # print(f"Remaining sleep: {remaining_sleep}")
            # print(f"Sleep end time: {sleep_end_time}")

            while time.time() < sleep_end_time and not stop_event.is_set():
                sleep_chunk = min(update_interval / 5, sleep_end_time - time.time())
                if sleep_chunk > 0:
                    time.sleep(sleep_chunk)
        
        # Set next update time to exactly 0.1 second from now
        next_update_time = time.time() + update_interval

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

def run(LC_type, BE_type, num_cores, NUMA_unaware, task_type_shm=None, debug_mode=False):
    os.makedirs(LC_type, exist_ok=True)
    os.makedirs(f"{LC_type}/{BE_type}", exist_ok=True)

    # Masstree configuration
    if LC_type == "masstree":
        masstree_dir = TailbenchDir / "masstree"
        QPS = 6410
        MAXREQS = QPS * 60
        WARMUPREQS = QPS
        MINSLEEPNS = 100
        NTHREADS = os.environ.get("NTHREADS", "20")
        
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
        
        # Construct masstree command
        LC_cmd = (
            f"bash -c 'cd {masstree_dir} && "
            f"TBENCH_QPS={QPS} TBENCH_MAXREQS={MAXREQS} TBENCH_WARMUPREQS={WARMUPREQS} "
            f"TBENCH_MINSLEEPNS={MINSLEEPNS} {taskset_cmd}"
            f"./mttest_integrated -j{NTHREADS} mycsba masstree'"
        )

    # SPEC CPU environment - need to cd to directory and source shrc to set up Perl environment
    spec_dir = os.path.expanduser("/home/dell-07/wltu/speccpu2006-v1.0.1")
    
    if num_cores:
        # cd to spec directory, source shrc (sets up Perl @INC), then run runspec
        BE_cmd = f"bash -c 'cd {spec_dir} && . ./shrc && taskset -c {First_SMT_silibing_core_ID}-{First_SMT_silibing_core_ID + num_cores - 1} runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {num_cores} {BE_type}'"
    elif NUMA_unaware:
        BE_cmd = f"bash -c 'cd {spec_dir} && . ./shrc && taskset 0x1111111111 runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {int(Num_total_cores / 2)} {BE_type}'"
    else:
        BE_cmd = f"bash -c 'cd {spec_dir} && . ./shrc && runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {int(Num_total_cores)} {BE_type}'"
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

    print("Starting background processes (BE)...")
    be_process = subprocess.Popen(BE_cmd,
                                stdout=open(f"{LC_type}/{BE_type}/BE.log", "w"), 
                                stderr=subprocess.STDOUT,
                                shell=True,
                                preexec_fn=os.setsid)

    print(f"BE process PID: {be_process.pid}")

    # Start LC
    print("Starting LC process...")
    lc_process = None
    try:
        lc_process = subprocess.Popen(LC_cmd,
                                    shell=True,
                                    stdout=open(f"{LC_type}/{BE_type}/LC.log", "w"), 
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

   # Start periodic BE thread updates if map_fd is available or in debug mode
    be_update_thread = None
    be_update_stop = threading.Event()
    
    if map_fd is not None or debug_mode:
        # Wait for processes to start
        time.sleep(1.5)
        
        if debug_mode:
            print(f"\n[DEBUG MODE] Starting periodic BE thread monitoring...")
        else:
            print(f"\nStarting periodic BE task type updates...")
        print(f"BE process PID: {be_process.pid}")
        
        # Start background thread for periodic updates
        be_update_thread = threading.Thread(
            target=collect_and_write_be_threads,
            args=(map_fd, be_process.pid, BE_type, be_update_stop, debug_mode),
            daemon=True
        )
        be_update_thread.start()
        if debug_mode:
            print("[DEBUG MODE] Periodic BE thread monitoring started (every 1 seconds)")
        else:
            print("Periodic BE thread update started (every 1 seconds)")
    
    try:
        # Wait for LC process
        if lc_process:
            try:
                lc_process.wait()
                # Signal timeout thread to stop (process completed normally)
                if lc_timeout_thread:
                    lc_timeout_stop.set()
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
    
    # # Stop periodic updates
    if be_update_thread is not None:
        print("Stopping periodic BE thread updates...")
        be_update_stop.set()
        be_update_thread.join(timeout=2.0)
        if be_update_thread.is_alive():
            print("Warning: BE update thread did not stop gracefully")
    
    # Check if BE process is still running and terminate it
    try:
        be_status = be_process.poll()
        if be_status is None:
            print("BE process still running, terminating...")
            os.killpg(os.getpgid(be_process.pid), signal.SIGTERM)
            try:
                be_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(be_process.pid), signal.SIGKILL)
                be_process.wait()
        else:
            print(f"BE process already finished (status: {be_status})")
    except (ProcessLookupError, AttributeError) as e:
        print(f"Error checking BE process status: {e}")
    
    print("Extract latency from the log file...")
    # Parse results
    lats_bin = TailbenchDir / "masstree" / "lats.bin"
    results_file = f"{LC_type}/{BE_type}/latency.log"
    
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
    parser.add_argument('--LC', choices = ['masstree'], help = 'The LC type')
    parser.add_argument('--BE', choices = SPEC_2006_BE_list, help = 'The BE type')
    parser.add_argument('--run_all_SPEC', action = 'store_true', help = 'To run all of the BE inside SPEC2006 one by one')
    parser.add_argument('-n', '--num_cores', type = int, help = 'The number of cores to for LC and BE each. If not given, we won\'t bind cores.')
    parser.add_argument('--NUMA_unaware', action = 'store_true', help = 'To only set one NUMA node, only needed when \"num_cores\" is not given.')
    parser.add_argument('--task-type-shm', type = str, help = 'Path to the BPF map for task type ring buffer (e.g., /sys/fs/bpf/scx_rusty_task_types)')
    parser.add_argument('--debug', action = 'store_true', help = 'Debug mode: print BE thread IDs with timestamps instead of writing to BPF map')
    args = parser.parse_args()
    
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
            run(LC_type, BE_type, num_cores, args.NUMA_unaware, args.task_type_shm, args.debug)
        exit()

    run(LC_type, args.BE, num_cores, args.NUMA_unaware, args.task_type_shm, args.debug)
    