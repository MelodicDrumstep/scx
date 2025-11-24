import os
import subprocess
import signal
import time
import argparse
import ctypes
import ctypes.util
import struct

Ruler_BE_list = ["port0_ruler", "port1_ruler", "port5_ruler", "int_add_ruler", "l1_cache_ruler", "l2_cache_ruler", "l3_cache_ruler"]
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

def get_docker_container_pid(container_name):
    """Get the main process PID of a docker container"""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Pid}}", container_name],
            capture_output=True,
            text=True,
            check=True
        )
        pid = int(result.stdout.strip())
        return pid
    except (subprocess.CalledProcessError, ValueError):
        return None

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

def gen_ruler_BE_script(BE_type, num_cores):
    script = f"""#!/bin/bash

# Array to store child process IDs
pids=()

# Trap signals and kill all child processes
cleanup() {{
    echo "Cleaning up child processes..."
    for pid in "${{pids[@]}}"; do
        kill "$pid" 2>/dev/null
    done
    exit
}}

# Set trap for common termination signals
trap cleanup SIGINT SIGTERM EXIT
"""

    if num_cores:
        script += f"""
for i in {{{First_SMT_silibing_core_ID}..{First_SMT_silibing_core_ID + num_cores - 1}}}
do
    taskset -c $i ./{BE_type} &
    pids+=($!)  # Store the PID of the most recent background process
done

wait
"""
    else:
        script += f"""
for i in {{{First_SMT_silibing_core_ID}..{First_SMT_silibing_core_ID * 2 - 1}}}
do
    ./{BE_type} &
    pids+=($!)  # Store the PID of the most recent background process
done

wait
"""
        
    script_filename = f"{BE_type}_BE.sh"
    with open(script_filename, 'w') as f:
        f.write(script)
    
    os.chmod(script_filename, 0o755)
    return script_filename

def kill_all_spec_processes():
    """Kill all runspec and benchmark processes"""
    commands = [
        "pkill -f runspec",
        "pkill -f specinvoke", 
        "pkill -f specmake",
        "pkill -f '400\.'",  # perlbench
        "pkill -f '401\.'",  # bzip2
        "pkill -f '403\.'",  # gcc
        "pkill -f '429\.'",  # mcf
        "pkill -f '445\.'",  # gobmk
        "pkill -f '456\.'",  # hmmer
        "pkill -f '458\.'",  # sjeng
        "pkill -f '462\.'",  # libquantum
        "pkill -f '464\.'",  # h264ref
        "pkill -f '471\.'",  # omnetpp
        "pkill -f '473\.'",  # astar
        "pkill -f '483\.'",  # xalancbmk
    ]
    
    for cmd in commands:
        try:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
    
    print("Killed all SPEC processes")

def run(LC_type, BE_type, num_cores, measure_IPC, NUMA_unaware, task_type_shm=None):
    os.makedirs(LC_type, exist_ok=True)
    os.makedirs(f"{LC_type}/{BE_type}", exist_ok=True)

    if num_cores:
        cpus_str = "--cpuset-cpus=" + (','.join(map(str, range(num_cores)))) + ' '
    elif NUMA_unaware:
        cpus_str = "--cpuset-cpus=" + NUMA0_cores + ' '
    else:
        cpus_str = ''

    if LC_type == "Graph-Analytics":
        LC_cmd = f"docker run --rm {cpus_str} --volumes-from twitter-data -e WORKLOAD_NAME=pr cloudsuite/graph-analytics --driver-memory 8g --executor-memory 8g"
    elif LC_type == "Data-Analytics":
        subprocess.run("docker rm -f data-master data-slave01 wikimedia-dataset 2>/dev/null", 
                        shell=True, capture_output=True)
        result = subprocess.run("docker ps -a | grep wikimedia-dataset", shell=True, capture_output=True, text=True)
        if "wikimedia-dataset" not in result.stdout:
            print("Creating dataset container...")
            subprocess.run("docker create --name wikimedia-dataset cloudsuite/wikimedia-pages-dataset", 
                        shell=True, check=True, capture_output=True)

        server_cmd = (
            f"docker run -d {cpus_str} --net host --volumes-from wikimedia-dataset "
            f"--name data-master cloudsuite/data-analytics --master --master-ip=127.0.0.1"
        )

        # Run graph analytics client with timed perf stat
        client_cmd = (
            f"docker run -d {cpus_str} --net host --volumes-from wikimedia-dataset "
            f"--name data-slave01 cloudsuite/data-analytics --slave --master-ip=127.0.0.1"
        )

        subprocess.run(server_cmd, shell=True)
        subprocess.run(client_cmd, shell=True)
        print("Running the server for web analysis")
        time.sleep(5)
        LC_cmd = "timeout 3m docker exec data-master benchmark"

    # SPEC CPU environment - need to cd to directory and source shrc to set up Perl environment
    spec_dir = os.path.expanduser("/home/dell-04/wltu/speccpu2006-v1.0.1")
    
    if BE_type in Ruler_BE_list:
        BE_script = gen_ruler_BE_script(BE_type, num_cores)
        BE_cmd = f"bash {BE_script}"
    else:
        if num_cores:
            # cd to spec directory, source shrc (sets up Perl @INC), then run runspec
            BE_cmd = f"bash -c 'cd {spec_dir} && . ./shrc && taskset -c {First_SMT_silibing_core_ID}-{First_SMT_silibing_core_ID + num_cores - 1} runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {num_cores} {BE_type}'"
        elif NUMA_unaware:
            BE_cmd = f"bash -c 'cd {spec_dir} && . ./shrc && taskset -c {NUMA0_cores} runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {int(Num_total_cores / 2)} {BE_type}'"
        else:
            BE_cmd = f"bash -c 'cd {spec_dir} && . ./shrc && runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {int(Num_total_cores)} {BE_type}'"

    print(f"LC_cmd : {LC_cmd}, BE_cmd : {BE_cmd}")

    # Open BPF map if task_type_shm is provided
    map_fd = None
    if task_type_shm:
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
    
    # Collect BE PIDs and write to ring buffer
    be_pids = []
    if map_fd is not None:
        # Wait for processes to start
        time.sleep(1.5)
        
        be_pids.append(be_process.pid)
        pgid_pids = get_process_group_pids(be_process.pid)
        be_pids.extend(pgid_pids)
        
        if BE_type in SPEC_2006_BE_list:
            # For SPEC benchmarks, get descendants and find by name
            descendant_pids = get_descendant_pids(be_process.pid, max_depth=5)
            be_pids.extend(descendant_pids)
            
            # Find SPEC benchmark processes by name
            try:
                benchmark_name = BE_type.split('.')[-1]
                result = subprocess.run(
                    ["pgrep", "-f", benchmark_name],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    spec_pids = [int(p) for p in result.stdout.strip().split('\n') if p]
                    be_pids.extend(spec_pids)
                    for spec_pid in spec_pids:
                        spec_descendants = get_descendant_pids(spec_pid, max_depth=3)
                        be_pids.extend(spec_descendants)
            except:
                pass
        else:
            descendant_pids = get_descendant_pids(be_process.pid, max_depth=3)
            be_pids.extend(descendant_pids)
        
        # For ruler BE scripts, find processes by name
        if BE_type in Ruler_BE_list:
            try:
                result = subprocess.run(
                    ["pgrep", "-f", BE_type],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    script_pids = [int(p) for p in result.stdout.strip().split('\n') if p]
                    be_pids.extend(script_pids)
                    for script_pid in script_pids:
                        script_descendants = get_descendant_pids(script_pid, max_depth=2)
                        be_pids.extend(script_descendants)
            except:
                pass
        
        # Wait a bit more and refresh
        time.sleep(0.5)
        if BE_type in SPEC_2006_BE_list:
            # Refresh for SPEC benchmarks
            descendant_pids = get_descendant_pids(be_process.pid, max_depth=5)
            be_pids.extend(descendant_pids)
            try:
                benchmark_name = BE_type.split('.')[-1]
                result = subprocess.run(
                    ["pgrep", "-f", benchmark_name],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    spec_pids = [int(p) for p in result.stdout.strip().split('\n') if p]
                    be_pids.extend(spec_pids)
            except:
                pass
        
        # Get all threads for all BE processes
        unique_be_pids = sorted(set(be_pids))
        be_threads = get_all_threads_for_processes(unique_be_pids)
        
        # For SPEC benchmarks, do one more pass after waiting longer
        if BE_type in SPEC_2006_BE_list:
            time.sleep(2.0)
            # Refresh PIDs one more time
            descendant_pids = get_descendant_pids(be_process.pid, max_depth=5)
            be_pids.extend(descendant_pids)
            pgid_pids = get_process_group_pids(be_process.pid)
            be_pids.extend(pgid_pids)
            try:
                benchmark_name = BE_type.split('.')[-1]
                result = subprocess.run(
                    ["pgrep", "-f", benchmark_name],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    spec_pids = [int(p) for p in result.stdout.strip().split('\n') if p]
                    be_pids.extend(spec_pids)
            except:
                pass
            unique_be_pids = sorted(set(be_pids))
            be_threads.extend(get_all_threads_for_processes(unique_be_pids))
        
        # Write BE threads to ring buffer
        print(f"\nWriting BE task type mappings to ring buffer...")
        for tid in set(be_threads):
            try:
                if write_task_type_update(map_fd, tid, TASK_TYPE_BE):
                    print(f"  Written: TID {tid} -> BE")
                else:
                    print(f"  Warning: Ring buffer full, could not write TID {tid} -> BE")
            except Exception as e:
                print(f"  Error writing TID {tid} -> BE: {e}")
    
    if measure_IPC:
        # Start perf stat processes for core 0 and core 20
        print("Starting perf stat processes...")
        perf_core_LC = subprocess.Popen([
            "perf", "stat", 
            "-e", "instructions,cycles",
            "-C", "0",
            "-I", "10000",
            "-o", f"{LC_type}/{BE_type}/perf_core_LC.log"
        ])
        
        perf_core_BE = subprocess.Popen([
            "perf", "stat", 
            "-e", "instructions,cycles", 
            "-C", f"{First_SMT_silibing_core_ID}", 
            # NOTICE : I take "20" since core 20 is the SMT sibiling of core 0 on my machine
            # And I just hardcode it in this script to simplify things
            "-I", "10000",
            "-o", f"{LC_type}/{BE_type}/perf_core_BE.log"
        ])
        
        print(f"Perf processes started - Core 0 PID: {perf_core_LC.pid}, Core {First_SMT_silibing_core_ID} PID: {perf_core_BE.pid}")

    # Start LC
    print("Starting LC process...")
    lc_process = None
    try:
        lc_process = subprocess.Popen(LC_cmd,
                                    shell=True,
                                    stdout=open(f"{LC_type}/{BE_type}/LC.log", "w"), 
                                    stderr=subprocess.STDOUT)
        print(f"LC process PID: {lc_process.pid}")
        
        # Collect LC PIDs and write to ring buffer
        lc_pids = []
        if map_fd is not None:
            # Wait for processes to start
            time.sleep(1.0)
            
            if LC_type == "Graph-Analytics":
                try:
                    result = subprocess.run(
                        ["docker", "ps", "--format", "{{.ID}} {{.Names}}", "--filter", "ancestor=cloudsuite/graph-analytics"],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    if result.stdout.strip():
                        container_id = result.stdout.strip().split('\n')[-1].split()[0]
                        container_pid = get_docker_container_pid(container_id)
                        if container_pid:
                            lc_pids.append(container_pid)
                            descendant_pids = get_descendant_pids(container_pid, max_depth=3)
                            lc_pids.extend(descendant_pids)
                except:
                    pass
                lc_pids.append(lc_process.pid)
            elif LC_type == "Data-Analytics":
                for container_name in ["data-master", "data-slave01"]:
                    container_pid = get_docker_container_pid(container_name)
                    if container_pid:
                        lc_pids.append(container_pid)
                        descendant_pids = get_descendant_pids(container_pid, max_depth=3)
                        lc_pids.extend(descendant_pids)
                lc_pids.append(lc_process.pid)
            else:
                lc_pids.append(lc_process.pid)
                descendant_pids = get_descendant_pids(lc_process.pid, max_depth=3)
                lc_pids.extend(descendant_pids)
            
            # Get all threads for all LC processes
            lc_threads = get_all_threads_for_processes(lc_pids)
            
            # Write LC threads to ring buffer
            print(f"\nWriting LC task type mappings to ring buffer...")
            for tid in set(lc_threads):
                try:
                    if write_task_type_update(map_fd, tid, TASK_TYPE_LC):
                        print(f"  Written: TID {tid} -> LC")
                    else:
                        print(f"  Warning: Ring buffer full, could not write TID {tid} -> LC")
                except Exception as e:
                    print(f"  Error writing TID {tid} -> LC: {e}")
        
        # Wait for LC process
        if lc_process:
            try:
                lc_process.wait()
                print("LC process completed")
            except Exception as e:
                print(f"Error waiting for LC process: {e}")
    except Exception as e:
        print(f"Error running LC process: {e}")
    
    # Wait for BE process to complete
    print("\nWaiting for BE process to complete...")
    try:
        be_process.wait()
        print("BE process completed")
    except Exception as e:
        print(f"Error waiting for BE process: {e}")
    finally:
        # Close BPF map FD if opened
        if map_fd is not None:
            try:
                init_libbpf()
                if libc:
                    libc.close(map_fd)
            except:
                pass
    
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
    
    # Check if BE process is still running and terminate it (shouldn't happen if wait() completed)
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
    
    if measure_IPC:
        # Kill perf processes first
        print("Stopping perf stat processes...")
        try:
            perf_core_LC.terminate()
            perf_core_BE.terminate()
            
            # Wait a bit for perf to terminate gracefully
            try:
                perf_core_LC.wait(timeout=5)
                perf_core_BE.wait(timeout=5)
                print("Perf processes terminated gracefully")
            except subprocess.TimeoutExpired:
                print("Forcing perf processes to terminate...")
                perf_core_LC.kill()
                perf_core_BE.kill()
                perf_core_LC.wait()
                perf_core_BE.wait()
        except (ProcessLookupError, AttributeError):
            pass
        
    # Kill SPEC processes
    kill_all_spec_processes()
    
    print("Execution completed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(epilog = 'Usage : run_exp.py --LC <LC_type> [--BE <BE_type> / --run_all_ruler / --run_all_SPEC] [-n <num_cores>]')
    parser.add_argument('--LC', choices = ['Graph-Analytics', 'Data-Analytics'], help = 'The LC type')
    parser.add_argument('--BE', choices = Ruler_BE_list + SPEC_2006_BE_list, help = 'The BE type')
    parser.add_argument('--run_all_ruler', action = 'store_true', help = 'To run all of the ruler BE one by one')
    parser.add_argument('--run_all_SPEC', action = 'store_true', help = 'To run all of the BE inside SPEC2006 one by one')
    parser.add_argument('-n', '--num_cores', type = int, help = 'The number of cores to for LC and BE each. If not given, we won\'t bind cores.')
    parser.add_argument('--measure_IPC', action = 'store_true', help = 'To measure the IPC of two cores using perf. Only valid if \"num_cores\" is set')
    parser.add_argument('--NUMA_unaware', action = 'store_true', help = 'To only set one NUMA node, only needed when \"num_cores\" is not given.')
    parser.add_argument('--task-type-shm', type = str, help = 'Path to the BPF map for task type ring buffer (e.g., /sys/fs/bpf/scx_rusty_task_types)')
    args = parser.parse_args()
    
    # num_cores == None means we do not bind cores
    num_cores = None

    if args.num_cores:
        num_cores = args.num_cores
        if args.NUMA_unaware:
            raise Exception("\"NUMA_unaware\" is set but \"num_cores\" is also set, which is not valid")
    elif args.measure_IPC:
        raise Exception("\"measure_IPC\" is set but \"num_cores\" is not, which is not valid")

    if not args.LC:
        raise Exception("No LC is given.")
    LC_type = args.LC

    if (not args.run_all_ruler) and (not args.run_all_SPEC) and (not args.BE):
        raise Exception("No BE is given.")

    if args.run_all_ruler or args.run_all_SPEC:
        if args.BE:
            print("Warning : \"run all\" is set, ignoring given BE")
        if args.run_all_ruler:
            for BE_type in Ruler_BE_list:
                run(LC_type, BE_type, num_cores, args.measure_IPC, args.NUMA_unaware, args.task_type_shm)            
        if args.run_all_SPEC:
            for BE_type in SPEC_2006_BE_list:
                run(LC_type, BE_type, num_cores, args.measure_IPC, args.NUMA_unaware, args.task_type_shm)
        exit()

    run(LC_type, args.BE, num_cores, args.measure_IPC, args.NUMA_unaware, args.task_type_shm)
    