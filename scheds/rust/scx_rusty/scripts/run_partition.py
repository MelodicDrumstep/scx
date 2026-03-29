import argparse
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from be_throughput_perf import parse_perf_stat_csv, throughput_monitor_worker

TailbenchDir = Path("/home/dell-07/wltu/Tailbench/tailbench")
SPEC_2006_BE_list = [
    "400.perlbench",
    "401.bzip2",
    "403.gcc",
    "429.mcf",
    "445.gobmk",
    "456.hmmer",
    "458.sjeng",
    "462.libquantum",
    "464.h264ref",
    "470.lbm",
    "473.astar",
    "483.xalancbmk",
]
First_SMT_silibing_core_ID = 20
Num_total_cores = 40

# Control policy parameters (adjust as needed)
CONTROL_INTERVAL_SEC = 1.0
LC_P99_HIGH_MS = 2.5
LC_P99_LOW_MS = 2
LC_MIN_CORES = 1

# We only use cores 0, 4, 8, 12 ... 36 (0x1111111111)
CORE_MASK_HEX = "0x1111111111"

DEFAULT_LATENCY_MAP_PATH = "/sys/fs/bpf/latency_map_path"

CLK_TCK = os.sysconf(os.sysconf_names["SC_CLK_TCK"])


def get_child_pids(pid: int) -> list[int]:
    try:
        result = subprocess.run(
            ["pgrep", "-P", str(pid)],
            capture_output=True,
            text=True,
            check=True,
        )
        pids = [int(p) for p in result.stdout.strip().split("\n") if p]
        return pids
    except (subprocess.CalledProcessError, ValueError):
        return []


def get_descendant_pids(pid: int, max_depth: int = 3) -> list[int]:
    pids: list[int] = []
    current_level = [pid]

    for _ in range(max_depth):
        next_level: list[int] = []
        for parent_pid in current_level:
            children = get_child_pids(parent_pid)
            pids.extend(children)
            next_level.extend(children)
        current_level = next_level
        if not current_level:
            break

    return pids


def get_all_thread_ids(pid: int) -> list[int]:
    thread_ids: list[int] = []
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


def get_process_group_pids(pid: int) -> list[int]:
    try:
        pgid = os.getpgid(pid)
        result = subprocess.run(
            ["pgrep", "-g", str(pgid)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return [int(p) for p in result.stdout.strip().split("\n") if p]
    except (OSError, ValueError, subprocess.CalledProcessError):
        pass
    return []


def get_all_threads_for_processes(pids: list[int]) -> list[int]:
    all_threads: list[int] = []
    for pid in pids:
        threads = get_all_thread_ids(pid)
        all_threads.extend(threads)
        if pid not in all_threads:
            all_threads.append(pid)
    return all_threads


def kill_all_spec_processes():
    commands = [
        "sudo pkill -f runspec",
        "sudo pkill -f specinvoke",
        "sudo pkill -f specmake",
        "sudo pkill -f run_base",
    ]

    for cmd in commands:
        try:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    print("Killed all SPEC processes")


def get_available_cores_from_mask(mask_hex: str, max_core: int) -> list[int]:
    mask = int(mask_hex, 16)
    cores: list[int] = []
    for cpu in range(max_core):
        if mask & (1 << cpu):
            cores.append(cpu)
    return cores


def set_cpuset_for_threads(pids: list[int], cores: list[int]):
    if not cores:
        return
    core_set = set(cores)
    for pid in pids:
        try:
            os.sched_setaffinity(pid, core_set)
            for tid in get_all_thread_ids(pid):
                try:
                    os.sched_setaffinity(tid, core_set)
                except (ProcessLookupError, PermissionError, OSError):
                    continue
        except (ProcessLookupError, PermissionError, OSError):
            continue


def apply_core_partition(
    lc_root_pid: int,
    be_root_pid: int | None,
    lc_cores: int,
    total_cores: int,
    available_cores: list[int],
):
    lc_cores = max(1, min(lc_cores, total_cores))
    be_cores = total_cores - lc_cores

    lc_core_list = available_cores[:lc_cores]
    be_core_list = available_cores[lc_cores:]

    lc_pids: list[int] = [lc_root_pid]
    lc_pids.extend(get_process_group_pids(lc_root_pid))
    lc_pids.extend(get_descendant_pids(lc_root_pid, max_depth=5))
    lc_pids = sorted(set(lc_pids))

    be_pids: list[int] = []
    if be_root_pid is not None:
        be_pids.append(be_root_pid)
        be_pids.extend(get_process_group_pids(be_root_pid))
        be_pids.extend(get_descendant_pids(be_root_pid, max_depth=5))
        be_pids = sorted(set(be_pids))

    set_cpuset_for_threads(lc_pids, lc_core_list)

    if be_pids:
        if be_cores == 0:
            for pid in be_pids:
                try:
                    os.kill(pid, signal.SIGSTOP)
                except ProcessLookupError:
                    continue
        else:
            for pid in be_pids:
                try:
                    os.kill(pid, signal.SIGCONT)
                except ProcessLookupError:
                    continue
            set_cpuset_for_threads(be_pids, be_core_list)

    print(
        f"Applied core partition: LC cores={lc_core_list}, "
        f"BE cores={be_core_list}",
    )

def set_be_thread_count(be_cores: int):
    print(f"Target BE thread/worker count ~ {be_cores}")

def measure_lc_tail_latency_ms_from_bpf_map(latency_map_path: str) -> float | None:
    """
    Read newest LC p99 latency from a pinned BPF map.

    Assumption (matching `scx_rusty/src/main.rs`): map stores a single u32 latency value
    (nanoseconds) at key 0.
    """
    if not latency_map_path or not os.path.exists(latency_map_path):
        return None

    cmd = [
        "sudo",
        "bpftool",
        "map",
        "lookup",
        "pinned",
        latency_map_path,
        "key",
        "0",
        "0",
        "0",
        "0",
    ]

    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        err = getattr(e, "stderr", None)
        if err:
            print(f"Failed to read latency map via bpftool: {err.strip()}")
        else:
            print("Failed to read latency map via bpftool")
        return None

    out = res.stdout.strip().replace("\n", " ")
    if "value:" not in out:
        return None

    value_part = out.split("value:", 1)[1].strip()
    hex_bytes: list[str] = []
    for tok in value_part.split():
        if len(tok) == 2 and all(c in "0123456789abcdefABCDEF" for c in tok):
            hex_bytes.append(tok)
        else:
            break

    if len(hex_bytes) < 4:
        return None

    raw = bytes(int(b, 16) for b in hex_bytes[:4])
    ns = int.from_bytes(raw, byteorder="little", signed=False)

    ms = ns / 1e6
    print(
        f"[DEBUG] BPF latency map {latency_map_path}: "
        f"p99={ns} ns ({ms:.3f} ms)"
    )
    return ms


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


def measure_lc_load(
    lc_root_pid: int,
    total_cores: int,
    last_cpu_times: dict[int, int],
    interval_sec: float,
) -> tuple[float, dict[int, int]]:
    lc_pids: list[int] = [lc_root_pid]
    lc_pids.extend(get_process_group_pids(lc_root_pid))
    lc_pids.extend(get_descendant_pids(lc_root_pid, max_depth=5))
    lc_pids = sorted(set(lc_pids))

    tids: list[int] = []
    for pid in lc_pids:
        tids.append(pid)
        tids.extend(get_all_thread_ids(pid))

    new_cpu_times: dict[int, int] = {}
    delta_ticks_total = 0

    for tid in set(tids):
        t = read_thread_cpu_time(tid)
        if t is None:
            continue
        new_cpu_times[tid] = t
        prev = last_cpu_times.get(tid)
        if prev is not None and t >= prev:
            delta_ticks_total += t - prev

    if interval_sec <= 0 or total_cores <= 0:
        return 0.0, new_cpu_times

    cpu_seconds = delta_ticks_total / float(CLK_TCK)
    capacity_seconds = interval_sec * float(total_cores)

    load_ratio = cpu_seconds / capacity_seconds if capacity_seconds > 0 else 0.0
    load_ratio = max(0.0, min(load_ratio, 1.5))

    return load_ratio, new_cpu_times


def run(
    LC_type: str,
    BE_type: str,
    num_cores: int | None,
    NUMA_unaware: bool,
    pressure: str,
    latency_map_path: str,
):
    os.makedirs(LC_type, exist_ok=True)
    os.makedirs(f"{LC_type}/{pressure}", exist_ok=True)
    os.makedirs(f"{LC_type}/{pressure}/{BE_type}", exist_ok=True)

    if pressure == "low":
        pressure_num = 0.3
    elif pressure == "medium":
        pressure_num = 0.5
    elif pressure == "high":
        pressure_num = 0.7
    else:
        raise Exception("Invalid pressure level, only [low / medium / high] are supported")

    if LC_type == "masstree":
        lats_bin = TailbenchDir / "masstree" / "lats.bin"
        masstree_dir = TailbenchDir / "masstree"
        QPS = int(11700 * pressure_num)
        MAXREQS = QPS * 60
        WARMUPREQS = QPS
        MINSLEEPNS = 100
        NTHREADS = os.environ.get("NTHREADS", "10")

        taskset_cmd = ""
        if num_cores:
            cpu_list = ",".join(map(str, range(num_cores)))
            taskset_cmd = f"taskset -c {cpu_list} "
        elif NUMA_unaware:
            taskset_cmd = f"taskset {CORE_MASK_HEX} "
        else:
            taskset_cmd = f"taskset {CORE_MASK_HEX} "

        LC_cmd = (
            f"bash -c 'sleep 10 && cd {masstree_dir} && "
            f"TBENCH_QPS={QPS} TBENCH_MAXREQS={MAXREQS} TBENCH_WARMUPREQS={WARMUPREQS} "
            f"TBENCH_MINSLEEPNS={MINSLEEPNS} {taskset_cmd}"
            f"./mttest_integrated -j{NTHREADS} mycsba masstree'"
        )

    elif LC_type == "specjbb":
        lats_bin = TailbenchDir / "specjbb" / "lats.bin"
        SPECJBB_DIR = TailbenchDir / "specjbb"
        qps = 140000
        run_sh = SPECJBB_DIR / "run.sh"
        if not run_sh.exists():
            print(f"ERROR: {run_sh} not found")
            return False

        LC_cmd = f"bash -c 'sleep 10 && {run_sh} {qps}'"

    else:
        raise Exception("Unsupported LC_type")

    if lats_bin.exists():
        os.remove(str(lats_bin))

    spec_dir = os.path.expanduser("/home/dell-07/wltu/speccpu2006-v1.0.1")

    if num_cores:
        BE_cmd = (
            f"bash -c 'sleep 10 && cd {spec_dir} && . ./shrc && "
            f"taskset -c {First_SMT_silibing_core_ID}-{First_SMT_silibing_core_ID + num_cores - 1} "
            f"runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {num_cores} {BE_type}'"
        )
    elif NUMA_unaware:
        BE_cmd = (
            f"bash -c 'sleep 10 && cd {spec_dir} && . ./shrc && "
            f"taskset {CORE_MASK_HEX} runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {int(Num_total_cores / 4)} {BE_type}'"
        )
    else:
        BE_cmd = (
            f"bash -c 'sleep 10 && cd {spec_dir} && . ./shrc && "
            f"runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {int(Num_total_cores)} {BE_type}'"
        )

    print(f"LC_cmd : {LC_cmd}, BE_cmd : {BE_cmd}")

    print("Starting LC process...")
    lc_process = None
    try:
        lc_process = subprocess.Popen(
            LC_cmd,
            shell=True,
            stdout=open(f"{LC_type}/{pressure}/{BE_type}/LC.log", "w"),
            stderr=subprocess.STDOUT,
        )
        print(f"LC process PID: {lc_process.pid}")
    except Exception as e:
        print(f"Error running LC process: {e}")
        return

    print("Starting background processes (BE)...")
    be_process = subprocess.Popen(
        BE_cmd,
        stdout=open(f"{LC_type}/{pressure}/{BE_type}/BE.log", "w"),
        stderr=subprocess.STDOUT,
        shell=True,
        preexec_fn=os.setsid,
    )

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

    available_cores = get_available_cores_from_mask(CORE_MASK_HEX, Num_total_cores)
    total_cores = len(available_cores)

    lc_cores = total_cores
    last_cpu_times: dict[int, int] = {}

    apply_core_partition(
        lc_root_pid=lc_process.pid,
        be_root_pid=be_process.pid,
        lc_cores=lc_cores,
        total_cores=total_cores,
        available_cores=available_cores,
    )
    set_be_thread_count(total_cores - lc_cores)

    print("Entering control loop for core partitioning...")

    while True:
        if lc_process.poll() is not None:
            print("LC process completed, exiting control loop...")
            break

        time.sleep(CONTROL_INTERVAL_SEC)

        latency_source = "none"
        measured_latency_ms = measure_lc_tail_latency_ms_from_bpf_map(latency_map_path)
        if measured_latency_ms is not None:
            latency_source = "bpf_map"
        else:
            print("Latency not available yet, skipping this interval.")
            continue
        lc_load, last_cpu_times = measure_lc_load(
            lc_root_pid=lc_process.pid,
            total_cores=total_cores,
            last_cpu_times=last_cpu_times,
            interval_sec=CONTROL_INTERVAL_SEC,
        )

        if measured_latency_ms is None:
            print("Latency not available yet, skipping this interval.")
            continue

        print(
            f"Latency source={latency_source}, p99={measured_latency_ms:.3f} ms "
            f"(low={LC_P99_LOW_MS:.3f}, high={LC_P99_HIGH_MS:.3f}), "
            f"LC_load={lc_load:.3f}, "
            f"LC_cores={lc_cores}, BE_cores={total_cores - lc_cores}",
        )

        be_cores = total_cores - lc_cores

        # If LC latency is low, give one more core to BE.
        if measured_latency_ms < LC_P99_LOW_MS:
            if lc_cores > LC_MIN_CORES:
                lc_cores = max(lc_cores - 1, LC_MIN_CORES)
                apply_core_partition(
                    lc_root_pid=lc_process.pid,
                    be_root_pid=be_process.pid,
                    lc_cores=lc_cores,
                    total_cores=total_cores,
                    available_cores=available_cores,
                )
                set_be_thread_count(total_cores - lc_cores)
            continue

        # If LC latency is high, give one more core to LC.
        if measured_latency_ms > LC_P99_HIGH_MS:
            if be_cores > 0:
                lc_cores = min(lc_cores + 1, total_cores)
                apply_core_partition(
                    lc_root_pid=lc_process.pid,
                    be_root_pid=be_process.pid,
                    lc_cores=lc_cores,
                    total_cores=total_cores,
                    available_cores=available_cores,
                )
                set_be_thread_count(total_cores - lc_cores)
            continue

        # Otherwise, keep the current partition.
        continue

    print("All processes completed")

    print("Cleaning up...")

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
                f.write(f"# used_time_sec={used_time:.9f}\n")
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

    results_file = f"{LC_type}/{pressure}/{BE_type}/latency.log"

    if not lats_bin.exists():
        print(f"WARNING: {lats_bin} not found after benchmark run")
        exit(1)

    print("\nParsing latency results...")
    parse_cmd = [
        "python3",
        str(TailbenchDir / "utilities" / "parselats.py"),
        str(lats_bin),
    ]

    try:
        with open(results_file, "w") as f:
            subprocess.run(
                parse_cmd,
                stdout=f,
                stderr=subprocess.PIPE,
                check=True,
                text=True,
            )
        print(f"Results saved to: {results_file}")
    except subprocess.CalledProcessError as e:
        print("ERROR: Failed to parse results")
        print(f"Error: {e.stderr}")

    kill_all_spec_processes()

    print("Execution completed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        epilog='Usage : run_partition.py --LC <LC_type> [--BE <BE_type> / --run_all_SPEC] [-n <num_cores>]',
    )
    parser.add_argument("--LC", choices=["masstree", "specjbb"], help="The LC type")
    parser.add_argument("--BE", choices=SPEC_2006_BE_list, help="The BE type")
    parser.add_argument(
        "--run_all_SPEC",
        action="store_true",
        help="To run all of the BE inside SPEC2006 one by one",
    )
    parser.add_argument(
        "-n",
        "--num_cores",
        type=int,
        help="The number of cores to for LC and BE each. If not given, we will not bind LC/BE by core count.",
    )
    parser.add_argument(
        "--NUMA_unaware",
        action="store_true",
        help='To only set one NUMA node, only needed when "num_cores" is not given.',
    )
    parser.add_argument(
        "-p",
        "--pressure",
        type=str,
        choices=["low", "medium", "high"],
        help="The pressure level to set for the LC process, [low / medium / high]",
    )
    parser.add_argument(
        "--latency-map-path",
        type=str,
        default=DEFAULT_LATENCY_MAP_PATH,
        help='Pinned BPF map path that stores newest LC p99 latency (ns), e.g. "/sys/fs/bpf/latency_map_path"',
    )
    args = parser.parse_args()

    if args.pressure:
        if args.pressure not in ["low", "medium", "high"]:
            raise Exception("Invalid pressure level, only [low / medium / high] are supported")
        pressure = args.pressure
    else:
        raise Exception("Pressure level is not given")

    num_cores: int | None = None

    if args.num_cores:
        num_cores = args.num_cores
        if args.NUMA_unaware and num_cores is not None:
            raise Exception('"NUMA_unaware" is set but "num_cores" is also set, which is not valid')

    if not args.LC:
        raise Exception("No LC is given.")
    LC_type = args.LC

    if (not args.run_all_SPEC) and (not args.BE):
        raise Exception("No BE is given.")

    if args.run_all_SPEC:
        if args.BE:
            print('Warning : "run all" is set, ignoring given BE')
        for BE_type in SPEC_2006_BE_list:
            run(LC_type, BE_type, num_cores, args.NUMA_unaware, pressure, args.latency_map_path)
        exit()

    run(LC_type, args.BE, num_cores, args.NUMA_unaware, pressure, args.latency_map_path)
    