import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from be_throughput_perf import parse_perf_stat_csv, throughput_monitor_worker
from tailbench_common import (
    CORE_MASK_HEX,
    Num_total_cores,
    SPEC_2006_BE_list,
    TailbenchDir,
    get_all_thread_ids,
    get_descendant_pids,
    get_process_group_pids,
    kill_all_spec_processes,
    read_thread_cpu_time,
)

QPS_limit_masstree = {
   10 : 11700,
   5 : 15300,
   15 : 7900,
   20 : 6400,
}

QPS_limit_specjbb = {
   10 : 15000, # tested
}

# Control policy parameters (adjust as needed)
CONTROL_INTERVAL_SEC = 1.0
LC_P99_HIGH_MS = 1.5
LC_P99_LOW_MS = 1.0
LC_MIN_CORES = 1

DEFAULT_LATENCY_MAP_PATH = "/sys/fs/bpf/latency_map_path"

CLK_TCK = os.sysconf(os.sysconf_names["SC_CLK_TCK"])

# After first SPEC BE (400.perlbench) under --run_all_SPEC: skip rest if end2end p99 exceeds this (ms).
FIRST_BE_P99_SKIP_MS_HIGH = 3.0
FIRST_BE_P99_SKIP_MS_MEDIUM_LOW = 2.0


def clear_tailbench_masstree_latency_artifacts() -> None:
    """Remove Tailbench masstree latency outputs so each run cannot reuse stale lats.bin."""
    d = TailbenchDir / "masstree"
    if not d.is_dir():
        return
    for name in ("lats.bin", "lats.txt"):
        p = d / name
        try:
            if p.is_file():
                p.unlink()
        except OSError as e:
            print(f"Warning: could not remove {p}: {e}")


def clear_tailbench_specjbb_latency_artifacts() -> None:
    """Remove Tailbench specjbb latency outputs (same rationale as masstree)."""
    d = TailbenchDir / "specjbb"
    if not d.is_dir():
        return
    for name in ("lats.bin", "lats.txt"):
        p = d / name
        try:
            if p.is_file():
                p.unlink()
        except OSError as e:
            print(f"Warning: could not remove {p}: {e}")


def _remove_latency_log_on_early_run_all_abort(
    lc_type: str, pressure: str, first_be: str
) -> None:
    """When --run_all_SPEC aborts after the first BE, drop parselats output so nothing is left on disk."""
    path = Path(lc_type) / pressure / first_be / "latency.log"
    try:
        if path.is_file():
            path.unlink()
    except OSError as e:
        print(f"Warning: could not remove {path}: {e}")


def extract_tailbench_end2end_p99_ms(lc_type: str) -> float | None:
    """Parse end2end p99 latency (ms) from Tailbench lats.bin via parselats.py."""
    if lc_type == "masstree":
        lats_bin = TailbenchDir / "masstree" / "lats.bin"
    elif lc_type == "specjbb":
        lats_bin = TailbenchDir / "specjbb" / "lats.bin"
    else:
        return None
    if not lats_bin.is_file():
        return None
    parse_cmd = [
        "python3",
        str(TailbenchDir / "utilities" / "parselats.py"),
        str(lats_bin),
    ]
    try:
        result = subprocess.run(
            parse_cmd,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    output = result.stdout
    pattern = r"end2end:.*?p99\s+([\d.]+)\s+ms"
    match = re.search(pattern, output, re.IGNORECASE)
    if match:
        return float(match.group(1))
    pattern2 = r"p99[:\s]+([\d.]+)\s*ms"
    match2 = re.search(pattern2, output, re.IGNORECASE)
    if match2:
        return float(match2.group(1))
    return None


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


def clear_lc_tail_latency_in_bpf_map(latency_map_path: str) -> bool:
    """Reset pinned latency map value (key 0) to 0 before next sampling window."""
    if not latency_map_path or not os.path.exists(latency_map_path):
        return False

    cmd = [
        "sudo",
        "bpftool",
        "map",
        "update",
        "pinned",
        latency_map_path,
        "key",
        "0",
        "0",
        "0",
        "0",
        "value",
        "0",
        "0",
        "0",
        "0",
    ]

    try:
        subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        err = getattr(e, "stderr", None)
        if err:
            print(f"Failed to clear latency map via bpftool: {err.strip()}")
        else:
            print("Failed to clear latency map via bpftool")
        return False


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
    lc_p99_low_ms: float,
    lc_p99_high_ms: float,
) -> bool | None:
    """Run one LC+BE pair. Returns True if BE throughput was computed, False if unavailable after run, None on early failure."""
    os.makedirs(LC_type, exist_ok=True)
    os.makedirs(f"{LC_type}/{pressure}", exist_ok=True)
    be_out_dir = Path(LC_type) / pressure / BE_type
    if be_out_dir.exists():
        shutil.rmtree(be_out_dir)
    be_out_dir.mkdir(parents=True, exist_ok=True)

    if pressure == "low":
        pressure_num = 0.3
    elif pressure == "medium":
        pressure_num = 0.5
    elif pressure == "high":
        pressure_num = 0.7
    else:
        raise Exception("Invalid pressure level, only [low / medium / high] are supported")

    taskset_cmd = f"taskset {CORE_MASK_HEX[int(num_cores)]}"

    if LC_type == "masstree":
        clear_tailbench_masstree_latency_artifacts()
        lats_bin = TailbenchDir / "masstree" / "lats.bin"
        masstree_dir = TailbenchDir / "masstree"
        QPS = int(QPS_limit_masstree[num_cores] * pressure_num)
        MAXREQS = QPS * 20
        WARMUPREQS = QPS
        MINSLEEPNS = 100
        NTHREADS = str(num_cores)

        LC_cmd = (
            f"bash -c 'sleep 5 && cd {masstree_dir} && "
            f"TBENCH_QPS={QPS} TBENCH_MAXREQS={MAXREQS} TBENCH_WARMUPREQS={WARMUPREQS} "
            f"TBENCH_MINSLEEPNS={MINSLEEPNS} {taskset_cmd} "
            f"./mttest_integrated -j{NTHREADS} mycsba masstree'"
        )

    elif LC_type == "specjbb":
        clear_tailbench_specjbb_latency_artifacts()
        lats_bin = TailbenchDir / "specjbb" / "lats.bin"
        SPECJBB_DIR = TailbenchDir / "specjbb"
        qps = int(QPS_limit_specjbb[num_cores] * pressure_num)
        run_sh = SPECJBB_DIR / "run.sh"
        if not run_sh.exists():
            print(f"ERROR: {run_sh} not found")
            return None

        # sleep 5s first
        LC_cmd = (
            f"bash -c 'sleep 5 && cd {SPECJBB_DIR} && sudo {taskset_cmd} {run_sh} {qps}'"
        )

    else:
        raise Exception("Unsupported LC_type")

    spec_dir = os.path.expanduser("/home/dell-07/wltu/speccpu2006-v1.0.1")

    taskset_cmd = f"taskset {CORE_MASK_HEX[int(num_cores)]}"

    if NUMA_unaware:
        # Add 10s sleep to allow scheduler to process ring buffer
        BE_cmd = f"bash -c 'sleep 5 && cd {spec_dir} && . ./shrc && {taskset_cmd} runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {int(num_cores)} {BE_type}'"

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
        return None

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

    available_cores = get_available_cores_from_mask(CORE_MASK_HEX[num_cores], Num_total_cores)
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
    if clear_lc_tail_latency_in_bpf_map(latency_map_path):
        print("Initialized latency map to 0 before control loop.")

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

        # A zero value means scheduler hasn't published a fresh sample yet.
        # Keep all cores on LC and do not allocate any core to BE before startup.
        if measured_latency_ms <= 0:
            if lc_cores != total_cores:
                lc_cores = total_cores
                apply_core_partition(
                    lc_root_pid=lc_process.pid,
                    be_root_pid=be_process.pid,
                    lc_cores=lc_cores,
                    total_cores=total_cores,
                    available_cores=available_cores,
                )
                set_be_thread_count(0)
            print("Latency is 0 (startup/no fresh sample yet), keep BE cores at 0.")
            continue

        lc_load, last_cpu_times = measure_lc_load(
            lc_root_pid=lc_process.pid,
            total_cores=total_cores,
            last_cpu_times=last_cpu_times,
            interval_sec=CONTROL_INTERVAL_SEC,
        )

        print(
            f"Latency source={latency_source}, p99={measured_latency_ms:.3f} ms "
            f"(low={lc_p99_low_ms:.3f}, high={lc_p99_high_ms:.3f}), "
            f"LC_load={lc_load:.3f}, "
            f"LC_cores={lc_cores}, BE_cores={total_cores - lc_cores}",
        )

        be_cores = total_cores - lc_cores

        # If LC latency is low, give one more core to BE.
        if measured_latency_ms < lc_p99_low_ms:
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
        if measured_latency_ms > lc_p99_high_ms:
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
                # f.write(f"# used_time_sec={used_time:.9f}\n")
                f.write(perf_stderr)
            print(f"[DEBUG] Saved perf output to: {perf_out_path}")
        except Exception as e:
            print(f"Warning: failed to write perf output file: {e}")
    be_throughput_available = instructions is not None and used_time > 0
    if be_throughput_available:
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
    return be_throughput_available


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
    parser.add_argument(
        "--lc-p99-low-ms",
        type=float,
        default=LC_P99_LOW_MS,
        help="LC p99 low threshold in ms; below this, one core is moved from LC to BE",
    )
    parser.add_argument(
        "--lc-p99-high-ms",
        type=float,
        default=LC_P99_HIGH_MS,
        help="LC p99 high threshold in ms; above this, one core is moved from BE to LC",
    )
    args = parser.parse_args()

    if args.pressure:
        if args.pressure not in ["low", "medium", "high"]:
            raise Exception("Invalid pressure level, only [low / medium / high] are supported")
        pressure = args.pressure
    else:
        raise Exception("Pressure level is not given")

    num_cores: int | None = None
    if not args.LC:
        raise Exception("No LC is given.")
    LC_type = args.LC

    if (not args.run_all_SPEC) and (not args.BE):
        raise Exception("No BE is given.")

    if args.lc_p99_low_ms < 0 or args.lc_p99_high_ms < 0:
        raise Exception("lc p99 thresholds must be non-negative")
    if args.lc_p99_low_ms >= args.lc_p99_high_ms:
        raise Exception("lc-p99-low-ms must be smaller than lc-p99-high-ms")

    if args.run_all_SPEC:
        if args.BE:
            print('Warning : "run all" is set, ignoring given BE')
        first_be = SPEC_2006_BE_list[0]
        if pressure == "high":
            first_be_p99_skip_ms = FIRST_BE_P99_SKIP_MS_HIGH
        else:
            first_be_p99_skip_ms = FIRST_BE_P99_SKIP_MS_MEDIUM_LOW
        for idx, BE_type in enumerate(SPEC_2006_BE_list):
            be_tp = run(
                LC_type,
                BE_type,
                args.num_cores,
                args.NUMA_unaware,
                args.pressure,
                args.latency_map_path,
                args.lc_p99_low_ms,
                args.lc_p99_high_ms,
            )
            if idx == 0 and BE_type == first_be:
                if be_tp is False:
                    print(
                        f"First BE ({first_be}) finished with BE throughput unavailable; "
                        "skipping all remaining SPEC benchmarks."
                    )
                    _remove_latency_log_on_early_run_all_abort(
                        LC_type, pressure, first_be
                    )
                    break
                p99_ms = extract_tailbench_end2end_p99_ms(LC_type)
                if p99_ms is None:
                    print(
                        "Warning: could not read end2end p99 after first BE; "
                        "continuing with remaining SPEC benchmarks."
                    )
                elif p99_ms > first_be_p99_skip_ms:
                    print(
                        f"First BE ({first_be}) end2end p99={p99_ms:.3f} ms "
                        f"> {first_be_p99_skip_ms} ms (pressure={pressure}); "
                        "skipping all remaining SPEC benchmarks."
                    )
                    _remove_latency_log_on_early_run_all_abort(
                        LC_type, pressure, first_be
                    )
                    break
        exit()

    run(
        LC_type,
        args.BE,
        args.num_cores,
        args.NUMA_unaware,
        args.pressure,
        args.latency_map_path,
        args.lc_p99_low_ms,
        args.lc_p99_high_ms,
    )
    