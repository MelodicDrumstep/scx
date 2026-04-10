#!/usr/bin/env python3
import argparse
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

# Allow `from be_throughput_perf import ...` when run from any cwd
sys.path.insert(0, str(Path(__file__).resolve().parent))
from be_throughput_perf import parse_perf_stat_csv, throughput_monitor_worker


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
    "473.astar",
    "483.xalancbmk",
]

First_SMT_silibing_core_ID = 20
Num_total_cores = 40

def build_be_cmd(be_type: str, num_cores: int | None, numa_unaware: bool) -> str:
    spec_dir = os.path.expanduser("/home/dell-07/wltu/speccpu2006-v1.0.1")
    if numa_unaware:
        if (not num_cores) or (num_cores == 10):
            taskset_cmd = f"taskset 0x1111111111 "
        elif num_cores == 5:
            taskset_cmd = f"taskset 0x1010101010"
        elif num_cores == 15:
            taskset_cmd = f"taskset 0x5555511111"
        elif num_cores == 20:
            taskset_cmd = f"taskset 0x5555555555"
        else:
            raise Exception("Invalid num_cores")
        return (
            f"bash -c 'sleep 10 && cd {spec_dir} && . ./shrc && "
            f"{taskset_cmd} "
            f"runspec -c x86.cfg --size=test --iterations=1000 -v 9 -r {int(Num_total_cores / 4)} {be_type}'"
        )
    else:
        raise Exception("Invalid num_cores")
        return ""

def kill_process_group(proc: subprocess.Popen, sig: signal.Signals) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, PermissionError):
        try:
            proc.send_signal(sig)
        except ProcessLookupError:
            pass


def run_one(be_type: str, num_cores: int | None, numa_unaware: bool, duration_sec: float, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    be_cmd = build_be_cmd(be_type, num_cores, numa_unaware)
    print(f"BE_cmd: {be_cmd}")

    be_process = subprocess.Popen(
        be_cmd,
        stdout=open(out_dir / "BE.log", "w"),
        stderr=subprocess.STDOUT,
        shell=True,
        preexec_fn=os.setsid,
    )
    print(f"BE root PID: {be_process.pid}")

    be_wall_start = time.monotonic()
    mon_state: dict = {}
    mon_thread = threading.Thread(
        target=throughput_monitor_worker,
        args=(be_process.pid, mon_state),
        kwargs={"perf_csv": True},
        daemon=True,
    )
    mon_thread.start()

    # Let BE run for duration; perf attaches once runspec appears.
    time.sleep(duration_sec)

    # Stop BE.
    kill_process_group(be_process, signal.SIGTERM)
    try:
        be_process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        kill_process_group(be_process, signal.SIGKILL)
        be_process.wait()

    # Collect perf output.
    mon_thread.join(timeout=125)
    perf_proc = mon_state.get("perf_proc")
    be_start_time = mon_state.get("perf_start_time")
    if be_start_time is None:
        be_start_time = be_wall_start
    if mon_state.get("runspec_pid") is None:
        print("Warning: runspec PID not found in BE subtree for perf stat.", file=sys.stderr)

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
            print(f"Warning: failed to stop/read perf output: {e}", file=sys.stderr)

    be_end_time = time.monotonic()
    be_real_time = max(0.0, be_end_time - be_start_time)
    used_time = be_real_time

    instructions, perf_time = (None, None)
    if perf_stderr:
        instructions, perf_time = parse_perf_stat_csv(perf_stderr)

    # Save perf output with used time header (same style as run_partition.py).
    perf_out_path = out_dir / "BE.perf.stat.csv"
    with open(perf_out_path, "w") as f:
        f.write(f"# used_time_sec={used_time:.9f}\n")
        f.write(perf_stderr)

    if instructions is None or used_time <= 0:
        print(f"BE baseline throughput unavailable (instructions={instructions}, used_time={used_time:.6f}s)")
        return

    instr_per_us = instructions / (used_time * 1_000_000.0)
    print(
        "BE baseline throughput: "
        f"instructions={instructions}, used_time={used_time:.6f}s, "
        f"instructions/us={instr_per_us:.6f}"
    )

    with open(out_dir / "baseline.txt", "w") as f:
        f.write(f"BE_type={be_type}\n")
        f.write(f"instructions={instructions}\n")
        f.write(f"used_time_sec={used_time:.9f}\n")
        f.write(f"instructions_per_us={instr_per_us:.9f}\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Measure BE-only baseline throughput (instructions/us) for SPEC CPU2006.")
    ap.add_argument("--BE", choices=SPEC_2006_BE_list, help="SPEC CPU2006 BE benchmark to run")
    ap.add_argument("--run_all_SPEC", action="store_true", help="Run all SPEC BE types in sequence")
    ap.add_argument("-n", "--num-cores", type=int, default=None, help="Pin BE to N cores (uses SMT sibling range)")
    ap.add_argument("--NUMA_unaware", action="store_true", help=f"Pin BE to mask {CORE_MASK_HEX}")
    ap.add_argument("--duration-sec", type=float, default=60.0, help="How long to let BE run before stopping (default 60s)")
    ap.add_argument("--out-root", default="baseline_partition", help="Output directory root (default: baseline_partition)")
    args = ap.parse_args()

    if not args.run_all_SPEC and not args.BE:
        ap.error("Either --BE or --run_all_SPEC is required")

    out_root = Path(args.out_root)

    be_types = SPEC_2006_BE_list if args.run_all_SPEC else [args.BE]
    for be_type in be_types:
        out_dir = out_root / str(be_type)
        run_one(be_type, args.num_cores, args.NUMA_unaware, args.duration_sec, out_dir)


if __name__ == "__main__":
    main()

