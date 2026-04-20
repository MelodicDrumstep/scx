#!/usr/bin/env python3
"""
Grid search script for scx_rusty with parameter tuning.
Runs Tailbench tests across different BE types with configurable scheduler parameters.
"""

import subprocess
import time
import signal
import os
import sys
from pathlib import Path
from typing import List, Tuple, Optional
import argparse

# ============================================================
# PARAMETER GRID - FILL IN YOUR TUPLES HERE
# Each tuple is (be_kick_cooldown_ms, latency_threshold_ns)
# ============================================================
PARAMETER_GRID: dict[str, List[Tuple[int, int]]] = {
    # "high": [
    #     (1200, 2200000),
    #     (1000, 2000000),
    #     (1000, 1800000),
    #     (1000, 1600000),
    #     (1000, 1200000),
    #     (600, 1000000),
    # ],
    "medium": [
        (300, 1800000),
        # (1000, 1600000),
        # (1000, 1400000),
        # (1000, 1200000),
        # (1000, 1000000),
        # (600, 1000000),
    ],
    # "low": [
    #     (1000, 1400000),
    #     (800, 1200000),
    #     (800, 1100000),
    #     (800, 1000000),
    #     (800, 900000),
    #     (600, 800000),
    # ],
}

# ============================================================
# BE TYPES TO TEST
# ============================================================
BE_TYPES: List[str] = [
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
]

# ============================================================
# CONFIGURATION
# ============================================================
SCRIPT_DIR = Path(__file__).parent.absolute()
SCHED_BIN = Path("/home/dell-07/wltu/scx/target/release/scx_rusty")
TASK_SHM = Path("/dev/shm/scx_rusty_task_types")
TIMEOUT_MS = 30000


def extract_performance_data(
    pressure: str,
    num_cores: int,
    cooldown_ms: int,
    latency_threshold_ns: int,
    be: str
) -> bool:
    """
    Extract performance data using extract_masstree_perf.py
    Returns True if successful, False otherwise.
    """
    # Construct the output filename
    # Format: coSMT_<pressure>_<num_cores>_<cooldown>_<threshold>.log
    output_filename = f"coSMT_{pressure}_{num_cores}_{cooldown_ms}_{latency_threshold_ns}_{be}.log"
    
    # Create the output directory if it doesn't exist
    output_dir = Path("BE_throughput_result")
    output_dir.mkdir(exist_ok=True)
    
    output_file = output_dir / output_filename
    
    # Construct the extraction command
    cmd = [
        "sudo", "python3", "extract_masstree_perf.py",
        "--root", f"masstree/{pressure}",
    ]
    
    print(f"[EXTRACT] Running performance extraction...")
    print(f"[EXTRACT] Output file: {output_file}")
    
    try:
        with open(output_file, 'w') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            print(f"[EXTRACT] Successfully saved to {output_file}")
            return True
        else:
            print(f"[EXTRACT] Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"[EXTRACT] Exception: {e}")
        return False

def run_command(cmd: List[str], sudo: bool = False, check: bool = False) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    if sudo:
        cmd = ["sudo"] + cmd
    
    print(f"[CMD] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.stdout:
        print(result.stdout)
    if result.stderr and result.returncode != 0:
        print(f"[STDERR] {result.stderr}", file=sys.stderr)
    
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    
    return result


def start_scheduler(
    cooldown_ms: int,
    latency_threshold_ns: int
) -> subprocess.Popen:
    """
    Start scx_rusty scheduler with given parameters.
    Returns the Popen object for the scheduler process.
    """
    cmd = [
        str(SCHED_BIN),
        "--task-type-shm", str(TASK_SHM),
        "--timeout-ms", str(TIMEOUT_MS),
        "--be-kick-cooldown-ms", str(cooldown_ms),
        "--latency-threshold-ns", str(latency_threshold_ns),
    ]
    
    print(f"[SCHEDULER] Starting with parameters: cooldown={cooldown_ms}ms, "
          f"threshold={latency_threshold_ns}ns")
    
    # Start scheduler as sudo process
    sudo_cmd = ["sudo"] + cmd
    proc = subprocess.Popen(
        sudo_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    return proc


def stop_scheduler(proc: subprocess.Popen):
    """Stop the scheduler process."""
    if proc.poll() is None:  # Process is still running
        print(f"[SCHEDULER] Stopping scheduler (pid={proc.pid})...")
        try:
            # Send SIGTERM first
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Force kill if not responding
                print("[SCHEDULER] Force killing...")
                proc.kill()
                proc.wait()
        except ProcessLookupError:
            pass
    else:
        print("[SCHEDULER] Already exited.")


def run_tailbench_test(
    lc: str,
    be: str,
    pressure: str,
    num_cores: int,
    cooldown_ms: int,
    latency_threshold_ns: int
) -> bool:
    """
    Run a single Tailbench test.
    Returns True if successful, False otherwise.
    """
    cmd = [
        "sudo", "python3", "run_test_tailbench.py",
        "--LC", lc,
        "--BE", be,
        "-n", str(num_cores),
        "--NUMA_unaware",
        "--task-type-shm", str(TASK_SHM),
        "-p", pressure,
    ]
    
    print(f"[TAILBENCH] Running: LC={lc}, BE={be}, pressure={pressure}, cores={num_cores}")
    
    result = run_command(cmd, sudo=False)  # Already has sudo in cmd
    
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description="Grid search for scx_rusty scheduler parameters"
    )
    parser.add_argument("LC", type=str, help="LC value (e.g., masstree, sharded, etc.)")
    parser.add_argument("pressure", type=str, help="Pressure value (e.g., high, medium, low)")
    parser.add_argument("num_cores", type=int, help="Number of cores to use")
    parser.add_argument(
        "--param-start", type=int, default=0, help="Starting parameter index (default: 0)"
    )
    parser.add_argument(
        "--param-end", type=int, default=None, help="Ending parameter index (default: all)"
    )
    parser.add_argument(
        "--be-filter",
        type=str,
        nargs="+",
        help="Specific BE types to test (default: all)"
    )
    
    args = parser.parse_args()
    
    # Validate paths
    if not SCHED_BIN.exists():
        print(f"Error: scx_rusty binary not found at {SCHED_BIN}")
        sys.exit(1)
    
    # Change to script directory
    os.chdir(SCRIPT_DIR)
    print(f"[SETUP] Working directory: {os.getcwd()}")
    
    # Determine parameter range
    param_end = args.param_end if args.param_end is not None else len(PARAMETER_GRID[args.pressure])
    parameters_to_run = list(enumerate(PARAMETER_GRID[args.pressure]))[args.param_start:param_end]
    
    # Filter BE types if requested
    be_types_to_run = args.be_filter if args.be_filter else BE_TYPES
    
    # Create results directory
    results_dir = Path("grid_search_results")
    results_dir.mkdir(exist_ok=True)
    
    print("=" * 80)
    print(f"Starting grid search: LC={args.LC}, pressure={args.pressure}, cores={args.num_cores}")
    print(f"Parameters to test: {len(parameters_to_run)} combinations")
    print(f"BE types to test: {len(be_types_to_run)}")
    print("=" * 80)
    
    # Display parameter grid
    print("\nParameter Grid:")
    for idx, (cooldown, threshold) in parameters_to_run:
        print(f"  [{idx}] cooldown={cooldown}ms, threshold={threshold}ns")
    print()
    
    # Track results
    results_summary = []
    
    # Run grid search
    for param_idx, (cooldown_ms, latency_threshold_ns) in parameters_to_run:
        print(f"\n{'#' * 80}")
        print(f"# Parameter set {param_idx}: cooldown={cooldown_ms}ms, "
            f"threshold={latency_threshold_ns}ns")
        print(f"{'#' * 80}")
        
        for be in be_types_to_run:
            print(f"\n{'=' * 80}")
            print(f"Testing: BE={be}, Parameters={param_idx}")
            print(f"{'=' * 80}")
            
            # Start scheduler
            scheduler_proc = start_scheduler(cooldown_ms, latency_threshold_ns)
            
            # Give scheduler time to initialize
            print("[SETUP] Waiting for scheduler to initialize...")
            time.sleep(3)
            
            # Check if scheduler is still running
            if scheduler_proc.poll() is not None:
                print("[ERROR] Scheduler exited unexpectedly!")
                continue
            
            # Run Tailbench test
            success = run_tailbench_test(
                args.LC, be, args.pressure, args.num_cores,
                cooldown_ms, latency_threshold_ns
            )
            
            # Stop scheduler
            stop_scheduler(scheduler_proc)
            
            # Record result
            results_summary.append({
                "param_idx": param_idx,
                "cooldown_ms": cooldown_ms,
                "latency_threshold_ns": latency_threshold_ns,
                "be": be,
                "success": success,
            })
            
            # Small delay between tests
            time.sleep(2)
        
        # Extract performance data AFTER all BEs for this parameter set are done
        print(f"\n[INFO] Completed parameter set {param_idx}. Extracting performance data...")
        extract_success = extract_performance_data(
            args.pressure, args.num_cores,
            cooldown_ms, latency_threshold_ns,
            "all_be"  # or you could loop through BEs again
        )
        
        print(f"\n[INFO] Completed parameter set {param_idx}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] User interrupted execution")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)