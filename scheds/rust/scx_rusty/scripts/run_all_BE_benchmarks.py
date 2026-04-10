#!/usr/bin/env python3

import subprocess
import shlex
from pathlib import Path

# Configuration
SCENARIOS = {
    "rusty": "masstree_rusty_4_10",
    "partition": "masstree_partition_4_10",
    "EEVDF": "masstree_EEVDF_4_10"
}

PRESSURES = ["low", "medium", "high"]

# Paths
BE_RESULT_DIR = Path("BE_throughput_result")
MASSTREE_DIR = Path("masstree")

def run_command(cmd, check=True):
    """Run a shell command and return the result."""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    return result

def run_masstree(num_cores, pressure):
    """Run tailbench masstree benchmark."""
    cmd = f"sudo ./run_tailbench_all_be.sh masstree {pressure} {num_cores}"
    run_command(cmd)

def extract_perf(num_cores, scenario, pressure):
    """Extract performance data for a given scenario and pressure."""
    output_file = BE_RESULT_DIR / f"{scenario}_{pressure}_{num_cores}.log"
    cmd = f"sudo python3 extract_masstree_perf.py --root {MASSTREE_DIR}/{pressure} > {output_file}"
    run_command(cmd)

def save_results(num_cores, scenario):
    """Rename masstree directory to scenario-specific name."""
    new_name = SCENARIOS[scenario] + f"_{num_cores}"
    if MASSTREE_DIR.exists():
        cmd = f"mv {MASSTREE_DIR} {new_name}"
        run_command(cmd)
        print(f"Moved {MASSTREE_DIR} to {new_name}")
    else:
        print(f"Warning: {MASSTREE_DIR} does not exist")

def run_partition_scenario(num_cores):
    """Run partition scenario for low and medium pressures."""
    for pressure in ["low", "medium"]:
        cmd = f"sudo python3 run_partition.py --LC masstree --run_all_SPEC -n {num_cores} --NUMA_unaware -p {pressure}"
        run_command(cmd)
        extract_perf(num_cores, "partition", pressure)

def run_eevdf_scenario(num_cores):
    """Run EEVDF scenario - high, medium and low pressures."""
    # Run high, medium and low
    for pressure in PRESSURES:
        cmd = ("sudo python3 run_test_tailbench.py --LC masstree --run_all_SPEC --NUMA_unaware "
               f"-n {num_cores} --task-type-shm /dev/shm/scx_rusty_task_types -p {pressure}")
        run_command(cmd)
    
    # Extract performance for all priorities
    for pressure in PRESSURES:
        extract_perf(num_cores, "EEVDF", pressure)

def main(num_cores):
    # Create output directory if it doesn't exist
    BE_RESULT_DIR.mkdir(exist_ok=True)
    
    # Run rusty scenario
    print("\n=== Running Rusty Scenario ===")
    run_masstree(num_cores, "medium")
    run_masstree(num_cores, "low")
    extract_perf(num_cores, "rusty", "medium")
    extract_perf(num_cores, "rusty", "low")
    save_results(num_cores, "rusty")
    
    # Run partition scenario
    print("\n=== Running Partition Scenario ===")
    run_partition_scenario(num_cores)
    save_results(num_cores, "partition")
    
    # Run EEVDF scenario
    print("\n=== Running EEVDF Scenario ===")
    run_eevdf_scenario(num_cores)
    save_results(num_cores, "EEVDF")
    
    print("\n=== All scenarios completed successfully ===")

if __name__ == "__main__":
    # get num_cores from command line, convert to int
    num_cores = int(sys.argv[1])
    try:
        main(num_cores)
    except subprocess.CalledProcessError as e:
        print(f"Error: Command failed with exit code {e.returncode}")
        print(f"Command: {e.cmd}")
        print(f"Output: {e.output}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)