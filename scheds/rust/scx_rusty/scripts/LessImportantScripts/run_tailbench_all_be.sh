#!/usr/bin/env bash
set -euo pipefail

# get LC and pressure from the command line
LC=$1
pressure=$2
num_cores=$3

# Directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# List of BE types (from run_partition.py)
BE_TYPES=(
"400.perlbench"
"401.bzip2"
"403.gcc"
"429.mcf"
"445.gobmk"
"456.hmmer"
"458.sjeng"
"462.libquantum"
"464.h264ref"
"473.astar"
"483.xalancbmk"
)

SCHED_BIN="/home/dell-07/wltu/scx/target/release/scx_rusty"
TASK_SHM="/dev/shm/scx_rusty_task_types"
TIMEOUT_MS=30000

for BE in "${BE_TYPES[@]}"; do
  echo "==== Running BE: ${BE} ===="

  # 1) Start scheduler as a separate process
  echo "Starting scx_rusty scheduler..."
  sudo "${SCHED_BIN}" \
    --task-type-shm "${TASK_SHM}" \
    --timeout-ms "${TIMEOUT_MS}" &
  RUSTY_PID=$!

  # Give scheduler a moment to initialize
  sleep 5

  # 2) Run tailbench test for this BE
  echo "Running Tailbench: LC=${LC}, BE=${BE}, pressure=${pressure}..."
  sudo python3 run_test_tailbench.py \
    --LC ${LC} \
    --BE "${BE}" \
    -n ${num_cores} \
    --NUMA_unaware \
    --task-type-shm "${TASK_SHM}" \
    -p ${pressure}

  # 3) After test finishes, kill scheduler if still running
  if ps -p "${RUSTY_PID}" > /dev/null 2>&1; then
    echo "Stopping scx_rusty (pid=${RUSTY_PID})..."
    sudo kill "${RUSTY_PID}" || true
    # Optional: wait briefly for clean exit
    sleep 1
  else
    echo "scx_rusty already exited."
  fi

  echo "==== Finished BE: ${BE} ===="
  echo
done

echo "All BE types completed."