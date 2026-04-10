#!/usr/bin/env bash
set -euo pipefail

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
"470.lbm"
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
  sleep 2

  # 2) Run tailbench test for this BE
  echo "Running Tailbench: LC=specjbb, BE=${BE}, pressure=high..."
  sudo python3 run_test_tailbench.py \
    --LC specjbb \
    --BE "${BE}" \
    --NUMA_unaware \
    --task-type-shm "${TASK_SHM}" \
    -p high

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