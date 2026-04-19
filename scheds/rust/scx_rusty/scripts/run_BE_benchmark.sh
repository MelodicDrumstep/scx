#!/usr/bin/env bash
num_cores=$1

sudo ./run_tailbench_all_be.sh masstree high $num_cores
sudo ./run_tailbench_all_be.sh masstree medium $num_cores
sudo ./run_tailbench_all_be.sh masstree low $num_cores
sudo python3 extract_masstree_perf.py --root masstree/high > BE_throughput_result/coSMT_high_$num_cores.log
sudo python3 extract_masstree_perf.py --root masstree/medium > BE_throughput_result/coSMT_medium_$num_cores.log
sudo python3 extract_masstree_perf.py --root masstree/low > BE_throughput_result/coSMT_low_$num_cores.log
mv masstree masstree_coSMT_$num_cores

# Partition sweep: P99 threshold pairs are listed in run_BE_partition_sweep.py
sudo python3 run_BE_partition_sweep.py "$num_cores"

sudo python3 run_test_tailbench.py --LC masstree --run_all_SPEC --NUMA_unaware -n $num_cores --task-type-shm /dev/shm/scx_rusty_task_types -p high
sudo python3 run_test_tailbench.py --LC masstree --run_all_SPEC --NUMA_unaware -n $num_cores --task-type-shm /dev/shm/scx_rusty_task_types -p medium
sudo python3 run_test_tailbench.py --LC masstree --run_all_SPEC --NUMA_unaware -n $num_cores --task-type-shm /dev/shm/scx_rusty_task_types -p low
sudo python3 extract_masstree_perf.py --root masstree/high > BE_throughput_result/EEVDF_high_$num_cores.log
sudo python3 extract_masstree_perf.py --root masstree/medium > BE_throughput_result/EEVDF_medium_$num_cores.log
sudo python3 extract_masstree_perf.py --root masstree/low > BE_throughput_result/EEVDF_low_$num_cores.log
mv masstree masstree_EEVDF_$num_cores
