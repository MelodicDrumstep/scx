#!/bin/bash
num_cores=$1

# # baseline
sudo python3 run_test_tailbench.py --LC specjbb --run_all_SPEC --NUMA_unaware -n $num_cores --task-type-shm /dev/shm/scx_rusty_task_types -p high --disable-skip
sudo python3 run_test_tailbench.py --LC specjbb --run_all_SPEC --NUMA_unaware -n $num_cores --task-type-shm /dev/shm/scx_rusty_task_types -p medium --disable-skip
sudo python3 run_test_tailbench.py --LC specjbb --run_all_SPEC --NUMA_unaware -n $num_cores --task-type-shm /dev/shm/scx_rusty_task_types -p low --disable-skip
sudo python3 extract_masstree_perf.py --root specjbb/high > BE_throughput_result/EEVDF_high_$num_cores.log
sudo python3 extract_masstree_perf.py --root specjbb/medium > BE_throughput_result/EEVDF_medium_$num_cores.log
sudo python3 extract_masstree_perf.py --root specjbb/low > BE_throughput_result/EEVDF_low_$num_cores.log

# baseline
sudo python3 run_masstree_latency_matrix.py

# # partition
sudo python3 run_BE_partition_sweep.py $num_cores

# coSMT
sudo python3 ./run_tailbench_all_be.py specjbb high $num_cores
sudo python3 ./run_tailbench_all_be.py specjbb medium $num_cores
sudo python3 ./run_tailbench_all_be.py specjbb low $num_cores

sudo python3 ./run_tailbench_all_be.py specjbb high $num_cores
sudo python3 ./run_tailbench_all_be.py specjbb medium $num_cores
sudo python3 ./run_tailbench_all_be.py specjbb low $num_cores

