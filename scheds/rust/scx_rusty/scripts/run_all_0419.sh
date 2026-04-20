#!/bin/bash
num_cores=$1

# partition
sudo python3 run_BE_partition_sweep.py $num_cores

# baseline
sudo python3 run_test_tailbench.py --LC masstree --run_all_SPEC --NUMA_unaware -n $num_cores --task-type-shm /dev/shm/scx_rusty_task_types -p high --disable-skip
sudo python3 run_test_tailbench.py --LC masstree --run_all_SPEC --NUMA_unaware -n $num_cores --task-type-shm /dev/shm/scx_rusty_task_types -p medium --disable-skip
sudo python3 run_test_tailbench.py --LC masstree --run_all_SPEC --NUMA_unaware -n $num_cores --task-type-shm /dev/shm/scx_rusty_task_types -p low --disable-skip
sudo python3 extract_masstree_perf.py --root masstree/high > BE_throughput_result/EEVDF_high_$num_cores.log
sudo python3 extract_masstree_perf.py --root masstree/medium > BE_throughput_result/EEVDF_medium_$num_cores.log
sudo python3 extract_masstree_perf.py --root masstree/low > BE_throughput_result/EEVDF_low_$num_cores.log

# coSMT
sudo python3 ./run_tailbench_all_be.py masstree high $num_cores
sudo python3 ./run_tailbench_all_be.py masstree medium $num_cores
sudo python3 ./run_tailbench_all_be.py masstree low $num_cores



