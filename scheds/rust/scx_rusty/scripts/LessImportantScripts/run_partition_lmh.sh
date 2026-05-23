#!/bin/bash
sudo python3 run_partition.py --LC masstree --run_all_SPEC --NUMA_unaware -p high
sudo python3 run_partition.py --LC masstree --run_all_SPEC --NUMA_unaware -p low
sudo python3 run_partition.py --LC masstree --run_all_SPEC --NUMA_unaware -p medium