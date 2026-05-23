# SENSE: SMT-Enabled Next-generation Scheduling Engine

SENSE is a **multi-domain BPF/userspace hybrid scheduler** built on `scx_rusty` (part of the Linux `sched_ext` framework). It extends the upstream `scx_rusty` with:

- **LC/BE task classification** — Latency-Critical (LC) and Best-Effort (BE) tasks are identified via a shared-memory ring buffer and scheduled differently.
- **SMT-aware core placement** — LC tasks get dedicated physical cores by kicking BE tasks off SMT siblings. BE dispatch is blocked when an LC task occupies either SMT thread of a physical core.
- **Latency-based BE throttling** — A userspace monitor reads LC p99 latency from a pinned BPF map. When latency exceeds the threshold, BE dispatch is globally paused.
- **Dynamic core partitioning** — The `run_partition.py` script can dynamically move cores between LC and BE NUMA domains based on real-time latency feedback.

The scheduler monitors workload in [src/main.rs](src/main.rs) and implements scheduling decisions in [src/bpf/main.bpf.c](src/bpf/main.bpf.c).

---

# Run

## 1. Start the Scheduler

```bash
sudo ../../../target/release/scx_rusty \
    --task-type-shm /dev/shm/scx_rusty_task_types \
    --timeout-ms 30000 \
    --latency-threshold-ns <LATENCY_THRESHOLD_NS> \
    --be-kick-cooldown-ms <BE_KICK_COOLDOWN_MS>
```

## 2. Run LC/BE Co-location Experiment

Run a single Latency-Critical (LC) workload alongside one Best-Effort (BE) benchmark:

```bash
sudo python3 scripts/run_test_tailbench.py \
    --LC masstree \
    --BE <BE_type> \
    --NUMA_unaware \
    -n <num_cores> \
    --task-type-shm /dev/shm/scx_rusty_task_types \
    -p <high|medium|low> \
    --latency-low-ms <LATENCY_LOW_MS> \
    --latency-high-ms <LATENCY_HIGH_MS> \
    --be-dispatch-interval-ms <BE_DISPATCH_INTERVAL_MS>
    --disable-skip
```

Run the full SPEC CPU2006 suite as BE:

```bash
sudo python3 scripts/run_test_tailbench.py \
    --LC masstree \
    --run_all_SPEC \
    --NUMA_unaware \
    -n <num_cores> \
    --task-type-shm /dev/shm/scx_rusty_task_types \
    -p <high|medium|low> \
    --latency-low-ms <LATENCY_LOW_MS> \
    --latency-high-ms <LATENCY_HIGH_MS> \
    --be-dispatch-interval-ms <BE_DISPATCH_INTERVAL_MS>
    --disable-skip
```

## 3. Dynamic Core Partitioning

Partition mode dynamically moves cores between LC and BE based on real-time p99 latency:

```bash
sudo python3 scripts/run_partition.py \
    --LC masstree \
    --BE <BE_type> \
    --NUMA_unaware \
    -n <num_cores> \
    -p <high|medium|low> \
    --lc_p99_low_ms <LC_P99_LOW_MS> \
    --lc_p99_high_ms <LC_P99_HIGH_MS>
```

Partition across all SPEC benchmarks:

```bash
sudo python3 scripts/run_partition.py \
    --LC masstree \
    --run_all_SPEC \
    --NUMA_unaware \
    -n <num_cores> \
    -p <high|medium|low> \
    -lc_p99_low_ms <LC_P99_LOW_MS> \
    -lc_p99_high_ms <LC_P99_HIGH_MS>
```

## Example: How to run 10 core, high load senarios

### SENSE Scheduler:

In one terminal:

```bash
sudo ../../../target/release/scx_rusty --task-type-shm /dev/shm/scx_rusty_task_types --timeout-ms 30000  --latency-high-ms 2.6 --latency-low-ms 2.2 --num-cores 10 --be-dispatch-interval-ms 180
```

Another terminal:

```bash
sudo python3 run_test_tailbench.py --LC masstree --BE 401.bzip2 --NUMA_unaware -n 10 --task-type-shm /dev/shm/scx_rusty_task_types -p high --disable-skip
```

### Isolation

```bash
sudo python3 run_partition.py --LC masstree --BE 401.bzip2 --NUMA_unaware -n 10 -p high
```

---

# Data Analysis

Extract per-BE p99 latency and throughput results:

```bash
python3 scripts/extract_masstree_perf.py --root masstree/high
```

---

# Details:

1. Requires modified support for Tailbench to write p99 latency into a ring buffer in shared memory.

2. Since BE processes continuously spawn child threads, the scheduler uses the parent process information from the process control block to identify BE tasks.

3. The performance of the SENSE scheduler is sensitive to the `latency_low_ms`, `latency_high_ms`, and `be_dispatch_interval_ms` parameters. These parameters need to be adjusted for different invocation scenarios.

4. To prevent a sudden surge in BE task scheduling—which would cause a sharp increase in LC latency—at the moment when LC performance targets transition from unsatisfied to satisfied, the SENSE scheduler introduces a rate limiting mechanism for scheduling BE tasks.

5. Run `sudo pkill -f runspec` if `Ctrl-C` fails to clean up a running test script.

# License

Based on `scx_rusty` — [GPL-2.0-only](LICENSE).
