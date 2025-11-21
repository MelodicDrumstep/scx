# scx_rusty

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

A multi-domain, BPF / user space hybrid scheduler. The BPF portion of the
scheduler does a simple round robin in each domain, and the user space portion
(written in Rust) calculates the load factor of each domain, and informs BPF of
how tasks should be load balanced accordingly.

## How To Install

Available as a [Rust crate](https://crates.io/crates/scx_rusty): `cargo add scx_rusty`

## Typical Use Case

`scx_rusty` is designed to be flexible, accommodating different architectures and
workloads. Various load balancing thresholds (e.g. greediness, frequency, etc),
as well as how `scx_rusty` should partition the system into scheduling domains, can
be tuned to achieve the optimal configuration for any given system or workload.

## Task Types via Shared Memory

`scx_rusty` can read task-type assignments from a shared memory file when it
starts. Provide a path (for example one under `/dev/shm`) via
`--task-type-shm <PATH>`. The file must contain whitespace-separated `PID TYPE`
pairs per line, where `TYPE` is either `LC` (latency critical) or `BE`
(best-effort). Lines beginning with `#` or blank lines are ignored. When a task
that is tagged as `BE` becomes runnable, the in-kernel scheduler gives it a 0.5%
chance of being enqueued rather than directly dispatched to a CPU, which lets
latency-critical work run first.

## Production Ready?

Yes. If tuned correctly, `scx_rusty` should be performant across various CPU
architectures and workloads. By default, `scx_rusty` creates a separate scheduling
domain per-LLC, so its default configuration may be performant as well. Note
however that `scx_rusty` does not yet disambiguate between LLCs in different NUMA
nodes, so it may perform better on multi-CCX machines where all the LLCs share
the same socket, as opposed to multi-socket machines.

Note as well that you may run into an issue with infeasible weights, where a
task with a very high weight may cause the scheduler to incorrectly leave cores
idle because it thinks they're necessary to accommodate the compute for a
single task. This can also happen in CFS, and should soon be addressed for
`scx_rusty`.
