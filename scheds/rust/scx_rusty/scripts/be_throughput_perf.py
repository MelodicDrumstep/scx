"""
Shared helpers for BE throughput measurement with `perf stat -p` on the runspec PID.

- BFS from the BE root shell PID to find a real `runspec` process (skip `bash -c` wrapper).
- Optional background worker thread to wait for runspec then attach perf.
- Optional `-x,` CSV output for `parse_perf_stat_csv`.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from collections import deque


def child_pids_for_bfs(pid: int) -> list[int]:
    try:
        r = subprocess.run(
            ["ps", "-o", "pid=", "--no-headers", "--ppid", str(pid)],
            capture_output=True,
            text=True,
            check=False,
        )
        if r.returncode != 0:
            return []
        return [int(x) for x in r.stdout.split() if x.strip()]
    except (ValueError, FileNotFoundError):
        return []


def read_process_cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
    except (FileNotFoundError, ProcessLookupError):
        return ""
    return raw.replace(b"\0", b" ").decode(errors="replace").strip()


def find_runspec_pid_bfs(root_pid: int, exclude_bash_c: bool = True) -> int | None:
    """
    BFS from the BE root shell PID; first process whose cmdline contains `runspec` but is
    not a `bash -c '... runspec ...'` wrapper.
    """
    q: deque[int] = deque([root_pid])
    seen: set[int] = set()
    while q:
        pid = q.popleft()
        if pid in seen:
            continue
        seen.add(pid)
        cmd = read_process_cmdline(pid)
        if "runspec" in cmd:
            if exclude_bash_c and "bash -c" in cmd:
                pass
            else:
                return pid
        for c in child_pids_for_bfs(pid):
            q.append(c)
    return None


def wait_for_runspec_pid_bfs(
    root_pid: int,
    timeout_sec: float = 120.0,
    poll_interval: float = 0.5,
) -> int | None:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        pid = find_runspec_pid_bfs(root_pid)
        if pid is not None:
            return pid
        time.sleep(poll_interval)
    return None


def start_be_throughput_monitor(be_pid: int, *, perf_csv: bool = False):
    """
    Start `sudo perf stat -e instructions -p <be_pid>`.

    If ``perf_csv`` is True, pass ``-x,`` so stderr is CSV-shaped for :func:`parse_perf_stat_csv`.

    Returns (perf_process, start_time_monotonic) or (None, start_time_monotonic) on failure.
    """
    print(f"[throughput] perf stat target PID: {be_pid}")
    start_time = time.monotonic()
    cmd: list[str] = [
        "sudo",
        "perf",
        "stat",
    ]
    if perf_csv:
        cmd.append("-x,")
    cmd.extend(
        [
            "-e",
            "instructions",
            "-p",
            str(be_pid),
        ]
    )
    try:
        perf_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        print(f"[throughput] started perf stat -p {be_pid}")
        return perf_proc, start_time
    except FileNotFoundError:
        print("Warning: `perf` not found; BE throughput will not be measured.")
        return None, start_time
    except Exception as e:
        print(f"Warning: failed to start `perf stat` for BE throughput: {e}")
        return None, start_time


def throughput_monitor_worker(root_pid: int, out: dict, *, perf_csv: bool = False) -> None:
    """Wait for runspec under BE root via BFS, then start ``perf stat -p``."""
    runspec_pid = wait_for_runspec_pid_bfs(root_pid)
    if runspec_pid is None:
        out["runspec_pid"] = None
        out["perf_proc"] = None
        out["perf_start_time"] = None
        return
    out["runspec_pid"] = runspec_pid
    perf_proc, out["perf_start_time"] = start_be_throughput_monitor(runspec_pid, perf_csv=perf_csv)
    out["perf_proc"] = perf_proc


def kill_be_tree(be_process: subprocess.Popen) -> None:
    try:
        pgid = os.getpgid(be_process.pid)
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            be_process.terminate()
        except ProcessLookupError:
            pass


def parse_perf_stat_csv(stderr_text: str) -> tuple[int | None, float | None]:
    """
    Parse `perf stat -x,` stderr output.
    Returns (instructions, seconds_elapsed).
    """
    instructions: int | None = None
    seconds_elapsed: float | None = None

    for line in stderr_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue

        event = parts[1]

        if event == "instructions":
            v = parts[0].replace(",", "").strip()
            try:
                instructions = int(float(v))
            except ValueError:
                continue

        if "seconds time elapsed" in line:
            v = parts[0].replace(",", "").strip()
            try:
                seconds_elapsed = float(v)
            except ValueError:
                continue

    return instructions, seconds_elapsed
