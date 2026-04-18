import os
import subprocess
from pathlib import Path

TailbenchDir = Path("/home/dell-07/wltu/Tailbench/tailbench")
SPEC_2006_BE_list = [
    "400.perlbench",
    "401.bzip2",
    "403.gcc",
    "429.mcf",
    "445.gobmk",
    "456.hmmer",
    "458.sjeng",
    "462.libquantum",
    "464.h264ref",
    "473.astar",
    "483.xalancbmk",
]
First_SMT_silibing_core_ID = 20
Num_total_cores = 40

CORE_MASK_HEX = {
    10: "0x1111111111",
    5: "0x1010101010",
    15: "0x5555511111",
    20: "0x5555555555",
}


def get_child_pids(pid: int) -> list[int]:
    try:
        result = subprocess.run(
            ["pgrep", "-P", str(pid)],
            capture_output=True,
            text=True,
            check=True,
        )
        return [int(p) for p in result.stdout.strip().split("\n") if p]
    except (subprocess.CalledProcessError, ValueError):
        return []


def get_descendant_pids(pid: int, max_depth: int = 3) -> list[int]:
    pids: list[int] = []
    current_level = [pid]
    for _ in range(max_depth):
        next_level: list[int] = []
        for parent_pid in current_level:
            children = get_child_pids(parent_pid)
            pids.extend(children)
            next_level.extend(children)
        current_level = next_level
        if not current_level:
            break
    return pids


def get_all_thread_ids(pid: int) -> list[int]:
    thread_ids: list[int] = []
    task_dir = f"/proc/{pid}/task"
    if not os.path.exists(task_dir):
        return thread_ids

    try:
        for tid_str in os.listdir(task_dir):
            try:
                thread_ids.append(int(tid_str))
            except ValueError:
                continue
    except (OSError, PermissionError):
        pass
    return thread_ids


def get_process_group_pids(pid: int) -> list[int]:
    try:
        pgid = os.getpgid(pid)
        result = subprocess.run(
            ["pgrep", "-g", str(pgid)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return [int(p) for p in result.stdout.strip().split("\n") if p]
    except (OSError, ValueError, subprocess.CalledProcessError):
        pass
    return []


def get_all_threads_for_processes(pids: list[int]) -> list[int]:
    all_threads: list[int] = []
    for pid in pids:
        threads = get_all_thread_ids(pid)
        all_threads.extend(threads)
        if pid not in all_threads:
            all_threads.append(pid)
    return all_threads


def read_thread_cpu_time(tid: int) -> int | None:
    stat_path = f"/proc/{tid}/stat"
    try:
        with open(stat_path, "r") as f:
            data = f.read().split()
        utime = int(data[13])
        stime = int(data[14])
        return utime + stime
    except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError, ValueError):
        return None


def kill_all_spec_processes():
    commands = [
        "sudo pkill -f runspec",
        "sudo pkill -f specinvoke",
        "sudo pkill -f specmake",
        "sudo pkill -f run_base",
    ]
    for cmd in commands:
        try:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    print("Killed all SPEC processes")
