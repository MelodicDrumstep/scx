#!/usr/bin/env python3
"""
Run specjbb + SPEC partition experiments while sweeping (--lc-p99-low-ms, --lc-p99-high-ms) pairs.

Replaces the run_partition block in run_BE_benchmark.sh (lines 12–18) with configurable lists.

Orchestration (partition + EEVDF + co-SMT) from this directory::

    sudo ./run_all_0419.sh <num_cores>          # e.g. sudo ./run_all_0419.sh 5

Or run multiple core counts::

    sudo ./run_all_0419_meta.sh

Equivalent from Python (delegates to the same shell script)::

    sudo python3 run_BE_partition_sweep.py --full-suite <num_cores>
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


# (pressure, list of (lc_p99_low_ms, lc_p99_high_ms))
# Edit these lists to sweep threshold pairs per pressure level.
P99_PAIRS_BY_PRESSURE: dict[str, list[tuple[float, float]]] = {
    "high": [
        (0.7, 0.9),
        (0.8, 1.0),
        (0.9, 1.1),
        (1.0, 1.2),
        (1.2, 1.5),
        (1.5, 2.0)
    ],
    "medium": [
        (0.5, 0.7),
        (0.4, 0.6),
        (0.5, 0.6),
        (0.6, 0.8),
        (0.7, 0.9),
        (0.8, 1.0),
    ],
    "low": [
        (0.3, 0.4),
        (0.4, 0.8),
        (0.6, 0.8),
        (0.7, 0.9),
        (0.8, 1.0),
    ],
}


def _limits_file_suffix(low_ms: float, high_ms: float) -> str:
    """Embed both p99 limits in artifact names (log + specjbb dir)."""
    return f"lc-p99-low-{low_ms:g}-high-{high_ms:g}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sweep lc p99 thresholds for run_partition.py (specjbb + --run_all_SPEC)."
    )
    parser.add_argument(
        "num_cores",
        type=int,
        help="Core count passed to -n (same as run_BE_benchmark.sh $1).",
    )
    parser.add_argument(
        "--scripts-dir",
        type=Path,
        default=None,
        help="Directory containing run_partition.py and extract_masstree_perf.py (default: this script's directory).",
    )
    parser.add_argument(
        "--full-suite",
        action="store_true",
        help="Run scripts/run_all_0419.sh <num_cores> (partition sweep + EEVDF + co-SMT). "
        "Uses P99_PAIRS_BY_PRESSURE from this file via the nested call to this script.",
    )
    args = parser.parse_args()

    scripts_dir = args.scripts_dir or Path(__file__).resolve().parent

    if args.full_suite:
        wrapper = scripts_dir / "run_all_0419.sh"
        if not wrapper.is_file():
            print(f"ERROR: missing {wrapper}", file=sys.stderr)
            return 1
        cmd = ["sudo", str(wrapper), str(args.num_cores)]
        print("Delegating full suite:", " ".join(cmd), "(cwd:", scripts_dir, ")")
        return subprocess.run(cmd, cwd=str(scripts_dir)).returncode or 0

    run_partition = scripts_dir / "run_partition.py"
    extract_perf = scripts_dir / "extract_masstree_perf.py"
    for name, path in ("run_partition.py", run_partition), ("extract_masstree_perf.py", extract_perf):
        if not path.is_file():
            print(f"ERROR: missing {name} at {path}", file=sys.stderr)
            return 1

    out_root = scripts_dir / "BE_throughput_result"
    out_root.mkdir(parents=True, exist_ok=True)
    masstree_dir = scripts_dir / "specjbb"

    # clean specjbb dir up if there's data
    if masstree_dir.is_dir():
        shutil.rmtree(masstree_dir)

    num_cores = args.num_cores

    for pressure, pairs in P99_PAIRS_BY_PRESSURE.items():
        for low_ms, high_ms in pairs:
            if low_ms >= high_ms:
                print(
                    f"ERROR: skip invalid pair for {pressure}: "
                    f"--lc-p99-low-ms {low_ms} must be < --lc-p99-high-ms {high_ms}",
                    file=sys.stderr,
                )
                return 1

            limits_suffix = _limits_file_suffix(low_ms, high_ms)
            print(
                f"\n=== partition: pressure={pressure} "
                f"lc-p99-low={low_ms} lc-p99-high={high_ms} (cores={num_cores}) ==="
            )

            cmd = [
                "sudo",
                "python3",
                str(run_partition),
                "--LC",
                "specjbb",
                "--run_all_SPEC",
                "--NUMA_unaware",
                "-n",
                str(num_cores),
                "-p",
                pressure,
                "--lc-p99-low-ms",
                str(low_ms),
                "--lc-p99-high-ms",
                str(high_ms),
            ]
            print("Running:", " ".join(cmd))
            subprocess.run(cmd, cwd=str(scripts_dir), check=True)

            log_path = out_root / f"partition_{pressure}_{num_cores}_{limits_suffix}.log"
            extract_cmd = [
                "sudo",
                "python3",
                str(extract_perf),
                "--root",
                f"specjbb/{pressure}",
            ]
            print("Writing:", log_path)
            with open(log_path, "w") as log_f:
                subprocess.run(extract_cmd, cwd=str(scripts_dir), stdout=log_f, check=True)

            # dest = scripts_dir / f"masstree_partition_{num_cores}_{pressure}_{limits_suffix}"
            # if dest.exists():
            #     shutil.rmtree(dest)
            # if not masstree_dir.is_dir():
            #     print(f"WARNING: expected {masstree_dir} after run; skip mv", file=sys.stderr)
            # else:
            #     shutil.move(str(masstree_dir), str(dest))
            #     print("Moved:", dest)

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
