#!/usr/bin/env python3
import argparse
import csv
import math
import re
import statistics
import subprocess
from collections import defaultdict
from pathlib import Path


LAT_RE = re.compile(r"^\s*end2end:.*?\|\s*p99\s+([0-9]+(?:\.[0-9]+)?)\s*ms\b", re.M)


def parse_latency_ms(latency_log: Path) -> float:
    text = latency_log.read_text()
    match = LAT_RE.search(text)
    if not match:
        raise ValueError(f"Cannot parse end2end p99 from {latency_log}")
    return float(match.group(1))


def quantile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        raise ValueError("Empty values")
    if len(sorted_values) == 1:
        return sorted_values[0]
    pos = (len(sorted_values) - 1) * q
    left = math.floor(pos)
    right = math.ceil(pos)
    if left == right:
        return sorted_values[left]
    frac = pos - left
    return sorted_values[left] * (1.0 - frac) + sorted_values[right] * frac


def filter_outliers_iqr(values: list[float]) -> tuple[list[float], list[float]]:
    # For very small samples, do not remove anything.
    if len(values) < 4:
        return list(values), []
    ordered = sorted(values)
    q1 = quantile(ordered, 0.25)
    q3 = quantile(ordered, 0.75)
    iqr = q3 - q1
    low = q1 - 1.5 * iqr
    high = q3 + 1.5 * iqr
    kept = [v for v in values if low <= v <= high]
    removed = [v for v in values if v < low or v > high]
    if not kept:
        return list(values), []
    return kept, removed


def run_once(
    scripts_dir: Path,
    pressure: str,
    num_cores: int,
    task_type_shm: str,
    out_root: Path,
    run_idx: int,
) -> dict[str, float]:
    cmd = [
        "python3",
        "run_test_tailbench.py",
        "--LC",
        "masstree",
        "--run_all_SPEC",
        "--NUMA_unaware",
        "-n",
        str(num_cores),
        "--task-type-shm",
        task_type_shm,
        "-p",
        pressure,
        "--disable-skip",
    ]
    print(f"[RUN] cores={num_cores} pressure={pressure} repeat={run_idx}")
    subprocess.run(cmd, cwd=scripts_dir, check=True)

    extract_log = out_root / f"EEVDF_{pressure}_{num_cores}_run{run_idx}.log"
    with extract_log.open("w") as f:
        subprocess.run(
            [
                "python3",
                "extract_masstree_perf.py",
                "--root",
                f"masstree/{pressure}",
            ],
            cwd=scripts_dir,
            check=True,
            stdout=f,
        )

    result: dict[str, float] = {}
    pressure_root = scripts_dir / "masstree" / pressure
    for latency_log in sorted(pressure_root.glob("*/latency.log")):
        bench = latency_log.parent.name
        result[bench] = parse_latency_ms(latency_log)
    if not result:
        raise RuntimeError(f"No latency.log found under {pressure_root}")
    return result


def run_once_single_be(
    scripts_dir: Path,
    pressure: str,
    num_cores: int,
    be_name: str,
    task_type_shm: str,
    out_root: Path,
    run_idx: int,
) -> float:
    cmd = [
        "python3",
        "run_test_tailbench.py",
        "--LC",
        "masstree",
        "--BE",
        be_name,
        "--NUMA_unaware",
        "-n",
        str(num_cores),
        "--task-type-shm",
        task_type_shm,
        "-p",
        pressure,
        "--disable-skip",
    ]
    print(f"[RUN] single-be={be_name} cores={num_cores} pressure={pressure} repeat={run_idx}")
    subprocess.run(cmd, cwd=scripts_dir, check=True)

    extract_log = out_root / f"EEVDF_{pressure}_{num_cores}_{be_name}_run{run_idx}.log"
    with extract_log.open("w") as f:
        subprocess.run(
            [
                "python3",
                "extract_masstree_perf.py",
                "--root",
                f"masstree/{pressure}",
            ],
            cwd=scripts_dir,
            check=True,
            stdout=f,
        )

    latency_log = scripts_dir / "masstree" / pressure / be_name / "latency.log"
    if not latency_log.exists():
        raise RuntimeError(f"Latency log not found: {latency_log}")
    return parse_latency_ms(latency_log)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run masstree latency matrix, remove outliers, and build summary tables."
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=5,
        help="Number of repeats for each (pressure, num_cores) pair. Default: 5",
    )
    parser.add_argument(
        "--task-type-shm",
        default="/dev/shm/scx_rusty_task_types",
        help="task-type-shm value passed to run_test_tailbench.py",
    )
    parser.add_argument(
        "--pressures",
        nargs="+",
        default=["high", "medium", "low"],
        choices=["high", "medium", "low"],
        help="Pressure levels to test.",
    )
    parser.add_argument(
        "--num-cores",
        nargs="+",
        type=int,
        default=[10, 15, 20],
        help="Core counts to test.",
    )
    parser.add_argument(
        "--out-dir",
        default="BE_throughput_result",
        help="Output directory for raw extract logs and summary tables.",
    )
    parser.add_argument(
        "--single-be",
        default="",
        help="Run only one BE benchmark with the provided single num_cores and pressure.",
    )
    args = parser.parse_args()

    scripts_dir = Path(__file__).resolve().parent
    out_root = scripts_dir / args.out_dir
    out_root.mkdir(parents=True, exist_ok=True)

    if args.single_be:
        if len(args.num_cores) != 1:
            raise SystemExit("--single-be mode requires exactly one value in --num-cores.")
        if len(args.pressures) != 1:
            raise SystemExit("--single-be mode requires exactly one value in --pressures.")

        num_cores = args.num_cores[0]
        pressure = args.pressures[0]
        be_name = args.single_be
        vals: list[float] = []
        for run_idx in range(1, args.repeats + 1):
            latency_ms = run_once_single_be(
                scripts_dir=scripts_dir,
                pressure=pressure,
                num_cores=num_cores,
                be_name=be_name,
                task_type_shm=args.task_type_shm,
                out_root=out_root,
                run_idx=run_idx,
            )
            vals.append(latency_ms)

        kept, removed = filter_outliers_iqr(vals)
        mean_latency = statistics.mean(kept)
        std_latency = statistics.pstdev(kept) if len(kept) > 1 else 0.0

        csv_path = out_root / "latency_single_be_summary.csv"
        with csv_path.open("w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "num_cores",
                    "pressure",
                    "benchmark",
                    "runs_total",
                    "runs_kept",
                    "runs_removed",
                    "latencies_raw_ms",
                    "latencies_kept_ms",
                    "latencies_removed_ms",
                    "mean_latency_ms",
                    "std_latency_ms",
                ],
            )
            writer.writeheader()
            writer.writerow(
                {
                    "num_cores": num_cores,
                    "pressure": pressure,
                    "benchmark": be_name,
                    "runs_total": len(vals),
                    "runs_kept": len(kept),
                    "runs_removed": len(removed),
                    "latencies_raw_ms": ",".join(f"{x:.3f}" for x in vals),
                    "latencies_kept_ms": ",".join(f"{x:.3f}" for x in kept),
                    "latencies_removed_ms": ",".join(f"{x:.3f}" for x in removed),
                    "mean_latency_ms": f"{mean_latency:.3f}",
                    "std_latency_ms": f"{std_latency:.3f}",
                }
            )

        md_path = out_root / "latency_single_be_summary.md"
        with md_path.open("w") as f:
            removed_text = ",".join(f"{x:.3f}" for x in removed) if removed else "-"
            f.write(
                "| num_cores | pressure | benchmark | runs_kept/runs_total | mean_latency_ms | std_latency_ms | removed_values_ms |\n"
            )
            f.write("|---:|---|---|---:|---:|---:|---|\n")
            f.write(
                f"| {num_cores} | {pressure} | {be_name} | {len(kept)}/{len(vals)} | "
                f"{mean_latency:.3f} | {std_latency:.3f} | {removed_text} |\n"
            )

        print(
            f"[RESULT] BE={be_name} cores={num_cores} pressure={pressure} "
            f"mean_latency_ms={mean_latency:.3f} kept={len(kept)}/{len(vals)} "
            f"raw=[{', '.join(f'{x:.3f}' for x in vals)}] "
            f"removed=[{', '.join(f'{x:.3f}' for x in removed) if removed else '-'}]"
        )
        print(f"[DONE] Wrote CSV summary: {csv_path}")
        print(f"[DONE] Wrote Markdown table: {md_path}")
        return

    # key=(num_cores, pressure, benchmark), value=list of latency(ms) over repeats
    all_values: dict[tuple[int, str, str], list[float]] = defaultdict(list)

    for num_cores in args.num_cores:
        for pressure in args.pressures:
            for run_idx in range(1, args.repeats + 1):
                run_values = run_once(
                    scripts_dir=scripts_dir,
                    pressure=pressure,
                    num_cores=num_cores,
                    task_type_shm=args.task_type_shm,
                    out_root=out_root,
                    run_idx=run_idx,
                )
                for bench, latency_ms in run_values.items():
                    all_values[(num_cores, pressure, bench)].append(latency_ms)

    rows = []
    for (num_cores, pressure, bench), vals in sorted(all_values.items()):
        kept, removed = filter_outliers_iqr(vals)
        mean_latency = statistics.mean(kept)
        std_latency = statistics.pstdev(kept) if len(kept) > 1 else 0.0
        rows.append(
            {
                "num_cores": num_cores,
                "pressure": pressure,
                "benchmark": bench,
                "runs_total": len(vals),
                "runs_kept": len(kept),
                "runs_removed": len(removed),
                "latencies_raw_ms": ",".join(f"{x:.3f}" for x in vals),
                "latencies_kept_ms": ",".join(f"{x:.3f}" for x in kept),
                "latencies_removed_ms": ",".join(f"{x:.3f}" for x in removed),
                "mean_latency_ms": round(mean_latency, 3),
                "std_latency_ms": round(std_latency, 3),
            }
        )

    csv_path = out_root / "latency_summary_by_be.csv"
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "num_cores",
                "pressure",
                "benchmark",
                "runs_total",
                "runs_kept",
                "runs_removed",
                "latencies_raw_ms",
                "latencies_kept_ms",
                "latencies_removed_ms",
                "mean_latency_ms",
                "std_latency_ms",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    md_path = out_root / "latency_summary_by_be.md"
    with md_path.open("w") as f:
        f.write(
            "| num_cores | pressure | benchmark | runs_kept/runs_total | mean_latency_ms | std_latency_ms | removed_values_ms |\n"
        )
        f.write("|---:|---|---|---:|---:|---:|---|\n")
        for row in rows:
            removed_text = row["latencies_removed_ms"] or "-"
            f.write(
                f"| {row['num_cores']} | {row['pressure']} | {row['benchmark']} | "
                f"{row['runs_kept']}/{row['runs_total']} | {row['mean_latency_ms']:.3f} | "
                f"{row['std_latency_ms']:.3f} | {removed_text} |\n"
            )

    print(f"[DONE] Wrote CSV summary: {csv_path}")
    print(f"[DONE] Wrote Markdown table: {md_path}")


if __name__ == "__main__":
    main()
