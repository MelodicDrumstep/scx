#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

# Matches: "end2end: mean ... | p95 ... | p99 3.024 ms | max ... ms"
END2END_P99_RE = re.compile(r"^\s*end2end:.*?\|\s*p99\s+([0-9]+(?:\.[0-9]+)?)\s*ms\b", re.M)
USED_TIME_RE = re.compile(r"^\s*#\s*used_time_sec\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*$")


def parse_p99_end2end_ms(latency_log_path: Path) -> float:
    text = latency_log_path.read_text()
    m = END2END_P99_RE.search(text)
    if not m:
        raise ValueError(f"Could not find `end2end p99 ... ms` in {latency_log_path}")
    return float(m.group(1))


def parse_instructions_per_sec(be_perf_stat_csv_path: Path) -> float:
    used_time_sec = None
    instructions = None

    for line in be_perf_stat_csv_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue

        # Header we added in scripts: "# used_time_sec=..."
        if line.startswith("#"):
            m = USED_TIME_RE.match(line)
            if m:
                used_time_sec = float(m.group(1))
            continue

        # perf stat -x, CSV line format (example):
        # "61057972714,,instructions,21076111350,100.00,,"
        parts = line.split(",")
        if len(parts) < 4:
            continue

        event = parts[2].strip()
        value = parts[3].strip()

        if event == "instructions":
            instructions = float(value)

    if used_time_sec is None:
        raise ValueError(f"Missing used_time_sec header in {be_perf_stat_csv_path}")
    if instructions is None:
        raise ValueError(f"Missing `instructions` row in {be_perf_stat_csv_path}")

    return instructions / used_time_sec


def main():
    ap = argparse.ArgumentParser(
        description="Extract p99 end2end latency and BE instructions/sec from masstree_partition/."
    )
    ap.add_argument(
        "--root",
        required=True,
        help="Path to masstree_partition/<level> (e.g. masstree_partition/high).",
    )
    ap.add_argument(
        "--out",
        default="",
        help="Optional output CSV path. If empty, prints to stdout.",
    )
    args = ap.parse_args()

    root = Path(args.root)
    if not root.exists():
        raise SystemExit(f"Root does not exist: {root}")

    rows = []
    # Expect: <root>/<benchmark>/latency.log and <root>/<benchmark>/BE.perf.stat.csv
    for lat_path in sorted(root.rglob("latency.log")):
        bench_dir = lat_path.parent
        be_perf_path = bench_dir / "BE.perf.stat.csv"
        if not be_perf_path.exists():
            print(f"Warning: missing {be_perf_path}, skipping {bench_dir.name}")
            continue

        p99_ms = parse_p99_end2end_ms(lat_path)
        ips = parse_instructions_per_sec(be_perf_path)

        rows.append((bench_dir.name, p99_ms, ips))

    # CSV header
    header = "benchmark,p99_end2end_ms,instructions_per_sec"
    out_lines = [header]
    def fmt_times_10_pow(x: float, digits: int = 2) -> str:
        if x == 0:
            return f"{0:.{digits}f}" # \times 10^9
        exp = int(f"{x:e}".split("e")[1])
        mant = x / (10 ** exp)
        return f"{mant:.{digits}f} \\\\times 10^{exp}"

    for bench, p99_ms, ips in rows:
        out_lines.append(f"{bench},{p99_ms:.3f},{fmt_times_10_pow(ips, 2)}")

    if args.out:
        Path(args.out).write_text("\n".join(out_lines) + "\n")
    else:
        print("\n".join(out_lines))


if __name__ == "__main__":
    main()