#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

# Matches: "end2end: mean ... | p95 ... | p99 3.024 ms | max ... ms"
END2END_P99_RE = re.compile(r"^\s*end2end:.*?\|\s*p99\s+([0-9]+(?:\.[0-9]+)?)\s*ms\b", re.M)
USED_TIME_RE = re.compile(r"^\s*#\s*used_time_sec\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*$")
USED_TIME_DEFAULT_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s+seconds time elapsed\s*$", re.M)
INSTRUCTIONS_DEFAULT_RE = re.compile(r"^\s*([0-9][0-9,]*)\s+instructions\s*$", re.M)


def parse_p99_end2end_ms(latency_log_path: Path) -> float:
    text = latency_log_path.read_text()
    m = END2END_P99_RE.search(text)
    if not m:
        raise ValueError(f"Could not find `end2end p99 ... ms` in {latency_log_path}")
    return float(m.group(1))


def parse_instructions_per_macrosecond(be_perf_stat_csv_path: Path) -> float:
    """
    Parse BE perf output and return instructions per microsecond.

    Supports two layouts:
    1) CSV-ish (-x,) with our injected "# used_time_sec=..." header.
    2) Human-readable perf output:
       "X instructions" and "Y seconds time elapsed"
    """
    raw_text = be_perf_stat_csv_path.read_text()
    # For parsing the human-readable perf output, ignore comments and empty lines
    # so headers like "# used_time_sec=..." don't interfere.
    filtered_lines = []
    for ln in raw_text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        filtered_lines.append(ln)
    text = "\n".join(filtered_lines)

    # print(text)

    used_time_sec = None
    instructions = None

    # 1) Prefer our injected header for used time (from the *raw* file).
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = USED_TIME_RE.match(line)
            if m:
                used_time_sec = float(m.group(1))
                break

    # 2) If missing, try default perf line.
    if used_time_sec is None:
        m = USED_TIME_DEFAULT_RE.search(text)
        if m:
            used_time_sec = float(m.group(1))

    # 3) Instructions: try default perf line first.
    if instructions is None:
        m = INSTRUCTIONS_DEFAULT_RE.search(text)
        if m:
            instructions = float(m.group(1).replace(",", ""))

    # 4) Instructions: try CSV-ish layout (-x,) if needed.
    if instructions is None:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 4:
                continue
            event = parts[2].strip()
            if event != "instructions":
                continue
            # Usually the instruction count is the first element.
            try:
                instructions = float(parts[0].replace(",", "").strip())
            except ValueError:
                # Fallback: sometimes count appears in another column.
                try:
                    instructions = float(parts[3].replace(",", "").strip())
                except ValueError:
                    instructions = None
            if instructions is not None:
                break

    if used_time_sec is None:
        raise ValueError(f"Missing used_time_sec in {be_perf_stat_csv_path}")
    if used_time_sec <= 0:
        raise ValueError(f"Invalid used_time_sec={used_time_sec} in {be_perf_stat_csv_path}")
    if instructions is None:
        raise ValueError(f"Missing `instructions` in {be_perf_stat_csv_path}")

    # 1 microsecond = 1e-6 seconds.
    instructions_per_us = instructions / (used_time_sec * 1_000_000.0)
    return instructions_per_us


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
    # Expect: <root>/<benchmark>/BE.perf.stat.csv always; latency.log may be missing.
    for be_perf_path in sorted(root.rglob("BE.perf.stat.csv")):
        bench_dir = be_perf_path.parent
        lat_path = bench_dir / "latency.log"

        ins_per_us = parse_instructions_per_macrosecond(be_perf_path)
        p99_ms: float | None = None
        if lat_path.exists():
            p99_ms = parse_p99_end2end_ms(lat_path)

        rows.append((bench_dir.name, p99_ms, ins_per_us))

    # CSV header
    header = "benchmark,p99_end2end_ms,instructions_per_microsecond"
    out_lines = [header]
    def fmt(x: float, digits: int = 3) -> str:
        return f"{x:.{digits}f}"

    for bench, p99_ms, ins_per_us in rows:
        p99_str = f"{p99_ms:.3f}" if p99_ms is not None else ""
        out_lines.append(f"{bench},{p99_str},{fmt(ins_per_us, 3)}")

    if args.out:
        Path(args.out).write_text("\n".join(out_lines) + "\n")
    else:
        print("\n".join(out_lines))


if __name__ == "__main__":
    main()