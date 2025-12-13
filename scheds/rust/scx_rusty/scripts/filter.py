import os
import re
from pathlib import Path

def extract_p99_latency(file_path):
    """Extract p99 end2end latency from a latency.log file"""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Pattern to match end2end p99 line
        pattern = r'end2end:.*?p99\s+([\d.]+)\s+ms'
        match = re.search(pattern, content)
        
        if match:
            return float(match.group(1))
        else:
            # Alternative pattern if the format is slightly different
            pattern2 = r'end2end.*?p99.*?([\d.]+)'
            match2 = re.search(pattern2, content)
            if match2:
                return float(match2.group(1))
            return None
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def main():
    # Get current directory
    current_dir = Path('.')
    
    # Find all directories that look like benchmarks (starting with numbers)
    benchmark_dirs = []
    for item in current_dir.iterdir():
        if item.is_dir() and item.name[0].isdigit():
            benchmark_dirs.append(item)
    
    # Sort directories by name
    benchmark_dirs.sort(key=lambda x: x.name)
    
    # Extract data
    results = []
    for bench_dir in benchmark_dirs:
        latency_file = bench_dir / 'latency.log'
        
        if latency_file.exists():
            p99_latency = extract_p99_latency(latency_file)
            if p99_latency is not None:
                results.append({
                    'BE Type': bench_dir.name,
                    'P99 End2End Latency (ms)': p99_latency
                })
            else:
                print(f"Warning: Could not extract p99 latency from {latency_file}")
        else:
            print(f"Warning: {latency_file} does not exist")
    
    # Print table
    if results:
        print("\nEnd-to-End P99 Latency Results")
        print("=" * 50)
        print(f"{'BE Type':<20} {'P99 End2End Latency (ms)':>25}")
        print("-" * 50)
        
        for result in results:
            print(f"{result['BE Type']:<20} {result['P99 End2End Latency (ms)']:>25.3f}")
        
        print("=" * 50)
        
        # Optional: Calculate statistics
        latencies = [r['P99 End2End Latency (ms)'] for r in results]
        if latencies:
            print(f"\nStatistics:")
            print(f"  Count: {len(latencies)}")
            print(f"  Average: {sum(latencies)/len(latencies):.3f} ms")
            print(f"  Min: {min(latencies):.3f} ms")
            print(f"  Max: {max(latencies):.3f} ms")
    else:
        print("No data extracted. Check if latency.log files exist in the benchmark directories.")

if __name__ == "__main__":
    main()