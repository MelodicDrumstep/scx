#!/usr/bin/env python3
"""
Visualization script for 30s-90s media streaming benchmark results
"""

import json
import matplotlib.pyplot as plt
import pandas as pd
import argparse
import os

def plot_results(results_file, output_dir):
    """Plot benchmark results focusing on P99 throughput"""
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    df = pd.DataFrame(results)
    
    # Create plots
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
    
    # Throughput vs Rate (Main focus)
    ax1.plot(df['rate'], df['throughput_p99'], 'r-o', linewidth=2, markersize=8, label='P99 Throughput')
    ax1.plot(df['rate'], df['throughput_avg'], 'b--o', linewidth=2, markersize=6, label='Average Throughput')
    ax1.set_xlabel('Request Rate (videos/sec)')
    ax1.set_ylabel('Throughput (Mbps)')
    ax1.set_title('P99 Throughput vs Request Rate\n(30s-90s Collection Window)')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Sample count vs Rate
    ax2.bar(df['rate'], df['sample_count'], width=df['rate'].max() * 0.05, alpha=0.7, color='green')
    ax2.set_xlabel('Request Rate (videos/sec)')
    ax2.set_ylabel('Sample Count')
    ax2.set_title('Metric Samples Collected\n(30s-90s Window)')
    ax2.grid(True, alpha=0.3)
    
    # Concurrent Clients vs Rate
    ax3.plot(df['rate'], df['concurrent_clients_avg'], 'g-o', linewidth=2)
    ax3.set_xlabel('Request Rate (videos/sec)')
    ax3.set_ylabel('Concurrent Clients')
    ax3.set_title('Concurrent Clients vs Request Rate')
    ax3.grid(True, alpha=0.3)
    
    # Errors vs Rate
    ax4.plot(df['rate'], df['total_errors_avg'], 'r-o', linewidth=2)
    ax4.set_xlabel('Request Rate (videos/sec)')
    ax4.set_ylabel('Total Errors')
    ax4.set_title('Errors vs Request Rate')
    ax4.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plot_file = os.path.join(output_dir, 'benchmark_plots_30s_90s.png')
    plt.savefig(plot_file, dpi=300, bbox_inches='tight')
    print(f"Plots saved to {plot_file}")
    
    # Show detailed summary
    print("\nPerformance Summary (30s-90s Collection Window):")
    print("="*70)
    print(f"{'Rate':>8} {'P99 Throughput':>15} {'Avg Throughput':>15} {'Samples':>10} {'Errors':>8}")
    print("-" * 70)
    for _, row in df.iterrows():
        print(f"{row['rate']:>8.1f} {row['throughput_p99']:>15.2f} {row['throughput_avg']:>15.2f} "
              f"{row['sample_count']:>10} {row['total_errors_avg']:>8.1f}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Visualize 30s-90s benchmark results')
    parser.add_argument('--results-file', required=True, help='JSON results file')
    parser.add_argument('--output-dir', required=True, help='Output directory for plots')
    
    args = parser.parse_args()
    plot_results(args.results_file, args.output_dir)