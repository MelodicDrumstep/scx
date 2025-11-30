#!/usr/bin/env python3
"""
Media Streaming Benchmark Script - Modified Launch Pattern
Uses fixed CPU pinning and auto-scaled video count (100 * rate)
"""

import subprocess
import time
import json
import csv
import os
import sys
import argparse
import threading
from datetime import datetime
from pathlib import Path
import signal

class MediaStreamingBenchmark:
    def __init__(self, config):
        self.config = config
        self.results = []
        self.current_client_process = None
        
        # Create output directories
        Path(config['output_dir']).mkdir(parents=True, exist_ok=True)
        Path(config['session_lists_dir']).mkdir(parents=True, exist_ok=True)
        
    def run_command(self, cmd, check=True, capture_output=True, wait=True):
        """Run a shell command and return the result"""
        try:
            if capture_output:
                result = subprocess.run(cmd, shell=True, check=check, 
                                      capture_output=True, text=True)
                return result.stdout, result.stderr
            else:
                if wait:
                    subprocess.run(cmd, shell=True, check=check)
                else:
                    # For non-blocking commands, use Popen
                    process = subprocess.Popen(cmd, shell=True)
                    if wait:
                        process.wait()
                    return process
                return None, None
        except subprocess.CalledProcessError as e:
            print(f"Error running command: {cmd}")
            print(f"Error: {e}")
            if check:
                raise
            return None, None

    def setup_dataset_and_server(self):
        """Setup the dataset container and server in correct order"""
        print("Step 1: Setting up dataset container (this will block until dataset is generated)...")
        # Clean up existing dataset container
        self.run_command("docker stop streaming_dataset 2>/dev/null || true", check=False)
        self.run_command("docker rm streaming_dataset 2>/dev/null || true", check=False)
        
        # Step 1: Run dataset container (this blocks until dataset generation is complete)
        cmd = "docker run --name streaming_dataset cloudsuite/media-streaming:dataset"
        print(f"Running: {cmd}")
        print("Waiting for dataset generation to complete... This may take a while.")
        self.run_command(cmd)
        print("Dataset generation completed!")
        
        # Step 2: Start the server with CPU pinning and file descriptor limits
        print("\nStep 2: Starting media streaming server with CPU pinning...")
        # Stop existing server if running
        self.run_command("docker stop streaming_server 2>/dev/null || true", check=False)
        self.run_command("docker rm streaming_server 2>/dev/null || true", check=False)
        
        cpuset_cpus = self.config['cpuset_cpus']
        cmd = (
            f"docker run --cpuset-cpus={cpuset_cpus} "
            f"--ulimit nofile=65536:65536 "  # File descriptor limit
            f"-d --name streaming_server --volumes-from streaming_dataset --net host "
            f"cloudsuite/media-streaming:server"
        )
        print(f"Running: {cmd}")
        self.run_command(cmd)
        
        # Step 3: Copy session lists
        print("\nStep 3: Copying session lists...")
        cmd = f"docker cp streaming_dataset:/videos/logs/. {self.config['session_lists_dir']}/"
        print(f"Running: {cmd}")
        self.run_command(cmd)
        
        # Wait for server to start
        print("Waiting for server to start...")
        time.sleep(10)

    def run_benchmark_phase(self, rate, phase_name):
        """Run a single benchmark phase with auto-scaled video count (100 * rate)"""
        print(f"\n=== Running benchmark phase: {phase_name} ===")
        print(f"Rate: {rate} videos/sec")
        print(f"Video count: {100 * rate} (auto-scaled as 100 * rate)")
        
        # Auto-scale video count: 100 * rate
        video_count = int(100 * rate)
        
        # Prepare client command with CPU pinning and file descriptor limits
        cpuset_cpus = self.config['cpuset_cpus']
        client_cmd = (
            f"docker run --rm --cpuset-cpus={cpuset_cpus} "
            f"--ulimit nofile=65536:65536 "  # File descriptor limit
            f"-t -v {self.config['session_lists_dir']}:/videos/logs "
            f"-v {self.config['output_dir']}:/output --net host "
            f"cloudsuite/media-streaming:client localhost "
            f"{self.config['videoperf_processes']} {video_count} {rate} PT"  # Ensure PT mode
        )
        
        # Start client process
        print(f"Starting client: {client_cmd}")
        process = subprocess.Popen(client_cmd, shell=True, stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        self.current_client_process = process
        
        # Collect metrics from 30s to 90s
        metrics = self.collect_metrics_30s_to_90s(process, rate, phase_name)
        
        # Stop the client process after 90 seconds
        print(f"Stopping client after 90 seconds...")
        self.stop_client_process(phase_name)
        
        return metrics

    def collect_metrics_30s_to_90s(self, process, rate, phase_name):
        """Collect metrics specifically from 30s to 90s after start"""
        start_time = time.time()
        collection_start_time = start_time + 30  # Start collecting at 30s
        collection_end_time = start_time + 90    # Stop collecting at 90s
        
        throughput_samples = []
        error_samples = []
        concurrent_clients_samples = []
        reply_rate_samples = []
        
        print("Waiting for 30 seconds before starting metric collection...")
        
        # Phase 1: Wait until 30 seconds (warm-up period)
        while time.time() < collection_start_time:
            # line = process.stdout.readline()
            # if line:
            #     print(f"Warm-up: {line.strip()}")
            time.sleep(0.1)
        
        print("Starting metric collection (30s - 90s)...")
        
        # Phase 2: Collect metrics from 30s to 90s
        while time.time() < collection_end_time:
            line = process.stdout.readline()
            if line:
                metrics = self.parse_metrics_line(line)
                if metrics:
                    throughput_samples.append(metrics['throughput'])
                    error_samples.append(metrics['total_errors'])
                    concurrent_clients_samples.append(metrics['concurrent_clients'])
                    reply_rate_samples.append(metrics['reply_rate'])
                    
                    print(f"Phase {phase_name} - {metrics}")
            
            time.sleep(0.1)
        
        # Calculate statistics from the 60-second collection window
        if throughput_samples:
            stats = {
                'phase': phase_name,
                'rate': rate,
                'video_count': int(100 * rate),  # Track the auto-scaled video count
                'collection_window': '30s-90s',
                'throughput_avg': sum(throughput_samples) / len(throughput_samples),
                'throughput_p99': self.percentile(throughput_samples, 99),
                'throughput_p95': self.percentile(throughput_samples, 95),
                'throughput_max': max(throughput_samples),
                'throughput_min': min(throughput_samples),
                'sample_count': len(throughput_samples),
                'total_errors_avg': sum(error_samples) / len(error_samples),
                'concurrent_clients_avg': sum(concurrent_clients_samples) / len(concurrent_clients_samples),
                'reply_rate_avg': sum(reply_rate_samples) / len(reply_rate_samples),
                'timestamp': datetime.now().isoformat()
            }
        else:
            stats = {
                'phase': phase_name,
                'rate': rate,
                'video_count': int(100 * rate),
                'collection_window': '30s-90s',
                'error': 'No metrics collected in 30s-90s window'
            }
        
        print(f"Collected {len(throughput_samples)} samples during 30s-90s window")
        return stats

    def stop_client_process(self, phase_name):
        """Stop the client process"""
        if self.current_client_process:
            # Terminate the process
            self.current_client_process.terminate()
            try:
                self.current_client_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.current_client_process.kill()
            
            self.current_client_process = None

    def parse_metrics_line(self, line):
        """Parse the metrics output line from videoperf"""
        if 'Throughput' not in line:
            return None
            
        try:
            # Sample line: "Throughput (Mbps) = 465.59  , total-errors = 0       , concurrent-clients = 161     , reply-rate = 17.6"
            parts = line.strip().split(',')
            
            throughput = float(parts[0].split('=')[1].strip())
            total_errors = int(parts[1].split('=')[1].strip())
            concurrent_clients = int(parts[2].split('=')[1].strip())
            reply_rate = float(parts[3].split('=')[1].strip())
            
            return {
                'throughput': throughput,
                'total_errors': total_errors,
                'concurrent_clients': concurrent_clients,
                'reply_rate': reply_rate
            }
        except (ValueError, IndexError) as e:
            print(f"Error parsing metrics line: {line}, Error: {e}")
            return None

    def percentile(self, data, percentile):
        """Calculate percentile from data list"""
        if not data:
            return 0
        sorted_data = sorted(data)
        index = (len(sorted_data) - 1) * percentile / 100
        lower_index = int(index)
        upper_index = lower_index + 1
        
        if upper_index >= len(sorted_data):
            return sorted_data[lower_index]
        
        weight = index - lower_index
        return sorted_data[lower_index] * (1 - weight) + sorted_data[upper_index] * weight

    def run_gradual_load_test(self):
        """Run the gradual load test with increasing rates and auto-scaled video counts"""
        print("Starting gradual load test (30s-90s collection window)...")
        print("Video count will be auto-scaled as 100 * rate")
        
        rates = self.generate_rates()
        
        for i, rate in enumerate(rates):
            phase_name = f"phase_{i+1}_rate_{rate}"
            
            try:
                metrics = self.run_benchmark_phase(rate, phase_name)
                self.results.append(metrics)
                
                # Save intermediate results
                self.save_results()
                
                # Check if we should stop (too many errors)
                if metrics.get('total_errors_avg', 0) > self.config['max_errors']:
                    print(f"Stopping test due to high error count: {metrics['total_errors_avg']}")
                    break
                    
                # Wait between phases
                print(f"Cooling down for {self.config['cooldown_duration']} seconds...")
                time.sleep(self.config['cooldown_duration'])
                
            except Exception as e:
                print(f"Error in phase {phase_name}: {e}")
                # Continue with next phase
                continue

    def generate_rates(self):
        """Generate rate progression for the test"""
        rates = []
        current_rate = self.config['initial_rate']
        
        while current_rate <= self.config['max_rate']:
            rates.append(current_rate)
            current_rate *= self.config['rate_multiplier']
            
        return [int(rate) for rate in rates]  # Ensure integer rates

    def save_results(self):
        """Save results to JSON and CSV files"""
        # Save as JSON
        json_file = os.path.join(self.config['output_dir'], 'benchmark_results_30s_90s.json')
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Save as CSV
        csv_file = os.path.join(self.config['output_dir'], 'benchmark_results_30s_90s.csv')
        if self.results:
            with open(csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                writer.writeheader()
                for row in self.results:
                    writer.writerow(row)
        
        print(f"Results saved to {json_file} and {csv_file}")

    def cleanup(self):
        """Clean up Docker containers"""
        print("Cleaning up containers...")
        
        # Stop any running client process
        if self.current_client_process:
            self.current_client_process.terminate()
            self.current_client_process = None
        
        commands = [
            "docker stop streaming_server 2>/dev/null || true",
            "docker rm streaming_server 2>/dev/null || true",
            "docker stop streaming_dataset 2>/dev/null || true",
            "docker rm streaming_dataset 2>/dev/null || true"
        ]
        
        for cmd in commands:
            self.run_command(cmd, check=False)

    def analyze_results(self):
        """Analyze and print benchmark results"""
        print("\n" + "="*60)
        print("BENCHMARK RESULTS ANALYSIS (30s-90s Collection Window)")
        print("="*60)
        print("Video count auto-scaled as 100 * rate")
        
        for result in self.results:
            print(f"\nPhase: {result['phase']}")
            print(f"  Rate: {result['rate']} videos/sec")
            print(f"  Video Count: {result.get('video_count', 'N/A')}")
            print(f"  Throughput - P99: {result.get('throughput_p99', 0):.2f} Mbps")
            print(f"  Throughput - Avg: {result.get('throughput_avg', 0):.2f} Mbps")
            print(f"  Sample Count: {result.get('sample_count', 0)}")
            print(f"  Concurrent Clients - Avg: {result.get('concurrent_clients_avg', 0):.1f}")
            print(f"  Reply Rate - Avg: {result.get('reply_rate_avg', 0):.1f} req/sec")
            print(f"  Total Errors - Avg: {result.get('total_errors_avg', 0):.1f}")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print('\n\nReceived interrupt signal. Cleaning up...')
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(description='Media Streaming Benchmark - Modified Launch Pattern')
    parser.add_argument('--output-dir', default='./benchmark_results_30s_90s', help='Output directory for results')
    parser.add_argument('--max-rate', type=int, default=3000, help='Maximum request rate to test')
    parser.add_argument('--initial-rate', type=int, default=10, help='Initial request rate')
    parser.add_argument('--rate-multiplier', type=float, default=10, help='Multiplier for rate increase')
    parser.add_argument('--cpuset-cpus', default='0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38', 
                       help='CPU cores to pin for server and client')
    
    args = parser.parse_args()
    
    # Configuration
    config = {
        'output_dir': args.output_dir,
        'session_lists_dir': './session_lists',
        
        # CPU pinning configuration
        'cpuset_cpus': args.cpuset_cpus,
        
        # Benchmark parameters
        'videoperf_processes': 20,
        'encryption_mode': 'PT',  # Plain text
        
        # Load test parameters
        'initial_rate': args.initial_rate,
        'max_rate': args.max_rate,
        'rate_multiplier': args.rate_multiplier,
        'cooldown_duration': 15,  # seconds between phases
        'max_errors': 10
    }
    
    benchmark = MediaStreamingBenchmark(config)
    
    try:
        # Setup following your exact steps
        print("The launch pattern:")
        print("1. docker run --name streaming_dataset cloudsuite/media-streaming:dataset")
        print("2. docker run --cpuset-cpus=<cpus> -d --name streaming_server --volumes-from streaming_dataset --net host cloudsuite/media-streaming:server")
        print("3. docker cp streaming_dataset:/videos/logs/. ./session_lists/")
        print("4. docker run --rm --cpuset-cpus=<cpus> -t -v session_lists:/videos/logs -v results:/output --net host cloudsuite/media-streaming:client localhost 20 <video_count> <rate> PT")
        print("   where video_count = 100 * rate")
        print("="*80)
        
        # Combined setup that handles the blocking dataset generation properly
        benchmark.setup_dataset_and_server()  # Steps 1, 2, 3 in correct order
        
        # Run benchmark (Step 4 with auto-scaled video count)
        benchmark.run_gradual_load_test()
        
        # Analyze results
        benchmark.analyze_results()
        
    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user")
    except Exception as e:
        print(f"Benchmark failed with error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        benchmark.cleanup()

if __name__ == "__main__":
    main()