#!/usr/bin/env python3
"""
Media Streaming Benchmark Script - Simplified Launch Pattern
Runs dataset and server once, then runs client with different parameters each time
"""

import subprocess
import time
import json
import csv
import os
import sys
import argparse
import shutil
from datetime import datetime
from pathlib import Path
import signal

class MediaStreamingBenchmark:
    def __init__(self, config):
        self.config = config
        self.results = []
        self.setup_completed = False
        
        # Create session_lists directory
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

    def setup_dataset_and_server_once(self):
        """Setup dataset and server only once (blocking)"""
        if self.setup_completed:
            print("Setup already completed, skipping...")
            return
            
        print("="*80)
        print("SETUP PHASE (One-time, blocking operations)")
        print("="*80)
        
        # Step 1: Run dataset container (blocking)
        print("\nStep 1: Running dataset container (this will block until complete)...")
        self.run_command("docker rm -f streaming_dataset 2>/dev/null || true", check=False)
        cmd = "docker run --name streaming_dataset cloudsuite/media-streaming:dataset"
        print(f"Running: {cmd}")
        self.run_command(cmd)
        print("✓ Dataset generation completed")
        
        # Step 2: Start the server with CPU pinning
        print("\nStep 2: Starting media streaming server...")
        self.run_command("docker rm -f streaming_server 2>/dev/null || true", check=False)
        cpuset_cpus = self.config['cpuset_cpus']
        cmd = (
            f"docker run --cpuset-cpus={cpuset_cpus} "
            f"-d --name streaming_server --volumes-from streaming_dataset --net host "
            f"cloudsuite/media-streaming:server 20"  # 20 Nginx workers
        )
        print(f"Running: {cmd}")
        self.run_command(cmd)
        print("✓ Server started")
        
        # Step 3: Copy session lists
        print("\nStep 3: Copying session lists...")
        # Clean session_lists directory
        shutil.rmtree(self.config['session_lists_dir'], ignore_errors=True)
        Path(self.config['session_lists_dir']).mkdir(parents=True, exist_ok=True)
        
        cmd = f"docker cp streaming_dataset:/videos/logs/. {self.config['session_lists_dir']}/"
        print(f"Running: {cmd}")
        self.run_command(cmd)
        print("✓ Session lists copied")
        
        # Wait for server to start
        print("Waiting for server to be ready...")
        time.sleep(10)
        
        self.setup_completed = True
        print("\n✓ Setup completed successfully!")

    def run_single_client_test(self, video_num, rate, test_name):
        """Run a single client test with given parameters"""
        print(f"\n" + "="*80)
        print(f"CLIENT TEST: {test_name}")
        print(f"Parameters: VideoNum={video_num}, Rate={rate}")
        print("="*80)
        
        # Clean results directory
        results_dir = self.config['results_dir']
        shutil.rmtree(results_dir, ignore_errors=True)
        Path(results_dir).mkdir(parents=True, exist_ok=True)
        
        # Build client command
        cpuset_cpus = self.config['cpuset_cpus']
        client_cmd = (
            f"docker run --rm --cpuset-cpus={cpuset_cpus} "
            f"-t -v {self.config['session_lists_dir']}:/videos/logs "
            f"-v {results_dir}:/output --net host "
            f"cloudsuite/media-streaming:client localhost "
            f"{self.config['videoperf_processes']} {video_num} {rate}"
        )
        
        print(f"Running client: {client_cmd}")
        
        # Start client process and capture output
        start_time = time.time()
        process = subprocess.Popen(client_cmd, shell=True, stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE, text=True, bufsize=1)
        
        # Collect output in real-time
        throughput_samples = []
        error_samples = []
        client_samples = []
        reply_rate_samples = []
        all_output = []
        
        print("\n--- Client Output ---")
        try:
            while True:
                # Read stdout line
                stdout_line = process.stdout.readline()
                if stdout_line:
                    print(stdout_line.strip())
                    all_output.append(stdout_line)
                    
                    # Parse metrics if available
                    metrics = self.parse_metrics_line(stdout_line)
                    if metrics:
                        throughput_samples.append(metrics['throughput'])
                        error_samples.append(metrics['total_errors'])
                        client_samples.append(metrics['concurrent_clients'])
                        reply_rate_samples.append(metrics['reply_rate'])
                
                # Check if process has finished
                if process.poll() is not None:
                    # Read any remaining output
                    remaining_stdout, stderr = process.communicate()
                    if remaining_stdout:
                        print(remaining_stdout.strip())
                        all_output.append(remaining_stdout)
                    if stderr:
                        print(f"STDERR: {stderr.strip()}")
                    break
                    
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print("\nClient test interrupted by user")
            process.terminate()
            process.wait()
        
        # Calculate statistics
        execution_time = time.time() - start_time
        
        stats = {
            'test_name': test_name,
            'video_num': video_num,
            'rate': rate,
            'execution_time_seconds': round(execution_time, 2),
            'sample_count': len(throughput_samples),
            'throughput_avg': sum(throughput_samples) / len(throughput_samples) if throughput_samples else 0,
            'throughput_max': max(throughput_samples) if throughput_samples else 0,
            'throughput_min': min(throughput_samples) if throughput_samples else 0,
            'total_errors_avg': sum(error_samples) / len(error_samples) if error_samples else 0,
            'total_errors_max': max(error_samples) if error_samples else 0,
            'concurrent_clients_avg': sum(client_samples) / len(client_samples) if client_samples else 0,
            'reply_rate_avg': sum(reply_rate_samples) / len(reply_rate_samples) if reply_rate_samples else 0,
            'timestamp': datetime.now().isoformat()
        }
        
        # Clean results directory after command finishes
        print("\nCleaning results directory...")
        shutil.rmtree(results_dir, ignore_errors=True)
        
        return stats, all_output

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
            return None

    def save_results(self, output_dir):
        """Save results to JSON and CSV files"""
        if not self.results:
            print("No results to save")
            return
            
        # Save as JSON
        json_file = os.path.join(output_dir, 'benchmark_results.json')
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Save as CSV
        csv_file = os.path.join(output_dir, 'benchmark_results.csv')
        if self.results:
            with open(csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                writer.writeheader()
                for row in self.results:
                    writer.writerow(row)
        
        print(f"Results saved to {json_file} and {csv_file}")

    def run_parameter_sweep(self, test_cases):
        """Run multiple test cases with different parameters"""
        print("\n" + "="*80)
        print("PARAMETER SWEEP TESTING")
        print("="*80)
        
        for i, test_case in enumerate(test_cases):
            video_num = test_case['video_num']
            rate = test_case['rate']
            test_name = test_case.get('name', f'test_{i+1}')
            
            print(f"\n\nTest {i+1}/{len(test_cases)}: {test_name}")
            
            stats, output = self.run_single_client_test(video_num, rate, test_name)
            self.results.append(stats)
            
            # Save output to file
            output_dir = self.config['output_dir']
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            output_file = os.path.join(output_dir, f'{test_name}_output.txt')
            with open(output_file, 'w') as f:
                f.writelines(output)
            
            # Print summary
            print(f"\n✓ Test {test_name} completed")
            print(f"  Throughput avg: {stats['throughput_avg']:.2f} Mbps")
            print(f"  Errors avg: {stats['total_errors_avg']:.2f}")
            print(f"  Execution time: {stats['execution_time_seconds']:.2f}s")
            
            # Wait between tests
            if i < len(test_cases) - 1:
                wait_time = self.config.get('cooldown_duration', 10)
                print(f"\nWaiting {wait_time} seconds before next test...")
                time.sleep(wait_time)

    def cleanup(self):
        """Clean up Docker containers"""
        print("\nCleaning up containers...")
        
        commands = [
            "docker stop streaming_server 2>/dev/null || true",
            "docker rm streaming_server 2>/dev/null || true",
            "docker stop streaming_dataset 2>/dev/null || true",
            "docker rm streaming_dataset 2>/dev/null || true"
        ]
        
        for cmd in commands:
            self.run_command(cmd, check=False)

    def print_summary(self):
        """Print summary of all tests"""
        print("\n" + "="*80)
        print("BENCHMARK SUMMARY")
        print("="*80)
        
        for result in self.results:
            print(f"\nTest: {result['test_name']}")
            print(f"  Parameters: VideoNum={result['video_num']}, Rate={result['rate']}")
            print(f"  Throughput: {result['throughput_avg']:.2f} Mbps (avg)")
            print(f"  Max Throughput: {result['throughput_max']:.2f} Mbps")
            print(f"  Errors: {result['total_errors_avg']:.2f} (avg)")
            print(f"  Concurrent Clients: {result['concurrent_clients_avg']:.1f} (avg)")
            print(f"  Reply Rate: {result['reply_rate_avg']:.1f} req/sec (avg)")
            print(f"  Execution Time: {result['execution_time_seconds']}s")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print('\n\nReceived interrupt signal. Cleaning up...')
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(description='Media Streaming Benchmark - Simple Client Tests')
    parser.add_argument('--output-dir', default='./benchmark_output', 
                       help='Output directory for results')
    parser.add_argument('--session-lists-dir', default='./session_lists',
                       help='Directory for session lists')
    parser.add_argument('--results-dir', default='./results',
                       help='Temporary results directory (cleaned after each test)')
    parser.add_argument('--cpuset-cpus', default='0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38', 
                       help='CPU cores to pin for server and client')
    
    # Test case parameters
    parser.add_argument('--test-cases', type=str, default='100:5,200:10,500:20,1000:50',
                       help='Test cases in format "video_num1:rate1,video_num2:rate2,..."')
    parser.add_argument('--cooldown-duration', type=int, default=10,
                       help='Seconds to wait between tests')
    
    args = parser.parse_args()
    
    # Parse test cases
    test_cases = []
    if args.test_cases:
        for i, test_str in enumerate(args.test_cases.split(',')):
            if ':' in test_str:
                video_num_str, rate_str = test_str.split(':')
                test_cases.append({
                    'name': f'test_{i+1}',
                    'video_num': int(video_num_str),
                    'rate': int(rate_str)
                })
    
    # Default test cases if none provided
    if not test_cases:
        test_cases = [
            {'name': 'low_load', 'video_num': 100, 'rate': 5},
            {'name': 'medium_load', 'video_num': 500, 'rate': 20},
            {'name': 'high_load', 'video_num': 1000, 'rate': 50},
        ]
    
    # Configuration
    config = {
        'output_dir': args.output_dir,
        'session_lists_dir': args.session_lists_dir,
        'results_dir': args.results_dir,
        'cpuset_cpus': args.cpuset_cpus,
        'videoperf_processes': 20,
        'cooldown_duration': args.cooldown_duration,
    }
    
    benchmark = MediaStreamingBenchmark(config)
    
    try:
        # One-time setup
        benchmark.setup_dataset_and_server_once()
        
        # Run parameter sweep
        benchmark.run_parameter_sweep(test_cases)
        
        # Save results
        benchmark.save_results(args.output_dir)
        
        # Print summary
        benchmark.print_summary()
        
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