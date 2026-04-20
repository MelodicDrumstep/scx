// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use libbpf_sys;
use std::ffi::CString;
use std::fs;
use std::os::unix::io::RawFd;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::thread;

const TASK_TYPE_RING_SIZE: usize = 1024;
const TASK_TYPE_LC: u8 = 0;
const TASK_TYPE_BE: u8 = 1;

/// Guard to ensure map FD is closed
struct MapFdGuard(RawFd);

impl Drop for MapFdGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Find a BPF map by name, searching common locations
/// Returns the file descriptor of the opened map
fn find_bpf_map_fd(map_name: &str) -> Result<RawFd> {
    // Try common pinned paths
    let common_paths = [
        format!("/sys/fs/bpf/{}", map_name),
        format!("/sys/fs/bpf/scx_rusty/{}", map_name),
        format!("/sys/fs/bpf/rusty/{}", map_name),
    ];

    for path in &common_paths {
        if let Ok(fd) = open_map_fd_by_path(path) {
            return Ok(fd);
        }
    }

    // Try to find the map by iterating through /sys/fs/bpf
    if let Ok(entries) = fs::read_dir("/sys/fs/bpf") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let map_path = path.join(map_name);
                if map_path.exists() {
                    if let Ok(fd) = open_map_fd_by_path(&map_path.to_string_lossy()) {
                        return Ok(fd);
                    }
                }
            } else if path.file_name().and_then(|n| n.to_str()) == Some(map_name) {
                if let Ok(fd) = open_map_fd_by_path(&path.to_string_lossy()) {
                    return Ok(fd);
                }
            }
        }
    }

    // Last resort: try to find by map ID using bpftool
    // This requires bpftool to be installed
    if let Ok(output) = Command::new("bpftool")
        .args(["map", "list"])
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains(map_name) {
                // Try to extract map ID (first number in the line)
                if let Some(id_str) = line.split_whitespace().next() {
                    if let Ok(map_id) = id_str.parse::<u32>() {
                        // Open map by ID: /sys/fs/bpf/map_id/{id}
                        let map_path = format!("/sys/fs/bpf/map_id/{}", map_id);
                        if let Ok(fd) = open_map_fd_by_path(&map_path) {
                            return Ok(fd);
                        }
                    }
                }
            }
        }
    }

    Err(anyhow!(
        "Could not find BPF map '{}'. Make sure the scheduler is running and the map is pinned.",
        map_name
    ))
}

/// Open a BPF map by path and return its file descriptor
fn open_map_fd_by_path(path: &str) -> Result<RawFd> {
    let path_cstr = CString::new(path)
        .context("Invalid path")?;
    
    // Use bpf_obj_get to get the map FD from the pinned path
    let fd = unsafe { libbpf_sys::bpf_obj_get(path_cstr.as_ptr() as *const libc::c_char) };
    if fd < 0 {
        return Err(anyhow!("Failed to open BPF map at {}: {}", path, std::io::Error::last_os_error()));
    }

    Ok(fd)
}

/// Test client for LC/BE task type support
///
/// This client launches one LC parent thread and one BE parent thread.
/// Each parent thread spawns child threads periodically, and we write
/// the parent thread PID (tgid) -> task type mappings into the ring buffer.
/// Child threads inherit the type from their parent's tgid.
#[derive(Debug, Parser)]
struct Opts {
    /// Path to the shared memory file (for compatibility, not used for ring buffer)
    #[clap(long)]
    task_type_shm: String,

    /// Number of LC threads to spawn every 10s
    #[clap(long, default_value = "1")]
    num_lc_threads: usize,

    /// Number of BE threads to spawn every 10s
    #[clap(long, default_value = "1")]
    num_be_threads: usize,
}

/// CPU cores to pin threads to: 0, 4, 8, 12, 16, 20, 24, 28, 32, 36
const CORES: [usize; 10] = [0, 4, 8, 12, 16, 20, 24, 28, 32, 36];

/// Write a task type update to the ring buffer
fn write_task_type_update(
    map_fd: RawFd,
    pid: u32,
    task_type: u8,
) -> Result<bool> {
    const RING_KEY: u32 = 0;

    let key = RING_KEY.to_ne_bytes();
    let mut value = vec![0u8; 12 + (TASK_TYPE_RING_SIZE * 8)];

    // Lookup the ring buffer using bpf_map_lookup_elem
    let ret = unsafe {
        libbpf_sys::bpf_map_lookup_elem(
            map_fd,
            key.as_ptr() as *const libc::c_void,
            value.as_mut_ptr() as *mut libc::c_void,
        )
    };
    
    if ret != 0 {
        return Err(anyhow!(
            "Failed to lookup task type ring buffer: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Parse the ring buffer structure
    // Layout: lock (4 bytes), producer (4 bytes), consumer (4 bytes), entries (array)
    if value.len() < 12 {
        return Err(anyhow!("Ring buffer structure too small"));
    }

    // Read current producer and consumer indices
    let producer = u32::from_ne_bytes([
        value[4],
        value[5],
        value[6],
        value[7],
    ]);
    let consumer = u32::from_ne_bytes([
        value[8],
        value[9],
        value[10],
        value[11],
    ]);

    // Check if ring buffer is full
    if producer.wrapping_sub(consumer) >= TASK_TYPE_RING_SIZE as u32 {
        return Ok(false); // Ring buffer is full
    }

    // Calculate the index for the new entry
    // Each entry is 8 bytes due to C struct padding: u32 pid (4) + u8 task_type (1) + 3 padding = 8
    let idx = producer % TASK_TYPE_RING_SIZE as u32;
    let entry_offset = 12 + (idx as usize * 8);

    if entry_offset + 8 > value.len() {
        return Err(anyhow!("Ring buffer entry out of bounds"));
    }

    // Prepare the update: we need to update producer index and the entry
    // Note: The ring buffer has a lock field, but for simplicity in this test client,
    // we're not using it. The BPF side uses proper locking when consuming entries.
    // For a production client, you might want to implement proper locking.

    // Write the entry (pid as u32, task_type as u8, padding zeros)
    let pid_bytes = pid.to_ne_bytes();
    value[entry_offset..entry_offset + 4].copy_from_slice(&pid_bytes);
    value[entry_offset + 4] = task_type;
    // Clear padding bytes (offset +5, +6, +7)
    value[entry_offset + 5] = 0;
    value[entry_offset + 6] = 0;
    value[entry_offset + 7] = 0;

    // Update producer index
    let new_producer = producer.wrapping_add(1);
    let producer_bytes = new_producer.to_ne_bytes();
    value[4..8].copy_from_slice(&producer_bytes);

    // Write back to the map using bpf_map_update_elem
    let ret = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map_fd,
            key.as_ptr() as *const libc::c_void,
            value.as_ptr() as *const libc::c_void,
            0, // BPF_ANY
        )
    };

    if ret != 0 {
        return Err(anyhow!(
            "Failed to update task type ring buffer: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(true)
}

/// Get the current process PID (which is the tgid for the main thread)
fn get_current_pid() -> u32 {
    unsafe { libc::getpid() as u32 }
}

/// Get child process PIDs of a given parent PID
// And also consider child threads
fn get_child_pids(parent_pid: u32) -> Result<Vec<u32>> {
    let mut child_pids = Vec::new();
    
    // Use pgrep -P to get direct children
    let output = Command::new("pgrep")
        .arg("-P")
        .arg(parent_pid.to_string())
        .output()
        .context("Failed to run pgrep")?;
    
    if !output.status.success() {
        // pgrep returns non-zero if no processes found, which is fine
        return Ok(child_pids);
    }
    
    let output_str = String::from_utf8(output.stdout)
        .context("Failed to parse pgrep output")?;
    
    for pid_str in output_str.lines() {
        if pid_str.is_empty() {
            continue;
        }
        if let Ok(pid) = pid_str.parse::<u32>() {
            child_pids.push(pid);
        }
    }

    // Get child threads, using ps -T -p <parent_pid>
    let threads = Command::new("ps")
        .arg("-T")
        .arg("-p")
        .arg(parent_pid.to_string())
        .output()
        .context("Failed to run ps")?;
    let threads_str = String::from_utf8(threads.stdout)
        .context("Failed to parse ps output")?;
    
    for line in threads_str.lines() {
        if line.is_empty() {
            continue;
        }
        let parts = line.split_whitespace().collect::<Vec<&str>>();
        if parts.len() != 2 {
            continue;
        }
        if let Ok(thread_pid) = parts[0].parse::<u32>() {
            child_pids.push(thread_pid);
        }
    }

    Ok(child_pids)
}

/// Recursively write all child processes of a parent to the ring buffer
fn recursively_write_children_to_ring_buffer(
    map_fd: RawFd,
    parent_pid: u32,
    task_type: u8,
    max_depth: usize,
    current_depth: usize,
) -> Result<usize> {
    if current_depth >= max_depth {
        return Ok(0);
    }
    
    let child_pids = get_child_pids(parent_pid)?;
    let mut written_count = 0;
    
    for child_pid in child_pids {
        // DEBUGING
        println!("  DEBUG: Writing child PID {} -> {} (depth {})", 
                 child_pid,
                 if task_type == TASK_TYPE_LC { "LC" } else { "BE" },
                 current_depth + 1);

        // Write this child PID to the ring buffer
        match write_task_type_update(map_fd, child_pid, task_type) {
            Ok(true) => {
                written_count += 1;
                if current_depth == 0 {
                    println!("  Written: Child PID {} -> {} (depth {})", 
                             child_pid,
                             if task_type == TASK_TYPE_LC { "LC" } else { "BE" },
                             current_depth + 1);
                }
            }
            Ok(false) => {
                eprintln!("  Warning: Ring buffer full, could not write child PID {} -> {}", 
                          child_pid, 
                          if task_type == TASK_TYPE_LC { "LC" } else { "BE" });
            }
            Err(e) => {
                eprintln!("  Error writing child PID {} -> {}: {}", 
                          child_pid,
                          if task_type == TASK_TYPE_LC { "LC" } else { "BE" },
                          e);
            }
        }
        
        // Recursively write grandchildren
        let grandchildren_written = recursively_write_children_to_ring_buffer(
            map_fd,
            child_pid,
            task_type,
            max_depth,
            current_depth + 1,
        )?;
        written_count += grandchildren_written;
    }
    
    Ok(written_count)
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    println!("Test Task Types Client");
    println!("  LC threads per batch: {}", opts.num_lc_threads);
    println!("  BE threads per batch: {}", opts.num_be_threads);
    println!("  Spawn interval: 60 seconds");
    println!("  Thread duration: 50-60 seconds (random)");
    println!("  Task type shm path: {}", opts.task_type_shm);

    // Convert the path to BPF filesystem path if needed
    // BPF maps must be pinned under /sys/fs/bpf/
    let bpf_path = if opts.task_type_shm.starts_with("/sys/fs/bpf/") {
        opts.task_type_shm.clone()
    } else {
        // Extract just the filename and put it under /sys/fs/bpf/
        let filename = std::path::Path::new(&opts.task_type_shm)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("scx_rusty_task_types");
        format!("/sys/fs/bpf/{}", filename)
    };

    println!("  Using BPF map path: {}", bpf_path);

    // Open the BPF map from the BPF filesystem path
    let map_fd = open_map_fd_by_path(&bpf_path)
        .context("Failed to open task_type_ring_buffer map. Make sure the scheduler is running and the map is pinned.")?;

    println!("Successfully opened task_type_ring_buffer map");

    // Ensure the FD is closed when we're done
    let _map_guard = MapFdGuard(map_fd);

    // Get the current process PID (this is the tgid for all threads in this process)
    let main_pid = get_current_pid();
    println!("\nMain process PID (tgid): {}", main_pid);

    // We need to create separate processes for LC and BE parent threads
    // because they need different tgids. Let's use a different approach:
    // Launch two separate processes, each with their own main thread that acts as parent
    
    // Launch LC parent process
    let lc_script = format!(r#"
        #!/bin/bash
        # LC parent process - spawns {} LC threads every 0s
        CORES=(0 4 8 12 16 20 24 28 32 36)
        COUNTER=0
        while true; do
            # Spawn {} child threads
            for i in $(seq 1 {}); do
                (
                    # Random duration 6-10 seconds
                    DUR=$((6 + RANDOM % 4))
                    # Pin to one of the 10 cores: 0, 4, 8, 12, 16, 20, 24, 28, 32, 36
                    CPU_IDX=$(( (COUNTER * {} + i - 1) % 10 ))
                    case $CPU_IDX in
                        0) CPU_ID=0 ;;
                        1) CPU_ID=4 ;;
                        2) CPU_ID=8 ;;
                        3) CPU_ID=12 ;;
                        4) CPU_ID=16 ;;
                        5) CPU_ID=20 ;;
                        6) CPU_ID=24 ;;
                        7) CPU_ID=28 ;;
                        8) CPU_ID=32 ;;
                        9) CPU_ID=36 ;;
                        *) CPU_ID=0 ;;
                    esac
                    taskset -c $CPU_ID timeout $DUR sh -c 'j=0; while true; do j=$((j+1)); done' 2>/dev/null || true
                ) &
            done
            COUNTER=$((COUNTER + 1))
            echo "LC parent spawned {} threads (batch $COUNTER)"
            sleep 5
        done
    "#, opts.num_lc_threads, opts.num_lc_threads, opts.num_lc_threads, opts.num_lc_threads, opts.num_lc_threads);
    
    let mut lc_child = Command::new("bash")
        .arg("-c")
        .arg(&lc_script)
        .spawn()
        .context("Failed to spawn LC parent process")?;
    let lc_pid = lc_child.id() as u32;
    thread::sleep(Duration::from_millis(100));

    // Launch BE parent process
    let be_script = format!(r#"
        #!/bin/bash
        # BE parent process - spawns {} BE threads every 10s
        COUNTER=0
        CORES=(0 4 8 12 16 20 24 28 32 36)
        while true; do
            # Spawn {} child threads
            for i in $(seq 1 {}); do
                (
                    # Random duration 6-10 seconds
                    DUR=$((6 + RANDOM % 4))
                    # Pin to one of the 10 cores: 0, 4, 8, 12, 16, 20, 24, 28, 32, 36
                    CPU_IDX=$(( (COUNTER * {} + i - 1) % 10 ))
                    case $CPU_IDX in
                        0) CPU_ID=0 ;;
                        1) CPU_ID=4 ;;
                        2) CPU_ID=8 ;;
                        3) CPU_ID=12 ;;
                        4) CPU_ID=16 ;;
                        5) CPU_ID=20 ;;
                        6) CPU_ID=24 ;;
                        7) CPU_ID=28 ;;
                        8) CPU_ID=32 ;;
                        9) CPU_ID=36 ;;
                        *) CPU_ID=0 ;;
                    esac
                    taskset -c $CPU_ID timeout $DUR sh -c 'j=0; while true; do j=$((j+2)); done' 2>/dev/null || true
                ) &
            done
            COUNTER=$((COUNTER + 1))
            echo "BE parent spawned {} threads (batch $COUNTER)"
            sleep 5
        done
    "#, opts.num_be_threads, opts.num_be_threads, opts.num_be_threads, opts.num_be_threads, opts.num_be_threads);
    
    let mut be_child = Command::new("bash")
        .arg("-c")
        .arg(&be_script)
        .spawn()
        .context("Failed to spawn BE parent process")?;
    let be_pid = be_child.id() as u32;
    thread::sleep(Duration::from_millis(100));

    // Write parent process PIDs (tgid) to the ring buffer
    println!("\nWriting parent process PIDs (tgid) to ring buffer...");
    
    match write_task_type_update(map_fd, lc_pid, TASK_TYPE_LC) {
        Ok(true) => println!("  Written: LC parent PID (tgid) {} -> LC", lc_pid),
        Ok(false) => eprintln!("  Warning: Ring buffer full, could not write LC parent PID {} -> LC", lc_pid),
        Err(e) => eprintln!("  Error writing LC parent PID {} -> LC: {}", lc_pid, e),
    }

    match write_task_type_update(map_fd, be_pid, TASK_TYPE_BE) {
        Ok(true) => println!("  Written: BE parent PID (tgid) {} -> BE", be_pid),
        Ok(false) => eprintln!("  Warning: Ring buffer full, could not write BE parent PID {} -> BE", be_pid),
        Err(e) => eprintln!("  Error writing BE parent PID {} -> BE: {}", be_pid, e),
    }

    // Now we recursively write the sub processes of the parent processes into the ring buffer
    println!("\nRecursively writing child processes to ring buffer...");
    
    // Wait a bit for processes to spawn
    thread::sleep(Duration::from_millis(500));
    
    // Recursively write LC child processes (max depth 3 to avoid too many processes)
    let lc_children_written = recursively_write_children_to_ring_buffer(
        map_fd,
        lc_pid,
        TASK_TYPE_LC,
        3, // max_depth
        0, // current_depth
    ).unwrap_or(0);
    
    // Recursively write BE child processes (max depth 3)
    let be_children_written = recursively_write_children_to_ring_buffer(
        map_fd,
        be_pid,
        TASK_TYPE_BE,
        3, // max_depth
        0, // current_depth
    ).unwrap_or(0);
    
    println!("  Written {} LC child processes", lc_children_written);
    println!("  Written {} BE child processes", be_children_written);

    println!("\nParent process PIDs written. Child processes are being tracked recursively.");
    println!("LC parent (PID {}) spawns {} threads every 60s", lc_pid, opts.num_lc_threads);
    println!("BE parent (PID {}) spawns {} threads every 60s", be_pid, opts.num_be_threads);
    println!("Threads run for 50-60 seconds and are pinned to CPUs: {:?}", CORES);
    println!("Press Ctrl+C to stop.");

    // Wait for Ctrl+C
    let shutdown = Arc::new(AtomicBool::new(false));
    
    // // Set up a periodic task to update child processes (they spawn every 10s)
    // let map_fd_clone = map_fd;
    // let lc_pid_clone = lc_pid;
    // let be_pid_clone = be_pid;
    // let shutdown_clone = shutdown.clone();
    
    // thread::spawn(move || {
    //     while !shutdown_clone.load(Ordering::Relaxed) {
    //         thread::sleep(Duration::from_secs(5)); // Check every 5 seconds
            
    //         // Periodically update child processes
    //         let _ = recursively_write_children_to_ring_buffer(
    //             map_fd_clone,
    //             lc_pid_clone,
    //             TASK_TYPE_LC,
    //             3,
    //             0,
    //         );
    //         let _ = recursively_write_children_to_ring_buffer(
    //             map_fd_clone,
    //             be_pid_clone,
    //             TASK_TYPE_BE,
    //             3,
    //             0,
    //         );
    //     }
    // });
    // let shutdown_clone = shutdown.clone();
    // ctrlc::set_handler(move || {
    //     shutdown_clone.store(true, Ordering::Relaxed);
    // })
    // .context("Error setting Ctrl-C handler")?;

    // Keep running until interrupted
    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(1));
        
        // Check if parent processes have died
        if let Ok(Some(_)) = lc_child.try_wait() {
            println!("LC parent process with PID {} has exited", lc_pid);
            break;
        }
        if let Ok(Some(_)) = be_child.try_wait() {
            println!("BE parent process with PID {} has exited", be_pid);
            break;
        }
    }

    println!("\nShutting down...");

    // Kill parent processes (this will also kill their child threads)
    let _ = lc_child.kill();
    let _ = lc_child.wait();
    let _ = be_child.kill();
    let _ = be_child.wait();

    println!("Done.");
    Ok(())
}

