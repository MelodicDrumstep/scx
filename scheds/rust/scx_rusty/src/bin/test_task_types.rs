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
use std::process::{Child, Command};
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
/// This client launches LC and BE programs and writes their PID -> task type
/// mappings into the ring buffer for the scheduler to consume.
#[derive(Debug, Parser)]
struct Opts {
    /// Path to the shared memory file (for compatibility, not used for ring buffer)
    #[clap(long)]
    task_type_shm: String,

    /// Number of LC (Latency Critical) tasks to launch
    #[clap(long, default_value = "0")]
    num_lc: usize,

    /// Number of BE (Best Effort) tasks to launch
    #[clap(long, default_value = "0")]
    num_be: usize,
}

struct TaskInfo {
    child: Child,
    pid: u32,
    task_type: u8,
}

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

/// Launch a simple busy loop program
fn launch_busy_loop(task_id: usize, task_type: &str) -> Result<TaskInfo> {
    // Launch a simple busy loop program
    // We'll use a simple shell command that runs a busy loop
    let child = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "while true; do :; done"
        ))
        .spawn()
        .context("Failed to spawn busy loop process")?;

    let pid = child.id() as u32;
    
    // Give the process a moment to start
    thread::sleep(Duration::from_millis(10));

    let task_type_val = match task_type {
        "LC" => TASK_TYPE_LC,
        "BE" => TASK_TYPE_BE,
        _ => return Err(anyhow!("Invalid task type: {}", task_type)),
    };

    println!("Launched {} task #{} with PID {}", task_type, task_id, pid);

    Ok(TaskInfo {
        child,
        pid,
        task_type: task_type_val,
    })
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    println!("Test Task Types Client");
    println!("  LC tasks: {}", opts.num_lc);
    println!("  BE tasks: {}", opts.num_be);
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

    // Launch LC tasks
    let mut lc_tasks = Vec::new();
    for i in 0..opts.num_lc {
        let task_info = launch_busy_loop(i, "LC")?;
        lc_tasks.push(task_info);
    }

    // Launch BE tasks
    let mut be_tasks = Vec::new();
    for i in 0..opts.num_be {
        let task_info = launch_busy_loop(i, "BE")?;
        be_tasks.push(task_info);
    }

    // Write all task type mappings to the ring buffer
    println!("\nWriting task type mappings to ring buffer...");
    
    for task_info in lc_tasks.iter() {
        match write_task_type_update(map_fd, task_info.pid, task_info.task_type) {
            Ok(true) => println!("  Written: PID {} -> LC", task_info.pid),
            Ok(false) => eprintln!("  Warning: Ring buffer full, could not write PID {} -> LC", task_info.pid),
            Err(e) => eprintln!("  Error writing PID {} -> LC: {}", task_info.pid, e),
        }
    }

    for task_info in be_tasks.iter() {
        match write_task_type_update(map_fd, task_info.pid, task_info.task_type) {
            Ok(true) => println!("  Written: PID {} -> BE", task_info.pid),
            Ok(false) => eprintln!("  Warning: Ring buffer full, could not write PID {} -> BE", task_info.pid),
            Err(e) => eprintln!("  Error writing PID {} -> BE: {}", task_info.pid, e),
        }
    }

    println!("\nAll task type mappings written. Tasks are running...");
    println!("Press Ctrl+C to stop.");

    // Wait for Ctrl+C
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    // Keep running until interrupted
    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(1));
        
        // Check if any processes have died
        for task_info in lc_tasks.iter_mut() {
            if let Ok(Some(_)) = task_info.child.try_wait() {
                println!("LC task with PID {} has exited", task_info.pid);
            }
        }
        for task_info in be_tasks.iter_mut() {
            if let Ok(Some(_)) = task_info.child.try_wait() {
                println!("BE task with PID {} has exited", task_info.pid);
            }
        }
    }

    println!("\nShutting down...");

    // Kill all child processes
    for mut task_info in lc_tasks {
        let _ = task_info.child.kill();
        let _ = task_info.child.wait();
    }
    for mut task_info in be_tasks {
        let _ = task_info.child.kill();
        let _ = task_info.child.wait();
    }

    println!("Done.");
    Ok(())
}

