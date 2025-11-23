// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{anyhow, Context, Result};
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;

use crate::bpf_intf;
use crate::BpfSkel;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskType {
    Lc,
    Be,
}

impl TaskType {
    pub fn from_str(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "LC" => Some(Self::Lc),
            "BE" => Some(Self::Be),
            _ => None,
        }
    }

    pub fn as_raw(self) -> u8 {
        match self {
            TaskType::Lc => bpf_intf::task_type_TASK_TYPE_LC as u8,
            TaskType::Be => bpf_intf::task_type_TASK_TYPE_BE as u8,
        }
    }
}

/// Write a task type update to the ring buffer.
/// This allows applications to dynamically update task types.
/// Returns Ok(true) if the update was successfully queued, Ok(false) if the ring buffer is full.
pub fn write_task_type_update(
    skel: &mut BpfSkel,
    pid: u32,
    task_type: TaskType,
) -> Result<bool> {
    const RING_KEY: u32 = 0;
    const TASK_TYPE_RING_SIZE: usize = bpf_intf::consts_TASK_TYPE_RING_SIZE as usize;

    let ring_map = &skel.maps.task_type_ring_buffer;
    let key = RING_KEY.to_ne_bytes();

    // Lookup the ring buffer
    let ring_data = ring_map
        .lookup(&key, MapFlags::ANY)
        .context("Failed to lookup task type ring buffer")?
        .ok_or_else(|| anyhow!("Task type ring buffer not found"))?;

    // Parse the ring buffer structure
    // Layout: lock (4 bytes), producer (4 bytes), consumer (4 bytes), entries (array)
    let ring_bytes = ring_data.as_slice();
    if ring_bytes.len() < 12 {
        return Err(anyhow!("Ring buffer structure too small"));
    }

    // Read current producer and consumer indices
    let producer = u32::from_ne_bytes([
        ring_bytes[4],
        ring_bytes[5],
        ring_bytes[6],
        ring_bytes[7],
    ]);
    let consumer = u32::from_ne_bytes([
        ring_bytes[8],
        ring_bytes[9],
        ring_bytes[10],
        ring_bytes[11],
    ]);

    // Check if ring buffer is full
    if producer - consumer >= TASK_TYPE_RING_SIZE as u32 {
        return Ok(false); // Ring buffer is full
    }

    // Calculate the index for the new entry
    // Each entry is 8 bytes due to C struct padding: u32 pid (4) + u8 task_type (1) + 3 padding = 8
    let idx = producer % TASK_TYPE_RING_SIZE as u32;
    let entry_offset = 12 + (idx as usize * 8);

    if entry_offset + 8 > ring_bytes.len() {
        return Err(anyhow!("Ring buffer entry out of bounds"));
    }

    // Prepare the update: we need to update producer index and the entry
    // Note: In a real implementation with proper locking, we'd use atomic operations
    // For now, we'll write the entry and update producer
    let mut new_ring_bytes = ring_bytes.to_vec();

    // Write the entry (pid as u32, task_type as u8, padding zeros)
    let pid_bytes = pid.to_ne_bytes();
    new_ring_bytes[entry_offset..entry_offset + 4].copy_from_slice(&pid_bytes);
    new_ring_bytes[entry_offset + 4] = task_type.as_raw();
    // Clear padding bytes (offset +5, +6, +7)
    new_ring_bytes[entry_offset + 5] = 0;
    new_ring_bytes[entry_offset + 6] = 0;
    new_ring_bytes[entry_offset + 7] = 0;

    // Update producer index
    let new_producer = producer + 1;
    let producer_bytes = new_producer.to_ne_bytes();
    new_ring_bytes[4..8].copy_from_slice(&producer_bytes);

    // Write back to the map
    ring_map
        .update(&key, &new_ring_bytes, MapFlags::ANY)
        .context("Failed to update task type ring buffer")?;

    Ok(true)
}

/// Initialize the task type ring buffer.
/// This should be called once during scheduler initialization.
/// Note: The pin path should be set before loading the skeleton.
pub fn init_task_type_ring_buffer(skel: &mut BpfSkel) -> Result<()> {
    const RING_KEY: u32 = 0;
    const TASK_TYPE_RING_SIZE: usize = bpf_intf::consts_TASK_TYPE_RING_SIZE as usize;

    let ring_map = &skel.maps.task_type_ring_buffer;
    let key = RING_KEY.to_ne_bytes();

    // Initialize ring buffer: lock (4 bytes), producer (0), consumer (0), entries (all zeros)
    // Each entry is 8 bytes due to C struct padding: u32 pid (4) + u8 task_type (1) + 3 padding = 8
    // Total size: 4 (lock) + 4 (producer) + 4 (consumer) + (TASK_TYPE_RING_SIZE * 8) (entries)
    let ring_data = vec![0u8; 12 + (TASK_TYPE_RING_SIZE * 8)];

    // Producer and consumer are already 0, lock is already 0
    // Just write the initialized structure
    ring_map
        .update(&key, &ring_data, MapFlags::ANY)
        .context("Failed to initialize task type ring buffer")?;

    Ok(())
}

