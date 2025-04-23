use anyhow::Result;
use env_logger;
use libbpf_rs::RingBufferBuilder;
use serde::Serialize;
use std::{ptr, time::{SystemTime, UNIX_EPOCH}};

include!(concat!(env!("OUT_DIR"), "/exec_monitor.skel.rs"));

#[repr(C)]
struct RawEvent {
    pid: u32,
    comm: [u8; 16],
    filename: [u8; 256],
}

#[derive(Serialize)]
struct Event {
    pid: u32,
    comm: String,
    filename: String,
    timestamp: u64,
}

fn main() -> Result<()> {
    env_logger::init();

    // Load and attach BPF skeleton
    let mut skel_builder = ExecMonitorSkelBuilder::default();
    let mut skel = skel_builder.open()?;
    skel.load()?;
    skel.attach()?;

    // Set up ring buffer to receive events
    let mut ringbuf = RingBufferBuilder::new()
        .add(skel.maps().events(), handle_event)
        .build()?;

    println!("Listening for execve events...");

    // Poll for events indefinitely
    loop {
        ringbuf.poll(std::u32::MAX)?;
    }
}

fn handle_event(_cpu: i32, data: &[u8]) -> i32 {
    // Parse raw bytes into our event struct
    let raw = unsafe { ptr::read_unaligned(data.as_ptr() as *const RawEvent) };
    let ev = Event {
        pid: raw.pid,
        comm: String::from_utf8_lossy(&raw.comm)
            .trim_end_matches(char::from(0))
            .to_string(),
        filename: String::from_utf8_lossy(&raw.filename)
            .trim_end_matches(char::from(0))
            .to_string(),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    };
    println!("{}", serde_json::to_string(&ev).unwrap());
    0
}
