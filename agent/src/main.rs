use anyhow::Result;
use env_logger;
use libbpf_rs::{RingBufferBuilder, skel::{OpenSkel, Skel, SkelBuilder}};
use log::{error, info};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

mod exec_monitor {
    include!(concat!(env!("OUT_DIR"), "/exec_monitor.skel.rs"));
}

#[derive(Copy, Clone)]
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

use exec_monitor::*;

fn main() -> Result<()> {
    env_logger::init();

    let skel_builder = ExecMonitorSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    info!("eBPF agent started successfully!");

    let maps = skel.maps(); 
    let mut builder = RingBufferBuilder::new();
    builder.add(maps.rb(), handle_event)?;
    let ringbuf = builder.build()?;

    loop {
        match ringbuf.poll(std::time::Duration::from_millis(100)) {
            Ok(_) => {}
            Err(e) => {
                error!("Error polling ring buffer: {}", e);
                break;
            }
        }
    }

    Ok(())
}

fn handle_event(data: &[u8]) -> i32 {
    if data.len() < std::mem::size_of::<RawEvent>() {
        error!("Received invalid data size from ring buffer");
        return 1;
    }

    let raw = unsafe { *(data.as_ptr() as *const RawEvent) };

    let ev = Event {
        pid: raw.pid,
        comm: std::str::from_utf8(&raw.comm)
            .unwrap_or("<invalid UTF-8>")
            .trim_end_matches('\0')
            .to_string(),
        filename: std::str::from_utf8(&raw.filename)
            .unwrap_or("<invalid UTF-8>")
            .trim_end_matches('\0')
            .to_string(),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    };

    println!("{}", serde_json::to_string(&ev).unwrap());

    0
}
