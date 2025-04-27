use core::ffi::c_char;
use anyhow::Result;
use env_logger;
use libbpf_rs::{RingBufferBuilder, skel::{OpenSkel, Skel, SkelBuilder}};
use log::{error, info, warn};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
use libc;

mod exec_monitor {
    include!(concat!(env!("OUT_DIR"), "/exec_monitor.skel.rs"));
}

use exec_monitor::*;

const TASK_COMM_LEN: usize = 16;
const FILENAME_LEN: usize = 256;

#[derive(Copy, Clone)]
#[repr(C)]
struct RawEvent {
    event_type: u32,
    pid: u32,
    comm: [c_char; TASK_COMM_LEN],
    filename: [c_char; FILENAME_LEN],
}

#[derive(Debug, Serialize)]
struct Event {
    event_type: u32,
    pid: u32,
    #[serde(serialize_with = "serialize_comm")]
    comm: [c_char; TASK_COMM_LEN],
    #[serde(serialize_with = "serialize_filename")]
    filename: [c_char; FILENAME_LEN],
    timestamp: u64,
}

fn c_char_array_to_string(arr: &[c_char]) -> String {
    let bytes: Vec<u8> = arr.iter()
                          .map(|&c| c as u8)
                          .take_while(|&b| b != 0)
                          .collect();
    String::from_utf8_lossy(&bytes).to_string()
}

fn serialize_comm<S>(comm: &[c_char; TASK_COMM_LEN], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&c_char_array_to_string(comm))
}

fn serialize_filename<S>(filename: &[c_char; FILENAME_LEN], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&c_char_array_to_string(filename))
}

fn handle_event(data: &[u8]) -> i32 {
    if data.len() < std::mem::size_of::<RawEvent>() {
        warn!("Received data smaller than expected RawEvent size: {} < {}", data.len(), std::mem::size_of::<RawEvent>());
        return 1;
    }

    let raw = unsafe { *(data.as_ptr() as *const RawEvent) };

    let ev = Event {
        event_type: raw.event_type,
        pid: raw.pid,
        comm: raw.comm,
        filename: raw.filename,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
    };

    match serde_json::to_string(&ev) {
        Ok(json) => {
            println!("{}", json);
        }
        Err(e) => {
            error!("Failed to serialize event to JSON: {}", e);
        }
    }

    0
}

fn main() -> Result<()> {
    env_logger::init();

    let skel_builder = ExecMonitorSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    info!("eBPF agent started successfully! Monitoring execve, execveat, open, openat.");

    let maps = skel.maps();
    let rb_map = maps.rb().clone();

    let mut builder = RingBufferBuilder::new();
    builder.add(&rb_map, handle_event)?;
    let ringbuf = builder.build()?;

    info!("Polling ring buffer for events...");
    loop {
        match ringbuf.poll(std::time::Duration::from_millis(100)) {
            Ok(_) => {}
            Err(libbpf_rs::Error::System(errno)) if errno == libc::EINTR => {
                info!("Poll interrupted (EINTR), exiting.");
                break;
            }
            Err(e) => {
                error!("Error polling ring buffer: {}", e);
                break;
            }
        }
    }

    Ok(())
}
