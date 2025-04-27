use core::ffi::c_char;
use anyhow::Result;
use env_logger;
use libbpf_rs::{RingBufferBuilder, skel::{OpenSkel, Skel, SkelBuilder}};
use log::{error, info, warn};
use serde::{Serialize, Deserialize};
use std::net::Ipv4Addr; 
use std::time::{SystemTime, UNIX_EPOCH};
use libc;

// Include the generated skeleton code
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod exec_monitor {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/generated_skel.rs"));
}

use exec_monitor::*;

const TASK_COMM_LEN: usize = 16;
const FILENAME_LEN: usize = 256;

// Event type constants
const EVENT_TYPE_EXEC: u32 = 0;
const EVENT_TYPE_OPEN: u32 = 1;
const EVENT_TYPE_CONNECT: u32 = 2;
const EVENT_TYPE_FORK: u32 = 3;
const EVENT_TYPE_PTRACE: u32 = 4;

// Event structure that matches our BPF code
#[repr(C)]
struct Event {
    event_type: u32,
    pid: u32,
    parent_pid: u32,
    child_pid: u32,
    comm: [i8; TASK_COMM_LEN],
    data: EventData,
}

#[repr(C)]
#[derive(Copy, Clone)]
union EventData {
    filename: [i8; FILENAME_LEN],
    net_info: NetInfo,
    ptrace_info: PtraceInfo,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct NetInfo {
    daddr: u32,
    dport: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PtraceInfo {
    request: i64,
    target_pid: u32,
}

// User-friendly, serializable event struct for JSON output
#[derive(Debug, Serialize, Deserialize)]
struct EventOutput {
    event_type: u32,
    pid: u32,
    parent_pid: Option<u32>,
    child_pid: Option<u32>,
    comm: String,
    filename: Option<String>,
    daddr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dport: Option<u16>,
    timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ptrace_request: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ptrace_target_pid: Option<u32>,
}

// Helper function to convert C string to Rust string
fn cstr_to_string(cstr: &[i8]) -> String {
    let bytes: Vec<u8> = cstr
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).to_string()
}

fn handle_event(data: &[u8]) -> i32 {
    if data.len() != std::mem::size_of::<Event>() {
        warn!(
            "Received data size mismatch: {} bytes, expected {}",
            data.len(),
            std::mem::size_of::<Event>()
        );
        return 1;
    }

    let raw: &Event = unsafe {
        &*(data.as_ptr() as *const Event)
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let mut event = EventOutput {
        event_type: raw.event_type,
        pid: raw.pid,
        parent_pid: Some(raw.parent_pid),
        child_pid: Some(raw.child_pid),
        comm: cstr_to_string(&raw.comm),
        filename: None,
        daddr: None,
        dport: None,
        timestamp,
        ptrace_request: None,
        ptrace_target_pid: None,
    };

    match raw.event_type {
        EVENT_TYPE_EXEC | EVENT_TYPE_OPEN => {
            let filename_bytes = unsafe { raw.data.filename };
            event.filename = Some(cstr_to_string(&filename_bytes));
        }
        EVENT_TYPE_CONNECT => {
            let net_info = unsafe { raw.data.net_info };
            let daddr = Ipv4Addr::from(u32::from_be(net_info.daddr));
            let dport = u16::from_be(net_info.dport);
            event.daddr = Some(daddr.to_string());
            event.dport = Some(dport);
        }
        EVENT_TYPE_PTRACE => {
            let ptrace_info = unsafe { raw.data.ptrace_info };
            event.ptrace_request = Some(ptrace_info.request);
            event.ptrace_target_pid = Some(ptrace_info.target_pid);
        }
        _ => {
            warn!("Received unknown event type: {}", raw.event_type);
            return 1;
        }
    }

    match serde_json::to_string(&event) {
        Ok(json) => println!("{}", json),
        Err(e) => warn!("Failed to serialize event to JSON: {} - Event: {:?}", e, event),
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
