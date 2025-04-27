use core::ffi::c_char;
use anyhow::Result;
use env_logger;
use libbpf_rs::{RingBufferBuilder, skel::{OpenSkel, Skel, SkelBuilder}};
use log::{error, info, warn};
use serde::Serialize;
use std::mem::MaybeUninit; 
use std::net::Ipv4Addr; 
use std::time::{SystemTime, UNIX_EPOCH};
use libc;

mod exec_monitor {
    include!(concat!(env!("OUT_DIR"), "/exec_monitor.skel.rs"));
}

use exec_monitor::*;

const TASK_COMM_LEN: usize = 16;
const FILENAME_LEN: usize = 256;

// Event type constants (should match C defines)
const EVENT_TYPE_EXEC: u32 = 0;
const EVENT_TYPE_OPEN: u32 = 1;
const EVENT_TYPE_CONNECT: u32 = 2;
const EVENT_TYPE_FORK: u32 = 3;

// Structure to hold raw network info (matching C layout)
#[derive(Copy, Clone)]
#[repr(C)]
struct RawNetInfo {
    daddr: u32, 
    dport: u16, 
}

// Raw event struct matching C layout, including union space
#[derive(Copy, Clone)]
#[repr(C)]
struct RawEvent {
    event_type: u32,
    pid: u32,
    comm: [c_char; TASK_COMM_LEN],
    // Represents the C union { char filename[256]; struct { u32 daddr; u16 dport; } net_info; };
    // Size is FILENAME_LEN (256) which is larger than RawNetInfo (6)
    union_data: [u8; FILENAME_LEN],
    parent_pid: u32,
    child_pid: u32,
}

// User-friendly, serializable event struct
#[derive(Debug, Serialize)]
struct Event {
    event_type: u32,
    pid: u32,
    parent_pid: Option<u32>,
    child_pid: Option<u32>,
    comm: String, 
    // Optional fields based on event type
    filename: Option<String>,
    daddr: Option<String>, 
    dport: Option<u16>,    
    timestamp: u64,
}

// Helper function stays the same
fn c_char_array_to_string(arr: &[c_char]) -> String {
    let bytes: Vec<u8> = arr.iter()
                          .map(|&c| c as u8)
                          .take_while(|&b| b != 0)
                          .collect();
    String::from_utf8_lossy(&bytes).to_string()
}

fn handle_event(data: &[u8]) -> i32 {
    if data.len() < std::mem::size_of::<RawEvent>() {
        warn!("Received data smaller than expected RawEvent size: {} < {}", data.len(), std::mem::size_of::<RawEvent>());
        return 1;
    }

    // Create an uninitialized RawEvent to copy data into safely
    let mut raw_event_uninit: MaybeUninit<RawEvent> = MaybeUninit::uninit();
    // SAFETY: We checked the size, and we're copying from a slice provided by the kernel/libbpf.
    // The pointer is valid for the size of RawEvent.
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), raw_event_uninit.as_mut_ptr() as *mut u8, std::mem::size_of::<RawEvent>());
        // Now assume it's initialized
        let raw = raw_event_uninit.assume_init();

        // Common fields
        let pid = raw.pid;
        // Convert comm directly here
        let comm_str = c_char_array_to_string(&raw.comm);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        let mut event = Event {
            event_type: raw.event_type,
            pid,
            parent_pid: None,
            child_pid: None,
            comm: comm_str,
            filename: None,
            daddr: None,
            dport: None,
            timestamp,
        };

        // Process union data based on event type
        match raw.event_type {
            EVENT_TYPE_EXEC | EVENT_TYPE_OPEN => {
                // Treat union_data as filename (c_char array)
                // SAFETY: We assume BPF program wrote filename for these types.
                // Need to cast the [u8] slice to a pointer of the correct c_char array type.
                let filename_ptr = raw.union_data.as_ptr() as *const [c_char; FILENAME_LEN];
                event.filename = Some(c_char_array_to_string(&*filename_ptr));
            }
            EVENT_TYPE_CONNECT => {
                 // Treat start of union_data as RawNetInfo
                 // SAFETY: We assume BPF program wrote net_info for this type.
                 // Ensure we don't read past the bounds of union_data (RawNetInfo is smaller).
                 if FILENAME_LEN >= std::mem::size_of::<RawNetInfo>() {
                    let net_info_ptr = raw.union_data.as_ptr() as *const RawNetInfo;
                    let net_info = *net_info_ptr;
                    // Convert IP and port from network byte order to host format
                    let ip_addr = Ipv4Addr::from(u32::from_be(net_info.daddr)); 
                    let port = u16::from_be(net_info.dport); 
                    event.daddr = Some(ip_addr.to_string());
                    event.dport = Some(port);
                 } else {
                     warn!("RawNetInfo size exceeds union_data buffer?");
                 }
            }
            EVENT_TYPE_FORK => {
                event.parent_pid = Some(raw.parent_pid);
                event.child_pid = Some(raw.child_pid);
            }
            _ => {
                warn!("Received unknown event type: {}", raw.event_type);
            }
        }

        // Serialize and print the user-friendly Event struct
        match serde_json::to_string(&event) {
            Ok(json) => {
                println!("{}", json);
            }
            Err(e) => {
                error!("Failed to serialize event to JSON: {}", e);
            }
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
