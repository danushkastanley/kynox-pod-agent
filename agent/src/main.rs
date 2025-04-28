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
const FS_INFO_LEN: usize = 128;

// Event type constants
const EVENT_TYPE_EXEC: u32 = 0;
const EVENT_TYPE_OPEN: u32 = 1;
const EVENT_TYPE_CONNECT: u32 = 2;
const EVENT_TYPE_FORK: u32 = 3;
const EVENT_TYPE_PTRACE: u32 = 4;
const EVENT_TYPE_SETUID: u32 = 5;
const EVENT_TYPE_SETGID: u32 = 6;
const EVENT_TYPE_MOUNT: u32 = 7;
const EVENT_TYPE_UMOUNT: u32 = 8;
const EVENT_TYPE_CAPSET: u32 = 9;
const EVENT_TYPE_BPF_PROG: u32 = 10;

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
    setuid_info: SetuidInfo,
    setgid_info: SetgidInfo,
    mount_info: MountInfo,
    umount_info: UmountInfo,
    capset_info: CapsetInfo,
    bpf_prog_info: BpfProgInfo,
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

#[repr(C)]
#[derive(Copy, Clone)]
struct SetuidInfo {
    uid: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SetgidInfo {
    gid: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct MountInfo {
    source: [i8; FS_INFO_LEN],
    target: [i8; FS_INFO_LEN],
    fstype: [i8; FS_INFO_LEN],
    flags: u64, // Use u64 to match unsigned long in BPF
}

#[repr(C)]
#[derive(Copy, Clone)]
struct UmountInfo {
    target: [i8; FS_INFO_LEN],
    flags: i32, // Use i32 to match int in BPF
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CapsetInfo {
    cap: u32,
    pid: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct BpfProgInfo {
    cmd: u32,
    prog_type: u32,
    insn_cnt: u32,
    license_len: u32,
    license: [i8; 64],
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
    #[serde(skip_serializing_if = "Option::is_none")]
    uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mount_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mount_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mount_fstype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mount_flags: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    umount_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    umount_flags: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capset_cap: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capset_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bpf_cmd: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bpf_prog_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bpf_insn_cnt: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bpf_license: Option<String>,
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
        uid: None,
        gid: None,
        mount_source: None,
        mount_target: None,
        mount_fstype: None,
        mount_flags: None,
        umount_target: None,
        umount_flags: None,
        capset_cap: None,
        capset_pid: None,
        bpf_cmd: None,
        bpf_prog_type: None,
        bpf_insn_cnt: None,
        bpf_license: None,
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
        EVENT_TYPE_SETUID => {
            let setuid_info = unsafe { raw.data.setuid_info };
            event.uid = Some(setuid_info.uid);
        }
        EVENT_TYPE_SETGID => {
            let setgid_info = unsafe { raw.data.setgid_info };
            event.gid = Some(setgid_info.gid);
        }
        EVENT_TYPE_MOUNT => {
            let mount_info = unsafe { raw.data.mount_info };
            event.mount_source = Some(cstr_to_string(&mount_info.source));
            event.mount_target = Some(cstr_to_string(&mount_info.target));
            event.mount_fstype = Some(cstr_to_string(&mount_info.fstype));
            event.mount_flags = Some(mount_info.flags);
        }
        EVENT_TYPE_UMOUNT => {
            let umount_info = unsafe { raw.data.umount_info };
            event.umount_target = Some(cstr_to_string(&umount_info.target));
            event.umount_flags = Some(umount_info.flags);
        }
        EVENT_TYPE_CAPSET => {
            let capset_info = unsafe { raw.data.capset_info };
            event.capset_cap = Some(capset_info.cap);
            event.capset_pid = Some(capset_info.pid);
            // We don't need specific filename/daddr for capset
            event.parent_pid = Some(raw.parent_pid); // Ensure parent PID is included if needed
            event.child_pid = None; // Capset doesn't have a child_pid concept here
        }
        EVENT_TYPE_BPF_PROG => {
            let bpf_info = unsafe { raw.data.bpf_prog_info };
            event.bpf_cmd = Some(bpf_info.cmd);
            event.bpf_prog_type = Some(bpf_info.prog_type);
            event.bpf_insn_cnt = Some(bpf_info.insn_cnt);
            if bpf_info.license_len > 0 {
                event.bpf_license = Some(cstr_to_string(&bpf_info.license));
            }
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
