use anyhow::Result;
use libbpf_rs::RingBufferBuilder;
use log::{error, info, warn, debug};
use std::sync::Arc;
use std::sync::Mutex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bpf::{ExecMonitorSkel, ExecMonitorSkelBuilder};
use crate::constants::{
    EVENT_TYPE_ACCEPT, EVENT_TYPE_BIND, EVENT_TYPE_BPF_PROG, EVENT_TYPE_CAPSET,
    EVENT_TYPE_CONNECT, EVENT_TYPE_EXEC, EVENT_TYPE_FORK, EVENT_TYPE_MOUNT, EVENT_TYPE_OPEN,
    EVENT_TYPE_PTRACE, EVENT_TYPE_SECCOMP, EVENT_TYPE_SETGID, EVENT_TYPE_SETUID,
    EVENT_TYPE_SOCKET, EVENT_TYPE_UMOUNT, EVENT_TYPE_CHMOD, SECCOMP_MODE_FILTER, SECCOMP_MODE_STRICT,
    SECCOMP_PRCTL, SECCOMP_SET_MODE_FILTER, SECCOMP_SET_MODE_STRICT, SECCOMP_SYSCALL,
    PR_GET_SECCOMP, PR_SET_SECCOMP,
};
use crate::events::Event;
pub use crate::events::EventOutput;
use crate::utils::cstr_to_string;

pub struct SyscallMonitor {
    skel: ExecMonitorSkel<'static>,
    ringbuf: Arc<Mutex<Option<libbpf_rs::RingBuffer<'static>>>>,
}

impl SyscallMonitor {
    pub fn new() -> Result<Self> {
        let skel_builder = ExecMonitorSkelBuilder::default();
        let open_skel = skel_builder.open()?;
        let skel = open_skel.load()?;
        
        Ok(Self {
            skel,
            ringbuf: Arc::new(Mutex::new(None)),
        })
    }

    pub fn attach(&mut self) -> Result<()> {
        self.skel.attach()?;
        info!("BPF programs attached successfully.");
        Ok(())
    }

    // Takes &mut self now to allow modifying maps
    pub fn setup_ring_buffer<F>(&mut self, callback: F) -> Result<()> 
    where
        F: FnMut(&[u8]) -> i32 + 'static + Send + Sync,
    {
        // No longer needs unsafe, declare maps as mutable
        let mut maps = self.skel.maps_mut(); 
        let map_ref = maps.rb(); 
 
        let mut builder = RingBufferBuilder::new();
        builder.add(map_ref, callback)?;

        let rb = builder.build()?;

        *self.ringbuf.lock().unwrap() = Some(rb);
        info!("Ring buffer setup complete.");

        Ok(())
    }

    pub fn poll(&self, timeout_ms: u32) -> Result<()> {
        let mut ringbuf_guard = self.ringbuf.lock().unwrap(); 
        if let Some(rb) = ringbuf_guard.as_mut() {
            match rb.poll(std::time::Duration::from_millis(timeout_ms.into())) {
                Ok(_) => Ok(()),
                Err(libbpf_rs::Error::System(errno)) if errno == libc::EINTR => {
                    Ok(())
                }
                Err(e) => {
                    error!("Error polling ring buffer: {}", e);
                    Err(e.into())
                }
            }
        } else {
            Err(anyhow::anyhow!("Ring buffer not initialized before polling"))
        }
    }
}

pub fn parse_bpf_event(data: &[u8]) -> Option<EventOutput> {
    if data.len() < std::mem::size_of::<Event>() {
        warn!("Received data smaller than expected Event size: {} bytes", data.len());
        return None;
    }
    // SAFETY: We've checked the size, assume the data layout matches the Event struct from BPF C code.
    let raw: &Event = unsafe { &*(data.as_ptr() as *const Event) };

    // Log the event type for debugging
    debug!("Received event type: {}", raw.event_type);

    // Initialize EventOutput, copying common fields from raw Event
    let mut event = EventOutput {
        event_type: raw.event_type,
        pid: raw.pid,
        parent_pid: Some(raw.parent_pid),
        child_pid: Some(raw.child_pid),
        comm: cstr_to_string(&raw.comm),
        container_id: Some(cstr_to_string(&raw.container_id)),
        filename: None,
        daddr: None,
        dport: None,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
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
        cap_effective: None,
        cap_pid: None,
        bpf_cmd: None,
        bpf_prog_type: None,
        bpf_insn_cnt: None,
        bpf_license: None,
        seccomp_operation: None,
        seccomp_option: None,
        seccomp_mode: None,
        seccomp_flags: None,
        socket_domain: None,
        socket_type: None,
        socket_protocol: None,
        socket_fd: None,
        socket_addr: None,
        socket_port: None,
        chmod_path: None,
        chmod_mode: None,
    };

    match raw.event_type {
        EVENT_TYPE_EXEC | EVENT_TYPE_OPEN => {
            event.filename = Some(cstr_to_string(&unsafe { raw.data.filename }));
        }
        EVENT_TYPE_CONNECT => {
            let net_info = unsafe { raw.data.net_info };
            event.dport = Some(net_info.dport);

            // Handle IPv4 vs IPv6 based on address family
            if net_info.family == libc::AF_INET6 as u16 {
                // IPv6 address
                let addr = Ipv6Addr::from(net_info.daddr6);
                event.daddr = Some(addr.to_string());
            } else {
                // IPv4 address (default)
                let addr = Ipv4Addr::from(u32::from_be(net_info.daddr));
                event.daddr = Some(addr.to_string());
            }
        }
        EVENT_TYPE_PTRACE => {
            let info = unsafe { raw.data.ptrace_info };
            event.ptrace_request = Some(info.request);
            event.ptrace_target_pid = Some(info.target_pid);
        }
        EVENT_TYPE_SETUID => {
            let info = unsafe { raw.data.setuid_info };
            event.uid = Some(info.uid);
        }
        EVENT_TYPE_SETGID => {
            let info = unsafe { raw.data.setgid_info };
            event.gid = Some(info.gid);
        }
        EVENT_TYPE_MOUNT => {
            let info = unsafe { raw.data.mount_info };
            event.mount_source = Some(cstr_to_string(&info.source));
            event.mount_target = Some(cstr_to_string(&info.target));
            event.mount_fstype = Some(cstr_to_string(&info.fstype));
            event.mount_flags = Some(info.flags);
        }
        EVENT_TYPE_UMOUNT => {
            let info = unsafe { raw.data.umount_info };
            event.umount_target = Some(cstr_to_string(&info.target));
            event.umount_flags = Some(info.flags);
        }
        EVENT_TYPE_CAPSET => {
            let info = unsafe { raw.data.capset_info };
            event.cap_effective = Some(info.cap);
            event.cap_pid = Some(info.pid);
        }
        EVENT_TYPE_FORK => {
            // Fork events only need the common fields which are already copied
        }
        EVENT_TYPE_BPF_PROG => {
            let info = unsafe { raw.data.bpf_prog_info };
            event.bpf_cmd = Some(info.cmd);
            event.bpf_prog_type = Some(info.prog_type);
            event.bpf_insn_cnt = Some(info.insn_cnt);
            event.bpf_license = Some(cstr_to_string(&info.license));
        }
        EVENT_TYPE_SECCOMP => {
            let info = unsafe { raw.data.seccomp_info };
            event.seccomp_operation = Some(match info.operation {
                SECCOMP_PRCTL => "prctl".to_string(),
                SECCOMP_SYSCALL => "seccomp".to_string(),
                _ => format!("unknown({})", info.operation),
            });
            event.seccomp_option = Some(match info.option {
                PR_SET_SECCOMP => "PR_SET_SECCOMP".to_string(),
                PR_GET_SECCOMP => "PR_GET_SECCOMP".to_string(),
                SECCOMP_SET_MODE_STRICT => "SECCOMP_SET_MODE_STRICT".to_string(),
                SECCOMP_SET_MODE_FILTER => "SECCOMP_SET_MODE_FILTER".to_string(),
                _ => format!("unknown({})", info.option),
            });
            event.seccomp_mode = Some(match info.mode {
                SECCOMP_MODE_STRICT => "SECCOMP_MODE_STRICT".to_string(),
                SECCOMP_MODE_FILTER => "SECCOMP_MODE_FILTER".to_string(),
                0 => "none".to_string(),
                _ => format!("unknown({})", info.mode),
            });
            event.seccomp_flags = Some(info.flags);
        }
        EVENT_TYPE_SOCKET | EVENT_TYPE_BIND | EVENT_TYPE_ACCEPT => {
            let info = unsafe { raw.data.sock_info };
            event.socket_domain = Some(match info.domain {
                libc::AF_INET => "AF_INET".to_string(),
                libc::AF_INET6 => "AF_INET6".to_string(),
                libc::AF_UNIX => "AF_UNIX".to_string(),
                libc::AF_NETLINK => "AF_NETLINK".to_string(),
                _ => format!("unknown({})", info.domain),
            });
            event.socket_type = Some(match info.type_ {
                libc::SOCK_STREAM => "SOCK_STREAM".to_string(),
                libc::SOCK_DGRAM => "SOCK_DGRAM".to_string(),
                libc::SOCK_RAW => "SOCK_RAW".to_string(),
                libc::SOCK_SEQPACKET => "SOCK_SEQPACKET".to_string(),
                _ => format!("unknown({})", info.type_),
            });
            event.socket_protocol = Some(info.protocol);
            event.socket_fd = Some(info.sock_fd);
            if raw.event_type == EVENT_TYPE_BIND {
                event.socket_port = Some(info.port);
                // Handle IPv4 vs IPv6 based on address family
                if info.family == libc::AF_INET6 as u16 {
                    // IPv6 address
                    let addr = Ipv6Addr::from(info.addr6);
                    event.socket_addr = Some(addr.to_string());
                } else if info.addr != 0 || info.family == libc::AF_INET as u16 {
                    // IPv4 address
                    let addr = Ipv4Addr::from(u32::from_be(info.addr));
                    event.socket_addr = Some(addr.to_string());
                }
            }
        }
        EVENT_TYPE_CHMOD => {
            let info = unsafe { raw.data.chmod_info };
            event.chmod_path = Some(cstr_to_string(&info.path));
            event.chmod_mode = Some(info.mode);
        }
        unknown_type => {
            error!("Unknown event type received: {}. Known types are 0-15.", unknown_type);
            return None;
        }
    }
    Some(event)
}
