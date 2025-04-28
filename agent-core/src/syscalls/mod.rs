use anyhow::Result;
use libbpf_rs::{RingBufferBuilder, Map};
use log::{error, info, warn};
use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bpf::*;
use crate::constants::*;
use crate::events::{Event, EventOutput};
use crate::utils::cstr_to_string;

// Wrapper to manage ring buffer lifecycle
struct RingBufferWrapper {
    // The actual ring buffer
    buffer: libbpf_rs::RingBuffer<'static>,
}

pub struct SyscallMonitor {
    skel: ExecMonitorSkel<'static>,
    // Using RefCell for internal mutability
    ringbuf: RefCell<Option<RingBufferWrapper>>,
}

impl SyscallMonitor {
    pub fn new() -> Result<Self> {
        let skel_builder = ExecMonitorSkelBuilder::default();
        let open_skel = skel_builder.open()?;
        let skel = open_skel.load()?;
        
        Ok(Self {
            skel,
            ringbuf: RefCell::new(None),
        })
    }

    pub fn attach(&mut self) -> Result<()> {
        self.skel.attach()?;
        Ok(())
    }

    pub fn setup_ring_buffer(&self) -> Result<()> {
        // SAFETY: This is safe because:
        // 1. The skeleton owns the maps and has 'static lifetime
        // 2. The maps exist as long as the skeleton exists
        // 3. The skeleton is dropped only when SyscallMonitor is dropped
        // 4. When SyscallMonitor is dropped, it also drops the ring buffer
        let rb = unsafe {
            let maps = self.skel.maps();
            let map_ref = maps.rb();
            
            // Create builder and get underlying ring buffer
            let mut builder = RingBufferBuilder::new();
            builder.add(map_ref, Self::handle_event)?;
            
            // Extend map reference lifetime to 'static since we know skeleton keeps it alive
            let rb = std::mem::transmute::<libbpf_rs::RingBuffer<'_>, libbpf_rs::RingBuffer<'static>>(
                builder.build()?
            );
            
            rb
        };

        // Store the ring buffer
        let wrapper = RingBufferWrapper { buffer: rb };
        *self.ringbuf.borrow_mut() = Some(wrapper);
        
        Ok(())
    }

    pub fn poll(&self, timeout_ms: u32) -> Result<()> {
        let ringbuf = self.ringbuf.borrow();
        if let Some(wrapper) = ringbuf.as_ref() {
            match wrapper.buffer.poll(std::time::Duration::from_millis(timeout_ms.into())) {
                Ok(_) => Ok(()),
                Err(libbpf_rs::Error::System(errno)) if errno == libc::EINTR => {
                    info!("Poll interrupted (EINTR)");
                    Ok(())
                }
                Err(e) => {
                    error!("Error polling ring buffer: {}", e);
                    Err(e.into())
                }
            }
        } else {
            Err(anyhow::anyhow!("Ring buffer not initialized"))
        }
    }

    fn handle_event(data: &[u8]) -> i32 {
        let raw = unsafe { &*(data.as_ptr() as *const Event) };
        
        let mut event = EventOutput {
            event_type: raw.event_type,
            pid: raw.pid,
            parent_pid: Some(raw.parent_pid),
            child_pid: Some(raw.child_pid),
            comm: cstr_to_string(&raw.comm),
            filename: None,
            daddr: None,
            dport: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
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
        };

        match raw.event_type {
            EVENT_TYPE_EXEC | EVENT_TYPE_OPEN => {
                event.filename = Some(cstr_to_string(unsafe { &raw.data.filename }));
            }
            EVENT_TYPE_CONNECT => {
                let net_info = unsafe { raw.data.net_info };
                if net_info.daddr != 0 {
                    let addr = Ipv4Addr::from(u32::from_be(net_info.daddr));
                    event.daddr = Some(addr.to_string());
                    event.dport = Some(net_info.dport);
                }
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
                event.cap_effective = Some(capset_info.cap);
                event.cap_pid = Some(capset_info.pid);
            }
            EVENT_TYPE_BPF_PROG => {
                let bpf_info = unsafe { raw.data.bpf_prog_info };
                event.bpf_cmd = Some(bpf_info.cmd);
                event.bpf_prog_type = Some(bpf_info.prog_type);
                event.bpf_insn_cnt = Some(bpf_info.insn_cnt);
                event.bpf_license = Some(cstr_to_string(&bpf_info.license));
            }
            EVENT_TYPE_SECCOMP => {
                let seccomp_info = unsafe { raw.data.seccomp_info };
                
                event.seccomp_operation = Some(match seccomp_info.operation {
                    1 => "prctl".to_string(),
                    2 => "seccomp".to_string(),
                    _ => format!("unknown({})", seccomp_info.operation),
                });

                event.seccomp_option = Some(match seccomp_info.option {
                    PR_SET_SECCOMP => "PR_SET_SECCOMP".to_string(),
                    PR_GET_SECCOMP => "PR_GET_SECCOMP".to_string(),
                    SECCOMP_SET_MODE_STRICT => "SECCOMP_SET_MODE_STRICT".to_string(),
                    SECCOMP_SET_MODE_FILTER => "SECCOMP_SET_MODE_FILTER".to_string(),
                    _ => format!("unknown({})", seccomp_info.option),
                });

                event.seccomp_mode = Some(match seccomp_info.mode {
                    SECCOMP_MODE_STRICT => "SECCOMP_MODE_STRICT".to_string(),
                    SECCOMP_MODE_FILTER => "SECCOMP_MODE_FILTER".to_string(),
                    0 => "none".to_string(),
                    _ => format!("unknown({})", seccomp_info.mode),
                });

                event.seccomp_flags = Some(seccomp_info.flags);
            }
            EVENT_TYPE_SOCKET | EVENT_TYPE_BIND | EVENT_TYPE_ACCEPT => {
                let sock_info = unsafe { raw.data.sock_info };
                
                event.socket_domain = Some(match sock_info.domain {
                    AF_INET => "AF_INET".to_string(),
                    AF_INET6 => "AF_INET6".to_string(),
                    _ => format!("unknown({})", sock_info.domain),
                });

                event.socket_type = Some(match sock_info.type_ {
                    SOCK_STREAM => "SOCK_STREAM".to_string(),
                    SOCK_DGRAM => "SOCK_DGRAM".to_string(),
                    SOCK_RAW => "SOCK_RAW".to_string(),
                    _ => format!("unknown({})", sock_info.type_),
                });

                event.socket_protocol = Some(sock_info.protocol);
                event.socket_fd = Some(sock_info.sock_fd);

                if raw.event_type == EVENT_TYPE_BIND {
                    if sock_info.addr != 0 {
                        let addr = Ipv4Addr::from(u32::from_be(sock_info.addr));
                        event.socket_addr = Some(addr.to_string());
                        event.socket_port = Some(sock_info.port);
                    }
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
}
