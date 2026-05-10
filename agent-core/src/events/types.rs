use crate::constants::*;

#[repr(C)]
pub struct Event {
    pub event_type: u32,
    pub pid: u32,
    pub parent_pid: u32,
    pub child_pid: u32,
    pub comm: [i8; TASK_COMM_LEN],
    pub container_id: [i8; CONTAINER_ID_LEN],
    pub data: EventData,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union EventData {
    pub filename: [i8; FILENAME_LEN],
    pub net_info: NetInfo,
    pub ptrace_info: PtraceInfo,
    pub setuid_info: SetuidInfo,
    pub setgid_info: SetgidInfo,
    pub mount_info: MountInfo,
    pub umount_info: UmountInfo,
    pub capset_info: CapsetInfo,
    pub bpf_prog_info: BpfProgInfo,
    pub seccomp_info: SeccompInfo,
    pub sock_info: SockInfo,
    pub chmod_info: ChmodInfo,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct NetInfo {
    pub daddr: u32,         // IPv4 address (network byte order)
    pub dport: u16,         // Destination port (host byte order)
    pub family: u16,        // Address family: AF_INET or AF_INET6
    pub daddr6: [u8; 16],   // IPv6 address (128 bits)
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PtraceInfo {
    pub request: i64,
    pub target_pid: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SetuidInfo {
    pub uid: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SetgidInfo {
    pub gid: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MountInfo {
    pub source: [i8; FS_INFO_LEN],
    pub target: [i8; FS_INFO_LEN],
    pub fstype: [i8; FS_INFO_LEN],
    pub flags: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UmountInfo {
    pub target: [i8; FS_INFO_LEN],
    pub flags: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CapsetInfo {
    pub cap: u32,
    pub pid: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BpfProgInfo {
    pub cmd: u32,
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub license_len: u32,
    pub license: [i8; 64],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SeccompInfo {
    pub operation: u32,
    pub option: u32,
    pub mode: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SockInfo {
    pub domain: i32,        // Socket domain (AF_INET, AF_INET6, etc.)
    pub type_: i32,         // Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
    pub protocol: i32,      // Protocol (0 for default)
    pub sock_fd: u32,       // Socket file descriptor
    pub addr: u32,          // IPv4 address (network byte order)
    pub port: u16,          // Port (host byte order)
    pub family: u16,        // Address family: AF_INET or AF_INET6
    pub addr6: [u8; 16],    // IPv6 address (128 bits)
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ChmodInfo {
    pub path: [i8; FILENAME_LEN],
    pub mode: u32,
}
