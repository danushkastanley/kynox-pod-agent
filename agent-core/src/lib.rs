pub mod events;
pub mod syscalls;
pub mod utils;

// Re-export commonly used items
pub use events::*;
pub use syscalls::*;
pub use utils::*;

// Include the generated skeleton code
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod bpf {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/generated_skel.rs"
    ));
}

// Constants
pub mod constants {
    pub const TASK_COMM_LEN: usize = 16;
    pub const FILENAME_LEN: usize = 256;
    pub const FS_INFO_LEN: usize = 128;
    pub const CONTAINER_ID_LEN: usize = 64;

    // Event type constants
    pub const EVENT_TYPE_EXEC: u32 = 0;
    pub const EVENT_TYPE_OPEN: u32 = 1;
    pub const EVENT_TYPE_CONNECT: u32 = 2;
    pub const EVENT_TYPE_FORK: u32 = 3;
    pub const EVENT_TYPE_PTRACE: u32 = 4;
    pub const EVENT_TYPE_SETUID: u32 = 5;
    pub const EVENT_TYPE_SETGID: u32 = 6;
    pub const EVENT_TYPE_MOUNT: u32 = 7;
    pub const EVENT_TYPE_UMOUNT: u32 = 8;
    pub const EVENT_TYPE_CAPSET: u32 = 9;
    pub const EVENT_TYPE_BPF_PROG: u32 = 10;
    pub const EVENT_TYPE_SECCOMP: u32 = 11;
    pub const EVENT_TYPE_SOCKET: u32 = 12;
    pub const EVENT_TYPE_BIND: u32 = 13;
    pub const EVENT_TYPE_ACCEPT: u32 = 14;
    pub const EVENT_TYPE_CHMOD: u32 = 16;
    pub const EVENT_TYPE_SETNS: u32 = 15;

    // Seccomp Operation Constants (from BPF struct context)
    pub const SECCOMP_PRCTL: u32 = 1; // Placeholder value, adjust if known from BPF C code
    pub const SECCOMP_SYSCALL: u32 = 2; // Placeholder value, adjust if known from BPF C code

    // Seccomp-related constants
    pub const PR_SET_SECCOMP: u32 = 22;
    pub const PR_GET_SECCOMP: u32 = 21;
    pub const SECCOMP_MODE_STRICT: u32 = 1;
    pub const SECCOMP_MODE_FILTER: u32 = 2;
    pub const SECCOMP_SET_MODE_STRICT: u32 = 0;
    pub const SECCOMP_SET_MODE_FILTER: u32 = 1;

    // Network-related constants
    pub const AF_INET: i32 = 2;
    pub const AF_INET6: i32 = 10;
    pub const SOCK_STREAM: i32 = 1;
    pub const SOCK_DGRAM: i32 = 2;
    pub const SOCK_RAW: i32 = 3;
}
