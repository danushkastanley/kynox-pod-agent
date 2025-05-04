// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/bpf.h>
#include <vmlinux.h> // Includes necessary kernel types if BTF is available
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

// Define basic types if not available
#ifndef __u8
typedef unsigned char __u8;
#endif
#ifndef __u16
typedef unsigned short __u16;
#endif
#ifndef __u32
typedef unsigned int __u32;
#endif
#ifndef __u64
typedef unsigned long long __u64;
#endif
#ifndef __s32
typedef signed int __s32;
#endif

// Define tracing structures if not fully available
struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long syscall_nr;
    unsigned long args[6];
};

struct sched_process_fork_args {
    unsigned long long unused;
    char parent_comm[16];
    __s32 parent_pid;
    char child_comm[16];
    __s32 child_pid;
};

// Define constants
#define TASK_COMM_LEN 16
#define AF_INET 2
#define FILENAME_LEN 256
#define FS_INFO_LEN 128 // Max length for mount/umount related strings

#define EVENT_TYPE_EXEC 0
#define EVENT_TYPE_OPEN 1
#define EVENT_TYPE_CONNECT 2
#define EVENT_TYPE_FORK 3
#define EVENT_TYPE_PTRACE 4
#define EVENT_TYPE_SETUID 5
#define EVENT_TYPE_SETGID 6
#define EVENT_TYPE_MOUNT 7
#define EVENT_TYPE_UMOUNT 8
#define EVENT_TYPE_CAPSET 9
#define EVENT_TYPE_BPF_PROG 10
#define EVENT_TYPE_SECCOMP 11
#define EVENT_TYPE_SOCKET 12
#define EVENT_TYPE_BIND 13
#define EVENT_TYPE_ACCEPT 14
#define EVENT_TYPE_CHMOD 15

// Network-related constants
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3

// Define seccomp-related constants
#define PR_SET_SECCOMP 22
#define PR_GET_SECCOMP 21
#define SECCOMP_MODE_STRICT 1
#define SECCOMP_MODE_FILTER 2
#define SECCOMP_SET_MODE_STRICT 0
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_GET_ACTION_AVAIL 2

struct exec_monitor_event {
    __u32 event_type;
    __u32 pid;
    __u32 parent_pid;
    __u32 child_pid;
    char comm[TASK_COMM_LEN];
    union {
        char filename[FILENAME_LEN];
        struct {
            __u32 daddr;
            __u16 dport;
        } net_info;
        struct {
            long request;
            __u32 target_pid;
        } ptrace_info;
        struct {
            __u32 uid;
        } setuid_info;
        struct {
            __u32 gid;
        } setgid_info;
        struct {
            char source[FS_INFO_LEN];
            char target[FS_INFO_LEN];
            char fstype[FS_INFO_LEN];
            unsigned long flags;
        } mount_info;
        struct {
            char target[FS_INFO_LEN];
            int flags;
        } umount_info;
        struct {
            __u32 cap;
            __u32 pid;
        } capset_info;
        struct {
            __u32 cmd;
            __u32 prog_type;
            __u32 insn_cnt;
            __u32 license_len;
            char license[64];
        } bpf_prog_info;
        struct {
            __u32 operation;
            __u32 option;
            __u32 mode;
            __u32 flags;
        } seccomp_info;
        struct {
            __s32 domain;
            __s32 type;
            __s32 protocol;
            __u32 sock_fd;
            __u32 addr;
            __u16 port;
        } sock_info;
        struct {
            char path[FILENAME_LEN];
            __u32 mode;
        } chmod_info;
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Rate limiting map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} rate_limit SEC(".maps");

// Rate limiting settings
#define RATE_LIMIT_INTERVAL 1000000000ULL  // 1 second in nanoseconds
#define RATE_LIMIT_BURST 100               // Maximum events per interval

char LICENSE[] SEC("license") = "GPL";

// Helper to check rate limit for a PID
static __always_inline bool check_rate_limit(__u32 pid) {
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_time = bpf_map_lookup_elem(&rate_limit, &pid);
    __u64 zero = 0;

    if (!last_time) {
        // First event for this PID
        bpf_map_update_elem(&rate_limit, &pid, &now, BPF_ANY);
        return true;
    }

    if (now - *last_time < RATE_LIMIT_INTERVAL / RATE_LIMIT_BURST) {
        // Too many events in the burst window
        return false;
    }

    // Update last event time
    bpf_map_update_elem(&rate_limit, &pid, &now, BPF_ANY);
    return true;
}

// Helper to submit an event
static __always_inline void submit_event(struct exec_monitor_event *e) {
    // Apply rate limiting
    if (!check_rate_limit(e->pid)) {
        return;
    }
    bpf_ringbuf_submit(e, 0);
}

// Helper to initialize common event fields
static __always_inline void init_event(struct exec_monitor_event *e, __u32 type) {
    e->event_type = type;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // Ensure other fields are zeroed initially
    e->parent_pid = 0;
    e->child_pid = 0;
    // Clearing union members - might be redundant depending on usage
    // but good for explicit safety. Choose one representative member.
    // Using bpf_memset or similar might be better if available and needed.
    // For now, clearing filename is sufficient if it's the largest member.
    for (int i = 0; i < FILENAME_LEN; i++) {
       e->filename[i] = 0;
    }
}

// Handler for execve syscall
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    init_event(e, EVENT_TYPE_EXEC);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[0]);

    submit_event(e);
    return 0;
}

// Handler for execveat syscall
SEC("tp/syscalls/sys_enter_execveat")
int handle_execveat(struct trace_event_raw_sys_enter *ctx) {
     struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    init_event(e, EVENT_TYPE_EXEC); // Treat execveat same as execve for now
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[1]);

    submit_event(e);
    return 0;
}

// Handler for open syscall
SEC("tp/syscalls/sys_enter_open")
int handle_open(struct trace_event_raw_sys_enter *ctx) {
     struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    init_event(e, EVENT_TYPE_OPEN);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[0]);

    submit_event(e);
    return 0;
}

// Handler for openat syscall
SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
     struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    init_event(e, EVENT_TYPE_OPEN); // Treat openat same as open
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[1]);

    submit_event(e);
    return 0;
}

// Handler for connect syscall
SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    __u16 family;
    struct exec_monitor_event *e;

    // Read the address family first (first 2 bytes of sockaddr)
    if (bpf_probe_read_user(&family, sizeof(family), (void *)ctx->args[1]) < 0) {
        bpf_printk("connect: failed to read family");
        return 0; // Failed to read family
    }

    // Only handle IPv4 for now
    if (family != AF_INET) {
        // bpf_printk("connect: non-IPv4 family: %d", family);
        return 0;
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    init_event(e, EVENT_TYPE_CONNECT);

    // Read IPv4 address and port using offsets
    // sockaddr_in structure: { u16 family; u16 port; u32 addr; u8 zero[8]; }
    // Use offsetof if possible, requires struct definition available
    #ifdef __VMLINUX_H__ // Check if vmlinux.h provided sockaddr_in
        void *addr_ptr = (void *)ctx->args[1];
        bpf_probe_read_user(&e->net_info.dport, sizeof(e->net_info.dport), addr_ptr + offsetof(struct sockaddr_in, sin_port));
        bpf_probe_read_user(&e->net_info.daddr, sizeof(e->net_info.daddr), addr_ptr + offsetof(struct sockaddr_in, sin_addr));
    #else
        // Fallback to hardcoded offsets if sockaddr_in is not fully defined
        void *addr_ptr = (void *)ctx->args[1];
        bpf_probe_read_user(&e->net_info.dport, sizeof(e->net_info.dport), addr_ptr + 2);  // port at offset 2
        bpf_probe_read_user(&e->net_info.daddr, sizeof(e->net_info.daddr), addr_ptr + 4);  // addr at offset 4
    #endif

    submit_event(e);
    return 0;
}

// Handler for process fork/clone using sched_process_fork tracepoint
SEC("tp/sched/sched_process_fork")
int handle_fork(struct sched_process_fork_args *ctx) {
    struct exec_monitor_event *e;

    // Extract parent and child PIDs from the context
    __s32 parent_pid = ctx->parent_pid; 
    __s32 child_pid = ctx->child_pid;   

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    // Initialize common fields - pid here will be the parent's pid at the time of fork
    init_event(e, EVENT_TYPE_FORK);
    e->pid = parent_pid; // Explicitly set PID to parent PID from context

    // Add specific fork info
    e->parent_pid = parent_pid;
    e->child_pid = child_pid;

    // Comm should be parent's comm, already set by init_event if called in parent's context

    submit_event(e);
    return 0;
}

// Handler for ptrace syscall
SEC("tp/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    init_event(e, EVENT_TYPE_PTRACE);

    // ptrace arguments: long request, pid_t pid, void *addr, void *data
    e->ptrace_info.request = (long)ctx->args[0];
    e->ptrace_info.target_pid = (__u32)ctx->args[1];

    submit_event(e);
    return 0;
}

// Handler for setuid syscall
SEC("tp/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    init_event(e, EVENT_TYPE_SETUID);

    // setuid argument: uid_t uid
    e->setuid_info.uid = (__u32)ctx->args[0];

    submit_event(e);
    return 0;
}

// Handler for setgid syscall
SEC("tp/syscalls/sys_enter_setgid")
int handle_setgid(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    init_event(e, EVENT_TYPE_SETGID);

    // setgid argument: gid_t gid
    e->setgid_info.gid = (__u32)ctx->args[0];

    submit_event(e);
    return 0;
}

// Handler for mount syscall
SEC("tp/syscalls/sys_enter_mount")
int handle_mount(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    init_event(e, EVENT_TYPE_MOUNT);

    // mount arguments: char *source, char *target, char *filesystemtype, unsigned long mountflags, void *data
    bpf_probe_read_user_str(&e->mount_info.source, sizeof(e->mount_info.source), (void *)ctx->args[0]);
    bpf_probe_read_user_str(&e->mount_info.target, sizeof(e->mount_info.target), (void *)ctx->args[1]);
    bpf_probe_read_user_str(&e->mount_info.fstype, sizeof(e->mount_info.fstype), (void *)ctx->args[2]);
    e->mount_info.flags = (unsigned long)ctx->args[3];

    submit_event(e);
    return 0;
}

// Handler for umount2 syscall (more common than umount)
/*
SEC("tp/syscalls/sys_enter_umount2")
int handle_umount2(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    init_event(e, EVENT_TYPE_UMOUNT);

    // umount2 arguments: const char *target, int flags
    bpf_probe_read_user_str(&e->umount_info.target, sizeof(e->umount_info.target), (void *)ctx->args[0]);
    e->umount_info.flags = (int)ctx->args[1];

    submit_event(e);
    return 0;
}
*/

// Handler for capset syscall
SEC("tp/syscalls/sys_enter_capset")
int handle_capset(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    init_event(e, EVENT_TYPE_CAPSET);

    // capset arguments: pid_t pid, cap_t cap
    e->capset_info.pid = (__u32)ctx->args[0];
    e->capset_info.cap = (__u32)ctx->args[1];

    submit_event(e);
    return 0;
}

// Handler for bpf syscall
SEC("tp/syscalls/sys_enter_bpf")
int handle_bpf(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_monitor_event *e;
    int cmd = (int)ctx->args[0];  // First argument is the command

    // We're primarily interested in BPF_PROG_LOAD (5)
    if (cmd != 5) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_BPF_PROG);

    // Get the attr argument which contains program details
    struct {
        __u32 prog_type;
        __u32 insn_cnt;
        __u64 insns;
        __u64 license;
        __u32 log_level;
        __u32 log_size;
        __u64 log_buf;
        __u32 kern_version;
        __u32 prog_flags;
    } attr;

    if (bpf_probe_read(&attr, sizeof(attr), (void *)ctx->args[1]) == 0) {
        e->bpf_prog_info.cmd = cmd;
        e->bpf_prog_info.prog_type = attr.prog_type;
        e->bpf_prog_info.insn_cnt = attr.insn_cnt;
        
        // Try to read the license string
        char license[64];
        if (bpf_probe_read_user_str(license, sizeof(license), (const void *)attr.license) > 0) {
            bpf_probe_read_kernel_str(e->bpf_prog_info.license, sizeof(e->bpf_prog_info.license), license);
            e->bpf_prog_info.license_len = sizeof(license);
        } else {
            e->bpf_prog_info.license_len = 0;
        }
    }

    submit_event(e);
    return 0;
}

// Handler for prctl syscall to monitor seccomp changes
SEC("tp/syscalls/sys_enter_prctl")
int handle_prctl(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_monitor_event *e;
    int option = (int)ctx->args[0];

    // We're only interested in seccomp-related prctl calls
    if (option != PR_SET_SECCOMP && option != PR_GET_SECCOMP) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_SECCOMP);
    
    e->seccomp_info.operation = 1; // 1 for prctl
    e->seccomp_info.option = option;
    
    if (option == PR_SET_SECCOMP) {
        e->seccomp_info.mode = (unsigned int)ctx->args[1];
        e->seccomp_info.flags = 0;
    } else {
        e->seccomp_info.mode = 0;
        e->seccomp_info.flags = 0;
    }

    submit_event(e);
    return 0;
}

// Handler for seccomp syscall
SEC("tp/syscalls/sys_enter_seccomp")
int handle_seccomp(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_monitor_event *e;
    unsigned int operation = (unsigned int)ctx->args[0];

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_SECCOMP);
    
    e->seccomp_info.operation = 2; // 2 for seccomp syscall
    e->seccomp_info.option = operation;
    e->seccomp_info.flags = (unsigned int)ctx->args[1];
    
    if (operation == SECCOMP_SET_MODE_FILTER) {
        // For SECCOMP_SET_MODE_FILTER, args[2] points to struct sock_fprog
        e->seccomp_info.mode = SECCOMP_MODE_FILTER;
    } else if (operation == SECCOMP_SET_MODE_STRICT) {
        e->seccomp_info.mode = SECCOMP_MODE_STRICT;
    } else {
        e->seccomp_info.mode = 0;
    }

    submit_event(e);
    return 0;
}

// Handler for socket syscall
SEC("tp/syscalls/sys_enter_socket")
int handle_socket(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_monitor_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_SOCKET);
    
    // socket(domain, type, protocol)
    e->sock_info.domain = (int)ctx->args[0];
    e->sock_info.type = (int)ctx->args[1];
    e->sock_info.protocol = (int)ctx->args[2];

    submit_event(e);
    return 0;
}

// Handler for bind syscall
SEC("tp/syscalls/sys_enter_bind")
int handle_bind(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_monitor_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_BIND);
    
    // bind(sockfd, addr, addrlen)
    e->sock_info.sock_fd = (int)ctx->args[0];

    struct sockaddr_in addr;
    if (bpf_probe_read(&addr, sizeof(addr), (void *)ctx->args[1]) == 0) {
        e->sock_info.port = bpf_ntohs(addr.sin_port);
        e->sock_info.addr = addr.sin_addr.s_addr;
    }

    submit_event(e);
    return 0;
}

// Handler for accept/accept4 syscalls
SEC("tp/syscalls/sys_enter_accept")
int handle_accept(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_monitor_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_ACCEPT);
    
    // accept(sockfd, addr, addrlen)
    e->sock_info.sock_fd = (int)ctx->args[0];

    // We can't get client addr/port at syscall entry
    // They will be filled by the kernel during accept
    e->sock_info.addr = 0;
    e->sock_info.port = 0;

    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_accept4")
int handle_accept4(struct trace_event_raw_sys_enter *ctx)
{
    return handle_accept(ctx);
}

// Handler for chmod syscall
SEC("tp/syscalls/sys_enter_chmod")
int handle_chmod(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_monitor_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_CHMOD);
    
    // Read the target path
    if (bpf_probe_read_user_str(e->chmod_info.path, sizeof(e->chmod_info.path), (const void *)ctx->args[0]) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    // Read the mode
    e->chmod_info.mode = (__u32)ctx->args[1];

    submit_event(e);
    return 0;
}

// Handler for fchmod syscall
SEC("tp/syscalls/sys_enter_fchmod")
int handle_fchmod(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_monitor_event *e;
    int fd = (int)ctx->args[0];
    char path[FILENAME_LEN];

    // Try to get path from fd
    if (bpf_probe_read_kernel_str(path, sizeof(path), (void *)fd) < 0) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_CHMOD);
    
    // Copy the path
    bpf_probe_read_kernel_str(e->chmod_info.path, sizeof(e->chmod_info.path), path);
    
    // Read the mode
    e->chmod_info.mode = (__u32)ctx->args[1];

    submit_event(e);
    return 0;
}

// Handler for fchmodat syscall
SEC("tp/syscalls/sys_enter_fchmodat")
int handle_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_monitor_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_CHMOD);
    
    // Read the target path
    if (bpf_probe_read_user_str(e->chmod_info.path, sizeof(e->chmod_info.path), (const void *)ctx->args[1]) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    // Read the mode
    e->chmod_info.mode = (__u32)ctx->args[2];

    submit_event(e);
    return 0;
}
