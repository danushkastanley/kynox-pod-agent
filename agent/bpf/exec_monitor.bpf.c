// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/bpf.h>
#include <linux/sched.h>

// Define size_t for signal.h
typedef __kernel_size_t size_t;

#include <linux/signal.h>
#include <linux/stddef.h>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Define tracing structures
struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long syscall_nr;
    unsigned long args[6];
};

// Define constants that might not be in vmlinux.h
#define TASK_COMM_LEN 16
#define AF_INET 2
#define FILENAME_LEN 256

// Define the GPL license
char LICENSE[] SEC("license") = "GPL";

#define EVENT_TYPE_EXEC 0
#define EVENT_TYPE_OPEN 1
#define EVENT_TYPE_CONNECT 2
#define EVENT_TYPE_FORK 3

struct event {
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
    union {
        char filename[FILENAME_LEN];
        struct {
            __u32 daddr;
            __u16 dport;
        } net_info;
        struct {
            __u32 clone_flags;
            __u32 exit_signal;
        } process_info;
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    e->event_type = EVENT_TYPE_EXEC;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_execveat")
int handle_execveat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    e->event_type = EVENT_TYPE_EXEC;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_open")
int handle_open(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    e->event_type = EVENT_TYPE_OPEN;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    e->event_type = EVENT_TYPE_OPEN;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    __u16 family;
    struct event *e;
    
    if (bpf_probe_read_user(&family, sizeof(family), (void *)ctx->args[1]) < 0) {
        return 0;
    }

    if (family != AF_INET) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->event_type = EVENT_TYPE_CONNECT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    void *addr_ptr = (void *)ctx->args[1];
    bpf_probe_read_user(&e->net_info.dport, sizeof(e->net_info.dport), addr_ptr + 2);
    bpf_probe_read_user(&e->net_info.daddr, sizeof(e->net_info.daddr), addr_ptr + 4);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_clone")
int handle_clone(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    __u64 pid_tgid;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    // Get current process info
    pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    if (bpf_get_current_comm(&e->comm, sizeof(e->comm)) != 0) {
        e->comm[0] = '\0';
    }

    // Set parent process info
    e->ppid = pid_tgid & 0xFFFFFFFF; // Lower 32 bits contain TGID (thread group ID)
    __builtin_memset(e->parent_comm, 0, sizeof(e->parent_comm));

    e->event_type = EVENT_TYPE_FORK;
    e->process_info.clone_flags = (__u32)ctx->args[0];
    e->process_info.exit_signal = (__u32)(ctx->args[0] & 0xff);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_fork")
int handle_fork(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    __u64 pid_tgid;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    // Get current process info
    pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    if (bpf_get_current_comm(&e->comm, sizeof(e->comm)) != 0) {
        e->comm[0] = '\0';
    }

    // Set parent process info
    e->ppid = pid_tgid & 0xFFFFFFFF; // Lower 32 bits contain TGID (thread group ID)
    __builtin_memset(e->parent_comm, 0, sizeof(e->parent_comm));

    e->event_type = EVENT_TYPE_FORK;
    e->process_info.clone_flags = 0;
    e->process_info.exit_signal = 17; // SIGCHLD value

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_vfork")
int handle_vfork(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    __u64 pid_tgid;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    // Get current process info
    pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    if (bpf_get_current_comm(&e->comm, sizeof(e->comm)) != 0) {
        e->comm[0] = '\0';
    }

    // Set parent process info
    e->ppid = pid_tgid & 0xFFFFFFFF; // Lower 32 bits contain TGID (thread group ID)
    __builtin_memset(e->parent_comm, 0, sizeof(e->parent_comm));

    e->event_type = EVENT_TYPE_FORK;
    e->process_info.clone_flags = 0;
    e->process_info.exit_signal = 17; // SIGCHLD value

    bpf_ringbuf_submit(e, 0);
    return 0;
}
