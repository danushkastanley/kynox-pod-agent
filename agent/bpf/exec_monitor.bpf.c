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

// Define tracing structures if not fully available via vmlinux.h/BTF
#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long syscall_nr;
    unsigned long args[6];
};

// Define sched_process_fork tracepoint arguments structure
struct sched_process_fork_args {
    unsigned long long unused;
    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};
#endif

// Define constants that might not be in vmlinux.h
#define TASK_COMM_LEN 16
#define AF_INET 2        // Typically defined in linux/socket.h or linux/in.h
#define FILENAME_LEN 256

// Define the GPL license
char LICENSE[] SEC("license") = "GPL";

#define EVENT_TYPE_EXEC 0
#define EVENT_TYPE_OPEN 1
#define EVENT_TYPE_CONNECT 2
#define EVENT_TYPE_FORK 3 // New event type for fork/clone

struct event {
    __u32 event_type; // 0:exec, 1:open/openat, 2:connect, 3:fork/clone
    __u32 pid;        // PID of the process triggering the event
    __u32 parent_pid; // Parent PID (for fork events)
    __u32 child_pid;  // Child PID (for fork events)
    char comm[TASK_COMM_LEN];
    union { // Use a union as filename/net_info aren't relevant for all events
        char filename[FILENAME_LEN];
        struct {
            __u32 daddr; // Destination IPv4 address (network byte order)
            __u16 dport; // Destination port (network byte order)
        } net_info;
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

// Helper to submit an event
static __always_inline void submit_event(struct event *e) {
    bpf_ringbuf_submit(e, 0);
}

// Helper to initialize common event fields
static __always_inline void init_event(struct event *e, __u32 type) {
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
    struct event *e;
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
     struct event *e;
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
     struct event *e;
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
     struct event *e;
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
    struct event *e;

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
    struct event *e;

    // Extract parent and child PIDs from the context
    pid_t parent_pid = ctx->parent_pid;
    pid_t child_pid = ctx->child_pid;

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
