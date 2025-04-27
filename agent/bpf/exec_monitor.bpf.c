// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Define constants that might not be in vmlinux.h
#define TASK_COMM_LEN 16
#define AF_INET 2
#define FILENAME_LEN 256

// Define the GPL license
char LICENSE[] SEC("license") = "GPL";

#define EVENT_TYPE_EXEC 0
#define EVENT_TYPE_OPEN 1
#define EVENT_TYPE_CONNECT 2 // New event type for connect

struct event {
    __u32 event_type; // 0 for exec, 1 for open/openat, 2 for connect
    __u32 pid;
    char comm[TASK_COMM_LEN];
    union { // Use a union as filename isn't relevant for connect
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
    // The filename is the first argument for open
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
    // The filename is the second argument for openat
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Handler for connect syscall
SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    __u16 family;
    struct event *e;
    
    // Read the address family first (first 2 bytes of sockaddr)
    if (bpf_probe_read_user(&family, sizeof(family), (void *)ctx->args[1]) < 0) {
        return 0; // Failed to read family
    }

    // Only handle IPv4 for now
    if (family != AF_INET) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->event_type = EVENT_TYPE_CONNECT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read IPv4 address and port (offset by 2 bytes from family)
    // sockaddr_in structure: { u16 family; u16 port; u32 addr; u8 zero[8]; }
    void *addr_ptr = (void *)ctx->args[1];
    bpf_probe_read_user(&e->net_info.dport, sizeof(e->net_info.dport), addr_ptr + 2);  // port at offset 2
    bpf_probe_read_user(&e->net_info.daddr, sizeof(e->net_info.daddr), addr_ptr + 4);  // addr at offset 4

    // No need for endian conversion here as we want network byte order
    // The userspace code will handle the conversion

    bpf_ringbuf_submit(e, 0);
    return 0;
}
