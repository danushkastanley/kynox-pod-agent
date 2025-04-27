// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h> // Include this for kernel types and constants like AF_INET
#include <linux/types.h>  // For __u32, __u64 etc.
#include <linux/socket.h> // For AF_INET (kernel version)
// #include <sys/socket.h> // Removed: Use definition from vmlinux.h
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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
        char filename[256];
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
    struct sockaddr *user_addr_ptr = (struct sockaddr *)ctx->args[1];
    struct sockaddr_in addr = {};
    struct event *e;
    __u16 family;

    // Read the address family first
    if (bpf_probe_read_user(&family, sizeof(family), &user_addr_ptr->sa_family) < 0) {
        return 0; // Failed to read family
    }

    // Only handle IPv4 for now
    if (family != AF_INET) {
        return 0;
    }

    // Read the full sockaddr_in struct for IPv4
    if (bpf_probe_read_user(&addr, sizeof(addr), user_addr_ptr) < 0) {
        return 0; // Failed to read address struct
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->event_type = EVENT_TYPE_CONNECT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->net_info.daddr = addr.sin_addr.s_addr; // Network byte order
    e->net_info.dport = addr.sin_port;         // Network byte order
    // Clear filename field for safety (optional, as it's a union)
    // bpf_probe_read_kernel_str(&e->filename, 1, ""); 

    bpf_ringbuf_submit(e, 0);
    return 0;
}
