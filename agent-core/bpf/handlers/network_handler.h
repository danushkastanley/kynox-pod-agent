#ifndef __NETWORK_HANDLER_H
#define __NETWORK_HANDLER_H

#include "../include/common.h"
#include "../core/event_handling.h"

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;
    struct sockaddr_in addr;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_CONNECT);
    
    if (bpf_probe_read(&addr, sizeof(addr), (void *)ctx->args[1]) == 0) {
        e->net_info.daddr = addr.sin_addr.s_addr;
        e->net_info.dport = bpf_ntohs(addr.sin_port);
    }

    submit_event(e);
    return 0;
}

// Common handler for socket events
__always_inline static int handle_socket_event(struct trace_event_raw_sys_enter *ctx, __u32 type) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, type);
    e->sock_info.sock_fd = (int)ctx->args[0];
    e->sock_info.addr = 0;  // Will be filled by kernel during accept
    e->sock_info.port = 0;  // Will be filled by kernel during accept

    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_socket")
int handle_socket(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_SOCKET);
    
    e->sock_info.domain = (int)ctx->args[0];
    e->sock_info.type = (int)ctx->args[1];
    e->sock_info.protocol = (int)ctx->args[2];

    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_bind")
int handle_bind(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_BIND);
    
    e->sock_info.sock_fd = (int)ctx->args[0];

    struct sockaddr_in addr;
    if (bpf_probe_read(&addr, sizeof(addr), (void *)ctx->args[1]) == 0) {
        e->sock_info.port = bpf_ntohs(addr.sin_port);
        e->sock_info.addr = addr.sin_addr.s_addr;
    }

    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_accept")
int handle_accept(struct trace_event_raw_sys_enter *ctx) {
    return handle_socket_event(ctx, EVENT_TYPE_ACCEPT);
}

SEC("tp/syscalls/sys_enter_accept4")
int handle_accept4(struct trace_event_raw_sys_enter *ctx) {
    return handle_socket_event(ctx, EVENT_TYPE_ACCEPT);
}

#endif /* __NETWORK_HANDLER_H */
