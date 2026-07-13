#ifndef __NETWORK_HANDLER_H
#define __NETWORK_HANDLER_H

#include "../include/common.h"
#include "../core/event_handling.h"

// sockaddr_in6 structure for IPv6
struct sockaddr_in6 {
    __u16 sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    __u8  sin6_addr[16];
    __u32 sin6_scope_id;
};

// Generic sockaddr to read family first
struct sockaddr_generic {
    __u16 sa_family;
};

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;
    struct sockaddr_generic sa_gen;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_CONNECT);

    // First read the address family
    if (bpf_probe_read(&sa_gen, sizeof(sa_gen), (void *)ctx->args[1]) != 0) {
        submit_event(e);
        return 0;
    }

    e->net_info.family = sa_gen.sa_family;

    if (sa_gen.sa_family == AF_INET) {
        // IPv4 address
        struct sockaddr_in addr4;
        if (bpf_probe_read(&addr4, sizeof(addr4), (void *)ctx->args[1]) == 0) {
            e->net_info.daddr = addr4.sin_addr.s_addr;
            e->net_info.dport = bpf_ntohs(addr4.sin_port);
        }
    } else if (sa_gen.sa_family == AF_INET6) {
        // IPv6 address
        struct sockaddr_in6 addr6;
        if (bpf_probe_read(&addr6, sizeof(addr6), (void *)ctx->args[1]) == 0) {
            e->net_info.dport = bpf_ntohs(addr6.sin6_port);
            // Copy IPv6 address bytes
            #pragma unroll
            for (int i = 0; i < 16; i++) {
                e->net_info.daddr6[i] = addr6.sin6_addr[i];
            }
        }
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
    struct sockaddr_generic sa_gen;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_BIND);
    e->sock_info.sock_fd = (int)ctx->args[0];

    // First read the address family
    if (bpf_probe_read(&sa_gen, sizeof(sa_gen), (void *)ctx->args[1]) != 0) {
        submit_event(e);
        return 0;
    }

    e->sock_info.family = sa_gen.sa_family;

    if (sa_gen.sa_family == AF_INET) {
        // IPv4 address
        struct sockaddr_in addr4;
        if (bpf_probe_read(&addr4, sizeof(addr4), (void *)ctx->args[1]) == 0) {
            e->sock_info.port = bpf_ntohs(addr4.sin_port);
            e->sock_info.addr = addr4.sin_addr.s_addr;
        }
    } else if (sa_gen.sa_family == AF_INET6) {
        // IPv6 address
        struct sockaddr_in6 addr6;
        if (bpf_probe_read(&addr6, sizeof(addr6), (void *)ctx->args[1]) == 0) {
            e->sock_info.port = bpf_ntohs(addr6.sin6_port);
            // Copy IPv6 address bytes
            #pragma unroll
            for (int i = 0; i < 16; i++) {
                e->sock_info.addr6[i] = addr6.sin6_addr[i];
            }
        }
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
