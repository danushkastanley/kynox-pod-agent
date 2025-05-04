#ifndef __FILE_HANDLER_H
#define __FILE_HANDLER_H

#include "../include/common.h"
#include "../core/event_handling.h"

// Common handler for file operations
__always_inline static int handle_file_event(struct trace_event_raw_sys_enter *ctx, const char* filename, __u32 event_type) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, event_type);
    
    if (bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_open")
int handle_open(struct trace_event_raw_sys_enter *ctx) {
    return handle_file_event(ctx, (const char *)ctx->args[0], EVENT_TYPE_OPEN);
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    return handle_file_event(ctx, (const char *)ctx->args[1], EVENT_TYPE_OPEN);
}

SEC("tp/syscalls/sys_enter_chmod")
int handle_chmod(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_CHMOD);
    
    if (bpf_probe_read_user_str(e->chmod_info.path, sizeof(e->chmod_info.path), (const void *)ctx->args[0]) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->chmod_info.mode = (__u32)ctx->args[1];
    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_fchmod")
int handle_fchmod(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;
    int fd = (int)ctx->args[0];
    char path[FILENAME_LEN];

    if (bpf_probe_read_kernel_str(path, sizeof(path), (void *)fd) < 0) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_CHMOD);
    bpf_probe_read_kernel_str(e->chmod_info.path, sizeof(e->chmod_info.path), path);
    e->chmod_info.mode = (__u32)ctx->args[1];
    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_fchmodat")
int handle_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_CHMOD);
    
    if (bpf_probe_read_user_str(e->chmod_info.path, sizeof(e->chmod_info.path), (const void *)ctx->args[1]) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->chmod_info.mode = (__u32)ctx->args[2];
    submit_event(e);
    return 0;
}

#endif /* __FILE_HANDLER_H */
