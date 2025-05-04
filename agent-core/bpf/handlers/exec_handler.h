#ifndef __EXEC_HANDLER_H
#define __EXEC_HANDLER_H

#include "../include/common.h"
#include "../core/event_handling.h"

// Common handler for exec events
__always_inline static int handle_exec_event(struct trace_event_raw_sys_enter *ctx, const char* filename) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_EXEC);
    
    if (bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    return handle_exec_event(ctx, (const char *)ctx->args[0]);
}

SEC("tp/syscalls/sys_enter_execveat")
int handle_execveat(struct trace_event_raw_sys_enter *ctx) {
    return handle_exec_event(ctx, (const char *)ctx->args[1]);
}

#endif /* __EXEC_HANDLER_H */
