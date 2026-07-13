#ifndef __SECURITY_HANDLER_H
#define __SECURITY_HANDLER_H

#include <linux/capability.h>
#include "../include/common.h"
#include "../core/event_handling.h"

SEC("tp/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_PTRACE);
    e->ptrace_info.request = ctx->args[0];
    e->ptrace_info.target_pid = (__u32)ctx->args[1];

    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_SETUID);
    e->setuid_info.uid = (__u32)ctx->args[0];

    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_setgid")
int handle_setgid(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_SETGID);
    e->setgid_info.gid = (__u32)ctx->args[0];

    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_mount")
int handle_mount(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_MOUNT);

    // Read mount source
    if (bpf_probe_read_user_str(e->mount_info.source, sizeof(e->mount_info.source), (const void *)ctx->args[0]) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    // Read mount target
    if (bpf_probe_read_user_str(e->mount_info.target, sizeof(e->mount_info.target), (const void *)ctx->args[1]) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    // Read filesystem type
    if (bpf_probe_read_user_str(e->mount_info.fstype, sizeof(e->mount_info.fstype), (const void *)ctx->args[2]) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->mount_info.flags = ctx->args[3];
    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_capset")
int handle_capset(struct trace_event_raw_sys_enter *ctx) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_CAPSET);

    // Read capability data
    struct __user_cap_header_struct header;
    if (bpf_probe_read(&header, sizeof(header), (void *)ctx->args[0]) == 0) {
        e->capset_info.pid = header.pid;
    }

    struct __user_cap_data_struct cap_data;
    if (bpf_probe_read(&cap_data, sizeof(cap_data), (void *)ctx->args[1]) == 0) {
        e->capset_info.cap = cap_data.effective;
    }

    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_prctl")
int handle_prctl(struct trace_event_raw_sys_enter *ctx) {
    long option = (long)ctx->args[0];
    if (option != PR_SET_SECCOMP && option != PR_GET_SECCOMP) {
        return 0;
    }

    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_SECCOMP);
    e->seccomp_info.operation = SECCOMP_PRCTL;
    e->seccomp_info.option = option;

    unsigned long mode = ctx->args[1];
    if (mode == SECCOMP_MODE_FILTER) {
        e->seccomp_info.mode = SECCOMP_MODE_FILTER;
    } else if (mode == SECCOMP_MODE_STRICT) {
        e->seccomp_info.mode = SECCOMP_MODE_STRICT;
    } else {
        e->seccomp_info.mode = 0;
    }

    e->seccomp_info.flags = (__u32)ctx->args[2];
    submit_event(e);
    return 0;
}

SEC("tp/syscalls/sys_enter_seccomp")
int handle_seccomp(struct trace_event_raw_sys_enter *ctx) {
    unsigned long operation = ctx->args[0];
    if (operation != SECCOMP_SET_MODE_FILTER && operation != SECCOMP_SET_MODE_STRICT) {
        return 0;
    }

    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_SECCOMP);
    e->seccomp_info.operation = SECCOMP_SYSCALL;
    e->seccomp_info.option = operation;

    if (operation == SECCOMP_SET_MODE_FILTER) {
        e->seccomp_info.mode = SECCOMP_MODE_FILTER;
    } else if (operation == SECCOMP_SET_MODE_STRICT) {
        e->seccomp_info.mode = SECCOMP_MODE_STRICT;
    } else {
        e->seccomp_info.mode = 0;
    }

    e->seccomp_info.flags = (__u32)ctx->args[1];
    submit_event(e);
    return 0;
}

#endif /* __SECURITY_HANDLER_H */
