// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "include/common.h"
#include "include/constants.h"
#include "include/types.h"
#include "core/event_handling.h"
#include "handlers/exec_handler.h"
#include "handlers/file_handler.h"
#include "handlers/network_handler.h"
#include "handlers/security_handler.h"

char LICENSE[] SEC("license") = "GPL";

// Process fork handler
SEC("tp/sched/sched_process_fork")
int handle_fork(struct sched_process_fork_args *ctx) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_FORK);
    e->parent_pid = ctx->parent_pid;
    e->child_pid = ctx->child_pid;

    // Copy parent and child comm
    bpf_probe_read_str(e->comm, sizeof(e->comm), ctx->parent_comm);

    submit_event(e);
    return 0;
}
