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

// Process fork handler. The BTF-typed tracepoint receives the parent and child
// task_struct pointers, so it does not depend on the raw tracepoint record layout,
// which changed in newer kernels (comm fields became variable-length strings).
SEC("tp_btf/sched_process_fork")
int BPF_PROG(handle_fork, struct task_struct *parent, struct task_struct *child) {
    struct exec_monitor_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    init_event(e, EVENT_TYPE_FORK);
    e->parent_pid = BPF_CORE_READ(parent, pid);
    e->child_pid = BPF_CORE_READ(child, pid);
    BPF_CORE_READ_STR_INTO(&e->comm, parent, comm);

    submit_event(e);
    return 0;
}
