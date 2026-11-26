#ifndef __EVENT_HANDLING_H
#define __EVENT_HANDLING_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/types.h>
#include <linux/sched.h>  // For task_struct access

#include "../include/common.h"

// Helper to check rate limit for a PID
__always_inline static bool check_rate_limit(__u32 pid) {
    __u64 curr_time = bpf_ktime_get_ns();
    __u64 *last_time = bpf_map_lookup_elem(&rate_limit, &pid);
    __u64 zero = 0;

    if (!last_time) {
        bpf_map_update_elem(&rate_limit, &pid, &zero, BPF_NOEXIST);
        last_time = bpf_map_lookup_elem(&rate_limit, &pid);
        if (!last_time) {
            return false;
        }
    }

    if (curr_time - *last_time < RATE_LIMIT_INTERVAL / RATE_LIMIT_BURST) {
        return false;
    }

    *last_time = curr_time;
    return true;
}

// Only high-volume, low-risk lifecycle events may be rate limited. Security-sensitive events
// must always reach user space, even when they follow another event from the same PID.
__always_inline static bool should_rate_limit(__u32 event_type) {
    return event_type == EVENT_TYPE_FORK;
}

// Helper to initialize common event fields
__always_inline static void init_event(struct exec_monitor_event *e, __u32 type) {
    e->event_type = type;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->parent_pid = BPF_CORE_READ(task, real_parent, tgid);
    e->child_pid = 0;  // Will be set by specific handlers if needed
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Try to get container ID if available
    #ifdef CONFIG_CGROUPS
    unsigned long cgroup_id = bpf_get_current_cgroup_id();
    if (cgroup_id) {
        // Convert cgroup_id to string and store in container_id
        // This is a simplified version, actual implementation might need more logic
        __builtin_memset(e->container_id, 0, CONTAINER_ID_LEN);
        bpf_probe_read_str(e->container_id, CONTAINER_ID_LEN, (void *)&cgroup_id);
    }
    #endif
}

// The agent's own PID namespace and TGID within it, set by user space before load.
// The agent reads /proc for every event it enriches; without this filter those reads
// generate new events, which feed back into more reads and saturate the ring buffer.
const volatile __u64 self_pidns_dev = 0;
const volatile __u64 self_pidns_ino = 0;
const volatile __u32 self_tgid = 0;

// True when the current task belongs to the agent process (any of its threads).
// The helper only succeeds for tasks whose active PID namespace is the agent's, so
// TGIDs from other namespaces can never collide with self_tgid.
__always_inline static bool is_self(void) {
    struct bpf_pidns_info ns = {};

    if (self_tgid == 0) {
        return false;
    }
    if (bpf_get_ns_current_pid_tgid(self_pidns_dev, self_pidns_ino, &ns, sizeof(ns)) != 0) {
        return false;
    }
    return ns.tgid == self_tgid;
}

// Helper to submit an event
__always_inline static void submit_event(struct exec_monitor_event *e) {
    if (is_self()) {
        bpf_ringbuf_discard(e, 0);
        return;
    }
    if (should_rate_limit(e->event_type) && !check_rate_limit(e->pid)) {
        bpf_ringbuf_discard(e, 0);
        return;
    }
    bpf_ringbuf_submit(e, 0);
}

#endif /* __EVENT_HANDLING_H */
