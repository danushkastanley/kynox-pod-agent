#ifndef __COMMON_H
#define __COMMON_H

#include <vmlinux.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/bpf.h>

#include "constants.h"
#include "types.h"

// Ring buffer map for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Rate limiting map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} rate_limit SEC(".maps");

#endif /* __COMMON_H */
