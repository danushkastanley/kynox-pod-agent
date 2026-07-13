#ifndef __TYPES_H
#define __TYPES_H

#include <linux/types.h>

// Basic event structure
struct exec_monitor_event {
    __u32 event_type;
    __u32 pid;
    __u32 parent_pid;
    __u32 child_pid;
    char comm[TASK_COMM_LEN];
    char container_id[CONTAINER_ID_LEN];
    union {
        char filename[FILENAME_LEN];
        struct net_info {
            __u32 daddr;        // IPv4 address (network byte order)
            __u16 dport;        // Destination port (host byte order)
            __u16 family;       // Address family: AF_INET or AF_INET6
            __u8 daddr6[16];    // IPv6 address (128 bits)
        } net_info;
        struct ptrace_info {
            long request;
            __u32 target_pid;
        } ptrace_info;
        struct setuid_info {
            __u32 uid;
        } setuid_info;
        struct setgid_info {
            __u32 gid;
        } setgid_info;
        struct mount_info {
            char source[FS_INFO_LEN];
            char target[FS_INFO_LEN];
            char fstype[FS_INFO_LEN];
            unsigned long flags;
        } mount_info;
        struct umount_info {
            char target[FS_INFO_LEN];
            int flags;
        } umount_info;
        struct capset_info {
            __u32 cap;
            __u32 pid;
        } capset_info;
        struct bpf_program_info {
            __u32 cmd;
            __u32 prog_type;
            __u32 insn_cnt;
            __u32 license_len;
            char license[64];
        } bpf_prog_info;
        struct seccomp_info {
            __u32 operation;
            __u32 option;
            __u32 mode;
            __u32 flags;
        } seccomp_info;
        struct sock_info {
            __s32 domain;       // Socket domain (AF_INET, AF_INET6, etc.)
            __s32 type;         // Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
            __s32 protocol;     // Protocol (0 for default)
            __u32 sock_fd;      // Socket file descriptor
            __u32 addr;         // IPv4 address (network byte order)
            __u16 port;         // Port (host byte order)
            __u16 family;       // Address family: AF_INET or AF_INET6
            __u8 addr6[16];     // IPv6 address (128 bits)
        } sock_info;
        struct chmod_info {
            char path[FILENAME_LEN];
            __u32 mode;
        } chmod_info;
    };
};

#endif /* __TYPES_H */
