#ifndef __CONSTANTS_H
#define __CONSTANTS_H

// Basic size constants
#define TASK_COMM_LEN 16
#define FILENAME_LEN 256
#define FS_INFO_LEN 128
#define CONTAINER_ID_LEN 64

// Event type constants
#define EVENT_TYPE_EXEC 0
#define EVENT_TYPE_OPEN 1
#define EVENT_TYPE_CONNECT 2
#define EVENT_TYPE_FORK 3
#define EVENT_TYPE_PTRACE 4
#define EVENT_TYPE_SETUID 5
#define EVENT_TYPE_SETGID 6
#define EVENT_TYPE_MOUNT 7
#define EVENT_TYPE_UMOUNT 8
#define EVENT_TYPE_CAPSET 9
#define EVENT_TYPE_BPF_PROG 10
#define EVENT_TYPE_SECCOMP 11
#define EVENT_TYPE_SOCKET 12
#define EVENT_TYPE_BIND 13
#define EVENT_TYPE_ACCEPT 14
#define EVENT_TYPE_CHMOD 16

// Seccomp operation types
#define SECCOMP_PRCTL 1
#define SECCOMP_SYSCALL 2

// Seccomp-related constants
#define PR_SET_SECCOMP 22
#define PR_GET_SECCOMP 21
#define SECCOMP_MODE_STRICT 1
#define SECCOMP_MODE_FILTER 2
#define SECCOMP_SET_MODE_STRICT 0
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_GET_ACTION_AVAIL 2

// Network-related constants
#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3

// Rate limiting settings
#define RATE_LIMIT_INTERVAL 1000000000ULL  // 1 second in nanoseconds
#define RATE_LIMIT_BURST 100               // Maximum events per interval

#endif /* __CONSTANTS_H */
