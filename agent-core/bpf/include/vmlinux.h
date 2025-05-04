#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#include <linux/types.h>

// Basic types
typedef unsigned short umode_t;
typedef _Bool bool;
#define true 1
#define false 0

// Forward declarations
struct file_operations;
struct vfsmount;
struct super_block;
struct thread_struct;
struct mm_struct;
struct task_struct;

// List handling
struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

// Thread info
struct thread_struct {
    unsigned long sp;
    unsigned long ip;
};

// Memory management
struct mm_struct {
    unsigned long start_code;
    unsigned long end_code;
    unsigned long start_data;
    unsigned long end_data;
    unsigned long start_brk;
    unsigned long brk;
    unsigned long start_stack;
    unsigned long arg_start;
    unsigned long arg_end;
    unsigned long env_start;
    unsigned long env_end;
};

// Basic task_struct definition with fields we need
struct task_struct {
    volatile long state;
    void *stack;
    int flags;
    int on_cpu;
    struct thread_struct *thread;
    int pid;
    int tgid;
    struct task_struct *real_parent;
    struct task_struct *parent;
    struct list_head children;
    struct list_head sibling;
    struct mm_struct *mm;
    struct mm_struct *active_mm;
    char comm[16];
};

// File operation structures
struct inode {
    umode_t i_mode;
    unsigned long i_ino;
    struct super_block *i_sb;
};

struct dentry {
    struct inode *d_inode;
    char d_iname[32];
};

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};

struct file {
    struct path f_path;
    struct inode *f_inode;
    const struct file_operations *f_op;
    unsigned int f_flags;
};

// System call tracing structures
struct trace_event_raw_sys_enter {
    __u64 unused;
    long syscall_nr;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit {
    __u64 unused;
    long syscall_nr;
    long ret;
};

// Process forking structures
struct sched_process_fork_args {
    __u64 unused;
    char parent_comm[16];
    __s32 parent_pid;
    char child_comm[16];
    __s32 child_pid;
};

#endif /* __VMLINUX_H__ */