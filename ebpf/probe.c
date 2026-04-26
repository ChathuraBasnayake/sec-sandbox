// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// probe.c — eBPF kernel sensor for npm-detonator
//
// Hooks two kernel tracepoints to monitor container behavior:
//   - syscalls/sys_enter_execve  → catches process execution
//   - syscalls/sys_enter_openat  → catches file access
//
// Events are pushed to a BPF ring buffer for the Go userspace loader to consume.
//
// Filtering strategy:
// On Docker Desktop WSL2, the PIDs reported by Docker don't match host PIDs.
// Instead, we use a hash set of allowed PIDs that the Go loader populates
// by scanning /proc for processes belonging to the target container.

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Event types
#define EVENT_EXECVE  1
#define EVENT_OPENAT  2
#define EVENT_CONNECT 3
#define EVENT_WRITE   4
#define EVENT_UNLINK  5

// Max filename length we capture
#define MAX_FILENAME_LEN 256
#define TASK_COMM_LEN    16

// Event structure pushed to ring buffer — must match Go struct exactly.
struct event {
    __u32 pid;                        // Process ID (host PID)
    __u32 ppid;                       // Parent Process ID
    __u64 timestamp_ns;               // Kernel timestamp (nanoseconds)
    __u32 event_type;                 // EVENT_EXECVE, EVENT_OPENAT, EVENT_CONNECT, EVENT_WRITE, EVENT_UNLINK
    char  comm[TASK_COMM_LEN];        // Process name (e.g., "node", "sh")
    char  filename[MAX_FILENAME_LEN]; // File being opened/executed (or IP for connect)
    __u32 connect_port;               // Destination port (EVENT_CONNECT only)
    __u32 connect_ip;                 // Destination IPv4 addr (EVENT_CONNECT only)
    __u64 write_bytes;                // Number of bytes written (EVENT_WRITE only)
    __s32 write_fd;                   // File descriptor (EVENT_WRITE only)
};

// Ring buffer map — 16MB, shared between both tracepoints.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

// Hash set of allowed PIDs.
// Key: __u32 = host PID
// Value: __u8 = 1 (just a marker)
// The Go loader populates this by scanning /proc for container processes.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);     // Up to 4096 concurrent container PIDs
    __type(key, __u32);
    __type(value, __u8);
} allowed_pids SEC(".maps");

// Check if the current process belongs to our target container.
// Simple O(1) hash lookup — no tree walking needed.
static __always_inline int is_target_process(void) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *allowed = bpf_map_lookup_elem(&allowed_pids, &pid);
    return allowed != NULL;
}

// Fill common event fields.
static __always_inline void fill_event_common(struct event *e, __u32 event_type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = event_type;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// ────────────────────────────────────────────────────────────────────
// Tracepoint: sched_process_fork
// Fires when a process forks/clones. Automatically tracks child PIDs.
// ────────────────────────────────────────────────────────────────────
SEC("tracepoint/sched/sched_process_fork")
int handle_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;
    
    __u8 *allowed = bpf_map_lookup_elem(&allowed_pids, &parent_pid);
    if (allowed) {
        __u8 marker = 1;
        bpf_map_update_elem(&allowed_pids, &child_pid, &marker, BPF_ANY);
    }
    return 0;
}

// ────────────────────────────────────────────────────────────────────
// Tracepoint: sys_enter_execve
// Fires when any process calls execve() — e.g., running "sh", "curl", "wget"
// ────────────────────────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    // execve args: args[0] = filename (const char __user *)
    const char *filename_ptr = (const char *)ctx->args[0];
    char buf[MAX_FILENAME_LEN] = {};
    bpf_probe_read_user_str(buf, sizeof(buf), filename_ptr);

    // Check for the magic marker file
    const char target[13] = "/tmp/DT_INIT";
    int match = 1;
    #pragma unroll
    for (int i=0; i<13; i++) {
        if (buf[i] != target[i]) {
            match = 0;
            break;
        }
    }

    if (match) {
        // MAGIC MARKER DETECTED!
        // This process is /tmp/DT_INIT, so its parent is the container init process (sh)!
        // We add the parent process to allowed_pids.
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
        
        __u8 marker = 1;
        bpf_map_update_elem(&allowed_pids, &ppid, &marker, BPF_ANY);
        bpf_printk("NPM-DETONATOR: Executed magic marker! Added PPID %d to map.\n", ppid);
    }

    if (!is_target_process())
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    fill_event_common(e, EVENT_EXECVE);

    #pragma unroll
    for (int i=0; i<MAX_FILENAME_LEN; i++) {
        e->filename[i] = buf[i];
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ────────────────────────────────────────────────────────────────────
// Tracepoint: sys_enter_openat
// Fires when any process opens a file — e.g., reading SSH keys, /etc/shadow
// ────────────────────────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    if (!is_target_process())
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    fill_event_common(e, EVENT_OPENAT);

    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ────────────────────────────────────────────────────────────────────
// Tracepoint: sys_enter_open
// Fires for legacy open() calls (common in some libcs like musl)
// ────────────────────────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_open")
int handle_open(struct trace_event_raw_sys_enter *ctx) {
    if (!is_target_process())
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    fill_event_common(e, EVENT_OPENAT);

    // open args: args[0] = filename
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ────────────────────────────────────────────────────────────────────
// Tracepoint: sys_enter_connect
// Fires when a process connects to a remote socket — catches C2 callbacks,
// data exfiltration, DNS resolution attempts.
// ────────────────────────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    if (!is_target_process())
        return 0;

    // connect args: args[1] = struct sockaddr __user *uservaddr
    //               args[2] = int addrlen
    struct sockaddr_in sa = {};
    const void *addr_ptr = (const void *)ctx->args[1];
    int addrlen = (int)ctx->args[2];

    // Only capture IPv4 connections (sa_family == AF_INET == 2)
    if (addrlen < (int)sizeof(struct sockaddr_in))
        return 0;

    bpf_probe_read_user(&sa, sizeof(sa), addr_ptr);
    if (sa.sin_family != 2) // AF_INET
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    fill_event_common(e, EVENT_CONNECT);
    e->connect_ip = sa.sin_addr.s_addr;        // Network byte order
    e->connect_port = __builtin_bswap16(sa.sin_port); // Convert to host byte order

    // Format IP as string in filename for easy display
    unsigned char *ip = (unsigned char *)&sa.sin_addr.s_addr;
    // We can't use snprintf in BPF, so store raw IP — Go will format it
    e->filename[0] = ip[0];
    e->filename[1] = '.';
    e->filename[2] = ip[1];
    e->filename[3] = '.';
    e->filename[4] = ip[2];
    e->filename[5] = '.';
    e->filename[6] = ip[3];
    e->filename[7] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ────────────────────────────────────────────────────────────────────
// Tracepoint: sys_enter_write
// Fires when a process writes data. We only emit events for writes to
// file descriptors > 2 (skip stdin/stdout/stderr) to reduce noise.
// ────────────────────────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx) {
    if (!is_target_process())
        return 0;

    // write args: args[0] = fd, args[1] = buf, args[2] = count
    int fd = (int)ctx->args[0];
    __u64 count = (__u64)ctx->args[2];

    // Skip stdout(1), stderr(2) — too noisy
    if (fd <= 2)
        return 0;

    // Only capture "interesting" writes (> 0 bytes)
    if (count == 0)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    fill_event_common(e, EVENT_WRITE);
    e->write_fd = fd;
    e->write_bytes = count;

    // Read the path from /proc/self/fd/N via the task's file descriptor table
    // This is expensive in BPF so we just record the fd number.
    // The Go userspace can resolve fd -> path if needed.
    e->filename[0] = 0; // Will be filled by Go if needed

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ────────────────────────────────────────────────────────────────────
// Tracepoint: sys_enter_unlinkat
// Fires when a process deletes a file. Catches anti-forensics behavior
// (deleting payload after execution, clearing logs).
// ────────────────────────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    if (!is_target_process())
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    fill_event_common(e, EVENT_UNLINK);

    // unlinkat args: args[1] = const char __user *pathname
    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

// Force BTF type emission for bpf2go -type event.
// Without this, the compiler may optimize away the struct type info.
const struct event *unused_event __attribute__((unused));
