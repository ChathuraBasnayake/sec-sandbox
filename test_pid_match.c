#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    const char *filename = (const char *)ctx->args[0];
    
    char buf[32];
    bpf_probe_read_user_str(buf, sizeof(buf), filename);
    
    bpf_printk("EXECVE PID=%d filename=%s\n", pid, buf);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
