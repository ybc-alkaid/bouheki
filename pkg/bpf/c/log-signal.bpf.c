
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tracepoint/syscalls/sys_enter_kill")
int sys_enter_kill(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (u32)(pid_tgid >> 32);  // Get the process ID

    // Print a simple hello world message with the PID
    bpf_printk("Hello World! Kill syscall called by PID: %u\n", pid);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
