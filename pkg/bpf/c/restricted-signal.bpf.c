
#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#define TASK_COMM_LEN 16

struct event {
  unsigned int pid;
  unsigned int tpid;
  int sig;
  int ret;
  char comm[TASK_COMM_LEN];
};

struct signallog_bouheki_config {
  u32 mode;
  u32 target;
};
struct callback_ctx {
  int sigtype;
  bool found;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} signal_events SEC(".maps");

BPF_HASH(signallog_bouheki_config_map, u32, struct signallog_bouheki_config,
         256);
BPF_HASH(allowed_types_signals, u32, int, 256);
BPF_HASH(denied_types_signals, u32, int, 256);

static u64 cb_check_path(void *map, void *key, void *value, void *ctx) {
  struct callback_ctx *cb_ctx = (struct callback_ctx *)ctx;
  int *sigtype = (int *)value;
  // bpf_printk("Checking %d\n vs %d\n", *sigtype, cb_ctx->sigtype);
  if (*sigtype == cb_ctx->sigtype ||
      *sigtype == 42) { // "*" charecter detected (TODO - maybe confuse with
                        // real-time signal 42)
    cb_ctx->found = true;
    return 1;
  }
  return 0;
}

SEC("lsm/task_kill")
int BPF_PROG(block_signal, struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred) {

  struct event event = {};
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  event.pid = pid_tgid >> 32;
  event.tpid = p->pid;
  event.sig = sig;

  __u32 tid;
  int ret = -1;
  int index = 0;
  struct signallog_bouheki_config *config =
      (struct signallog_bouheki_config *)bpf_map_lookup_elem(
          &signallog_bouheki_config_map, &index);


  if (sig ==0) { // ignore signal 0 which is used for testing existence of a process
    return 0;
  }

   if (info == (void *)1) {
        // Permit the signal if it is coming from the kernel
        // see task_kill here for more https://www.kernel.org/doc/html/v5.2/security/LSM.html
        return 0;
    }

  bpf_get_current_comm(event.comm, sizeof(event.comm));
// Debugging print statements
    bpf_printk("Got signal %d from PID %d to PID %d\n", sig, event.pid, event.tpid);
    bpf_printk("Checking denied signals\n");
  // Print all elements in the denied_types_signals map
  // bpf_for_each_map_elem(&denied_types_signals, cb_print_map_elem, NULL, 0);

  struct callback_ctx cb = {.sigtype = event.sig, .found = false};
  cb.found = false;
  bpf_for_each_map_elem(&denied_types_signals, cb_check_path, &cb, 0);
  if (cb.found) {
    bpf_printk("Access Denied: %s\n", cb.sigtype);
    ret = -EPERM;
    goto out;
  }

  bpf_for_each_map_elem(&allowed_types_signals, cb_check_path, &cb, 0);
  if (cb.found) {
    ret = 0;
    goto out;
  }

out:
  event.ret = ret;
  if (config && config->mode == MODE_MONITOR) {
        ret = 0;
    }
  bpf_perf_event_output((void *)ctx, &signal_events, BPF_F_CURRENT_CPU, &event,
                        sizeof(event));
  bpf_printk("Returning %d\n", event.ret);
  return ret;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
