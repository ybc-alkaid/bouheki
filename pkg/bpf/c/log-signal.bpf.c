
#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#define MAX_ENTRIES 10240
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
    if (*sigtype == cb_ctx->sigtype) {
        cb_ctx->found = true;
        return 1;
    }
    return 0;
}
static u64 cb_print_map_elem(void *map, void *key, void *value, void *ctx) {
    int *k = (int *)key;
    int *v = (int *)value;
    bpf_printk("Map Element - Key: %d, Value: %d\n", *k, *v);
    return 0;
}

static int probe_entry(void *ctx, pid_t tpid, int sig) {
  struct event event = {};
  __u64 pid_tgid;
  __u32 tid;
  int ret = -1;
  struct signallog_bouheki_config *config = (struct signallog_bouheki_config *)bpf_map_lookup_elem(&signallog_bouheki_config_map, 0);

  pid_tgid = bpf_get_current_pid_tgid();
  tid = (__u32)pid_tgid;
  event.pid = pid_tgid >> 32;
  event.tpid = tpid;
  event.sig = sig;
  if (sig ==
      0) { // ignore signal 0 which is used for testing existence of a process
    return 0;
  }
  bpf_get_current_comm(event.comm, sizeof(event.comm));

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
  if (config && config->mode == MODE_MONITOR) {
        ret = 0;
    }
  event.ret = ret;
    bpf_printk("Returning %d\n", event.ret);
  bpf_perf_event_output((void *)ctx, &signal_events, BPF_F_CURRENT_CPU, &event,
                        sizeof(event));

  return ret;
}

static int probe_exit(void *ctx, int ret) {
  // TODO - whatst the need of this function?
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tid = (__u32)pid_tgid;
  struct event *eventp;

  //  eventp = bpf_map_lookup_elem(&signal_events, &tid);
  if (!eventp)
    return 0;

  eventp->ret = ret;

  //  bpf_printk("PID %d (%s) sent signal %d ",
  //            eventp->pid, eventp->comm, eventp->sig);
  //  bpf_printk("to PID %d, ret = %d",
  //            eventp->tpid, ret);

cleanup:
  //  bpf_map_delete_elem(&signal_events, &tid);
  return ret;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx) {
  // sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_kill/format
  pid_t tpid = (pid_t)ctx->args[0];
  int sig = (int)ctx->args[1];

  return probe_entry(ctx, tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx) {
  return probe_exit(ctx, ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";