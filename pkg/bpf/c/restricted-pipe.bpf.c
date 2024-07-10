
#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>
#include <linux/errno.h>

#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
  unsigned int pid;
  unsigned int tpid;
  int sig;
  int ret;
  char comm[TASK_COMM_LEN];
};

struct pipe_bouheki_config {
  u32 mode;
  u32 target;
};
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} signal_events SEC(".maps");

BPF_HASH(pipe_bouheki_config_map, u32, struct pipe_bouheki_config, 256);

SEC("lsm/inode_create")
int BPF_PROG(restricted_pipe, struct inode *inode, struct dentry *dentry,
             umode_t mode) {
  int ret = -1;
  int index = 0;
  struct pipe_bouheki_config *config =
      (struct pipe_bouheki_config *)bpf_map_lookup_elem(
          &pipe_bouheki_config_map, &index);
  if (S_ISFIFO(mode)) {
    struct task_struct *current_task;
    struct uts_namespace *uts_ns;
    struct mnt_namespace *mnt_ns;
    struct nsproxy *nsproxy;

    current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);

    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (config->mode == MODE_BLOCK) {
      ret = -EPERM;
      bpf_printk("Pipe Denied : %d", pid);
      goto out;
    }
  }
  
out:

  if (config && config->mode == MODE_MONITOR) {
    ret = 0;
  }
  return ret;
}