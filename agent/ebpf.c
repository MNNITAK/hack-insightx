// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

struct event_t {
    __u32 pid;
    __u32 tid;
    char comm[TASK_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 type;
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct event_t *event;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->type = 0;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    event->saddr = 0;
    event->daddr = 0;
    event->sport = 0;
    event->dport = 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int trace_tcp_accept(struct pt_regs *ctx)
{
    struct event_t *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->type = 1;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    event->saddr = 0;
    event->daddr = 0;
    event->sport = 0;
    event->dport = 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
