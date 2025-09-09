
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "sGPL";

enum event_type {
    EVENT_SYSCALL,
    EVENT_FORK,
    EVENT_EXIT,
};

struct event_t {
    u32 pid;
    u32 root_pid;
    u64 syscall_id;  // only valid if EVENT_SYSCALL
    char comm[16];
    enum event_type type;
};

struct config {
    pid_t target_pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 ppid = ctx->parent_pid;
    u32 cpid = ctx->child_pid;
    u32 key = 0;

    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg) return 0;

    if (ppid == cfg->target_pid || bpf_map_lookup_elem(&pid_map, &ppid)) {
        u8 one = 1;

        if (ppid == cfg->target_pid)
            bpf_map_update_elem(&pid_map, &ppid, &one, BPF_NOEXIST);

        bpf_map_update_elem(&pid_map, &cpid, &one, BPF_ANY);

        struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = cpid;
            e->root_pid = cfg->target_pid;
            e->type = EVENT_FORK;
            e->syscall_id = 0;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
    }

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&pid_map, &pid)) {
        return 0;
    }

    u8 *track = bpf_map_lookup_elem(&pid_map, &pid);
    if (!track) return 0;

    u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->root_pid = cfg->target_pid;
    e->syscall_id = ctx->id;
    e->type = EVENT_SYSCALL;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&pid_map, &pid)) {
        return 0;
    }
    bpf_map_delete_elem(&pid_map, &pid);

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        u32 key = 0;
        struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
        if (!cfg) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }

        e->pid = pid;
        e->root_pid = cfg->target_pid;
        e->type = EVENT_EXIT;
        e->syscall_id = 0;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}
