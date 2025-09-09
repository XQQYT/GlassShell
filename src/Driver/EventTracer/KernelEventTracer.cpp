#include "GlassShell/Driver/EventTracer/KernelEventTracer.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#include <iostream>

std::unordered_map<uint32_t, std::function<void(KernelEventTracer::event_t)>>
    KernelEventTracer::s_pidCb;

struct config {
    pid_t target_pid;
};

KernelEventTracer::KernelEventTracer(uint32_t target_pid, uint32_t bind_pty_id,
                                     std::function<void(event_t)> hasEvent) {
    m_pid = target_pid;
    m_running = true;
    m_bindPtyId = bind_pty_id;
    s_pidCb.insert({m_pid, hasEvent});

    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    m_bpfObj = bpf_object__open_file("SyscallTrace.bpf.o", NULL);
    if (!m_bpfObj) {
        fprintf(stderr, "failed to open BPF object\n");
        return;
    }
    bpf_object__load(m_bpfObj);

    struct bpf_map *cfg_map =
        bpf_object__find_map_by_name(m_bpfObj, "config_map");
    if (!cfg_map) {
        fprintf(stderr, "failed to find config_map\n");
        return;
    }

    int cfg_fd = bpf_map__fd(cfg_map);
    int key = 0;
    struct config cfg = {.target_pid = static_cast<pid_t>(m_pid)};
    bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY);

    int pid_map_fd = bpf_object__find_map_fd_by_name(m_bpfObj, "pid_map");
    if (pid_map_fd < 0) {
        fprintf(stderr, "failed to find pid_map\n");
        return;
    }
    uint8_t one = 1;
    bpf_map_update_elem(pid_map_fd, &m_pid, &one, BPF_ANY);

    struct bpf_program *prog = NULL;
    bpf_object__for_each_program(prog, m_bpfObj) {
        const char *sec = bpf_program__section_name(prog);
        if (strcmp(sec, "tracepoint/raw_syscalls/sys_enter") == 0) {
            m_linkSysEnter = bpf_program__attach_tracepoint(
                prog, "raw_syscalls", "sys_enter");
            if (!m_linkSysEnter) {
                fprintf(stderr, "failed to attach sys_enter\n");
                return;
            }
        } else if (strcmp(sec, "tracepoint/sched/sched_process_fork") == 0) {
            m_linkFork = bpf_program__attach_tracepoint(prog, "sched",
                                                        "sched_process_fork");
            if (!m_linkFork) {
                fprintf(stderr, "failed to attach sched_process_fork\n");
                return;
            }
        } else if (strcmp(sec, "tracepoint/sched/sched_process_exit") == 0) {
            m_linkExit = bpf_program__attach_tracepoint(prog, "sched",
                                                        "sched_process_exit");
            if (!m_linkExit) {
                fprintf(stderr, "failed to attach sched_process_exit\n");
                return;
            }
        }
    }

    int ringbuf_map_fd = bpf_object__find_map_fd_by_name(m_bpfObj, "events");
    if (ringbuf_map_fd < 0) {
        fprintf(stderr, "failed to get ringbuf fd\n");
        return;
    }

    m_rb = ring_buffer__new(ringbuf_map_fd, handle_event, NULL, NULL);
    if (!m_rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        return;
    }

    m_readThread = std::thread(&KernelEventTracer::readEvent, this);
}

KernelEventTracer::~KernelEventTracer() {
    m_running = false;
    if (m_readThread.joinable()) {
        m_readThread.join();
    }
    ring_buffer__free(m_rb);
    bpf_link__destroy(m_linkSysEnter);
    bpf_link__destroy(m_linkFork);
    bpf_link__destroy(m_linkExit);
    bpf_object__close(m_bpfObj);

    s_pidCb.erase(m_pid);
}

int KernelEventTracer::handle_event(void *ctx, void *data, size_t data_sz) {
    struct event_t *e = (event_t *)data;
    if (s_pidCb.find(e->root_pid) != s_pidCb.end()) {
        s_pidCb[e->root_pid](*e);
    }
    return 0;
}

void KernelEventTracer::readEvent() {
    while (m_running) {
        err = ring_buffer__poll(m_rb, 100 /* ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
}
