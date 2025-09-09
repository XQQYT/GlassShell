#pragma once

#include <stdint.h>

#include <functional>
#include <thread>
#include <unordered_map>

class KernelEventTracer {
   public:
    enum event_type {
        EVENT_SYSCALL,
        EVENT_FORK,
        EVENT_EXIT,
    };

    struct event_t {
        uint32_t pid;
        uint32_t root_pid;
        uint64_t syscall_id;  // only valid if EVENT_SYSCALL
        char comm[16];
        enum event_type type;
    };

   public:
    KernelEventTracer(uint32_t target_pid, uint32_t bind_pty_id,
                      std::function<void(event_t)> hasEvent);
    ~KernelEventTracer();

   private:
    static int handle_event(void *ctx, void *data, size_t data_sz);
    void readEvent();

   private:
    static std::unordered_map<uint32_t, std::function<void(event_t)>> s_pidCb;
    uint32_t m_pid;
    uint32_t m_bindPtyId;
    volatile bool m_running;
    std::thread m_readThread;

    struct bpf_object *m_bpfObj;
    struct bpf_link *m_linkSysEnter;
    struct bpf_link *m_linkFork;
    struct bpf_link *m_linkExit;
    struct ring_buffer *m_rb;
    int err;
};