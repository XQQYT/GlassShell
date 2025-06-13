// opensnoop.c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>

static volatile bool exiting = false;

struct syscall_args_event {
    uint32_t pid;
    uint64_t syscall_id;
    uint64_t args[6];
    char comm[16];
};

struct config {
    pid_t target_pid;
};

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct syscall_args_event *e = (struct syscall_args_event*)data;

    printf("PID %d (%s) syscall %llu\n", e->pid, e->comm, e->syscall_id);
    // printf("  args: %llx %llx %llx %llx %llx %llx\n",
    //        e->args[0], e->args[1], e->args[2],
    //        e->args[3], e->args[4], e->args[5]);

    return 0;
}

static void sig_handler(int signo) {
    exiting = true;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);

    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    obj = bpf_object__open_file("opensnoop.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }
    bpf_object__load(obj);

    struct bpf_map *cfg_map = bpf_object__find_map_by_name(obj, "config_map");
    if (!cfg_map) {
        fprintf(stderr, "failed to find config_map\n");
        return 1;
    }

    int cfg_fd = bpf_map__fd(cfg_map);
    int key = 0;
    struct config cfg = {
        .target_pid = target_pid
    };
    bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY);

    struct bpf_program *prog = NULL;
    bpf_object__for_each_program(prog, obj) {
        const char *sec = bpf_program__section_name(prog);
        if (strcmp(sec, "tracepoint/raw_syscalls/sys_enter") == 0)
            break;
    }

    if (!prog) {
        fprintf(stderr, "failed to find tracepoint program\n");
        return 1;
    }

    link = bpf_program__attach_tracepoint(prog, "raw_syscalls", "sys_enter");
    if (!link) {
        fprintf(stderr, "failed to attach program\n");
        return 1;
    }

    int ringbuf_map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (ringbuf_map_fd < 0) {
        fprintf(stderr, "failed to get ringbuf fd\n");
        return 1;
    }

    rb = ring_buffer__new(ringbuf_map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    printf("Tracing openat for pid %d... Press Ctrl-C to exit.\n", target_pid);
    signal(SIGINT, sig_handler);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}
