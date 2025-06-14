find_program(CLANG_EXECUTABLE clang REQUIRED)

set(BPF_CFLAGS -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86)

set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/SyscallTrace.bpf.c)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/SyscallTrace.bpf.o)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h")
    message(STATUS "Generating vmlinux.h from BTF")
    execute_process(COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c
                    OUTPUT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h")
endif()

add_custom_command(OUTPUT ${BPF_OBJ}
    COMMAND ${CLANG_EXECUTABLE} ${BPF_CFLAGS}
            -I${CMAKE_CURRENT_SOURCE_DIR}
            -c ${BPF_SRC} -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h
    COMMENT "Compiling BPF program: ${BPF_SRC}"
)

add_custom_target(bpf_target ALL DEPENDS ${BPF_OBJ})
