cmake_minimum_required(VERSION 3.20)
project(GlassShell VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

add_subdirectory(Bpf)
add_subdirectory(src/EventBus)
add_subdirectory(src/Driver)

add_executable(${PROJECT_NAME}
    src/main.cpp
)
add_dependencies(${PROJECT_NAME} bpf_target)

target_link_libraries(${PROJECT_NAME}
)

# 拷贝 bpf.o 到执行目录
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_BINARY_DIR}/Bpf/SyscallTrace.bpf.o
            $<TARGET_FILE_DIR:${PROJECT_NAME}>/SyscallTrace.bpf.o
)
