cmake_minimum_required(VERSION 3.20)

project(Demo VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(
    ${CMAKE_SOURCE_DIR}/../include
)

add_executable(shellWrapper
    shellWrapper.cpp
)

add_executable(monitorSystemCall
    monitorSystemCall.cpp
)

target_link_libraries(monitorSystemCall
    bpf 
    elf
)
