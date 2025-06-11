add_library(EventBus STATIC
    EventBus.cpp
)

target_include_directories(EventBus PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)
