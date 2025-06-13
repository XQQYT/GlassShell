
add_library(Driver STATIC
    Pty/PtyDriver.cpp
)

target_include_directories(Driver PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(Driver 

)