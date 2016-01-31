project(mcp)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_FLAGS "-std=c99 -Wextra -Wall -pedantic -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -fomit-frame-pointer -fPIC")
enable_testing()

include_directories(mcp_base/ mcp_extra/)

add_subdirectory(mcp_base/)
add_subdirectory(mcp_extra/)
add_subdirectory(mcp_modern/)