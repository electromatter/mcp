project(mcp_extra)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_FLAGS "-Wall -Wextra -pedantic -std=c99")

include_directories(../mcp_base/)
add_executable(e test.c utils.c use_openssl.c use_zlib.c json.c framers.c)
target_link_libraries(e crypto z)
