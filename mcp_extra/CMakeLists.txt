project(mcp_extra)
cmake_minimum_required(VERSION 2.8)

find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)

set(CMAKE_C_FLAGS "-std=c99 -Wall -Wextra -pedantic")

add_library(mcp_extra framers.c utils.c use_zlib.c use_openssl.c)
add_dependencies(mcp_extra mcp_base)
