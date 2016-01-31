find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(mcp_extra framers.c utils.c net.c use_zlib.c use_openssl.c)
add_dependencies(mcp_extra mcp_base)
