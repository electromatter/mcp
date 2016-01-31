/* mcp_extra/net.h
 *
 * Copyright (c) 2016 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#ifndef NET_H
#define NET_H

#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "fbuf.h"

int mcp_format_addr(char *dest, struct sockaddr *addr, socklen_t len);
int mcp_parse_addr(const char *name, int default_port, struct sockaddr *addr, socklen_t *len);
int mcp_listen(const char *addr, int default_port);
int mcp_connect(const char *addr, int default_port);
int mcp_accept(int from_fd, struct sockaddr *addr, socklen_t *len);
ssize_t fbuf_read(struct fbuf *buf, int fd, ssize_t size);
ssize_t fbuf_write(struct fbuf *buf, int fd, ssize_t size);

#endif