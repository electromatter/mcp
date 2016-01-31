/* mcp_extra/utils.h
 *
 * Copyright (c) 2016 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#ifndef MCP_EXTRA_UTILS_H
#define MCP_EXTRA_UTILS_H

#include <stdio.h>

void mcp_hexdigest(char *hex, const unsigned char *digest, int digest_length);
void mcp_sha1_hexdigest(char hex[42], const void *data, size_t size);

#endif

