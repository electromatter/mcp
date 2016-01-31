/* mcp_extra/framers.h
 *
 * Copyright (c) 2015 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#ifndef MCP_EXTRA_FRAMERS
#define MCP_EXTRA_FRAMERS

#include "mcp.h"

#define MCP_MAX_FRAME	(MCP_BYTES_MAX_SIZE)

/* deflate implementation */
mcp_error_t mcp_inflate(struct fbuf *dest, const void *src, size_t src_size);
mcp_error_t mcp_deflate(struct fbuf *dest, const void *src, size_t src_size);

/* simple framer */
const void *mcp_simple_frame(struct mcp_parse *src, uint32_t *id,
		size_t *data_length);

int mcg_simple_frame(struct fbuf *dest, uint32_t id,
		const void *data, size_t data_length);

/* compressed framer */
/* this function will return a pointer into temp when the packet is
 * compressed. */
const void *mcp_compressed_frame(struct mcp_parse *src, uint32_t *id,
		size_t *data_length, struct fbuf *temp);

/* temp and temp1 may be freed after this call */
int mcg_compressed_frame(struct fbuf *dest, uint32_t id,
		const void *data, size_t data_length,
		size_t threshold, struct fbuf *temp, struct fbuf *temp1);

#endif
