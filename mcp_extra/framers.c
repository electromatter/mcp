/* mcp_extra/framers.c
 *
 * Copyright (c) 2016 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#include "framers.h"

#include "fbuf.h"

#include <assert.h>

static const void *mcp_inner_frame(struct mcp_parse *src, uint32_t *id,
		size_t *data_length)
{
	*id = mcp_varlong(src);
	*data_length = mcp_avail(src);
	if (!mcp_ok(src))
		return NULL;
	return mcp_raw(src, mcp_avail(src));
}

const void *mcp_simple_frame(struct mcp_parse *src, uint32_t *id,
		size_t *data_length)
{
	size_t frame_size;
	const void *ret, *inner_bytes;
	struct mcp_parse inner;
	
	inner_bytes = mcp_bytes(src, &frame_size);
	mcp_start(&inner, inner_bytes, frame_size);
	
	if (!mcp_ok(src))
		return NULL;
	
	ret = mcp_inner_frame(&inner, id, data_length);
	if (!mcp_ok(&inner))
		src->error = inner.error;
	
	assert(mcp_eof(&inner));
	
	return ret;
}

static size_t size_varlong(uint64_t value) {
	size_t size = 1;
	while (value > 0) {
		size++;
		value >>= 7;
	}
	return size;
}

int mcg_simple_frame(struct fbuf *dest, uint32_t id,
		const void *data, size_t data_length)
{
	int err = 0;
	size_t id_length = size_varlong(id);
	
	if (data_length < MCP_MAX_FRAME - id_length)
		return 1;
	
	err |= mcg_varlong(dest, data_length + id_length);
	err |= mcg_varlong(dest, id);
	err |= mcg_raw(dest, data, data_length);
	
	return err;
}

const void *mcp_compressed_frame(struct mcp_parse *src, uint32_t *id,
		size_t *data_length, struct fbuf *temp)
{
	size_t frame_size, data_size, comp_size;
	const void *outer_bytes, *inner_bytes, *ret;
	struct mcp_parse outer, inner;
	
	outer_bytes = mcp_bytes(src, &frame_size);
	mcp_start(&outer, outer_bytes, frame_size);
	
	if (!mcp_ok(src))
		return NULL;
	
	data_size = mcp_varlong(&outer);
	if (!mcp_ok(&outer)) {
		src->error = outer.error;
		return NULL;
	}
	
	if (data_size > 0) {
		/* decompress */
		fbuf_clear(temp);
		comp_size = mcp_avail(&outer);
		if (mcp_inflate(temp, mcp_raw(&outer, comp_size), comp_size) != MCP_EOK ||
			fbuf_avail(temp) != data_size) {
			src->error = MCP_EINVAL;
			return 0;
		}
		inner_bytes = fbuf_ptr(temp);
	} else {
		/* there was no compression */
		data_size = mcp_avail(&outer);
		inner_bytes = mcp_raw(&outer, data_size);
	}
	
	assert(mcp_ok(&outer) && mcp_eof(&outer));
	
	mcp_start(&inner, inner_bytes, data_size);
	
	ret = mcp_inner_frame(&inner, id, data_length);
	if (!mcp_ok(&inner))
		src->error = inner.error;
	
	assert(mcp_eof(&inner));
	
	return ret;
}

int mcg_compressed_frame(struct fbuf *dest, uint32_t id,
		const void *data, size_t data_length,
		size_t threshold, struct fbuf *temp, struct fbuf *temp1)
{
	int err = 0;
	size_t id_size = size_varlong(id),
			data_size = id_size + data_length,
			frame_size;
	if (data_size < threshold) {
		if (data_length < MCP_MAX_FRAME - id_size - 1)
			return 1;
		/* no compression */
		err |= mcg_varlong(dest, data_size + 1);
		err |= mcg_byte(dest, 0);
		err |= mcg_varlong(dest, id);
		err |= mcg_raw(dest, data, data_length);
	} else {
		/* compression */
		fbuf_clear(temp);
		err |= mcg_varlong(temp, id);
		err |= mcg_raw(temp, data, data_length);
		if (err)
			return err;
		
		fbuf_clear(temp1);
		if (mcp_deflate(temp1, fbuf_ptr(temp), fbuf_avail(temp)) != MCP_EOK)
			return 1;
		
		frame_size = size_varlong(data_size) + fbuf_avail(temp1);
		if (fbuf_avail(temp1) > MCP_MAX_FRAME - size_varlong(data_size))
			return 1;
		
		err |= mcg_varlong(dest, frame_size);
		err |= mcg_varlong(dest, data_size);
		err |= fbuf_copy(dest, fbuf_ptr(temp1), fbuf_avail(temp1));
	}
	
	return err;
}
