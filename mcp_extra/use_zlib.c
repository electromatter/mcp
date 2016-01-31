/* mcp_extra/use_zlib.c
 *
 * Copyright (c) 2016 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#include "stubs.h"

#include "fbuf.h"

#include <assert.h>

#include <zlib.h>

#define CHUNK_SIZE		(16384)
#define LEVEL			(-1)

mcp_error_t mcp_inflate(struct fbuf *dest, const void *src, size_t src_size)
{
	int ret = 0;
	z_stream stream;
	
	stream.zalloc = NULL;
	stream.zfree = NULL;
	stream.opaque = NULL;
	stream.avail_in = 0;
	stream.next_in = 0;
	
	if (inflateInit(&stream) != Z_OK)
		return -1;
	
	stream.avail_in = src_size;
	stream.next_in = (void*)src;
	
	do {
		stream.next_out = fbuf_wptr(dest, CHUNK_SIZE);
		stream.avail_out = fbuf_wavail(dest);
		
		ret = inflate(&stream, Z_NO_FLUSH);
		assert(ret != Z_STREAM_ERROR);
		switch (ret) {
		case Z_NEED_DICT:
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			inflateEnd(&stream);
			return -1;
		}
		
		fbuf_produce(dest, fbuf_wavail(dest) - stream.avail_out);
	} while (stream.avail_out == 0);
	
	inflateEnd(&stream);
	if (ret == Z_STREAM_END)
		return MCP_EOK;
	return MCP_EINVAL;
}

mcp_error_t mcp_deflate(struct fbuf *dest, const void *src, size_t src_size)
{
	int ret;
	z_stream stream;
	
	stream.zalloc = Z_NULL;
	stream.zfree = Z_NULL;
	stream.opaque = Z_NULL;
	if (deflateInit(&stream, LEVEL) != Z_OK)
		return MCP_ENOMEM;
	
	stream.avail_in = src_size;
	stream.next_in = (void*)src;
	do {
		stream.next_out = fbuf_wptr(dest, CHUNK_SIZE);
		stream.avail_out = fbuf_wavail(dest);
		
		if (stream.next_out == NULL) {
			deflateEnd(&stream);
			return MCP_ENOMEM;
		}
		
		ret = deflate(&stream, Z_FINISH);
		assert(ret != Z_STREAM_ERROR);
		
		fbuf_produce(dest, fbuf_wavail(dest) - stream.avail_out);
	} while (stream.avail_out == 0);
	assert(stream.avail_in == 0);
	assert(ret == Z_STREAM_END);
	
	deflateEnd(&stream);
	return MCP_EOK;
}
