/* mcp_modern/base.c
 *
 * Copyright (c) 2016 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#include "base.h"

/* Server */
void mcm_server_parse(union mcm_any *dest, enum mcm_mode mode, enum mcm_id id, struct mcp_parse *src)
{
	if (!mcp_ok(src))
		return;
	
	switch (mode) {
	case MCM_HANDSHAKE:
		mcm_server_parse_handshake(dest, id, src);
		return;
	case MCM_STATUS:
		mcm_server_parse_status(dest, id, src);
		return;
	case MCM_LOGIN:
		mcm_server_parse_login(dest, id, src);
		return;
	default:
		src->error = MCP_EINVAL;
		return;
	}
}

int mcm_server_pack(struct fbuf *dest, enum mcm_mode mode, const union mcm_any *src)
{
	switch (mode) {
	case MCM_STATUS:
		return mcm_server_pack_status(dest, src);
	case MCM_LOGIN:
		return mcm_server_pack_login(dest, src);
	default:
		return 1;
	}
}

/* Client*/
void mcm_client_parse(union mcm_any *dest, enum mcm_mode mode, enum mcm_id id, struct mcp_parse *src)
{
	if (!mcp_ok(src))
		return;
	
	switch (mode) {
	case MCM_STATUS:
		mcm_client_parse_status(dest, id, src);
		return;
	case MCM_LOGIN:
		mcm_client_parse_login(dest, id, src);
		return;
	default:
		src->error = MCP_EINVAL;
		return;
	}
}

int mcm_client_pack(struct fbuf *dest, enum mcm_mode mode, const union mcm_any *src)
{
	switch (mode) {
	case MCM_HANDSHAKE:
		return mcm_client_pack_hanshake(dest, src);
	case MCM_STATUS:
		return mcm_client_pack_status(dest, src);
	case MCM_LOGIN:
		return mcm_client_pack_login(dest, src);
	default:
		return 1;
	}
}
