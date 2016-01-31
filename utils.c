/* mcp_extra/utils.c
 *
 * Copyright (c) 2016 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#include "utils.h"

void mcp_hexdigest(char *hex, const unsigned char *digest, int digest_length)
{
	const char hexchar[] = "0123456789abcdef";
	char *ptr = hex;
	int i, x, neg;
	
	x = neg = !!(digest[0] & 0x80);
	
	/* null terminator */
	*ptr++ = 0;
	
	/* do the two's complement to build up the hex in reverse */
	i = digest_length;
	while (i --> 0) {
		if (neg)
			x += (digest[i] ^ 0xff);
		else
			x += digest[i];
		*ptr++ = hexchar[x & 0xf];
		x >>= 4;
		*ptr++ = hexchar[x & 0xf];
		x >>= 4;
	}
	
	/* find the last non-zero digit to trim leading zeros */
	while (ptr --> hex && *ptr == '0');
	
	/* add the sign */
	if (neg)
		*++ptr = '-';
	
	/* reverse the result */
	do {
		x = *hex;
		*hex = *ptr;
		*ptr = x;
	} while (++hex < --ptr);
}
