/* mcp_extra/stubs.h
 *
 * Copyright (c) 2016 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */
#ifndef MCP_EXTRA_STUBS_H
#define MCP_EXTRA_STUBS_H

#include <sys/types.h>

#include "mcp.h"

/* Deflate compression algorithim */
mcp_error_t mcp_inflate(struct fbuf *dest, const void *src, size_t src_size);
mcp_error_t mcp_deflate(struct fbuf *dest, const void *src, size_t src_size);

/* AES128/CFB8 cipher */
struct mcp_cipher;

#define CIPHER_KEY_SIZE	16

struct mcp_cipher *mcp_new_cipher(const unsigned char key[CIPHER_KEY_SIZE],
		const unsigned char en_iv[CIPHER_KEY_SIZE], const unsigned char de_iv[CIPHER_KEY_SIZE]);
void mcp_free_cipher(struct mcp_cipher *c);

void mcp_cipher_secret(struct mcp_cipher *c, unsigned char key[CIPHER_KEY_SIZE],
		unsigned char en_iv[CIPHER_KEY_SIZE], unsigned char de_iv[CIPHER_KEY_SIZE]);

/* in and out may be the same pointer, or non overlapping distinct pointers */
void mcp_encrypt(struct mcp_cipher *c, void *out, void *in, size_t size);
void mcp_decrypt(struct mcp_cipher *c, void *out, void *in, size_t size);

/* RSA */
struct mcp_rsa;

struct mcp_rsa *mcp_gen_key(int bits, int e);
void mcp_free_rsa(struct mcp_rsa *rsa);

struct mcp_rsa *mcp_rsa_import(struct mcp_parse *buf, int is_private);
mcp_error_t mcg_rsa_private(struct fbuf *dest, struct mcp_rsa *rsa);
mcp_error_t mcg_rsa_pubkey(struct fbuf *dest, struct mcp_rsa *rsa);

size_t mcp_rsa_size(struct mcp_rsa *rsa);

mcp_error_t mcp_rsa_encrypt(struct mcp_rsa *rsa, struct fbuf *dest, const void *src, size_t src_sz);
mcp_error_t mcp_rsa_decrypt(struct mcp_rsa *rsa, struct fbuf *dest, const void *src, size_t src_sz);

/* SHA-1 */
void mcp_sha1(unsigned char digest[20], const void *data, size_t size);

/* CSPRNG */
void mcp_secure_random(void *dest, size_t size);

#endif

