/* mcp_extra/use_openssl.c
 *
 * Copyright (c) 2016 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#include "stubs.h"

#include "fbuf.h"
#include "mcp_internal.h"

#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

struct mcp_cipher {
	EVP_CIPHER_CTX en_ctx, de_ctx;
	unsigned char key[CIPHER_KEY_SIZE], en_iv[CIPHER_KEY_SIZE], de_iv[CIPHER_KEY_SIZE];
};

struct mcp_cipher *mcp_new_cipher(const unsigned char key[CIPHER_KEY_SIZE],
		const unsigned char en_iv[CIPHER_KEY_SIZE], const unsigned char de_iv[CIPHER_KEY_SIZE])
{
	struct mcp_cipher *c = malloc(sizeof(*c));
	
	if (c == NULL)
		return NULL;
	
	memcpy(c->key, key, CIPHER_KEY_SIZE);
	memcpy(c->en_iv, en_iv, CIPHER_KEY_SIZE);
	memcpy(c->de_iv, de_iv, CIPHER_KEY_SIZE);
	
	EVP_CIPHER_CTX_init(&c->en_ctx);
	EVP_CIPHER_CTX_init(&c->de_ctx);
	
	assert(EVP_EncryptInit_ex(&c->en_ctx, EVP_aes_128_cfb8(), NULL, key, en_iv));
	assert(EVP_EncryptInit_ex(&c->de_ctx, EVP_aes_128_cfb8(), NULL, key, de_iv));
	
	return c;
}

void mcp_free_cipher(struct mcp_cipher *c)
{
	if (c == NULL)
		return;
	EVP_CIPHER_CTX_cleanup(&c->en_ctx);
	EVP_CIPHER_CTX_cleanup(&c->de_ctx);
	memset(c, 0, sizeof(*c));
	free(c);
}

void mcp_cipher_secret(struct mcp_cipher *c, unsigned char key[CIPHER_KEY_SIZE],
		unsigned char en_iv[CIPHER_KEY_SIZE], unsigned char de_iv[CIPHER_KEY_SIZE])
{
	memcpy(key, c->key, CIPHER_KEY_SIZE);
	memcpy(en_iv, c->en_iv, CIPHER_KEY_SIZE);
	memcpy(de_iv, c->de_iv, CIPHER_KEY_SIZE);
}

#define BLOCK_SIZE (1 << 24)

static void do_encipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t size)
{
	int inl, outl;
	while (size > 0) {
		inl = size > BLOCK_SIZE ? BLOCK_SIZE : size;
		assert(EVP_EncryptUpdate(ctx, out, &outl, in, inl));
		assert(outl == inl);
		size -= inl;
		out += inl;
		in += inl;
	}
}

static void do_decipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t size)
{
	int inl, outl;
	while (size > 0) {
		inl = size > BLOCK_SIZE ? BLOCK_SIZE : size;
		assert(EVP_DecryptUpdate(ctx, out, &outl, in, inl));
		assert(outl == inl);
		size -= inl;
		out += inl;
		in += inl;
	}
}

void mcp_encrypt(struct mcp_cipher *c, void *out, void *in, size_t size)
{
	/* process in blocks */
	do_encipher(&c->en_ctx, out, in ,size);
	
	/* shift the iv */
	if (size < CIPHER_KEY_SIZE) {
		memcpy(c->en_iv, c->en_iv + size, CIPHER_KEY_SIZE - size);
		memcpy(c->en_iv + CIPHER_KEY_SIZE - size, out, size);
	} else {
		memcpy(c->en_iv, (char*)out + size - CIPHER_KEY_SIZE, CIPHER_KEY_SIZE);
	}
}

void mcp_decrypt(struct mcp_cipher *c, void *out, void *in, size_t size)
{
	/* process in blocks */
	do_decipher(&c->de_ctx, out, in ,size);
	
	/* shift the iv */
	if (size < CIPHER_KEY_SIZE) {
		memcpy(c->de_iv, c->de_iv + size, CIPHER_KEY_SIZE - size);
		memcpy(c->de_iv + CIPHER_KEY_SIZE - size, in, size);
	} else {
		memcpy(c->de_iv, (char*)in + size - CIPHER_KEY_SIZE, CIPHER_KEY_SIZE);
	}
}

struct mcp_rsa *mcp_gen_key(int bits, int e)
{
	return (void*)RSA_generate_key(bits, e, NULL, NULL);
}

void mcp_free_rsa(struct mcp_rsa *rsa)
{
	RSA_free((void*)rsa);
}

struct mcp_rsa *mcp_rsa_import(struct mcp_parse *buf, int is_private)
{
	struct mcp_rsa *ret;
	const unsigned char *src;
	
	if (mcp_error(buf) != MCP_EOK)
		return NULL;
	
	/* Try private */
	src = mcp_ptr(buf);
	ret = (void*)d2i_RSAPrivateKey(NULL, &src, mcp_avail(buf));
	if (ret != NULL)
		return ret;
	
	if (is_private) {
		buf->error = MCP_EINVAL;
		return NULL;
	}
	
	/* Try public */
	src = mcp_ptr(buf);
	ret = (void*)d2i_RSA_PUBKEY(NULL, &src, mcp_avail(buf));
	if (ret != NULL)
		return ret;
	
	buf->error = MCP_EINVAL;
	return NULL;
}

mcp_error_t mcg_rsa_private(struct fbuf *dest, struct mcp_rsa *rsa)
{
	unsigned char *ptr;
	int len = i2d_RSAPrivateKey((void*)rsa, NULL);
	
	if (len < 0)
		return MCP_EINVAL;
	
	ptr = fbuf_wptr(dest, len);
	if (ptr == NULL)
		return MCP_ENOMEM;
	
	assert(i2d_RSAPrivateKey((void*)rsa, &ptr) == len);
	assert(ptr - fbuf_wptr(dest, 0) == len);
	
	fbuf_produce(dest, len);
	return MCP_EOK;
}

mcp_error_t mcg_rsa_pubkey(struct fbuf *dest, struct mcp_rsa *rsa)
{
	unsigned char *ptr;
	int len = i2d_RSA_PUBKEY((void*)rsa, NULL);
	
	if (len < 0)
		return MCP_EINVAL;
	
	ptr = fbuf_wptr(dest, len);
	if (ptr == NULL)
		return MCP_ENOMEM;
	
	assert(i2d_RSA_PUBKEY((void*)rsa, &ptr) == len);
	assert(ptr - fbuf_wptr(dest, 0) == len);
	
	fbuf_produce(dest, len);
	return MCP_EOK;
}

size_t mcp_rsa_size(struct mcp_rsa *rsa)
{
	int ret = RSA_size((void*)rsa);
	assert(ret > 0);
	return ret;
}

mcp_error_t mcp_rsa_encrypt(struct mcp_rsa *rsa, struct fbuf *dest, const void *src, size_t src_sz)
{
	size_t sz = mcp_rsa_size(rsa);
	unsigned char *ptr = fbuf_wptr(dest, sz);
	
	if (ptr == NULL)
		return MCP_ENOMEM;
	
	if (src_sz > sz)
		return MCP_EINVAL;
	
	if (RSA_public_encrypt(src_sz, src, ptr, (void*)rsa, RSA_PKCS1_PADDING) != (int)sz)
		return MCP_EINVAL;
	
	fbuf_produce(dest, sz);
	
	return MCP_EOK;
}

mcp_error_t mcp_rsa_decrypt(struct mcp_rsa *rsa, struct fbuf *dest, const void *src, size_t src_sz)
{
	int ret;
	size_t sz = mcp_rsa_size(rsa);
	unsigned char *ptr = fbuf_wptr(dest, sz);
	
	if (ptr == NULL)
		return MCP_ENOMEM;
	
	if (src_sz != sz)
		return MCP_EINVAL;
	
	ret = RSA_private_decrypt(src_sz, src, ptr, (void*)rsa, RSA_PKCS1_PADDING);
	
	if (ret < 0)
		return MCP_EINVAL;
	
	fbuf_produce(dest, ret);
	
	return MCP_EOK;
}

void mcp_sha1(unsigned char digest[20], const void *data, size_t size)
{
	SHA1(data, size, digest);
}

void mcp_secure_random(void *dest, size_t size)
{
	unsigned char *out = dest;
	int inl;
	while (size > 0) {
		inl = size > BLOCK_SIZE ? BLOCK_SIZE : size;
		RAND_bytes(out, inl);
		size -= inl;
		out += inl;
	}
}
