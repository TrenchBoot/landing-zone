/*
 * SHA-256, as specified in
 * http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf
 *
 * SHA-256 code by Jean-Luc Cooke <jlcooke@certainkey.com>.
 *
 * Copyright (c) Jean-Luc Cooke <jlcooke@certainkey.com>
 * Copyright (c) Andrew McDonald <andrew@mcdonald.org.uk>
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2014 Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <byteswap.h>
#include <defs.h>
#include <types.h>
#include <errno-base.h>
#include <sha256.h>

typedef u32 __be32;
typedef u64 __be64;

static inline u32 ror32(u32 word, unsigned int shift)
{
	return (word >> shift) | (word << (32 - shift));
}

static inline u32 Ch(u32 x, u32 y, u32 z)
{
	return z ^ (x & (y ^ z));
}

static inline u32 Maj(u32 x, u32 y, u32 z)
{
	return (x & y) | (z & (x | y));
}

#define e0(x)       (ror32(x, 2) ^ ror32(x, 13) ^ ror32(x, 22))
#define e1(x)       (ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25))
#define s0(x)       (ror32(x, 7) ^ ror32(x, 18) ^ (x >> 3))
#define s1(x)       (ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10))

static inline void LOAD_OP(int I, u32 *W, const u8 *input)
{
	W[I] = be32_to_cpu(((__be32 *)(input))[I]);
}

static inline u32 BLEND_OP(u32 *W)
{
	static unsigned i = 0;
	u32 ret;

	W[i] = s1(W[(i-2) & 0xf]) + W[(i-7) & 0xf] + s0(W[(i-15) & 0xf]) + W[i];
	ret = W[i];
	i++;
	i &= 0xf;
	return ret;
}

static void sha256_transform(u32 *state, const u8 *input)
{
	u32 a, b, c, d, e, f, g, h, t1, t2;
	u32 W[16];
	int i;

	/* load the input */
	for (i = 0; i < 16; i++)
		LOAD_OP(i, W, input);

	/* load the state into our registers */
	a = state[0];  b = state[1];  c = state[2];  d = state[3];
	e = state[4];  f = state[5];  g = state[6];  h = state[7];

	/* now iterate */
	t1 = h + e1(e) + Ch(e, f, g) + 0x428a2f98 + W[0];
	t2 = e0(a) + Maj(a, b, c);    d += t1;    h = t1 + t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0x71374491 + W[1];
	t2 = e0(h) + Maj(h, a, b);    c += t1;    g = t1 + t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0xb5c0fbcf + W[2];
	t2 = e0(g) + Maj(g, h, a);    b += t1;    f = t1 + t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0xe9b5dba5 + W[3];
	t2 = e0(f) + Maj(f, g, h);    a += t1;    e = t1 + t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0x3956c25b + W[4];
	t2 = e0(e) + Maj(e, f, g);    h += t1;    d = t1 + t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0x59f111f1 + W[5];
	t2 = e0(d) + Maj(d, e, f);    g += t1;    c = t1 + t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0x923f82a4 + W[6];
	t2 = e0(c) + Maj(c, d, e);    f += t1;    b = t1 + t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0xab1c5ed5 + W[7];
	t2 = e0(b) + Maj(b, c, d);    e += t1;    a = t1 + t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0xd807aa98 + W[8];
	t2 = e0(a) + Maj(a, b, c);    d += t1;    h = t1 + t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0x12835b01 + W[9];
	t2 = e0(h) + Maj(h, a, b);    c += t1;    g = t1 + t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0x243185be + W[10];
	t2 = e0(g) + Maj(g, h, a);    b += t1;    f = t1 + t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0x550c7dc3 + W[11];
	t2 = e0(f) + Maj(f, g, h);    a += t1;    e = t1 + t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0x72be5d74 + W[12];
	t2 = e0(e) + Maj(e, f, g);    h += t1;    d = t1 + t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0x80deb1fe + W[13];
	t2 = e0(d) + Maj(d, e, f);    g += t1;    c = t1 + t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0x9bdc06a7 + W[14];
	t2 = e0(c) + Maj(c, d, e);    f += t1;    b = t1 + t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0xc19bf174 + W[15];
	t2 = e0(b) + Maj(b, c, d);    e += t1;    a = t1+t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0xe49b69c1 + BLEND_OP(W);
	t2 = e0(a) + Maj(a, b, c);    d += t1;    h = t1+t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0xefbe4786 + BLEND_OP(W);
	t2 = e0(h) + Maj(h, a, b);    c += t1;    g = t1+t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0x0fc19dc6 + BLEND_OP(W);
	t2 = e0(g) + Maj(g, h, a);    b += t1;    f = t1+t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0x240ca1cc + BLEND_OP(W);
	t2 = e0(f) + Maj(f, g, h);    a += t1;    e = t1+t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0x2de92c6f + BLEND_OP(W);
	t2 = e0(e) + Maj(e, f, g);    h += t1;    d = t1+t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0x4a7484aa + BLEND_OP(W);
	t2 = e0(d) + Maj(d, e, f);    g += t1;    c = t1+t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0x5cb0a9dc + BLEND_OP(W);
	t2 = e0(c) + Maj(c, d, e);    f += t1;    b = t1+t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0x76f988da + BLEND_OP(W);
	t2 = e0(b) + Maj(b, c, d);    e += t1;    a = t1+t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0x983e5152 + BLEND_OP(W);
	t2 = e0(a) + Maj(a, b, c);    d += t1;    h = t1+t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0xa831c66d + BLEND_OP(W);
	t2 = e0(h) + Maj(h, a, b);    c += t1;    g = t1+t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0xb00327c8 + BLEND_OP(W);
	t2 = e0(g) + Maj(g, h, a);    b += t1;    f = t1+t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0xbf597fc7 + BLEND_OP(W);
	t2 = e0(f) + Maj(f, g, h);    a += t1;    e = t1+t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0xc6e00bf3 + BLEND_OP(W);
	t2 = e0(e) + Maj(e, f, g);    h += t1;    d = t1+t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0xd5a79147 + BLEND_OP(W);
	t2 = e0(d) + Maj(d, e, f);    g += t1;    c = t1+t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0x06ca6351 + BLEND_OP(W);
	t2 = e0(c) + Maj(c, d, e);    f += t1;    b = t1+t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0x14292967 + BLEND_OP(W);
	t2 = e0(b) + Maj(b, c, d);    e += t1;    a = t1+t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0x27b70a85 + BLEND_OP(W);
	t2 = e0(a) + Maj(a, b, c);    d += t1;    h = t1+t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0x2e1b2138 + BLEND_OP(W);
	t2 = e0(h) + Maj(h, a, b);    c += t1;    g = t1+t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0x4d2c6dfc + BLEND_OP(W);
	t2 = e0(g) + Maj(g, h, a);    b += t1;    f = t1+t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0x53380d13 + BLEND_OP(W);
	t2 = e0(f) + Maj(f, g, h);    a += t1;    e = t1+t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0x650a7354 + BLEND_OP(W);
	t2 = e0(e) + Maj(e, f, g);    h += t1;    d = t1+t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0x766a0abb + BLEND_OP(W);
	t2 = e0(d) + Maj(d, e, f);    g += t1;    c = t1+t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0x81c2c92e + BLEND_OP(W);
	t2 = e0(c) + Maj(c, d, e);    f += t1;    b = t1+t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0x92722c85 + BLEND_OP(W);
	t2 = e0(b) + Maj(b, c, d);    e += t1;    a = t1+t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0xa2bfe8a1 + BLEND_OP(W);
	t2 = e0(a) + Maj(a, b, c);    d += t1;    h = t1+t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0xa81a664b + BLEND_OP(W);
	t2 = e0(h) + Maj(h, a, b);    c += t1;    g = t1+t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0xc24b8b70 + BLEND_OP(W);
	t2 = e0(g) + Maj(g, h, a);    b += t1;    f = t1+t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0xc76c51a3 + BLEND_OP(W);
	t2 = e0(f) + Maj(f, g, h);    a += t1;    e = t1+t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0xd192e819 + BLEND_OP(W);
	t2 = e0(e) + Maj(e, f, g);    h += t1;    d = t1+t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0xd6990624 + BLEND_OP(W);
	t2 = e0(d) + Maj(d, e, f);    g += t1;    c = t1+t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0xf40e3585 + BLEND_OP(W);
	t2 = e0(c) + Maj(c, d, e);    f += t1;    b = t1+t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0x106aa070 + BLEND_OP(W);
	t2 = e0(b) + Maj(b, c, d);    e += t1;    a = t1+t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0x19a4c116 + BLEND_OP(W);
	t2 = e0(a) + Maj(a, b, c);    d += t1;    h = t1+t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0x1e376c08 + BLEND_OP(W);
	t2 = e0(h) + Maj(h, a, b);    c += t1;    g = t1+t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0x2748774c + BLEND_OP(W);
	t2 = e0(g) + Maj(g, h, a);    b += t1;    f = t1+t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0x34b0bcb5 + BLEND_OP(W);
	t2 = e0(f) + Maj(f, g, h);    a += t1;    e = t1+t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0x391c0cb3 + BLEND_OP(W);
	t2 = e0(e) + Maj(e, f, g);    h += t1;    d = t1+t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0x4ed8aa4a + BLEND_OP(W);
	t2 = e0(d) + Maj(d, e, f);    g += t1;    c = t1+t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0x5b9cca4f + BLEND_OP(W);
	t2 = e0(c) + Maj(c, d, e);    f += t1;    b = t1+t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0x682e6ff3 + BLEND_OP(W);
	t2 = e0(b) + Maj(b, c, d);    e += t1;    a = t1+t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0x748f82ee + BLEND_OP(W);
	t2 = e0(a) + Maj(a, b, c);    d += t1;    h = t1+t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0x78a5636f + BLEND_OP(W);
	t2 = e0(h) + Maj(h, a, b);    c += t1;    g = t1+t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0x84c87814 + BLEND_OP(W);
	t2 = e0(g) + Maj(g, h, a);    b += t1;    f = t1+t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0x8cc70208 + BLEND_OP(W);
	t2 = e0(f) + Maj(f, g, h);    a += t1;    e = t1+t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0x90befffa + BLEND_OP(W);
	t2 = e0(e) + Maj(e, f, g);    h += t1;    d = t1+t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0xa4506ceb + BLEND_OP(W);
	t2 = e0(d) + Maj(d, e, f);    g += t1;    c = t1+t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0xbef9a3f7 + BLEND_OP(W);
	t2 = e0(c) + Maj(c, d, e);    f += t1;    b = t1+t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0xc67178f2 + BLEND_OP(W);
	t2 = e0(b) + Maj(b, c, d);    e += t1;    a = t1+t2;

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_init(struct sha256_state *sctx)
{
	sctx->state[0] = SHA256_H0;
	sctx->state[1] = SHA256_H1;
	sctx->state[2] = SHA256_H2;
	sctx->state[3] = SHA256_H3;
	sctx->state[4] = SHA256_H4;
	sctx->state[5] = SHA256_H5;
	sctx->state[6] = SHA256_H6;
	sctx->state[7] = SHA256_H7;
	sctx->count = 0;
}

static void sha256_update(struct sha256_state *sctx, const u8 *data, u32 len)
{
	unsigned int partial, done;
	const u8 *src;

	partial = sctx->count & 0x3f;
	sctx->count += len;
	done = 0;
	src = data;

	if ((partial + len) > 63) {
		if (partial) {
			done = -partial;
			memcpy(sctx->buf + partial, data, done + 64);
			src = sctx->buf;
		}

		do {
			sha256_transform(sctx->state, src);
			done += 64;
			src = data + done;
		} while (done + 63 < len);

		partial = 0;
	}
	memcpy(sctx->buf + partial, src, len - done);
}

static void sha256_final(struct sha256_state *sctx, u8 *out)
{
	__be32 *dst = (__be32 *)out;
	__be64 bits;
	unsigned int index, pad_len;
	int i;
	static const u8 padding[64] = { 0x80, };

	/* Save number of bits */
	bits = cpu_to_be64(sctx->count << 3);

	/* Pad out to 56 mod 64. */
	index = sctx->count & 0x3f;
	pad_len = (index < 56) ? (56 - index) : ((64+56) - index);
	sha256_update(sctx, padding, pad_len);

	/* Append length (before padding) */
	sha256_update(sctx, (const u8 *)&bits, sizeof(bits));

	/* Store state in digest */
	for (i = 0; i < 8; i++)
		dst[i] = cpu_to_be32(sctx->state[i]);
}

void sha256sum(u8 *hash, void *data, u32 len)
{
	struct sha256_state sctx = {};

	memset(hash, 0, SHA256_DIGEST_SIZE);
	sha256_init(&sctx);
	sha256_update(&sctx, (const u8 *)data, len);
	sha256_final(&sctx, hash);
}
