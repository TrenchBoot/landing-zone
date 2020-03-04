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

const u32 K[] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
	0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

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
	t1 = h + e1(e) + Ch(e, f, g) + K[0] + W[0];
	t2 = e0(a) + Maj(a, b, c);    d += t1;    h = t1 + t2;
	t1 = g + e1(d) + Ch(d, e, f) + K[1] + W[1];
	t2 = e0(h) + Maj(h, a, b);    c += t1;    g = t1 + t2;
	t1 = f + e1(c) + Ch(c, d, e) + K[2] + W[2];
	t2 = e0(g) + Maj(g, h, a);    b += t1;    f = t1 + t2;
	t1 = e + e1(b) + Ch(b, c, d) + K[3] + W[3];
	t2 = e0(f) + Maj(f, g, h);    a += t1;    e = t1 + t2;
	t1 = d + e1(a) + Ch(a, b, c) + K[4] + W[4];
	t2 = e0(e) + Maj(e, f, g);    h += t1;    d = t1 + t2;
	t1 = c + e1(h) + Ch(h, a, b) + K[5] + W[5];
	t2 = e0(d) + Maj(d, e, f);    g += t1;    c = t1 + t2;
	t1 = b + e1(g) + Ch(g, h, a) + K[6] + W[6];
	t2 = e0(c) + Maj(c, d, e);    f += t1;    b = t1 + t2;
	t1 = a + e1(f) + Ch(f, g, h) + K[7] + W[7];
	t2 = e0(b) + Maj(b, c, d);    e += t1;    a = t1 + t2;

	t1 = h + e1(e) + Ch(e, f, g) + K[8] + W[8];
	t2 = e0(a) + Maj(a, b, c);    d += t1;    h = t1 + t2;
	t1 = g + e1(d) + Ch(d, e, f) + K[9] + W[9];
	t2 = e0(h) + Maj(h, a, b);    c += t1;    g = t1 + t2;
	t1 = f + e1(c) + Ch(c, d, e) + K[10] + W[10];
	t2 = e0(g) + Maj(g, h, a);    b += t1;    f = t1 + t2;
	t1 = e + e1(b) + Ch(b, c, d) + K[11] + W[11];
	t2 = e0(f) + Maj(f, g, h);    a += t1;    e = t1 + t2;
	t1 = d + e1(a) + Ch(a, b, c) + K[12] + W[12];
	t2 = e0(e) + Maj(e, f, g);    h += t1;    d = t1 + t2;
	t1 = c + e1(h) + Ch(h, a, b) + K[13] + W[13];
	t2 = e0(d) + Maj(d, e, f);    g += t1;    c = t1 + t2;
	t1 = b + e1(g) + Ch(g, h, a) + K[14] + W[14];
	t2 = e0(c) + Maj(c, d, e);    f += t1;    b = t1 + t2;
	t1 = a + e1(f) + Ch(f, g, h) + K[15] + W[15];
	t2 = e0(b) + Maj(b, c, d);    e += t1;    a = t1+t2;

	for (i = 16; i < 64; i += 8)
	{
		t1 = h + e1(e) + Ch(e, f, g) + K[i] + BLEND_OP(W);
		t2 = e0(a) + Maj(a, b, c);    d += t1;    h = t1+t2;
		t1 = g + e1(d) + Ch(d, e, f) + K[i+1] + BLEND_OP(W);
		t2 = e0(h) + Maj(h, a, b);    c += t1;    g = t1+t2;
		t1 = f + e1(c) + Ch(c, d, e) + K[i+2] + BLEND_OP(W);
		t2 = e0(g) + Maj(g, h, a);    b += t1;    f = t1+t2;
		t1 = e + e1(b) + Ch(b, c, d) + K[i+3] + BLEND_OP(W);
		t2 = e0(f) + Maj(f, g, h);    a += t1;    e = t1+t2;
		t1 = d + e1(a) + Ch(a, b, c) + K[i+4] + BLEND_OP(W);
		t2 = e0(e) + Maj(e, f, g);    h += t1;    d = t1+t2;
		t1 = c + e1(h) + Ch(h, a, b) + K[i+5] + BLEND_OP(W);
		t2 = e0(d) + Maj(d, e, f);    g += t1;    c = t1+t2;
		t1 = b + e1(g) + Ch(g, h, a) + K[i+6] + BLEND_OP(W);
		t2 = e0(c) + Maj(c, d, e);    f += t1;    b = t1+t2;
		t1 = a + e1(f) + Ch(f, g, h) + K[i+7] + BLEND_OP(W);
		t2 = e0(b) + Maj(b, c, d);    e += t1;    a = t1+t2;
	}

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_init(struct sha256_state *sctx)
{
	*sctx = (struct sha256_state){
		.state = {
			SHA256_H0,
			SHA256_H1,
			SHA256_H2,
			SHA256_H3,
			SHA256_H4,
			SHA256_H5,
			SHA256_H6,
			SHA256_H7,
		},
	};
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
	struct sha256_state sctx;

	sha256_init(&sctx);
	sha256_update(&sctx, (const u8 *)data, len);
	sha256_final(&sctx, hash);
}
