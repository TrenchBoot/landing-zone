/* sha1sum.c - print SHA-1 Message-Digest Algorithm
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 * Copyright (C) 2004 g10 Code GmbH
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* SHA-1 coden take from gnupg 1.3.92.

   Note, that this is a simple tool to be used for MS Windows.
*/

#include <byteswap.h>
#include <defs.h>
#include <types.h>
#include <errno-base.h>
#include <sha1sum.h>

static inline u32
rol( u32 x, int n)
{
    return (x << n) | (x >> (-n & 31));
}

typedef struct {
	u64		count;
	u32		h0, h1, h2, h3, h4;
	unsigned char	buf[64];
} SHA1_CONTEXT;

static void
sha1_init( SHA1_CONTEXT *hd )
{
    *hd = (SHA1_CONTEXT){
        .h0 = 0x67452301,
        .h1 = 0xefcdab89,
        .h2 = 0x98badcfe,
        .h3 = 0x10325476,
        .h4 = 0xc3d2e1f0,
    };
}

static u32 sha1_blend(u32 *x, unsigned int i)
{
#define X(i) x[(i) & 15]

    return X(i) = rol(X(i) ^ X(i - 14) ^ X(i - 8) ^ X(i - 3), 1);

#undef X
}

/****************
 * Transform the message X which consists of 16 32-bit-words
 */
static void sha1_transform(SHA1_CONTEXT *hd, const void *_data)
{
    const u32 *data = _data;
    u32 a,b,c,d,e;
    u32 x[16];
    int i;

    /* get values from the chaining vars */
    a = hd->h0;
    b = hd->h1;
    c = hd->h2;
    d = hd->h3;
    e = hd->h4;

    for (i = 0; i < 16; ++i)
        x[i] = cpu_to_be32(data[i]);


#define K1  0x5A827999L
#define K2  0x6ED9EBA1L
#define K3  0x8F1BBCDCL
#define K4  0xCA62C1D6L
#define F1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )
#define F2(x,y,z)   ( x ^ y ^ z )
#define F3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )
#define F4(x,y,z)   ( x ^ y ^ z )


#define M(i) sha1_blend(x, i)
#define R(a,b,c,d,e,f,k,m)  do { e += rol( a, 5 )     \
				      + f( b, c, d )  \
				      + k	      \
				      + m;	      \
				 b = rol( b, 30 );    \
			       } while(0)

    for (i = 0; i < 15; i += 5) {
        R(a, b, c, d, e, F1, K1, x[i + 0]);
        R(e, a, b, c, d, F1, K1, x[i + 1]);
        R(d, e, a, b, c, F1, K1, x[i + 2]);
        R(c, d, e, a, b, F1, K1, x[i + 3]);
        R(b, c, d, e, a, F1, K1, x[i + 4]);
    }

    R( a, b, c, d, e, F1, K1, x[15] );
    R( e, a, b, c, d, F1, K1, M(16) );
    R( d, e, a, b, c, F1, K1, M(17) );
    R( c, d, e, a, b, F1, K1, M(18) );
    R( b, c, d, e, a, F1, K1, M(19) );

    for (i = 20; i < 40; i += 5) {
        R(a, b, c, d, e, F2, K2, M(i + 0));
        R(e, a, b, c, d, F2, K2, M(i + 1));
        R(d, e, a, b, c, F2, K2, M(i + 2));
        R(c, d, e, a, b, F2, K2, M(i + 3));
        R(b, c, d, e, a, F2, K2, M(i + 4));
    }

    for (; i < 60; i += 5) {
        R(a, b, c, d, e, F3, K3, M(i + 0));
        R(e, a, b, c, d, F3, K3, M(i + 1));
        R(d, e, a, b, c, F3, K3, M(i + 2));
        R(c, d, e, a, b, F3, K3, M(i + 3));
        R(b, c, d, e, a, F3, K3, M(i + 4));
    }

    for (; i < 80; i += 5) {
        R(a, b, c, d, e, F4, K4, M(i + 0));
        R(e, a, b, c, d, F4, K4, M(i + 1));
        R(d, e, a, b, c, F4, K4, M(i + 2));
        R(c, d, e, a, b, F4, K4, M(i + 3));
        R(b, c, d, e, a, F4, K4, M(i + 4));
    }

    /* Update chaining vars */
    hd->h0 += a;
    hd->h1 += b;
    hd->h2 += c;
    hd->h3 += d;
    hd->h4 += e;
}


static void sha1_once(SHA1_CONTEXT *hd, const void *data, u32 len)
{
    hd->count = len;
    for (; len >= 64; data += 64, len -= 64)
        sha1_transform(hd, data);

    memcpy(hd->buf, data, len);
}


/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 20 bytes representing the digest.
 */

static void
sha1_final(SHA1_CONTEXT *hd, u8 hash[SHA1_DIGEST_SIZE])
{
    unsigned int partial = hd->count & 0x3f;

    /* Start padding */
    hd->buf[partial++] = 0x80;

    if (partial > 56) {
        /* Need one extra block - pad to 64 */
        memset(hd->buf + partial, 0, 64 - partial);
        sha1_transform(hd, hd->buf);
        partial = 0;
    }
    /* Pad to 56 */
    memset(hd->buf + partial, 0, 56 - partial);

    /* append the 64 bit count */
    u64 *count = (void *)&hd->buf[56];
    *count = cpu_to_be64(hd->count << 3);
    sha1_transform(hd, hd->buf);

    u32 *p = (void *)hash;
    *p++ = be32_to_cpu(hd->h0);
    *p++ = be32_to_cpu(hd->h1);
    *p++ = be32_to_cpu(hd->h2);
    *p++ = be32_to_cpu(hd->h3);
    *p++ = be32_to_cpu(hd->h4);
}

void sha1sum(u8 hash[static SHA1_DIGEST_SIZE], const void *ptr, u32 len)
{
    SHA1_CONTEXT ctx;

    sha1_init(&ctx);
    sha1_once(&ctx, ptr, len);
    sha1_final(&ctx, hash);
}

/*
Local Variables:
compile-command: "cc -Wall -g -o sha1sum sha1sum.c"
End:
*/
