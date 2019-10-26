/*
 *  Copyright (C) 2014 Red Hat Inc.
 *
 *  Author: Vivek Goyal <vgoyal@redhat.com>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#ifndef SHA256_H
#define SHA256_H

#include <types.h>


#define SHA256_DIGEST_SIZE	32
#define SHA256_BLOCK_SIZE	64

#define SHA256_H0	0x6a09e667UL
#define SHA256_H1	0xbb67ae85UL
#define SHA256_H2	0x3c6ef372UL
#define SHA256_H3	0xa54ff53aUL
#define SHA256_H4	0x510e527fUL
#define SHA256_H5	0x9b05688cUL
#define SHA256_H6	0x1f83d9abUL
#define SHA256_H7	0x5be0cd19UL

/*
 * Stand-alone implementation of the SHA256 algorithm. It is designed to
 * have as little dependencies as possible so it can be used in the
 * kexec_file purgatory. In other cases you should use the implementation in
 * crypto/.
 *
 * For details see lib/sha256.c in Linux kernel
 */

struct sha256_state {
	u32 state[SHA256_DIGEST_SIZE / 4];
	u64 count;
	u8 buf[SHA256_BLOCK_SIZE];
};


void sha256sum(u8 *hash, const u8 *data, u32 len);

#endif /* SHA256_H */
