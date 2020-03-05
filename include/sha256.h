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

void sha256sum(u8 hash[static SHA256_DIGEST_SIZE], const void *ptr, u32 len);

#endif /* SHA256_H */
