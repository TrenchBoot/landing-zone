/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <types.h>

#ifndef __MEM_H__
#define __MEM_H__

static inline void *memcpy(void *dst, const void *src, size_t count)
{
	u8* dst8 = (u8*)dst;
	u8* src8 = (u8*)src;

	while (count--)
		*dst8++ = *src8++;

	return dst;
}

static inline void *memset(void *s, int c, u32 n)
{
	char *buf = (char*)s;

	for ( ; n--; )
		*buf++ = c;

	return buf;
}

#endif /* __MEM_H__ */
