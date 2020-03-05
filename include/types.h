/*
 * Definitions in this header come from various places in the Linux
 * sources.
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

#ifndef __TYPES_H__
#define __TYPES_H__

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef unsigned char		u8;
typedef unsigned short		u16;
typedef unsigned int		u32;
typedef unsigned long long	u64;
typedef signed char		s8;
typedef short			s16;
typedef int			s32;
typedef long long		s64;

typedef unsigned long	uintptr_t;

typedef unsigned long	size_t;
typedef long		ssize_t;

#define NULL ((void *)0)

/*
 * Local declaration of bits of libc
 *
 * Use __builtin_???() wherever possible to allow the compiler to perform
 * optimisations (e.g. constant folding) where possible.  Calls to ???() will
 * be emitted as needed.
 */

void *memset(void *s, int c, size_t n);
#define memset(d, c, n) __builtin_memset(d, c, n)

void *memcpy(void *dst, const void *src, size_t n);
#define memcpy(d, s, n) __builtin_memcpy(d, s, n)

#endif /* __TYPES_H__ */
