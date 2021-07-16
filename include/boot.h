/*
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

/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *   Copyright 2009 Intel Corporation; author H. Peter Anvin
 *
 *   This file is part of the Linux kernel, and is made available under
 *   the terms of the GNU General Public License version 2.
 *
 * ----------------------------------------------------------------------- */

/*
 * Header file for the real-mode kernel code
 */

/*
 * Just a snippet from kernel of what we need
 */

#include <defs.h>
#include <types.h>

#ifndef __BOOT_H__
#define __BOOT_H__

extern const char _start[];
extern volatile u32 lz_stack_canary;

typedef struct __packed sl_header {
	u16 lz_entry_point;
	u16 bootloader_data_offset;
	u16 lz_info_offset;
} sl_header_t;
extern sl_header_t sl_header;

typedef struct __packed lz_info {
	u8  uuid[16]; /* 78 f1 26 8e 04 92 11 e9  83 2a c8 5b 76 c4 cc 02 */
	u32 version;
	u16 msb_key_algo;
	u8  msb_key_hash[];
} lz_info_t;

/* The same as TPML_DIGEST_VALUES but little endian, as event log expects it */
typedef struct __packed ev_log_hash {
	u32 count;
	u16 sha1_id;
	u8 sha1_hash[20];
	u16 sha256_id;
	u8 sha256_hash[32];
} ev_log_hash_t;

/* Keep in sync with head.S and sanity_check.sh */
typedef struct __packed lz_header {
	u32 boot_protocol;
	u32 proto_struct;
	u32 event_log_addr;
	u32 event_log_size;
	ev_log_hash_t lz_hashes;
} lz_header_t;
extern lz_header_t lz_header;

/* Fences */
#define mb()		asm volatile("mfence" : : : "memory")
#define rmb()		asm volatile("lfence" : : : "memory")
#define wmb()		asm volatile("sfence" : : : "memory")
#define barrier()	asm volatile("" : : : "memory")

#define smp_rmb()	barrier()
#define smp_wmb()	barrier()
#define smp_mb()	mb()

/* MMIO Functions */
static inline u8 ioread8(void *addr)
{
	u8 val;

	barrier();
	val = (*(volatile u8 *)(addr));
	rmb();
	return val;
}

static inline u16 ioread16(void *addr)
{
	u16 val;

	barrier();
	val = (*(volatile u16 *)(addr));
	rmb();
	return val;
}

static inline u32 ioread32(void *addr)
{
	u32 val;

	barrier();
	val = (*(volatile u32 *)(addr));
	rmb();
	return val;
}

static inline void iowrite8(u8 val, void *addr)
{

	wmb();
	(*(volatile u8 *)(addr)) = val;
	barrier();
}

static inline void iowrite16(u16 val, void *addr)
{

	wmb();
	(*(volatile u16 *)(addr)) = val;
	barrier();
}

static inline void iowrite32(u32 val, void *addr)
{
	wmb();
	(*(volatile u32 *)(addr)) = val;
	barrier();
}

/* Basic port I/O */
static inline u8 inb(u16 port)
{
	u8 val;

	asm volatile("inb %1,%0" : "=a" (val) : "dN" (port));
	return val;
}

static inline u16 inw(u16 port)
{
	u16 val;

	asm volatile("inw %1,%0" : "=a" (val) : "dN" (port));
	return val;
}

static inline u32 inl(u16 port)
{
	u32 val;

	asm volatile("inl %1,%0" : "=a" (val) : "dN" (port));
	return val;
}

static inline void outb(u8 val, u16 port)
{
	asm volatile("outb %0,%1" : : "a" (val), "dN" (port));
}

static inline void outw(u16 val, u16 port)
{
	asm volatile("outw %0,%1" : : "a" (val), "dN" (port));
}

static inline void outl(u32 val, u16 port)
{
	asm volatile("outl %0,%1" : : "a" (val), "dN" (port));
}

static inline void io_delay(void)
{
	const u16 DELAY_PORT = 0x80;

	asm volatile("outb %%al,%0" : : "dN" (DELAY_PORT));
}

static inline void stgi(void)
{
	asm volatile(".byte 0x0f, 0x01, 0xdc" ::: "memory");
}

static inline void __attribute__((noreturn)) die(void)
{
	asm volatile("ud2");
	unreachable();
}

#endif /* __BOOT_H__ */
