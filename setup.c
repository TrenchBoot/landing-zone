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

#include <defs.h>
#include <types.h>
#include <config.h>
#include <boot.h>
#include <mem.h>
#include <pci.h>
#include <dev.h>
#include <tpm.h>
#include <sha1sum.h>

static __text void *lz_base;
static __text lz_header_t *lz_header;
static __text void *zero_page;
static __text SHA1_CONTEXT sha1ctx;

void setup2(void);

static void print(char * txt) {
	while (*txt != '\0') {
		if (*txt == '\n')
			print_char('\r');
		print_char(*txt++);
	}
}

static void print_p(const void * _p) {
	char tmp[sizeof(void*)*2 + 5] = "0x";
	int i;
	size_t p = (size_t)_p;

	for (i=0; i<sizeof(void*); i++) {
		if ((p & 0xf) >= 10)
			tmp[sizeof(void*)*2 + 1 - 2*i] = (p & 0xf) + 'a' - 10;
		else
			tmp[sizeof(void*)*2 + 1 - 2*i] = (p & 0xf) + '0';
		p >>= 4;
		if ((p & 0xf) >= 10)
			tmp[sizeof(void*)*2 - 2*i] = (p & 0xf) + 'a' - 10;
		else
			tmp[sizeof(void*)*2 - 2*i] = (p & 0xf) + '0';
		p >>= 4;
	}
	tmp[sizeof(void*)*2 + 2] = ':';
	tmp[sizeof(void*)*2 + 3] = ' ';
	tmp[sizeof(void*)*2 + 4] = '\0';
	print(tmp);
}

static void print_b(char p) {
	char tmp[4];
	int i;

	if ((p & 0xf) >= 10)
		tmp[1] = (p & 0xf) + 'a' - 10;
	else
		tmp[1] = (p & 0xf) + '0';
	p >>= 4;
	if ((p & 0xf) >= 10)
		tmp[0] = (p & 0xf) + 'a' - 10;
	else
		tmp[0] = (p & 0xf) + '0';

	tmp[2] = ' ';
	tmp[3] = '\0';
	print(tmp);
}

static inline int isprint(int c)
{
	return c >= ' ' && c <= '~';
}

void hexdump(const void *memory, size_t length)
{
	int i;
	uint8_t *line;
	int all_zero = 0;
	int all_one = 0;
	size_t num_bytes;

	for (i = 0; i < length; i += 16) {
		int j;
		num_bytes = 16;
		line = ((uint8_t *)memory) + i;

		all_zero++;
		all_one++;
		for (j = 0; j < num_bytes; j++) {
			if (line[j] != 0) {
				all_zero = 0;
				break;
			}
		}

		for (j = 0; j < num_bytes; j++) {
			if (line[j] != 0xff) {
				all_one = 0;
				break;
			}
		}

		if ((all_zero < 2) && (all_one < 2)) {
			print_p(memory + i);
			for (j = 0; j < num_bytes; j++)
				print_b(line[j]);
			for (; j < 16; j++)
				print("   ");
			print("  ");
			for (j = 0; j < num_bytes; j++)
				isprint(line[j]) ? print_char(line[j]) : print_char('.');
			print("\n");
		} else if ((all_zero == 2) || (all_one == 2)) {
			print("...\n");
		}
	}
}

void setup(void *_lz_base)
{
	void *dev_table;
	void *second_stack;
	u32 *tb_dev_map;
	u64 pfn, end_pfn;
	u32 dev;

	/*
	 * Now in 64b mode, paging is setup. This is the launching point. We can
	 * now do what we want. First order of business is to setup
	 * DEV to cover memory from the start of bzImage to the end of the LZ
	 * "kernel". At the end, trampoline to the PM entry point which will
	 * include the Secure Launch stub.
	 */

	/* Store the lz_base for all to use */
	lz_base = _lz_base;

	/* The LZ header setup by the bootloader */
	lz_header = (lz_header_t*)((u8*)lz_base + sizeof(sl_header_t));

	/* The Zero Page with the boot_params and legacy header */
	zero_page = (u8*)(u64)lz_header->zero_page_addr;

	/* DEV CODE */

	/* Pointer to dev_table bitmap for DEV protection */
	dev_table = (u8*)lz_base + LZ_DEV_TABLE_OFFSET;

	pfn = PAGE_PFN(0x1000000 /*zero_page*/);
	end_pfn = PAGE_PFN(PAGE_DOWN((u8*)lz_base + 0x10000));

	/* TODO: check end_pfn is not ouside of range of DEV map */

	/* build protection bitmap */
	for (;pfn <= end_pfn; pfn++) {
		dev_protect_page(pfn, (u8*)dev_table);
	}

	dev = dev_locate();
	dev_load_map(dev, (u32)((u64)dev_table));
	dev_flush_cache(dev);

	/* Set the DEV address for the TB stub to use */
	tb_dev_map = (u32*)((u8*)zero_page + BP_TB_DEV_MAP);
	*tb_dev_map = (u32)((u64)dev_table);

	/*
	 * Switch to our nice big stack which starts at the page behind the
	 * landing zone and of course grows down.
	 */
	second_stack = lz_base - LZ_SECOND_STAGE_STACK_OFFSET;
	load_stack(second_stack);

	/* Call secondary setup on new stack */
	setup2();

	/* Should never get here */
	die();
}

void setup2(void)
{
	u32 *code32_start;
	u32 *data, size;
	void *pm_kernel_entry;
	struct tpm *tpm;

	code32_start = (u32*)((u8*)zero_page + BP_CODE32_START);
	pm_kernel_entry = (void*)((u64)(*code32_start));

	/*
	 * TODO Note these functions can fail but there is no clear way to
	 * report the error unless SKINIT has some resource to do this. For
	 * now, if an error is returned, this code will most likely just crash.
	 */
	tpm = enable_tpm();
	tpm_request_locality(tpm, 2);

	/* extend TB Loader code segment into PCR17 */
	print("TPM extending ");
	data = (u32*)(uintptr_t)*code32_start;
	print_p(data);
	size = lz_header->slaunch_loader_size;
	sha1sum(&sha1ctx, data, size);
	print("shasum calculated, ");
	tpm_extend_pcr(tpm, 17, TPM_HASH_ALG_SHA1, &sha1ctx.buf[0]);
	print("PCR extended\n");

	tpm_relinquish_locality(tpm);
	free_tpm(tpm);

	/* End of the line, off to the protected mode entry into the kernel */
	print("pm_kernel_entry:\n");
	hexdump(pm_kernel_entry, 0x100);
	print("zero_page:\n");
	hexdump(zero_page, 0x100);
	print("lz_base:\n");
	hexdump(lz_base, 0x100);
	lz_exit(pm_kernel_entry, zero_page, lz_base);

	/* Should never get here */
	die();
}
