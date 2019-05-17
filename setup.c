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
	while (*txt != '\0') print_char(*txt++);
	print_char('\r');
	print_char('\n');
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

	pfn = PAGE_PFN(zero_page);
	end_pfn = PAGE_PFN(PAGE_DOWN((u8*)lz_base + 0x10000));

	/* TODO: check end_pfn is not ouside of range of DEV map */

	/* build protection bitmap */
	for (;pfn++; pfn <= end_pfn)
		dev_protect_page(pfn, (u8*)dev_table);

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
	data = (u32*)(uintptr_t)*code32_start;
	size = lz_header->slaunch_loader_size;
	sha1sum(&sha1ctx, data, size);
	tpm_extend_pcr(tpm, 17, TPM_HASH_ALG_SHA1, &sha1ctx.buf[0]);

	tpm_relinquish_locality(tpm);
	free_tpm(tpm);

	/* End of the line, off to the protected mode entry into the kernel */
	lz_exit(pm_kernel_entry, zero_page, lz_base);

	/* Should never get here */
	die();
}
