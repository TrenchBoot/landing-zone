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
#include <pci.h>
#include <dev.h>
#include <tpm.h>
#include <sha1sum.h>
#include <sha256.h>

static u8 __page_data dev_table[3 * PAGE_SIZE];

static SHA1_CONTEXT sha1ctx;
static u8 sha256_hash[SHA256_DIGEST_SIZE];

#ifdef DEBUG
static void print_char(char c)
{
	while ( !(inb(0x3f8 + 5) & 0x20) )
		;

	outb(0x3f8, c);
}

static void print(const char * txt) {
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
#else
static void print(const char * unused) { }
static void hexdump(const void *unused, size_t unused2) { }
#endif

/*
 * Function return ABI magic:
 *
 * By returning a simple object of two pointers, the SYSV ABI splits it across
 * %rax and %rdx rather than spilling it to the stack.  This is far more
 * convenient for our asm caller to deal with.
 */
typedef struct {
	void *pm_kernel_entry; /* %eax */
	void *zero_page;       /* %edx */
} asm_return_t;

asm_return_t lz_main(void)
{
	u32 *tb_dev_map;
	u64 pfn, end_pfn;
	u32 dev;
	u32 *code32_start;
	u32 *slaunch_header_offset;
	u32 *sl_stub_entry_offset;
	u32 *data, size;
	void *pm_kernel_entry, *zero_page;
	struct tpm *tpm;

	/*
	 * Now in 64b mode, paging is setup. This is the launching point. We can
	 * now do what we want. First order of business is to setup
	 * DEV to cover memory from the start of bzImage to the end of the LZ
	 * "kernel". At the end, trampoline to the PM entry point which will
	 * include the Secure Launch stub.
	 */

	/* The Zero Page with the boot_params and legacy header */
	zero_page = _p(lz_header.zero_page_addr);

	/* DEV CODE */

	pfn = PAGE_PFN(zero_page);
	end_pfn = PAGE_PFN(PAGE_DOWN((u8*)lz_base + 0x10000));

	/* TODO: check end_pfn is not ouside of range of DEV map */

	/* build protection bitmap */
	for (;pfn <= end_pfn; pfn++) {
		dev_protect_page(pfn, dev_table);
	}

	pci_init();
	dev = dev_locate();
	dev_load_map(dev, _u(dev_table));
	dev_flush_cache(dev);

	/* Set the DEV address for the TB stub to use */
	tb_dev_map = zero_page + BP_TB_DEV_MAP;
	*tb_dev_map = _u(dev_table);

	code32_start = zero_page + BP_CODE32_START;
	slaunch_header_offset = zero_page + BP_MLE_HEADER;
	sl_stub_entry_offset = _p(*code32_start + *slaunch_header_offset + 24);

	print("sl_stub_entry_offset:\n");
	hexdump(sl_stub_entry_offset, 0x100);

	pm_kernel_entry = _p(*code32_start + *sl_stub_entry_offset);

	/*
	 * TODO Note these functions can fail but there is no clear way to
	 * report the error unless SKINIT has some resource to do this. For
	 * now, if an error is returned, this code will most likely just crash.
	 */
	tpm = enable_tpm();
	tpm_request_locality(tpm, 2);

	/* extend TB Loader code segment into PCR17 */
	data = (u32*)(uintptr_t)*code32_start;
	size = (*(u32*)((u8*)zero_page + BP_SYSSIZE)) << 4;

	if (tpm->family == TPM12) {
		sha1sum(&sha1ctx, data, size);
		print("shasum calculated:\n");
		hexdump(sha1ctx.buf, 20);
		tpm_extend_pcr(tpm, 17, TPM_HASH_ALG_SHA1, &sha1ctx.buf[0]);
		print("PCR extended\n");
	} else if (tpm->family == TPM20) {
		sha256sum(sha256_hash, data, size);
		print("shasum calculated:\n");
		hexdump(sha256_hash, SHA256_DIGEST_SIZE);
		tpm_extend_pcr(tpm, 17, TPM_HASH_ALG_SHA256, &sha256_hash[0]);
		print("PCR extended\n");
	}

	tpm_relinquish_locality(tpm);
	free_tpm(tpm);

	/* End of the line, off to the protected mode entry into the kernel */
	print("pm_kernel_entry:\n");
	hexdump(pm_kernel_entry, 0x100);
	print("zero_page:\n");
	hexdump(zero_page, 0x100);
	print("lz_base:\n");
	hexdump(lz_base, 0x100);

	return (asm_return_t){ pm_kernel_entry, zero_page };
}
