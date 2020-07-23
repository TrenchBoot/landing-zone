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
#include <boot.h>
#include <pci.h>
#include "tpmlib/tpm.h"
#include "tpmlib/tpm2_constants.h"
#include <sha1sum.h>
#include <sha256.h>
#include <linux-bootparams.h>

#ifdef DEBUG
static void print_char(char c)
{
	while ( !(inb(0x3f8 + 5) & 0x20) )
		;

	outb(c, 0x3f8);
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
	u8 *line;
	int all_zero = 0;
	int all_one = 0;
	size_t num_bytes;

	for (i = 0; i < length; i += 16) {
		int j;
		num_bytes = 16;
		line = ((u8 *)memory) + i;

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
static void print_p(const void * unused) { }
static void hexdump(const void *unused, size_t unused2) { }
#endif

static void extend_pcr(struct tpm *tpm, void *data, u32 size, u32 pcr)
{
	if (tpm->family == TPM12) {
		u8 hash[SHA1_DIGEST_SIZE];

		sha1sum(hash, data, size);
		print("shasum calculated:\n");
		hexdump(hash, SHA1_DIGEST_SIZE);
		tpm_extend_pcr(tpm, pcr, TPM_ALG_SHA1, hash);
		print("PCR extended\n");
	} else if (tpm->family == TPM20) {
		u8 sha256_hash[SHA256_DIGEST_SIZE];

		sha256sum(sha256_hash, data, size);
		print("shasum calculated:\n");
		hexdump(sha256_hash, SHA256_DIGEST_SIZE);
		tpm_extend_pcr(tpm, pcr, TPM_ALG_SHA256, &sha256_hash[0]);
		print("PCR extended\n");
	}
}

/*
 * Checks if ptr points to *uncompressed* part of the kernel
 */
static inline void *is_in_kernel(struct boot_params *bp, void *ptr)
{
	if (ptr < _p(bp->code32_start) ||
	    ptr >= _p(bp->code32_start + (bp->syssize << 4)) ||
	    (ptr >= _p(bp->code32_start + bp->payload_offset) &&
	     ptr < _p(bp->code32_start + bp->payload_offset + bp->payload_length)))
	    return NULL;
	return ptr;
}

static inline struct kernel_info *get_kernel_info(struct boot_params *bp)
{
	return is_in_kernel(bp, _p(bp->code32_start + bp->kern_info_offset));
}

static inline struct mle_header *get_mle_hdr(struct boot_params *bp,
                                      struct kernel_info *ki)
{
	return is_in_kernel(bp, _p(bp->code32_start + ki->mle_header_offset));
}

static inline void *get_kernel_entry(struct boot_params *bp,
                                     struct mle_header *mle_hdr)
{
	return is_in_kernel(bp, _p(bp->code32_start + mle_hdr->sl_stub_entry));
}

/*
 * Even though die() has both __attribute__((noreturn)) and unreachable(),
 * Clang still complains if it isn't repeated here.
 */
static void __attribute__((noreturn)) reboot(void)
{
	print("Rebooting now...");
	die();
	unreachable();
}

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
	struct boot_params *bp;
	struct kernel_info *ki;
	struct mle_header *mle_header;
	void *pm_kernel_entry;
	struct tpm *tpm;

	/*
	 * Now in 64b mode, paging is setup. This is the launching point. We can
	 * now do what we want. First order of business is to setup
	 * DEV to cover memory from the start of bzImage to the end of the LZ
	 * "kernel". At the end, trampoline to the PM entry point which will
	 * include the Secure Launch stub.
	 */

	/* The Zero Page with the boot_params and legacy header */
	bp = _p(lz_header.zero_page_addr);

	pci_init();

	print("\ncode32_start ");
	print_p(_p(bp->code32_start));

	if (bp->version                            < 0x020f
	    || (ki = get_kernel_info(bp))         == NULL
	    || ki->header                         != KERNEL_INFO_HEADER
	    || (mle_header = get_mle_hdr(bp, ki)) == NULL
	    || mle_header->uuid[0]                != MLE_UUID0
	    || mle_header->uuid[1]                != MLE_UUID1
	    || mle_header->uuid[2]                != MLE_UUID2
	    || mle_header->uuid[3]                != MLE_UUID3) {
		print("\nKernel is too old or MLE header not present.\n");
		reboot();
	}

	print("\nmle_header\n");
	hexdump(mle_header, sizeof(struct mle_header));

	pm_kernel_entry = get_kernel_entry(bp, mle_header);

	if (pm_kernel_entry == NULL) {
		print("\nBad kernel entry in MLE header.\n");
		reboot();
	}

	/*
	 * TODO Note these functions can fail but there is no clear way to
	 * report the error unless SKINIT has some resource to do this. For
	 * now, if an error is returned, this code will most likely just crash.
	 */
	tpm = enable_tpm();
	tpm_request_locality(tpm, 2);

	/* extend TB Loader code segment into PCR17 */
	extend_pcr(tpm, _p(bp->code32_start), bp->syssize << 4, 17);

	tpm_relinquish_locality(tpm);
	free_tpm(tpm);

	/* End of the line, off to the protected mode entry into the kernel */
	print("pm_kernel_entry:\n");
	hexdump(pm_kernel_entry, 0x100);
	print("zero_page:\n");
	hexdump(bp, 0x280);
	print("lz_base:\n");
	hexdump(_start, 0x100);

	print("lz_main() is about to exit\n");

	return (asm_return_t){ pm_kernel_entry, bp };
}

static void __maybe_unused build_assertions(void)
{
    struct boot_params b;
    struct kernel_info k;

    BUILD_BUG_ON(offsetof(typeof(b), tb_dev_map)        != 0x0d8);
    BUILD_BUG_ON(offsetof(typeof(b), syssize)           != 0x1f4);
    BUILD_BUG_ON(offsetof(typeof(b), version)           != 0x206);
    BUILD_BUG_ON(offsetof(typeof(b), code32_start)      != 0x214);
    BUILD_BUG_ON(offsetof(typeof(b), cmd_line_ptr)      != 0x228);
    BUILD_BUG_ON(offsetof(typeof(b), cmdline_size)      != 0x238);
    BUILD_BUG_ON(offsetof(typeof(b), payload_offset)    != 0x248);
    BUILD_BUG_ON(offsetof(typeof(b), payload_length)    != 0x24c);
    BUILD_BUG_ON(offsetof(typeof(b), kern_info_offset)  != 0x268);

    BUILD_BUG_ON(offsetof(typeof(k), mle_header_offset) != 0x010);
}
