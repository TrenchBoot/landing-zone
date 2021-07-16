/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 *
 * Author:
 *     Ross Philipson <ross.philipson@oracle.com>
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
#include <iommu_defs.h>
#include <multiboot2.h>

/* Selectors, CS and SS compatible with initial state after SKINIT */
#define CS_SEL32         0x0008
#define DS_SEL           0x0010
#ifdef __x86_64__
#define CS_SEL64         0x0018
#endif

	.section .headers, "ax", @progbits

GLOBAL(sl_header)
	.word	_entry           /* SL header LZ offset to code start */
	.word	bootloader_data  /* SL header LZ measured length */
	.word	lz_info
ENDDATA(sl_header)

GLOBAL(lz_stack_canary)
	.long STACK_CANARY
ENDDATA(lz_stack_canary)
lz_stack:
	.fill 0x280, 1, 0xcc   /* Enough space for now */
	.align 0x10, 0         /* Ensure proper alignment for 64bit */
.L_stack_base:
ENDDATA(lz_stack)

	.text
	.code32

GLOBAL(_entry)
	/*
	 * Per the spec:
	 * %eax	   - Beginning of LZ containing the SL header
	 * %edx	   - Family/Model/Stepping
	 * %esp	   - %eax + 64k (End of SLB)
	 * %cs	   - 32bit Flat, selector 0x08
	 * %ss	   - 32bit Flat, selector 0x10
	 * %ds/etc - 16bit Real Mode segments.	Unusable.
	 *
	 * Restore the world, get back into long mode.
	 *
	 * The GDT needs relocating before we have a usable %ds, which must be
	 * done with an %ss-relative write.  Therefore, we store the base
	 * address in %ebp.
	 */
	mov	%eax, %ebp

	/* Set up the Stage 1 stack. */
	lea	.L_stack_base(%ebp), %esp

	/*
	 * Clobber IDTR.limit to prevent stray interrupts/exceptions/INT from
	 * vectoring via the IVT into unmeasured code.
	 */
	push	$0
	push	$0
	lidt	(%esp)
	add	$8, %esp

	/* Clear R_INIT and DIS_A20M.  */
	mov	$IA32_VM_CR, %ecx
	rdmsr
	and	$~(VM_CR_DIS_A20M | VM_CR_R_INIT), %eax
	wrmsr

	/* Relocate GDT.base, 64bit ljmp offset, and pagetables. */
	add	%ebp, 2 + gdtr(%ebp)
#ifdef __x86_64__
	add	%ebp, 1 + .Ljump64(%ebp)
	add	%ebp,        l4_identmap(%ebp) /* L4[0] => L3        */
	add	%ebp,        l3_identmap(%ebp) /* L3[0] => First  L2 */
	add	%ebp, 0x08 + l3_identmap(%ebp) /* L3[1] => Second L2 */
	add	%ebp, 0x10 + l3_identmap(%ebp) /* L3[2] => Third  L2 */
	add	%ebp, 0x18 + l3_identmap(%ebp) /* L3[3] => Fourth L2 */
	add	%ebp,        l2_identmap(%ebp) /* L2[0] => L1        */
#endif

	/* Load GDT */
	lgdt	gdtr(%ebp)

	/* Load data segment regs.  %ss is already flat and matches DS_SEL. */
	mov	$DS_SEL, %eax
	mov	%eax, %ds
	mov	%eax, %es

#ifdef __x86_64__
	/* Restore CR4, PAE must be enabled before IA-32e mode */
	mov	%cr4, %ecx
	or	$CR4_PAE, %ecx
	mov	%ecx, %cr4

	/* Load PML4 table location into PT base register */
	lea	l4_identmap(%ebp), %eax
	mov	%eax, %cr3

	/* Enable IA-32e mode and paging */
	mov	$IA32_EFER, %ecx
	rdmsr
	or	$EFER_LME >> 8, %ah
	wrmsr

	mov	%cr0, %eax
	or	$CR0_PG | CR0_NE | CR0_TS | CR0_MP, %eax
	mov	%eax, %cr0

	/* Now in IA-32e compatibility mode, ljmp to 64b mode */
.Ljump64:
        ljmp	$CS_SEL64, $1f /* Offset - dynamically relocated. */

	.code64

1:
#endif	/* 64bit setup. */

	call	lz_main

	/*
	 * lz_main() is magic.  It returns two pointers by register:
	 *
	 * %eax - protected mode kernel entry
	 * %edx - ZP base
	 *
	 * We stash the entry point in %ebx and the Zero Page pointer in %esi.
	 * This both protects them from clobbering during teardown, and
	 * matches the ABI for entering Linux.
	 */
	mov	%eax, %ebx
	mov	%edx, %esi

#ifdef __x86_64__

	/* Setup target to ret to compat mode */
	lea	1f(%rip), %ecx
	push	$CS_SEL32
	push	%rcx
	lretq

	.code32
1:	/* Now in IA-32e compatibility mode, next stop is protected mode */

	/* Turn paging off - we are identity mapped so we will survive */
	mov	%cr0, %eax
	and	$~(CR0_PG | CR0_NE | CR0_TS | CR0_MP), %eax
	mov	%eax, %cr0

	/* Disable IA-32e mode */
	mov	$IA32_EFER, %ecx
	rdmsr
	and	$~(EFER_LME >> 8), %ah
	wrmsr

	/* Now in protected mode, make things look like TXT post launch */
	mov	%cr4, %eax
	and	$~CR4_PAE, %eax
	mov	%eax, %cr4
#endif /* 64bit teardown. */

	push	$0
	popf

	cmpl	$MULTIBOOT2, boot_protocol(%ebp)
	je	multiboot2_kernel

	/* Jump to entry target - EBX: startup_32, ESI: ZP base, EDX: LZ base */
	mov	%ebp, %edx
	jmp	*%ebx

multiboot2_kernel:
	/* Jump to entry target - EBX: MBI pointer, EAX: Multiboot2 magic number */
	xchg	%esi, %ebx
	mov	$MULTIBOOT2_BOOTLOADER_MAGIC, %eax
	jmp *%esi
ENDFUNC(_entry)

	.data

.align 8
gdt:
	/* Null Segment. Reused for 32bit GDTR */
	.word   0
gdtr:
	.word	.Lgdt_end - gdt - 1 /* Limit */
	.long	gdt                 /* Base - dynamically relocated. */
ENDDATA(gdtr)

	/* 32b Code Segment */
	.word	0xffff /* Limit 1 */
	.word	0x0000 /* Base 1 */
	.byte	0x00   /* Base 2 */
	.byte	0x9b   /* P=1 DPL=0 S=1 Type=0010 C=0 W=1 A=1 */
	.byte	0xcf   /* G=1 D=1 L=0 AVL=0 Limit 2 */
	.byte	0x00   /* Base 3 */
	/* Data Segment, can be used both in 32b and 64b */
	.word	0xffff /* Limit 1 */
	.word	0x0000 /* Base 1 */
	.byte	0x00   /* Base 2 */
	.byte	0x93   /* P=1 DPL=0 S=1 Type=0010 C=0 W=1 A=1 */
	.byte	0xcf   /* G=1 D=1 L=0 AVL=0 Limit 2 */
	.byte	0x00   /* Base 3 */
#ifdef __x86_64__
	/* 64b Code Segment */
	.word	0x0000 /* Limit 1 */
	.word	0x0000 /* Base 1 */
	.byte	0x00   /* Base 2 */
	.byte	0x9b   /* P=1 DPL=0 S=1 Type=1010 C=0 R=1 A=1 */
	.byte	0x20   /* G=0 D=0 L=1 AVL=0 Limit 2 */
	.byte	0x00   /* Base 3 */
#endif
.Lgdt_end:
ENDDATA(gdt)

.section .page_data, "a", @progbits
.align PAGE_SIZE
#ifdef __x86_64__
	/* 64bit Pagetables, identity map of the first 4G of RAM. */

l1_identmap: /* 1x L1 page, mapping 2M of RAM.  No relocations. */
	idx = 0
	.rept 512
	.quad (idx << L1_PT_SHIFT) + _PAGE_AD + _PAGE_RW + _PAGE_PRESENT
	idx = idx + 1
	.endr
ENDDATA(l1_identmap)

l2_identmap: /* 4x L2 pages, each mapping 1G of RAM.  1 relocation. */
	.quad l1_identmap + _PAGE_AD + _PAGE_RW + _PAGE_PRESENT
	idx = 1
	.rept (512 * 4) - 1
	.quad (idx << L2_PT_SHIFT) + _PAGE_PSE + _PAGE_AD + _PAGE_RW + _PAGE_PRESENT
	idx = idx + 1
	.endr
ENDDATA(l2_identmap)

l3_identmap: /* 1x L3 page, mapping the 4x L2 pages.  4 relocations. */
	idx = 0
	.rept 4
	.quad l2_identmap + (idx * PAGE_SIZE) + _PAGE_AD + _PAGE_RW + _PAGE_PRESENT
	idx = idx + 1
	.endr
	.align PAGE_SIZE
ENDDATA(l3_identmap)

l4_identmap: /* 1x L4 page, mapping the L3 page. 1 relocation. */
	.quad l3_identmap + _PAGE_AD + _PAGE_RW + _PAGE_PRESENT
	.align PAGE_SIZE
ENDDATA(l4_identmap)
#endif

GLOBAL(command_buf)
	.fill PAGE_SIZE
ENDDATA(command_buf)

GLOBAL(event_log)
	.fill PAGE_SIZE
ENDDATA(event_log)

GLOBAL(device_table)
	.rept (256)
	.quad IOMMU_DTE_Q0_V + IOMMU_DTE_Q0_TV
	.quad 0
	.quad 0 /* IOMMU_DTE_Q2_IV + IOMMU_DTE_Q2_IG */
	.quad 0
	.endr
ENDDATA(device_table)

	.section .lz_info, "a", @progbits
GLOBAL(lz_info)
	.long	0x8e26f178	/* UUID */
	.long	0xe9119204
	.long	0x5bc82a83
	.long	0x02ccc476
	.long	0		/* Version */
	.word	0		/* MSB Key Algorithm */
	.fill	0x14		/* MSB Key Hash */

	/* Hashes of LZ to be written to DRTM TPM event log */
	.long	2		/* count */
	.word	0x0004		/* sha1_id */
	.fill   0x14		/* sha1_hash */
	.word	0x000B		/* sha256_id */
	.fill   0x20		/* sha256_hash */
ENDDATA(lz_info)

	.section .bootloader_data, "a", @progbits
GLOBAL(bootloader_data)
	.word	0			/* Dummy data to make sure that file isn't truncated */
