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
#include <config.h>

/* Selectors, CS and SS compatible with initial state after SKINIT */
#define CS_SEL32         0x0008
#define DS_SEL           0x0010
#define CS_SEL64         0x0018

	.section .text

sl_header:
	.word	_entry /* SL header LZ offset to code start */
	.word	0xffff /* SL header LZ total length */

GLOBAL(lz_header) /* The LZ header setup by the bootloader */
	.long	0x8e26f178 /* UUID */
	.long	0xe9119204
	.long	0x5bc82a83
	.long	0x02ccc476
	.long	0 /* Total size of Trenchboot Intermediate Loader */
		  /* bzImage (padded out to next page) */
	.long	0 /* Zero Page address */
	.fill	0x14 /* MSB Key Hash */
ENDDATA(lz_header)

lz_first_stack:
	.fill LZ_FIRST_STAGE_STACK_SIZE, 1, 0

	.code32

.globl _entry
_entry:
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
	movl	%eax, %ebp

	/* Set up the Stage 1 stack. */
	leal	LZ_FIRST_STAGE_STACK_START(%ebp), %esp

	/* Clear R_INIT and DIS_A20M.  */
	movl	$(IA32_VM_CR), %ecx
	rdmsr
	andl	$(~(1 << VM_CR_R_INIT)), %eax
	andl	$(~(1 << VM_CR_DIS_A20M)), %eax
	wrmsr

	/* Relocate GDT.base, 64bit ljmp offset, and pagetables. */
	addl	%ebp, 2 + gdtr(%ebp)
	addl	%ebp, 1 + .Ljump64(%ebp)
	addl	%ebp,        l4_identmap(%ebp) /* L4[0] => L3        */
	addl	%ebp,        l3_identmap(%ebp) /* L3[0] => First  L2 */
	addl	%ebp, 0x08 + l3_identmap(%ebp) /* L3[1] => Second L2 */
	addl	%ebp, 0x10 + l3_identmap(%ebp) /* L3[2] => Third  L2 */
	addl	%ebp, 0x18 + l3_identmap(%ebp) /* L3[3] => Fourth L2 */
	addl	%ebp,        l2_identmap(%ebp) /* L2[0] => L1        */

	/* Load GDT */
	lgdt	gdtr(%ebp)

	/* Load data segment regs.  %ss is already flat and matches DS_SEL. */
	movl	$DS_SEL, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs

	/* Restore CR4, PAE must be enabled before IA-32e mode */
	movl	%cr4, %ecx
	orl	$(CR4_PAE | CR4_PGE), %ecx
	movl	%ecx, %cr4

	/* Load PML4 table location into PT base register */
	leal	l4_identmap(%ebp), %eax
	movl	%eax, %cr3

	/* Enable IA-32e mode and paging */
	movl	$(IA32_EFER), %ecx
	rdmsr
	orl	$(1 << EFER_LME), %eax
	wrmsr
	movl	%cr0, %eax
	orl	$(CR0_PG | CR0_NE | CR0_ET | CR0_MP | CR0_PE), %eax
	movl	%eax, %cr0
	jmp	1f
1:
	/* Now in IA-32e compatibility mode, ljmp to 64b mode */

.Ljump64:
        ljmpl	$CS_SEL64, $1f /* Offset - dynamically relocated. */

	.code64

1:
	/* Pass the base of the LZ to the setup code */
	movl	%ebp, %edi

	/* End of the line, we should never return */
	callq	setup
	ud2

.globl print_char
print_char:
	pushq	%rax
	pushq	%rdx
	xorq	%rdx, %rdx
	movw	$0x3f8, %dx
	addw	$5, %dx
1:
	inb	%dx, %al
	testb	$0x20, %al
	jz	1b
	movw	$0x3f8, %dx
	movl	%edi, %eax
	outb	%al, %dx
	popq	%rdx
	popq	%rax
	retq

.globl load_stack
load_stack:
	movq	(%rsp), %rax /* Return address */
	movq	%rdi, %rsp
	pushq	%rax
	retq

.globl stgi
stgi:
	.byte	0x0f, 0x01, 0xdc
	retq

.globl lz_exit
lz_exit:
	/* RDI has protected mode kernel entry */
	/* RSI has ZP base (where startup_32 expects it) */
	/* RDX has LZ base (where Trenchboot expects it) */

	/* Save entry target where TXT would pass it */
	movl	%edi, %ebx

	/* Stash RDX in RBP since r/w MSR will clobber it */
	movq	%rdx, %rbp

	/* Setup target to ret to compat mode */
	lea	.Lentry_compat(%rip), %rcx

	/* Do the far return */
	pushq	$CS_SEL32
	pushq	%rcx
	lretq

	.code32

.Lentry_compat:
	/* Now in IA-32e compatibility mode, next stop is protected mode */

	/* Turn paging off - we are identity mapped so we will survive */
	movl	%cr0, %eax
	andl	$(~CR0_PG), %eax
	movl	%eax, %cr0

	/* Disable IA-32e mode */
	movl	$(IA32_EFER), %ecx
	rdmsr
	andl	$(~(1 << EFER_LME)), %eax
	wrmsr

.Lentry32:
	/* Now in protected mode, make things look like TXT post launch */
	pushfl
	popl	%eax
	movl	$(0x00000002), %eax
	pushl	%eax
	popfl /* EFLAGS = 00000002H */

	movl	%cr0, %eax
	andl	$(~CR0_WP), %eax
	andl	$(~CR0_AM), %eax
	movl	%eax, %cr0 /* -PG, -AM, -WP; Others unchanged */

	movl	%cr4, %eax
	xorl	%eax, %eax
	andl	$(CR4_SMXE), %eax
	movl	%eax, %cr4 /* 0x00004000 +SMX -PAE -PGE*/

	movl	$(IA32_EFER), %ecx
	rdmsr
	andl	$(~(1 << EFER_SCE)), %eax
	andl	$(~(1 << EFER_NXE)), %eax
	andl	$(~(1 << EFER_SVME)), %eax
	wrmsr /* IA32_EFER = 0 */

	movl	%dr7, %eax
	movl	$(0x00000400), %eax
	movl	%eax, %dr7 /* DR7 = 00000400H */

	movl	$(IA32_DEBUGCTL), %ecx
	rdmsr
	xorw	%ax, %ax /* 16 - 63 reserved */
	wrmsr /* IA32_DEBUGCTL = 0 */

	/* Jump to entry target - EBX: startup_32 ESI: ZP base EDX: LZ base */
	movl	%ebp, %edx
	jmp	*%ebx

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
	/* 64b Code Segment */
	.word	0x0000 /* Limit 1 */
	.word	0x0000 /* Base 1 */
	.byte	0x00   /* Base 2 */
	.byte	0x9b   /* P=1 DPL=0 S=1 Type=1010 C=0 R=1 A=1 */
	.byte	0x20   /* G=0 D=0 L=1 AVL=0 Limit 2 */
	.byte	0x00   /* Base 3 */
.Lgdt_end:
ENDDATA(gdt)

	.section .page_data, "a", @progbits
	.align PAGE_SIZE

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
