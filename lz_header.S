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
#define CS_SEL64         0x0008
#define CS_SEL32         0x0010
#define DS_SEL           0x0018

	.section .text

	.global lz_start
lz_start:

sl_header:
	.word	(_entry - lz_start) /* SL header LZ offset to code start */
	.word	0xffff /* SL header LZ total length */

lz_header:
	.long	0x8e26f178 /* UUID */
	.long	0xe9119204
	.long	0x5bc82a83
	.long	0x02ccc476
	.long	0 /* Total size of Trenchboot Intermediate Loader */
		  /* bzImage (padded out to next page) */
	.long	0 /* Zero Page address */
	.fill	0x14 /* MSB Key Hash */

lz_first_stack:
	.fill LZ_FIRST_STAGE_STACK_SIZE, 1, 0

	.code32

.globl _entry
_entry:
	/*
	 * Per the spec:
	 * EAX - Beginning of LZ containing the SL header.
	 *
	 * Restore the world, get back into longer mode. EBX contains the entry
	 * point which is our only known location in protected mode. We will
	 * use it to set things right then validate it later.
	 */
	movl	%eax, %ebx
	movl	%eax, %esi

	/* Clear R_INIT and DIS_A20M.  */
	movl	$(IA32_VM_CR), %ecx
	rdmsr
	andl	$(~(1 << VM_CR_R_INIT)), %eax
	andl	$(~(1 << VM_CR_DIS_A20M)), %eax
	wrmsr

	/* Fixup some addresses for the GDT and long jump */
	leal	(gdt_desc64 - lz_start + 2)(%ebx), %ebp
	leal	(gdt_table64 - lz_start)(%ebx), %eax
	movl	%eax, (%ebp)

	leal	(.Ljump64 - lz_start + 1)(%ebx), %ebp
	leal	(.Lentry64 - lz_start)(%ebx), %eax
	movl	%eax, (%ebp)

	/* Load GDT */
	leal	(gdt_desc64 - lz_start)(%ebx), %ebp
	lgdt	(%ebp)

	/* Load data segment regs */
	movw	$DS_SEL, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss

	/* Zero out all page table pages so there are no surprises */
	cld /* just in case */
	movl	%ebx, %edi
	addl	$(LZ_PAGE_TABLES_OFFSET), %edi
	xorl	%eax, %eax
	movl	$(LZ_PAGE_TABLES_SIZE/4), %ecx
	rep stosl

	/* First page is the PML4 table with one PDP entry */
	movl	%ebx, %eax
	addl	$(LZ_PAGE_TABLES_OFFSET), %eax
	movl	%eax, %ecx
	addl	$PAGE_SIZE, %ecx
	orl	$0x3, %ecx
	movl	%ecx, (%eax)

	/* Second page is the PDP table with 4 PD entries */
	addl	$PAGE_SIZE, %eax
	movl	%eax, %ecx
	xorl	%edx, %edx
1:
	addl	$PAGE_SIZE, %ecx
	cmpb	$4, %dl
	jz	2f
	orl	$0x3, %ecx
	movl	%ecx, (%eax)
	addl	$0x8, %eax
	incb	%dl
	jmp	1b
2:      /* EAX Page 2 + 0x20 */

	/* Next 4 pages are PDs that map all of mem < 4G as 2M pages */
	addl	$(PAGE_SIZE - 0x20), %eax
	xorl	%edx, %edx
	xorl	%ecx, %ecx
	xorl	%ebx, %ebx
	addl	$0x83, %ecx
1:
	cmpw	$512, %dx
	jz	2f
	movl	%ecx, (%eax)
	addl	$0x8, %eax
	addl	$0x200000, %ecx
	incw	%dx
	jmp	1b
2:
	cmpb	$3, %bl
	jz	3f
	incb	%bl
	xorl	%edx, %edx
	jmp	1b
3:
	/* Done setting up page tables, lower 4G all identity mapped */
	movl	%esi, %ebx

	/* Restore CR4, PAE must be enabled before IA-32e mode */
	movl	%cr4, %ecx
	orl	$(CR4_PAE | CR4_PGE), %ecx
	movl	%ecx, %cr4

	/* Load PML4 table location into PT base register */
	movl	%ebx, %eax
	addl	$LZ_PAGE_TABLES_OFFSET, %eax
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
	.byte	0xea       /* far jmp op */
	.long	0x00000000 /* offset (fixed up) */
	.word	CS_SEL64   /* 64b code segment selector */

	.code64

.Lentry64:
	/* Load data segment regs */
	movw	$DS_SEL, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss

	/* ESI still has original EBX, put it back */
	xorq	%rbx, %rbx
	movl	%esi, %ebx

	/* Load the stage 1 stack */
	movq	%rbx, %rax
	addq	$LZ_FIRST_STAGE_STACK_START, %rax
	movq	%rax, %rsp

	/* Pass the base of the LZ to the setup code */
	movq	%rbx, %rdi

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
	lea		.Lentry_compat(%rip), %rcx

	/* Do the far return */
	pushq	$CS_SEL32
	pushq	%rcx
	retfq

	.code32

.Lentry_compat:
	/* Now in IA-32e compatibility mode, next stop is protected mode */
	/* Load 32b data segment in the segment regs */
	movw	$DS_SEL, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss

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

/* GDT */
.align 16
gdt_desc64:
	.word	gdt_table64_end - gdt_table64 - 1 /* Limit */
	.quad	0x0000000000000000 /* Base */
gdt_desc64_end:

.align 16
gdt_table64:
	/* Null Segment */
	.quad	0x0000000000000000
	/* 64b Code Segment */
	.word	0x0000 /* Limit 1 */
	.word	0x0000 /* Base 1 */
	.byte	0x00   /* Base 2 */
	.byte	0x9a   /* P=1 DPL=0 S=1 Type=1010 C=0 R=1 A=0 */
	.byte	0x20   /* G=0 D=0 L=1 AVL=0 Limit 2 */
	.byte	0x00   /* Base 3 */
	/* 32b Code Segment */
	.word	0xffff /* Limit 1 */
	.word	0x0000 /* Base 1 */
	.byte	0x00   /* Base 2 */
	.byte	0x9a   /* P=1 DPL=0 S=1 Type=0010 C=0 W=1 A=0 */
	.byte	0xcf   /* G=1 D=1 L=0 AVL=0 Limit 2 */
	.byte	0x00   /* Base 3 */
	/* Data Segment, can be used both in 32b and 64b */
	.word	0xffff /* Limit 1 */
	.word	0x0000 /* Base 1 */
	.byte	0x00   /* Base 2 */
	.byte	0x92   /* P=1 DPL=0 S=1 Type=0010 C=0 W=1 A=0 */
	.byte	0xcf   /* G=1 D=1 L=0 AVL=0 Limit 2 */
	.byte	0x00   /* Base 3 */
gdt_table64_end:
