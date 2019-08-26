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
#define CS_SEL           0x0008
#define DS_SEL           0x0010
#define CS_LZ            0x0018
#define DS_LZ            0x0020

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
	.fill LZ_FIRST_STAGE_STACK_SIZE/4, 4, 0xcefaedfe

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
	movl	$LZ_FIRST_STAGE_STACK_START, %esp

	/* Clear R_INIT and DIS_A20M.  */
	movl	$(IA32_VM_CR), %ecx
	rdmsr
	andl	$(~(1 << VM_CR_R_INIT)), %eax
	andl	$(~(1 << VM_CR_DIS_A20M)), %eax
	wrmsr

	movl	%ebp, %eax

	/* Relocate GDT.base, ljmp offset, and LZ segments base addresses. */
	addl	%ebp, 2 + gdtr(%ebp)
	addl	%ebp, 1 + .Ljump(%ebp)
	addw	%ax, _lz_cs_base1(%ebp)
	addw	%ax, _lz_ds_base1(%ebp)
	shrl	$16, %eax
	addb	%al, 2 + _lz_cs_base1(%ebp)
	addb	%al, 2 + _lz_ds_base1(%ebp)
	addb	%ah, _lz_cs_base3(%ebp)
	addb	%ah, _lz_ds_base3(%ebp)

	/* Load GDT */
	lgdt	gdtr(%ebp)

	/* Load data segment regs. */
	movl	$DS_LZ, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
	movl	$DS_SEL, %eax
	movl	%eax, %fs
	movl	%eax, %gs

	ljmpl	$CS_LZ, $1f
1:
	/* Pass the base of the LZ to the setup code */
	pushl	%ebp

	/* End of the line, we should never return */
	calll	setup
	ud2

.globl print_char
print_char:
	movw	$0x3f8, %dx
	addw	$5, %dx
1:
	inb	%dx, %al
	testb	$0x20, %al
	jz	1b
	movw	$0x3f8, %dx
	movl	4(%esp), %eax
	outb	%al, %dx
	retl

.globl load_stack
load_stack:
	movl    (%esp), %eax /* Return address */
	movl    4(%esp), %esp
	pushl   %eax
	retl

.globl stgi
stgi:
	.byte	0x0f, 0x01, 0xdc
	retl

.globl lz_exit
lz_exit:
	/* We do not return */
	addl $4, %esp

	/* Now in protected mode, make things look like TXT post launch */
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

	movl	$(0x00000400), %eax
	movl	%eax, %dr7 /* DR7 = 00000400H */

	movl	$(IA32_DEBUGCTL), %ecx
	rdmsr
	xorw	%ax, %ax /* 16 - 63 reserved */
	wrmsr /* IA32_DEBUGCTL = 0 */

	/* Save entry target where TXT would pass it */
	/* EBX has protected mode kernel entry */
	/* ESI has ZP base (where startup_32 expects it) */
	/* EDX has LZ base (where Trenchboot expects it) */
	popl	%ebx
	popl	%esi
	popl	%edx

	/* Load flat data segments. */
	movl	$DS_SEL, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss

	/* Switch CS back to flat mode */
.Ljump:
	ljmpl	$CS_SEL, $1f
1:

	/* Jump to entry target - EBX: startup_32 ESI: ZP base EDX: LZ base */
	jmpl	*%ebx

	.data

.align 8
gdt:
	/* Null Segment. Reused for 32bit GDTR */
	.word   0
gdtr:
	.word	.Lgdt_end - gdt - 1 /* Limit */
	.long	gdt                 /* Base  */
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
	/* LZ Code Segment */
	.word	0x0010 /* Limit 1 */
_lz_cs_base1:
	.word	0x0000 /* Base 1 */
	.byte	0x00   /* Base 2 */
	.byte	0x9b   /* P=1 DPL=0 S=1 Type=1010 C=0 R=1 A=1 */
	.byte	0xc0   /* G=1 D=1 L=0 AVL=0 Limit 2 */
_lz_cs_base3:
	.byte	0x00   /* Base 3 */
	/* LZ Data Segment */
	.word	0x0010 /* Limit 1 */
_lz_ds_base1:
	.word	0x0000 /* Base 1 */
	.byte	0x00   /* Base 2 */
	.byte	0x93   /* P=1 DPL=0 S=1 Type=0010 C=0 R=1 A=1 */
	.byte	0xc0   /* G=1 D=1 L=0 AVL=0 Limit 2 */
_lz_ds_base3:
	.byte	0x00   /* Base 3 */
.Lgdt_end:
ENDDATA(gdt)

