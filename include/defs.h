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

#ifndef __DEFS_H__
#define __DEFS_H__

/*
 * All global references, including externs, need to be treated as hidden, to
 * avoid a GOT reference in the 32bit build.
 */
#pragma GCC visibility push(hidden)

#define LINUX_BOOT      0
#define MULTIBOOT2      2

#define STACK_CANARY    0xDEADBEEF

#define PAGE_SHIFT      12
#define PAGE_SIZE       (1 << PAGE_SHIFT)
#define PAGE_MASK       (~(PAGE_SIZE - 1))
#define PAGE_UP(p)      (((uintptr_t)(p) + PAGE_SIZE - 1) & PAGE_MASK)
#define PAGE_DOWN(p)    ((uintptr_t)(p) & ~(PAGE_SIZE - 1))
#define PAGE_PFN(p)     ((uintptr_t)(p) >> PAGE_SHIFT)

#define GIGABYTE    0x40000000
#define SLB_SIZE    0x10000

#define _u(x) ((uintptr_t)(x))
#define _p(x) ((void *)_u(x))

#ifdef __ASSEMBLY__

#define GLOBAL(name) \
    .global name;    \
    name:

#define ENDDATA(name)    \
    .type name, @object; \
    .size name, . - name

#define ENDFUNC(name)      \
    .type name, @function; \
    .size name, . - name

#endif

#define __packed        __attribute__ ((packed))
#define __maybe_unused  __attribute__ ((unused))
#define noinline        __attribute__ ((noinline))

/* Due to the 64k total size limit, group all page aligned data together. */
#define __page_data \
    __attribute__ ((__section__(".page_data"), __aligned__(PAGE_SIZE)))

#define unreachable()   __builtin_unreachable()
#define offsetof(a, b)  __builtin_offsetof(a, b)

#define BUILD_BUG_ON(x) ({ _Static_assert(!(x), "!(" #x ")"); })

/* CRs */
#define CR0_PE  0x00000001 /* Protected mode Enable */
#define CR0_MP  0x00000002 /* "Math" (fpu) Present */
#define CR0_EM  0x00000004 /* EMulate FPU instructions. (trap ESC only) */
#define CR0_TS  0x00000008 /* Task Switched (if MP, trap ESC and WAIT) */
#define CR0_ET  0x00000010 /* Extension type */
#define CR0_PG  0x80000000 /* PaGing enable */
#define CR0_NE  0x00000020 /* Numeric Error enable (EX16 vs IRQ13) */
#define CR0_WP  0x00010000 /* Write Protect (honor page protect in all modes) */
#define CR0_AM  0x00040000 /* Alignment Mask (set to enable AC flag) */
#define CR0_NW  0x20000000 /* Not Write-through */
#define CR0_CD  0x40000000 /* Cache Disable */

#define CR4_VME   0x00000001 /* Virtual 8086 mode extensions */
#define CR4_PVI   0x00000002 /* Protected-mode virtual interrupts */
#define CR4_TSD   0x00000004 /* Time stamp disable */
#define CR4_DE    0x00000008 /* Debugging extensions */
#define CR4_PSE   0x00000010 /* Page size extensions */
#define CR4_PAE   0x00000020 /* Physical address extension */
#define CR4_MCE   0x00000040 /* Machine check enable */
#define CR4_PGE   0x00000080 /* Page global enable */
#define CR4_PCE   0x00000100 /* Performance monitoring counter enable */
#define CR4_FXSR  0x00000200/* Fast FPU save/restore used by OS */
#define CR4_XMM   0x00000400 /* enable SIMD/MMX2 to use except 16 */
#define CR4_VMXE  0x00002000/* enable VMX */
#define CR4_SMXE  0x00004000/* enable SMX */
#define CR4_PCIDE 0x00020000/* enable PCID */

/* Pagetable bits */
#define _PAGE_PRESENT  0x001
#define _PAGE_RW       0x002
#define _PAGE_AD       0x060
#define _PAGE_PSE      0x080
#define L1_PT_SHIFT    12 /* 4Kb */
#define L2_PT_SHIFT    21 /* 2Mb */

/* MSRs */

#define IA32_EFER     0xc0000080
#define IA32_VM_CR    0xc0010114
#define IA32_DEBUGCTL 0x000001d9

/* EFER bits */
#define EFER_SCE  (1 <<  0) /* SYSCALL/SYSRET */
#define EFER_LME  (1 <<  8) /* Long Mode enable */
#define EFER_LMA  (1 << 10) /* Long Mode Active (read-only) */
#define EFER_NXE  (1 << 11) /* no execute */
#define EFER_SVME (1 << 12) /* SVM extensions enable */

/* VM CR MSR bits */
#define VM_CR_DPD          (1 << 0)
#define VM_CR_R_INIT       (1 << 1)
#define VM_CR_DIS_A20M     (1 << 2)
#define VM_CR_SVME_DISABLE (1 << 4)

#endif /* __DEFS_H__ */
