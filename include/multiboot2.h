/*   multiboot2.h - Multiboot 2 header file. */
/*   Copyright (C) 1999,2003,2007,2008,2009,2010  Free Software Foundation, Inc.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL ANY
 *  DEVELOPER OR DISTRIBUTOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 *  IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef MULTIBOOT_HEADER
#define MULTIBOOT_HEADER 1

/*  This should be in %eax. */
#define MULTIBOOT2_BOOTLOADER_MAGIC             0x36d76289

/*  Flags set in the ’flags’ member of the multiboot header. */
#define MULTIBOOT_TAG_ALIGN                  8
#define MULTIBOOT_TAG_TYPE_END               0
#define MULTIBOOT_TAG_TYPE_CMDLINE           1
#define MULTIBOOT_TAG_TYPE_MODULE            3
#define MULTIBOOT_TAG_TYPE_ELF_SECTIONS      9
#define MULTIBOOT_TAG_TYPE_LOAD_BASE_ADDR    21

#ifndef __ASSEMBLY__

typedef unsigned char           u8;
typedef unsigned short          u16;
typedef unsigned int            u32;
typedef unsigned long long      u64;

struct multiboot_tag
{
  u32 type;
  u32 size;
};

struct multiboot_tag_string
{
  u32 type;
  u32 size;
  char string[0];
};

struct multiboot_tag_module
{
  u32 type;
  u32 size;
  u32 mod_start;
  u32 mod_end;
  char cmdline[0];
};

typedef struct {
  u32 pad0[1];
  u32 sh_type;
  u32 pad1[2];
  u32 sh_offset;
  u32 sh_size;
  u32 pad2[4];
} Elf32_Shdr;

enum ShT_Types {
  SHT_NULL      = 0,   // Null section
  SHT_PROGBITS  = 1,   // Program information
  SHT_SYMTAB    = 2,   // Symbol table
  SHT_STRTAB    = 3,   // String table
  SHT_RELA      = 4,   // Relocation (w/ addend)
  SHT_HASH      = 5,   // Symbol hash table
  SHT_DYNAMIC   = 6,   // Dynamic linking information
  SHT_NOTE      = 7,   // Notes
  SHT_NOBITS    = 8,   // Not present in file (bss)
  SHT_REL       = 9,   // Relocation (no addend)
  SHT_SHLIB     = 10,  // Reserved
  SHT_DYNSYM    = 11   // Dynamic loader symbol table
};

struct multiboot_tag_elf_sections
{
  u32 type;
  u32 size;
  u32 num;
  u32 entsize;
  u32 shndx;
  char sections[0];
};

struct multiboot_tag_load_base_addr
{
  u32 type;
  u32 size;
  u32 load_base_addr;
};

static inline struct multiboot_tag *multiboot_next_tag(struct multiboot_tag *t)
{
  void *tag = (void *)t;
  tag += (t->size + (MULTIBOOT_TAG_ALIGN - 1)) & ~(MULTIBOOT_TAG_ALIGN - 1);
  return tag;
}

#endif /*  ! __ASSEMBLY__ */

#endif /*  ! MULTIBOOT_HEADER */
