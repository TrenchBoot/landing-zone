/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BOOTPARAMS_H
#define _LINUX_BOOTPARAMS_H

struct boot_params {
    u8 _pad0[0x0d8];
    u32 tb_dev_map;
    u8 _pad2[0x118];
    u32 syssize;
    u8 _pad3[0x00e];
    u16 version;
    u8 _pad4[0x00c];
    u32 code32_start;
    u8 _pad6[0x010];
    u32 cmd_line_ptr;
    u8 _pad8[0x00c];
    u32 cmdline_size;
    u8 _pad10[0x02c];
    u32 kern_info_offset;
};

#define KERNEL_INFO_HEADER 0x506f544c

struct kernel_info {
    u32 header;
    u32 size;
    u32 size_total;
    u32 setup_type_max;
    u32 mle_header_offset;
};

#define MLE_UUID0	0x9082ac5a
#define MLE_UUID1	0x74a7476f
#define MLE_UUID2	0xa2555c0f
#define MLE_UUID3	0x42b651cb
struct mle_header {
	u32 uuid[4];
	u32 size;		/* 0x00000034 MLE header size */
	u32 version;		/* 0x00020002 MLE version 2.2 */
	u32 sl_stub_entry;	/* Linear entry point of MLE (virt. address) */
	/* The following fields are used only for Intel TXT */
	u32 first_page;		/* First valid page of MLE */
	u32 start_offset;	/* Offset within binary of first byte of MLE */
	u32 end_offset;		/* Offset within binary of last byte + 1 of MLE */
	u32 vector;		/* Bit vector of MLE-supported capabilities */
	u32 cmdline_start;	/* Starting linear address of command line */
	u32 cmdline_end;	/* Ending linear address of command line */
};

#endif /* _LINUX_BOOTPARAMS_H */
