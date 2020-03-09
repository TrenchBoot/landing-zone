/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BOOTPARAMS_H
#define _LINUX_BOOTPARAMS_H

struct boot_params {
    u8 _pad0[0x0d8];
    u32 tb_dev_map;
    u8 _pad2[0x118];
    u32 syssize;
    u8 _pad4[0x01c];
    u32 code32_start;
    u8 _pad6[0x010];
    u32 cmd_line_ptr;
    u8 _pad8[0x00c];
    u32 cmdline_size;
    u8 _pad10[0x02c];
    u32 mle_header;
};

#endif /* _LINUX_BOOTPARAMS_H */
