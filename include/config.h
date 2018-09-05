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

#ifndef __CONFIG_H__
#define __CONFIG_H__

/**********************************************************
 * LZ fixed memory layout
 *
 * +---------------+ EAX - 0x1000 - PAGE_UP(Size IL Image)
 * |               |
 * | Intermediate  |
 * |   Loader      |
 * |   bzImage     |
 * |               |
 * +---------------+ EAX - 0x1000
 * |   Second      |
 * |   Stage       |
 * |   Stack       |
 * +---------------+ EAX (begin LZ)
 * |   SL Header   | [0x4b]
 * | ------------- |
 * |   LZ Header   | [0x2Cb]
 * | ------------- |
 * |   First       | [0x1D0b]
 * |   Stage       |
 * |   Stack       |
 * | ------------- | EAX + 0x200
 * |               |
 * |   LZ Code     |
 * |               |
 * | ------------- | EAX + 0x7000
 * |     DEV       | [0x3000b]
 * |   Tables      |
 * | ------------- | EAX + 0xA000
 * |    Page       | [0x6000b]
 * |   Tables      |
 * +---------------+ EAX + 0x10000 (end of LZ)
 *
 **********************************************************/

#define LZ_SECOND_STAGE_STACK_OFFSET (0x1000) /* Negative */
#define LZ_SECOND_STAGE_STACK_SIZE   (0x1000)

#define LZ_SL_HEADER_OFFSET          (0x0)
#define LZ_SL_HEADER_SIZE            (0x4)

#define LZ_HEADER_OFFSET             (0x4)
#define LZ_HEADER_SIZE               (0x2c)

#define LZ_FIRST_STAGE_STACK_START   (0x200)
#define LZ_FIRST_STAGE_STACK_SIZE    (0x1d0)

#define LZ_DATA_SECTION_SIZE         (0x200)

#define LZ_DEV_TABLE_OFFSET          (0x7000)
#define LZ_DEV_TABLE_SIZE            (0x3000)

#define LZ_PAGE_TABLES_OFFSET        (0xA000)
#define LZ_PAGE_TABLES_SIZE          (0x6000)

#endif /* __CONFIG_H__ */
