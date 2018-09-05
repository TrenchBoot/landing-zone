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

#ifndef __DEV_H__
#define __DEV_H__

#define DEV_PCI_BUS             0x0
#define DEV_PCI_DEVICE          0x18
#define DEV_PCI_FUNCTION        0x3

#define DEV_OP_OFFSET		4
#define DEV_DATA_OFFSET		8

#define DEV_BASE_LO             0
#define DEV_BASE_HI             1
#define DEV_MAP                 2
#define DEV_CAP                 3
#define DEV_CR                  4
#define DEV_ERR_STATUS          5
#define DEV_ERR_ADDR_LO         6
#define DEV_ERR_ADDR_HI         7

#define DEV_MAP_V0_MASK 1<<5
#define DEV_MAP_V1_MASK 1<<11

#define DEV_CAP_REV(c)	(c & 0xFF)
#define DEV_CAP_DOMS(c)	((c & 0xFF00) >> 8)
#define DEV_CAP_MAPS(c)	((c & 0xFF0000) >> 16)

#define DEV_BASE_LO_VALID_MASK		1<<0
#define DEV_BASE_LO_PROTECTED_MASK	1<<1
#define DEV_BASE_LO_SET_SIZE(b,s)	(b & (s << 2))
#define DEV_BASE_LO_ADDR_MASK		0xFFFFF000

#define DEV_CR_ENABLE_MASK	1<<0
#define DEV_CR_MEM_CLR_MASK	1<<1
#define DEV_CR_IOSP_EN_MASK	1<<2
#define DEV_CR_MCE_EN_MASK	1<<3
#define DEV_CR_INV_CACHE_MASK	1<<4
#define DEV_CR_SL_DEV_EN_MASK	1<<5
#define DEV_CR_WALK_PROBE_MASK	1<<6

#define INVALID_CAP(c) ((c == 0) || (c == 0xF0))


static inline u32 dev_read(u32 dev, u32 function, u32 index)
{
        u32 value;

        pci_conf1_write(0, DEV_PCI_BUS,
			PCI_DEVFN(DEV_PCI_DEVICE,DEV_PCI_FUNCTION),
			dev + DEV_OP_OFFSET,
			4,
			(u32)(((function & 0xff) << 8) + (index & 0xff)) );

        pci_conf1_read(0, DEV_PCI_BUS,
			PCI_DEVFN(DEV_PCI_DEVICE,DEV_PCI_FUNCTION),
			dev + DEV_DATA_OFFSET,
			4, &value);

	return value;
}

static inline void dev_write(u32 dev, u32 function, u32 index, u32 value)
{
        pci_conf1_write(0, DEV_PCI_BUS,
			PCI_DEVFN(DEV_PCI_DEVICE,DEV_PCI_FUNCTION),
			dev + DEV_OP_OFFSET,
			4,
			(u32)(((function & 0xff) << 8) + (index & 0xff)) );

        pci_conf1_write(0, DEV_PCI_BUS,
			PCI_DEVFN(DEV_PCI_DEVICE,DEV_PCI_FUNCTION),
			dev + DEV_DATA_OFFSET,
			4, value);
}


u32 dev_locate(void);
u32 dev_load_map(u32 dev, u32 dev_bitmap_paddr);
void dev_flush_cache(u32 dev);
void dev_protect_page(u32 pfn, u8 *bit_vector);

#endif /* __DEV_H__ */
