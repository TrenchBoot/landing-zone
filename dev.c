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

#include <defs.h>
#include <types.h>
#include <pci.h>
#include <dev.h>

u32 dev_locate(void)
{
	u32 pci_cap_ptr;
	u32 pci_cap_id;

	/* read capabilities pointer */
        pci_conf1_read(0, DEV_PCI_BUS,
			PCI_DEVFN(DEV_PCI_DEVICE,DEV_PCI_FUNCTION),
			PCI_CAPABILITY_LIST,
			4, &pci_cap_ptr);

	if (INVALID_CAP(pci_cap_ptr))
		return 0;

	pci_cap_ptr &= 0xFF;

	while (pci_cap_ptr != 0)
	{
		pci_conf1_read(0, DEV_PCI_BUS,
				PCI_DEVFN(DEV_PCI_DEVICE,DEV_PCI_FUNCTION),
				pci_cap_ptr,
				1, &pci_cap_id);

		if (pci_cap_id == PCI_CAPABILITIES_POINTER_ID_DEV)
			break;

		pci_conf1_read(0, DEV_PCI_BUS,
				PCI_DEVFN(DEV_PCI_DEVICE,DEV_PCI_FUNCTION),
				pci_cap_ptr,
				1, &pci_cap_ptr);
	}

        if (INVALID_CAP(pci_cap_ptr))
                return 0;

	return pci_cap_ptr;
}

u32 dev_load_map(u32 dev, u32 dev_bitmap_paddr)
{
	u8 i;
	/* since work with each reg one at a time, consolidate into a
	 * single reg variable to reduce stack usage
	 */
	u32 dev_map;
	u32 dev_cap;
	u32 dev_base_lo;
	u32 dev_cr;

	dev_cap = dev_read(dev, DEV_CAP, 0);

	/* disable all the DEV maps. */
	dev_map &= !DEV_MAP_V0_MASK;
	dev_map &= !DEV_MAP_V1_MASK;

	for (i = 0; i < DEV_CAP_MAPS(dev_cap); i++)
		dev_write(dev, DEV_MAP, i, dev_map);


	/* set the DEV_BASE_HI and DEV_BASE_LO registers of domain 0 */
	/* DEV bitmap is within 4GB physical */
	dev_write(dev, DEV_BASE_HI, 0, 0);

	dev_base_lo = 0;
	dev_base_lo &= DEV_BASE_LO_VALID_MASK;
	dev_base_lo &= !DEV_BASE_LO_PROTECTED_MASK;

	/* since already zeroed out, no need to set to zero */
	/* dev_base_lo = DEV_BASE_LO_SET_SIZE(dev_base_lo,0) */

	dev_base_lo &= (DEV_BASE_LO_ADDR_MASK & dev_bitmap_paddr);

	dev_write(dev, DEV_BASE_LO, 0, dev_base_lo);

	/* invalidate all other domains */
	dev_base_lo &= !DEV_BASE_LO_VALID_MASK;
	dev_base_lo &= !DEV_BASE_LO_ADDR_MASK;

	for (i = 1; i < DEV_CAP_MAPS(dev_cap); i++)
	{
		dev_write(dev, DEV_BASE_HI, i, 0);
		dev_write(dev, DEV_BASE_LO, i, dev_base_lo);
	}

	/* enable DEV protections */
	dev_cr = 0;
	dev_cr |= (DEV_CR_ENABLE_MASK | DEV_CR_IOSP_EN_MASK |
			DEV_CR_SL_DEV_EN_MASK);

	dev_write(dev, DEV_CR, 0, dev_cr);

	return 0;
}

void dev_flush_cache(u32 dev)
{
	u32 dev_cr;

	dev_cr = dev_read(dev, DEV_CR, 0);
	dev_cr |= (DEV_CR_INV_CACHE_MASK | DEV_CR_ENABLE_MASK);
	dev_write(dev, DEV_CR, 0, dev_cr);

	/* TODO: extend loop with timeout to prohibit infinite loop */
	while (dev_cr & DEV_CR_INV_CACHE_MASK)
                dev_cr = dev_read(dev, DEV_CR, 0);
}

void dev_protect_page(u32 pfn, u8 *bit_vector)
{
	u32 byte, bit;

	byte= pfn / 8;
	bit= pfn & 7;
	bit_vector[byte] |= (1 << bit);
}

