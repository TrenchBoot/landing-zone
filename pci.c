/*
 * These bits are from Linux. Copyrights, where present, come from the
 * files the definitions came from. Code in this module is from
 * arch/x86/pci/direct.c
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
#include <types.h>
#include <errno-base.h>
#include <boot.h>
#include <pci.h>

/*
 * Functions for accessing PCI base (first 256 bytes) and extended
 * (4096 bytes per PCI function) configuration space with type 1
 * accesses.
 */

#define PCI_CONF1_ADDRESS(bus, devfn, reg) \
        (0x80000000 | ((reg & 0xF00) << 16) | (bus << 16) \
        | (devfn << 8) | (reg & 0xFC))

static int pci_conf1_read(unsigned int seg, unsigned int bus,
                          unsigned int devfn, int reg, int len,
                          u32 *value)
{
	unsigned long flags;

	if (seg || (bus > 255) || (devfn > 255) || (reg > 4095))
	{
		*value = -1;
		return -EINVAL;
	}

	outl(PCI_CONF1_ADDRESS(bus, devfn, reg), 0xCF8);

	switch (len)
	{
	case 1:
		*value = inb(0xCFC + (reg & 3));
		break;
	case 2:
		*value = inw(0xCFC + (reg & 2));
		break;
	case 3:
		*value = inw(0xCFC);
		break;
	case 4:
		*value = inl(0xCFC);
		break;
	}

	return 0;
}

static int pci_conf1_write(unsigned int seg, unsigned int bus,
                           unsigned int devfn, int reg, int len,
                           u32 value)
{
	unsigned long flags;

	if (seg || (bus > 255) || (devfn > 255) || (reg > 4095))
		return -EINVAL;

	outl(PCI_CONF1_ADDRESS(bus, devfn, reg), 0xCF8);

	switch (len)
	{
	case 1:
		outb((u8)value, 0xCFC + (reg & 3));
		break;
	case 2:
		outw((u16)value, 0xCFC + (reg & 2));
		break;
	case 3:
		outw((u16)value, 0xCFC);
		break;
	case 4:
		outl((u32)value, 0xCFC);
		break;
	}

	return 0;
}

static void *mmio_base_addr;

#define PCI_MMIO_ADDRESS(bus, devfn, reg) \
        (void *)((size_t)mmio_base_addr | (bus << 20ULL) | (devfn << 12ULL) | reg)

static int pci_mmio_read(unsigned int seg, unsigned int bus,
                   unsigned int devfn, int reg, int len, u32 *value)
{
	if (seg || (bus > 255) || (devfn > 255) || (reg > 4095))
	{
		*value = -1;
		return -EINVAL;
	}

	void *addr = PCI_MMIO_ADDRESS(bus, devfn, reg);

	switch (len)
	{
	case 1:
		*value = ioread8(addr);
		break;
	case 2:
		*value = ioread16((void *)((size_t)addr & ~1ULL));
		break;
	case 3:
		*value = ioread16((void *)((size_t)addr & ~3ULL));
		break;
	case 4:
		*value = ioread32((void *)((size_t)addr & ~3ULL));
		break;
	}
}

static int pci_mmio_write(unsigned int seg, unsigned int bus,
                    unsigned int devfn, int reg, int len, u32 value)
{
	if (seg || (bus > 255) || (devfn > 255) || (reg > 4095))
		return -EINVAL;

	void *addr = PCI_MMIO_ADDRESS(bus, devfn, reg);

	switch (len)
	{
	case 1:
		iowrite8(addr, (u8)value);
		break;
	case 2:
		iowrite16((void *)((size_t)addr & ~1ULL), (u16)value);
		break;
	case 3:
		iowrite16((void *)((size_t)addr & ~3ULL), (u16)value);
		break;
	case 4:
		iowrite32((void *)((size_t)addr & ~3ULL), (u32)value);
		break;
	}
}

void pci_init(void)
{
	u32 eax, edx;

	asm volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(0xc0010058));

	if (eax & 1)	// MMIO configuration space is enabled
	{
		mmio_base_addr = (void *)(((u64)edx << 32ULL) | (eax & 0xfff00000));
		pci_read = &pci_mmio_read;
		pci_write = &pci_mmio_write;
	}
	else
	{
		pci_read = &pci_conf1_read;
		pci_write = &pci_conf1_write;
	}
}
