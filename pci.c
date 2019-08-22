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
#include <pci.h>

u32 mmio_base_addr;

void pci_init(void)
{
	u32 eax, edx;

	asm volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(0xc0010058));

	/* MMIO configuration space not enabled, or above 4G ? */
	if (!(eax & 1) || edx)
		die();

	mmio_base_addr = eax & 0xfff00000;
}
