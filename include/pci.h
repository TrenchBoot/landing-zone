/*
 * Bits are from Linux. Copyrights, where present, come from the
 * files the definitions came from.
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

#ifndef __PCI_H__
#define __PCI_H__

/* From include/uapi/linux/pci_regs.h */

#define PCI_CONFIG_ADDR_PORT    (0x0cf8)
#define PCI_CONFIG_DATA_PORT    (0x0cfc)

#define PCI_CAPABILITY_LIST     0x34    /* Offset of first capability list entry */

/* PCI capability ID for SVM DEV - AMD Manual */
#define PCI_CAPABILITIES_POINTER_ID_DEV    0x0F

/* From include/uapi/linux/pci.h */

/*
 * The PCI interface treats multi-function devices as independent
 * devices.  The slot/function address of each device is encoded
 * in a single byte as follows:
 *
 *      7:3 = slot
 *      2:0 = function
 */
#define PCI_DEVFN(slot, func)   ((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_SLOT(devfn)         (((devfn) >> 3) & 0x1f)
#define PCI_FUNC(devfn)         ((devfn) & 0x07)


/* From arch/x86/pci/direct.c definitions */

extern int (*pci_read)(unsigned int seg, unsigned int bus,
                       unsigned int devfn, int reg, int len, u32 *value);


extern int (*pci_write)(unsigned int seg, unsigned int bus,
                        unsigned int devfn, int reg, int len, u32 value);

void pci_init(void);

#endif /* __PCI_H__ */
