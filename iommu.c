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
#include <boot.h>
#include <types.h>
#include <pci.h>
#include <iommu.h>
#include <iommu_defs.h>

static u64 *mmio_base;

#ifdef DEBUG
static void print_char(char c)
{
	while ( !(inb(0x3f8 + 5) & 0x20) )
		;

	outb(0x3f8, c);
}

static void print(char * txt) {
	while (*txt != '\0') {
		if (*txt == '\n')
			print_char('\r');
		print_char(*txt++);
	}
}

static void print_u64(u64 p) {
	char tmp[sizeof(void*)*2 + 5] = "0x";
	int i;

	for (i=0; i<sizeof(void*); i++) {
		if ((p & 0xf) >= 10)
			tmp[sizeof(void*)*2 + 1 - 2*i] = (p & 0xf) + 'a' - 10;
		else
			tmp[sizeof(void*)*2 + 1 - 2*i] = (p & 0xf) + '0';
		p >>= 4;
		if ((p & 0xf) >= 10)
			tmp[sizeof(void*)*2 - 2*i] = (p & 0xf) + 'a' - 10;
		else
			tmp[sizeof(void*)*2 - 2*i] = (p & 0xf) + '0';
		p >>= 4;
	}
	tmp[sizeof(void*)*2 + 2] = ':';
	tmp[sizeof(void*)*2 + 3] = ' ';
	tmp[sizeof(void*)*2 + 4] = '\0';
	print(tmp);
}
#else
static void print(const char * unused) { }
static void print_u64(u64 unused) { }
#endif


static u32 _locate(unsigned int bus, unsigned int devfn)
{
	u32 pci_cap_ptr;
	u32 next;

	/* Read capabilities pointer */
	pci_read(0, bus,
	         devfn,
	         PCI_CAPABILITY_LIST,
	         4, &pci_cap_ptr);

	if (INVALID_CAP(pci_cap_ptr))
		return 0;

	pci_cap_ptr &= 0xFF;

	while (pci_cap_ptr != 0)
	{
		pci_read(0, bus,
		         devfn,
		         pci_cap_ptr,
		         4, &next);

		if (PCI_CAP_ID(next) == PCI_CAPABILITIES_POINTER_ID_DEV)
			break;

		pci_cap_ptr = PCI_CAP_PTR(next);
	}

	if (INVALID_CAP(pci_cap_ptr))
		return 0;

	return pci_cap_ptr;
}

u32 iommu_locate(void)
{
	return _locate(IOMMU_PCI_BUS,
	               PCI_DEVFN(IOMMU_PCI_DEVICE, IOMMU_PCI_FUNCTION));
}

u32 dev_locate(void)
{
	return _locate(DEV_PCI_BUS,
	               PCI_DEVFN(DEV_PCI_DEVICE, DEV_PCI_FUNCTION));
}

static inline u32 dev_read(u32 dev, u32 function, u32 index)
{
        u32 value;

        pci_write(0, DEV_PCI_BUS,
			PCI_DEVFN(DEV_PCI_DEVICE,DEV_PCI_FUNCTION),
			dev + DEV_OP_OFFSET,
			4,
			(u32)(((function & 0xff) << 8) + (index & 0xff)) );

        pci_read(0, DEV_PCI_BUS,
			PCI_DEVFN(DEV_PCI_DEVICE,DEV_PCI_FUNCTION),
			dev + DEV_DATA_OFFSET,
			4, &value);

	return value;
}

static inline void dev_write(u32 dev, u32 function, u32 index, u32 value)
{
        pci_write(0, DEV_PCI_BUS,
			PCI_DEVFN(DEV_PCI_DEVICE,DEV_PCI_FUNCTION),
			dev + DEV_OP_OFFSET,
			4,
			(u32)(((function & 0xff) << 8) + (index & 0xff)) );

        pci_write(0, DEV_PCI_BUS,
			PCI_DEVFN(DEV_PCI_DEVICE,DEV_PCI_FUNCTION),
			dev + DEV_DATA_OFFSET,
			4, value);
}

void dev_disable_sl(u32 dev)
{
	u32 dev_cr = dev_read(dev, DEV_CR, 0);
	dev_write(dev, DEV_CR, 0, dev_cr & ~DEV_CR_SL_DEV_EN_MASK);
}

static void send_command(iommu_command_t cmd)
{
	u32 cmd_ptr = mmio_base[IOMMU_MMIO_COMMAND_BUF_TAIL] >> 4;
	command_buf[cmd_ptr++] = cmd;
	asm volatile("wbinvd; sfence" ::: "memory");
	mmio_base[IOMMU_MMIO_COMMAND_BUF_TAIL] = (cmd_ptr << 4) & 0xfff;
}

u32 iommu_load_device_table(u32 cap, volatile u64 *completed)
{
	u32 low, hi;
	iommu_command_t cmd = {0};

	pci_read(0, IOMMU_PCI_BUS,
	         PCI_DEVFN(IOMMU_PCI_DEVICE, IOMMU_PCI_FUNCTION),
	         IOMMU_CAP_BA_LOW(cap),
	         4, &low);

	/* IOMMU must be enabled by AGESA */
	if ((low & IOMMU_CAP_BA_LOW_ENABLE) == 0)
		return 1;

	pci_read(0, IOMMU_PCI_BUS,
	         PCI_DEVFN(IOMMU_PCI_DEVICE, IOMMU_PCI_FUNCTION),
	         IOMMU_CAP_BA_HIGH(cap),
	         4, &hi);

	mmio_base = _p((u64)hi << 32 | (low & 0xffffc000));

	print("IOMMU MMIO Base Address = ");
	print_u64((u64)hi << 32 | (low & 0xffffc000));
	print("\n");

	print_u64(mmio_base[IOMMU_MMIO_STATUS_REGISTER]);
	print("IOMMU_MMIO_STATUS_REGISTER\n");

	/* Disable IOMMU and all its features */
	mmio_base[IOMMU_MMIO_CONTROL_REGISTER] &= ~IOMMU_CR_ENABLE_ALL_MASK;
	barrier();

	/* Address and size of Device Table (bits 8:0 = 0 -> 4KB; 1 -> 8KB ...) */
	mmio_base[IOMMU_MMIO_DEVICE_TABLE_BA] = (u64)_u(device_table) | 1;

	print_u64(mmio_base[IOMMU_MMIO_DEVICE_TABLE_BA]);
	print("IOMMU_MMIO_DEVICE_TABLE_BA\n");

	/* Address and size of Command Buffer, reset head and tail registers */
	mmio_base[IOMMU_MMIO_COMMAND_BUF_BA] = (u64)_u(command_buf) | (0x8ULL << 56);
	mmio_base[IOMMU_MMIO_COMMAND_BUF_HEAD] = 0;
	mmio_base[IOMMU_MMIO_COMMAND_BUF_TAIL] = 0;

	print_u64(mmio_base[IOMMU_MMIO_COMMAND_BUF_BA]);
	print("IOMMU_MMIO_COMMAND_BUF_BA\n");

	/* Address and size of Event Log, reset head and tail registers */
	mmio_base[IOMMU_MMIO_EVENT_LOG_BA] = (u64)_u(event_log) | (0x8ULL << 56);
	mmio_base[IOMMU_MMIO_EVENT_LOG_HEAD] = 0;
	mmio_base[IOMMU_MMIO_EVENT_LOG_TAIL] = 0;

	print_u64(mmio_base[IOMMU_MMIO_EVENT_LOG_BA]);
	print("IOMMU_MMIO_EVENT_LOG_BA\n");

	/* Clear EventLogInt set by IOMMU not being able to read command buffer */
	mmio_base[IOMMU_MMIO_STATUS_REGISTER] &= ~2;
	barrier();
	mmio_base[IOMMU_MMIO_CONTROL_REGISTER] |= IOMMU_CR_CmdBufEn | IOMMU_CR_EventLogEn;
	asm volatile("wbinvd; sfence" ::: "memory");

	mmio_base[IOMMU_MMIO_CONTROL_REGISTER] |= IOMMU_CR_IommuEn;

	print_u64(mmio_base[IOMMU_MMIO_STATUS_REGISTER]);
	print("IOMMU_MMIO_STATUS_REGISTER\n");

	if (mmio_base[IOMMU_MMIO_EXTENDED_FEATURE] & IOMMU_EF_IASup) {
		print("INVALIDATE_IOMMU_ALL\n");
		cmd.opcode = INVALIDATE_IOMMU_ALL;
		send_command(cmd);
	} /* TODO: else? */

	print_u64(mmio_base[IOMMU_MMIO_EXTENDED_FEATURE]);
	print("IOMMU_MMIO_EXTENDED_FEATURE\n");
	print_u64(mmio_base[IOMMU_MMIO_STATUS_REGISTER]);
	print("IOMMU_MMIO_STATUS_REGISTER\n");

	/* Write to a variable inside SLB (does not work in the first call) */
	cmd.u0 = _u(completed) | 1;
	/* This should be '_u(completed)>>32', but SLB can't be above 4GB anyway */
	cmd.u1 = 0;

	cmd.opcode = COMPLETION_WAIT;
	cmd.u2 = 0x656e6f64;	/* "done" */
	send_command(cmd);

	print_u64(mmio_base[IOMMU_MMIO_STATUS_REGISTER]);
	print("IOMMU_MMIO_STATUS_REGISTER\n");

	return 0;
}
