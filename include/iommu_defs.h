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

#ifndef __IOMMU_DEFS_H__
#define __IOMMU_DEFS_H__

#define IOMMU_PCI_BUS			0x0
#define IOMMU_PCI_DEVICE		0x0
#define IOMMU_PCI_FUNCTION		0x2

/* fields of Device Table entry (incomplete list) */
#define IOMMU_DTE_Q0_V			(1ULL << 0)
#define IOMMU_DTE_Q0_TV			(1ULL << 1)
#define IOMMU_DTE_Q0_IR			(1ULL << 61)
#define IOMMU_DTE_Q0_IW			(1ULL << 62)

#define IOMMU_DTE_Q1_I			(1ULL << (96 - 64))

#define IOMMU_DTE_Q2_IV			(1ULL << (128 - 128))
#define IOMMU_DTE_Q2_IG			(1ULL << (133 - 128))
#define IOMMU_DTE_Q2_INITPASS		(1ULL << (184 - 128))
#define IOMMU_DTE_Q2_EINTPASS		(1ULL << (185 - 128))
#define IOMMU_DTE_Q2_NMIPASS		(1ULL << (186 - 128))

#define IOMMU_CAP_BA_LOW(c)		(c + 4)
#define IOMMU_CAP_BA_LOW_ENABLE		(1ULL << 0)

#define IOMMU_CAP_BA_HIGH(c)		(c + 8)

/* indices into u64 table */
#define IOMMU_MMIO_DEVICE_TABLE_BA	(0x00 >> 3)
#define IOMMU_MMIO_COMMAND_BUF_BA	(0x08 >> 3)
#define IOMMU_MMIO_EVENT_LOG_BA		(0x10 >> 3)
#define IOMMU_MMIO_CONTROL_REGISTER	(0x18 >> 3)
#define IOMMU_MMIO_EXCLUSION_BASE	(0x20 >> 3)
#define IOMMU_MMIO_EXCLUSION_LIMIT	(0x28 >> 3)
#define IOMMU_MMIO_EXTENDED_FEATURE	(0x30 >> 3)
#define IOMMU_MMIO_COMMAND_BUF_HEAD	(0x2000 >> 3)
#define IOMMU_MMIO_COMMAND_BUF_TAIL	(0x2008 >> 3)
#define IOMMU_MMIO_EVENT_LOG_HEAD	(0x2010 >> 3)
#define IOMMU_MMIO_EVENT_LOG_TAIL	(0x2018 >> 3)
#define IOMMU_MMIO_STATUS_REGISTER	(0x2020 >> 3)

#define IOMMU_CR_IommuEn		(1ULL << 0)
#define IOMMU_CR_HtTunEn		(1ULL << 1)
#define IOMMU_CR_EventLogEn		(1ULL << 2)
#define IOMMU_CR_EventIntEn		(1ULL << 3)
#define IOMMU_CR_ComWaitIntEn		(1ULL << 4)
#define IOMMU_CR_CmdBufEn		(1ULL << 12)
#define IOMMU_CR_PPRLogEn		(1ULL << 13)
#define IOMMU_CR_PprIntEn		(1ULL << 14)
#define IOMMU_CR_PPREn			(1ULL << 15)
#define IOMMU_CR_GTEn			(1ULL << 16)
#define IOMMU_CR_GAEn			(1ULL << 17)
#define IOMMU_CR_SmiFEn			(1ULL << 22)
#define IOMMU_CR_SmiFLogEn		(1ULL << 24)
#define IOMMU_CR_GALogEn		(1ULL << 28)
#define IOMMU_CR_GAIntEn		(1ULL << 29)
#define IOMMU_CR_DualPprLogEn		(3ULL << 30)
#define IOMMU_CR_DualEventLogEn		(3ULL << 32)
#define IOMMU_CR_DevTblSegEn		(7ULL << 34)
#define IOMMU_CR_PrivAbrtEn		(3ULL << 37)
#define IOMMU_CR_PprAutoRspEn		(1ULL << 39)
#define IOMMU_CR_MarcEn			(1ULL << 40)
#define IOMMU_CR_BlkStopMrkEn		(1ULL << 41)
#define IOMMU_CR_PprAutoRspAon		(1ULL << 42)

#define IOMMU_CR_ENABLE_ALL_MASK	(IOMMU_CR_IommuEn | \
					 IOMMU_CR_HtTunEn | \
					 IOMMU_CR_EventLogEn | \
					 IOMMU_CR_EventIntEn | \
					 IOMMU_CR_ComWaitIntEn | \
					 IOMMU_CR_CmdBufEn | \
					 IOMMU_CR_PPRLogEn | \
					 IOMMU_CR_PprIntEn | \
					 IOMMU_CR_PPREn | \
					 IOMMU_CR_GTEn | \
					 IOMMU_CR_GAEn | \
					 IOMMU_CR_SmiFEn | \
					 IOMMU_CR_SmiFLogEn | \
					 IOMMU_CR_GALogEn | \
					 IOMMU_CR_GAIntEn | \
					 IOMMU_CR_DualPprLogEn | \
					 IOMMU_CR_DualEventLogEn | \
					 IOMMU_CR_DevTblSegEn | \
					 IOMMU_CR_PrivAbrtEn | \
					 IOMMU_CR_PprAutoRspEn | \
					 IOMMU_CR_MarcEn | \
					 IOMMU_CR_BlkStopMrkEn | \
					 IOMMU_CR_PprAutoRspAon)

#define IOMMU_EF_IASup			(1ULL << 6)

#define COMPLETION_WAIT			1
#define INVALIDATE_DEVTAB_ENTRY		2
#define INVALIDATE_IOMMU_PAGES		3
#define INVALIDATE_IOTLB_PAGES		4
#define INVALIDATE_INTERRUPT_TABLE	5
#define PREFETCH_IOMMU_PAGES		6
#define COMPLETE_PPR_REQUEST		7
#define INVALIDATE_IOMMU_ALL		8

#define INVALID_CAP(c) 			((c == 0) || (c == 0xFFFFFFFF) || (c == 0xFF))

#endif /* __IOMMU_DEFS_H__ */
