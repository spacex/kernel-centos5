/*
 * Essentially a modified version of Benjamin Herrenschmidt's PCI Direct
 * IOMMU work that takes the DMA offset from the pci_dn.  Used to allow
 * support for fixed IOMMU mapping on certain cell machines.  For 64-bit
 * devices this avoids the performance overhead of mapping and unmapping
 * pages at runtime.  32-bit devices are unable to use the fixed mapping.
 *
 * Copyright 2003 Benjamin Herrenschmidt (benh@kernel.crashing.org)
 * Copyright 2008 IBM Corporation, Mark Nelson
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/bootmem.h>
#include <linux/mm.h>
#include <linux/dma-mapping.h>

#include <asm/sections.h>
#include <asm/io.h>
#include <asm/prom.h>
#include <asm/machdep.h>
#include <asm/pmac_feature.h>
#include <asm/abs_addr.h>

static u64 get_pci_fixed_dma_offset(struct pci_dev *pdev)
{
	struct pci_dn *pdn = get_pdn(pdev);

	if (pdn->use_iommu_fixed)
		return pdn->addr;

	return 0;
}

static void *pci_fixed_alloc_coherent(struct device *hwdev, size_t size,
				   dma_addr_t *dma_handle, gfp_t flag)
{
	void *ret;

	ret = (void *)__get_free_pages(flag, get_order(size));
	if (ret != NULL) {
		memset(ret, 0, size);
		*dma_handle = virt_to_abs(ret) +
				get_pci_fixed_dma_offset(to_pci_dev(hwdev));
	}
	return ret;
}

static void pci_fixed_free_coherent(struct device *hwdev, size_t size,
				 void *vaddr, dma_addr_t dma_handle)
{
	free_pages((unsigned long)vaddr, get_order(size));
}

static dma_addr_t pci_fixed_map_single(struct device *hwdev, void *ptr,
		size_t size, enum dma_data_direction direction)
{
	return virt_to_abs(ptr) + get_pci_fixed_dma_offset(to_pci_dev(hwdev));
}

static void pci_fixed_unmap_single(struct device *hwdev, dma_addr_t dma_addr,
		size_t size, enum dma_data_direction direction)
{
}

static int pci_fixed_map_sg(struct device *hwdev, struct scatterlist *sg,
		int nents, enum dma_data_direction direction)
{
	int i;

	for (i = 0; i < nents; i++, sg++) {
		sg->dma_address = page_to_phys(sg->page) + sg->offset +
			get_pci_fixed_dma_offset(to_pci_dev(hwdev));
		sg->dma_length = sg->length;
	}

	return nents;
}

static void pci_fixed_unmap_sg(struct device *hwdev, struct scatterlist *sg,
		int nents, enum dma_data_direction direction)
{
}

static int pci_fixed_dma_supported(struct device *dev, u64 mask)
{
	return mask == DMA_64BIT_MASK;
}

struct dma_mapping_ops pci_fixed_ops = {
	.alloc_coherent = pci_fixed_alloc_coherent,
	.free_coherent = pci_fixed_free_coherent,
	.map_single = pci_fixed_map_single,
	.unmap_single = pci_fixed_unmap_single,
	.map_sg = pci_fixed_map_sg,
	.unmap_sg = pci_fixed_unmap_sg,
	.dma_supported = pci_fixed_dma_supported,
};
