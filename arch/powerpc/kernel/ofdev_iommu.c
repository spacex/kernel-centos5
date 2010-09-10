/*
 * Copyright (C) 2001 Mike Corrigan & Dave Engebretsen, IBM Corporation
 *
 * Rewrite, cleanup, new allocation schemes:
 * Copyright (C) 2004 Olof Johansson, IBM Corporation
 *
 * Dynamic DMA mapping support, platform-independent parts.
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


#include <linux/init.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/dma-mapping.h>
#include <asm/io.h>
#include <asm/prom.h>
#include <asm/iommu.h>
#include <asm/machdep.h>
#include <asm/of_device.h>

static inline struct iommu_table *device_to_table(struct device *hwdev)
{
	struct of_device *ofdev = to_of_device(hwdev);

	return hwdev ? ofdev->iommu : NULL;
}


static inline unsigned long device_to_mask(struct device *hwdev)
{
	struct of_device *ofdev = to_of_device(hwdev);

	return ofdev->dma_mask;
}

static inline unsigned long device_to_node(struct device *hwdev)
{
#ifdef CONFIG_NUMA
	struct of_device *ofdev = to_of_device(hwdev);

	return ofdev->numa_node;
#else
	return 0;
#endif
}


/* Allocates a contiguous real buffer and creates mappings over it.
 * Returns the virtual address of the buffer and sets dma_handle
 * to the dma address (mapping) of the first page.
 */
static void *ofdev_iommu_alloc_coherent(struct device *hwdev, size_t size,
			   dma_addr_t *dma_handle, gfp_t flag)
{
	return iommu_alloc_coherent(device_to_table(hwdev), size, dma_handle,
			device_to_mask(hwdev), flag, device_to_node(hwdev));
}

static void ofdev_iommu_free_coherent(struct device *hwdev, size_t size,
			 void *vaddr, dma_addr_t dma_handle)
{
	iommu_free_coherent(device_to_table(hwdev), size, vaddr, dma_handle);
}

/* Creates TCEs for a user provided buffer.  The user buffer must be
 * contiguous real kernel storage (not vmalloc).  The address of the buffer
 * passed here is the kernel (virtual) address of the buffer.  The buffer
 * need not be page aligned, the dma_addr_t returned will point to the same
 * byte within the page as vaddr.
 */
static dma_addr_t ofdev_iommu_map_single(struct device *hwdev, void *vaddr,
		size_t size, enum dma_data_direction direction)
{
	return iommu_map_single(device_to_table(hwdev), vaddr, size,
			        device_to_mask(hwdev), direction);
}


static void ofdev_iommu_unmap_single(struct device *hwdev, dma_addr_t dma_handle,
		size_t size, enum dma_data_direction direction)
{
	iommu_unmap_single(device_to_table(hwdev), dma_handle, size, direction);
}


static int ofdev_iommu_map_sg(struct device *dev, struct scatterlist *sglist,
		int nelems, enum dma_data_direction direction)
{
	return iommu_map_sg(dev, device_to_table(dev), sglist,
			nelems, device_to_mask(dev), direction);
}

static void ofdev_iommu_unmap_sg(struct device *dev, struct scatterlist *sglist,
		int nelems, enum dma_data_direction direction)
{
	iommu_unmap_sg(device_to_table(dev), sglist, nelems, direction);
}

/* We support DMA to/from any memory page via the iommu */
static int ofdev_iommu_dma_supported(struct device *dev, u64 mask)
{
	struct iommu_table *tbl = device_to_table(dev);

	if (!tbl || tbl->it_offset > mask) {
		printk(KERN_INFO "Warning: IOMMU table offset too big for device mask\n");
		if (tbl)
			printk(KERN_INFO "mask: 0x%08lx, table offset: 0x%08lx\n",
				mask, tbl->it_offset);
		else
			printk(KERN_INFO "mask: 0x%08lx, table unavailable\n",
				mask);
		return 0;
	} else
		return 1;
}

struct dma_mapping_ops ofdev_iommu_ops = {
	.alloc_coherent = ofdev_iommu_alloc_coherent,
	.free_coherent = ofdev_iommu_free_coherent,
	.map_single = ofdev_iommu_map_single,
	.unmap_single = ofdev_iommu_unmap_single,
	.map_sg = ofdev_iommu_map_sg,
	.unmap_sg = ofdev_iommu_unmap_sg,
	.dma_supported = ofdev_iommu_dma_supported,
};

void ofdev_iommu_init(void)
{
	of_platform_dma_ops = ofdev_iommu_ops;
}
