/*
 * Copyright (C) 2001 Mike Corrigan & Dave Engebretsen, IBM Corporation
 * Rewrite, cleanup:
 * Copyright (C) 2004 Olof Johansson <olof@lixom.net>, IBM Corporation
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

#ifndef _ASM_IOMMU_H
#define _ASM_IOMMU_H
#ifdef __KERNEL__

#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <asm/types.h>
#include <asm/bitops.h>

#define IOMMU_PAGE_SHIFT      12
#define IOMMU_PAGE_SIZE       (ASM_CONST(1) << IOMMU_PAGE_SHIFT)
#define IOMMU_PAGE_MASK       (~((1 << IOMMU_PAGE_SHIFT) - 1))
#define IOMMU_PAGE_ALIGN(addr) _ALIGN_UP(addr, IOMMU_PAGE_SIZE)

#ifndef __ASSEMBLY__

/* Pure 2^n version of get_order */
static __inline__ __attribute_const__ int get_iommu_order(unsigned long size)
{
	return __ilog2((size - 1) >> IOMMU_PAGE_SHIFT) + 1;
}

#endif   /* __ASSEMBLY__ */


/*
 * IOMAP_MAX_ORDER defines the largest contiguous block
 * of dma space we can get.  IOMAP_MAX_ORDER = 13
 * allows up to 2**12 pages (4096 * 4096) = 16 MB
 */
#define IOMAP_MAX_ORDER		13

struct iommu_table {
	unsigned long  it_busno;     /* Bus number this table belongs to */
	unsigned long  it_size;      /* Size of iommu table in entries */
	unsigned long  it_offset;    /* Offset into global table */
	unsigned long  it_base;      /* mapped address of tce table */
	unsigned long  it_index;     /* which iommu table this is */
	unsigned long  it_type;      /* type: PCI or Virtual Bus */
	unsigned long  it_blocksize; /* Entries in each block (cacheline) */
	unsigned long  it_hint;      /* Hint for next alloc */
	unsigned long  it_largehint; /* Hint for large allocs */
	unsigned long  it_halfpoint; /* Breaking point for small/large allocs */
	spinlock_t     it_lock;      /* Protects it_map */
	unsigned long *it_map;       /* A simple allocation bitmap for now */
};

struct scatterlist;
struct device_node;

#ifdef CONFIG_PPC_MULTIPLATFORM

/* Walks all buses and creates iommu tables */
extern void iommu_setup_pSeries(void);
extern void iommu_setup_dart(void);

/* Frees table for an individual device node */
extern void iommu_free_table(struct device_node *dn);

#endif /* CONFIG_PPC_MULTIPLATFORM */

/* Initializes an iommu_table based in values set in the passed-in
 * structure
 */
extern struct iommu_table *iommu_init_table(struct iommu_table * tbl,
					    int nid);

extern int iommu_map_sg(struct device *dev, struct iommu_table *tbl,
		struct scatterlist *sglist, int nelems, unsigned long mask,
		enum dma_data_direction direction);
extern void iommu_unmap_sg(struct iommu_table *tbl, struct scatterlist *sglist,
		int nelems, enum dma_data_direction direction);

#ifdef CONFIG_HAVE_DMA_ATTRS
/*
 * Hack: we drill a hole all the way through the powerpc IOMMU support in order
 *       to pass down the 'weak ordering' flag from struct dma_attrs in a way
 *       that does not impact the kABI. The mainline kernel has redefined
 *       all these functions to take an extra struct dma_attrs argument.
 *       Instead, we defined a minimal set of extra functions.
 */
extern int pci_iommu_map_sg_weak(struct device *pdev, struct scatterlist *sglist,
		int nelems, enum dma_data_direction direction);
extern void pci_iommu_unmap_sg_weak(struct device *pdev, struct scatterlist *sglist,
		int nelems, enum dma_data_direction direction);
extern int iommu_map_sg_weak(struct device *dev, struct iommu_table *tbl,
		struct scatterlist *sglist, int nelems, unsigned long mask,
		enum dma_data_direction direction);
extern void tce_build_cell_weak(struct iommu_table *tbl, long index, long npages,
	unsigned long uaddr, enum dma_data_direction direction);
#endif /* CONFIG_HAVE_DMA_ATTRS */

extern void *iommu_alloc_coherent(struct iommu_table *tbl, size_t size,
		dma_addr_t *dma_handle, unsigned long mask,
		gfp_t flag, int node);
extern void iommu_free_coherent(struct iommu_table *tbl, size_t size,
		void *vaddr, dma_addr_t dma_handle);
extern dma_addr_t iommu_map_single(struct iommu_table *tbl, void *vaddr,
		size_t size, unsigned long mask,
		enum dma_data_direction direction);
extern void iommu_unmap_single(struct iommu_table *tbl, dma_addr_t dma_handle,
		size_t size, enum dma_data_direction direction);

extern void iommu_init_early_pSeries(void);
extern void iommu_init_early_iSeries(void);
extern void iommu_init_early_dart(void);

#ifdef CONFIG_PCI
extern void pci_iommu_init(void);
extern void pci_direct_iommu_init(void);
extern struct dma_mapping_ops pci_fixed_ops;
extern unsigned long pci_direct_dma_offset;
extern int cell_use_iommu_fixed;
extern u64 cell_iommu_get_fixed_address(struct pci_dev *dev);
extern void cell_pci_dma_dev_setup(struct pci_dev *dev);
#else
static inline void pci_iommu_init(void) { }
#endif

extern void ofdev_iommu_init(void);

extern void alloc_dart_table(void);

#endif /* __KERNEL__ */
#endif /* _ASM_IOMMU_H */
