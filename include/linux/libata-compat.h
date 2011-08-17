#ifndef __LIBATA_COMPAT_H__
#define __LIBATA_COMPAT_H__

#include <linux/pci.h>

#define init_timer_deferrable(foo) init_timer(foo)

#define for_each_sg(sgl, sg, n_elem, i) \
	for ((sg) = (sgl), (i) = 0; (i) < (n_elem); (i)++, (sg)++)

static inline void sg_init_table(struct scatterlist *sg, unsigned int count)
{
}

static inline struct scatterlist *sg_next(struct scatterlist *sg)
{
	return sg + 1;
}

static inline struct scatterlist *sg_last(struct scatterlist *sgl,
                                          unsigned int nents)
{
	return &sgl[nents - 1];
}

static inline void sg_set_page(struct scatterlist *sg, struct page *page,
                               unsigned int len, unsigned int offset)
{
	sg->page = page;
        sg->offset = offset;
}

static inline struct page *sg_page(struct scatterlist *sg)
{
	return sg->page;
}

#ifdef CONFIG_PCI

static inline int pci_reenable_device(struct pci_dev *pdev)
{
	return pci_enable_device(pdev);
}

#endif /* CONFIG_PCI */

#endif /* __LIBATA_COMPAT_H__ */
