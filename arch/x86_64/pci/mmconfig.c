/*
 * mmconfig.c - Low-level direct PCI config space access via MMCONFIG
 * 
 * This is an 64bit optimized version that always keeps the full mmconfig
 * space mapped. This allows lockless config space operation.
 */

#include <linux/pci.h>
#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/bitmap.h>
#include <linux/dmi.h>
#include <asm/e820.h>

#include "pci.h"

/* aperture is up to 256MB but BIOS may reserve less */
#define MMCONFIG_APER_MIN	(2 * 1024*1024)
#define MMCONFIG_APER_MAX	(256 * 1024*1024)

/* Static virtual mapping of the MMCONFIG aperture */
struct mmcfg_virt {
	struct acpi_table_mcfg_config *cfg;
	char __iomem *virt;
};
static struct mmcfg_virt *pci_mmcfg_virt;

static char __iomem *get_virt(unsigned int seg, unsigned bus)
{
	int cfg_num = -1;
	struct acpi_table_mcfg_config *cfg;

	while (1) {
		++cfg_num;
		if (cfg_num >= pci_mmcfg_config_num)
			break;
		cfg = pci_mmcfg_virt[cfg_num].cfg;
		if (cfg->pci_segment_group_number != seg)
			continue;
		if ((cfg->start_bus_number <= bus) &&
		    (cfg->end_bus_number >= bus))
			return pci_mmcfg_virt[cfg_num].virt;
	}

	/* Handle more broken MCFG tables on Asus etc.
	   They only contain a single entry for bus 0-0. Assume
 	   this applies to all busses. */
	cfg = &pci_mmcfg_config[0];
	if (pci_mmcfg_config_num == 1 &&
		cfg->pci_segment_group_number == 0 &&
		(cfg->start_bus_number | cfg->end_bus_number) == 0)
		return pci_mmcfg_virt[0].virt;

	/* Fall back to type 0 */
	return NULL;
}

static char __iomem *pci_dev_base(unsigned int seg, unsigned int bus, unsigned int devfn)
{
	char __iomem *addr;

	addr = get_virt(seg, bus);
	if (!addr)
		return NULL;
 	return addr + ((bus << 20) | (devfn << 12));
}

static int pci_mmcfg_read(unsigned int seg, unsigned int bus,
			  unsigned int devfn, int reg, int len, u32 *value)
{
	char __iomem *addr;

	/* Why do we have this when nobody checks it. How about a BUG()!? -AK */
	if (unlikely((bus > 255) || (devfn > 255) || (reg > 4095))) {
err:		*value = -1;
		return -EINVAL;
	}

	if (reg < 256)
		return pci_conf1_read(seg,bus,devfn,reg,len,value);

	addr = pci_dev_base(seg, bus, devfn);
	if (!addr)
		goto err;

	switch (len) {
	case 1:
		*value = mmio_config_readb(addr + reg);
		break;
	case 2:
		*value = mmio_config_readw(addr + reg);
		break;
	case 4:
		*value = mmio_config_readl(addr + reg);
		break;
	}

	return 0;
}

static int pci_mmcfg_write(unsigned int seg, unsigned int bus,
			   unsigned int devfn, int reg, int len, u32 value)
{
	char __iomem *addr;

	/* Why do we have this when nobody checks it. How about a BUG()!? -AK */
	if (unlikely((bus > 255) || (devfn > 255) || (reg > 4095)))
		return -EINVAL;

	if (reg < 256)
		return pci_conf1_write(seg,bus,devfn,reg,len,value);

	addr = pci_dev_base(seg, bus, devfn);
	if (!addr)
		return -EINVAL;

	switch (len) {
	case 1:
		mmio_config_writeb(addr + reg, value);
		break;
	case 2:
		mmio_config_writew(addr + reg, value);
		break;
	case 4:
		mmio_config_writel(addr + reg, value);
		break;
	}

	return 0;
}

static struct pci_raw_ops pci_mmcfg = {
	.read =		pci_mmcfg_read,
	.write =	pci_mmcfg_write,
};

void __init pci_mmcfg_init(void)
{
	int i;

	if ((pci_probe & PCI_PROBE_MMCONF) == 0)
		return;

	acpi_table_parse(ACPI_MCFG, acpi_parse_mcfg);
	if ((pci_mmcfg_config_num == 0) ||
	    (pci_mmcfg_config == NULL) ||
	    (pci_mmcfg_config[0].base_address == 0))
		return;

	if (!e820_all_mapped(pci_mmcfg_config[0].base_address,
			pci_mmcfg_config[0].base_address + MMCONFIG_APER_MIN,
			E820_RESERVED)) {
		printk(KERN_ERR "PCI: BIOS Bug: MCFG area at %x is not E820-reserved\n",
				pci_mmcfg_config[0].base_address);
		printk(KERN_ERR "PCI: Not using MMCONFIG.\n");
		return;
	}

	/* RED-PEN i386 doesn't do _nocache right now */
	pci_mmcfg_virt = kmalloc(sizeof(*pci_mmcfg_virt) * pci_mmcfg_config_num, GFP_KERNEL);
	if (pci_mmcfg_virt == NULL) {
		printk("PCI: Can not allocate memory for mmconfig structures\n");
		return;
	}
	for (i = 0; i < pci_mmcfg_config_num; ++i) {
		pci_mmcfg_virt[i].cfg = &pci_mmcfg_config[i];
		pci_mmcfg_virt[i].virt = ioremap_nocache(pci_mmcfg_config[i].base_address,
							 MMCONFIG_APER_MAX);
		if (!pci_mmcfg_virt[i].virt) {
			printk("PCI: Cannot map mmconfig aperture for segment %d\n",
			       pci_mmcfg_config[i].pci_segment_group_number);
			return;
		}
		printk(KERN_INFO "PCI: Using MMCONFIG at %x\n", pci_mmcfg_config[i].base_address);
	}

	raw_pci_ops = &pci_mmcfg;
	pci_probe = pci_probe & ~PCI_PROBE_MASK;
	pci_probe = pci_probe | PCI_PROBE_MMCONF | PCI_USING_MMCONF;
}
