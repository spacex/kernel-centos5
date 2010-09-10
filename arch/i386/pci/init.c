#include <linux/pci.h>
#include <linux/init.h>
#include "pci.h"

/* arch_initcall has too random ordering, so call the initializers
   in the right sequence from here. */
static __init int pci_access_init(void)
{
	struct pci_raw_ops *mmcfg_ops = NULL;

#ifdef CONFIG_PCI_MMCONFIG
	pci_mmcfg_init();
	/*
	 * We still need legacy PCI config access routines for devices that
	 * don't respond to MMCONFIG accesses. Save raw_pci_ops in a local
	 * variable to restore it if MMCONFIG was successfully initialized.
	 */
	mmcfg_ops = raw_pci_ops;
#endif

#ifdef CONFIG_PCI_BIOS
	pci_pcbios_init();
#endif
	/*
	 * don't check for raw_pci_ops here because we want pcbios as last
	 * fallback, yet it's needed to run first to set pcibios_last_bus
	 * in case legacy PCI probing is used. otherwise detecting peer busses
	 * fails.
	 */
#ifdef CONFIG_PCI_DIRECT
	pci_direct_init();
#endif
	if (mmcfg_ops)
		raw_pci_ops = mmcfg_ops;

	if (!raw_pci_ops)
		printk(KERN_ERR "PCI: Fatal: No PCI config space access "
		       "function found\n");
	return 0;
}
arch_initcall(pci_access_init);
