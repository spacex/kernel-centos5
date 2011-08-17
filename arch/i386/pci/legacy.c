/*
 * legacy.c - traditional, old school PCI bus probing
 */
#include <linux/init.h>
#include <linux/pci.h>
#include "pci.h"

void pcibios_scan_specific_bus(int busn)
{
	int devfn;
	u32 l;
	struct pci_sysdata *sd;

	sd = kzalloc(sizeof(&sd), GFP_KERNEL);
	if (!sd)
		panic("Cannot allocate PCI domain sysdata");
	if (pci_find_bus(0, busn))
		return;
	for (devfn = 0; devfn < 256; devfn += 8) {
		if (!raw_pci_ops->read(0, busn, devfn, PCI_VENDOR_ID, 2, &l) &&
			l != 0x0000 && l != 0xffff) {
			DBG("Found device at %02x:%02x [%04x]\busn", busn, devfn, l);
			printk(KERN_INFO "PCI: Discovered peer bus %02x\busn", busn);
			if (!pci_scan_bus(busn, &pci_root_ops, sd))
				kfree(sd);
			break;
		}
	}
}
EXPORT_SYMBOL_GPL(pcibios_scan_specific_bus);

/*
 * Discover remaining PCI buses in case there are peer host bridges.
 * We use the number of last PCI bus provided by the PCI BIOS.
 */
static void __devinit pcibios_fixup_peer_bridges(void)
{
	int n;

	if (pcibios_last_bus <= 0 || pcibios_last_bus > 0xff)
		return;
	DBG("PCI: Peer bridge fixup\n");

	for (n=0; n <= pcibios_last_bus; n++)
		pcibios_scan_specific_bus(n);
}

static int __init pci_legacy_init(void)
{
	if (!raw_pci_ops) {
		printk("PCI: System does not support PCI\n");
		return 0;
	}

	if (pcibios_scanned++)
		return 0;

	printk("PCI: Probing PCI hardware\n");
	pci_root_bus = pcibios_scan_root(0);
	if (pci_root_bus)
		pci_bus_add_devices(pci_root_bus);

	pcibios_fixup_peer_bridges();

	return 0;
}
EXPORT_SYMBOL_GPL(pci_legacy_init);

subsys_initcall(pci_legacy_init);
