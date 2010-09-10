/*
 * PCI error reporting handler for Axon
 *
 * (C) Copyright IBM Corp. 2007
 *
 * Authors : Jens Osterkamp <Jens.Osterkamp@de.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/reboot.h>

#include <asm/machdep.h>
#include <asm/prom.h>

#include "../../kernel/msi.h"

/*
 * Axon PCI bridge registers
 */
#define AXON_PCI_BRIDGE_OFFSET		0x0ec80000

/* PCI status */
#define AXON_PCI_STATUS			0x04

/* PCI error status */
#define AXON_PCI_ERROR_STATUS		0x54

struct axon_pci {
	struct device_node *dn;
	void __iomem *base;
	int virq;
};

static u32 axon_pci_read(struct axon_pci *axon_pci, unsigned int reg)
{
	return in_be32(axon_pci->base + AXON_PCI_BRIDGE_OFFSET + reg);
}

static void axon_pci_dump_registers(struct axon_pci *axon_pci)
{
	printk("\naxon_pci: AXON_PCI_STATUS = 0x%08x\n",
	       axon_pci_read(axon_pci, AXON_PCI_STATUS));

	printk("axon_pci: AXON_PCI_ERROR_STATUS = 0x%08x\n",
	       axon_pci_read(axon_pci, AXON_PCI_ERROR_STATUS));
}

static irqreturn_t axon_pci_interrupt(int irq, void *ptr)
{
	struct axon_pci *axon_pci = (struct axon_pci *) ptr;

	axon_pci_dump_registers(axon_pci);

	panic("\naxon_pci: an unrecoverable error on PCI node %s occured !\n",
	      axon_pci->dn->full_name);

	/* should never happen */
	return IRQ_HANDLED;
}

static int axon_pci_setup_one(struct device_node *dn)
{
	int ret, virq;
	unsigned int flags;
	struct axon_pci *axon_pci;
	const u32 *addr;
	u64 ioaddr, size;

	pr_debug("axon_pci: setting up dn %s\n", dn->full_name);

	axon_pci = kzalloc(sizeof(struct axon_pci), GFP_KERNEL);
	if (!axon_pci) {
		printk(KERN_ERR "axon_pci: could not allocate axon_pci for %s\n",
		       dn->full_name);
		goto out;
	}

	axon_pci->dn = dn;

	addr = of_get_address(dn, 0, &size, &flags);

	if (addr == 0) {
		printk(KERN_ERR "axon_pci: addr of resource is 0\n");
		goto out_free;
	}

	if (size == 0) {
		printk(KERN_ERR "axon_pci: length of resource is 0\n");
		goto out_free;
	}

	ioaddr = of_translate_address(dn, addr);

	axon_pci->base = ioremap(ioaddr, size);

	if (axon_pci->base == NULL) {
		printk(KERN_ERR "axon_pci: unable to ioremap io address\n");
		goto out_free;
	}

	virq = irq_of_parse_and_map(dn, 0);
	if (virq == NO_IRQ) {
		printk(KERN_ERR "axon_pci: irq parse and map failed for %s\n",
		       dn->full_name);
		goto out_free;
	}

	ret = request_irq(virq, axon_pci_interrupt,
			IRQF_DISABLED, "axon_pci", axon_pci);
	if (ret) {
		printk(KERN_ERR "axon_pci: request for irq %d on dn %s failed \n",
		       virq, dn->full_name);
		goto out_free;
	}

	pr_info("axon_pci: registered error handler on irq %d for %s\n",
	       virq, axon_pci->dn->full_name);

	return 0;

out_free:
	kfree(axon_pci);
out:
	return -ENODEV;
}

static int axon_pci_init(void)
{
	struct device_node *dn;
	int n=0;

	for_each_compatible_node(dn, NULL, "ibm,axon-pcix") {
		if (axon_pci_setup_one(dn) == 0)
			n++;
	}

	if (n == 0) {
		pr_info("No pcix nodes found\n");
	}

	return 0;
}

subsys_initcall(axon_pci_init);
