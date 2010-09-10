/*
 * PCIe error reporting handler for Axon
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
 * Axon UTL registers
 */
#define AXON_UTL_STATUS			0x04
#define AXON_UTL_PCIE_PORT_STATUS	0xa4
#define AXON_UTL_PCIE_PORT_CMPLX_STATUS	0xb0

struct axon_utl {
	struct device_node *dn;
	void __iomem *base;
	int virq;
};

static u32 axon_utl_read(struct axon_utl *axon_utl, unsigned int reg)
{
	return in_be32(axon_utl->base + reg);
}

static void axon_utl_dump_registers(struct axon_utl *axon_utl)
{
	printk("\naxon_utl: AXON_UTL_STATUS = 0x%08x\n",
	       axon_utl_read(axon_utl, AXON_UTL_STATUS));

	printk("axon_utl: AXON_UTL_PCIE_PORT_STATUS = 0x%08x\n",
	       axon_utl_read(axon_utl, AXON_UTL_PCIE_PORT_STATUS));

	printk("axon_utl: AXON_UTL_PCIE_ROOT_CMPLX_STATUS = 0x%08x\n",
	       axon_utl_read(axon_utl, AXON_UTL_PCIE_PORT_CMPLX_STATUS));
}

static irqreturn_t axon_utl_interrupt(int irq, void *ptr)
{
	struct axon_utl *axon_utl = (struct axon_utl *) ptr;

	axon_utl_dump_registers(axon_utl);

	panic("\naxon_utl: an unrecoverable error on PCIe node %s occured !\n",
	      axon_utl->dn->full_name);

	/* should never happen */
	return IRQ_HANDLED;
}

static int axon_utl_setup_one(struct device_node *dn)
{
	int ret, virq;
	unsigned int flags;
	struct axon_utl *axon_utl;
	const u32 *addr;
	u64 ioaddr, size;

	pr_debug("axon_utl: setting up dn %s\n", dn->full_name);

	axon_utl = kzalloc(sizeof(struct axon_utl), GFP_KERNEL);
	if (!axon_utl) {
		printk(KERN_ERR "axon_utl: could not allocate axon_utl for %s\n",
		       dn->full_name);
		goto out;
	}

	axon_utl->dn = dn;

	addr = of_get_address(dn, 0, &size, &flags);

	if (addr == 0) {
		printk(KERN_ERR "axon_utl: addr of resource is 0\n");
		goto out_free;
	}

	if (size == 0) {
		printk(KERN_ERR "axon_utl: length of resource is 0\n");
		goto out_free;
	}

	ioaddr = of_translate_address(dn, addr);

	axon_utl->base = ioremap(ioaddr, size);

	if (axon_utl->base == NULL) {
		printk(KERN_ERR "axon_utl: unable to ioremap io address\n");
		goto out_free;
	}

	virq = irq_of_parse_and_map(dn, 0);
	if (virq == NO_IRQ) {
		printk(KERN_ERR "axon_utl: irq parse and map failed for %s\n",
		       dn->full_name);
		goto out_free;
	}

	ret = request_irq(virq, axon_utl_interrupt,
			IRQF_DISABLED, "axon_utl", axon_utl);
	if (ret) {
		printk(KERN_ERR "axon_utl: request for irq %d on dn %s failed \n",
		       virq, dn->full_name);
		goto out_free;
	}

	pr_info("axon_utl: registered error handler on irq %d for %s\n",
	       virq, axon_utl->dn->full_name);

	return 0;

out_free:
	kfree(axon_utl);
out:
	return -ENODEV;
}

static int axon_utl_init(void)
{
	struct device_node *dn;
	int n=0;

	for_each_compatible_node(dn, NULL, "ibm,axon-pciex-utl") {
		if (axon_utl_setup_one(dn) == 0)
			n++;
	}

	if (n == 0) {
		pr_info("No pciex nodes found\n");
	}

	return 0;
}

subsys_initcall(axon_utl_init);
