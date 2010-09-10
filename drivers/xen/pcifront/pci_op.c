/*
 * PCI Frontend Operations - Communicates with frontend
 *
 *   Author: Ryan Wilson <hap9@epoch.ncsc.mil>
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <xen/evtchn.h>
#include "pcifront.h"

static int verbose_request = 0;
module_param(verbose_request, int, 0644);

static int errno_to_pcibios_err(int errno)
{
	switch (errno) {
	case XEN_PCI_ERR_success:
		return PCIBIOS_SUCCESSFUL;

	case XEN_PCI_ERR_dev_not_found:
		return PCIBIOS_DEVICE_NOT_FOUND;

	case XEN_PCI_ERR_invalid_offset:
	case XEN_PCI_ERR_op_failed:
		return PCIBIOS_BAD_REGISTER_NUMBER;

	case XEN_PCI_ERR_not_implemented:
		return PCIBIOS_FUNC_NOT_SUPPORTED;

	case XEN_PCI_ERR_access_denied:
		return PCIBIOS_SET_FAILED;
	}
	return errno;
}

static int do_pci_op(struct pcifront_device *pdev, struct xen_pci_op *op)
{
	int err = 0;
	struct xen_pci_op *active_op = &pdev->sh_info->op;
	unsigned long irq_flags;
	evtchn_port_t port = pdev->evtchn;
	s64 ns, ns_timeout;
	struct timeval tv;

	spin_lock_irqsave(&pdev->sh_info_lock, irq_flags);

	memcpy(active_op, op, sizeof(struct xen_pci_op));

	/* Go */
	wmb();
	set_bit(_XEN_PCIF_active, (unsigned long *)&pdev->sh_info->flags);
	notify_remote_via_evtchn(port);

	/*
	 * We set a poll timeout of 3 seconds but give up on return after
	 * 2 seconds. It is better to time out too late rather than too early
	 * (in the latter case we end up continually re-executing poll() with a
	 * timeout in the past). 1s difference gives plenty of slack for error.
	 */
	do_gettimeofday(&tv);
	ns_timeout = timeval_to_ns(&tv) + 2 * NSEC_PER_SEC;

	clear_evtchn(port);

	while (test_bit(_XEN_PCIF_active,
			(unsigned long *)&pdev->sh_info->flags)) {
		if (HYPERVISOR_poll(&port, 1, jiffies + 3*HZ))
			BUG();
		clear_evtchn(port);
		do_gettimeofday(&tv);
		ns = timeval_to_ns(&tv);
		if (ns > ns_timeout) {
			dev_err(&pdev->xdev->dev,
				"pciback not responding!!!\n");
			clear_bit(_XEN_PCIF_active,
				  (unsigned long *)&pdev->sh_info->flags);
			err = XEN_PCI_ERR_dev_not_found;
			goto out;
		}
	}

	memcpy(op, active_op, sizeof(struct xen_pci_op));

	err = op->err;
      out:
	spin_unlock_irqrestore(&pdev->sh_info_lock, irq_flags);
	return err;
}

/* Access to this function is spinlocked in drivers/pci/access.c */
static int pcifront_bus_read(struct pci_bus *bus, unsigned int devfn,
			     int where, int size, u32 * val)
{
	int err = 0;
	struct xen_pci_op op = {
		.cmd    = XEN_PCI_OP_conf_read,
		.domain = pci_domain_nr(bus),
		.bus    = bus->number,
		.devfn  = devfn,
		.offset = where,
		.size   = size,
	};
	struct pcifront_sd *sd = bus->sysdata;
	struct pcifront_device *pdev = pcifront_get_pdev(sd);

	if (verbose_request)
		dev_info(&pdev->xdev->dev,
			 "read dev=%04x:%02x:%02x.%01x - offset %x size %d\n",
			 pci_domain_nr(bus), bus->number, PCI_SLOT(devfn),
			 PCI_FUNC(devfn), where, size);

	err = do_pci_op(pdev, &op);

	if (likely(!err)) {
		if (verbose_request)
			dev_info(&pdev->xdev->dev, "read got back value %x\n",
				 op.value);

		*val = op.value;
	} else if (err == -ENODEV) {
		/* No device here, pretend that it just returned 0 */
		err = 0;
		*val = 0;
	}

	return errno_to_pcibios_err(err);
}

/* Access to this function is spinlocked in drivers/pci/access.c */
static int pcifront_bus_write(struct pci_bus *bus, unsigned int devfn,
			      int where, int size, u32 val)
{
	struct xen_pci_op op = {
		.cmd    = XEN_PCI_OP_conf_write,
		.domain = pci_domain_nr(bus),
		.bus    = bus->number,
		.devfn  = devfn,
		.offset = where,
		.size   = size,
		.value  = val,
	};
	struct pcifront_sd *sd = bus->sysdata;
	struct pcifront_device *pdev = pcifront_get_pdev(sd);

	if (verbose_request)
		dev_info(&pdev->xdev->dev,
			 "write dev=%04x:%02x:%02x.%01x - "
			 "offset %x size %d val %x\n",
			 pci_domain_nr(bus), bus->number,
			 PCI_SLOT(devfn), PCI_FUNC(devfn), where, size, val);

	return errno_to_pcibios_err(do_pci_op(pdev, &op));
}

struct pci_ops pcifront_bus_ops = {
	.read = pcifront_bus_read,
	.write = pcifront_bus_write,
};

#ifdef CONFIG_PCI_MSI
int pci_frontend_enable_msix(struct pci_dev *dev,
		struct msix_entry *entries,
		int nvec)
{
	int err;
	int i;
	struct xen_pci_op op = {
		.cmd    = XEN_PCI_OP_enable_msix,
		.domain = pci_domain_nr(dev->bus),
		.bus = dev->bus->number,
		.devfn = dev->devfn,
		.value = nvec,
	};
	struct pcifront_sd *sd = dev->bus->sysdata;
	struct pcifront_device *pdev = pcifront_get_pdev(sd);

	if (nvec > SH_INFO_MAX_VEC) {
		printk("too much vector for pci frontend%x\n", nvec);
		return -EINVAL;
	}

	for (i = 0; i < nvec; i++) {
		op.msix_entries[i].entry = entries[i].entry;
		op.msix_entries[i].vector = entries[i].vector;
	}

	err = do_pci_op(pdev, &op);

	if (!err) {
		if (!op.value) {
			/* we get the result */
			for ( i = 0; i < nvec; i++)
				entries[i].vector = op.msix_entries[i].vector;
			return 0;
		}
		else {
            printk("enable msix get value %x\n", op.value);
			return op.value;
		}
	}
	else {
        printk("enable msix get err %x\n", err);
		return err;
	}
}

void pci_frontend_disable_msix(struct pci_dev* dev)
{
	int err;
	struct xen_pci_op op = {
		.cmd    = XEN_PCI_OP_disable_msix,
		.domain = pci_domain_nr(dev->bus),
		.bus = dev->bus->number,
		.devfn = dev->devfn,
	};
	struct pcifront_sd *sd = dev->bus->sysdata;
	struct pcifront_device *pdev = pcifront_get_pdev(sd);

	err = do_pci_op(pdev, &op);

	/* What should do for error ? */
	if (err)
		printk("pci_disable_msix get err %x\n", err);
}

int pci_frontend_enable_msi(struct pci_dev *dev)
{
	int err;
	struct xen_pci_op op = {
		.cmd    = XEN_PCI_OP_enable_msi,
		.domain = pci_domain_nr(dev->bus),
		.bus = dev->bus->number,
		.devfn = dev->devfn,
	};
	struct pcifront_sd *sd = dev->bus->sysdata;
	struct pcifront_device *pdev = pcifront_get_pdev(sd);

	err = do_pci_op(pdev, &op);
	if (likely(!err)) {
		dev->irq = op.value;
	}
	else {
		printk("pci frontend enable msi failed for dev %x:%x \n",
				op.bus, op.devfn);
		err = -EINVAL;
	}
	return err;
}

void pci_frontend_disable_msi(struct pci_dev* dev)
{
	int err;
	struct xen_pci_op op = {
		.cmd    = XEN_PCI_OP_disable_msi,
		.domain = pci_domain_nr(dev->bus),
		.bus = dev->bus->number,
		.devfn = dev->devfn,
	};
	struct pcifront_sd *sd = dev->bus->sysdata;
	struct pcifront_device *pdev = pcifront_get_pdev(sd);

	err = do_pci_op(pdev, &op);
	if (err == XEN_PCI_ERR_dev_not_found) {
		/* XXX No response from backend, what shall we do? */
		printk("get no response from backend for disable MSI\n");
		return;
	}
	if (likely(!err))
		dev->irq = op.value;
	else
		/* how can pciback notify us fail? */
		printk("get fake response frombackend \n");
}
#endif /* CONFIG_PCI_MSI */

/* Claim resources for the PCI frontend as-is, backend won't allow changes */
static void pcifront_claim_resource(struct pci_dev *dev, void *data)
{
	struct pcifront_device *pdev = data;
	int i;
	struct resource *r;

	for (i = 0; i < PCI_NUM_RESOURCES; i++) {
		r = &dev->resource[i];

		if (!r->parent && r->start && r->flags) {
			dev_dbg(&pdev->xdev->dev, "claiming resource %s/%d\n",
				pci_name(dev), i);
			pci_claim_resource(dev, i);
		}
	}
}

int pcifront_scan_root(struct pcifront_device *pdev,
		       unsigned int domain, unsigned int bus)
{
	struct pci_bus *b;
	struct pcifront_sd *sd = NULL;
	struct pci_bus_entry *bus_entry = NULL;
	int err = 0;

#ifndef CONFIG_PCI_DOMAINS
	if (domain != 0) {
		dev_err(&pdev->xdev->dev,
			"PCI Root in non-zero PCI Domain! domain=%d\n", domain);
		dev_err(&pdev->xdev->dev,
			"Please compile with CONFIG_PCI_DOMAINS\n");
		err = -EINVAL;
		goto err_out;
	}
#endif

	dev_info(&pdev->xdev->dev, "Creating PCI Frontend Bus %04x:%02x\n",
		 domain, bus);

	bus_entry = kmalloc(sizeof(*bus_entry), GFP_KERNEL);
	sd = kmalloc(sizeof(*sd), GFP_KERNEL);
	if (!bus_entry || !sd) {
		err = -ENOMEM;
		goto err_out;
	}
	pcifront_init_sd(sd, domain, pdev);

	b = pci_scan_bus_parented(&pdev->xdev->dev, bus,
				  &pcifront_bus_ops, sd);
	if (!b) {
		dev_err(&pdev->xdev->dev,
			"Error creating PCI Frontend Bus!\n");
		err = -ENOMEM;
		goto err_out;
	}
	bus_entry->bus = b;

	list_add(&bus_entry->list, &pdev->root_buses);

	/* Claim resources before going "live" with our devices */
	pci_walk_bus(b, pcifront_claim_resource, pdev);

	pci_bus_add_devices(b);

	return 0;

      err_out:
	kfree(bus_entry);
	kfree(sd);

	return err;
}

static void free_root_bus_devs(struct pci_bus *bus)
{
	struct pci_dev *dev;

	down_write(&pci_bus_sem);
	while (!list_empty(&bus->devices)) {
		dev = container_of(bus->devices.next, struct pci_dev, bus_list);
		up_write(&pci_bus_sem);

		dev_dbg(&dev->dev, "removing device\n");
		pci_remove_bus_device(dev);

		down_write(&pci_bus_sem);
	}
	up_write(&pci_bus_sem);
}

void pcifront_free_roots(struct pcifront_device *pdev)
{
	struct pci_bus_entry *bus_entry, *t;

	dev_dbg(&pdev->xdev->dev, "cleaning up root buses\n");

	list_for_each_entry_safe(bus_entry, t, &pdev->root_buses, list) {
		list_del(&bus_entry->list);

		free_root_bus_devs(bus_entry->bus);

		kfree(bus_entry->bus->sysdata);

		device_unregister(bus_entry->bus->bridge);
		pci_remove_bus(bus_entry->bus);

		kfree(bus_entry);
	}
}
