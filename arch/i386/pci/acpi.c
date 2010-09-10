#include <linux/pci.h>
#include <linux/acpi.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/dmi.h>
#include <asm/numa.h>
#include "pci.h"

static int __devinit can_skip_ioresource_align(struct dmi_system_id *d)
{
	pci_probe |= PCI_CAN_SKIP_ISA_ALIGN;
	printk(KERN_INFO "PCI: %s detected, can skip ISA alignment\n", d->ident);
	return 0;
}

static struct dmi_system_id acpi_pciprobe_dmi_table[] = {
/*
 * Systems where PCI IO resource ISA alignment can be skipped
 * when the ISA enable bit in the bridge control is not set
 */
	{
		.callback = can_skip_ioresource_align,
		.ident = "IBM System x3800",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "IBM"),
			DMI_MATCH(DMI_PRODUCT_NAME, "x3800"),
		},
	},
	{
		.callback = can_skip_ioresource_align,
		.ident = "IBM System x3850",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "IBM"),
			DMI_MATCH(DMI_PRODUCT_NAME, "x3850"),
		},
	},
	{
		.callback = can_skip_ioresource_align,
		.ident = "IBM System x3950",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "IBM"),
			DMI_MATCH(DMI_PRODUCT_NAME, "x3950"),
		},
	},
	{}
};

struct pci_root_info {
	char *name;
	unsigned int res_num;
	struct resource *res;
	struct pci_bus *bus;
	int busnum;
};

static acpi_status
resource_to_addr(struct acpi_resource *resource,
			struct acpi_resource_address64 *addr)
{
	acpi_status status;

	status = acpi_resource_to_address64(resource, addr);
	if (ACPI_SUCCESS(status) &&
	    (addr->resource_type == ACPI_MEMORY_RANGE ||
	    addr->resource_type == ACPI_IO_RANGE) &&
	    addr->address_length > 0 &&
	    addr->producer_consumer == ACPI_PRODUCER) {
		return AE_OK;
	}
	return AE_ERROR;
}

static acpi_status
count_resource(struct acpi_resource *acpi_res, void *data)
{
	struct pci_root_info *info = data;
	struct acpi_resource_address64 addr;
	acpi_status status;

	status = resource_to_addr(acpi_res, &addr);
	if (ACPI_SUCCESS(status))
		info->res_num++;
	return AE_OK;
}

static acpi_status
setup_resource(struct acpi_resource *acpi_res, void *data)
{
	struct pci_root_info *info = data;
	struct resource *res;
	struct acpi_resource_address64 addr;
	acpi_status status;
	unsigned long flags;
	struct resource *root;

	status = resource_to_addr(acpi_res, &addr);
	if (!ACPI_SUCCESS(status))
		return AE_OK;

	if (addr.resource_type == ACPI_MEMORY_RANGE) {
		root = &iomem_resource;
		flags = IORESOURCE_MEM;
		if (addr.info.mem.caching == ACPI_PREFETCHABLE_MEMORY)
			flags |= IORESOURCE_PREFETCH;
	} else if (addr.resource_type == ACPI_IO_RANGE) {
		root = &ioport_resource;
		flags = IORESOURCE_IO;
	} else
		return AE_OK;

	res = &info->res[info->res_num];
	res->name = info->name;
	res->flags = flags;
	res->start = addr.minimum + addr.translation_offset;
	res->end = res->start + addr.address_length - 1;
	res->child = NULL;

	if (insert_resource(root, res)) {
		printk(KERN_ERR "PCI: Failed to allocate 0x%lx-0x%lx "
			"from %s for %s\n", (unsigned long) res->start,
			(unsigned long) res->end, root->name, info->name);
	} else {
		info->bus->resource[info->res_num] = res;
		info->res_num++;
	}
	return AE_OK;
}

static void
adjust_transparent_bridge_resources(struct pci_bus *bus)
{
	struct pci_dev *dev;

	list_for_each_entry(dev, &bus->devices, bus_list) {
		int i;
		u16 class = dev->class >> 8;

		if (class == PCI_CLASS_BRIDGE_PCI && dev->transparent) {
			for(i = 3; i < PCI_BUS_NUM_RESOURCES; i++)
				dev->subordinate->resource[i] =
						dev->bus->resource[i - 3];
		}
	}
}

static void
get_current_resources(struct acpi_device *device, int busnum,
			struct pci_bus *bus)
{
	struct pci_root_info info;
	size_t size;

	info.bus = bus;
	info.res_num = 0;
	acpi_walk_resources(device->handle, METHOD_NAME__CRS, count_resource,
				&info);
	if (!info.res_num)
		return;

	size = sizeof(*info.res) * info.res_num;
	info.res = kmalloc(size, GFP_KERNEL);
	if (!info.res)
		goto res_alloc_fail;

	info.name = kmalloc(12, GFP_KERNEL);
	if (!info.name)
		goto name_alloc_fail;
	sprintf(info.name, "PCI Bus #%02x", busnum);

	info.res_num = 0;
	acpi_walk_resources(device->handle, METHOD_NAME__CRS, setup_resource,
				&info);
	if (info.res_num)
		adjust_transparent_bridge_resources(bus);

	return;

name_alloc_fail:
	kfree(info.res);
res_alloc_fail:
	return;
}

struct pci_bus * __devinit pci_acpi_scan_root(struct acpi_device *device, int domain, int busnum)
{
	struct pci_bus *bus;

	dmi_check_system(acpi_pciprobe_dmi_table);

	if (domain != 0) {
		printk(KERN_WARNING "PCI: Multiple domains not supported\n");
		return NULL;
	}

	bus = pcibios_scan_root(busnum);
#ifdef CONFIG_ACPI_NUMA
	if (bus != NULL) {
		int pxm = acpi_get_pxm(device->handle);
		if (pxm >= 0) {
			bus->sysdata = (void *)(unsigned long)pxm_to_node(pxm);
			printk("bus %d -> pxm %d -> node %ld\n",
				busnum, pxm, (long)(bus->sysdata));
		}
	}
#endif

	if (bus && (pci_probe & PCI_USE__CRS))
		get_current_resources(device, busnum, bus);
	
	return bus;
}

extern int pci_routeirq;
static int __init pci_acpi_init(void)
{
	struct pci_dev *dev = NULL;

	if (pcibios_scanned)
		return 0;

	if (acpi_noirq)
		return 0;

	printk(KERN_INFO "PCI: Using ACPI for IRQ routing\n");
	acpi_irq_penalty_init();
	pcibios_scanned++;
	pcibios_enable_irq = acpi_pci_irq_enable;
	pcibios_disable_irq = acpi_pci_irq_disable;

	if (pci_routeirq) {
		/*
		 * PCI IRQ routing is set up by pci_enable_device(), but we
		 * also do it here in case there are still broken drivers that
		 * don't use pci_enable_device().
		 */
		printk(KERN_INFO "PCI: Routing PCI interrupts for all devices because \"pci=routeirq\" specified\n");
		for_each_pci_dev(dev)
			acpi_pci_irq_enable(dev);
	} else
		printk(KERN_INFO "PCI: If a device doesn't work, try \"pci=routeirq\".  If it helps, post a report\n");

#ifdef CONFIG_X86_IO_APIC
	if (acpi_ioapic)
		print_IO_APIC();
#endif

	return 0;
}
subsys_initcall(pci_acpi_init);
