/*
 *	$Id: pci.c,v 1.91 1999/01/21 13:34:01 davem Exp $
 *
 *	PCI Bus Services, see include/linux/pci.h for further explanation.
 *
 *	Copyright 1993 -- 1997 Drew Eckhardt, Frederic Potter,
 *	David Mosberger-Tang
 *
 *	Copyright 1997 -- 2000 Martin Mares <mj@ucw.cz>
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/interrupt.h>
#include <asm/dma.h>	/* isa_dma_bridge_buggy */
#include "pci.h"

unsigned int pci_pm_d3_delay = 10;

/**
 * pci_bus_max_busnr - returns maximum PCI bus number of given bus' children
 * @bus: pointer to PCI bus structure to search
 *
 * Given a PCI bus, returns the highest PCI bus number present in the set
 * including the given PCI bus and its list of child PCI buses.
 */
unsigned char __devinit
pci_bus_max_busnr(struct pci_bus* bus)
{
	struct list_head *tmp;
	unsigned char max, n;

	max = bus->subordinate;
	list_for_each(tmp, &bus->children) {
		n = pci_bus_max_busnr(pci_bus_b(tmp));
		if(n > max)
			max = n;
	}
	return max;
}
EXPORT_SYMBOL_GPL(pci_bus_max_busnr);

void __iomem *pci_ioremap_bar(struct pci_dev *pdev, int bar)
{
	/*
	 * Make sure the BAR is actually a memory resource, not an IO resource
	 */
	if (!(pci_resource_flags(pdev, bar) & IORESOURCE_MEM)) {
		WARN_ON(1);
		return NULL;
	}
	return ioremap_nocache(pci_resource_start(pdev, bar),
			       pci_resource_len(pdev, bar));
}
EXPORT_SYMBOL_GPL(pci_ioremap_bar);

#define PCI_FIND_CAP_TTL	48

static int __pci_find_next_cap_ttl(struct pci_bus *bus, unsigned int devfn,
				   u8 pos, int cap, int *ttl)
{
	u8 id;

	while ((*ttl)--) {
		pci_bus_read_config_byte(bus, devfn, pos, &pos);
		if (pos < 0x40)
			break;
		pos &= ~3;
		pci_bus_read_config_byte(bus, devfn, pos + PCI_CAP_LIST_ID,
					 &id);
		if (id == 0xff)
			break;
		if (id == cap)
			return pos;
		pos += PCI_CAP_LIST_NEXT;
	}
	return 0;
}

static int __pci_find_next_cap(struct pci_bus *bus, unsigned int devfn, u8 pos, int cap)
{
	u8 id;
	int ttl = 48;

	while (ttl--) {
		pci_bus_read_config_byte(bus, devfn, pos, &pos);
		if (pos < 0x40)
			break;
		pos &= ~3;
		pci_bus_read_config_byte(bus, devfn, pos + PCI_CAP_LIST_ID,
					 &id);
		if (id == 0xff)
			break;
		if (id == cap)
			return pos;
		pos += PCI_CAP_LIST_NEXT;
	}
	return 0;
}

int pci_find_next_capability(struct pci_dev *dev, u8 pos, int cap)
{
	return __pci_find_next_cap(dev->bus, dev->devfn,
				   pos + PCI_CAP_LIST_NEXT, cap);
}
EXPORT_SYMBOL_GPL(pci_find_next_capability);

static int __pci_bus_find_cap(struct pci_bus *bus, unsigned int devfn, u8 hdr_type, int cap)
{
	u16 status;
	u8 pos;

	pci_bus_read_config_word(bus, devfn, PCI_STATUS, &status);
	if (!(status & PCI_STATUS_CAP_LIST))
		return 0;

	switch (hdr_type) {
	case PCI_HEADER_TYPE_NORMAL:
	case PCI_HEADER_TYPE_BRIDGE:
		pos = PCI_CAPABILITY_LIST;
		break;
	case PCI_HEADER_TYPE_CARDBUS:
		pos = PCI_CB_CAPABILITY_LIST;
		break;
	default:
		return 0;
	}
	return __pci_find_next_cap(bus, devfn, pos, cap);
}

static int __pci_bus_find_cap_start(struct pci_bus *bus,
				    unsigned int devfn, u8 hdr_type)
{
	u16 status;

	pci_bus_read_config_word(bus, devfn, PCI_STATUS, &status);
	if (!(status & PCI_STATUS_CAP_LIST))
		return 0;

	switch (hdr_type) {
	case PCI_HEADER_TYPE_NORMAL:
	case PCI_HEADER_TYPE_BRIDGE:
		return PCI_CAPABILITY_LIST;
	case PCI_HEADER_TYPE_CARDBUS:
		return PCI_CB_CAPABILITY_LIST;
	default:
		return 0;
	}

	return 0;
}

/**
 * pci_find_capability - query for devices' capabilities 
 * @dev: PCI device to query
 * @cap: capability code
 *
 * Tell if a device supports a given PCI capability.
 * Returns the address of the requested capability structure within the
 * device's PCI configuration space or 0 in case the device does not
 * support it.  Possible values for @cap:
 *
 *  %PCI_CAP_ID_PM           Power Management 
 *  %PCI_CAP_ID_AGP          Accelerated Graphics Port 
 *  %PCI_CAP_ID_VPD          Vital Product Data 
 *  %PCI_CAP_ID_SLOTID       Slot Identification 
 *  %PCI_CAP_ID_MSI          Message Signalled Interrupts
 *  %PCI_CAP_ID_CHSWP        CompactPCI HotSwap 
 *  %PCI_CAP_ID_PCIX         PCI-X
 *  %PCI_CAP_ID_EXP          PCI Express
 */
int pci_find_capability(struct pci_dev *dev, int cap)
{
	return __pci_bus_find_cap(dev->bus, dev->devfn, dev->hdr_type, cap);
}

/**
 * pci_bus_find_capability - query for devices' capabilities 
 * @bus:   the PCI bus to query
 * @devfn: PCI device to query
 * @cap:   capability code
 *
 * Like pci_find_capability() but works for pci devices that do not have a
 * pci_dev structure set up yet. 
 *
 * Returns the address of the requested capability structure within the
 * device's PCI configuration space or 0 in case the device does not
 * support it.
 */
int pci_bus_find_capability(struct pci_bus *bus, unsigned int devfn, int cap)
{
	u8 hdr_type;

	pci_bus_read_config_byte(bus, devfn, PCI_HEADER_TYPE, &hdr_type);

	return __pci_bus_find_cap(bus, devfn, hdr_type & 0x7f, cap);
}

/**
 * pci_find_ext_capability - Find an extended capability
 * @dev: PCI device to query
 * @cap: capability code
 *
 * Returns the address of the requested extended capability structure
 * within the device's PCI configuration space or 0 if the device does
 * not support it.  Possible values for @cap:
 *
 *  %PCI_EXT_CAP_ID_ERR		Advanced Error Reporting
 *  %PCI_EXT_CAP_ID_VC		Virtual Channel
 *  %PCI_EXT_CAP_ID_DSN		Device Serial Number
 *  %PCI_EXT_CAP_ID_PWR		Power Budgeting
 */
int pci_find_ext_capability(struct pci_dev *dev, int cap)
{
	u32 header;
	int ttl = 480; /* 3840 bytes, minimum 8 bytes per capability */
	int pos = 0x100;

	if (dev->cfg_size <= 256)
		return 0;

	if (pci_read_config_dword(dev, pos, &header) != PCIBIOS_SUCCESSFUL)
		return 0;

	/*
	 * If we have no capabilities, this is indicated by cap ID,
	 * cap version and next pointer all being 0.
	 */
	if (header == 0)
		return 0;

	while (ttl-- > 0) {
		if (PCI_EXT_CAP_ID(header) == cap)
			return pos;

		pos = PCI_EXT_CAP_NEXT(header);
		if (pos < 0x100)
			break;

		if (pci_read_config_dword(dev, pos, &header) != PCIBIOS_SUCCESSFUL)
			break;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(pci_find_ext_capability);

static int __pci_find_next_ht_cap(struct pci_dev *dev, int pos, int ht_cap)
{
	int rc, ttl = PCI_FIND_CAP_TTL;
	u8 cap, mask;

	if (ht_cap == HT_CAPTYPE_SLAVE || ht_cap == HT_CAPTYPE_HOST)
		mask = HT_3BIT_CAP_MASK;
	else
		mask = HT_5BIT_CAP_MASK;

	pos = __pci_find_next_cap_ttl(dev->bus, dev->devfn, pos,
				      PCI_CAP_ID_HT, &ttl);
	while (pos) {
		rc = pci_read_config_byte(dev, pos + 3, &cap);
		if (rc != PCIBIOS_SUCCESSFUL)
			return 0;

		if ((cap & mask) == ht_cap)
			return pos;

		pos = __pci_find_next_cap_ttl(dev->bus, dev->devfn,
					      pos + PCI_CAP_LIST_NEXT,
					      PCI_CAP_ID_HT, &ttl);
	}

	return 0;
}
/**
 * pci_find_next_ht_capability - query a device's Hypertransport capabilities
 * @dev: PCI device to query
 * @pos: Position from which to continue searching
 * @ht_cap: Hypertransport capability code
 *
 * To be used in conjunction with pci_find_ht_capability() to search for
 * all capabilities matching @ht_cap. @pos should always be a value returned
 * from pci_find_ht_capability().
 *
 * NB. To be 100% safe against broken PCI devices, the caller should take
 * steps to avoid an infinite loop.
 */
int pci_find_next_ht_capability(struct pci_dev *dev, int pos, int ht_cap)
{
	return __pci_find_next_ht_cap(dev, pos + PCI_CAP_LIST_NEXT, ht_cap);
}
EXPORT_SYMBOL_GPL(pci_find_next_ht_capability);

/**
 * pci_find_ht_capability - query a device's Hypertransport capabilities
 * @dev: PCI device to query
 * @ht_cap: Hypertransport capability code
 *
 * Tell if a device supports a given Hypertransport capability.
 * Returns an address within the device's PCI configuration space
 * or 0 in case the device does not support the request capability.
 * The address points to the PCI capability, of type PCI_CAP_ID_HT,
 * which has a Hypertransport capability matching @ht_cap.
 */
int pci_find_ht_capability(struct pci_dev *dev, int ht_cap)
{
	int pos;

	pos = __pci_bus_find_cap_start(dev->bus, dev->devfn, dev->hdr_type);
	if (pos)
		pos = __pci_find_next_ht_cap(dev, pos, ht_cap);

	return pos;
}
EXPORT_SYMBOL_GPL(pci_find_ht_capability);

/**
 * pci_find_parent_resource - return resource region of parent bus of given region
 * @dev: PCI device structure contains resources to be searched
 * @res: child resource record for which parent is sought
 *
 *  For given resource region of given device, return the resource
 *  region of parent bus the given region is contained in or where
 *  it should be allocated from.
 */
struct resource *
pci_find_parent_resource(const struct pci_dev *dev, struct resource *res)
{
	const struct pci_bus *bus = dev->bus;
	int i;
	struct resource *best = NULL;

	for(i = 0; i < PCI_BUS_NUM_RESOURCES; i++) {
		struct resource *r = bus->resource[i];
		if (!r)
			continue;
		if (res->start && !(res->start >= r->start && res->end <= r->end))
			continue;	/* Not contained */
		if ((res->flags ^ r->flags) & (IORESOURCE_IO | IORESOURCE_MEM))
			continue;	/* Wrong type */
		if (!((res->flags ^ r->flags) & IORESOURCE_PREFETCH))
			return r;	/* Exact match */
		if ((res->flags & IORESOURCE_PREFETCH) && !(r->flags & IORESOURCE_PREFETCH))
			best = r;	/* Approximating prefetchable by non-prefetchable */
	}
	return best;
}

/**
 * pci_restore_bars - restore a devices BAR values (e.g. after wake-up)
 * @dev: PCI device to have its BARs restored
 *
 * Restore the BAR values for a given device, so as to make it
 * accessible by its driver.
 */
void
pci_restore_bars(struct pci_dev *dev)
{
	int i, numres;

	switch (dev->hdr_type) {
	case PCI_HEADER_TYPE_NORMAL:
		numres = 6;
		break;
	case PCI_HEADER_TYPE_BRIDGE:
		numres = 2;
		break;
	case PCI_HEADER_TYPE_CARDBUS:
		numres = 1;
		break;
	default:
		/* Should never get here, but just in case... */
		return;
	}

	for (i = 0; i < numres; i ++)
		pci_update_resource(dev, &dev->resource[i], i);
}

int (*platform_pci_set_power_state)(struct pci_dev *dev, pci_power_t t);

/**
 * pci_set_power_state - Set the power state of a PCI device
 * @dev: PCI device to be suspended
 * @state: PCI power state (D0, D1, D2, D3hot, D3cold) we're entering
 *
 * Transition a device to a new power state, using the Power Management 
 * Capabilities in the device's config space.
 *
 * RETURN VALUE: 
 * -EINVAL if trying to enter a lower state than we're already in.
 * 0 if we're already in the requested state.
 * -EIO if device does not support PCI PM.
 * 0 if we can successfully change the power state.
 */
int
pci_set_power_state(struct pci_dev *dev, pci_power_t state)
{
	int pm, need_restore = 0;
	u16 pmcsr, pmc;

	/* bound the state we're entering */
	if (state > PCI_D3hot)
		state = PCI_D3hot;

	/* Validate current state:
	 * Can enter D0 from any state, but if we can only go deeper 
	 * to sleep if we're already in a low power state
	 */
	if (state != PCI_D0 && dev->current_state > state) {
		printk(KERN_ERR "%s(): %s: state=%d, current state=%d\n",
			__FUNCTION__, pci_name(dev), state, dev->current_state);
		return -EINVAL;
	} else if (dev->current_state == state)
		return 0;        /* we're already there */

	/*
	 * If the device or the parent bridge can't support PCI PM, ignore
	 * the request if we're doing anything besides putting it into D0
	 * (which would only happen on boot).
	 */
	if ((state == PCI_D1 || state == PCI_D2) && pci_no_d1d2(dev))
		return 0;

	/* find PCI PM capability in list */
	pm = pci_find_capability(dev, PCI_CAP_ID_PM);
	
	/* abort if the device doesn't support PM capabilities */
	if (!pm)
		return -EIO; 

	pci_read_config_word(dev,pm + PCI_PM_PMC,&pmc);
	if ((pmc & PCI_PM_CAP_VER_MASK) > 3) {
		printk(KERN_DEBUG
		       "PCI: %s has unsupported PM cap regs version (%u)\n",
		       pci_name(dev), pmc & PCI_PM_CAP_VER_MASK);
		return -EIO;
	}

	/* check if this device supports the desired state */
	if (state == PCI_D1 && !(pmc & PCI_PM_CAP_D1))
		return -EIO;
	else if (state == PCI_D2 && !(pmc & PCI_PM_CAP_D2))
		return -EIO;

	pci_read_config_word(dev, pm + PCI_PM_CTRL, &pmcsr);

	/* If we're (effectively) in D3, force entire word to 0.
	 * This doesn't affect PME_Status, disables PME_En, and
	 * sets PowerState to 0.
	 */
	switch (dev->current_state) {
	case PCI_D0:
	case PCI_D1:
	case PCI_D2:
		pmcsr &= ~PCI_PM_CTRL_STATE_MASK;
		pmcsr |= state;
		break;
	case PCI_UNKNOWN: /* Boot-up */
		if ((pmcsr & PCI_PM_CTRL_STATE_MASK) == PCI_D3hot
		 && !(pmcsr & PCI_PM_CTRL_NO_SOFT_RESET))
			need_restore = 1;
		/* Fall-through: force to D0 */
	default:
		pmcsr = 0;
		break;
	}

	/* enter specified state */
	pci_write_config_word(dev, pm + PCI_PM_CTRL, pmcsr);

	/* Mandatory power management transition delays */
	/* see PCI PM 1.1 5.6.1 table 18 */
	if (state == PCI_D3hot || dev->current_state == PCI_D3hot)
		msleep(pci_pm_d3_delay);
	else if (state == PCI_D2 || dev->current_state == PCI_D2)
		udelay(200);

	/*
	 * Give firmware a chance to be called, such as ACPI _PRx, _PSx
	 * Firmware method after native method ?
	 */
	if (platform_pci_set_power_state)
		platform_pci_set_power_state(dev, state);

	dev->current_state = state;

	/* According to section 5.4.1 of the "PCI BUS POWER MANAGEMENT
	 * INTERFACE SPECIFICATION, REV. 1.2", a device transitioning
	 * from D3hot to D0 _may_ perform an internal reset, thereby
	 * going to "D0 Uninitialized" rather than "D0 Initialized".
	 * For example, at least some versions of the 3c905B and the
	 * 3c556B exhibit this behaviour.
	 *
	 * At least some laptop BIOSen (e.g. the Thinkpad T21) leave
	 * devices in a D3hot state at boot.  Consequently, we need to
	 * restore at least the BARs so that the device will be
	 * accessible to its driver.
	 */
	if (need_restore)
		pci_restore_bars(dev);

	return 0;
}

int (*platform_pci_choose_state)(struct pci_dev *dev, pm_message_t state);
 
/**
 * pci_choose_state - Choose the power state of a PCI device
 * @dev: PCI device to be suspended
 * @state: target sleep state for the whole system. This is the value
 *	that is passed to suspend() function.
 *
 * Returns PCI power state suitable for given device and given system
 * message.
 */

pci_power_t pci_choose_state(struct pci_dev *dev, pm_message_t state)
{
	int ret;

	if (!pci_find_capability(dev, PCI_CAP_ID_PM))
		return PCI_D0;

	if (platform_pci_choose_state) {
		ret = platform_pci_choose_state(dev, state);
		if (ret >= 0)
			state.event = ret;
	}

	switch (state.event) {
	case PM_EVENT_ON:
		return PCI_D0;
	case PM_EVENT_FREEZE:
	case PM_EVENT_SUSPEND:
		return PCI_D3hot;
	default:
		printk("They asked me for state %d\n", state.event);
		BUG();
	}
	return PCI_D0;
}

EXPORT_SYMBOL(pci_choose_state);

static int pci_save_pcie_state(struct pci_dev *dev)
{
	int pos, i = 0;
	struct pci_cap_saved_state *save_state;
	u16 *cap;

	pos = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (pos <= 0)
		return 0;

	save_state = pci_find_saved_cap(dev, PCI_CAP_ID_EXP);
	if (!save_state) {
		save_state = kzalloc(sizeof(*save_state) + sizeof(u16) * 7, GFP_KERNEL);
		if (!save_state) {
			printk(KERN_ERR "Out of memory in pci_save_pcie_state\n");
			return -ENOMEM;
		}
		save_state->cap_nr = PCI_CAP_ID_EXP;
		pci_add_saved_cap(dev, save_state);
	}
	cap = (u16 *)&save_state->data[0];

	pci_read_config_word(dev, pos + PCI_EXP_DEVCTL, &cap[i++]);
	pci_read_config_word(dev, pos + PCI_EXP_LNKCTL, &cap[i++]);
	pci_read_config_word(dev, pos + PCI_EXP_SLTCTL, &cap[i++]);
	pci_read_config_word(dev, pos + PCI_EXP_RTCTL, &cap[i++]);
	pci_read_config_word(dev, pos + PCI_EXP_DEVCTL2, &cap[i++]);
	pci_read_config_word(dev, pos + PCI_EXP_LNKCTL2, &cap[i++]);
	pci_read_config_word(dev, pos + PCI_EXP_SLTCTL2, &cap[i++]);
	return 0;
}

static void pci_restore_pcie_state(struct pci_dev *dev)
{
	int i = 0, pos;
	struct pci_cap_saved_state *save_state;
	u16 *cap;

	save_state = pci_find_saved_cap(dev, PCI_CAP_ID_EXP);
	pos = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (!save_state || pos <= 0)
		return;
	cap = (u16 *)&save_state->data[0];

	pci_write_config_word(dev, pos + PCI_EXP_DEVCTL, cap[i++]);
	pci_write_config_word(dev, pos + PCI_EXP_LNKCTL, cap[i++]);
	pci_write_config_word(dev, pos + PCI_EXP_SLTCTL, cap[i++]);
	pci_write_config_word(dev, pos + PCI_EXP_RTCTL, cap[i++]);
	pci_write_config_word(dev, pos + PCI_EXP_DEVCTL2, cap[i++]);
	pci_write_config_word(dev, pos + PCI_EXP_LNKCTL2, cap[i++]);
	pci_write_config_word(dev, pos + PCI_EXP_SLTCTL2, cap[i++]);
}

/**
 * pci_save_state - save the PCI configuration space of a device before suspending
 * @dev: - PCI device that we're dealing with
 */
int
pci_save_state(struct pci_dev *dev)
{
	int i;

	/* XXX: 100% dword access ok here? */
	for (i = 0; i < 16; i++)
		pci_read_config_dword(dev, i * 4,&dev->saved_config_space[i]);
	if ((i = pci_save_msi_state(dev)) != 0)
		return i;
	if ((i = pci_save_msix_state(dev)) != 0)
		return i;
	if ((i = pci_save_pcie_state(dev)) != 0)
		return i;
	return 0;
}

/** 
 * pci_restore_state - Restore the saved state of a PCI device
 * @dev: - PCI device that we're dealing with
 */
int 
pci_restore_state(struct pci_dev *dev)
{
	int i;
	int val;

	/* PCI Express register must be restored first */
	pci_restore_pcie_state(dev);

	/*
	 * The Base Address register should be programmed before the command
	 * register(s)
	 */
	for (i = 15; i >= 0; i--) {
		pci_read_config_dword(dev, i * 4, &val);
		if (val != dev->saved_config_space[i]) {
			printk(KERN_DEBUG "PM: Writing back config space on "
				"device %s at offset %x (was %x, writing %x)\n",
				pci_name(dev), i,
				val, (int)dev->saved_config_space[i]);
			pci_write_config_dword(dev,i * 4,
				dev->saved_config_space[i]);
		}
	}
	pci_restore_msi_state(dev);
	pci_restore_msix_state(dev);
	pci_restore_iov_state(dev);
	return 0;
}

/**
 * pci_enable_device_bars - Initialize some of a device for use
 * @dev: PCI device to be initialized
 * @bars: bitmask of BAR's that must be configured
 *
 *  Initialize device before it's used by a driver. Ask low-level code
 *  to enable selected I/O and memory resources. Wake up the device if it 
 *  was suspended. Beware, this function can fail.
 */
 
int
pci_enable_device_bars(struct pci_dev *dev, int bars)
{
	int err;

	err = pci_set_power_state(dev, PCI_D0);
	if (err < 0 && err != -EIO)
		return err;
	err = pcibios_enable_device(dev, bars);
	if (err < 0)
		return err;
	return 0;
}

static int do_pci_enable_device(struct pci_dev *dev, int bars)
{
	int err;
	err = pci_enable_device_bars(dev, bars);
	if (err)
		return err;
	pci_fixup_device(pci_fixup_enable, dev);

	return 0;
}

static int __pci_enable_device_flags(struct pci_dev *dev,
				     resource_size_t flags)
{
	int err;
	int i, bars = 0;

	if (dev->is_enabled)
		return 0;		/* already enabled */

	dev->is_enabled = 1;

	for (i = 0; i < DEVICE_COUNT_RESOURCE; i++)
		if (dev->resource[i].flags & flags)
			bars |= (1 << i);

	err = do_pci_enable_device(dev, bars);
	if (err < 0)
		dev->is_enabled = 0;
	return err;
}

/**
 * pci_enable_device_io - Initialize a device for use with IO space
 * @dev: PCI device to be initialized
 *
 *  Initialize device before it's used by a driver. Ask low-level code
 *  to enable I/O resources. Wake up the device if it was suspended.
 *  Beware, this function can fail.
 */
int pci_enable_device_io(struct pci_dev *dev)
{
	return __pci_enable_device_flags(dev, IORESOURCE_IO);
}

/**
 * pci_enable_device_mem - Initialize a device for use with Memory space
 * @dev: PCI device to be initialized
 *
 *  Initialize device before it's used by a driver. Ask low-level code
 *  to enable Memory resources. Wake up the device if it was suspended.
 *  Beware, this function can fail.
 */
int pci_enable_device_mem(struct pci_dev *dev)
{
	return __pci_enable_device_flags(dev, IORESOURCE_MEM);
}

/**
 * pci_enable_device - Initialize device before it's used by a driver.
 * @dev: PCI device to be initialized
 *
 *  Initialize device before it's used by a driver. Ask low-level code
 *  to enable I/O and memory. Wake up the device if it was suspended.
 *  Beware, this function can fail.
 *
 *  Note we don't actually enable the device many times if we call
 *  this function repeatedly.
 */
int
pci_enable_device(struct pci_dev *dev)
{
	return __pci_enable_device_flags(dev, IORESOURCE_MEM | IORESOURCE_IO);
}

/*
 * Managed PCI resources.  This manages device on/off, intx/msi/msix
 * on/off and BAR regions.  pci_dev itself records msi/msix status, so
 * there's no need to track it separately.  pci_devres is initialized
 * when a device is enabled using managed PCI device enable interface.
 */
struct pci_devres {
	unsigned int enabled:1;
	unsigned int pinned:1;
	unsigned int orig_intx:1;
	unsigned int restore_intx:1;
	u32 region_mask;
};

static void pcim_release(struct device *gendev, void *res)
{
	struct pci_dev *dev = container_of(gendev, struct pci_dev, dev);
	struct pci_devres *this = res;
	int i;

	if (dev->msi_enabled)
		pci_disable_msi(dev);
	if (dev->msix_enabled)
		pci_disable_msix(dev);

	for (i = 0; i < DEVICE_COUNT_RESOURCE; i++)
		if (this->region_mask & (1 << i))
			pci_release_region(dev, i);

	if (this->restore_intx)
		pci_intx(dev, this->orig_intx);

	if (this->enabled && !this->pinned)
		pci_disable_device(dev);
}

static struct pci_devres * get_pci_dr(struct pci_dev *pdev)
{
	struct pci_devres *dr, *new_dr;

	dr = devres_find(&pdev->dev, pcim_release, NULL, NULL);
	if (dr)
		return dr;

	new_dr = devres_alloc(pcim_release, sizeof(*new_dr), GFP_KERNEL);
	if (!new_dr)
		return NULL;
	return devres_get(&pdev->dev, new_dr, NULL, NULL);
}

static struct pci_devres * find_pci_dr(struct pci_dev *pdev)
{
	if (pci_is_managed(pdev))
		return devres_find(&pdev->dev, pcim_release, NULL, NULL);
	return NULL;
}

/**
 * pcim_enable_device - Managed pci_enable_device()
 * @pdev: PCI device to be initialized
 *
 * Managed pci_enable_device().
 */
int pcim_enable_device(struct pci_dev *pdev)
{
	struct pci_devres *dr;
	int rc;

	dr = get_pci_dr(pdev);
	if (unlikely(!dr))
		return -ENOMEM;
	if (dr->enabled)
		return 0;

	rc = pci_enable_device(pdev);
	if (!rc) {
		pdev->is_managed = 1;
		dr->enabled = 1;
	}
	return rc;
}

/**
 * pcim_pin_device - Pin managed PCI device
 * @pdev: PCI device to pin
 *
 * Pin managed PCI device @pdev.  Pinned device won't be disabled on
 * driver detach.  @pdev must have been enabled with
 * pcim_enable_device().
 */
void pcim_pin_device(struct pci_dev *pdev)
{
	struct pci_devres *dr;

	dr = find_pci_dr(pdev);
	WARN_ON(!dr || !dr->enabled);
	if (dr)
		dr->pinned = 1;
}

/**
 * pcibios_disable_device - disable arch specific PCI resources for device dev
 * @dev: the PCI device to disable
 *
 * Disables architecture specific PCI resources for the device. This
 * is the default implementation. Architecture implementations can
 * override this.
 */
void __attribute__ ((weak)) pcibios_disable_device (struct pci_dev *dev) {}

/**
 * pci_disable_device - Disable PCI device after use
 * @dev: PCI device to be disabled
 *
 * Signal to the system that the PCI device is not in use by the system
 * anymore.  This only involves disabling PCI bus-mastering, if active.
 */
void
pci_disable_device(struct pci_dev *dev)
{
	struct pci_devres *dr;
	u16 pci_command;

	dr = find_pci_dr(dev);
	if (dr)
		dr->enabled = 0;

	if (dev->msi_enabled)
		disable_msi_mode(dev, pci_find_capability(dev, PCI_CAP_ID_MSI),
			PCI_CAP_ID_MSI);
	if (dev->msix_enabled)
		disable_msi_mode(dev, pci_find_capability(dev, PCI_CAP_ID_MSI),
			PCI_CAP_ID_MSIX);

	pci_read_config_word(dev, PCI_COMMAND, &pci_command);
	if (pci_command & PCI_COMMAND_MASTER) {
		pci_command &= ~PCI_COMMAND_MASTER;
		pci_write_config_word(dev, PCI_COMMAND, pci_command);
	}
	dev->is_busmaster = 0;

	pcibios_disable_device(dev);
	dev->is_enabled = 0;
}

/**
 * pcibios_set_pcie_reset_state - set reset state for device dev
 * @dev: the PCI-E device reset
 * @state: Reset state to enter into
 *
 *
 * Sets the PCI reset state for the device. This is the default
 * implementation. Architecture implementations can override this.
 */
int __attribute__ ((weak)) pcibios_set_pcie_reset_state (struct pci_dev *dev,
							 enum pcie_reset_state state)
{
	return -EINVAL;
}

/**
 * pci_set_pcie_reset_state - set reset state for device dev
 * @dev: the PCI-E device reset
 * @state: Reset state to enter into
 *
 *
 * Sets the PCI reset state for the device.
 */
int pci_set_pcie_reset_state(struct pci_dev *dev, enum pcie_reset_state state)
{
	return pcibios_set_pcie_reset_state(dev, state);
}

/**
 * pci_enable_wake - enable device to generate PME# when suspended
 * @dev: - PCI device to operate on
 * @state: - Current state of device.
 * @enable: - Flag to enable or disable generation
 * 
 * Set the bits in the device's PM Capabilities to generate PME# when
 * the system is suspended. 
 *
 * -EIO is returned if device doesn't have PM Capabilities. 
 * -EINVAL is returned if device supports it, but can't generate wake events.
 * 0 if operation is successful.
 * 
 */
int pci_enable_wake(struct pci_dev *dev, pci_power_t state, int enable)
{
	int pm;
	u16 value;

	/* find PCI PM capability in list */
	pm = pci_find_capability(dev, PCI_CAP_ID_PM);

	/* If device doesn't support PM Capabilities, but request is to disable
	 * wake events, it's a nop; otherwise fail */
	if (!pm) 
		return enable ? -EIO : 0; 

	/* Check device's ability to generate PME# */
	pci_read_config_word(dev,pm+PCI_PM_PMC,&value);

	value &= PCI_PM_CAP_PME_MASK;
	value >>= ffs(PCI_PM_CAP_PME_MASK) - 1;   /* First bit of mask */

	/* Check if it can generate PME# from requested state. */
	if (!value || !(value & (1 << state))) 
		return enable ? -EINVAL : 0;

	pci_read_config_word(dev, pm + PCI_PM_CTRL, &value);

	/* Clear PME_Status by writing 1 to it and enable PME# */
	value |= PCI_PM_CTRL_PME_STATUS | PCI_PM_CTRL_PME_ENABLE;

	if (!enable)
		value &= ~PCI_PM_CTRL_PME_ENABLE;

	pci_write_config_word(dev, pm + PCI_PM_CTRL, value);
	
	return 0;
}

/**
 * pci_enable_ari - enable ARI forwarding if hardware support it
 * @dev: the PCI device
 */
void pci_enable_ari(struct pci_dev *dev)
{
	int pos;
	u32 cap;
	u16 ctrl;
	struct pci_dev *bridge;

	if (dev->devfn)
		return;

	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_ARI);
	if (!pos)
		return;

	bridge = dev->bus->self;
	if (!bridge)
		return;

	pos = pci_find_capability(bridge, PCI_CAP_ID_EXP);
	if (!pos)
		return;

	pci_read_config_dword(bridge, pos + PCI_EXP_DEVCAP2, &cap);
	if (!(cap & PCI_EXP_DEVCAP2_ARI))
		return;

	pci_read_config_word(bridge, pos + PCI_EXP_DEVCTL2, &ctrl);
	ctrl |= PCI_EXP_DEVCTL2_ARI;
	pci_write_config_word(bridge, pos + PCI_EXP_DEVCTL2, ctrl);

	bridge->ari_enabled = 1;
}

static int pci_acs_enable;

/**
 * pci_request_acs - ask for ACS to be enabled if supported
 */
void pci_request_acs(void)
{
	pci_acs_enable = 1;
}

/**
 * pci_enable_acs - enable ACS if hardware support it
 * @dev: the PCI device
 */
void pci_enable_acs(struct pci_dev *dev)
{
	int pos;
	u16 cap;
	u16 ctrl;

	if (!pci_acs_enable)
		return;

	if (!dev->is_pcie)
		return;

	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_ACS);
	if (!pos)
		return;

	pci_read_config_word(dev, pos + PCI_ACS_CAP, &cap);
	pci_read_config_word(dev, pos + PCI_ACS_CTRL, &ctrl);

	/* Source Validation */
	ctrl |= (cap & PCI_ACS_SV);

	/* P2P Request Redirect */
	ctrl |= (cap & PCI_ACS_RR);

	/* P2P Completion Redirect */
	ctrl |= (cap & PCI_ACS_CR);

	/* Upstream Forwarding */
	ctrl |= (cap & PCI_ACS_UF);

	pci_write_config_word(dev, pos + PCI_ACS_CTRL, ctrl);
}

int
pci_get_interrupt_pin(struct pci_dev *dev, struct pci_dev **bridge)
{
	u8 pin;

	pin = dev->pin;
	if (!pin)
		return -1;
	pin--;
	while (dev->bus->self) {
		pin = (pin + PCI_SLOT(dev->devfn)) % 4;
		dev = dev->bus->self;
	}
	*bridge = dev;
	return pin;
}

/**
 *	pci_release_region - Release a PCI bar
 *	@pdev: PCI device whose resources were previously reserved by pci_request_region
 *	@bar: BAR to release
 *
 *	Releases the PCI I/O and memory resources previously reserved by a
 *	successful call to pci_request_region.  Call this function only
 *	after all use of the PCI regions has ceased.
 */
void pci_release_region(struct pci_dev *pdev, int bar)
{
	struct pci_devres *dr;

	if (pci_resource_len(pdev, bar) == 0)
		return;
	if (pci_resource_flags(pdev, bar) & IORESOURCE_IO)
		release_region(pci_resource_start(pdev, bar),
				pci_resource_len(pdev, bar));
	else if (pci_resource_flags(pdev, bar) & IORESOURCE_MEM)
		release_mem_region(pci_resource_start(pdev, bar),
				pci_resource_len(pdev, bar));

	dr = find_pci_dr(pdev);
	if (dr)
		dr->region_mask &= ~(1 << bar);
}

/**
 *	pci_request_region - Reserved PCI I/O and memory resource
 *	@pdev: PCI device whose resources are to be reserved
 *	@bar: BAR to be reserved
 *	@res_name: Name to be associated with resource.
 *
 *	Mark the PCI region associated with PCI device @pdev BR @bar as
 *	being reserved by owner @res_name.  Do not access any
 *	address inside the PCI regions unless this call returns
 *	successfully.
 *
 *	Returns 0 on success, or %EBUSY on error.  A warning
 *	message is also printed on failure.
 */
int pci_request_region(struct pci_dev *pdev, int bar, const char *res_name)
{
	struct pci_devres *dr;

	if (pci_resource_len(pdev, bar) == 0)
		return 0;
		
	if (pci_resource_flags(pdev, bar) & IORESOURCE_IO) {
		if (!request_region(pci_resource_start(pdev, bar),
			    pci_resource_len(pdev, bar), res_name))
			goto err_out;
	}
	else if (pci_resource_flags(pdev, bar) & IORESOURCE_MEM) {
		if (!request_mem_region(pci_resource_start(pdev, bar),
				        pci_resource_len(pdev, bar), res_name))
			goto err_out;
	}

	dr = find_pci_dr(pdev);
	if (dr)
		dr->region_mask |= 1 << bar;

	return 0;

err_out:
	printk (KERN_WARNING "PCI: Unable to reserve %s region #%d:%llx@%llx "
		"for device %s\n",
		pci_resource_flags(pdev, bar) & IORESOURCE_IO ? "I/O" : "mem",
		bar + 1, /* PCI BAR # */
		(unsigned long long)pci_resource_len(pdev, bar),
		(unsigned long long)pci_resource_start(pdev, bar),
		pci_name(pdev));
	return -EBUSY;
}

/**
 * pci_release_selected_regions - Release selected PCI I/O and memory resources
 * @pdev: PCI device whose resources were previously reserved
 * @bars: Bitmask of BARs to be released
 *
 * Release selected PCI I/O and memory resources previously reserved.
 * Call this function only after all use of the PCI regions has ceased.
 */
void pci_release_selected_regions(struct pci_dev *pdev, int bars)
{
	int i;

	for (i = 0; i < 6; i++)
		if (bars & (1 << i))
			pci_release_region(pdev, i);
}

/**
 * pci_request_selected_regions - Reserve selected PCI I/O and memory resources
 * @pdev: PCI device whose resources are to be reserved
 * @bars: Bitmask of BARs to be requested
 * @res_name: Name to be associated with resource
 */
int pci_request_selected_regions(struct pci_dev *pdev, int bars,
				 const char *res_name)
{
	int i;

	for (i = 0; i < 6; i++)
		if (bars & (1 << i))
			if(pci_request_region(pdev, i, res_name))
				goto err_out;
	return 0;

err_out:
	while(--i >= 0)
		if (bars & (1 << i))
			pci_release_region(pdev, i);

	return -EBUSY;
}

/**
 *	pci_release_regions - Release reserved PCI I/O and memory resources
 *	@pdev: PCI device whose resources were previously reserved by pci_request_regions
 *
 *	Releases all PCI I/O and memory resources previously reserved by a
 *	successful call to pci_request_regions.  Call this function only
 *	after all use of the PCI regions has ceased.
 */

void pci_release_regions(struct pci_dev *pdev)
{
	pci_release_selected_regions(pdev, (1 << 6) - 1);
}

/**
 *	pci_request_regions - Reserved PCI I/O and memory resources
 *	@pdev: PCI device whose resources are to be reserved
 *	@res_name: Name to be associated with resource.
 *
 *	Mark all PCI regions associated with PCI device @pdev as
 *	being reserved by owner @res_name.  Do not access any
 *	address inside the PCI regions unless this call returns
 *	successfully.
 *
 *	Returns 0 on success, or %EBUSY on error.  A warning
 *	message is also printed on failure.
 */
int pci_request_regions(struct pci_dev *pdev, const char *res_name)
{
	return pci_request_selected_regions(pdev, ((1 << 6) - 1), res_name);
}

static void __pci_set_master(struct pci_dev *dev, bool enable)
{
	u16 old_cmd, cmd;

	pci_read_config_word(dev, PCI_COMMAND, &old_cmd);
	if (enable)
		cmd = old_cmd | PCI_COMMAND_MASTER;
	else
		cmd = old_cmd & ~PCI_COMMAND_MASTER;
	if (cmd != old_cmd) {
		pr_debug("PCI: %s bus mastering for device %s\n",
			enable ? "Enabling" : "Disabling", pci_name(dev));
		pci_write_config_word(dev, PCI_COMMAND, cmd);
	}
	dev->is_busmaster = enable;
}
/**
 * pci_set_master - enables bus-mastering for device dev
 * @dev: the PCI device to enable
 *
 * Enables bus-mastering on the device and calls pcibios_set_master()
 * to do the needed arch specific settings.
 */
void pci_set_master(struct pci_dev *dev)
{
	__pci_set_master(dev, true);
	pcibios_set_master(dev);
}

/**
 * pci_clear_master - disables bus-mastering for device dev
 * @dev: the PCI device to disable
 */
void pci_clear_master(struct pci_dev *dev)
{
	__pci_set_master(dev, false);
}

#ifndef HAVE_ARCH_PCI_MWI
/* This can be overridden by arch code. */
u8 pci_cache_line_size = L1_CACHE_BYTES >> 2;

/**
 * pci_generic_prep_mwi - helper function for pci_set_mwi
 * @dev: the PCI device for which MWI is enabled
 *
 * Helper function for generic implementation of pcibios_prep_mwi
 * function.  Originally copied from drivers/net/acenic.c.
 * Copyright 1998-2001 by Jes Sorensen, <jes@trained-monkey.org>.
 *
 * RETURNS: An appropriate -ERRNO error value on error, or zero for success.
 */
static int
pci_generic_prep_mwi(struct pci_dev *dev)
{
	u8 cacheline_size;

	if (!pci_cache_line_size)
		return -EINVAL;		/* The system doesn't support MWI. */

	/* Validate current setting: the PCI_CACHE_LINE_SIZE must be
	   equal to or multiple of the right value. */
	pci_read_config_byte(dev, PCI_CACHE_LINE_SIZE, &cacheline_size);
	if (cacheline_size >= pci_cache_line_size &&
	    (cacheline_size % pci_cache_line_size) == 0)
		return 0;

	/* Write the correct value. */
	pci_write_config_byte(dev, PCI_CACHE_LINE_SIZE, pci_cache_line_size);
	/* Read it back. */
	pci_read_config_byte(dev, PCI_CACHE_LINE_SIZE, &cacheline_size);
	if (cacheline_size == pci_cache_line_size)
		return 0;

	printk(KERN_DEBUG "PCI: cache line size of %d is not supported "
	       "by device %s\n", pci_cache_line_size << 2, pci_name(dev));

	return -EINVAL;
}
#endif /* !HAVE_ARCH_PCI_MWI */

/**
 * pci_set_mwi - enables memory-write-invalidate PCI transaction
 * @dev: the PCI device for which MWI is enabled
 *
 * Enables the Memory-Write-Invalidate transaction in %PCI_COMMAND,
 * and then calls @pcibios_set_mwi to do the needed arch specific
 * operations or a generic mwi-prep function.
 *
 * RETURNS: An appropriate -ERRNO error value on error, or zero for success.
 */
int
pci_set_mwi(struct pci_dev *dev)
{
	int rc;
	u16 cmd;

#ifdef HAVE_ARCH_PCI_MWI
	rc = pcibios_prep_mwi(dev);
#else
	rc = pci_generic_prep_mwi(dev);
#endif

	if (rc)
		return rc;

	pci_read_config_word(dev, PCI_COMMAND, &cmd);
	if (! (cmd & PCI_COMMAND_INVALIDATE)) {
		pr_debug("PCI: Enabling Mem-Wr-Inval for device %s\n", pci_name(dev));
		cmd |= PCI_COMMAND_INVALIDATE;
		pci_write_config_word(dev, PCI_COMMAND, cmd);
	}
	
	return 0;
}

/**
 * pci_try_set_mwi - enables memory-write-invalidate PCI transaction
 * @dev: the PCI device for which MWI is enabled
 *
 * Enables the Memory-Write-Invalidate transaction in %PCI_COMMAND.
 * Callers are not required to check the return value.
 *
 * RETURNS: An appropriate -ERRNO error value on error, or zero for success.
 */
int pci_try_set_mwi(struct pci_dev *dev)
{
	int rc = pci_set_mwi(dev);
	return rc;
}

/**
 * pci_clear_mwi - disables Memory-Write-Invalidate for device dev
 * @dev: the PCI device to disable
 *
 * Disables PCI Memory-Write-Invalidate transaction on the device
 */
void
pci_clear_mwi(struct pci_dev *dev)
{
	u16 cmd;

	pci_read_config_word(dev, PCI_COMMAND, &cmd);
	if (cmd & PCI_COMMAND_INVALIDATE) {
		cmd &= ~PCI_COMMAND_INVALIDATE;
		pci_write_config_word(dev, PCI_COMMAND, cmd);
	}
}

/**
 * pci_intx - enables/disables PCI INTx for device dev
 * @pdev: the PCI device to operate on
 * @enable: boolean: whether to enable or disable PCI INTx
 *
 * Enables/disables PCI INTx for device dev
 */
void
pci_intx(struct pci_dev *pdev, int enable)
{
	u16 pci_command, new;

	pci_read_config_word(pdev, PCI_COMMAND, &pci_command);

	if (enable) {
		new = pci_command & ~PCI_COMMAND_INTX_DISABLE;
	} else {
		new = pci_command | PCI_COMMAND_INTX_DISABLE;
	}

	if (new != pci_command) {
		struct pci_devres *dr;

		pci_write_config_word(pdev, PCI_COMMAND, new);

		dr = find_pci_dr(pdev);
		if (dr && !dr->restore_intx) {
			dr->restore_intx = 1;
			dr->orig_intx = !enable;
		}
	}
}

#ifndef HAVE_ARCH_PCI_SET_DMA_MASK
/*
 * These can be overridden by arch-specific implementations
 */
int
pci_set_dma_mask(struct pci_dev *dev, u64 mask)
{
	if (!pci_dma_supported(dev, mask))
		return -EIO;

	dev->dma_mask = mask;

	return 0;
}
    
int
pci_set_consistent_dma_mask(struct pci_dev *dev, u64 mask)
{
	if (!pci_dma_supported(dev, mask))
		return -EIO;

	dev->dev.coherent_dma_mask = mask;

	return 0;
}
#endif

static int __pcie_flr(struct pci_dev *dev, int probe)
{
	u16 status;
	u32 cap;
	int exppos = pci_find_capability(dev, PCI_CAP_ID_EXP);

	if (!exppos)
		return -ENOTTY;
	pci_read_config_dword(dev, exppos + PCI_EXP_DEVCAP, &cap);
	if (!(cap & PCI_EXP_DEVCAP_FLR))
		return -ENOTTY;

	if (probe)
		return 0;

	pci_block_user_cfg_access(dev);

	/* Wait for Transaction Pending bit clean */
	msleep(100);
	pci_read_config_word(dev, exppos + PCI_EXP_DEVSTA, &status);
	if (status & PCI_EXP_DEVSTA_TRPND) {
		dev_info(&dev->dev, "Busy after 100ms while trying to reset; "
			"sleeping for 1 second\n");
		ssleep(1);
		pci_read_config_word(dev, exppos + PCI_EXP_DEVSTA, &status);
		if (status & PCI_EXP_DEVSTA_TRPND)
			dev_info(&dev->dev, "Still busy after 1s; "
				"proceeding with reset anyway\n");
	}

	pci_write_config_word(dev, exppos + PCI_EXP_DEVCTL,
				PCI_EXP_DEVCTL_BCR_FLR);
	mdelay(100);

	pci_unblock_user_cfg_access(dev);
	return 0;
}

static int __pci_dev_specific_reset(struct pci_dev *dev, int probe)
{
	struct pci_dev_reset_methods *i;

	for (i = pci_dev_reset_methods; i->reset; i++) {
		if ((i->vendor == dev->vendor ||
		     i->vendor == (u16)PCI_ANY_ID) &&
		    (i->device == dev->device ||
		     i->device == (u16)PCI_ANY_ID))
			return i->reset(dev, probe);
	}

	return -ENOTTY;
}

static int __pci_af_flr(struct pci_dev *dev, int probe)
{
	int cappos = pci_find_capability(dev, PCI_CAP_ID_AF);
	u8 status;
	u8 cap;

	if (!cappos)
		return -ENOTTY;
	pci_read_config_byte(dev, cappos + PCI_AF_CAP, &cap);
	if (!(cap & PCI_AF_CAP_TP) || !(cap & PCI_AF_CAP_FLR))
		return -ENOTTY;

	if (probe)
		return 0;

	pci_block_user_cfg_access(dev);

	/* Wait for Transaction Pending bit clean */
	msleep(100);
	pci_read_config_byte(dev, cappos + PCI_AF_STATUS, &status);
	if (status & PCI_AF_STATUS_TP) {
		dev_info(&dev->dev, "Busy after 100ms while trying to"
				" reset; sleeping for 1 second\n");
		ssleep(1);
		pci_read_config_byte(dev,
				cappos + PCI_AF_STATUS, &status);
		if (status & PCI_AF_STATUS_TP)
			dev_info(&dev->dev, "Still busy after 1s; "
					"proceeding with reset anyway\n");
	}
	pci_write_config_byte(dev, cappos + PCI_AF_CTRL, PCI_AF_CTRL_FLR);
	mdelay(100);

	pci_unblock_user_cfg_access(dev);
	return 0;
}

static int __pci_reset_function(struct pci_dev *pdev, int probe)
{
	int res;

	res = __pci_dev_specific_reset(pdev, probe);
	if (res != -ENOTTY)
		return res;

	res = __pcie_flr(pdev, probe);
	if (res != -ENOTTY)
		return res;

	res = __pci_af_flr(pdev, probe);
	if (res != -ENOTTY)
		return res;

	return res;
}

/**
 * pci_execute_reset_function() - Reset a PCI device function
 * @dev: Device function to reset
 *
 * Some devices allow an individual function to be reset without affecting
 * other functions in the same device.  The PCI device must be responsive
 * to PCI config space in order to use this function.
 *
 * The device function is presumed to be unused when this function is called.
 * Resetting the device will make the contents of PCI configuration space
 * random, so any caller of this must be prepared to reinitialise the
 * device including MSI, bus mastering, BARs, decoding IO and memory spaces,
 * etc.
 *
 * Returns 0 if the device function was successfully reset or -ENOTTY if the
 * device doesn't support resetting a single function.
 */
int pci_execute_reset_function(struct pci_dev *dev)
{
	return __pci_reset_function(dev, 0);
}
EXPORT_SYMBOL_GPL(pci_execute_reset_function);

/**
 * pci_reset_function() - quiesce and reset a PCI device function
 * @dev: Device function to reset
 *
 * Some devices allow an individual function to be reset without affecting
 * other functions in the same device.  The PCI device must be responsive
 * to PCI config space in order to use this function.
 *
 * This function does not just reset the PCI portion of a device, but
 * clears all the state associated with the device.  This function differs
 * from pci_execute_reset_function in that it saves and restores device state
 * over the reset.
 *
 * Returns 0 if the device function was successfully reset or -ENOTTY if the
 * device doesn't support resetting a single function.
 */
int pci_reset_function(struct pci_dev *dev)
{
	int r = __pci_reset_function(dev, 1);

	if (r < 0)
		return r;

	if (!dev->msi_enabled && !dev->msix_enabled && dev->irq != 0)
		disable_irq(dev->irq);
	pci_save_state(dev);

	pci_write_config_word(dev, PCI_COMMAND, PCI_COMMAND_INTX_DISABLE);

	r = pci_execute_reset_function(dev);

	pci_restore_state(dev);
	if (!dev->msi_enabled && !dev->msix_enabled && dev->irq != 0)
		enable_irq(dev->irq);

	return r;
}
EXPORT_SYMBOL_GPL(pci_reset_function);

/**
 * pcix_get_max_mmrbc - get PCI-X maximum designed memory read byte count
 * @dev: PCI device to query
 *
 * Returns mmrbc: maximum designed memory read count in bytes
 *    or appropriate error value.
 */
int
pcix_get_max_mmrbc(struct pci_dev *dev)
{
	int ret, err, cap;
	u32 stat;
	
	cap = pci_find_capability(dev, PCI_CAP_ID_PCIX);
	if (!cap)
		return -EINVAL;

	err = pci_read_config_dword(dev, cap + PCI_X_STATUS, &stat);
	if (err)
		return -EINVAL;

	ret = (stat & PCI_X_STATUS_MAX_READ) >> 12;

	return ret;
}
EXPORT_SYMBOL(pcix_get_max_mmrbc);

/**
 * pcix_get_mmrbc - get PCI-X maximum memory read byte count
 * @dev: PCI device to query
 *
 * Returns mmrbc: maximum memory read count in bytes
 *    or appropriate error value.
 */
int
pcix_get_mmrbc(struct pci_dev *dev)
{
	int ret, cap;
	u32 cmd;
	
	cap = pci_find_capability(dev, PCI_CAP_ID_PCIX);
	if (!cap)
		return -EINVAL;
	
	ret = pci_read_config_dword(dev, cap + PCI_X_CMD, &cmd);
	if (!ret)
		ret = 512 << ((cmd & PCI_X_CMD_MAX_READ) >> 2);
	
	return ret;
}
EXPORT_SYMBOL(pcix_get_mmrbc);

/**
 * pcix_set_mmrbc - set PCI-X maximum memory read byte count
 * @dev: PCI device to query
 * @mmrbc: maximum memory read count in bytes
 *    valid values are 512, 1024, 2048, 4096
 *
 * If possible sets maximum memory read byte count, some bridges have erratas
 * that prevent this.
 */
int
pcix_set_mmrbc(struct pci_dev *dev, int mmrbc)
{
	int cap, err = -EINVAL;
	u32 stat, cmd, v, o;
		
	if (mmrbc < 512 || mmrbc > 4096 || (mmrbc & (mmrbc-1)))
		goto out;
	
	v = ffs(mmrbc) - 10;
	
	cap = pci_find_capability(dev, PCI_CAP_ID_PCIX);
	if (!cap)
		goto out;
	
	err = pci_read_config_dword(dev, cap + PCI_X_STATUS, &stat);
	if (err)
		goto out;
	
	if (v > (stat & PCI_X_STATUS_MAX_READ) >> 21)
		return -E2BIG;
	
	err = pci_read_config_dword(dev, cap + PCI_X_CMD, &cmd);
	if (err)
		goto out;
	
	o = (cmd & PCI_X_CMD_MAX_READ) >> 2;
	if (o != v) {
		if (v > o && dev->bus && 
		   (dev->bus->bus_flags & PCI_BUS_FLAGS_NO_MMRBC))
			return -EIO;
		
		cmd &= ~PCI_X_CMD_MAX_READ;
		cmd |= v << 2;
		err = pci_write_config_dword(dev, cap + PCI_X_CMD, cmd);
	}
out:
	return err;
}
EXPORT_SYMBOL(pcix_set_mmrbc);

/**
 * pcie_get_readrq - get PCI Express read request size
 * @dev: PCI device to query
 *
 * Returns maximum memory read request in bytes
 *    or appropriate error value.
 */
int pcie_get_readrq(struct pci_dev *dev)
{
	int ret, cap;
	u16 ctl;

	cap = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (!cap)
		return -EINVAL;

	ret = pci_read_config_word(dev, cap + PCI_EXP_DEVCTL, &ctl);
	if (!ret)
	ret = 128 << ((ctl & PCI_EXP_DEVCTL_READRQ) >> 12);

	return ret;
}
EXPORT_SYMBOL(pcie_get_readrq);

/**
 * pcie_set_readrq - set PCI Express maximum memory read request
 * @dev: PCI device to query
 * @count: maximum memory read count in bytes
 *    valid values are 128, 256, 512, 1024, 2048, 4096
 *
 * If possible sets maximum read byte count
 */
int
pcie_set_readrq(struct pci_dev *dev, int rq)
{
	int cap, err = -EINVAL;
	u16 ctl, v;
	
	if (rq < 128 || rq > 4096 || (rq & (rq-1)))
		goto out;
	
	v = (ffs(rq) - 8) << 12;
	
	cap = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (!cap)
		goto out;

	err = pci_read_config_word(dev, cap + PCI_EXP_DEVCTL, &ctl);
	if (err)
		goto out;
	
	if ((ctl & PCI_EXP_DEVCTL_READRQ) != v) {
		ctl &= ~PCI_EXP_DEVCTL_READRQ;
		ctl |= v;
		err = pci_write_config_dword(dev, cap + PCI_EXP_DEVCTL, ctl);
	}
	
out:
	return err;
}
EXPORT_SYMBOL(pcie_set_readrq);

/**
 * pci_select_bars - Make BAR mask from the type of resource
 * @pdev: the PCI device for which BAR mask is made
 * @flags: resource type mask to be selected
 *
 * This helper routine makes bar mask from the type of resource.
 */
int pci_select_bars(struct pci_dev *dev, unsigned long flags)
{
	int i, bars = 0;
	for (i = 0; i < PCI_NUM_RESOURCES; i++)
		if (pci_resource_flags(dev, i) & flags)
			bars |= (1 << i);
	return bars;
}

/**
 * pci_resource_bar - get position of the BAR associated with a resource
 * @dev: the PCI device
 * @resno: the resource number
 * @type: the BAR type to be filled in
 *
 * Returns BAR position in config space, or 0 if the BAR is invalid.
 */
int pci_resource_bar(struct pci_dev *dev, int resno, enum pci_bar_type *type)
{
	int reg;

	if (resno < PCI_ROM_RESOURCE) {
		*type = pci_bar_unknown;
		return PCI_BASE_ADDRESS_0 + 4 * resno;
	} else if (resno == PCI_ROM_RESOURCE) {
		*type = pci_bar_mem32;
		return dev->rom_base_reg;
	} else if (resno > PCI_NUM_RESOURCES) {
		/* device specific resource */
		reg = pci_iov_resource_bar(dev, resno, type);
		if (reg)
			return reg;
	}

	dev_err(&dev->dev, "BAR: invalid resource #%d\n", resno);
	return 0;
}

/**
 * pci_ext_cfg_enabled - can we access extended PCI config space?
 * @dev: The PCI device of the root bridge.
 *
 * Returns 1 if we can access PCI extended config space (offsets
 * greater than 0xff). This is the default implementation. Architecture
 * implementations can override this.
 */
int __attribute__ ((weak)) pci_ext_cfg_avail(struct pci_dev *dev)
{
	return 1;
}

static int __devinit pci_init(void)
{
	struct pci_dev *dev = NULL;

	while ((dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, dev)) != NULL) {
		pci_fixup_device(pci_fixup_final, dev);
	}
	return 0;
}

static int __devinit pci_setup(char *str)
{
	while (str) {
		char *k = strchr(str, ',');
		if (k)
			*k++ = 0;
		if (*str && (str = pcibios_setup(str)) && *str) {
			if (!strcmp(str, "nomsi")) {
				pci_no_msi();
			} else if (!strcmp(str, "aer")) {
				pci_aer_enable();
			} else {
				printk(KERN_ERR "PCI: Unknown option `%s'\n",
						str);
			}
		}
		str = k;
	}
	return 1;
}

device_initcall(pci_init);

__setup("pci=", pci_setup);

#if defined(CONFIG_ISA) || defined(CONFIG_EISA)
/* FIXME: Some boxes have multiple ISA bridges! */
struct pci_dev *isa_bridge;
EXPORT_SYMBOL(isa_bridge);
#endif

EXPORT_SYMBOL_GPL(pci_restore_bars);
EXPORT_SYMBOL(pci_enable_device_bars);
EXPORT_SYMBOL(pci_enable_device_io);
EXPORT_SYMBOL(pci_enable_device_mem);
EXPORT_SYMBOL(pci_enable_device);
EXPORT_SYMBOL(pcim_enable_device);
EXPORT_SYMBOL(pcim_pin_device);
EXPORT_SYMBOL(pci_disable_device);
EXPORT_SYMBOL(pci_find_capability);
EXPORT_SYMBOL(pci_bus_find_capability);
EXPORT_SYMBOL(pci_release_regions);
EXPORT_SYMBOL(pci_request_regions);
EXPORT_SYMBOL(pci_release_region);
EXPORT_SYMBOL(pci_request_region);
EXPORT_SYMBOL(pci_release_selected_regions);
EXPORT_SYMBOL(pci_request_selected_regions);
EXPORT_SYMBOL(pci_set_master);
EXPORT_SYMBOL(pci_clear_master);
EXPORT_SYMBOL(pci_set_mwi);
EXPORT_SYMBOL(pci_try_set_mwi);
EXPORT_SYMBOL(pci_clear_mwi);
EXPORT_SYMBOL_GPL(pci_intx);
EXPORT_SYMBOL(pci_set_dma_mask);
EXPORT_SYMBOL(pci_set_consistent_dma_mask);
EXPORT_SYMBOL(pci_assign_resource);
EXPORT_SYMBOL(pci_find_parent_resource);
EXPORT_SYMBOL(pci_select_bars);

EXPORT_SYMBOL(pci_set_power_state);
EXPORT_SYMBOL(pci_save_state);
EXPORT_SYMBOL(pci_restore_state);
EXPORT_SYMBOL(pci_enable_wake);
EXPORT_SYMBOL_GPL(pci_set_pcie_reset_state);

/* Quirk info */

EXPORT_SYMBOL(isa_dma_bridge_buggy);
EXPORT_SYMBOL(pci_pci_problems);
