/*
 * This file contains work-arounds for x86 and x86_64 platform bugs.
 */
#include <linux/pci.h>
#include <linux/irq.h>

#if defined(CONFIG_X86_IO_APIC) && defined(CONFIG_SMP) && defined(CONFIG_PCI)

static void __devinit quirk_intel_irqbalance(struct pci_dev *dev)
{
	u8 config, rev;
	u32 word;

	/* BIOS may enable hardware IRQ balancing for
	 * E7520/E7320/E7525(revision ID 0x9 and below)
	 * based platforms.
	 * Disable SW irqbalance/affinity on those platforms.
	 */
	pci_read_config_byte(dev, PCI_CLASS_REVISION, &rev);
	if (rev > 0x9)
		return;

	printk(KERN_INFO "Intel E7520/7320/7525 detected.");

	/* enable access to config space*/
	pci_read_config_byte(dev, 0xf4, &config);
	pci_write_config_byte(dev, 0xf4, config|0x2);

	/* read xTPR register */
	raw_pci_ops->read(0, 0, 0x40, 0x4c, 2, &word);

	if (!(word & (1 << 13))) {
		printk(KERN_INFO "Disabling irq balancing and affinity\n");
#ifdef CONFIG_IRQBALANCE
		irqbalance_disable("");
#endif
		noirqdebug_setup("");
#ifdef CONFIG_PROC_FS
		no_irq_affinity = 1;
#endif
	}

	/* put back the original value for config space*/
	if (!(config & 0x2))
		pci_write_config_byte(dev, 0xf4, config);
}

static void __devinit fix_hypertransport_config(struct pci_dev *dev)
{
	u32 htcfg;
	/*
	 * we found a hypertransport bus
	 * make sure that we are broadcasting
	 * interrupts to all cpus on the ht bus
	 * if we're using extended apic ids
	 */
	pci_read_config_dword(dev, 0x68, &htcfg);
	if (htcfg & (1 << 18)) {
		printk(KERN_INFO "Detected use of extended apic ids on hypertransport bus\n");
		if ((htcfg & (1 << 17)) == 0) {
			printk(KERN_INFO "Enabling hypertransport extended apic interrupt broadcast\n");
			printk(KERN_INFO "Note this is a bios bug, please contact your vendor\n");
			htcfg |= (1 << 17);
			pci_write_config_dword(dev, 0x68, htcfg);
		}
	}
}

struct pci_dev *mcp55_rewrite = NULL;

static void __devinit check_mcp55_legacy_irq_routing(struct pci_dev *dev)
{
	u32 cfg;
	printk(KERN_CRIT "FOUND MCP55 CHIP\n");
	/*
	 *Some MCP55 chips have a legacy irq routing config register, and most BIOS
	 *engineers have set it so that legacy interrupts are only routed to the BSP.
	 *While this makes sense in most cases, it doesn't work for kexec, since we might 
	 *wind up booting on a processor other than the BSP.  The right fix for this is 
	 *to move to symmetric io mode, and enable the ioapics very early in the boot process.
	 *That seems like far to invasive a fix in RHEL5, so here, we're just going to check
	 *for the appropriate configuration, and tell kexec to rewrite the config register 
	 *if we find that we need to broadcast legacy interrupts
	 */
	pci_read_config_dword(dev, 0x74, &cfg);
	printk(KERN_CRIT "cfg value is %x\n",cfg);	
	/*
	 * We expect legacy interrupts to be routed to INTIN0 on the lapics of all processors
	 * (not just the BSP).  To ensure this, bit 2 must be clear, and bit 15 must be clear
	 * if either of these conditions is not met, we have fixups we need to preform
	 */
	if (cfg & ((1 << 2) | (1 << 15))) {
		/*
		 * Either bit 2 or 15 wasn't clear, so we need to rewrite this cfg register 
		 * when starting kexec
		 */
		printk(KERN_CRIT "DETECTED RESTRICTED ROUTING ON MCP55!  FLAGGING\n");
		mcp55_rewrite = dev;
	}
}

DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_E7320_MCH,	quirk_intel_irqbalance);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_E7525_MCH,	quirk_intel_irqbalance);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_E7520_MCH,	quirk_intel_irqbalance);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_AMD,	PCI_DEVICE_ID_AMD_K8_NB, fix_hypertransport_config);
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_NVIDIA,	0x0360			, check_mcp55_legacy_irq_routing);
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_NVIDIA,	0x0364			, check_mcp55_legacy_irq_routing);
#endif
