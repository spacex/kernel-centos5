/*
 * linux/drivers/clocksource/acpi_pm.c
 *
 * This file contains the ACPI PM based clocksource.
 *
 * This code was largely moved from the i386 timer_pm.c file
 * which was (C) Dominik Brodowski <linux@brodo.de> 2003
 * and contained the following comments:
 *
 * Driver to use the Power Management Timer (PMTMR) available in some
 * southbridges as primary timing source for the Linux kernel.
 *
 * Based on parts of linux/drivers/acpi/hardware/hwtimer.c, timer_pit.c,
 * timer_hpet.c, and on Arjan van de Ven's implementation for 2.4.
 *
 * This file is licensed under the GPL v2.
 */

#include <linux/clocksource.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <asm/io.h>

/* Number of PMTMR ticks expected during calibration run */
#define PMTMR_TICKS_PER_SEC 3579545

/*
 * The I/O port the PMTMR resides at.
 * The location is detected during setup_arch(),
 * in arch/i386/acpi/boot.c
 */
u32 pmtmr_ioport __read_mostly;

#define ACPI_PM_MASK CLOCKSOURCE_MASK(24) /* limit it to 24 bits */

static inline u32 read_pmtmr(void)
{
	/* mask the output to 24 bits */
	return inl(pmtmr_ioport) & ACPI_PM_MASK;
}

cycle_t acpi_pm_read_verified(void)
{
	u32 v1 = 0, v2 = 0, v3 = 0;

	/*
	 * It has been reported that because of various broken
	 * chipsets (ICH4, PIIX4 and PIIX4E) where the ACPI PM clock
	 * source is not latched, you must read it multiple
	 * times to ensure a safe value is read:
	 */
	do {
		v1 = read_pmtmr();
		v2 = read_pmtmr();
		v3 = read_pmtmr();
	} while ((v1 > v2 && v1 < v3) || (v2 > v3 && v2 < v1)
			|| (v3 > v1 && v3 < v2));

	return (cycle_t)v2;
}

static cycle_t acpi_pm_read(void)
{
	return (cycle_t)read_pmtmr();
}

static struct clocksource clocksource_acpi_pm = {
	.name		= "acpi_pm",
	.rating		= 200,
	.read		= acpi_pm_read,
	.mask		= (cycle_t)ACPI_PM_MASK,
	.mult		= 0, /*to be caluclated*/
	.shift		= 22,
	.is_continuous	= 1,
};


#ifdef CONFIG_PCI
static int acpi_pm_good;
static int __init acpi_pm_good_setup(char *__str)
{
       acpi_pm_good = 1;
       return 1;
}
__setup("acpi_pm_good", acpi_pm_good_setup);

static inline void acpi_pm_need_workaround(void)
{
	clocksource_acpi_pm.read = acpi_pm_read_verified;
	clocksource_acpi_pm.rating = 110;
}

/*
 * PIIX4 Errata:
 *
 * The power management timer may return improper results when read.
 * Although the timer value settles properly after incrementing,
 * while incrementing there is a 3 ns window every 69.8 ns where the
 * timer value is indeterminate (a 4.2% chance that the data will be
 * incorrect when read). As a result, the ACPI free running count up
 * timer specification is violated due to erroneous reads.
 */
static void __devinit acpi_pm_check_blacklist(struct pci_dev *dev)
{
	u8 rev;

	if (acpi_pm_good)
		return;

	pci_read_config_byte(dev, PCI_REVISION_ID, &rev);
	/* the bug has been fixed in PIIX4M */
	if (rev < 3) {
		printk(KERN_WARNING "* Found PM-Timer Bug on the chipset."
		       " Due to workarounds for a bug,\n"
		       "* this clock source is slow. Consider trying"
		       " other clock sources\n");

		acpi_pm_need_workaround();
	}
}
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82371AB_3,
			acpi_pm_check_blacklist);

static void __devinit acpi_pm_check_graylist(struct pci_dev *dev)
{
	if (acpi_pm_good)
		return;

	printk(KERN_WARNING "* The chipset may have PM-Timer Bug. Due to"
	       " workarounds for a bug,\n"
	       "* this clock source is slow. If you are sure your timer"
	       " does not have\n"
	       "* this bug, please use \"acpi_pm_good\" to disable the"
	       " workaround\n");

	acpi_pm_need_workaround();
}
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801DB_0,
			acpi_pm_check_graylist);
#endif


static int __init init_acpi_pm_clocksource(void)
{
	u32 value1, value2;
	unsigned int i;

	if (!pmtmr_ioport)
		return -ENODEV;

	clocksource_acpi_pm.mult = clocksource_hz2mult(PMTMR_TICKS_PER_SEC,
						clocksource_acpi_pm.shift);

	/* "verify" this timing source: */
	value1 = read_pmtmr();
	for (i = 0; i < 10000; i++) {
		value2 = read_pmtmr();
		if (value2 == value1)
			continue;
		if (value2 > value1)
			goto pm_good;
		if ((value2 < value1) && ((value2) < 0xFFF))
			goto pm_good;
		printk(KERN_INFO "PM-Timer had inconsistent results:"
			" 0x%#x, 0x%#x - aborting.\n", value1, value2);
		return -EINVAL;
	}
	printk(KERN_INFO "PM-Timer had no reasonable result:"
			" 0x%#x - aborting.\n", value1);
	return -ENODEV;

pm_good:
	return clocksource_register(&clocksource_acpi_pm);
}


static int __init disable_pmtmr(char *str)
{
	pmtmr_ioport = 0;
	return 1;
}
__setup("nopmtimer", disable_pmtmr);
module_init(init_acpi_pm_clocksource);
