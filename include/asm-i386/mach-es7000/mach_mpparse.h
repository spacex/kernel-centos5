#ifndef __ASM_MACH_MPPARSE_H
#define __ASM_MACH_MPPARSE_H

#include <linux/acpi.h>

static inline void mpc_oem_bus_info(struct mpc_config_bus *m, char *name, 
				struct mpc_config_translation *translation)
{
	Dprintk("Bus #%d is %s\n", m->mpc_busid, name);
}

static inline void mpc_oem_pci_bus(struct mpc_config_bus *m, 
				struct mpc_config_translation *translation)
{
}

extern int parse_unisys_oem (char *oemptr);
extern int find_unisys_acpi_oem_table(unsigned long *oem_addr);
extern void setup_unisys(void);

#ifdef CONFIG_ACPI
static inline int es7000_check_dsdt(void)
{
	struct acpi_table_header *header = NULL;
	if(!acpi_get_table_header_early(ACPI_DSDT, &header))
		acpi_table_print(header, 0);
	if (!strncmp(header->oem_id, "UNISYS", 6))
		return 1;
	return 0;
}
#endif

#endif /* __ASM_MACH_MPPARSE_H */
