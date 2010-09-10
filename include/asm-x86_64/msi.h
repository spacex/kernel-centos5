/*
 * Copyright (C) 2003-2004 Intel
 * Copyright (C) Tom Long Nguyen (tom.l.nguyen@intel.com)
 */

#ifndef ASM_MSI_H
#define ASM_MSI_H

#include <asm/desc.h>
#ifndef CONFIG_XEN
#include <asm/mach_apic.h>
#endif
#include <asm/smp.h>

#ifndef CONFIG_XEN
#define LAST_DEVICE_VECTOR	(FIRST_SYSTEM_VECTOR - 1)
#else
#define LAST_DYNAMIC_VECTOR 0xdf
#define LAST_DEVICE_VECTOR	(LAST_DYNAMIC_VECTOR)
#endif

#define MSI_TARGET_CPU_SHIFT	12

extern struct msi_ops msi_apic_ops;

static inline int msi_arch_init(void)
{
	msi_register(&msi_apic_ops);
	return 0;
}

#endif /* ASM_MSI_H */
