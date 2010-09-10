/*
 * Copyright (C) 2005 - 2010 ServerEngines
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.  The full GNU General
 * Public License is included in this distribution in the file called COPYING.
 *
 * Contact Information:
 * linux-drivers@serverengines.com
 *
 * ServerEngines
 * 209 N. Fair Oaks Ave
 * Sunnyvale, CA 94085
 */

#ifndef BE_COMPAT_H
#define BE_COMPAT_H

#define PTR_ALIGN(p, a)         	((typeof(p))			\
					ALIGN((unsigned long)(p), (a)))

#define DEFINE_PCI_DEVICE_TABLE(_table) struct pci_device_id _table[] 	\
						__devinitdata

/* Backport of request_irq */
typedef irqreturn_t(*backport_irq_handler_t) (int, void *);
static inline int
backport_request_irq(unsigned int irq, irqreturn_t(*handler) (int, void *),
		unsigned long flags, const char *dev_name, void *dev_id)
{
	return request_irq(irq,
			(irqreturn_t(*) (int, void *, struct pt_regs *))handler,
			flags, dev_name, dev_id);
}
#define request_irq 			backport_request_irq

#endif				/* BE_COMPAT_H */

