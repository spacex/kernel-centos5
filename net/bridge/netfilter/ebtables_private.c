/*
 *  ebtables
 *
 *  Author:
 *  Bart De Schuymer		<bdschuym@pandora.be>
 *
 *  ebtables.c,v 2.0, July, 2002
 *
 *  This code is stongly inspired on the iptables code which is
 *  Copyright (C) 1999 Paul `Rusty' Russell & Michael J. Neuling
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */

/* used for print_string */
#include <linux/sched.h>
#include <linux/tty.h>

#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <net/sock.h>
/* needed for logical [in,out]-dev filtering */
#include "../br_private.h"

/* list_named_find */
#define ASSERT_READ_LOCK(x)
#define ASSERT_WRITE_LOCK(x)
#include <linux/netfilter_ipv4/listhelp.h>
#include <linux/mutex.h>

static inline int ebt_dev_check(char *entry, const struct net_device *device)
{
	int i = 0;
	char *devname = device->name;

	if (*entry == '\0')
		return 0;
	if (!device)
		return 1;
	/* 1 is the wildcard token */
	while (entry[i] != '\0' && entry[i] != 1 && entry[i] == devname[i])
		i++;
	return (devname[i] != entry[i] && entry[i] != 1);
}

#define FWINV2(bool,invflg) ((bool) ^ !!(e->invflags & invflg))
/* process standard matches */
int ebt_basic_match(struct ebt_entry *e, struct ethhdr *h,
		    const struct net_device *in, const struct net_device *out)
{
	int verdict, i;

	if (e->bitmask & EBT_802_3) {
		if (FWINV2(ntohs(h->h_proto) >= 1536, EBT_IPROTO))
			return 1;
	} else if (!(e->bitmask & EBT_NOPROTO) &&
	   FWINV2(e->ethproto != h->h_proto, EBT_IPROTO))
		return 1;

	if (FWINV2(ebt_dev_check(e->in, in), EBT_IIN))
		return 1;
	if (FWINV2(ebt_dev_check(e->out, out), EBT_IOUT))
		return 1;
	if ((!in || !in->br_port) ? 0 : FWINV2(ebt_dev_check(
	   e->logical_in, in->br_port->br->dev), EBT_ILOGICALIN))
		return 1;
	if ((!out || !out->br_port) ? 0 : FWINV2(ebt_dev_check(
	   e->logical_out, out->br_port->br->dev), EBT_ILOGICALOUT))
		return 1;

	if (e->bitmask & EBT_SOURCEMAC) {
		verdict = 0;
		for (i = 0; i < 6; i++)
			verdict |= (h->h_source[i] ^ e->sourcemac[i]) &
			   e->sourcemsk[i];
		if (FWINV2(verdict != 0, EBT_ISOURCE) )
			return 1;
	}
	if (e->bitmask & EBT_DESTMAC) {
		verdict = 0;
		for (i = 0; i < 6; i++)
			verdict |= (h->h_dest[i] ^ e->destmac[i]) &
			   e->destmsk[i];
		if (FWINV2(verdict != 0, EBT_IDEST) )
			return 1;
	}
	return 0;
}
