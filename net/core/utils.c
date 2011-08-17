/*
 *	Generic address resultion entity
 *
 *	Authors:
 *	net_random Alan Cox
 *	net_ratelimit Andy Kleen
 *
 *	Created by Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/percpu.h>
#include <linux/init.h>

#include <asm/byteorder.h>
#include <asm/system.h>
#include <asm/uaccess.h>

/*
 * RHEL5's net_{s}random are on the kabi whitelist, so while we've backported
 * the move of net_random to lib/random32.c and random32(), we can't use the
 * same #define net_random random32 upstream does, if we want to preserve kabi
 * in a way that our kabi tools can deal with. This works though.
 */
unsigned long net_random(void)
{
	unsigned long r;

	r = (unsigned long)random32();

	return r;
}
EXPORT_SYMBOL(net_random);

void net_srandom(unsigned long entropy)
{
	srandom32((__force u32)entropy);
}
EXPORT_SYMBOL(net_srandom);


int net_msg_cost = 5*HZ;
int net_msg_burst = 10;

/* 
 * All net warning printk()s should be guarded by this function.
 */ 
int net_ratelimit(void)
{
	return __printk_ratelimit(net_msg_cost, net_msg_burst);
}

EXPORT_SYMBOL(net_ratelimit);

/*
 * Convert an ASCII string to binary IP.
 * This is outside of net/ipv4/ because various code that uses IP addresses
 * is otherwise not dependent on the TCP/IP stack.
 */

__be32 in_aton(const char *str)
{
	unsigned long l;
	unsigned int val;
	int i;

	l = 0;
	for (i = 0; i < 4; i++)
	{
		l <<= 8;
		if (*str != '\0')
		{
			val = 0;
			while (*str != '\0' && *str != '.' && *str != '\n')
			{
				val *= 10;
				val += *str - '0';
				str++;
			}
			l |= val;
			if (*str != '\0')
				str++;
		}
	}
	return(htonl(l));
}

EXPORT_SYMBOL(in_aton);
