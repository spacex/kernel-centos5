/*
 *  linux/drivers/net/netconsole.c
 *
 *  Copyright (C) 2001  Ingo Molnar <mingo@redhat.com>
 *
 *  This file contains the implementation of an IRQ-safe, crash-safe
 *  kernel console implementation that outputs kernel messages to the
 *  network.
 *
 * Modification history:
 *
 * 2001-09-17    started by Ingo Molnar.
 * 2003-08-11    2.6 port by Matt Mackall
 *               simplified options
 *               generic card hooks
 *               works non-modular
 * 2003-09-07    rewritten with netpoll api
 */

/****************************************************************
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2, or (at your option)
 *      any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ****************************************************************/

#include <linux/mm.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/console.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/netpoll.h>

MODULE_AUTHOR("Maintainer: Matt Mackall <mpm@selenic.com>");
MODULE_DESCRIPTION("Console driver for network interfaces");
MODULE_LICENSE("GPL");

#define MAX_PARAM_LENGTH	256
#define MAX_PRINT_CHUNK		1000

static char config[MAX_PARAM_LENGTH];
module_param_string(netconsole, config, MAX_PARAM_LENGTH, 0);
MODULE_PARM_DESC(netconsole, " netconsole=[src-port]@[src-ip]/[dev],[tgt-port]@<tgt-ip>/[tgt-macaddr]\n");

#ifndef	MODULE
static int __init option_setup(char *opt)
{
	strlcpy(config, opt, MAX_PARAM_LENGTH);
	return 1;
}
__setup("netconsole=", option_setup);
#endif	/* MODULE */

static struct netpoll np = {
	.name		= "netconsole",
	.dev_name	= "eth0",
	.local_port	= 6665,
	.remote_port	= 6666,
	.remote_mac	= {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	.drop		= netpoll_queue,
};

/* Handle network interface device notifications */
static int netconsole_netdev_event(struct notifier_block *this,
				   unsigned long event,
				   void *ptr)
{
	struct net_device *dev = ptr;

	if (np.dev == dev) {
		switch (event) {
		case NETDEV_CHANGENAME:
			strlcpy(np.dev_name, dev->name, IFNAMSIZ);
			break;
		case NETDEV_UNREGISTER:
		case NETDEV_RELEASE:
		case NETDEV_JOIN:
			netpoll_cleanup(&np);
			printk(KERN_INFO "netconsole: network logging stopped"
					 ", as interface %s ", dev->name);
			if (event == NETDEV_UNREGISTER)
				printk(KERN_CONT "unregistered\n");
			else if (event == NETDEV_RELEASE)
				printk(KERN_CONT "released slaves\n");
			else if (event == NETDEV_JOIN)
				printk(KERN_CONT "joined a master device\n");
			break;
		}
	}

	return NOTIFY_DONE;
}

static struct notifier_block netconsole_netdev_notifier = {
	.notifier_call  = netconsole_netdev_event,
};

static void write_msg(struct console *con, const char *msg, unsigned int len)
{
	int frag, left;
	unsigned long flags;

	if (np.dev && netif_running(np.dev)) {
		local_irq_save(flags);
		for (left = len; left;) {
			frag = min(left, MAX_PRINT_CHUNK);
			netpoll_send_udp(&np, msg, frag);
			msg += frag;
			left -= frag;
		}
		local_irq_restore(flags);
	}
}

static struct console netconsole = {
	.name	= "netcon",
	.flags	= CON_ENABLED | CON_PRINTBUFFER,
	.write	= write_msg,
};

static int __init init_netconsole(void)
{
	int err = 0;

	if (!strnlen(config, MAX_PARAM_LENGTH)) {
		printk(KERN_INFO "netconsole: not configured, aborting\n");
		goto out;
	}

	err = netpoll_parse_options(&np, config);
	if (err)
		goto out;

	err = netpoll_setup(&np);
	if (err)
		goto out;

	err = register_netdevice_notifier(&netconsole_netdev_notifier);
	if (err)
		goto out;

	register_console(&netconsole);
	printk(KERN_INFO "netconsole: network logging started\n");

out:
	return err;
}

static void __exit cleanup_netconsole(void)
{
	unregister_console(&netconsole);
	unregister_netdevice_notifier(&netconsole_netdev_notifier);
	netpoll_cleanup(&np);
}

module_init(init_netconsole);
module_exit(cleanup_netconsole);
