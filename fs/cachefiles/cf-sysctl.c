/* cf-sysctl.c: Control parameters
 *
 * Copyright (C) 2006 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include "internal.h"

static struct ctl_table_header *cachefiles_sysctl;

/*
 * Something that isn't CTL_ANY, CTL_NONE or a value that may clash.
 * Use the same values as fs/nfs/sysctl.c
 */
#define CTL_UNNUMBERED -2

static ctl_table cachefiles_sysctl_table[] = {
        {
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "debug",
		.data		= &cachefiles_debug,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= &proc_doulongvec_minmax
	},
	{ .ctl_name = 0 }
};

static ctl_table cachefiles_sysctl_dir[] = {
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "cachefiles",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= cachefiles_sysctl_table
	},
	{ .ctl_name = 0 }
};

static ctl_table cachefiles_sysctl_root[] = {
	{
		.ctl_name = CTL_FS,
		.procname = "fs",
		.mode = 0555,
		.child = cachefiles_sysctl_dir,
	},
	{ .ctl_name = 0 }
};

int __init cachefiles_sysctl_init(void)
{
	cachefiles_sysctl = register_sysctl_table(cachefiles_sysctl_root, 0);
	if (!cachefiles_sysctl)
		return -ENOMEM;
	return 0;
}

void __exit cachefiles_sysctl_cleanup(void)
{
	unregister_sysctl_table(cachefiles_sysctl);
}
