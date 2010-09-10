/*
 * Compat wrapper module for the iSCSI interface
 *
 * Copyright (C) 2009 Red Hat, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/module.h>

static unsigned long iscsi_if_loaded;

#define ISCSI_IF_LOADED 1

/**
 * iscsi_if_claim - load iscsi interface.
 *
 * Only iscsi interfaces should call this. Because they all
 * use the same netlink number and export the same sysfs tree
 * only one can be allowed at a time.
 */
int iscsi_if_load(void)
{
	if (test_and_set_bit(ISCSI_IF_LOADED, &iscsi_if_loaded)) {
		printk(KERN_ERR "iSCSI transport class interface already "
		       "loaded.\n");
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(iscsi_if_load);

void iscsi_if_release(void)
{
	clear_bit(ISCSI_IF_LOADED, &iscsi_if_loaded);
}
EXPORT_SYMBOL_GPL(iscsi_if_release);

MODULE_DESCRIPTION("Compat wrapper for iSCSI Transport Interface");
MODULE_LICENSE("GPL");
/*
 * The purpose of this module is to only allow one interface to be used
 * at a time and to make sure that the module version is displayed in a
 * common place. The -871 part is ignored by usersapce tools. They are
 * concerned about the major and minor which indicates the
 * interface versioning. For RHEL tihs will always be 2.0.
 */
MODULE_VERSION("2.0-871");
