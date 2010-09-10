/* main.c: general filesystem caching manager
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include "fscache-int.h"

int fscache_debug;

static int fscache_init(void);
static void fscache_exit(void);

fs_initcall(fscache_init);
module_exit(fscache_exit);

MODULE_DESCRIPTION("FS Cache Manager");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

static void fscache_ktype_release(struct kobject *kobject);

static struct sysfs_ops fscache_sysfs_ops = {
	.show		= NULL,
	.store		= NULL,
};

static struct kobj_type fscache_ktype = {
	.release	= fscache_ktype_release,
	.sysfs_ops	= &fscache_sysfs_ops,
	.default_attrs	= NULL,
};

struct kset fscache_kset = {
	.kobj.name	= "fscache",
	.kobj.kset	= &fs_subsys.kset,
	.ktype		= &fscache_ktype,
};

EXPORT_SYMBOL(fscache_kset);

/*****************************************************************************/
/*
 * initialise the fs caching module
 */
static int __init fscache_init(void)
{
	int ret;

	fscache_cookie_jar =
		kmem_cache_create("fscache_cookie_jar",
				  sizeof(struct fscache_cookie),
				  0,
				  0,
				  fscache_cookie_init_once,
				  NULL);

	if (!fscache_cookie_jar) {
		printk(KERN_NOTICE
		       "FS-Cache: Failed to allocate a cookie jar\n");
		return -ENOMEM;
	}

	ret = kset_register(&fscache_kset);
	if (ret < 0) {
		kmem_cache_destroy(fscache_cookie_jar);
		return ret;
	}

	printk(KERN_NOTICE "FS-Cache: Loaded\n");
	return 0;

}

/*****************************************************************************/
/*
 * clean up on module removal
 */
static void __exit fscache_exit(void)
{
	_enter("");

	kset_unregister(&fscache_kset);
	kmem_cache_destroy(fscache_cookie_jar);
	printk(KERN_NOTICE "FS-Cache: unloaded\n");

}

/*****************************************************************************/
/*
 * release the ktype
 */
static void fscache_ktype_release(struct kobject *kobject)
{
}
