/* cf-main.c: network filesystem caching backend to use cache files on a
 *            premounted filesystem
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
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/statfs.h>
#include <linux/proc_fs.h>
#include <linux/sysctl.h>
#include "internal.h"

unsigned long cachefiles_debug;

static int cachefiles_init(void);
static void cachefiles_exit(void);

fs_initcall(cachefiles_init);
module_exit(cachefiles_exit);

MODULE_DESCRIPTION("Mounted-filesystem based cache");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

kmem_cache_t *cachefiles_object_jar;

static void cachefiles_object_init_once(void *_object, kmem_cache_t *cachep,
					unsigned long flags)
{
	struct cachefiles_object *object = _object;

	switch (flags & (SLAB_CTOR_VERIFY | SLAB_CTOR_CONSTRUCTOR)) {
	case SLAB_CTOR_CONSTRUCTOR:
		memset(object, 0, sizeof(*object));
		fscache_object_init(&object->fscache);
		init_rwsem(&object->sem);
		spin_lock_init(&object->work_lock);
		INIT_LIST_HEAD(&object->read_list);
		INIT_LIST_HEAD(&object->read_pend_list);
		INIT_WORK(&object->read_work, &cachefiles_read_copier_work,
			  object);
		INIT_LIST_HEAD(&object->write_list);
		INIT_WORK(&object->write_work, &cachefiles_write_work, object);
		break;

	default:
		break;
	}
}

/*****************************************************************************/
/*
 * initialise the fs caching module
 */
static int __init cachefiles_init(void)
{
	struct proc_dir_entry *pde;
	int ret;

	/* create a proc entry to use as a handle for the userspace daemon */
	ret = -ENOMEM;

	pde = create_proc_entry("cachefiles", 0600, proc_root_fs);
	if (!pde) {
		kerror("Unable to create /proc/fs/cachefiles");
		goto error_proc;
	}

	if (cachefiles_sysctl_init() < 0) {
		kerror("Unable to create sysctl parameters");
		goto error_object_jar;
	}

	pde->owner = THIS_MODULE;
	pde->proc_fops = &cachefiles_proc_fops;
	cachefiles_proc = pde;

	/* create an object jar */
	cachefiles_object_jar =
		kmem_cache_create("cachefiles_object_jar",
				  sizeof(struct cachefiles_object),
				  0,
				  SLAB_HWCACHE_ALIGN,
				  cachefiles_object_init_once,
				  NULL);
	if (!cachefiles_object_jar) {
		printk(KERN_NOTICE
		       "CacheFiles: Failed to allocate an object jar\n");
		goto error_sysctl;
	}

	printk(KERN_INFO "CacheFiles: Loaded\n");
	return 0;

error_sysctl:
	cachefiles_sysctl_cleanup();
error_object_jar:
	remove_proc_entry("cachefiles", proc_root_fs);
error_proc:
	kerror("failed to register: %d", ret);
	return ret;
}

/*****************************************************************************/
/*
 * clean up on module removal
 */
static void __exit cachefiles_exit(void)
{
	printk(KERN_INFO "CacheFiles: Unloading\n");

	kmem_cache_destroy(cachefiles_object_jar);
	remove_proc_entry("cachefiles", proc_root_fs);
	cachefiles_sysctl_cleanup();
}
