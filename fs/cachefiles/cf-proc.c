/* cf-proc.c: /proc/fs/cachefiles interface
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
#include <linux/namespace.h>
#include <linux/statfs.h>
#include <linux/proc_fs.h>
#include <linux/ctype.h>
#include "internal.h"

static int cachefiles_proc_open(struct inode *, struct file *);
static int cachefiles_proc_release(struct inode *, struct file *);
static ssize_t cachefiles_proc_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t cachefiles_proc_write(struct file *, const char __user *, size_t, loff_t *);
static int cachefiles_proc_frun(struct cachefiles_cache *cache, char *args);
static int cachefiles_proc_fcull(struct cachefiles_cache *cache, char *args);
static int cachefiles_proc_fstop(struct cachefiles_cache *cache, char *args);
static int cachefiles_proc_brun(struct cachefiles_cache *cache, char *args);
static int cachefiles_proc_bcull(struct cachefiles_cache *cache, char *args);
static int cachefiles_proc_bstop(struct cachefiles_cache *cache, char *args);
static int cachefiles_proc_cull(struct cachefiles_cache *cache, char *args);
static int cachefiles_proc_debug(struct cachefiles_cache *cache, char *args);
static int cachefiles_proc_dir(struct cachefiles_cache *cache, char *args);
static int cachefiles_proc_tag(struct cachefiles_cache *cache, char *args);

struct proc_dir_entry *cachefiles_proc;

static unsigned long cachefiles_open;

struct file_operations cachefiles_proc_fops = {
	.open		= cachefiles_proc_open,
	.release	= cachefiles_proc_release,
	.read		= cachefiles_proc_read,
	.write		= cachefiles_proc_write,
};

struct cachefiles_proc_cmd {
	char name[8];
	int (*handler)(struct cachefiles_cache *cache, char *args);
};

static const struct cachefiles_proc_cmd cachefiles_proc_cmds[] = {
	{ "bind",	cachefiles_proc_bind	},
	{ "brun",	cachefiles_proc_brun	},
	{ "bcull",	cachefiles_proc_bcull	},
	{ "bstop",	cachefiles_proc_bstop	},
	{ "cull",	cachefiles_proc_cull	},
	{ "debug",	cachefiles_proc_debug	},
	{ "dir",	cachefiles_proc_dir	},
	{ "frun",	cachefiles_proc_frun	},
	{ "fcull",	cachefiles_proc_fcull	},
	{ "fstop",	cachefiles_proc_fstop	},
	{ "tag",	cachefiles_proc_tag	},
	{ "",		NULL			}
};


/*****************************************************************************/
/*
 * do various checks
 */
static int cachefiles_proc_open(struct inode *inode, struct file *file)
{
	struct cachefiles_cache *cache;

	_enter("");

	/* only the superuser may do this */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* /proc/fs/cachefiles may only be open once at a time */
	if (xchg(&cachefiles_open, 1) == 1)
		return -EBUSY;

	/* allocate a cache record */
	cache = kzalloc(sizeof(struct cachefiles_cache), GFP_KERNEL);
	if (!cache) {
		cachefiles_open = 0;
		return -ENOMEM;
	}

	cache->active_nodes = RB_ROOT;
	rwlock_init(&cache->active_lock);

	/* set default caching limits
	 * - limit at 1% free space and/or free files
	 * - cull below 5% free space and/or free files
	 * - cease culling above 7% free space and/or free files
	 */
	cache->frun_percent = 7;
	cache->fcull_percent = 5;
	cache->fstop_percent = 1;
	cache->brun_percent = 7;
	cache->bcull_percent = 5;
	cache->bstop_percent = 1;

	file->private_data = cache;
	cache->cachefilesd = file;
	return 0;
}

/*****************************************************************************/
/*
 * release a cache
 */
static int cachefiles_proc_release(struct inode *inode, struct file *file)
{
	struct cachefiles_cache *cache = file->private_data;

	_enter("");

	ASSERT(cache);

	set_bit(CACHEFILES_DEAD, &cache->flags);

	cachefiles_proc_unbind(cache);

	ASSERT(!cache->active_nodes.rb_node);

	/* clean up the control file interface */
	cache->cachefilesd = NULL;
	file->private_data = NULL;
	cachefiles_open = 0;

	kfree(cache);

	_leave("");
	return 0;
}

/*****************************************************************************/
/*
 * read the cache state
 */
static ssize_t cachefiles_proc_read(struct file *file, char __user *_buffer,
				    size_t buflen, loff_t *pos)
{
	struct cachefiles_cache *cache = file->private_data;
	char buffer[256];
	int n;

	_enter(",,%zu,", buflen);

	if (!test_bit(CACHEFILES_READY, &cache->flags))
		return 0;

	/* check how much space the cache has */
	cachefiles_has_space(cache, 0, 0);

	/* summarise */
	n = snprintf(buffer, sizeof(buffer),
		     "cull=%c"
		     " frun=%llx"
		     " fcull=%llx"
		     " fstop=%llx"
		     " brun=%llx"
		     " bcull=%llx"
		     " bstop=%llx",
		     test_bit(CACHEFILES_CULLING, &cache->flags) ? '1' : '0',
		     (unsigned long long) cache->frun,
		     (unsigned long long) cache->fcull,
		     (unsigned long long) cache->fstop,
		     (unsigned long long) cache->brun,
		     (unsigned long long) cache->bcull,
		     (unsigned long long) cache->bstop
		     );

	if (n > buflen)
		return -EMSGSIZE;

	if (copy_to_user(_buffer, buffer, n) != 0)
		return -EFAULT;

	return n;
}

/*****************************************************************************/
/*
 * command the cache
 */
static ssize_t cachefiles_proc_write(struct file *file,
				     const char __user *_data, size_t datalen,
				     loff_t *pos)
{
	const struct cachefiles_proc_cmd *cmd;
	struct cachefiles_cache *cache = file->private_data;
	ssize_t ret;
	char *data, *args, *cp;

	_enter(",,%zu,", datalen);

	ASSERT(cache);

	if (test_bit(CACHEFILES_DEAD, &cache->flags))
		return -EIO;

	if (datalen < 0 || datalen > PAGE_SIZE - 1)
		return -EOPNOTSUPP;

	/* drag the command string into the kernel so we can parse it */
	data = kmalloc(datalen + 1, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = -EFAULT;
	if (copy_from_user(data, _data, datalen) != 0)
		goto error;

	data[datalen] = '\0';

	ret = -EINVAL;
	if (memchr(data, '\0', datalen))
		goto error;

	/* strip any newline */
	cp = memchr(data, '\n', datalen);
	if (cp) {
		if (cp == data)
			goto error;

		*cp = '\0';
	}

	/* parse the command */
	ret = -EOPNOTSUPP;

	for (args = data; *args; args++)
		if (isspace(*args))
			break;
	if (*args) {
		if (args == data)
			goto error;
		*args = '\0';
		for (args++; isspace(*args); args++)
			continue;
	}

	/* run the appropriate command handler */
	for (cmd = cachefiles_proc_cmds; cmd->name[0]; cmd++)
		if (strcmp(cmd->name, data) == 0)
			goto found_command;

error:
	kfree(data);
	_leave(" = %d", ret);
	return ret;

found_command:
	mutex_lock_nested(&file->f_dentry->d_inode->i_mutex, 1);

	ret = -EIO;
	if (!test_bit(CACHEFILES_DEAD, &cache->flags))
		ret = cmd->handler(cache, args);

	mutex_unlock(&file->f_dentry->d_inode->i_mutex);

	if (ret == 0)
		ret = datalen;
	goto error;
}

/*****************************************************************************/
/*
 * give a range error for cache space constraints
 * - can be tail-called
 */
static int cachefiles_proc_range_error(struct cachefiles_cache *cache, char *args)
{
	kerror("Free space limits must be in range"
	       " 0%%<=stop<cull<run<100%%");

	return -EINVAL;
}

/*****************************************************************************/
/*
 * set the percentage of files at which to stop culling
 * - command: "frun <N>%"
 */
static int cachefiles_proc_frun(struct cachefiles_cache *cache, char *args)
{
	unsigned long frun;

	_enter(",%s", args);

	if (!*args)
		return -EINVAL;

	frun = simple_strtoul(args, &args, 10);
	if (args[0] != '%' || args[1] != '\0')
		return -EINVAL;

	if (frun <= cache->fcull_percent || frun >= 100)
		return cachefiles_proc_range_error(cache, args);

	cache->frun_percent = frun;
	return 0;
}

/*****************************************************************************/
/*
 * set the percentage of files at which to start culling
 * - command: "fcull <N>%"
 */
static int cachefiles_proc_fcull(struct cachefiles_cache *cache, char *args)
{
	unsigned long fcull;

	_enter(",%s", args);

	if (!*args)
		return -EINVAL;

	fcull = simple_strtoul(args, &args, 10);
	if (args[0] != '%' || args[1] != '\0')
		return -EINVAL;

	if (fcull <= cache->fstop_percent || fcull >= cache->frun_percent)
		return cachefiles_proc_range_error(cache, args);

	cache->fcull_percent = fcull;
	return 0;
}

/*****************************************************************************/
/*
 * set the percentage of files at which to stop allocating
 * - command: "fstop <N>%"
 */
static int cachefiles_proc_fstop(struct cachefiles_cache *cache, char *args)
{
	unsigned long fstop;

	_enter(",%s", args);

	if (!*args)
		return -EINVAL;

	fstop = simple_strtoul(args, &args, 10);
	if (args[0] != '%' || args[1] != '\0')
		return -EINVAL;

	if (fstop < 0 || fstop >= cache->fcull_percent)
		return cachefiles_proc_range_error(cache, args);

	cache->fstop_percent = fstop;
	return 0;
}

/*****************************************************************************/
/*
 * set the percentage of blocks at which to stop culling
 * - command: "brun <N>%"
 */
static int cachefiles_proc_brun(struct cachefiles_cache *cache, char *args)
{
	unsigned long brun;

	_enter(",%s", args);

	if (!*args)
		return -EINVAL;

	brun = simple_strtoul(args, &args, 10);
	if (args[0] != '%' || args[1] != '\0')
		return -EINVAL;

	if (brun <= cache->bcull_percent || brun >= 100)
		return cachefiles_proc_range_error(cache, args);

	cache->brun_percent = brun;
	return 0;
}

/*****************************************************************************/
/*
 * set the percentage of blocks at which to start culling
 * - command: "bcull <N>%"
 */
static int cachefiles_proc_bcull(struct cachefiles_cache *cache, char *args)
{
	unsigned long bcull;

	_enter(",%s", args);

	if (!*args)
		return -EINVAL;

	bcull = simple_strtoul(args, &args, 10);
	if (args[0] != '%' || args[1] != '\0')
		return -EINVAL;

	if (bcull <= cache->bstop_percent || bcull >= cache->brun_percent)
		return cachefiles_proc_range_error(cache, args);

	cache->bcull_percent = bcull;
	return 0;
}

/*****************************************************************************/
/*
 * set the percentage of blocks at which to stop allocating
 * - command: "bstop <N>%"
 */
static int cachefiles_proc_bstop(struct cachefiles_cache *cache, char *args)
{
	unsigned long bstop;

	_enter(",%s", args);

	if (!*args)
		return -EINVAL;

	bstop = simple_strtoul(args, &args, 10);
	if (args[0] != '%' || args[1] != '\0')
		return -EINVAL;

	if (bstop < 0 || bstop >= cache->bcull_percent)
		return cachefiles_proc_range_error(cache, args);

	cache->bstop_percent = bstop;
	return 0;
}

/*****************************************************************************/
/*
 * set the cache directory
 * - command: "dir <name>"
 */
static int cachefiles_proc_dir(struct cachefiles_cache *cache, char *args)
{
	char *dir;

	_enter(",%s", args);

	if (!*args) {
		kerror("Empty directory specified");
		return -EINVAL;
	}

	if (cache->rootdirname) {
		kerror("Second cache directory specified");
		return -EEXIST;
	}

	dir = kstrdup(args, GFP_KERNEL);
	if (!dir)
		return -ENOMEM;

	cache->rootdirname = dir;
	return 0;
}

/*****************************************************************************/
/*
 * set the cache tag
 * - command: "tag <name>"
 */
static int cachefiles_proc_tag(struct cachefiles_cache *cache, char *args)
{
	char *tag;

	_enter(",%s", args);

	if (!*args) {
		kerror("Empty tag specified");
		return -EINVAL;
	}

	if (cache->tag)
		return -EEXIST;

	tag = kstrdup(args, GFP_KERNEL);
	if (!tag)
		return -ENOMEM;

	cache->tag = tag;
	return 0;
}

/*****************************************************************************/
/*
 * request a node in the cache be culled
 * - command: "cull <dirfd> <name>"
 */
static int cachefiles_proc_cull(struct cachefiles_cache *cache, char *args)
{
	struct dentry *dir;
	struct file *dirfile;
	int dirfd, fput_needed, ret;

	_enter(",%s", args);

	dirfd = simple_strtoul(args, &args, 0);

	if (!args || !isspace(*args))
		goto inval;

	while (isspace(*args))
		args++;

	if (!*args)
		goto inval;

	if (strchr(args, '/'))
		goto inval;

	if (!test_bit(CACHEFILES_READY, &cache->flags)) {
		kerror("cull applied to unready cache");
		return -EIO;
	}

	if (test_bit(CACHEFILES_DEAD, &cache->flags)) {
		kerror("cull applied to dead cache");
		return -EIO;
	}

	/* extract the directory dentry from the fd */
	dirfile = fget_light(dirfd, &fput_needed);
	if (!dirfile) {
		kerror("cull dirfd not open");
		return -EBADF;
	}

	dir = dget(dirfile->f_dentry);
	fput_light(dirfile, fput_needed);
	dirfile = NULL;

	if (!S_ISDIR(dir->d_inode->i_mode))
		goto notdir;

	ret = cachefiles_cull(cache, dir, args);

	dput(dir);
	_leave(" = %d", ret);
	return ret;

notdir:
	dput(dir);
	kerror("cull command requires dirfd to be a directory");
	return -ENOTDIR;

inval:
	kerror("cull command requires dirfd and filename");
	return -EINVAL;
}

/*****************************************************************************/
/*
 * set debugging mode
 * - command: "debug <mask>"
 */
static int cachefiles_proc_debug(struct cachefiles_cache *cache, char *args)
{
	unsigned long mask;

	_enter(",%s", args);

	mask = simple_strtoul(args, &args, 0);
	if (!args || args[0] != '\0')
		goto inval;

	cachefiles_debug = mask;
	_leave(" = %ld", mask);
	return 0;

inval:
	kerror("debug command requires mask");
	return -EINVAL;
}
