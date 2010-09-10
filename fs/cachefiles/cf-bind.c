/* cf-bind.c: bind and unbind a cache from the filesystem backing it
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

static int cachefiles_proc_add_cache(struct cachefiles_cache *cache,
				     struct vfsmount *mnt);

/*****************************************************************************/
/*
 * bind a directory as a cache
 */
int cachefiles_proc_bind(struct cachefiles_cache *cache, char *args)
{
	_enter("{%u,%u,%u,%u,%u,%u},%s",
	       cache->frun_percent,
	       cache->fcull_percent,
	       cache->fstop_percent,
	       cache->brun_percent,
	       cache->bcull_percent,
	       cache->bstop_percent,
	       args);

	/* start by checking things over */
	ASSERT(cache->fstop_percent >= 0 &&
	       cache->fstop_percent < cache->fcull_percent &&
	       cache->fcull_percent < cache->frun_percent &&
	       cache->frun_percent  < 100);

	ASSERT(cache->bstop_percent >= 0 &&
	       cache->bstop_percent < cache->bcull_percent &&
	       cache->bcull_percent < cache->brun_percent &&
	       cache->brun_percent  < 100);

	if (*args) {
		kerror("'bind' command doesn't take an argument");
		return -EINVAL;
	}

	if (!cache->rootdirname) {
		kerror("No cache directory specified");
		return -EINVAL;
	}

	/* don't permit already bound caches to be re-bound */
	if (test_bit(CACHEFILES_READY, &cache->flags)) {
		kerror("Cache already bound");
		return -EBUSY;
	}

	/* make sure we have copies of the tag and dirname strings */
	if (!cache->tag) {
		/* the tag string is released by the fops->release()
		 * function, so we don't release it on error here */
		cache->tag = kstrdup("CacheFiles", GFP_KERNEL);
		if (!cache->tag)
			return -ENOMEM;
	}

	/* add the cache */
	return cachefiles_proc_add_cache(cache, NULL);
}

/*****************************************************************************/
/*
 * add a cache
 */
static int cachefiles_proc_add_cache(struct cachefiles_cache *cache,
				     struct vfsmount *mnt)
{
	struct cachefiles_object *fsdef;
	struct nameidata nd;
	struct kstatfs stats;
	struct dentry *graveyard, *cachedir, *root;
	int ret;

	_enter("");

	/* allocate the root index object */
	ret = -ENOMEM;

	fsdef = kmem_cache_alloc(cachefiles_object_jar, SLAB_KERNEL);
	if (!fsdef)
		goto error_root_object;

	atomic_set(&fsdef->usage, 1);
	atomic_set(&fsdef->fscache_usage, 1);
	fsdef->type = FSCACHE_COOKIE_TYPE_INDEX;

	_debug("- fsdef %p", fsdef);

	/* look up the directory at the root of the cache */
	memset(&nd, 0, sizeof(nd));

	ret = path_lookup(cache->rootdirname, LOOKUP_DIRECTORY, &nd);
	if (ret < 0)
		goto error_open_root;

	/* bind to the special mountpoint we've prepared */
	if (mnt) {
		atomic_inc(&nd.mnt->mnt_sb->s_active);
		mnt->mnt_sb = nd.mnt->mnt_sb;
		mnt->mnt_flags = nd.mnt->mnt_flags;
		mnt->mnt_flags |= MNT_NOSUID | MNT_NOEXEC | MNT_NODEV;
		mnt->mnt_root = dget(nd.dentry);
		mnt->mnt_mountpoint = mnt->mnt_root;

		/* copy the name, but ignore kstrdup() failing ENOMEM - we'll
		 * just end up with an devicenameless mountpoint */
		mnt->mnt_devname = kstrdup(nd.mnt->mnt_devname, GFP_KERNEL);
		path_release(&nd);

		cache->mnt = mntget(mnt);
		root = dget(mnt->mnt_root);
	} else {
		cache->mnt = nd.mnt;
		root = nd.dentry;

		nd.mnt = NULL;
		nd.dentry = NULL;
		path_release(&nd);
	}

	/* check parameters */
	ret = -EOPNOTSUPP;
	if (!root->d_inode ||
	    !root->d_inode->i_op ||
	    !root->d_inode->i_op->lookup ||
	    !root->d_inode->i_op->mkdir ||
	    !root->d_inode->i_op->setxattr ||
	    !root->d_inode->i_op->getxattr ||
	    !root->d_sb ||
	    !root->d_sb->s_op ||
	    !root->d_sb->s_op->statfs ||
	    !root->d_sb->s_op->sync_fs)
		goto error_unsupported;

	ret = -EROFS;
	if (root->d_sb->s_flags & MS_RDONLY)
		goto error_unsupported;

	/* get the cache size and blocksize */
	ret = root->d_sb->s_op->statfs(root, &stats);
	if (ret < 0)
		goto error_unsupported;

	ret = -ERANGE;
	if (stats.f_bsize <= 0)
		goto error_unsupported;

	ret = -EOPNOTSUPP;
	if (stats.f_bsize > PAGE_SIZE)
		goto error_unsupported;

	cache->bsize = stats.f_bsize;
	cache->bshift = 0;
	if (stats.f_bsize < PAGE_SIZE)
		cache->bshift = PAGE_SHIFT - long_log2(stats.f_bsize);

	_debug("blksize %u (shift %u)",
	       cache->bsize, cache->bshift);

	_debug("size %llu, avail %llu",
	       (unsigned long long) stats.f_blocks,
	       (unsigned long long) stats.f_bavail);

	/* set up caching limits */
	do_div(stats.f_files, 100);
	cache->fstop = stats.f_files * cache->fstop_percent;
	cache->fcull = stats.f_files * cache->fcull_percent;
	cache->frun  = stats.f_files * cache->frun_percent;

	_debug("limits {%llu,%llu,%llu} files",
	       (unsigned long long) cache->frun,
	       (unsigned long long) cache->fcull,
	       (unsigned long long) cache->fstop);

	stats.f_blocks >>= cache->bshift;
	do_div(stats.f_blocks, 100);
	cache->bstop = stats.f_blocks * cache->bstop_percent;
	cache->bcull = stats.f_blocks * cache->bcull_percent;
	cache->brun  = stats.f_blocks * cache->brun_percent;

	_debug("limits {%llu,%llu,%llu} blocks",
	       (unsigned long long) cache->brun,
	       (unsigned long long) cache->bcull,
	       (unsigned long long) cache->bstop);

	/* get the cache directory and check its type */
	cachedir = cachefiles_get_directory(cache, root, "cache");
	if (IS_ERR(cachedir)) {
		ret = PTR_ERR(cachedir);
		goto error_unsupported;
	}

	fsdef->dentry = cachedir;

	ret = cachefiles_check_object_type(fsdef);
	if (ret < 0)
		goto error_unsupported;

	/* get the graveyard directory */
	graveyard = cachefiles_get_directory(cache, root, "graveyard");
	if (IS_ERR(graveyard)) {
		ret = PTR_ERR(graveyard);
		goto error_unsupported;
	}

	cache->graveyard = graveyard;

	/* publish the cache */
	fscache_init_cache(&cache->cache,
			   &cachefiles_cache_ops,
			   "%02x:%02x",
			   MAJOR(fsdef->dentry->d_sb->s_dev),
			   MINOR(fsdef->dentry->d_sb->s_dev)
			   );

	ret = fscache_add_cache(&cache->cache, &fsdef->fscache, cache->tag);
	if (ret < 0)
		goto error_add_cache;

	/* done */
	set_bit(CACHEFILES_READY, &cache->flags);
	dput(root);

	printk(KERN_INFO "CacheFiles:"
	       " File cache on %s registered\n",
	       cache->cache.identifier);

	/* check how much space the cache has */
	cachefiles_has_space(cache, 0, 0);

	return 0;

error_add_cache:
	dput(cache->graveyard);
	cache->graveyard = NULL;
error_unsupported:
	mntput(cache->mnt);
	cache->mnt = NULL;
	dput(fsdef->dentry);
	fsdef->dentry = NULL;
	dput(root);
error_open_root:
	kmem_cache_free(cachefiles_object_jar, fsdef);
error_root_object:
	kerror("Failed to register: %d", ret);
	return ret;
}

/*****************************************************************************/
/*
 * unbind a cache on fd release
 */
void cachefiles_proc_unbind(struct cachefiles_cache *cache)
{
	_enter("");

	if (test_bit(CACHEFILES_READY, &cache->flags)) {
		printk(KERN_INFO "CacheFiles:"
		       " File cache on %s unregistering\n",
		       cache->cache.identifier);

		fscache_withdraw_cache(&cache->cache);
	}

	if (cache->cache.fsdef)
		cache->cache.ops->put_object(cache->cache.fsdef);

	dput(cache->graveyard);
	mntput(cache->mnt);

	kfree(cache->rootdirname);
	kfree(cache->tag);

	_leave("");
}
