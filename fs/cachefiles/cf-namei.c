/* cf-namei.c: CacheFiles path walking and related routines
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
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/quotaops.h>
#include <linux/xattr.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include "internal.h"

/*****************************************************************************/
/*
 * record the fact that an object is now active
 */
static void cachefiles_mark_object_active(struct cachefiles_cache *cache,
					  struct cachefiles_object *object)
{
	struct cachefiles_object *xobject;
	struct rb_node **_p, *_parent = NULL;
	struct dentry *dentry;

	_enter(",%p", object);

	write_lock(&cache->active_lock);

	if (test_and_set_bit(CACHEFILES_OBJECT_ACTIVE, &object->flags))
		BUG();

	dentry = object->dentry;
	_p = &cache->active_nodes.rb_node;
	while (*_p) {
		_parent = *_p;
		xobject = rb_entry(_parent,
				   struct cachefiles_object, active_node);

		if (xobject->dentry > dentry)
			_p = &(*_p)->rb_left;
		else if (xobject->dentry < dentry)
			_p = &(*_p)->rb_right;
		else
			BUG(); /* uh oh... this dentry shouldn't be here */
	}

	rb_link_node(&object->active_node, _parent, _p);
	rb_insert_color(&object->active_node, &cache->active_nodes);

	write_unlock(&cache->active_lock);
}

/*****************************************************************************/
/*
 * delete an object representation from the cache
 * - file backed objects are unlinked
 * - directory backed objects are stuffed into the graveyard for userspace to
 *   delete
 * - unlocks the directory mutex
 */
static int cachefiles_bury_object(struct cachefiles_cache *cache,
				  struct dentry *dir,
				  struct dentry *rep)
{
	struct dentry *grave, *alt, *trap;
	struct qstr name;
	const char *old_name;
	char nbuffer[8 + 8 + 1];
	int ret;

	_enter(",'%*.*s','%*.*s'",
	       dir->d_name.len, dir->d_name.len, dir->d_name.name,
	       rep->d_name.len, rep->d_name.len, rep->d_name.name);

	/* non-directories can just be unlinked */
	if (!S_ISDIR(rep->d_inode->i_mode)) {
		_debug("unlink stale object");
		ret = dir->d_inode->i_op->unlink(dir->d_inode, rep);

		mutex_unlock(&dir->d_inode->i_mutex);

		if (ret == 0) {
			_debug("d_delete");
			d_delete(rep);
		} else if (ret == -EIO) {
			cachefiles_io_error(cache, "Unlink failed");
		}

		_leave(" = %d", ret);
		return ret;
	}

	/* directories have to be moved to the graveyard */
	_debug("move stale object to graveyard");
	mutex_unlock(&dir->d_inode->i_mutex);

try_again:
	/* first step is to make up a grave dentry in the graveyard */
	sprintf(nbuffer, "%08x%08x",
		(uint32_t) xtime.tv_sec,
		(uint32_t) atomic_inc_return(&cache->gravecounter));

	name.name = nbuffer;
	name.len = strlen(name.name);

	/* hash the name */
	name.hash = full_name_hash(name.name, name.len);

	if (dir->d_op && dir->d_op->d_hash) {
		ret = dir->d_op->d_hash(dir, &name);
		if (ret < 0) {
			if (ret == -EIO)
				cachefiles_io_error(cache, "Hash failed");

			_leave(" = %d", ret);
			return ret;
		}
	}

	/* do the multiway lock magic */
	trap = lock_rename(cache->graveyard, dir);

	/* do some checks before getting the grave dentry */
	if (rep->d_parent != dir) {
		/* the entry was probably culled when we dropped the parent dir
		 * lock */
		unlock_rename(cache->graveyard, dir);
		_leave(" = 0 [culled?]");
		return 0;
	}

	if (!S_ISDIR(cache->graveyard->d_inode->i_mode)) {
		unlock_rename(cache->graveyard, dir);
		cachefiles_io_error(cache, "Graveyard no longer a directory");
		return -EIO;
	}

	if (trap == rep) {
		unlock_rename(cache->graveyard, dir);
		cachefiles_io_error(cache, "May not make directory loop");
		return -EIO;
	}

	if (d_mountpoint(rep)) {
		unlock_rename(cache->graveyard, dir);
		cachefiles_io_error(cache, "Mountpoint in cache");
		return -EIO;
	}

	/* see if there's a dentry already there for this name */
	grave = d_lookup(cache->graveyard, &name);
	if (!grave) {
		_debug("not found");

		grave = d_alloc(cache->graveyard, &name);
		if (!grave) {
			unlock_rename(cache->graveyard, dir);
			_leave(" = -ENOMEM");
			return -ENOMEM;
		}

		alt = cache->graveyard->d_inode->i_op->lookup(
			cache->graveyard->d_inode, grave, NULL);
		if (IS_ERR(alt)) {
			unlock_rename(cache->graveyard, dir);
			dput(grave);

			if (PTR_ERR(alt) == -ENOMEM) {
				_leave(" = -ENOMEM");
				return -ENOMEM;
			}

			cachefiles_io_error(cache, "Lookup error %ld",
					    PTR_ERR(alt));
			return -EIO;
		}

		if (alt) {
			dput(grave);
			grave = alt;
		}
	}

	if (grave->d_inode) {
		unlock_rename(cache->graveyard, dir);
		dput(grave);
		grave = NULL;
		cond_resched();
		goto try_again;
	}

	if (d_mountpoint(grave)) {
		unlock_rename(cache->graveyard, dir);
		dput(grave);
		cachefiles_io_error(cache, "Mountpoint in graveyard");
		return -EIO;
	}

	/* target should not be an ancestor of source */
	if (trap == grave) {
		unlock_rename(cache->graveyard, dir);
		dput(grave);
		cachefiles_io_error(cache, "May not make directory loop");
		return -EIO;
	}

	/* attempt the rename */
	DQUOT_INIT(dir->d_inode);
	DQUOT_INIT(cache->graveyard->d_inode);

	old_name = fsnotify_oldname_init(rep->d_name.name);

	ret = dir->d_inode->i_op->rename(dir->d_inode, rep,
					 cache->graveyard->d_inode, grave);

	if (ret == 0) {
		d_move(rep, grave);
		fsnotify_move(dir->d_inode, cache->graveyard->d_inode,
			      old_name, rep->d_name.name, 1,
			      grave->d_inode, rep->d_inode);
	} else if (ret != -ENOMEM) {
		cachefiles_io_error(cache, "Rename failed with error %d", ret);
	}

	fsnotify_oldname_free(old_name);

	unlock_rename(cache->graveyard, dir);
	dput(grave);
	_leave(" = 0");
	return 0;
}

/*****************************************************************************/
/*
 * delete an object representation from the cache
 */
int cachefiles_delete_object(struct cachefiles_cache *cache,
			     struct cachefiles_object *object)
{
	struct dentry *dir;
	int ret;

	_enter(",{%p}", object->dentry);

	ASSERT(object->dentry);
	ASSERT(object->dentry->d_inode);
	ASSERT(object->dentry->d_parent);

	dir = dget_parent(object->dentry);

	mutex_lock(&dir->d_inode->i_mutex);
	ret = cachefiles_bury_object(cache, dir, object->dentry);

	dput(dir);
	_leave(" = %d", ret);
	return ret;
}

/*****************************************************************************/
/*
 * walk from the parent object to the child object through the backing
 * filesystem, creating directories as we go
 */
int cachefiles_walk_to_object(struct cachefiles_object *parent,
			      struct cachefiles_object *object,
			      char *key,
			      struct cachefiles_xattr *auxdata)
{
	struct cachefiles_cache *cache;
	struct dentry *dir, *next = NULL, *new;
	struct qstr name;
	uid_t fsuid;
	gid_t fsgid;
	int ret;

	_enter("{%p}", parent->dentry);

	cache = container_of(parent->fscache.cache,
			     struct cachefiles_cache, cache);

	ASSERT(parent->dentry);
	ASSERT(parent->dentry->d_inode);

	if (!(S_ISDIR(parent->dentry->d_inode->i_mode))) {
		// TODO: convert file to dir
		_leave("looking up in none directory");
		return -ENOBUFS;
	}

	fsuid = current->fsuid;
	fsgid = current->fsgid;
	current->fsuid = 0;
	current->fsgid = 0;

	dir = dget(parent->dentry);

advance:
	/* attempt to transit the first directory component */
	name.name = key;
	key = strchr(key, '/');
	if (key) {
		name.len = key - (char *) name.name;
		*key++ = 0;
	} else {
		name.len = strlen(name.name);
	}

	/* hash the name */
	name.hash = full_name_hash(name.name, name.len);

	if (dir->d_op && dir->d_op->d_hash) {
		ret = dir->d_op->d_hash(dir, &name);
		if (ret < 0) {
			cachefiles_io_error(cache, "Hash failed");
			goto error_out2;
		}
	}

lookup_again:
	/* search the current directory for the element name */
	_debug("lookup '%s' %x", name.name, name.hash);

	mutex_lock(&dir->d_inode->i_mutex);

	next = d_lookup(dir, &name);
	if (!next) {
		_debug("not found");

		new = d_alloc(dir, &name);
		if (!new)
			goto nomem_d_alloc;

		ASSERT(dir->d_inode->i_op);
		ASSERT(dir->d_inode->i_op->lookup);

		next = dir->d_inode->i_op->lookup(dir->d_inode, new, NULL);
		if (IS_ERR(next))
			goto lookup_error;

		if (!next)
			next = new;
		else
			dput(new);

		if (next->d_inode) {
			ret = -EPERM;
			if (!next->d_inode->i_op ||
			    !next->d_inode->i_op->setxattr ||
			    !next->d_inode->i_op->getxattr ||
			    !next->d_inode->i_op->removexattr)
				goto error;

			if (key && (!next->d_inode->i_op->lookup ||
				    !next->d_inode->i_op->mkdir ||
				    !next->d_inode->i_op->create ||
				    !next->d_inode->i_op->rename ||
				    !next->d_inode->i_op->rmdir ||
				    !next->d_inode->i_op->unlink))
				goto error;
		}
	}

	_debug("next -> %p %s", next, next->d_inode ? "positive" : "negative");

	if (!key)
		object->new = !next->d_inode;

	/* we need to create the object if it's negative */
	if (key || object->type == FSCACHE_COOKIE_TYPE_INDEX) {
		/* index objects and intervening tree levels must be subdirs */
		if (!next->d_inode) {
			ret = cachefiles_has_space(cache, 1, 0);
			if (ret < 0)
				goto create_error;

			DQUOT_INIT(dir->d_inode);
			ret = dir->d_inode->i_op->mkdir(dir->d_inode, next, 0);
			if (ret < 0)
				goto create_error;

			ASSERT(next->d_inode);

			fsnotify_mkdir(dir->d_inode, next);

			_debug("mkdir -> %p{%p{ino=%lu}}",
			       next, next->d_inode, next->d_inode->i_ino);

		} else if (!S_ISDIR(next->d_inode->i_mode)) {
			kerror("inode %lu is not a directory",
			       next->d_inode->i_ino);
			ret = -ENOBUFS;
			goto error;
		}

	} else {
		/* non-index objects start out life as files */
		if (!next->d_inode) {
			ret = cachefiles_has_space(cache, 1, 0);
			if (ret < 0)
				goto create_error;

			DQUOT_INIT(dir->d_inode);
			ret = dir->d_inode->i_op->create(dir->d_inode, next,
							 S_IFREG, NULL);
			if (ret < 0)
				goto create_error;

			ASSERT(next->d_inode);

			fsnotify_create(dir->d_inode, next);

			_debug("create -> %p{%p{ino=%lu}}",
			       next, next->d_inode, next->d_inode->i_ino);

		} else if (!S_ISDIR(next->d_inode->i_mode) &&
			   !S_ISREG(next->d_inode->i_mode)
			   ) {
			kerror("inode %lu is not a file or directory",
			       next->d_inode->i_ino);
			ret = -ENOBUFS;
			goto error;
		}
	}

	/* process the next component */
	if (key) {
		_debug("advance");
		mutex_unlock(&dir->d_inode->i_mutex);
		dput(dir);
		dir = next;
		next = NULL;
		goto advance;
	}

	/* we've found the object we were looking for */
	object->dentry = next;

	/* if we've found that the terminal object exists, then we need to
	 * check its attributes and delete it if it's out of date */
	if (!object->new) {
		_debug("validate '%*.*s'",
		       next->d_name.len, next->d_name.len, next->d_name.name);

		ret = cachefiles_check_object_xattr(object, auxdata);
		if (ret == -ESTALE) {
			/* delete the object (the deleter drops the directory
			 * mutex) */
			object->dentry = NULL;

			ret = cachefiles_bury_object(cache, dir, next);
			dput(next);
			next = NULL;

			if (ret < 0)
				goto delete_error;

			_debug("redo lookup");
			goto lookup_again;
		}
	}

	/* note that we're now using this object */
	cachefiles_mark_object_active(cache, object);

	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
	dir = NULL;

	if (object->new) {
		/* attach data to a newly constructed terminal object */
		ret = cachefiles_set_object_xattr(object, auxdata);
		if (ret < 0)
			goto check_error;
	} else {
		/* always update the atime on an object we've just looked up
		 * (this is used to keep track of culling, and atimes are only
		 * updated by read, write and readdir but not lookup or
		 * open) */
		touch_atime(cache->mnt, next);
	}

	/* open a file interface onto a data file */
	if (object->type != FSCACHE_COOKIE_TYPE_INDEX) {
		if (S_ISREG(object->dentry->d_inode->i_mode)) {
			const struct address_space_operations *aops;

			ret = -EPERM;
			aops = object->dentry->d_inode->i_mapping->a_ops;
			if (!aops->bmap ||
			    !aops->prepare_write ||
			    !aops->commit_write)
				goto check_error;

			object->backer = object->dentry;
		} else {
			BUG(); // TODO: open file in data-class subdir
		}
	}

	current->fsuid = fsuid;
	current->fsgid = fsgid;
	object->new = 0;

	_leave(" = 0 [%lu]", object->dentry->d_inode->i_ino);
	return 0;

create_error:
	_debug("create error %d", ret);
	if (ret == -EIO)
		cachefiles_io_error(cache, "create/mkdir failed");
	goto error;

check_error:
	_debug("check error %d", ret);
	write_lock(&cache->active_lock);
	rb_erase(&object->active_node, &cache->active_nodes);
	write_unlock(&cache->active_lock);

	dput(object->dentry);
	object->dentry = NULL;
	goto error_out;

delete_error:
	_debug("delete error %d", ret);
	goto error_out2;

lookup_error:
	_debug("lookup error %ld", PTR_ERR(next));
	dput(new);
	ret = PTR_ERR(next);
	if (ret == -EIO)
		cachefiles_io_error(cache, "Lookup failed");
	next = NULL;
	goto error;

nomem_d_alloc:
	ret = -ENOMEM;
error:
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(next);
error_out2:
	dput(dir);
error_out:
	current->fsuid = fsuid;
	current->fsgid = fsgid;

	if (ret == -ENOSPC)
		ret = -ENOBUFS;

	_leave(" = error %d", -ret);
	return ret;
}

/*****************************************************************************/
/*
 * get a subdirectory
 */
struct dentry *cachefiles_get_directory(struct cachefiles_cache *cache,
					struct dentry *dir,
					const char *dirname)
{
	struct dentry *subdir, *new;
	struct qstr name;
	uid_t fsuid;
	gid_t fsgid;
	int ret;

	_enter("");

	/* set up the name */
	name.name = dirname;
	name.len = strlen(dirname);
	name.hash = full_name_hash(name.name, name.len);

	if (dir->d_op && dir->d_op->d_hash) {
		ret = dir->d_op->d_hash(dir, &name);
		if (ret < 0) {
			if (ret == -EIO)
				kerror("Hash failed");
			_leave(" = %d", ret);
			return ERR_PTR(ret);
		}
	}

	/* search the current directory for the element name */
	_debug("lookup '%s' %x", name.name, name.hash);

	fsuid = current->fsuid;
	fsgid = current->fsgid;
	current->fsuid = 0;
	current->fsgid = 0;

	mutex_lock(&dir->d_inode->i_mutex);

	subdir = d_lookup(dir, &name);
	if (!subdir) {
		_debug("not found");

		new = d_alloc(dir, &name);
		if (!new)
			goto nomem_d_alloc;

		subdir = dir->d_inode->i_op->lookup(dir->d_inode, new, NULL);
		if (IS_ERR(subdir))
			goto lookup_error;

		if (!subdir)
			subdir = new;
		else
			dput(new);
	}

	_debug("subdir -> %p %s",
	       subdir, subdir->d_inode ? "positive" : "negative");

	/* we need to create the subdir if it doesn't exist yet */
	if (!subdir->d_inode) {
		ret = cachefiles_has_space(cache, 1, 0);
		if (ret < 0)
			goto mkdir_error;

		DQUOT_INIT(dir->d_inode);
		ret = dir->d_inode->i_op->mkdir(dir->d_inode, subdir, 0700);
		if (ret < 0)
			goto mkdir_error;

		ASSERT(subdir->d_inode);

		fsnotify_mkdir(dir->d_inode, subdir);

		_debug("mkdir -> %p{%p{ino=%lu}}",
		       subdir,
		       subdir->d_inode,
		       subdir->d_inode->i_ino);
	}

	mutex_unlock(&dir->d_inode->i_mutex);

	current->fsuid = fsuid;
	current->fsgid = fsgid;

	/* we need to make sure the subdir is a directory */
	ASSERT(subdir->d_inode);

	if (!S_ISDIR(subdir->d_inode->i_mode)) {
		kerror("%s is not a directory", dirname);
		ret = -EIO;
		goto check_error;
	}

	ret = -EPERM;
	if (!subdir->d_inode->i_op ||
	    !subdir->d_inode->i_op->setxattr ||
	    !subdir->d_inode->i_op->getxattr ||
	    !subdir->d_inode->i_op->lookup ||
	    !subdir->d_inode->i_op->mkdir ||
	    !subdir->d_inode->i_op->create ||
	    !subdir->d_inode->i_op->rename ||
	    !subdir->d_inode->i_op->rmdir ||
	    !subdir->d_inode->i_op->unlink)
		goto check_error;

	_leave(" = [%lu]", subdir->d_inode->i_ino);
	return subdir;

check_error:
	dput(subdir);
	_leave(" = %d [check]", ret);
	return ERR_PTR(ret);

mkdir_error:
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(subdir);
	kerror("mkdir %s failed with error %d", dirname, ret);
	goto error_out;

lookup_error:
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(new);
	ret = PTR_ERR(subdir);
	kerror("Lookup %s failed with error %d", dirname, ret);
	goto error_out;

nomem_d_alloc:
	mutex_unlock(&dir->d_inode->i_mutex);
	ret = -ENOMEM;
	goto error_out;

error_out:
	current->fsuid = fsuid;
	current->fsgid = fsgid;
	_leave(" = %d", ret);
	return ERR_PTR(ret);
}

/*****************************************************************************/
/*
 * cull an object if it's not in use
 * - called only by cache manager daemon
 */
int cachefiles_cull(struct cachefiles_cache *cache, struct dentry *dir,
		    char *filename)
{
	struct cachefiles_object *object;
	struct rb_node *_n;
	struct dentry *victim, *new;
	struct qstr name;
	int ret;

	_enter(",%*.*s/,%s",
	       dir->d_name.len, dir->d_name.len, dir->d_name.name, filename);

	/* set up the name */
	name.name = filename;
	name.len = strlen(filename);
	name.hash = full_name_hash(name.name, name.len);

	if (dir->d_op && dir->d_op->d_hash) {
		ret = dir->d_op->d_hash(dir, &name);
		if (ret < 0) {
			if (ret == -EIO)
				cachefiles_io_error(cache, "Hash failed");
			_leave(" = %d", ret);
			return ret;
		}
	}

	/* look up the victim */
	mutex_lock(&dir->d_inode->i_mutex);

	victim = d_lookup(dir, &name);
	if (!victim) {
		_debug("not found");

		new = d_alloc(dir, &name);
		if (!new)
			goto nomem_d_alloc;

		victim = dir->d_inode->i_op->lookup(dir->d_inode, new, NULL);
		if (IS_ERR(victim))
			goto lookup_error;

		if (!victim)
			victim = new;
		else
			dput(new);
	}

	_debug("victim -> %p %s",
	       victim, victim->d_inode ? "positive" : "negative");

	/* if the object is no longer there then we probably retired the object
	 * at the netfs's request whilst the cull was in progress
	 */
	if (!victim->d_inode) {
		mutex_unlock(&dir->d_inode->i_mutex);
		dput(victim);
		_leave(" = -ENOENT [absent]");
		return -ENOENT;
	}

	/* check to see if we're using this object */
	read_lock(&cache->active_lock);

	_n = cache->active_nodes.rb_node;

	while (_n) {
		object = rb_entry(_n, struct cachefiles_object, active_node);

		if (object->dentry > victim)
			_n = _n->rb_left;
		else if (object->dentry < victim)
			_n = _n->rb_right;
		else
			goto object_in_use;
	}

	read_unlock(&cache->active_lock);

	/* okay... the victim is not being used so we can cull it
	 * - start by marking it as stale
	 */
	_debug("victim is cullable");

	ret = cachefiles_remove_object_xattr(cache, victim);
	if (ret < 0)
		goto error_unlock;

	/*  actually remove the victim (drops the dir mutex) */
	_debug("bury");

	ret = cachefiles_bury_object(cache, dir, victim);
	if (ret < 0)
		goto error;

	dput(victim);
	_leave(" = 0");
	return 0;


object_in_use:
	read_unlock(&cache->active_lock);
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(victim);
	_leave(" = -EBUSY [in use]");
	return -EBUSY;

nomem_d_alloc:
	mutex_unlock(&dir->d_inode->i_mutex);
	_leave(" = -ENOMEM");
	return -ENOMEM;

lookup_error:
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(new);
	ret = PTR_ERR(victim);
	if (ret == -EIO)
		cachefiles_io_error(cache, "Lookup failed");
	goto choose_error;

error_unlock:
	mutex_unlock(&dir->d_inode->i_mutex);
error:
	dput(victim);
choose_error:
	if (ret == -ENOENT) {
		/* file or dir now absent - probably retired by netfs */
		_leave(" = -ESTALE [absent]");
		return -ESTALE;
	}

	if (ret != -ENOMEM) {
		kerror("Internal error: %d", ret);
		ret = -EIO;
	}

	_leave(" = %d", ret);
	return ret;
}
