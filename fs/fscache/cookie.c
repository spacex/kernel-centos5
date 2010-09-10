/* cookie.c: general filesystem cache cookie management
 *
 * Copyright (C) 2004-5 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include "fscache-int.h"

static LIST_HEAD(fscache_cache_tag_list);
static LIST_HEAD(fscache_cache_list);
static LIST_HEAD(fscache_netfs_list);
static DECLARE_RWSEM(fscache_addremove_sem);
static struct fscache_cache_tag fscache_nomem_tag;

kmem_cache_t *fscache_cookie_jar;

static void fscache_withdraw_object(struct fscache_cache *cache,
				    struct fscache_object *object);

static void __fscache_cookie_put(struct fscache_cookie *cookie);

static inline void fscache_cookie_put(struct fscache_cookie *cookie)
{
	/* check to see whether the cookie has already been released by looking
	 * for the poison when slab debugging is on */
#ifdef CONFIG_DEBUG_SLAB
	BUG_ON((atomic_read(&cookie->usage) & 0xffff0000) == 0x6b6b0000);
#endif

	BUG_ON(atomic_read(&cookie->usage) <= 0);

	if (atomic_dec_and_test(&cookie->usage))
		__fscache_cookie_put(cookie);

}

/*****************************************************************************/
/*
 * look up a cache tag
 */
struct fscache_cache_tag *__fscache_lookup_cache_tag(const char *name)
{
	struct fscache_cache_tag *tag, *xtag;

	/* firstly check for the existence of the tag under read lock */
	down_read(&fscache_addremove_sem);

	list_for_each_entry(tag, &fscache_cache_tag_list, link) {
		if (strcmp(tag->name, name) == 0) {
			atomic_inc(&tag->usage);
			up_read(&fscache_addremove_sem);
			return tag;
		}
	}

	up_read(&fscache_addremove_sem);

	/* the tag does not exist - create a candidate */
	xtag = kmalloc(sizeof(*xtag) + strlen(name) + 1, GFP_KERNEL);
	if (!xtag)
		/* return a dummy tag if out of memory */
		return &fscache_nomem_tag;

	atomic_set(&xtag->usage, 1);
	strcpy(xtag->name, name);

	/* write lock, search again and add if still not present */
	down_write(&fscache_addremove_sem);

	list_for_each_entry(tag, &fscache_cache_tag_list, link) {
		if (strcmp(tag->name, name) == 0) {
			atomic_inc(&tag->usage);
			up_write(&fscache_addremove_sem);
			kfree(xtag);
			return tag;
		}
	}

	list_add_tail(&xtag->link, &fscache_cache_tag_list);
	up_write(&fscache_addremove_sem);
	return xtag;
}

/*****************************************************************************/
/*
 * release a reference to a cache tag
 */
void __fscache_release_cache_tag(struct fscache_cache_tag *tag)
{
	if (tag != &fscache_nomem_tag) {
		down_write(&fscache_addremove_sem);

		if (atomic_dec_and_test(&tag->usage))
			list_del_init(&tag->link);
		else
			tag = NULL;

		up_write(&fscache_addremove_sem);

		kfree(tag);
	}
}

/*****************************************************************************/
/*
 * register a network filesystem for caching
 */
int __fscache_register_netfs(struct fscache_netfs *netfs)
{
	struct fscache_netfs *ptr;
	int ret;

	_enter("{%s}", netfs->name);

	INIT_LIST_HEAD(&netfs->link);

	/* allocate a cookie for the primary index */
	netfs->primary_index =
		kmem_cache_zalloc(fscache_cookie_jar, SLAB_KERNEL);

	if (!netfs->primary_index) {
		_leave(" = -ENOMEM");
		return -ENOMEM;
	}

	/* initialise the primary index cookie */
	atomic_set(&netfs->primary_index->usage, 1);
	atomic_set(&netfs->primary_index->children, 0);

	netfs->primary_index->def		= &fscache_fsdef_netfs_def;
	netfs->primary_index->parent		= &fscache_fsdef_index;
	netfs->primary_index->netfs		= netfs;
	netfs->primary_index->netfs_data	= netfs;

	atomic_inc(&netfs->primary_index->parent->usage);
	atomic_inc(&netfs->primary_index->parent->children);

	init_rwsem(&netfs->primary_index->sem);
	INIT_HLIST_HEAD(&netfs->primary_index->backing_objects);

	/* check the netfs type is not already present */
	down_write(&fscache_addremove_sem);

	ret = -EEXIST;
	list_for_each_entry(ptr, &fscache_netfs_list, link) {
		if (strcmp(ptr->name, netfs->name) == 0)
			goto already_registered;
	}

	list_add(&netfs->link, &fscache_netfs_list);
	ret = 0;

	printk("FS-Cache: netfs '%s' registered for caching\n", netfs->name);

already_registered:
	up_write(&fscache_addremove_sem);

	if (ret < 0) {
		netfs->primary_index->parent = NULL;
		__fscache_cookie_put(netfs->primary_index);
		netfs->primary_index = NULL;
	}

	_leave(" = %d", ret);
	return ret;
}

EXPORT_SYMBOL(__fscache_register_netfs);

/*****************************************************************************/
/*
 * unregister a network filesystem from the cache
 * - all cookies must have been released first
 */
void __fscache_unregister_netfs(struct fscache_netfs *netfs)
{
	_enter("{%s.%u}", netfs->name, netfs->version);

	down_write(&fscache_addremove_sem);

	list_del(&netfs->link);
	fscache_relinquish_cookie(netfs->primary_index, 0);

	up_write(&fscache_addremove_sem);

	printk("FS-Cache: netfs '%s' unregistered from caching\n",
	       netfs->name);

	_leave("");
}

EXPORT_SYMBOL(__fscache_unregister_netfs);

/*****************************************************************************/
/*
 * initialise a cache record
 */
void fscache_init_cache(struct fscache_cache *cache,
			struct fscache_cache_ops *ops,
			const char *idfmt,
			...)
{
	va_list va;

	memset(cache, 0, sizeof(*cache));

	cache->ops = ops;

	va_start(va, idfmt);
	vsnprintf(cache->identifier, sizeof(cache->identifier), idfmt, va);
	va_end(va);

	INIT_LIST_HEAD(&cache->link);
	INIT_LIST_HEAD(&cache->object_list);
	spin_lock_init(&cache->object_list_lock);
	init_rwsem(&cache->withdrawal_sem);
}

EXPORT_SYMBOL(fscache_init_cache);

/*****************************************************************************/
/*
 * declare a mounted cache as being open for business
 */
int fscache_add_cache(struct fscache_cache *cache,
		      struct fscache_object *ifsdef,
		      const char *tagname)
{
	struct fscache_cache_tag *tag;

	BUG_ON(!cache->ops);
	BUG_ON(!ifsdef);

	cache->flags = 0;

	if (!tagname)
		tagname = cache->identifier;

	BUG_ON(!tagname[0]);

	_enter("{%s.%s},,%s", cache->ops->name, cache->identifier, tagname);

	if (!cache->ops->grab_object(ifsdef))
		BUG();

	ifsdef->cookie = &fscache_fsdef_index;
	ifsdef->cache = cache;
	cache->fsdef = ifsdef;

	down_write(&fscache_addremove_sem);

	/* instantiate or allocate a cache tag */
	list_for_each_entry(tag, &fscache_cache_tag_list, link) {
		if (strcmp(tag->name, tagname) == 0) {
			if (tag->cache) {
				printk(KERN_ERR
				       "FS-Cache: cache tag '%s' already in use\n",
				       tagname);
				up_write(&fscache_addremove_sem);
				return -EEXIST;
			}

			atomic_inc(&tag->usage);
			goto found_cache_tag;
		}
	}

	tag = kmalloc(sizeof(*tag) + strlen(tagname) + 1, GFP_KERNEL);
	if (!tag) {
		up_write(&fscache_addremove_sem);
		return -ENOMEM;
	}

	atomic_set(&tag->usage, 1);
	strcpy(tag->name, tagname);
	list_add_tail(&tag->link, &fscache_cache_tag_list);

found_cache_tag:
	tag->cache = cache;
	cache->tag = tag;

	/* add the cache to the list */
	list_add(&cache->link, &fscache_cache_list);

	/* add the cache's netfs definition index object to the cache's
	 * list */
	spin_lock(&cache->object_list_lock);
	list_add_tail(&ifsdef->cache_link, &cache->object_list);
	spin_unlock(&cache->object_list_lock);

	/* add the cache's netfs definition index object to the top level index
	 * cookie as a known backing object */
	down_write(&fscache_fsdef_index.sem);

	hlist_add_head(&ifsdef->cookie_link,
		       &fscache_fsdef_index.backing_objects);

	atomic_inc(&fscache_fsdef_index.usage);

	/* done */
	up_write(&fscache_fsdef_index.sem);
	up_write(&fscache_addremove_sem);

	printk(KERN_NOTICE
	       "FS-Cache: Cache \"%s\" added (type %s)\n",
	       cache->tag->name, cache->ops->name);

	_leave(" = 0 [%s]", cache->identifier);
	return 0;
}

EXPORT_SYMBOL(fscache_add_cache);

/*****************************************************************************/
/*
 * note a cache I/O error
 */
void fscache_io_error(struct fscache_cache *cache)
{
	set_bit(FSCACHE_IOERROR, &cache->flags);

	printk(KERN_ERR "FS-Cache: Cache %s stopped due to I/O error\n",
	       cache->ops->name);
}

EXPORT_SYMBOL(fscache_io_error);

/*****************************************************************************/
/*
 * withdraw an unmounted cache from the active service
 */
void fscache_withdraw_cache(struct fscache_cache *cache)
{
	struct fscache_object *object;

	_enter("");

	printk(KERN_NOTICE
	       "FS-Cache: Withdrawing cache \"%s\"\n",
	       cache->tag->name);

	/* make the cache unavailable for cookie acquisition */
	down_write(&cache->withdrawal_sem);

	down_write(&fscache_addremove_sem);
	list_del_init(&cache->link);
	cache->tag->cache = NULL;
	up_write(&fscache_addremove_sem);

	/* mark all objects as being withdrawn */
	spin_lock(&cache->object_list_lock);
	list_for_each_entry(object, &cache->object_list, cache_link) {
		set_bit(FSCACHE_OBJECT_WITHDRAWN, &object->flags);
	}
	spin_unlock(&cache->object_list_lock);

	/* make sure all pages pinned by operations on behalf of the netfs are
	 * written to disc */
	cache->ops->sync_cache(cache);

	/* dissociate all the netfs pages backed by this cache from the block
	 * mappings in the cache */
	cache->ops->dissociate_pages(cache);

	/* we now have to destroy all the active objects pertaining to this
	 * cache */
	spin_lock(&cache->object_list_lock);

	while (!list_empty(&cache->object_list)) {
		object = list_entry(cache->object_list.next,
				    struct fscache_object, cache_link);
		list_del_init(&object->cache_link);
		spin_unlock(&cache->object_list_lock);

		_debug("withdraw %p", object->cookie);

		/* we've extracted an active object from the tree - now dispose
		 * of it */
		fscache_withdraw_object(cache, object);

		spin_lock(&cache->object_list_lock);
	}

	spin_unlock(&cache->object_list_lock);

	fscache_release_cache_tag(cache->tag);
	cache->tag = NULL;

	_leave("");
}

EXPORT_SYMBOL(fscache_withdraw_cache);

/*****************************************************************************/
/*
 * withdraw an object from active service at the behest of the cache
 * - need break the links to a cached object cookie
 * - called under two situations:
 *   (1) recycler decides to reclaim an in-use object
 *   (2) a cache is unmounted
 * - have to take care as the cookie can be being relinquished by the netfs
 *   simultaneously
 * - the active object is pinned by the caller holding a refcount on it
 */
static void fscache_withdraw_object(struct fscache_cache *cache,
				    struct fscache_object *object)
{
	struct fscache_cookie *cookie, *xcookie = NULL;

	_enter(",%p", object);

	/* first of all we have to break the links between the object and the
	 * cookie
	 * - we have to hold both semaphores BUT we have to get the cookie sem
	 *   FIRST
	 */
	cache->ops->lock_object(object);

	cookie = object->cookie;
	if (cookie) {
		/* pin the cookie so that is doesn't escape */
		atomic_inc(&cookie->usage);

		/* re-order the locks to avoid deadlock */
		cache->ops->unlock_object(object);
		down_write(&cookie->sem);
		cache->ops->lock_object(object);

		/* erase references from the object to the cookie */
		hlist_del_init(&object->cookie_link);

		xcookie = object->cookie;
		object->cookie = NULL;

		up_write(&cookie->sem);
	}

	cache->ops->unlock_object(object);

	/* we've broken the links between cookie and object */
	if (xcookie) {
		fscache_cookie_put(xcookie);
		cache->ops->put_object(object);
	}

	/* unpin the cookie */
	if (cookie) {
		if (cookie->def && cookie->def->now_uncached)
			cookie->def->now_uncached(cookie->netfs_data);
		fscache_cookie_put(cookie);
	}

	_leave("");
}

/*****************************************************************************/
/*
 * select a cache on which to store an object
 * - the cache addremove semaphore must be at least read-locked by the caller
 * - the object will never be an index
 */
static struct fscache_cache *fscache_select_cache_for_object(struct fscache_cookie *cookie)
{
	struct fscache_cache_tag *tag;
	struct fscache_object *object;
	struct fscache_cache *cache;

	_enter("");

	if (list_empty(&fscache_cache_list)) {
		_leave(" = NULL [no cache]");
		return NULL;
	}

	/* we check the parent to determine the cache to use */
	down_read(&cookie->parent->sem);

	/* the first in the parent's backing list should be the preferred
	 * cache */
	if (!hlist_empty(&cookie->parent->backing_objects)) {
		object = hlist_entry(cookie->parent->backing_objects.first,
				     struct fscache_object, cookie_link);

		cache = object->cache;
		if (test_bit(FSCACHE_IOERROR, &cache->flags))
			cache = NULL;

		up_read(&cookie->parent->sem);
		_leave(" = %p [parent]", cache);
		return cache;
	}

	/* the parent is unbacked */
	if (cookie->parent->def->type != FSCACHE_COOKIE_TYPE_INDEX) {
		/* parent not an index and is unbacked */
		up_read(&cookie->parent->sem);
		_leave(" = NULL [parent ubni]");
		return NULL;
	}

	up_read(&cookie->parent->sem);

	if (!cookie->parent->def->select_cache)
		goto no_preference;

	/* ask the netfs for its preference */
	tag = cookie->parent->def->select_cache(
		cookie->parent->parent->netfs_data,
		cookie->parent->netfs_data);

	if (!tag)
		goto no_preference;

	if (tag == &fscache_nomem_tag) {
		_leave(" = NULL [nomem tag]");
		return NULL;
	}

	if (!tag->cache) {
		_leave(" = NULL [unbacked tag]");
		return NULL;
	}

	if (test_bit(FSCACHE_IOERROR, &tag->cache->flags))
		return NULL;

	_leave(" = %p [specific]", tag->cache);
	return tag->cache;

no_preference:
	/* netfs has no preference - just select first cache */
	cache = list_entry(fscache_cache_list.next,
			   struct fscache_cache, link);
	_leave(" = %p [first]", cache);
	return cache;
}

/*****************************************************************************/
/*
 * get a backing object for a cookie from the chosen cache
 * - the cookie must be write-locked by the caller
 * - all parent indexes will be obtained recursively first
 */
static struct fscache_object *fscache_lookup_object(struct fscache_cookie *cookie,
						    struct fscache_cache *cache)
{
	struct fscache_cookie *parent = cookie->parent;
	struct fscache_object *pobject, *object;
	struct hlist_node *_p;

	_enter("{%s/%s},",
	       parent && parent->def ? parent->def->name : "",
	       cookie->def ? (char *) cookie->def->name : "<file>");

	if (test_bit(FSCACHE_IOERROR, &cache->flags))
		return NULL;

	/* see if we have the backing object for this cookie + cache immediately
	 * to hand
	 */
	object = NULL;
	hlist_for_each_entry(object, _p,
			     &cookie->backing_objects, cookie_link
			     ) {
		if (object->cache == cache)
			break;
	}

	if (object) {
		_leave(" = %p [old]", object);
		return object;
	}

	BUG_ON(!parent); /* FSDEF entries don't have a parent */

	/* we don't have a backing cookie, so we need to consult the object's
	 * parent index in the selected cache and maybe insert an entry
	 * therein; so the first thing to do is make sure that the parent index
	 * is represented on disc
	 */
	down_read(&parent->sem);

	pobject = NULL;
	hlist_for_each_entry(pobject, _p,
			     &parent->backing_objects, cookie_link
			     ) {
		if (pobject->cache == cache)
			break;
	}

	if (!pobject) {
		/* we don't know about the parent object */
		up_read(&parent->sem);
		down_write(&parent->sem);

		pobject = fscache_lookup_object(parent, cache);
		if (IS_ERR(pobject)) {
			up_write(&parent->sem);
			_leave(" = %ld [no ipobj]", PTR_ERR(pobject));
			return pobject;
		}

		_debug("pobject=%p", pobject);

		BUG_ON(pobject->cookie != parent);

		downgrade_write(&parent->sem);
	}

	/* now we can attempt to look up this object in the parent, possibly
	 * creating a representation on disc when we do so
	 */
	object = cache->ops->lookup_object(cache, pobject, cookie);
	up_read(&parent->sem);

	if (IS_ERR(object)) {
		_leave(" = %ld [no obj]", PTR_ERR(object));
		return object;
	}

	/* keep track of it */
	cache->ops->lock_object(object);

	BUG_ON(!hlist_unhashed(&object->cookie_link));

	/* attach to the cache's object list */
	if (list_empty(&object->cache_link)) {
		spin_lock(&cache->object_list_lock);
		list_add(&object->cache_link, &cache->object_list);
		spin_unlock(&cache->object_list_lock);
	}

	/* attach to the cookie */
	object->cookie = cookie;
	atomic_inc(&cookie->usage);
	hlist_add_head(&object->cookie_link, &cookie->backing_objects);

	/* done */
	cache->ops->unlock_object(object);
	_leave(" = %p [new]", object);
	return object;
}

/*****************************************************************************/
/*
 * request a cookie to represent an object (index, datafile, xattr, etc)
 * - parent specifies the parent object
 *   - the top level index cookie for each netfs is stored in the fscache_netfs
 *     struct upon registration
 * - idef points to the definition
 * - the netfs_data will be passed to the functions pointed to in *def
 * - all attached caches will be searched to see if they contain this object
 * - index objects aren't stored on disk until there's a dependent file that
 *   needs storing
 * - other objects are stored in a selected cache immediately, and all the
 *   indexes forming the path to it are instantiated if necessary
 * - we never let on to the netfs about errors
 *   - we may set a negative cookie pointer, but that's okay
 */
struct fscache_cookie *__fscache_acquire_cookie(struct fscache_cookie *parent,
						struct fscache_cookie_def *def,
						void *netfs_data)
{
	struct fscache_cookie *cookie;
	struct fscache_cache *cache;
	struct fscache_object *object;
	int ret = 0;

	BUG_ON(!def);

	_enter("{%s},{%s},%p",
	       parent ? (char *) parent->def->name : "<no-parent>",
	       def->name, netfs_data);

	/* if there's no parent cookie, then we don't create one here either */
	if (!parent) {
		_leave(" [no parent]");
		return NULL;
	}

	/* validate the definition */
	BUG_ON(!def->get_key);
	BUG_ON(!def->name[0]);

	BUG_ON(def->type == FSCACHE_COOKIE_TYPE_INDEX &&
	       parent->def->type != FSCACHE_COOKIE_TYPE_INDEX);

	/* allocate and initialise a cookie */
	cookie = kmem_cache_alloc(fscache_cookie_jar, SLAB_KERNEL);
	if (!cookie) {
		_leave(" [ENOMEM]");
		return NULL;
	}

	atomic_set(&cookie->usage, 1);
	atomic_set(&cookie->children, 0);

	atomic_inc(&parent->usage);
	atomic_inc(&parent->children);

	cookie->def		= def;
	cookie->parent		= parent;
	cookie->netfs		= parent->netfs;
	cookie->netfs_data	= netfs_data;

	/* now we need to see whether the backing objects for this cookie yet
	 * exist, if not there'll be nothing to search */
	down_read(&fscache_addremove_sem);

	if (list_empty(&fscache_cache_list)) {
		up_read(&fscache_addremove_sem);
		_leave(" = %p [no caches]", cookie);
		return cookie;
	}

	/* if the object is an index then we need do nothing more here - we
	 * create indexes on disk when we need them as an index may exist in
	 * multiple caches */
	if (cookie->def->type != FSCACHE_COOKIE_TYPE_INDEX) {
		down_write(&cookie->sem);

		/* the object is a file - we need to select a cache in which to
		 * store it */
		cache = fscache_select_cache_for_object(cookie);
		if (!cache)
			goto no_cache; /* couldn't decide on a cache */

		/* create a file index entry on disc, along with all the
		 * indexes required to find it again later */
		object = fscache_lookup_object(cookie, cache);
		if (IS_ERR(object)) {
			ret = PTR_ERR(object);
			goto error;
		}

		up_write(&cookie->sem);
	}
out:
	up_read(&fscache_addremove_sem);
	_leave(" = %p", cookie);
	return cookie;

no_cache:
	ret = -ENOMEDIUM;
	goto error_cleanup;
error:
	if (ret != -ENOBUFS) {
		printk(KERN_ERR "FS-Cache: error from cache: %d\n", ret);
		ret = -ENOBUFS;
	}
error_cleanup:
	if (cookie) {
		up_write(&cookie->sem);
		__fscache_cookie_put(cookie);
		cookie = NULL;
		atomic_dec(&parent->children);
	}

	goto out;
}

EXPORT_SYMBOL(__fscache_acquire_cookie);

/*****************************************************************************/
/*
 * release a cookie back to the cache
 * - the object will be marked as recyclable on disc if retire is true
 * - all dependents of this cookie must have already been unregistered
 *   (indexes/files/pages)
 */
void __fscache_relinquish_cookie(struct fscache_cookie *cookie, int retire)
{
	struct fscache_cache *cache;
	struct fscache_object *object;
	struct hlist_node *_p;

	if (!cookie) {
		_leave(" [no cookie]");
		return;
	}

	_enter("%p{%s},%d", cookie, cookie->def->name, retire);

	if (atomic_read(&cookie->children) != 0) {
		printk("FS-Cache: cookie still has children\n");
		BUG();
	}

	/* detach pointers back to the netfs */
	down_write(&cookie->sem);

	cookie->netfs_data	= NULL;
	cookie->def		= NULL;

	/* mark retired objects for recycling */
	if (retire) {
		hlist_for_each_entry(object, _p,
				     &cookie->backing_objects,
				     cookie_link
				     ) {
			set_bit(FSCACHE_OBJECT_RECYCLING, &object->flags);
		}
	}

	/* break links with all the active objects */
	while (!hlist_empty(&cookie->backing_objects)) {
		object = hlist_entry(cookie->backing_objects.first,
				     struct fscache_object,
				     cookie_link);

		/* detach each cache object from the object cookie */
		set_bit(FSCACHE_OBJECT_RELEASING, &object->flags);

		hlist_del_init(&object->cookie_link);

		cache = object->cache;
		cache->ops->lock_object(object);
		object->cookie = NULL;
		cache->ops->unlock_object(object);

		if (atomic_dec_and_test(&cookie->usage))
			/* the cookie refcount shouldn't be reduced to 0 yet */
			BUG();

		spin_lock(&cache->object_list_lock);
		list_del_init(&object->cache_link);
		spin_unlock(&cache->object_list_lock);

		cache->ops->put_object(object);
	}

	up_write(&cookie->sem);

	if (cookie->parent) {
#ifdef CONFIG_DEBUG_SLAB
		BUG_ON((atomic_read(&cookie->parent->children) & 0xffff0000) == 0x6b6b0000);
#endif
		atomic_dec(&cookie->parent->children);
	}

	/* finally dispose of the cookie */
	fscache_cookie_put(cookie);

	_leave("");
}

EXPORT_SYMBOL(__fscache_relinquish_cookie);

/*****************************************************************************/
/*
 * update the index entries backing a cookie
 */
void __fscache_update_cookie(struct fscache_cookie *cookie)
{
	struct fscache_object *object;
	struct hlist_node *_p;

	if (!cookie) {
		_leave(" [no cookie]");
		return;
	}

	_enter("{%s}", cookie->def->name);

	BUG_ON(!cookie->def->get_aux);

	down_write(&cookie->sem);
	down_read(&cookie->parent->sem);

	/* update the index entry on disc in each cache backing this cookie */
	hlist_for_each_entry(object, _p,
			     &cookie->backing_objects, cookie_link
			     ) {
		if (!test_bit(FSCACHE_IOERROR, &object->cache->flags))
			object->cache->ops->update_object(object);
	}

	up_read(&cookie->parent->sem);
	up_write(&cookie->sem);
	_leave("");
}

EXPORT_SYMBOL(__fscache_update_cookie);

/*****************************************************************************/
/*
 * destroy a cookie
 */
static void __fscache_cookie_put(struct fscache_cookie *cookie)
{
	struct fscache_cookie *parent;

	_enter("%p", cookie);

	for (;;) {
		parent = cookie->parent;
		BUG_ON(!hlist_empty(&cookie->backing_objects));
		kmem_cache_free(fscache_cookie_jar, cookie);

		if (!parent)
			break;

		cookie = parent;
		BUG_ON(atomic_read(&cookie->usage) <= 0);
		if (!atomic_dec_and_test(&cookie->usage))
			break;
	}

	_leave("");
}

/*****************************************************************************/
/*
 * initialise an cookie jar slab element prior to any use
 */
void fscache_cookie_init_once(void *_cookie, kmem_cache_t *cachep,
			      unsigned long flags)
{
	struct fscache_cookie *cookie = _cookie;

	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
	    SLAB_CTOR_CONSTRUCTOR) {
		memset(cookie, 0, sizeof(*cookie));
		init_rwsem(&cookie->sem);
		INIT_HLIST_HEAD(&cookie->backing_objects);
	}
}

/*****************************************************************************/
/*
 * pin an object into the cache
 */
int __fscache_pin_cookie(struct fscache_cookie *cookie)
{
	struct fscache_object *object;
	int ret;

	_enter("%p", cookie);

	if (hlist_empty(&cookie->backing_objects)) {
		_leave(" = -ENOBUFS");
		return -ENOBUFS;
	}

	/* not supposed to use this for indexes */
	BUG_ON(cookie->def->type == FSCACHE_COOKIE_TYPE_INDEX);

	/* prevent the file from being uncached whilst we access it and exclude
	 * read and write attempts on pages
	 */
	down_write(&cookie->sem);

	ret = -ENOBUFS;
	if (!hlist_empty(&cookie->backing_objects)) {
		/* get and pin the backing object */
		object = hlist_entry(cookie->backing_objects.first,
				     struct fscache_object, cookie_link);

		if (test_bit(FSCACHE_IOERROR, &object->cache->flags))
			goto out;

		if (!object->cache->ops->pin_object) {
			ret = -EOPNOTSUPP;
			goto out;
		}

		/* prevent the cache from being withdrawn */
		if (fscache_operation_lock(object)) {
			if (object->cache->ops->grab_object(object)) {
				/* ask the cache to honour the operation */
				ret = object->cache->ops->pin_object(object);

				object->cache->ops->put_object(object);
			}

			fscache_operation_unlock(object);
		}
	}

out:
	up_write(&cookie->sem);
	_leave(" = %d", ret);
	return ret;
}

EXPORT_SYMBOL(__fscache_pin_cookie);

/*****************************************************************************/
/*
 * unpin an object into the cache
 */
void __fscache_unpin_cookie(struct fscache_cookie *cookie)
{
	struct fscache_object *object;
	int ret;

	_enter("%p", cookie);

	if (hlist_empty(&cookie->backing_objects)) {
		_leave(" [no obj]");
		return;
	}

	/* not supposed to use this for indexes */
	BUG_ON(cookie->def->type == FSCACHE_COOKIE_TYPE_INDEX);

	/* prevent the file from being uncached whilst we access it and exclude
	 * read and write attempts on pages
	 */
	down_write(&cookie->sem);

	ret = -ENOBUFS;
	if (!hlist_empty(&cookie->backing_objects)) {
		/* get and unpin the backing object */
		object = hlist_entry(cookie->backing_objects.first,
				     struct fscache_object, cookie_link);

		if (test_bit(FSCACHE_IOERROR, &object->cache->flags))
			goto out;

		if (!object->cache->ops->unpin_object)
			goto out;

		/* prevent the cache from being withdrawn */
		if (fscache_operation_lock(object)) {
			if (object->cache->ops->grab_object(object)) {
				/* ask the cache to honour the operation */
				object->cache->ops->unpin_object(object);

				object->cache->ops->put_object(object);
			}

			fscache_operation_unlock(object);
		}
	}

out:
	up_write(&cookie->sem);
	_leave("");
}

EXPORT_SYMBOL(__fscache_unpin_cookie);
