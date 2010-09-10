/* cf-interface.c: CacheFiles to FS-Cache interface
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
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/statfs.h>
#include <linux/buffer_head.h>
#include "internal.h"

#define list_to_page(head) (list_entry((head)->prev, struct page, lru))
#define log2(n) ffz(~(n))

/*****************************************************************************/
/*
 * look up the nominated node in this cache, creating it if necessary
 */
static struct fscache_object *cachefiles_lookup_object(
	struct fscache_cache *_cache,
	struct fscache_object *_parent,
	struct fscache_cookie *cookie)
{
	struct cachefiles_object *parent, *object;
	struct cachefiles_cache *cache;
	struct cachefiles_xattr *auxdata;
	unsigned keylen, auxlen;
	void *buffer;
	char *key;
	int ret;

	ASSERT(_parent);

	cache = container_of(_cache, struct cachefiles_cache, cache);
	parent = container_of(_parent, struct cachefiles_object, fscache);

	_enter("{%s},%p,%p", cache->cache.identifier, parent, cookie);

	/* create a new object record and a temporary leaf image */
	object = kmem_cache_alloc(cachefiles_object_jar, SLAB_KERNEL);
	if (!object)
		goto nomem_object;

	BUG_ON(object->backer != NULL);

	atomic_set(&object->usage, 1);
	atomic_set(&object->fscache_usage, 1);

	fscache_object_init(&object->fscache);
	object->fscache.cookie = cookie;
	object->fscache.cache = parent->fscache.cache;

	object->type = cookie->def->type;

	/* get hold of the raw key
	 * - stick the length on the front and leave space on the back for the
	 *   encoder
	 */
	buffer = kmalloc((2 + 512) + 3, GFP_KERNEL);
	if (!buffer)
		goto nomem_buffer;

	keylen = cookie->def->get_key(cookie->netfs_data, buffer + 2, 512);
	ASSERTCMP(keylen, <, 512);

	*(uint16_t *)buffer = keylen;
	((char *)buffer)[keylen + 2] = 0;
	((char *)buffer)[keylen + 3] = 0;
	((char *)buffer)[keylen + 4] = 0;

	/* turn the raw key into something that can work with as a filename */
	key = cachefiles_cook_key(buffer, keylen + 2, object->type);
	if (!key)
		goto nomem_key;

	/* get hold of the auxiliary data and prepend the object type */
	auxdata = buffer;
	auxlen = 0;
	if (cookie->def->get_aux) {
		auxlen = cookie->def->get_aux(cookie->netfs_data,
					      auxdata->data, 511);
		ASSERTCMP(auxlen, <, 511);
	}

	auxdata->len = auxlen + 1;
	auxdata->type = cookie->def->type;

	/* look up the key, creating any missing bits */
	ret = cachefiles_walk_to_object(parent, object, key, auxdata);
	if (ret < 0)
		goto lookup_failed;

	kfree(buffer);
	kfree(key);
	_leave(" = %p", &object->fscache);
	return &object->fscache;

lookup_failed:
	kmem_cache_free(cachefiles_object_jar, object);
	kfree(buffer);
	kfree(key);
	_leave(" = %d", ret);
	return ERR_PTR(ret);

nomem_key:
	kfree(buffer);
nomem_buffer:
	kmem_cache_free(cachefiles_object_jar, object);
nomem_object:
	_leave(" = -ENOMEM");
	return ERR_PTR(-ENOMEM);

}

/*****************************************************************************/
/*
 * increment the usage count on an inode object (may fail if unmounting)
 */
static struct fscache_object *cachefiles_grab_object(struct fscache_object *_object)
{
	struct cachefiles_object *object;

	_enter("%p", _object);

	object = container_of(_object, struct cachefiles_object, fscache);

#ifdef CACHEFILES_DEBUG_SLAB
	ASSERT((atomic_read(&object->fscache_usage) & 0xffff0000) != 0x6b6b0000);
#endif

	atomic_inc(&object->fscache_usage);
	return &object->fscache;

}

/*****************************************************************************/
/*
 * lock the semaphore on an object object
 */
static void cachefiles_lock_object(struct fscache_object *_object)
{
	struct cachefiles_object *object;

	_enter("%p", _object);

	object = container_of(_object, struct cachefiles_object, fscache);

#ifdef CACHEFILES_DEBUG_SLAB
	ASSERT((atomic_read(&object->fscache_usage) & 0xffff0000) != 0x6b6b0000);
#endif

	down_write(&object->sem);

}

/*****************************************************************************/
/*
 * unlock the semaphore on an object object
 */
static void cachefiles_unlock_object(struct fscache_object *_object)
{
	struct cachefiles_object *object;

	_enter("%p", _object);

	object = container_of(_object, struct cachefiles_object, fscache);
	up_write(&object->sem);

}

/*****************************************************************************/
/*
 * update the auxilliary data for an object object on disk
 */
static void cachefiles_update_object(struct fscache_object *_object)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;

	_enter("%p", _object);

	object = container_of(_object, struct cachefiles_object, fscache);
	cache = container_of(object->fscache.cache, struct cachefiles_cache, cache);

	//cachefiles_tree_update_object(super, object);

}

/*****************************************************************************/
/*
 * dispose of a reference to an object object
 */
static void cachefiles_put_object(struct fscache_object *_object)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;

	ASSERT(_object);

	object = container_of(_object, struct cachefiles_object, fscache);
	_enter("%p{%d}", object, atomic_read(&object->usage));

	ASSERT(object);

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

#ifdef CACHEFILES_DEBUG_SLAB
	ASSERT((atomic_read(&object->fscache_usage) & 0xffff0000) != 0x6b6b0000);
#endif

	if (!atomic_dec_and_test(&object->fscache_usage))
		return;

	_debug("- kill object %p", object);

	/* delete retired objects */
	if (test_bit(FSCACHE_OBJECT_RECYCLING, &object->fscache.flags) &&
	    _object != cache->cache.fsdef
	    ) {
		_debug("- retire object %p", object);
		cachefiles_delete_object(cache, object);
	}

	/* close the filesystem stuff attached to the object */
	if (object->backer != object->dentry)
		dput(object->backer);
	object->backer = NULL;

	/* note that the object is now inactive */
	if (test_bit(CACHEFILES_OBJECT_ACTIVE, &object->flags)) {
		write_lock(&cache->active_lock);
		if (!test_and_clear_bit(CACHEFILES_OBJECT_ACTIVE,
					&object->flags))
			BUG();
		rb_erase(&object->active_node, &cache->active_nodes);
		write_unlock(&cache->active_lock);
	}

	dput(object->dentry);
	object->dentry = NULL;

	/* then dispose of the object */
	kmem_cache_free(cachefiles_object_jar, object);

	_leave("");

}

/*****************************************************************************/
/*
 * sync a cache
 */
static void cachefiles_sync_cache(struct fscache_cache *_cache)
{
	struct cachefiles_cache *cache;
	int ret;

	_enter("%p", _cache);

	cache = container_of(_cache, struct cachefiles_cache, cache);

	/* make sure all pages pinned by operations on behalf of the netfs are
	 * written to disc */
	ret = fsync_super(cache->mnt->mnt_sb);
	if (ret == -EIO)
		cachefiles_io_error(cache,
				    "Attempt to sync backing fs superblock"
				    " returned error %d",
				    ret);

}

/*****************************************************************************/
/*
 * set the data size on an object
 */
static int cachefiles_set_i_size(struct fscache_object *_object, loff_t i_size)
{
	struct cachefiles_object *object;
	struct iattr newattrs;
	int ret;

	_enter("%p,%llu", _object, i_size);

	object = container_of(_object, struct cachefiles_object, fscache);

	if (i_size == object->i_size)
		return 0;

	if (!object->backer)
		return -ENOBUFS;

	ASSERT(S_ISREG(object->backer->d_inode->i_mode));

	newattrs.ia_size = i_size;
	newattrs.ia_valid = ATTR_SIZE;

	mutex_lock(&object->backer->d_inode->i_mutex);
	ret = notify_change(object->backer, &newattrs);
	mutex_unlock(&object->backer->d_inode->i_mutex);

	if (ret == -EIO) {
		cachefiles_io_error_obj(object, "Size set failed");
		ret = -ENOBUFS;
	}

	_leave(" = %d", ret);
	return ret;

}

/*****************************************************************************/
/*
 * see if we have space for a number of pages and/or a number of files in the
 * cache
 */
int cachefiles_has_space(struct cachefiles_cache *cache,
			 unsigned fnr, unsigned bnr)
{
	struct kstatfs stats;
	int ret;

	_enter("{%llu,%llu,%llu,%llu,%llu,%llu},%u,%u",
	       (unsigned long long) cache->frun,
	       (unsigned long long) cache->fcull,
	       (unsigned long long) cache->fstop,
	       (unsigned long long) cache->brun,
	       (unsigned long long) cache->bcull,
	       (unsigned long long) cache->bstop,
	       fnr, bnr);

	/* find out how many pages of blockdev are available */
	memset(&stats, 0, sizeof(stats));

	ret = cache->mnt->mnt_sb->s_op->statfs(cache->mnt->mnt_root, &stats);
	if (ret < 0) {
		if (ret == -EIO)
			cachefiles_io_error(cache, "statfs failed");
		return ret;
	}

	stats.f_bavail >>= cache->bshift;

	_debug("avail %llu,%llu",
	       (unsigned long long) stats.f_ffree,
	       (unsigned long long) stats.f_bavail);

	/* see if there is sufficient space */
	if (stats.f_ffree > fnr)
		stats.f_ffree -= fnr;
	else
		stats.f_ffree = 0;

	if (stats.f_bavail > bnr)
		stats.f_bavail -= bnr;
	else
		stats.f_bavail = 0;

	ret = -ENOBUFS;
	if (stats.f_ffree < cache->fstop ||
	    stats.f_bavail < cache->bstop)
		goto begin_cull;

	ret = 0;
	if (stats.f_ffree < cache->fcull ||
	    stats.f_bavail < cache->bcull)
		goto begin_cull;

	if (test_bit(CACHEFILES_CULLING, &cache->flags) &&
	    stats.f_ffree >= cache->frun &&
	    stats.f_bavail >= cache->brun
	    ) {
		if (test_and_clear_bit(CACHEFILES_CULLING, &cache->flags)) {
			_debug("cease culling");
			send_sigurg(&cache->cachefilesd->f_owner);
		}
	}

	_leave(" = 0");
	return 0;

begin_cull:
	if (!test_and_set_bit(CACHEFILES_CULLING, &cache->flags)) {
		_debug("### CULL CACHE ###");
		send_sigurg(&cache->cachefilesd->f_owner);
	}

	_leave(" = %d", ret);
	return ret;

}

/*****************************************************************************/
/*
 * waiting reading backing files
 */
static int cachefiles_read_waiter(wait_queue_t *wait, unsigned mode,
				  int sync, void *_key)
{
	struct cachefiles_one_read *monitor =
		container_of(wait, struct cachefiles_one_read, monitor);
	struct wait_bit_key *key = _key;
	struct page *page = wait->private;

	ASSERT(key);

	_enter("{%lu},%u,%d,{%p,%u}",
	       monitor->netfs_page->index, mode, sync,
	       key->flags, key->bit_nr);

	if (key->flags != &page->flags ||
	    key->bit_nr != PG_locked)
		return 0;

	_debug("--- monitor %p %lx ---", page, page->flags);

	if (!PageUptodate(page) && !PageError(page))
		dump_stack();

	/* remove from the waitqueue */
	list_del(&wait->task_list);

	/* move onto the action list and queue for keventd */
	ASSERT(monitor->object);

	spin_lock(&monitor->object->work_lock);
	list_move(&monitor->obj_link, &monitor->object->read_list);
	spin_unlock(&monitor->object->work_lock);

	schedule_work(&monitor->object->read_work);

	return 0;

}

/*****************************************************************************/
/*
 * let keventd drive the copying of pages
 */
void cachefiles_read_copier_work(void *_object)
{
	struct cachefiles_one_read *monitor;
	struct cachefiles_object *object = _object;
	struct fscache_cookie *cookie = object->fscache.cookie;
	struct pagevec pagevec;
	int error, max;

	_enter("{ino=%lu}", object->backer->d_inode->i_ino);

	pagevec_init(&pagevec, 0);

	max = 8;
	spin_lock_irq(&object->work_lock);

	while (!list_empty(&object->read_list)) {
		monitor = list_entry(object->read_list.next,
				     struct cachefiles_one_read, obj_link);
		list_del(&monitor->obj_link);

		spin_unlock_irq(&object->work_lock);

		_debug("- copy {%lu}", monitor->back_page->index);

		error = -EIO;
		if (PageUptodate(monitor->back_page)) {
			copy_highpage(monitor->netfs_page, monitor->back_page);

			pagevec_add(&pagevec, monitor->netfs_page);
			cookie->def->mark_pages_cached(
				cookie->netfs_data,
				monitor->netfs_page->mapping,
				&pagevec);
			pagevec_reinit(&pagevec);

			error = 0;
		}

		if (error)
			cachefiles_io_error_obj(
				object,
				"readpage failed on backing file %lx",
				(unsigned long) monitor->back_page->flags);

		page_cache_release(monitor->back_page);

		monitor->end_io_func(monitor->netfs_page,
				     monitor->context,
				     error);

		page_cache_release(monitor->netfs_page);
		fscache_put_context(cookie, monitor->context);
		kfree(monitor);

		/* let keventd have some air occasionally */
		max--;
		if (max < 0 || need_resched()) {
			if (!list_empty(&object->read_list))
				schedule_work(&object->read_work);
			_leave(" [maxed out]");
			return;
		}

		spin_lock_irq(&object->work_lock);
	}

	spin_unlock_irq(&object->work_lock);

	_leave("");

}

/*****************************************************************************/
/*
 * read the corresponding page to the given set from the backing file
 * - an uncertain page is simply discarded, to be tried again another time
 */
static int cachefiles_read_backing_file_one(struct cachefiles_object *object,
					    fscache_rw_complete_t end_io_func,
					    void *context,
					    struct page *netpage,
					    struct pagevec *lru_pvec)
{
	struct cachefiles_one_read *monitor;
	struct address_space *bmapping;
	struct page *newpage, *backpage;
	int ret;

	_enter("");

	ASSERTCMP(pagevec_count(lru_pvec), ==, 0);
	pagevec_reinit(lru_pvec);

	_debug("read back %p{%lu,%d}",
	       netpage, netpage->index, page_count(netpage));

	monitor = kzalloc(sizeof(*monitor), GFP_KERNEL);
	if (!monitor)
		goto nomem;

	monitor->netfs_page = netpage;
	monitor->object = object;
	monitor->end_io_func = end_io_func;
	monitor->context = fscache_get_context(object->fscache.cookie,
					       context);

	init_waitqueue_func_entry(&monitor->monitor, cachefiles_read_waiter);

	/* attempt to get hold of the backing page */
	bmapping = object->backer->d_inode->i_mapping;
	newpage = NULL;

	for (;;) {
		backpage = find_get_page(bmapping, netpage->index);
		if (backpage)
			goto backing_page_already_present;

		if (!newpage) {
			newpage = page_cache_alloc_cold(bmapping);
			if (!newpage)
				goto nomem_monitor;
		}

		ret = add_to_page_cache(newpage, bmapping,
					netpage->index, GFP_KERNEL);
		if (ret == 0)
			goto installed_new_backing_page;
		if (ret != -EEXIST)
			goto nomem_page;
	}

	/* we've installed a new backing page, so now we need to add it
	 * to the LRU list and start it reading */
installed_new_backing_page:
	_debug("- new %p", newpage);

	backpage = newpage;
	newpage = NULL;

	page_cache_get(backpage);
	pagevec_add(lru_pvec, backpage);
	__pagevec_lru_add(lru_pvec);

	ret = bmapping->a_ops->readpage(NULL, backpage);
	if (ret < 0)
		goto read_error;

	/* set the monitor to transfer the data across */
monitor_backing_page:
	_debug("- monitor add");

	/* install the monitor */
	page_cache_get(monitor->netfs_page);
	page_cache_get(backpage);
	monitor->back_page = backpage;

	spin_lock_irq(&object->work_lock);
	list_add_tail(&monitor->obj_link, &object->read_pend_list);
	spin_unlock_irq(&object->work_lock);

	monitor->monitor.private = backpage;
	install_page_waitqueue_monitor(backpage, &monitor->monitor);
	monitor = NULL;

	/* but the page may have been read before the monitor was
	 * installed, so the monitor may miss the event - so we have to
	 * ensure that we do get one in such a case */
	if (!TestSetPageLocked(backpage))
		unlock_page(backpage);
	goto success;

	/* if the backing page is already present, it can be in one of
	 * three states: read in progress, read failed or read okay */
backing_page_already_present:
	_debug("- present");

	if (newpage) {
		page_cache_release(newpage);
		newpage = NULL;
	}

	if (PageError(backpage))
		goto io_error;

	if (PageUptodate(backpage))
		goto backing_page_already_uptodate;

	goto monitor_backing_page;

	/* the backing page is already up to date, attach the netfs
	 * page to the pagecache and LRU and copy the data across */
backing_page_already_uptodate:
	_debug("- uptodate");

	copy_highpage(netpage, backpage);
	end_io_func(netpage, context, 0);

success:
	_debug("success");
	ret = 0;

out:
	if (backpage)
		page_cache_release(backpage);
	if (monitor) {
		fscache_put_context(object->fscache.cookie, monitor->context);
		kfree(monitor);
	}

	_leave(" = %d", ret);
	return ret;

read_error:
	_debug("read error %d", ret);
	if (ret == -ENOMEM)
		goto out;
io_error:
	cachefiles_io_error_obj(object, "page read error on backing file");
	ret = -EIO;
	goto out;

nomem_page:
	page_cache_release(newpage);
nomem_monitor:
	fscache_put_context(object->fscache.cookie, monitor->context);
	kfree(monitor);
nomem:
	_leave(" = -ENOMEM");
	return -ENOMEM;

}

/*****************************************************************************/
/*
 * read a page from the cache or allocate a block in which to store it
 * - cache withdrawal is prevented by the caller
 * - returns -EINTR if interrupted
 * - returns -ENOMEM if ran out of memory
 * - returns -ENOBUFS if no buffers can be made available
 * - returns -ENOBUFS if page is beyond EOF
 * - if the page is backed by a block in the cache:
 *   - a read will be started which will call the callback on completion
 *   - 0 will be returned
 * - else if the page is unbacked:
 *   - the metadata will be retained
 *   - -ENODATA will be returned
 */
static int cachefiles_read_or_alloc_page(struct fscache_object *_object,
					 struct page *page,
					 fscache_rw_complete_t end_io_func,
					 void *context,
					 unsigned long gfp)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;
	struct fscache_cookie *cookie;
	struct pagevec pagevec;
	struct inode *inode;
	sector_t block0, block;
	unsigned shift;
	int ret;

	object = container_of(_object, struct cachefiles_object, fscache);
	cache = container_of(object->fscache.cache, struct cachefiles_cache, cache);

	_enter("{%p},{%lx},,,", object, page->index);

	if (!object->backer)
		return -ENOBUFS;

	inode = object->backer->d_inode;
	ASSERT(S_ISREG(inode->i_mode));
	ASSERT(inode->i_mapping->a_ops->bmap);
	ASSERT(inode->i_mapping->a_ops->readpages);

	/* calculate the shift required to use bmap */
	if (inode->i_sb->s_blocksize > PAGE_SIZE)
		return -ENOBUFS;

	shift = PAGE_SHIFT - inode->i_sb->s_blocksize_bits;

	cookie = object->fscache.cookie;

	pagevec_init(&pagevec, 0);

	/* we assume the absence or presence of the first block is a good
	 * enough indication for the page as a whole
	 * - TODO: don't use bmap() for this as it is _not_ actually good
	 *   enough for this as it doesn't indicate errors, but it's all we've
	 *   got for the moment
	 */
	block0 = page->index;
	block0 <<= shift;

	block = inode->i_mapping->a_ops->bmap(inode->i_mapping, block0);
	_debug("%llx -> %llx",
	       (unsigned long long) block0,
	       (unsigned long long) block);

	if (block) {
		/* submit the apparently valid page to the backing fs to be
		 * read from disk */
		ret = cachefiles_read_backing_file_one(object,
						       end_io_func,
						       context,
						       page,
						       &pagevec);
		ret = 0;
	} else if (cachefiles_has_space(cache, 0, 1) == 0) {
		/* there's space in the cache we can use */
		pagevec_add(&pagevec, page);
		cookie->def->mark_pages_cached(cookie->netfs_data,
					       page->mapping, &pagevec);
		ret = -ENODATA;
	} else {
		ret = -ENOBUFS;
	}

	_leave(" = %d", ret);
	return ret;

}

/*****************************************************************************/
/*
 * read the corresponding pages to the given set from the backing file
 * - any uncertain pages are simply discarded, to be tried again another time
 */
static int cachefiles_read_backing_file(struct cachefiles_object *object,
					fscache_rw_complete_t end_io_func,
					void *context,
					struct address_space *mapping,
					struct list_head *list,
					struct pagevec *lru_pvec)
{
	struct cachefiles_one_read *monitor = NULL;
	struct address_space *bmapping = object->backer->d_inode->i_mapping;
	struct page *newpage = NULL, *netpage, *_n, *backpage = NULL;
	int ret = 0;

	_enter("");

	ASSERTCMP(pagevec_count(lru_pvec), ==, 0);
	pagevec_reinit(lru_pvec);

	list_for_each_entry_safe(netpage, _n, list, lru) {
		list_del(&netpage->lru);

		_debug("read back %p{%lu,%d}",
		       netpage, netpage->index, page_count(netpage));

		if (!monitor) {
			monitor = kzalloc(sizeof(*monitor), GFP_KERNEL);
			if (!monitor)
				goto nomem;

			monitor->object = object;
			monitor->end_io_func = end_io_func;
			monitor->context = fscache_get_context(
				object->fscache.cookie, context);

			init_waitqueue_func_entry(&monitor->monitor,
						  cachefiles_read_waiter);
		}

		for (;;) {
			backpage = find_get_page(bmapping, netpage->index);
			if (backpage)
				goto backing_page_already_present;

			if (!newpage) {
				newpage = page_cache_alloc_cold(bmapping);
				if (!newpage)
					goto nomem;
			}

			ret = add_to_page_cache(newpage, bmapping,
						netpage->index, GFP_KERNEL);
			if (ret == 0)
				goto installed_new_backing_page;
			if (ret != -EEXIST)
				goto nomem;
		}

		/* we've installed a new backing page, so now we need to add it
		 * to the LRU list and start it reading */
	installed_new_backing_page:
		_debug("- new %p", newpage);

		backpage = newpage;
		newpage = NULL;

		page_cache_get(backpage);
		if (!pagevec_add(lru_pvec, backpage))
			__pagevec_lru_add(lru_pvec);

	reread_backing_page:
		ret = bmapping->a_ops->readpage(NULL, backpage);
		if (ret < 0)
			goto read_error;

		/* add the netfs page to the pagecache and LRU, and set the
		 * monitor to transfer the data across */
	monitor_backing_page:
		_debug("- monitor add");

		ret = add_to_page_cache(netpage, mapping, netpage->index,
					GFP_KERNEL);
		if (ret < 0) {
			if (ret == -EEXIST) {
				page_cache_release(netpage);
				continue;
			}
			goto nomem;
		}

		page_cache_get(netpage);
		if (!pagevec_add(lru_pvec, netpage))
			__pagevec_lru_add(lru_pvec);

		/* install a monitor */
		page_cache_get(netpage);
		monitor->netfs_page = netpage;

		page_cache_get(backpage);
		monitor->back_page = backpage;

		spin_lock_irq(&object->work_lock);
		list_add_tail(&monitor->obj_link, &object->read_pend_list);
		spin_unlock_irq(&object->work_lock);

		monitor->monitor.private = backpage;
		install_page_waitqueue_monitor(backpage, &monitor->monitor);
		monitor = NULL;

		/* but the page may have been read before the monitor was
		 * installed, so the monitor may miss the event - so we have to
		 * ensure that we do get one in such a case */
		if (!TestSetPageLocked(backpage)) {
			_debug("2unlock %p", backpage);
			unlock_page(backpage);
		}

		page_cache_release(backpage);
		backpage = NULL;

		page_cache_release(netpage);
		netpage = NULL;
		continue;

		/* if the backing page is already present, it can be in one of
		 * three states: read in progress, read failed or read okay */
	backing_page_already_present:
		_debug("- present %p", backpage);

		if (PageError(backpage))
			goto io_error;

		if (PageUptodate(backpage))
			goto backing_page_already_uptodate;

		_debug("- not ready %p{%lx}", backpage, backpage->flags);

		if (TestSetPageLocked(backpage))
			goto monitor_backing_page;

		if (PageError(backpage)) {
			unlock_page(backpage);
			goto io_error;
		}

		if (PageUptodate(backpage))
			goto backing_page_already_uptodate_unlock;

		/* we've locked a page that's neither up to date nor erroneous,
		 * so we need to attempt to read it again */
		goto reread_backing_page;

		/* the backing page is already up to date, attach the netfs
		 * page to the pagecache and LRU and copy the data across */
	backing_page_already_uptodate_unlock:
		unlock_page(backpage);
	backing_page_already_uptodate:
		_debug("- uptodate");

		ret = add_to_page_cache(netpage, mapping, netpage->index,
					GFP_KERNEL);
		if (ret < 0) {
			if (ret == -EEXIST) {
				page_cache_release(netpage);
				continue;
			}
			goto nomem;
		}

		copy_highpage(netpage, backpage);

		page_cache_release(backpage);
		backpage = NULL;

		page_cache_get(netpage);
		if (!pagevec_add(lru_pvec, netpage))
			__pagevec_lru_add(lru_pvec);

		end_io_func(netpage, context, 0);

		page_cache_release(netpage);
		netpage = NULL;
		continue;
	}

	netpage = NULL;

	_debug("out");

out:
	/* tidy up */
	pagevec_lru_add(lru_pvec);

	if (newpage)
		page_cache_release(newpage);
	if (netpage)
		page_cache_release(netpage);
	if (backpage)
		page_cache_release(backpage);
	if (monitor) {
		fscache_put_context(object->fscache.cookie, monitor->context);
		kfree(monitor);
	}

	list_for_each_entry_safe(netpage, _n, list, lru) {
		list_del(&netpage->lru);
		page_cache_release(netpage);
	}

	_leave(" = %d", ret);
	return ret;

nomem:
	_debug("nomem");
	ret = -ENOMEM;
	goto out;

read_error:
	_debug("read error %d", ret);
	if (ret == -ENOMEM)
		goto out;
io_error:
	cachefiles_io_error_obj(object, "page read error on backing file");
	ret = -EIO;
	goto out;

}

/*****************************************************************************/
/*
 * read a list of pages from the cache or allocate blocks in which to store
 * them
 */
static int cachefiles_read_or_alloc_pages(struct fscache_object *_object,
					  struct address_space *mapping,
					  struct list_head *pages,
					  unsigned *nr_pages,
					  fscache_rw_complete_t end_io_func,
					  void *context,
					  unsigned long gfp)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;
	struct fscache_cookie *cookie;
	struct list_head backpages;
	struct pagevec pagevec;
	struct inode *inode;
	struct page *page, *_n;
	unsigned shift, nrbackpages;
	int ret, ret2, space;

	object = container_of(_object, struct cachefiles_object, fscache);
	cache = container_of(object->fscache.cache, struct cachefiles_cache, cache);

	_enter("{%p},,%d,,", object, *nr_pages);

	if (!object->backer)
		return -ENOBUFS;

	space = 1;
	if (cachefiles_has_space(cache, 0, *nr_pages) < 0)
		space = 0;

	inode = object->backer->d_inode;
	ASSERT(S_ISREG(inode->i_mode));
	ASSERT(inode->i_mapping->a_ops->bmap);
	ASSERT(inode->i_mapping->a_ops->readpages);

	/* calculate the shift required to use bmap */
	if (inode->i_sb->s_blocksize > PAGE_SIZE)
		return -ENOBUFS;

	shift = PAGE_SHIFT - inode->i_sb->s_blocksize_bits;

	pagevec_init(&pagevec, 0);

	cookie = object->fscache.cookie;

	INIT_LIST_HEAD(&backpages);
	nrbackpages = 0;

	ret = space ? -ENODATA : -ENOBUFS;
	list_for_each_entry_safe(page, _n, pages, lru) {
		sector_t block0, block;

		/* we assume the absence or presence of the first block is a
		 * good enough indication for the page as a whole
		 * - TODO: don't use bmap() for this as it is _not_ actually
		 *   good enough for this as it doesn't indicate errors, but
		 *   it's all we've got for the moment
		 */
		block0 = page->index;
		block0 <<= shift;

		block = inode->i_mapping->a_ops->bmap(inode->i_mapping,
						      block0);
		_debug("%llx -> %llx",
		       (unsigned long long) block0,
		       (unsigned long long) block);

		if (block) {
			/* we have data - add it to the list to give to the
			 * backing fs */
			list_move(&page->lru, &backpages);
			(*nr_pages)--;
			nrbackpages++;
		} else if (space && pagevec_add(&pagevec, page) == 0) {
			cookie->def->mark_pages_cached(cookie->netfs_data,
						       mapping, &pagevec);
			pagevec_reinit(&pagevec);
			ret = -ENODATA;
		}
	}

	if (pagevec_count(&pagevec) > 0) {
		cookie->def->mark_pages_cached(cookie->netfs_data,
					       mapping, &pagevec);
		pagevec_reinit(&pagevec);
	}

	if (list_empty(pages))
		ret = 0;

	/* submit the apparently valid pages to the backing fs to be read from disk */
	if (nrbackpages > 0) {
		ret2 = cachefiles_read_backing_file(object,
						    end_io_func,
						    context,
						    mapping,
						    &backpages,
						    &pagevec);

		ASSERTCMP(pagevec_count(&pagevec), ==, 0);

		if (ret2 == -ENOMEM || ret2 == -EINTR)
			ret = ret2;
	}

	_leave(" = %d [nr=%u%s]",
	       ret, *nr_pages, list_empty(pages) ? " empty" : "");
	return ret;

}

/*****************************************************************************/
/*
 * read a page from the cache or allocate a block in which to store it
 * - cache withdrawal is prevented by the caller
 * - returns -EINTR if interrupted
 * - returns -ENOMEM if ran out of memory
 * - returns -ENOBUFS if no buffers can be made available
 * - returns -ENOBUFS if page is beyond EOF
 * - otherwise:
 *   - the metadata will be retained
 *   - 0 will be returned
 */
static int cachefiles_allocate_page(struct fscache_object *_object,
				    struct page *page,
				    unsigned long gfp)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;

	object = container_of(_object, struct cachefiles_object, fscache);
	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	_enter("%p,{%lx},,,", object, page->index);

	return cachefiles_has_space(cache, 0, 1);

}

/*****************************************************************************/
/*
 * page storer
 */
void cachefiles_write_work(void *_object)
{
	struct cachefiles_one_write *writer;
	struct cachefiles_object *object = _object;
	int ret, max;

	_enter("%p", object);

	ASSERT(!irqs_disabled());

	spin_lock_irq(&object->work_lock);
	max = 8;

	while (!list_empty(&object->write_list)) {
		writer = list_entry(object->write_list.next,
				    struct cachefiles_one_write, obj_link);
		list_del(&writer->obj_link);

		spin_unlock_irq(&object->work_lock);

		_debug("- store {%lu}", writer->netfs_page->index);

		ret = generic_file_buffered_write_one_kernel_page(
			object->backer->d_inode->i_mapping,
			writer->netfs_page->index,
			writer->netfs_page);

		if (ret == -ENOSPC) {
			ret = -ENOBUFS;
		} else if (ret == -EIO) {
			cachefiles_io_error_obj(object,
						"write page to backing file"
						" failed");
			ret = -ENOBUFS;
		}

		_debug("- callback");
		writer->end_io_func(writer->netfs_page,
				    writer->context,
				    ret);

		_debug("- put net");
		page_cache_release(writer->netfs_page);
		fscache_put_context(object->fscache.cookie, writer->context);
		kfree(writer);

		/* let keventd have some air occasionally */
		max--;
		if (max < 0 || need_resched()) {
			if (!list_empty(&object->write_list))
				schedule_work(&object->write_work);
			_leave(" [maxed out]");
			return;
		}

		_debug("- next");
		spin_lock_irq(&object->work_lock);
	}

	spin_unlock_irq(&object->work_lock);
	_leave("");

}

/*****************************************************************************/
/*
 * request a page be stored in the cache
 * - cache withdrawal is prevented by the caller
 * - this request may be ignored if there's no cache block available, in which
 *   case -ENOBUFS will be returned
 * - if the op is in progress, 0 will be returned
 */
static int cachefiles_write_page(struct fscache_object *_object,
				 struct page *page,
				 fscache_rw_complete_t end_io_func,
				 void *context,
				 unsigned long gfp)
{
//	struct cachefiles_one_write *writer;
	struct cachefiles_object *object;
	int ret;

	object = container_of(_object, struct cachefiles_object, fscache);

	_enter("%p,%p{%lx},,,", object, page, page->index);

	if (!object->backer)
		return -ENOBUFS;

	ASSERT(S_ISREG(object->backer->d_inode->i_mode));

#if 0 // set to 1 for deferred writing
	/* queue the operation for deferred processing by keventd */
	writer = kzalloc(sizeof(*writer), GFP_KERNEL);
	if (!writer)
		return -ENOMEM;

	page_cache_get(page);
	writer->netfs_page = page;
	writer->object = object;
	writer->end_io_func = end_io_func;
	writer->context = facache_get_context(object->fscache.cookie, context);

	spin_lock_irq(&object->work_lock);
	list_add_tail(&writer->obj_link, &object->write_list);
	spin_unlock_irq(&object->work_lock);

	schedule_work(&object->write_work);
	ret = 0;

#else
	/* copy the page to ext3 and let it store it in its own time */
	ret = generic_file_buffered_write_one_kernel_page(
		object->backer->d_inode->i_mapping, page->index, page);

	if (ret != 0) {
		if (ret == -EIO)
			cachefiles_io_error_obj(object,
						"write page to backing file"
						" failed");
		ret = -ENOBUFS;
	} else {
		/* only invoke the callback if successful, we return the error
		 * directly otherwise */
		end_io_func(page, context, ret);
	}
#endif

	_leave(" = %d", ret);
	return ret;

}

/*****************************************************************************/
/*
 * detach a backing block from a page
 * - cache withdrawal is prevented by the caller
 */
static void cachefiles_uncache_pages(struct fscache_object *_object,
				     struct pagevec *pagevec)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;

	object = container_of(_object, struct cachefiles_object, fscache);
	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	_enter("%p,{%lu,%lx},,,",
	       object, pagevec->nr, pagevec->pages[0]->index);

}

/*****************************************************************************/
/*
 * dissociate a cache from all the pages it was backing
 */
static void cachefiles_dissociate_pages(struct fscache_cache *cache)
{
	_enter("");

}

struct fscache_cache_ops cachefiles_cache_ops = {
	.name			= "cachefiles",
	.lookup_object		= cachefiles_lookup_object,
	.grab_object		= cachefiles_grab_object,
	.lock_object		= cachefiles_lock_object,
	.unlock_object		= cachefiles_unlock_object,
	.update_object		= cachefiles_update_object,
	.put_object		= cachefiles_put_object,
	.sync_cache		= cachefiles_sync_cache,
	.set_i_size		= cachefiles_set_i_size,
	.read_or_alloc_page	= cachefiles_read_or_alloc_page,
	.read_or_alloc_pages	= cachefiles_read_or_alloc_pages,
	.allocate_page		= cachefiles_allocate_page,
	.write_page		= cachefiles_write_page,
	.uncache_pages		= cachefiles_uncache_pages,
	.dissociate_pages	= cachefiles_dissociate_pages,
};
