/* vnode.c: AFS vnode management
 *
 * Copyright (C) 2002 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include "volume.h"
#include "cell.h"
#include "cmservice.h"
#include "fsclient.h"
#include "vlclient.h"
#include "vnode.h"
#include "internal.h"

static void afs_vnode_cb_timed_out(struct afs_timer *timer);

struct afs_timer_ops afs_vnode_cb_timed_out_ops = {
	.timed_out	= afs_vnode_cb_timed_out,
};

#ifdef CONFIG_AFS_FSCACHE
static uint16_t afs_vnode_cache_get_key(const void *cookie_netfs_data,
					void *buffer, uint16_t buflen);
static void afs_vnode_cache_get_attr(const void *cookie_netfs_data,
				     uint64_t *size);
static uint16_t afs_vnode_cache_get_aux(const void *cookie_netfs_data,
					void *buffer, uint16_t buflen);
static fscache_checkaux_t afs_vnode_cache_check_aux(void *cookie_netfs_data,
						    const void *buffer,
						    uint16_t buflen);
static void afs_vnode_cache_mark_pages_cached(void *cookie_netfs_data,
					      struct address_space *mapping,
					      struct pagevec *cached_pvec);
static void afs_vnode_cache_now_uncached(void *cookie_netfs_data);

struct fscache_cookie_def afs_vnode_cache_index_def = {
	.name			= "AFS.vnode",
	.type			= FSCACHE_COOKIE_TYPE_DATAFILE,
	.get_key		= afs_vnode_cache_get_key,
	.get_attr		= afs_vnode_cache_get_attr,
	.get_aux		= afs_vnode_cache_get_aux,
	.check_aux		= afs_vnode_cache_check_aux,
	.mark_pages_cached	= afs_vnode_cache_mark_pages_cached,
	.now_uncached		= afs_vnode_cache_now_uncached,
};
#endif

/*****************************************************************************/
/*
 * handle a callback timing out
 * TODO: retain a ref to vnode struct for an outstanding callback timeout
 */
static void afs_vnode_cb_timed_out(struct afs_timer *timer)
{
	struct afs_server *oldserver;
	struct afs_vnode *vnode;

	vnode = list_entry(timer, struct afs_vnode, cb_timeout);

	_enter("%p", vnode);

	/* set the changed flag in the vnode and release the server */
	spin_lock(&vnode->lock);

	oldserver = xchg(&vnode->cb_server, NULL);
	if (oldserver) {
		vnode->flags |= AFS_VNODE_CHANGED;

		spin_lock(&afs_cb_hash_lock);
		list_del_init(&vnode->cb_hash_link);
		spin_unlock(&afs_cb_hash_lock);

		spin_lock(&oldserver->cb_lock);
		list_del_init(&vnode->cb_link);
		spin_unlock(&oldserver->cb_lock);
	}

	spin_unlock(&vnode->lock);

	afs_put_server(oldserver);

	_leave("");
} /* end afs_vnode_cb_timed_out() */

/*****************************************************************************/
/*
 * finish off updating the recorded status of a file
 * - starts callback expiry timer
 * - adds to server's callback list
 */
static void afs_vnode_finalise_status_update(struct afs_vnode *vnode,
					     struct afs_server *server,
					     int ret)
{
	struct afs_server *oldserver = NULL;

	_enter("%p,%p,%d", vnode, server, ret);

	spin_lock(&vnode->lock);

	vnode->flags &= ~AFS_VNODE_CHANGED;

	if (ret == 0) {
		/* adjust the callback timeout appropriately */
		afs_kafstimod_add_timer(&vnode->cb_timeout,
					vnode->cb_expiry * HZ);

		spin_lock(&afs_cb_hash_lock);
		list_move_tail(&vnode->cb_hash_link,
			      &afs_cb_hash(server, &vnode->fid));
		spin_unlock(&afs_cb_hash_lock);

		/* swap ref to old callback server with that for new callback
		 * server */
		oldserver = xchg(&vnode->cb_server, server);
		if (oldserver != server) {
			if (oldserver) {
				spin_lock(&oldserver->cb_lock);
				list_del_init(&vnode->cb_link);
				spin_unlock(&oldserver->cb_lock);
			}

			afs_get_server(server);
			spin_lock(&server->cb_lock);
			list_add_tail(&vnode->cb_link, &server->cb_promises);
			spin_unlock(&server->cb_lock);
		}
		else {
			/* same server */
			oldserver = NULL;
		}
	}
	else if (ret == -ENOENT) {
		/* the file was deleted - clear the callback timeout */
		oldserver = xchg(&vnode->cb_server, NULL);
		afs_kafstimod_del_timer(&vnode->cb_timeout);

		_debug("got NOENT from server - marking file deleted");
		vnode->flags |= AFS_VNODE_DELETED;
	}

	vnode->update_cnt--;

	spin_unlock(&vnode->lock);

	wake_up_all(&vnode->update_waitq);

	afs_put_server(oldserver);

	_leave("");

} /* end afs_vnode_finalise_status_update() */

/*****************************************************************************/
/*
 * fetch file status from the volume
 * - don't issue a fetch if:
 *   - the changed bit is not set and there's a valid callback
 *   - there are any outstanding ops that will fetch the status
 * - TODO implement local caching
 */
int afs_vnode_fetch_status(struct afs_vnode *vnode)
{
	struct afs_server *server;
	int ret;

	DECLARE_WAITQUEUE(myself, current);

	_enter("%s,{%u,%u,%u}",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid, vnode->fid.vnode, vnode->fid.unique);

	if (!(vnode->flags & AFS_VNODE_CHANGED) && vnode->cb_server) {
		_leave(" [unchanged]");
		return 0;
	}

	if (vnode->flags & AFS_VNODE_DELETED) {
		_leave(" [deleted]");
		return -ENOENT;
	}

	spin_lock(&vnode->lock);

	if (!(vnode->flags & AFS_VNODE_CHANGED)) {
		spin_unlock(&vnode->lock);
		_leave(" [unchanged]");
		return 0;
	}

	if (vnode->update_cnt > 0) {
		/* someone else started a fetch */
		_debug("conflict");

		set_current_state(TASK_UNINTERRUPTIBLE);
		add_wait_queue(&vnode->update_waitq, &myself);

		/* wait for the status to be updated */
		for (;;) {
			if (!(vnode->flags & AFS_VNODE_CHANGED))
				break;
			if (vnode->flags & AFS_VNODE_DELETED)
				break;

			/* it got updated and invalidated all before we saw
			 * it */
			if (vnode->update_cnt == 0) {
				remove_wait_queue(&vnode->update_waitq,
						  &myself);
				set_current_state(TASK_RUNNING);
				goto get_anyway;
			}

			spin_unlock(&vnode->lock);

			schedule();
			set_current_state(TASK_UNINTERRUPTIBLE);

			spin_lock(&vnode->lock);
		}

		remove_wait_queue(&vnode->update_waitq, &myself);
		spin_unlock(&vnode->lock);
		set_current_state(TASK_RUNNING);

		_leave(" [conflicted, %d", !!(vnode->flags & AFS_VNODE_DELETED));
		return vnode->flags & AFS_VNODE_DELETED ? -ENOENT : 0;
	}

 get_anyway:
	/* okay... we're going to have to initiate the op */
	vnode->update_cnt++;

	spin_unlock(&vnode->lock);

	/* merge AFS status fetches and clear outstanding callback on this
	 * vnode */
	do {
		/* pick a server to query */
		ret = afs_volume_pick_fileserver(vnode->volume, &server);
		if (ret<0)
			return ret;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_rxfs_fetch_file_status(server, vnode, NULL);

	} while (!afs_volume_release_fileserver(vnode->volume, server, ret));

	/* adjust the flags */
	afs_vnode_finalise_status_update(vnode, server, ret);

	_leave(" = %d", ret);
	return ret;
} /* end afs_vnode_fetch_status() */

/*****************************************************************************/
/*
 * fetch file data from the volume
 * - TODO implement caching and server failover
 */
int afs_vnode_fetch_data(struct afs_vnode *vnode,
			 struct afs_rxfs_fetch_descriptor *desc)
{
	struct afs_server *server;
	int ret;

	_enter("%s,{%u,%u,%u}",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique);

	/* this op will fetch the status */
	spin_lock(&vnode->lock);
	vnode->update_cnt++;
	spin_unlock(&vnode->lock);

	/* merge in AFS status fetches and clear outstanding callback on this
	 * vnode */
	do {
		/* pick a server to query */
		ret = afs_volume_pick_fileserver(vnode->volume, &server);
		if (ret < 0)
			return ret;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_rxfs_fetch_file_data(server, vnode, desc, NULL);

	} while (!afs_volume_release_fileserver(vnode->volume, server, ret));

	/* adjust the flags */
	afs_vnode_finalise_status_update(vnode, server, ret);

	_leave(" = %d", ret);
	return ret;

} /* end afs_vnode_fetch_data() */

/*****************************************************************************/
/*
 * break any outstanding callback on a vnode
 * - only relevent to server that issued it
 */
int afs_vnode_give_up_callback(struct afs_vnode *vnode)
{
	struct afs_server *server;
	int ret;

	_enter("%s,{%u,%u,%u}",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique);

	spin_lock(&afs_cb_hash_lock);
	list_del_init(&vnode->cb_hash_link);
	spin_unlock(&afs_cb_hash_lock);

	/* set the changed flag in the vnode and release the server */
	spin_lock(&vnode->lock);

	afs_kafstimod_del_timer(&vnode->cb_timeout);

	server = xchg(&vnode->cb_server, NULL);
	if (server) {
		vnode->flags |= AFS_VNODE_CHANGED;

		spin_lock(&server->cb_lock);
		list_del_init(&vnode->cb_link);
		spin_unlock(&server->cb_lock);
	}

	spin_unlock(&vnode->lock);

	ret = 0;
	if (server) {
		ret = afs_rxfs_give_up_callback(server, vnode);
		afs_put_server(server);
	}

	_leave(" = %d", ret);
	return ret;
} /* end afs_vnode_give_up_callback() */

/*****************************************************************************/
/*
 * set the key for the index entry
 */
#ifdef CONFIG_AFS_FSCACHE
static uint16_t afs_vnode_cache_get_key(const void *cookie_netfs_data,
					void *buffer, uint16_t bufmax)
{
	const struct afs_vnode *vnode = cookie_netfs_data;
	uint16_t klen;

	_enter("{%x,%x,%Lx},%p,%u",
	       vnode->fid.vnode, vnode->fid.unique, vnode->status.version,
	       buffer, bufmax);

	klen = sizeof(vnode->fid.vnode);
	if (klen > bufmax)
		return 0;

	memcpy(buffer, &vnode->fid.vnode, sizeof(vnode->fid.vnode));

	_leave(" = %u", klen);
	return klen;

} /* end afs_vnode_cache_get_key() */
#endif

/*****************************************************************************/
/*
 * provide an updated file attributes
 */
#ifdef CONFIG_AFS_FSCACHE
static void afs_vnode_cache_get_attr(const void *cookie_netfs_data,
				     uint64_t *size)
{
	const struct afs_vnode *vnode = cookie_netfs_data;

	_enter("{%x,%x,%Lx},",
	       vnode->fid.vnode, vnode->fid.unique, vnode->status.version);

	*size = i_size_read((struct inode *) &vnode->vfs_inode);

} /* end afs_vnode_cache_get_attr() */
#endif

/*****************************************************************************/
/*
 * provide new auxilliary cache data
 */
#ifdef CONFIG_AFS_FSCACHE
static uint16_t afs_vnode_cache_get_aux(const void *cookie_netfs_data,
					void *buffer, uint16_t bufmax)
{
	const struct afs_vnode *vnode = cookie_netfs_data;
	uint16_t dlen;

	_enter("{%x,%x,%Lx},%p,%u",
	       vnode->fid.vnode, vnode->fid.unique, vnode->status.version,
	       buffer, bufmax);

	dlen = sizeof(vnode->fid.unique) + sizeof(vnode->status.version);
	if (dlen > bufmax)
		return 0;

	memcpy(buffer, &vnode->fid.unique, sizeof(vnode->fid.unique));
	buffer += sizeof(vnode->fid.unique);
	memcpy(buffer, &vnode->status.version, sizeof(vnode->status.version));

	_leave(" = %u", dlen);
	return dlen;

} /* end afs_vnode_cache_get_aux() */
#endif

/*****************************************************************************/
/*
 * check that the auxilliary data indicates that the entry is still valid
 */
#ifdef CONFIG_AFS_FSCACHE
static fscache_checkaux_t afs_vnode_cache_check_aux(void *cookie_netfs_data,
						    const void *buffer,
						    uint16_t buflen)
{
	struct afs_vnode *vnode = cookie_netfs_data;
	uint16_t dlen;

	_enter("{%x,%x,%Lx},%p,%u",
	       vnode->fid.vnode, vnode->fid.unique, vnode->status.version,
	       buffer, buflen);

	/* check the size of the data is what we're expecting */
	dlen = sizeof(vnode->fid.unique) + sizeof(vnode->status.version);
	if (dlen != buflen) {
		_leave(" = OBSOLETE [len %hx != %hx]", dlen, buflen);
		return FSCACHE_CHECKAUX_OBSOLETE;
	}

	if (memcmp(buffer,
		   &vnode->fid.unique,
		   sizeof(vnode->fid.unique)
		   ) != 0
	    ) {
		unsigned unique;

		memcpy(&unique, buffer, sizeof(unique));

		_leave(" = OBSOLETE [uniq %x != %x]",
		       unique, vnode->fid.unique);
		return FSCACHE_CHECKAUX_OBSOLETE;
	}

	if (memcmp(buffer + sizeof(vnode->fid.unique),
		   &vnode->status.version,
		   sizeof(vnode->status.version)
		   ) != 0
	    ) {
		afs_dataversion_t version;

		memcpy(&version, buffer + sizeof(vnode->fid.unique),
		       sizeof(version));

		_leave(" = OBSOLETE [vers %llx != %llx]",
		       version, vnode->status.version);
		return FSCACHE_CHECKAUX_OBSOLETE;
	}

	_leave(" = SUCCESS");
	return FSCACHE_CHECKAUX_OKAY;

} /* end afs_vnode_cache_check_aux() */
#endif

/*****************************************************************************/
/*
 * indication of pages that now have cache metadata retained
 * - this function should mark the specified pages as now being cached
 */
#ifdef CONFIG_AFS_FSCACHE
static void afs_vnode_cache_mark_pages_cached(void *cookie_netfs_data,
					      struct address_space *mapping,
					      struct pagevec *cached_pvec)
{
	unsigned long loop;

	for (loop = 0; loop < cached_pvec->nr; loop++) {
		struct page *page = cached_pvec->pages[loop];

		_debug("- mark %p{%lx}", page, page->index);

		SetPagePrivate(page);
	}

} /* end afs_vnode_cache_mark_pages_cached() */
#endif

/*****************************************************************************/
/*
 * indication the cookie is no longer uncached
 * - this function is called when the backing store currently caching a cookie
 *   is removed
 * - the netfs should use this to clean up any markers indicating cached pages
 * - this is mandatory for any object that may have data
 */
static void afs_vnode_cache_now_uncached(void *cookie_netfs_data)
{
	struct afs_vnode *vnode = cookie_netfs_data;
	struct pagevec pvec;
	pgoff_t first;
	int loop, nr_pages;

	_enter("{%x,%x,%Lx}",
	       vnode->fid.vnode, vnode->fid.unique, vnode->status.version);

	pagevec_init(&pvec, 0);
	first = 0;

	for (;;) {
		/* grab a bunch of pages to clean */
		nr_pages = pagevec_lookup(&pvec, vnode->vfs_inode.i_mapping,
					  first,
					  PAGEVEC_SIZE - pagevec_count(&pvec));
		if (!nr_pages)
			break;

		for (loop = 0; loop < nr_pages; loop++)
			ClearPagePrivate(pvec.pages[loop]);

		first = pvec.pages[nr_pages - 1]->index + 1;

		pvec.nr = nr_pages;
		pagevec_release(&pvec);
		cond_resched();
	}

	_leave("");

} /* end afs_vnode_cache_now_uncached() */
