/* file.c: AFS filesystem file handling
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
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/buffer_head.h>
#include "volume.h"
#include "vnode.h"
#include <rxrpc/call.h>
#include "internal.h"

#define list_to_page(head) (list_entry((head)->prev, struct page, lru))

#if 0
static int afs_file_open(struct inode *inode, struct file *file);
static int afs_file_release(struct inode *inode, struct file *file);
#endif

static int afs_file_readpage(struct file *file, struct page *page);
static void afs_file_invalidatepage(struct page *page, unsigned long offset);
static int afs_file_releasepage(struct page *page, gfp_t gfp_flags);
static int afs_file_mmap(struct file * file, struct vm_area_struct * vma);

#ifdef CONFIG_AFS_FSCACHE
static int afs_file_readpages(struct file *filp, struct address_space *mapping,
			      struct list_head *pages, unsigned nr_pages);
static int afs_file_page_mkwrite(struct vm_area_struct *vma, struct page *page);
#endif

struct inode_operations afs_file_inode_operations = {
	.getattr	= afs_inode_getattr,
};

const struct file_operations afs_file_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_file_read,
	.mmap		= afs_file_mmap,
	.sendfile	= generic_file_sendfile,
};

const struct address_space_operations afs_fs_aops = {
	.readpage	= afs_file_readpage,
#ifdef CONFIG_AFS_FSCACHE
	.readpages	= afs_file_readpages,
#endif
	.sync_page	= block_sync_page,
	.set_page_dirty	= __set_page_dirty_nobuffers,
	.releasepage	= afs_file_releasepage,
	.invalidatepage	= afs_file_invalidatepage,
};

static struct vm_operations_struct afs_fs_vm_operations = {
	.nopage		= filemap_nopage,
	.populate	= filemap_populate,
#ifdef CONFIG_AFS_FSCACHE
	.page_mkwrite	= afs_file_page_mkwrite,
#endif
};

/*****************************************************************************/
/*
 * set up a memory mapping on an AFS file
 * - we set our own VMA ops so that we can catch the page becoming writable for
 *   userspace for shared-writable mmap
 */
static int afs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	_enter("");

	file_accessed(file);
	vma->vm_ops = &afs_fs_vm_operations;
	return 0;

} /* end afs_file_mmap() */

/*****************************************************************************/
/*
 * deal with notification that a page was read from the cache
 */
#ifdef CONFIG_AFS_FSCACHE
static void afs_file_readpage_read_complete(struct page *page,
					    void *data,
					    int error)
{
	_enter("%p,%p,%d", page, data, error);

	/* if the read completes with an error, we just unlock the page and let
	 * the VM reissue the readpage */
	if (!error)
		SetPageUptodate(page);
	unlock_page(page);

} /* end afs_file_readpage_read_complete() */
#endif

/*****************************************************************************/
/*
 * deal with notification that a page was written to the cache
 */
#ifdef CONFIG_AFS_FSCACHE
static void afs_file_readpage_write_complete(struct page *page,
					     void *data,
					     int error)
{
	_enter("%p,%p,%d", page, data, error);

	/* note that the page has been written to the cache and can now be
	 * modified */
	end_page_fs_misc(page);

} /* end afs_file_readpage_write_complete() */
#endif

/*****************************************************************************/
/*
 * AFS read page from file (or symlink)
 */
static int afs_file_readpage(struct file *file, struct page *page)
{
	struct afs_rxfs_fetch_descriptor desc;
	struct afs_vnode *vnode;
	struct inode *inode;
	int ret;

	inode = page->mapping->host;

	_enter("{%lu},%p{%lu}", inode->i_ino, page, page->index);

	vnode = AFS_FS_I(inode);

	BUG_ON(!PageLocked(page));

	ret = -ESTALE;
	if (vnode->flags & AFS_VNODE_DELETED)
		goto error;

#ifdef CONFIG_AFS_FSCACHE
	/* is it cached? */
	ret = fscache_read_or_alloc_page(vnode->cache,
					 page,
					 afs_file_readpage_read_complete,
					 NULL,
					 GFP_KERNEL);
#else
	ret = -ENOBUFS;
#endif

	switch (ret) {
		/* read BIO submitted (page in cache) */
	case 0:
		break;

		/* page not yet cached */
	case -ENODATA:
		_debug("cache said ENODATA");
		goto go_on;

		/* page will not be cached */
	case -ENOBUFS:
		_debug("cache said ENOBUFS");
	default:
	go_on:
		desc.fid	= vnode->fid;
		desc.offset	= page->index << PAGE_CACHE_SHIFT;
		desc.size	= min((size_t) (inode->i_size - desc.offset),
				      (size_t) PAGE_SIZE);
		desc.buffer	= kmap(page);

		clear_page(desc.buffer);

		/* read the contents of the file from the server into the
		 * page */
		ret = afs_vnode_fetch_data(vnode, &desc);
		kunmap(page);
		if (ret < 0) {
			if (ret == -ENOENT) {
				kdebug("got NOENT from server"
				       " - marking file deleted and stale");
				vnode->flags |= AFS_VNODE_DELETED;
				ret = -ESTALE;
			}

#ifdef CONFIG_AFS_FSCACHE
			fscache_uncache_page(vnode->cache, page);
			ClearPagePrivate(page);
#endif
			goto error;
		}

		SetPageUptodate(page);

		/* send the page to the cache */
#ifdef CONFIG_AFS_FSCACHE
		if (PagePrivate(page)) {
			if (TestSetPageFsMisc(page))
				BUG();
			if (fscache_write_page(vnode->cache,
					       page,
					       afs_file_readpage_write_complete,
					       NULL,
					       GFP_KERNEL) != 0
			    ) {
				fscache_uncache_page(vnode->cache, page);
				ClearPagePrivate(page);
				end_page_fs_misc(page);
			}
		}
#endif
		unlock_page(page);
	}

	_leave(" = 0");
	return 0;

 error:
	SetPageError(page);
	unlock_page(page);

	_leave(" = %d", ret);
	return ret;

} /* end afs_file_readpage() */

/*****************************************************************************/
/*
 * read a set of pages
 */
#ifdef CONFIG_AFS_FSCACHE
static int afs_file_readpages(struct file *filp, struct address_space *mapping,
			      struct list_head *pages, unsigned nr_pages)
{
	struct afs_vnode *vnode;
#if 0
	struct pagevec lru_pvec;
	unsigned page_idx;
#endif
	int ret = 0;

	_enter(",{%lu},,%d", mapping->host->i_ino, nr_pages);

	vnode = AFS_FS_I(mapping->host);
	if (vnode->flags & AFS_VNODE_DELETED) {
		_leave(" = -ESTALE");
		return -ESTALE;
	}

	/* attempt to read as many of the pages as possible */
	ret = fscache_read_or_alloc_pages(vnode->cache,
					  mapping,
					  pages,
					  &nr_pages,
					  afs_file_readpage_read_complete,
					  NULL,
					  mapping_gfp_mask(mapping));

	switch (ret) {
		/* all pages are being read from the cache */
	case 0:
		BUG_ON(!list_empty(pages));
		BUG_ON(nr_pages != 0);
		_leave(" = 0 [reading all]");
		return 0;

		/* there were pages that couldn't be read from the cache */
	case -ENODATA:
	case -ENOBUFS:
		break;

		/* other error */
	default:
		_leave(" = %d", ret);
		return ret;
	}

	/* load the missing pages from the network */
	ret = read_cache_pages(mapping, pages,
			       (void *) afs_file_readpage, NULL);

	_leave(" = %d [netting]", ret);
	return ret;

} /* end afs_file_readpages() */
#endif

/*****************************************************************************/
/*
 * invalidate part or all of a page
 */
static void afs_file_invalidatepage(struct page *page, unsigned long offset)
{
	_enter("{%lu},%lu", page->index, offset);

	BUG_ON(!PageLocked(page));

	if (PagePrivate(page)) {
		/* We release buffers only if the entire page is being
		 * invalidated.
		 * The get_block cached value has been unconditionally
		 * invalidated, so real IO is not possible anymore.
		 */
		if (offset == 0 && !PageWriteback(page))
			page->mapping->a_ops->releasepage(page, 0);
	}

	_leave("");

} /* end afs_file_invalidatepage() */

/*****************************************************************************/
/*
 * release a page and cleanup its private data
 */
static int afs_file_releasepage(struct page *page, gfp_t gfp_flags)
{
	_enter("{%lu},%x", page->index, gfp_flags);

#ifdef CONFIG_AFS_FSCACHE
	wait_on_page_fs_misc(page);
	fscache_uncache_page(AFS_FS_I(page->mapping->host)->cache, page);
	ClearPagePrivate(page);
#endif

	/* indicate that the page can be released */
	_leave(" = 1");
	return 1;

} /* end afs_file_releasepage() */

/*****************************************************************************/
/*
 * wait for the disc cache to finish writing before permitting modification of
 * our page in the page cache
 */
#ifdef CONFIG_AFS_FSCACHE
static int afs_file_page_mkwrite(struct vm_area_struct *vma, struct page *page)
{
	wait_on_page_fs_misc(page);
	return 0;

} /* end afs_file_page_mkwrite() */
#endif
