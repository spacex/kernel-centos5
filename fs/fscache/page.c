/* page.c: general filesystem cache cookie management
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
#include <linux/fscache-cache.h>
#include <linux/buffer_head.h>
#include <linux/pagevec.h>
#include "fscache-int.h"

/*****************************************************************************/
/*
 * set the data file size on an object in the cache
 */
int __fscache_set_i_size(struct fscache_cookie *cookie, loff_t i_size)
{
	struct fscache_object *object;
	int ret;

	_enter("%p,%llu,", cookie, i_size);

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

		/* prevent the cache from being withdrawn */
		if (object->cache->ops->set_i_size &&
		    fscache_operation_lock(object)
		    ) {
			if (object->cache->ops->grab_object(object)) {
				/* ask the cache to honour the operation */
				ret = object->cache->ops->set_i_size(object,
								     i_size);

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

EXPORT_SYMBOL(__fscache_set_i_size);

/*****************************************************************************/
/*
 * reserve space for an object
 */
int __fscache_reserve_space(struct fscache_cookie *cookie, loff_t size)
{
	struct fscache_object *object;
	int ret;

	_enter("%p,%llu,", cookie, size);

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

		if (!object->cache->ops->reserve_space) {
			ret = -EOPNOTSUPP;
			goto out;
		}

		/* prevent the cache from being withdrawn */
		if (fscache_operation_lock(object)) {
			if (object->cache->ops->grab_object(object)) {
				/* ask the cache to honour the operation */
				ret = object->cache->ops->reserve_space(object,
									size);

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

EXPORT_SYMBOL(__fscache_reserve_space);

/*****************************************************************************/
/*
 * read a page from the cache or allocate a block in which to store it
 * - we return:
 *   -ENOMEM	- out of memory, nothing done
 *   -EINTR	- interrupted
 *   -ENOBUFS	- no backing object available in which to cache the block
 *   -ENODATA	- no data available in the backing object for this block
 *   0		- dispatched a read - it'll call end_io_func() when finished
 */
int __fscache_read_or_alloc_page(struct fscache_cookie *cookie,
				 struct page *page,
				 fscache_rw_complete_t end_io_func,
				 void *context,
				 gfp_t gfp)
{
	struct fscache_object *object;
	int ret;

	_enter("%p,{%lu},", cookie, page->index);

	if (hlist_empty(&cookie->backing_objects)) {
		_leave(" -ENOBUFS [no backing objects]");
		return -ENOBUFS;
	}

	/* not supposed to use this for indexes */
	BUG_ON(cookie->def->type == FSCACHE_COOKIE_TYPE_INDEX);

	/* prevent the file from being uncached whilst we access it */
	down_read(&cookie->sem);

	ret = -ENOBUFS;
	if (!hlist_empty(&cookie->backing_objects)) {
		/* get and pin the backing object */
		object = hlist_entry(cookie->backing_objects.first,
				     struct fscache_object, cookie_link);

		if (test_bit(FSCACHE_IOERROR, &object->cache->flags))
			goto out;

		/* prevent the cache from being withdrawn */
		if (fscache_operation_lock(object)) {
			if (object->cache->ops->grab_object(object)) {
				/* ask the cache to honour the operation */
				ret = object->cache->ops->read_or_alloc_page(
					object,
					page,
					end_io_func,
					context,
					gfp);

				object->cache->ops->put_object(object);
			}

			fscache_operation_unlock(object);
		}
	}

out:
	up_read(&cookie->sem);
	_leave(" = %d", ret);
	return ret;
}

EXPORT_SYMBOL(__fscache_read_or_alloc_page);

/*****************************************************************************/
/*
 * read a list of page from the cache or allocate a block in which to store
 * them
 * - we return:
 *   -ENOMEM	- out of memory, some pages may be being read
 *   -EINTR	- interrupted, some pages may be being read
 *   -ENOBUFS	- no backing object or space available in which to cache any
 *                pages not being read
 *   -ENODATA	- no data available in the backing object for some or all of
 *                the pages
 *   0		- dispatched a read on all pages
 *
 * end_io_func() will be called for each page read from the cache as it is
 * finishes being read
 *
 * any pages for which a read is dispatched will be removed from pages and
 * nr_pages
 */
int __fscache_read_or_alloc_pages(struct fscache_cookie *cookie,
				  struct address_space *mapping,
				  struct list_head *pages,
				  unsigned *nr_pages,
				  fscache_rw_complete_t end_io_func,
				  void *context,
				  gfp_t gfp)
{
	struct fscache_object *object;
	int ret;

	_enter("%p,,%d,,,", cookie, *nr_pages);

	if (hlist_empty(&cookie->backing_objects)) {
		_leave(" -ENOBUFS [no backing objects]");
		return -ENOBUFS;
	}

	/* not supposed to use this for indexes */
	BUG_ON(cookie->def->type == FSCACHE_COOKIE_TYPE_INDEX);
	BUG_ON(list_empty(pages));
	BUG_ON(*nr_pages <= 0);

	/* prevent the file from being uncached whilst we access it */
	down_read(&cookie->sem);

	ret = -ENOBUFS;
	if (!hlist_empty(&cookie->backing_objects)) {
		/* get and pin the backing object */
		object = hlist_entry(cookie->backing_objects.first,
				     struct fscache_object, cookie_link);

		if (test_bit(FSCACHE_IOERROR, &object->cache->flags))
			goto out;

		/* prevent the cache from being withdrawn */
		if (fscache_operation_lock(object)) {
			if (object->cache->ops->grab_object(object)) {
				/* ask the cache to honour the operation */
				ret = object->cache->ops->read_or_alloc_pages(
					object,
					mapping,
					pages,
					nr_pages,
					end_io_func,
					context,
					gfp);

				object->cache->ops->put_object(object);
			}

			fscache_operation_unlock(object);
		}
	}

out:
	up_read(&cookie->sem);
	_leave(" = %d", ret);
	return ret;
}

EXPORT_SYMBOL(__fscache_read_or_alloc_pages);

/*****************************************************************************/
/*
 * allocate a block in the cache on which to store a page
 * - we return:
 *   -ENOMEM	- out of memory, nothing done
 *   -EINTR	- interrupted
 *   -ENOBUFS	- no backing object available in which to cache the block
 *   0		- block allocated
 */
int __fscache_alloc_page(struct fscache_cookie *cookie,
			 struct page *page,
			 gfp_t gfp)
{
	struct fscache_object *object;
	int ret;

	_enter("%p,{%lu},", cookie, page->index);

	if (hlist_empty(&cookie->backing_objects)) {
		_leave(" -ENOBUFS [no backing objects]");
		return -ENOBUFS;
	}

	/* not supposed to use this for indexes */
	BUG_ON(cookie->def->type == FSCACHE_COOKIE_TYPE_INDEX);

	/* prevent the file from being uncached whilst we access it */
	down_read(&cookie->sem);

	ret = -ENOBUFS;
	if (!hlist_empty(&cookie->backing_objects)) {
		/* get and pin the backing object */
		object = hlist_entry(cookie->backing_objects.first,
				     struct fscache_object, cookie_link);

		if (test_bit(FSCACHE_IOERROR, &object->cache->flags))
			goto out;

		/* prevent the cache from being withdrawn */
		if (fscache_operation_lock(object)) {
			if (object->cache->ops->grab_object(object)) {
				/* ask the cache to honour the operation */
				ret = object->cache->ops->allocate_page(object,
									page,
									gfp);

				object->cache->ops->put_object(object);
			}

			fscache_operation_unlock(object);
		}
	}

out:
	up_read(&cookie->sem);
	_leave(" = %d", ret);
	return ret;
}

EXPORT_SYMBOL(__fscache_alloc_page);

/*****************************************************************************/
/*
 * request a page be stored in the cache
 * - returns:
 *   -ENOMEM	- out of memory, nothing done
 *   -EINTR	- interrupted
 *   -ENOBUFS	- no backing object available in which to cache the page
 *   0		- dispatched a write - it'll call end_io_func() when finished
 */
int __fscache_write_page(struct fscache_cookie *cookie,
			 struct page *page,
			 fscache_rw_complete_t end_io_func,
			 void *context,
			 gfp_t gfp)
{
	struct fscache_object *object;
	int ret;

	_enter("%p,{%lu},", cookie, page->index);

	/* not supposed to use this for indexes */
	BUG_ON(cookie->def->type == FSCACHE_COOKIE_TYPE_INDEX);

	/* prevent the file from been uncached whilst we deal with it */
	down_read(&cookie->sem);

	ret = -ENOBUFS;
	if (!hlist_empty(&cookie->backing_objects)) {
		object = hlist_entry(cookie->backing_objects.first,
				     struct fscache_object, cookie_link);

		if (test_bit(FSCACHE_IOERROR, &object->cache->flags))
			goto out;

		/* prevent the cache from being withdrawn */
		if (fscache_operation_lock(object)) {
			/* ask the cache to honour the operation */
			ret = object->cache->ops->write_page(object,
							     page,
							     end_io_func,
							     context,
							     gfp);
			fscache_operation_unlock(object);
		}
	}

out:
	up_read(&cookie->sem);
	_leave(" = %d", ret);
	return ret;
}

EXPORT_SYMBOL(__fscache_write_page);

/*****************************************************************************/
/*
 * request several pages be stored in the cache
 * - returns:
 *   -ENOMEM	- out of memory, nothing done
 *   -EINTR	- interrupted
 *   -ENOBUFS	- no backing object available in which to cache the page
 *   0		- dispatched a write - it'll call end_io_func() when finished
 */
int __fscache_write_pages(struct fscache_cookie *cookie,
			  struct pagevec *pagevec,
			  fscache_rw_complete_t end_io_func,
			  void *context,
			  gfp_t gfp)
{
	struct fscache_object *object;
	int ret;

	_enter("%p,{%ld},", cookie, pagevec->nr);

	/* not supposed to use this for indexes */
	BUG_ON(cookie->def->type == FSCACHE_COOKIE_TYPE_INDEX);

	/* prevent the file from been uncached whilst we deal with it */
	down_read(&cookie->sem);

	ret = -ENOBUFS;
	if (!hlist_empty(&cookie->backing_objects)) {
		object = hlist_entry(cookie->backing_objects.first,
				     struct fscache_object, cookie_link);

		if (test_bit(FSCACHE_IOERROR, &object->cache->flags))
			goto out;

		/* prevent the cache from being withdrawn */
		if (fscache_operation_lock(object)) {
			/* ask the cache to honour the operation */
			ret = object->cache->ops->write_pages(object,
							      pagevec,
							      end_io_func,
							      context,
							      gfp);
			fscache_operation_unlock(object);
		}
	}

out:
	up_read(&cookie->sem);
	_leave(" = %d", ret);
	return ret;
}

EXPORT_SYMBOL(__fscache_write_pages);

/*****************************************************************************/
/*
 * remove a page from the cache
 */
void __fscache_uncache_page(struct fscache_cookie *cookie, struct page *page)
{
	struct fscache_object *object;
	struct pagevec pagevec;

	_enter(",{%lu}", page->index);

	/* not supposed to use this for indexes */
	BUG_ON(cookie->def->type == FSCACHE_COOKIE_TYPE_INDEX);

	if (hlist_empty(&cookie->backing_objects)) {
		_leave(" [no backing]");
		return;
	}

	pagevec_init(&pagevec, 0);
	pagevec_add(&pagevec, page);

	/* ask the cache to honour the operation */
	down_read(&cookie->sem);

	if (!hlist_empty(&cookie->backing_objects)) {
		object = hlist_entry(cookie->backing_objects.first,
				     struct fscache_object, cookie_link);

		/* prevent the cache from being withdrawn */
		if (fscache_operation_lock(object)) {
			object->cache->ops->uncache_pages(object, &pagevec);
			fscache_operation_unlock(object);
		}
	}

	up_read(&cookie->sem);

	_leave("");
}

EXPORT_SYMBOL(__fscache_uncache_page);

/*****************************************************************************/
/*
 * remove a bunch of pages from the cache
 */
void __fscache_uncache_pages(struct fscache_cookie *cookie,
			     struct pagevec *pagevec)
{
	struct fscache_object *object;

	_enter(",{%ld}", pagevec->nr);

	BUG_ON(pagevec->nr <= 0);
	BUG_ON(!pagevec->pages[0]);

	/* not supposed to use this for indexes */
	BUG_ON(cookie->def->type == FSCACHE_COOKIE_TYPE_INDEX);

	if (hlist_empty(&cookie->backing_objects)) {
		_leave(" [no backing]");
		return;
	}

	/* ask the cache to honour the operation */
	down_read(&cookie->sem);

	if (!hlist_empty(&cookie->backing_objects)) {
		object = hlist_entry(cookie->backing_objects.first,
				     struct fscache_object, cookie_link);

		/* prevent the cache from being withdrawn */
		if (fscache_operation_lock(object)) {
			object->cache->ops->uncache_pages(object, pagevec);
			fscache_operation_unlock(object);
		}
	}

	up_read(&cookie->sem);

	_leave("");
}

EXPORT_SYMBOL(__fscache_uncache_pages);
