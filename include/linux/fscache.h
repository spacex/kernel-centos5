/* fscache.h: general filesystem caching interface
 *
 * Copyright (C) 2004-5 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * NOTE!!! See:
 *
 *	Documentation/filesystems/caching/netfs-api.txt
 *
 * for a description of the network filesystem interface declared here.
 */

#ifndef _LINUX_FSCACHE_H
#define _LINUX_FSCACHE_H

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>

struct pagevec;
struct fscache_cache_tag;
struct fscache_cookie;
struct fscache_netfs;
struct fscache_netfs_operations;

typedef void (*fscache_rw_complete_t)(struct page *page,
				      void *context,
				      int error);

/* result of index entry consultation */
typedef enum {
	FSCACHE_CHECKAUX_OKAY,		/* entry okay as is */
	FSCACHE_CHECKAUX_NEEDS_UPDATE,	/* entry requires update */
	FSCACHE_CHECKAUX_OBSOLETE,	/* entry requires deletion */
} fscache_checkaux_t;

/*****************************************************************************/
/*
 * fscache cookie definition
 */
struct fscache_cookie_def
{
	/* name of cookie type */
	char name[16];

	/* cookie type */
	uint8_t type;
#define FSCACHE_COOKIE_TYPE_INDEX	0
#define FSCACHE_COOKIE_TYPE_DATAFILE	1

	/* select the cache into which to insert an entry in this index
	 * - optional
	 * - should return a cache identifier or NULL to cause the cache to be
	 *   inherited from the parent if possible or the first cache picked
	 *   for a non-index file if not
	 */
	struct fscache_cache_tag *(*select_cache)(const void *parent_netfs_data,
						  const void *cookie_netfs_data);

	/* get an index key
	 * - should store the key data in the buffer
	 * - should return the amount of amount stored
	 * - not permitted to return an error
	 * - the netfs data from the cookie being used as the source is
	 *   presented
	 */
	uint16_t (*get_key)(const void *cookie_netfs_data,
			    void *buffer,
			    uint16_t bufmax);

	/* get certain file attributes from the netfs data
	 * - this function can be absent for an index
	 * - not permitted to return an error
	 * - the netfs data from the cookie being used as the source is
	 *   presented
	 */
	void (*get_attr)(const void *cookie_netfs_data, uint64_t *size);

	/* get the auxilliary data from netfs data
	 * - this function can be absent if the index carries no state data
	 * - should store the auxilliary data in the buffer
	 * - should return the amount of amount stored
	 * - not permitted to return an error
	 * - the netfs data from the cookie being used as the source is
	 *   presented
	 */
	uint16_t (*get_aux)(const void *cookie_netfs_data,
			    void *buffer,
			    uint16_t bufmax);

	/* consult the netfs about the state of an object
	 * - this function can be absent if the index carries no state data
	 * - the netfs data from the cookie being used as the target is
	 *   presented, as is the auxilliary data
	 */
	fscache_checkaux_t (*check_aux)(void *cookie_netfs_data,
					const void *data,
					uint16_t datalen);

	/* get an extra reference on a read context
	 * - this function can be absent if the completion function doesn't
	 *   require a context
	 */
	void (*get_context)(void *cookie_netfs_data, void *context);

	/* release an extra reference on a read context
	 * - this function can be absent if the completion function doesn't
	 *   require a context
	 */
	void (*put_context)(void *cookie_netfs_data, void *context);

	/* indicate pages that now have cache metadata retained
	 * - this function should mark the specified pages as now being cached
	 */
	void (*mark_pages_cached)(void *cookie_netfs_data,
				  struct address_space *mapping,
				  struct pagevec *cached_pvec);

	/* indicate the cookie is no longer cached
	 * - this function is called when the backing store currently caching
	 *   a cookie is removed
	 * - the netfs should use this to clean up any markers indicating
	 *   cached pages
	 * - this is mandatory for any object that may have data
	 */
	void (*now_uncached)(void *cookie_netfs_data);
};

/* pattern used to fill dead space in an index entry */
#define FSCACHE_INDEX_DEADFILL_PATTERN 0x79

#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
extern struct fscache_cookie *__fscache_acquire_cookie(struct fscache_cookie *parent,
						       struct fscache_cookie_def *def,
						       void *netfs_data);

extern void __fscache_relinquish_cookie(struct fscache_cookie *cookie,
					int retire);

extern void __fscache_update_cookie(struct fscache_cookie *cookie);
#endif

static inline
struct fscache_cookie *fscache_acquire_cookie(struct fscache_cookie *parent,
					      struct fscache_cookie_def *def,
					      void *netfs_data)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (parent)
		return __fscache_acquire_cookie(parent, def, netfs_data);
#endif
	return NULL;
}

static inline
void fscache_relinquish_cookie(struct fscache_cookie *cookie,
			       int retire)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (cookie)
		__fscache_relinquish_cookie(cookie, retire);
#endif
}

static inline
void fscache_update_cookie(struct fscache_cookie *cookie)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (cookie)
		__fscache_update_cookie(cookie);
#endif
}

/*****************************************************************************/
/*
 * pin or unpin a cookie in a cache
 * - only available for data cookies
 */
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
extern int __fscache_pin_cookie(struct fscache_cookie *cookie);
extern void __fscache_unpin_cookie(struct fscache_cookie *cookie);
#endif

static inline
int fscache_pin_cookie(struct fscache_cookie *cookie)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (cookie)
		return __fscache_pin_cookie(cookie);
#endif
	return -ENOBUFS;
}

static inline
void fscache_unpin_cookie(struct fscache_cookie *cookie)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (cookie)
		__fscache_unpin_cookie(cookie);
#endif
}

/*****************************************************************************/
/*
 * fscache cached network filesystem type
 * - name, version and ops must be filled in before registration
 * - all other fields will be set during registration
 */
struct fscache_netfs
{
	uint32_t			version;	/* indexing version */
	const char			*name;		/* filesystem name */
	struct fscache_cookie		*primary_index;
	struct fscache_netfs_operations	*ops;
	struct list_head		link;		/* internal link */
};

struct fscache_netfs_operations
{
};

#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
extern int __fscache_register_netfs(struct fscache_netfs *netfs);
extern void __fscache_unregister_netfs(struct fscache_netfs *netfs);
#endif

static inline
int fscache_register_netfs(struct fscache_netfs *netfs)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	return __fscache_register_netfs(netfs);
#else
	return 0;
#endif
}

static inline
void fscache_unregister_netfs(struct fscache_netfs *netfs)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	__fscache_unregister_netfs(netfs);
#endif
}

/*****************************************************************************/
/*
 * look up a cache tag
 * - cache tags are used to select specific caches in which to cache indexes
 */
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
extern struct fscache_cache_tag *__fscache_lookup_cache_tag(const char *name);
extern void __fscache_release_cache_tag(struct fscache_cache_tag *tag);
#endif

static inline
struct fscache_cache_tag *fscache_lookup_cache_tag(const char *name)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	return __fscache_lookup_cache_tag(name);
#else
	return NULL;
#endif
}

static inline
void fscache_release_cache_tag(struct fscache_cache_tag *tag)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	__fscache_release_cache_tag(tag);
#endif
}

/*****************************************************************************/
/*
 * set the data size on a cached object
 * - no pages beyond the end of the object will be accessible
 * - returns -ENOBUFS if the file is not backed
 * - returns -ENOSPC if a pinned file of that size can't be stored
 * - returns 0 if okay
 */
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
extern int __fscache_set_i_size(struct fscache_cookie *cookie, loff_t i_size);
#endif

static inline
int fscache_set_i_size(struct fscache_cookie *cookie, loff_t i_size)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (cookie)
		return __fscache_set_i_size(cookie, i_size);
#endif
	return -ENOBUFS;
}

/*****************************************************************************/
/*
 * reserve data space for a cached object
 * - returns -ENOBUFS if the file is not backed
 * - returns -ENOSPC if there isn't enough space to honour the reservation
 * - returns 0 if okay
 */
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
extern int __fscache_reserve_space(struct fscache_cookie *cookie, loff_t size);
#endif

static inline
int fscache_reserve_space(struct fscache_cookie *cookie, loff_t size)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (cookie)
		return __fscache_reserve_space(cookie, size);
#endif
	return -ENOBUFS;
}

/*****************************************************************************/
/*
 * read a page from the cache or allocate a block in which to store it
 * - if the page is not backed by a file:
 *   - -ENOBUFS will be returned and nothing more will be done
 * - else if the page is backed by a block in the cache:
 *   - a read will be started which will call end_io_func on completion
 * - else if the page is unbacked:
 *   - a block will be allocated
 *   - -ENODATA will be returned
 */
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
extern int __fscache_read_or_alloc_page(struct fscache_cookie *cookie,
					struct page *page,
					fscache_rw_complete_t end_io_func,
					void *context,
					gfp_t gfp);
#endif

static inline
int fscache_read_or_alloc_page(struct fscache_cookie *cookie,
			       struct page *page,
			       fscache_rw_complete_t end_io_func,
			       void *context,
			       gfp_t gfp)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (cookie)
		return __fscache_read_or_alloc_page(cookie, page, end_io_func,
						    context, gfp);
#endif
	return -ENOBUFS;
}

#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
extern int __fscache_read_or_alloc_pages(struct fscache_cookie *cookie,
					 struct address_space *mapping,
					 struct list_head *pages,
					 unsigned *nr_pages,
					 fscache_rw_complete_t end_io_func,
					 void *context,
					 gfp_t gfp);
#endif

static inline
int fscache_read_or_alloc_pages(struct fscache_cookie *cookie,
				struct address_space *mapping,
				struct list_head *pages,
				unsigned *nr_pages,
				fscache_rw_complete_t end_io_func,
				void *context,
				gfp_t gfp)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (cookie)
		return __fscache_read_or_alloc_pages(cookie, mapping, pages,
						     nr_pages, end_io_func,
						     context, gfp);
#endif
	return -ENOBUFS;
}

/*
 * allocate a block in which to store a page
 * - if the page is not backed by a file:
 *   - -ENOBUFS will be returned and nothing more will be done
 * - else
 *   - a block will be allocated if there isn't one
 *   - 0 will be returned
 */
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
extern int __fscache_alloc_page(struct fscache_cookie *cookie,
				struct page *page,
				gfp_t gfp);
#endif

static inline
int fscache_alloc_page(struct fscache_cookie *cookie,
		       struct page *page,
		       gfp_t gfp)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (cookie)
		return __fscache_alloc_page(cookie, page, gfp);
#endif
	return -ENOBUFS;
}

/*
 * request a page be stored in the cache
 * - this request may be ignored if no cache block is currently allocated, in
 *   which case it:
 *   - returns -ENOBUFS
 * - if a cache block was already allocated:
 *   - a BIO will be dispatched to write the page (end_io_func will be called
 *     from the completion function)
 *   - returns 0
 */
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
extern int __fscache_write_page(struct fscache_cookie *cookie,
				struct page *page,
				fscache_rw_complete_t end_io_func,
				void *context,
				gfp_t gfp);

extern int __fscache_write_pages(struct fscache_cookie *cookie,
				 struct pagevec *pagevec,
				 fscache_rw_complete_t end_io_func,
				 void *context,
				 gfp_t gfp);
#endif

static inline
int fscache_write_page(struct fscache_cookie *cookie,
		       struct page *page,
		       fscache_rw_complete_t end_io_func,
		       void *context,
		       gfp_t gfp)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (cookie)
		return __fscache_write_page(cookie, page, end_io_func,
					    context, gfp);
#endif
	return -ENOBUFS;
}

static inline
int fscache_write_pages(struct fscache_cookie *cookie,
			struct pagevec *pagevec,
			fscache_rw_complete_t end_io_func,
			void *context,
			gfp_t gfp)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (cookie)
		return __fscache_write_pages(cookie, pagevec, end_io_func,
					     context, gfp);
#endif
	return -ENOBUFS;
}

/*
 * indicate that caching is no longer required on a page
 * - note: cannot cancel any outstanding BIOs between this page and the cache
 */
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
extern void __fscache_uncache_page(struct fscache_cookie *cookie,
				   struct page *page);
extern void __fscache_uncache_pages(struct fscache_cookie *cookie,
				    struct pagevec *pagevec);
#endif

static inline
void fscache_uncache_page(struct fscache_cookie *cookie,
			  struct page *page)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (cookie)
		__fscache_uncache_page(cookie, page);
#endif
}

static inline
void fscache_uncache_pagevec(struct fscache_cookie *cookie,
			     struct pagevec *pagevec)
{
#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
	if (cookie)
		__fscache_uncache_pages(cookie, pagevec);
#endif
}

#endif /* _LINUX_FSCACHE_H */
