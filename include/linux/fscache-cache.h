/* fscache-cache.h: general filesystem caching backing cache interface
 *
 * Copyright (C) 2004-6 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * NOTE!!! See:
 *
 *	Documentation/filesystems/caching/backend-api.txt
 *
 * for a description of the cache backend interface declared here.
 */

#ifndef _LINUX_FSCACHE_CACHE_H
#define _LINUX_FSCACHE_CACHE_H

#include <linux/fscache.h>

#define NR_MAXCACHES BITS_PER_LONG

struct fscache_cache;
struct fscache_cache_ops;
struct fscache_object;

/*
 * cache tag definition
 */
struct fscache_cache_tag {
	struct list_head		link;
	struct fscache_cache		*cache;		/* cache referred to by this tag */
	atomic_t			usage;
	char				name[0];	/* tag name */
};

/*
 * cache definition
 */
struct fscache_cache {
	struct fscache_cache_ops	*ops;
	struct fscache_cache_tag	*tag;		/* tag representing this cache */
	struct list_head		link;		/* link in list of caches */
	struct rw_semaphore		withdrawal_sem;	/* withdrawal control sem */
	size_t				max_index_size;	/* maximum size of index data */
	char				identifier[32];	/* cache label */

	/* node management */
	struct list_head		object_list;	/* list of data/index objects */
	spinlock_t			object_list_lock;
	struct fscache_object		*fsdef;		/* object for the fsdef index */
	unsigned long			flags;
#define FSCACHE_IOERROR			0	/* cache stopped on I/O error */
};

extern void fscache_init_cache(struct fscache_cache *cache,
			       struct fscache_cache_ops *ops,
			       const char *idfmt,
			       ...) __attribute__ ((format (printf,3,4)));

extern int fscache_add_cache(struct fscache_cache *cache,
			     struct fscache_object *fsdef,
			     const char *tagname);
extern void fscache_withdraw_cache(struct fscache_cache *cache);

extern void fscache_io_error(struct fscache_cache *cache);

/*****************************************************************************/
/*
 * cache operations
 */
struct fscache_cache_ops {
	/* name of cache provider */
	const char *name;

	/* look up the object for a cookie, creating it on disc if necessary */
	struct fscache_object *(*lookup_object)(struct fscache_cache *cache,
						struct fscache_object *parent,
						struct fscache_cookie *cookie);

	/* increment the usage count on this object (may fail if unmounting) */
	struct fscache_object *(*grab_object)(struct fscache_object *object);

	/* lock a semaphore on an object */
	void (*lock_object)(struct fscache_object *object);

	/* unlock a semaphore on an object */
	void (*unlock_object)(struct fscache_object *object);

	/* pin an object in the cache */
	int (*pin_object)(struct fscache_object *object);

	/* unpin an object in the cache */
	void (*unpin_object)(struct fscache_object *object);

	/* store the updated auxilliary data on an object */
	void (*update_object)(struct fscache_object *object);

	/* dispose of a reference to an object */
	void (*put_object)(struct fscache_object *object);

	/* sync a cache */
	void (*sync_cache)(struct fscache_cache *cache);

	/* set the data size of an object */
	int (*set_i_size)(struct fscache_object *object, loff_t i_size);

	/* reserve space for an object's data and associated metadata */
	int (*reserve_space)(struct fscache_object *object, loff_t i_size);

	/* request a backing block for a page be read or allocated in the
	 * cache */
	int (*read_or_alloc_page)(struct fscache_object *object,
				  struct page *page,
				  fscache_rw_complete_t end_io_func,
				  void *context,
				  unsigned long gfp);

	/* request backing blocks for a list of pages be read or allocated in
	 * the cache */
	int (*read_or_alloc_pages)(struct fscache_object *object,
				   struct address_space *mapping,
				   struct list_head *pages,
				   unsigned *nr_pages,
				   fscache_rw_complete_t end_io_func,
				   void *context,
				   unsigned long gfp);

	/* request a backing block for a page be allocated in the cache so that
	 * it can be written directly */
	int (*allocate_page)(struct fscache_object *object,
			     struct page *page,
			     unsigned long gfp);

	/* write a page to its backing block in the cache */
	int (*write_page)(struct fscache_object *object,
			  struct page *page,
			  fscache_rw_complete_t end_io_func,
			  void *context,
			  unsigned long gfp);

	/* write several pages to their backing blocks in the cache */
	int (*write_pages)(struct fscache_object *object,
			   struct pagevec *pagevec,
			   fscache_rw_complete_t end_io_func,
			   void *context,
			   unsigned long gfp);

	/* detach backing block from a bunch of pages */
	void (*uncache_pages)(struct fscache_object *object,
			     struct pagevec *pagevec);

	/* dissociate a cache from all the pages it was backing */
	void (*dissociate_pages)(struct fscache_cache *cache);
};

/*****************************************************************************/
/*
 * data file or index object cookie
 * - a file will only appear in one cache
 * - a request to cache a file may or may not be honoured, subject to
 *   constraints such as disc space
 * - indexes files are created on disc just-in-time
 */
struct fscache_cookie {
	atomic_t			usage;		/* number of users of this cookie */
	atomic_t			children;	/* number of children of this cookie */
	struct rw_semaphore		sem;		/* list creation vs scan lock */
	struct hlist_head		backing_objects; /* object(s) backing this file/index */
	struct fscache_cookie_def	*def;		/* definition */
	struct fscache_cookie		*parent;	/* parent of this entry */
	struct fscache_netfs		*netfs;		/* owner network fs definition */
	void				*netfs_data;	/* back pointer to netfs */
};

extern struct fscache_cookie fscache_fsdef_index;

/*****************************************************************************/
/*
 * on-disc cache file or index handle
 */
struct fscache_object {
	unsigned long			flags;
#define FSCACHE_OBJECT_RELEASING	0	/* T if object is being released */
#define FSCACHE_OBJECT_RECYCLING	1	/* T if object is being retired */
#define FSCACHE_OBJECT_WITHDRAWN	2	/* T if object has been withdrawn */

	struct list_head		cache_link;	/* link in cache->object_list */
	struct hlist_node		cookie_link;	/* link in cookie->backing_objects */
	struct fscache_cache		*cache;		/* cache that supplied this object */
	struct fscache_cookie		*cookie;	/* netfs's file/index object */
};

static inline
void fscache_object_init(struct fscache_object *object)
{
	object->flags = 0;
	INIT_LIST_HEAD(&object->cache_link);
	INIT_HLIST_NODE(&object->cookie_link);
	object->cache = NULL;
	object->cookie = NULL;
}

/* find the parent index object for a object */
static inline
struct fscache_object *fscache_find_parent_object(struct fscache_object *object)
{
	struct fscache_object *parent;
	struct fscache_cookie *cookie = object->cookie;
	struct fscache_cache *cache = object->cache;
	struct hlist_node *_p;

	hlist_for_each_entry(parent, _p,
			     &cookie->parent->backing_objects,
			     cookie_link
			     ) {
		if (parent->cache == cache)
			return parent;
	}

	return NULL;
}

/* get an extra reference to a context */
static inline
void *fscache_get_context(struct fscache_cookie *cookie, void *context)
{
	if (cookie->def->get_context)
		cookie->def->get_context(cookie->netfs_data, context);
	return context;
}

/* release an extra reference to a context */
static inline
void fscache_put_context(struct fscache_cookie *cookie, void *context)
{
	if (cookie->def->put_context)
		cookie->def->put_context(cookie->netfs_data, context);
}

#endif /* _LINUX_FSCACHE_CACHE_H */
