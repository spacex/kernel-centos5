/* fscache-int.h: internal definitions
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _FSCACHE_INT_H
#define _FSCACHE_INT_H

#include <linux/fscache-cache.h>
#include <linux/timer.h>
#include <linux/bio.h>

extern kmem_cache_t *fscache_cookie_jar;

extern struct fscache_cookie fscache_fsdef_index;
extern struct fscache_cookie_def fscache_fsdef_netfs_def;

extern void fscache_cookie_init_once(void *_cookie, kmem_cache_t *cachep, unsigned long flags);

/*
 * prevent the cache from being withdrawn whilst an operation is in progress
 * - returns false if the cache is being withdrawn already or if the cache is
 *   waiting to withdraw itself
 * - returns true if the cache was not being withdrawn
 * - fscache_withdraw_cache() will wait using down_write() until all ops are
 *   complete
 */
static inline int fscache_operation_lock(struct fscache_object *object)
{
	return down_read_trylock(&object->cache->withdrawal_sem);
}

/*
 * release the operation lock
 */
static inline void fscache_operation_unlock(struct fscache_object *object)
{
	up_read(&object->cache->withdrawal_sem);
}


/*****************************************************************************/
/*
 * debug tracing
 */
#define dbgprintk(FMT,...) \
	printk("[%-6.6s] "FMT"\n",current->comm ,##__VA_ARGS__)
#define _dbprintk(FMT,...) do { } while(0)

#define kenter(FMT,...)	dbgprintk("==> %s("FMT")",__FUNCTION__ ,##__VA_ARGS__)
#define kleave(FMT,...)	dbgprintk("<== %s()"FMT"",__FUNCTION__ ,##__VA_ARGS__)
#define kdebug(FMT,...)	dbgprintk(FMT ,##__VA_ARGS__)

#define kjournal(FMT,...) _dbprintk(FMT ,##__VA_ARGS__)

#define dbgfree(ADDR)  _dbprintk("%p:%d: FREEING %p",__FILE__,__LINE__,ADDR)

#define dbgpgalloc(PAGE)						\
do {									\
	_dbprintk("PGALLOC %s:%d: %p {%lx,%lu}\n",			\
		  __FILE__,__LINE__,					\
		  (PAGE),(PAGE)->mapping->host->i_ino,(PAGE)->index	\
		  );							\
} while(0)

#define dbgpgfree(PAGE)						\
do {								\
	if ((PAGE))						\
		_dbprintk("PGFREE %s:%d: %p {%lx,%lu}\n",	\
			  __FILE__,__LINE__,			\
			  (PAGE),				\
			  (PAGE)->mapping->host->i_ino,		\
			  (PAGE)->index				\
			  );					\
} while(0)

#ifdef __KDEBUG
#define _enter(FMT,...)	kenter(FMT,##__VA_ARGS__)
#define _leave(FMT,...)	kleave(FMT,##__VA_ARGS__)
#define _debug(FMT,...)	kdebug(FMT,##__VA_ARGS__)
#else
#define _enter(FMT,...)	do { } while(0)
#define _leave(FMT,...)	do { } while(0)
#define _debug(FMT,...)	do { } while(0)
#endif

#endif /* _FSCACHE_INT_H */
