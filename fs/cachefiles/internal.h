/* internal.h: general netfs cache on cache files internal defs
 *
 * Copyright (C) 2006 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 *
 * CacheFiles layout:
 *
 *	/..../CacheDir/
 *		index
 *		0/
 *		1/
 *		2/
 *		  index
 *		  0/
 *		  1/
 *		  2/
 *		    index
 *		    0
 *		    1
 *		    2
 */

#include <linux/fscache-cache.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

struct cachefiles_cache;
struct cachefiles_object;

extern unsigned long cachefiles_debug;
#define CACHEFILES_DEBUG_KENTER	1
#define CACHEFILES_DEBUG_KLEAVE	2
#define CACHEFILES_DEBUG_KDEBUG	4

extern struct fscache_cache_ops cachefiles_cache_ops;
extern struct proc_dir_entry *cachefiles_proc;
extern struct file_operations cachefiles_proc_fops;

/*****************************************************************************/
/*
 * node records
 */
struct cachefiles_object {
	struct fscache_object		fscache;	/* fscache handle */
	struct dentry			*dentry;	/* the file/dir representing this object */
	struct dentry			*backer;	/* backing file */
	loff_t				i_size;		/* object size */
	atomic_t			usage;		/* basic object usage count */
	unsigned long			flags;
#define CACHEFILES_OBJECT_ACTIVE	0		/* T if marked active */
	atomic_t			fscache_usage;	/* FSDEF object usage count */
	uint8_t				type;		/* object type */
	uint8_t				new;		/* T if object new */
	spinlock_t			work_lock;
	struct rw_semaphore		sem;
	struct work_struct		read_work;	/* read page copier */
	struct list_head		read_list;	/* pages to copy */
	struct list_head		read_pend_list;	/* pages to pending read from backer */
	struct work_struct		write_work;	/* page writer */
	struct list_head		write_list;	/* pages to store */
	struct rb_node			active_node;	/* link in active tree (dentry is key) */
};

extern kmem_cache_t *cachefiles_object_jar;

/*****************************************************************************/
/*
 * Cache files cache definition
 */
struct cachefiles_cache {
	struct fscache_cache		cache;		/* FS-Cache record */
	struct vfsmount			*mnt;		/* mountpoint holding the cache */
	struct dentry			*graveyard;	/* directory into which dead objects go */
	struct file			*cachefilesd;	/* manager daemon handle */
	struct rb_root			active_nodes;	/* active nodes (can't be culled) */
	rwlock_t			active_lock;	/* lock for active_nodes */
	atomic_t			gravecounter;	/* graveyard uniquifier */
	unsigned			frun_percent;	/* when to stop culling (% files) */
	unsigned			fcull_percent;	/* when to start culling (% files) */
	unsigned			fstop_percent;	/* when to stop allocating (% files) */
	unsigned			brun_percent;	/* when to stop culling (% blocks) */
	unsigned			bcull_percent;	/* when to start culling (% blocks) */
	unsigned			bstop_percent;	/* when to stop allocating (% blocks) */
	unsigned			bsize;		/* cache's block size */
	unsigned			bshift;		/* min(log2 (PAGE_SIZE / bsize), 0) */
	uint64_t			frun;		/* when to stop culling */
	uint64_t			fcull;		/* when to start culling */
	uint64_t			fstop;		/* when to stop allocating */
	sector_t			brun;		/* when to stop culling */
	sector_t			bcull;		/* when to start culling */
	sector_t			bstop;		/* when to stop allocating */
	unsigned long			flags;
#define CACHEFILES_READY		0	/* T if cache prepared */
#define CACHEFILES_DEAD			1	/* T if cache dead */
#define CACHEFILES_CULLING		2	/* T if cull engaged */
	char				*rootdirname;	/* name of cache root directory */
	char				*tag;		/* cache binding tag */
};

/*****************************************************************************/
/*
 * backing file read tracking
 */
struct cachefiles_one_read {
	wait_queue_t			monitor;	/* link into monitored waitqueue */
	struct page			*back_page;	/* backing file page we're waiting for */
	struct page			*netfs_page;	/* netfs page we're going to fill */
	struct cachefiles_object	*object;
	struct list_head		obj_link;	/* link in object's lists */
	fscache_rw_complete_t		end_io_func;
	void				*context;
};

/*****************************************************************************/
/*
 * backing file write tracking
 */
struct cachefiles_one_write {
	struct page			*netfs_page;	/* netfs page to copy */
	struct cachefiles_object	*object;
	struct list_head		obj_link;	/* link in object's lists */
	fscache_rw_complete_t		end_io_func;
	void				*context;
};

/*****************************************************************************/
/*
 * auxiliary data xattr buffer
 */
struct cachefiles_xattr {
	uint16_t			len;
	uint8_t				type;
	uint8_t				data[];
};


/* cf-bind.c */
extern int cachefiles_proc_bind(struct cachefiles_cache *cache, char *args);
extern void cachefiles_proc_unbind(struct cachefiles_cache *cache);

/* cf-interface.c */
extern void cachefiles_read_copier_work(void *_object);
extern void cachefiles_write_work(void *_object);
extern int cachefiles_has_space(struct cachefiles_cache *cache,
				unsigned fnr, unsigned bnr);

/* cf-key.c */
extern char *cachefiles_cook_key(const u8 *raw, int keylen, uint8_t type);

/* cf-namei.c */
extern int cachefiles_delete_object(struct cachefiles_cache *cache,
				    struct cachefiles_object *object);
extern int cachefiles_walk_to_object(struct cachefiles_object *parent,
				     struct cachefiles_object *object,
				     char *key,
				     struct cachefiles_xattr *auxdata);
extern struct dentry *cachefiles_get_directory(struct cachefiles_cache *cache,
					       struct dentry *dir,
					       const char *name);

extern int cachefiles_cull(struct cachefiles_cache *cache, struct dentry *dir,
			   char *filename);

/* cf-sysctl.c */
extern int __init cachefiles_sysctl_init(void);
extern void __exit cachefiles_sysctl_cleanup(void);

/* cf-xattr.c */
extern int cachefiles_check_object_type(struct cachefiles_object *object);
extern int cachefiles_set_object_xattr(struct cachefiles_object *object,
				       struct cachefiles_xattr *auxdata);
extern int cachefiles_check_object_xattr(struct cachefiles_object *object,
					 struct cachefiles_xattr *auxdata);
extern int cachefiles_remove_object_xattr(struct cachefiles_cache *cache,
					  struct dentry *dentry);


/*****************************************************************************/
/*
 * error handling
 */
#define kerror(FMT,...) printk(KERN_ERR "CacheFiles: "FMT"\n" ,##__VA_ARGS__);

#define cachefiles_io_error(___cache, FMT, ...)		\
do {							\
	kerror("I/O Error: " FMT ,##__VA_ARGS__);	\
	fscache_io_error(&(___cache)->cache);		\
	set_bit(CACHEFILES_DEAD, &(___cache)->flags);	\
} while(0)

#define cachefiles_io_error_obj(object, FMT, ...)			\
do {									\
	struct cachefiles_cache *___cache;				\
									\
	___cache = container_of((object)->fscache.cache,		\
				struct cachefiles_cache, cache);	\
	cachefiles_io_error(___cache, FMT ,##__VA_ARGS__);		\
} while(0)


/*****************************************************************************/
/*
 * debug tracing
 */
#define dbgprintk(FMT,...) \
	printk("[%-6.6s] "FMT"\n",current->comm ,##__VA_ARGS__)

/* make sure we maintain the format strings, even when debugging is disabled */
static inline void _dbprintk(const char *fmt, ...)
	__attribute__((format(printf,1,2)));
static inline void _dbprintk(const char *fmt, ...)
{
}

#define kenter(FMT,...)	dbgprintk("==> %s("FMT")",__FUNCTION__ ,##__VA_ARGS__)
#define kleave(FMT,...)	dbgprintk("<== %s()"FMT"",__FUNCTION__ ,##__VA_ARGS__)
#define kdebug(FMT,...)	dbgprintk(FMT ,##__VA_ARGS__)


#if defined(__KDEBUG)
#define _enter(FMT,...)	kenter(FMT,##__VA_ARGS__)
#define _leave(FMT,...)	kleave(FMT,##__VA_ARGS__)
#define _debug(FMT,...)	kdebug(FMT,##__VA_ARGS__)

#elif defined(CONFIG_CACHEFILES_DEBUG)
#define _enter(FMT,...)					\
do {							\
	if (cachefiles_debug & CACHEFILES_DEBUG_KENTER)	\
		kenter(FMT,##__VA_ARGS__);		\
} while (0)

#define _leave(FMT,...)					\
do {							\
	if (cachefiles_debug & CACHEFILES_DEBUG_KLEAVE)	\
		kleave(FMT,##__VA_ARGS__);		\
} while (0)

#define _debug(FMT,...)					\
do {							\
	if (cachefiles_debug & CACHEFILES_DEBUG_KDEBUG)	\
		kdebug(FMT,##__VA_ARGS__);		\
} while (0)

#else
#define _enter(FMT,...)	_dbprintk("==> %s("FMT")",__FUNCTION__ ,##__VA_ARGS__)
#define _leave(FMT,...)	_dbprintk("<== %s()"FMT"",__FUNCTION__ ,##__VA_ARGS__)
#define _debug(FMT,...)	_dbprintk(FMT ,##__VA_ARGS__)
#endif

#if 1 // defined(__KDEBUGALL)

#define ASSERT(X)							\
do {									\
	if (unlikely(!(X))) {						\
		printk(KERN_ERR "\n");					\
		printk(KERN_ERR "CacheFiles: Assertion failed\n");	\
		BUG();							\
	}								\
} while(0)

#define ASSERTCMP(X, OP, Y)						\
do {									\
	if (unlikely(!((X) OP (Y)))) {					\
		printk(KERN_ERR "\n");					\
		printk(KERN_ERR "CacheFiles: Assertion failed\n");	\
		printk(KERN_ERR "%lx " #OP " %lx is false\n",		\
		       (unsigned long)(X), (unsigned long)(Y));		\
		BUG();							\
	}								\
} while(0)

#define ASSERTIF(C, X)							\
do {									\
	if (unlikely((C) && !(X))) {					\
		printk(KERN_ERR "\n");					\
		printk(KERN_ERR "CacheFiles: Assertion failed\n");	\
		BUG();							\
	}								\
} while(0)

#define ASSERTIFCMP(C, X, OP, Y)					\
do {									\
	if (unlikely((C) && !((X) OP (Y)))) {				\
		printk(KERN_ERR "\n");					\
		printk(KERN_ERR "CacheFiles: Assertion failed\n");	\
		printk(KERN_ERR "%lx " #OP " %lx is false\n",		\
		       (unsigned long)(X), (unsigned long)(Y));		\
		BUG();							\
	}								\
} while(0)

#else

#define ASSERT(X)				\
do {						\
} while(0)

#define ASSERTCMP(X, OP, Y)			\
do {						\
} while(0)

#define ASSERTIF(C, X)				\
do {						\
} while(0)

#define ASSERTIFCMP(C, X, OP, Y)		\
do {						\
} while(0)

#endif
