/*
 * Copyright (C) 2005-2008 Red Hat, Inc. All rights reserved.
 *
 * Module Author: Heinz Mauelshagen <Mauelshagen@RedHat.com>
 *
 * This file is released under the GPL.
 *
 * WARNING: this is Alpha software wich can corrupt your data!
 *
 *
 * Linux 2.6 Device Mapper RAID4 and RAID5 target.
 *
 * Supports:
 *	o RAID4 with dedicated and selectable parity device
 *	o RAID5 with rotating parity (left+right, symmetric+asymmetric)
 *
 *
 * Thanks to MD for:
 *    o the raid address calculation algorithm
 *    o the base of the biovec <-> page list copier.
 *
 *
 * Uses region hash to keep track of how many writes are in flight to
 * regions in order to use dirty log to keep state of regions to recover:
 *
 *    o clean regions (those which are synchronized
 * 	and don't have write io in flight)
 *    o dirty regions (those with write io in flight)
 *
 *
 * On startup, any dirty regions are migrated to the 'nosync' state
 * and are subject to recovery by the daemon.
 *
 * See raid_ctr() for table definition.
 *
 *
 * FIXME:
 * o add virtual interface for locking
 * o remove instrumentation (REMOVEME:)
 *
 */

static const char *version = "v0.2429";

#include "dm.h"
#include "dm-bio-list.h"
#include "dm-mem-cache.h"
#include "dm-message.h"
#include "dm-region_hash.h"
#include "dm-raid45.h"

#include <linux/dm-io.h>
#include <linux/dm-dirty-log.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>

#define	STR_LEN(ptr, str) ptr, str, strlen(ptr)
#define bio_list_for_each(bio, bl) \
	for (bio = (bl)->head; bio; bio = bio->bi_next)
static inline int bio_list_empty(const struct bio_list *bl)
{
	return !bl->head;
}


/*
 * Configurable parameters
 */
#define	INLINE

/* Default # of stripes if not set in constructor. */
#define	STRIPES			64

/* Minimum/maximum # of selectable stripes. */
#define	STRIPES_MIN		8
#define	STRIPES_MAX		16384

/* Default chunk size in sectors if not set in constructor. */
#define	CHUNK_SIZE		64

/* Default io size in sectors if not set in constructor. */
#define	IO_SIZE_MIN		SECTORS_PER_PAGE
#define	IO_SIZE			IO_SIZE_MIN

/* Maximum setable chunk size in sectors. */
#define	CHUNK_SIZE_MAX		16384

/* Recover io size default in sectors. */
#define	RECOVER_IO_SIZE_MIN	64
#define	RECOVER_IO_SIZE		256

/* Default percentage recover io bandwidth. */
#define	BANDWIDTH		10
#define	BANDWIDTH_MIN		1
#define	BANDWIDTH_MAX		100
/*
 * END Configurable parameters
 */

#define	TARGET	"dm-raid45"
#define	DAEMON	"kraid45d"
#define	DM_MSG_PREFIX	TARGET

#define	SECTORS_PER_PAGE	(PAGE_SIZE >> SECTOR_SHIFT)

/* Amount/size for __xor(). */
#define	SECTORS_PER_XOR	SECTORS_PER_PAGE
#define	XOR_SIZE	PAGE_SIZE

/* Derive raid_set from stripe_cache pointer. */
#define	RS(x)	container_of(x, struct raid_set, sc)

/* Check value in range. */
#define	range_ok(i, min, max)	(i >= min && i <= max)

/* Page reference. */
#define PAGE(stripe, p)	((stripe)->obj[p].pl->page)

/* Bio list reference. */
#define	BL(stripe, p, rw)	(stripe->ss[p].bl + rw)

/* Page list reference. */
#define	PL(stripe, p)		(stripe->obj[p].pl)

/* Check argument is power of 2. */
#define POWER_OF_2(a) (!(a & (a - 1)))

/* xor optimization. */
typedef unsigned long xor_t;

/* Factor out to dm-bio-list.h */
static inline void bio_list_push(struct bio_list *bl, struct bio *bio)
{
	bio->bi_next = bl->head;
	bl->head = bio;

	if (!bl->tail)
		bl->tail = bio;
}

/* Factor out to dm.h */
#define TI_ERR_RET(str, ret) \
        do { ti->error = DM_MSG_PREFIX ": " str; return ret; } while(0);
#define TI_ERR(str)     TI_ERR_RET(str, -EINVAL)

/*-----------------------------------------------------------------
 * Stripe cache
 *
 * Cache for all reads and writes to raid sets (operational or degraded)
 *
 * We need to run all data to and from a RAID set through this cache,
 * because parity chunks need to get calculated from data chunks
 * or, in the degraded/resynchronization case, missing chunks need
 * to be reconstructed using the other chunks of the stripe.
 *---------------------------------------------------------------*/
/* Protect kmem cache # counter. */
static atomic_t _stripe_sc_nr = ATOMIC_INIT(-1); /* kmem cache # counter. */

/* A stripe set (holds bios hanging off). */
struct stripe_set {
	struct stripe *stripe;	/* Backpointer to stripe for endio(). */
	struct bio_list bl[3]; /* Reads, writes, and writes merged. */
#define	WRITE_MERGED	2
};

#if READ != 0 || WRITE != 1
#error dm-raid45: READ/WRITE != 0/1 used as index!!!
#endif

/*
 * Stripe linked list indexes. Keep order, because the stripe
 * and the stripe cache rely on the first 3!
 */
enum list_types {
	LIST_IO = 0,	/* Stripes with io pending. */
	LIST_ENDIO,	/* Stripes to endio. */
	LIST_LRU,	/* Least recently used stripes. */
	LIST_HASH,	/* Hashed stripes. */
	NR_LISTS,	/* To size array in struct stripe. */
};

enum lock_types {
	LOCK_ENDIO = 0,	/* Protect endio list. */
	LOCK_LRU,	/* Protect lru list. */
	NR_LOCKS,	/* To size array in struct stripe_cache. */
};

/* A stripe: the io object to handle all reads and writes to a RAID set. */
struct stripe {
	struct stripe_cache *sc;	/* Backpointer to stripe cache. */

	sector_t key;		/* Hash key. */
	sector_t region;	/* Region stripe is mapped to. */

	/* Reference count. */
	atomic_t cnt;

	struct {
		unsigned long flags;	/* flags (see below). */

		/*
		 * Pending ios in flight:
		 *
		 * used as a 'lock' to control move of stripe to endio list
		 */
		atomic_t pending;	/* Pending ios in flight. */

		/* Sectors to read and write for multi page stripe sets. */
		unsigned size;
	} io;

	/* Lock on stripe (for clustering). */
	void *lock;

	/*
	 * 4 linked lists:
	 *   o io list to flush io
	 *   o endio list
	 *   o LRU list to put stripes w/o reference count on
	 *   o stripe cache hash
	 */
	struct list_head lists[NR_LISTS];

	struct {
		unsigned short parity;	/* Parity chunk index. */
		short recover;		/* Recovery chunk index. */
	} idx;

	/* This sets memory cache object (dm-mem-cache). */
	struct dm_mem_cache_object *obj;

	/* Array of stripe sets (dynamically allocated). */
	struct stripe_set ss[0];
};

/* States stripes can be in (flags field). */
enum stripe_states {
	STRIPE_ACTIVE,		/* Active io on stripe. */
	STRIPE_ERROR,		/* io error on stripe. */
	STRIPE_MERGED,		/* Writes got merged. */
	STRIPE_READ,		/* Read. */
	STRIPE_RBW,		/* Read-before-write. */
	STRIPE_RECONSTRUCT,	/* reconstruct of a missing chunk required. */
	STRIPE_RECOVER,		/* Stripe used for RAID set recovery. */
};

/* ... and macros to access them. */
#define	BITOPS(name, what, var, flag) \
static inline int TestClear ## name ## what(struct var *v) \
{ return test_and_clear_bit(flag, &v->io.flags); } \
static inline int TestSet ## name ## what(struct var *v) \
{ return test_and_set_bit(flag, &v->io.flags); } \
static inline void Clear ## name ## what(struct var *v) \
{ clear_bit(flag, &v->io.flags); } \
static inline void Set ## name ## what(struct var *v) \
{ set_bit(flag, &v->io.flags); } \
static inline int name ## what(struct var *v) \
{ return test_bit(flag, &v->io.flags); }


BITOPS(Stripe, Active, stripe, STRIPE_ACTIVE)
BITOPS(Stripe, Merged, stripe, STRIPE_MERGED)
BITOPS(Stripe, Error, stripe, STRIPE_ERROR)
BITOPS(Stripe, Read, stripe, STRIPE_READ)
BITOPS(Stripe, RBW, stripe, STRIPE_RBW)
BITOPS(Stripe, Reconstruct, stripe, STRIPE_RECONSTRUCT)
BITOPS(Stripe, Recover, stripe, STRIPE_RECOVER)

/* A stripe hash. */
struct stripe_hash {
	struct list_head *hash;
	unsigned buckets;
	unsigned mask;
	unsigned prime;
	unsigned shift;
};

/* A stripe cache. */
struct stripe_cache {
	/* Stripe hash. */
	struct stripe_hash hash;

	/* Stripes with io to flush, stripes to endio and LRU lists. */
	struct list_head lists[3];

	/* Locks to protect endio and lru lists. */
	spinlock_t locks[NR_LOCKS];

	/* Slab cache to allocate stripes from. */
	struct {
		struct kmem_cache *cache;	/* Cache itself. */
		char name[32];	/* Unique name. */
	} kc;

	struct dm_io_client *dm_io_client; /* dm-io client resource context. */

	/* dm-mem-cache client resource context. */
	struct dm_mem_cache_client *dm_mem_cache_client;

	int stripes_parm;	    /* # stripes parameter from constructor. */
	atomic_t stripes;	    /* actual # of stripes in cache. */
	atomic_t stripes_to_shrink; /* # of stripes to shrink cache by. */
	atomic_t stripes_last;	    /* last # of stripes in cache. */
	atomic_t active_stripes;    /* actual # of active stripes in cache. */

	/* REMOVEME: */
	atomic_t max_active_stripes; /* actual # of active stripes in cache. */
};

/* Flag specs for raid_dev */ ;
enum raid_dev_flags { DEVICE_FAILED, IO_QUEUED };

/* The raid device in a set. */
struct raid_dev {
	struct dm_dev *dev;
	unsigned long flags;	/* raid_dev_flags. */
	sector_t start;		/* offset to map to. */
};

/* Flags spec for raid_set. */
enum raid_set_flags {
	RS_CHECK_OVERWRITE,	/* Check for chunk overwrites. */
	RS_DEAD,		/* RAID set inoperational. */
	RS_DEVEL_STATS,		/* REMOVEME: display status information. */
	RS_IO_ERROR,		/* io error on set. */
	RS_RECOVER,		/* Do recovery. */
	RS_RECOVERY_BANDWIDTH,	/* Allow recovery bandwidth (delayed bios). */
	RS_REGION_GET,		/* get a region to recover. */
	RS_SC_BUSY,		/* stripe cache busy -> send an event. */
	RS_SUSPENDED,		/* RAID set suspendedn. */
};

/* REMOVEME: devel stats counters. */
enum stats_types {
	S_BIOS_READ,
	S_BIOS_ADDED_READ,
	S_BIOS_ENDIO_READ,
	S_BIOS_WRITE,
	S_BIOS_ADDED_WRITE,
	S_BIOS_ENDIO_WRITE,
	S_CAN_MERGE,
	S_CANT_MERGE,
	S_CONGESTED,
	S_DM_IO_READ,
	S_DM_IO_WRITE,
	S_ACTIVE_READS,
	S_BANDWIDTH,
	S_BARRIER,
	S_BIO_COPY_PL_NEXT,
	S_DEGRADED,
	S_DELAYED_BIOS,
	S_EVICT,
	S_FLUSHS,
	S_HITS_1ST,
	S_IOS_POST,
	S_INSCACHE,
	S_MAX_LOOKUP,
	S_MERGE_PAGE_LOCKED,
	S_NO_BANDWIDTH,
	S_NOT_CONGESTED,
	S_NO_RW,
	S_NOSYNC,
	S_PROHIBITPAGEIO,
	S_RECONSTRUCT_EI,
	S_RECONSTRUCT_DEV,
	S_REDO,
	S_REQUEUE,
	S_STRIPE_ERROR,
	S_SUM_DELAYED_BIOS,
	S_XORS,
	S_NR_STATS,	/* # of stats counters. */
};

/* Status type -> string mappings. */
struct stats_map {
	const enum stats_types type;
	const char *str;
};

static struct stats_map stats_map[] = {
	{ S_BIOS_READ, "r=" },
	{ S_BIOS_ADDED_READ, "/" },
	{ S_BIOS_ENDIO_READ, "/" },
	{ S_BIOS_WRITE, " w=" },
	{ S_BIOS_ADDED_WRITE, "/" },
	{ S_BIOS_ENDIO_WRITE, "/" },
	{ S_DM_IO_READ, " rc=" },
	{ S_DM_IO_WRITE, " wc=" },
	{ S_ACTIVE_READS, " active_reads=" },
	{ S_BANDWIDTH, " bandwidth=" },
	{ S_NO_BANDWIDTH, " no_bandwidth=" },
	{ S_BARRIER, " barrier=" },
	{ S_BIO_COPY_PL_NEXT, " bio_copy_pl_next=" },
	{ S_CAN_MERGE, " can_merge=" },
	{ S_MERGE_PAGE_LOCKED, "/page_locked=" },
	{ S_CANT_MERGE, "/cant_merge=" },
	{ S_CONGESTED, " congested=" },
	{ S_NOT_CONGESTED, "/not_congested=" },
	{ S_DEGRADED, " degraded=" },
	{ S_DELAYED_BIOS, " delayed_bios=" },
	{ S_SUM_DELAYED_BIOS, "/sum_delayed_bios=" },
	{ S_EVICT, " evict=" },
	{ S_FLUSHS, " flushs=" },
	{ S_HITS_1ST, " hits_1st=" },
	{ S_IOS_POST, " ios_post=" },
	{ S_INSCACHE, " inscache=" },
	{ S_MAX_LOOKUP, " max_lookup=" },
	{ S_NO_RW, " no_rw=" },
	{ S_NOSYNC, " nosync=" },
	{ S_PROHIBITPAGEIO, " ProhibitPageIO=" },
	{ S_RECONSTRUCT_EI, " reconstruct_ei=" },
	{ S_RECONSTRUCT_DEV, " reconstruct_dev=" },
	{ S_REDO, " redo=" },
	{ S_REQUEUE, " requeue=" },
	{ S_STRIPE_ERROR, " stripe_error=" },
	{ S_XORS, " xors=" },
};

/*
 * A RAID set.
 */
typedef void (*xor_function_t)(unsigned count, xor_t **data);
struct raid_set {
	struct dm_target *ti;	/* Target pointer. */

	struct {
		unsigned long flags;	/* State flags. */
		spinlock_t in_lock;	/* Protects central input list below. */
		struct bio_list in;	/* Pending ios (central input list). */
		struct bio_list work;	/* ios work set. */
		wait_queue_head_t suspendq;	/* suspend synchronization. */
		atomic_t in_process;	/* counter of queued bios (suspendq). */
		atomic_t in_process_max;/* counter of queued bios max. */

		/* io work. */
		struct workqueue_struct *wq;
		struct work_struct ws;
	} io;

	/* External locking. */
	struct dmraid45_locking_type *locking;

	struct stripe_cache sc;	/* Stripe cache for this set. */

	/* Xor optimization. */
	struct {
		struct xor_func *f;
		unsigned chunks;
		unsigned speed;
	} xor;

	/* Recovery parameters. */
	struct recover {
		struct dm_dirty_log *dl;	/* Dirty log. */
		void *rh;	/* Region hash. */

		region_t nr_regions;
		region_t nr_regions_to_recover;
		region_t nr_regions_recovered;
		unsigned long start_jiffies;
		unsigned long end_jiffies;

		unsigned bandwidth;	     /* Recovery bandwidth [%]. */
		unsigned bandwidth_work; /* Recovery bandwidth [factor]. */
		unsigned bandwidth_parm; /*  " constructor parm. */
		unsigned io_size;        /* io size <= chunk size. */
		unsigned io_size_parm;   /* io size ctr parameter. */

		/* recovery io throttling. */
		atomic_t io_count[2];	/* counter recover/regular io. */
		unsigned long last_jiffies;

		void *reg;	/* Actual region to recover. */
		struct stripe *stripe; /* Stripe used for recovery. */
		sector_t pos;	/* Position within region to recover. */
		sector_t end;	/* End of region to recover. */
	} recover;

	/* RAID set parameters. */
	struct {
		struct raid_type *raid_type;	/* RAID type (eg, RAID4). */
		unsigned raid_parms;	/* # variable raid parameters. */

		unsigned chunk_size;	/* Sectors per chunk. */
		unsigned chunk_size_parm;
		unsigned chunk_mask;	/* Mask for amount. */
		unsigned chunk_shift;	/* rsector chunk size shift. */

		unsigned io_size;	/* Sectors per io. */
		unsigned io_size_parm;
		unsigned io_mask;	/* Mask for amount. */
		unsigned io_shift_mask;	/* Mask for raid_address(). */
		unsigned io_shift;	/* rsector io size shift. */
		unsigned pages_per_io;	/* Pages per io. */

		sector_t sectors_per_dev;	/* Sectors per device. */

		atomic_t failed_devs;		/* Amount of devices failed. */

		/* Index of device to initialize. */
		int dev_to_init;
		int dev_to_init_parm;

		/* Raid devices dynamically allocated. */
		unsigned raid_devs;	/* # of RAID devices below. */
		unsigned data_devs;	/* # of RAID data devices. */

		int ei;		/* index of failed RAID device. */

		/* index of dedicated parity device (i.e. RAID4). */
		int pi;
		int pi_parm;	/* constructor parm for status output. */
	} set;

	/* REMOVEME: devel stats counters. */
	atomic_t stats[S_NR_STATS];

	/* Dynamically allocated temporary pointers for xor(). */
	xor_t **data;

	/* Dynamically allocated RAID devices. Alignment? */
	struct raid_dev dev[0];
};


BITOPS(RS, Bandwidth, raid_set, RS_RECOVERY_BANDWIDTH)
BITOPS(RS, CheckOverwrite, raid_set, RS_CHECK_OVERWRITE)
BITOPS(RS, Dead, raid_set, RS_DEAD)
BITOPS(RS, DevelStats, raid_set, RS_DEVEL_STATS)
BITOPS(RS, IoError, raid_set, RS_IO_ERROR)
BITOPS(RS, Recover, raid_set, RS_RECOVER)
BITOPS(RS, RegionGet, raid_set, RS_REGION_GET)
BITOPS(RS, ScBusy, raid_set, RS_SC_BUSY)
BITOPS(RS, Suspended, raid_set, RS_SUSPENDED)
#undef BITOPS

#define	PageIO(page)		PageChecked(page)
#define	AllowPageIO(page)	SetPageChecked(page)
#define	ProhibitPageIO(page)	ClearPageChecked(page)

/*-----------------------------------------------------------------
 * Raid-4/5 set structures.
 *---------------------------------------------------------------*/
/* RAID level definitions. */
enum raid_level {
	raid4,
	raid5,
};

/* Symmetric/Asymmetric, Left/Right parity rotating algorithms. */
enum raid_algorithm {
	none,
	left_asym,
	right_asym,
	left_sym,
	right_sym,
};

struct raid_type {
	const char *name;		/* RAID algorithm. */
	const char *descr;		/* Descriptor text for logging. */
	const unsigned parity_devs;	/* # of parity devices. */
	const unsigned minimal_devs;	/* minimal # of devices in set. */
	const enum raid_level level;		/* RAID level. */
	const enum raid_algorithm algorithm;	/* RAID algorithm. */
};

/* Supported raid types and properties. */
static struct raid_type raid_types[] = {
	{"raid4", "RAID4 (dedicated parity disk)", 1, 3, raid4, none},
	{"raid5_la", "RAID5 (left asymmetric)", 1, 3, raid5, left_asym},
	{"raid5_ra", "RAID5 (right asymmetric)", 1, 3, raid5, right_asym},
	{"raid5_ls", "RAID5 (left symmetric)", 1, 3, raid5, left_sym},
	{"raid5_rs", "RAID5 (right symmetric)", 1, 3, raid5, right_sym},
};

/* Address as calculated by raid_address(). */
struct address {
	sector_t key;		/* Hash key (start address of stripe). */
	unsigned di, pi;	/* Data and parity disks index. */
};

/* REMOVEME: reset statistics counters. */
static void stats_reset(struct raid_set *rs)
{
	unsigned s = S_NR_STATS;

	while (s--)
		atomic_set(rs->stats + s, 0);
}

/*----------------------------------------------------------------
 * RAID set management routines.
 *--------------------------------------------------------------*/
/*
 * Begin small helper functions.
 */
/* Queue (optionally delayed) io work. */
static void wake_do_raid_delayed(struct raid_set *rs, unsigned long delay)
{
	struct work_struct *ws = &rs->io.ws;

	cancel_delayed_work(ws);
	queue_delayed_work(rs->io.wq, ws, delay);
}

/* Queue io work immediately (called from region hash too). */
static INLINE void wake_do_raid(void *context)
{
	wake_do_raid_delayed(context, 0);
}

/* Wait until all io has been processed. */
static INLINE void wait_ios(struct raid_set *rs)
{
	wait_event(rs->io.suspendq, !atomic_read(&rs->io.in_process));
}

/* Declare io queued to device. */
static INLINE void io_dev_queued(struct raid_dev *dev)
{
	set_bit(IO_QUEUED, &dev->flags);
}

/* Io on device and reset ? */
static inline int io_dev_clear(struct raid_dev *dev)
{
	return test_and_clear_bit(IO_QUEUED, &dev->flags);
}

/* Get an io reference. */
static INLINE void io_get(struct raid_set *rs)
{
	int p = atomic_inc_return(&rs->io.in_process);

	if (p > atomic_read(&rs->io.in_process_max))
		atomic_set(&rs->io.in_process_max, p); /* REMOVEME: max. */
}

/* Put the io reference and conditionally wake io waiters. */
static INLINE void io_put(struct raid_set *rs)
{
	/* Intel: rebuild data corrupter? */
	if (!atomic_read(&rs->io.in_process)) {
		DMERR("%s would go negative!!!", __func__);
		return;
	}

	if (atomic_dec_and_test(&rs->io.in_process))
		wake_up(&rs->io.suspendq);
}

/* Calculate device sector offset. */
static INLINE sector_t _sector(struct raid_set *rs, struct bio *bio)
{
	sector_t sector = bio->bi_sector;

	sector_div(sector, rs->set.data_devs);
	return sector;
}

/* Test device operational. */
static INLINE int dev_operational(struct raid_set *rs, unsigned p)
{
	return !test_bit(DEVICE_FAILED, &rs->dev[p].flags);
}

/* Return # of active stripes in stripe cache. */
static INLINE int sc_active(struct stripe_cache *sc)
{
	return atomic_read(&sc->active_stripes);
}

/* Test io pending on stripe. */
static INLINE int stripe_io(struct stripe *stripe)
{
	return atomic_read(&stripe->io.pending);
}

static INLINE void stripe_io_inc(struct stripe *stripe)
{
	atomic_inc(&stripe->io.pending);
}

static INLINE void stripe_io_dec(struct stripe *stripe)
{
	atomic_dec(&stripe->io.pending);
}

/* Wrapper needed by for_each_io_dev(). */
static void _stripe_io_inc(struct stripe *stripe, unsigned p)
{
	stripe_io_inc(stripe);
}

/* Error a stripe. */
static INLINE void stripe_error(struct stripe *stripe, struct page *page)
{
	SetStripeError(stripe);
	SetPageError(page);
	atomic_inc(RS(stripe->sc)->stats + S_STRIPE_ERROR);
}

/* Page IOed ok. */
enum dirty_type { CLEAN, DIRTY };
static INLINE void page_set(struct page *page, enum dirty_type type)
{
	switch (type) {
	case DIRTY:
		SetPageDirty(page);
		AllowPageIO(page);
		break;

	case CLEAN:
		ClearPageDirty(page);
		break;

	default:
		BUG();
	}

	SetPageUptodate(page);
	ClearPageError(page);
}

/* Return region state for a sector. */
static INLINE int
region_state(struct raid_set *rs, sector_t sector, unsigned long state)
{
	void *rh = rs->recover.rh;

	if (unlikely(RSRecover(rs)))
		return rh_state(rh, rh_sector_to_region(rh, sector), 1) & state;
	else
		return 0;
}

/* Check maximum devices which may fail in a raid set. */
static inline int raid_set_degraded(struct raid_set *rs)
{
	return RSIoError(rs);
}

/* Check # of devices which may fail in a raid set. */
static INLINE int raid_set_operational(struct raid_set *rs)
{
	/* Too many failed devices -> BAD. */
	return atomic_read(&rs->set.failed_devs) <= 
	       rs->set.raid_type->parity_devs;
}

/*
 * Return true in case a page_list should be read/written
 *
 * Conditions to read/write:
 *	o 1st page in list not uptodate
 *	o 1st page in list dirty
 *	o if we optimized io away, we flag it using the pages checked bit.
 */
static INLINE unsigned page_io(struct page *page)
{
	/* Optimization: page was flagged to need io during first run. */
	if (PagePrivate(page)) {
		ClearPagePrivate(page);
		return 1;
	}

	/* Avoid io if prohibited or a locked page. */
	if (!PageIO(page) || PageLocked(page))
		return 0;

	if (!PageUptodate(page) || PageDirty(page)) {
		/* Flag page needs io for second run optimization. */
		SetPagePrivate(page);
		return 1;
	}

	return 0;
}

/* Call a function on each page list needing io. */
static INLINE unsigned
for_each_io_dev(struct raid_set *rs, struct stripe *stripe,
		void (*f_io)(struct stripe *stripe, unsigned p))
{
	unsigned p = rs->set.raid_devs, r = 0;

	while (p--) {
		if (page_io(PAGE(stripe, p))) {
			f_io(stripe, p);
			r++;
		}
	}

	return r;
}

/* Reconstruct a particular device ?. */
static INLINE int dev_to_init(struct raid_set *rs)
{
	return rs->set.dev_to_init > -1;
}

/*
 * Index of device to calculate parity on.
 * Either the parity device index *or* the selected device to init
 * after a spare replacement.
 */
static INLINE unsigned dev_for_parity(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);

	return dev_to_init(rs) ? rs->set.dev_to_init : stripe->idx.parity;
}

/* Return the index of the device to be recovered. */
static int idx_get(struct raid_set *rs)
{
	/* Avoid to read in the pages to be reconstructed anyway. */
	if (dev_to_init(rs))
		return rs->set.dev_to_init;
	else if (rs->set.raid_type->level == raid4)
		return rs->set.pi;

	return -1;
}

/* RAID set congested function. */
static int raid_set_congested(void *congested_data, int bdi_bits)
{
	struct raid_set *rs = congested_data;
	int r = 0; /* Assume uncongested. */
	unsigned p = rs->set.raid_devs;

	/* If any of our component devices are overloaded. */
	while (p--)
		r |= bdi_congested(&bdev_get_queue(rs->dev[p].dev->bdev)->backing_dev_info, bdi_bits);

	/* REMOVEME: statistics. */
	atomic_inc(rs->stats + (r ? S_CONGESTED : S_NOT_CONGESTED));
	return r;
}

/* Display RAID set dead message once. */
static void raid_set_dead(struct raid_set *rs)
{
	if (!TestSetRSDead(rs)) {
		unsigned p;
		char buf[BDEVNAME_SIZE];

		DMERR("FATAL: too many devices failed -> RAID set dead");

		for (p = 0; p < rs->set.raid_devs; p++) {
			if (!dev_operational(rs, p))
				DMERR("device /dev/%s failed",
				      bdevname(rs->dev[p].dev->bdev, buf));
		}
	}
}

/* RAID set degrade check. */
static INLINE int
raid_set_check_and_degrade(struct raid_set *rs,
			   struct stripe *stripe, unsigned p)
{
	if (test_and_set_bit(DEVICE_FAILED, &rs->dev[p].flags))
		return -EPERM;

	/* Through an event in case of member device errors. */
	dm_table_event(rs->ti->table);
	atomic_inc(&rs->set.failed_devs);

	/* Only log the first member error. */
	if (!TestSetRSIoError(rs)) {
		char buf[BDEVNAME_SIZE];

		/* Store index for recovery. */
		mb();
		rs->set.ei = p;
		mb();

		DMERR("CRITICAL: %sio error on device /dev/%s "
		      "in region=%llu; DEGRADING RAID set",
		      stripe ? "" : "FAKED ",
		      bdevname(rs->dev[p].dev->bdev, buf),
		      (unsigned long long) (stripe ? stripe->key : 0));
		DMERR("further device error messages suppressed");
	}

	return 0;
}

static void
raid_set_check_degrade(struct raid_set *rs, struct stripe *stripe)
{
	unsigned p = rs->set.raid_devs;

	while (p--) {
		struct page *page = PAGE(stripe, p);

		if (PageError(page)) {
			ClearPageError(page);
			raid_set_check_and_degrade(rs, stripe, p);
		}
	}
}

/* RAID set upgrade check. */
static int raid_set_check_and_upgrade(struct raid_set *rs, unsigned p)
{
	if (!test_and_clear_bit(DEVICE_FAILED, &rs->dev[p].flags))
		return -EPERM;

	if (atomic_dec_and_test(&rs->set.failed_devs)) {
		ClearRSIoError(rs);
		rs->set.ei = -1;
	}

	return 0;
}

/* Lookup a RAID device by name or by major:minor number. */
union dev_lookup {
	const char *dev_name;
	struct raid_dev *dev;
};
enum lookup_type { byname, bymajmin, bynumber };
static int raid_dev_lookup(struct raid_set *rs, enum lookup_type by,
			   union dev_lookup *dl)
{
	unsigned p;

	/*
	 * Must be an incremental loop, because the device array
	 * can have empty slots still on calls from raid_ctr()
	 */
	for (p = 0; p < rs->set.raid_devs; p++) {
		char buf[BDEVNAME_SIZE];
		struct raid_dev *dev = rs->dev + p;

		if (!dev->dev)
			break;

		/* Format dev string appropriately if necessary. */
		if (by == byname)
			bdevname(dev->dev->bdev, buf);
		else if (by == bymajmin)
			format_dev_t(buf, dev->dev->bdev->bd_dev);

		/* Do the actual check. */
		if (by == bynumber) {
			if (dl->dev->dev->bdev->bd_dev ==
			    dev->dev->bdev->bd_dev)
				return p;
		} else if (!strcmp(dl->dev_name, buf))
			return p;
	}

	return -ENODEV;
}

/* End io wrapper. */
static INLINE void
_bio_endio(struct raid_set *rs, struct bio *bio, int error)
{
	/* REMOVEME: statistics. */
	atomic_inc(rs->stats + (bio_data_dir(bio) == WRITE ?
		   S_BIOS_ENDIO_WRITE : S_BIOS_ENDIO_READ));
	bio_endio(bio, bio->bi_size, error);
	io_put(rs);		/* Wake any suspend waiters. */
}

/*
 * End small helper functions.
 */


/*
 * Stripe hash functions
 */
/* Initialize/destroy stripe hash. */
static int hash_init(struct stripe_hash *hash, unsigned stripes)
{
	unsigned buckets = 1, max_buckets = stripes / 4;
	unsigned hash_primes[] = {
		/* Table of primes for hash_fn/table size optimization. */
		3, 7, 13, 27, 53, 97, 193, 389, 769,
		1543, 3079, 6151, 12289, 24593,
	};

	/* Calculate number of buckets (2^^n <= stripes / 4). */
	while ((buckets <<= 1) < max_buckets);

	/* Allocate stripe hash. */
	hash->hash = vmalloc(buckets * sizeof(*hash->hash));
	if (!hash->hash)
		return -ENOMEM;

	hash->buckets = buckets;
	hash->mask = buckets - 1;
	hash->shift = ffs(buckets);
	if (hash->shift > ARRAY_SIZE(hash_primes) + 1)
		hash->shift = ARRAY_SIZE(hash_primes) + 1;

	BUG_ON(hash->shift - 2 > ARRAY_SIZE(hash_primes) + 1);
	hash->prime = hash_primes[hash->shift - 2];

	/* Initialize buckets. */
	while (buckets--)
		INIT_LIST_HEAD(hash->hash + buckets);

	return 0;
}

static INLINE void hash_exit(struct stripe_hash *hash)
{
	if (hash->hash) {
		vfree(hash->hash);
		hash->hash = NULL;
	}
}

/* List add (head/tail/locked/unlocked) inlines. */
enum list_lock_type { LIST_LOCKED, LIST_UNLOCKED };
#define	LIST_DEL(name, list) \
static void stripe_ ## name ## _del(struct stripe *stripe, \
				    enum list_lock_type lock) { \
	struct list_head *lh = stripe->lists + (list); \
	spinlock_t *l = NULL; \
\
	if (lock == LIST_LOCKED) { \
		l = stripe->sc->locks + LOCK_LRU; \
		spin_lock_irq(l); \
	} \
\
\
	if (!list_empty(lh)) \
		list_del_init(lh); \
\
	if (lock == LIST_LOCKED) \
		spin_unlock_irq(l); \
}

LIST_DEL(hash, LIST_HASH)
LIST_DEL(lru, LIST_LRU)
#undef LIST_DEL

enum list_pos_type { POS_HEAD, POS_TAIL };
#define	LIST_ADD(name, list) \
static void stripe_ ## name ## _add(struct stripe *stripe, \
				    enum list_pos_type pos, \
				    enum list_lock_type lock) { \
	struct list_head *lh = stripe->lists + (list); \
	struct stripe_cache *sc = stripe->sc; \
	spinlock_t *l = NULL; \
\
	if (lock == LIST_LOCKED) { \
		l = sc->locks + LOCK_LRU; \
		spin_lock_irq(l); \
	} \
\
	if (list_empty(lh)) { \
		if (pos == POS_HEAD) \
			list_add(lh, sc->lists + (list)); \
		else \
			list_add_tail(lh, sc->lists + (list)); \
	} \
\
	if (lock == LIST_LOCKED) \
		spin_unlock_irq(l); \
}

LIST_ADD(endio, LIST_ENDIO)
LIST_ADD(io, LIST_IO)
LIST_ADD(lru, LIST_LRU)
#undef LIST_ADD

#define POP(list) \
	if (list_empty(sc->lists + list)) \
		stripe = NULL; \
	else { \
		stripe = list_entry(sc->lists[list].next, struct stripe, \
				    lists[list]); \
		list_del_init(&stripe->lists[list]); \
	}

/* Pop an available stripe off the lru list. */
static struct stripe *stripe_lru_pop(struct stripe_cache *sc)
{
	struct stripe *stripe;
	spinlock_t *lock = sc->locks + LOCK_LRU;

	spin_lock_irq(lock);
	POP(LIST_LRU);
	spin_unlock_irq(lock);

	if (stripe)
		/* Remove from hash before reuse. */
		stripe_hash_del(stripe, LIST_UNLOCKED);

	return stripe;
}

static inline unsigned hash_fn(struct stripe_hash *hash, sector_t key)
{
	return (unsigned) (((key * hash->prime) >> hash->shift) & hash->mask);
}

static inline struct list_head *
hash_bucket(struct stripe_hash *hash, sector_t key)
{
	return hash->hash + hash_fn(hash, key);
}

/* Insert an entry into a hash. */
static inline void hash_insert(struct stripe_hash *hash, struct stripe *stripe)
{
	list_add(stripe->lists + LIST_HASH, hash_bucket(hash, stripe->key));
}

/* Insert an entry into the stripe hash. */
static inline void
sc_insert(struct stripe_cache *sc, struct stripe *stripe)
{
	hash_insert(&sc->hash, stripe);
}

/* Lookup an entry in the stripe hash. */
static inline struct stripe *
stripe_lookup(struct stripe_cache *sc, sector_t key)
{
	unsigned c = 0;
	struct stripe *stripe;
	struct list_head *bucket = hash_bucket(&sc->hash, key);

	list_for_each_entry(stripe, bucket, lists[LIST_HASH]) {
		/* REMOVEME: statisics. */
		if (++c > atomic_read(RS(sc)->stats + S_MAX_LOOKUP))
			atomic_set(RS(sc)->stats + S_MAX_LOOKUP, c);

		if (stripe->key == key)
			return stripe;
	}

	return NULL;
}

/* Resize the stripe cache hash on size changes. */
static int hash_resize(struct stripe_cache *sc)
{
	/* Resize threshold reached? */
	if (atomic_read(&sc->stripes) > 2 * atomic_read(&sc->stripes_last)
	    || atomic_read(&sc->stripes) < atomic_read(&sc->stripes_last) / 4) {
		int r;
		struct stripe_hash hash, hash_tmp;
		spinlock_t *lock;

		r = hash_init(&hash, atomic_read(&sc->stripes));
		if (r)
			return r;

		lock = sc->locks + LOCK_LRU;
		spin_lock_irq(lock);
		if (sc->hash.hash) {
			unsigned b = sc->hash.buckets;
			struct list_head *pos, *tmp;
	
			/* Walk old buckets and insert into new. */
			while (b--) {
				list_for_each_safe(pos, tmp, sc->hash.hash + b)
				    hash_insert(&hash,
						list_entry(pos, struct stripe,
							   lists[LIST_HASH]));
			}

		}

		memcpy(&hash_tmp, &sc->hash, sizeof(hash_tmp));
		memcpy(&sc->hash, &hash, sizeof(sc->hash));
		atomic_set(&sc->stripes_last, atomic_read(&sc->stripes));
		spin_unlock_irq(lock);

		hash_exit(&hash_tmp);
	}

	return 0;
}

/*
 * Stripe cache locking functions
 */
/* Dummy lock function for local RAID4+5. */
static void *no_lock(sector_t key, enum lock_type type)
{
	return &no_lock;
}

/* Dummy unlock function for local RAID4+5. */
static void no_unlock(void *lock_handle)
{
}

/* No locking (for local RAID 4+5). */
static struct dmraid45_locking_type locking_none = {
	.lock = no_lock,
	.unlock = no_unlock,
};

/* Clustered RAID 4+5. */
/* FIXME: code this. */
static struct dmraid45_locking_type locking_cluster = {
	.lock = no_lock,
	.unlock = no_unlock,
};

/* Lock a stripe (for clustering). */
static int
stripe_lock(struct raid_set *rs, struct stripe *stripe, int rw, sector_t key)
{
	stripe->lock = rs->locking->lock(key, rw == READ ? RAID45_SHARED :
							   RAID45_EX);
	return stripe->lock ? 0 : -EPERM;
}

/* Unlock a stripe (for clustering). */
static void stripe_unlock(struct raid_set *rs, struct stripe *stripe)
{
	rs->locking->unlock(stripe->lock);
	stripe->lock = NULL;
}

/*
 * Stripe cache functions.
 */
/*
 * Invalidate all page lists pages of a stripe.
 *
 * I only keep state for the whole list in the first page.
 */
static INLINE void
stripe_pages_invalidate(struct stripe *stripe)
{
	unsigned p = RS(stripe->sc)->set.raid_devs;

	while (p--) {
		struct page *page = PAGE(stripe, p);

		ProhibitPageIO(page);
		ClearPageChecked(page);
		ClearPageDirty(page);
		ClearPageError(page);
		ClearPageLocked(page);
		ClearPagePrivate(page);
		ClearPageUptodate(page);
	}
}

/* Prepare stripe for (re)use. */
static INLINE void stripe_invalidate(struct stripe *stripe)
{
	stripe->io.flags = 0;
	stripe_pages_invalidate(stripe);
}

/* Allow io on all chunks of a stripe. */
static INLINE void stripe_allow_io(struct stripe *stripe)
{
	unsigned p = RS(stripe->sc)->set.raid_devs;

	while (p--)
		AllowPageIO(PAGE(stripe, p));
}

/* Initialize a stripe. */
static void
stripe_init(struct stripe_cache *sc, struct stripe *stripe, unsigned io_size)
{
	unsigned p = RS(sc)->set.raid_devs;
	unsigned i;

	/* Work all io chunks. */
	while (p--) {
		struct stripe_set *ss = stripe->ss + p;

		stripe->obj[p].private = ss;
		ss->stripe = stripe;

		i = ARRAY_SIZE(ss->bl);
		while (i--)
			bio_list_init(ss->bl + i);
	}

	stripe->sc = sc;

	i = ARRAY_SIZE(stripe->lists);
	while (i--)
		INIT_LIST_HEAD(&stripe->lists[i]);

	stripe->io.size = io_size;
	atomic_set(&stripe->cnt, 0);
	atomic_set(&stripe->io.pending, 0);

	stripe_invalidate(stripe);
}

/* Number of pages per chunk. */
static inline unsigned chunk_pages(unsigned io_size)
{
	return dm_div_up(io_size, SECTORS_PER_PAGE);
}

/* Number of pages per stripe. */
static inline unsigned stripe_pages(struct raid_set *rs, unsigned io_size)
{
	return chunk_pages(io_size) * rs->set.raid_devs;
}

/* Initialize part of page_list (recovery). */
static INLINE void stripe_zero_pl_part(struct stripe *stripe, unsigned p,
				       unsigned start, unsigned count)
{
	unsigned pages = chunk_pages(count);
	/* Get offset into the page_list. */
	struct page_list *pl = pl_elem(PL(stripe, p), start / SECTORS_PER_PAGE);

	BUG_ON(!pl);
	while (pl && pages--) {
		BUG_ON(!pl->page);
		memset(page_address(pl->page), 0, PAGE_SIZE);
		pl = pl->next;
	}
}

/* Initialize parity chunk of stripe. */
static INLINE void stripe_zero_chunk(struct stripe *stripe, unsigned p)
{
	stripe_zero_pl_part(stripe, p, 0, stripe->io.size);
}

/* Return dynamic stripe structure size. */
static INLINE size_t stripe_size(struct raid_set *rs)
{
	return sizeof(struct stripe) +
		      rs->set.raid_devs * sizeof(struct stripe_set);
}

/* Allocate a stripe and its memory object. */
enum grow { grow, keep };
static struct stripe *stripe_alloc(struct stripe_cache *sc,
				   unsigned io_size, enum grow grow)
{
	int r;
	unsigned pages_per_chunk = chunk_pages(io_size);
	struct stripe *stripe;

	stripe = kmem_cache_alloc(sc->kc.cache, GFP_KERNEL);
	if (stripe) {
		memset(stripe, 0, stripe_size(RS(sc)));

		/* Grow the dm-mem-cache on request. */
		if (grow == grow) {
			r = dm_mem_cache_grow(sc->dm_mem_cache_client,
					      pages_per_chunk);
			if (r)
				goto err_free;
		}

		stripe->obj = dm_mem_cache_alloc(sc->dm_mem_cache_client,
						 pages_per_chunk);
		if (!stripe->obj)
			goto err_shrink;

		stripe_init(sc, stripe, io_size);
	}

	return stripe;

   err_shrink:
	if (grow == grow)
		dm_mem_cache_shrink(sc->dm_mem_cache_client, pages_per_chunk);
   err_free:
	kmem_cache_free(sc->kc.cache, stripe);
	return NULL;
}

/*
 * Free a stripes memory object, shrink the
 * memory cache and free the stripe itself
 */
static void stripe_free(struct stripe *stripe)
{
	dm_mem_cache_free(stripe->sc->dm_mem_cache_client, stripe->obj);
	dm_mem_cache_shrink(stripe->sc->dm_mem_cache_client,
			    chunk_pages(stripe->io.size));
	kmem_cache_free(stripe->sc->kc.cache, stripe);
}

/* Free the recovery stripe. */
static void stripe_recover_free(struct raid_set *rs)
{
	if (rs->recover.stripe) {
		ClearRSRecover(rs);
		stripe_free(rs->recover.stripe);
		rs->recover.stripe = NULL;
	}
}

/* Push a stripe safely onto the endio list to be handled by do_endios(). */
static INLINE void stripe_endio_push(struct stripe *stripe)
{
	int wake;
	unsigned long flags;
	struct stripe_cache *sc = stripe->sc;
	spinlock_t *lock = sc->locks + LOCK_ENDIO;

	spin_lock_irqsave(lock, flags);
	wake = list_empty(sc->lists + LIST_ENDIO);
	stripe_endio_add(stripe, POS_HEAD, LIST_UNLOCKED);
	spin_unlock_irqrestore(lock, flags);

	if (wake)
		wake_do_raid(RS(sc));
}

/* Protected check for stripe cache endio list empty. */
static INLINE int stripe_endio_empty(struct stripe_cache *sc)
{
	int r;
	spinlock_t *lock = sc->locks + LOCK_ENDIO;

	spin_lock_irq(lock);
	r = list_empty(sc->lists + LIST_ENDIO);
	spin_unlock_irq(lock);

	return r;
}

/* Pop a stripe off safely off the endio list. */
static struct stripe *stripe_endio_pop(struct stripe_cache *sc)
{
	struct stripe *stripe;
	spinlock_t *lock = sc->locks + LOCK_ENDIO;

	/* This runs in parallel with endio(). */
	spin_lock_irq(lock);
	POP(LIST_ENDIO)
	spin_unlock_irq(lock);
	return stripe;
}

#undef POP

/* Evict stripe from cache. */
static void stripe_evict(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);
	stripe_hash_del(stripe, LIST_UNLOCKED);	/* Take off hash. */

	if (list_empty(stripe->lists + LIST_LRU)) {
		stripe_lru_add(stripe, POS_TAIL, LIST_LOCKED);
		atomic_inc(rs->stats + S_EVICT); /* REMOVEME: statistics. */
	}
}

/* Grow stripe cache. */
static int
sc_grow(struct stripe_cache *sc, unsigned stripes, enum grow grow)
{
	int r = 0;
	struct raid_set *rs = RS(sc);

	/* Try to allocate this many (additional) stripes. */
	while (stripes--) {
		struct stripe *stripe = stripe_alloc(sc, rs->set.io_size, grow);

		if (likely(stripe)) {
			stripe_lru_add(stripe, POS_TAIL, LIST_LOCKED);
			atomic_inc(&sc->stripes);
		} else {
			r = -ENOMEM;
			break;
		}
	}

	ClearRSScBusy(rs);
	return r ? r : hash_resize(sc);
}

/* Shrink stripe cache. */
static int sc_shrink(struct stripe_cache *sc, unsigned stripes)
{
	int r = 0;

	/* Try to get unused stripe from LRU list. */
	while (stripes--) {
		struct stripe *stripe;

		stripe = stripe_lru_pop(sc);
		if (stripe) {
			/* An lru stripe may never have ios pending!. */
			BUG_ON(stripe_io(stripe));
			stripe_free(stripe);
			atomic_dec(&sc->stripes);
		} else {
			r = -ENOENT;
			break;
		}
	}

	/* Check if stats are still sane. */
	if (atomic_read(&sc->max_active_stripes) >
	    atomic_read(&sc->stripes))
		atomic_set(&sc->max_active_stripes, 0);

	if (r)
		return r;

	ClearRSScBusy(RS(sc));
	return hash_resize(sc);
}

/* Create stripe cache. */
static int sc_init(struct raid_set *rs, unsigned stripes)
{
	unsigned i, nr;
	struct stripe_cache *sc = &rs->sc;
	struct stripe *stripe;

	/* Initialize lists and locks. */
	i = ARRAY_SIZE(sc->lists);
	while (i--)
		INIT_LIST_HEAD(sc->lists + i);

	i = NR_LOCKS;
	while (i--)
		spin_lock_init(sc->locks + i);

	/* Initialize atomic variables. */
	atomic_set(&sc->stripes, 0);
	atomic_set(&sc->stripes_last, 0);
	atomic_set(&sc->stripes_to_shrink, 0);
	atomic_set(&sc->active_stripes, 0);
	atomic_set(&sc->max_active_stripes, 0);	/* REMOVEME: */

	/*
	 * We need a runtime unique # to suffix the kmem cache name
	 * because we'll have one for each active RAID set.
	 */
	nr = atomic_inc_return(&_stripe_sc_nr);
	sprintf(sc->kc.name, "%s_%d", TARGET, nr);
	sc->kc.cache = kmem_cache_create(sc->kc.name, stripe_size(rs),
					 0, 0, NULL, NULL);
	if (!sc->kc.cache)
		return -ENOMEM;

	/* Create memory cache client context and Allocate memory objects. */
	sc->dm_mem_cache_client = dm_mem_cache_client_create(
		stripes * stripe_pages(rs, rs->set.io_size) +
		2 * stripe_pages(rs, rs->recover.io_size),
		stripes + 2, rs->set.raid_devs);
	if (IS_ERR(sc->dm_mem_cache_client))
		return PTR_ERR(sc->dm_mem_cache_client);

	/* Allocate stripe for set recovery. */
	stripe = stripe_alloc(sc, rs->recover.io_size, keep);
	if (!stripe)
		return -ENOMEM;

	SetStripeRecover(stripe);
	rs->recover.stripe = stripe;
	return sc_grow(sc, stripes, keep);	/* Grow the cache. */
}

/* Destroy the stripe cache. */
static void sc_exit(struct stripe_cache *sc)
{
	if (sc->hash.hash) {
		if (sc->kc.cache) {
			BUG_ON(sc_shrink(sc, atomic_read(&sc->stripes)));
			kmem_cache_destroy(sc->kc.cache);
		}

		if (sc->dm_mem_cache_client)
			dm_mem_cache_client_destroy(sc->dm_mem_cache_client);

		hash_exit(&sc->hash);
	}
}

/*
 * Calculate RAID address
 *
 * Delivers tuple with the index of the data disk holding the chunk
 * in the set, the parity disks index and the start of the stripe
 * within the address space of the set (used as the stripe cache hash key).
 */
/* thx MD. */
static struct address *
raid_address(struct raid_set *rs, sector_t sector, struct address *addr)
{
	unsigned data_devs = rs->set.data_devs, di, pi,
		 raid_devs = rs->set.raid_devs;
	sector_t stripe, tmp;

	/*
	 * chunk_number = sector / chunk_size
	 * stripe = chunk_number / data_devs
	 * di = stripe % data_devs;
	 */
	stripe = sector >> rs->set.chunk_shift;
	di = sector_div(stripe, data_devs);

	switch (rs->set.raid_type->level) {
	case raid5:
		tmp = stripe;
		pi = sector_div(tmp, raid_devs);

		switch (rs->set.raid_type->algorithm) {
		case left_asym:		/* Left asymmetric. */
			pi = data_devs - pi;
		case right_asym:	/* Right asymmetric. */
			if (di >= pi)
				di++;
			break;

		case left_sym:		/* Left symmetric. */
			pi = data_devs - pi;
		case right_sym:		/* Right symmetric. */
			di = (pi + di + 1) % raid_devs;
			break;

		default:
			DMERR("Unknown RAID algorithm %d",
			      rs->set.raid_type->algorithm);
			goto out;
		}

		break;

	case raid4:
		pi = rs->set.pi;
		if (di >= pi)
			di++;
		break;

	default:
		DMERR("Unknown RAID level %d", rs->set.raid_type->level);
		goto out;
	}

	/*
	 * Hash key = start offset on any single device of the RAID set;
	 * adjusted in case io size differs from chunk size.
	 */
	addr->key = (stripe << rs->set.chunk_shift) +
		    (sector & rs->set.io_shift_mask);
	addr->di = di;
	addr->pi = pi;

   out:
	return addr;
}

/*
 * Copy data across between stripe pages and bio vectors.
 *
 * Pay attention to data alignment in stripe and bio pages.
 */
static void
bio_copy_page_list(int rw, struct stripe *stripe,
		   struct page_list *pl, struct bio *bio)
{
	unsigned i, page_offset;
	void *page_addr;
	struct raid_set *rs = RS(stripe->sc);
	struct bio_vec *bv;

	/* Get start page in page list for this sector. */
	i = (bio->bi_sector & rs->set.io_mask) / SECTORS_PER_PAGE;
	pl = pl_elem(pl, i);

	page_addr = page_address(pl->page);
	page_offset = to_bytes(bio->bi_sector & (SECTORS_PER_PAGE - 1));

	/* Walk all segments and copy data across between bio_vecs and pages. */
	bio_for_each_segment(bv, bio, i) {
		int len = bv->bv_len, size;
		unsigned bio_offset = 0;
		void *bio_addr = __bio_kmap_atomic(bio, i, KM_USER0);
   redo:
		size = (page_offset + len > PAGE_SIZE) ?
		       PAGE_SIZE - page_offset : len;

		if (rw == READ)
			memcpy(bio_addr + bio_offset,
			       page_addr + page_offset, size);
		else
			memcpy(page_addr + page_offset,
			       bio_addr + bio_offset, size);

		page_offset += size;
		if (page_offset == PAGE_SIZE) {
			/*
			 * We reached the end of the chunk page ->
			 * need refer to the next one to copy more data.
			 */
			len -= size;
			if (len) {
				/* Get next page. */
				pl = pl->next;
				BUG_ON(!pl);
				page_addr = page_address(pl->page);
				page_offset = 0;
				bio_offset += size;
				/* REMOVEME: statistics. */
				atomic_inc(rs->stats + S_BIO_COPY_PL_NEXT);
				goto redo;
			}
		}

		__bio_kunmap_atomic(bio_addr, KM_USER0);
	}
}

/*
 * Xor optimization macros.
 */
/* Xor data pointer declaration and initialization macros. */
#define DECLARE_2	xor_t *d0 = data[0], *d1 = data[1]
#define DECLARE_3	DECLARE_2, *d2 = data[2]
#define DECLARE_4	DECLARE_3, *d3 = data[3]
#define DECLARE_5	DECLARE_4, *d4 = data[4]
#define DECLARE_6	DECLARE_5, *d5 = data[5]
#define DECLARE_7	DECLARE_6, *d6 = data[6]
#define DECLARE_8	DECLARE_7, *d7 = data[7]

/* Xor unrole macros. */
#define D2(n)	d0[n] = d0[n] ^ d1[n]
#define D3(n)	D2(n) ^ d2[n]
#define D4(n)	D3(n) ^ d3[n]
#define D5(n)	D4(n) ^ d4[n]
#define D6(n)	D5(n) ^ d5[n]
#define D7(n)	D6(n) ^ d6[n]
#define D8(n)	D7(n) ^ d7[n]

#define	X_2(macro, offset)	macro(offset); macro(offset + 1);
#define	X_4(macro, offset)	X_2(macro, offset); X_2(macro, offset + 2);
#define	X_8(macro, offset)	X_4(macro, offset); X_4(macro, offset + 4);
#define	X_16(macro, offset)	X_8(macro, offset); X_8(macro, offset + 8);
#define	X_32(macro, offset)	X_16(macro, offset); X_16(macro, offset + 16);
#define	X_64(macro, offset)	X_32(macro, offset); X_32(macro, offset + 32);

/* Define a _xor_#chunks_#xors_per_run() function. */
#define	_XOR(chunks, xors_per_run) \
static void _xor ## chunks ## _ ## xors_per_run(xor_t **data) \
{ \
	unsigned end = XOR_SIZE / sizeof(data[0]), i; \
	DECLARE_ ## chunks; \
\
	for (i = 0; i < end; i += xors_per_run) { \
		X_ ## xors_per_run(D ## chunks, i); \
	} \
}

/* Define xor functions for 2 - 8 chunks. */
#define	MAKE_XOR_PER_RUN(xors_per_run) \
	_XOR(2, xors_per_run); _XOR(3, xors_per_run); \
	_XOR(4, xors_per_run); _XOR(5, xors_per_run); \
	_XOR(6, xors_per_run); _XOR(7, xors_per_run); \
	_XOR(8, xors_per_run);

MAKE_XOR_PER_RUN(8)	/* Define _xor_*_8() functions. */
MAKE_XOR_PER_RUN(16)	/* Define _xor_*_16() functions. */
MAKE_XOR_PER_RUN(32)	/* Define _xor_*_32() functions. */
MAKE_XOR_PER_RUN(64)	/* Define _xor_*_64() functions. */

#define MAKE_XOR(xors_per_run) \
struct { \
	void (*f)(xor_t**); \
} static xor_funcs ## xors_per_run[] = { \
	{ NULL }, \
	{ NULL }, \
	{ _xor2_ ## xors_per_run }, \
	{ _xor3_ ## xors_per_run }, \
	{ _xor4_ ## xors_per_run }, \
	{ _xor5_ ## xors_per_run }, \
	{ _xor6_ ## xors_per_run }, \
	{ _xor7_ ## xors_per_run }, \
	{ _xor8_ ## xors_per_run }, \
}; \
\
static void xor_ ## xors_per_run(unsigned n, xor_t **data) \
{ \
	/* Call respective function for amount of chunks. */ \
	xor_funcs ## xors_per_run[n].f(data); \
}

/* Define xor_8() - xor_64 functions. */
MAKE_XOR(8)
MAKE_XOR(16)
MAKE_XOR(32)
MAKE_XOR(64)

/* Maximum number of chunks, which can be xor'ed in one go. */
#define	XOR_CHUNKS_MAX	(ARRAY_SIZE(xor_funcs8) - 1)

struct xor_func {
	xor_function_t f;
	const char *name;
} static xor_funcs[] = {
	{xor_8,   "xor_8"},
	{xor_16,  "xor_16"},
	{xor_32,  "xor_32"},
	{xor_64,  "xor_64"},
};

/*
 * Calculate crc.
 *
 * This indexes into the page list of the stripe.
 *
 * All chunks will be xored into the parity chunk
 * in maximum groups of xor.chunks.
 *
 * FIXME: try mapping the pages on discontiguous memory.
 */
static void xor(struct stripe *stripe, unsigned pi, unsigned sector)
{
	struct raid_set *rs = RS(stripe->sc);
	unsigned max_chunks = rs->xor.chunks, n, p;
	unsigned o = sector / SECTORS_PER_PAGE; /* Offset into the page_list. */
	xor_t **d = rs->data;
	xor_function_t xor_f = rs->xor.f->f;

	/* Address of parity page to xor into. */
	d[0] = page_address(pl_elem(PL(stripe, pi), o)->page);

	/* Preset pointers to data pages. */
	for (n = 1, p = rs->set.raid_devs; p--; ) {
		if (p != pi && PageIO(PAGE(stripe, p)))
			d[n++] = page_address(pl_elem(PL(stripe, p), o)->page);

		/* If max chunks -> xor .*/
		if (n == max_chunks) {
			xor_f(n, d);
			n = 1;
		}
	}

	/* If chunks -> xor. */
	if (n > 1)
		xor_f(n, d);

	/* Set parity page uptodate and clean. */
	page_set(PAGE(stripe, pi), CLEAN);
}

/* Common xor loop through all stripe page lists. */
static void common_xor(struct stripe *stripe, sector_t count,
		       unsigned off, unsigned p)
{
	unsigned sector;

	for (sector = off; sector < count; sector += SECTORS_PER_XOR)
		xor(stripe, p, sector);

	atomic_inc(RS(stripe->sc)->stats + S_XORS); /* REMOVEME: statistics. */
}

/*
 * Calculate parity sectors on intact stripes.
 *
 * Need to calculate raid address for recover stripe, because its
 * chunk sizes differs and is typically larger than io chunk size.
 */
static void parity_xor(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);
	unsigned chunk_size = rs->set.chunk_size,
		 io_size = stripe->io.size, 
		 xor_size = chunk_size > io_size ? io_size : chunk_size;
	sector_t off;

	/* This can be the recover stripe with a larger io size. */
	for (off = 0; off < io_size; off += xor_size) {
		unsigned pi;

		/*
		 * Recover stripe likely is bigger than regular io
		 * ones and has no precalculated parity disk index ->
		 * need to calculate RAID address.
		 */
		if (unlikely(StripeRecover(stripe))) {
			struct address addr;

			raid_address(rs,
				     (stripe->key + off) * rs->set.data_devs,
				     &addr);
			pi = addr.pi;
			stripe_zero_pl_part(stripe, pi, off,
					    rs->set.chunk_size);
		} else
			pi = stripe->idx.parity;

		common_xor(stripe, xor_size, off, pi);
		page_set(PAGE(stripe, pi), DIRTY);
	}
}

/* Reconstruct missing chunk. */
static void reconstruct_xor(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);
	int p = stripe->idx.recover;

	BUG_ON(p < 0);

	/* REMOVEME: statistics. */
	atomic_inc(rs->stats + (raid_set_degraded(rs) ?
		    S_RECONSTRUCT_EI : S_RECONSTRUCT_DEV));

	/* Zero chunk to be reconstructed. */
	stripe_zero_chunk(stripe, p);
	common_xor(stripe, stripe->io.size, 0, p);
}

/*
 * Try getting a stripe either from the hash or from the lru list
 */
static inline void _stripe_get(struct stripe *stripe)
{
	atomic_inc(&stripe->cnt);
}

static struct stripe *stripe_get(struct raid_set *rs, struct address *addr)
{
	struct stripe_cache *sc = &rs->sc;
	struct stripe *stripe;


	stripe = stripe_lookup(sc, addr->key);
	if (stripe) {
		_stripe_get(stripe);
		/* Remove from the lru list if on. */
		stripe_lru_del(stripe, LIST_LOCKED);
		atomic_inc(rs->stats + S_HITS_1ST); /* REMOVEME: statistics. */
	} else {
		/* Second try to get an LRU stripe. */
		stripe = stripe_lru_pop(sc);
		if (stripe) {
			_stripe_get(stripe);
			/* Invalidate before reinserting with changed key. */
			stripe_invalidate(stripe);
			stripe->key = addr->key;
			stripe->region = rh_sector_to_region(rs->recover.rh,
							     addr->key);
			stripe->idx.parity = addr->pi;
			sc_insert(sc, stripe);
			/* REMOVEME: statistics. */
			atomic_inc(rs->stats + S_INSCACHE);
		}
	}

	return stripe;
}

/*
 * Decrement reference count on a stripe.
 *
 * Move it to list of LRU stripes if zero.
 */
static void stripe_put(struct stripe *stripe)
{
	if (atomic_dec_and_test(&stripe->cnt)) {
		if (TestClearStripeActive(stripe))
			atomic_dec(&stripe->sc->active_stripes);

		/* Put stripe onto the LRU list. */
		stripe_lru_add(stripe, POS_TAIL, LIST_LOCKED);
	}

	BUG_ON(atomic_read(&stripe->cnt) < 0);
}

/*
 * Process end io
 *
 * I need to do it here because I can't in interrupt
 *
 * Read and write functions are split in order to avoid
 * conditionals in the main loop for performamce reasons.
 */
typedef void(*endio_helper_function)(struct stripe *, struct page_list *,
				     struct bio *);

/* Helper read bios on a page list. */
static void _bio_copy_page_list(struct stripe *stripe, struct page_list *pl,
				struct bio *bio)
{
	bio_copy_page_list(READ, stripe, pl, bio);
}

/* Helper write bios on a page list. */
static void _rh_dec(struct stripe *stripe, struct page_list *pl,
		    struct bio *bio)
{
	rh_dec(RS(stripe->sc)->recover.rh, stripe->region);
}

/* End io all bios on a page list. */
static inline int
page_list_endio(int rw, struct stripe *stripe, unsigned p, unsigned *count)
{
	int r = 0;
	struct bio_list *bl = BL(stripe, p, rw);

	if (!bio_list_empty(bl)) {
		struct page_list *pl = PL(stripe, p);
		struct page *page = pl->page;

		if (PageLocked(page))
			r = -EBUSY;
		else if (PageUptodate(page)) {
			struct bio *bio;
			struct raid_set *rs = RS(stripe->sc);
			endio_helper_function h_f =
			   rw == READ ? _bio_copy_page_list : _rh_dec;

			while ((bio = bio_list_pop(bl))) {
				h_f(stripe, pl, bio);
				_bio_endio(rs, bio, 0);
				stripe_put(stripe);
				if (count)
					(*count)++;
			}
		} else
			r = -EAGAIN;
	}

	return r;
}

/*
 * End io all reads/writes on a stripe copying
 * read date accross from stripe to bios.
 */
static int stripe_end_io(int rw, struct stripe *stripe, unsigned *count)
{
	int r = 0;
	unsigned p = RS(stripe->sc)->set.raid_devs;

	while (p--) {
		int rr = page_list_endio(rw, stripe, p, count);

		if (rr && r != -EIO)
			r = rr;
	}

	return r;
}

/* Fail all ios on a bio list and return # of bios. */
static unsigned
bio_list_fail(struct raid_set *rs, struct stripe *stripe, struct bio_list *bl)
{
	unsigned r;
	struct bio *bio;

	raid_set_dead(rs);

	/* Update region counters. */
	if (stripe) {
		void *rh = rs->recover.rh;

		bio_list_for_each(bio, bl) {
			if (bio_data_dir(bio) == WRITE)
				rh_dec(rh, stripe->region);
		}
	}

	/* Error end io all bios. */
	for (r = 0; (bio = bio_list_pop(bl)); r++)
		_bio_endio(rs, bio, -EIO);

	return r;
}

/* Fail all ios of a bio list of a stripe and drop io pending count. */
static void
stripe_bio_list_fail(struct raid_set *rs, struct stripe *stripe,
		     struct bio_list *bl)
{
	unsigned put = bio_list_fail(rs, stripe, bl);

	while (put--)
		stripe_put(stripe);
}

/* Fail all ios hanging off all bio lists of a stripe. */
static void stripe_fail_io(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);
	unsigned p = rs->set.raid_devs;

	stripe_evict(stripe);

	while (p--) {
		struct stripe_set *ss = stripe->ss + p;
		int i = ARRAY_SIZE(ss->bl);

		while (i--)
			stripe_bio_list_fail(rs, stripe, ss->bl + i);
	}
}

/*
 * Handle all stripes by handing them to the daemon, because we can't
 * map their pages to copy the data in interrupt context.
 *
 * We don't want to handle them here either, while interrupts are disabled.
 */

/* Read/write endio function for dm-io (interrupt context). */
static void endio(unsigned long error, void *context)
{
	struct dm_mem_cache_object *obj = context;
	struct stripe_set *ss = obj->private;
	struct stripe *stripe = ss->stripe;
	struct page *page = obj->pl->page;

	if (unlikely(error))
		stripe_error(stripe, page);
	else 
		page_set(page, CLEAN);

	ClearPageLocked(page);
	stripe_io_dec(stripe);

	/* Add stripe to endio list and wake daemon. */
	stripe_endio_push(stripe);
}

/*
 * Recovery io throttling
 */
/* Conditionally reset io counters. */
enum count_type { IO_WORK = 0, IO_RECOVER };
static int recover_io_reset(struct raid_set *rs)
{
	unsigned long j = jiffies;

	/* Pay attention to jiffies overflows. */
	if (j > rs->recover.last_jiffies + HZ
	    || j < rs->recover.last_jiffies) {
		rs->recover.last_jiffies = j;
		atomic_set(rs->recover.io_count + IO_WORK, 0);
		atomic_set(rs->recover.io_count + IO_RECOVER, 0);
		return 1;
	}

	return 0;
}

/* Count ios. */
static INLINE void
recover_io_count(struct raid_set *rs, struct stripe *stripe)
{
	if (RSRecover(rs)) {
		recover_io_reset(rs);
		atomic_inc(rs->recover.io_count +
			   (stripe == rs->recover.stripe ?
			    IO_RECOVER : IO_WORK));
	}
}

/* Read/Write a page_list asynchronously. */
static void page_list_rw(struct stripe *stripe, unsigned p)
{
	struct stripe_cache *sc = stripe->sc;
	struct raid_set *rs = RS(sc);
	struct dm_mem_cache_object *obj = stripe->obj + p;
	struct page_list *pl = obj->pl;
	struct page *page = pl->page;
	struct raid_dev *dev = rs->dev + p;
	struct io_region io = {
		.bdev = dev->dev->bdev,
		.sector = stripe->key,
		.count = stripe->io.size,
	};
	struct dm_io_request control = {
		.bi_rw = PageDirty(page) ? WRITE : READ,
		.mem.type = DM_IO_PAGE_LIST,
		.mem.ptr.pl = pl,
		.mem.offset = 0,
		.notify.fn = endio,
		.notify.context = obj,
		.client = sc->dm_io_client,
	};

	BUG_ON(PageLocked(page));

	/*
	 * Don't rw past end of device, which can happen, because
	 * typically sectors_per_dev isn't divisable by io_size.
	 */
	if (unlikely(io.sector + io.count > rs->set.sectors_per_dev))
		io.count = rs->set.sectors_per_dev - io.sector;

	io.sector += dev->start;	/* Add <offset>. */
	recover_io_count(rs, stripe);	/* Recovery io accounting. */

	/* REMOVEME: statistics. */
	atomic_inc(rs->stats + (PageDirty(page) ? S_DM_IO_WRITE: S_DM_IO_READ));

	ClearPageError(page);
	SetPageLocked(page);
	io_dev_queued(dev);
	BUG_ON(dm_io(&control, 1, &io, NULL));
}

/*
 * Write dirty / read not uptodate page lists of a stripe.
 */
static unsigned stripe_page_lists_rw(struct raid_set *rs, struct stripe *stripe)
{
	unsigned r;

	/*
	 * Increment the pending count on the stripe
	 * first, so that we don't race in endio().
	 *
	 * An inc (IO) is needed for any page:
	 *
	 * o not uptodate
	 * o dirtied by writes merged
	 * o dirtied by parity calculations
	 */
	r = for_each_io_dev(rs, stripe, _stripe_io_inc);
	if (r) {
		/* io needed: chunks are not uptodate/dirty. */
		int max;	/* REMOVEME: */
		struct stripe_cache *sc = &rs->sc;

		if (!TestSetStripeActive(stripe))
			atomic_inc(&sc->active_stripes);

		/* Take off the lru list in case it got added there. */
		stripe_lru_del(stripe, LIST_LOCKED);

		/* Submit actual io. */
		for_each_io_dev(rs, stripe, page_list_rw);

		/* REMOVEME: statistics */
		max = sc_active(sc);
		if (atomic_read(&sc->max_active_stripes) < max)
			atomic_set(&sc->max_active_stripes, max);

		atomic_inc(rs->stats + S_FLUSHS);
		/* END REMOVEME: statistics */
	}

	return r;
}

/* Work in all pending writes. */
static INLINE void _writes_merge(struct stripe *stripe, unsigned p)
{
	struct bio_list *write = BL(stripe, p, WRITE);

	if (!bio_list_empty(write)) {
		struct page_list *pl = stripe->obj[p].pl;
		struct bio *bio;
		struct bio_list *write_merged = BL(stripe, p, WRITE_MERGED);

		/*
		 * We can play with the lists without holding a lock,
		 * because it is just us accessing them anyway.
		 */
		bio_list_for_each(bio, write)
			bio_copy_page_list(WRITE, stripe, pl, bio);

		bio_list_merge(write_merged, write);
		bio_list_init(write);
		page_set(pl->page, DIRTY);
	}
}

/* Merge in all writes hence dirtying respective pages. */
static INLINE void writes_merge(struct stripe *stripe)
{
	unsigned p = RS(stripe->sc)->set.raid_devs;

	while (p--)
		_writes_merge(stripe, p);
}

/* Check, if a chunk gets completely overwritten. */
static INLINE int stripe_check_overwrite(struct stripe *stripe, unsigned p)
{
	unsigned sectors = 0;
	struct bio *bio;
	struct bio_list *bl = BL(stripe, p, WRITE);

	bio_list_for_each(bio, bl)
		sectors += bio_sectors(bio);

	return sectors == RS(stripe->sc)->set.io_size;
}

/*
 * Prepare stripe to avoid io on broken/reconstructed
 * drive in order to reconstruct date on endio.
 */
enum prepare_type { IO_ALLOW, IO_PROHIBIT };
static void stripe_prepare(struct stripe *stripe, unsigned p,
			   enum prepare_type type)
{
	struct page *page = PAGE(stripe, p);

	switch (type) {
	case IO_PROHIBIT:
		/*
 		 * In case we prohibit, we gotta make sure, that
 		 * io on all chunks is allowed initially.
 		 */
		stripe_allow_io(stripe);

		/* REMOVEME: statistics. */
		atomic_inc(RS(stripe->sc)->stats + S_PROHIBITPAGEIO);
		ProhibitPageIO(page);
		stripe->idx.recover = p;
		SetStripeReconstruct(stripe);
		break;

	case IO_ALLOW:
		AllowPageIO(page);
		stripe->idx.recover = -1;
		ClearStripeReconstruct(stripe);
		break;

	default:
		BUG();
	}
}

/*
 * Degraded/reconstruction mode.
 *
 * Check stripe state to figure which chunks don't need IO.
 */
static INLINE void stripe_check_reconstruct(struct stripe *stripe,
					    int prohibited)
{
	struct raid_set *rs = RS(stripe->sc);

	/*
	 * Degraded mode (device(s) failed) ->
	 * avoid io on the failed device.
	 */
	if (unlikely(raid_set_degraded(rs))) {
		/* REMOVEME: statistics. */
		atomic_inc(rs->stats + S_DEGRADED);
		stripe_prepare(stripe, rs->set.ei, IO_PROHIBIT);
		return;
	} else {
		/*
		 * Reconstruction mode (ie. a particular device or
		 * some (rotating) parity chunk is being resynchronized) ->
		 *   o make sure all needed pages are read in
		 *   o writes are allowed to go through
		 */
		int r = region_state(rs, stripe->key, RH_NOSYNC);

		if (r) {
			/* REMOVEME: statistics. */
			atomic_inc(rs->stats + S_NOSYNC);
			stripe_prepare(stripe, dev_for_parity(stripe),
				       IO_PROHIBIT);
			return;
		}
	}

 	/*
	 * All disks good. Avoid reading parity chunk and reconstruct it
	 * unless we have prohibited io to chunk(s).
	 */
	if (!prohibited) {
		if (StripeMerged(stripe))
			stripe_prepare(stripe, stripe->idx.parity, IO_ALLOW);
		else {
			stripe_prepare(stripe, stripe->idx.parity, IO_PROHIBIT);

			/*
			 * Overrule stripe_prepare to reconstruct the
			 * parity chunk, because it'll be created new anyway.
			 */
			ClearStripeReconstruct(stripe);
		}
	}
}

/* Check, if stripe is ready to merge writes. */
static INLINE int stripe_check_merge(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);
	int prohibited = 0;
	unsigned chunks = 0, p = rs->set.raid_devs;

	/* Walk all chunks. */
	while (p--) {
		struct page *page = PAGE(stripe, p);

		/* Can't merge active chunks. */
		if (PageLocked(page)) {
			/* REMOVEME: statistics. */
			atomic_inc(rs->stats + S_MERGE_PAGE_LOCKED);
			break;
		}

		/* Can merge uptodate chunks and have to count parity chunk. */
		if (PageUptodate(page) || p == stripe->idx.parity) {
			chunks++;
			continue;
		}

		/* Read before write ordering. */
		if (RSCheckOverwrite(rs) &&
		    bio_list_empty(BL(stripe, p, READ))) {
			int r = stripe_check_overwrite(stripe, p);

			if (r) {
				chunks++;
				/* REMOVEME: statistics. */
				atomic_inc(RS(stripe->sc)->stats +
					   S_PROHIBITPAGEIO);
				ProhibitPageIO(page);
				prohibited = 1;
			}
		}
	}

	if (chunks == rs->set.raid_devs) {
		/* All pages are uptodate or get written over or mixture. */
		/* REMOVEME: statistics. */
		atomic_inc(rs->stats + S_CAN_MERGE);
		return 0;
	} else
		/* REMOVEME: statistics.*/
		atomic_inc(rs->stats + S_CANT_MERGE);

	return prohibited ? 1 : -EPERM;
}

/* Check, if stripe is ready to merge writes. */
static INLINE int stripe_check_read(struct stripe *stripe)
{
	int r = 0;
	unsigned p = RS(stripe->sc)->set.raid_devs;

	/* Walk all chunks. */
	while (p--) {
		struct page *page = PAGE(stripe, p);

		if (!PageLocked(page) &&
		    bio_list_empty(BL(stripe, p, READ))) {
			ProhibitPageIO(page);
			r = 1;
		}
	}

	return r;
}

/*
 * Read/write a stripe.
 *
 * All stripe read/write activity goes through this function.
 *
 * States to cover:
 *   o stripe to read and/or write
 *   o stripe with error to reconstruct
 */
static int stripe_rw(struct stripe *stripe)
{
	struct raid_set *rs = RS(stripe->sc);
	int prohibited = 0, r;

	/*
	 * Check the state of the RAID set and if degraded (or
	 * resynchronizing for reads), read in all other chunks but
	 * the one on the dead/resynchronizing device in order to be
	 * able to reconstruct the missing one.
	 *
	 * Merge all writes hanging off uptodate pages of the stripe.
	 */

	/* Initially allow io on all chunks and prohibit below, if necessary. */
	stripe_allow_io(stripe);

	if (StripeRBW(stripe)) {
		r = stripe_check_merge(stripe);
		if (!r) {
			/*
			 * If I could rely on valid parity (which would only
			 * be sure in case of a full synchronization),
			 * I could xor a fraction of chunks out of
			 * parity and back in.
			 *
			 * For the time being, I got to redo parity...
			 */
			// parity_xor(stripe);		/* Xor chunks out. */
			stripe_zero_chunk(stripe, stripe->idx.parity);
			writes_merge(stripe);		/* Merge writes in. */
			parity_xor(stripe);		/* Update parity. */
			ClearStripeRBW(stripe);		/* Disable RBW. */
			SetStripeMerged(stripe);	/* Writes merged. */
		} 

		if (r > 0)
			prohibited = 1;
	} else if (!raid_set_degraded(rs))
		/* Only allow for read avoidance if not degraded. */
		prohibited = stripe_check_read(stripe);

	/*
	 * Check, if io needs to be allowed/prohibeted on certain chunks
	 * because of a degraded set or reconstruction on a region.
	 */
	stripe_check_reconstruct(stripe, prohibited);

	/* Now submit any reads/writes. */
	r = stripe_page_lists_rw(rs, stripe);
	if (!r) {
		/*
		 * No io submitted because of chunk io prohibited or
		 * locked pages -> push to end io list for processing.
		 */
		atomic_inc(rs->stats + S_NO_RW); /* REMOVEME: statistics. */
		stripe_endio_push(stripe);
		wake_do_raid(rs);	/* Wake myself. */
	}

	return 0;
}

/* Flush stripe either via flush list or imeediately. */
enum flush_type { FLUSH_DELAY, FLUSH_NOW };
static int stripe_flush(struct stripe *stripe, enum flush_type type)
{
	int r = 0;

	stripe_lru_del(stripe, LIST_LOCKED);

	/* Delay flush by putting it on io list for later processing. */
	if (type == FLUSH_DELAY)
		stripe_io_add(stripe, POS_TAIL, LIST_UNLOCKED);

	/* Immediately flush. */
	else if (type == FLUSH_NOW) {
		if (likely(raid_set_operational(RS(stripe->sc))))
			r = stripe_rw(stripe); /* Read/write stripe. */
		else
			/* Optimization: Fail early on failed sets. */
			stripe_fail_io(stripe);
	} else
		BUG();

	return r;
}

/*
 * Queue reads and writes to a stripe by hanging
 * their bios off the stripsets read/write lists.
 *
 * Endio reads on uptodate chunks.
 */
static INLINE int stripe_queue_bio(struct raid_set *rs, struct bio *bio,
				   struct bio_list *reject)
{
	int r = 0;
	struct address addr;
	struct stripe *stripe =
		stripe_get(rs, raid_address(rs, bio->bi_sector, &addr));

	if (stripe) {
		int rr, rw = bio_data_dir(bio);

		rr = stripe_lock(rs, stripe, rw, addr.key); /* Lock stripe */
		if (rr) {
			stripe_put(stripe);
			goto out;
		}

		/* Distinguish read and write cases. */
		bio_list_add(BL(stripe, addr.di, rw), bio);

		/* REMOVEME: statistics */
		atomic_inc(rs->stats + (rw == WRITE ?
			   S_BIOS_ADDED_WRITE : S_BIOS_ADDED_READ));

		if (rw == READ)
			SetStripeRead(stripe);
		else {
			SetStripeRBW(stripe);

			/* Inrement pending write count on region. */
			rh_inc(rs->recover.rh, stripe->region);
			r = 1;	/* Region hash needs a flush. */
		}

		/*
		 * Optimize stripe flushing:
		 *
		 * o directly start io for read stripes.
		 *
		 * o put stripe onto stripe caches io_list for RBW,
		 *   so that do_flush() can belabour it after we put
		 *   more bios to the stripe for overwrite optimization.
		 */
		stripe_flush(stripe,
			     StripeRead(stripe) ? FLUSH_NOW : FLUSH_DELAY);

	/* Got no stripe from cache -> reject bio. */
	} else {
   out:
		bio_list_add(reject, bio);
		/* REMOVEME: statistics. */
		atomic_inc(rs->stats + S_IOS_POST);
	}

	return r;
}

/*
 * Recovery functions
 */
/* Read a stripe off a raid set for recovery. */
static int recover_read(struct raid_set *rs, struct stripe *stripe, int idx)
{
	/* Invalidate all pages so that they get read in. */
	stripe_pages_invalidate(stripe);

	/* Allow io on all recovery chunks. */
	stripe_allow_io(stripe);

	if (idx > -1)
		ProhibitPageIO(PAGE(stripe, idx));

	stripe->key = rs->recover.pos;
	return stripe_page_lists_rw(rs, stripe);
}

/* Write a stripe to a raid set for recovery. */
static int recover_write(struct raid_set *rs, struct stripe *stripe, int idx)
{
	/*
	 * If this is a reconstruct of a particular device, then
	 * reconstruct the respective page(s), else create parity page(s).
	 */
	if (idx > -1) {
		struct page *page = PAGE(stripe, idx);

		AllowPageIO(page);
		stripe_zero_chunk(stripe, idx);
		common_xor(stripe, stripe->io.size, 0, idx);
		page_set(page, DIRTY);
	} else
		parity_xor(stripe);

	return stripe_page_lists_rw(rs, stripe);
}

/* Recover bandwidth available ?. */
static int recover_bandwidth(struct raid_set *rs)
{
	int r, work;

	/* On reset -> allow recovery. */
	r = recover_io_reset(rs);
	if (r || RSBandwidth(rs))
		goto out;

	work = atomic_read(rs->recover.io_count + IO_WORK);
	if (work) {
		/* Pay attention to larger recover stripe size. */
		int recover =
		    atomic_read(rs->recover.io_count + IO_RECOVER) *
				rs->recover.stripe->io.size /
				rs->set.io_size;

		/*
		 * Don't use more than given bandwidth of
		 * the work io for recovery.
		 */
		if (recover > work / rs->recover.bandwidth_work) {
			/* REMOVEME: statistics. */
			atomic_inc(rs->stats + S_NO_BANDWIDTH);
			return 0;
		}
	}

   out:
	atomic_inc(rs->stats + S_BANDWIDTH);	/* REMOVEME: statistics. */
	return 1;
}

/* Try to get a region to recover. */
static int recover_get_region(struct raid_set *rs)
{
	struct recover *rec = &rs->recover;
	void *rh = rec->rh;

	/* Start quiescing some regions. */
	if (!RSRegionGet(rs)) {
		int r = recover_bandwidth(rs); /* Enough bandwidth ?. */

		if (r) {
			if (rh_recovery_prepare(rh) < 0) {
				DMINFO("No %sregions to recover",
				       rec->nr_regions_to_recover ?
				       "more " : "");
				return -ENOENT;
			}
		} else
			return -EAGAIN;

		SetRSRegionGet(rs);
	}

	if (!rec->reg) {
		rec->reg = rh_recovery_start(rh);
		if (rec->reg) {
			/*
			 * A reference for the the region I'll
			 * keep till I've completely synced it.
			 */
			io_get(rs);
			rec->pos =
			   rh_region_to_sector(rh,
					       rh_get_region_key(rec->reg));
			rec->end = rec->pos + rh_get_region_size(rh);
			return 1;
		} else
			return -EAGAIN;
	}

	return 0;
}

/* Read/write a recovery stripe. */
static INLINE int recover_stripe_rw(struct raid_set *rs, struct stripe *stripe)
{
	/* Read/write flip-flop. */
	if (TestClearStripeRBW(stripe)) {
		SetStripeRead(stripe);
		return recover_read(rs, stripe, idx_get(rs));
	} else if (TestClearStripeRead(stripe))
		return recover_write(rs, stripe, idx_get(rs));

	return 0;
}

/* Reset recovery variables. */
static void recovery_region_reset(struct raid_set *rs)
{
	rs->recover.reg = NULL;
	ClearRSRegionGet(rs);
}

/* Update region hash state. */
static void recover_rh_update(struct raid_set *rs, int error)
{
	struct recover *rec = &rs->recover;
	void *rh = rec->rh;
	void *reg = rec->reg;

	if (reg) {
		rh_recovery_end(reg, error);
		if (!error)
			rec->nr_regions_recovered++;

		recovery_region_reset(rs);
	}

	rh_update_states(rh);
	rh_flush(rh);
	io_put(rs);	/* Release the io reference for the region. */
}

/* Called by main io daemon to recover regions. */
static INLINE void do_recovery(struct raid_set *rs)
{
	if (RSRecover(rs)) {
		int r;
		struct recover *rec = &rs->recover;
		struct stripe *stripe = rec->stripe;

		/* If recovery is active -> return. */
		if (StripeActive(stripe))
			return;

		/* io error is fatal for recovery -> stop it. */
		if (unlikely(StripeError(stripe)))
			goto err;

		/* Get a region to recover. */
		r = recover_get_region(rs);
		switch (r) {
		case 1:	/* Got a new region. */
			/* Flag read before write. */
			ClearStripeRead(stripe);
			SetStripeRBW(stripe);
			break;

		case 0:
			/* Got a region in the works. */
			r = recover_bandwidth(rs);
			if (r) /* Got enough bandwidth. */
				break;

		case -EAGAIN:
			/* No bandwidth/quiesced region yet, try later. */
			wake_do_raid_delayed(rs, HZ / 10);
			return;

		case -ENOENT:	/* No more regions. */
			dm_table_event(rs->ti->table);
			goto free;
		}

		/* Read/write a recover stripe. */
		r = recover_stripe_rw(rs, stripe);
		if (r) {
			/* IO initiated, get another reference for the IO. */
			io_get(rs);
			return;
		}

		/* Update recovery position within region. */
		rec->pos += stripe->io.size;

		/* If we're at end of region, update region hash. */
		if (rec->pos >= rec->end ||
		    rec->pos >= rs->set.sectors_per_dev)
			recover_rh_update(rs, 0);
		else
			SetStripeRBW(stripe);

		/* Schedule myself for another round... */
		wake_do_raid(rs);
		return;

   err:
		raid_set_check_degrade(rs, stripe);

		{
			char buf[BDEVNAME_SIZE];
	
			DMERR("stopping recovery due to "
			      "ERROR on /dev/%s, stripe at offset %llu",
			      bdevname(rs->dev[rs->set.ei].dev->bdev, buf),
			      (unsigned long long) stripe->key);
	
		}

		/* Make sure, that all quiesced regions get released. */
		do {
			if (rec->reg)
				rh_recovery_end(rec->reg, -EIO);
	
			rec->reg = rh_recovery_start(rec->rh);
		} while (rec->reg);
	
		recover_rh_update(rs, -EIO);
   free:
		stripe_recover_free(rs);
		rs->set.dev_to_init = -1;
		rs->recover.end_jiffies = jiffies;
		/* Check for jiffies overrun. */
		if (rs->recover.end_jiffies < rs->recover.start_jiffies)
			rs->recover.end_jiffies = ~0;
	}
}

/*
 * END recovery functions
 */

/* End io process all stripes handed in by endio() callback. */
static void do_endios(struct raid_set *rs)
{
	struct stripe_cache *sc = &rs->sc;
	struct stripe *stripe;

	while ((stripe = stripe_endio_pop(sc))) {
		unsigned count;

		/* Recovery stripe special case. */
		if (unlikely(StripeRecover(stripe))) {
			if (stripe_io(stripe))
				continue;

			io_put(rs); /* Release region io reference. */
			ClearStripeActive(stripe);
			atomic_dec(&sc->active_stripes); /* REMOVEME: */
			continue;
		}

		/* Early end io all reads on any uptodate chunks. */
		stripe_end_io(READ, stripe, (count = 0, &count));
		if (stripe_io(stripe)) {
			if (count) /* REMOVEME: statistics. */
				atomic_inc(rs->stats + S_ACTIVE_READS);

			continue;
		}

		/* Set stripe inactive after all io got processed. */
		if (TestClearStripeActive(stripe))
			atomic_dec(&sc->active_stripes);

		/* Unlock stripe (for clustering). */
		stripe_unlock(rs, stripe);

		/*
		 * If an io error on a stripe occured and the RAID set
		 * is still operational, requeue the stripe for io.
		 */
		if (TestClearStripeError(stripe)) {
			raid_set_check_degrade(rs, stripe);
			ClearStripeReconstruct(stripe);

			if (!StripeMerged(stripe) &&
			    raid_set_operational(rs)) {
				stripe_pages_invalidate(stripe);
				stripe_flush(stripe, FLUSH_DELAY);
				/* REMOVEME: statistics. */
				atomic_inc(rs->stats + S_REQUEUE); 
				continue;
			}
		}

		/* Check if the RAID set is inoperational to error ios. */
		if (!raid_set_operational(rs)) {
			ClearStripeReconstruct(stripe);
			stripe_fail_io(stripe);
			BUG_ON(atomic_read(&stripe->cnt));
			continue;
		}

		/* Got to reconstruct a missing chunk. */
		if (TestClearStripeReconstruct(stripe))
			reconstruct_xor(stripe);

		/*
		 * Now that we've got a complete stripe, we can
		 * process the rest of the end ios on reads.
		 */
		BUG_ON(stripe_end_io(READ, stripe, NULL));
		ClearStripeRead(stripe);

		/*
		 * Read-before-write stripes need to be flushed again in
		 * order to work the write data into the pages *after*
		 * they were read in.
		 */
		if (TestClearStripeMerged(stripe))
			/* End io all bios which got merged already. */
			BUG_ON(stripe_end_io(WRITE_MERGED, stripe, NULL));

		/* Got to put on flush list because of new writes. */
		if (StripeRBW(stripe))
			stripe_flush(stripe, FLUSH_DELAY);
	}
}

/*
 * Stripe cache shrinking.
 */
static INLINE void do_sc_shrink(struct raid_set *rs)
{
	unsigned shrink = atomic_read(&rs->sc.stripes_to_shrink);

	if (shrink) {
		unsigned cur = atomic_read(&rs->sc.stripes);

		sc_shrink(&rs->sc, shrink);
		shrink -= cur - atomic_read(&rs->sc.stripes);
		atomic_set(&rs->sc.stripes_to_shrink, shrink);

		/*
		 * Wake myself up in case we failed to shrink the
		 * requested amount in order to try again later.
		 */
		if (shrink)
			wake_do_raid(rs);
	}
}


/*
 * Process all ios
 *
 * We do different things with the io depending on the
 * state of the region that it's in:
 *
 * o reads: hang off stripe cache or postpone if full
 *
 * o writes:
 *
 *  CLEAN/DIRTY/NOSYNC:	increment pending and hang io off stripe's stripe set.
 *			In case stripe cache is full or busy, postpone the io.
 *
 *  RECOVERING:		delay the io until recovery of the region completes.
 *
 */
static INLINE void do_ios(struct raid_set *rs, struct bio_list *ios)
{
	int r;
	unsigned flush = 0;
	void *rh = rs->recover.rh;
	struct bio *bio;
	struct bio_list delay, reject;

	bio_list_init(&delay);
	bio_list_init(&reject);

	/*
	 * Classify each io:
	 *    o delay to recovering regions
	 *    o queue to all other regions
	 */
	while ((bio = bio_list_pop(ios))) {
		/*
		 * In case we get a barrier bio, push it back onto
		 * the input queue unless all work queues are empty
		 * and the stripe cache is inactive.
		 */
		if (unlikely(bio_barrier(bio))) {
			/* REMOVEME: statistics. */
			atomic_inc(rs->stats + S_BARRIER);
			if (!list_empty(rs->sc.lists + LIST_IO) ||
			    !bio_list_empty(&delay) ||
			    !bio_list_empty(&reject) ||
			    sc_active(&rs->sc)) {
				bio_list_push(ios, bio);
				break;
			}
		}

		r = region_state(rs, _sector(rs, bio), RH_RECOVERING);
		if (unlikely(r)) {
			/* Got to wait for recovering regions. */
			bio_list_add(&delay, bio);
			SetRSBandwidth(rs);
		} else {
			/*
	 		 * Process ios to non-recovering regions by queueing
	 		 * them to stripes (does rh_inc()) for writes).
	 		 */
			flush += stripe_queue_bio(rs, bio, &reject);
		}
	}

	if (flush)
		rh_flush(rh);	/* Writes got queued -> flush dirty log. */

	/* Delay ios to regions which are recovering. */
	while ((bio = bio_list_pop(&delay))) {
		/* REMOVEME: statistics.*/
		atomic_inc(rs->stats + S_DELAYED_BIOS);
		atomic_inc(rs->stats + S_SUM_DELAYED_BIOS);
		rh_delay_by_region(rh, bio,
				   rh_sector_to_region(rh, _sector(rs, bio)));
	}

	/* Merge any rejected bios back to the head of the input list. */
	bio_list_merge_head(ios, &reject);
}

/* Flush any stripes on the io list. */
static INLINE void do_flush(struct raid_set *rs)
{
	struct list_head *list = rs->sc.lists + LIST_IO, *pos, *tmp;

	list_for_each_safe(pos, tmp, list) {
		int r = stripe_flush(list_entry(pos, struct stripe,
						lists[LIST_IO]), FLUSH_NOW);

		/* Remove from the list only if the stripe got processed. */
		if (!r)
			list_del_init(pos);
	}
}

/* Send an event in case we're getting too busy. */
static INLINE void do_busy_event(struct raid_set *rs)
{
	if ((sc_active(&rs->sc) > atomic_read(&rs->sc.stripes) * 4 / 5)) {
		if (!TestSetRSScBusy(rs))
			dm_table_event(rs->ti->table);
	} else
		ClearRSScBusy(rs);
}

static inline void blk_unplug(request_queue_t *q)
{
	if (q)
		q->unplug_fn(q);
}

/* Unplug: let the io role on the sets devices. */
static INLINE void do_unplug(struct raid_set *rs)
{
	struct raid_dev *dev = rs->dev + rs->set.raid_devs;

	while (dev-- > rs->dev) {
		/* Only call any device unplug function, if io got queued. */
		if (io_dev_clear(dev))
			blk_unplug(bdev_get_queue(dev->dev->bdev));
	}
}

/*-----------------------------------------------------------------
 * RAID daemon
 *---------------------------------------------------------------*/
/*
 * o belabour all end ios
 * o optionally shrink the stripe cache
 * o update the region hash states
 * o optionally do recovery
 * o grab the input queue
 * o work an all requeued or new ios and perform stripe cache flushs
 *   unless the RAID set is inoperational (when we error ios)
 * o check, if the stripe cache gets too busy and throw an event if so
 * o unplug any component raid devices with queued bios
 */
static void do_raid(void *data)
{
	struct work_struct *ws = data;
	struct raid_set *rs = container_of(ws, struct raid_set, io.ws);
	struct bio_list *ios = &rs->io.work, *ios_in = &rs->io.in;
	spinlock_t *lock = &rs->io.in_lock;
	
	/*
	 * We always need to end io, so that ios
	 * can get errored in case the set failed
	 * and the region counters get decremented
	 * before we update the region hash states.
	 */
   redo:
	do_endios(rs);

	/*
	 * Now that we've end io'd, which may have put stripes on
	 * the LRU list, we shrink the stripe cache if requested.
	 */
	do_sc_shrink(rs);

	/* Update region hash states before we go any further. */
	rh_update_states(rs->recover.rh);

	/* Try to recover regions. */
	do_recovery(rs);

	/* More endios -> process. */
	if (!stripe_endio_empty(&rs->sc)) {
		atomic_inc(rs->stats + S_REDO);
		goto redo;
	}

	/* Quickly grab all new ios queued and add them to the work list. */
	spin_lock_irq(lock);
	bio_list_merge(ios, ios_in);
	bio_list_init(ios_in);
	spin_unlock_irq(lock);

	/* Let's assume we're operational most of the time ;-). */
	if (likely(raid_set_operational(rs))) {
		/* If we got ios, work them into the cache. */
		if (!bio_list_empty(ios)) {
			do_ios(rs, ios);
			do_unplug(rs);	/* Unplug the sets device queues. */
		}

		do_flush(rs);		/* Flush any stripes on io list. */
		do_unplug(rs);		/* Unplug the sets device queues. */
		do_busy_event(rs);	/* Check if we got too busy. */

		/* More endios -> process. */
		if (!stripe_endio_empty(&rs->sc)) {
			atomic_inc(rs->stats + S_REDO);
			goto redo;
		}
	} else
		/* No way to reconstruct data with too many devices failed. */
		bio_list_fail(rs, NULL, ios);
}

/*
 * Callback for region hash to dispatch
 * delayed bios queued to recovered regions
 * (Gets called via rh_update_states()).
 */
static void dispatch_delayed_bios(void *context, struct bio_list *bl)
{
	struct raid_set *rs = context;
	struct bio *bio;

	/* REMOVEME: decrement pending delayed bios counter. */
	bio_list_for_each(bio, bl)
		atomic_dec(rs->stats + S_DELAYED_BIOS);

	/* Merge region hash private list to work list. */
	bio_list_merge_head(&rs->io.work, bl);
	bio_list_init(bl);
	ClearRSBandwidth(rs);
}

/*************************************************************
 * Constructor helpers
 *************************************************************/
#define XOR_SPEED_SIZE	rs->recover.io_size

/* Calculate MB/sec. */
static INLINE unsigned mbpers(struct raid_set *rs, unsigned speed)
{
	return to_bytes(speed * rs->set.data_devs *
			XOR_SPEED_SIZE * HZ >> 10) >> 10;
}

/*
 * Discover fastest xor algorithm and # of chunks combination.
 */
/* Calculate speed for algorithm and # of chunks. */
static INLINE unsigned xor_speed(struct raid_set *rs)
{
	unsigned r = 0;
	unsigned long j;

	for (j = jiffies; j == jiffies;); /* Wait for next tick. */

	/* Do xors for a full tick. */
	for (j = jiffies; j == jiffies;) {
		mb();
		common_xor(rs->recover.stripe, XOR_SPEED_SIZE, 0, 0);
		mb();
		r++;
		mb();
	}

	return r;
}

/* Optimize xor algorithm for this RAID set. */
static unsigned xor_optimize(struct raid_set *rs)
{
	unsigned chunks_max = 2, speed_max = 0;
	struct xor_func *f = ARRAY_END(xor_funcs), *f_max = NULL;

	/*
	* Got to allow io on all chunks, so that
	* xor() will actually work on them.
 	*/
	stripe_allow_io(rs->recover.stripe);

	/* Try all xor functions. */
	while (f-- > xor_funcs) {
		unsigned speed;

		/* Set actual xor function for common_xor(). */
		rs->xor.f = f;
		rs->xor.chunks = XOR_CHUNKS_MAX + 1;

		while (rs->xor.chunks-- > 2) {
			speed = xor_speed(rs);
			if (speed > speed_max) {
				speed_max = speed;
				chunks_max = rs->xor.chunks;
				f_max = f;
			}
		}
	}

	/* Memorize optimum parameters. */
	rs->xor.f = f_max;
	rs->xor.chunks = chunks_max;
	return speed_max;
}

/*
 * Allocate a RAID context (a RAID set)
 */
static int
context_alloc(struct raid_set **raid_set, struct raid_type *raid_type,
	      unsigned stripes, unsigned chunk_size, unsigned io_size,
	      unsigned recover_io_size, unsigned raid_devs,
	      sector_t sectors_per_dev,
	      struct dm_target *ti, unsigned dl_parms, char **argv)
{
	int r;
	unsigned p;
	size_t len;
	sector_t region_size, ti_len;
	struct raid_set *rs = NULL;
	struct dm_dirty_log *dl;

	/*
	 * Create the dirty log
	 *
	 * We need to change length for the dirty log constructor,
	 * because we want an amount of regions for all stripes derived
	 * from the single device size, so that we can keep region
	 * size = 2^^n independant of the number of devices
	 */
	ti_len = ti->len;
	ti->len = sectors_per_dev;
	dl = dm_dirty_log_create(argv[0], ti, dl_parms, argv + 2);
	ti->len = ti_len;
	if (!dl)
		goto bad_dirty_log;

	/* Chunk size *must* be smaller than region size. */
	region_size = dl->type->get_region_size(dl);
	if (chunk_size > region_size)
		goto bad_chunk_size;

	/* Recover io size *must* be smaller than region size as well. */
	if (recover_io_size > region_size)
		goto bad_recover_io_size;

	/* Size and allocate the RAID set structure. */
	len = sizeof(*rs->data) + sizeof(*rs->dev);
	if (array_too_big(sizeof(*rs), len, raid_devs))
		goto bad_array;

	len = sizeof(*rs) + raid_devs * len;
	rs = kzalloc(len, GFP_KERNEL);
	if (!rs)
		goto bad_alloc;

	atomic_set(&rs->io.in_process, 0);
	atomic_set(&rs->io.in_process_max, 0);
	rs->recover.io_size = recover_io_size;

	/* Pointer to data array. */
	rs->data = (xor_t **) ((void *) rs->dev + raid_devs * sizeof(*rs->dev));
	rs->recover.dl = dl;
	rs->set.raid_devs = p = raid_devs;
	rs->set.data_devs = raid_devs - raid_type->parity_devs;
	rs->set.raid_type = raid_type;

	/*
	 * Set chunk and io size and respective shifts
	 * (used to avoid divisions)
	 */
	rs->set.chunk_size = chunk_size;
	rs->set.chunk_mask = chunk_size - 1;
	rs->set.chunk_shift = ffs(chunk_size) - 1;

	rs->set.io_size = io_size;
	rs->set.io_mask = io_size - 1;
	rs->set.io_shift = ffs(io_size) - 1;
	rs->set.io_shift_mask = rs->set.chunk_mask & ~rs->set.io_mask;

	rs->set.pages_per_io = chunk_pages(io_size);
	rs->set.sectors_per_dev = sectors_per_dev;

	rs->set.ei = -1;	/* Indicate no failed device. */
	atomic_set(&rs->set.failed_devs, 0);

	rs->ti = ti;

	atomic_set(rs->recover.io_count + IO_WORK, 0);
	atomic_set(rs->recover.io_count + IO_RECOVER, 0);

	/* Initialize io lock and queues. */
	spin_lock_init(&rs->io.in_lock);
	bio_list_init(&rs->io.in);
	bio_list_init(&rs->io.work);

	init_waitqueue_head(&rs->io.suspendq);	/* Suspend waiters (dm-io). */

	rs->recover.nr_regions = dm_sector_div_up(sectors_per_dev, region_size);
	r = rh_init(&rs->recover.rh, 1, dispatch_delayed_bios, rs,
		    wake_do_raid, rs, dl, region_size,
		    rs->recover.nr_regions);
	if (r)
		goto bad_rh;

	/* Initialize stripe cache. */
	r = sc_init(rs, stripes);
	if (r)
		goto bad_sc;

	/* Create dm-io client context. */
	rs->sc.dm_io_client = dm_io_client_create(rs->set.raid_devs *
						  rs->set.pages_per_io);
	if (IS_ERR(rs->sc.dm_io_client))
		goto bad_dm_io_client;

	/* REMOVEME: statistics. */
	stats_reset(rs);
	ClearRSDevelStats(rs);	/* Disnable development status. */

	*raid_set = rs;
	return 0;

   bad_dirty_log:
	TI_ERR_RET("Error creating dirty log", -ENOMEM);


   bad_chunk_size:
	dm_dirty_log_destroy(dl);
	TI_ERR("Chunk size larger than region size");

   bad_recover_io_size:
	dm_dirty_log_destroy(dl);
	TI_ERR("Recover stripe io size larger than region size");

   bad_array:
	dm_dirty_log_destroy(dl);
	TI_ERR("Arry too big");

   bad_alloc:
	dm_dirty_log_destroy(dl);
	TI_ERR_RET("Cannot allocate raid context", -ENOMEM);

   bad_rh:
	dm_dirty_log_destroy(dl);
	ti->error = DM_MSG_PREFIX "Error creating dirty region hash";
	goto free_rs;

   bad_sc:
	ti->error = DM_MSG_PREFIX "Error creating stripe cache";
	goto free;

   bad_dm_io_client:
	ti->error = DM_MSG_PREFIX "Error allocating dm-io resources";
   free:
	sc_exit(&rs->sc);
	rh_exit(rs->recover.rh);
   free_rs:
	kfree(rs);
	return -ENOMEM;
}

/* Free a RAID context (a RAID set). */
static void
context_free(struct raid_set *rs, struct dm_target *ti, unsigned r)
{
	while (r--)
		dm_put_device(ti, rs->dev[r].dev);

	dm_io_client_destroy(rs->sc.dm_io_client);
	stripe_recover_free(rs);
	sc_exit(&rs->sc);
	rh_exit(rs->recover.rh);	/* Destroys dirty log as well. */
	kfree(rs);
}

/* Create work queue and initialize work. */
static int rs_workqueue_init(struct raid_set *rs)
{
	struct dm_target *ti = rs->ti;

	rs->io.wq = create_singlethread_workqueue(DAEMON);
	if (!rs->io.wq)
		TI_ERR_RET("failed to create " DAEMON, -ENOMEM);

	INIT_WORK(&rs->io.ws, do_raid, &rs->io.ws);
	return 0;
}

/* Return pointer to raid_type structure for raid name. */
static struct raid_type *get_raid_type(char *name)
{
	struct raid_type *r = ARRAY_END(raid_types);

	while (r-- > raid_types) {
		if (!strnicmp(STR_LEN(r->name, name)))
			return r;
	}

	return NULL;
}

/* FIXME: factor out to dm core. */
static int multiple(sector_t a, sector_t b, sector_t *n)
{
	sector_t r = a;

	sector_div(r, b);
	*n = r;
	return a == r * b;
}

/* Log RAID set information to kernel log. */
static void raid_set_log(struct raid_set *rs, unsigned speed)
{
	unsigned p;
	char buf[BDEVNAME_SIZE];

	for (p = 0; p < rs->set.raid_devs; p++)
		DMINFO("/dev/%s is raid disk %u",
		       bdevname(rs->dev[p].dev->bdev, buf), p);

	DMINFO("%d/%d/%d sectors chunk/io/recovery size, %u stripes",
	       rs->set.chunk_size, rs->set.io_size, rs->recover.io_size,
	       atomic_read(&rs->sc.stripes));
	DMINFO("algorithm \"%s\", %u chunks with %uMB/s", rs->xor.f->name,
	       rs->xor.chunks, mbpers(rs, speed));
	DMINFO("%s set with net %u/%u devices", rs->set.raid_type->descr,
	       rs->set.data_devs, rs->set.raid_devs);
}

/* Get all devices and offsets. */
static int
dev_parms(struct dm_target *ti, struct raid_set *rs,
	  char **argv, int *p)
{
	for (*p = 0; *p < rs->set.raid_devs; (*p)++, argv += 2) {
		int r;
		unsigned long long tmp;
		struct raid_dev *dev = rs->dev + *p;
		union dev_lookup dl = {.dev = dev };

		/* Get offset and device. */
		r = sscanf(argv[1], "%llu", &tmp);
		if (r != 1)
			TI_ERR("Invalid RAID device offset parameter");

		dev->start = tmp;
		r = dm_get_device(ti, argv[0], dev->start,
				  rs->set.sectors_per_dev,
				  dm_table_get_mode(ti->table), &dev->dev);
		if (r)
			TI_ERR_RET("RAID device lookup failure", r);

		r = raid_dev_lookup(rs, bynumber, &dl);
		if (r != -ENODEV && r < *p) {
			(*p)++;	/* Ensure dm_put_device() on actual device. */
			TI_ERR_RET("Duplicate RAID device", -ENXIO);
		}
	}

	return 0;
}

/* Set recovery bandwidth. */
static INLINE void
recover_set_bandwidth(struct raid_set *rs, unsigned bandwidth)
{
	rs->recover.bandwidth = bandwidth;
	rs->recover.bandwidth_work = 100 / bandwidth;
}

/* Handle variable number of RAID parameters. */
static int
raid_variable_parms(struct dm_target *ti, char **argv,
		    unsigned i, int *raid_parms,
		    int *chunk_size, int *chunk_size_parm,
		    int *stripes, int *stripes_parm,
		    int *io_size, int *io_size_parm,
		    int *recover_io_size, int *recover_io_size_parm,
		    int *bandwidth, int *bandwidth_parm)
{
	/* Fetch # of variable raid parameters. */
	if (sscanf(argv[i++], "%d", raid_parms) != 1 ||
	    !range_ok(*raid_parms, 0, 5))
		TI_ERR("Bad variable raid parameters number");

	if (*raid_parms) {
		/*
		 * If we've got variable RAID parameters,
		 * chunk size is the first one
		 */
		if (sscanf(argv[i++], "%d", chunk_size) != 1 ||
		    (*chunk_size != -1 &&
		     (!POWER_OF_2(*chunk_size) ||
		      !range_ok(*chunk_size, IO_SIZE_MIN, CHUNK_SIZE_MAX))))
			TI_ERR ("Invalid chunk size; "
				"must be 2^^n and <= 16384");

		*chunk_size_parm = *chunk_size;
		if (*chunk_size == -1)
			*chunk_size = CHUNK_SIZE;

		/*
		 * In case we've got 2 or more variable raid
		 * parameters, the number of stripes is the second one
		 */
		if (*raid_parms > 1) {
			if (sscanf(argv[i++], "%d", stripes) != 1 ||
			    (*stripes != -1 &&
			     !range_ok(*stripes, STRIPES_MIN,
				       STRIPES_MAX)))
				TI_ERR("Invalid number of stripes: must "
				       "be >= 8 and <= 8192");
		}

		*stripes_parm = *stripes;
		if (*stripes == -1)
			*stripes = STRIPES;

		/*
		 * In case we've got 3 or more variable raid
		 * parameters, the io size is the third one.
		 */
		if (*raid_parms > 2) {
			if (sscanf(argv[i++], "%d", io_size) != 1 ||
			    (*io_size != -1 &&
			     (!POWER_OF_2(*io_size) ||
			      !range_ok(*io_size, IO_SIZE_MIN,
				        min(BIO_MAX_SECTORS / 2,
					*chunk_size)))))
				TI_ERR("Invalid io size; must "
				       "be 2^^n and less equal "
				       "min(BIO_MAX_SECTORS/2, chunk size)");
		} else
			*io_size = *chunk_size;

		*io_size_parm = *io_size;
		if (*io_size == -1)
			*io_size = *chunk_size;

		/*
		 * In case we've got 4 variable raid parameters,
		 * the recovery stripe io_size is the fourth one
		 */
		if (*raid_parms > 3) {
			if (sscanf(argv[i++], "%d", recover_io_size) != 1 ||
			    (*recover_io_size != -1 &&
			     (!POWER_OF_2(*recover_io_size) ||
			     !range_ok(*recover_io_size, RECOVER_IO_SIZE_MIN,
				       BIO_MAX_SECTORS / 2))))
				TI_ERR("Invalid recovery io size; must be "
				       "2^^n and less equal BIO_MAX_SECTORS/2");
		}

		*recover_io_size_parm = *recover_io_size;
		if (*recover_io_size == -1)
			*recover_io_size = RECOVER_IO_SIZE;

		/*
		 * In case we've got 5 variable raid parameters,
		 * the recovery io bandwidth is the fifth one
		 */
		if (*raid_parms > 4) {
			if (sscanf(argv[i++], "%d", bandwidth) != 1 ||
			    (*bandwidth != -1 &&
			     !range_ok(*bandwidth, BANDWIDTH_MIN,
				       BANDWIDTH_MAX)))
				TI_ERR("Invalid recovery bandwidth "
				       "percentage; must be > 0 and <= 100");
		}

		*bandwidth_parm = *bandwidth;
		if (*bandwidth == -1)
			*bandwidth = BANDWIDTH;
	}

	return 0;
}

/* Parse optional locking parameters. */
static int
raid_locking_parms(struct dm_target *ti, char **argv,
		   unsigned i, int *locking_parms,
		   struct dmraid45_locking_type **locking_type)
{
	*locking_parms = 0;
	*locking_type = &locking_none;

	if (!strnicmp(argv[i], "none", strlen(argv[i])))
		*locking_parms = 1;
	else if (!strnicmp(argv[i + 1], "locking", strlen(argv[i + 1]))) {
		*locking_type = &locking_none;
		*locking_parms = 2;
	} else if (!strnicmp(argv[i + 1], "cluster", strlen(argv[i + 1]))) {
		*locking_type = &locking_cluster;
		/* FIXME: namespace. */
		*locking_parms = 3;
	}

	return *locking_parms == 1 ? -EINVAL : 0;
}

/* Set backing device information properties of RAID set. */
static void rs_set_bdi(struct raid_set *rs, unsigned stripes, unsigned chunks)
{
	unsigned p, ra_pages;
	struct mapped_device *md = dm_table_get_md(rs->ti->table);
	struct backing_dev_info *bdi = &dm_disk(md)->queue->backing_dev_info;

	/* Set read-ahead for the RAID set and the component devices. */
	bdi->ra_pages = stripes * stripe_pages(rs, rs->set.io_size);
	ra_pages = chunks * chunk_pages(rs->set.io_size);
	for (p = rs->set.raid_devs; p--; )
		bdev_get_queue(rs->dev[p].dev->bdev)->backing_dev_info.ra_pages = ra_pages;

	/* Set congested function and data. */
	bdi->congested_fn = raid_set_congested;
	bdi->congested_data = rs;

	dm_put(md);
}

/* Get backing device information properties of RAID set. */
static void rs_get_ra(struct raid_set *rs, unsigned *stripes, unsigned *chunks)
{
	struct mapped_device *md = dm_table_get_md(rs->ti->table);

	 *stripes = dm_disk(md)->queue->backing_dev_info.ra_pages
		    / stripe_pages(rs, rs->set.io_size);
	*chunks = bdev_get_queue(rs->dev->dev->bdev)->backing_dev_info.ra_pages
		  / chunk_pages(rs->set.io_size);

	dm_put(md);
}

/*
 * Construct a RAID4/5 mapping:
 *
 * log_type #log_params <log_params> \
 * raid_type [#parity_dev] #raid_variable_params <raid_params> \
 * [locking "none"/"cluster"]
 * #raid_devs #dev_to_initialize [<dev_path> <offset>]{3,}
 *
 * log_type = "core"/"disk",
 * #log_params = 1-3 (1-2 for core dirty log type, 3 for disk dirty log only)
 * log_params = [dirty_log_path] region_size [[no]sync])
 *
 * raid_type = "raid4", "raid5_la", "raid5_ra", "raid5_ls", "raid5_rs"
 *
 * #parity_dev = N if raid_type = "raid4"
 * o N = -1: pick default = last device
 * o N >= 0 and < #raid_devs: parity device index
 *
 * #raid_variable_params = 0-5; raid_params (-1 = default):
 *   [chunk_size [#stripes [io_size [recover_io_size [%recovery_bandwidth]]]]]
 *   o chunk_size (unit to calculate drive addresses; must be 2^^n, > 8
 *     and <= CHUNK_SIZE_MAX)
 *   o #stripes is number of stripes allocated to stripe cache
 *     (must be > 1 and < STRIPES_MAX)
 *   o io_size (io unit size per device in sectors; must be 2^^n and > 8)
 *   o recover_io_size (io unit size per device for recovery in sectors;
       must be 2^^n, > SECTORS_PER_PAGE and <= region_size)
 *   o %recovery_bandwith is the maximum amount spend for recovery during
 *     application io (1-100%)
 * If raid_variable_params = 0, defaults will be used.
 * Any raid_variable_param can be set to -1 to apply a default
 *
 * #raid_devs = N (N >= 3)
 *
 * #dev_to_initialize = N
 * -1: initialize parity on all devices
 * >= 0 and < #raid_devs: initialize raid_path; used to force reconstruction
 * of a failed devices content after replacement
 *
 * <dev_path> = device_path (eg, /dev/sdd1)
 * <offset>   = begin at offset on <dev_path>
 *
 */
#define	MIN_PARMS	13
static int raid_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int bandwidth = BANDWIDTH, bandwidth_parm = -1,
	    chunk_size = CHUNK_SIZE, chunk_size_parm = -1,
	    dev_to_init, dl_parms, locking_parms, parity_parm, pi = -1,
	    i, io_size = IO_SIZE, io_size_parm = -1,
	    r, raid_devs, raid_parms,
	    recover_io_size = RECOVER_IO_SIZE, recover_io_size_parm = -1,
	    stripes = STRIPES, stripes_parm = -1;
	unsigned speed;
	sector_t tmp, sectors_per_dev;
	struct dmraid45_locking_type *locking;
	struct raid_set *rs;
	struct raid_type *raid_type;

	/* Ensure minimum number of parameters. */
	if (argc < MIN_PARMS)
		TI_ERR("Not enough parameters");

	/* Fetch # of dirty log parameters. */
	if (sscanf(argv[1], "%d", &dl_parms) != 1
	    || !range_ok(dl_parms, 1, 4711))
		TI_ERR("Bad dirty log parameters number");

	/* Check raid_type. */
	raid_type = get_raid_type(argv[dl_parms + 2]);
	if (!raid_type)
		TI_ERR("Bad raid type");

	/* In case of RAID4, parity drive is selectable. */
	parity_parm = !!(raid_type->level == raid4);

	/* Handle variable number of RAID parameters. */
	r = raid_variable_parms(ti, argv, dl_parms + parity_parm + 3,
				&raid_parms,
				&chunk_size, &chunk_size_parm,
				&stripes, &stripes_parm,
				&io_size, &io_size_parm,
				&recover_io_size, &recover_io_size_parm,
				&bandwidth, &bandwidth_parm);
	if (r)
		return r;

	r = raid_locking_parms(ti, argv,
			       dl_parms + parity_parm + raid_parms + 4,
			       &locking_parms, &locking);
	if (r)
		return r;

	/* # of raid devices. */
	if (sscanf(argv[dl_parms + parity_parm + raid_parms + locking_parms +4],
	     "%d", &raid_devs) != 1 || raid_devs < raid_type->minimal_devs)
		TI_ERR("Invalid number of raid devices");

	/* In case of RAID4, check parity drive index is in limits. */
	if (raid_type->level == raid4) {
		/* Fetch index of parity device. */
		if (sscanf(argv[dl_parms + 3], "%d", &pi) != 1 ||
		    !range_ok(pi, 0, raid_devs - 1))
			TI_ERR("Invalid RAID4 parity device index");
	}

	/*
	 * Index of device to initialize starts at 0
	 *
	 * o -1 -> don't initialize a particular device,
	 * o 0..raid_devs-1 -> initialize respective device
	 *   (used for reconstruction of a replaced device)
	 */
	if (sscanf
	    (argv[dl_parms + parity_parm + raid_parms + locking_parms + 5],
	     "%d", &dev_to_init) != 1
	    || !range_ok(dev_to_init, -1, raid_devs - 1))
		TI_ERR("Invalid number for raid device to initialize");

	/* Check # of raid device arguments. */
	if (argc - dl_parms - parity_parm - raid_parms - 6 !=
	    2 * raid_devs)
		TI_ERR("Wrong number of raid device/offset arguments");

	/*
	 * Check that the table length is devisable
	 * w/o rest by (raid_devs - parity_devs)
	 */
	if (!multiple(ti->len, raid_devs - raid_type->parity_devs,
		      &sectors_per_dev))
		TI_ERR
		    ("Target length not divisable by number of data devices");

	/*
	 * Check that the device size is
	 * devisable w/o rest by chunk size
	 */
	if (!multiple(sectors_per_dev, chunk_size, &tmp))
		TI_ERR("Device length not divisable by chunk_size");

	/****************************************************************
	 * Now that we checked the constructor arguments ->
	 * let's allocate the RAID set
	 ****************************************************************/
	r = context_alloc(&rs, raid_type, stripes, chunk_size, io_size,
			  recover_io_size, raid_devs, sectors_per_dev,
			  ti, dl_parms, argv);
	if (r)
		return r;

	/*
	 * Set these here in order to avoid passing
	 * too many arguments to context_alloc()
	 */
	rs->set.dev_to_init_parm = dev_to_init;
	rs->set.dev_to_init = dev_to_init;
	rs->set.pi_parm = pi;
	rs->set.pi = (pi == -1) ? rs->set.data_devs : pi;
	rs->set.raid_parms = raid_parms;
	rs->set.chunk_size_parm = chunk_size_parm;
	rs->set.io_size_parm = io_size_parm;
	rs->sc.stripes_parm = stripes_parm;
	rs->recover.io_size_parm = recover_io_size_parm;
	rs->recover.bandwidth_parm = bandwidth_parm;
	recover_set_bandwidth(rs, bandwidth);

	/* Use locking type to lock stripe access. */
	rs->locking = locking;

	/* Get the device/offset tupels. */
	argv += dl_parms + 6 + parity_parm + raid_parms;
	r = dev_parms(ti, rs, argv, &i);
	if (r)
		goto err;

	/* Initialize recovery. */
	rs->recover.start_jiffies = jiffies;
	rs->recover.end_jiffies = 0;
	recovery_region_reset(rs);
	SetRSRecover(rs);

	/* Set backing device information (eg. read ahead). */
	rs_set_bdi(rs, chunk_size * 2, io_size * 4);
	SetRSCheckOverwrite(rs); /* Allow chunk overwrite checks. */

	speed = xor_optimize(rs); /* Select best xor algorithm. */

	/* Initialize work queue to handle this RAID set's io. */
	r = rs_workqueue_init(rs);
	if (r)
		goto err;

	raid_set_log(rs, speed); /* Log information about RAID set. */

	/*
	 * Make sure that dm core only hands maximum io size
	 * length down and pays attention to io boundaries.
	 */
	ti->split_io = rs->set.io_size;
	ti->private = rs;
	return 0;

   err:
	context_free(rs, ti, i);
	return r;
}

/*
 * Destruct a raid mapping
 */
static void raid_dtr(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;

	/* Indicate recovery end. */
	ClearRSRecover(rs);
	wake_do_raid(rs);	/* Wake daemon. */
	wait_ios(rs);		/* Wait for any io still being processed. */
	destroy_workqueue(rs->io.wq);
	context_free(rs, ti, rs->set.raid_devs);
}

/* Queues ios to RAID sets. */
static inline void queue_bio(struct raid_set *rs, struct bio *bio)
{
	int wake;
	struct bio_list *in = &rs->io.in;
	spinlock_t *in_lock = &rs->io.in_lock;

	spin_lock_irq(in_lock);
	wake = bio_list_empty(in);
	bio_list_add(in, bio);
	spin_unlock_irq(in_lock);

	/* Wake daemon if input list was empty. */
	if (wake)
		wake_do_raid(rs);
}

/* Raid mapping function. */
static int raid_map(struct dm_target *ti, struct bio *bio,
		    union map_info *map_context)
{
	/* I don't want to waste stripe cache capacity. */
	if (bio_rw(bio) == READA)
		return -EIO;
	else {
		struct raid_set *rs = ti->private;

		/* REMOVEME: statistics. */
		atomic_inc(rs->stats +
			   (bio_data_dir(bio) == WRITE ?
			    S_BIOS_WRITE : S_BIOS_READ));

		/*
		 * Get io reference to be waiting for to drop
		 * to zero on device suspension/destruction.
		 */
		io_get(rs);
		bio->bi_sector -= ti->begin;	/* Remap sector. */
		queue_bio(rs, bio);		/* Queue to the daemon. */
		return DM_MAPIO_SUBMITTED;	/* Handle later. */
	}
}

/* Device suspend. */
static void raid_postsuspend(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;
	struct dm_dirty_log *dl = rs->recover.dl;

	SetRSSuspended(rs);

	if (RSRecover(rs))
		rh_stop_recovery(rs->recover.rh); /* Wakes do_raid(). */
	else
		wake_do_raid(rs);

	wait_ios(rs);	/* Wait for completion of all ios being processed. */
	if (dl->type->postsuspend && dl->type->postsuspend(dl))
		/* Suspend dirty log. */
		/* FIXME: need better error handling. */
		DMWARN("log suspend failed");
}

/* Device resume. */
static void raid_resume(struct dm_target *ti)
{
	struct raid_set *rs = ti->private;
	struct dm_dirty_log *dl = rs->recover.dl;

	if (dl->type->resume && dl->type->resume(dl))
		/* Resume dirty log. */
		/* FIXME: need better error handling. */
		DMWARN("log resume failed");

	rs->recover.nr_regions_to_recover =
	    rs->recover.nr_regions - dl->type->get_sync_count(dl);

	ClearRSSuspended(rs);

	/* Reset any unfinished recovery. */
	if (RSRecover(rs)) {
		recovery_region_reset(rs);
		rh_start_recovery(rs->recover.rh); /* Calls wake_do_raid(). */
	} else
		wake_do_raid(rs);
}

static INLINE unsigned sc_size(struct raid_set *rs)
{
	return to_sector(atomic_read(&rs->sc.stripes) *
			 (sizeof(struct stripe) +
			  (sizeof(struct stripe_set) +
			   (sizeof(struct page_list) +
			    to_bytes(rs->set.io_size) *
			    rs->set.raid_devs)) +
			  (rs->recover.
			   end_jiffies ? 0 : to_bytes(rs->set.raid_devs *
						      rs->recover.
						      io_size))));
}

/* REMOVEME: status output for development. */
static void
raid_devel_stats(struct dm_target *ti, char *result,
		 unsigned *size, unsigned maxlen)
{
	unsigned chunks, stripes, sz = *size;
	unsigned long j;
	char buf[BDEVNAME_SIZE], *p;
	struct stats_map *sm, *sm_end = ARRAY_END(stats_map);
	struct raid_set *rs = ti->private;
	struct recover *rec = &rs->recover;
	struct timespec ts;

	DMEMIT("%s ", version);
	DMEMIT("io_inprocess=%d ", atomic_read(&rs->io.in_process));
	DMEMIT("io_inprocess_max=%d ", atomic_read(&rs->io.in_process_max));

	for (sm = stats_map; sm < sm_end; sm++)
		DMEMIT("%s%d", sm->str, atomic_read(rs->stats + sm->type));

	DMEMIT(" overwrite=%s ", RSCheckOverwrite(rs) ? "on" : "off");
	DMEMIT("sc=%u/%u/%u/%u/%u ", rs->set.chunk_size, rs->set.io_size,
	       atomic_read(&rs->sc.stripes), rs->sc.hash.buckets,
	       sc_size(rs));

	j = (rec->end_jiffies ? rec->end_jiffies : jiffies) -
	    rec->start_jiffies;
	jiffies_to_timespec(j, &ts);
	sprintf(buf, "%ld.%ld", ts.tv_sec, ts.tv_nsec);
	p = strchr(buf, '.');
	p[3] = 0;

	DMEMIT("rg=%llu%s/%llu/%llu/%u %s ",
	       (unsigned long long) rec->nr_regions_recovered,
	       RSRegionGet(rs) ? "+" : "",
	       (unsigned long long) rec->nr_regions_to_recover,
	       (unsigned long long) rec->nr_regions, rec->bandwidth, buf);

	rs_get_ra(rs, &stripes, &chunks);
	DMEMIT("ra=%u/%u ", stripes, chunks);

	*size = sz;
}

static int
raid_status(struct dm_target *ti, status_type_t type,
	    char *result, unsigned maxlen)
{
	unsigned i, sz = 0;
	char buf[BDEVNAME_SIZE];
	struct raid_set *rs = ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		/* REMOVEME: statistics. */
		if (RSDevelStats(rs))
			raid_devel_stats(ti, result, &sz, maxlen);

		DMEMIT("%u ", rs->set.raid_devs);

		for (i = 0; i < rs->set.raid_devs; i++)
			DMEMIT("%s ",
			       format_dev_t(buf, rs->dev[i].dev->bdev->bd_dev));

		DMEMIT("1 ");
		for (i = 0; i < rs->set.raid_devs; i++) {
			DMEMIT("%c", dev_operational(rs, i) ? 'A' : 'D');

			if (rs->set.raid_type->level == raid4 &&
			    i == rs->set.pi)
				DMEMIT("p");

			if (rs->set.dev_to_init == i)
				DMEMIT("i");
		}

		break;

	case STATUSTYPE_TABLE:
		sz = rs->recover.dl->type->status(rs->recover.dl, type,
						  result, maxlen);
		DMEMIT("%s %u ", rs->set.raid_type->name,
		       rs->set.raid_parms);

		if (rs->set.raid_type->level == raid4)
			DMEMIT("%d ", rs->set.pi_parm);

		if (rs->set.raid_parms)
			DMEMIT("%d ", rs->set.chunk_size_parm);

		if (rs->set.raid_parms > 1)
			DMEMIT("%d ", rs->sc.stripes_parm);

		if (rs->set.raid_parms > 2)
			DMEMIT("%d ", rs->set.io_size_parm);

		if (rs->set.raid_parms > 3)
			DMEMIT("%d ", rs->recover.io_size_parm);

		if (rs->set.raid_parms > 4)
			DMEMIT("%d ", rs->recover.bandwidth_parm);

		DMEMIT("%u %d ", rs->set.raid_devs, rs->set.dev_to_init);

		for (i = 0; i < rs->set.raid_devs; i++)
			DMEMIT("%s %llu ",
			       format_dev_t(buf,
					    rs->dev[i].dev->bdev->bd_dev),
			       (unsigned long long) rs->dev[i].start);
	}

	return 0;
}

/*
 * Message interface
 */
enum raid_msg_actions {
	act_bw,			/* Recovery bandwidth switch. */
	act_dev,		/* Device failure switch. */
	act_overwrite,		/* Stripe overwrite check. */
	act_read_ahead,		/* Set read ahead. */
	act_stats,		/* Development statistics switch. */
	act_sc,			/* Stripe cache switch. */

	act_on,			/* Set entity on. */
	act_off,		/* Set entity off. */
	act_reset,		/* Reset entity. */

	act_set = act_on,	/* Set # absolute. */
	act_grow = act_off,	/* Grow # by an amount. */
	act_shrink = act_reset,	/* Shrink # by an amount. */
};

/* Turn a delta to absolute. */
static int _absolute(unsigned long action, int act, int r)
{
	/* Make delta absolute. */
	if (test_bit(act_set, &action));
	else if (test_bit(act_grow, &action))
		r += act;
	else if (test_bit(act_shrink, &action))
		r = act - r;
	else
		r = -EINVAL;

	return r;
}

 /* Change recovery io bandwidth. */
static int bandwidth_change(struct dm_msg *msg, void *context)
{
	struct raid_set *rs = context;
	int act = rs->recover.bandwidth;
	int bandwidth = DM_MSG_INT_ARG(msg);

	if (range_ok(bandwidth, BANDWIDTH_MIN, BANDWIDTH_MAX)) {
		/* Make delta bandwidth absolute. */
		bandwidth = _absolute(msg->action, act, bandwidth);

		/* Check range. */
		if (range_ok(bandwidth, BANDWIDTH_MIN, BANDWIDTH_MAX)) {
			recover_set_bandwidth(rs, bandwidth);
			return 0;
		}
	}

	set_bit(dm_msg_ret_arg, &msg->ret);
	set_bit(dm_msg_ret_inval, &msg->ret);
	return -EINVAL;
}

/* Change state of a device (running/offline). */
/* FIXME: this only works while recovering!. */
static int device_state(struct dm_msg *msg, void *context)
{
	int r;
	const char *str = "is already ";
	union dev_lookup dl = { .dev_name = DM_MSG_STR_ARG(msg) };
	struct raid_set *rs = context;

	r = raid_dev_lookup(rs, strchr(dl.dev_name, ':') ?
			    bymajmin : byname, &dl);
	if (r == -ENODEV) {
		DMERR("device %s is no member of this set", dl.dev_name);
		return r;
	}

	if (test_bit(act_off, &msg->action)) {
		if (dev_operational(rs, r))
			str = "";
	} else if (!dev_operational(rs, r))
		str = "";

	DMINFO("/dev/%s %s%s", dl.dev_name, str,
	       test_bit(act_off, &msg->action) ? "offline" : "running");

	return test_bit(act_off, &msg->action) ?
	       raid_set_check_and_degrade(rs, NULL, r) :
	       raid_set_check_and_upgrade(rs, r);
}

/* Set/reset development feature flags. */
static int devel_flags(struct dm_msg *msg, void *context)
{
	struct raid_set *rs = context;

	if (test_bit(act_on, &msg->action))
		return test_and_set_bit(msg->spec->parm,
					&rs->io.flags) ? -EPERM : 0;
	else if (test_bit(act_off, &msg->action))
		return test_and_clear_bit(msg->spec->parm,
					  &rs->io.flags) ? 0 : -EPERM;
	else if (test_bit(act_reset, &msg->action)) {
		if (test_bit(act_stats, &msg->action)) {
			stats_reset(rs);
			goto on;
		} else if (test_bit(act_overwrite, &msg->action)) {
   on:
			set_bit(msg->spec->parm, &rs->io.flags);
			return 0;
		}
	}

	return -EINVAL;
}

 /* Set stripe and chunk read ahead pages. */
static int read_ahead_set(struct dm_msg *msg, void *context)
{
	int stripes = DM_MSG_INT_ARGS(msg, 0);
	int chunks  = DM_MSG_INT_ARGS(msg, 1);

	if (range_ok(stripes, 1, 512) &&
	    range_ok(chunks, 1, 512)) {
		rs_set_bdi(context, stripes, chunks);
		return 0;
	}

	set_bit(dm_msg_ret_arg, &msg->ret);
	set_bit(dm_msg_ret_inval, &msg->ret);
	return -EINVAL;
}

/* Resize the stripe cache. */
static int stripecache_resize(struct dm_msg *msg, void *context)
{
	int act, stripes;
	struct raid_set *rs = context;

	/* Deny permission in case the daemon is still shrinking!. */
	if (atomic_read(&rs->sc.stripes_to_shrink))
		return -EPERM;

	stripes = DM_MSG_INT_ARG(msg);
	if (stripes > 0) {
		act = atomic_read(&rs->sc.stripes);

		/* Make delta stripes absolute. */
		stripes = _absolute(msg->action, act, stripes);

		/*
		 * Check range and that the # of stripes changes.
		 * We can grow from gere but need to leave any
		 * shrinking to the worker for synchronization.
		 */
		if (range_ok(stripes, STRIPES_MIN, STRIPES_MAX)) {
			if (stripes > act)
				return sc_grow(&rs->sc, stripes - act, grow);
			else if (stripes < act) {
				atomic_set(&rs->sc.stripes_to_shrink,
					   act - stripes);
				wake_do_raid(rs);
			}

			return 0;
		}
	}

	set_bit(dm_msg_ret_arg, &msg->ret);
	set_bit(dm_msg_ret_inval, &msg->ret);
	return -EINVAL;
}

/* Parse the RAID message action. */
/*
 * 'ba[ndwidth] {se[t],g[row],sh[rink]} #'	# e.g 'ba se 50'
 * 'de{vice] o[ffline]/r[unning] DevName/maj:min' # e.g 'device o /dev/sda'
 * "o[verwrite]  {on,of[f],r[eset]}'		# e.g. 'o of'
 * "r[ead_ahead] set #stripes #chunks		# e.g. 'r se 3 2'
 * 'sta[tistics] {on,of[f],r[eset]}'		# e.g. 'stat of'
 * 'str[ipecache] {se[t],g[row],sh[rink]} #'	# e.g. 'stripe set 1024'
 *
 */
static int
raid_message(struct dm_target *ti, unsigned argc, char **argv)
{
	/* Variables to store the parsed parameters im. */
	static int i[2];
	static unsigned long *i_arg[] = {
		(unsigned long *) i + 0,
		(unsigned long *) i + 1,
	};
	static char *p;
	static unsigned long *p_arg[] = { (unsigned long *) &p };

	/* Declare all message option strings. */
	static char *str_sgs[] = { "set", "grow", "shrink" };
	static char *str_dev[] = { "running", "offline" };
	static char *str_oor[] = { "on", "off", "reset" };

	/* Declare all actions. */
	static unsigned long act_sgs[] = { act_set, act_grow, act_shrink };
	static unsigned long act_oor[] = { act_on, act_off, act_reset };

	/* Bandwidth option. */
	static struct dm_message_option bw_opt = { 3, str_sgs, act_sgs };
	static struct dm_message_argument bw_args =
		{ 1, i_arg, { dm_msg_int_t } };

	/* Device option. */
	static struct dm_message_option dev_opt = { 2, str_dev, act_oor };
	static struct dm_message_argument dev_args =
		{ 1, p_arg, { dm_msg_base_t } };

	/* Read ahead option. */
	static struct dm_message_option ra_opt = { 1, str_sgs, act_sgs };
	static struct dm_message_argument ra_args =
		{ 2, i_arg, { dm_msg_int_t, dm_msg_int_t } };

	static struct dm_message_argument null_args =
		{ 0, NULL, { dm_msg_int_t } };

	/* Overwrite and statistics option. */
	static struct dm_message_option ovr_stats_opt = { 3, str_oor, act_oor };

	/* Sripecache option. */
	static struct dm_message_option stripe_opt = { 3, str_sgs, act_sgs };

	/* Declare messages. */
	static struct dm_msg_spec specs[] = {
		{ "bandwidth", act_bw, &bw_opt, &bw_args,
		  0, bandwidth_change },
		{ "device", act_dev, &dev_opt, &dev_args,
		  0, device_state },
		{ "overwrite", act_overwrite, &ovr_stats_opt, &null_args,
		  RS_CHECK_OVERWRITE, devel_flags },
		{ "read_ahead", act_read_ahead, &ra_opt, &ra_args,
		  0, read_ahead_set },
		{ "statistics", act_stats, &ovr_stats_opt, &null_args,
		  RS_DEVEL_STATS, devel_flags },
		{ "stripecache", act_sc, &stripe_opt, &bw_args,
		  0, stripecache_resize },
	};

	/* The message for the parser. */
	struct dm_msg msg = {
		.num_specs = ARRAY_SIZE(specs),
		.specs = specs,
	};

	return dm_message_parse(TARGET, &msg, ti->private, argc, argv);
}
/*
 * END message interface
 */

static struct target_type raid_target = {
	.name = "raid45",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = raid_ctr,
	.dtr = raid_dtr,
	.map = raid_map,
	.postsuspend = raid_postsuspend,
	.resume = raid_resume,
	.status = raid_status,
	.message = raid_message,
};

static void init_exit(const char *bad_msg, const char *good_msg, int r)
{
	if (r)
		DMERR("Failed to %sregister target [%d]", bad_msg, r);
	else
		DMINFO("%s %s", good_msg, version);
}

static int __init dm_raid_init(void)
{
	int r;

	r = dm_register_target(&raid_target);
	init_exit("", "initialized", r);
	return r;
}

static void __exit dm_raid_exit(void)
{
	int r;

	r = dm_unregister_target(&raid_target);
	init_exit("un", "exit", r);
}

/* Module hooks. */
module_init(dm_raid_init);
module_exit(dm_raid_exit);

MODULE_DESCRIPTION(DM_NAME " raid4/5 target");
MODULE_AUTHOR("Heinz Mauelshagen <hjm@redhat.com>");
MODULE_LICENSE("GPL");
