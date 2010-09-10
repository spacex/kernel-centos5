/*
 * Copyright (C) 2003 Sistina Software Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"
#include "dm-bio-list.h"
#include "dm-bio-record.h"
#include "dm-io.h"
#include "dm-log.h"
#include "kcopyd.h"

#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#define DM_MSG_PREFIX "raid1"
#define DM_IO_PAGES 64

DECLARE_WAIT_QUEUE_HEAD(recovery_stopped_event);

/*-----------------------------------------------------------------
 * Region hash
 *
 * The mirror splits itself up into discrete regions.  Each
 * region can be in one of three states: clean, dirty,
 * nosync.  There is no need to put clean regions in the hash.
 *
 * In addition to being present in the hash table a region _may_
 * be present on one of three lists.
 *
 *   clean_regions: Regions on this list have no io pending to
 *   them, they are in sync, we are no longer interested in them,
 *   they are dull.  rh_update_states() will remove them from the
 *   hash table.
 *
 *   quiesced_regions: These regions have been spun down, ready
 *   for recovery.  rh_recovery_start() will remove regions from
 *   this list and hand them to kmirrord, which will schedule the
 *   recovery io with kcopyd.
 *
 *   recovered_regions: Regions that kcopyd has successfully
 *   recovered.  rh_update_states() will now schedule any delayed
 *   io, up the recovery_count, and remove the region from the
 *   hash.
 *
 * There are 2 locks:
 *   A rw spin lock 'hash_lock' protects just the hash table,
 *   this is never held in write mode from interrupt context,
 *   which I believe means that we only have to disable irqs when
 *   doing a write lock.
 *
 *   An ordinary spin lock 'region_lock' that protects the three
 *   lists in the region_hash, with the 'state', 'list' and
 *   'bhs_delayed' fields of the regions.  This is used from irq
 *   context, so all other uses will have to suspend local irqs.
 *---------------------------------------------------------------*/
struct mirror_set;
struct region_hash {
	struct mirror_set *ms;
	uint32_t region_size;
	unsigned region_shift;

	/* holds persistent region state */
	struct dirty_log *log;

	/* hash table */
	rwlock_t hash_lock;
	mempool_t *region_pool;
	unsigned int mask;
	unsigned int nr_buckets;
	struct list_head *buckets;

	spinlock_t region_lock;
	atomic_t recovery_in_flight;
	struct semaphore recovery_count;
	struct list_head clean_regions;
	struct list_head quiesced_regions;
	struct list_head recovered_regions;
	struct list_head failed_recovered_regions;
};

enum {
	RH_CLEAN,
	RH_DIRTY,
	RH_NOSYNC,
	RH_RECOVERING
};

struct region {
	struct region_hash *rh;	/* FIXME: can we get rid of this ? */
	region_t key;
	int state;

	struct list_head hash_list;
	struct list_head list;

	atomic_t pending;
	struct bio_list delayed_bios;
};


/*-----------------------------------------------------------------
 * Mirror set structures.
 *---------------------------------------------------------------*/
struct mirror {
	atomic_t error_count;  /* Error counter to flag mirror failure */
	struct mirror_set *ms;
	struct dm_dev *dev;
	sector_t offset;
};

struct mirror_set {
	struct dm_target *ti;
	struct list_head list;
	struct region_hash rh;
	struct kcopyd_client *kcopyd_client;

	spinlock_t lock;	/* protects the lists */
	struct bio_list reads;
	struct bio_list writes;
	struct bio_list failures;

	struct dm_io_client *io_client;

	/* recovery */
	region_t nr_regions;
	int in_sync;
	int log_failure;
	atomic_t suspend;

	struct mirror *default_mirror;	/* Default mirror */

	unsigned int nr_mirrors;
	atomic_t read_count;      /* Read counter for read balancing */
	struct mirror *read_mirror; /* Last mirror read. */

	struct workqueue_struct *kmirrord_wq;
	struct work_struct kmirrord_work;

	struct mirror mirror[0];
};

/*
 * Conversion fns
 */
static inline region_t bio_to_region(struct region_hash *rh, struct bio *bio)
{
	return (bio->bi_sector - rh->ms->ti->begin) >> rh->region_shift;
}

static inline sector_t region_to_sector(struct region_hash *rh, region_t region)
{
	return region << rh->region_shift;
}

static inline void wake(struct mirror_set *ms)
{
	queue_work(ms->kmirrord_wq, &ms->kmirrord_work);
}

/* FIXME move this */
static void queue_bio(struct mirror_set *ms, struct bio *bio, int rw);

#define MIN_REGIONS 64
#define MAX_RECOVERY 1
static int rh_init(struct region_hash *rh, struct mirror_set *ms,
		   struct dirty_log *log, uint32_t region_size,
		   region_t nr_regions)
{
	unsigned int nr_buckets, max_buckets;
	size_t i;

	/*
	 * Calculate a suitable number of buckets for our hash
	 * table.
	 */
	max_buckets = nr_regions >> 6;
	for (nr_buckets = 128u; nr_buckets < max_buckets; nr_buckets <<= 1)
		;
	nr_buckets >>= 1;

	rh->ms = ms;
	rh->log = log;
	rh->region_size = region_size;
	rh->region_shift = ffs(region_size) - 1;
	rwlock_init(&rh->hash_lock);
	rh->mask = nr_buckets - 1;
	rh->nr_buckets = nr_buckets;

	rh->buckets = vmalloc(nr_buckets * sizeof(*rh->buckets));
	if (!rh->buckets) {
		DMERR("unable to allocate region hash memory");
		return -ENOMEM;
	}

	for (i = 0; i < nr_buckets; i++)
		INIT_LIST_HEAD(rh->buckets + i);

	spin_lock_init(&rh->region_lock);
	sema_init(&rh->recovery_count, 0);
	atomic_set(&rh->recovery_in_flight, 0);
	INIT_LIST_HEAD(&rh->clean_regions);
	INIT_LIST_HEAD(&rh->quiesced_regions);
	INIT_LIST_HEAD(&rh->recovered_regions);
	INIT_LIST_HEAD(&rh->failed_recovered_regions);

	rh->region_pool = mempool_create_kmalloc_pool(MIN_REGIONS,
						      sizeof(struct region));
	if (!rh->region_pool) {
		vfree(rh->buckets);
		rh->buckets = NULL;
		return -ENOMEM;
	}

	return 0;
}

static void rh_exit(struct region_hash *rh)
{
	unsigned int h;
	struct region *reg, *nreg;

	BUG_ON(!list_empty(&rh->quiesced_regions));
	for (h = 0; h < rh->nr_buckets; h++) {
		list_for_each_entry_safe(reg, nreg, rh->buckets + h, hash_list) {
			BUG_ON(atomic_read(&reg->pending));
			mempool_free(reg, rh->region_pool);
		}
	}

	if (rh->log)
		dm_destroy_dirty_log(rh->log);
	if (rh->region_pool)
		mempool_destroy(rh->region_pool);
	vfree(rh->buckets);
}

#define RH_HASH_MULT 2654435387U

static inline unsigned int rh_hash(struct region_hash *rh, region_t region)
{
	return (unsigned int) ((region * RH_HASH_MULT) >> 12) & rh->mask;
}

static struct region *__rh_lookup(struct region_hash *rh, region_t region)
{
	struct region *reg;

	list_for_each_entry (reg, rh->buckets + rh_hash(rh, region), hash_list)
		if (reg->key == region)
			return reg;

	return NULL;
}

static void __rh_insert(struct region_hash *rh, struct region *reg)
{
	unsigned int h = rh_hash(rh, reg->key);
	list_add(&reg->hash_list, rh->buckets + h);
}

static struct region *__rh_alloc(struct region_hash *rh, region_t region)
{
	struct region *reg, *nreg;

	read_unlock(&rh->hash_lock);
	nreg = mempool_alloc(rh->region_pool, GFP_ATOMIC);
	if (unlikely(!nreg))
		nreg = kmalloc(sizeof(struct region), GFP_NOIO);
	nreg->state = rh->log->type->in_sync(rh->log, region, 1) ?
		RH_CLEAN : RH_NOSYNC;
	nreg->rh = rh;
	nreg->key = region;

	INIT_LIST_HEAD(&nreg->list);

	atomic_set(&nreg->pending, 0);
	bio_list_init(&nreg->delayed_bios);
	write_lock_irq(&rh->hash_lock);

	reg = __rh_lookup(rh, region);
	if (reg)
		/* we lost the race */
		mempool_free(nreg, rh->region_pool);

	else {
		__rh_insert(rh, nreg);
		if (nreg->state == RH_CLEAN) {
			spin_lock(&rh->region_lock);
			list_add(&nreg->list, &rh->clean_regions);
			spin_unlock(&rh->region_lock);
		}
		reg = nreg;
	}
	write_unlock_irq(&rh->hash_lock);
	read_lock(&rh->hash_lock);

	return reg;
}

static inline struct region *__rh_find(struct region_hash *rh, region_t region)
{
	struct region *reg;

	reg = __rh_lookup(rh, region);
	if (!reg)
		reg = __rh_alloc(rh, region);

	return reg;
}

static int rh_state(struct region_hash *rh, region_t region, int may_block)
{
	int r;
	struct region *reg;

	read_lock(&rh->hash_lock);
	reg = __rh_lookup(rh, region);
	read_unlock(&rh->hash_lock);

	if (reg)
		return reg->state;

	/*
	 * The region wasn't in the hash, so we fall back to the
	 * dirty log.
	 */
	r = rh->log->type->in_sync(rh->log, region, may_block);

	/*
	 * Any error from the dirty log (eg. -EWOULDBLOCK) gets
	 * taken as a RH_NOSYNC
	 */
	return r == 1 ? RH_CLEAN : RH_NOSYNC;
}

static inline int rh_in_sync(struct region_hash *rh,
			     region_t region, int may_block)
{
	int state = rh_state(rh, region, may_block);
	return state == RH_CLEAN || state == RH_DIRTY;
}

static void dispatch_bios(struct mirror_set *ms, struct bio_list *bio_list)
{
	struct bio *bio;

	while ((bio = bio_list_pop(bio_list))) {
		queue_bio(ms, bio, WRITE);
	}
}

static void complete_resync_work(struct region *reg, int success)
{
	struct region_hash *rh = reg->rh;

	rh->log->type->set_region_sync(rh->log, reg->key, success);

	/*
	 * Dispatch the bios before we call 'wake_up_all'.
	 * This is important because if we are suspending,
	 * we want to know that recovery is complete and
	 * the work queue is flushed.  If we wake_up_all
	 * before we dispatch_bios (queue bios and call wake()),
	 * then we risk suspending before the work queue
	 * has been properly flushed.
	 */
	dispatch_bios(rh->ms, &reg->delayed_bios);
	if (atomic_dec_and_test(&rh->recovery_in_flight))
		wake_up_all(&recovery_stopped_event);
	up(&rh->recovery_count);
}

static void rh_update_states(struct region_hash *rh)
{
	struct region *reg, *next;

	LIST_HEAD(clean);
	LIST_HEAD(recovered);
	LIST_HEAD(failed_recovered);

	/*
	 * Quickly grab the lists.
	 */
	write_lock_irq(&rh->hash_lock);
	spin_lock(&rh->region_lock);
	if (!list_empty(&rh->clean_regions)) {
		list_splice(&rh->clean_regions, &clean);
		INIT_LIST_HEAD(&rh->clean_regions);

		list_for_each_entry (reg, &clean, list)
			list_del(&reg->hash_list);
	}

	if (!list_empty(&rh->recovered_regions)) {
		list_splice(&rh->recovered_regions, &recovered);
		INIT_LIST_HEAD(&rh->recovered_regions);

		list_for_each_entry (reg, &recovered, list)
			list_del(&reg->hash_list);
	}

	if (!list_empty(&rh->failed_recovered_regions)) {
		list_splice(&rh->failed_recovered_regions, &failed_recovered);
		INIT_LIST_HEAD(&rh->failed_recovered_regions);

		list_for_each_entry (reg, &failed_recovered, list)
			list_del(&reg->hash_list);
	}

	spin_unlock(&rh->region_lock);
	write_unlock_irq(&rh->hash_lock);

	/*
	 * All the regions on the recovered and clean lists have
	 * now been pulled out of the system, so no need to do
	 * any more locking.
	 */
	list_for_each_entry_safe (reg, next, &recovered, list) {
		rh->log->type->clear_region(rh->log, reg->key);
		complete_resync_work(reg, 1);
		mempool_free(reg, rh->region_pool);
	}

	list_for_each_entry_safe (reg, next, &failed_recovered, list) {
		complete_resync_work(reg, 0);
		mempool_free(reg, rh->region_pool);
	}

	list_for_each_entry_safe (reg, next, &clean, list) {
		rh->log->type->clear_region(rh->log, reg->key);
		mempool_free(reg, rh->region_pool);
	}
	/*
	 * If the log implementation is good, it will only
	 * flush (to disk) if it is necessary.
	 */
	rh->log->type->flush(rh->log);
}

static void rh_inc(struct region_hash *rh, region_t region)
{
	struct region *reg;

	read_lock(&rh->hash_lock);
	reg = __rh_find(rh, region);

	spin_lock_irq(&rh->region_lock);
	atomic_inc(&reg->pending);

	if (reg->state == RH_CLEAN) {
		reg->state = RH_DIRTY;
		list_del_init(&reg->list);	/* take off the clean list */
		spin_unlock_irq(&rh->region_lock);

		rh->log->type->mark_region(rh->log, reg->key);
	} else
		spin_unlock_irq(&rh->region_lock);


	read_unlock(&rh->hash_lock);
}

static void rh_inc_pending(struct region_hash *rh, struct bio_list *bios)
{
	struct bio *bio;

	for (bio = bios->head; bio; bio = bio->bi_next)
		rh_inc(rh, bio_to_region(rh, bio));
}

static void rh_dec(struct region_hash *rh, region_t region)
{
	unsigned long flags;
	struct region *reg;
	int should_wake = 0;

	read_lock(&rh->hash_lock);
	reg = __rh_lookup(rh, region);
	read_unlock(&rh->hash_lock);

	spin_lock_irqsave(&rh->region_lock, flags);
	if (atomic_dec_and_test(&reg->pending)) {
		/*
		 * There is no pending I/O for this region.
		 * We can move the region to corresponding list for next action.
		 * At this point, the region is not yet connected to any list.
		 *
		 * If the state is RH_NOSYNC, the region should be kept off
		 * from clean list.
		 * The hash entry for RH_NOSYNC will remain in memory
		 * until the region is recovered or the map is reloaded.
		 */

		/* do nothing for RH_NOSYNC */
		if (reg->state == RH_RECOVERING) {
			list_add_tail(&reg->list, &rh->quiesced_regions);
		} else if (reg->state == RH_DIRTY) {
			reg->state = RH_CLEAN;
			list_add(&reg->list, &rh->clean_regions);
		}
		should_wake = 1;
	}
	spin_unlock_irqrestore(&rh->region_lock, flags);

	if (should_wake)
		wake(rh->ms);
}

/*
 * Starts quiescing a region in preparation for recovery.
 */
static int __rh_recovery_prepare(struct region_hash *rh)
{
	int r;
	struct region *reg;
	region_t region;

	/*
	 * Ask the dirty log what's next.
	 */
	r = rh->log->type->get_resync_work(rh->log, &region);
	if (r <= 0)
		return r;

	/*
	 * Get this region, and start it quiescing by setting the
	 * recovering flag.
	 */
	read_lock(&rh->hash_lock);
	reg = __rh_find(rh, region);
	read_unlock(&rh->hash_lock);

	spin_lock_irq(&rh->region_lock);
	reg->state = RH_RECOVERING;

	/* Already quiesced ? */
	if (atomic_read(&reg->pending))
		list_del_init(&reg->list);
	else
		list_move(&reg->list, &rh->quiesced_regions);

	spin_unlock_irq(&rh->region_lock);

	return 1;
}

static void rh_recovery_prepare(struct region_hash *rh)
{
	/* Extra reference to avoid race with rh_stop_recovery */
	atomic_inc(&rh->recovery_in_flight);

	while (!down_trylock(&rh->recovery_count)) {
		atomic_inc(&rh->recovery_in_flight);
		if (__rh_recovery_prepare(rh) <= 0) {
			atomic_dec(&rh->recovery_in_flight);
			up(&rh->recovery_count);
			break;
		}
	}

	/* Drop the extra reference */
	if (atomic_dec_and_test(&rh->recovery_in_flight))
		wake_up_all(&recovery_stopped_event);
}

/*
 * Returns any quiesced regions.
 */
static struct region *rh_recovery_start(struct region_hash *rh)
{
	struct region *reg = NULL;

	spin_lock_irq(&rh->region_lock);
	if (!list_empty(&rh->quiesced_regions)) {
		reg = list_entry(rh->quiesced_regions.next,
				 struct region, list);
		list_del_init(&reg->list);	/* remove from the quiesced list */
	}
	spin_unlock_irq(&rh->region_lock);

	return reg;
}

static void rh_recovery_end(struct region *reg, int success)
{
	struct region_hash *rh = reg->rh;

	spin_lock_irq(&rh->region_lock);
	if (success ||
	    (rh->log->type->get_failure_response(rh->log) == DMLOG_IOERR_IGNORE))
		list_add(&reg->list, &reg->rh->recovered_regions);
	else {
		reg->state = RH_NOSYNC;
		list_add(&reg->list, &reg->rh->failed_recovered_regions);
	}
	spin_unlock_irq(&rh->region_lock);

	wake(rh->ms);
}

static int rh_flush(struct region_hash *rh)
{
	return rh->log->type->flush(rh->log);
}

static void rh_delay(struct region_hash *rh, struct bio *bio)
{
	struct region *reg;

	read_lock(&rh->hash_lock);
	reg = __rh_find(rh, bio_to_region(rh, bio));
	bio_list_add(&reg->delayed_bios, bio);
	read_unlock(&rh->hash_lock);
}

static void rh_stop_recovery(struct region_hash *rh)
{
	int i;

	/* wait for any recovering regions */
	for (i = 0; i < MAX_RECOVERY; i++)
		down(&rh->recovery_count);
}

static void rh_start_recovery(struct region_hash *rh)
{
	int i;

	for (i = 0; i < MAX_RECOVERY; i++)
		up(&rh->recovery_count);

	wake(rh->ms);
}

struct bio_map_info {
	struct mirror *bmi_m;
	struct dm_bio_details bmi_bd;
};

static mempool_t *bio_map_info_pool = NULL;

static void *bio_map_info_alloc(unsigned int gfp_mask, void *pool_data){
	return kmalloc(sizeof(struct bio_map_info), gfp_mask);
}

static void bio_map_info_free(void *element, void *pool_data){
	kfree(element);
}

/*
 * Every mirror should look like this one.
 */
#define DEFAULT_MIRROR 0

/*
 * This is yucky.  We squirrel the mirror struct away inside
 * bi_next for read/write buffers.  This is safe since the bh
 * doesn't get submitted to the lower levels of block layer.
 */
static struct mirror *bio_get_m(struct bio *bio)
{
	return (struct mirror *) bio->bi_next;
}

static void bio_set_m(struct bio *bio, struct mirror *m)
{
	bio->bi_next = (struct bio *) m;
}

/*-----------------------------------------------------------------
 * Recovery.
 *
 * When a mirror is first activated we may find that some regions
 * are in the no-sync state.  We have to recover these by
 * recopying from the default mirror to all the others.
 *---------------------------------------------------------------*/
static void fail_mirror(struct mirror *m);
static void recovery_complete(int read_err, unsigned int write_err,
			      void *context)
{
	struct region *reg = (struct region *) context;
	struct mirror_set *ms = reg->rh->ms;
	unsigned long write_error = write_err;
	int m, bit = 0;

	if (read_err) {
		/* Read error means the failure of default mirror. */
		DMERR("Unable to read from primary mirror during recovery");
		fail_mirror(ms->default_mirror);
	}

	if (write_error) {
		DMERR("Write error during recovery (error = %#lx)",
		      write_error);
		/*
		 * Bits correspond to devices (excluding default mirror).
		 * The default mirror cannot change during recovery.
		 */
		for (m = 0; m < ms->nr_mirrors; m++) {
			if (&ms->mirror[m] == ms->default_mirror)
				continue;
			if (test_bit(bit, &write_error))
				fail_mirror(ms->mirror + m);
			bit++;
		}
	}

	rh_recovery_end(reg, !(read_err || write_err));
}

static int recover(struct mirror_set *ms, struct region *reg)
{
	int r;
	unsigned int i;
	struct io_region from, to[KCOPYD_MAX_REGIONS], *dest;
	struct mirror *m;
	unsigned long flags = 0;

	/* fill in the source */
	m = ms->default_mirror;
	from.bdev = m->dev->bdev;
	from.sector = m->offset + region_to_sector(reg->rh, reg->key);
	if (reg->key == (ms->nr_regions - 1)) {
		/*
		 * The final region may be smaller than
		 * region_size.
		 */
		from.count = ms->ti->len & (reg->rh->region_size - 1);
		if (!from.count)
			from.count = reg->rh->region_size;
	} else
		from.count = reg->rh->region_size;

	/* fill in the destinations */
	for (i = 0, dest = to; i < ms->nr_mirrors; i++) {
		if (&ms->mirror[i] == ms->default_mirror)
			continue;

		m = ms->mirror + i;
		dest->bdev = m->dev->bdev;
		dest->sector = m->offset + region_to_sector(reg->rh, reg->key);
		dest->count = from.count;
		dest++;
	}

	/* hand to kcopyd */
	if (ms->rh.log->type->get_failure_response(ms->rh.log) == DMLOG_IOERR_IGNORE)
		set_bit(KCOPYD_IGNORE_ERROR, &flags);

	r = kcopyd_copy(ms->kcopyd_client, &from, ms->nr_mirrors - 1, to, flags,
			recovery_complete, reg);

	return r;
}

static void do_recovery(struct mirror_set *ms)
{
	int r;
	struct region *reg;
	struct dirty_log *log = ms->rh.log;

	/*
	 * Start quiescing some regions.
	 */
	rh_recovery_prepare(&ms->rh);

	/*
	 * Copy any already quiesced regions.
	 */
	while ((reg = rh_recovery_start(&ms->rh))) {
		r = recover(ms, reg);
		if (r)
			rh_recovery_end(reg, 0);
	}

	/*
	 * Update the in sync flag.
	 */
	if (!ms->in_sync &&
	    (log->type->get_sync_count(log) == ms->nr_regions)) {
		/* the sync is complete */
		dm_table_event(ms->ti->table);
		ms->in_sync = 1;
	}
}

/*-----------------------------------------------------------------
 * Reads
 *---------------------------------------------------------------*/
/* Switch to next dev, via round-robin, after MIN_READS reads */
#define MIN_READS 128

/* choose_mirror
 * @ms: the mirror set
 *
 * This function is used for read balancing.
 *
 * Returns: chosen mirror, or NULL on failure
 */
static struct mirror *choose_mirror(struct mirror_set *ms)
{
	struct mirror *start_mirror = ms->read_mirror;

	/*
	 * Perform MIN_READS on each working mirror then
	 * advance to the next one.  start_mirror stores
	 * the first we tried, so we know when we're done.
	 */
	do {
		if (likely(!atomic_read(&ms->read_mirror->error_count)) &&
		    !atomic_dec_and_test(&ms->read_count))
			goto use_mirror;

		atomic_set(&ms->read_count, MIN_READS);

		if (ms->read_mirror-- == ms->mirror)
			ms->read_mirror += ms->nr_mirrors;
	} while (ms->read_mirror != start_mirror);

	/*
	 * We've rejected every mirror.
	 * Confirm the start_mirror can be used.
	 */
	if (unlikely(atomic_read(&ms->read_mirror->error_count)))
		return NULL;

use_mirror:
	return ms->read_mirror;
}

/* fail_mirror
 * @m: mirror device to fail
 *
 * If the device is valid, mark it invalid.  Also,
 * if this is the default mirror device (i.e. the primary
 * device) and the mirror set is in-sync, choose an
 * alternate primary device.
 *
 * This function cannot block.
 */
static void fail_mirror(struct mirror *m)
{
	struct mirror_set *ms = m->ms;
	struct mirror *new;

	atomic_inc(&m->error_count);

	if (atomic_read(&m->error_count) > 1)
		return;

	if (m != ms->default_mirror)
		return;

	/*
	 * If the default mirror fails, change it.
	 * In the case of cluster mirroring, the default
	 * is changed in rh_update_states.
	 */
	if (!ms->in_sync) {
		/*
		 * Can not switch primary.  Better to issue requests
		 * to same failing device than to risk returning
		 * corrupt data.
		 */
		DMERR("Primary mirror device has failed while mirror is not in-sync");
		DMERR("Unable to choose alternative primary device");
		return;
	}

	for (new = ms->mirror; new < ms->mirror + ms->nr_mirrors; new++)
		if (!atomic_read(&new->error_count)) {
			ms->default_mirror = new;
			break;
		}

	if (unlikely(new == ms->mirror + ms->nr_mirrors))
		DMWARN("All sides of mirror have failed.");
}

static int default_ok(struct mirror *m)
{
	return !atomic_read(&m->ms->default_mirror->error_count);
}

static int mirror_available(struct mirror_set *ms, struct bio *bio)
{
	region_t region = bio_to_region(&ms->rh, bio);

	if (ms->rh.log->type->in_sync(ms->rh.log, region, 0) > 0)
		return choose_mirror(ms) ? 1 : 0;

	return 0;
}

/*
 * remap a buffer to a particular mirror.
 */
static sector_t map_sector(struct mirror *m, struct bio *bio)
{
	return m->offset + (bio->bi_sector - m->ms->ti->begin);
}

static void map_bio(struct mirror *m, struct bio *bio)
{
	bio->bi_bdev = m->dev->bdev;
	bio->bi_sector = map_sector(m, bio);
}

static void map_region(struct io_region *io, struct mirror *m,
		       struct bio *bio)
{
	io->bdev = m->dev->bdev;
	io->sector = map_sector(m, bio);
	io->count = bio->bi_size >> 9;
}

/*-----------------------------------------------------------------
 * Reads
 *---------------------------------------------------------------*/
static void read_callback(unsigned long error, void *context)
{
	struct bio *bio = (struct bio *)context;
	struct mirror *m;

	m = bio_get_m(bio);
	bio_set_m(bio, NULL);

	if (unlikely(error)) {
		DMWARN("A read failure occurred on a mirror device.");
		fail_mirror(m);
		if (likely(default_ok(m)) || mirror_available(m->ms, bio)) {
			DMWARN("Trying different device.");
			queue_bio(m->ms, bio, bio_rw(bio));
		} else {
			DMERR("No other device available, failing I/O.");
			bio_endio(bio, bio->bi_size, -EIO);
		}
	} else
		bio_endio(bio, bio->bi_size, 0);
}

/* Asynchronous read. */
static void read_async_bio(struct mirror *m, struct bio *bio)
{
	struct io_region io;
	struct dm_io_request io_req = {
		.bi_rw = READ,
		.mem.type = DM_IO_BVEC,
		.mem.ptr.bvec = bio->bi_io_vec + bio->bi_idx,
		.notify.fn = read_callback,
		.notify.context = bio,
		.client = m->ms->io_client,
	};

	map_region(&io, m, bio);
	bio_set_m(bio, m);
	(void) dm_io(&io_req, 1, &io, NULL);
}

static void do_reads(struct mirror_set *ms, struct bio_list *reads)
{
	struct bio *bio;
	struct mirror *m;

	while ((bio = bio_list_pop(reads))) {
		/*
		 * We can only read balance if the region is in sync.
		 */
		if (likely(rh_in_sync(&ms->rh,
				      bio_to_region(&ms->rh, bio), 1)))
			m = choose_mirror(ms);
		else {
			m = ms->default_mirror;

			/* If default has failed, we give up. */
			if (unlikely(m && atomic_read(&m->error_count)))
				m = NULL;
		}

		if (likely(m))
			read_async_bio(m, bio);
		else
			bio_endio(bio, bio->bi_size, -EIO);
	}
}

/*-----------------------------------------------------------------
 * Writes.
 *
 * We do different things with the write io depending on the
 * state of the region that it's in:
 *
 * SYNC: 	increment pending, use kcopyd to write to *all* mirrors
 * RECOVERING:	delay the io until recovery completes
 * NOSYNC:	increment pending, just write to the default mirror
 *---------------------------------------------------------------*/

/* __bio_mark_nosync
 * @ms
 * @bio
 * @done
 * @error
 *
 * The bio was written on some mirror(s) but failed on other mirror(s).
 * We can successfully endio the bio but should avoid the region being
 * marked clean by setting the state RH_NOSYNC.
 *
 * This function is _not_ interrupt safe!
 */
static void __bio_mark_nosync(struct mirror_set *ms,
			      struct bio *bio, unsigned int done, int error)
{
	unsigned long flags;
	struct region_hash *rh = &ms->rh;
	struct dirty_log *log = ms->rh.log;
	struct region *reg;
	region_t region = bio_to_region(rh, bio);
	int recovering = 0;

	/* We must inform the log that the sync count has changed. */
	log->type->set_region_sync(log, region, 0);
	ms->in_sync = 0;

	read_lock(&rh->hash_lock);
	reg = __rh_find(rh, region);
	read_unlock(&rh->hash_lock);

	/* region hash entry should exist because write was in-flight */
	BUG_ON(!reg);
	BUG_ON(!list_empty(&reg->list));

	spin_lock_irqsave(&rh->region_lock, flags);
	/*
	 * Possible cases:
	 *   1) RH_DIRTY
	 *   2) RH_NOSYNC: was dirty, other preceeding writes failed
	 *   3) RH_RECOVERING: flushing pending writes
	 * Either case, the region should have not been connected to list.
	 */
	recovering = (reg->state == RH_RECOVERING);
	reg->state = RH_NOSYNC;
	BUG_ON(!list_empty(&reg->list));
	spin_unlock_irqrestore(&rh->region_lock, flags);

	bio_endio(bio, done, error);
	if (recovering)
		complete_resync_work(reg, 0);
}

static void write_callback(unsigned long error, void *context)
{
	unsigned int i, ret = 0;
	struct bio *bio = (struct bio *) context;
	struct mirror_set *ms;
	int uptodate = 0;
	int should_wake = 0;
	unsigned long flags;

	ms = (bio_get_m(bio))->ms;
	bio_set_m(bio, NULL);

	/*
	 * NOTE: We don't decrement the pending count here,
	 * instead it is done by the targets endio function.
	 * This way we handle both writes to SYNC and NOSYNC
	 * regions with the same code.
	 */
	if (unlikely(error)) {
		for (i = 0; i < ms->nr_mirrors; i++) {
			if (test_bit(i, &error))
				fail_mirror(ms->mirror + i);
			else
				uptodate = 1;
		}

		if (likely(uptodate)) {
			/*
			 * Need to raise event.  Since raising
			 * events can block, we need to do it in
			 * the main thread.
			 */
			spin_lock_irqsave(&ms->lock, flags);
			if (!ms->failures.head)
				should_wake = 1;
			bio_list_add(&ms->failures, bio);
			spin_unlock_irqrestore(&ms->lock, flags);
			if (should_wake)
				wake(ms);
			return;
		} else {
			DMERR("All replicated volumes dead, failing I/O");
			/* None of the writes succeeded, fail the I/O. */
			ret = -EIO;
		}
	}

	bio_endio(bio, bio->bi_size, ret);
}

static void do_write(struct mirror_set *ms, struct bio *bio)
{
	unsigned int i;
	struct io_region io[ms->nr_mirrors], *dest = io;
	struct mirror *m;
	struct dm_io_request io_req = {
		.bi_rw = WRITE,
		.mem.type = DM_IO_BVEC,
		.mem.ptr.bvec = bio->bi_io_vec + bio->bi_idx,
		.notify.fn = write_callback,
		.notify.context = bio,
		.client = ms->io_client,
	};

	for (i = 0, m = ms->mirror; i < ms->nr_mirrors; i++, m++)
		map_region(dest++, m, bio);

	/*
	 * We can use the default mirror here, because we
	 * only need it in order to retrieve the reference
	 * to the mirror set in write_callback().
	 */
	bio_set_m(bio, ms->default_mirror);
	(void) dm_io(&io_req, ms->nr_mirrors, io, NULL);
}

static void do_writes(struct mirror_set *ms, struct bio_list *writes)
{
	int state;
	struct bio *bio;
	struct bio_list sync, nosync, recover, *this_list = NULL;
	struct bio_list requeue;
	struct dirty_log *log = ms->rh.log;
	region_t region;

	if (!writes->head)
		return;

	/*
	 * Classify each write.
	 */
	bio_list_init(&sync);
	bio_list_init(&nosync);
	bio_list_init(&recover);
	bio_list_init(&requeue);

	while ((bio = bio_list_pop(writes))) {
		region = bio_to_region(&ms->rh, bio);

		if (log->type->is_remote_recovering &&
		    log->type->is_remote_recovering(log, region)) {
			bio_list_add(&requeue, bio);
			continue;
		}

		state = rh_state(&ms->rh, region, 1);
		switch (state) {
		case RH_CLEAN:
		case RH_DIRTY:
			this_list = &sync;
			break;

		case RH_NOSYNC:
			this_list = &nosync;
			break;

		case RH_RECOVERING:
			this_list = &recover;
			break;
		}

		bio_list_add(this_list, bio);
	}

	/*
	 * Add bios that are delayed due to remote recovery
	 * back on to the write queue
	 */
	spin_lock_irq(&ms->lock);
	bio_list_merge(&ms->writes, &requeue);
	spin_unlock_irq(&ms->lock);

	/*
	 * Increment the pending counts for any regions that will
	 * be written to (writes to recover regions are going to
	 * be delayed).
	 */
	rh_inc_pending(&ms->rh, &sync);
	rh_inc_pending(&ms->rh, &nosync);

	ms->log_failure = rh_flush(&ms->rh);

	/*
	 * Dispatch io.
	 */
	if (ms->log_failure) {
		spin_lock_irq(&ms->lock);
		bio_list_merge(&ms->failures, &sync);
		spin_unlock_irq(&ms->lock);
	} else {
		while ((bio = bio_list_pop(&sync)))
			do_write(ms, bio);
	}

	while ((bio = bio_list_pop(&recover)))
		rh_delay(&ms->rh, bio);

	while ((bio = bio_list_pop(&nosync))) {
		map_bio(ms->default_mirror, bio);
		generic_make_request(bio);
	}
}

static void do_failures(struct mirror_set *ms, struct bio_list *failures)
{
	struct bio *bio;
	struct dirty_log *log = ms->rh.log;

	if (!failures->head)
		return;

	if (ms->log_failure) {
		/*
		 * If the log has failed, unattempted writes are being
		 * put on the failures list.  We can't issue those writes
		 * until a log has been marked, so we must store them.
		 *
		 * If a 'noflush' suspend is in progress, we can requeue
		 * the I/O's to the core.  This give userspace a chance
		 * to reconfigure the mirror, at which point the core
		 * will reissue the writes.  If the 'noflush' flag is
		 * not set, we have no choice but to return errors.
		 *
		 * Some writes on the failures list may have been
		 * submitted before the log failure and represent a
		 * failure to write to one of the devices.  It is ok
		 * for us to treat them the same and requeue them
		 * as well.
		 */
		if (dm_noflush_suspending(ms->ti)) {
			while ((bio = bio_list_pop(failures)))
				bio_endio(bio, bio->bi_size, DM_ENDIO_REQUEUE);
		} else if (atomic_read(&ms->suspend)) {
			while ((bio = bio_list_pop(failures)))
				bio_endio(bio, bio->bi_size, -EIO);
		} else {
			spin_lock_irq(&ms->lock);
			bio_list_merge(&ms->failures, failures);
			spin_unlock_irq(&ms->lock);
			wake(ms);
		}
		return;
	}

	if (log->type->get_failure_response(log) == DMLOG_IOERR_BLOCK)
		dm_table_event(ms->ti->table);

	while ((bio = bio_list_pop(failures)))
		__bio_mark_nosync(ms, bio, bio->bi_size, 0);
}

/*-----------------------------------------------------------------
 * kmirrord
 *---------------------------------------------------------------*/
static int do_mirror(struct mirror_set *ms)
{
	struct bio_list reads, writes, failures;

	spin_lock_irq(&ms->lock);
	reads = ms->reads;
	writes = ms->writes;
	failures = ms->failures;
	bio_list_init(&ms->reads);
	bio_list_init(&ms->writes);
	bio_list_init(&ms->failures);
	spin_unlock_irq(&ms->lock);

	rh_update_states(&ms->rh);
	do_recovery(ms);
	do_reads(ms, &reads);
	do_writes(ms, &writes);
	do_failures(ms, &failures);

	return (ms->writes.head || ms->failures.head) ? 1 : 0;
}

static void do_work(void *data)
{
	while (do_mirror(data))
		schedule();
}

/*-----------------------------------------------------------------
 * Target functions
 *---------------------------------------------------------------*/
static struct mirror_set *alloc_context(unsigned int nr_mirrors,
					uint32_t region_size,
					struct dm_target *ti,
					struct dirty_log *dl)
{
	size_t len;
	struct mirror_set *ms = NULL;

	if (array_too_big(sizeof(*ms), sizeof(ms->mirror[0]), nr_mirrors))
		return NULL;

	len = sizeof(*ms) + (sizeof(ms->mirror[0]) * nr_mirrors);

	ms = kmalloc(len, GFP_KERNEL);
	if (!ms) {
		ti->error = "Cannot allocate mirror context";
		return NULL;
	}

	memset(ms, 0, len);
	spin_lock_init(&ms->lock);

	ms->ti = ti;
	ms->nr_mirrors = nr_mirrors;
	ms->nr_regions = dm_sector_div_up(ti->len, region_size);
	ms->in_sync = 0;
	ms->log_failure = 0;
	atomic_set(&ms->suspend, 0);
	ms->read_mirror = &ms->mirror[DEFAULT_MIRROR];
	ms->default_mirror = &ms->mirror[DEFAULT_MIRROR];

	ms->io_client = dm_io_client_create(DM_IO_PAGES);
	if (IS_ERR(ms->io_client)) {
		ti->error = "Error creating dm_io client";
		kfree(ms);
 		return NULL;
	}

	if (rh_init(&ms->rh, ms, dl, region_size, ms->nr_regions)) {
		ti->error = "Error creating dirty region hash";
		kfree(ms);
		return NULL;
	}

	atomic_set(&ms->read_count, MIN_READS);

	bio_list_init(&ms->failures);

	return ms;
}

static void free_context(struct mirror_set *ms, struct dm_target *ti,
			 unsigned int m)
{
	while (m--)
		dm_put_device(ti, ms->mirror[m].dev);

	dm_io_client_destroy(ms->io_client);
	rh_exit(&ms->rh);
	kfree(ms);
}

static inline int _check_region_size(struct dm_target *ti, uint32_t size)
{
	return !(size % (PAGE_SIZE >> 9) || (size & (size - 1)) ||
		 size > ti->len);
}

static int get_mirror(struct mirror_set *ms, struct dm_target *ti,
		      unsigned int mirror, char **argv)
{
	unsigned long long offset;

	if (sscanf(argv[1], "%llu", &offset) != 1) {
		ti->error = "Invalid offset";
		return -EINVAL;
	}

	if (dm_get_device(ti, argv[0], offset, ti->len,
			  dm_table_get_mode(ti->table),
			  &ms->mirror[mirror].dev)) {
		ti->error = "Device lookup failure";
		return -ENXIO;
	}

	ms->mirror[mirror].offset = offset;
	atomic_set(&(ms->mirror[mirror].error_count), 0);
	ms->mirror[mirror].ms = ms;

	return 0;
}

/*
 * Create dirty log: log_type #log_params <log_params>
 */
static struct dirty_log *create_dirty_log(struct dm_target *ti,
					  unsigned int argc, char **argv,
					  unsigned int *args_used)
{
	unsigned int param_count;
	struct dirty_log *dl;

	if (argc < 2) {
		ti->error = "Insufficient mirror log arguments";
		return NULL;
	}

	if (sscanf(argv[1], "%u", &param_count) != 1) {
		ti->error = "Invalid mirror log argument count";
		return NULL;
	}

	*args_used = 2 + param_count;

	if (argc < *args_used) {
		ti->error = "Insufficient mirror log arguments";
		return NULL;
	}

	dl = dm_create_dirty_log(argv[0], ti, param_count, argv + 2);
	if (!dl) {
		ti->error = "Error creating mirror dirty log";
		return NULL;
	}

	if (!_check_region_size(ti, dl->type->get_region_size(dl))) {
		ti->error = "Invalid region size";
		dm_destroy_dirty_log(dl);
		return NULL;
	}

	return dl;
}

/*
 * Construct a mirror mapping:
 *
 * log_type #log_params <log_params>
 * #mirrors [mirror_path offset]{2,}
 *
 * log_type is "core" or "disk"
 * #log_params is between 1 and 3
 */
static int mirror_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	int r;
	unsigned int nr_mirrors, m, args_used;
	struct mirror_set *ms;
	struct dirty_log *dl;

	dl = create_dirty_log(ti, argc, argv, &args_used);
	if (!dl)
		return -EINVAL;

	argv += args_used;
	argc -= args_used;

	if (!argc || sscanf(argv[0], "%u", &nr_mirrors) != 1 ||
	    nr_mirrors < 2 || nr_mirrors > KCOPYD_MAX_REGIONS + 1) {
		ti->error = "Invalid number of mirrors";
		dm_destroy_dirty_log(dl);
		return -EINVAL;
	}

	argv++, argc--;

	if (argc != nr_mirrors * 2) {
		ti->error = "Wrong number of mirror arguments";
		dm_destroy_dirty_log(dl);
		return -EINVAL;
	}

	ms = alloc_context(nr_mirrors, dl->type->get_region_size(dl), ti, dl);
	if (!ms) {
		dm_destroy_dirty_log(dl);
		return -ENOMEM;
	}

	/* Get the mirror parameter sets */
	for (m = 0; m < nr_mirrors; m++) {
		r = get_mirror(ms, ti, m, argv);
		if (r) {
			free_context(ms, ti, m);
			return r;
		}
		argv += 2;
		argc -= 2;
	}

	ti->private = ms;
 	ti->split_io = ms->rh.region_size;

	ms->kmirrord_wq = create_singlethread_workqueue("kmirrord");
	if (!ms->kmirrord_wq) {
		DMERR("couldn't start kmirrord");
		free_context(ms, ti, ms->nr_mirrors);
		return -ENOMEM;
	}
	INIT_WORK(&ms->kmirrord_work, do_work, ms);

	r = kcopyd_client_create(DM_IO_PAGES, &ms->kcopyd_client);
	if (r) {
		destroy_workqueue(ms->kmirrord_wq);
		free_context(ms, ti, ms->nr_mirrors);
		return r;
	}

	wake(ms);
	return 0;
}

static void mirror_dtr(struct dm_target *ti)
{
	struct mirror_set *ms = (struct mirror_set *) ti->private;

	flush_workqueue(ms->kmirrord_wq);
	kcopyd_client_destroy(ms->kcopyd_client);
	destroy_workqueue(ms->kmirrord_wq);
	free_context(ms, ti, ms->nr_mirrors);
}

static void queue_bio(struct mirror_set *ms, struct bio *bio, int rw)
{
	unsigned long flags;
	int should_wake = 0;
	struct bio_list *bl;

	bl = (rw == WRITE) ? &ms->writes : &ms->reads;
	spin_lock_irqsave(&ms->lock, flags);
	should_wake = !(bl->head);
	bio_list_add(bl, bio);
	spin_unlock_irqrestore(&ms->lock, flags);

	if (should_wake)
		wake(ms);
}

/*
 * Mirror mapping function
 */
static int mirror_map(struct dm_target *ti, struct bio *bio,
		      union map_info *map_context)
{
	int r, rw = bio_rw(bio);
	struct mirror *m;
	struct mirror_set *ms = ti->private;
	struct bio_map_info *bmi = NULL;
	struct dm_bio_details *bd = NULL;

	if (rw == WRITE) {
		/* Save region for mirror_end_io() handler */
		map_context->ll = bio_to_region(&ms->rh, bio);
		queue_bio(ms, bio, rw);
		return 0;
	}

	/* All about the reads now */

	r = ms->rh.log->type->in_sync(ms->rh.log,
				      bio_to_region(&ms->rh, bio), 0);
	if (r < 0 && r != -EWOULDBLOCK)
		return r;

	if (r == -EWOULDBLOCK)
		r = 0;

	if (likely(r)) {
		/*
		 * Optimize reads by avoiding to hand them to daemon.
		 *
		 * In case they fail, queue them for another shot
		 * in the mirror_end_io() function.
		 */
		m = choose_mirror(ms);
		if (likely(m)) {
			bmi = mempool_alloc(bio_map_info_pool, GFP_NOIO);

			if (likely(bmi)) {
				/* without this, a read is not retryable */
				bd = &bmi->bmi_bd;
				dm_bio_record(bd, bio);
				map_context->ptr = bmi;
				bmi->bmi_m = m;
			} else {
				/* we could fail now, but we can at least  **
				** give it a shot.  The bd is only used to **
				** retry in the event of a failure anyway. **
				** If we fail, we can fail the I/O then.   */
				map_context->ptr = NULL;
			}

			map_bio(m, bio);
			return 1; /* Mapped -> queue request. */
		} else
			return -EIO;
	} else {
		/* Either not clean, or -EWOULDBLOCK */
		if (rw == READA)
			return -EWOULDBLOCK;

		queue_bio(ms, bio, rw);
	}

	return 0;
}

static int mirror_end_io(struct dm_target *ti, struct bio *bio,
			 int error, union map_info *map_context)
{
	int rw = bio_rw(bio);
	struct mirror_set *ms = (struct mirror_set *) ti->private;
	struct mirror *m = NULL;
	struct dm_bio_details *bd = NULL;

	/*
	 * We need to dec pending if this was a write.
	 */
	if (rw == WRITE) {
		rh_dec(&ms->rh, map_context->ll);
		return error;
	}

	if (error == -EOPNOTSUPP)
		goto out;

	if ((error == -EWOULDBLOCK) && bio_rw_ahead(bio))
		goto out;

	if (unlikely(error)) {
		DMERR("A read failure occurred on a mirror device.");
		if (!map_context->ptr) {
			/*
			 * There wasn't enough memory to record necessary
			 * information for a retry or there was no other
			 * mirror in-sync.
			 */
			DMERR("Unable to retry read.");
			return -EIO;
		}
		m = ((struct bio_map_info *)map_context->ptr)->bmi_m;
		fail_mirror(m); /* Flag error on mirror. */

		/*
		 * A failed read needs to get queued
		 * to the daemon for another shot to
		 * one (if any) intact mirrors.
		 */
		if (default_ok(m) || mirror_available(ms, bio)) {
			bd = &(((struct bio_map_info *)map_context->ptr)->bmi_bd
				);

			DMWARN("Trying different device.");
			dm_bio_restore(bd, bio);
			mempool_free(map_context->ptr, bio_map_info_pool);
			map_context->ptr = NULL;
			queue_bio(ms, bio, rw);
			return 1; /* We want another shot on the bio. */
		}
		DMERR("All replicated volumes dead, failing I/O");
	}

out:
	if (map_context->ptr)
		mempool_free(map_context->ptr, bio_map_info_pool);

	return error;
}

static void mirror_presuspend(struct dm_target *ti)
{
	struct mirror_set *ms = (struct mirror_set *) ti->private;
	struct dirty_log *log = ms->rh.log;

	atomic_set(&ms->suspend, 1);

	/*
	 * We must finish up all the work that we've
	 * generated (i.e. recovery work).
	 */
	rh_stop_recovery(&ms->rh);

	wait_event(recovery_stopped_event,
		   !atomic_read(&ms->rh.recovery_in_flight));

	if (log->type->presuspend && log->type->presuspend(log))
		/* FIXME: need better error handling */
		DMWARN("log presuspend failed");

	/*
	 * Now that recovery is complete/stopped and the
	 * delayed bios are queued, we need to wait for
	 * the worker thread to complete.  This way,
	 * we know that all of our I/O has been pushed.
	 */
	flush_workqueue(ms->kmirrord_wq);
}

static void mirror_postsuspend(struct dm_target *ti)
{
	struct mirror_set *ms = (struct mirror_set *) ti->private;
	struct dirty_log *log = ms->rh.log;

	if (log->type->postsuspend && log->type->postsuspend(log))
		/* FIXME: need better error handling */
		DMWARN("log postsuspend failed");
}

static void mirror_resume(struct dm_target *ti)
{
	struct mirror_set *ms = (struct mirror_set *) ti->private;
	struct dirty_log *log = ms->rh.log;

	atomic_set(&ms->suspend, 0);
	if (log->type->resume && log->type->resume(log))
		/* FIXME: need better error handling */
		DMWARN("log resume failed");
	rh_start_recovery(&ms->rh);
}

static int mirror_status(struct dm_target *ti, status_type_t type,
			 char *result, unsigned int maxlen)
{
	unsigned int m, sz = 0;
	struct mirror_set *ms = (struct mirror_set *) ti->private;
	char buffer[ms->nr_mirrors + 1];

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%d ", ms->nr_mirrors);
		for (m = 0; m < ms->nr_mirrors; m++) {
			DMEMIT("%s ", ms->mirror[m].dev->name);
			buffer[m] = atomic_read(&(ms->mirror[m].error_count)) ?
				'D' : 'A';
		}
		buffer[m] = '\0';

		DMEMIT("%llu/%llu 1 %s ",
		       ms->rh.log->type->get_sync_count(ms->rh.log),
		       ms->nr_regions, buffer);
		ms->rh.log->type->status(ms->rh.log, type, result+sz, maxlen-sz);
		break;

	case STATUSTYPE_TABLE:
		sz = ms->rh.log->type->status(ms->rh.log, type, result, maxlen);
		DMEMIT("%d", ms->nr_mirrors);
		for (m = 0; m < ms->nr_mirrors; m++)
			DMEMIT(" %s %llu", ms->mirror[m].dev->name,
				(unsigned long long)ms->mirror[m].offset);
	}

	return 0;
}

static struct target_type mirror_target = {
	.name	 = "mirror",
	.version = {1, 2, 0},
	.module	 = THIS_MODULE,
	.ctr	 = mirror_ctr,
	.dtr	 = mirror_dtr,
	.map	 = mirror_map,
	.end_io	 = mirror_end_io,
	.presuspend = mirror_presuspend,
	.postsuspend = mirror_postsuspend,
	.resume	 = mirror_resume,
	.status	 = mirror_status,
};

static int __init dm_mirror_init(void)
{
	int r;

	bio_map_info_pool = mempool_create(100, bio_map_info_alloc,
					   bio_map_info_free, NULL);
	if (!bio_map_info_pool)
		return -ENOMEM;

	r = dm_dirty_log_init();
	if (r)
		return r;

	r = dm_register_target(&mirror_target);
	if (r < 0) {
		DMERR("%s: Failed to register mirror target",
		      mirror_target.name);
		dm_dirty_log_exit();
	}

	return r;
}

static void __exit dm_mirror_exit(void)
{
	int r;

	r = dm_unregister_target(&mirror_target);
	if (r < 0)
		DMERR("%s: unregister failed %d", mirror_target.name, r);

	dm_dirty_log_exit();
}

/* Module hooks */
module_init(dm_mirror_init);
module_exit(dm_mirror_exit);

MODULE_DESCRIPTION(DM_NAME " mirror target");
MODULE_AUTHOR("Joe Thornber");
MODULE_LICENSE("GPL");
