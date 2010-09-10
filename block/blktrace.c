/*
 * Copyright (C) 2006 Jens Axboe <axboe@suse.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/blktrace_api.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/debugfs.h>
#include <trace/block.h>
#include <asm/uaccess.h>

static DEFINE_PER_CPU(unsigned long long, blk_trace_cpu_offset) = { 0, };
static unsigned int blktrace_seq __read_mostly = 1;

/* Global reference count of probes */
static DEFINE_MUTEX(blk_probe_mutex);
static atomic_t blk_probes_ref = ATOMIC_INIT(0);

static int blk_register_tracepoints(void);
static void blk_unregister_tracepoints(void);

/*
 * Send out a notify for this process, if we haven't done so since a trace
 * started
 */
static void trace_note_tsk(struct blk_trace *bt, struct task_struct *tsk)
{
	struct blk_io_trace *t;

	t = relay_reserve(bt->rchan, sizeof(*t) + sizeof(tsk->comm));
	if (t) {
		t->magic = BLK_IO_TRACE_MAGIC | BLK_IO_TRACE_VERSION;
		t->device = bt->dev;
		t->action = BLK_TC_ACT(BLK_TC_NOTIFY);
		t->pid = tsk->pid;
		t->cpu = smp_processor_id();
		t->pdu_len = sizeof(tsk->comm);
		memcpy((void *) t + sizeof(*t), tsk->comm, t->pdu_len);
		tsk->btrace_seq = blktrace_seq;
	}
}

static int act_log_check(struct blk_trace *bt, u32 what, sector_t sector,
			 pid_t pid)
{
	if (((bt->act_mask << BLK_TC_SHIFT) & what) == 0)
		return 1;
	if (sector < bt->start_lba || sector > bt->end_lba)
		return 1;
	if (bt->pid && pid != bt->pid)
		return 1;

	return 0;
}

/*
 * Data direction bit lookup
 */
static u32 ddir_act[2] __read_mostly = { BLK_TC_ACT(BLK_TC_READ), BLK_TC_ACT(BLK_TC_WRITE) };

/*
 * Bio action bits of interest
 */
static u32 bio_act[5] __read_mostly = { 0, BLK_TC_ACT(BLK_TC_BARRIER), BLK_TC_ACT(BLK_TC_SYNC), 0, BLK_TC_ACT(BLK_TC_AHEAD) };

/*
 * More could be added as needed, taking care to increment the decrementer
 * to get correct indexing
 */
#define trace_barrier_bit(rw)	\
	(((rw) & (1 << BIO_RW_BARRIER)) >> (BIO_RW_BARRIER - 0))
#define trace_sync_bit(rw)	\
	(((rw) & (1 << BIO_RW_SYNC)) >> (BIO_RW_SYNC - 1))
#define trace_ahead_bit(rw)	\
	(((rw) & (1 << BIO_RW_AHEAD)) << (2 - BIO_RW_AHEAD))

/*
 * The worker for the various blk_add_trace*() types. Fills out a
 * blk_io_trace structure and places it in a per-cpu subbuffer.
 */
void __blk_add_trace(struct blk_trace *bt, sector_t sector, int bytes,
		     int rw, u32 what, int error, int pdu_len, void *pdu_data)
{
	struct task_struct *tsk = current;
	struct blk_io_trace *t;
	unsigned long flags;
	unsigned long *sequence;
	pid_t pid;
	int cpu;

	if (unlikely(bt->trace_state != Blktrace_running))
		return;

	what |= ddir_act[rw & WRITE];
	what |= bio_act[trace_barrier_bit(rw)];
	what |= bio_act[trace_sync_bit(rw)];
	what |= bio_act[trace_ahead_bit(rw)];

	pid = tsk->pid;
	if (unlikely(act_log_check(bt, what, sector, pid)))
		return;

	/*
	 * A word about the locking here - we disable interrupts to reserve
	 * some space in the relay per-cpu buffer, to prevent an irq
	 * from coming in and stepping on our toes. Once reserved, it's
	 * enough to get preemption disabled to prevent read of this data
	 * before we are through filling it. get_cpu()/put_cpu() does this
	 * for us
	 */
	local_irq_save(flags);

	if (unlikely(tsk->btrace_seq != blktrace_seq))
		trace_note_tsk(bt, tsk);

	t = relay_reserve(bt->rchan, sizeof(*t) + pdu_len);
	if (t) {
		cpu = smp_processor_id();
		sequence = per_cpu_ptr(bt->sequence, cpu);

		t->magic = BLK_IO_TRACE_MAGIC | BLK_IO_TRACE_VERSION;
		t->sequence = ++(*sequence);
		t->time = sched_clock() - per_cpu(blk_trace_cpu_offset, cpu);
		t->sector = sector;
		t->bytes = bytes;
		t->action = what;
		t->pid = pid;
		t->device = bt->dev;
		t->cpu = cpu;
		t->error = error;
		t->pdu_len = pdu_len;

		if (pdu_len)
			memcpy((void *) t + sizeof(*t), pdu_data, pdu_len);
	}

	local_irq_restore(flags);
}

EXPORT_SYMBOL_GPL(__blk_add_trace);

static struct dentry *blk_tree_root;
static struct mutex blk_tree_mutex;
static unsigned int root_users;

static inline void blk_remove_root(void)
{
	if (blk_tree_root) {
		debugfs_remove(blk_tree_root);
		blk_tree_root = NULL;
	}
}

static void blk_remove_tree(struct dentry *dir)
{
	mutex_lock(&blk_tree_mutex);
	debugfs_remove(dir);
	if (--root_users == 0)
		blk_remove_root();
	mutex_unlock(&blk_tree_mutex);
}

static struct dentry *blk_create_tree(const char *blk_name)
{
	struct dentry *dir = NULL;
	int created = 0;

	mutex_lock(&blk_tree_mutex);

	if (!blk_tree_root) {
		blk_tree_root = debugfs_create_dir("block", NULL);
		if (!blk_tree_root)
			goto err;
		created = 1;
	}

	dir = debugfs_create_dir(blk_name, blk_tree_root);
	if (dir)
		root_users++;
	else {
		/* Delete root only if we created it */
		if (created)
			blk_remove_root();
	}

err:
	mutex_unlock(&blk_tree_mutex);
	return dir;
}

static void blk_trace_cleanup(struct blk_trace *bt)
{
	relay_close(bt->rchan);
	debugfs_remove(bt->dropped_file);
	blk_remove_tree(bt->dir);
	free_percpu(bt->sequence);
	kfree(bt);
	mutex_lock(&blk_probe_mutex);
	if (atomic_dec_and_test(&blk_probes_ref))
		blk_unregister_tracepoints();
	mutex_unlock(&blk_probe_mutex);
}

int blk_trace_remove(request_queue_t *q)
{
	struct blk_trace *bt;

	bt = xchg(&q->blk_trace, NULL);
	if (!bt)
		return -EINVAL;

	if (bt->trace_state == Blktrace_setup ||
	    bt->trace_state == Blktrace_stopped)
		blk_trace_cleanup(bt);

	return 0;
}
EXPORT_SYMBOL_GPL(blk_trace_remove);

static int blk_dropped_open(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;

	return 0;
}

static ssize_t blk_dropped_read(struct file *filp, char __user *buffer,
				size_t count, loff_t *ppos)
{
	struct blk_trace *bt = filp->private_data;
	char buf[16];

	snprintf(buf, sizeof(buf), "%u\n", atomic_read(&bt->dropped));

	return simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));
}

static struct file_operations blk_dropped_fops = {
	.owner =	THIS_MODULE,
	.open =		blk_dropped_open,
	.read =		blk_dropped_read,
};

/*
 * Keep track of how many times we encountered a full subbuffer, to aid
 * the user space app in telling how many lost events there were.
 */
static int blk_subbuf_start_callback(struct rchan_buf *buf, void *subbuf,
				     void *prev_subbuf, size_t prev_padding)
{
	struct blk_trace *bt;

	if (!relay_buf_full(buf))
		return 1;

	bt = buf->chan->private_data;
	atomic_inc(&bt->dropped);
	return 0;
}

static int blk_remove_buf_file_callback(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}

static struct dentry *blk_create_buf_file_callback(const char *filename,
						   struct dentry *parent,
						   int mode,
						   struct rchan_buf *buf,
						   int *is_global)
{
	return debugfs_create_file(filename, mode, parent, buf,
					&relay_file_operations);
}

static struct rchan_callbacks blk_relay_callbacks = {
	.subbuf_start		= blk_subbuf_start_callback,
	.create_buf_file	= blk_create_buf_file_callback,
	.remove_buf_file	= blk_remove_buf_file_callback,
};

/*
 * Setup everything required to start tracing
 */
int blk_trace_setup(request_queue_t *q, char *name, dev_t dev,
			   char __user *arg)
{
	struct blk_user_trace_setup buts;
	struct blk_trace *old_bt, *bt = NULL;
	struct dentry *dir = NULL;
	int ret, i;

	if (copy_from_user(&buts, arg, sizeof(buts)))
		return -EFAULT;

	if (!buts.buf_size || !buts.buf_nr)
		return -EINVAL;

	strcpy(buts.name, name);

	/*
	 * some device names have larger paths - convert the slashes
	 * to underscores for this to work as expected
	 */
	for (i = 0; i < strlen(buts.name); i++)
		if (buts.name[i] == '/')
			buts.name[i] = '_';

	if (copy_to_user(arg, &buts, sizeof(buts)))
		return -EFAULT;

	ret = -ENOMEM;
	bt = kzalloc(sizeof(*bt), GFP_KERNEL);
	if (!bt)
		goto err;

	bt->sequence = alloc_percpu(unsigned long);
	if (!bt->sequence)
		goto err;

	ret = -ENOENT;
	dir = blk_create_tree(buts.name);
	if (!dir)
		goto err;

	bt->dir = dir;
	bt->dev = dev;
	atomic_set(&bt->dropped, 0);

	ret = -EIO;
	bt->dropped_file = debugfs_create_file("dropped", 0444, dir, bt, &blk_dropped_fops);
	if (!bt->dropped_file)
		goto err;

	bt->rchan = relay_open("trace", dir, buts.buf_size, buts.buf_nr, &blk_relay_callbacks);
	if (!bt->rchan)
		goto err;
	bt->rchan->private_data = bt;

	bt->act_mask = buts.act_mask;
	if (!bt->act_mask)
		bt->act_mask = (u16) -1;

	bt->start_lba = buts.start_lba;
	bt->end_lba = buts.end_lba;
	if (!bt->end_lba)
		bt->end_lba = -1ULL;

	bt->pid = buts.pid;
	bt->trace_state = Blktrace_setup;

	ret = 0;
	mutex_lock(&blk_probe_mutex);
	if (atomic_add_return(1, &blk_probes_ref) == 1)
		ret = blk_register_tracepoints();
	mutex_unlock(&blk_probe_mutex);
	if (ret != 0)
		goto err;

	ret = -EBUSY;
	old_bt = xchg(&q->blk_trace, bt);
	if (old_bt) {
		(void) xchg(&q->blk_trace, old_bt);
		goto err_unregister_tracepoints;
	}

	return 0;

err_unregister_tracepoints:
	mutex_lock(&blk_probe_mutex);
	if (atomic_dec_and_test(&blk_probes_ref))
		blk_unregister_tracepoints();
	mutex_unlock(&blk_probe_mutex);
err:
	if (dir)
		blk_remove_tree(dir);
	if (bt) {
		if (bt->dropped_file)
			debugfs_remove(bt->dropped_file);
		if (bt->sequence)
			free_percpu(bt->sequence);
		if (bt->rchan)
			relay_close(bt->rchan);
		kfree(bt);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(blk_trace_setup);

int blk_trace_startstop(request_queue_t *q, int start)
{
	struct blk_trace *bt;
	int ret;

	if ((bt = q->blk_trace) == NULL)
		return -EINVAL;

	/*
	 * For starting a trace, we can transition from a setup or stopped
	 * trace. For stopping a trace, the state must be running
	 */
	ret = -EINVAL;
	if (start) {
		if (bt->trace_state == Blktrace_setup ||
		    bt->trace_state == Blktrace_stopped) {
			blktrace_seq++;
			smp_mb();
			bt->trace_state = Blktrace_running;
			ret = 0;
		}
	} else {
		if (bt->trace_state == Blktrace_running) {
			bt->trace_state = Blktrace_stopped;
			relay_flush(bt->rchan);
			ret = 0;
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(blk_trace_startstop);

/**
 * blk_trace_ioctl: - handle the ioctls associated with tracing
 * @bdev:	the block device
 * @cmd: 	the ioctl cmd
 * @arg:	the argument data, if any
 *
 **/
int blk_trace_ioctl(struct block_device *bdev, unsigned cmd, char __user *arg)
{
	request_queue_t *q;
	int ret, start = 0;
	char b[BDEVNAME_SIZE];

	q = bdev_get_queue(bdev);
	if (!q)
		return -ENXIO;

	mutex_lock(&bdev->bd_mutex);

	switch (cmd) {
	case BLKTRACESETUP:
		strcpy(b, bdevname(bdev, b));
		ret = blk_trace_setup(q, b, bdev->bd_dev, arg);
		break;
	case BLKTRACESTART:
		start = 1;
	case BLKTRACESTOP:
		ret = blk_trace_startstop(q, start);
		break;
	case BLKTRACETEARDOWN:
		ret = blk_trace_remove(q);
		break;
	default:
		ret = -ENOTTY;
		break;
	}

	mutex_unlock(&bdev->bd_mutex);
	return ret;
}

/**
 * blk_trace_shutdown: - stop and cleanup trace structures
 * @q:    the request queue associated with the device
 *
 **/
void blk_trace_shutdown(request_queue_t *q)
{
	blk_trace_startstop(q, 0);
	blk_trace_remove(q);
}

/*
 * Average offset over two calls to sched_clock() with a gettimeofday()
 * in the middle
 */
static void blk_check_time(unsigned long long *t)
{
	unsigned long long a, b;
	struct timeval tv;

	a = sched_clock();
	do_gettimeofday(&tv);
	b = sched_clock();

	*t = tv.tv_sec * 1000000000 + tv.tv_usec * 1000;
	*t -= (a + b) / 2;
}

static void blk_trace_check_cpu_time(void *data)
{
	unsigned long long *t;
	int cpu = get_cpu();

	t = &per_cpu(blk_trace_cpu_offset, cpu);

	/*
	 * Just call it twice, hopefully the second call will be cache hot
	 * and a little more precise
	 */
	blk_check_time(t);
	blk_check_time(t);

	put_cpu();
}

/*
 * Call blk_trace_check_cpu_time() on each CPU to calibrate our inter-CPU
 * timings
 */
static void blk_trace_calibrate_offsets(void)
{
	unsigned long flags;

	smp_call_function(blk_trace_check_cpu_time, NULL, 1, 1);
	local_irq_save(flags);
	blk_trace_check_cpu_time(NULL);
	local_irq_restore(flags);
}

static void blk_trace_set_ht_offsets(void)
{
#if defined(CONFIG_SCHED_SMT)
	int cpu, i;

	/*
	 * now make sure HT siblings have the same time offset
	 */
	preempt_disable();
	for_each_online_cpu(cpu) {
		unsigned long long *cpu_off, *sibling_off;

		for_each_cpu_mask(i, cpu_sibling_map[cpu]) {
			if (i == cpu)
				continue;

			cpu_off = &per_cpu(blk_trace_cpu_offset, cpu);
			sibling_off = &per_cpu(blk_trace_cpu_offset, i);
			*sibling_off = *cpu_off;
		}
	}
	preempt_enable();
#endif
}

static __init int blk_trace_init(void)
{
	mutex_init(&blk_tree_mutex);
	blk_trace_calibrate_offsets();
	blk_trace_set_ht_offsets();

	return 0;
}

module_init(blk_trace_init);

/*
 * blktrace probes
 */

/**
 * __blk_add_trace_rq - Add a trace for a request oriented action
 * @q:		queue the io is for
 * @rq:		the source request
 * @what:	the action
 *
 * Description:
 *     Records an action against a request. Will log the bio offset + size.
 *
 **/
static void __blk_add_trace_rq(struct request_queue *q, struct request *rq,
			       u32 what)
{
	struct blk_trace *bt = q->blk_trace;
	int rw = rq->flags & 0x03;

	if (likely(!bt))
		return;

	if (blk_pc_request(rq)) {
		what |= BLK_TC_ACT(BLK_TC_PC);
		__blk_add_trace(bt, 0, rq->data_len, rw, what, rq->errors,
				sizeof(rq->cmd), rq->cmd);
	} else  {
		what |= BLK_TC_ACT(BLK_TC_FS);
		__blk_add_trace(bt, rq->hard_sector, rq->hard_nr_sectors << 9,
				rw, what, rq->errors, 0, NULL);
	}
}

static void blk_add_trace_rq_insert(struct request_queue *q, struct request *rq)
{
	__blk_add_trace_rq(q, rq, BLK_TA_INSERT);
}

static void blk_add_trace_rq_issue(struct request_queue *q, struct request *rq)
{
	__blk_add_trace_rq(q, rq, BLK_TA_ISSUE);
}

static void blk_add_trace_rq_requeue(struct request_queue *q, struct request *rq)
{
	__blk_add_trace_rq(q, rq, BLK_TA_REQUEUE);
}

static void blk_add_trace_rq_complete(struct request_queue *q, struct request *rq)
{
	__blk_add_trace_rq(q, rq, BLK_TA_COMPLETE);
}

#define WARN_MISSING_TRACEPOINT(what) do { \
	static char warnings_about_missing_tracepoints; \
	if (warnings_about_missing_tracepoints < 10) { \
		printk(KERN_WARNING "%s: no tracepoint for %d", \
		       __func__, what); \
	       ++warnings_about_missing_tracepoints; \
	} \
} while (0);

void blk_add_trace_rq(struct request_queue *q, struct request *rq, u32 what)
{
	/*
	 * We redirect here to the upstream tracepoints so that we can
	 * catch these events while keeping the blk_add_trace_rq
	 * function for 3rd party drivers. Warn about newer actions
	 * but push them into the relay channel for the benefit of 
	 * blktrace(8) users.
	 */
	switch (what) {
	case BLK_TA_INSERT:	trace_block_rq_insert(q, rq);	break;
	case BLK_TA_ISSUE:	trace_block_rq_issue(q, rq);	break;
	case BLK_TA_REQUEUE:	trace_block_rq_requeue(q, rq);	break;
	case BLK_TA_COMPLETE:	trace_block_rq_complete(q, rq);	break;
	default: {
		struct blk_trace *bt = q->blk_trace;

		WARN_MISSING_TRACEPOINT(what);

		if (likely(!bt))
			return;

		__blk_add_trace_rq(q, rq, what);
	}
		break;
	}
}

EXPORT_SYMBOL_GPL(blk_add_trace_rq);

/**
 * __blk_add_trace_bio - Add a trace for a bio oriented action
 * @q:		queue the io is for
 * @bio:	the source bio
 * @what:	the action
 *
 * Description:
 *     Records an action against a bio. Will log the bio offset + size.
 *
 **/
static void __blk_add_trace_bio(struct request_queue *q, struct bio *bio, u32 what)
{
	struct blk_trace *bt = q->blk_trace;

	if (likely(!bt))
		return;

	__blk_add_trace(bt, bio->bi_sector, bio->bi_size, bio->bi_rw, what,
			!bio_flagged(bio, BIO_UPTODATE), 0, NULL);
}

static void blk_add_trace_bio_bounce(struct request_queue *q, struct bio *bio)
{
	__blk_add_trace_bio(q, bio, BLK_TA_BOUNCE);
}

static void blk_add_trace_bio_complete(struct request_queue *q, struct bio *bio)
{
	__blk_add_trace_bio(q, bio, BLK_TA_COMPLETE);
}

static void blk_add_trace_bio_backmerge(struct request_queue *q, struct bio *bio)
{
	__blk_add_trace_bio(q, bio, BLK_TA_BACKMERGE);
}

static void blk_add_trace_bio_frontmerge(struct request_queue *q, struct bio *bio)
{
	__blk_add_trace_bio(q, bio, BLK_TA_FRONTMERGE);
}

static void blk_add_trace_bio_queue(struct request_queue *q, struct bio *bio)
{
	__blk_add_trace_bio(q, bio, BLK_TA_QUEUE);
}

static void blk_add_trace_getrq(struct request_queue *q, struct bio *bio, int rw)
{
	if (bio)
		__blk_add_trace_bio(q, bio, BLK_TA_GETRQ);
	else {
		struct blk_trace *bt = q->blk_trace;

		if (bt)
			__blk_add_trace(bt, 0, 0, rw, BLK_TA_GETRQ, 0, 0, NULL);
	}
}


static void blk_add_trace_sleeprq(struct request_queue *q, struct bio *bio, int rw)
{
	if (bio)
		__blk_add_trace_bio(q, bio, BLK_TA_SLEEPRQ);
	else {
		struct blk_trace *bt = q->blk_trace;

		if (bt)
			__blk_add_trace(bt, 0, 0, rw, BLK_TA_SLEEPRQ, 0, 0, NULL);
	}
}

static void blk_add_trace_plug(struct request_queue *q)
{
	struct blk_trace *bt = q->blk_trace;

	if (bt)
		__blk_add_trace(bt, 0, 0, 0, BLK_TA_PLUG, 0, 0, NULL);
}

static void blk_add_trace_unplug_io(struct request_queue *q)
{
	struct blk_trace *bt = q->blk_trace;

	if (bt) {
		unsigned int pdu = q->rq.count[READ] + q->rq.count[WRITE];
		__be64 rpdu = cpu_to_be64(pdu);

		__blk_add_trace(bt, 0, 0, 0, BLK_TA_UNPLUG_IO, 0,
				sizeof(rpdu), &rpdu);
	}
}

static void blk_add_trace_unplug_timer(struct request_queue *q)
{
	struct blk_trace *bt = q->blk_trace;

	if (bt) {
		unsigned int pdu = q->rq.count[READ] + q->rq.count[WRITE];
		__be64 rpdu = cpu_to_be64(pdu);

		__blk_add_trace(bt, 0, 0, 0, BLK_TA_UNPLUG_TIMER, 0,
				sizeof(rpdu), &rpdu);
	}
}

static void blk_add_trace_split(struct request_queue *q, struct bio *bio,
				unsigned int pdu)
{
	struct blk_trace *bt = q->blk_trace;

	if (bt) {
		__be64 rpdu = cpu_to_be64(pdu);

		__blk_add_trace(bt, bio->bi_sector, bio->bi_size, bio->bi_rw,
				BLK_TA_SPLIT, !bio_flagged(bio, BIO_UPTODATE),
				sizeof(rpdu), &rpdu);
	}
}

/**
 * __blk_add_trace_remap - Add a trace for a remap operation
 * @q:		queue the io is for
 * @bio:	the source bio
 * @dev:	target device
 * @from:	source sector
 * @to:		target sector
 *
 * Description:
 *     Device mapper or raid target sometimes need to split a bio because
 *     it spans a stripe (or similar). Add a trace for that action.
 *
 **/
void blk_add_trace_remap(struct request_queue *q, struct bio *bio,
				dev_t dev, sector_t from, sector_t to)
{
	struct blk_trace *bt = q->blk_trace;
	struct blk_io_trace_remap r;

	if (likely(!bt))
		return;

	r.device_from = cpu_to_be32(dev);
	r.device_to = cpu_to_be32(bio->bi_bdev->bd_dev);
	r.sector = cpu_to_be64(to);

	__blk_add_trace(bt, from, bio->bi_size, bio->bi_rw, BLK_TA_REMAP,
			!bio_flagged(bio, BIO_UPTODATE), sizeof(r), &r);
}

EXPORT_SYMBOL_GPL(blk_add_trace_remap);

void blk_add_trace_bio(struct request_queue *q, struct bio *bio, u32 what)
{
	/*
	 * We redirect here to the upstream tracepoints so that we can
	 * catch these events while keeping the blk_add_trace_bio
	 * function for 3rd party drivers. Warn about newer actions
	 * but push them into the relay channel for the benefit of 
	 * blktrace(8) users.
	 */
	switch (what) {
	case BLK_TA_BACKMERGE:	trace_block_bio_backmerge(q, bio);  break;
	case BLK_TA_FRONTMERGE:	trace_block_bio_frontmerge(q, bio); break;
	case BLK_TA_QUEUE:	trace_block_bio_queue(q, bio);	    break;
	case BLK_TA_COMPLETE:	trace_block_bio_complete(q, bio);   break;
	case BLK_TA_BOUNCE:	trace_block_bio_bounce(q, bio);	    break;
	default: {
		struct blk_trace *bt = q->blk_trace;

		WARN_MISSING_TRACEPOINT(what);

		if (likely(!bt))
			return;

		__blk_add_trace_bio(q, bio, what);
	}
		break;
	}
}

EXPORT_SYMBOL_GPL(blk_add_trace_bio);

/**
 * blk_add_trace_generic - Add a trace for a generic action
 * @q:		queue the io is for
 * @bio:	the source bio
 * @rw:		the data direction
 * @what:	the action
 *
 * Description:
 *     Records a simple trace
 *
 **/
void blk_add_trace_generic(struct request_queue *q, struct bio *bio,
			   int rw, u32 what)
{
	/*
	 * We redirect here to the upstream tracepoints so that we can
	 * catch these events while keeping the blk_add_trace_generic
	 * function for 3rd party drivers. Warn about newer actions
	 * but push them into the relay channel for the benefit of 
	 * blktrace(8) users.
	 */
	switch (what) {
	case BLK_TA_PLUG:    trace_block_plug(q);	      break;
	case BLK_TA_GETRQ:   trace_block_getrq(q, bio, rw);   break;
	case BLK_TA_SLEEPRQ: trace_block_sleeprq(q, bio, rw); break;
	default: {
		struct blk_trace *bt = q->blk_trace;

		WARN_MISSING_TRACEPOINT(what);

		if (likely(!bt))
			return;

		if (bio)
			__blk_add_trace_bio(q, bio, what);
		else
			__blk_add_trace(bt, 0, 0, rw, what, 0, 0, NULL);
	}
		break;
	}
}

EXPORT_SYMBOL_GPL(blk_add_trace_generic);

/**
 * blk_add_trace_pdu_int - Add a trace for a bio with an integer payload
 * @q:		queue the io is for
 * @what:	the action
 * @bio:	the source bio
 * @pdu:	the integer payload
 *
 * Description:
 *     Adds a trace with some integer payload. This might be an unplug
 *     option given as the action, with the depth at unplug time given
 *     as the payload
 *
 **/
void blk_add_trace_pdu_int(struct request_queue *q, u32 what,
			   struct bio *bio, unsigned int pdu)
{
	/*
	 * We redirect here to the upstream tracepoints so that we can
	 * catch these events while keeping the blk_add_trace_pdu_int
	 * function for 3rd party drivers. Warn about newer actions
	 * but push them into the relay channel for the benefit of 
	 * blktrace(8) users.
	 */
	switch (what) {
	case BLK_TA_UNPLUG_IO:	  trace_block_unplug_io(q);	  break;
	case BLK_TA_UNPLUG_TIMER: trace_block_unplug_timer(q);	  break;
	case BLK_TA_SPLIT:	  trace_block_split(q, bio, pdu); break;
	default: {
		struct blk_trace *bt = q->blk_trace;
		__be64 rpdu = cpu_to_be64(pdu);

		WARN_MISSING_TRACEPOINT(what);

		if (likely(!bt))
			return;

		if (bio)
			__blk_add_trace(bt, bio->bi_sector, bio->bi_size,
					bio->bi_rw, what,
					!bio_flagged(bio, BIO_UPTODATE),
					sizeof(rpdu), &rpdu);
		else
			__blk_add_trace(bt, 0, 0, 0, what, 0, sizeof(rpdu),
					&rpdu);
	}
		break;
	}
}

EXPORT_SYMBOL_GPL(blk_add_trace_pdu_int);

#define last_register_trace_block(tpoint)				\
	ret = register_trace_block_##tpoint(blk_add_trace_##tpoint);	\
	if (ret) {							\
               pr_info("blktrace: register_trace_block_%s failed\n",	\
			#tpoint);					\
               goto *exit_point;					\
	}

#define register_trace_block(tpoint)					\
	last_register_trace_block(tpoint) 				\
	else exit_point = &&fail_unregister_probe_##tpoint;

#define fail_trace_block(tpoint)					\
	fail_unregister_probe_##tpoint:					\
               unregister_trace_block_##tpoint(blk_add_trace_##tpoint)


static int blk_register_tracepoints(void)
{
	int ret;
	void *exit_point = &&error;

	register_trace_block(bio_bounce);
	register_trace_block(bio_complete);
	register_trace_block(bio_backmerge);
	register_trace_block(bio_frontmerge);
	register_trace_block(bio_queue);
	register_trace_block(rq_insert);
	register_trace_block(rq_issue);
	register_trace_block(rq_requeue);
	register_trace_block(rq_complete);
	register_trace_block(getrq);
	register_trace_block(sleeprq);
	register_trace_block(plug);
	register_trace_block(unplug_timer);
	register_trace_block(unplug_io);
	register_trace_block(split);
	last_register_trace_block(remap);

	return 0;

	fail_trace_block(split);
	fail_trace_block(unplug_io);
	fail_trace_block(unplug_timer);
	fail_trace_block(plug);
	fail_trace_block(sleeprq);
	fail_trace_block(getrq);
	fail_trace_block(rq_complete);
	fail_trace_block(rq_requeue);
	fail_trace_block(rq_issue);
	fail_trace_block(rq_insert);
	fail_trace_block(bio_queue);
	fail_trace_block(bio_frontmerge);
	fail_trace_block(bio_backmerge);
	fail_trace_block(bio_complete);
	fail_trace_block(bio_bounce);
error:
	return ret;
}

static void blk_unregister_tracepoints(void)
{
	unregister_trace_block_remap(blk_add_trace_remap);
	unregister_trace_block_split(blk_add_trace_split);
	unregister_trace_block_unplug_io(blk_add_trace_unplug_io);
	unregister_trace_block_unplug_timer(blk_add_trace_unplug_timer);
	unregister_trace_block_plug(blk_add_trace_plug);
	unregister_trace_block_sleeprq(blk_add_trace_sleeprq);
	unregister_trace_block_getrq(blk_add_trace_getrq);
	unregister_trace_block_bio_queue(blk_add_trace_bio_queue);
	unregister_trace_block_bio_frontmerge(blk_add_trace_bio_frontmerge);
	unregister_trace_block_bio_backmerge(blk_add_trace_bio_backmerge);
	unregister_trace_block_bio_complete(blk_add_trace_bio_complete);
	unregister_trace_block_bio_bounce(blk_add_trace_bio_bounce);
	unregister_trace_block_rq_complete(blk_add_trace_rq_complete);
	unregister_trace_block_rq_requeue(blk_add_trace_rq_requeue);
	unregister_trace_block_rq_issue(blk_add_trace_rq_issue);
	unregister_trace_block_rq_insert(blk_add_trace_rq_insert);
}
