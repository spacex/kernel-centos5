#ifndef BLKTRACE_H
#define BLKTRACE_H

#include <linux/blkdev.h>
#include <linux/relay.h>

/*
 * Trace categories
 */
enum blktrace_cat {
	BLK_TC_READ	= 1 << 0,	/* reads */
	BLK_TC_WRITE	= 1 << 1,	/* writes */
	BLK_TC_BARRIER	= 1 << 2,	/* barrier */
	BLK_TC_SYNC	= 1 << 3,	/* sync IO */
	BLK_TC_QUEUE	= 1 << 4,	/* queueing/merging */
	BLK_TC_REQUEUE	= 1 << 5,	/* requeueing */
	BLK_TC_ISSUE	= 1 << 6,	/* issue */
	BLK_TC_COMPLETE	= 1 << 7,	/* completions */
	BLK_TC_FS	= 1 << 8,	/* fs requests */
	BLK_TC_PC	= 1 << 9,	/* pc requests */
	BLK_TC_NOTIFY	= 1 << 10,	/* special message */
	BLK_TC_AHEAD	= 1 << 11,	/* readahead */
	BLK_TC_DRV_DATA = 1 << 14,	/* binary per-driver data */

	BLK_TC_END	= 1 << 15,	/* only 16-bits, reminder */
};

#define BLK_TC_SHIFT		(16)
#define BLK_TC_ACT(act)		((act) << BLK_TC_SHIFT)

/*
 * Basic trace actions
 */
enum blktrace_act {
	__BLK_TA_QUEUE = 1,		/* queued */
	__BLK_TA_BACKMERGE,		/* back merged to existing rq */
	__BLK_TA_FRONTMERGE,		/* front merge to existing rq */
	__BLK_TA_GETRQ,			/* allocated new request */
	__BLK_TA_SLEEPRQ,		/* sleeping on rq allocation */
	__BLK_TA_REQUEUE,		/* request requeued */
	__BLK_TA_ISSUE,			/* sent to driver */
	__BLK_TA_COMPLETE,		/* completed by driver */
	__BLK_TA_PLUG,			/* queue was plugged */
	__BLK_TA_UNPLUG_IO,		/* queue was unplugged by io */
	__BLK_TA_UNPLUG_TIMER,		/* queue was unplugged by timer */
	__BLK_TA_INSERT,		/* insert request */
	__BLK_TA_SPLIT,			/* bio was split */
	__BLK_TA_BOUNCE,		/* bio was bounced */
	__BLK_TA_REMAP,			/* bio was remapped */
	__BLK_TA_ABORT,			/* request aborted */
	__BLK_TA_DRV_DATA,		/* driver-specific binary data */
};

/*
 * Trace actions in full. Additionally, read or write is masked
 */
#define BLK_TA_QUEUE		(__BLK_TA_QUEUE | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_BACKMERGE	(__BLK_TA_BACKMERGE | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_FRONTMERGE	(__BLK_TA_FRONTMERGE | BLK_TC_ACT(BLK_TC_QUEUE))
#define	BLK_TA_GETRQ		(__BLK_TA_GETRQ | BLK_TC_ACT(BLK_TC_QUEUE))
#define	BLK_TA_SLEEPRQ		(__BLK_TA_SLEEPRQ | BLK_TC_ACT(BLK_TC_QUEUE))
#define	BLK_TA_REQUEUE		(__BLK_TA_REQUEUE | BLK_TC_ACT(BLK_TC_REQUEUE))
#define BLK_TA_ISSUE		(__BLK_TA_ISSUE | BLK_TC_ACT(BLK_TC_ISSUE))
#define BLK_TA_COMPLETE		(__BLK_TA_COMPLETE| BLK_TC_ACT(BLK_TC_COMPLETE))
#define BLK_TA_PLUG		(__BLK_TA_PLUG | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_UNPLUG_IO	(__BLK_TA_UNPLUG_IO | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_UNPLUG_TIMER	(__BLK_TA_UNPLUG_TIMER | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_INSERT		(__BLK_TA_INSERT | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_SPLIT		(__BLK_TA_SPLIT)
#define BLK_TA_BOUNCE		(__BLK_TA_BOUNCE)
#define BLK_TA_REMAP		(__BLK_TA_REMAP | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_DRV_DATA		(__BLK_TA_DRV_DATA | BLK_TC_ACT(BLK_TC_DRV_DATA))

#define BLK_IO_TRACE_MAGIC	0x65617400
#define BLK_IO_TRACE_VERSION	0x07

/*
 * The trace itself
 */
struct blk_io_trace {
	u32 magic;		/* MAGIC << 8 | version */
	u32 sequence;		/* event number */
	u64 time;		/* in microseconds */
	u64 sector;		/* disk offset */
	u32 bytes;		/* transfer length */
	u32 action;		/* what happened */
	u32 pid;		/* who did it */
	u32 device;		/* device number */
	u32 cpu;		/* on what cpu did it happen */
	u16 error;		/* completion error */
	u16 pdu_len;		/* length of data after this trace */
};

/*
 * The remap event
 */
struct blk_io_trace_remap {
	__be32 device_from;
	u32 device_to;
	__be64 sector;
};

enum {
	Blktrace_setup = 1,
	Blktrace_running,
	Blktrace_stopped,
};

struct blk_trace {
	int trace_state;
	struct rchan *rchan;
	unsigned long *sequence;
	u16 act_mask;
	u64 start_lba;
	u64 end_lba;
	u32 pid;
	u32 dev;
	struct dentry *dir;
	struct dentry *dropped_file;
	atomic_t dropped;
};

/*
 * User setup structure passed with BLKTRACESTART
 */
struct blk_user_trace_setup {
	char name[BDEVNAME_SIZE];	/* output */
	u16 act_mask;			/* input */
	u32 buf_size;			/* input */
	u32 buf_nr;			/* input */
	u64 start_lba;
	u64 end_lba;
	u32 pid;
};

#if defined(CONFIG_BLK_DEV_IO_TRACE)
#include <trace/block.h>

extern int blk_trace_ioctl(struct block_device *, unsigned, char __user *);
extern void blk_trace_shutdown(request_queue_t *);
extern void __blk_add_trace(struct blk_trace *, sector_t, int, int, u32, int, int, void *);
extern void blk_add_trace_rq(struct request_queue *q, struct request *rq,
			     u32 what);
extern void blk_add_trace_bio(struct request_queue *q, struct bio *bio,
			      u32 what);
extern void blk_add_trace_generic(struct request_queue *q,
				  struct bio *bio, int rw, u32 what);
extern void blk_add_trace_pdu_int(struct request_queue *q, u32 what,
				  struct bio *bio, unsigned int pdu);
extern void blk_add_trace_remap(struct request_queue *q, struct bio *bio,
				dev_t dev, sector_t from, sector_t to);

/**
 * blk_add_driver_data - Add binary message with driver-specific data
 * @q:		queue the io is for
 * @rq:		io request
 * @data:	driver-specific data
 * @len:	length of driver-specific data
 *
 * Description:
 *     Some drivers might want to write driver-specific data per request.
 *
 **/
static inline void blk_add_driver_data(struct request_queue *q,
				       struct request *rq,
				       void *data, size_t len)
{
	struct blk_trace *bt = q->blk_trace;

	if (likely(!bt))
		return;

	if (blk_pc_request(rq))
		__blk_add_trace(bt, 0, rq->data_len, 0, BLK_TA_DRV_DATA,
				rq->errors, len, data);
	else
		__blk_add_trace(bt, rq->hard_sector, rq->hard_nr_sectors << 9,
				0, BLK_TA_DRV_DATA, rq->errors, len, data);
}

extern int blk_trace_setup(request_queue_t *q, char *name, dev_t dev,
			   char __user *arg);
extern int blk_trace_startstop(request_queue_t *q, int start);
extern int blk_trace_remove(request_queue_t *q);

#else /* !CONFIG_BLK_DEV_IO_TRACE */
#define blk_trace_ioctl(bdev, cmd, arg)		(-ENOTTY)
#define blk_trace_shutdown(q)			do { } while (0)
#define blk_add_trace_rq(q, rq, what)		do { } while (0)
#define blk_add_trace_bio(q, rq, what)		do { } while (0)
#define blk_add_trace_generic(q, rq, rw, what)	do { } while (0)
#define blk_add_trace_pdu_int(q, what, bio, pdu)	do { } while (0)
#define blk_add_trace_remap(q, bio, dev, f, t)	do {} while (0)
#define do_blk_trace_setup(q, name, dev, buts)	(-ENOTTY)
#define blk_trace_setup(q, name, dev, arg)	(-ENOTTY)
#define blk_trace_startstop(q, start)		(-ENOTTY)
#define blk_trace_remove(q)			(-ENOTTY)
#define blk_add_driver_data(q, rq, data, len)  do {} while (0)
#endif /* CONFIG_BLK_DEV_IO_TRACE */

#endif
