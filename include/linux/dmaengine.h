/*
 * Copyright(c) 2004 - 2006 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * The full GNU General Public License is included in this distribution in the
 * file called COPYING.
 */
#ifndef DMAENGINE_H
#define DMAENGINE_H

#if defined(CONFIG_DMA_ENGINE_V3) || defined(CONFIG_DMA_ENGINE)

#include <linux/device.h>
#include <linux/uio.h>
#ifndef __GENKSYMS__
#include <linux/dma-mapping.h>
#endif


/**
 * enum dma_event - resource PNP/power managment events
 * @DMA_RESOURCE_SUSPEND: DMA device going into low power state
 * @DMA_RESOURCE_RESUME: DMA device returning to full power
 * @DMA_RESOURCE_ADDED: DMA device added to the system
 * @DMA_RESOURCE_REMOVED: DMA device removed from the system
 */
enum dma_event {
	DMA_RESOURCE_SUSPEND,
	DMA_RESOURCE_RESUME,
	DMA_RESOURCE_ADDED,
	DMA_RESOURCE_REMOVED,
};

/**
 * typedef dma_cookie_t - an opaque DMA cookie
 *
 * if dma_cookie_t is >0 it's a DMA request cookie, <0 it's an error code
 */
typedef s32 dma_cookie_t;

#define dma_submit_error(cookie) ((cookie) < 0 ? 1 : 0)

/**
 * enum dma_status - DMA transaction status
 * @DMA_SUCCESS: transaction completed successfully
 * @DMA_IN_PROGRESS: transaction not yet processed
 * @DMA_ERROR: transaction failed
 */
enum dma_status {
	DMA_SUCCESS,
	DMA_IN_PROGRESS,
	DMA_ERROR,
};

/**
 * struct dma_chan_percpu - the per-CPU part of struct dma_chan
 * @refcount: local_t used for open-coded "bigref" counting
 * @memcpy_count: transaction counter
 * @bytes_transferred: byte counter
 */

struct dma_chan_percpu {
	local_t refcount;
	/* stats */
	unsigned long memcpy_count;
	unsigned long bytes_transferred;
};

/**
 * struct dma_chan - devices supply DMA channels, clients use them
 * @client: ptr to the client user of this chan, will be %NULL when unused
 * @device: ptr to the dma device who supplies this channel, always !%NULL
 * @cookie: last cookie value returned to client
 * @chan_id: channel ID for sysfs
 * @class_dev: class device for sysfs
 * @refcount: kref, used in "bigref" slow-mode
 * @slow_ref: indicates that the DMA channel is free
 * @rcu: the DMA channel's RCU head
 * @client_node: used to add this to the client chan list
 * @device_node: used to add this to the device chan list
 * @local: per-cpu pointer to a struct dma_chan_percpu
 * @device_v3: pointer to dma_device version 3 structure
 * @client_count: how many clients are using this channel
 * @table_count: number of appearances in the mem-to-mem allocation table
 * @dev: class device for sysfs
 * @private: private data for certain client-channel associations
 */
struct dma_chan {
	struct dma_client *client;
	struct dma_device *device;
	dma_cookie_t cookie;

	/* sysfs */
	int chan_id;
	struct class_device class_dev;

	struct kref refcount;
	int slow_ref;
	struct rcu_head rcu;

	struct list_head client_node;
	struct list_head device_node;
	struct dma_chan_percpu *local;

#ifndef __GENKSYMS__
	struct dma_device_v3 *device_v3;
	int client_count;
	int table_count;
	struct dma_chan_dev *dev;
	void *private;
#endif
};

/**
 * struct dma_chan_dev - relate sysfs device node to backing channel device
 * @chan - driver channel device
 * @device - sysfs device
 * @dev_id - parent dma_device dev_id
 * @idr_ref - reference count to gate release of dma_device dev_id
 */
struct dma_chan_dev {
	struct dma_chan *chan;
	struct class_device class_dev;
	int dev_id;
	atomic_t *idr_ref;
};

void dma_chan_cleanup_v3(struct kref *kref);
void dma_chan_cleanup(struct kref *kref);

/*
 * typedef dma_event_callback - function pointer to a DMA event callback
 */
typedef void (*dma_event_callback) (struct dma_client *client,
		struct dma_chan *chan, enum dma_event event);

/**
 * struct dma_device - info on the entity supplying DMA services
 * @chancnt: how many DMA channels are supported
 * @channels: the list of struct dma_chan
 * @global_node: list_head for global dma_device_list
 * @refcount: reference count
 * @done: IO completion struct
 * @dev_id: unique device ID
 * @device_alloc_chan_resources: allocate resources and return the
 *	number of allocated descriptors
 * @device_free_chan_resources: release DMA channel's resources
 * @device_memcpy_buf_to_buf: memcpy buf pointer to buf pointer
 * @device_memcpy_buf_to_pg: memcpy buf pointer to struct page
 * @device_memcpy_pg_to_pg: memcpy struct page/offset to struct page/offset
 * @device_memcpy_complete: poll the status of an IOAT DMA transaction
 * @device_memcpy_issue_pending: push appended descriptors to hardware
 */
struct dma_device {

	unsigned int chancnt;
	struct list_head channels;
	struct list_head global_node;

	struct kref refcount;
	struct completion done;

	int dev_id;

	int (*device_alloc_chan_resources)(struct dma_chan *chan);
	void (*device_free_chan_resources)(struct dma_chan *chan);
	dma_cookie_t (*device_memcpy_buf_to_buf)(struct dma_chan *chan,
			void *dest, void *src, size_t len);
	dma_cookie_t (*device_memcpy_buf_to_pg)(struct dma_chan *chan,
			struct page *page, unsigned int offset, void *kdata,
			size_t len);
	dma_cookie_t (*device_memcpy_pg_to_pg)(struct dma_chan *chan,
			struct page *dest_pg, unsigned int dest_off,
			struct page *src_pg, unsigned int src_off, size_t len);
	enum dma_status (*device_memcpy_complete)(struct dma_chan *chan,
			dma_cookie_t cookie, dma_cookie_t *last,
			dma_cookie_t *used);
	void (*device_memcpy_issue_pending)(struct dma_chan *chan);
};

/* --- public DMA engine API --- */

struct dma_client *dma_async_client_register(dma_event_callback event_callback);
void dma_async_client_unregister(struct dma_client *client);
#ifdef CONFIG_DMA_ENGINE_V3
void dmaengine_get(void);
void dmaengine_put(void);
#else
static inline void dmaengine_get(void)
{
}
static inline void dmaengine_put(void)
{
}
#endif

void dma_async_client_chan_request(struct dma_client *client,
		unsigned int number);

/**
 * dma_async_memcpy_buf_to_buf - offloaded copy between virtual addresses
 * @chan: DMA channel to offload copy to
 * @dest: destination address (virtual)
 * @src: source address (virtual)
 * @len: length
 *
 * Both @dest and @src must be mappable to a bus address according to the
 * DMA mapping API rules for streaming mappings.
 * Both @dest and @src must stay memory resident (kernel memory or locked
 * user space pages).
 */
static inline dma_cookie_t dma_async_memcpy_buf_to_buf(struct dma_chan *chan,
	void *dest, void *src, size_t len)
{
	int cpu = get_cpu();
	per_cpu_ptr(chan->local, cpu)->bytes_transferred += len;
	per_cpu_ptr(chan->local, cpu)->memcpy_count++;
	put_cpu();

	return chan->device->device_memcpy_buf_to_buf(chan, dest, src, len);
}

/**
 * dma_async_memcpy_buf_to_pg - offloaded copy from address to page
 * @chan: DMA channel to offload copy to
 * @page: destination page
 * @offset: offset in page to copy to
 * @kdata: source address (virtual)
 * @len: length
 *
 * Both @page/@offset and @kdata must be mappable to a bus address according
 * to the DMA mapping API rules for streaming mappings.
 * Both @page/@offset and @kdata must stay memory resident (kernel memory or
 * locked user space pages)
 */
static inline dma_cookie_t dma_async_memcpy_buf_to_pg(struct dma_chan *chan,
	struct page *page, unsigned int offset, void *kdata, size_t len)
{
	int cpu = get_cpu();
	per_cpu_ptr(chan->local, cpu)->bytes_transferred += len;
	per_cpu_ptr(chan->local, cpu)->memcpy_count++;
	put_cpu();

	return chan->device->device_memcpy_buf_to_pg(chan, page, offset,
	                                             kdata, len);
}

/**
 * dma_async_memcpy_pg_to_pg - offloaded copy from page to page
 * @chan: DMA channel to offload copy to
 * @dest_pg: destination page
 * @dest_off: offset in page to copy to
 * @src_pg: source page
 * @src_off: offset in page to copy from
 * @len: length
 *
 * Both @dest_page/@dest_off and @src_page/@src_off must be mappable to a bus
 * address according to the DMA mapping API rules for streaming mappings.
 * Both @dest_page/@dest_off and @src_page/@src_off must stay memory resident
 * (kernel memory or locked user space pages).
 */
static inline dma_cookie_t dma_async_memcpy_pg_to_pg(struct dma_chan *chan,
	struct page *dest_pg, unsigned int dest_off, struct page *src_pg,
	unsigned int src_off, size_t len)
{
	int cpu = get_cpu();
	per_cpu_ptr(chan->local, cpu)->bytes_transferred += len;
	per_cpu_ptr(chan->local, cpu)->memcpy_count++;
	put_cpu();

	return chan->device->device_memcpy_pg_to_pg(chan, dest_pg, dest_off,
	                                            src_pg, src_off, len);
}

/**
 * dma_async_memcpy_issue_pending - flush pending copies to HW
 * @chan: target DMA channel
 *
 * This allows drivers to push copies to HW in batches,
 * reducing MMIO writes where possible.
 */
static inline void dma_async_memcpy_issue_pending(struct dma_chan *chan)
{
	return chan->device->device_memcpy_issue_pending(chan);
}

/**
 * dma_async_memcpy_complete - poll for transaction completion
 * @chan: DMA channel
 * @cookie: transaction identifier to check status of
 * @last: returns last completed cookie, can be NULL
 * @used: returns last issued cookie, can be NULL
 *
 * If @last and @used are passed in, upon return they reflect the driver
 * internal state and can be used with dma_async_is_complete() to check
 * the status of multiple cookies without re-checking hardware state.
 */
static inline enum dma_status dma_async_memcpy_complete(struct dma_chan *chan,
	dma_cookie_t cookie, dma_cookie_t *last, dma_cookie_t *used)
{
	return chan->device->device_memcpy_complete(chan, cookie, last, used);
}

/**
 * dma_async_is_complete - test a cookie against chan state
 * @cookie: transaction identifier to test status of
 * @last_complete: last know completed transaction
 * @last_used: last cookie value handed out
 *
 * dma_async_is_complete() is used in dma_async_memcpy_complete()
 * the test logic is separated for lightweight testing of multiple cookies
 */
static inline enum dma_status dma_async_is_complete(dma_cookie_t cookie,
			dma_cookie_t last_complete, dma_cookie_t last_used)
{
	if (last_complete <= last_used) {
		if ((cookie <= last_complete) || (cookie > last_used))
			return DMA_SUCCESS;
	} else {
		if ((cookie <= last_complete) && (cookie > last_used))
			return DMA_SUCCESS;
	}
	return DMA_IN_PROGRESS;
}


/* --- DMA device --- */

int dma_async_device_register(struct dma_device *device);
void dma_async_device_unregister(struct dma_device *device);

/* --- Helper iov-locking functions --- */

struct dma_page_list {
	char *base_address;
	int nr_pages;
	struct page **pages;
#ifndef __GENKSYMS__
	char __user *base_address_v3;
#endif
};

struct dma_pinned_list {
	int nr_iovecs;
	struct dma_page_list page_list[0];
};

struct dma_pinned_list *dma_pin_iovec_pages(struct iovec *iov, size_t len);
struct dma_pinned_list *dma_pin_iovec_pages_v3(struct iovec *iov, size_t len);
void dma_unpin_iovec_pages(struct dma_pinned_list* pinned_list);
void dma_unpin_iovec_pages_v3(struct dma_pinned_list* pinned_list);

dma_cookie_t dma_memcpy_to_iovec(struct dma_chan *chan, struct iovec *iov,
	struct dma_pinned_list *pinned_list, unsigned char *kdata, size_t len);
dma_cookie_t dma_memcpy_pg_to_iovec(struct dma_chan *chan, struct iovec *iov,
	struct dma_pinned_list *pinned_list, struct page *page,
	unsigned int offset, size_t len);

dma_cookie_t dma_memcpy_to_iovec_v3(struct dma_chan *chan, struct iovec *iov,
	struct dma_pinned_list *pinned_list, unsigned char *kdata, size_t len);
dma_cookie_t dma_memcpy_pg_to_iovec_v3(struct dma_chan *chan, struct iovec *iov,
	struct dma_pinned_list *pinned_list, struct page *page,
	unsigned int offset, size_t len);

#define dma_submit_error(cookie) ((cookie) < 0 ? 1 : 0)

/**
 * enum dma_transaction_type - DMA transaction types/indexes
 */
enum dma_transaction_type {
	DMA_MEMCPY,
	DMA_XOR,
	DMA_PQ_XOR,
	DMA_DUAL_XOR,
	DMA_PQ_UPDATE,
	DMA_ZERO_SUM,
	DMA_PQ_ZERO_SUM,
	DMA_MEMSET,
	DMA_MEMCPY_CRC32C,
	DMA_INTERRUPT,
	DMA_PRIVATE,
	DMA_SLAVE,
};

/* last transaction type for creation of the capabilities mask */
#define DMA_TX_TYPE_END (DMA_SLAVE + 1)

/**
 * enum dma_ctrl_flags - DMA flags to augment operation preparation,
 *      control completion, and communicate status.
 * @DMA_PREP_INTERRUPT - trigger an interrupt (callback) upon completion of
 *      this transaction
 * @DMA_CTRL_ACK - the descriptor cannot be reused until the client
 *      acknowledges receipt, i.e. has has a chance to establish any
 *      dependency chains
 * @DMA_COMPL_SKIP_SRC_UNMAP - set to disable dma-unmapping the source buffer(s)
 * @DMA_COMPL_SKIP_DEST_UNMAP - set to disable dma-unmapping the destination(s)
 * @DMA_COMPL_SRC_UNMAP_SINGLE - set to do the source dma-unmapping as single
 * 	(if not set, do the source dma-unmapping as page)
 * @DMA_COMPL_DEST_UNMAP_SINGLE - set to do the destination dma-unmapping as single
 * 	(if not set, do the destination dma-unmapping as page)
 */
enum dma_ctrl_flags {
	DMA_PREP_INTERRUPT = (1 << 0),
	DMA_CTRL_ACK = (1 << 1),
	DMA_COMPL_SKIP_SRC_UNMAP = (1 << 2),
	DMA_COMPL_SKIP_DEST_UNMAP = (1 << 3),
	DMA_COMPL_SRC_UNMAP_SINGLE = (1 << 4),
	DMA_COMPL_DEST_UNMAP_SINGLE = (1 << 5),
};

/**
 * dma_cap_mask_t - capabilities bitmap modeled after cpumask_t.
 * See linux/cpumask.h
 */
typedef struct { DECLARE_BITMAP(bits, DMA_TX_TYPE_END); } dma_cap_mask_t;

/*
 * typedef dma_event_callback - function pointer to a DMA event callback
 * For each channel added to the system this routine is called for each client.
 * If the client would like to use the channel it returns '1' to signal (ack)
 * the dmaengine core to take out a reference on the channel and its
 * corresponding device.  A client must not 'ack' an available channel more
 * than once.  When a channel is removed all clients are notified.  If a client
 * is using the channel it must 'ack' the removal.  A client must not 'ack' a
 * removed channel more than once.
 * @client - 'this' pointer for the client context
 * @chan - channel to be acted upon
 * @state - available or removed
 */
typedef void (*dma_async_tx_callback)(void *dma_async_param);

/**
 * struct dma_async_tx_descriptor - async transaction descriptor
 * ---dma generic offload fields---
 * @cookie: tracking cookie for this transaction, set to -EBUSY if
 *      this tx is sitting on a dependency list
 * @flags: flags to augment operation preparation, control completion, and
 *      communicate status
 * @phys: physical address of the descriptor
 * @tx_list: driver common field for operations that require multiple
 *      descriptors
 * @chan: target channel for this operation
 * @tx_submit: set the prepared descriptor(s) to be executed by the engine
 * @callback: routine to call after this operation is complete
 * @callback_param: general parameter to pass to the callback routine
 * ---async_tx api specific fields---
 * @next: at completion submit this descriptor
 * @parent: pointer to the next level up in the dependency chain
 * @lock: protect the parent and next pointers
 */
struct dma_async_tx_descriptor {
	dma_cookie_t cookie;
	enum dma_ctrl_flags flags; /* not a 'long' to pack with cookie */
	dma_addr_t phys;
	struct list_head tx_list;
	struct dma_chan *chan;
	dma_cookie_t (*tx_submit)(struct dma_async_tx_descriptor *tx);
	dma_async_tx_callback callback;
	void *callback_param;
	struct dma_async_tx_descriptor *next;
	struct dma_async_tx_descriptor *parent;
	spinlock_t lock;
};

#ifdef CONFIG_DMA_ENGINE_V3
enum dma_status dma_wait_for_async_tx(struct dma_async_tx_descriptor *tx);
void dma_issue_pending_all(void);
#else
static inline enum dma_status dma_wait_for_async_tx(struct dma_async_tx_descriptor *tx)
{
	return DMA_SUCCESS;
}
static inline void dma_issue_pending_all(void)
{
	do { } while (0);
}
#endif

/**
 * struct dma_device_v3 - info on the entity supplying DMA services
 * @chancnt: how many DMA channels are supported
 * @privatecnt: how many DMA channels are requested by dma_request_channel
 * @channels: the list of struct dma_chan
 * @global_node: list_head for global dma_device_list
 * @cap_mask: one or more dma_capability flags
 * @max_xor: maximum number of xor sources, 0 if no capability
 * @refcount: reference count
 * @done: IO completion struct
 * @dev_id: unique device ID
 * @dev: struct device reference for dma mapping api
 * @device_alloc_chan_resources: allocate resources and return the
 *      number of allocated descriptors
 * @device_free_chan_resources: release DMA channel's resources
 * @device_prep_dma_memcpy: prepares a memcpy operation
 * @device_prep_dma_xor: prepares a xor operation
 * @device_prep_dma_zero_sum: prepares a zero_sum operation
 * @device_prep_dma_memset: prepares a memset operation
 * @device_prep_dma_interrupt: prepares an end of chain interrupt operation
 * @device_prep_slave_sg: prepares a slave dma operation
 * @device_terminate_all: terminate all pending operations
 * @device_is_tx_complete: poll for transaction completion
 * @device_issue_pending: push pending transactions to hardware
 */
struct dma_device_v3 {
	unsigned int chancnt;
	unsigned int privatecnt;
	struct list_head channels;
	struct list_head global_node;
	dma_cap_mask_t  cap_mask;
	int max_xor;

	int dev_id;
	struct device *dev;

	int (*device_alloc_chan_resources)(struct dma_chan *chan);
	void (*device_free_chan_resources)(struct dma_chan *chan);

	struct dma_async_tx_descriptor *(*device_prep_dma_memcpy)(
		struct dma_chan *chan, dma_addr_t dest, dma_addr_t src,
		size_t len, unsigned long flags);
	struct dma_async_tx_descriptor *(*device_prep_dma_xor)(
		struct dma_chan *chan, dma_addr_t dest, dma_addr_t *src,
		unsigned int src_cnt, size_t len, unsigned long flags);
	struct dma_async_tx_descriptor *(*device_prep_dma_zero_sum)(
		struct dma_chan *chan, dma_addr_t *src, unsigned int src_cnt,
		size_t len, u32 *result, unsigned long flags);
	struct dma_async_tx_descriptor *(*device_prep_dma_memset)(
		struct dma_chan *chan, dma_addr_t dest, int value, size_t len,
		unsigned long flags);
	struct dma_async_tx_descriptor *(*device_prep_dma_interrupt)(
		struct dma_chan *chan, unsigned long flags);

	struct dma_async_tx_descriptor *(*device_prep_slave_sg)(
		struct dma_chan *chan, struct scatterlist *sgl,
		unsigned int sg_len, enum dma_data_direction direction,
		unsigned long flags);
	void (*device_terminate_all)(struct dma_chan *chan);

	enum dma_status (*device_is_tx_complete)(struct dma_chan *chan,
		dma_cookie_t cookie, dma_cookie_t *last,
		dma_cookie_t *used);
	void (*device_issue_pending)(struct dma_chan *chan);
};

/* --- public DMA engine API --- */

dma_cookie_t dma_async_memcpy_buf_to_buf_v3(struct dma_chan *chan,
	void *dest, void *src, size_t len);
dma_cookie_t dma_async_memcpy_buf_to_pg_v3(struct dma_chan *chan,
	struct page *page, unsigned int offset, void *kdata, size_t len);
dma_cookie_t dma_async_memcpy_pg_to_pg_v3(struct dma_chan *chan,
	struct page *dest_pg, unsigned int dest_off, struct page *src_pg,
	unsigned int src_off, size_t len);
void dma_async_tx_descriptor_init_v3(struct dma_async_tx_descriptor *tx,
	struct dma_chan *chan);

static inline void async_tx_ack(struct dma_async_tx_descriptor *tx)
{
	tx->flags |= DMA_CTRL_ACK;
}

static inline void async_tx_clear_ack(struct dma_async_tx_descriptor *tx)
{
	tx->flags &= ~DMA_CTRL_ACK;
}

static inline bool async_tx_test_ack(struct dma_async_tx_descriptor *tx)
{
	return (tx->flags & DMA_CTRL_ACK) == DMA_CTRL_ACK;
}

#define first_dma_cap(mask) __first_dma_cap(&(mask))
static inline int __first_dma_cap(const dma_cap_mask_t *srcp)
{
	return min_t(int, DMA_TX_TYPE_END,
		     find_first_bit(srcp->bits, DMA_TX_TYPE_END));
}

#define next_dma_cap(n, mask) __next_dma_cap((n), &(mask))
static inline int __next_dma_cap(int n, const dma_cap_mask_t *srcp)
{
	return min_t(int, DMA_TX_TYPE_END,
		     find_next_bit(srcp->bits, DMA_TX_TYPE_END, n+1));
}

#define dma_cap_set(tx, mask) __dma_cap_set((tx), &(mask))
static inline void
__dma_cap_set(enum dma_transaction_type tx_type, dma_cap_mask_t *dstp)
{
	set_bit(tx_type, dstp->bits);
}

#define dma_cap_clear(tx, mask) __dma_cap_clear((tx), &(mask))
static inline void
__dma_cap_clear(enum dma_transaction_type tx_type, dma_cap_mask_t *dstp)
{
	clear_bit(tx_type, dstp->bits);
}

#define dma_cap_zero(mask) __dma_cap_zero(&(mask))
static inline void __dma_cap_zero(dma_cap_mask_t *dstp)
{
	bitmap_zero(dstp->bits, DMA_TX_TYPE_END);
}

#define dma_has_cap(tx, mask) __dma_has_cap((tx), &(mask))
static inline int
__dma_has_cap(enum dma_transaction_type tx_type, dma_cap_mask_t *srcp)
{
	return test_bit(tx_type, srcp->bits);
}

#define for_each_dma_cap_mask(cap, mask) \
		for ((cap) = first_dma_cap(mask); \
			(cap) < DMA_TX_TYPE_END; \
			(cap) = next_dma_cap((cap), (mask)))

/**
 * dma_async_issue_pending - flush pending transactions to HW
 * @chan: target DMA channel
 *
 * This allows drivers to push copies to HW in batches,
 * reducing MMIO writes where possible.
 */
static inline void dma_async_issue_pending(struct dma_chan *chan)
{
	chan->device_v3->device_issue_pending(chan);
}

#define dma_async_memcpy_issue_pending_v3(chan) dma_async_issue_pending(chan)

/**
 * dma_async_is_tx_complete - poll for transaction completion
 * @chan: DMA channel
 * @cookie: transaction identifier to check status of
 * @last: returns last completed cookie, can be NULL
 * @used: returns last issued cookie, can be NULL
 *
 * If @last and @used are passed in, upon return they reflect the driver
 * internal state and can be used with dma_async_is_complete() to check
 * the status of multiple cookies without re-checking hardware state.
 */
static inline enum dma_status dma_async_is_tx_complete(struct dma_chan *chan,
	dma_cookie_t cookie, dma_cookie_t *last, dma_cookie_t *used)
{
	return chan->device_v3->device_is_tx_complete(chan, cookie, last, used);
}

#define dma_async_memcpy_complete_v3(chan, cookie, last, used)\
	dma_async_is_tx_complete(chan, cookie, last, used)

/* --- DMA device --- */

int dma_async_device_register_v3(struct dma_device_v3 *device);
void dma_async_device_unregister_v3(struct dma_device_v3 *device);
void dma_run_dependencies(struct dma_async_tx_descriptor *tx);
struct dma_chan *dma_find_channel(enum dma_transaction_type tx_type);
#define dma_request_channel(mask, x, y) __dma_request_channel(&(mask), x, y)
void dma_release_channel(struct dma_chan *chan);

/**
 * typedef dma_filter_fn - callback filter for dma_request_channel
 * @chan: channel to be reviewed
 * @filter_param: opaque parameter passed through dma_request_channel
 *
 * When this optional parameter is specified in a call to dma_request_channel a
 * suitable channel is passed to this routine for further dispositioning before
 * being returned.  Where 'suitable' indicates a non-busy channel that
 * satisfies the given capability mask.  It returns 'true' to indicate that the
 * channel is suitable.
 */
typedef bool (*dma_filter_fn)(struct dma_chan *chan, void *filter_param);

struct dma_chan *__dma_request_channel(dma_cap_mask_t *mask, dma_filter_fn fn, void *fn_param);

/**
 * struct dma_client - info on the entity making use of DMA services
 * @event_callback: func ptr to call when something happens
 * @chan_count: number of chans allocated
 * @chans_desired: number of chans requested. Can be +/- chan_count
 * @lock: protects access to the channels list
 * @channels: the list of DMA channels allocated
 * @global_node: list_head for global dma_client_list
 */
struct dma_client {
	dma_event_callback	event_callback;
	unsigned int		chan_count;
	unsigned int		chans_desired;

	spinlock_t		lock;
	struct list_head	channels;
	struct list_head	global_node;
};

#endif /* CONFIG_DMA_ENGINE */

#ifdef CONFIG_NET_DMA
#define net_dmaengine_get()	dmaengine_get()
#define net_dmaengine_put()	dmaengine_put()
#else
static inline void net_dmaengine_get(void)
{
}
static inline void net_dmaengine_put(void)
{
}
#endif
#endif /* DMAENGINE_H */
