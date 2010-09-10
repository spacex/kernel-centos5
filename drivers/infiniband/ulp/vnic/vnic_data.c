/*
 * Copyright (c) 2006 QLogic, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <net/inet_sock.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/vmalloc.h>

#include "vnic_util.h"
#include "vnic_viport.h"
#include "vnic_main.h"
#include "vnic_config.h"
#include "vnic_data.h"
#include "vnic_trailer.h"
#include "vnic_stats.h"

static void data_received_kick(struct io *io);
static void data_xmit_complete(struct io *io);

u32 min_rcv_skb = 60;
module_param(min_rcv_skb, int, 0444);
MODULE_PARM_DESC(min_rcv_skb, "Packets of size (in bytes) less than"
		 " or equal this value will be copied during receive."
		 " Default 60");

u32 min_xmt_skb = 60;
module_param(min_xmt_skb, int, 0444);
MODULE_PARM_DESC(min_xmit_skb, "Packets of size (in bytes) less than"
		 " or equal to this value will be copied during transmit."
		 "Default 60");

int data_init(struct data * data, struct viport * viport,
	      struct data_config * config, struct ib_pd *pd)
{
	DATA_FUNCTION("data_init()\n");

	data->parent = viport;
	data->config = config;
	data->ib_conn.viport = viport;
	data->ib_conn.ib_config = &config->ib_config;
	data->ib_conn.state = IB_CONN_UNINITTED;

	if ((min_xmt_skb < 60) || (min_xmt_skb > 9000)) {
		DATA_ERROR("min_xmt_skb (%d) must be between 60 and 9000\n",
			   min_xmt_skb);
		goto failure;
	}
	if (vnic_ib_conn_init(&data->ib_conn, viport, pd,
			      &config->ib_config)) {
		DATA_ERROR("Data IB connection initialization failed\n");
		goto failure;
	}
	data->mr = ib_get_dma_mr(pd,
				 IB_ACCESS_LOCAL_WRITE |
				 IB_ACCESS_REMOTE_READ |
				 IB_ACCESS_REMOTE_WRITE);
	if (IS_ERR(data->mr)) {
		DATA_ERROR("failed to register memory for"
			   " data connection\n");
		goto destroy_conn;
	}

	data->ib_conn.cm_id = ib_create_cm_id(viport->config->ibdev,
					      vnic_ib_cm_handler,
					      &data->ib_conn);

	if (IS_ERR(data->ib_conn.cm_id)) {
		DATA_ERROR("creating data CM ID failed\n");
		goto destroy_conn;
	}

	return 0;

destroy_conn:
	ib_destroy_qp(data->ib_conn.qp);
	ib_destroy_cq(data->ib_conn.cq);
failure:
	return -1;
}

static void data_post_recvs(struct data *data)
{
	unsigned long flags;

	DATA_FUNCTION("data_post_recvs()\n");
	spin_lock_irqsave(&data->recv_ios_lock, flags);
	while (!list_empty(&data->recv_ios)) {
		struct io *io = list_entry(data->recv_ios.next,
					   struct io, list_ptrs);
		struct recv_io *recv_io = (struct recv_io *)io;

		list_del(&recv_io->io.list_ptrs);
		spin_unlock_irqrestore(&data->recv_ios_lock, flags);
		if (vnic_ib_post_recv(&data->ib_conn, &recv_io->io)) {
			viport_failure(data->parent);
			return;
		}
		spin_lock_irqsave(&data->recv_ios_lock, flags);
	}
	spin_unlock_irqrestore(&data->recv_ios_lock, flags);
}

static void data_init_pool_work_reqs(struct data * data,
				      struct recv_io * recv_io)
{
	struct recv_pool	*recv_pool = &data->recv_pool;
	struct xmit_pool	*xmit_pool = &data->xmit_pool;
	struct rdma_io		*rdma_io;
	struct rdma_dest	*rdma_dest;
	dma_addr_t		xmit_dma;
	u8			*xmit_data;
	unsigned int		i;

	INIT_LIST_HEAD(&data->recv_ios);
	spin_lock_init(&data->recv_ios_lock);
	spin_lock_init(&data->xmit_buf_lock);
	for (i = 0; i < data->config->num_recvs; i++) {
		recv_io[i].io.viport = data->parent;
		recv_io[i].io.routine = data_received_kick;
		recv_io[i].list.addr = data->region_data_dma;
		recv_io[i].list.length = 4;
		recv_io[i].list.lkey = data->mr->lkey;

		recv_io[i].io.rwr.wr_id = (u64)&recv_io[i].io;
		recv_io[i].io.rwr.sg_list = &recv_io[i].list;
		recv_io[i].io.rwr.num_sge = 1;

		list_add(&recv_io[i].io.list_ptrs, &data->recv_ios);
	}

	INIT_LIST_HEAD(&recv_pool->avail_recv_bufs);
	for (i = 0; i < recv_pool->pool_sz; i++) {
		rdma_dest = &recv_pool->recv_bufs[i];
		list_add(&rdma_dest->list_ptrs,
			 &recv_pool->avail_recv_bufs);
	}

	xmit_dma = xmit_pool->xmitdata_dma;
	xmit_data = xmit_pool->xmit_data;

	for (i = 0; i < xmit_pool->num_xmit_bufs; i++) {
		rdma_io = &xmit_pool->xmit_bufs[i];
		rdma_io->index = i;
		rdma_io->io.viport = data->parent;
		rdma_io->io.routine = data_xmit_complete;

		rdma_io->list[0].lkey = data->mr->lkey;
		rdma_io->list[1].lkey = data->mr->lkey;
		rdma_io->io.swr.wr_id = (u64)rdma_io;
		rdma_io->io.swr.sg_list = rdma_io->list;
		rdma_io->io.swr.num_sge = 2;
		rdma_io->io.swr.opcode = IB_WR_RDMA_WRITE;
		rdma_io->io.swr.send_flags = IB_SEND_SIGNALED;
		rdma_io->io.type = RDMA;

		rdma_io->data = xmit_data;
		rdma_io->data_dma = xmit_dma;

		xmit_data += ALIGN(min_xmt_skb, VIPORT_TRAILER_ALIGNMENT);
		xmit_dma += ALIGN(min_xmt_skb, VIPORT_TRAILER_ALIGNMENT);
		rdma_io->trailer = (struct viport_trailer *)xmit_data;
		rdma_io->trailer_dma = xmit_dma;
		xmit_data += sizeof(struct viport_trailer);
		xmit_dma += sizeof(struct viport_trailer);
	}

	xmit_pool->rdma_rkey = data->mr->rkey;
	xmit_pool->rdma_addr = xmit_pool->buf_pool_dma;
}

static void data_init_free_bufs_swrs(struct data * data)
{
	struct rdma_io		*rdma_io;
	struct send_io		*send_io;

	rdma_io = &data->free_bufs_io;
	rdma_io->io.viport = data->parent;
	rdma_io->io.routine = NULL;

	rdma_io->list[0].lkey = data->mr->lkey;

	rdma_io->io.swr.wr_id = (u64)rdma_io;
	rdma_io->io.swr.sg_list = rdma_io->list;
	rdma_io->io.swr.num_sge = 1;
	rdma_io->io.swr.opcode = IB_WR_RDMA_WRITE;
	rdma_io->io.swr.send_flags = IB_SEND_SIGNALED;
	rdma_io->io.type = RDMA;

	send_io = &data->kick_io;
	send_io->io.viport = data->parent;
	send_io->io.routine = NULL;

	send_io->list.addr = data->region_data_dma;
	send_io->list.length = 0;
	send_io->list.lkey = data->mr->lkey;

	send_io->io.swr.wr_id = (u64)send_io;
	send_io->io.swr.sg_list = &send_io->list;
	send_io->io.swr.num_sge = 1;
	send_io->io.swr.opcode = IB_WR_SEND;
	send_io->io.swr.send_flags = IB_SEND_SIGNALED;
	send_io->io.type = SEND;
}

static int data_init_buf_pools(struct data * data)
{
	struct recv_pool	*recv_pool = &data->recv_pool;
	struct xmit_pool	*xmit_pool = &data->xmit_pool;
	struct viport		*viport = data->parent;

	recv_pool->buf_pool_len =
	    sizeof(struct buff_pool_entry) * recv_pool->eioc_pool_sz;

	recv_pool->buf_pool = kzalloc(recv_pool->buf_pool_len, GFP_KERNEL);

	if (!recv_pool->buf_pool) {
		DATA_ERROR("failed allocating %d bytes"
			   " for recv pool bufpool\n",
			   recv_pool->buf_pool_len);
		goto failure;
	}

	recv_pool->buf_pool_dma =
	    dma_map_single(viport->config->ibdev->dma_device,
			   recv_pool->buf_pool, recv_pool->buf_pool_len,
			   DMA_TO_DEVICE);

	if (dma_mapping_error(recv_pool->buf_pool_dma)) {
		DATA_ERROR("xmit buf_pool dma map error\n");
		goto free_recv_pool;
	}

	xmit_pool->buf_pool_len =
	    sizeof(struct buff_pool_entry) * xmit_pool->pool_sz;
	xmit_pool->buf_pool = kzalloc(xmit_pool->buf_pool_len, GFP_KERNEL);

	if (!xmit_pool->buf_pool) {
		DATA_ERROR("failed allocating %d bytes"
			   " for xmit pool bufpool\n",
			   xmit_pool->buf_pool_len);
		goto unmap_recv_pool;
	}

	xmit_pool->buf_pool_dma =
	    dma_map_single(viport->config->ibdev->dma_device,
			   xmit_pool->buf_pool, xmit_pool->buf_pool_len,
			   DMA_FROM_DEVICE);

	if (dma_mapping_error(xmit_pool->buf_pool_dma)) {
		DATA_ERROR("xmit buf_pool dma map error\n");
		goto free_xmit_pool;
	}

	xmit_pool->xmit_data = kzalloc(xmit_pool->xmitdata_len, GFP_KERNEL);

	if (!xmit_pool->xmit_data) {
		DATA_ERROR("failed allocating %d bytes for xmit data\n",
			   xmit_pool->xmitdata_len);
		goto unmap_xmit_pool;
	}

	xmit_pool->xmitdata_dma =
	    dma_map_single(viport->config->ibdev->dma_device,
			   xmit_pool->xmit_data, xmit_pool->xmitdata_len,
			   DMA_TO_DEVICE);

	if (dma_mapping_error(xmit_pool->xmitdata_dma)) {
		DATA_ERROR("xmit data dma map error\n");
		goto free_xmit_data;
	}

	return 0;

free_xmit_data:
	kfree(xmit_pool->xmit_data);
unmap_xmit_pool:
	dma_unmap_single(data->parent->config->ibdev->dma_device,
			 xmit_pool->buf_pool_dma,
			 xmit_pool->buf_pool_len, DMA_FROM_DEVICE);
free_xmit_pool:
	kfree(xmit_pool->buf_pool);
unmap_recv_pool:
	dma_unmap_single(data->parent->config->ibdev->dma_device,
			 recv_pool->buf_pool_dma,
			 recv_pool->buf_pool_len, DMA_TO_DEVICE);
free_recv_pool:
	kfree(recv_pool->buf_pool);
failure:
	return -1;
}

static void data_init_xmit_pool(struct data * data)
{
	struct xmit_pool	*xmit_pool = &data->xmit_pool;

	xmit_pool->pool_sz =
		be32_to_cpu(data->eioc_pool_parms.num_recv_pool_entries);
	xmit_pool->buffer_sz =
		be32_to_cpu(data->eioc_pool_parms.size_recv_pool_entry);

	xmit_pool->notify_count = 0;
	xmit_pool->notify_bundle = data->config->notify_bundle;
	xmit_pool->next_xmit_pool = 0;
	xmit_pool->num_xmit_bufs = xmit_pool->notify_bundle * 2;
	xmit_pool->next_xmit_buf = 0;
	xmit_pool->last_comp_buf = xmit_pool->num_xmit_bufs - 1;

	xmit_pool->kick_count = 0;
	xmit_pool->kick_byte_count = 0;

	xmit_pool->send_kicks =
	  be32_to_cpu(data->
		      eioc_pool_parms.num_recv_pool_entries_before_kick)
	  || be32_to_cpu(data->
		      eioc_pool_parms.num_recv_pool_bytes_before_kick);
	xmit_pool->kick_bundle =
	    be32_to_cpu(data->
		        eioc_pool_parms.num_recv_pool_entries_before_kick);
	xmit_pool->kick_byte_bundle =
	    be32_to_cpu(data->
			eioc_pool_parms.num_recv_pool_bytes_before_kick);

	xmit_pool->need_buffers = 1;

	xmit_pool->xmitdata_len =
	    BUFFER_SIZE(min_xmt_skb) * xmit_pool->num_xmit_bufs;
}

static void data_init_recv_pool(struct data * data)
{
	struct recv_pool	*recv_pool = &data->recv_pool;

	recv_pool->pool_sz = data->config->host_recv_pool_entries;
	recv_pool->eioc_pool_sz =
		be32_to_cpu(data->host_pool_parms.num_recv_pool_entries);
	if (recv_pool->pool_sz > recv_pool->eioc_pool_sz)
		recv_pool->pool_sz =
		    be32_to_cpu(data->host_pool_parms.num_recv_pool_entries);

	recv_pool->buffer_sz =
		    be32_to_cpu(data->host_pool_parms.size_recv_pool_entry);

	recv_pool->sz_free_bundle =
		be32_to_cpu(data->
			host_pool_parms.free_recv_pool_entries_per_update);
	recv_pool->num_free_bufs = 0;
	recv_pool->num_posted_bufs = 0;

	recv_pool->next_full_buf = 0;
	recv_pool->next_free_buf = 0;
	recv_pool->kick_on_free  = 0;
}

int data_connect(struct data * data)
{
	struct xmit_pool	*xmit_pool = &data->xmit_pool;
	struct recv_pool	*recv_pool = &data->recv_pool;
	struct recv_io		* recv_io;
	unsigned int		sz;
	struct viport		*viport = data->parent;

	DATA_FUNCTION("data_connect()\n");

	data_init_recv_pool(data);
	data_init_xmit_pool(data);

	sz = sizeof(struct rdma_dest) * recv_pool->pool_sz    +
	     sizeof(struct recv_io) * data->config->num_recvs +
	     sizeof(struct rdma_io) * xmit_pool->num_xmit_bufs;

	data->local_storage = vmalloc(sz);

	if (!data->local_storage) {
		DATA_ERROR("failed allocating %d bytes"
			   " local storage\n", sz);
		goto out;
	}

	memset(data->local_storage, 0, sz);

	recv_pool->recv_bufs = (struct rdma_dest *)data->local_storage;
	sz = sizeof(struct rdma_dest) * recv_pool->pool_sz;

	recv_io = (struct recv_io *)(data->local_storage + sz);
	sz += sizeof(struct recv_io) * data->config->num_recvs;

	xmit_pool->xmit_bufs = (struct rdma_io *)(data->local_storage + sz);
	data->region_data = kzalloc(4, GFP_KERNEL);

	if (!data->region_data) {
		DATA_ERROR("failed to alloc memory for region data\n");
		goto free_local_storage;
	}

	data->region_data_dma =
	    dma_map_single(viport->config->ibdev->dma_device,
			   data->region_data, 4, DMA_BIDIRECTIONAL);

	if (dma_mapping_error(data->region_data_dma)) {
		DATA_ERROR("region data dma map error\n");
		goto free_region_data;
	}

	if (data_init_buf_pools(data))
		goto unmap_region_data;

	data_init_free_bufs_swrs(data);
	data_init_pool_work_reqs(data, recv_io);

	data_post_recvs(data);

	if (vnic_ib_cm_connect(&data->ib_conn))
		goto unmap_region_data;

	return 0;

unmap_region_data:
	dma_unmap_single(data->parent->config->ibdev->dma_device,
			 data->region_data_dma, 4, DMA_BIDIRECTIONAL);
free_region_data:
		kfree(data->region_data);
free_local_storage:
		vfree(data->local_storage);
out:
	return -1;
}

static void data_add_free_buffer(struct data *data, int index,
				 struct rdma_dest *rdma_dest)
{
	struct recv_pool *pool = &data->recv_pool;
	struct buff_pool_entry *bpe;

	DATA_FUNCTION("data_add_free_buffer()\n");
	rdma_dest->trailer->connection_hash_and_valid = 0;
	dma_sync_single_for_cpu(data->parent->config->ibdev->dma_device,
				pool->buf_pool_dma, pool->buf_pool_len,
				DMA_TO_DEVICE);

	bpe = &pool->buf_pool[index];
	bpe->rkey = cpu_to_be32(data->mr->rkey);

	bpe->remote_addr = cpu_to_be64((unsigned long long)
					virt_to_phys(rdma_dest->data));
	bpe->valid = (u32) (rdma_dest - &pool->recv_bufs[0]) + 1;
	++pool->num_free_bufs;

	dma_sync_single_for_device(data->parent->config->ibdev->dma_device,
				   pool->buf_pool_dma, pool->buf_pool_len,
				   DMA_TO_DEVICE);
}

/* NOTE: this routine is not reentrant */
static void data_alloc_buffers(struct data *data, int initial_allocation)
{
	struct recv_pool *pool = &data->recv_pool;
	struct rdma_dest *rdma_dest;
	struct sk_buff *skb;
	int index;

	DATA_FUNCTION("data_alloc_buffers()\n");
	index = ADD(pool->next_free_buf, pool->num_free_bufs,
		    pool->eioc_pool_sz);

	while (!list_empty(&pool->avail_recv_bufs)) {
		rdma_dest =
		    list_entry(pool->avail_recv_bufs.next,
			       struct rdma_dest, list_ptrs);
		if (!rdma_dest->skb) {
			if (initial_allocation)
				skb = alloc_skb(pool->buffer_sz + 2,
						GFP_KERNEL);
			else
				skb = dev_alloc_skb(pool->buffer_sz + 2);
			if (!skb) {
				DATA_ERROR("failed to alloc skb\n");
				break;
			}
			skb_reserve(skb, 2);
			skb_put(skb, pool->buffer_sz);
			rdma_dest->skb = skb;
			rdma_dest->data = skb->data;
			rdma_dest->trailer =
			  (struct viport_trailer *)(rdma_dest->data +
						    pool->buffer_sz -
						    sizeof(struct
							   viport_trailer));
		}
		rdma_dest->trailer->connection_hash_and_valid = 0;

		list_del_init(&rdma_dest->list_ptrs);

		data_add_free_buffer(data, index, rdma_dest);
		index = NEXT(index, pool->eioc_pool_sz);
	}
}

static void data_send_kick_message(struct data *data)
{
	struct xmit_pool *pool = &data->xmit_pool;
	DATA_FUNCTION("data_send_kick_message()\n");
	/* stop timer for bundle_timeout */
	if (data->kick_timer_on) {
		del_timer(&data->kick_timer);
		data->kick_timer_on = 0;
	}
	pool->kick_count = 0;
	pool->kick_byte_count = 0;

	/* TODO: keep track of when kick is outstanding, and
	 * don't reuse until complete
	 */
	if (vnic_ib_post_send(&data->ib_conn, &data->free_bufs_io.io)) {
		DATA_ERROR("failed to post send\n");
		viport_failure(data->parent);
	}
}

static void data_send_free_recv_buffers(struct data *data)
{
	struct recv_pool *pool = &data->recv_pool;
	struct ib_send_wr *swr = &data->free_bufs_io.io.swr;

	int bufs_sent = 0;
	u64 rdma_addr;
	u32 offset;
	u32 sz;
	unsigned int num_to_send, next_increment;

	DATA_FUNCTION("data_send_free_recv_buffers()\n");

	for (num_to_send = pool->sz_free_bundle;
	     num_to_send <= pool->num_free_bufs;
	     num_to_send += pool->sz_free_bundle) {
		/* handle multiple bundles as one when possible. */
		next_increment = num_to_send + pool->sz_free_bundle;
		if ((next_increment <= pool->num_free_bufs)
		    && (pool->next_free_buf + next_increment <=
			pool->eioc_pool_sz)) {
			continue;
		}

		offset = pool->next_free_buf *
				sizeof(struct buff_pool_entry);
		sz = num_to_send * sizeof(struct buff_pool_entry);
		rdma_addr = pool->eioc_rdma_addr + offset;
		swr->sg_list->length = sz;
		swr->sg_list->addr = pool->buf_pool_dma + offset;
		swr->wr.rdma.remote_addr = rdma_addr;

		if (vnic_ib_post_send(&data->ib_conn,
		    &data->free_bufs_io.io)) {
			DATA_ERROR("failed to post send\n");
			viport_failure(data->parent);
			break;
		}
		INC(pool->next_free_buf, num_to_send, pool->eioc_pool_sz);
		pool->num_free_bufs -= num_to_send;
		pool->num_posted_bufs += num_to_send;
		bufs_sent = 1;
	}

	if (bufs_sent) {
		if (pool->kick_on_free)
			data_send_kick_message(data);
	}
	if (pool->num_posted_bufs == 0) {
		DATA_ERROR("%s: unable to allocate receive buffers\n",
			   config_viport_name(data->parent->config));
		viport_failure(data->parent);
	}
}

void data_connected(struct data *data)
{
	DATA_FUNCTION("data_connected()\n");
	data->free_bufs_io.io.swr.wr.rdma.rkey =
				data->recv_pool.eioc_rdma_rkey;
	data_alloc_buffers(data, 1);
	data_send_free_recv_buffers(data);
	data->connected = 1;
}

void data_disconnect(struct data *data)
{
	struct xmit_pool *xmit_pool = &data->xmit_pool;
	struct recv_pool *recv_pool = &data->recv_pool;
	unsigned int i;

	DATA_FUNCTION("data_disconnect()\n");

	data->connected = 0;
	if (data->kick_timer_on) {
		del_timer_sync(&data->kick_timer);
		data->kick_timer_on = 0;
	}

	for (i = 0; i < xmit_pool->num_xmit_bufs; i++) {
		if (xmit_pool->xmit_bufs[i].skb)
			dev_kfree_skb(xmit_pool->xmit_bufs[i].skb);
		xmit_pool->xmit_bufs[i].skb = NULL;

	}
	for (i = 0; i < recv_pool->pool_sz; i++) {
		if (data->recv_pool.recv_bufs[i].skb)
			dev_kfree_skb(recv_pool->recv_bufs[i].skb);
		recv_pool->recv_bufs[i].skb = NULL;
	}
	vfree(data->local_storage);
	if (data->region_data) {
		dma_unmap_single(data->parent->config->ibdev->dma_device,
				 data->region_data_dma, 4,
				 DMA_BIDIRECTIONAL);
		kfree(data->region_data);
	}

	if (recv_pool->buf_pool) {
		dma_unmap_single(data->parent->config->ibdev->dma_device,
				 recv_pool->buf_pool_dma,
				 recv_pool->buf_pool_len, DMA_TO_DEVICE);
		kfree(recv_pool->buf_pool);
	}

	if (xmit_pool->buf_pool) {
		dma_unmap_single(data->parent->config->ibdev->dma_device,
				 xmit_pool->buf_pool_dma,
				 xmit_pool->buf_pool_len, DMA_FROM_DEVICE);
		kfree(xmit_pool->buf_pool);
	}

	if (xmit_pool->xmit_data) {
		dma_unmap_single(data->parent->config->ibdev->dma_device,
				 xmit_pool->xmitdata_dma,
				 xmit_pool->xmitdata_len, DMA_TO_DEVICE);
		kfree(xmit_pool->xmit_data);
	}
}

void data_cleanup(struct data *data)
{
	if (ib_send_cm_dreq(data->ib_conn.cm_id, NULL, 0))
		printk(KERN_DEBUG "data CM DREQ sending failed\n");

	ib_destroy_cm_id(data->ib_conn.cm_id);
	ib_destroy_qp(data->ib_conn.qp);
	ib_destroy_cq(data->ib_conn.cq);
	ib_dereg_mr(data->mr);

}

static int data_alloc_xmit_buffer(struct data *data, struct sk_buff *skb,
				  struct buff_pool_entry **pp_bpe,
				  struct rdma_io **pp_rdma_io,
				  int *last)
{
	struct xmit_pool	*pool = &data->xmit_pool;
	unsigned long		flags;
	int			ret;

	DATA_FUNCTION("data_alloc_xmit_buffer()\n");

	spin_lock_irqsave(&data->xmit_buf_lock, flags);
	dma_sync_single_for_cpu(data->parent->config->ibdev->dma_device,
				pool->buf_pool_dma, pool->buf_pool_len,
				DMA_TO_DEVICE);
	*last = 0;
	*pp_rdma_io = &pool->xmit_bufs[pool->next_xmit_buf];
	*pp_bpe = &pool->buf_pool[pool->next_xmit_pool];

	if ((*pp_bpe)->valid && pool->next_xmit_buf !=
	     pool->last_comp_buf) {
		INC(pool->next_xmit_buf, 1, pool->num_xmit_bufs);
		INC(pool->next_xmit_pool, 1, pool->pool_sz);
		if (!pool->buf_pool[pool->next_xmit_pool].valid) {
			DATA_INFO("just used the last EIOU"
				  " receive buffer\n");
			*last = 1;
			pool->need_buffers = 1;
			vnic_stop_xmit(data->parent->vnic,
				       data->parent->parent);
			data_kickreq_stats(data);
		} else if (pool->next_xmit_buf == pool->last_comp_buf) {
			DATA_INFO("just used our last xmit buffer\n");
			pool->need_buffers = 1;
			vnic_stop_xmit(data->parent->vnic,
				       data->parent->parent);
		}
		(*pp_rdma_io)->skb = skb;
		(*pp_bpe)->valid = 0;
		ret = 0;
	} else {
		data_no_xmitbuf_stats(data);
		DATA_ERROR("Out of xmit buffers\n");
		vnic_stop_xmit(data->parent->vnic,
			       data->parent->parent);
		ret = -1;
	}

	dma_sync_single_for_device(data->parent->config->ibdev->
				   dma_device, pool->buf_pool_dma,
				   pool->buf_pool_len, DMA_TO_DEVICE);
	spin_unlock_irqrestore(&data->xmit_buf_lock, flags);
	return ret;
}

static void data_rdma_packet(struct data *data, struct buff_pool_entry *bpe,
			     struct rdma_io *rdma_io)
{
	struct ib_send_wr	*swr;
	struct sk_buff		*skb;
	dma_addr_t		trailer_data_dma;
	dma_addr_t		skb_data_dma;
	struct xmit_pool	*xmit_pool = &data->xmit_pool;
	struct viport		*viport = data->parent;
	u8			*d;
	int			len;
	int			fill_len;

	DATA_FUNCTION("data_rdma_packet()\n");
	swr = &rdma_io->io.swr;
	skb = rdma_io->skb;
	len = ALIGN(rdma_io->len, VIPORT_TRAILER_ALIGNMENT);
	fill_len = len - skb->len;

	dma_sync_single_for_cpu(data->parent->config->ibdev->dma_device,
				xmit_pool->xmitdata_dma,
				xmit_pool->xmitdata_len, DMA_TO_DEVICE);

	d = (u8 *) rdma_io->trailer - fill_len;
	trailer_data_dma = rdma_io->trailer_dma - fill_len;
	memset(d, 0, fill_len);

	swr->sg_list[0].length = skb->len;
	if (skb->len <= min_xmt_skb) {
		memcpy(rdma_io->data, skb->data, skb->len);
		swr->sg_list[0].lkey = data->mr->lkey;
		swr->sg_list[0].addr = rdma_io->data_dma;
		dev_kfree_skb_any(skb);
		rdma_io->skb = NULL;
	} else {
		swr->sg_list[0].lkey = data->mr->lkey;

		skb_data_dma = dma_map_single(viport->config->ibdev->dma_device,
					      skb->data, skb->len,
					      DMA_TO_DEVICE);

		if (dma_mapping_error(skb_data_dma)) {
			DATA_ERROR("skb data dma map error\n");
			goto failure;
		}

		rdma_io->skb_data_dma = skb_data_dma;

		swr->sg_list[0].addr = skb_data_dma;
		skb_orphan(skb);
	}
	dma_sync_single_for_cpu(data->parent->config->ibdev->dma_device,
				xmit_pool->buf_pool_dma,
				xmit_pool->buf_pool_len, DMA_TO_DEVICE);

	swr->sg_list[1].addr = trailer_data_dma;
	swr->sg_list[1].length = fill_len + sizeof(struct viport_trailer);
	swr->sg_list[0].lkey = data->mr->lkey;
	swr->wr.rdma.remote_addr = be64_to_cpu(bpe->remote_addr);
	swr->wr.rdma.remote_addr += data->xmit_pool.buffer_sz;
	swr->wr.rdma.remote_addr -= (sizeof(struct viport_trailer) + len);
	swr->wr.rdma.rkey = be32_to_cpu(bpe->rkey);

	dma_sync_single_for_device(data->parent->config->ibdev->dma_device,
				   xmit_pool->buf_pool_dma,
				   xmit_pool->buf_pool_len, DMA_TO_DEVICE);

	data->xmit_pool.notify_count++;
	if (data->xmit_pool.notify_count >= data->xmit_pool.notify_bundle) {
		data->xmit_pool.notify_count = 0;
		swr->send_flags = IB_SEND_SIGNALED;
	} else {
		swr->send_flags = 0;
	}
	dma_sync_single_for_device(data->parent->config->ibdev->dma_device,
				   xmit_pool->xmitdata_dma,
				   xmit_pool->xmitdata_len, DMA_TO_DEVICE);
	if (vnic_ib_post_send(&data->ib_conn, &rdma_io->io)) {
		DATA_ERROR("failed to post send for data RDMA write\n");
		viport_failure(data->parent);
		goto failure;
	}

	data_xmits_stats(data);
failure:
	dma_sync_single_for_device(data->parent->config->ibdev->dma_device,
				   xmit_pool->xmitdata_dma,
				   xmit_pool->xmitdata_len, DMA_TO_DEVICE);
}

static void data_kick_timeout_handler(unsigned long arg)
{
	struct data *data = (struct data *)arg;

	DATA_FUNCTION("data_kick_timeout_handler()\n");
	data->kick_timer_on = 0;
	data_send_kick_message(data);
}

int data_xmit_packet(struct data *data, struct sk_buff *skb)
{
	struct xmit_pool	*pool = &data->xmit_pool;
	struct rdma_io		*rdma_io;
	struct buff_pool_entry	*bpe;
	struct viport_trailer	*trailer;
	unsigned int		sz = skb->len;
	int			last;

	DATA_FUNCTION("data_xmit_packet()\n");
	if (sz > pool->buffer_sz) {
		DATA_ERROR("outbound packet too large, size = %d\n", sz);
		return -1;
	}

	if (data_alloc_xmit_buffer(data, skb, &bpe, &rdma_io, &last)) {
		DATA_ERROR("error in allocating data xmit buffer\n");
		return -1;
	}

	dma_sync_single_for_cpu(data->parent->config->ibdev->dma_device,
				pool->xmitdata_dma, pool->xmitdata_len,
				DMA_TO_DEVICE);
	trailer = rdma_io->trailer;

	memset(trailer, 0, sizeof *trailer);
	memcpy(trailer->dest_mac_addr, skb->data, ETH_ALEN);

	if (skb->sk)
		trailer->connection_hash_and_valid = 0x40 |
			 ((be16_to_cpu(inet_sk(skb->sk)->sport) +
			   be16_to_cpu( inet_sk(skb->sk)->dport)) & 0x3f);

	trailer->connection_hash_and_valid |= CHV_VALID;

	if ((sz > 16) && (*(__be16 *) (skb->data + 12) ==
			   __constant_cpu_to_be16(ETH_P_8021Q))) {
		trailer->vlan = *(__be16 *) (skb->data + 14);
		memmove(skb->data + 4, skb->data, 12);
		skb_pull(skb, 4);
		trailer->pkt_flags |= PF_VLAN_INSERT;
	}
	if (last)
		trailer->pkt_flags |= PF_KICK;
	if (sz < ETH_ZLEN) {
		/* EIOU requires all packets to be
		 * of ethernet minimum packet size.
		 */
		trailer->data_length = __constant_cpu_to_be16(ETH_ZLEN);
		rdma_io->len = ETH_ZLEN;
	} else {
		trailer->data_length = cpu_to_be16(sz);
		rdma_io->len = sz;
	}

	if (skb->ip_summed == CHECKSUM_HW) {
		trailer->tx_chksum_flags = TX_CHKSUM_FLAGS_CHECKSUM_V4
		    | TX_CHKSUM_FLAGS_IP_CHECKSUM
		    | TX_CHKSUM_FLAGS_TCP_CHECKSUM
		    | TX_CHKSUM_FLAGS_UDP_CHECKSUM;
	}

	dma_sync_single_for_device(data->parent->config->ibdev->dma_device,
				   pool->xmitdata_dma, pool->xmitdata_len,
				   DMA_TO_DEVICE);

	data_rdma_packet(data, bpe, rdma_io);

	if (pool->send_kicks) {
		/* EIOC needs kicks to inform it of sent packets */
		pool->kick_count++;
		pool->kick_byte_count += sz;
		if ((pool->kick_count >= pool->kick_bundle)
		    || (pool->kick_byte_count >= pool->kick_byte_bundle)) {
			data_send_kick_message(data);
		} else if (pool->kick_count == 1) {
			init_timer(&data->kick_timer);
			/* timeout_before_kick is in usec */
			data->kick_timer.expires =
			   msecs_to_jiffies(be32_to_cpu(data->
				eioc_pool_parms.timeout_before_kick) * 1000)
				+ jiffies;
			data->kick_timer.data = (unsigned long)data;
			data->kick_timer.function = data_kick_timeout_handler;
			add_timer(&data->kick_timer);
			data->kick_timer_on = 1;
		}
	}
	return 0;
}

void data_check_xmit_buffers(struct data *data)
{
	struct xmit_pool *pool = &data->xmit_pool;
	unsigned long flags;

	DATA_FUNCTION("data_check_xmit_buffers()\n");
	spin_lock_irqsave(&data->xmit_buf_lock, flags);
	dma_sync_single_for_cpu(data->parent->config->ibdev->dma_device,
				pool->buf_pool_dma, pool->buf_pool_len,
				DMA_TO_DEVICE);

	if (data->xmit_pool.need_buffers
	    && pool->buf_pool[pool->next_xmit_pool].valid
	    && pool->next_xmit_buf != pool->last_comp_buf) {
		data->xmit_pool.need_buffers = 0;
		vnic_restart_xmit(data->parent->vnic,
				  data->parent->parent);
		DATA_INFO("there are free xmit buffers\n");
	}
	dma_sync_single_for_device(data->parent->config->ibdev->dma_device,
				   pool->buf_pool_dma, pool->buf_pool_len,
				   DMA_TO_DEVICE);

	spin_unlock_irqrestore(&data->xmit_buf_lock, flags);
}

static struct sk_buff *data_recv_to_skbuff(struct data *data,
					   struct rdma_dest *rdma_dest)
{
	struct viport_trailer *trailer;
	struct sk_buff *skb = NULL;
	int start;
	unsigned int len;
	u8 rx_chksum_flags;

	DATA_FUNCTION("data_recv_to_skbuff()\n");
	trailer = rdma_dest->trailer;
	start = data_offset(data, trailer);
	len = data_len(data, trailer);

	if (len <= min_rcv_skb)
		skb = dev_alloc_skb(len + VLAN_HLEN + 2);
			 /* leave room for VLAN header and alignment */
	if (skb) {
		skb_reserve(skb, VLAN_HLEN + 2);
		memcpy(skb->data, rdma_dest->data + start, len);
		skb_put(skb, len);
	} else {
		skb = rdma_dest->skb;
		rdma_dest->skb = NULL;
		rdma_dest->trailer = NULL;
		rdma_dest->data = NULL;
		skb_pull(skb, start);
		skb_trim(skb, len);
	}

	rx_chksum_flags = trailer->rx_chksum_flags;
	DATA_INFO("rx_chksum_flags = %d, LOOP = %c, IP = %c,"
	     " TCP = %c, UDP = %c\n",
	     rx_chksum_flags,
	     (rx_chksum_flags & RX_CHKSUM_FLAGS_LOOPBACK) ? 'Y' : 'N',
	     (rx_chksum_flags & RX_CHKSUM_FLAGS_IP_CHECKSUM_SUCCEEDED) ? 'Y'
	     : (rx_chksum_flags & RX_CHKSUM_FLAGS_IP_CHECKSUM_FAILED) ? 'N' :
	     '-',
	     (rx_chksum_flags & RX_CHKSUM_FLAGS_TCP_CHECKSUM_SUCCEEDED) ? 'Y'
	     : (rx_chksum_flags & RX_CHKSUM_FLAGS_TCP_CHECKSUM_FAILED) ? 'N' :
	     '-',
	     (rx_chksum_flags & RX_CHKSUM_FLAGS_UDP_CHECKSUM_SUCCEEDED) ? 'Y'
	     : (rx_chksum_flags & RX_CHKSUM_FLAGS_UDP_CHECKSUM_FAILED) ? 'N' :
	     '-');

	if ((rx_chksum_flags & RX_CHKSUM_FLAGS_LOOPBACK)
	    || ((rx_chksum_flags & RX_CHKSUM_FLAGS_IP_CHECKSUM_SUCCEEDED)
		&& ((rx_chksum_flags & RX_CHKSUM_FLAGS_TCP_CHECKSUM_SUCCEEDED)
		    || (rx_chksum_flags &
			RX_CHKSUM_FLAGS_UDP_CHECKSUM_SUCCEEDED))))
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	else
		skb->ip_summed = CHECKSUM_NONE;

	if (trailer->pkt_flags & PF_VLAN_INSERT) {
		u8 *rv;

		rv = skb_push(skb, 4);
		memmove(rv, rv + 4, 12);
		*(__be16 *) (rv + 12) = __constant_cpu_to_be16(ETH_P_8021Q);
		if (trailer->pkt_flags & PF_PVID_OVERRIDDEN)
			*(__be16 *) (rv + 14) = trailer->vlan &
					__constant_cpu_to_be16(0xF000);
		else
			*(__be16 *) (rv + 14) = trailer->vlan;
	}

	return skb;
}

static int data_incoming_recv(struct data *data)
{
	struct recv_pool *pool = &data->recv_pool;
	struct rdma_dest *rdma_dest;
	struct viport_trailer *trailer;
	struct buff_pool_entry *bpe;
	struct sk_buff *skb;

	DATA_FUNCTION("data_incoming_recv()\n");
	if (pool->next_full_buf == pool->next_free_buf)
		return -1;
	bpe = &pool->buf_pool[pool->next_full_buf];
	rdma_dest = &pool->recv_bufs[bpe->valid - 1];
	trailer = rdma_dest->trailer;

	if (!trailer
	    || !(trailer->connection_hash_and_valid & CHV_VALID))
		return -1;

	/* received a packet */
	if (trailer->pkt_flags & PF_KICK)
		pool->kick_on_free = 1;

	skb = data_recv_to_skbuff(data, rdma_dest);

	if (skb) {
		vnic_recv_packet(data->parent->vnic,
				 data->parent->parent, skb);
		list_add(&rdma_dest->list_ptrs, &pool->avail_recv_bufs);
	}

	dma_sync_single_for_cpu(data->parent->config->ibdev->dma_device,
				pool->buf_pool_dma, pool->buf_pool_len,
				DMA_TO_DEVICE);

	bpe->valid = 0;
	dma_sync_single_for_device(data->parent->config->ibdev->
				   dma_device, pool->buf_pool_dma,
				   pool->buf_pool_len, DMA_TO_DEVICE);

	INC(pool->next_full_buf, 1, pool->eioc_pool_sz);
	pool->num_posted_bufs--;
	data_recvs_stats(data);
	return 0;
}

static void data_received_kick(struct io *io)
{
	struct data *data = &io->viport->data;
	unsigned long flags;

	DATA_FUNCTION("data_received_kick()\n");
	data_note_kickrcv_time();
	spin_lock_irqsave(&data->recv_ios_lock, flags);
	list_add(&io->list_ptrs, &data->recv_ios);
	spin_unlock_irqrestore(&data->recv_ios_lock, flags);
	data_post_recvs(data);
	data_rcvkicks_stats(data);
	data_check_xmit_buffers(data);

	while (!data_incoming_recv(data));

	if (data->connected) {
		data_alloc_buffers(data, 0);
		data_send_free_recv_buffers(data);
	}
}

static void data_xmit_complete(struct io *io)
{
	struct rdma_io *rdma_io = (struct rdma_io *)io;
	struct data *data = &io->viport->data;
	struct xmit_pool *pool = &data->xmit_pool;
	struct sk_buff *skb;

	DATA_FUNCTION("data_xmit_complete()\n");

	if (rdma_io->skb)
		dma_unmap_single(data->parent->config->ibdev->dma_device,
				 rdma_io->skb_data_dma, rdma_io->skb->len,
				 DMA_TO_DEVICE);

	while (pool->last_comp_buf != rdma_io->index) {
		INC(pool->last_comp_buf, 1, pool->num_xmit_bufs);
		skb = pool->xmit_bufs[pool->last_comp_buf].skb;
		if (skb)
			dev_kfree_skb_any(skb);
		pool->xmit_bufs[pool->last_comp_buf].skb = NULL;
	}

	data_check_xmit_buffers(data);
}
