/*
 * Copyright (c) 2006 Intel Corporation.  All rights reserved.
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

#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/pci.h>

#include <rdma/ib_cache.h>
#include <rdma/ib_local_sa.h>

MODULE_AUTHOR("Sean Hefty");
MODULE_DESCRIPTION("InfiniBand subnet administration caching");
MODULE_LICENSE("Dual BSD/GPL");

static int retry_timer = 5000; /* 5 sec */
module_param(retry_timer, int, 0444);
MODULE_PARM_DESC(retry_timer, "Time in ms between retried requests.");

static int retries = 3;
module_param(retries, int, 0444);
MODULE_PARM_DESC(retries, "Number of times to retry a request.");

static unsigned long cache_timeout = 15 * 60 * 1000; /* 15 min */
module_param(cache_timeout, ulong, 0444);
MODULE_PARM_DESC(cache_timeout, "Time in ms between cache updates.  "
				"Set to 0 to disable cache.");

static unsigned long hold_time = 30 * 1000; /* 30 sec */
module_param(hold_time, ulong, 0444);
MODULE_PARM_DESC(hold_timer, "Minimal time in ms between cache updates.");

static unsigned long update_delay = 3000; /* 3 sec */
module_param(update_delay, ulong, 0444);
MODULE_PARM_DESC(update_delay, "Delay in ms between an event and an update.");

enum {
	IB_MAX_PATHS_PER_DEST = 0x7F
};

static unsigned long paths_per_dest = IB_MAX_PATHS_PER_DEST;
module_param(paths_per_dest, ulong, 0444);
MODULE_PARM_DESC(paths_per_dest, "Maximum number of paths to retrieve "
				 "to each destination (DGID).  Set to 0 "
				 "to disable cache.");

static void sa_db_add_one(struct ib_device *device);
static void sa_db_remove_one(struct ib_device *device);

static struct ib_client sa_db_client = {
	.name   = "local_sa",
	.add    = sa_db_add_one,
	.remove = sa_db_remove_one
};

static LIST_HEAD(dev_list);
static DECLARE_RWSEM(lock);
static unsigned long hold_time, update_delay;
static struct workqueue_struct *sa_wq;

struct sa_db_port {
	struct sa_db_device *dev;
	struct ib_mad_agent *agent;
	struct rb_root paths;
	unsigned long update_time;
	int update;
	struct work_struct work;
	union ib_gid gid;
	int port_num;
};

struct sa_db_device {
	struct list_head list;
	struct ib_device *device;
	struct ib_event_handler event_handler;
	struct sa_db_port port[0];
};

struct ib_sa_iterator {
	struct ib_sa_iterator	*next;
};

struct ib_sa_attr_list {
	struct ib_sa_iterator	iter;
	struct ib_sa_iterator	*tail;
	int			update;
	union ib_gid		gid;
	struct rb_node		node;
};

struct ib_path_rec_info {
	struct ib_sa_iterator	iter;	/* keep first for ib_get_next_sa_attr */
	struct ib_sa_path_rec	rec;
};

struct ib_sa_iter {
	struct ib_mad_recv_wc *recv_wc;
	struct ib_mad_recv_buf *recv_buf;
	int attr_size;
	int attr_offset;
	int data_offset;
	int data_left;
	void *attr;
	u8 attr_data[0];
};

static void send_handler(struct ib_mad_agent *agent,
			 struct ib_mad_send_wc *mad_send_wc)
{
	ib_destroy_ah(mad_send_wc->send_buf->ah);
	ib_free_send_mad(mad_send_wc->send_buf);
}

static void free_attr_list(struct ib_sa_attr_list *attr_list)
{
	struct ib_sa_iterator *cur;

	for (cur = attr_list->iter.next; cur; cur = attr_list->iter.next) {
		attr_list->iter.next = cur->next;
		kfree(cur);
	}
	attr_list->tail = &attr_list->iter;
}

static void remove_all_attrs(struct rb_root *root)
{
	struct rb_node *node, *next_node;
	struct ib_sa_attr_list *attr_list;

	for (node = rb_first(root); node; node = next_node) {
		next_node = rb_next(node);
		rb_erase(node, root);
		attr_list = rb_entry(node, struct ib_sa_attr_list, node);
		free_attr_list(attr_list);
		kfree(attr_list);
	}
}

static struct ib_sa_attr_list * insert_attr_list(struct rb_root *root,
						 struct ib_sa_attr_list
							*attr_list)
{
	struct rb_node **link = &root->rb_node;
	struct rb_node *parent = NULL;
	struct ib_sa_attr_list *cur_attr_list;
	int cmp;

	while (*link) {
		parent = *link;
		cur_attr_list = rb_entry(parent, struct ib_sa_attr_list, node);
		cmp = memcmp(&cur_attr_list->gid, &attr_list->gid,
			     sizeof attr_list->gid);
		if (cmp < 0)
			link = &(*link)->rb_left;
		else if (cmp > 0)
			link = &(*link)->rb_right;
		else
			return cur_attr_list;
	}
	rb_link_node(&attr_list->node, parent, link);
	rb_insert_color(&attr_list->node, root);
	return NULL;
}

static struct ib_sa_attr_list * find_attr_list(struct rb_root *root,
					       u8 *gid)
{
	struct rb_node *node = root->rb_node;
	struct ib_sa_attr_list *attr_list;
	int cmp;

	while (node) {
		attr_list = rb_entry(node, struct ib_sa_attr_list, node);
		cmp = memcmp(&attr_list->gid, gid, sizeof attr_list->gid);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else
			return attr_list;
	}
	return NULL;
}

static int insert_attr(struct rb_root *root, int update, void *key,
		       struct ib_sa_iterator *iter)
{
	struct ib_sa_attr_list *attr_list;
	void *err;

	attr_list = find_attr_list(root, key);
	if (!attr_list) {
		attr_list = kmalloc(sizeof *attr_list, GFP_KERNEL);
		if (!attr_list)
			return -ENOMEM;

		attr_list->iter.next = NULL;
		attr_list->tail = &attr_list->iter;
		attr_list->update = update;
		memcpy(attr_list->gid.raw, key, sizeof attr_list->gid);

		err = insert_attr_list(root, attr_list);
		if (err) {
			kfree(attr_list);
			return PTR_ERR(err);
		}
	} else if (attr_list->update != update) {
		free_attr_list(attr_list);
		attr_list->update = update;
	}

	/*
	 * Assume that the SA returned the best attribute first, and insert
	 * attributes on the tail.
	 */
	attr_list->tail->next = iter;
	iter->next = NULL;
	attr_list->tail = iter;
	return 0;
}

static struct ib_sa_iter *ib_sa_iter_create(struct ib_mad_recv_wc *mad_recv_wc)
{
	struct ib_sa_iter *iter;
	struct ib_sa_mad *mad = (struct ib_sa_mad *) mad_recv_wc->recv_buf.mad;
	int attr_size, attr_offset;

	attr_offset = be16_to_cpu(mad->sa_hdr.attr_offset) * 8;
	attr_size = 64;		/* path record length */
	if (attr_offset < attr_size)
		return ERR_PTR(-EINVAL);

	iter = kzalloc(sizeof *iter + attr_size, GFP_KERNEL);
	if (!iter)
		return ERR_PTR(-ENOMEM);

	iter->data_left = mad_recv_wc->mad_len - IB_MGMT_SA_HDR;
	iter->recv_wc = mad_recv_wc;
	iter->recv_buf = &mad_recv_wc->recv_buf;
	iter->attr_offset = attr_offset;
	iter->attr_size = attr_size;
	return iter;
}

static void ib_sa_iter_free(struct ib_sa_iter *iter)
{
	kfree(iter);
}

static void *ib_sa_iter_next(struct ib_sa_iter *iter)
{
	struct ib_sa_mad *mad;
	int left, offset = 0;

	while (iter->data_left >= iter->attr_offset) {
		while (iter->data_offset < IB_MGMT_SA_DATA) {
			mad = (struct ib_sa_mad *) iter->recv_buf->mad;

			left = IB_MGMT_SA_DATA - iter->data_offset;
			if (left < iter->attr_size) {
				/* copy first piece of the attribute */
				iter->attr = &iter->attr_data;
				memcpy(iter->attr,
				       &mad->data[iter->data_offset], left);
				offset = left;
				break;
			} else if (offset) {
				/* copy the second piece of the attribute */
				memcpy(iter->attr + offset, &mad->data[0],
				       iter->attr_size - offset);
				iter->data_offset = iter->attr_size - offset;
				offset = 0;
			} else {
				iter->attr = &mad->data[iter->data_offset];
				iter->data_offset += iter->attr_size;
			}

			iter->data_left -= iter->attr_offset;
			goto out;
		}
		iter->data_offset = 0;
		iter->recv_buf = list_entry(iter->recv_buf->list.next,
					    struct ib_mad_recv_buf, list);
	}
	iter->attr = NULL;
out:
	return iter->attr;
}

/*
 * Copy a path record from a received MAD and insert it into our index.
 * The path record in the MAD is in network order, so must be swapped.  It
 * can also span multiple MADs, just to make our life hard.
 */
static void update_path_rec(struct sa_db_port *port,
			    struct ib_mad_recv_wc *mad_recv_wc)
{
	struct ib_sa_iter *iter;
	struct ib_path_rec_info *path_info;
	void *attr;

	iter = ib_sa_iter_create(mad_recv_wc);
	if (IS_ERR(iter))
		return;

	down_write(&lock);
	port->update++;
	while ((attr = ib_sa_iter_next(iter)) &&
	       (path_info = kmalloc(sizeof *path_info, GFP_KERNEL))) {

		ib_sa_unpack_attr(&path_info->rec, attr, IB_SA_ATTR_PATH_REC);
		if (insert_attr(&port->paths, port->update,
				path_info->rec.dgid.raw,
				&path_info->iter)) {
			kfree(path_info);
			break;
		}
	}
	up_write(&lock);
	ib_sa_iter_free(iter);
}

static void recv_handler(struct ib_mad_agent *mad_agent,
			 struct ib_mad_recv_wc *mad_recv_wc)
{
	struct ib_sa_mad *mad = (void *) mad_recv_wc->recv_buf.mad;

	if (mad->mad_hdr.status)
		goto done;

	switch (cpu_to_be16(mad->mad_hdr.attr_id)) {
	case IB_SA_ATTR_PATH_REC:
		update_path_rec(mad_agent->context, mad_recv_wc);
		break;
	default:
		break;
	}
done:
	ib_free_recv_mad(mad_recv_wc);
}

static struct ib_mad_send_buf* get_sa_msg(struct sa_db_port *port)
{
	struct ib_port_attr	port_attr;
	struct ib_ah_attr	ah_attr;
	struct ib_mad_send_buf	*msg;
	int ret;

	ret = ib_query_port(port->dev->device, port->port_num, &port_attr);
	if (ret || port_attr.state != IB_PORT_ACTIVE)
		return NULL;

	msg = ib_create_send_mad(port->agent, 1, 0, 0, IB_MGMT_SA_HDR,
				 IB_MGMT_SA_DATA, GFP_KERNEL);
	if (IS_ERR(msg))
		return NULL;

	memset(&ah_attr, 0, sizeof ah_attr);
	ah_attr.dlid = port_attr.sm_lid;
	ah_attr.sl = port_attr.sm_sl;
	ah_attr.port_num = port->port_num;

	msg->ah = ib_create_ah(port->agent->qp->pd, &ah_attr);
	if (IS_ERR(msg->ah)) {
		ib_free_send_mad(msg);
		return NULL;
	}

	msg->timeout_ms = retry_timer;
	msg->retries = retries;
	msg->context[0] = port;
	return msg;
}

static __be64 form_tid(u32 hi_tid)
{
	static atomic_t tid;
	return cpu_to_be64((((u64) hi_tid) << 32) |
			   ((u32) atomic_inc_return(&tid)));
}

static void format_path_req(struct sa_db_port *port,
			    struct ib_mad_send_buf *msg)
{
	struct ib_sa_mad *mad = msg->mad;
	struct ib_sa_path_rec path_rec;

	mad->mad_hdr.base_version  = IB_MGMT_BASE_VERSION;
	mad->mad_hdr.mgmt_class	   = IB_MGMT_CLASS_SUBN_ADM;
	mad->mad_hdr.class_version = IB_SA_CLASS_VERSION;
	mad->mad_hdr.method	   = IB_SA_METHOD_GET_TABLE;
	mad->mad_hdr.attr_id	   = cpu_to_be16(IB_SA_ATTR_PATH_REC);
	mad->mad_hdr.tid	   = form_tid(msg->mad_agent->hi_tid);

	mad->sa_hdr.comp_mask = IB_SA_PATH_REC_SGID | IB_SA_PATH_REC_NUMB_PATH;

	path_rec.sgid = port->gid;
	path_rec.numb_path = paths_per_dest;
	ib_sa_pack_attr(mad->data, &path_rec, IB_SA_ATTR_PATH_REC);
}

static void update_cache(void *_port)
{
	struct sa_db_port *port = (struct sa_db_port *)_port;
	struct ib_mad_send_buf *msg;

	msg = get_sa_msg(port);
	if (!msg)
		return;

	format_path_req(port, msg);

	if (ib_post_send_mad(msg, NULL)) {
		ib_destroy_ah(msg->ah);
		ib_free_send_mad(msg);
		return;
	}

	/*
	 * We record the time that we requested the update, rather than use the
	 * time that the update occurred.  This allows us to generate a new
	 * update if an event occurs while we're still processing this one.
	 */
	port->update_time = jiffies;
	queue_delayed_work(sa_wq, &port->work, cache_timeout);
}

static void schedule_update(struct sa_db_port *port)
{
	unsigned long time, delay;

	if (!paths_per_dest)
		return;

	time = jiffies;
	if (time_after(time, port->update_time + hold_time))
		delay = update_delay;
	else
		delay = port->update_time + hold_time - time;

	cancel_delayed_work(&port->work);
	queue_delayed_work(sa_wq, &port->work, delay);
}

static void handle_event(struct ib_event_handler *event_handler,
			 struct ib_event *event)
{
	struct sa_db_device *dev;
	dev = container_of(event_handler, typeof(*dev), event_handler);

	if (event->event == IB_EVENT_PORT_ERR    ||
	    event->event == IB_EVENT_PORT_ACTIVE ||
	    event->event == IB_EVENT_LID_CHANGE  ||
	    event->event == IB_EVENT_PKEY_CHANGE ||
	    event->event == IB_EVENT_SM_CHANGE	 ||
	    event->event == IB_EVENT_CLIENT_REREGISTER)
		schedule_update(&dev->port[event->element.port_num - 1]);
}

int ib_get_path_rec(struct ib_device *device, u8 port_num, union ib_gid *sgid,
		    union ib_gid *dgid, u16 pkey, struct ib_sa_path_rec *rec)
{
	struct ib_sa_iterator *iter;
	struct ib_sa_path_rec *path;
	int ret = -ENODATA;

	iter = ib_create_path_iter(device, port_num, dgid);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	for (path = ib_get_next_sa_attr(&iter); path;
	     path = ib_get_next_sa_attr(&iter)) {
		if (pkey == path->pkey &&
		    !memcmp(sgid, path->sgid.raw, sizeof *sgid)) {
			memcpy(rec, path, sizeof *rec);
			ret = 0;
			break;
		    }
	}

	ib_free_sa_iter(iter);
	return ret;
}
EXPORT_SYMBOL(ib_get_path_rec);

struct ib_sa_iterator *ib_create_path_iter(struct ib_device *device,
					   u8 port_num, union ib_gid *dgid)
{
	struct sa_db_device *dev;
	struct sa_db_port *port;
	struct ib_sa_attr_list *list;
	int ret;

	down_read(&lock);
	dev = ib_get_client_data(device, &sa_db_client);
	if (!dev) {
		ret = -ENODEV;
		goto err;
	}
	port = &dev->port[port_num - 1];

	list = find_attr_list(&port->paths, dgid->raw);
	if (!list) {
		ret = -ENODATA;
		goto err;
	}

	return &list->iter;
err:
	up_read(&lock);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(ib_create_path_iter);

void ib_free_sa_iter(struct ib_sa_iterator *iter)
{
	up_read(&lock);
}
EXPORT_SYMBOL(ib_free_sa_iter);

void *ib_get_next_sa_attr(struct ib_sa_iterator **iter)
{
	*iter = (*iter)->next;
	if (*iter)
		return ((void *)(*iter)) + sizeof(**iter);
	else
		return NULL;
}
EXPORT_SYMBOL(ib_get_next_sa_attr);

static void sa_db_add_one(struct ib_device *device)
{
	struct sa_db_device *dev;
	struct sa_db_port *port;
	int i;

	if (rdma_node_get_transport(device->node_type) != RDMA_TRANSPORT_IB)
		return;

	dev = kmalloc(sizeof *dev + device->phys_port_cnt * sizeof *port,
		      GFP_KERNEL);
	if (!dev)
		return;

	for (i = 1; i <= device->phys_port_cnt; i++) {
		port = &dev->port[i-1];
		port->dev = dev;
		port->port_num = i;
		port->update_time = jiffies - hold_time;
		port->update = 0;
		INIT_WORK(&port->work, update_cache, port);
		port->paths = RB_ROOT;

		if (ib_get_cached_gid(device, i, 0, &port->gid))
			goto err;

		port->agent = ib_register_mad_agent(device, i, IB_QPT_GSI,
						    NULL, IB_MGMT_RMPP_VERSION,
						    send_handler, recv_handler,
						    port);
		if (IS_ERR(port->agent))
			goto err;
	}

	dev->device = device;
	ib_set_client_data(device, &sa_db_client, dev);

	down_write(&lock);
	list_add_tail(&dev->list, &dev_list);
	up_write(&lock);

	/* Initialization must be complete before cache updates can occur. */
	INIT_IB_EVENT_HANDLER(&dev->event_handler, device, handle_event);
	ib_register_event_handler(&dev->event_handler);

	/* Force an update now. */
	for (i = 1; i <= device->phys_port_cnt; i++)
		schedule_update(&dev->port[i-1]);
	return;
err:
	while (--i) {
		ib_unregister_mad_agent(dev->port[i-1].agent);
		remove_all_attrs(&dev->port[i-1].paths);
	}
	kfree(dev);
}

static void sa_db_remove_one(struct ib_device *device)
{
	struct sa_db_device *dev;
	int i;

	dev = ib_get_client_data(device, &sa_db_client);
	if (!dev)
		return;

	ib_unregister_event_handler(&dev->event_handler);
	for (i = 0; i < device->phys_port_cnt; i++)
		cancel_delayed_work(&dev->port[i].work);
	flush_workqueue(sa_wq);

	for (i = 0; i < device->phys_port_cnt; i++) {
		ib_unregister_mad_agent(dev->port[i].agent);
		remove_all_attrs(&dev->port[i].paths);
	}

	down_write(&lock);
	list_del(&dev->list);
	up_write(&lock);
	kfree(dev);
}

static int __init sa_db_init(void)
{
	int ret;

	cache_timeout = msecs_to_jiffies(cache_timeout);
	hold_time = msecs_to_jiffies(hold_time);
	update_delay = msecs_to_jiffies(update_delay);

	if (!cache_timeout)
		paths_per_dest = 0;
	else if (paths_per_dest > IB_MAX_PATHS_PER_DEST)
		paths_per_dest = IB_MAX_PATHS_PER_DEST;

	sa_wq = create_singlethread_workqueue("local_sa");
	if (!sa_wq)
		return -ENOMEM;

	ret = ib_register_client(&sa_db_client);
	if (ret)
		goto err;
	return 0;

err:
	destroy_workqueue(sa_wq);
	return ret;
}

static void __exit sa_db_cleanup(void)
{
	ib_unregister_client(&sa_db_client);
	destroy_workqueue(sa_wq);
}

module_init(sa_db_init);
module_exit(sa_db_cleanup);
