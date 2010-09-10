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

#include <linux/string.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <rdma/ib_cache.h>

#include "vnic_util.h"
#include "vnic_config.h"
#include "vnic_ib.h"
#include "vnic_viport.h"
#include "vnic_sys.h"
#include "vnic_main.h"
#include "vnic_stats.h"

static int vnic_ib_inited = 0;

static void vnic_add_one(struct ib_device *device);
static void vnic_remove_one(struct ib_device *device);

static struct ib_client vnic_client = {
	.name = "vnic",
	.add = vnic_add_one,
	.remove = vnic_remove_one
};

static struct ib_sa_client vnic_sa_client;

static CLASS_DEVICE_ATTR(create_primary, S_IWUSR, NULL,
			 vnic_create_primary);
static CLASS_DEVICE_ATTR(create_secondary, S_IWUSR, NULL,
			 vnic_create_secondary);

static CLASS_DEVICE_ATTR(delete_vnic, S_IWUSR, NULL, vnic_delete);

static struct vnic_ib_port *vnic_add_port(struct vnic_ib_device *device,
					  u8 port_num)
{
	struct vnic_ib_port *port;

	port = kzalloc(sizeof *port, GFP_KERNEL);
	if (!port)
		return NULL;

	init_completion(&port->cdev_info.released);
	port->dev = device;
	port->port_num = port_num;

	port->cdev_info.class_dev.class = &vnic_class;
	port->cdev_info.class_dev.dev = device->dev->dma_device;
	snprintf(port->cdev_info.class_dev.class_id, BUS_ID_SIZE,
		 "vnic-%s-%d", device->dev->name, port_num);

	if (class_device_register(&port->cdev_info.class_dev))
		goto free_port;

	if (class_device_create_file(&port->cdev_info.class_dev,
				     &class_device_attr_create_primary))
		goto err_class;
	if (class_device_create_file(&port->cdev_info.class_dev,
				     &class_device_attr_create_secondary))
		goto err_class;

	return port;
err_class:
	class_device_unregister(&port->cdev_info.class_dev);
free_port:
	kfree(port);

	return NULL;
}

static void vnic_add_one(struct ib_device *device)
{
	struct vnic_ib_device *vnic_dev;
	struct vnic_ib_port *port;
	int s, e, p;

	vnic_dev = kmalloc(sizeof *vnic_dev, GFP_KERNEL);
	if (!vnic_dev)
		return;

	vnic_dev->dev = device;
	INIT_LIST_HEAD(&vnic_dev->port_list);

	if (device->node_type == RDMA_NODE_IB_SWITCH) {
		s = 0;
		e = 0;

	} else {
		s = 1;
		e = device->phys_port_cnt;

	}

	for (p = s; p <= e; p++) {
		port = vnic_add_port(vnic_dev, p);
		if (port)
			list_add_tail(&port->list, &vnic_dev->port_list);
	}

	ib_set_client_data(device, &vnic_client, vnic_dev);

}

static void vnic_remove_one(struct ib_device *device)
{
	struct vnic_ib_device *vnic_dev;
	struct vnic_ib_port *port, *tmp_port;

	vnic_dev = ib_get_client_data(device, &vnic_client);
	list_for_each_entry_safe(port, tmp_port,
				 &vnic_dev->port_list, list) {
		class_device_unregister(&port->cdev_info.class_dev);
		/*
		 * wait for sysfs entries to go away, so that no new vnics
		 * are created
		 */
		wait_for_completion(&port->cdev_info.released);
		kfree(port);

	}
	kfree(vnic_dev);
}

int vnic_ib_init(void)
{
	int ret = -1;

	IB_FUNCTION("vnic_ib_init()\n");

	/* class has to be registered before
	 * calling ib_register_client() because, that call
	 * will trigger vnic_add_port() which will register
	 * class_device for the port with the parent class
	 * as vnic_class
	 */
	ret = class_register(&vnic_class);
	if (ret) {
		printk(KERN_ERR PFX "couldn't register class"
		       " infiniband_vnic; error %d", ret);
		goto out;
	}

	ib_sa_register_client(&vnic_sa_client);
	ret = ib_register_client(&vnic_client);
	if (ret) {
		printk(KERN_ERR PFX "couldn't register IB client;"
		       " error %d", ret);
		goto err_ib_reg;
	}

	interface_cdev.class_dev.class = &vnic_class;
	snprintf(interface_cdev.class_dev.class_id,
		 BUS_ID_SIZE, "interfaces");
	init_completion(&interface_cdev.released);
	ret = class_device_register(&interface_cdev.class_dev);
	if (ret) {
		printk(KERN_ERR PFX "couldn't register class interfaces;"
		       " error %d", ret);
		goto err_class_dev;
	}
	ret = class_device_create_file(&interface_cdev.class_dev,
				       &class_device_attr_delete_vnic);
	if (ret) {
		printk(KERN_ERR PFX "couldn't create class file"
		       " 'delete_vnic'; error %d", ret);
		goto err_class_file;
	}

	vnic_ib_inited = 1;

	return ret;
err_class_file:
	class_device_unregister(&interface_cdev.class_dev);
err_class_dev:
	ib_unregister_client(&vnic_client);
err_ib_reg:
	ib_sa_unregister_client(&vnic_sa_client);
	class_unregister(&vnic_class);
out:
	return ret;
}

void vnic_ib_cleanup(void)
{
	IB_FUNCTION("vnic_ib_cleanup()\n");

	if (!vnic_ib_inited)
		return;

	class_device_unregister(&interface_cdev.class_dev);
	wait_for_completion(&interface_cdev.released);

	ib_unregister_client(&vnic_client);
	ib_sa_unregister_client(&vnic_sa_client);
	class_unregister(&vnic_class);
}

static void vnic_path_rec_completion(int status,
				     struct ib_sa_path_rec *pathrec,
				     void *context)
{
	struct vnic_ib_path_info *p = context;
	p->status = status;
	if (!status)
		p->path = *pathrec;

	complete(&p->done);
}

int vnic_ib_get_path(struct netpath *netpath, struct vnic * vnic)
{
	struct viport_config *config = netpath->viport->config;
	int ret = 0;

	init_completion(&config->path_info.done);
	IB_INFO("Using SA path rec get time out value of %d\n",
	       config->sa_path_rec_get_timeout);
	config->path_info.path_query_id =
			 ib_sa_path_rec_get(&vnic_sa_client,
					    config->ibdev,
					    config->port,
					    &config->path_info.path,
					    IB_SA_PATH_REC_DGID      |
					    IB_SA_PATH_REC_SGID      |
					    IB_SA_PATH_REC_NUMB_PATH |
					    IB_SA_PATH_REC_PKEY,
					    config->sa_path_rec_get_timeout,
					    GFP_KERNEL,
					    vnic_path_rec_completion,
					    &config->path_info,
					    &config->path_info.path_query);

	if (config->path_info.path_query_id < 0) {
		IB_ERROR("SA path record query failed; error %d\n",
			 config->path_info.path_query_id);
		ret= config->path_info.path_query_id;
		goto out;
	}

	wait_for_completion(&config->path_info.done);

	if (config->path_info.status < 0) {
		printk(KERN_WARNING PFX "path record query failed for dgid "
		       "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
		       (int)be16_to_cpu(*(__be16 *) &config->path_info.path.
					dgid.raw[0]),
		       (int)be16_to_cpu(*(__be16 *) &config->path_info.path.
					dgid.raw[2]),
		       (int)be16_to_cpu(*(__be16 *) &config->path_info.path.
					dgid.raw[4]),
		       (int)be16_to_cpu(*(__be16 *) &config->path_info.path.
					dgid.raw[6]),
		       (int)be16_to_cpu(*(__be16 *) &config->path_info.path.
					dgid.raw[8]),
		       (int)be16_to_cpu(*(__be16 *) &config->path_info.path.
					dgid.raw[10]),
		       (int)be16_to_cpu(*(__be16 *) &config->path_info.path.
					dgid.raw[12]),
		       (int)be16_to_cpu(*(__be16 *) &config->path_info.path.
					dgid.raw[14]));

		if (config->path_info.status == -ETIMEDOUT)
			printk(KERN_WARNING PFX
			       "reason: path record query timed out\n");
		else if (config->path_info.status == -EIO)
			printk(KERN_WARNING PFX
			       "reason: error in sending path record query\n");
		else
			printk(KERN_WARNING PFX "reason: error %d in sending"
			       " path record query\n",
			       config->path_info.status);

		ret = config->path_info.status;
	}
out:
	if (ret)
		netpath_timer(netpath, vnic->config->no_path_timeout);

	return ret;
}

static void ib_qp_event(struct ib_event *event, void *context)
{
	IB_ERROR("QP event %d\n", event->event);
}

static void vnic_ib_completion(struct ib_cq *cq, void *ptr)
{
	struct ib_wc wc;
	struct io *io;
	struct vnic_ib_conn *ib_conn = ptr;
	cycles_t           comp_time;
	u32              comp_num = 0;

	vnic_ib_note_comptime_stats(&comp_time);
	vnic_ib_callback_stats(ib_conn);

	ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	while (ib_poll_cq(cq, 1, &wc) > 0) {
		io = (struct io *)(wc.wr_id);
		vnic_ib_comp_stats(ib_conn, &comp_num);
		if (wc.status) {
#if 0
			IB_ERROR("completion error  wc.status %d"
				 " wc.opcode %d vendor err 0x%x\n",
				 wc.status, wc.opcode, wc.vendor_err);
#endif
		} else if (io) {
			vnic_ib_io_stats(io, ib_conn, comp_time);
			if (io->routine)
				(*io->routine) (io);
		}
	}
	vnic_ib_maxio_stats(ib_conn, comp_num);
}

static int vnic_ib_mod_qp_to_rts(struct ib_cm_id * cm_id,
			     struct vnic_ib_conn * ib_conn)
{
	int attr_mask = 0;
	int ret;
	struct ib_qp_attr *qp_attr = NULL;

	qp_attr = kmalloc(sizeof *qp_attr, GFP_KERNEL);
	if (!qp_attr)
		return -ENOMEM;

	qp_attr->qp_state = IB_QPS_RTR;

	if ((ret = ib_cm_init_qp_attr(cm_id, qp_attr, &attr_mask)))
		goto out;

	if((ret = ib_modify_qp(ib_conn->qp, qp_attr, attr_mask)))
		goto out;

	IB_INFO("QP RTR\n");

	qp_attr->qp_state = IB_QPS_RTS;

	if((ret = ib_cm_init_qp_attr(cm_id, qp_attr, &attr_mask)))
		goto out;

	if((ret=ib_modify_qp(ib_conn->qp, qp_attr, attr_mask)))
		goto out;

	IB_INFO("QP RTS\n");

	if((ret = ib_send_cm_rtu(cm_id, NULL, 0)))
		goto out;
out:
	kfree(qp_attr);
	return ret;
}

int vnic_ib_cm_handler(struct ib_cm_id *cm_id, struct ib_cm_event *event)
{
	struct vnic_ib_conn *ib_conn = cm_id->context;
	struct viport *viport = ib_conn->viport;
	int err = 0;
	int disconn = 0;

	switch (event->event) {
	case IB_CM_REQ_ERROR:
		IB_ERROR("sending CM REQ failed\n");
		err = 1;
		disconn = 1;
		break;
	case IB_CM_REP_RECEIVED:
		IB_INFO("CM REP recvd\n");
		if (vnic_ib_mod_qp_to_rts(cm_id, ib_conn))
			err = 1;
		else {
			ib_conn->state = IB_CONN_CONNECTED;
			vnic_ib_connected_time_stats(ib_conn);
			IB_INFO("RTU SENT\n");
		}
		break;
	case IB_CM_REJ_RECEIVED:
		printk(KERN_ERR PFX "CM rejected control connection \n");
		if (event->param.rej_rcvd.reason ==
		    IB_CM_REJ_INVALID_SERVICE_ID)
			printk(KERN_ERR "reason: invalid service ID. "
			       "IOCGUID value specified may be incorrect\n");
		else
			printk(KERN_ERR "reason code : 0x%x\n",
			       event->param.rej_rcvd.reason);

		err = 1;
		disconn = 1;
		break;
	case IB_CM_MRA_RECEIVED:
		IB_INFO("CM MRA received\n");
		break;

	case IB_CM_DREP_RECEIVED:
		IB_INFO("CM DREP recvd\n");
		ib_conn->state = IB_CONN_DISCONNECTED;
		break;

	case IB_CM_TIMEWAIT_EXIT:
		IB_ERROR("CM timewait exit\n");
		err = 1;
		break;

	default:
		IB_INFO("unhandled CM event %d\n", event->event);
		break;

	}

	if (disconn)
		viport->disconnect = 1;

	if (err) {
		ib_conn->state = IB_CONN_DISCONNECTED;
		viport_failure(viport);
	}

	viport_kick(viport);
	return 0;
}


int vnic_ib_cm_connect(struct vnic_ib_conn *ib_conn)
{
	struct ib_cm_req_param	*req = NULL;
	struct viport		*viport;
	int 			ret = -1;

	if (!vnic_ib_conn_initted(ib_conn)) {
		IB_ERROR("IB Connection out of state for CM connect (%d)\n",
			 ib_conn->state);
		return -EINVAL;
	}

	vnic_ib_conntime_stats(ib_conn);
	req = kzalloc(sizeof *req, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	viport	= ib_conn->viport;

	req->primary_path	= &viport->config->path_info.path;
	req->alternate_path	= NULL;
	req->qp_num		= ib_conn->qp->qp_num;
	req->qp_type		= ib_conn->qp->qp_type;
	req->service_id 	= ib_conn->ib_config->service_id;
	req->private_data	= &ib_conn->ib_config->conn_data;
	req->private_data_len	= sizeof(struct vnic_connection_data);
	req->flow_control	= 1;

	get_random_bytes(&req->starting_psn, 4);
	req->starting_psn &= 0xffffff;

	/*
	 * Both responder_resources and initiator_depth are set to zero
	 * as we do not need RDMA read.
	 *
	 * They also must be set to zero, otherwise data connections
	 * are rejected by VEx.
	 */
	req->responder_resources 	= 0;
	req->initiator_depth		= 0;
	req->remote_cm_response_timeout = 20;
	req->local_cm_response_timeout  = 20;
	req->retry_count		= ib_conn->ib_config->retry_count;
	req->rnr_retry_count		= ib_conn->ib_config->rnr_retry_count;
	req->max_cm_retries		= 15;

	ib_conn->state = IB_CONN_CONNECTING;

	ret = ib_send_cm_req(ib_conn->cm_id, req);

	kfree(req);

	if (ret) {
		IB_ERROR("CM REQ sending failed; error %d \n", ret);
		ib_conn->state = IB_CONN_DISCONNECTED;
	}

	return ret;
}

static int vnic_ib_init_qp(struct vnic_ib_conn * ib_conn,
			   struct vnic_ib_config *config,
			   struct ib_pd	*pd,
			   struct viport_config * viport_config)
{
	struct ib_qp_init_attr	*init_attr;
	struct ib_qp_attr	*attr;
	int			ret;

	init_attr = kzalloc(sizeof *init_attr, GFP_KERNEL);
	if (!init_attr)
		return -ENOMEM;

	init_attr->event_handler	= ib_qp_event;
	init_attr->cap.max_send_wr	= config->num_sends;
	init_attr->cap.max_recv_wr	= config->num_recvs;
	init_attr->cap.max_recv_sge	= config->recv_scatter;
	init_attr->cap.max_send_sge	= config->send_gather;
	init_attr->sq_sig_type		= IB_SIGNAL_ALL_WR;
	init_attr->qp_type		= IB_QPT_RC;
	init_attr->send_cq		= ib_conn->cq;
	init_attr->recv_cq		= ib_conn->cq;

	ib_conn->qp = ib_create_qp(pd, init_attr);

	if (IS_ERR(ib_conn->qp)) {
		ret = -1;
		IB_ERROR("could not create QP\n");
		goto free_init_attr;
	}

	attr = kmalloc(sizeof *attr, GFP_KERNEL);
	if (!attr) {
		ret = -ENOMEM;
		goto destroy_qp;
	}

	ret = ib_find_cached_pkey(viport_config->ibdev,
				  viport_config->port,
				  be16_to_cpu(viport_config->path_info.path.
					      pkey),
				  &attr->pkey_index);
	if (ret) {
		printk(KERN_WARNING PFX "ib_find_cached_pkey() failed; "
		       "error %d\n", ret);
		goto freeattr;
	}

	attr->qp_state		= IB_QPS_INIT;
	attr->qp_access_flags	= IB_ACCESS_REMOTE_WRITE;
	attr->port_num		= viport_config->port;

	ret = ib_modify_qp(ib_conn->qp, attr,
			   IB_QP_STATE |
			   IB_QP_PKEY_INDEX |
			   IB_QP_ACCESS_FLAGS | IB_QP_PORT);
	if (ret) {
		printk(KERN_WARNING PFX "could not modify QP; error %d \n",
		       ret);
		goto freeattr;
	}

	kfree(attr);
	kfree(init_attr);
	return ret;

freeattr:
	kfree(attr);
destroy_qp:
	ib_destroy_qp(ib_conn->qp);
free_init_attr:
	kfree(init_attr);
	return ret;
}

int vnic_ib_conn_init(struct vnic_ib_conn *ib_conn, struct viport *viport,
		      struct ib_pd *pd, struct vnic_ib_config *config)
{
	struct viport_config	*viport_config = viport->config;
	int		ret = -1;
	unsigned int	cq_size = config->num_sends + config->num_recvs;


	if (!vnic_ib_conn_uninitted(ib_conn)) {
		IB_ERROR("IB Connection out of state for init (%d)\n",
			 ib_conn->state);
		return -EINVAL;
	}

	ib_conn->cq = ib_create_cq(viport_config->ibdev, vnic_ib_completion,
				   NULL, ib_conn, cq_size);
	if (IS_ERR(ib_conn->cq)) {
		IB_ERROR("could not create CQ\n");
		goto out;
	}

	ib_req_notify_cq(ib_conn->cq, IB_CQ_NEXT_COMP);

	ret = vnic_ib_init_qp(ib_conn, config, pd, viport_config);

	if(ret)
		goto destroy_cq;

	ib_conn->conn_lock  = SPIN_LOCK_UNLOCKED;
	ib_conn->state = IB_CONN_INITTED;

	return ret;

destroy_cq:
	ib_destroy_cq(ib_conn->cq);
out:
	return ret;
}

int vnic_ib_post_recv(struct vnic_ib_conn * ib_conn, struct io * io)
{
	cycles_t		post_time;
	struct ib_recv_wr	*bad_wr;
	int			ret = -1;
	unsigned long		flags;

	IB_FUNCTION("vnic_ib_post_recv()\n");

	spin_lock_irqsave(&ib_conn->conn_lock, flags);

	if (!vnic_ib_conn_initted(ib_conn) &&
	    !vnic_ib_conn_connected(ib_conn))
		return -EINVAL;

	vnic_ib_pre_rcvpost_stats(ib_conn, io, &post_time);
	io->type = RECV;
	ret = ib_post_recv(ib_conn->qp, &io->rwr, &bad_wr);
	if (ret) {
		IB_ERROR("error in posting rcv wr; error %d\n", ret);
		goto out;
	}

	vnic_ib_post_rcvpost_stats(ib_conn, post_time);
out:
	spin_unlock_irqrestore(&ib_conn->conn_lock, flags);
	return ret;

}

int vnic_ib_post_send(struct vnic_ib_conn * ib_conn, struct io * io)
{
	cycles_t		post_time;
	unsigned long		flags;
	struct ib_send_wr	*bad_wr;
	int			ret = -1;

	IB_FUNCTION("vnic_ib_post_send()\n");

	spin_lock_irqsave(&ib_conn->conn_lock, flags);
	if (!vnic_ib_conn_connected(ib_conn)) {
		IB_ERROR("IB Connection out of state for"
			 " posting sends (%d)\n", ib_conn->state);
		goto out;
	}

	vnic_ib_pre_sendpost_stats(io, &post_time);
	if (io->swr.opcode == IB_WR_RDMA_WRITE)
		io->type = RDMA;
	else
		io->type = SEND;

	ret = ib_post_send(ib_conn->qp, &io->swr, &bad_wr);
	if (ret) {
		IB_ERROR("error in posting send wr; error %d\n", ret);
		goto out;
	}

	vnic_ib_post_sendpost_stats(ib_conn, io, post_time);
out:
	spin_unlock_irqrestore(&ib_conn->conn_lock, flags);
	return ret;
}
