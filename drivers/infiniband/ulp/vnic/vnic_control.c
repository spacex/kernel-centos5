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

#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/vmalloc.h>

#include "vnic_util.h"
#include "vnic_main.h"
#include "vnic_viport.h"
#include "vnic_control.h"
#include "vnic_config.h"
#include "vnic_control_pkt.h"
#include "vnic_stats.h"

static void control_log_control_packet(struct vnic_control_packet *pkt);

static inline char *control_ifcfg_name(struct control *control)
{
	if (!control)
		return "nctl";
	if (!control->parent)
		return "np";
	if (!control->parent->parent)
		return "npp";
	if (!control->parent->parent->parent)
		return "nppp";
	if (!control->parent->parent->parent->config)
		return "npppc";
	return (control->parent->parent->parent->config->name);
}

static void control_recv(struct control *control, struct recv_io *recv_io)
{
	if (vnic_ib_post_recv(&control->ib_conn, &recv_io->io))
		viport_failure(control->parent);
}

static void control_recv_complete(struct io *io)
{
	struct recv_io			*recv_io = (struct recv_io *)io;
	struct recv_io			*last_recv_io;
	struct control			*control = &io->viport->control;
	struct vnic_control_packet	*pkt = control_packet(recv_io);
	struct vnic_control_header	*c_hdr = &pkt->hdr;
	unsigned long			flags;
	cycles_t			response_time;

	CONTROL_FUNCTION("%s: control_recv_complete()\n",
			 control_ifcfg_name(control));

	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->recv_dma, control->recv_len,
				DMA_FROM_DEVICE);
	control_note_rsptime_stats(&response_time);
	CONTROL_PACKET(pkt);
	spin_lock_irqsave(&control->io_lock, flags);
	if (c_hdr->pkt_type == TYPE_INFO) {
		last_recv_io = control->info;
		control->info = recv_io;
		spin_unlock_irqrestore(&control->io_lock, flags);
		viport_kick(control->parent);
		if (last_recv_io)
			control_recv(control, last_recv_io);
	} else if (c_hdr->pkt_type == TYPE_RSP) {
		if (control->rsp_expected
		    && (c_hdr->pkt_seq_num == control->seq_num)) {
			control->response = recv_io;
			control->rsp_expected = 0;
			spin_unlock_irqrestore(&control->io_lock, flags);
			control_update_rsptime_stats(control,
						     response_time);
			viport_kick(control->parent);
		} else {
			spin_unlock_irqrestore(&control->io_lock, flags);
			control_recv(control, recv_io);
		}
	} else {
		list_add_tail(&recv_io->io.list_ptrs,
			      &control->failure_list);
		spin_unlock_irqrestore(&control->io_lock, flags);
		viport_kick(control->parent);
	}
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
}

static void control_timeout(unsigned long data)
{
	struct control *control;

	control = (struct control *)data;
	CONTROL_FUNCTION("%s: control_timeout()\n",
			 control_ifcfg_name(control));
	control->timer_state = TIMER_EXPIRED;
	control->rsp_expected = 0;
	viport_kick(control->parent);
}

static void control_timer(struct control *control, int timeout)
{
	CONTROL_FUNCTION("%s: control_timer()\n",
			 control_ifcfg_name(control));
	if (control->timer_state == TIMER_ACTIVE)
		mod_timer(&control->timer, jiffies + timeout);
	else {
		init_timer(&control->timer);
		control->timer.expires = jiffies + timeout;
		control->timer.data = (unsigned long)control;
		control->timer.function = control_timeout;
		control->timer_state = TIMER_ACTIVE;
		add_timer(&control->timer);
	}
}

static void control_timer_stop(struct control *control)
{
	CONTROL_FUNCTION("%s: control_timer_stop()\n",
			 control_ifcfg_name(control));
	if (control->timer_state == TIMER_ACTIVE)
		del_timer_sync(&control->timer);

	control->timer_state = TIMER_IDLE;
}

static int control_send(struct control *control, struct send_io *send_io)
{
	CONTROL_FUNCTION("%s: control_send()\n",
			 control_ifcfg_name(control));
	if (control->req_outstanding) {
		CONTROL_ERROR("%s: IB send never completed\n",
			      control_ifcfg_name(control));
		goto out;
	}

	control->req_outstanding = 1;
	control_timer(control, control->config->rsp_timeout);
	control_note_reqtime_stats(control);
	if (vnic_ib_post_send(&control->ib_conn, &control->send_io.io)) {
		CONTROL_ERROR("failed to post send\n");
		control->req_outstanding = 0;
		goto out;
	}

	return 0;
out:
	viport_failure(control->parent);
	return -1;

}

static void control_send_complete(struct io *io)
{
	struct control *control = &io->viport->control;

	CONTROL_FUNCTION("%s: control_send_complete()\n",
			 control_ifcfg_name(control));
	control->req_outstanding = 0;
}

void control_process_async(struct control *control)
{
	struct recv_io			*recv_io;
	struct vnic_control_packet	*pkt;
	unsigned long			flags;

	CONTROL_FUNCTION("%s: control_process_async()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->recv_dma, control->recv_len,
				DMA_FROM_DEVICE);

	spin_lock_irqsave(&control->io_lock, flags);
	recv_io = control->info;
	if (recv_io) {
		CONTROL_INFO("%s: processing info packet\n",
			     control_ifcfg_name(control));
		control->info = NULL;
		spin_unlock_irqrestore(&control->io_lock, flags);
		pkt = control_packet(recv_io);
		if (pkt->hdr.pkt_cmd == CMD_REPORT_STATUS) {
			u32		status;
			status =
			  be32_to_cpu(pkt->cmd.report_status.status_number);
			switch (status) {
			case VNIC_STATUS_LINK_UP:
				CONTROL_INFO("%s: link up\n",
					     control_ifcfg_name(control));
				vnic_link_up(control->parent->vnic,
					     control->parent->parent);
				break;
			case VNIC_STATUS_LINK_DOWN:
				CONTROL_INFO("%s: link down\n",
					     control_ifcfg_name(control));
				vnic_link_down(control->parent->vnic,
					       control->parent->parent);
				break;
			default:
				CONTROL_ERROR("%s: asynchronous status"
					      " received from EIOC\n",
					      control_ifcfg_name(control));
				control_log_control_packet(pkt);
				break;
			}
		}
		if ((pkt->hdr.pkt_cmd != CMD_REPORT_STATUS) ||
		     pkt->cmd.report_status.is_fatal) {
			viport_failure(control->parent);
		}
		control_recv(control, recv_io);
		spin_lock_irqsave(&control->io_lock, flags);
	}

	while (!list_empty(&control->failure_list)) {
		CONTROL_INFO("%s: processing error packet\n",
			     control_ifcfg_name(control));
		recv_io = (struct recv_io *)
		    list_entry(control->failure_list.next, struct io,
			       list_ptrs);
		list_del(&recv_io->io.list_ptrs);
		spin_unlock_irqrestore(&control->io_lock, flags);
		pkt = control_packet(recv_io);
		CONTROL_ERROR("%s: asynchronous error received from EIOC\n",
			      control_ifcfg_name(control));
		control_log_control_packet(pkt);
		if ((pkt->hdr.pkt_type != TYPE_ERR)
		    || (pkt->hdr.pkt_cmd != CMD_REPORT_STATUS)
		    || pkt->cmd.report_status.is_fatal) {
			viport_failure(control->parent);
		}
		control_recv(control, recv_io);
		spin_lock_irqsave(&control->io_lock, flags);
	}
	spin_unlock_irqrestore(&control->io_lock, flags);
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);

	CONTROL_INFO("%s: done control_process_async\n",
		     control_ifcfg_name(control));
}

static struct send_io *control_init_hdr(struct control *control, u8 cmd)
{
	struct control_config		*config;
	struct vnic_control_packet	*pkt;
	struct vnic_control_header	*hdr;

	CONTROL_FUNCTION("control_init_hdr()\n");
	config = control->config;

	pkt = control_packet(&control->send_io);
	hdr = &pkt->hdr;

	hdr->pkt_type = TYPE_REQ;
	hdr->pkt_cmd = cmd;
	control->seq_num++;
	hdr->pkt_seq_num = control->seq_num;
	control->req_retry_counter = 0;
	hdr->pkt_retry_count = control->req_retry_counter;

	return &control->send_io;
}

static struct recv_io *control_get_rsp(struct control *control)
{
	struct recv_io	*recv_io;
	unsigned long	flags;

	CONTROL_FUNCTION("%s: control_get_rsp()\n",
			 control_ifcfg_name(control));
	spin_lock_irqsave(&control->io_lock, flags);
	recv_io = control->response;
	if (recv_io) {
		control_timer_stop(control);
		control->response = NULL;
		spin_unlock_irqrestore(&control->io_lock, flags);
		return recv_io;
	}
	spin_unlock_irqrestore(&control->io_lock, flags);
	if (control->timer_state == TIMER_EXPIRED) {
		struct vnic_control_packet *pkt =
		    control_packet(&control->send_io);
		struct vnic_control_header *hdr = &pkt->hdr;

		control->timer_state = TIMER_IDLE;
		CONTROL_ERROR("%s: no response received from EIOC\n",
			      control_ifcfg_name(control));
		control_timeout_stats(control);
		control->req_retry_counter++;
		if (control->req_retry_counter >=
		    control->config->req_retry_count) {
			CONTROL_ERROR("%s: control packet retry exceeded\n",
				      control_ifcfg_name(control));
			viport_failure(control->parent);
		} else {
			hdr->pkt_retry_count =
			    control->req_retry_counter;
			control_send(control, &control->send_io);
		}
	}

	return NULL;
}

int control_init_vnic_req(struct control *control)
{
	struct send_io			*send_io;
	struct control_config		*config = control->config;
	struct vnic_control_packet	*pkt;
	struct vnic_cmd_init_vnic_req	*init_vnic_req;

	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->send_dma, control->send_len,
				DMA_TO_DEVICE);

	send_io = control_init_hdr(control, CMD_INIT_VNIC);
	if (!send_io)
		goto failure;

	pkt = control_packet(send_io);
	init_vnic_req = &pkt->cmd.init_vnic_req;
	init_vnic_req->vnic_major_version =
				 __constant_cpu_to_be16(VNIC_MAJORVERSION);
	init_vnic_req->vnic_minor_version =
				 __constant_cpu_to_be16(VNIC_MINORVERSION);
	init_vnic_req->vnic_instance = config->vnic_instance;
	init_vnic_req->num_data_paths = 1;
	init_vnic_req->num_address_entries =
				cpu_to_be16(config->max_address_entries);

	CONTROL_PACKET(pkt);

	control->rsp_expected = pkt->hdr.pkt_cmd;

	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);

	return control_send(control, send_io);
failure:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);
	return -1;
}

static int control_chk_vnic_rsp_values(struct control *control,
				       u16 *num_addrs,
				       u8 num_data_paths,
				       u8 num_lan_switches)
{

	struct control_config		*config = control->config;

	if ((control->maj_ver > VNIC_MAJORVERSION)
	    || ((control->maj_ver == VNIC_MAJORVERSION)
		&& (control->min_ver > VNIC_MINORVERSION))) {
		CONTROL_ERROR("%s: unsupported version\n",
			      control_ifcfg_name(control));
		goto failure;
	}
	if (num_data_paths != 1) {
		CONTROL_ERROR("%s: EIOC returned too many datapaths\n",
			      control_ifcfg_name(control));
		goto failure;
	}
	if (*num_addrs > config->max_address_entries) {
		CONTROL_ERROR("%s: EIOC returned more address"
			      " entries than requested\n",
			      control_ifcfg_name(control));
		goto failure;
	}
	if (*num_addrs < config->min_address_entries) {
		CONTROL_ERROR("%s: not enough address entries\n",
			      control_ifcfg_name(control));
		goto failure;
	}
	if (num_lan_switches < 1) {
		CONTROL_ERROR("%s: EIOC returned no lan switches\n",
			      control_ifcfg_name(control));
		goto failure;
	}
	if (num_lan_switches > 1) {
		CONTROL_ERROR("%s: EIOC returned multiple lan switches\n",
			      control_ifcfg_name(control));
		goto failure;
	}

	return 0;
failure:
	return -1;
}

int control_init_vnic_rsp(struct control *control, u32 *features,
			  u8 *mac_address, u16 *num_addrs, u16 *vlan)
{
	u8 num_data_paths;
	u8 num_lan_switches;
	struct recv_io			*recv_io;
	struct vnic_control_packet	*pkt;
	struct vnic_cmd_init_vnic_rsp	*init_vnic_rsp;


	CONTROL_FUNCTION("%s: control_init_vnic_rsp()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->recv_dma, control->recv_len,
				DMA_FROM_DEVICE);

	recv_io = control_get_rsp(control);
	if (!recv_io)
		goto out;

	pkt = control_packet(recv_io);
	if (pkt->hdr.pkt_cmd != CMD_INIT_VNIC) {
		CONTROL_ERROR("%s: sent control request:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(control_last_req(control));
		CONTROL_ERROR("%s: received control response:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(pkt);
		goto failure;
	}

	init_vnic_rsp = &pkt->cmd.init_vnic_rsp;
	control->maj_ver = be16_to_cpu(init_vnic_rsp->vnic_major_version);
	control->min_ver = be16_to_cpu(init_vnic_rsp->vnic_minor_version);
	num_data_paths = init_vnic_rsp->num_data_paths;
	num_lan_switches = init_vnic_rsp->num_lan_switches;
	*features = be32_to_cpu(init_vnic_rsp->features_supported);
	*num_addrs = be16_to_cpu(init_vnic_rsp->num_address_entries);

	if (control_chk_vnic_rsp_values(control, num_addrs,
					num_data_paths,
					num_lan_switches))
		goto failure;

	control->lan_switch.lan_switch_num =
			init_vnic_rsp->lan_switch[0].lan_switch_num;
	control->lan_switch.num_enet_ports =
			init_vnic_rsp->lan_switch[0].num_enet_ports;
	control->lan_switch.default_vlan =
			init_vnic_rsp->lan_switch[0].default_vlan;
	*vlan = be16_to_cpu(control->lan_switch.default_vlan);
	memcpy(control->lan_switch.hw_mac_address,
	       init_vnic_rsp->lan_switch[0].hw_mac_address, ETH_ALEN);
	memcpy(mac_address, init_vnic_rsp->lan_switch[0].hw_mac_address,
	       ETH_ALEN);

	control_recv(control, recv_io);
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return 0;
failure:
	viport_failure(control->parent);
out:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return -1;
}

static void copy_recv_pool_config(struct vnic_recv_pool_config *src,
				  struct vnic_recv_pool_config *dst)
{
	dst->size_recv_pool_entry  = src->size_recv_pool_entry;
	dst->num_recv_pool_entries = src->num_recv_pool_entries;
	dst->timeout_before_kick   = src->timeout_before_kick;
	dst->num_recv_pool_entries_before_kick =
				src->num_recv_pool_entries_before_kick;
	dst->num_recv_pool_bytes_before_kick =
				src->num_recv_pool_bytes_before_kick;
	dst->free_recv_pool_entries_per_update =
				src->free_recv_pool_entries_per_update;
}

static int check_recv_pool_config_value(__be32 *src, __be32 *dst,
					__be32 *max, __be32 *min,
					char *name)
{
	u32 value;

	value = be32_to_cpu(*src);
	if (value > be32_to_cpu(*max)) {
		CONTROL_ERROR("value %s too large\n", name);
		return -1;
	} else if (value < be32_to_cpu(*min)) {
		CONTROL_ERROR("value %s too small\n", name);
		return -1;
	}

	*dst = cpu_to_be32(value);
	return 0;
}

static int check_recv_pool_config(struct vnic_recv_pool_config *src,
				  struct vnic_recv_pool_config *dst,
				  struct vnic_recv_pool_config *max,
				  struct vnic_recv_pool_config *min)
{
	if (check_recv_pool_config_value(&src->size_recv_pool_entry,
				     &dst->size_recv_pool_entry,
				     &max->size_recv_pool_entry,
				     &min->size_recv_pool_entry,
				     "size_recv_pool_entry")
	    || check_recv_pool_config_value(&src->num_recv_pool_entries,
				     &dst->num_recv_pool_entries,
				     &max->num_recv_pool_entries,
				     &min->num_recv_pool_entries,
				     "num_recv_pool_entries")
	    || check_recv_pool_config_value(&src->timeout_before_kick,
				     &dst->timeout_before_kick,
				     &max->timeout_before_kick,
				     &min->timeout_before_kick,
				     "timeout_before_kick")
	    || check_recv_pool_config_value(&src->
				     num_recv_pool_entries_before_kick,
				     &dst->
				     num_recv_pool_entries_before_kick,
				     &max->
				     num_recv_pool_entries_before_kick,
				     &min->
				     num_recv_pool_entries_before_kick,
				     "num_recv_pool_entries_before_kick")
	    || check_recv_pool_config_value(&src->
				     num_recv_pool_bytes_before_kick,
				     &dst->
				     num_recv_pool_bytes_before_kick,
				     &max->
				     num_recv_pool_bytes_before_kick,
				     &min->
				     num_recv_pool_bytes_before_kick,
				     "num_recv_pool_bytes_before_kick")
	    || check_recv_pool_config_value(&src->
				     free_recv_pool_entries_per_update,
				     &dst->
				     free_recv_pool_entries_per_update,
				     &max->
				     free_recv_pool_entries_per_update,
				     &min->
				     free_recv_pool_entries_per_update,
				     "free_recv_pool_entries_per_update"))
		goto failure;

	if (!is_power_of2(be32_to_cpu(dst->num_recv_pool_entries))) {
		CONTROL_ERROR("num_recv_pool_entries (%d)"
			      " must be power of 2\n",
			      dst->num_recv_pool_entries);
		goto failure;
	}

	if (!is_power_of2(be32_to_cpu(dst->
				      free_recv_pool_entries_per_update))) {
		CONTROL_ERROR("free_recv_pool_entries_per_update (%d)"
			      " must be power of 2\n",
			      dst->free_recv_pool_entries_per_update);
		goto failure;
	}

	if (be32_to_cpu(dst->free_recv_pool_entries_per_update) >=
	    be32_to_cpu(dst->num_recv_pool_entries)) {
		CONTROL_ERROR("free_recv_pool_entries_per_update (%d) must"
			      " be less than num_recv_pool_entries (%d)\n",
			      dst->free_recv_pool_entries_per_update,
			      dst->num_recv_pool_entries);
		goto failure;
	}

	if (be32_to_cpu(dst->num_recv_pool_entries_before_kick) >=
	    be32_to_cpu(dst->num_recv_pool_entries)) {
		CONTROL_ERROR("num_recv_pool_entries_before_kick (%d) must"
			      " be less than num_recv_pool_entries (%d)\n",
			      dst->num_recv_pool_entries_before_kick,
			      dst->num_recv_pool_entries);
		goto failure;
	}

	return 0;
failure:
	return -1;
}

int control_config_data_path_req(struct control * control, u64 path_id,
				     struct vnic_recv_pool_config * host,
				     struct vnic_recv_pool_config * eioc)
{
	struct send_io				*send_io;
	struct vnic_control_packet		*pkt;
	struct vnic_cmd_config_data_path	*config_data_path;

	CONTROL_FUNCTION("%s: control_config_data_path_req()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->send_dma, control->send_len,
				DMA_TO_DEVICE);

	send_io = control_init_hdr(control, CMD_CONFIG_DATA_PATH);
	if (!send_io)
		goto failure;

	pkt = control_packet(send_io);
	config_data_path = &pkt->cmd.config_data_path_req;
	config_data_path->data_path = 0;
	config_data_path->path_identifier = path_id;
	copy_recv_pool_config(host,
			      &config_data_path->host_recv_pool_config);
	copy_recv_pool_config(eioc,
			      &config_data_path->eioc_recv_pool_config);
	CONTROL_PACKET(pkt);

	control->rsp_expected = pkt->hdr.pkt_cmd;

	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);

	return control_send(control, send_io);
failure:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);
	return -1;
}

int control_config_data_path_rsp(struct control * control,
				 struct vnic_recv_pool_config * host,
				 struct vnic_recv_pool_config * eioc,
				 struct vnic_recv_pool_config * max_host,
				 struct vnic_recv_pool_config * max_eioc,
				 struct vnic_recv_pool_config * min_host,
				 struct vnic_recv_pool_config * min_eioc)
{
	struct recv_io				*recv_io;
	struct vnic_control_packet		*pkt;
	struct vnic_cmd_config_data_path	*config_data_path;

	CONTROL_FUNCTION("%s: control_config_data_path_rsp()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->recv_dma, control->recv_len,
				DMA_FROM_DEVICE);

	recv_io = control_get_rsp(control);
	if (!recv_io)
		goto out;

	pkt = control_packet(recv_io);
	if (pkt->hdr.pkt_cmd != CMD_CONFIG_DATA_PATH) {
		CONTROL_ERROR("%s: sent control request:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(control_last_req(control));
		CONTROL_ERROR("%s: received control response:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(pkt);
		goto failure;
	}

	config_data_path = &pkt->cmd.config_data_path_rsp;
	if (config_data_path->data_path != 0) {
		CONTROL_ERROR("%s: received CMD_CONFIG_DATA_PATH response"
			      " for wrong data path: %u\n",
			      control_ifcfg_name(control),
			      config_data_path->data_path);
		goto failure;
	}

	if (check_recv_pool_config(&config_data_path->
				   host_recv_pool_config,
				   host, max_host, min_host)
	    || check_recv_pool_config(&config_data_path->
				      eioc_recv_pool_config,
				      eioc, max_eioc, min_eioc)) {
		goto failure;
	}

	control_recv(control, recv_io);
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);

	return 0;
failure:
	viport_failure(control->parent);
out:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return -1;
}

int control_exchange_pools_req(struct control * control, u64 addr, u32 rkey)
{
	struct send_io			*send_io;
	struct vnic_control_packet	*pkt;
	struct vnic_cmd_exchange_pools	*exchange_pools;

	CONTROL_FUNCTION("%s: control_exchange_pools_req()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->send_dma, control->send_len,
				DMA_TO_DEVICE);

	send_io = control_init_hdr(control, CMD_EXCHANGE_POOLS);
	if (!send_io)
		goto failure;

	pkt = control_packet(send_io);
	exchange_pools = &pkt->cmd.exchange_pools_req;
	exchange_pools->data_path = 0;
	exchange_pools->pool_rkey = cpu_to_be32(rkey);
	exchange_pools->pool_addr = cpu_to_be64(addr);

	control->rsp_expected = pkt->hdr.pkt_cmd;

	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);
	return control_send(control, send_io);
failure:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);
	return -1;
}

int control_exchange_pools_rsp(struct control * control, u64 * addr,
			       u32 * rkey)
{
	struct recv_io			*recv_io;
	struct vnic_control_packet	*pkt;
	struct vnic_cmd_exchange_pools	*exchange_pools;

	CONTROL_FUNCTION("%s: control_exchange_pools_rsp()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->recv_dma, control->recv_len,
				DMA_FROM_DEVICE);

	recv_io = control_get_rsp(control);
	if (!recv_io)
		goto out;

	pkt = control_packet(recv_io);
	if (pkt->hdr.pkt_cmd != CMD_EXCHANGE_POOLS) {
		CONTROL_ERROR("%s: sent control request:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(control_last_req(control));
		CONTROL_ERROR("%s: received control response:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(pkt);
		goto failure;
	}

	exchange_pools = &pkt->cmd.exchange_pools_rsp;
	*rkey = be32_to_cpu(exchange_pools->pool_rkey);
	*addr = be64_to_cpu(exchange_pools->pool_addr);

	if (exchange_pools->data_path != 0) {
		CONTROL_ERROR("%s: received CMD_EXCHANGE_POOLS response"
			      " for wrong data path: %u\n",
			      control_ifcfg_name(control),
			      exchange_pools->data_path);
		goto failure;
	}

	control_recv(control, recv_io);
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return 0;
failure:
	viport_failure(control->parent);
out:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return -1;
}

int control_config_link_req(struct control * control, u16 flags, u16 mtu)
{
	struct send_io			*send_io;
	struct vnic_cmd_config_link	*config_link_req;
	struct vnic_control_packet	*pkt;

	CONTROL_FUNCTION("%s: control_config_link_req()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->send_dma, control->send_len,
				DMA_TO_DEVICE);

	send_io = control_init_hdr(control, CMD_CONFIG_LINK);
	if (!send_io)
		goto failure;

	pkt = control_packet(send_io);
	config_link_req = &pkt->cmd.config_link_req;
	config_link_req->lan_switch_num =
				control->lan_switch.lan_switch_num;
	config_link_req->cmd_flags = VNIC_FLAG_SET_MTU;
	if (flags & IFF_UP)
		config_link_req->cmd_flags |= VNIC_FLAG_ENABLE_NIC;
	else
		config_link_req->cmd_flags |= VNIC_FLAG_DISABLE_NIC;
	if (flags & IFF_ALLMULTI)
		config_link_req->cmd_flags |= VNIC_FLAG_ENABLE_MCAST_ALL;
	else
		config_link_req->cmd_flags |= VNIC_FLAG_DISABLE_MCAST_ALL;
	if (flags & IFF_PROMISC) {
		config_link_req->cmd_flags |= VNIC_FLAG_ENABLE_PROMISC;
		/* the EIOU doesn't really do PROMISC mode.
		 * if PROMISC is set, it only receives unicast packets
		 * I also have to set MCAST_ALL if I want real
		 * PROMISC mode.
		 */
		config_link_req->cmd_flags &= ~VNIC_FLAG_DISABLE_MCAST_ALL;
		config_link_req->cmd_flags |= VNIC_FLAG_ENABLE_MCAST_ALL;
	} else
		config_link_req->cmd_flags |= VNIC_FLAG_DISABLE_PROMISC;

	config_link_req->mtu_size = cpu_to_be16(mtu);

	control->rsp_expected = pkt->hdr.pkt_cmd;
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);
	return control_send(control, send_io);
failure:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);
	return -1;
}

int control_config_link_rsp(struct control * control, u16 * flags,
				u16 * mtu)
{
	struct recv_io			*recv_io;
	struct vnic_control_packet	*pkt;
	struct vnic_cmd_config_link	*config_link_rsp;

	CONTROL_FUNCTION("%s: control_config_link_rsp()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->recv_dma, control->recv_len,
				DMA_FROM_DEVICE);

	recv_io = control_get_rsp(control);
	if (!recv_io)
		goto out;

	pkt = control_packet(recv_io);
	if (pkt->hdr.pkt_cmd != CMD_CONFIG_LINK) {
		CONTROL_ERROR("%s: sent control request:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(control_last_req(control));
		CONTROL_ERROR("%s: received control response:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(pkt);
		goto failure;
	}
	config_link_rsp = &pkt->cmd.config_link_rsp;
	if (config_link_rsp->cmd_flags & VNIC_FLAG_ENABLE_NIC)
		*flags |= IFF_UP;
	if (config_link_rsp->cmd_flags & VNIC_FLAG_ENABLE_MCAST_ALL)
		*flags |= IFF_ALLMULTI;
	if (config_link_rsp->cmd_flags & VNIC_FLAG_ENABLE_PROMISC)
		*flags |= IFF_PROMISC;

	*mtu = be16_to_cpu(config_link_rsp->mtu_size);

	control_recv(control, recv_io);
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return 0;
failure:
	viport_failure(control->parent);
out:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return -1;
}

/* control_config_addrs_req:
 * return values:
 *          -1: failure
 *           0: incomplete (successful operation, but more address
 *              table entries to be updated)
 *           1: complete
 */
int control_config_addrs_req(struct control *control,
			     struct vnic_address_op *addrs, u16 num)
{
	u16  i;
	u8   j;
	int  ret = 1;
	struct send_io				*send_io;
	struct vnic_control_packet		*pkt;
	struct vnic_cmd_config_addresses	*config_addrs_req;

	CONTROL_FUNCTION("%s: control_config_addrs_req()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->send_dma, control->send_len,
				DMA_TO_DEVICE);

	send_io = control_init_hdr(control, CMD_CONFIG_ADDRESSES);
	if (!send_io)
		goto failure;

	pkt = control_packet(send_io);
	config_addrs_req = &pkt->cmd.config_addresses_req;
	config_addrs_req->lan_switch_num =
				control->lan_switch.lan_switch_num;
	for (i = 0, j = 0; (i < num) && (j < 16); i++) {
		if (!addrs[i].operation)
			continue;
		config_addrs_req->list_address_ops[j].index = cpu_to_be16(i);
		config_addrs_req->list_address_ops[j].operation =
							VNIC_OP_SET_ENTRY;
		config_addrs_req->list_address_ops[j].valid = addrs[i].valid;
		memcpy(config_addrs_req->list_address_ops[j].address,
		       addrs[i].address, ETH_ALEN);
		config_addrs_req->list_address_ops[j].vlan = addrs[i].vlan;
		addrs[i].operation = 0;
		j++;
	}
	for (; i < num; i++) {
		if (addrs[i].operation) {
			ret = 0;
			break;
		}
	}
	config_addrs_req->num_address_ops = j;

	control->rsp_expected = pkt->hdr.pkt_cmd;
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);

	if (control_send(control, send_io))
		return -1;
	return ret;
failure:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);
	return -1;
}

int control_config_addrs_rsp(struct control * control)
{
	struct recv_io *recv_io;
	struct vnic_control_packet *pkt;
	struct vnic_cmd_config_addresses *config_addrs_rsp;

	CONTROL_FUNCTION("%s: control_config_addrs_rsp()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->recv_dma, control->recv_len,
				DMA_FROM_DEVICE);

	recv_io = control_get_rsp(control);
	if (!recv_io)
		goto out;

	pkt = control_packet(recv_io);
	if (pkt->hdr.pkt_cmd != CMD_CONFIG_ADDRESSES) {
		CONTROL_ERROR("%s: sent control request:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(control_last_req(control));
		CONTROL_ERROR("%s: received control response:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(pkt);
		goto failure;
	}
	config_addrs_rsp = &pkt->cmd.config_addresses_rsp;

	control_recv(control, recv_io);
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return 0;
failure:
	viport_failure(control->parent);
out:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return -1;
}

int control_report_statistics_req(struct control * control)
{
	struct send_io				*send_io;
	struct vnic_control_packet		*pkt;
	struct vnic_cmd_report_stats_req	*report_statistics_req;

	CONTROL_FUNCTION("%s: control_report_statistics_req()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->send_dma, control->send_len,
				DMA_TO_DEVICE);

	send_io = control_init_hdr(control, CMD_REPORT_STATISTICS);
	if (!send_io)
		goto failure;

	pkt = control_packet(send_io);
	report_statistics_req = &pkt->cmd.report_statistics_req;
	report_statistics_req->lan_switch_num =
	    control->lan_switch.lan_switch_num;

	control->rsp_expected = pkt->hdr.pkt_cmd;
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);
	return control_send(control, send_io);
failure:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);
	return -1;
}

int control_report_statistics_rsp(struct control * control,
				  struct vnic_cmd_report_stats_rsp * stats)
{
	struct recv_io				*recv_io;
	struct vnic_control_packet		*pkt;
	struct vnic_cmd_report_stats_rsp	*rep_stat_rsp;

	CONTROL_FUNCTION("%s: control_report_statistics_rsp()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->recv_dma, control->recv_len,
				DMA_FROM_DEVICE);

	recv_io = control_get_rsp(control);
	if (!recv_io)
		goto out;

	pkt = control_packet(recv_io);
	if (pkt->hdr.pkt_cmd != CMD_REPORT_STATISTICS) {
		CONTROL_ERROR("%s: sent control request:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(control_last_req(control));
		CONTROL_ERROR("%s: received control response:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(pkt);
		goto failure;
	}

	rep_stat_rsp = &pkt->cmd.report_statistics_rsp;

	stats->if_in_broadcast_pkts   = rep_stat_rsp->if_in_broadcast_pkts;
	stats->if_in_multicast_pkts   = rep_stat_rsp->if_in_multicast_pkts;
	stats->if_in_octets	      = rep_stat_rsp->if_in_octets;
	stats->if_in_ucast_pkts       = rep_stat_rsp->if_in_ucast_pkts;
	stats->if_in_nucast_pkts      = rep_stat_rsp->if_in_nucast_pkts;
	stats->if_in_underrun	      = rep_stat_rsp->if_in_underrun;
	stats->if_in_errors	      = rep_stat_rsp->if_in_errors;
	stats->if_out_errors	      = rep_stat_rsp->if_out_errors;
	stats->if_out_octets	      = rep_stat_rsp->if_out_octets;
	stats->if_out_ucast_pkts      = rep_stat_rsp->if_out_ucast_pkts;
	stats->if_out_multicast_pkts  = rep_stat_rsp->if_out_multicast_pkts;
	stats->if_out_broadcast_pkts  = rep_stat_rsp->if_out_broadcast_pkts;
	stats->if_out_nucast_pkts     = rep_stat_rsp->if_out_nucast_pkts;
	stats->if_out_ok	      = rep_stat_rsp->if_out_ok;
	stats->if_in_ok		      = rep_stat_rsp->if_in_ok;
	stats->if_out_ucast_bytes     = rep_stat_rsp->if_out_ucast_bytes;
	stats->if_out_multicast_bytes = rep_stat_rsp->if_out_multicast_bytes;
	stats->if_out_broadcast_bytes = rep_stat_rsp->if_out_broadcast_bytes;
	stats->if_in_ucast_bytes      = rep_stat_rsp->if_in_ucast_bytes;
	stats->if_in_multicast_bytes  = rep_stat_rsp->if_in_multicast_bytes;
	stats->if_in_broadcast_bytes  = rep_stat_rsp->if_in_broadcast_bytes;
	stats->ethernet_status	      = rep_stat_rsp->ethernet_status;

	control_recv(control, recv_io);
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);

	return 0;
failure:
	viport_failure(control->parent);
out:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return -1;
}

int control_reset_req(struct control * control)
{
	struct send_io			*send_io;
	struct vnic_control_packet	*pkt;

	CONTROL_FUNCTION("%s: control_reset_req()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->send_dma, control->send_len,
				DMA_TO_DEVICE);

	send_io = control_init_hdr(control, CMD_RESET);
	if (!send_io)
		goto failure;

	pkt = control_packet(send_io);

	control->rsp_expected = pkt->hdr.pkt_cmd;
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);
	return control_send(control, send_io);
failure:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);
	return -1;
}

int control_reset_rsp(struct control * control)
{
	struct recv_io			*recv_io;
	struct vnic_control_packet	*pkt;

	CONTROL_FUNCTION("%s: control_reset_rsp()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->recv_dma, control->recv_len,
				DMA_FROM_DEVICE);

	recv_io = control_get_rsp(control);
	if (!recv_io)
		goto out;

	pkt = control_packet(recv_io);
	if (pkt->hdr.pkt_cmd != CMD_RESET) {
		CONTROL_ERROR("%s: sent control request:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(control_last_req(control));
		CONTROL_ERROR("%s: received control response:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(pkt);
		goto failure;
	}

	control_recv(control, recv_io);
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return 0;
failure:
	viport_failure(control->parent);
out:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return -1;
}

int control_heartbeat_req(struct control * control, u32 hb_interval)
{
	struct send_io			*send_io;
	struct vnic_control_packet	*pkt;
	struct vnic_cmd_heartbeat	*heartbeat_req;

	CONTROL_FUNCTION("%s: control_heartbeat_req()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->send_dma, control->send_len,
				DMA_TO_DEVICE);

	send_io = control_init_hdr(control, CMD_HEARTBEAT);
	if (!send_io)
		goto failure;

	pkt = control_packet(send_io);
	heartbeat_req = &pkt->cmd.heartbeat_req;
	heartbeat_req->hb_interval = cpu_to_be32(hb_interval);

	control->rsp_expected = pkt->hdr.pkt_cmd;
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);
	return control_send(control, send_io);
failure:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->send_dma, control->send_len,
				   DMA_TO_DEVICE);
	return -1;
}

int control_heartbeat_rsp(struct control * control)
{
	struct recv_io			*recv_io;
	struct vnic_control_packet	*pkt;
	struct vnic_cmd_heartbeat	*heartbeat_rsp;

	CONTROL_FUNCTION("%s: control_heartbeat_rsp()\n",
			 control_ifcfg_name(control));
	dma_sync_single_for_cpu(control->parent->config->ibdev->dma_device,
				control->recv_dma, control->recv_len,
				DMA_FROM_DEVICE);

	recv_io = control_get_rsp(control);
	if (!recv_io)
		goto out;

	pkt = control_packet(recv_io);
	if (pkt->hdr.pkt_cmd != CMD_HEARTBEAT) {
		CONTROL_ERROR("%s: sent control request:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(control_last_req(control));
		CONTROL_ERROR("%s: received control response:\n",
			      control_ifcfg_name(control));
		control_log_control_packet(pkt);
		goto failure;
	}

	heartbeat_rsp = &pkt->cmd.heartbeat_rsp;

	control_recv(control, recv_io);
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return 0;
failure:
	viport_failure(control->parent);
out:
	dma_sync_single_for_device(control->parent->config->ibdev->dma_device,
				   control->recv_dma, control->recv_len,
				   DMA_FROM_DEVICE);
	return -1;
}

static int control_init_recv_ios(struct control * control,
				 struct viport * viport,
				 struct vnic_control_packet * pkt)
{
	struct io		*io;
	struct ib_device	*ibdev = viport->config->ibdev;
	struct control_config	*config = control->config;
	dma_addr_t		recv_dma;
	unsigned int		i;


	control->recv_len = sizeof *pkt * config->num_recvs;
	control->recv_dma = dma_map_single(ibdev->dma_device,
					   pkt, control->recv_len,
					   DMA_FROM_DEVICE);

	if (dma_mapping_error(control->recv_dma)) {
		CONTROL_ERROR("control recv dma map error\n");
		goto failure;
	}

	recv_dma = control->recv_dma;
	for (i = 0; i < config->num_recvs; i++) {
		io = &control->recv_ios[i].io;
		io->viport = viport;
		io->routine = control_recv_complete;
		io->type = RECV;

		control->recv_ios[i].virtual_addr = (u8 *)pkt;
		control->recv_ios[i].list.addr = recv_dma;
		control->recv_ios[i].list.length = sizeof *pkt;
		control->recv_ios[i].list.lkey = control->mr->lkey;

		recv_dma = recv_dma + sizeof *pkt;
		pkt++;

		io->rwr.wr_id = (u64)io;
		io->rwr.sg_list = &control->recv_ios[i].list;
		io->rwr.num_sge = 1;
		if (vnic_ib_post_recv(&control->ib_conn, io))
			goto unmap_recv;
	}

	return 0;
unmap_recv:
	dma_unmap_single(control->parent->config->ibdev->dma_device,
			 control->recv_dma, control->send_len,
			 DMA_FROM_DEVICE);
failure:
	return -1;
}

static int control_init_send_ios(struct control *control,
				 struct viport *viport,
				 struct vnic_control_packet * pkt)
{
	struct io		* io;
	struct ib_device	*ibdev = viport->config->ibdev;

	control->send_io.virtual_addr = (u8*)pkt;
	control->send_len = sizeof *pkt;
	control->send_dma = dma_map_single(ibdev->dma_device, pkt,
					   control->send_len,
					   DMA_TO_DEVICE);
	if (dma_mapping_error(control->send_dma)) {
		CONTROL_ERROR("control send dma map error\n");
		goto failure;
	}

	io = &control->send_io.io;
	io->viport = viport;
	io->routine = control_send_complete;

	control->send_io.list.addr = control->send_dma;
	control->send_io.list.length = sizeof *pkt;
	control->send_io.list.lkey = control->mr->lkey;

	io->swr.wr_id = (u64)io;
	io->swr.sg_list = &control->send_io.list;
	io->swr.num_sge = 1;
	io->swr.opcode = IB_WR_SEND;
	io->swr.send_flags = IB_SEND_SIGNALED;
	io->type = SEND;

	return 0;
failure:
	return -1;
}

int control_init(struct control * control, struct viport * viport,
		 struct control_config * config, struct ib_pd * pd)
{
	struct vnic_control_packet	*pkt;
	unsigned int sz;

	CONTROL_FUNCTION("%s: control_init()\n",
			 control_ifcfg_name(control));
	control->parent = viport;
	control->config = config;
	control->ib_conn.viport = viport;
	control->ib_conn.ib_config = &config->ib_config;
	control->ib_conn.state = IB_CONN_UNINITTED;
	control->req_outstanding = 0;
	control->seq_num = 0;
	control->response = NULL;
	control->info = NULL;
	INIT_LIST_HEAD(&control->failure_list);
	spin_lock_init(&control->io_lock);

	if (vnic_ib_conn_init(&control->ib_conn, viport, pd,
			      &config->ib_config)) {
		CONTROL_ERROR("Control IB connection"
			      " initialization failed\n");
		goto failure;
	}

	control->mr = ib_get_dma_mr(pd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(control->mr)) {
		CONTROL_ERROR("%s: failed to register memory"
			      " for control connection\n",
			      control_ifcfg_name(control));
		goto destroy_conn;
	}

	control->ib_conn.cm_id = ib_create_cm_id(viport->config->ibdev,
						 vnic_ib_cm_handler,
						 &control->ib_conn);
	if (IS_ERR(control->ib_conn.cm_id)) {
		CONTROL_ERROR("creating control CM ID failed\n");
		goto destroy_conn;
	}

	sz = sizeof(struct recv_io) * config->num_recvs;
	control->recv_ios = vmalloc(sz);
	memset(control->recv_ios, 0, sz);

	if (!control->recv_ios) {
		CONTROL_ERROR("%s: failed allocating space for recv ios\n",
			      control_ifcfg_name(control));
		goto destroy_conn;
	}

	/*One send buffer and num_recvs recv buffers */
	control->local_storage = kzalloc(sizeof *pkt *
					 (config->num_recvs + 1),
					 GFP_KERNEL);

	if (!control->local_storage) {
		CONTROL_ERROR("%s: failed allocating space"
			      " for local storage\n",
			      control_ifcfg_name(control));
		goto destroy_conn;
	}

	pkt = control->local_storage;
	if (control_init_send_ios(control, viport, pkt))
		goto free_storage;

	pkt++;
	if (control_init_recv_ios(control, viport, pkt))
		goto unmap_send;

	return 0;

unmap_send:
	dma_unmap_single(control->parent->config->ibdev->dma_device,
			 control->send_dma, control->send_len,
			 DMA_TO_DEVICE);
free_storage:
	vfree(control->recv_ios);
	kfree(control->local_storage);
destroy_conn:
	ib_destroy_qp(control->ib_conn.qp);
	ib_destroy_cq(control->ib_conn.cq);
failure:
	return -1;
}

void control_cleanup(struct control *control)
{
	CONTROL_FUNCTION("%s: control_disconnect()\n",
			 control_ifcfg_name(control));

	if (ib_send_cm_dreq(control->ib_conn.cm_id, NULL, 0))
		printk(KERN_DEBUG "control CM DREQ sending failed\n");

	control_timer_stop(control);
	ib_destroy_cm_id(control->ib_conn.cm_id);
	ib_destroy_qp(control->ib_conn.qp);
	ib_destroy_cq(control->ib_conn.cq);
	ib_dereg_mr(control->mr);
	dma_unmap_single(control->parent->config->ibdev->dma_device,
			 control->send_dma, control->send_len,
			 DMA_TO_DEVICE);
	dma_unmap_single(control->parent->config->ibdev->dma_device,
			 control->recv_dma, control->send_len,
			 DMA_FROM_DEVICE);
	vfree(control->recv_ios);
	kfree(control->local_storage);

}

static void control_log_report_status_pkt(struct vnic_control_packet *pkt)
{
	printk(KERN_INFO
	       "               pkt_cmd = CMD_REPORT_STATUS\n");
	printk(KERN_INFO
	       "               pkt_seq_num = %u,"
	       " pkt_retry_count = %u\n",
	       pkt->hdr.pkt_seq_num,
	       pkt->hdr.pkt_retry_count);
	printk(KERN_INFO
	       "               lan_switch_num = %u, is_fatal = %u\n",
	       pkt->cmd.report_status.lan_switch_num,
	       pkt->cmd.report_status.is_fatal);
	printk(KERN_INFO
	       "               status_number = %u, status_info = %u\n",
	       be32_to_cpu(pkt->cmd.report_status.status_number),
	       be32_to_cpu(pkt->cmd.report_status.status_info));
	pkt->cmd.report_status.file_name[31] = '\0';
	pkt->cmd.report_status.routine[31] = '\0';
	printk(KERN_INFO "               filename = %s, routine = %s\n",
	       pkt->cmd.report_status.file_name,
	       pkt->cmd.report_status.routine);
	printk(KERN_INFO
	       "               line_num = %u, error_parameter = %u\n",
	       be32_to_cpu(pkt->cmd.report_status.line_num),
	       be32_to_cpu(pkt->cmd.report_status.error_parameter));
	pkt->cmd.report_status.desc_text[127] = '\0';
	printk(KERN_INFO "               desc_text = %s\n",
	       pkt->cmd.report_status.desc_text);
}

static void control_log_report_stats_pkt(struct vnic_control_packet *pkt)
{
	printk(KERN_INFO
	       "               pkt_cmd = CMD_REPORT_STATISTICS\n");
	printk(KERN_INFO
	       "               pkt_seq_num = %u,"
	       " pkt_retry_count = %u\n",
	       pkt->hdr.pkt_seq_num,
	       pkt->hdr.pkt_retry_count);
	printk(KERN_INFO "               lan_switch_num = %u\n",
	       pkt->cmd.report_statistics_req.lan_switch_num);
	if (pkt->hdr.pkt_type == TYPE_REQ)
		return;
	printk(KERN_INFO "               if_in_broadcast_pkts = %llu",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_in_broadcast_pkts));
	printk(" if_in_multicast_pkts = %llu\n",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_in_multicast_pkts));
	printk(KERN_INFO "               if_in_octets = %llu",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_in_octets));
	printk(" if_in_ucast_pkts = %llu\n",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_in_ucast_pkts));
	printk(KERN_INFO "               if_in_nucast_pkts = %llu",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_in_nucast_pkts));
	printk(" if_in_underrun = %llu\n",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_in_underrun));
	printk(KERN_INFO "               if_in_errors = %llu",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_in_errors));
	printk(" if_out_errors = %llu\n",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_out_errors));
	printk(KERN_INFO "               if_out_octets = %llu",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_out_octets));
	printk(" if_out_ucast_pkts = %llu\n",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_out_ucast_pkts));
	printk(KERN_INFO "               if_out_multicast_pkts = %llu",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_out_multicast_pkts));
	printk(" if_out_broadcast_pkts = %llu\n",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_out_broadcast_pkts));
	printk(KERN_INFO "               if_out_nucast_pkts = %llu",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_out_nucast_pkts));
	printk(" if_out_ok = %llu\n",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.if_out_ok));
	printk(KERN_INFO "               if_in_ok = %llu",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.if_in_ok));
	printk(" if_out_ucast_bytes = %llu\n",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_out_ucast_bytes));
	printk(KERN_INFO "               if_out_multicast_bytes = %llu",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
		      if_out_multicast_bytes));
	printk(" if_out_broadcast_bytes = %llu\n",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_out_broadcast_bytes));
	printk(KERN_INFO "               if_in_ucast_bytes = %llu",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_in_ucast_bytes));
	printk(" if_in_multicast_bytes = %llu\n",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_in_multicast_bytes));
	printk(KERN_INFO "               if_in_broadcast_bytes = %llu",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   if_in_broadcast_bytes));
	printk(" ethernet_status = %llu\n",
	       be64_to_cpu(pkt->cmd.report_statistics_rsp.
			   ethernet_status));
}

static void control_log_config_link_pkt(struct vnic_control_packet *pkt)
{
	printk(KERN_INFO
	       "               pkt_cmd = CMD_CONFIG_LINK\n");
	printk(KERN_INFO
	       "               pkt_seq_num = %u,"
	       " pkt_retry_count = %u\n",
	       pkt->hdr.pkt_seq_num,
	       pkt->hdr.pkt_retry_count);
	printk(KERN_INFO "               cmd_flags = %x\n",
	       pkt->cmd.config_link_req.cmd_flags);
	if (pkt->cmd.config_link_req.cmd_flags & VNIC_FLAG_ENABLE_NIC)
		printk(KERN_INFO
		       "                      VNIC_FLAG_ENABLE_NIC\n");
	if (pkt->cmd.config_link_req.cmd_flags & VNIC_FLAG_DISABLE_NIC)
		printk(KERN_INFO
		       "                      VNIC_FLAG_DISABLE_NIC\n");
	if (pkt->cmd.config_link_req.
	    cmd_flags & VNIC_FLAG_ENABLE_MCAST_ALL)
		printk(KERN_INFO
		       "                     VNIC_FLAG_ENABLE_"
		       "MCAST_ALL\n");
	if (pkt->cmd.config_link_req.
	    cmd_flags & VNIC_FLAG_DISABLE_MCAST_ALL)
		printk(KERN_INFO
		       "                       VNIC_FLAG_DISABLE_"
		       "MCAST_ALL\n");
	if (pkt->cmd.config_link_req.
	    cmd_flags & VNIC_FLAG_ENABLE_PROMISC)
		printk(KERN_INFO
		       "                       VNIC_FLAG_ENABLE_"
		       "PROMISC\n");
	if (pkt->cmd.config_link_req.
	    cmd_flags & VNIC_FLAG_DISABLE_PROMISC)
		printk(KERN_INFO
		       "                       VNIC_FLAG_DISABLE_"
		       "PROMISC\n");
	if (pkt->cmd.config_link_req.cmd_flags & VNIC_FLAG_SET_MTU)
		printk(KERN_INFO
		       "                       VNIC_FLAG_SET_MTU\n");
	printk(KERN_INFO
	       "               lan_switch_num = %x, mtu_size = %d\n",
	       pkt->cmd.config_link_req.lan_switch_num,
	       be16_to_cpu(pkt->cmd.config_link_req.mtu_size));
	if (pkt->hdr.pkt_type == TYPE_RSP) {
		printk(KERN_INFO
		       "               default_vlan = %u,"
		       " hw_mac_address ="
		       " %02x:%02x:%02x:%02x:%02x:%02x\n",
		       be16_to_cpu(pkt->cmd.config_link_req.
				   default_vlan),
		       pkt->cmd.config_link_req.hw_mac_address[0],
		       pkt->cmd.config_link_req.hw_mac_address[1],
		       pkt->cmd.config_link_req.hw_mac_address[2],
		       pkt->cmd.config_link_req.hw_mac_address[3],
		       pkt->cmd.config_link_req.hw_mac_address[4],
		       pkt->cmd.config_link_req.hw_mac_address[5]);
	}
}

static void control_log_config_addrs_pkt(struct vnic_control_packet *pkt)
{
	int i;

	printk(KERN_INFO
	       "               pkt_cmd = CMD_CONFIG_ADDRESSES\n");
	printk(KERN_INFO
	       "               pkt_seq_num = %u,"
	       " pkt_retry_count = %u\n",
	       pkt->hdr.pkt_seq_num,
	       pkt->hdr.pkt_retry_count);
	printk(KERN_INFO
	       "               num_address_ops = %x,"
	       " lan_switch_num = %d\n",
	       pkt->cmd.config_addresses_req.num_address_ops,
	       pkt->cmd.config_addresses_req.lan_switch_num);
	for (i = 0; (i < pkt->cmd.config_addresses_req.num_address_ops)
	     && (i < 16); i++) {
		printk(KERN_INFO
		       "               list_address_ops[%u].index"
		       " = %u\n",
		       i,
		       be16_to_cpu(pkt->cmd.config_addresses_req.
			      list_address_ops[i].index));
		switch (pkt->cmd.config_addresses_req.
		        list_address_ops[i].operation) {
		case VNIC_OP_GET_ENTRY:
			printk(KERN_INFO
			       "               list_address_ops[%u]."
			       "operation = VNIC_OP_GET_ENTRY\n",
			       i);
			break;
		case VNIC_OP_SET_ENTRY:
			printk(KERN_INFO
			       "               list_address_ops[%u]."
			       "operation = VNIC_OP_SET_ENTRY\n",
			       i);
			break;
		default:
			printk(KERN_INFO
			       "               list_address_ops[%u]."
			       "operation = UNKNOWN(%d)\n",
			       i,
			       pkt->cmd.config_addresses_req.
			       list_address_ops[i].operation);
			break;
		}
		printk(KERN_INFO
		       "               list_address_ops[%u].valid"
		       " = %u\n",
		       i,
		       pkt->cmd.config_addresses_req.
		       list_address_ops[i].valid);
		printk(KERN_INFO
		       "               list_address_ops[%u].address"
		       " = %02x:%02x:%02x:%02x:%02x:%02x\n",
		       i,
		       pkt->cmd.config_addresses_req.
		       list_address_ops[i].address[0],
		       pkt->cmd.config_addresses_req.
		       list_address_ops[i].address[1],
		       pkt->cmd.config_addresses_req.
		       list_address_ops[i].address[2],
		       pkt->cmd.config_addresses_req.
		       list_address_ops[i].address[3],
		       pkt->cmd.config_addresses_req.
		       list_address_ops[i].address[4],
		       pkt->cmd.config_addresses_req.
		       list_address_ops[i].address[5]);
		printk(KERN_INFO
		       "               list_address_ops[%u].vlan"
		       " = %u\n",
		       i,
		       be16_to_cpu(pkt->cmd.config_addresses_req.
			      list_address_ops[i].vlan));
	}

}

static void control_log_exch_pools_pkt(struct vnic_control_packet *pkt)
{
	printk(KERN_INFO
	       "               pkt_cmd = CMD_EXCHANGE_POOLS\n");
	printk(KERN_INFO
	       "               pkt_seq_num = %u,"
	       " pkt_retry_count = %u\n",
	       pkt->hdr.pkt_seq_num,
	       pkt->hdr.pkt_retry_count);
	printk(KERN_INFO "               datapath = %u\n",
	       pkt->cmd.exchange_pools_req.data_path);
	printk(KERN_INFO "               pool_rkey = %08x"
	       " pool_addr = %llx\n",
	       be32_to_cpu(pkt->cmd.exchange_pools_req.pool_rkey),
	       be64_to_cpu(pkt->cmd.exchange_pools_req.pool_addr));
}

static void control_log_data_path_pkt(struct vnic_control_packet *pkt)
{
	printk(KERN_INFO
	       "               pkt_cmd = CMD_CONFIG_DATA_PATH\n");
	printk(KERN_INFO
	       "               pkt_seq_num = %u,"
	       " pkt_retry_count = %u\n",
	       pkt->hdr.pkt_seq_num,
	       pkt->hdr.pkt_retry_count);
	printk(KERN_INFO "               path_identifier = %llx,"
	       " data_path = %u\n",
	       pkt->cmd.config_data_path_req.path_identifier,
	       pkt->cmd.config_data_path_req.data_path);
	printk(KERN_INFO
	       "host config    size_recv_pool_entry = %u,"
	       " num_recv_pool_entries = %u\n",
	       be32_to_cpu(pkt->cmd.config_data_path_req.
		      host_recv_pool_config.size_recv_pool_entry),
	       be32_to_cpu(pkt->cmd.config_data_path_req.
		      host_recv_pool_config.num_recv_pool_entries));
	printk(KERN_INFO
	       "               timeout_before_kick = %u,"
	       " num_recv_pool_entries_before_kick = %u\n",
	       be32_to_cpu(pkt->cmd.config_data_path_req.
		      host_recv_pool_config.timeout_before_kick),
	       be32_to_cpu(pkt->cmd.config_data_path_req.
		      host_recv_pool_config.
		      num_recv_pool_entries_before_kick));
	printk(KERN_INFO
	       "               num_recv_pool_bytes_before_kick = %u,"
	       " free_recv_pool_entries_per_update = %u\n",
	       be32_to_cpu(pkt->cmd.config_data_path_req.
		      host_recv_pool_config.
		      num_recv_pool_bytes_before_kick),
	       be32_to_cpu(pkt->cmd.config_data_path_req.
		      host_recv_pool_config.
		      free_recv_pool_entries_per_update));
	printk(KERN_INFO
	       "eioc config    size_recv_pool_entry = %u,"
	       " num_recv_pool_entries = %u\n",
	       be32_to_cpu(pkt->cmd.config_data_path_req.
		      eioc_recv_pool_config.size_recv_pool_entry),
	       be32_to_cpu(pkt->cmd.config_data_path_req.
		      eioc_recv_pool_config.num_recv_pool_entries));
	printk(KERN_INFO
	       "               timeout_before_kick = %u,"
	       " num_recv_pool_entries_before_kick = %u\n",
	       be32_to_cpu(pkt->cmd.config_data_path_req.
		      eioc_recv_pool_config.timeout_before_kick),
	       be32_to_cpu(pkt->cmd.config_data_path_req.
		      eioc_recv_pool_config.
		      num_recv_pool_entries_before_kick));
	printk(KERN_INFO
	       "               num_recv_pool_bytes_before_kick = %u,"
	       " free_recv_pool_entries_per_update = %u\n",
	       be32_to_cpu(pkt->cmd.config_data_path_req.
		      eioc_recv_pool_config.
		      num_recv_pool_bytes_before_kick),
	       be32_to_cpu(pkt->cmd.config_data_path_req.
		      eioc_recv_pool_config.
		      free_recv_pool_entries_per_update));
}

static void control_log_init_vnic_pkt(struct vnic_control_packet *pkt)
{
	printk(KERN_INFO
	       "               pkt_cmd = CMD_INIT_VNIC\n");
	printk(KERN_INFO
	       "               pkt_seq_num = %u,"
	       " pkt_retry_count = %u\n",
	       pkt->hdr.pkt_seq_num,
	       pkt->hdr.pkt_retry_count);
	printk(KERN_INFO
	       "               vnic_major_version = %u,"
	       " vnic_minor_version = %u\n",
	       be16_to_cpu(pkt->cmd.init_vnic_req.vnic_major_version),
	       be16_to_cpu(pkt->cmd.init_vnic_req.vnic_minor_version));
	if (pkt->hdr.pkt_type == TYPE_REQ) {
		printk(KERN_INFO
		       "               vnic_instance = %u,"
		       " num_data_paths = %u\n",
		       pkt->cmd.init_vnic_req.vnic_instance,
		       pkt->cmd.init_vnic_req.num_data_paths);
		printk(KERN_INFO
		       "               num_address_entries = %u\n",
		       be16_to_cpu(pkt->cmd.init_vnic_req.
			      num_address_entries));
	} else {
		printk(KERN_INFO
		       "               num_lan_switches = %u,"
		       " num_data_paths = %u\n",
		       pkt->cmd.init_vnic_rsp.num_lan_switches,
		       pkt->cmd.init_vnic_rsp.num_data_paths);
		printk(KERN_INFO
		       "               num_address_entries = %u,"
		       " features_supported = %08x\n",
		       be16_to_cpu(pkt->cmd.init_vnic_rsp.
			      num_address_entries),
		       be32_to_cpu(pkt->cmd.init_vnic_rsp.
			      features_supported));
		if (pkt->cmd.init_vnic_rsp.num_lan_switches != 0) {
			printk(KERN_INFO
			       "lan_switch[0]  lan_switch_num = %u,"
			       " num_enet_ports = %08x\n",
			       pkt->cmd.init_vnic_rsp.
			       lan_switch[0].lan_switch_num,
			       pkt->cmd.init_vnic_rsp.
			       lan_switch[0].num_enet_ports);
			printk(KERN_INFO
			       "               default_vlan = %u,"
			       " hw_mac_address ="
			       " %02x:%02x:%02x:%02x:%02x:%02x\n",
			       be16_to_cpu(pkt->cmd.init_vnic_rsp.
				      lan_switch[0].default_vlan),
			       pkt->cmd.init_vnic_rsp.lan_switch[0].
			       hw_mac_address[0],
			       pkt->cmd.init_vnic_rsp.lan_switch[0].
			       hw_mac_address[1],
			       pkt->cmd.init_vnic_rsp.lan_switch[0].
			       hw_mac_address[2],
			       pkt->cmd.init_vnic_rsp.lan_switch[0].
			       hw_mac_address[3],
			       pkt->cmd.init_vnic_rsp.lan_switch[0].
			       hw_mac_address[4],
			       pkt->cmd.init_vnic_rsp.lan_switch[0].
			       hw_mac_address[5]);
		}
	}
}

static void control_log_control_packet(struct vnic_control_packet *pkt)
{
	switch (pkt->hdr.pkt_type) {
	case TYPE_INFO:
		printk(KERN_INFO "control_packet: pkt_type = TYPE_INFO\n");
		break;
	case TYPE_REQ:
		printk(KERN_INFO "control_packet: pkt_type = TYPE_REQ\n");
		break;
	case TYPE_RSP:
		printk(KERN_INFO "control_packet: pkt_type = TYPE_RSP\n");
		break;
	case TYPE_ERR:
		printk(KERN_INFO "control_packet: pkt_type = TYPE_ERR\n");
		break;
	default:
		printk(KERN_INFO "control_packet: pkt_type = UNKNOWN\n");
	}

	switch (pkt->hdr.pkt_cmd) {
	case CMD_INIT_VNIC:
		control_log_init_vnic_pkt(pkt);
		break;
	case CMD_CONFIG_DATA_PATH:
		control_log_data_path_pkt(pkt);
		break;
	case CMD_EXCHANGE_POOLS:
		control_log_exch_pools_pkt(pkt);
		break;
	case CMD_CONFIG_ADDRESSES:
		control_log_config_addrs_pkt(pkt);
		break;
	case CMD_CONFIG_LINK:
		control_log_config_link_pkt(pkt);
		break;
	case CMD_REPORT_STATISTICS:
		control_log_report_stats_pkt(pkt);
		break;
	case CMD_CLEAR_STATISTICS:
		printk(KERN_INFO
		       "               pkt_cmd = CMD_CLEAR_STATISTICS\n");
		printk(KERN_INFO
		       "               pkt_seq_num = %u,"
		       " pkt_retry_count = %u\n",
		       pkt->hdr.pkt_seq_num,
		       pkt->hdr.pkt_retry_count);
		break;
	case CMD_REPORT_STATUS:
		control_log_report_status_pkt(pkt);

		break;
	case CMD_RESET:
		printk(KERN_INFO
		       "               pkt_cmd = CMD_RESET\n");
		printk(KERN_INFO
		       "               pkt_seq_num = %u,"
		       " pkt_retry_count = %u\n",
		       pkt->hdr.pkt_seq_num,
		       pkt->hdr.pkt_retry_count);
		break;
	case CMD_HEARTBEAT:
		printk(KERN_INFO
		       "               pkt_cmd = CMD_HEARTBEAT\n");
		printk(KERN_INFO
		       "               pkt_seq_num = %u,"
		       " pkt_retry_count = %u\n",
		       pkt->hdr.pkt_seq_num,
		       pkt->hdr.pkt_retry_count);
		printk(KERN_INFO "               hb_interval = %d\n",
		       be32_to_cpu(pkt->cmd.heartbeat_req.hb_interval));
		break;
	default:
		printk(KERN_INFO
		       "               pkt_cmd = UNKNOWN (%u)\n",
		       pkt->hdr.pkt_cmd);
		printk(KERN_INFO
		       "               pkt_seq_num = %u,"
		       " pkt_retry_count = %u\n",
		       pkt->hdr.pkt_seq_num,
		       pkt->hdr.pkt_retry_count);
		break;
	}
}
