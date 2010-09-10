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

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/completion.h>

#include <rdma/ib_cache.h>

#include "vnic_util.h"
#include "vnic_main.h"
#include "vnic_netpath.h"
#include "vnic_viport.h"
#include "vnic_ib.h"
#include "vnic_stats.h"

#define MODULEVERSION "0.6.1"
#define MODULEDETAILS "QLogic Corp. Virtual NIC (VNIC) driver version " MODULEVERSION

MODULE_AUTHOR("QLogic Corp.");
MODULE_DESCRIPTION(MODULEDETAILS);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_SUPPORTED_DEVICE("QLogic Ethernet Virtual I/O Controller");

u32 vnic_debug = 0;

module_param(vnic_debug, uint, 0444);
MODULE_PARM_DESC(vnic_debug, "Enable debug tracing if > 0");

LIST_HEAD(vnic_list);

const char driver[] = "qlgc_vnic";

DECLARE_WAIT_QUEUE_HEAD(vnic_npevent_queue);
LIST_HEAD(vnic_npevent_list);
DECLARE_COMPLETION(vnic_npevent_thread_exit);
spinlock_t vnic_npevent_list_lock = SPIN_LOCK_UNLOCKED;
int vnic_npevent_thread = -1;
int vnic_npevent_thread_end = 0;


void vnic_connected(struct vnic *vnic, struct netpath *netpath)
{
	VNIC_FUNCTION("vnic_connected()\n");
	if (netpath->second_bias)
		vnic_npevent_queue_evt(netpath, VNIC_SECNP_CONNECTED);
	else
		vnic_npevent_queue_evt(netpath, VNIC_PRINP_CONNECTED);

	vnic_connected_stats(vnic);
}

void vnic_disconnected(struct vnic *vnic, struct netpath *netpath)
{
	VNIC_FUNCTION("vnic_disconnected()\n");
	if (netpath->second_bias)
		vnic_npevent_queue_evt(netpath, VNIC_SECNP_DISCONNECTED);
	else
		vnic_npevent_queue_evt(netpath, VNIC_PRINP_DISCONNECTED);
}

void vnic_link_up(struct vnic *vnic, struct netpath *netpath)
{
	VNIC_FUNCTION("vnic_link_up()\n");
	if (netpath->second_bias)
		vnic_npevent_queue_evt(netpath, VNIC_SECNP_LINKUP);
	else
		vnic_npevent_queue_evt(netpath, VNIC_PRINP_LINKUP);
}

void vnic_link_down(struct vnic *vnic, struct netpath *netpath)
{
	VNIC_FUNCTION("vnic_link_down()\n");
	if (netpath->second_bias)
		vnic_npevent_queue_evt(netpath, VNIC_SECNP_LINKDOWN);
	else
		vnic_npevent_queue_evt(netpath, VNIC_PRINP_LINKDOWN);
}

void vnic_stop_xmit(struct vnic *vnic, struct netpath *netpath)
{
	VNIC_FUNCTION("vnic_stop_xmit()\n");
	if (netpath == vnic->current_path) {
		if (vnic->xmit_started) {
			netif_stop_queue(&vnic->netdevice);
			vnic->xmit_started = 0;
		}

		vnic_stop_xmit_stats(vnic);
	}
}

void vnic_restart_xmit(struct vnic *vnic, struct netpath *netpath)
{
	VNIC_FUNCTION("vnic_restart_xmit()\n");
	if (netpath == vnic->current_path) {
		if (!vnic->xmit_started) {
			netif_wake_queue(&vnic->netdevice);
			vnic->xmit_started = 1;
		}

		vnic_restart_xmit_stats(vnic);
	}
}

void vnic_recv_packet(struct vnic *vnic, struct netpath *netpath,
		      struct sk_buff *skb)
{
	VNIC_FUNCTION("vnic_recv_packet()\n");
	if ((netpath != vnic->current_path) || !vnic->open) {
		VNIC_INFO("tossing packet\n");
		dev_kfree_skb(skb);
		return;
	}

	vnic->netdevice.last_rx = jiffies;
	skb->dev = &vnic->netdevice;
	skb->protocol = eth_type_trans(skb, skb->dev);
	if (!vnic->config->use_rx_csum)
		skb->ip_summed = CHECKSUM_NONE;
	netif_rx(skb);
	vnic_recv_pkt_stats(vnic);
}

static struct net_device_stats *vnic_get_stats(struct net_device *device)
{
	struct vnic *vnic;
	struct netpath *np;

	VNIC_FUNCTION("vnic_get_stats()\n");
	vnic = (struct vnic *)device->priv;

	np = vnic->current_path;
	if (np && np->viport)
		viport_get_stats(np->viport, &vnic->stats);
	return &vnic->stats;
}

static int vnic_open(struct net_device *device)
{
	struct vnic *vnic;

	VNIC_FUNCTION("vnic_open()\n");
	vnic = (struct vnic *)device->priv;

	vnic->open++;
	vnic_npevent_queue_evt(&vnic->primary_path, VNIC_NP_SETLINK);
	vnic->xmit_started = 1;
	netif_start_queue(&vnic->netdevice);

	return 0;
}

static int vnic_stop(struct net_device *device)
{
	struct vnic *vnic;
	int ret = 0;

	VNIC_FUNCTION("vnic_stop()\n");
	vnic = (struct vnic *)device->priv;
	netif_stop_queue(device);
	vnic->xmit_started = 0;
	vnic->open--;
	vnic_npevent_queue_evt(&vnic->primary_path, VNIC_NP_SETLINK);

	return ret;
}

static int vnic_hard_start_xmit(struct sk_buff *skb,
				struct net_device *device)
{
	struct vnic *vnic;
	struct netpath *np;
	cycles_t xmit_time;
	int	 ret = -1;

	VNIC_FUNCTION("vnic_hard_start_xmit()\n");
	vnic = (struct vnic *)device->priv;
	np = vnic->current_path;

	vnic_pre_pkt_xmit_stats(&xmit_time);

	if (np && np->viport)
		ret = viport_xmit_packet(np->viport, skb);

	if (ret) {
		vnic_xmit_fail_stats(vnic);
		dev_kfree_skb_any(skb);
		vnic->stats.tx_dropped++;
		goto out;
	}

	device->trans_start = jiffies;
	vnic_post_pkt_xmit_stats(vnic, xmit_time);
out:
	return 0;
}

static void vnic_tx_timeout(struct net_device *device)
{
	struct vnic *vnic;

	VNIC_FUNCTION("vnic_tx_timeout()\n");
	vnic = (struct vnic *)device->priv;
	device->trans_start = jiffies;

	if (vnic->current_path->viport)
		viport_failure(vnic->current_path->viport);

	VNIC_ERROR("vnic_tx_timeout\n");
}

static void vnic_set_multicast_list(struct net_device *device)
{
	struct vnic *vnic;
	unsigned long flags;

	VNIC_FUNCTION("vnic_set_multicast_list()\n");
	vnic = (struct vnic *)device->priv;

	spin_lock_irqsave(&vnic->lock, flags);
	/* the vnic_link_evt thread also needs to be able to access
	 * mc_list. it is only safe to access the mc_list
	 * in the netdevice from this call, so make a local
	 * copy of it in the vnic. the mc_list is a linked
	 * list, but my copy is an array where each element's
	 * next pointer points to the next element. when I
	 * reallocate the list, I always size it with 10
	 * extra elements so I don't have to resize it as
	 * often. I only downsize the list when it goes empty.
	 */
	if (device->mc_count == 0) {
		if (vnic->mc_list_len) {
			vnic->mc_list_len = vnic->mc_count = 0;
			kfree(vnic->mc_list);
		}
	} else {
		struct dev_mc_list *mc_list = device->mc_list;
		int i;

		if (device->mc_count > vnic->mc_list_len) {
			if (vnic->mc_list_len)
				kfree(vnic->mc_list);
			vnic->mc_list_len = device->mc_count + 10;
			vnic->mc_list = kmalloc(vnic->mc_list_len *
						sizeof *mc_list, GFP_ATOMIC);
			if (!vnic->mc_list) {
				vnic->mc_list_len = vnic->mc_count = 0;
				VNIC_ERROR("failed allocating mc_list\n");
				goto failure;
			}
		}
		vnic->mc_count = device->mc_count;
		for (i = 0; i < device->mc_count; i++) {
			vnic->mc_list[i] = *mc_list;
			vnic->mc_list[i].next = &vnic->mc_list[i + 1];
			mc_list = mc_list->next;
		}
	}
	spin_unlock_irqrestore(&vnic->lock, flags);

	if (vnic->primary_path.viport)
		viport_set_multicast(vnic->primary_path.viport,
				     vnic->mc_list, vnic->mc_count);

	if (vnic->secondary_path.viport)
		viport_set_multicast(vnic->secondary_path.viport,
				     vnic->mc_list, vnic->mc_count);

	vnic_npevent_queue_evt(&vnic->primary_path, VNIC_NP_SETLINK);
	return;
failure:
	spin_unlock_irqrestore(&vnic->lock, flags);
}

static int vnic_set_mac_address(struct net_device *device, void *addr)
{
	struct vnic	*vnic;
	struct sockaddr	*sockaddr = addr;
	u8		*address;
	int		ret = -1;

	VNIC_FUNCTION("vnic_set_mac_address()\n");
	vnic = (struct vnic *)device->priv;

	if (!is_valid_ether_addr(sockaddr->sa_data))
		return -EADDRNOTAVAIL;

	if (netif_running(device))
		return -EBUSY;

	memcpy(device->dev_addr, sockaddr->sa_data, ETH_ALEN);
	address = sockaddr->sa_data;

	if (vnic->primary_path.viport)
		ret = viport_set_unicast(vnic->primary_path.viport,
					 address);

	if (ret)
		return ret;

	/* Ignore result of set unicast for secondary path viport.
	 * Consider the operation a success if we are able to atleast
	 * set the primary path viport address
	 */
	if (vnic->secondary_path.viport)
		viport_set_unicast(vnic->secondary_path.viport, address);

	vnic->mac_set = 1;
	/* I'm assuming that this should work even if nothing is connected
	 * at the moment.  note that this might return before the address has
	 * actually been changed.
	 */
	return 0;
}

static int vnic_change_mtu(struct net_device *device, int mtu)
{
	struct vnic	*vnic;
	int		ret = 0;
	int		pri_max_mtu;
	int		sec_max_mtu;

	VNIC_FUNCTION("vnic_change_mtu()\n");
	vnic = (struct vnic *)device->priv;

	if (vnic->primary_path.viport)
		pri_max_mtu = viport_max_mtu(vnic->primary_path.viport);
	else
		pri_max_mtu = MAX_PARAM_VALUE;

	if (vnic->secondary_path.viport)
		sec_max_mtu = viport_max_mtu(vnic->secondary_path.viport);
	else
		sec_max_mtu = MAX_PARAM_VALUE;

	if ((mtu < pri_max_mtu) && (mtu < sec_max_mtu)) {
		device->mtu = mtu;
		vnic_npevent_queue_evt(&vnic->primary_path,
				       VNIC_NP_SETLINK);
	}

	return ret;
}

static int vnic_npevent_register(struct vnic *vnic, struct netpath *netpath)
{
	u8	*address;
	int	ret;

	if (!vnic->mac_set) {
		/* if netpath == secondary_path, then the primary path isn't
		 * connected.  MAC address will be set when the primary
		 * connects.
		 */
		netpath_get_hw_addr(netpath, vnic->netdevice.dev_addr);
		address = vnic->netdevice.dev_addr;

		if (vnic->secondary_path.viport)
			viport_set_unicast(vnic->secondary_path.viport,
					   address);

		vnic->mac_set = 1;
	}

	ret = register_netdev(&vnic->netdevice);
	if (ret) {
		printk(KERN_WARNING PFX "failed registering netdev "
		       "error %d\n", ret);
		return ret;
	}

	vnic->state = VNIC_REGISTERED;
	vnic->carrier = 2; /*special value to force netif_carrier_(on|off)*/
	return 0;
}

static void vnic_npevent_dequeue_all(struct vnic *vnic)
{
	unsigned long flags;
	struct vnic_npevent *npevt, *tmp;

	spin_lock_irqsave(&vnic_npevent_list_lock, flags);
	if (list_empty(&vnic_npevent_list))
		goto out;
	list_for_each_entry_safe(npevt, tmp, &vnic_npevent_list,
				 list_ptrs) {
		if ((npevt->vnic == vnic)) {
			list_del(&npevt->list_ptrs);
			kfree(npevt);
		}
	}
out:
	spin_unlock_irqrestore(&vnic_npevent_list_lock, flags);
}


static const char *const vnic_npevent_str[] = {
	"PRIMARY CONNECTED",
	"PRIMARY DISCONNECTED",
	"PRIMARY CARRIER",
	"PRIMARY NO CARRIER",
	"PRIMARY TIMER EXPIRED",
	"SECONDARY CONNECTED",
	"SECONDARY DISCONNECTED",
	"SECONDARY CARRIER",
	"SECONDARY NO CARRIER",
	"SECONDARY TIMER EXPIRED",
	"SETLINK",
	"FREE VNIC",
};

static void update_path_and_reconnect(struct netpath *netpath,
				      struct vnic *vnic)
{
	struct viport_config *config = netpath->viport->config;
	int delay = 1;

	if (vnic_ib_get_path(netpath, vnic))
		return;
	/*
	 * tell viport_connect to wait for default_no_path_timeout
	 * before connecting if  we are retrying the same path index
	 * within default_no_path_timeout.
	 * This prevents flooding connect requests to a path (or set
	 * of paths) that aren't successfully connecting for some reason.
	 */
	if (jiffies > netpath->connect_time +
		      vnic->config->no_path_timeout) {
		netpath->path_idx = config->path_idx;
		netpath->connect_time = jiffies;
		netpath->delay_reconnect = 0;
		delay = 0;
	} else if (config->path_idx != netpath->path_idx) {
		delay = netpath->delay_reconnect;
		netpath->path_idx = config->path_idx;
		netpath->delay_reconnect = 1;
	} else
		delay = 1;
	viport_connect(netpath->viport, delay);
}

static void vnic_set_uni_multicast(struct vnic * vnic,
				   struct netpath * netpath)
{
	unsigned long	flags;
	u8		*address;

	if (vnic->mac_set) {
		address = vnic->netdevice.dev_addr;

		if (netpath->viport)
			viport_set_unicast(netpath->viport, address);
	}
	spin_lock_irqsave(&vnic->lock, flags);

	if (vnic->mc_list && netpath->viport)
		viport_set_multicast(netpath->viport, vnic->mc_list,
				     vnic->mc_count);

	spin_unlock_irqrestore(&vnic->lock, flags);
	if (vnic->state == VNIC_REGISTERED) {
		if (!netpath->viport)
			return;
		viport_set_link(netpath->viport,
				vnic->netdevice.flags & ~IFF_UP,
				vnic->netdevice.mtu);
	}
}

static void vnic_set_netpath_timers(struct vnic *vnic,
				    struct netpath *netpath)
{
	switch (netpath->timer_state) {
	case NETPATH_TS_IDLE:
		netpath->timer_state = NETPATH_TS_ACTIVE;
		if (vnic->state == VNIC_UNINITIALIZED)
			netpath_timer(netpath,
				      vnic->config->
				      primary_connect_timeout);
		else
			netpath_timer(netpath,
				      vnic->config->
				      primary_reconnect_timeout);
			break;
	case NETPATH_TS_ACTIVE:
		/*nothing to do*/
		break;
	case NETPATH_TS_EXPIRED:
		if (vnic->state == VNIC_UNINITIALIZED) {
			vnic_npevent_register(vnic, netpath);
		}
		break;
	}
}

static void vnic_check_primary_path_timer(struct vnic * vnic)
{
	switch (vnic->primary_path.timer_state) {
	case NETPATH_TS_ACTIVE:
		/* nothing to do. just wait */
		break;
	case NETPATH_TS_IDLE:
		netpath_timer(&vnic->primary_path,
			      vnic->config->
			      primary_switch_timeout);
		break;
	case NETPATH_TS_EXPIRED:
		printk(KERN_INFO PFX
		       "%s: switching to primary path\n",
		       vnic->config->name);

		vnic->current_path = &vnic->primary_path;
		if (vnic->config->use_tx_csum
		    && netpath_can_tx_csum(vnic->
					   current_path)) {
			vnic->netdevice.features |=
					    NETIF_F_IP_CSUM;
		}
		break;
	}
}

static void vnic_carrier_loss(struct vnic * vnic,
			      struct netpath *last_path)
{
	if (vnic->primary_path.carrier) {
		vnic->carrier = 1;
		vnic->current_path = &vnic->primary_path;

		if (last_path && last_path != vnic->current_path)
			printk(KERN_INFO PFX
			       "%s: failing over to primary path\n",
			       vnic->config->name);
		else if (!last_path)
			printk(KERN_INFO PFX "%s: using primary path\n",
			       vnic->config->name);

		if (vnic->config->use_tx_csum &&
		    netpath_can_tx_csum(vnic->current_path))
			vnic->netdevice.features |= NETIF_F_IP_CSUM;

	} else if ((vnic->secondary_path.carrier) &&
		   (vnic->secondary_path.timer_state != NETPATH_TS_ACTIVE)) {
		vnic->carrier = 1;
		vnic->current_path = &vnic->secondary_path;

		if (last_path && last_path != vnic->current_path)
			printk(KERN_INFO PFX
			       "%s: failing over to secondary path\n",
			       vnic->config->name);
		else if (!last_path)
			printk(KERN_INFO PFX "%s: using secondary path\n",
			       vnic->config->name);

		if (vnic->config->use_tx_csum &&
		    netpath_can_tx_csum(vnic->current_path))
			vnic->netdevice.features |= NETIF_F_IP_CSUM;

	}

}

static void vnic_handle_path_change(struct vnic * vnic,
				    struct netpath **path)
{
	struct netpath * last_path = *path;

	if (!last_path) {
		if (vnic->current_path == &vnic->primary_path)
			last_path = &vnic->secondary_path;
		else
			last_path = &vnic->primary_path;

	}

	if (vnic->current_path && vnic->current_path->viport)
		viport_set_link(vnic->current_path->viport,
				vnic->netdevice.flags,
				vnic->netdevice.mtu);

	if (last_path->viport)
		viport_set_link(last_path->viport,
				 vnic->netdevice.flags &
				 ~IFF_UP, vnic->netdevice.mtu);

	vnic_restart_xmit(vnic, vnic->current_path);
}

static void vnic_report_path_change(struct vnic * vnic,
				    struct netpath *last_path,
				    int other_path_ok)
{
	if (!vnic->current_path) {
		if (last_path == &vnic->primary_path)
			printk(KERN_INFO PFX "%s: primary path lost, "
			       "no failover path available\n",
			       vnic->config->name);
		else
			printk(KERN_INFO PFX "%s: secondary path lost, "
			       "no failover path available\n",
			       vnic->config->name);
		return;
	}

	if (last_path != vnic->current_path)
		return;

	if (vnic->current_path == &vnic->secondary_path) {
		if (other_path_ok != vnic->primary_path.carrier) {
			if (other_path_ok)
				printk(KERN_INFO PFX "%s: primary path no"
				       " longer available for failover\n",
				       vnic->config->name);
			else
				printk(KERN_INFO PFX "%s: primary path now"
				       " available for failover\n",
				       vnic->config->name);
		}
	} else {
		if (other_path_ok != vnic->secondary_path.carrier) {
			if (other_path_ok)
				printk(KERN_INFO PFX "%s: secondary path no"
				       " longer available for failover\n",
				       vnic->config->name);
			else
				printk(KERN_INFO PFX "%s: secondary path now"
				       " available for failover\n",
				       vnic->config->name);
		}
	}
}

static void vnic_handle_free_vnic_evt(struct vnic * vnic)
{
	netpath_timer_stop(&vnic->primary_path);
	netpath_timer_stop(&vnic->secondary_path);
	vnic->current_path = NULL;
	netpath_free(&vnic->primary_path);
	netpath_free(&vnic->secondary_path);
	if (vnic->state == VNIC_REGISTERED)
		unregister_netdev(&vnic->netdevice);
	vnic_npevent_dequeue_all(vnic);
	kfree(vnic->config);
	if (vnic->mc_list_len) {
		vnic->mc_list_len = vnic->mc_count = 0;
		kfree(vnic->mc_list);
	}

	sysfs_remove_group(&vnic->class_dev_info.class_dev.kobj,
			   &vnic_dev_attr_group);
	vnic_cleanup_stats_files(vnic);
	class_device_unregister(&vnic->class_dev_info.class_dev);
	wait_for_completion(&vnic->class_dev_info.released);
}

static struct vnic * vnic_handle_npevent(struct vnic *vnic,
					 enum vnic_npevent_type npevt_type)
{
	struct netpath	*netpath;

	VNIC_INFO("%s: processing %s, netpath=%s, carrier=%d\n",
		  vnic->config->name, vnic_npevent_str[npevt_type],
		  netpath_to_string(vnic, vnic->current_path),
		  vnic->carrier);

	switch (npevt_type) {
	case VNIC_PRINP_CONNECTED:
		netpath = &vnic->primary_path;
		if (vnic->state == VNIC_UNINITIALIZED) {
			if (vnic_npevent_register(vnic, netpath))
				break;
		}
		vnic_set_uni_multicast(vnic, netpath);
		break;
	case VNIC_SECNP_CONNECTED:
		vnic_set_uni_multicast(vnic, &vnic->secondary_path);
		break;
	case VNIC_PRINP_TIMEREXPIRED:
		netpath = &vnic->primary_path;
		netpath->timer_state = NETPATH_TS_EXPIRED;
		if (!netpath->carrier)
			update_path_and_reconnect(netpath, vnic);
		break;
	case VNIC_SECNP_TIMEREXPIRED:
		netpath = &vnic->secondary_path;
		netpath->timer_state = NETPATH_TS_EXPIRED;
		if (!netpath->carrier)
			update_path_and_reconnect(netpath, vnic);
		else {
			if (vnic->state == VNIC_UNINITIALIZED)
				vnic_npevent_register(vnic, netpath);
		}
		break;
	case VNIC_PRINP_LINKUP:
		vnic->primary_path.carrier = 1;
		break;
	case VNIC_SECNP_LINKUP:
		netpath = &vnic->secondary_path;
		netpath->carrier = 1;
		if (!vnic->carrier)
			vnic_set_netpath_timers(vnic, netpath);
		break;
	case VNIC_PRINP_LINKDOWN:
		vnic->primary_path.carrier = 0;
		break;
	case VNIC_SECNP_LINKDOWN:
		if (vnic->state == VNIC_UNINITIALIZED)
			netpath_timer_stop(&vnic->secondary_path);
		vnic->secondary_path.carrier = 0;
		break;
	case VNIC_PRINP_DISCONNECTED:
		netpath = &vnic->primary_path;
		netpath_timer_stop(netpath);
		netpath->carrier = 0;
		update_path_and_reconnect(netpath, vnic);
		break;
	case VNIC_SECNP_DISCONNECTED:
		netpath = &vnic->secondary_path;
		netpath_timer_stop(netpath);
		netpath->carrier = 0;
		update_path_and_reconnect(netpath, vnic);
		break;
	case VNIC_NP_FREEVNIC:
		vnic_handle_free_vnic_evt(vnic);
		kfree(vnic);
		vnic = NULL;
		break;
	case VNIC_NP_SETLINK:
		netpath = vnic->current_path;
		if (!netpath || !netpath->viport)
			break;
		viport_set_link(netpath->viport,
				vnic->netdevice.flags,
				vnic->netdevice.mtu);
		break;
	}
	return vnic;
}

static int vnic_npevent_statemachine(void *context)
{
	struct vnic_npevent	*vnic_link_evt;
	enum vnic_npevent_type	npevt_type;
	struct vnic		*vnic;
	int			last_carrier;
	int			other_path_ok = 0;
	struct netpath		*last_path;

	daemonize("vnic_link_evt");

	while (!vnic_npevent_thread_end ||
	       !list_empty(&vnic_npevent_list)) {
		unsigned long flags;

		wait_event_interruptible(vnic_npevent_queue,
					 !list_empty(&vnic_npevent_list)
					 || vnic_npevent_thread_end);
		spin_lock_irqsave(&vnic_npevent_list_lock, flags);
		if (list_empty(&vnic_npevent_list)) {
			spin_unlock_irqrestore(&vnic_npevent_list_lock,
					       flags);
			VNIC_INFO("netpath statemachine wake"
				  " on empty list\n");
			continue;
		}

		vnic_link_evt = list_entry(vnic_npevent_list.next,
					   struct vnic_npevent,
					   list_ptrs);
		list_del(&vnic_link_evt->list_ptrs);
		spin_unlock_irqrestore(&vnic_npevent_list_lock, flags);
		vnic = vnic_link_evt->vnic;
		npevt_type = vnic_link_evt->event_type;
		kfree(vnic_link_evt);

		if (vnic->current_path == &vnic->secondary_path)
			other_path_ok = vnic->primary_path.carrier;
		else if (vnic->current_path == &vnic->primary_path)
			other_path_ok = vnic->secondary_path.carrier;

		vnic = vnic_handle_npevent(vnic, npevt_type);

		if (!vnic)
			continue;

		last_carrier = vnic->carrier;
		last_path = vnic->current_path;

		if (!vnic->current_path ||
		    !vnic->current_path->carrier) {
			vnic->carrier = 0;
			vnic->current_path = NULL;
			vnic->netdevice.features &= ~NETIF_F_IP_CSUM;
		}

		if (!vnic->carrier)
			vnic_carrier_loss(vnic, last_path);
		else if ((vnic->current_path != &vnic->primary_path) &&
			 (vnic->config->prefer_primary) &&
			 (vnic->primary_path.carrier))
				vnic_check_primary_path_timer(vnic);

		if (last_path)
			vnic_report_path_change(vnic, last_path,
						other_path_ok);

		VNIC_INFO("new netpath=%s, carrier=%d\n",
			  netpath_to_string(vnic, vnic->current_path),
			  vnic->carrier);

		if (vnic->current_path != last_path)
			vnic_handle_path_change(vnic, &last_path);

		if (vnic->carrier != last_carrier) {
			if (vnic->carrier) {
				VNIC_INFO("netif_carrier_on\n");
				netif_carrier_on(&vnic->netdevice);
				vnic_carrier_loss_stats(vnic);
			} else {
				VNIC_INFO("netif_carrier_off\n");
				netif_carrier_off(&vnic->netdevice);
				vnic_disconn_stats(vnic);
			}

		}
	}
	complete_and_exit(&vnic_npevent_thread_exit, 0);
	return 0;
}

void vnic_npevent_queue_evt(struct netpath *netpath,
			    enum vnic_npevent_type evt)
{
	struct vnic_npevent *npevent;
	unsigned long flags;

	npevent = kmalloc(sizeof *npevent, GFP_ATOMIC);
	if (!npevent) {
		VNIC_ERROR("Could not allocate memory for vnic event\n");
		return;
	}
	npevent->vnic = netpath->parent;
	npevent->event_type = evt;
	INIT_LIST_HEAD(&npevent->list_ptrs);
	spin_lock_irqsave(&vnic_npevent_list_lock, flags);
	list_add_tail(&npevent->list_ptrs, &vnic_npevent_list);
	spin_unlock_irqrestore(&vnic_npevent_list_lock, flags);
	wake_up(&vnic_npevent_queue);
}

void vnic_npevent_dequeue_evt(struct netpath *netpath,
			      enum vnic_npevent_type evt)
{
	unsigned long flags;
	struct vnic_npevent *npevt, *tmp;
	struct vnic * vnic = netpath->parent;

	spin_lock_irqsave(&vnic_npevent_list_lock, flags);
	if (list_empty(&vnic_npevent_list))
		goto out;
	list_for_each_entry_safe(npevt, tmp, &vnic_npevent_list,
				 list_ptrs) {
		if ((npevt->vnic == vnic) &&
		    (npevt->event_type == evt)) {
			list_del(&npevt->list_ptrs);
			kfree(npevt);
			break;
		}
	}
out:
	spin_unlock_irqrestore(&vnic_npevent_list_lock, flags);
}

static int vnic_npevent_start(void)
{
	VNIC_FUNCTION("vnic_npevent_start()\n");

	if ((vnic_npevent_thread =
	     kernel_thread(vnic_npevent_statemachine, NULL, 0)) < 0) {
		printk(KERN_WARNING PFX "failed to create vnic npevent"
		       " thread; error %d\n", vnic_npevent_thread);
		return vnic_npevent_thread;
	}

	return 0;
}

void vnic_npevent_cleanup(void)
{
	if (vnic_npevent_thread >= 0) {
		vnic_npevent_thread_end = 1;
		wake_up(&vnic_npevent_queue);
		wait_for_completion(&vnic_npevent_thread_exit);
		vnic_npevent_thread = -1;
	}
}

struct vnic *vnic_allocate(struct vnic_config *config)
{
	struct vnic *vnic = NULL;
	struct net_device *device;

	VNIC_FUNCTION("vnic_allocate()\n");
	vnic = kzalloc(sizeof *vnic, GFP_KERNEL);
	if (!vnic) {
		VNIC_ERROR("failed allocating vnic structure\n");
		return NULL;
	}

	vnic->lock = SPIN_LOCK_UNLOCKED;
	vnic_alloc_stats(vnic);
	vnic->state = VNIC_UNINITIALIZED;
	vnic->config = config;
	device = &vnic->netdevice;

	strcpy(device->name, config->name);

	ether_setup(device);

	device->priv			= (void *)vnic;
	device->get_stats		= vnic_get_stats;
	device->open			= vnic_open;
	device->stop			= vnic_stop;
	device->hard_start_xmit		= vnic_hard_start_xmit;
	device->tx_timeout		= vnic_tx_timeout;
	device->set_multicast_list	= vnic_set_multicast_list;
	device->set_mac_address		= vnic_set_mac_address;
	device->change_mtu		= vnic_change_mtu;
	device->watchdog_timeo 		= 10 * HZ;
	device->features		= 0;

	netpath_init(&vnic->primary_path, vnic, 0);
	netpath_init(&vnic->secondary_path, vnic, 1);

	vnic->current_path = NULL;

	list_add_tail(&vnic->list_ptrs, &vnic_list);

	return vnic;
}

void vnic_free(struct vnic *vnic)
{
	VNIC_FUNCTION("vnic_free()\n");
	list_del(&vnic->list_ptrs);
	vnic_npevent_queue_evt(&vnic->primary_path, VNIC_NP_FREEVNIC);
}

static void __exit vnic_cleanup(void)
{
	VNIC_FUNCTION("vnic_cleanup()\n");

	VNIC_INIT("unloading %s\n", MODULEDETAILS);

	while (!list_empty(&vnic_list)) {
		struct vnic *vnic =
		    list_entry(vnic_list.next, struct vnic, list_ptrs);
		vnic_free(vnic);
	}

	vnic_npevent_cleanup();
	viport_cleanup();
	vnic_ib_cleanup();
}

static int __init vnic_init(void)
{
	int ret;
	VNIC_FUNCTION("vnic_init()\n");
	VNIC_INIT("Initializing %s\n", MODULEDETAILS);

	if ((ret=config_start())) {
		VNIC_ERROR("config_start failed\n");
		goto failure;
	}

	if ((ret=vnic_ib_init())) {
		VNIC_ERROR("ib_start failed\n");
		goto failure;
	}

	if ((ret=viport_start())) {
		VNIC_ERROR("viport_start failed\n");
		goto failure;
	}

	if ((ret=vnic_npevent_start())) {
		VNIC_ERROR("vnic_npevent_start failed\n");
		goto failure;
	}

	return 0;
failure:
	vnic_cleanup();
	return ret;
}

module_init(vnic_init);
module_exit(vnic_cleanup);
