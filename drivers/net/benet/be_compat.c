/*
 * Copyright (C) 2005 - 2009 ServerEngines
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.  The full GNU General
 * Public License is included in this distribution in the file called COPYING.
 *
 * Contact Information:
 * linux-drivers@serverengines.com
 *
 * ServerEngines
 * 209 N. Fair Oaks Ave
 * Sunnyvale, CA 94085
 */

#include "be.h"

/* new netdev backport */
void be_netdev_ops_init(struct net_device *netdev, struct net_device_ops *ops)
{
	netdev->open = ops->ndo_open;
	netdev->stop = ops->ndo_stop;
	netdev->hard_start_xmit = ops->ndo_start_xmit;
	netdev->set_mac_address = ops->ndo_set_mac_address;
	netdev->get_stats = ops->ndo_get_stats;
	netdev->set_multicast_list = ops->ndo_set_rx_mode;
	netdev->change_mtu = ops->ndo_change_mtu;
	netdev->vlan_rx_register = ops->ndo_vlan_rx_register;
	netdev->vlan_rx_add_vid = ops->ndo_vlan_rx_add_vid;
	netdev->vlan_rx_kill_vid = ops->ndo_vlan_rx_kill_vid;
#ifdef CONFIG_NET_POLL_CONTROLLER
	netdev->poll_controller = ops->ndo_poll_controller;
#endif
}

int eth_validate_addr(struct net_device *netdev)
{
	return 1;
}

/* New NAPI backport */
int be_poll_compat(struct net_device *netdev, int *budget)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	u32 work_done, can_do;
	can_do = min(*budget, netdev->quota);
	work_done = be_poll(&adapter->napi, can_do);
	*budget -= work_done;
	netdev->quota -= work_done;
	if (work_done < can_do)
		return 0;
	else
		return 1;
}

