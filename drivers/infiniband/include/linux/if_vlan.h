#ifndef __BACKPORT_LINUX_IF_VLAN_H_TO_2_6_20__
#define __BACKPORT_LINUX_IF_VLAN_H_TO_2_6_20__

#include_next <linux/if_vlan.h>

#define vlan_dev_info(x) VLAN_DEV_INFO(x)

static inline u16 vlan_dev_vlan_id(const struct net_device *dev)
{
	return vlan_dev_info(dev)->vlan_id;
}

#define vlan_dev_real_dev(netdev) (VLAN_DEV_INFO(netdev)->real_dev)
#define vlan_dev_vlan_id(netdev) (VLAN_DEV_INFO(netdev)->vlan_id)

static inline int is_vlan_dev(struct net_device *dev)
{
	return dev->priv_flags & IFF_802_1Q_VLAN;
}

#endif
