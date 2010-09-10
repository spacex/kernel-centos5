#ifndef BACKPORT_LINUX_NETDEVICE_TO_2_6_18
#define BACKPORT_LINUX_NETDEVICE_TO_2_6_18
#include_next <linux/netdevice.h>

static inline int skb_checksum_help_to_2_6_18(struct sk_buff *skb)
{
        return skb_checksum_help(skb, 0);
}

#define skb_checksum_help skb_checksum_help_to_2_6_18

#undef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev, ops) \
	(netdev)->ethtool_ops = (struct ethtool_ops *)(ops)

#endif
