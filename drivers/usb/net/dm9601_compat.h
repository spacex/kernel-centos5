#ifndef __DM9601_COMPAT_H__
#define __DM9601_COMPAT_H__

#include <linux/netdevice.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/usb.h>
#include "usbnet.h"

static int usbnet_get_settings(struct net_device *net, struct ethtool_cmd *cmd)
{
	struct usbnet *dev = netdev_priv(net);

	if (!dev->mii.mdio_read)
		return -EOPNOTSUPP;

	return mii_ethtool_gset(&dev->mii, cmd);
}

static int usbnet_set_settings(struct net_device *net, struct ethtool_cmd *cmd)
{
	struct usbnet *dev = netdev_priv(net);
	int retval;

	if (!dev->mii.mdio_write)
		return -EOPNOTSUPP;

	retval = mii_ethtool_sset(&dev->mii, cmd);

	if (dev->driver_info->link_reset)
		dev->driver_info->link_reset(dev);

	return retval;
}

static int usbnet_nway_reset(struct net_device *net)
{
	struct usbnet *dev = netdev_priv(net);

	if (!dev->mii.mdio_write)
		return -EOPNOTSUPP;

	return mii_nway_restart(&dev->mii);
}

#endif

