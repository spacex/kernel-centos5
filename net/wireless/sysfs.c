/*
 * This file provides /sys/class/ieee80211/<wiphy name>/
 * and some default attributes.
 *
 * Copyright 2005-2006	Jiri Benc <jbenc@suse.cz>
 * Copyright 2006	Johannes Berg <johannes@sipsolutions.net>
 *
 * This file is GPLv2 as found in COPYING.
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/nl80211.h>
#include <linux/rtnetlink.h>
#include <net/cfg80211.h>
#include "sysfs.h"
#include "core.h"

static inline struct cfg80211_registered_device *cdev_to_rdev(
	struct class_device *cdev)
{
	return container_of(cdev, struct cfg80211_registered_device,
			    wiphy.class_dev);
}

static ssize_t _show_index(struct class_device *cdev,
			   char *buf)
{
	return sprintf(buf, "%d\n", cdev_to_rdev(cdev)->idx);
}

static ssize_t _show_permaddr(struct class_device *cdev,
			      char *buf)
{
	char *addr = cdev_to_rdev(cdev)->wiphy.perm_addr;

	return sprintf(buf, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		       addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static struct class_device_attribute ieee80211_class_dev_attrs[] = {
	__ATTR(index, S_IRUGO, _show_index, NULL),
	__ATTR(macaddress, S_IRUGO, _show_permaddr, NULL),
	{}
};

static void wiphy_class_dev_release(struct class_device *cdev)
{
	struct cfg80211_registered_device *dev = cdev_to_rdev(cdev);

	cfg80211_dev_free(dev);
}

static int wiphy_uevent(struct class_device *cdev, char **envp,
			int num_envp, char *buf, int size)
{
	return 0;
}

struct class ieee80211_class = {
	.name = "ieee80211",
	.owner = THIS_MODULE,
	.release = wiphy_class_dev_release,
	.class_dev_attrs = ieee80211_class_dev_attrs,
#ifdef CONFIG_HOTPLUG
	.uevent = wiphy_uevent,
#endif
};

int wiphy_sysfs_init(void)
{
	return class_register(&ieee80211_class);
}

void wiphy_sysfs_exit(void)
{
	class_unregister(&ieee80211_class);
}
