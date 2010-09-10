#ifndef __WIRELESS_SYSFS_H
#define __WIRELESS_SYSFS_H

extern int wiphy_sysfs_init(void);
extern void wiphy_sysfs_exit(void);

#if 0 /* Not in RHEL5... */
extern struct class ieee80211_class;
#else
extern struct bus_type ieee80211_bus_type;
extern struct device ieee80211_bus;
extern void wiphy_dev_release(struct device *dev);
#endif

#endif /* __WIRELESS_SYSFS_H */
