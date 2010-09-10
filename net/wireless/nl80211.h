#ifndef __NET_WIRELESS_NL80211_H
#define __NET_WIRELESS_NL80211_H

#include "core.h"

#ifdef CONFIG_NL80211

/**
 * enum nl80211_multicast_groups - multicast groups for nl80211
 * @NL80211_GROUP_CONFIG: members of this group are notified of
 *     configuration changes
 */
enum nl80211_multicast_groups {
	/* be notified of configuration changes like wiphy renames */
	NL80211_GROUP_CONFIG,

	/* add groups here */

	/* keep last */
	__NL80211_GROUP_AFTER_LAST
};
#define NL80211_GROUP_MAX (__NL80211_GROUP_AFTER_LAST - 1)

extern int nl80211_init(void);
extern void nl80211_exit(void);
extern void nl80211_notify_dev_rename(struct cfg80211_registered_device *rdev);
#else
static inline int nl80211_init(void)
{
	return 0;
}
static inline void nl80211_exit(void)
{
}
static inline void nl80211_notify_dev_rename(
	struct cfg80211_registered_device *rdev)
{
}
#endif /* CONFIG_NL80211 */

#endif /* __NET_WIRELESS_NL80211_H */
