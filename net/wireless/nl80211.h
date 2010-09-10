#ifndef __NET_WIRELESS_NL80211_H
#define __NET_WIRELESS_NL80211_H

#include "core.h"

/**
 * enum nl80211_multicast_groups - multicast groups for nl80211
 * @NL80211_GROUP_CONFIG: members of this group are notified of
 *     configuration changes
 * @NL80211_GROUP_SCAN: members of this group are notified of
 *     scan results
 * @NL80211_GROUP_REGULATORY: members of this group are notified of
 *     regulatory changes
 * @NL80211_GROUP_MLME: members of this group are notified of
 *     MLME events
 */
enum nl80211_multicast_groups {
	/* be notified of configuration changes like wiphy renames */
	NL80211_GROUP_CONFIG,
	/* be notified of scan results */
	NL80211_GROUP_SCAN,
	/* be notified of regulatory changes */
	NL80211_GROUP_REGULATORY,
	/* be notified of MLME events */
	NL80211_GROUP_MLME,

	/* add groups here */

	/* keep last */
	__NL80211_GROUP_AFTER_LAST
};
#define NL80211_GROUP_MAX (__NL80211_GROUP_AFTER_LAST - 1)

int nl80211_init(void);
void nl80211_exit(void);
void nl80211_notify_dev_rename(struct cfg80211_registered_device *rdev);
void nl80211_send_scan_start(struct cfg80211_registered_device *rdev,
			     struct net_device *netdev);
void nl80211_send_scan_done(struct cfg80211_registered_device *rdev,
			    struct net_device *netdev);
void nl80211_send_scan_aborted(struct cfg80211_registered_device *rdev,
			       struct net_device *netdev);
void nl80211_send_reg_change_event(struct regulatory_request *request);
void nl80211_send_rx_auth(struct cfg80211_registered_device *rdev,
			  struct net_device *netdev,
			  const u8 *buf, size_t len, gfp_t gfp);
void nl80211_send_rx_assoc(struct cfg80211_registered_device *rdev,
			   struct net_device *netdev,
			   const u8 *buf, size_t len, gfp_t gfp);
void nl80211_send_deauth(struct cfg80211_registered_device *rdev,
			 struct net_device *netdev,
			 const u8 *buf, size_t len, gfp_t gfp);
void nl80211_send_disassoc(struct cfg80211_registered_device *rdev,
			   struct net_device *netdev,
			   const u8 *buf, size_t len, gfp_t gfp);
void nl80211_send_auth_timeout(struct cfg80211_registered_device *rdev,
			       struct net_device *netdev,
			       const u8 *addr, gfp_t gfp);
void nl80211_send_assoc_timeout(struct cfg80211_registered_device *rdev,
				struct net_device *netdev,
				const u8 *addr, gfp_t gfp);
void nl80211_send_connect_result(struct cfg80211_registered_device *rdev,
				 struct net_device *netdev, const u8 *bssid,
				 const u8 *req_ie, size_t req_ie_len,
				 const u8 *resp_ie, size_t resp_ie_len,
				 u16 status, gfp_t gfp);
void nl80211_send_roamed(struct cfg80211_registered_device *rdev,
			 struct net_device *netdev, const u8 *bssid,
			 const u8 *req_ie, size_t req_ie_len,
			 const u8 *resp_ie, size_t resp_ie_len, gfp_t gfp);
void nl80211_send_disconnected(struct cfg80211_registered_device *rdev,
			       struct net_device *netdev, u16 reason,
			       const u8 *ie, size_t ie_len, bool from_ap);

void
nl80211_michael_mic_failure(struct cfg80211_registered_device *rdev,
			    struct net_device *netdev, const u8 *addr,
			    enum nl80211_key_type key_type,
			    int key_id, const u8 *tsc, gfp_t gfp);

void
nl80211_send_beacon_hint_event(struct wiphy *wiphy,
			       struct ieee80211_channel *channel_before,
			       struct ieee80211_channel *channel_after);

void nl80211_send_ibss_bssid(struct cfg80211_registered_device *rdev,
			     struct net_device *netdev, const u8 *bssid,
			     gfp_t gfp);

#endif /* __NET_WIRELESS_NL80211_H */
