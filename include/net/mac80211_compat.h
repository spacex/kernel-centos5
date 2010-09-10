#ifndef __MAC80211_COMPAT_H__
#define __MAC80211_COMPAT_H__

#define BIT(nr)			(1UL << (nr))

/*
 *      We tag multicasts with these structures.
 */

#define dev_addr_list	dev_mc_list
#define da_addr        dmi_addr
#define da_addrlen     dmi_addrlen
#define da_users       dmi_users
#define da_gusers      dmi_gusers

extern void	dev_mc_unsync(struct net_device *to, struct net_device *from);
extern int	dev_mc_sync(struct net_device *to, struct net_device *from);

extern void	__dev_set_rx_mode(struct net_device *dev);

#ifndef __maybe_unused
#define __maybe_unused
#endif

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
extern char *print_mac(char *buf, const u8 *addr);
#define DECLARE_MAC_BUF(var) char var[18] __maybe_unused

#ifndef uninitialized_var
#define uninitialized_var(x)	x = x
#endif

#endif /* __MAC80211_COMPAT_H__ */
