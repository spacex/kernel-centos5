#ifndef __MAC80211_COMPAT_H__
#define __MAC80211_COMPAT_H__

/*
 * Bits copied from compat-wireless-2.6
 *
 * git://git.kernel.org/pub/scm/linux/kernel/git/mcgrof/compat-wireless-2.6.git
 */

/*
 * The net_device has a spin_lock on newer kernels, on older kernels we're out of luck
 */
#define netif_addr_lock_bh
#define netif_addr_unlock_bh

extern int		__dev_addr_sync(struct dev_addr_list **to, int *to_count, struct dev_addr_list **from, int *from_count);
extern void		__dev_addr_unsync(struct dev_addr_list **to, int *to_count, struct dev_addr_list **from, int *from_count);

#endif /* __MAC80211_COMPAT_H__ */
