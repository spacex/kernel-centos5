#ifndef _NETXEN_NIC_COMPAT_H
#define _NETXEN_NIC_COMPAT_H

#ifndef list_splice_tail_init
#define list_splice_tail_init list_splice_init
#endif

#ifndef vlan_dev_real_dev
#define vlan_dev_real_dev(dev) VLAN_DEV_INFO(dev)->real_dev
#endif

#ifndef NETIF_F_LRO
#define	NETIF_F_LRO		32768		/* large receive offload */
#endif

#ifndef work_func_t
typedef void (*work_func_t)(void *);
#endif

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

#ifndef pr_err
#define pr_err(fmt, ...) \
	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#endif
#ifndef pr_warning
#define pr_warning(fmt, ...) \
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#endif

#ifndef to_net_dev
#define to_net_dev(class) container_of(class, struct net_device, class_dev)
#endif

#endif
