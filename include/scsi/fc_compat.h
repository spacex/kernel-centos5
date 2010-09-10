/*
 * Compat helpers for libfc
 */
#ifndef _FC_COMPAT_H_
#define _FC_COMPAT_H_

#include <asm/unaligned.h>
#include <linux/workqueue.h>
#include <linux/scatterlist.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>

#ifndef for_each_sg
#define for_each_sg(sglist, __sg, nr, __i)        \
	for (__i = 0, __sg = (sglist); __i < (nr); __i++, __sg = sg_next(__sg))

static inline struct scatterlist *sg_next(struct scatterlist *sg)
{       
	if (!sg)
		return NULL;
	return sg + 1;
}

static inline struct page *sg_page(struct scatterlist *sg)
{ 
	return sg->page;
}
#endif

#define BIT(nr) (1UL << (nr))

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_BUF_SIZE 18
#define DECLARE_MAC_BUF(var) char var[MAC_BUF_SIZE]

static size_t _format_mac_addr(char *buf, int buflen,
                                const unsigned char *addr, int len)
{
	int i;
	char *cp = buf;

	for (i = 0; i < len; i++) {
		cp += scnprintf(cp, buflen - (cp - buf), "%02x", addr[i]);
		if (i == len - 1)
			break;
		cp += strlcpy(cp, ":", buflen - (cp - buf));
	}
	return cp - buf;
}

static inline char *print_mac(char *buf, const unsigned char *addr)
{
	_format_mac_addr(buf, MAC_BUF_SIZE, addr, ETH_ALEN);
	return buf;
}

#define dev_get_by_name(_inet, _name)  dev_get_by_name(_name)

#define vlan_dev_real_dev(_ndev) VLAN_DEV_INFO(_ndev)->real_dev
#define vlan_dev_vlan_id(_ndev) VLAN_DEV_INFO(_ndev)->vlan_id

#define dev_unicast_add(_netdev, _addr) \
	dev_set_promiscuity(_netdev, 1)
#define dev_unicast_delete(_netdev, _addr) \
	dev_set_promiscuity(_netdev, -1);

#define put_unaligned_be64(_val, _ptr) put_unaligned(cpu_to_be64(_val), _ptr)
#define get_unaligned_be64(_ptr) be64_to_cpu(get_unaligned(_ptr))

#define kmem_cache_create(_name, _size, _align, _flags, _ctor) \
	kmem_cache_create(_name, _size, _align, _flags, _ctor, NULL)

#define flush_work(_wk) flush_scheduled_work()

struct delayed_work {
        struct work_struct work;
};

static inline int cancel_delayed_work_sync(struct delayed_work *dwork)
{
	int ret;

	ret = cancel_delayed_work(&dwork->work);
	if (!ret)
		flush_scheduled_work();
	return ret;
}

#define cancel_delayed_work(_dwork) cancel_delayed_work(&(_dwork)->work)

static inline int schedule_delayed_work_compat(struct delayed_work *work,
					       unsigned long delay)
{
	if (likely(!delay))
		return schedule_work(&work->work);
	else
		return schedule_delayed_work(&work->work, delay);
}

static inline void INIT_WORK_compat(struct work_struct *work, void *func)
{
        INIT_WORK(work, func, work);
}

static inline int queue_delayed_work_compat(struct workqueue_struct *wq,
					    struct delayed_work *dwork,
					    unsigned long delay)
{
	return queue_delayed_work(wq, &dwork->work, delay);
}

#undef INIT_WORK
#define INIT_WORK(_work, _func) INIT_WORK_compat(_work, _func)
#define INIT_DELAYED_WORK(_work,_func) INIT_WORK(&(_work)->work, _func)

#define queue_delayed_work queue_delayed_work_compat
#define schedule_delayed_work schedule_delayed_work_compat

#define cancel_work_sync(_wk) flush_work(_wk)

#define __alloc_percpu(_sz, _align) __alloc_percpu(_sz)
#undef alloc_percpu
#define alloc_percpu(_sz) __alloc_percpu(sizeof(_sz), 0)

#define nr_cpu_ids NR_CPUS

static inline int dev_ethtool_get_settings(struct net_device *netdev,
				    struct ethtool_cmd *ecmd)
{
	return netdev->ethtool_ops->get_settings(netdev, ecmd);
}

#endif
