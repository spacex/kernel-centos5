#ifndef __R8169_COMPAT_H__
#define __R8169_COMPAT_H__

#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/workqueue.h>

static inline __be16 backport_eth_type_trans(struct sk_buff *skb,
					     struct net_device *dev)
{
	skb->dev = dev;
	return eth_type_trans(skb, dev);
}

#define eth_type_trans backport_eth_type_trans

static inline void vlan_group_set_device(struct vlan_group *vg, int vlan_id,
					 struct net_device *dev)
{
	vg->vlan_devices[vlan_id] = NULL;
}

typedef void (*work_func_t)(struct work_struct *work);

struct delayed_work {
	struct work_struct work;
};

static inline void backport_INIT_WORK(struct work_struct *work, void *func)
{
	INIT_WORK(work, func, work);
}

static inline void backport_PREPARE_WORK(struct work_struct *work, void *func)
{
	PREPARE_WORK(work, func, work);
}

static inline int backport_schedule_delayed_work(struct delayed_work *work,
						 unsigned long delay)
{
	if (likely(!delay))
		return schedule_work(&work->work);
	else
		return schedule_delayed_work(&work->work, delay);
}


#undef INIT_WORK
#define INIT_WORK(_work, _func) backport_INIT_WORK(_work, _func)
#define INIT_DELAYED_WORK(_work,_func) INIT_WORK(&(_work)->work, _func)

#undef PREPARE_WORK
#define PREPARE_WORK(_work, _func) backport_PREPARE_WORK(_work, _func)
#define PREPARE_DELAYED_WORK(_work, _func) PREPARE_WORK(&(_work)->work, _func)

#define schedule_delayed_work backport_schedule_delayed_work

#endif

