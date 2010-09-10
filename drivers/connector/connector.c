/*
 * 	connector.c
 * 
 * 2004-2005 Copyright (c) Evgeniy Polyakov <johnpol@2ka.mipt.ru>
 * All rights reserved.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/moduleparam.h>
#include <linux/connector.h>
#include <linux/mutex.h>

#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Evgeniy Polyakov <johnpol@2ka.mipt.ru>");
MODULE_DESCRIPTION("Generic userspace <-> kernelspace connector.");

static struct cn_dev cdev;

int cn_already_initialized = 0;

/*
 * msg->seq and msg->ack are used to determine message genealogy.
 * When someone sends message it puts there locally unique sequence
 * and random acknowledge numbers.  Sequence number may be copied into
 * nlmsghdr->nlmsg_seq too.
 *
 * Sequence number is incremented with each message to be sent.
 *
 * If we expect reply to our message then the sequence number in
 * received message MUST be the same as in original message, and
 * acknowledge number MUST be the same + 1.
 *
 * If we receive a message and its sequence number is not equal to the
 * one we are expecting then it is a new message.
 *
 * If we receive a message and its sequence number is the same as one
 * we are expecting but it's acknowledgement number is not equal to
 * the acknowledgement number in the original message + 1, then it is
 * a new message.
 *
 */
int cn_netlink_send(struct cn_msg *msg, u32 __group, gfp_t gfp_mask)
{
	struct cn_callback_entry *__cbq;
	unsigned int size;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct cn_msg *data;
	struct cn_dev *dev = &cdev;
	u32 group = 0;
	int found = 0;

	if (!__group) {
		spin_lock_bh(&dev->cbdev->queue_lock);
		list_for_each_entry(__cbq, &dev->cbdev->queue_list,
				    callback_entry) {
			if (cn_cb_equal(&__cbq->id.id, &msg->id)) {
				found = 1;
				group = __cbq->group;
			}
		}
		spin_unlock_bh(&dev->cbdev->queue_lock);

		if (!found)
			return -ENODEV;
	} else {
		group = __group;
	}

	if (!netlink_has_listeners(dev->nls, group))
		return -ESRCH;

	size = NLMSG_SPACE(sizeof(*msg) + msg->len);

	skb = alloc_skb(size, gfp_mask);
	if (!skb)
		return -ENOMEM;

	nlh = NLMSG_PUT(skb, 0, msg->seq, NLMSG_DONE, size - sizeof(*nlh));

	data = NLMSG_DATA(nlh);

	memcpy(data, msg, sizeof(*data) + msg->len);

	NETLINK_CB(skb).dst_group = group;

	return netlink_broadcast(dev->nls, skb, 0, group, gfp_mask);

nlmsg_failure:
	kfree_skb(skb);
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(cn_netlink_send);

/*
 * Callback helper - queues work and setup destructor for given data.
 */
static int cn_call_callback(struct cn_msg *msg, void (*destruct_data)(void *), void *data)
{
	struct cn_callback_entry *__cbq;
	struct cn_dev *dev = &cdev;
	int err = -ENODEV;

	spin_lock_bh(&dev->cbdev->queue_lock);
	list_for_each_entry(__cbq, &dev->cbdev->queue_list, callback_entry) {
		if (cn_cb_equal(&__cbq->id.id, &msg->id)) {
			if (likely(!test_bit(0, &__cbq->work.pending) &&
					__cbq->data.ddata == NULL)) {
				__cbq->data.callback_priv = msg;

				__cbq->data.ddata = data;
				__cbq->data.destruct_data = destruct_data;

				if (queue_work(dev->cbdev->cn_queue,
						&__cbq->work))
					err = 0;
			} else {
				struct work_struct *w;
				struct cn_callback_data *d;
				
				w = kzalloc(sizeof(*w) + sizeof(*d), GFP_ATOMIC);
				if (w) {
					d = (struct cn_callback_data *)(w+1);

					d->callback_priv = msg;
					d->callback = __cbq->data.callback;
					d->ddata = data;
					d->destruct_data = destruct_data;
					d->free = w;

					INIT_LIST_HEAD(&w->entry);
					w->pending = 0;
					w->func = &cn_queue_wrapper;
					w->data = d;
					init_timer(&w->timer);
					
					if (queue_work(dev->cbdev->cn_queue, w))
						err = 0;
					else {
						kfree(w);
						err = -EINVAL;
					}
				} else
					err = -ENOMEM;
			}
			break;
		}
	}
	spin_unlock_bh(&dev->cbdev->queue_lock);

	return err;
}

/*
 * Skb receive helper - checks skb and msg size and calls callback
 * helper.
 */
static int __cn_rx_skb(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	u32 pid, uid, seq, group;
	struct cn_msg *msg;

	pid = NETLINK_CREDS(skb)->pid;
	uid = NETLINK_CREDS(skb)->uid;
	seq = nlh->nlmsg_seq;
	group = NETLINK_CB((skb)).dst_group;
	msg = NLMSG_DATA(nlh);

	return cn_call_callback(msg, (void (*)(void *))kfree_skb, skb);
}

/*
 * Main netlink receiving function.
 *
 * It checks skb and netlink header sizes and calls the skb receive
 * helper with a shared skb.
 */
static void cn_rx_skb(struct sk_buff *__skb)
{
	struct nlmsghdr *nlh;
	u32 len;
	int err;
	struct sk_buff *skb;

	skb = skb_get(__skb);

	if (skb->len >= NLMSG_SPACE(0)) {
		nlh = (struct nlmsghdr *)skb->data;

		if (nlh->nlmsg_len < sizeof(struct cn_msg) ||
		    skb->len < nlh->nlmsg_len ||
		    nlh->nlmsg_len > CONNECTOR_MAX_MSG_SIZE) {
			kfree_skb(skb);
			goto out;
		}

		len = NLMSG_ALIGN(nlh->nlmsg_len);
		if (len > skb->len)
			len = skb->len;

		err = __cn_rx_skb(skb, nlh);
		if (err < 0)
			kfree_skb(skb);
	}

out:
	kfree_skb(__skb);
}

/*
 * Netlink socket input callback - dequeues the skbs and calls the
 * main netlink receiving function.
 */
static void cn_input(struct sock *sk, int len)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL)
		cn_rx_skb(skb);
}

/*
 * Callback add routing - adds callback with given ID and name.
 * If there is registered callback with the same ID it will not be added.
 *
 * May sleep.
 */
int cn_add_callback(struct cb_id *id, char *name, void (*callback)(void *))
{
	int err;
	struct cn_dev *dev = &cdev;

	if (!cn_already_initialized)
		return -EAGAIN;

	err = cn_queue_add_callback(dev->cbdev, name, id, callback);
	if (err)
		return err;

	return 0;
}
EXPORT_SYMBOL_GPL(cn_add_callback);

/*
 * Callback remove routing - removes callback
 * with given ID.
 * If there is no registered callback with given
 * ID nothing happens.
 *
 * May sleep while waiting for reference counter to become zero.
 */
void cn_del_callback(struct cb_id *id)
{
	struct cn_dev *dev = &cdev;

	cn_queue_del_callback(dev->cbdev, id);
}
EXPORT_SYMBOL_GPL(cn_del_callback);

static int __devinit cn_init(void)
{
	struct cn_dev *dev = &cdev;

	dev->input = cn_input;

	dev->nls = netlink_kernel_create(NETLINK_CONNECTOR,
					 CN_NETLINK_USERS + 0xf,
					 dev->input, THIS_MODULE);
	if (!dev->nls)
		return -EIO;

	dev->cbdev = cn_queue_alloc_dev("cqueue", dev->nls);
	if (!dev->cbdev) {
		if (dev->nls->sk_socket)
			sock_release(dev->nls->sk_socket);
		return -EINVAL;
	}
	
	cn_already_initialized = 1;

	return 0;
}

static void __devexit cn_fini(void)
{
	struct cn_dev *dev = &cdev;

	cn_already_initialized = 0;

	cn_queue_free_dev(dev->cbdev);
	if (dev->nls->sk_socket)
		sock_release(dev->nls->sk_socket);
}

subsys_initcall(cn_init);
module_exit(cn_fini);
