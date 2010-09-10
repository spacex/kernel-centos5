/*
 * Copyright(c) 2007 - 2008 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Maintained at www.Open-FCoE.org
 */

#include <linux/pci.h>
#include <scsi/libfcoe.h>
#include <scsi/fc_transport_fcoe.h>

/* internal fcoe transport */
struct fcoe_transport_internal {
	struct fcoe_transport *t;
	struct net_device *netdev;
	struct list_head list;
};

/* fcoe transports list and its lock */
static LIST_HEAD(fcoe_transports);
static DEFINE_MUTEX(fcoe_transports_lock);

/**
 * fcoe_transport_default - returns ptr to the default transport fcoe_sw
 **/
struct fcoe_transport *fcoe_transport_default(void)
{
	return &fcoe_sw_transport;
}

/**
 * fcoe_transport_device_lookup - find out netdev is managed by the
 * transport
 * assign a transport to a device
 * @netdev: the netdev the transport to be attached to
 *
 * This will look for existing offload driver, if not found, it falls back to
 * the default sw hba (fcoe_sw) as its fcoe transport.
 *
 * Returns: 0 for success
 **/
static struct fcoe_transport_internal *fcoe_transport_device_lookup(
	struct fcoe_transport *t, struct net_device *netdev)
{
	struct fcoe_transport_internal *ti;

	/* assign the transpor to this device */
	mutex_lock(&t->devlock);
	list_for_each_entry(ti, &t->devlist, list) {
		if (ti->netdev == netdev) {
			mutex_unlock(&t->devlock);
			return ti;
		}
	}
	mutex_unlock(&t->devlock);
	return NULL;
}
/**
 * fcoe_transport_device_add - assign a transport to a device
 * @netdev: the netdev the transport to be attached to
 *
 * This will look for existing offload driver, if not found, it falls back to
 * the default sw hba (fcoe_sw) as its fcoe transport.
 *
 * Returns: 0 for success
 **/
static int fcoe_transport_device_add(struct fcoe_transport *t,
				     struct net_device *netdev)
{
	struct fcoe_transport_internal *ti;

	ti = fcoe_transport_device_lookup(t, netdev);
	if (ti) {
		printk(KERN_DEBUG "fcoe_transport_device_add:"
		       "device %s is already added to transport %s\n",
		       netdev->name, t->name);
		return -EEXIST;
	}
	/* allocate an internal struct to host the netdev and the list */
	ti = kzalloc(sizeof(*ti), GFP_KERNEL);
	if (!ti)
		return -ENOMEM;

	ti->t = t;
	ti->netdev = netdev;
	INIT_LIST_HEAD(&ti->list);
	dev_hold(ti->netdev);

	mutex_lock(&t->devlock);
	list_add(&ti->list, &t->devlist);
	mutex_unlock(&t->devlock);

	printk(KERN_DEBUG "fcoe_transport_device_add:"
		       "device %s added to transport %s\n",
		       netdev->name, t->name);

	return 0;
}

/**
 * fcoe_transport_device_remove - remove a device from its transport
 * @netdev: the netdev the transport to be attached to
 *
 * this removes the device from the transport so the given transport will
 * not manage this device any more
 *
 * Returns: 0 for success
 **/
static int fcoe_transport_device_remove(struct fcoe_transport *t,
					struct net_device *netdev)
{
	struct fcoe_transport_internal *ti;

	ti = fcoe_transport_device_lookup(t, netdev);
	if (!ti) {
		printk(KERN_DEBUG "fcoe_transport_device_remove:"
		       "device %s is not managed by transport %s\n",
		       netdev->name, t->name);
		return -ENODEV;
	}
	mutex_lock(&t->devlock);
	list_del(&ti->list);
	mutex_unlock(&t->devlock);
	printk(KERN_DEBUG "fcoe_transport_device_remove:"
	       "device %s removed from transport %s\n",
	       netdev->name, t->name);
	dev_put(ti->netdev);
	kfree(ti);
	return 0;
}

/**
 * fcoe_transport_device_remove_all - remove all from transport devlist
 *
 * this removes the device from the transport so the given transport will
 * not manage this device any more
 *
 * Returns: 0 for success
 **/
static void fcoe_transport_device_remove_all(struct fcoe_transport *t)
{
	struct fcoe_transport_internal *ti, *tmp;

	mutex_lock(&t->devlock);
	list_for_each_entry_safe(ti, tmp, &t->devlist, list) {
		list_del(&ti->list);
		kfree(ti);
	}
	mutex_unlock(&t->devlock);
}

/**
 * fcoe_transport_register - adds a fcoe transport to the fcoe transports list
 * @t: ptr to the fcoe transport to be added
 *
 * Returns: 0 for success
 **/
int fcoe_transport_register(struct fcoe_transport *t)
{
	struct fcoe_transport *tt;

	/* TODO - add fcoe_transport specific initialization here */
	mutex_lock(&fcoe_transports_lock);
	list_for_each_entry(tt, &fcoe_transports, list) {
		if (tt == t) {
			mutex_unlock(&fcoe_transports_lock);
			return -EEXIST;
		}
	}
	list_add_tail(&t->list, &fcoe_transports);
	mutex_unlock(&fcoe_transports_lock);

	mutex_init(&t->devlock);
	INIT_LIST_HEAD(&t->devlist);

	printk(KERN_DEBUG "fcoe_transport_register:%s\n", t->name);

	return 0;
}
EXPORT_SYMBOL_GPL(fcoe_transport_register);

/**
 * fcoe_transport_unregister - remove the tranport fro the fcoe transports list
 * @t: ptr to the fcoe transport to be removed
 *
 * Returns: 0 for success
 **/
int fcoe_transport_unregister(struct fcoe_transport *t)
{
	struct fcoe_transport *tt, *tmp;

	mutex_lock(&fcoe_transports_lock);
	list_for_each_entry_safe(tt, tmp, &fcoe_transports, list) {
		if (tt == t) {
			list_del(&t->list);
			mutex_unlock(&fcoe_transports_lock);
			fcoe_transport_device_remove_all(t);
			printk(KERN_DEBUG "fcoe_transport_unregister:%s\n",
			       t->name);
			return 0;
		}
	}
	mutex_unlock(&fcoe_transports_lock);
	return -ENODEV;
}
EXPORT_SYMBOL_GPL(fcoe_transport_unregister);

/**
 * fcoe_transport_attach - load transport to fcoe
 * @netdev: the netdev the transport to be attached to
 *
 * This will look for existing offload driver, if not found, it falls back to
 * the default sw hba (fcoe_sw) as its fcoe transport.
 *
 * Returns: 0 for success
 **/
int fcoe_transport_attach(struct net_device *netdev)
{
	struct fcoe_transport *t;

	/* find the corresponding transport */
	t = fcoe_transport_default();
	if (!t) {
		printk(KERN_DEBUG "fcoe_transport_attach"
		       ":no transport for %s:use %s\n",
		       netdev->name, t->name);
		return -ENODEV;
	}
	/* add to the transport */
	if (fcoe_transport_device_add(t, netdev)) {
		printk(KERN_DEBUG "fcoe_transport_attach"
		       ":failed to add %s to tramsport %s\n",
		       netdev->name, t->name);
		return -EIO;
	}
	/* transport create function */
	if (t->create)
		t->create(netdev);

	printk(KERN_DEBUG "fcoe_transport_attach:transport %s for %s\n",
	       t->name, netdev->name);
	return 0;
}
EXPORT_SYMBOL_GPL(fcoe_transport_attach);

/**
 * fcoe_transport_release - unload transport from fcoe
 * @netdev: the net device on which fcoe is to be released
 *
 * Returns: 0 for success
 **/
int fcoe_transport_release(struct net_device *netdev)
{
	struct fcoe_transport *t;

	/* find the corresponding transport */
	t = fcoe_transport_default();
	if (!t) {
		printk(KERN_DEBUG "fcoe_transport_release:"
		       "no transport for %s:use %s\n",
		       netdev->name, t->name);
		return -ENODEV;
	}
	/* remove the device from the transport */
	if (fcoe_transport_device_remove(t, netdev)) {
		printk(KERN_DEBUG "fcoe_transport_release:"
		       "failed to add %s to tramsport %s\n",
		       netdev->name, t->name);
		return -EIO;
	}
	/* transport destroy function */
	if (t->destroy)
		t->destroy(netdev);

	printk(KERN_DEBUG "fcoe_transport_release:"
	       "device %s dettached from transport %s\n",
	       netdev->name, t->name);

	return 0;
}
EXPORT_SYMBOL_GPL(fcoe_transport_release);

/**
 * fcoe_transport_init - initializes fcoe transport layer
 *
 * This prepares for the fcoe transport layer
 *
 * Returns: none
 **/
int __init fcoe_transport_init(void)
{
	INIT_LIST_HEAD(&fcoe_transports);
	mutex_init(&fcoe_transports_lock);
	return 0;
}

/**
 * fcoe_transport_exit - cleans up the fcoe transport layer
 * This cleans up the fcoe transport layer. removing any transport on the list,
 * note that the transport destroy func is not called here.
 *
 * Returns: none
 **/
int __exit fcoe_transport_exit(void)
{
	struct fcoe_transport *t, *tmp;

	mutex_lock(&fcoe_transports_lock);
	list_for_each_entry_safe(t, tmp, &fcoe_transports, list) {
		list_del(&t->list);
		mutex_unlock(&fcoe_transports_lock);
		fcoe_transport_device_remove_all(t);
		mutex_lock(&fcoe_transports_lock);
	}
	mutex_unlock(&fcoe_transports_lock);
	return 0;
}
