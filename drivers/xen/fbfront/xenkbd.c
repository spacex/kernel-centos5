/*
 * linux/drivers/input/keyboard/xenkbd.c -- Xen para-virtual input device
 *
 * Copyright (C) 2005 Anthony Liguori <aliguori@us.ibm.com>
 * Copyright (C) 2006 Red Hat, Inc., Markus Armbruster <armbru@redhat.com>
 *
 *  Based on linux/drivers/input/mouse/sermouse.c
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License. See the file COPYING in the main directory of this archive for
 *  more details.
 */

/*
 * TODO:
 *
 * Switch to grant tables together with xenfb.c.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/input.h>
#include <asm/hypervisor.h>
#include <xen/evtchn.h>
#include <xen/interface/io/fbif.h>
#include <xen/interface/io/kbdif.h>
#include <xen/xenbus.h>

struct xenkbd_info
{
	struct input_dev *dev;
	struct xenkbd_page *page;
	unsigned evtchn;
	int irq;
	struct xenbus_device *xbdev;
};

static int abs_pointer;
module_param(abs_pointer, bool, 0);
MODULE_PARM_DESC(abs_pointer, "Enable absolute pointer mode");

static int xenkbd_remove(struct xenbus_device *);
static int xenkbd_connect_backend(struct xenbus_device *, struct xenkbd_info *);
static void xenkbd_disconnect_backend(struct xenkbd_info *);

/*
 * Note: if you need to send out events, see xenfb_do_update() for how
 * to do that.
 */

static irqreturn_t input_handler(int rq, void *dev_id, struct pt_regs *regs)
{
	struct xenkbd_info *info = dev_id;
	struct xenkbd_page *page = info->page;
	__u32 cons, prod;

	prod = page->in_prod;
	if (prod == page->in_cons)
		return IRQ_HANDLED;
	rmb();			/* ensure we see ring contents up to prod */
	for (cons = page->in_cons; cons != prod; cons++) {
		union xenkbd_in_event *event;
		event = &XENKBD_IN_RING_REF(page, cons);

		switch (event->type) {
		case XENKBD_TYPE_MOTION:
			if (event->motion.rel_z)
				input_report_rel(info->dev, REL_WHEEL,
						 -event->motion.rel_z);
			input_report_rel(info->dev, REL_X, event->motion.rel_x);
			input_report_rel(info->dev, REL_Y, event->motion.rel_y);
			break;
		case XENKBD_TYPE_KEY:
			input_report_key(info->dev, event->key.keycode, event->key.pressed);
			break;
		case XENKBD_TYPE_POS:
			if (event->pos.rel_z)
				input_report_rel(info->dev, REL_WHEEL,
						 -event->pos.rel_z);
			input_report_abs(info->dev, ABS_X, event->pos.abs_x);
			input_report_abs(info->dev, ABS_Y, event->pos.abs_y);
			break;
		}
	}
	input_sync(info->dev);
	mb();			/* ensure we got ring contents */
	page->in_cons = cons;
	notify_remote_via_evtchn(info->evtchn);

	return IRQ_HANDLED;
}

int __devinit xenkbd_probe(struct xenbus_device *dev,
			   const struct xenbus_device_id *id)
{
	int ret, i;
	struct xenkbd_info *info;
	struct input_dev *input_dev;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating info structure");
		return -ENOMEM;
	}
	dev->dev.driver_data = info;
	info->xbdev = dev;
	info->irq = -1;

	info->page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!info->page)
		goto error_nomem;

	input_dev = input_allocate_device();
	if (!input_dev)
		goto error_nomem;

	input_dev->evbit[0] = BIT(EV_KEY) | BIT(EV_REL) | BIT(EV_ABS);
	input_dev->keybit[LONG(BTN_MOUSE)]
		= BIT(BTN_LEFT) | BIT(BTN_MIDDLE) | BIT(BTN_RIGHT);
	/* TODO additional buttons */
	input_dev->relbit[0] = BIT(REL_X) | BIT(REL_Y) | BIT(REL_WHEEL);

	/* FIXME not sure this is quite right */
	for (i = 0; i < 256; i++)
		set_bit(i, input_dev->keybit);

	input_dev->name = "Xen Virtual Keyboard/Mouse";

	input_set_abs_params(input_dev, ABS_X, 0, XENFB_WIDTH, 0, 0);
	input_set_abs_params(input_dev, ABS_Y, 0, XENFB_HEIGHT, 0, 0);

	ret = input_register_device(input_dev);
	if (ret) {
		input_free_device(input_dev);
		xenbus_dev_fatal(dev, ret, "input_register_device");
		goto error;
	}
	info->dev = input_dev;

	ret = xenkbd_connect_backend(dev, info);
	if (ret < 0)
		goto error;

	return 0;

 error_nomem:
	ret = -ENOMEM;
	xenbus_dev_fatal(dev, ret, "allocating device memory");
 error:
	xenkbd_remove(dev);
	return ret;
}

static int xenkbd_resume(struct xenbus_device *dev)
{
	struct xenkbd_info *info = dev->dev.driver_data;

	xenkbd_disconnect_backend(info);
	memset(info->page, 0, PAGE_SIZE);
	return xenkbd_connect_backend(dev, info);
}

static int xenkbd_remove(struct xenbus_device *dev)
{
	struct xenkbd_info *info = dev->dev.driver_data;

	xenkbd_disconnect_backend(info);
	if (info->dev)
		input_unregister_device(info->dev);
	free_page((unsigned long)info->page);
	kfree(info);
	return 0;
}

static int xenkbd_connect_backend(struct xenbus_device *dev,
				  struct xenkbd_info *info)
{
	int ret;
	struct xenbus_transaction xbt;

	ret = xenbus_alloc_evtchn(dev, &info->evtchn);
	if (ret)
		return ret;
	ret = bind_evtchn_to_irqhandler(info->evtchn, input_handler, 0,
					"xenkbd", info);
	if (ret < 0) {
		xenbus_free_evtchn(dev, info->evtchn);
		xenbus_dev_fatal(dev, ret, "bind_evtchn_to_irqhandler");
		return ret;
	}
	info->irq = ret;

 again:
	ret = xenbus_transaction_start(&xbt);
	if (ret) {
		xenbus_dev_fatal(dev, ret, "starting transaction");
		return ret;
	}
	ret = xenbus_printf(xbt, dev->nodename, "page-ref", "%lu",
			    virt_to_mfn(info->page));
	if (ret)
		goto error_xenbus;
	ret = xenbus_printf(xbt, dev->nodename, "event-channel", "%u",
			    info->evtchn);
	if (ret)
		goto error_xenbus;
	ret = xenbus_transaction_end(xbt, 0);
	if (ret) {
		if (ret == -EAGAIN)
			goto again;
		xenbus_dev_fatal(dev, ret, "completing transaction");
		return ret;
	}

	xenbus_switch_state(dev, XenbusStateInitialised);
	return 0;

 error_xenbus:
	xenbus_transaction_end(xbt, 1);
	xenbus_dev_fatal(dev, ret, "writing xenstore");
	return ret;
}

static void xenkbd_disconnect_backend(struct xenkbd_info *info)
{
	if (info->irq >= 0)
		unbind_from_irqhandler(info->irq, info);
	info->irq = -1;
}

static void xenkbd_backend_changed(struct xenbus_device *dev,
				   enum xenbus_state backend_state)
{
	struct xenkbd_info *info = dev->dev.driver_data;
	int ret, val;

	switch (backend_state) {
	case XenbusStateInitialising:
	case XenbusStateInitialised:
	case XenbusStateUnknown:
	case XenbusStateClosed:
		break;

	case XenbusStateInitWait:
	InitWait:
		if (abs_pointer) {
			ret = xenbus_scanf(XBT_NIL, info->xbdev->otherend,
					   "feature-abs-pointer", "%d", &val);
			if (ret < 0)
				val = 0;
			if (val) {
				ret = xenbus_printf(XBT_NIL, info->xbdev->nodename,
						    "request-abs-pointer", "1");
				if (ret)
					; /* FIXME */
			}
		}
		xenbus_switch_state(dev, XenbusStateConnected);
		break;

	case XenbusStateConnected:
		/*
		 * Work around xenbus race condition: If backend goes
		 * through InitWait to Connected fast enough, we can
		 * get Connected twice here.
		 */
		if (dev->state != XenbusStateConnected)
			goto InitWait; /* no InitWait seen yet, fudge it */
		break;

	case XenbusStateClosing:
		xenbus_frontend_closed(dev);
		break;
	}
}

static struct xenbus_device_id xenkbd_ids[] = {
	{ "vkbd" },
	{ "" }
};

static struct xenbus_driver xenkbd = {
	.name = "vkbd",
	.owner = THIS_MODULE,
	.ids = xenkbd_ids,
	.probe = xenkbd_probe,
	.remove = xenkbd_remove,
	.resume = xenkbd_resume,
	.otherend_changed = xenkbd_backend_changed,
};

static int __init xenkbd_init(void)
{
	if (!is_running_on_xen())
		return -ENODEV;

	/* Nothing to do if running in dom0. */
	if (is_initial_xendomain())
		return -ENODEV;

	return xenbus_register_frontend(&xenkbd);
}

static void __exit xenkbd_cleanup(void)
{
	return xenbus_unregister_driver(&xenkbd);
}

module_init(xenkbd_init);
module_exit(xenkbd_cleanup);

MODULE_LICENSE("GPL");
