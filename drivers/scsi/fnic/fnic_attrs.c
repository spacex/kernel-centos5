/*
 * Copyright 2008 Cisco Systems, Inc.  All rights reserved.
 * Copyright 2007 Nuova Systems, Inc.  All rights reserved.
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/skbuff.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/device.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include "vnic_dev.h"
#include "vnic_intr.h"
#include "vnic_stats.h"
#include "fnic_io.h"
#include "fnic.h"

static ssize_t fnic_show_state(struct class_device *cdev, char *buf)
{
	struct fc_lport *lp = shost_priv(class_to_shost(cdev));
	struct fnic *fnic = lport_priv(lp);

	return snprintf(buf, PAGE_SIZE, "%s\n", fnic_state_str[fnic->state]);
}

static ssize_t fnic_show_drv_version(struct class_device *cdev, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", DRV_VERSION);
}

static ssize_t fnic_show_link_state(struct class_device *cdev, char *buf)
{
	struct fc_lport *lp = shost_priv(class_to_shost(cdev));

	return snprintf(buf, PAGE_SIZE, "%s\n", (lp->link_status & FC_LINK_UP)
			? "Link Up" : "Link Down");
}

static CLASS_DEVICE_ATTR(fnic_state, S_IRUGO, fnic_show_state, NULL);
static CLASS_DEVICE_ATTR(drv_version, S_IRUGO, fnic_show_drv_version, NULL);
static CLASS_DEVICE_ATTR(link_state, S_IRUGO, fnic_show_link_state, NULL);

struct class_device_attribute *fnic_attrs[] = {
	&class_device_attr_fnic_state,
	&class_device_attr_drv_version,
	&class_device_attr_link_state,
	NULL,
};
