/******************************************************************************
 * blkback/vbd.c
 * 
 * Routines for managing virtual block devices (VBDs).
 * 
 * Copyright (c) 2003-2005, Keir Fraser & Steve Hand
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "common.h"
#include <xen/xenbus.h>

#define vbd_sz(_v)   ((_v)->bdev->bd_part ?				\
	(_v)->bdev->bd_part->nr_sects : (_v)->bdev->bd_disk->capacity)

/*
 * Structure holding dummy device information. This structure is shared by
 * all dummy devices as it is used only to fullfil driver requirements and
 * is not significant for guest.
 */
static struct block_device dummy_dev;

/*
 * Function copies device structure taken as argument to dummy structure
 * that is used in case we want to close original device. Function sets
 * all pointer members to 0, except block_device.bd_disk attribute that
 * is used by blkback driver so has to be accessible. 
 */
struct block_device* vbd_dev_dummy_copy(const struct block_device* bdev)
{
	static struct gendisk dummy_disk;

	memcpy(&dummy_dev,bdev,sizeof(struct block_device));
	memcpy(&dummy_disk,bdev->bd_disk,sizeof(struct gendisk));

	dummy_dev.bd_inode = NULL;
	dummy_dev.bd_holder = NULL;
	dummy_dev.bd_contains = NULL;
	dummy_dev.bd_part = NULL;
	dummy_dev.bd_inode_backing_dev_info = NULL;
	dummy_dev.bd_inodes.next = &dummy_dev.bd_inodes;
	dummy_dev.bd_inodes.prev = &dummy_dev.bd_inodes;
	dummy_dev.bd_list.next = &dummy_dev.bd_list;
	dummy_dev.bd_list.prev = &dummy_dev.bd_list;
#ifdef CONFIG_SYSFS
	dummy_dev.bd_holder_list.next = &dummy_dev.bd_holder_list;
	dummy_dev.bd_holder_list.prev = &dummy_dev.bd_holder_list;
#endif
	dummy_dev.bd_disk = &dummy_disk;
	dummy_disk.part = NULL;
	dummy_disk.fops = NULL;
	dummy_disk.queue = NULL;
	dummy_disk.private_data = NULL;
	dummy_disk.driverfs_dev = NULL;
	dummy_disk.holder_dir = NULL;
	dummy_disk.slave_dir = NULL;
	dummy_disk.random = NULL;
#ifdef  CONFIG_SMP
	dummy_disk.dkstats = NULL;
#endif

	return &dummy_dev;
}

/* 
 * Function checks xenstore if device taken as argument is used in
 * hvm. In that case returns 1, otherwise returns 0.
 *
 * For check is used /vm/<uuid>/image record. This contains string 
 * that describes guest.
 */
int vbd_is_hvm(struct xenbus_device *dev)
{
	int id,err;
	char buf[1024];
	char *uuid, *image;
	int ret = 0;

	err = xenbus_scanf(XBT_NIL, dev->nodename, "frontend-id", "%d", &id);
	if (err != 1) {
		xenbus_dev_fatal(dev, err, "Can't read frontend-id");
		return ret;
	}

	sprintf(buf, "/local/domain/%d", id);
	uuid = xenbus_read(XBT_NIL, buf, "vm", NULL);
	if (!uuid) {
		xenbus_dev_fatal(dev, err, "Can't read domain uuid");
		return ret;
	}

	sprintf(buf, "%s", uuid);
	image = xenbus_read(XBT_NIL, buf, "image", NULL);

	if (image && !IS_ERR(image)) {
		if (strstr(image, "(hvm"))
			ret = 1;
		kfree(image); 
	} 

	kfree(uuid);
	
	return ret;
}


unsigned long long vbd_size(struct vbd *vbd)
{
	return vbd_sz(vbd);
}

unsigned int vbd_info(struct vbd *vbd)
{
	return vbd->type | (vbd->readonly?VDISK_READONLY:0);
}

unsigned long vbd_secsize(struct vbd *vbd)
{
	return bdev_hardsect_size(vbd->bdev);
}

int vbd_create(blkif_t *blkif, blkif_vdev_t handle, unsigned major,
	       unsigned minor, int readonly, struct xenbus_device *dev)
{
	struct vbd *vbd;
	struct block_device *bdev;

	vbd = &blkif->vbd;
	vbd->handle   = handle; 
	vbd->readonly = readonly;
	vbd->type     = 0;

	vbd->pdevice  = MKDEV(major, minor);

	bdev = open_by_devnum(vbd->pdevice,
			      vbd->readonly ? FMODE_READ : FMODE_WRITE);

	if (IS_ERR(bdev)) {
		DPRINTK("vbd_creat: device %08x could not be opened.\n",
			vbd->pdevice);
		return -ENOENT;
	}

	vbd->bdev = bdev;

	if (vbd->bdev->bd_disk == NULL) {
		DPRINTK("vbd_creat: device %08x doesn't exist.\n",
			vbd->pdevice);
		vbd_free(vbd);
		return -ENOENT;
	}

	if (vbd->bdev->bd_disk->flags & GENHD_FL_CD) {
		vbd->type |= VDISK_CDROM;
/*
 * When a blkback device is plugged in, blkback driver uses open_by_devnum 
 * to obtain reference to a block_device structure describing device. Calling 
 * open_by_devnum increase use counter. Cdrom driver do not reallocate read
 * buffer after medium change until use count is set to 0. In case of HVM guest
 * qemu opens/close its own handle from user space instead of using handle hold
 * by blkback driver. This behavior leads to situation when use counter's
 * minimal value is 1 and so read buffer is not reallocate and disk size of 
 * previous medium is used. When new medium is bigger than old one, only part
 * equal to old medium size is accessible.
 * As blkback handle is not needed outside blkback driver and blkback driver
 * use this handle only for updating status after plugging in, fake structure
 * can be used to fullfil requirements of blkback driver. Original structure
 * is returned to system so use counter is lowered by one and can be 0.
 */
		if (vbd_is_hvm(dev)) {
			vbd->bdev = vbd_dev_dummy_copy(bdev);
			blkdev_put(bdev);
		}
	}
	if (vbd->bdev->bd_disk->flags & GENHD_FL_REMOVABLE)
		vbd->type |= VDISK_REMOVABLE;

	DPRINTK("Successful creation of handle=%04x (dom=%u)\n",
		handle, blkif->domid);
	return 0;
}

void vbd_free(struct vbd *vbd)
{
	if (vbd->bdev && vbd->bdev != &dummy_dev)
		blkdev_put(vbd->bdev);
	vbd->bdev = NULL;
}

int vbd_translate(struct phys_req *req, blkif_t *blkif, int operation)
{
	struct vbd *vbd = &blkif->vbd;
	int rc = -EACCES;

	if ((operation == WRITE) && vbd->readonly)
		goto out;

	if (unlikely((req->sector_number + req->nr_sects) > vbd_sz(vbd)))
		goto out;

	req->dev  = vbd->pdevice;
	req->bdev = vbd->bdev;
	rc = 0;

 out:
	return rc;
}
