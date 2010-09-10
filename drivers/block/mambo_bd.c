/*
 *  Bogus Block Driver for PowerPC Full System Simulator
 *
 *  (C) Copyright IBM Corporation 2003-2005
 *
 *  Bogus Disk Driver
 *
 *  Author: Eric Van Hensbegren <ericvh@gmail.com>
 *
 *    inspired by drivers/block/nbd.c
 *    written by Pavel Machek and Steven Whitehouse
 *
 *  Some code is from the IBM Full System Simulator Group in ARL
 *  Author: PAtrick Bohrer <IBM Austin Research Lab>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to:
 * Free Software Foundation
 * 51 Franklin Street, Fifth Floor
 * Boston, MA  02111-1301  USA
 *
 */

#include <linux/major.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/ioctl.h>
#include <linux/blkdev.h>
#include <net/sock.h>

#include <asm/systemsim.h>

#include <asm/uaccess.h>
#include <asm/types.h>

#define MAJOR_NR 112
#define MAX_MBD 128

#define MBD_SET_BLKSIZE _IO( 0xab, 1 )
#define MBD_SET_SIZE    _IO( 0xab, 2 )
#define MBD_SET_SIZE_BLOCKS     _IO( 0xab, 7 )
#define MBD_DISCONNECT  _IO( 0xab, 8 )

struct mbd_device {
	int initialized;
	int refcnt;
	int flags;
	struct gendisk *disk;
};

static struct mbd_device mbd_dev[MAX_MBD];

#define BD_INFO_SYNC   0
#define BD_INFO_STATUS 1
#define BD_INFO_BLKSZ  2
#define BD_INFO_DEVSZ  3
#define BD_INFO_CHANGE 4

#define BOGUS_DISK_READ  116
#define BOGUS_DISK_WRITE 117
#define BOGUS_DISK_INFO  118

static inline int
MamboBogusDiskRead(int devno, void *buf, ulong sect, ulong nrsect)
{
	return callthru3(BOGUS_DISK_READ, (unsigned long)buf,
			 (unsigned long)sect,
			 (unsigned long)((nrsect << 16) | devno));
}

static inline int
MamboBogusDiskWrite(int devno, void *buf, ulong sect, ulong nrsect)
{
	return callthru3(BOGUS_DISK_WRITE, (unsigned long)buf,
			 (unsigned long)sect,
			 (unsigned long)((nrsect << 16) | devno));
}

static inline int MamboBogusDiskInfo(int op, int devno)
{
	return callthru2(BOGUS_DISK_INFO, (unsigned long)op,
			 (unsigned long)devno);
}

static int mbd_init_disk(int devno)
{
	struct gendisk *disk = mbd_dev[devno].disk;
	unsigned int sz;

	if (!__onsim())
		return -1;

	/* check disk configured */
	if (!MamboBogusDiskInfo(BD_INFO_STATUS, devno)) {
		printk(KERN_ERR
		       "Attempting to open bogus disk before initializaiton\n");
		return 0;
	}

	mbd_dev[devno].initialized++;

	sz = MamboBogusDiskInfo(BD_INFO_DEVSZ, devno);

	if (sz == -1)
		return 0;

	printk("Initializing disk %d with devsz %u\n", devno, sz);

	set_capacity(disk, sz << 1);

	return 1;
}

static void do_mbd_request(request_queue_t * q)
{
	int result = 0;
	struct request *req;

	while ((req = elv_next_request(q)) != NULL) {
		int minor = req->rq_disk->first_minor;

		switch (rq_data_dir(req)) {
		case READ:
			result = MamboBogusDiskRead(minor,
						    req->buffer, req->sector,
						    req->current_nr_sectors);
			break;
		case WRITE:
			result = MamboBogusDiskWrite(minor,
						     req->buffer, req->sector,
						     req->current_nr_sectors);
		};

		if (result)
			end_request(req, 0);	/* failure */
		else
			end_request(req, 1);	/* success */
	}
}

static int mbd_release(struct inode *inode, struct file *file)
{
	struct mbd_device *lo;
	int dev;

	if (!inode)
		return -ENODEV;
	dev = inode->i_bdev->bd_disk->first_minor;
	if (dev >= MAX_MBD)
		return -ENODEV;
	if (MamboBogusDiskInfo(BD_INFO_SYNC, dev) < 0) {
		printk(KERN_ALERT "mbd_release: unable to sync\n");
	}
	lo = &mbd_dev[dev];
	if (lo->refcnt <= 0)
		printk(KERN_ALERT "mbd_release: refcount(%d) <= 0\n",
		       lo->refcnt);
	lo->refcnt--;
	return 0;
}

static int mbd_revalidate(struct gendisk *disk)
{
	int devno = disk->first_minor;

	mbd_init_disk(devno);

	return 0;
}

static int mbd_open(struct inode *inode, struct file *file)
{
	int dev;

	if (!inode)
		return -EINVAL;
	dev = inode->i_bdev->bd_disk->first_minor;
	if (dev >= MAX_MBD)
		return -ENODEV;

	check_disk_change(inode->i_bdev);

	if (!mbd_dev[dev].initialized)
		if (!mbd_init_disk(dev))
			return -ENODEV;

	mbd_dev[dev].refcnt++;
	return 0;
}

static struct block_device_operations mbd_fops = {
      owner:THIS_MODULE,
      open:mbd_open,
      release:mbd_release,
	/* media_changed:      mbd_check_change, */
      revalidate_disk:mbd_revalidate,
};

static spinlock_t mbd_lock = SPIN_LOCK_UNLOCKED;

static int __init mbd_init(void)
{
	int err = -ENOMEM;
	int i;

	for (i = 0; i < MAX_MBD; i++) {
		struct gendisk *disk = alloc_disk(1);
		if (!disk)
			goto out;
		mbd_dev[i].disk = disk;
		/*
		 * The new linux 2.5 block layer implementation requires
		 * every gendisk to have its very own request_queue struct.
		 * These structs are big so we dynamically allocate them.
		 */
		disk->queue = blk_init_queue(do_mbd_request, &mbd_lock);
		if (!disk->queue) {
			put_disk(disk);
			goto out;
		}
	}

	if (register_blkdev(MAJOR_NR, "mbd")) {
		err = -EIO;
		goto out;
	}
#ifdef MODULE
	printk("mambo bogus disk: registered device at major %d\n", MAJOR_NR);
#else
	printk("mambo bogus disk: compiled in with kernel\n");
#endif

	for (i = 0; i < MAX_MBD; i++) {	/* load defaults */
		struct gendisk *disk = mbd_dev[i].disk;
		mbd_dev[i].initialized = 0;
		mbd_dev[i].refcnt = 0;
		mbd_dev[i].flags = 0;
		disk->major = MAJOR_NR;
		disk->first_minor = i;
		disk->fops = &mbd_fops;
		disk->private_data = &mbd_dev[i];
		sprintf(disk->disk_name, "mambobd%d", i);
		set_capacity(disk, 0x7ffffc00ULL << 1);	/* 2 TB */
		add_disk(disk);
	}

	return 0;
      out:
	while (i--) {
		if (mbd_dev[i].disk->queue)
			blk_cleanup_queue(mbd_dev[i].disk->queue);
		put_disk(mbd_dev[i].disk);
	}
	return -EIO;
}

static void __exit mbd_cleanup(void)
{
	if (unregister_blkdev(MAJOR_NR, "mbd") != 0)
		printk("mbd: cleanup_module failed\n");
	else
		printk("mbd: module cleaned up.\n");
}

module_init(mbd_init);
module_exit(mbd_cleanup);

MODULE_DESCRIPTION("Mambo Block Device");
MODULE_LICENSE("GPL");
