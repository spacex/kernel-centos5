/*
 * File...........: linux/fs/partitions/ibm.c
 * Author(s)......: Holger Smolinski <Holger.Smolinski@de.ibm.com>
 *                  Volker Sameske <sameske@de.ibm.com>
 * Bugreports.to..: <Linux390@de.ibm.com>
 * (C) IBM Corporation, IBM Deutschland Entwicklung GmbH, 1999,2000
 */

#include <linux/buffer_head.h>
#include <linux/hdreg.h>
#include <linux/slab.h>
#include <asm/dasd.h>
#include <asm/ebcdic.h>
#include <asm/uaccess.h>
#include <asm/vtoc.h>

#include "check.h"
#include "ibm.h"

/*
 * compute the block number from a
 * cyl-cyl-head-head structure
 */
static sector_t
cchh2blk (struct vtoc_cchh *ptr, struct hd_geometry *geo) {

	sector_t cyl;
	__u16 head;

	/*decode cylinder and heads for large volumes */
	cyl = ptr->hh & 0xFFF0;
	cyl <<= 12;
	cyl |= ptr->cc;
	head = ptr->hh & 0x000F;
	return cyl * geo->heads * geo->sectors +
	       head * geo->sectors;
}

/*
 * compute the block number from a
 * cyl-cyl-head-head-block structure
 */
static sector_t
cchhb2blk (struct vtoc_cchhb *ptr, struct hd_geometry *geo) {

	sector_t cyl;
	__u16 head;

	/*decode cylinder and heads for large volumes */
	cyl = ptr->hh & 0xFFF0;
	cyl <<= 12;
	cyl |= ptr->cc;
	head = ptr->hh & 0x000F;
	return  cyl * geo->heads * geo->sectors +
		head * geo->sectors +
		ptr->b;
}

/*
 */
int
ibm_partition(struct parsed_partitions *state, struct block_device *bdev)
{
	int blocksize, res;
	loff_t i_size, offset, size, fmt_size;
	dasd_information_t *info;
	struct hd_geometry *geo;
	char type[5] = {0,};
	char name[7] = {0,};
	union label_t {
		struct vtoc_volume_label_cdl vol;
		struct vtoc_volume_label_ldl lnx;
		struct vtoc_cms_label cms;
	} *label;
	unsigned char *data;
	Sector sect;
	
	res = 0;
	blocksize = bdev_hardsect_size(bdev);
	if (blocksize <= 0)
		goto out_exit;
	i_size = i_size_read(bdev->bd_inode);
	if (i_size == 0)
		goto out_exit;

	if ((info = kmalloc(sizeof(dasd_information_t), GFP_KERNEL)) == NULL)
		goto out_exit;
	if ((geo = kmalloc(sizeof(struct hd_geometry), GFP_KERNEL)) == NULL)
		goto out_nogeo;
	if ((label = kmalloc(sizeof(union label_t), GFP_KERNEL)) == NULL)
		goto out_nolab;

	if (ioctl_by_bdev(bdev, BIODASDINFO, (unsigned long)info) != 0 ||
	    ioctl_by_bdev(bdev, HDIO_GETGEO, (unsigned long)geo) != 0)
		goto out_freeall;

	/*
	 * Get volume label, extract name and type.
	 */
	data = read_dev_sector(bdev, info->label_block*(blocksize/512), &sect);
	if (data == NULL)
		goto out_readerr;

	memcpy(label, data, sizeof(union label_t));
	put_dev_sector(sect);

	if ((!info->FBA_layout) && (!strcmp(info->type, "ECKD"))) {
		strncpy(type, label->vol.vollbl, 4);
		strncpy(name, label->vol.volid, 6);
	} else {
		strncpy(type, label->lnx.vollbl, 4);
		strncpy(name, label->lnx.volid, 6);
	}
	EBCASC(type, 4);
	EBCASC(name, 6);
	
	res = 1;

	/*
	 * Three different types: CMS1, VOL1 and LNX1/unlabeled
	 */
	if (strncmp(type, "CMS1", 4) == 0) {
		/*
		 * VM style CMS1 labeled disk
		 */
		blocksize = label->cms.block_size;
		if (label->cms.disk_offset != 0) {
			printk("CMS1/%8s(MDSK):", name);
			/* disk is reserved minidisk */
			offset = label->cms.disk_offset;
			size = (label->cms.block_count - 1) * (blocksize >> 9);
		} else {
			printk("CMS1/%8s:", name);
			offset = (info->label_block + 1);
			size = label->cms.block_count
				* (blocksize >> 9);
		}
		put_partition(state, 1, offset*(blocksize >> 9),
				 size-offset*(blocksize >> 9));
	} else if ((strncmp(type, "VOL1", 4) == 0) &&
		(!info->FBA_layout) && (!strcmp(info->type, "ECKD"))) {
		/*
		 * New style VOL1 labeled disk
		 */
		sector_t blk;
		int counter;

		printk("VOL1/%8s:", name);

		/* get block number and read then go through format1 labels */
		blk = cchhb2blk(&label->vol.vtoc, geo) + 1;
		counter = 0;
		while ((data = read_dev_sector(bdev, blk*(blocksize/512),
					       &sect)) != NULL) {
			struct vtoc_format1_label f1;
			char *ch;

			memcpy(&f1, data, sizeof(struct vtoc_format1_label));
			put_dev_sector(sect);

			/* skip FMT4 / FMT5 / FMT7 labels */
			if (f1.DS1FMTID == _ascebc['4']
			    || f1.DS1FMTID == _ascebc['5']
			    || f1.DS1FMTID == _ascebc['7']
			    || f1.DS1FMTID == _ascebc['9']) {
			        blk++;
				continue;
			}

			/* only FMT1 and 8 labels valid at this point */
			if (f1.DS1FMTID != _ascebc['1'] &&
			    f1.DS1FMTID != _ascebc['8'])
				break;

			/* OK, we got valid partition data */
		        offset = cchh2blk(&f1.DS1EXT1.llimit, geo);
			size  = cchh2blk(&f1.DS1EXT1.ulimit, geo) -
				offset + geo->sectors;
			if (counter >= state->limit)
				break;
			put_partition(state, counter + 1,
				      offset * (blocksize >> 9),
				      size * (blocksize >> 9));

			/* Corrupting the label buffer now to save the stack. */
			EBCASC(f1.DS1DSNAM, 44);
			f1.DS1DSNAM[44] = 0;
			ch = strstr(f1.DS1DSNAM, "PART");
			if (ch != NULL && strncmp(ch + 9, "RAID  ", 6) == 0)
				state->parts[counter + 1].flags = 1;

			counter++;
			blk++;
		}
		if (!data)
		/* Are we not supposed to report this ? */
			goto out_readerr;
	} else {
		/*
		 * Old style LNX1 or unlabeled disk
		 */
		if (strncmp(type, "LNX1", 4) == 0) {
			printk("LNX1/%8s:", name);
			if (label->lnx.ldl_version == 0xf2) {
                                        fmt_size = label->lnx.formatted_blocks
                                                * (blocksize >> 9);
			} else if (!strcmp(info->type, "ECKD")) {
				/* formated w/o large volume support */
                                        fmt_size = geo->cylinders * geo->heads
						* geo->sectors * (blocksize >> 9);
			} else {
				/* old label and no usable disk geometry
				 * (e.g. DIAG) */
				fmt_size = i_size >> 9;
			}
			size = i_size >> 9;
			if (fmt_size < size)
				size = fmt_size;
			offset = (info->label_block + 1);
		} else {
			/* unlabeled disk */
			printk("(nonl)");
			size = i_size >> 9;
			offset = (info->label_block + 1);
		}
		put_partition(state, 1, offset*(blocksize >> 9),
			      size-offset*(blocksize >> 9));
	}

	printk("\n");
	goto out_freeall;


out_readerr:
	res = -1;
out_freeall:
	kfree(label);
out_nolab:
	kfree(geo);
out_nogeo:
	kfree(info);
out_exit:
	return res;
}
