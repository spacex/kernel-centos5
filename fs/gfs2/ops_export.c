/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/buffer_head.h>
#include <linux/gfs2_ondisk.h>
#include <linux/crc32.h>
#include <linux/lm_interface.h>

#include "gfs2.h"
#include "incore.h"
#include "dir.h"
#include "glock.h"
#include "glops.h"
#include "inode.h"
#include "super.h"
#include "rgrp.h"
#include "util.h"

#define GFS2_SMALL_FH_SIZE 4
#define GFS2_LARGE_FH_SIZE 8

static struct dentry *gfs2_decode_fh(struct super_block *sb,
				     __u32 *p,
				     int fh_len,
				     int fh_type,
				     int (*acceptable)(void *context,
						       struct dentry *dentry),
				     void *context)
{
	__be32 *fh = (__force __be32 *)p;
	struct gfs2_inum_host inum, parent;

	memset(&parent, 0, sizeof(struct gfs2_inum));

	switch (fh_type) {
	case GFS2_LARGE_FH_SIZE:
		parent.no_formal_ino = ((u64)be32_to_cpu(fh[4])) << 32;
		parent.no_formal_ino |= be32_to_cpu(fh[5]);
		parent.no_addr = ((u64)be32_to_cpu(fh[6])) << 32;
		parent.no_addr |= be32_to_cpu(fh[7]);
	case GFS2_SMALL_FH_SIZE:
		inum.no_formal_ino = ((u64)be32_to_cpu(fh[0])) << 32;
		inum.no_formal_ino |= be32_to_cpu(fh[1]);
		inum.no_addr = ((u64)be32_to_cpu(fh[2])) << 32;
		inum.no_addr |= be32_to_cpu(fh[3]);
		break;
	default:
		return NULL;
	}

	return gfs2_export_ops.find_exported_dentry(sb, &inum, &parent,
						    acceptable, context);
}

static int gfs2_encode_fh(struct dentry *dentry, __u32 *p, int *len,
			  int connectable)
{
	__be32 *fh = (__force __be32 *)p;
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct gfs2_inode *ip = GFS2_I(inode);

	if (*len < GFS2_SMALL_FH_SIZE ||
	    (connectable && *len < GFS2_LARGE_FH_SIZE))
		return 255;

	fh[0] = cpu_to_be32(ip->i_no_formal_ino >> 32);
	fh[1] = cpu_to_be32(ip->i_no_formal_ino & 0xFFFFFFFF);
	fh[2] = cpu_to_be32(ip->i_no_addr >> 32);
	fh[3] = cpu_to_be32(ip->i_no_addr & 0xFFFFFFFF);
	*len = GFS2_SMALL_FH_SIZE;

	if (!connectable || inode == sb->s_root->d_inode)
		return *len;

	spin_lock(&dentry->d_lock);
	inode = dentry->d_parent->d_inode;
	ip = GFS2_I(inode);
	igrab(inode);
	spin_unlock(&dentry->d_lock);

	fh[4] = cpu_to_be32(ip->i_no_formal_ino >> 32);
	fh[5] = cpu_to_be32(ip->i_no_formal_ino & 0xFFFFFFFF);
	fh[6] = cpu_to_be32(ip->i_no_addr >> 32);
	fh[7] = cpu_to_be32(ip->i_no_addr & 0xFFFFFFFF);
	*len = GFS2_LARGE_FH_SIZE;

	iput(inode);

	return *len;
}

struct get_name_filldir {
	struct gfs2_inum_host inum;
	char *name;
};

static int get_name_filldir(void *opaque, const char *name, int length,
			    loff_t offset, u64 inum, unsigned int type)
{
	struct get_name_filldir *gnfd = opaque;

	if (inum != gnfd->inum.no_addr)
		return 0;

	memcpy(gnfd->name, name, length);
	gnfd->name[length] = 0;

	return 1;
}

static int gfs2_get_name(struct dentry *parent, char *name,
			 struct dentry *child)
{
	struct inode *dir = parent->d_inode;
	struct inode *inode = child->d_inode;
	struct gfs2_inode *dip, *ip;
	struct get_name_filldir gnfd;
	struct gfs2_holder gh;
	u64 offset = 0;
	int error;

	if (!dir)
		return -EINVAL;

	if (!S_ISDIR(dir->i_mode) || !inode)
		return -EINVAL;

	dip = GFS2_I(dir);
	ip = GFS2_I(inode);

	*name = 0;
	gnfd.inum.no_addr = ip->i_no_addr;
	gnfd.inum.no_formal_ino = ip->i_no_formal_ino;
	gnfd.name = name;

	error = gfs2_glock_nq_init(dip->i_gl, LM_ST_SHARED, 0, &gh);
	if (error)
		return error;

	error = gfs2_dir_read(dir, &offset, &gnfd, get_name_filldir);

	gfs2_glock_dq_uninit(&gh);

	if (!error && !*name)
		error = -ENOENT;

	return error;
}

static struct dentry *gfs2_get_parent(struct dentry *child)
{
	struct qstr dotdot;
	struct inode *inode;
	struct dentry *dentry;

	gfs2_str2qstr(&dotdot, "..");
	inode = gfs2_lookupi(child->d_inode, &dotdot, 1, NULL);

	if (!inode)
		return ERR_PTR(-ENOENT);
	/*
	 * In case of an error, @inode carries the error value, and we
	 * have to return that as a(n invalid) pointer to dentry.
	 */
	if (IS_ERR(inode))
		return ERR_PTR(PTR_ERR(inode));

	dentry = d_alloc_anon(inode);
	if (!dentry) {
		iput(inode);
		return ERR_PTR(-ENOMEM);
	}

	dentry->d_op = &gfs2_dops;
	return dentry;
}

static struct dentry *gfs2_get_dentry(struct super_block *sb, void *inum_obj)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;
	struct gfs2_inum_host *inum = inum_obj;
	struct inode *inode;
	struct dentry *dentry;

	inode = gfs2_ilookup(sb, inum->no_addr);
	if (inode) {
		if (GFS2_I(inode)->i_no_formal_ino != inum->no_formal_ino) {
			iput(inode);
			return ERR_PTR(-ESTALE);
		}
	} else {
		inode = gfs2_lookup_by_inum(sdp, inum->no_addr,
					    &inum->no_formal_ino,
					    GFS2_BLKST_DINODE);
		if (inode == ERR_PTR(-ENOENT))
			inode = gfs2_ilookup(sb, inum->no_addr);
	}

	if (IS_ERR(inode))
		return ERR_CAST(inode);

	dentry = d_alloc_anon(inode);
	if (!dentry) {
		iput(inode);
		return ERR_PTR(-ENOMEM);
	}

	dentry->d_op = &gfs2_dops;
	return dentry;
}

const struct export_operations gfs2_export_ops = {
	.decode_fh = gfs2_decode_fh,
	.encode_fh = gfs2_encode_fh,
	.get_name = gfs2_get_name,
	.get_parent = gfs2_get_parent,
	.get_dentry = gfs2_get_dentry,
};

