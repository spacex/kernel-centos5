/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/buffer_head.h>
#include <linux/pagemap.h>
#include <linux/uio.h>
#include <linux/blkdev.h>
#include <linux/mm.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/gfs2_ondisk.h>
#include <linux/ext2_fs.h>
#include <linux/crc32.h>
#include <linux/lm_interface.h>
#include <linux/writeback.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>
#include <linux/mpage.h>

#include "gfs2.h"
#include "incore.h"
#include "bmap.h"
#include "dir.h"
#include "glock.h"
#include "glops.h"
#include "inode.h"
#include "lm.h"
#include "log.h"
#include "meta_io.h"
#include "ops_vm.h"
#include "quota.h"
#include "rgrp.h"
#include "trans.h"
#include "util.h"
#include "eaops.h"
#include "ops_address.h"

/*
 * Most fields left uninitialised to catch anybody who tries to
 * use them. f_flags set to prevent file_accessed() from touching
 * any other part of this. Its use is purely as a flag so that we
 * know (in readpage()) whether or not do to locking.
 */
struct file gfs2_internal_file_sentinel = {
	.f_flags = O_NOATIME|O_RDONLY,
};

static int gfs2_read_actor(read_descriptor_t *desc, struct page *page,
			   unsigned long offset, unsigned long size)
{
	char *kaddr;
	unsigned long count = desc->count;

	if (size > count)
		size = count;

	kaddr = kmap(page);
	memcpy(desc->arg.data, kaddr + offset, size);
	kunmap(page);

	desc->count = count - size;
	desc->written += size;
	desc->arg.buf += size;
	return size;
}

int gfs2_internal_read(struct gfs2_inode *ip, struct file_ra_state *ra_state,
		       char *buf, loff_t *pos, unsigned size)
{
	struct inode *inode = &ip->i_inode;
	read_descriptor_t desc;
	desc.written = 0;
	desc.arg.data = buf;
	desc.count = size;
	desc.error = 0;
	do_generic_mapping_read(inode->i_mapping, ra_state,
				&gfs2_internal_file_sentinel, pos, &desc,
				gfs2_read_actor, 0);
	return desc.written ? desc.written : desc.error;
}

/**
 * gfs2_llseek - seek to a location in a file
 * @file: the file
 * @offset: the offset
 * @origin: Where to seek from (SEEK_SET, SEEK_CUR, or SEEK_END)
 *
 * SEEK_END requires the glock for the file because it references the
 * file's size.
 *
 * Returns: The new offset, or errno
 */

static loff_t gfs2_llseek(struct file *file, loff_t offset, int origin)
{
	struct gfs2_inode *ip = GFS2_I(file->f_mapping->host);
	struct gfs2_holder i_gh;
	loff_t error;

	if (origin == 2) {
		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY,
					   &i_gh);
		if (!error) {
			error = remote_llseek(file, offset, origin);
			gfs2_glock_dq_uninit(&i_gh);
		}
	} else
		error = remote_llseek(file, offset, origin);

	return error;
}

/**
 * gfs2_readdir - Read directory entries from a directory
 * @file: The directory to read from
 * @dirent: Buffer for dirents
 * @filldir: Function used to do the copying
 *
 * Returns: errno
 */

static int gfs2_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	struct inode *dir = file->f_mapping->host;
	struct gfs2_inode *dip = GFS2_I(dir);
	struct gfs2_holder d_gh;
	u64 offset = file->f_pos;
	int error;

	gfs2_holder_init(dip->i_gl, LM_ST_SHARED, 0, &d_gh);
	error = gfs2_glock_nq(&d_gh);
	if (error) {
		gfs2_holder_uninit(&d_gh);
		return error;
	}

	error = gfs2_dir_read(dir, &offset, dirent, filldir);

	gfs2_glock_dq_uninit(&d_gh);

	file->f_pos = offset;

	return error;
}

/**
 * fsflags_cvt
 * @table: A table of 32 u32 flags
 * @val: a 32 bit value to convert
 *
 * This function can be used to convert between fsflags values and
 * GFS2's own flags values.
 *
 * Returns: the converted flags
 */
static u32 fsflags_cvt(const u32 *table, u32 val)
{
	u32 res = 0;
	while(val) {
		if (val & 1)
			res |= *table;
		table++;
		val >>= 1;
	}
	return res;
}

static const u32 fsflags_to_gfs2[32] = {
	[3] = GFS2_DIF_SYNC,
	[4] = GFS2_DIF_IMMUTABLE,
	[5] = GFS2_DIF_APPENDONLY,
	[7] = GFS2_DIF_NOATIME,
	[12] = GFS2_DIF_EXHASH,
	[14] = GFS2_DIF_INHERIT_JDATA,
	[20] = GFS2_DIF_INHERIT_DIRECTIO,
};

static const u32 gfs2_to_fsflags[32] = {
	[gfs2fl_Sync] = FS_SYNC_FL,
	[gfs2fl_Immutable] = FS_IMMUTABLE_FL,
	[gfs2fl_AppendOnly] = FS_APPEND_FL,
	[gfs2fl_NoAtime] = FS_NOATIME_FL,
	[gfs2fl_ExHash] = FS_INDEX_FL,
	[gfs2fl_InheritDirectio] = FS_DIRECTIO_FL,
	[gfs2fl_InheritJdata] = FS_JOURNAL_DATA_FL,
};

static int gfs2_get_flags(struct file *filp, u32 __user *ptr)
{
	struct inode *inode = filp->f_dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int error;
	u32 fsflags;

	gfs2_holder_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
	error = gfs2_glock_nq(&gh);
	if (error)
		return error;

	fsflags = fsflags_cvt(gfs2_to_fsflags, ip->i_diskflags);
	if (!S_ISDIR(inode->i_mode)) {
		if (ip->i_diskflags & GFS2_DIF_JDATA)
			fsflags |= FS_JOURNAL_DATA_FL;
		if (ip->i_diskflags & GFS2_DIF_DIRECTIO)
			fsflags |= FS_DIRECTIO_FL;
	}
	if (put_user(fsflags, ptr))
		error = -EFAULT;

	gfs2_glock_dq(&gh);
	gfs2_holder_uninit(&gh);
	return error;
}

void gfs2_set_inode_flags(struct inode *inode)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	unsigned int flags = inode->i_flags;

	flags &= ~(S_SYNC|S_APPEND|S_IMMUTABLE|S_NOATIME|S_DIRSYNC);
	if (ip->i_diskflags & GFS2_DIF_IMMUTABLE)
		flags |= S_IMMUTABLE;
	if (ip->i_diskflags & GFS2_DIF_APPENDONLY)
		flags |= S_APPEND;
	if (ip->i_diskflags & GFS2_DIF_NOATIME)
		flags |= S_NOATIME;
	if (ip->i_diskflags & GFS2_DIF_SYNC)
		flags |= S_SYNC;
	inode->i_flags = flags;
}

/* Flags that can be set by user space */
#define GFS2_FLAGS_USER_SET (GFS2_DIF_JDATA|			\
			     GFS2_DIF_DIRECTIO|			\
			     GFS2_DIF_IMMUTABLE|		\
			     GFS2_DIF_APPENDONLY|		\
			     GFS2_DIF_NOATIME|			\
			     GFS2_DIF_SYNC|			\
			     GFS2_DIF_SYSTEM|			\
			     GFS2_DIF_INHERIT_DIRECTIO|		\
			     GFS2_DIF_INHERIT_JDATA)

/**
 * gfs2_set_flags - set flags on an inode
 * @inode: The inode
 * @flags: The flags to set
 * @mask: Indicates which flags are valid
 *
 */
static int do_gfs2_set_flags(struct file *filp, u32 reqflags, u32 mask)
{
	struct inode *inode = filp->f_dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct buffer_head *bh;
	struct gfs2_holder gh;
	int error;
	u32 new_flags, flags;

	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	if (error)
		return error;

	flags = ip->i_diskflags;
	new_flags = (flags & ~mask) | (reqflags & mask);
	if ((new_flags ^ flags) == 0)
		goto out;

	error = -EINVAL;
	if ((new_flags ^ flags) & ~GFS2_FLAGS_USER_SET)
		goto out;

	error = -EPERM;
	if (IS_IMMUTABLE(inode) && (new_flags & GFS2_DIF_IMMUTABLE))
		goto out;
	if (IS_APPEND(inode) && (new_flags & GFS2_DIF_APPENDONLY))
		goto out;
	if (((new_flags ^ flags) & GFS2_DIF_IMMUTABLE) &&
	    !capable(CAP_LINUX_IMMUTABLE))
		goto out;
	if (!IS_IMMUTABLE(inode)) {
		error = permission(inode, MAY_WRITE, NULL);
		if (error)
			goto out;
	}
	if ((flags ^ new_flags) & GFS2_DIF_JDATA) {
		if (flags & GFS2_DIF_JDATA)
			gfs2_log_flush(sdp, ip->i_gl);
		error = filemap_fdatawrite(inode->i_mapping);
		if (error)
			goto out;
		error = filemap_fdatawait(inode->i_mapping);
		if (error)
			goto out;
	}
	error = gfs2_trans_begin(sdp, RES_DINODE, 0);
	if (error)
		goto out;
	error = gfs2_meta_inode_buffer(ip, &bh);
	if (error)
		goto out_trans_end;
	gfs2_trans_add_bh(ip->i_gl, bh, 1);
	ip->i_diskflags = new_flags;
	gfs2_dinode_out(ip, bh->b_data);
	brelse(bh);
	gfs2_set_inode_flags(inode);
	gfs2_set_aops(inode);
out_trans_end:
	gfs2_trans_end(sdp);
out:
	gfs2_glock_dq_uninit(&gh);
	return error;
}

static int gfs2_set_flags(struct file *filp, u32 __user *ptr)
{
	struct inode *inode = filp->f_dentry->d_inode;
	u32 fsflags, gfsflags;
	if (get_user(fsflags, ptr))
		return -EFAULT;
	gfsflags = fsflags_cvt(fsflags_to_gfs2, fsflags);
	if (!S_ISDIR(inode->i_mode)) {
		if (gfsflags & GFS2_DIF_INHERIT_JDATA)
			gfsflags ^= (GFS2_DIF_JDATA | GFS2_DIF_INHERIT_JDATA);
		if (gfsflags & GFS2_DIF_INHERIT_DIRECTIO)
			gfsflags ^= (GFS2_DIF_DIRECTIO | GFS2_DIF_INHERIT_DIRECTIO);
		return do_gfs2_set_flags(filp, gfsflags, ~0);
	}
	return do_gfs2_set_flags(filp, gfsflags, ~GFS2_DIF_JDATA);
}

static long gfs2_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch(cmd) {
	case FS_IOC_GETFLAGS:
		return gfs2_get_flags(filp, (u32 __user *)arg);
	case FS_IOC_SETFLAGS:
		return gfs2_set_flags(filp, (u32 __user *)arg);
	}
	return -ENOTTY;
}

/**
 * gfs2_allocate_page_backing - Use bmap to allocate blocks
 * @page: The (locked) page to allocate backing for
 *
 * We try to allocate all the blocks required for the page in
 * one go. This might fail for various reasons, so we keep
 * trying until all the blocks to back this page are allocated.
 * If some of the blocks are already allocated, thats ok too.
 */

static int gfs2_allocate_page_backing(struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct buffer_head bh;
	unsigned long size = PAGE_CACHE_SIZE;
	u64 lblock = page->index << (PAGE_CACHE_SHIFT - inode->i_blkbits);

	do {
		bh.b_state = 0;
		bh.b_size = size;
		gfs2_block_map(inode, lblock, &bh, 1);
		if (!buffer_mapped(&bh))
			return -EIO;
		size -= bh.b_size;
		lblock += (bh.b_size >> inode->i_blkbits);
	} while(size > 0);
	return 0;
}

/**
 * gfs2_page_mkwrite - Make a shared, mmap()ed, page writable
 * @vma: The virtual memory area
 * @page: The page which is about to become writable
 *
 * When the page becomes writable, we need to ensure that we have
 * blocks allocated on disk to back that page.
 */

static int gfs2_page_mkwrite(struct vm_area_struct *vma, struct page *page)
{
	struct inode *inode = vma->vm_file->f_dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	unsigned long last_index;
	u64 pos = page->index << PAGE_CACHE_SHIFT;
	unsigned int data_blocks, ind_blocks, rblocks;
	int alloc_required = 0;
	struct gfs2_holder gh;
	struct gfs2_alloc *al;
	int ret;

	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	ret = gfs2_glock_nq(&gh);
	if (ret)
		goto out;

	set_bit(GIF_SW_PAGED, &ip->i_flags);
	ret = gfs2_write_alloc_required(ip, pos, PAGE_CACHE_SIZE, &alloc_required);
	if (ret || !alloc_required)
		goto out_unlock;

	al = gfs2_alloc_get(ip);
	if (al == NULL) {
		ret = -ENOMEM;
		goto out_unlock;
	}
	ret = gfs2_quota_lock(ip, NO_QUOTA_CHANGE, NO_QUOTA_CHANGE);
	if (ret)
		goto out_alloc_put;
	ret = gfs2_quota_check(ip, ip->i_inode.i_uid, ip->i_inode.i_gid);
	if (ret)
		goto out_quota_unlock;
	gfs2_write_calc_reserv(ip, PAGE_CACHE_SIZE, &data_blocks, &ind_blocks);
	al->al_requested = data_blocks + ind_blocks;
	ret = gfs2_inplace_reserve(ip);
	if (ret)
		goto out_quota_unlock;

	rblocks = RES_DINODE + ind_blocks;
	if (gfs2_is_jdata(ip))
		rblocks += data_blocks ? data_blocks : 1;
	if (ind_blocks || data_blocks)
		rblocks += RES_STATFS + RES_QUOTA;
	ret = gfs2_trans_begin(sdp, rblocks, 0);
	if (ret)
		goto out_trans_fail;

	lock_page(page);
	ret = -EINVAL;
	last_index = ip->i_inode.i_size >> PAGE_CACHE_SHIFT;
	if (page->index > last_index)
		goto out_unlock_page;
	ret = 0;
	if (!PageUptodate(page) || page->mapping != ip->i_inode.i_mapping)
		goto out_unlock_page;
	if (gfs2_is_stuffed(ip)) {
		ret = gfs2_unstuff_dinode(ip, page);
		if (ret)
			goto out_unlock_page;
	}
	ret = gfs2_allocate_page_backing(page);

out_unlock_page:
	unlock_page(page);
	gfs2_trans_end(sdp);
out_trans_fail:
	gfs2_inplace_release(ip);
out_quota_unlock:
	gfs2_quota_unlock(ip);
out_alloc_put:
	gfs2_alloc_put(ip);
out_unlock:
	gfs2_glock_dq(&gh);
out:
	gfs2_holder_uninit(&gh);
	return ret;
}

static int just_schedule(void *word)
{
	schedule();
	return 0;
}

static void wait_on_invalidate(struct gfs2_glock *gl)
{
	might_sleep();
	wait_on_bit(&gl->gl_flags, GLF_INVALIDATE_IN_PROGRESS, just_schedule,
		    TASK_UNINTERRUPTIBLE);
}

static struct page *gfs2_nopage(struct vm_area_struct *area,
				unsigned long address, int *type)
{
	struct file *file = area->vm_file;
	struct inode *inode = file->f_mapping->host;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_glock *gl = ip->i_gl;
	struct gfs2_sbd *sdp = gl->gl_sbd;

	if (likely(file != &gfs2_internal_file_sentinel)) {
		gfs2_glock_hold(gl);
		if (likely(!test_bit(SDF_SHUTDOWN, &sdp->sd_flags)))
			wait_on_invalidate(gl);
		gfs2_glock_put(gl);
	}

	return filemap_nopage(area, address, type);
}

static struct vm_operations_struct gfs2_vm_ops = {
	.nopage = gfs2_nopage,
	.page_mkwrite = gfs2_page_mkwrite,
};


/**
 * gfs2_mmap -
 * @file: The file to map
 * @vma: The VMA which described the mapping
 *
 * There is no need to get a lock here unless we should be updating
 * atime. We ignore any locking errors since the only consequence is
 * a missed atime update (which will just be deferred until later).
 *
 * Returns: 0
 */

static int gfs2_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct gfs2_inode *ip = GFS2_I(file->f_mapping->host);

	if (!(file->f_flags & O_NOATIME)) {
		struct gfs2_holder i_gh;
		int error;

		gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &i_gh);
		error = gfs2_glock_nq(&i_gh);
		file_accessed(file);
		if (error == 0)
			gfs2_glock_dq_uninit(&i_gh);
	}
	vma->vm_ops = &gfs2_vm_ops;

	return 0;
}

/**
 * gfs2_open - open a file
 * @inode: the inode to open
 * @file: the struct file for this opening
 *
 * Returns: errno
 */

static int gfs2_open(struct inode *inode, struct file *file)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder i_gh;
	struct gfs2_file *fp;
	int error;

	fp = kzalloc(sizeof(struct gfs2_file), GFP_KERNEL);
	if (!fp)
		return -ENOMEM;

	mutex_init(&fp->f_fl_mutex);

	gfs2_assert_warn(GFS2_SB(inode), !file->private_data);
	file->private_data = fp;

	if (S_ISREG(ip->i_inode.i_mode)) {
		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY,
					   &i_gh);
		if (error)
			goto fail;

		if (!(file->f_flags & O_LARGEFILE) &&
		    ip->i_disksize > MAX_NON_LFS) {
			error = -EFBIG;
			goto fail_gunlock;
		}

		/* Listen to the Direct I/O flag */

		if (ip->i_diskflags & GFS2_DIF_DIRECTIO)
			file->f_flags |= O_DIRECT;

		gfs2_glock_dq_uninit(&i_gh);
	}

	return 0;

fail_gunlock:
	gfs2_glock_dq_uninit(&i_gh);
fail:
	file->private_data = NULL;
	kfree(fp);
	return error;
}

/**
 * gfs2_close - called to close a struct file
 * @inode: the inode the struct file belongs to
 * @file: the struct file being closed
 *
 * Returns: errno
 */

static int gfs2_close(struct inode *inode, struct file *file)
{
	struct gfs2_sbd *sdp = inode->i_sb->s_fs_info;
	struct gfs2_file *fp;

	fp = file->private_data;
	file->private_data = NULL;

	if (gfs2_assert_warn(sdp, fp))
		return -EIO;

	kfree(fp);

	return 0;
}

/**
 * gfs2_fsync - sync the dirty data for a file (across the cluster)
 * @file: the file that points to the dentry (we ignore this)
 * @dentry: the dentry that points to the inode to sync
 *
 * The VFS will flush "normal" data for us. We only need to worry
 * about metadata here. For journaled data, we just do a log flush
 * as we can't avoid it. Otherwise we can just bale out if datasync
 * is set. For stuffed inodes we must flush the log in order to
 * ensure that all data is on disk.
 *
 * The call to write_inode_now() is there to write back metadata and
 * the inode itself. It does also try and write the data, but thats
 * (hopefully) a no-op due to the VFS having already called filemap_fdatawrite()
 * for us.
 *
 * Returns: errno
 */

static int gfs2_fsync(struct file *file, struct dentry *dentry, int datasync)
{
	struct inode *inode = dentry->d_inode;
	int sync_state = inode->i_state & (I_DIRTY_SYNC|I_DIRTY_DATASYNC);
	int ret = 0;

	if (gfs2_is_jdata(GFS2_I(inode))) {
		gfs2_log_flush(GFS2_SB(inode), GFS2_I(inode)->i_gl);
		return 0;
	}

	if (sync_state != 0) {
		if (!datasync)
			ret = write_inode_now(inode, 0);

		if (gfs2_is_stuffed(GFS2_I(inode)))
			gfs2_log_flush(GFS2_SB(inode), GFS2_I(inode)->i_gl);
	}

	return ret;
}

/**
 * gfs2_setlease - acquire/release a file lease
 * @file: the file pointer
 * @arg: lease type
 * @fl: file lock
 *
 * Returns: errno
 */

static int gfs2_setlease(struct file *file, long arg, struct file_lock **fl)
{
	/*
	 * We don't currently have a way to enforce a lease across the whole
	 * cluster; until we do, disable leases (by just returning -EINVAL)
	 */
	return -EINVAL;
}

/**
 * gfs2_lock - acquire/release a posix lock on a file
 * @file: the file pointer
 * @cmd: either modify or retrieve lock state, possibly wait
 * @fl: type and range of lock
 *
 * Returns: errno
 */

static int gfs2_lock(struct file *file, int cmd, struct file_lock *fl)
{
	struct gfs2_inode *ip = GFS2_I(file->f_mapping->host);
	struct gfs2_sbd *sdp = GFS2_SB(file->f_mapping->host);
	struct lm_lockname name =
		{ .ln_number = ip->i_no_addr,
		  .ln_type = LM_TYPE_PLOCK };

	if (!(fl->fl_flags & FL_POSIX))
		return -ENOLCK;
	if ((ip->i_inode.i_mode & (S_ISGID | S_IXGRP)) == S_ISGID &&
		fl->fl_type != F_UNLCK)
		return -ENOLCK;

	if (sdp->sd_args.ar_localflocks) {
		if (IS_GETLK(cmd)) {
			posix_test_lock(file, fl, NULL);
			return 0;
		} else {
			return posix_lock_file_wait(file, fl);
		}
	}

	if (cmd == F_CANCELLK) {
		/* Hack: */
		cmd = F_SETLK;
		fl->fl_type = F_UNLCK;
	}
	if (IS_GETLK(cmd))
		return gfs2_lm_plock_get(sdp, &name, file, fl);
	else if (fl->fl_type == F_UNLCK)
		return gfs2_lm_punlock(sdp, &name, file, fl);
	else
		return gfs2_lm_plock(sdp, &name, file, cmd, fl);
}

static int do_flock(struct file *file, int cmd, struct file_lock *fl)
{
	struct gfs2_file *fp = file->private_data;
	struct gfs2_holder *fl_gh = &fp->f_fl_gh;
	struct gfs2_inode *ip = GFS2_I(file->f_dentry->d_inode);
	struct gfs2_glock *gl;
	unsigned int state;
	int flags;
	int error = 0;

	state = (fl->fl_type == F_WRLCK) ? LM_ST_EXCLUSIVE : LM_ST_SHARED;
	flags = (IS_SETLKW(cmd) ? 0 : LM_FLAG_TRY) | GL_EXACT | GL_NOCACHE;

	mutex_lock(&fp->f_fl_mutex);

	gl = fl_gh->gh_gl;
	if (gl) {
		if (fl_gh->gh_state == state)
			goto out;
		flock_lock_file_wait(file,
				     &(struct file_lock){.fl_type = F_UNLCK});
		gfs2_glock_dq_wait(fl_gh);
		gfs2_holder_reinit(state, flags, fl_gh);
	} else {
		error = gfs2_glock_get(GFS2_SB(&ip->i_inode), ip->i_no_addr,
				       &gfs2_flock_glops, CREATE, &gl);
		if (error)
			goto out;
		gfs2_holder_init(gl, state, flags, fl_gh);
		gfs2_glock_put(gl);
	}
	error = gfs2_glock_nq(fl_gh);
	if (error) {
		gfs2_holder_uninit(fl_gh);
		if (error == GLR_TRYFAILED)
			error = -EAGAIN;
	} else {
		error = flock_lock_file_wait(file, fl);
		gfs2_assert_warn(GFS2_SB(&ip->i_inode), !error);
	}

out:
	mutex_unlock(&fp->f_fl_mutex);
	return error;
}

static void do_unflock(struct file *file, struct file_lock *fl)
{
	struct gfs2_file *fp = file->private_data;
	struct gfs2_holder *fl_gh = &fp->f_fl_gh;

	mutex_lock(&fp->f_fl_mutex);
	flock_lock_file_wait(file, fl);
	if (fl_gh->gh_gl)
		gfs2_glock_dq_uninit(fl_gh);
	mutex_unlock(&fp->f_fl_mutex);
}

/**
 * gfs2_flock - acquire/release a flock lock on a file
 * @file: the file pointer
 * @cmd: either modify or retrieve lock state, possibly wait
 * @fl: type and range of lock
 *
 * Returns: errno
 */

static int gfs2_flock(struct file *file, int cmd, struct file_lock *fl)
{
	struct gfs2_inode *ip = GFS2_I(file->f_mapping->host);

	if (!(fl->fl_flags & FL_FLOCK))
		return -ENOLCK;
	if (fl->fl_type & LOCK_MAND)
		return -EOPNOTSUPP;

	if (fl->fl_type == F_UNLCK) {
		do_unflock(file, fl);
		return 0;
	} else
		return do_flock(file, cmd, fl);
}

static inline int gfs2_fault_in_pages_readable(const char __user *uaddr,
					       int size)
{
        volatile char c;
        int ret;

        if (unlikely(size == 0))
                return 0;

        ret = __get_user(c, uaddr);
        if (ret == 0) {
                const char __user *end = uaddr + size - 1;

                if (((unsigned long)uaddr & PAGE_MASK) !=
                                ((unsigned long)end & PAGE_MASK))
                        ret = __get_user(c, end);
        }
        return ret;
}

static ssize_t gfs2_perform_write(struct file *file,
				  struct iov_iter *i, loff_t pos)
{
	struct address_space *mapping = file->f_mapping;
	long status = 0;
	ssize_t written = 0;
	unsigned int flags = 0;

	/*
	 * Copies from kernel address space cannot fail (NFSD is a big user).
	 */
	/*if (segment_eq(get_fs(), KERNEL_DS))
	  flags |= AOP_FLAG_UNINTERRUPTIBLE;*/

	do {
		struct page *page;
		pgoff_t index;		/* Pagecache index for current page */
		unsigned long offset;	/* Offset into pagecache page */
		unsigned long bytes;	/* Bytes to write to page */
		size_t copied;		/* Bytes copied from user */
		void *fsdata;

		offset = (pos & (PAGE_CACHE_SIZE - 1));
		index = pos >> PAGE_CACHE_SHIFT;
		bytes = min_t(unsigned long, PAGE_CACHE_SIZE - offset,
						iov_iter_count(i));

again:

		/*
		 * Bring in the user page that we will copy from _first_.
		 * Otherwise there's a nasty deadlock on copying from the
		 * same page as we're writing to, without it being marked
		 * up-to-date.
		 *
		 * Not only is this an optimisation, but it is also required
		 * to check that the address is actually valid, when atomic
		 * usercopies are used, below.
		 */
		if (unlikely(iov_iter_fault_in_readable(i, bytes))) {
			status = -EFAULT;
			break;
		}

		status = gfs2_write_begin(file, mapping, pos, bytes, flags,
						&page, &fsdata);
		if (unlikely(status))
			break;

		/* pagefault disable */
		inc_preempt_count();
		barrier();
		copied = iov_iter_copy_from_user_atomic(page, i, offset, bytes);
		/* pagefault enable */
		barrier();
		dec_preempt_count();
		barrier();
		preempt_check_resched();

		flush_dcache_page(page);

		status = gfs2_write_end(file, mapping, pos, bytes, copied,
					page, fsdata);
		if (unlikely(status < 0))
			break;
		copied = status;

		cond_resched();

		iov_iter_advance(i, copied);
		if (unlikely(copied == 0)) {
			/*
			 * If we were unable to copy any data at all, we must
			 * fall back to a single segment length write.
			 *
			 * If we didn't fallback here, we could livelock
			 * because not all segments in the iov can be copied at
			 * once without a pagefault.
			 */
			bytes = min_t(unsigned long, PAGE_CACHE_SIZE - offset,
						iov_iter_single_seg_count(i));
			goto again;
		}
		pos += copied;
		written += copied;

		balance_dirty_pages_ratelimited(mapping);

	} while (iov_iter_count(i));

	return written ? written : status;
}

static ssize_t
gfs2_file_buffered_write(struct kiocb *iocb, const struct iovec *iov,
			 unsigned long nr_segs, loff_t pos, loff_t *ppos,
			 size_t count, ssize_t written)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	struct inode *inode = mapping->host;
	ssize_t status;
	struct iov_iter i;

	iov_iter_init(&i, iov, nr_segs, count, written);
	status = gfs2_perform_write(file, &i, pos);

	if (likely(status >= 0)) {
		written += status;
		*ppos = pos + status;

		/*
		 * For now, when the user asks for O_SYNC, we'll actually give
		 * O_DSYNC
		 */
		if (unlikely((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
			if (!a_ops->writepage || !is_sync_kiocb(iocb))
				status = generic_osync_inode(inode, mapping,
						OSYNC_METADATA|OSYNC_DATA);
		}
  	}
	
	/*
	 * If we get here for O_DIRECT writes then we must have fallen through
	 * to buffered writes (block instantiation inside i_size).  So we sync
	 * the file data here, to try to honour O_DIRECT expectations.
	 */
	if (unlikely(file->f_flags & O_DIRECT) && written)
		status = filemap_write_and_wait(mapping);

	return written ? written : status;
}

static ssize_t
__gfs2_file_aio_write_nolock(struct kiocb *iocb, const struct iovec *iov,
			     unsigned long nr_segs, loff_t *ppos)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	size_t ocount;		/* original count */
	size_t count;		/* after file limit checks */
	struct inode 	*inode = mapping->host;
	loff_t		pos;
	ssize_t		written;
	ssize_t		err;

	ocount = 0;
	err = generic_segment_checks(iov, &nr_segs, &ocount, VERIFY_READ);
	if (err)
		return err;

	count = ocount;
	pos = *ppos;

	vfs_check_frozen(inode->i_sb, SB_FREEZE_WRITE);

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = mapping->backing_dev_info;
	written = 0;

	if (file->f_flags & O_APPEND) {
		struct dentry *dentry = file->f_dentry;
		struct gfs2_inode *ip = GFS2_I(dentry->d_inode);
		struct gfs2_holder gh;
		ssize_t ret;

		ret = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
		if (ret)
			return ret;
		gfs2_glock_dq_uninit(&gh);
	}

	err = generic_write_checks(file, &pos, &count, S_ISBLK(inode->i_mode));
	if (err)
		goto out;

	if (count == 0)
		goto out;

	err = remove_suid(file->f_dentry);
	if (err)
		goto out;

	file_update_time(file);

	/* coalesce the iovecs and go direct-to-BIO for O_DIRECT */
	if (unlikely(file->f_flags & O_DIRECT)) {
		loff_t endbyte;
		ssize_t written_buffered;

		written = generic_file_direct_write(iocb, iov, &nr_segs, pos,
							ppos, count, ocount);
		if (written < 0 || written == count)
			goto out;
		/*
		 * direct-io write to a hole: fall through to buffered I/O
		 * for completing the rest of the request.
		 */
		pos += written;
		count -= written;
		written_buffered = gfs2_file_buffered_write(iocb, iov,
							    nr_segs, pos,
							    ppos, count,
							    written);
		/*
		 * If gfs2_file_buffered_write() returned a synchronous error
		 * then we want to return the number of bytes which were
		 * direct-written, or the error code if that was zero.  Note
		 * that this differs from normal direct-io semantics, which
		 * will return -EFOO even if some bytes were written.
		 */
		if (written_buffered < 0) {
			err = written_buffered;
			goto out;
		}

		/*
		 * We need to ensure that the page cache pages are written to
		 * disk and invalidated to preserve the expected O_DIRECT
		 * semantics.
		 */
		endbyte = pos + written_buffered - written - 1;
		err = do_sync_file_range(file, pos, endbyte,
					 SYNC_FILE_RANGE_WAIT_BEFORE|
					 SYNC_FILE_RANGE_WRITE|
					 SYNC_FILE_RANGE_WAIT_AFTER);
		if (err == 0) {
			written = written_buffered;
			invalidate_mapping_pages(mapping,
						 pos >> PAGE_CACHE_SHIFT,
						 endbyte >> PAGE_CACHE_SHIFT);
		} else {
			/*
			 * We don't know how much we wrote, so just return
			 * the number of bytes which were direct-written
			 */
		}
	} else {
		written = gfs2_file_buffered_write(iocb, iov, nr_segs,
						   pos, ppos, count, written);
	}
out:
	current->backing_dev_info = NULL;
	return written ? written : err;
}

static ssize_t
gfs2_file_aio_write_nolock(struct kiocb *iocb, const struct iovec *iov,
			   unsigned long nr_segs, loff_t *ppos)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret;
	loff_t pos = *ppos;

	ret = __gfs2_file_aio_write_nolock(iocb, iov, nr_segs, ppos);

	if (ret > 0 && ((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
		int err;

		err = sync_page_range_nolock(inode, mapping, pos, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}

static ssize_t gfs2_file_aio_write(struct kiocb *iocb, const char __user *buf,
				   size_t count, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret;
	struct iovec local_iov = { .iov_base = (void __user *)buf,
					.iov_len = count };

	BUG_ON(iocb->ki_pos != pos);

	mutex_lock(&inode->i_mutex);
	ret = __gfs2_file_aio_write_nolock(iocb, &local_iov, 1, &iocb->ki_pos);
	mutex_unlock(&inode->i_mutex);

	if (ret > 0 && ((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
		ssize_t err;

		err = sync_page_range(inode, mapping, pos, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}

static ssize_t gfs2_file_write_nolock(struct file *file,
				      const struct iovec *iov,
				      unsigned long nr_segs, loff_t *ppos)
{
	struct kiocb kiocb;
	ssize_t ret;

	init_sync_kiocb(&kiocb, file);
	ret = gfs2_file_aio_write_nolock(&kiocb, iov, nr_segs, ppos);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&kiocb);
	return ret;
}

static ssize_t gfs2_file_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t	ret;
	struct iovec local_iov = { .iov_base = (void __user *)buf,
					.iov_len = count };

	mutex_lock(&inode->i_mutex);
	ret = gfs2_file_write_nolock(file, &local_iov, 1, ppos);
	mutex_unlock(&inode->i_mutex);

	if (ret > 0 && ((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
		ssize_t err;

		err = sync_page_range(inode, mapping, *ppos - ret, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}

static ssize_t gfs2_file_writev(struct file *file, const struct iovec *iov,
				unsigned long nr_segs, loff_t *ppos)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret;

	mutex_lock(&inode->i_mutex);
	ret = gfs2_file_write_nolock(file, iov, nr_segs, ppos);
	mutex_unlock(&inode->i_mutex);

	if (ret > 0 && ((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
		int err;

		err = sync_page_range(inode, mapping, *ppos - ret, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}

const struct file_operations_ext gfs2_file_fops = {
	.f_op_orig.llseek		= gfs2_llseek,
	.f_op_orig.read		= generic_file_read,
	.f_op_orig.readv		= generic_file_readv,
	.f_op_orig.aio_read	= generic_file_aio_read,
	.f_op_orig.write		= gfs2_file_write,
	.f_op_orig.writev		= gfs2_file_writev,
	.f_op_orig.aio_write	= gfs2_file_aio_write,
	.f_op_orig.unlocked_ioctl	= gfs2_ioctl,
	.f_op_orig.mmap		= gfs2_mmap,
	.f_op_orig.open		= gfs2_open,
	.f_op_orig.release	= gfs2_close,
	.f_op_orig.fsync		= gfs2_fsync,
	.f_op_orig.lock		= gfs2_lock,
	.f_op_orig.sendfile	= generic_file_sendfile,
	.f_op_orig.flock		= gfs2_flock,
	.f_op_orig.splice_read	= generic_file_splice_read,
	.f_op_orig.splice_write	= generic_file_splice_write,
	.setlease = gfs2_setlease,
};

const struct file_operations gfs2_dir_fops = {
	.readdir	= gfs2_readdir,
	.unlocked_ioctl	= gfs2_ioctl,
	.open		= gfs2_open,
	.release	= gfs2_close,
	.fsync		= gfs2_fsync,
	.lock		= gfs2_lock,
	.flock		= gfs2_flock,
};

const struct file_operations_ext gfs2_file_fops_nolock = {
	.f_op_orig.llseek		= gfs2_llseek,
	.f_op_orig.read		= generic_file_read,
	.f_op_orig.readv		= generic_file_readv,
	.f_op_orig.aio_read	= generic_file_aio_read,
	.f_op_orig.write		= gfs2_file_write,
	.f_op_orig.writev		= gfs2_file_writev,
	.f_op_orig.aio_write	= gfs2_file_aio_write,
	.f_op_orig.unlocked_ioctl	= gfs2_ioctl,
	.f_op_orig.mmap		= gfs2_mmap,
	.f_op_orig.open		= gfs2_open,
	.f_op_orig.release	= gfs2_close,
	.f_op_orig.fsync		= gfs2_fsync,
	/* .f_op_orig.lock = NULL, */
	.f_op_orig.sendfile	= generic_file_sendfile,
	.f_op_orig.flock		= gfs2_flock,
	.f_op_orig.splice_read	= generic_file_splice_read,
	.f_op_orig.splice_write	= generic_file_splice_write,
	/* .setlease = NULL, */
};

const struct file_operations gfs2_dir_fops_nolock = {
	.readdir	= gfs2_readdir,
	.unlocked_ioctl	= gfs2_ioctl,
	.open		= gfs2_open,
	.release	= gfs2_close,
	.fsync		= gfs2_fsync,
};

