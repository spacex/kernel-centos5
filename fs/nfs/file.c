/*
 *  linux/fs/nfs/file.c
 *
 *  Copyright (C) 1992  Rick Sladkey
 *
 *  Changes Copyright (C) 1994 by Florian La Roche
 *   - Do not copy data too often around in the kernel.
 *   - In nfs_file_read the return value of kmalloc wasn't checked.
 *   - Put in a better version of read look-ahead buffering. Original idea
 *     and implementation by Wai S Kok elekokws@ee.nus.sg.
 *
 *  Expire cache on write to a file by Wai S Kok (Oct 1994).
 *
 *  Total rewrite of read side for new NFS buffer cache.. Linus.
 *
 *  nfs regular file handling functions
 */

#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_mount.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>
#include <linux/swap.h>

#include <asm/uaccess.h>
#include <asm/system.h>

#include "delegation.h"
#include "iostat.h"
#include "internal.h"

#define NFSDBG_FACILITY		NFSDBG_FILE

static int nfs_file_open(struct inode *, struct file *);
static int nfs_file_release(struct inode *, struct file *);
static loff_t nfs_file_llseek(struct file *file, loff_t offset, int origin);
static int  nfs_file_mmap(struct file *, struct vm_area_struct *);
static ssize_t nfs_file_sendfile(struct file *, loff_t *, size_t, read_actor_t, void *);
static ssize_t nfs_file_read(struct kiocb *, char __user *, size_t, loff_t);
static ssize_t nfs_file_write(struct kiocb *, const char __user *, size_t, loff_t);
static int  nfs_file_flush(struct file *, fl_owner_t id);
static int  nfs_fsync(struct file *, struct dentry *dentry, int datasync);
static int nfs_check_flags(int flags);
static int nfs_lock(struct file *filp, int cmd, struct file_lock *fl);
static int nfs_flock(struct file *filp, int cmd, struct file_lock *fl);

const struct file_operations nfs_file_operations = {
	.llseek		= nfs_file_llseek,
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read		= nfs_file_read,
	.aio_write		= nfs_file_write,
	.mmap		= nfs_file_mmap,
	.open		= nfs_file_open,
	.flush		= nfs_file_flush,
	.release	= nfs_file_release,
	.fsync		= nfs_fsync,
	.lock		= nfs_lock,
	.flock		= nfs_flock,
	.sendfile	= nfs_file_sendfile,
	.check_flags	= nfs_check_flags,
};

struct inode_operations nfs_file_inode_operations = {
	.permission	= nfs_permission,
	.getattr	= nfs_getattr,
	.setattr	= nfs_setattr,
};

#ifdef CONFIG_NFS_V3
struct inode_operations nfs3_file_inode_operations = {
	.permission	= nfs_permission,
	.getattr	= nfs_getattr,
	.setattr	= nfs_setattr,
	.listxattr	= nfs3_listxattr,
	.getxattr	= nfs3_getxattr,
	.setxattr	= nfs3_setxattr,
	.removexattr	= nfs3_removexattr,
};
#endif  /* CONFIG_NFS_v3 */

/* Hack for future NFS swap support */
#ifndef IS_SWAPFILE
# define IS_SWAPFILE(inode)	(0)
#endif

static int nfs_check_flags(int flags)
{
	if ((flags & (O_APPEND | O_DIRECT)) == (O_APPEND | O_DIRECT))
		return -EINVAL;

	return 0;
}

/*
 * Open file
 */
static int
nfs_file_open(struct inode *inode, struct file *filp)
{
	int res;

	res = nfs_check_flags(filp->f_flags);
	if (res)
		return res;

	nfs_inc_stats(inode, NFSIOS_VFSOPEN);
	lock_kernel();
	res = NFS_PROTO(inode)->file_open(inode, filp);
	unlock_kernel();
	return res;
}

static int
nfs_file_release(struct inode *inode, struct file *filp)
{
	nfs_inc_stats(inode, NFSIOS_VFSRELEASE);
	return NFS_PROTO(inode)->file_release(inode, filp);
}

/**
 * nfs_revalidate_size - Revalidate the file size
 * @inode - pointer to inode struct
 * @file - pointer to struct file
 *
 * Revalidates the file length. This is basically a wrapper around
 * nfs_revalidate_inode() that takes into account the fact that we may
 * have cached writes (in which case we don't care about the server's
 * idea of what the file length is), or O_DIRECT (in which case we
 * shouldn't trust the cache).
 */
static int nfs_revalidate_file_size(struct inode *inode, struct file *filp)
{
	struct nfs_server *server = NFS_SERVER(inode);
	struct nfs_inode *nfsi = NFS_I(inode);

	if (server->flags & NFS_MOUNT_NOAC)
		goto force_reval;
	if (filp->f_flags & O_DIRECT)
		goto force_reval;
	if (!(nfsi->cache_validity & NFS_INO_REVAL_PAGECACHE) && !nfs_attribute_timeout(inode))
		return 0;
force_reval:
	return __nfs_revalidate_inode(server, inode);
}

static loff_t nfs_file_llseek(struct file *filp, loff_t offset, int origin)
{
	/* origin == SEEK_END => we must revalidate the cached file length */
	if (origin == 2) {
		struct inode *inode = filp->f_mapping->host;
		int retval = nfs_revalidate_file_size(inode, filp);
		if (retval < 0)
			return (loff_t)retval;
	}
	return remote_llseek(filp, offset, origin);
}

/*
 * Helper for nfs_file_flush() and nfs_fsync()
 *
 * Notice that it clears the NFS_CONTEXT_ERROR_WRITE before synching to
 * disk, but it retrieves and clears ctx->error after synching, despite
 * the two being set at the same time in nfs_context_set_write_error().
 * This is because the former is used to notify the _next_ call to
 * nfs_file_write() that a write error occured, and hence cause it to
 * fall back to doing a synchronous write.
 */
static int nfs_do_fsync(struct nfs_open_context *ctx, struct inode *inode)
{
	int have_error, status;
	int ret = 0;

	have_error = test_and_clear_bit(NFS_CONTEXT_ERROR_WRITE, &ctx->flags);
	status = nfs_wb_all_sync(inode);
	have_error |= test_bit(NFS_CONTEXT_ERROR_WRITE, &ctx->flags);
	if (have_error)
		ret = xchg(&ctx->error, 0);
	if (!ret)
		ret = status;
	return ret;
}

/*
 * Flush all dirty pages, and check for write errors.
 *
 */
static int
nfs_file_flush(struct file *file, fl_owner_t id)
{
	struct nfs_open_context *ctx = (struct nfs_open_context *)file->private_data;
	struct inode	*inode = file->f_dentry->d_inode;

	dfprintk(VFS, "nfs: flush(%s/%ld)\n", inode->i_sb->s_id, inode->i_ino);

	if ((file->f_mode & FMODE_WRITE) == 0)
		return 0;
	nfs_inc_stats(inode, NFSIOS_VFSFLUSH);

	/* Flush writes to the server and return any errors */
	return nfs_do_fsync(ctx, inode);
}

static ssize_t
nfs_file_read(struct kiocb *iocb, char __user * buf, size_t count, loff_t pos)
{
	struct dentry * dentry = iocb->ki_filp->f_dentry;
	struct inode * inode = dentry->d_inode;
	ssize_t result;

#ifdef CONFIG_NFS_DIRECTIO
	if (iocb->ki_filp->f_flags & O_DIRECT)
		return nfs_file_direct_read(iocb, buf, count, pos);
#endif

	dfprintk(VFS, "nfs: read(%s/%s, %lu@%lu)\n",
		dentry->d_parent->d_name.name, dentry->d_name.name,
		(unsigned long) count, (unsigned long) pos);

	result = nfs_revalidate_mapping(inode, iocb->ki_filp->f_mapping);
	nfs_add_stats(inode, NFSIOS_NORMALREADBYTES, count);
	if (!result)
		result = generic_file_aio_read(iocb, buf, count, pos);
	return result;
}

static ssize_t
nfs_file_sendfile(struct file *filp, loff_t *ppos, size_t count,
		read_actor_t actor, void *target)
{
	struct dentry *dentry = filp->f_dentry;
	struct inode *inode = dentry->d_inode;
	ssize_t res;

	dfprintk(VFS, "nfs: sendfile(%s/%s, %lu@%Lu)\n",
		dentry->d_parent->d_name.name, dentry->d_name.name,
		(unsigned long) count, (unsigned long long) *ppos);

	res = nfs_revalidate_mapping(inode, filp->f_mapping);
	if (!res)
		res = generic_file_sendfile(filp, ppos, count, actor, target);
	return res;
}

static int
nfs_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct dentry *dentry = file->f_dentry;
	struct inode *inode = dentry->d_inode;
	int	status;

	dfprintk(VFS, "nfs: mmap(%s/%s)\n",
		dentry->d_parent->d_name.name, dentry->d_name.name);

	status = nfs_revalidate_mapping(inode, file->f_mapping);
	if (!status)
		status = generic_file_mmap(file, vma);
	return status;
}

/*
 * Flush any dirty pages for this process, and check for write errors.
 * The return status from this call provides a reliable indication of
 * whether any write errors occurred for this process.
 */
static int
nfs_fsync(struct file *file, struct dentry *dentry, int datasync)
{
	struct nfs_open_context *ctx = (struct nfs_open_context *)file->private_data;
	struct inode *inode = dentry->d_inode;

	dfprintk(VFS, "nfs: fsync(%s/%ld)\n", inode->i_sb->s_id, inode->i_ino);

	nfs_inc_stats(inode, NFSIOS_VFSFSYNC);
	return nfs_do_fsync(ctx, inode);
}

/*
 * Decide whether a read/modify/write cycle may be more efficient
 * then a modify/write/read cycle when writing to a page in the
 * page cache.
 *
 * The modify/write/read cycle may occur if a page is read before
 * being completely filled by the writer.  In this situation, the
 * page must be completely written to stable storage on the server
 * before it can be refilled by reading in the page from the server.
 * This can lead to expensive, small, FILE_SYNC mode writes being
 * done.
 *
 * It may be more efficient to read the page first if the file is
 * open for reading in addition to writing, the page is not marked
 * as Uptodate, it is not dirty or waiting to be committed,
 * indicating that it was previously allocated and then modified,
 * that there were valid bytes of data in that range of the file,
 * and that the new data won't completely replace the old data in
 * that range of the file.
 */
static int nfs_want_read_modify_write(struct file *file, struct page *page,
					loff_t pos, unsigned len)
{
	unsigned int pglen = nfs_page_length(page->mapping->host, page);
	unsigned int offset = pos & (PAGE_CACHE_SIZE - 1);
	unsigned int end = offset + len;

	if ((file->f_mode & FMODE_READ) &&	/* open for read? */
	    !PageUptodate(page) &&		/* Uptodate? */
	    !PagePrivate(page) &&		/* i/o request already? */
	    pglen &&				/* valid bytes of file? */
	    (end < pglen || offset))		/* replace all valid bytes? */
		return 1;
	return 0;
}

/*
 * This does the "real" work of the write. We must allocate and lock the
 * page to be sent back to the generic routine, which then copies the
 * data from user space.
 *
 * If the writer ends up delaying the write, the writer needs to
 * increment the page use counts until he is done with the page.
 */
static int nfs_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct page *page;
	int once_thru = 0;

	dfprintk(PAGECACHE, "NFS: write_begin(%s/%s(%ld), %u@%lld)\n",
		file->f_dentry->d_parent->d_name.name,
		file->f_dentry->d_name.name,
		mapping->host->i_ino, len, (long long) pos);
start:
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	*pagep = page;

	ret = nfs_flush_incompatible(file, page);
	if (ret) {
		unlock_page(page);
		page_cache_release(page);
	} else if (!once_thru &&
		   nfs_want_read_modify_write(file, page, pos, len)) {
		once_thru = 1;
		ret = nfs_readpage(file, page);
		page_cache_release(page);
		if (!ret)
			goto start;
	}
	return ret;
}

static int nfs_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	unsigned offset = pos & (PAGE_CACHE_SIZE - 1);
	int status;

	dfprintk(PAGECACHE, "NFS: write_end(%s/%s(%ld), %u@%lld)\n",
		file->f_dentry->d_parent->d_name.name,
		file->f_dentry->d_name.name,
		mapping->host->i_ino, len, (long long) pos);

	lock_kernel();
	status = nfs_updatepage(file, page, offset, copied);
	unlock_kernel();

	unlock_page(page);
	page_cache_release(page);

	return status < 0 ? status : copied;
}

static void nfs_invalidate_page(struct page *page, unsigned long offset)
{
	struct inode *inode = page->mapping->host;

	dfprintk(PAGECACHE, "NFS: invalidate_page(%p, %lu)\n", page, offset);

	/* Cancel any unstarted writes on this page */
	if (offset == 0)
		nfs_sync_inode_wait(inode, page->index, 1, FLUSH_INVALIDATE);
}

static int nfs_release_page(struct page *page, gfp_t gfp)
{
	struct address_space *mapping = page->mapping;

	dfprintk(PAGECACHE, "NFS: release_page(%p)\n", page);

	/* Only do I/O if gfp is a superset of GFP_KERNEL */
	if (mapping && (gfp & GFP_KERNEL) == GFP_KERNEL) {
		int how = FLUSH_SYNC;

		/* Don't let kswapd deadlock waiting for OOM RPC calls */
		if (current_is_kswapd())
			how = 0;
		nfs_commit_inode(mapping->host, how);
	}
	/* If PagePrivate() is set, then the page is not freeable */
	if (PagePrivate(page))
		return 0;
	return 1;
}

static int nfs_launder_page(struct page *page)
{
	struct inode *inode = page->mapping->host;

	dfprintk(PAGECACHE, "NFS: launder_page(%ld, %llu)\n",
		inode->i_ino, (long long)page_offset(page));

	return nfs_wb_page(inode, page);
}

/*
 * Since we use page->private for our own nefarious purposes when using
 * fscache, we have to override extra address space ops to prevent fs/buffer.c
 * from getting confused, even though we may not have asked its opinion
 */
const struct address_space_operations_ext nfs_file_aops = {
	.orig_aops.readpage = nfs_readpage,
	.orig_aops.readpages = nfs_readpages,
	.orig_aops.set_page_dirty = __set_page_dirty_nobuffers,
	.orig_aops.writepage = nfs_writepage,
	.orig_aops.writepages = nfs_writepages,
	.orig_aops.invalidatepage = nfs_invalidate_page,
	.orig_aops.releasepage = nfs_release_page,
#ifdef CONFIG_NFS_DIRECTIO
	.orig_aops.direct_IO = nfs_direct_IO,
#endif
	.write_begin = nfs_write_begin,
	.write_end = nfs_write_end,
	.launder_page = nfs_launder_page,
};

/* 
 * Write to a file (through the page cache).
 */
static int nfs_need_sync_write(struct file *filp, struct inode *inode)
{
	struct nfs_open_context *ctx;

	if (IS_SYNC(inode) || (filp->f_flags & O_SYNC))
		return 1;
	ctx = filp->private_data;
	if (test_bit(NFS_CONTEXT_ERROR_WRITE, &ctx->flags))
		return 1;
	return 0;
}

static ssize_t
nfs_file_write(struct kiocb *iocb, const char __user *buf, size_t count, loff_t pos)
{
	struct dentry * dentry = iocb->ki_filp->f_dentry;
	struct inode * inode = dentry->d_inode;
	ssize_t result;

#ifdef CONFIG_NFS_DIRECTIO
	if (iocb->ki_filp->f_flags & O_DIRECT)
		return nfs_file_direct_write(iocb, buf, count, pos);
#endif

	dfprintk(VFS, "nfs: write(%s/%s(%ld), %lu@%lu)\n",
		dentry->d_parent->d_name.name, dentry->d_name.name,
		inode->i_ino, (unsigned long) count, (unsigned long) pos);

	result = -EBUSY;
	if (IS_SWAPFILE(inode))
		goto out_swapfile;
	/*
	 * O_APPEND implies that we must revalidate the file length.
	 */
	if (iocb->ki_filp->f_flags & O_APPEND) {
		result = nfs_revalidate_file_size(inode, iocb->ki_filp);
		if (result)
			goto out;
	}

	result = count;
	if (!count)
		goto out;

	nfs_add_stats(inode, NFSIOS_NORMALWRITTENBYTES, count);
	result = generic_file_aio_write(iocb, buf, count, pos);
	/* Return error values for O_SYNC and IS_SYNC() */
	if (result >= 0 && nfs_need_sync_write(iocb->ki_filp, inode)) {
		int err = nfs_do_fsync(iocb->ki_filp->private_data, inode);
		if (err < 0)
			result = err;
	}
out:
	return result;

out_swapfile:
	printk(KERN_INFO "NFS: attempt to write to active swap file!\n");
	goto out;
}

static int do_getlk(struct file *filp, int cmd, struct file_lock *fl)
{
	struct inode *inode = filp->f_mapping->host;
	int status = 0;

	lock_kernel();
	/* Try local locking first */
	if (posix_test_lock(filp, fl, NULL))
		goto out;

	if (nfs_have_delegation(inode, FMODE_READ))
		goto out_noconflict;

	if (NFS_SERVER(inode)->flags & NFS_MOUNT_NONLM)
		goto out_noconflict;

	status = NFS_PROTO(inode)->lock(filp, cmd, fl);
out:
	unlock_kernel();
	return status;
out_noconflict:
	fl->fl_type = F_UNLCK;
	goto out;
}

static int do_vfs_lock(struct file *file, struct file_lock *fl)
{
	int res = 0;
	switch (fl->fl_flags & (FL_POSIX|FL_FLOCK)) {
		case FL_POSIX:
			res = posix_lock_file_wait(file, fl);
			break;
		case FL_FLOCK:
			res = flock_lock_file_wait(file, fl);
			break;
		default:
			BUG();
	}
	return res;
}

static int do_unlk(struct file *filp, int cmd, struct file_lock *fl)
{
	struct inode *inode = filp->f_mapping->host;
	int status;

	/*
	 * Flush all pending writes before doing anything
	 * with locks..
	 */
	nfs_sync_mapping(filp->f_mapping);

	/* NOTE: special case
	 * 	If we're signalled while cleaning up locks on process exit, we
	 * 	still need to complete the unlock.
	 */
	lock_kernel();
	/* Use local locking if mounted with "-onolock" */
	if (!(NFS_SERVER(inode)->flags & NFS_MOUNT_NONLM))
		status = NFS_PROTO(inode)->lock(filp, cmd, fl);
	else
		status = do_vfs_lock(filp, fl);
	unlock_kernel();
	return status;
}

static int do_setlk(struct file *filp, int cmd, struct file_lock *fl)
{
	struct inode *inode = filp->f_mapping->host;
	int status;

	/*
	 * Flush all pending writes before doing anything
	 * with locks..
	 */
	status = nfs_sync_mapping(filp->f_mapping);
	if (status != 0)
		goto out;

	lock_kernel();
	/* Use local locking if mounted with "-onolock" */
	if (!(NFS_SERVER(inode)->flags & NFS_MOUNT_NONLM))
		status = NFS_PROTO(inode)->lock(filp, cmd, fl);
	else
		status = do_vfs_lock(filp, fl);
	unlock_kernel();
	if (status < 0)
		goto out;
	/*
	 * Make sure we clear the cache whenever we try to get the lock.
	 * This makes locking act as a cache coherency point.
	 */
	nfs_sync_mapping(filp->f_mapping);
	nfs_zap_caches(inode);
out:
	return status;
}

/*
 * Lock a (portion of) a file
 */
static int nfs_lock(struct file *filp, int cmd, struct file_lock *fl)
{
	struct inode * inode = filp->f_mapping->host;

	dprintk("NFS: nfs_lock(f=%s/%ld, t=%x, fl=%x, r=%Ld:%Ld)\n",
			inode->i_sb->s_id, inode->i_ino,
			fl->fl_type, fl->fl_flags,
			(long long)fl->fl_start, (long long)fl->fl_end);
	nfs_inc_stats(inode, NFSIOS_VFSLOCK);

	/* No mandatory locks over NFS */
	if ((inode->i_mode & (S_ISGID | S_IXGRP)) == S_ISGID &&
	    fl->fl_type != F_UNLCK)
		return -ENOLCK;

	if (IS_GETLK(cmd))
		return do_getlk(filp, cmd, fl);
	if (fl->fl_type == F_UNLCK)
		return do_unlk(filp, cmd, fl);
	return do_setlk(filp, cmd, fl);
}

/*
 * Lock a (portion of) a file
 */
static int nfs_flock(struct file *filp, int cmd, struct file_lock *fl)
{
	dprintk("NFS: nfs_flock(f=%s/%ld, t=%x, fl=%x)\n",
			filp->f_dentry->d_inode->i_sb->s_id,
			filp->f_dentry->d_inode->i_ino,
			fl->fl_type, fl->fl_flags);

	/*
	 * No BSD flocks over NFS allowed.
	 * Note: we could try to fake a POSIX lock request here by
	 * using ((u32) filp | 0x80000000) or some such as the pid.
	 * Not sure whether that would be unique, though, or whether
	 * that would break in other places.
	 */
	if (!(fl->fl_flags & FL_FLOCK))
		return -ENOLCK;

	/* We're simulating flock() locks using posix locks on the server */
	fl->fl_owner = (fl_owner_t)filp;
	fl->fl_start = 0;
	fl->fl_end = OFFSET_MAX;

	if (fl->fl_type == F_UNLCK)
		return do_unlk(filp, cmd, fl);
	return do_setlk(filp, cmd, fl);
}
