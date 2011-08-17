/*
 * inode.c - basic inode and dentry operations.
 *
 * sysfs is Copyright (c) 2001-3 Patrick Mochel
 *
 * Please see Documentation/filesystems/sysfs.txt for more information.
 */

#undef DEBUG 

#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include "sysfs.h"

extern struct super_block * sysfs_sb;

static inline void set_inode_attr(struct inode * inode, struct iattr * iattr);

static const struct address_space_operations sysfs_aops = {
	.readpage	= simple_readpage,
	.prepare_write	= simple_prepare_write,
	.commit_write	= simple_commit_write
};

static struct backing_dev_info sysfs_backing_dev_info = {
	.ra_pages	= 0,	/* No readahead */
	.capabilities	= BDI_CAP_NO_ACCT_DIRTY | BDI_CAP_NO_WRITEBACK,
};

static struct inode_operations sysfs_inode_operations ={
	.permission	= sysfs_permission,
	.setattr	= sysfs_setattr,
	.getattr	= sysfs_getattr,
	.setxattr	= sysfs_setxattr,
};

static struct sysfs_inode_attrs *sysfs_init_inode_attrs(struct sysfs_dirent *sd)
{
	struct sysfs_inode_attrs *attrs;
	struct iattr *iattrs;

	attrs = kzalloc(sizeof(struct sysfs_inode_attrs), GFP_KERNEL);
	if (!attrs)
		return NULL;
	iattrs = &attrs->ia_iattr;

	/* assign default attributes */
	iattrs->ia_mode = sd->s_mode;
	iattrs->ia_uid = 0;
	iattrs->ia_gid = 0;
	iattrs->ia_atime = iattrs->ia_mtime = iattrs->ia_ctime = CURRENT_TIME;

	return attrs;
}

static void sysfs_refresh_inode(struct sysfs_dirent *sd, struct inode *inode)
{
	struct sysfs_inode_attrs *iattrs = sd->s_iattr;

	inode->i_mode = sd->s_mode;
	if (iattrs) {
		/* sysfs_dirent has non-default attributes
		 * get them from persistent copy in sysfs_dirent
		 */
		set_inode_attr(inode, &iattrs->ia_iattr);
		security_inode_notifysecctx(inode,
					    iattrs->ia_secdata,
					    iattrs->ia_secdata_len);
	}
}

int sysfs_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	struct sysfs_dirent *sd = dentry->d_fsdata;
	struct inode *inode = dentry->d_inode;

	/* locking not backported from f8d4f618fed5a4978afada52 */
	/* mutex_lock(&sysfs_mutex); */
	sysfs_refresh_inode(sd, inode);
	/* mutex_unlock(&sysfs_mutex); */

	generic_fillattr(inode, stat);
	return 0;
}

int sysfs_setattr(struct dentry * dentry, struct iattr * iattr)
{
	struct inode * inode = dentry->d_inode;
	struct sysfs_dirent * sd = dentry->d_fsdata;
	struct sysfs_inode_attrs *sd_attrs;
	struct iattr *iattrs;
	unsigned int ia_valid = iattr->ia_valid;
	int error;

	if (!sd)
		return -EINVAL;

	sd_attrs = sd->s_iattr;

	error = inode_change_ok(inode, iattr);
	if (error)
		return error;

	error = inode_setattr(inode, iattr);
	if (error)
		return error;

	if (!sd_attrs) {
		/* setting attributes for the first time, allocate now */
		sd_attrs = sysfs_init_inode_attrs(sd);
		if (!sd_attrs)
			return -ENOMEM;
		sd->s_iattr = sd_attrs;
	} else {
		/* attributes were changed at least once in past */
		iattrs = &sd_attrs->ia_iattr;

		if (ia_valid & ATTR_UID)
			iattrs->ia_uid = iattr->ia_uid;
		if (ia_valid & ATTR_GID)
			iattrs->ia_gid = iattr->ia_gid;
		if (ia_valid & ATTR_ATIME)
			iattrs->ia_atime = timespec_trunc(iattr->ia_atime,
					inode->i_sb->s_time_gran);
		if (ia_valid & ATTR_MTIME)
			iattrs->ia_mtime = timespec_trunc(iattr->ia_mtime,
					inode->i_sb->s_time_gran);
		if (ia_valid & ATTR_CTIME)
			iattrs->ia_ctime = timespec_trunc(iattr->ia_ctime,
					inode->i_sb->s_time_gran);
		if (ia_valid & ATTR_MODE) {
			umode_t mode = iattr->ia_mode;

			if (!in_group_p(inode->i_gid) && !capable(CAP_FSETID))
				mode &= ~S_ISGID;
			iattrs->ia_mode = sd->s_mode = mode;
		}
	}
	return error;
}

int sysfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	struct sysfs_dirent *sd = dentry->d_fsdata;
	struct sysfs_inode_attrs *iattrs;
	void *secdata;
	int error;
	u32 secdata_len = 0;

	if (!sd)
		return -EINVAL;
	if (!sd->s_iattr)
		sd->s_iattr = sysfs_init_inode_attrs(sd);
	if (!sd->s_iattr)
		return -ENOMEM;

	iattrs = sd->s_iattr;

	if (!strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN)) {
		const char *suffix = name + XATTR_SECURITY_PREFIX_LEN;
		error = security_inode_setsecurity(dentry->d_inode, suffix,
						value, size, flags);
		if (error)
			goto out;
		error = security_inode_getsecctx(dentry->d_inode,
						&secdata, &secdata_len);
		if (error)
			goto out;
		if (iattrs->ia_secdata)
			security_release_secctx(iattrs->ia_secdata,
						iattrs->ia_secdata_len);
		iattrs->ia_secdata = secdata;
		iattrs->ia_secdata_len = secdata_len;

	} else
		return -EINVAL;
out:
	return error;
}

static inline void set_default_inode_attr(struct inode * inode, mode_t mode)
{
	inode->i_mode = mode;
	inode->i_uid = 0;
	inode->i_gid = 0;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
}

static inline void set_inode_attr(struct inode * inode, struct iattr * iattr)
{
	inode->i_mode = iattr->ia_mode;
	inode->i_uid = iattr->ia_uid;
	inode->i_gid = iattr->ia_gid;
	inode->i_atime = iattr->ia_atime;
	inode->i_mtime = iattr->ia_mtime;
	inode->i_ctime = iattr->ia_ctime;
}

/*
 * sysfs has a different i_mutex lock order behavior for i_mutex than other
 * filesystems; sysfs i_mutex is called in many places with subsystem locks
 * held. At the same time, many of the VFS locking rules do not apply to
 * sysfs at all (cross directory rename for example). To untangle this mess
 * (which gives false positives in lockdep), we're giving sysfs inodes their
 * own class for i_mutex.
 */
static struct lock_class_key sysfs_inode_imutex_key;

struct inode * sysfs_new_inode(mode_t mode, struct sysfs_dirent * sd)
{
	struct inode * inode = new_inode(sysfs_sb);

	sd->s_mode = mode;

	if (inode) {
		inode->i_blocks = 0;
		inode->i_mapping->a_ops = &sysfs_aops;
		inode->i_mapping->backing_dev_info = &sysfs_backing_dev_info;
		inode->i_op = &sysfs_inode_operations;
		inode->i_ino = sd->s_ino;
		lockdep_set_class(&inode->i_mutex, &sysfs_inode_imutex_key);
		inode->i_private = sysfs_get(sd);

		set_default_inode_attr(inode, mode);
		sysfs_refresh_inode(sd, inode);
	}
	return inode;
}

int sysfs_create(struct dentry * dentry, int mode, int (*init)(struct inode *))
{
	int error = 0;
	struct inode * inode = NULL;
	if (dentry) {
		if (!dentry->d_inode) {
			struct sysfs_dirent * sd = dentry->d_fsdata;
			if ((inode = sysfs_new_inode(mode, sd))) {
				if (dentry->d_parent && dentry->d_parent->d_inode) {
					struct inode *p_inode = dentry->d_parent->d_inode;
					p_inode->i_mtime = p_inode->i_ctime = CURRENT_TIME;
				}
				goto Proceed;
			}
			else 
				error = -ENOMEM;
		} else
			error = -EEXIST;
	} else 
		error = -ENOENT;
	goto Done;

 Proceed:
	if (init)
		error = init(inode);
	if (!error) {
		d_instantiate(dentry, inode);
		if (S_ISDIR(mode))
			dget(dentry);  /* pin only directory dentry in core */
	} else
		iput(inode);
 Done:
	return error;
}

/*
 * Get the name for corresponding element represented by the given sysfs_dirent
 */
const unsigned char * sysfs_get_name(struct sysfs_dirent *sd)
{
	struct attribute * attr;
	struct bin_attribute * bin_attr;
	struct sysfs_symlink  * sl;

	BUG_ON(!sd || !sd->s_element);

	switch (sd->s_type) {
		case SYSFS_DIR:
			/* Always have a dentry so use that */
			return sd->s_dentry->d_name.name;

		case SYSFS_KOBJ_ATTR:
			attr = sd->s_element;
			return attr->name;

		case SYSFS_KOBJ_BIN_ATTR:
			bin_attr = sd->s_element;
			return bin_attr->attr.name;

		case SYSFS_KOBJ_LINK:
			sl = sd->s_element;
			return sl->link_name;
	}
	return NULL;
}


/*
 * Unhashes the dentry corresponding to given sysfs_dirent
 * Called with parent inode's i_mutex held.
 */
void sysfs_drop_dentry(struct sysfs_dirent * sd, struct dentry * parent)
{
	struct dentry *dentry = NULL;

	/* We're not holding a reference to ->s_dentry dentry but the
	 * field will stay valid as long as sysfs_lock is held.
	 */
	spin_lock(&sysfs_lock);
	spin_lock(&dcache_lock);

	/* dget dentry if it's still alive */
	if (sd->s_dentry && sd->s_dentry->d_inode)
		dentry = dget_locked(sd->s_dentry);

	spin_unlock(&dcache_lock);
	spin_unlock(&sysfs_lock);

	/* drop dentry */
	if (dentry) {
		spin_lock(&dcache_lock);
		spin_lock(&dentry->d_lock);
		if (!d_unhashed(dentry) && dentry->d_inode) {
			dget_locked(dentry);
			__d_drop(dentry);
			spin_unlock(&dentry->d_lock);
			spin_unlock(&dcache_lock);
			simple_unlink(parent->d_inode, dentry);
		} else {
			spin_unlock(&dentry->d_lock);
			spin_unlock(&dcache_lock);
		}

		dput(dentry);
	}
}

/*
 * The sysfs_dirent serves as both an inode and a directory entry for sysfs.
 * To prevent the sysfs inode numbers from being freed prematurely we take a
 * reference to sysfs_dirent from the sysfs inode.  A
 * super_operations.evict_inode() implementation is needed to drop that
 * reference upon inode destruction.
 */
void sysfs_evict_inode(struct inode *inode)
{
	struct sysfs_dirent *sd  = inode->i_private;

	truncate_inode_pages(&inode->i_data, 0);
	clear_inode(inode);
	sysfs_put(sd);
}

void sysfs_hash_and_remove(struct dentry * dir, const char * name)
{
	struct sysfs_dirent * sd;
	struct sysfs_dirent * parent_sd;

	if (!dir)
		return;

	if (dir->d_inode == NULL)
		/* no inode means this hasn't been made visible yet */
		return;

	parent_sd = dir->d_fsdata;
	mutex_lock(&dir->d_inode->i_mutex);
	list_for_each_entry(sd, &parent_sd->s_children, s_sibling) {
		if (!sd->s_element)
			continue;
		if (!strcmp(sysfs_get_name(sd), name)) {
			list_del_init(&sd->s_sibling);
			sysfs_drop_dentry(sd, dir);
			sysfs_put(sd);
			break;
		}
	}
	mutex_unlock(&dir->d_inode->i_mutex);
}

int sysfs_permission(struct inode *inode, int mask, struct nameidata *nd)
{
	struct sysfs_dirent *sd = inode->i_private;

	/* locking not backported from f8d4f618fed5a4978afada52 */
	/* mutex_lock(&sysfs_mutex); */
	sysfs_refresh_inode(sd, inode);
	/* mutex_unlock(&sysfs_mutex); */

	return generic_permission(inode, mask, NULL);
}
