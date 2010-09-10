#ifndef BACKPORT_LINUX_FS_H
#define BACKPORT_LINUX_FS_H

#include_next <linux/fs.h>
#include <linux/mount.h>

#define FILE_LOCK_DEFERRED 1

#define ATTR_KILL_PRIV  (1 << 14)

static inline void __locks_copy_lock(struct file_lock *new, const struct file_lock *fl)
{
	new->fl_owner = fl->fl_owner;
	new->fl_pid = fl->fl_pid;
	new->fl_file = NULL;
	new->fl_flags = fl->fl_flags;
	new->fl_type = fl->fl_type;
	new->fl_start = fl->fl_start;
	new->fl_end = fl->fl_end;
	new->fl_ops = NULL;
	new->fl_lmops = NULL;
}

#define vfs_setlease(a, b, c) setlease(a, b, c)

static inline int __mandatory_lock(struct inode *ino)
{
	return (ino->i_mode & (S_ISGID | S_IXGRP)) == S_ISGID;
}

#define mandatory_lock(_args) MANDATORY_LOCK(_args)

static inline int backport_vfs_symlink(struct inode *dir, struct dentry *dentry, const char *oldname)
{
	return vfs_symlink(dir, dentry, oldname, 0);
}

#define vfs_symlink(_dir, _dentry, _oldname) backport_vfs_symlink(_dir, _dentry, _oldname)

#ifdef CONFIG_DEBUG_WRITECOUNT
static inline void file_take_write(struct file *f)
{
	WARN_ON(f->f_mnt_write_state != 0);
	f->f_mnt_write_state = FILE_MNT_WRITE_TAKEN;
}
#else
static inline void file_take_write(struct file *filp) {}
#endif

static inline int inode_permission(struct inode *inode, int flags)
{
	return permission(inode, flags, NULL);
}

static inline int __mnt_is_readonly(struct vfsmount *mnt)
{
	if (mnt->mnt_sb->s_flags & MS_RDONLY)
		return 1;
	return 0;
}

#endif
