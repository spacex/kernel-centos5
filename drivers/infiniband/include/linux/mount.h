#ifndef BACKPORT_LINUX_MOUNT_H
#define BACKPORT_LINUX_MOUNT_H

#include_next <linux/mount.h>
#include <linux/fs.h>

extern int backport_mnt_want_write(struct vfsmount *mnt);
extern void backport_mnt_drop_write(struct vfsmount *mnt);
extern int backport_init_mnt_writers(void);

#define mnt_want_write backport_mnt_want_write
#define mnt_drop_write backport_mnt_drop_write
#define init_mnt_writers backport_init_mnt_writers

#endif
