/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * directory.c: directory listing support
 */

#define __KERNEL_SYSCALLS__
#include <net/tux.h>

/****************************************************************
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2, or (at your option)
 *      any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ****************************************************************/

char * tux_print_path (tux_req_t *req, struct dentry *dentry, struct vfsmount *mnt, char *buf, unsigned int max_len)
{
	char *res;
	struct dentry *cwd, *root;
	struct vfsmount *cwd_mnt, *rootmnt;

	cwd = dget(dentry);
	cwd_mnt = mntget(mnt);
	root = dget(req->docroot_dentry);
	rootmnt = mntget(req->docroot_mnt);

	spin_lock(&dcache_lock);
	res = __d_path(cwd, cwd_mnt, root, rootmnt, buf, max_len);
	spin_unlock(&dcache_lock);

	dput(cwd);
	mntput(cwd_mnt);
	dput(root);
	mntput(rootmnt);

	return res;
}

/*
 * There are filesystems that do not fill in ->d_type correctly.
 * Determine file-type.
 */
static int get_d_type (struct dentry *dentry)
{
	unsigned int mode = dentry->d_inode->i_mode;

	if (S_ISREG(mode))
		return DT_REG;
	if (S_ISDIR(mode))
		return DT_DIR;
	if (S_ISLNK(mode))
		return DT_LNK;
	if (S_ISFIFO(mode))
		return DT_FIFO;
	if (S_ISSOCK(mode))
		return DT_SOCK;
	if (S_ISCHR(mode))
		return DT_CHR;
	if (S_ISBLK(mode))
		return DT_BLK;
	return 0;
}

static void do_dir_line (tux_req_t *req, int cachemiss)
{
	struct linux_dirent64 *dirp, *dirp0;
	char string0[MAX_OBJECTNAME_LEN+200], *tmp;
	int len, curroff, total, str_len = 0;
	int err, flag = cachemiss ? 0 : LOOKUP_ATOMIC;
	struct nameidata base = { };
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;
	struct vfsmount *mnt = NULL;

	if (req->proto->check_req_err(req, cachemiss))
		return;

	tmp = NULL;
	dirp0 = req->dirp0;
	curroff = req->curroff;
	total = req->total;

	dirp = (struct linux_dirent64 *)((char *)dirp0 + curroff);
	if (!dirp->d_name || !dirp->d_name[0])
		goto next_dir;
	/*
	 * Hide .xxxxx files:
	 */
	if (dirp->d_name[0] == '.')
		goto next_dir;
	Dprintk("<%s T:%d (off:%Ld) (len:%d)>\n", dirp->d_name, dirp->d_type, dirp->d_off, dirp->d_reclen);
	if (tux_hide_unreadable) {
		switch (dirp->d_type) {
			default:
				goto next_dir;
			case DT_UNKNOWN:
			case DT_REG:
			case DT_DIR:
			case DT_LNK:
			/* valid entries - fall through. */
				;
		}
	}
	len = strlen(dirp->d_name);
	if (len >= MAX_OBJECTNAME_LEN) {
		dirp->d_name[MAX_OBJECTNAME_LEN] = 0;
		len = MAX_OBJECTNAME_LEN-1;
	}

	if (!req->dentry)
		TUX_BUG();

	base.flags = flag;
	base.last_type = LAST_ROOT;
	base.dentry = dget(req->dentry);
	base.mnt = mntget(req->cwd_mnt);

	switch_docroot(req);
	err = path_walk(dirp->d_name, &base);

	Dprintk("path_walk() returned %d.\n", err);

	if (err) {
		if (err == -EWOULDBLOCKIO) {
			add_tux_atom(req, do_dir_line);
			queue_cachemiss(req);
			return;
		}
		goto next_dir;
	}

	dentry = base.dentry;
	mnt = base.mnt;
	if (!dentry)
		TUX_BUG();
	if (IS_ERR(dentry))
		TUX_BUG();
	inode = dentry->d_inode;
	if (!inode)
		TUX_BUG();
	if (!dirp->d_type)
		dirp->d_type = get_d_type(dentry);
	if (tux_hide_unreadable) {
		umode_t mode;

		mode = inode->i_mode;
		if (mode & tux_mode_forbidden)
			goto out_dput;
		if (!(mode & tux_mode_allowed))
			goto out_dput;

		err = permission(inode, MAY_READ, NULL);
		if (err)
			goto out_dput;
		if (dirp->d_type == DT_DIR) {
			err = permission(inode, MAY_EXEC, NULL);
			if (err)
				goto out_dput;
		}
	}

	tmp = req->proto->print_dir_line(req, string0, dirp->d_name, len, dirp->d_type, dentry, inode);
	if (tmp)
		str_len = tmp-string0;
out_dput:
	dput(dentry);
	mntput(mnt);
next_dir:
	curroff += dirp->d_reclen;

	if (tmp && (tmp != string0))
		Dprintk("writing line (len: %d): <%s>\n", strlen(string0), string0);

	if (curroff < total) {
		req->dirp0 = dirp0;
		req->curroff = curroff;
		add_tux_atom(req, do_dir_line);
	} else {
		kfree(dirp0);
		req->dirp0 = NULL;
		req->curroff = 0;
		// falls back to the list_directory atom
	}
	if (tmp && (tmp != string0))
		__send_async_message(req, string0, 200, str_len, 0);
	else
		add_req_to_workqueue(req);
}

#define NAME_OFFSET(de) ((int) ((de)->d_name - (char *) (de)))
#define ROUND_UP(x) (((x)+sizeof(long)-1) & ~(sizeof(long)-1))
#define ROUND_UP64(x) (((x)+sizeof(u64)-1) & ~(sizeof(u64)-1))

static int filldir64(void * __buf, const char * name, int namlen, loff_t offset,
		     u64 ino, unsigned int d_type)
{
	struct linux_dirent64 * dirent, d;
	struct getdents_callback64 * buf = (struct getdents_callback64 *) __buf;
	int reclen = ROUND_UP64(NAME_OFFSET(dirent) + namlen + 1);
	int err;

	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > buf->count)
		return -EINVAL;
	dirent = buf->previous;
	if (dirent) {
		d.d_off = offset;
		err = copy_to_user(&dirent->d_off, &d.d_off, sizeof(d.d_off));
		BUG_ON(err);
	}
	dirent = buf->current_dir;
	buf->previous = dirent;
	memset(&d, 0, NAME_OFFSET(&d));
	d.d_ino = ino;
	d.d_reclen = reclen;
	d.d_type = d_type;
	err = copy_to_user(dirent, &d, NAME_OFFSET(&d));
	BUG_ON(err);
	err = copy_to_user(dirent->d_name, name, namlen);
	BUG_ON(err);
	err = put_user(0, dirent->d_name + namlen);
	BUG_ON(err);
	dirent = (void *)dirent + reclen;
	buf->current_dir = dirent;
	buf->count -= reclen;
	return 0;
}
#define DIRENT_SIZE 3000

void list_directory (tux_req_t *req, int cachemiss)
{
	struct getdents_callback64 buf;
	struct linux_dirent64 *dirp0;
	mm_segment_t oldmm;
	int total;

	Dprintk("list_directory(%p, %d), dentry: %p.\n", req, cachemiss, req->dentry);
	if (!req->cwd_dentry)
		TUX_BUG();

	if (!cachemiss) {
		add_tux_atom(req, list_directory);
		queue_cachemiss(req);
		return;
	}

	dirp0 = tux_kmalloc(DIRENT_SIZE);

	buf.current_dir = dirp0;
	buf.previous = NULL;
	buf.count = DIRENT_SIZE;
	buf.error = 0;

	oldmm = get_fs(); set_fs(KERNEL_DS);
	set_fs(KERNEL_DS);
	total = vfs_readdir(req->in_file, filldir64, &buf);
	set_fs(oldmm);

	if (buf.previous)
		total = DIRENT_SIZE - buf.count;

	Dprintk("total: %d (buf.error: %d, buf.previous %p)\n",
		total, buf.error, buf.previous);

	if (total < 0) {
		kfree(dirp0);
		req_err(req);
		add_req_to_workqueue(req);
		return;
	}
	if (!total) {
		kfree(dirp0);
		req->in_file->f_pos = 0;
		add_req_to_workqueue(req);
		return;
	}

	if (!req->cwd_dentry)
		TUX_BUG();
	add_tux_atom(req, list_directory);

	req->dirp0 = dirp0;
	req->curroff = 0;
	req->total = total;
	add_tux_atom(req, do_dir_line);

	add_req_to_workqueue(req);
}

