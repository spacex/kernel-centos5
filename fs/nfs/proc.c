/*
 *  linux/fs/nfs/proc.c
 *
 *  Copyright (C) 1992, 1993, 1994  Rick Sladkey
 *
 *  OS-independent nfs remote procedure call functions
 *
 *  Tuned by Alan Cox <A.Cox@swansea.ac.uk> for >3K buffers
 *  so at last we can have decent(ish) throughput off a 
 *  Sun server.
 *
 *  Coding optimized and cleaned up by Florian La Roche.
 *  Note: Error returns are optimized for NFS_OK, which isn't translated via
 *  nfs_stat_to_errno(), but happens to be already the right return code.
 *
 *  Also, the code currently doesn't check the size of the packet, when
 *  it decodes the packet.
 *
 *  Feel free to fix it and mail me the diffs if it worries you.
 *
 *  Completely rewritten to support the new RPC call interface;
 *  rewrote and moved the entire XDR stuff to xdr.c
 *  --Olaf Kirch June 1996
 *
 *  The code below initializes all auto variables explicitly, otherwise
 *  it will fail to work as a module (gcc generates a memset call for an
 *  incomplete struct).
 */

#include <linux/types.h>
#include <linux/param.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/utsname.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/pagemap.h>
#include <linux/sunrpc/clnt.h>
#include <linux/nfs.h>
#include <linux/nfs2.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_page.h>
#include <linux/lockd/bind.h>
#include <linux/smp_lock.h>
#include "internal.h"

#define NFSDBG_FACILITY		NFSDBG_PROC

/*
 * Bare-bones access to getattr: this is for nfs_read_super.
 */
static int
nfs_proc_get_root(struct nfs_server *server, struct nfs_fh *fhandle,
		  struct nfs_fsinfo *info)
{
	struct nfs_fattr *fattr = info->fattr;
	struct nfs2_fsstat fsinfo;
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_GETATTR],
		.rpc_argp	= fhandle,
		.rpc_resp	= fattr,
	};
	int status;

	dprintk("%s: call getattr\n", __FUNCTION__);
	nfs_fattr_init(fattr);
	status = rpc_call_sync(server->nfs_client->cl_rpcclient, &msg, 0);
	dprintk("%s: reply getattr: %d\n", __FUNCTION__, status);
	if (status)
		return status;
	dprintk("%s: call statfs\n", __FUNCTION__);
	msg.rpc_proc = &nfs_procedures[NFSPROC_STATFS];
	msg.rpc_resp = &fsinfo;
	status = rpc_call_sync(server->nfs_client->cl_rpcclient, &msg, 0);
	dprintk("%s: reply statfs: %d\n", __FUNCTION__, status);
	if (status)
		return status;
	info->rtmax  = NFS_MAXDATA;
	info->rtpref = fsinfo.tsize;
	info->rtmult = fsinfo.bsize;
	info->wtmax  = NFS_MAXDATA;
	info->wtpref = fsinfo.tsize;
	info->wtmult = fsinfo.bsize;
	info->dtpref = fsinfo.tsize;
	info->maxfilesize = 0x7FFFFFFF;
	info->lease_time = 0;
	return 0;
}

/*
 * One function for each procedure in the NFS protocol.
 */
static int
nfs_proc_getattr(struct nfs_server *server, struct nfs_fh *fhandle,
		struct nfs_fattr *fattr)
{
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_GETATTR],
		.rpc_argp	= fhandle,
		.rpc_resp	= fattr,
	};
	int	status;

	dprintk("NFS call  getattr\n");
	nfs_fattr_init(fattr);
	status = rpc_call_sync(server->client, &msg, 0);
	dprintk("NFS reply getattr: %d\n", status);
	return status;
}

static int
nfs_proc_setattr(struct dentry *dentry, struct nfs_fattr *fattr,
		 struct iattr *sattr)
{
	struct inode *inode = dentry->d_inode;
	struct nfs_sattrargs	arg = { 
		.fh	= NFS_FH(inode),
		.sattr	= sattr
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_SETATTR],
		.rpc_argp	= &arg,
		.rpc_resp	= fattr,
	};
	int	status;

	/* Mask out the non-modebit related stuff from attr->ia_mode */
	sattr->ia_mode &= S_IALLUGO;

	dprintk("NFS call  setattr\n");
	nfs_fattr_init(fattr);
	status = rpc_call_sync(NFS_CLIENT(inode), &msg, 0);
	if (status == 0)
		nfs_setattr_update_inode(inode, sattr);
	dprintk("NFS reply setattr: %d\n", status);
	return status;
}

static int
nfs_proc_lookup(struct inode *dir, struct qstr *name,
		struct nfs_fh *fhandle, struct nfs_fattr *fattr)
{
	struct nfs_diropargs	arg = {
		.fh		= NFS_FH(dir),
		.name		= name->name,
		.len		= name->len
	};
	struct nfs_diropok	res = {
		.fh		= fhandle,
		.fattr		= fattr
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_LOOKUP],
		.rpc_argp	= &arg,
		.rpc_resp	= &res,
	};
	int			status;

	dprintk("NFS call  lookup %s\n", name->name);
	nfs_fattr_init(fattr);
	status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);
	dprintk("NFS reply lookup: %d\n", status);
	return status;
}

static int nfs_proc_readlink(struct inode *inode, struct page *page,
		unsigned int pgbase, unsigned int pglen)
{
	struct nfs_readlinkargs	args = {
		.fh		= NFS_FH(inode),
		.pgbase		= pgbase,
		.pglen		= pglen,
		.pages		= &page
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_READLINK],
		.rpc_argp	= &args,
	};
	int			status;

	dprintk("NFS call  readlink\n");
	status = rpc_call_sync(NFS_CLIENT(inode), &msg, 0);
	dprintk("NFS reply readlink: %d\n", status);
	return status;
}

static int nfs_proc_read(struct nfs_read_data *rdata)
{
	int			flags = rdata->flags;
	struct inode *		inode = rdata->inode;
	struct nfs_fattr *	fattr = rdata->res.fattr;
	struct rpc_message	msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_READ],
		.rpc_argp	= &rdata->args,
		.rpc_resp	= &rdata->res,
		.rpc_cred	= rdata->cred,
	};
	int			status;

	dprintk("NFS call  read %d @ %Ld\n", rdata->args.count,
			(long long) rdata->args.offset);
	nfs_fattr_init(fattr);
	status = rpc_call_sync(NFS_CLIENT(inode), &msg, flags);
	nfs_invalidate_atime(inode);
	if (status >= 0) {
		nfs_refresh_inode(inode, fattr);
		/* Emulate the eof flag, which isn't normally needed in NFSv2
		 * as it is guaranteed to always return the file attributes
		 */
		if (rdata->args.offset + rdata->args.count >= fattr->size)
			rdata->res.eof = 1;
	}
	dprintk("NFS reply read: %d\n", status);
	return status;
}

static int nfs_proc_write(struct nfs_write_data *wdata)
{
	int			flags = wdata->flags;
	struct inode *		inode = wdata->inode;
	struct nfs_fattr *	fattr = wdata->res.fattr;
	struct rpc_message	msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_WRITE],
		.rpc_argp	= &wdata->args,
		.rpc_resp	= &wdata->res,
		.rpc_cred	= wdata->cred,
	};
	int			status;

	dprintk("NFS call  write %d @ %Ld\n", wdata->args.count,
			(long long) wdata->args.offset);
	nfs_fattr_init(fattr);
	status = rpc_call_sync(NFS_CLIENT(inode), &msg, flags);
	if (status >= 0) {
		nfs_post_op_update_inode_force_wcc(inode, fattr);
		wdata->res.count = wdata->args.count;
		wdata->verf.committed = NFS_FILE_SYNC;
	}
	dprintk("NFS reply write: %d\n", status);
	return status < 0? status : wdata->res.count;
}

static int
nfs_proc_create(struct inode *dir, struct dentry *dentry, struct iattr *sattr,
		int flags, struct nameidata *nd)
{
	struct nfs_fh		fhandle;
	struct nfs_fattr	fattr;
	struct nfs_createargs	arg = {
		.fh		= NFS_FH(dir),
		.name		= dentry->d_name.name,
		.len		= dentry->d_name.len,
		.sattr		= sattr
	};
	struct nfs_diropok	res = {
		.fh		= &fhandle,
		.fattr		= &fattr
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_CREATE],
		.rpc_argp	= &arg,
		.rpc_resp	= &res,
	};
	int			status;

	nfs_fattr_init(&fattr);
	dprintk("NFS call  create %s\n", dentry->d_name.name);
	status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);
	nfs_mark_for_revalidate(dir);
	if (status == 0)
		status = nfs_instantiate(dentry, &fhandle, &fattr);
	dprintk("NFS reply create: %d\n", status);
	return status;
}

/*
 * In NFSv2, mknod is grafted onto the create call.
 */
static int
nfs_proc_mknod(struct inode *dir, struct dentry *dentry, struct iattr *sattr,
	       dev_t rdev)
{
	struct nfs_fh fhandle;
	struct nfs_fattr fattr;
	struct nfs_createargs	arg = {
		.fh		= NFS_FH(dir),
		.name		= dentry->d_name.name,
		.len		= dentry->d_name.len,
		.sattr		= sattr
	};
	struct nfs_diropok	res = {
		.fh		= &fhandle,
		.fattr		= &fattr
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_CREATE],
		.rpc_argp	= &arg,
		.rpc_resp	= &res,
	};
	int status, mode;

	dprintk("NFS call  mknod %s\n", dentry->d_name.name);

	mode = sattr->ia_mode;
	if (S_ISFIFO(mode)) {
		sattr->ia_mode = (mode & ~S_IFMT) | S_IFCHR;
		sattr->ia_valid &= ~ATTR_SIZE;
	} else if (S_ISCHR(mode) || S_ISBLK(mode)) {
		sattr->ia_valid |= ATTR_SIZE;
		sattr->ia_size = new_encode_dev(rdev);/* get out your barf bag */
	}

	nfs_fattr_init(&fattr);
	status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);
	nfs_mark_for_revalidate(dir);

	if (status == -EINVAL && S_ISFIFO(mode)) {
		sattr->ia_mode = mode;
		nfs_fattr_init(&fattr);
		status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);
	}
	if (status == 0)
		status = nfs_instantiate(dentry, &fhandle, &fattr);
	dprintk("NFS reply mknod: %d\n", status);
	return status;
}
  
static int
nfs_proc_remove(struct inode *dir, struct qstr *name)
{
	struct nfs_removeargs arg = {
		.fh = NFS_FH(dir),
		.name.len = name->len,
		.name.name = name->name,
	};
	struct rpc_message msg = { 
		.rpc_proc = &nfs_procedures[NFSPROC_REMOVE],
		.rpc_argp = &arg,
	};
	int			status;

	dprintk("NFS call  remove %s\n", name->name);
	status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);
	nfs_mark_for_revalidate(dir);

	dprintk("NFS reply remove: %d\n", status);
	return status;
}

static void
nfs_proc_unlink_setup(struct rpc_message *msg, struct inode *dir)
{
	msg->rpc_proc = &nfs_procedures[NFSPROC_REMOVE];
}

static int nfs_proc_unlink_done(struct rpc_task *task, struct inode *dir)
{
	nfs_mark_for_revalidate(dir);
	return 1;
}

static void
nfs_proc_rename_setup(struct rpc_message *msg, struct inode *dir)
{
	msg->rpc_proc = &nfs_procedures[NFSPROC_RENAME];
}

static int
nfs_proc_rename_done(struct rpc_task *task, struct inode *old_dir,
		     struct inode *new_dir)
{
	nfs_mark_for_revalidate(old_dir);
	nfs_mark_for_revalidate(new_dir);
	return 1;
}

static int
nfs_proc_rename(struct inode *old_dir, struct qstr *old_name,
		struct inode *new_dir, struct qstr *new_name)
{
	struct nfs_renameargs	arg = {
		.old_dir	= NFS_FH(old_dir),
		.old_name	= old_name,
		.new_dir	= NFS_FH(new_dir),
		.new_name	= new_name,
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_RENAME],
		.rpc_argp	= &arg,
	};
	int			status;

	dprintk("NFS call  rename %s -> %s\n", old_name->name, new_name->name);
	status = rpc_call_sync(NFS_CLIENT(old_dir), &msg, 0);
	nfs_mark_for_revalidate(old_dir);
	nfs_mark_for_revalidate(new_dir);
	dprintk("NFS reply rename: %d\n", status);
	return status;
}

static int
nfs_proc_link(struct inode *inode, struct inode *dir, struct qstr *name)
{
	struct nfs_linkargs	arg = {
		.fromfh		= NFS_FH(inode),
		.tofh		= NFS_FH(dir),
		.toname		= name->name,
		.tolen		= name->len
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_LINK],
		.rpc_argp	= &arg,
	};
	int			status;

	dprintk("NFS call  link %s\n", name->name);
	status = rpc_call_sync(NFS_CLIENT(inode), &msg, 0);
	nfs_mark_for_revalidate(inode);
	nfs_mark_for_revalidate(dir);
	dprintk("NFS reply link: %d\n", status);
	return status;
}

static int
nfs_proc_symlink(struct inode *dir, struct dentry *dentry, struct page *page,
		 unsigned int len, struct iattr *sattr)
{
	struct nfs_fh fhandle;
	struct nfs_fattr fattr;
	struct nfs_symlinkargs	arg = {
		.fromfh		= NFS_FH(dir),
		.fromname	= dentry->d_name.name,
		.fromlen	= dentry->d_name.len,
		.pages		= &page,
		.pathlen	= len,
		.sattr		= sattr
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_SYMLINK],
		.rpc_argp	= &arg,
	};
	int			status;

	if (len > NFS2_MAXPATHLEN)
		return -ENAMETOOLONG;

	dprintk("NFS call  symlink %s\n", dentry->d_name.name);

	status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);
	nfs_mark_for_revalidate(dir);

	/*
	 * V2 SYMLINK requests don't return any attributes.  Setting the
	 * filehandle size to zero indicates to nfs_instantiate that it
	 * should fill in the data with a LOOKUP call on the wire.
	 */
	if (status == 0) {
		nfs_fattr_init(&fattr);
		fhandle.size = 0;
		status = nfs_instantiate(dentry, &fhandle, &fattr);
	}

	dprintk("NFS reply symlink: %d\n", status);
	return status;
}

static int
nfs_proc_mkdir(struct inode *dir, struct dentry *dentry, struct iattr *sattr)
{
	struct nfs_fh fhandle;
	struct nfs_fattr fattr;
	struct nfs_createargs	arg = {
		.fh		= NFS_FH(dir),
		.name		= dentry->d_name.name,
		.len		= dentry->d_name.len,
		.sattr		= sattr
	};
	struct nfs_diropok	res = {
		.fh		= &fhandle,
		.fattr		= &fattr
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_MKDIR],
		.rpc_argp	= &arg,
		.rpc_resp	= &res,
	};
	int			status;

	dprintk("NFS call  mkdir %s\n", dentry->d_name.name);
	nfs_fattr_init(&fattr);
	status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);
	nfs_mark_for_revalidate(dir);
	if (status == 0)
		status = nfs_instantiate(dentry, &fhandle, &fattr);
	dprintk("NFS reply mkdir: %d\n", status);
	return status;
}

static int
nfs_proc_rmdir(struct inode *dir, struct qstr *name)
{
	struct nfs_diropargs	arg = {
		.fh		= NFS_FH(dir),
		.name		= name->name,
		.len		= name->len
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_RMDIR],
		.rpc_argp	= &arg,
	};
	int			status;

	dprintk("NFS call  rmdir %s\n", name->name);
	status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);
	nfs_mark_for_revalidate(dir);
	dprintk("NFS reply rmdir: %d\n", status);
	return status;
}

/*
 * The READDIR implementation is somewhat hackish - we pass a temporary
 * buffer to the encode function, which installs it in the receive
 * the receive iovec. The decode function just parses the reply to make
 * sure it is syntactically correct; the entries itself are decoded
 * from nfs_readdir by calling the decode_entry function directly.
 */
static int
nfs_proc_readdir(struct dentry *dentry, struct rpc_cred *cred,
		 u64 cookie, struct page *page, unsigned int count, int plus)
{
	struct inode		*dir = dentry->d_inode;
	struct nfs_readdirargs	arg = {
		.fh		= NFS_FH(dir),
		.cookie		= cookie,
		.count		= count,
		.pages		= &page,
	};
	struct rpc_message	msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_READDIR],
		.rpc_argp	= &arg,
		.rpc_cred	= cred,
	};
	int			status;

	lock_kernel();

	dprintk("NFS call  readdir %d\n", (unsigned int)cookie);
	status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);

	nfs_invalidate_atime(dir);

	dprintk("NFS reply readdir: %d\n", status);
	unlock_kernel();
	return status;
}

static int
nfs_proc_statfs(struct nfs_server *server, struct nfs_fh *fhandle,
			struct nfs_fsstat *stat)
{
	struct nfs2_fsstat fsinfo;
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_STATFS],
		.rpc_argp	= fhandle,
		.rpc_resp	= &fsinfo,
	};
	int	status;

	dprintk("NFS call  statfs\n");
	nfs_fattr_init(stat->fattr);
	status = rpc_call_sync(server->client, &msg, 0);
	dprintk("NFS reply statfs: %d\n", status);
	if (status)
		goto out;
	stat->tbytes = (u64)fsinfo.blocks * fsinfo.bsize;
	stat->fbytes = (u64)fsinfo.bfree  * fsinfo.bsize;
	stat->abytes = (u64)fsinfo.bavail * fsinfo.bsize;
	stat->tfiles = 0;
	stat->ffiles = 0;
	stat->afiles = 0;
out:
	return status;
}

static int
nfs_proc_fsinfo(struct nfs_server *server, struct nfs_fh *fhandle,
			struct nfs_fsinfo *info)
{
	struct nfs2_fsstat fsinfo;
	struct rpc_message msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_STATFS],
		.rpc_argp	= fhandle,
		.rpc_resp	= &fsinfo,
	};
	int	status;

	dprintk("NFS call  fsinfo\n");
	nfs_fattr_init(info->fattr);
	status = rpc_call_sync(server->client, &msg, 0);
	dprintk("NFS reply fsinfo: %d\n", status);
	if (status)
		goto out;
	info->rtmax  = NFS_MAXDATA;
	info->rtpref = fsinfo.tsize;
	info->rtmult = fsinfo.bsize;
	info->wtmax  = NFS_MAXDATA;
	info->wtpref = fsinfo.tsize;
	info->wtmult = fsinfo.bsize;
	info->dtpref = fsinfo.tsize;
	info->maxfilesize = 0x7FFFFFFF;
	info->lease_time = 0;
out:
	return status;
}

static int
nfs_proc_pathconf(struct nfs_server *server, struct nfs_fh *fhandle,
		  struct nfs_pathconf *info)
{
	info->max_link = 0;
	info->max_namelen = NFS2_MAXNAMLEN;
	return 0;
}

static int nfs_read_done(struct rpc_task *task, struct nfs_read_data *data)
{
	nfs_invalidate_atime(data->inode);
	if (task->tk_status >= 0) {
		nfs_refresh_inode(data->inode, data->res.fattr);
		/* Emulate the eof flag, which isn't normally needed in NFSv2
		 * as it is guaranteed to always return the file attributes
		 */
		if (data->args.offset + data->args.count >= data->res.fattr->size)
			data->res.eof = 1;
	}
	return 0;
}

static void nfs_proc_read_setup(struct nfs_read_data *data)
{
	struct rpc_message	msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_READ],
		.rpc_argp	= &data->args,
		.rpc_resp	= &data->res,
		.rpc_cred	= data->cred,
	};

	rpc_call_setup(&data->task, &msg, 0);
}

static int nfs_write_done(struct rpc_task *task, struct nfs_write_data *data)
{
	if (task->tk_status >= 0)
		nfs_post_op_update_inode_force_wcc(data->inode, data->res.fattr);
	return 0;
}

static void nfs_proc_write_setup(struct nfs_write_data *data, int how)
{
	struct rpc_message	msg = {
		.rpc_proc	= &nfs_procedures[NFSPROC_WRITE],
		.rpc_argp	= &data->args,
		.rpc_resp	= &data->res,
		.rpc_cred	= data->cred,
	};

	/* Note: NFSv2 ignores @stable and always uses NFS_FILE_SYNC */
	data->args.stable = NFS_FILE_SYNC;

	/* Finalize the task. */
	rpc_call_setup(&data->task, &msg, 0);
}

static void
nfs_proc_commit_setup(struct nfs_write_data *data, int how)
{
	BUG();
}

static int
nfs_proc_lock(struct file *filp, int cmd, struct file_lock *fl)
{
	return nlmclnt_proc(filp->f_dentry->d_inode, cmd, fl);
}


const struct nfs_rpc_ops nfs_v2_clientops = {
	.version	= 2,		       /* protocol version */
	.dentry_ops	= &nfs_dentry_operations,
	.dir_inode_ops	= &nfs_dir_inode_operations,
	.file_inode_ops	= &nfs_file_inode_operations,
	.getroot	= nfs_proc_get_root,
	.getattr	= nfs_proc_getattr,
	.setattr	= nfs_proc_setattr,
	.lookup		= nfs_proc_lookup,
	.access		= NULL,		       /* access */
	.readlink	= nfs_proc_readlink,
	.read		= nfs_proc_read,
	.write		= nfs_proc_write,
	.commit		= NULL,		       /* commit */
	.create		= nfs_proc_create,
	.remove		= nfs_proc_remove,
	.unlink_setup	= nfs_proc_unlink_setup,
	.unlink_done	= nfs_proc_unlink_done,
	.rename		= nfs_proc_rename,
	.rename_setup	= nfs_proc_rename_setup,
	.rename_done	= nfs_proc_rename_done,
	.link		= nfs_proc_link,
	.symlink	= nfs_proc_symlink,
	.mkdir		= nfs_proc_mkdir,
	.rmdir		= nfs_proc_rmdir,
	.readdir	= nfs_proc_readdir,
	.mknod		= nfs_proc_mknod,
	.statfs		= nfs_proc_statfs,
	.fsinfo		= nfs_proc_fsinfo,
	.pathconf	= nfs_proc_pathconf,
	.decode_dirent	= nfs_decode_dirent,
	.read_setup	= nfs_proc_read_setup,
	.read_done	= nfs_read_done,
	.write_setup	= nfs_proc_write_setup,
	.write_done	= nfs_write_done,
	.commit_setup	= nfs_proc_commit_setup,
	.file_open	= nfs_open,
	.file_release	= nfs_release,
	.lock		= nfs_proc_lock,
	.close_context	= nfs_close_context,
};
