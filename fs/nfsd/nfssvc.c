/*
 * linux/fs/nfsd/nfssvc.c
 *
 * Central processing for nfsd.
 *
 * Authors:	Olaf Kirch (okir@monad.swb.de)
 *
 * Copyright (C) 1995, 1996, 1997 Olaf Kirch <okir@monad.swb.de>
 */

#include <linux/module.h>

#include <linux/time.h>
#include <linux/errno.h>
#include <linux/nfs.h>
#include <linux/in.h>
#include <linux/uio.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/fs_struct.h>

#include <linux/sunrpc/types.h>
#include <linux/sunrpc/stats.h>
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/svcsock.h>
#include <linux/sunrpc/cache.h>
#include <linux/nfsd/nfsd.h>
#include <linux/nfsd/stats.h>
#include <linux/nfsd/cache.h>
#include <linux/nfsd/syscall.h>
#include <linux/lockd/bind.h>
#include <linux/nfsacl.h>

#define NFSDDBG_FACILITY	NFSDDBG_SVC

/* these signals will be delivered to an nfsd thread 
 * when handling a request
 */
#define ALLOWED_SIGS	(sigmask(SIGKILL))
/* these signals will be delivered to an nfsd thread
 * when not handling a request. i.e. when waiting
 */
#define SHUTDOWN_SIGS	(sigmask(SIGKILL) | sigmask(SIGHUP) | sigmask(SIGINT) | sigmask(SIGQUIT))
/* if the last thread dies with SIGHUP, then the exports table is
 * left unchanged ( like 2.4-{0-9} ).  Any other signal will clear
 * the exports table (like 2.2).
 */
#define	SIG_NOCLEAN	SIGHUP

extern struct svc_program	nfsd_program;
static void			nfsd(struct svc_rqst *rqstp);
struct timeval			nfssvc_boot;
       struct svc_serv 		*nfsd_serv;
static atomic_t			nfsd_busy;
static unsigned long		nfsd_last_call;
static DEFINE_SPINLOCK(nfsd_call_lock);

struct nfsd_list {
	struct list_head 	list;
	struct task_struct	*task;
};
static struct list_head nfsd_list = LIST_HEAD_INIT(nfsd_list);

#if defined(CONFIG_NFSD_V2_ACL) || defined(CONFIG_NFSD_V3_ACL)
static struct svc_stat	nfsd_acl_svcstats;
static struct svc_version *	nfsd_acl_version[] = {
#if defined(CONFIG_NFSD_V2_ACL)
	[2] = &nfsd_acl_version2,
#endif
	[3] = &nfsd_acl_version3,
};

#if defined(CONFIG_NFSD_V2_ACL)
#define NFSD_ACL_MINVERS            2
#else
#define NFSD_ACL_MINVERS            3
#endif

#define NFSD_ACL_NRVERS		ARRAY_SIZE(nfsd_acl_version)
static struct svc_version *nfsd_acl_versions[NFSD_ACL_NRVERS];

static struct svc_program	nfsd_acl_program = {
	.pg_prog		= NFS_ACL_PROGRAM,
	.pg_nvers		= NFSD_ACL_NRVERS,
	.pg_vers		= nfsd_acl_versions,
	.pg_name		= "nfsacl",
	.pg_class		= "nfsd",
	.pg_stats		= &nfsd_acl_svcstats,
	.pg_authenticate	= &svc_set_client,
};

static struct svc_stat	nfsd_acl_svcstats = {
	.program	= &nfsd_acl_program,
};
#endif /* defined(CONFIG_NFSD_V2_ACL) || defined(CONFIG_NFSD_V3_ACL) */

extern struct svc_version nfsd_version2, nfsd_version3, nfsd_version4;

static struct svc_version *	nfsd_version[] = {
	[2] = &nfsd_version2,
#if defined(CONFIG_NFSD_V3)
	[3] = &nfsd_version3,
#endif
#if defined(CONFIG_NFSD_V4)
	[4] = &nfsd_version4,
#endif
};

#define NFSD_MINVERS    	2
#define NFSD_NRVERS		ARRAY_SIZE(nfsd_version)
static struct svc_version *nfsd_versions[NFSD_NRVERS];

struct svc_program		nfsd_program = {
#if defined(CONFIG_NFSD_V2_ACL) || defined(CONFIG_NFSD_V3_ACL)
	.pg_next		= &nfsd_acl_program,
#endif
	.pg_prog		= NFS_PROGRAM,		/* program number */
	.pg_nvers		= NFSD_NRVERS,		/* nr of entries in nfsd_version */
	.pg_vers		= nfsd_versions,	/* version table */
	.pg_name		= "nfsd",		/* program name */
	.pg_class		= "nfsd",		/* authentication class */
	.pg_stats		= &nfsd_svcstats,	/* version table */
	.pg_authenticate	= &svc_set_client,	/* export authentication */

};

int nfsd_vers(int vers, enum vers_op change)
{
	if (vers < NFSD_MINVERS || vers >= NFSD_NRVERS)
		return -1;
	switch(change) {
	case NFSD_SET:
		nfsd_versions[vers] = nfsd_version[vers];
#if defined(CONFIG_NFSD_V2_ACL) || defined(CONFIG_NFSD_V3_ACL)
		if (vers < NFSD_ACL_NRVERS)
			nfsd_acl_versions[vers] = nfsd_acl_version[vers];
#endif
		break;
	case NFSD_CLEAR:
		nfsd_versions[vers] = NULL;
#if defined(CONFIG_NFSD_V2_ACL) || defined(CONFIG_NFSD_V3_ACL)
		if (vers < NFSD_ACL_NRVERS)
			nfsd_acl_versions[vers] = NULL;
#endif
		break;
	case NFSD_TEST:
		return nfsd_versions[vers] != NULL;
	case NFSD_AVAIL:
		return nfsd_version[vers] != NULL;
	}
	return 0;
}
/*
 * Maximum number of nfsd processes
 */
#define	NFSD_MAXSERVS		8192

int nfsd_nrthreads(void)
{
	if (nfsd_serv == NULL)
		return 0;
	else
		return nfsd_serv->sv_nrthreads;
}

static int killsig;	/* signal that was used to kill last nfsd */
static void nfsd_last_thread(struct svc_serv *serv)
{
	/* When last nfsd thread exits we need to do some clean-up */
	struct svc_sock *svsk;
	list_for_each_entry(svsk, &serv->sv_permsocks, sk_list)
		lockd_down();
	nfsd_serv = NULL;
	nfsd_racache_shutdown();
	nfs4_state_shutdown();

	printk(KERN_WARNING "nfsd: last server has exited\n");
	if (killsig != SIG_NOCLEAN) {
		printk(KERN_WARNING "nfsd: unexporting all filesystems\n");
		nfsd_export_flush();
	}
}
void nfsd_reset_versions(void)
{
	int found_one = 0;
	int i;

	for (i = NFSD_MINVERS; i < NFSD_NRVERS; i++) {
		if (nfsd_program.pg_vers[i])
			found_one = 1;
	}

	if (!found_one) {
		for (i = NFSD_MINVERS; i < NFSD_NRVERS; i++)
			nfsd_program.pg_vers[i] = nfsd_version[i];
#if defined(CONFIG_NFSD_V2_ACL) || defined(CONFIG_NFSD_V3_ACL)
		for (i = NFSD_ACL_MINVERS; i < NFSD_ACL_NRVERS; i++)
			nfsd_acl_program.pg_vers[i] =
				nfsd_acl_version[i];
#endif
	}
}

int nfsd_create_serv(void)
{
	int err = 0;
	lock_kernel();
	if (nfsd_serv) {
		nfsd_serv->sv_nrthreads++;
		unlock_kernel();
		return 0;
	}

	atomic_set(&nfsd_busy, 0);
	nfsd_serv = svc_create(&nfsd_program, NFSD_BUFSIZE);
	if (nfsd_serv == NULL)
		err = -ENOMEM;
	svc_shutdown(nfsd_serv, nfsd_last_thread);
	unlock_kernel();
	do_gettimeofday(&nfssvc_boot);		/* record boot time */
	return err;
}

static int nfsd_init_socks(int port)
{
	int error;
	if (!list_empty(&nfsd_serv->sv_permsocks))
		return 0;

	error = svc_makesock(nfsd_serv, IPPROTO_UDP, port);
	if (error < 0)
		return error;
	error = lockd_up_proto(IPPROTO_UDP);
	if (error < 0)
		return error;

#ifdef CONFIG_NFSD_TCP
	error = svc_makesock(nfsd_serv, IPPROTO_TCP, port);
	if (error < 0)
		return error;
	error = lockd_up_proto(IPPROTO_TCP);
	if (error < 0)
		return error;
#endif
	return 0;
}

int
nfsd_svc(unsigned short port, int nrservs)
{
	int	error;
	struct list_head *victim;
	
	lock_kernel();
	dprintk("nfsd: creating service: port %d tcp %d udp %d\n",
		nfsd_port, NFSCTL_TCPISSET(nfsd_portbits), 
		NFSCTL_UDPISSET(nfsd_portbits));
	error = -EINVAL;
	if (nrservs <= 0)
		nrservs = 0;
	if (nrservs > NFSD_MAXSERVS)
		nrservs = NFSD_MAXSERVS;
	
	/* Readahead param cache - will no-op if it already exists */
	error =	nfsd_racache_init(2*nrservs);
	if (error<0)
		goto out;
	error = nfs4_state_start();
	if (error<0)
		goto out;

	nfsd_reset_versions();

	error = nfsd_create_serv();

	if (error)
		goto out;
	error = nfsd_init_socks(port);
	if (error)
		goto failure;

	nrservs -= (nfsd_serv->sv_nrthreads-1);
	while (nrservs > 0) {
		nrservs--;
		__module_get(THIS_MODULE);
		error = svc_create_thread(nfsd, nfsd_serv);
		if (error < 0) {
			module_put(THIS_MODULE);
			break;
		}
	}
	victim = nfsd_list.next;
	while (nrservs < 0 && victim != &nfsd_list) {
		struct nfsd_list *nl =
			list_entry(victim,struct nfsd_list, list);
		victim = victim->next;
		send_sig(SIG_NOCLEAN, nl->task, 1);
		nrservs++;
	}
 failure:
	svc_destroy(nfsd_serv);		/* Release server */
 out:
	unlock_kernel();
	return error;
}

static inline void
update_thread_usage(int busy_threads)
{
	unsigned long prev_call;
	unsigned long diff;
	int decile;

	spin_lock(&nfsd_call_lock);
	prev_call = nfsd_last_call;
	nfsd_last_call = jiffies;
	decile = busy_threads*10/nfsdstats.th_cnt;
	if (decile>0 && decile <= 10) {
		diff = nfsd_last_call - prev_call;
		if ( (nfsdstats.th_usage[decile-1] += diff) >= NFSD_USAGE_WRAP)
			nfsdstats.th_usage[decile-1] -= NFSD_USAGE_WRAP;
		if (decile == 10)
			nfsdstats.th_fullcnt++;
	}
	spin_unlock(&nfsd_call_lock);
}

/*
 * This is the NFS server kernel thread
 */
static void
nfsd(struct svc_rqst *rqstp)
{
	struct svc_serv	*serv = rqstp->rq_server;
	struct fs_struct *fsp;
	int		err;
	struct nfsd_list me;
	sigset_t shutdown_mask, allowed_mask;

	/* Lock module and set up kernel thread */
	lock_kernel();
	daemonize("nfsd");

	/* After daemonize() this kernel thread shares current->fs
	 * with the init process. We need to create files with a
	 * umask of 0 instead of init's umask. */
	fsp = copy_fs_struct(current->fs);
	if (!fsp) {
		printk("Unable to start nfsd thread: out of memory\n");
		goto out;
	}
	exit_fs(current);
	current->fs = fsp;
	current->fs->umask = 0;

	siginitsetinv(&shutdown_mask, SHUTDOWN_SIGS);
	siginitsetinv(&allowed_mask, ALLOWED_SIGS);

	nfsdstats.th_cnt++;

	me.task = current;
	list_add(&me.list, &nfsd_list);

	unlock_kernel();

	/*
	 * We want less throttling in balance_dirty_pages() so that nfs to
	 * localhost doesn't cause nfsd to lock up due to all the client's
	 * dirty pages.
	 */
	current->flags |= PF_LESS_THROTTLE;

	/*
	 * The main request loop
	 */
	for (;;) {
		/* Block all but the shutdown signals */
		sigprocmask(SIG_SETMASK, &shutdown_mask, NULL);

		/*
		 * Find a socket with data available and call its
		 * recvfrom routine.
		 */
		while ((err = svc_recv(serv, rqstp,
				       60*60*HZ)) == -EAGAIN)
			;
		if (err < 0)
			break;
		update_thread_usage(atomic_read(&nfsd_busy));
		atomic_inc(&nfsd_busy);

		/* Lock the export hash tables for reading. */
		exp_readlock();

		/* Process request with signals blocked.  */
		sigprocmask(SIG_SETMASK, &allowed_mask, NULL);

		svc_process(serv, rqstp);

		/* Unlock export hash tables */
		exp_readunlock();
		update_thread_usage(atomic_read(&nfsd_busy));
		atomic_dec(&nfsd_busy);
	}

	if (err != -EINTR) {
		printk(KERN_WARNING "nfsd: terminating on error %d\n", -err);
	} else {
		unsigned int	signo;

		for (signo = 1; signo <= _NSIG; signo++)
			if (sigismember(&current->pending.signal, signo) &&
			    !sigismember(&current->blocked, signo))
				break;
		killsig = signo;
	}
	/* Clear signals before calling svc_exit_thread() */
	flush_signals(current);

	lock_kernel();

	list_del(&me.list);
	nfsdstats.th_cnt --;

out:
	/* Release the thread */
	svc_exit_thread(rqstp);

	/* Release module */
	unlock_kernel();
	module_put_and_exit(0);
}

static __be32 map_new_errors(u32 vers, __be32 nfserr)
{
	if (nfserr == nfserr_jukebox && vers == 2)
		return nfserr_dropit;
	if (nfserr == nfserr_wrongsec && vers < 4)
		return nfserr_acces;
	return nfserr;
}

int
nfsd_dispatch(struct svc_rqst *rqstp, u32 *statp)
{
	struct svc_procedure	*proc;
	kxdrproc_t		xdr;
	u32			nfserr;
	u32			*nfserrp;

	dprintk("nfsd_dispatch: vers %d proc %d\n",
				rqstp->rq_vers, rqstp->rq_proc);
	proc = rqstp->rq_procinfo;

	/* Check whether we have this call in the cache. */
	switch (nfsd_cache_lookup(rqstp, proc->pc_cachetype)) {
	case RC_INTR:
	case RC_DROPIT:
		return 0;
	case RC_REPLY:
		return 1;
	case RC_DOIT:;
		/* do it */
	}

	/* Decode arguments */
	xdr = proc->pc_decode;
	if (xdr && !xdr(rqstp, (u32*)rqstp->rq_arg.head[0].iov_base,
			rqstp->rq_argp)) {
		dprintk("nfsd: failed to decode arguments!\n");
		nfsd_cache_update(rqstp, RC_NOCACHE, NULL);
		*statp = rpc_garbage_args;
		return 1;
	}

	/* need to grab the location to store the status, as
	 * nfsv4 does some encoding while processing 
	 */
	nfserrp = rqstp->rq_res.head[0].iov_base
		+ rqstp->rq_res.head[0].iov_len;
	rqstp->rq_res.head[0].iov_len += sizeof(u32);

	/* Now call the procedure handler, and encode NFS status. */
	nfserr = proc->pc_func(rqstp, rqstp->rq_argp, rqstp->rq_resp);
	nfserr = map_new_errors(rqstp->rq_vers, nfserr);
	if (nfserr == nfserr_jukebox && rqstp->rq_vers == 2)
		nfserr = nfserr_dropit;
	if (nfserr == nfserr_dropit) {
		dprintk("nfsd: Dropping request due to malloc failure!\n");
		nfsd_cache_update(rqstp, RC_NOCACHE, NULL);
		return 0;
	}

	if (rqstp->rq_proc != 0)
		*nfserrp++ = nfserr;

	/* Encode result.
	 * For NFSv2, additional info is never returned in case of an error.
	 */
	if (!(nfserr && rqstp->rq_vers == 2)) {
		xdr = proc->pc_encode;
		if (xdr && !xdr(rqstp, nfserrp,
				rqstp->rq_resp)) {
			/* Failed to encode result. Release cache entry */
			dprintk("nfsd: failed to encode result!\n");
			nfsd_cache_update(rqstp, RC_NOCACHE, NULL);
			*statp = rpc_system_err;
			return 1;
		}
	}

	/* Store reply in cache. */
	nfsd_cache_update(rqstp, proc->pc_cachetype, statp + 1);
	return 1;
}
