/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2008 Red Hat, Inc.  All rights reserved.
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
#include <linux/lm_interface.h>
#include <linux/bio.h>

#include "gfs2.h"
#include "incore.h"
#include "bmap.h"
#include "glock.h"
#include "glops.h"
#include "inode.h"
#include "log.h"
#include "meta_io.h"
#include "recovery.h"
#include "rgrp.h"
#include "util.h"
#include "trans.h"

/**
 * ail_empty_gl - remove all buffers for a given lock from the AIL
 * @gl: the glock
 *
 * None of the buffers should be dirty, locked, or pinned.
 */

static void gfs2_ail_empty_gl(struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct list_head *head = &gl->gl_ail_list;
	struct gfs2_bufdata *bd;
	struct buffer_head *bh;
	struct gfs2_trans tr;

	memset(&tr, 0, sizeof(tr));
	tr.tr_revokes = atomic_read(&gl->gl_ail_count);

	if (!tr.tr_revokes)
		return;

	/* A shortened, inline version of gfs2_trans_begin() */
	tr.tr_reserved = 1 + gfs2_struct2blk(sdp, tr.tr_revokes, sizeof(u64));
	tr.tr_ip = (unsigned long)__builtin_return_address(0);
	INIT_LIST_HEAD(&tr.tr_list_buf);
	gfs2_log_reserve(sdp, tr.tr_reserved, 1);
	BUG_ON(current->journal_info);
	current->journal_info = &tr;

	gfs2_log_lock(sdp);
	while (!list_empty(head)) {
		bd = list_entry(head->next, struct gfs2_bufdata,
				bd_ail_gl_list);
		bh = bd->bd_bh;
		gfs2_remove_from_ail(bd);
		bd->bd_bh = NULL;
		bh->b_private = NULL;
		bd->bd_blkno = bh->b_blocknr;
		gfs2_assert_withdraw(sdp, !buffer_busy(bh));
		gfs2_trans_add_revoke(sdp, bd);
	}
	gfs2_assert_withdraw(sdp, !atomic_read(&gl->gl_ail_count));
	gfs2_log_unlock(sdp);

	gfs2_trans_end(sdp);
	gfs2_log_flush(sdp, NULL);
}

/**
 * gfs2_pte_inval - Sync and invalidate all PTEs associated with a glock
 * @gl: the glock
 *
 */

static void gfs2_pte_inval(struct gfs2_glock *gl)
{
	struct gfs2_inode *ip;
	struct inode *inode;

	ip = gl->gl_object;
	inode = &ip->i_inode;
	if (!ip || !S_ISREG(inode->i_mode))
		return;

	unmap_shared_mapping_range(inode->i_mapping, 0, 0);
	if (test_bit(GIF_SW_PAGED, &ip->i_flags))
		set_bit(GLF_DIRTY, &gl->gl_flags);
}

/**
 * meta_go_sync - sync out the metadata for this glock
 * @gl: the glock
 *
 * Called when demoting or unlocking an EX glock.  We must flush
 * to disk all dirty buffers/pages relating to this glock, and must not
 * not return to caller to demote/unlock the glock until I/O is complete.
 */

static void meta_go_sync(struct gfs2_glock *gl)
{
	if (gl->gl_state != LM_ST_EXCLUSIVE)
		return;

	if (test_and_clear_bit(GLF_DIRTY, &gl->gl_flags)) {
		gfs2_log_flush(gl->gl_sbd, gl);
		gfs2_meta_sync(gl);
		gfs2_ail_empty_gl(gl);
	}
}

/**
 * gfs2_meta_inval - Invalidate all buffers associated with a glock
 * @gl: the glock
 *
 */

static void gfs2_meta_inval(struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct inode *aspace = gl->gl_aspace;
	struct address_space *mapping = gl->gl_aspace->i_mapping;

	gfs2_assert_withdraw(sdp, !atomic_read(&gl->gl_ail_count));

	atomic_inc(&aspace->i_writecount);
	truncate_inode_pages(mapping, 0);
	atomic_dec(&aspace->i_writecount);

	gfs2_assert_withdraw(sdp, !mapping->nrpages);
}

/**
 * meta_go_inval - invalidate the metadata for this glock
 * @gl: the glock
 * @flags:
 *
 */

static void meta_go_inval(struct gfs2_glock *gl, int flags)
{
	if (!(flags & DIO_METADATA))
		return;

	gfs2_meta_inval(gl);
	if (gl->gl_ops == &gfs2_rgrp_glops && gl->gl_object) {
		struct gfs2_rgrpd *rgd = (struct gfs2_rgrpd *)gl->gl_object;

		rgd->rd_flags &= ~GFS2_RDF_UPTODATE;
	}
}

/**
 * inode_go_sync - Sync the dirty data and/or metadata for an inode glock
 * @gl: the glock protecting the inode
 *
 */

static void inode_go_sync(struct gfs2_glock *gl)
{
	struct gfs2_inode *ip = gl->gl_object;

	if (gl->gl_state != LM_ST_UNLOCKED)
		gfs2_pte_inval(gl);
	if (gl->gl_state != LM_ST_EXCLUSIVE)
		return;

	if (ip && !S_ISREG(ip->i_inode.i_mode))
		ip = NULL;

	if (test_bit(GLF_DIRTY, &gl->gl_flags)) {
		if (ip && !gfs2_is_jdata(ip))
			filemap_fdatawrite(ip->i_inode.i_mapping);
		gfs2_log_flush(gl->gl_sbd, gl);
		if (ip && gfs2_is_jdata(ip))
			filemap_fdatawrite(ip->i_inode.i_mapping);
		gfs2_meta_sync(gl);
		if (ip) {
			struct address_space *mapping = ip->i_inode.i_mapping;
			int error = filemap_fdatawait(mapping);
			if (error == -ENOSPC)
				set_bit(AS_ENOSPC, &mapping->flags);
			else if (error)
				set_bit(AS_EIO, &mapping->flags);
		}
		clear_bit(GLF_DIRTY, &gl->gl_flags);
		gfs2_ail_empty_gl(gl);
	}
}

/**
 * inode_go_inval - prepare a inode glock to be released
 * @gl: the glock
 * @flags:
 *
 */

static void inode_go_inval(struct gfs2_glock *gl, int flags)
{
	struct gfs2_inode *ip = gl->gl_object;
	int meta = (flags & DIO_METADATA);

	if (meta) {
		gfs2_meta_inval(gl);
		if (ip)
			set_bit(GIF_INVALID, &ip->i_flags);
	}

	if (gl->gl_object == GFS2_I(gl->gl_sbd->sd_rindex))
		gl->gl_sbd->sd_rindex_uptodate = 0;
	if (ip && S_ISREG(ip->i_inode.i_mode))
		truncate_inode_pages(ip->i_inode.i_mapping, 0);
}

/**
 * inode_go_demote_ok - Check to see if it's ok to unlock an inode glock
 * @gl: the glock
 *
 * Returns: 1 if it's ok
 */

static int inode_go_demote_ok(const struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	if (sdp->sd_jindex == gl->gl_object || sdp->sd_rindex == gl->gl_object)
		return 0;
	return 1;
}

/**
 * inode_go_lock - operation done after an inode lock is locked by a process
 * @gl: the glock
 * @flags:
 *
 * Returns: errno
 */

static int inode_go_lock(struct gfs2_holder *gh)
{
	struct gfs2_glock *gl = gh->gh_gl;
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct gfs2_inode *ip = gl->gl_object;
	int error = 0;

	if (!ip || (gh->gh_flags & GL_SKIP))
		return 0;

	if (test_bit(GIF_INVALID, &ip->i_flags)) {
		error = gfs2_inode_refresh(ip);
		if (error)
			return error;
	}

	if ((ip->i_diskflags & GFS2_DIF_TRUNC_IN_PROG) &&
	    (gl->gl_state == LM_ST_EXCLUSIVE) &&
	    (gh->gh_state == LM_ST_EXCLUSIVE)) {
		spin_lock(&sdp->sd_trunc_lock);
		if (list_empty(&ip->i_trunc_list))
			list_add(&sdp->sd_trunc_list, &ip->i_trunc_list);
		spin_unlock(&sdp->sd_trunc_lock);
		wake_up(&sdp->sd_quota_wait);
		return 1;
	}

	return error;
}

/**
 * inode_go_dump - print information about an inode
 * @seq: The iterator
 * @ip: the inode
 *
 * Returns: 0 on success, -ENOBUFS when we run out of space
 */

static int inode_go_dump(struct seq_file *seq, const struct gfs2_glock *gl)
{
	const struct gfs2_inode *ip = gl->gl_object;
	if (ip == NULL)
		return 0;
	gfs2_print_dbg(seq, " I: n:%llu/%llu t:%u f:0x%02lx d:0x%08x s:%llu/%llu\n",
		  (unsigned long long)ip->i_no_formal_ino,
		  (unsigned long long)ip->i_no_addr,
		  IF2DT(ip->i_inode.i_mode), ip->i_flags,
		  (unsigned int)ip->i_diskflags,
		  (unsigned long long)ip->i_inode.i_size,
		  (unsigned long long)ip->i_disksize);
	return 0;
}

/**
 * rgrp_go_demote_ok - Check to see if it's ok to unlock a RG's glock
 * @gl: the glock
 *
 * Returns: 1 if it's ok
 */

static int rgrp_go_demote_ok(const struct gfs2_glock *gl)
{
	return !gl->gl_aspace->i_mapping->nrpages;
}

/**
 * rgrp_go_lock - operation done after an rgrp lock is locked by
 *    a first holder on this node.
 * @gl: the glock
 * @flags:
 *
 * Returns: errno
 */

static int rgrp_go_lock(struct gfs2_holder *gh)
{
	return gfs2_rgrp_bh_get(gh->gh_gl->gl_object);
}

/**
 * rgrp_go_unlock - operation done before an rgrp lock is unlocked by
 *    a last holder on this node.
 * @gl: the glock
 * @flags:
 *
 */

static void rgrp_go_unlock(struct gfs2_holder *gh)
{
	gfs2_rgrp_bh_put(gh->gh_gl->gl_object);
}

/**
 * rgrp_go_dump - print out an rgrp
 * @seq: The iterator
 * @gl: The glock in question
 *
 */

static int rgrp_go_dump(struct seq_file *seq, const struct gfs2_glock *gl)
{
	const struct gfs2_rgrpd *rgd = gl->gl_object;
	if (rgd == NULL)
		return 0;
	gfs2_print_dbg(seq, " R: n:%llu f:%02x b:%u/%u i:%u\n",
		       (unsigned long long)rgd->rd_addr, rgd->rd_flags,
		       rgd->rd_free, rgd->rd_free_clone, rgd->rd_dinodes);
	return 0;
}

/**
 * trans_go_sync - promote/demote the transaction glock
 * @gl: the glock
 * @state: the requested state
 * @flags:
 *
 */

static void trans_go_xmote_th(struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;

	if (gl->gl_state != LM_ST_UNLOCKED &&
	    test_bit(SDF_JOURNAL_LIVE, &sdp->sd_flags)) {
		gfs2_meta_syncfs(sdp);
		gfs2_log_shutdown(sdp);
	}
}

/**
 * trans_go_xmote_bh - After promoting/demoting the transaction glock
 * @gl: the glock
 *
 */

static int trans_go_xmote_bh(struct gfs2_glock *gl, struct gfs2_holder *gh)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct gfs2_inode *ip = GFS2_I(sdp->sd_jdesc->jd_inode);
	struct gfs2_glock *j_gl = ip->i_gl;
	struct gfs2_log_header_host head;
	int error;

	if (test_bit(SDF_JOURNAL_LIVE, &sdp->sd_flags)) {
		j_gl->gl_ops->go_inval(j_gl, DIO_METADATA);

		error = gfs2_find_jhead(sdp->sd_jdesc, &head);
		if (error)
			gfs2_consist(sdp);
		if (!(head.lh_flags & GFS2_LOG_HEAD_UNMOUNT))
			gfs2_consist(sdp);

		/*  Initialize some head of the log stuff  */
		if (!test_bit(SDF_SHUTDOWN, &sdp->sd_flags)) {
			sdp->sd_log_sequence = head.lh_sequence + 1;
			gfs2_log_pointers_init(sdp, head.lh_blkno);
		}
	}
	return 0;
}

/**
 * trans_go_demote_ok
 * @gl: the glock
 *
 * Always returns 0
 */

static int trans_go_demote_ok(const struct gfs2_glock *gl)
{
	return 0;
}

/**
 * iopen_go_callback - schedule the dcache entry for the inode to be deleted
 * @gl: the glock
 *
 * gl_spin lock is held while calling this
 */
static void iopen_go_callback(struct gfs2_glock *gl)
{
	struct gfs2_inode *ip = (struct gfs2_inode *)gl->gl_object;
	struct gfs2_sbd *sdp = gl->gl_sbd;

	if (sdp->sd_vfs->s_flags & MS_RDONLY)
		return;

	if (gl->gl_demote_state == LM_ST_UNLOCKED &&
	    gl->gl_state == LM_ST_SHARED &&
	    ip && test_bit(GIF_USER, &ip->i_flags)) {
		gfs2_glock_hold(gl);
		if (queue_delayed_work(gfs2_delete_workqueue, &gl->gl_delete, 0) == 0)
			gfs2_glock_put_nolock(gl);
	}
}

/**
 * quota_go_demote_ok - Check to see if it's ok to unlock a quota glock
 * @gl: the glock
 *
 * Returns: 1 if it's ok
 */

static int quota_go_demote_ok(const struct gfs2_glock *gl)
{
	return !atomic_read(&gl->gl_lvb_count);
}

const struct gfs2_glock_operations gfs2_meta_glops = {
	.go_xmote_th = meta_go_sync,
	.go_type = LM_TYPE_META,
};

const struct gfs2_glock_operations gfs2_inode_glops = {
	.go_xmote_th = inode_go_sync,
	.go_inval = inode_go_inval,
	.go_demote_ok = inode_go_demote_ok,
	.go_lock = inode_go_lock,
	.go_dump = inode_go_dump,
	.go_type = LM_TYPE_INODE,
};

const struct gfs2_glock_operations gfs2_rgrp_glops = {
	.go_xmote_th = meta_go_sync,
	.go_inval = meta_go_inval,
	.go_demote_ok = rgrp_go_demote_ok,
	.go_lock = rgrp_go_lock,
	.go_unlock = rgrp_go_unlock,
	.go_dump = rgrp_go_dump,
	.go_type = LM_TYPE_RGRP,
};

const struct gfs2_glock_operations gfs2_trans_glops = {
	.go_xmote_th = trans_go_xmote_th,
	.go_xmote_bh = trans_go_xmote_bh,
	.go_demote_ok = trans_go_demote_ok,
	.go_type = LM_TYPE_NONDISK,
};

const struct gfs2_glock_operations gfs2_iopen_glops = {
	.go_type = LM_TYPE_IOPEN,
	.go_callback = iopen_go_callback,
};

const struct gfs2_glock_operations gfs2_flock_glops = {
	.go_type = LM_TYPE_FLOCK,
};

const struct gfs2_glock_operations gfs2_nondisk_glops = {
	.go_type = LM_TYPE_NONDISK,
};

const struct gfs2_glock_operations gfs2_quota_glops = {
	.go_demote_ok = quota_go_demote_ok,
	.go_type = LM_TYPE_QUOTA,
};

const struct gfs2_glock_operations gfs2_journal_glops = {
	.go_type = LM_TYPE_JOURNAL,
};

