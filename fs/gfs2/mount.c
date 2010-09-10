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
#include <linux/lm_interface.h>
#include <linux/parser.h>

#include "gfs2.h"
#include "incore.h"
#include "super.h"
#include "sys.h"
#include "util.h"

enum {
	Opt_lockproto,
	Opt_locktable,
	Opt_hostdata,
	Opt_spectator,
	Opt_ignore_local_fs,
	Opt_localflocks,
	Opt_localcaching,
	Opt_debug,
	Opt_nodebug,
	Opt_upgrade,
	Opt_num_glockd,
	Opt_acl,
	Opt_noacl,
	Opt_quota_off,
	Opt_quota_account,
	Opt_quota_on,
	Opt_quota,
	Opt_noquota,
	Opt_suiddir,
	Opt_nosuiddir,
	Opt_data_writeback,
	Opt_data_ordered,
	Opt_meta,
	Opt_err_withdraw,
	Opt_err_panic,
	Opt_statfs_quantum,
	Opt_statfs_percent,
	Opt_quota_quantum,
	Opt_err,
};

static match_table_t tokens = {
	{Opt_lockproto, "lockproto=%s"},
	{Opt_locktable, "locktable=%s"},
	{Opt_hostdata, "hostdata=%s"},
	{Opt_spectator, "spectator"},
	{Opt_ignore_local_fs, "ignore_local_fs"},
	{Opt_localflocks, "localflocks"},
	{Opt_localcaching, "localcaching"},
	{Opt_debug, "debug"},
	{Opt_nodebug, "nodebug"},
	{Opt_upgrade, "upgrade"},
	{Opt_num_glockd, "num_glockd=%d"},
	{Opt_acl, "acl"},
	{Opt_noacl, "noacl"},
	{Opt_quota_off, "quota=off"},
	{Opt_quota_account, "quota=account"},
	{Opt_quota_on, "quota=on"},
	{Opt_quota, "quota"},
	{Opt_noquota, "noquota"},
	{Opt_suiddir, "suiddir"},
	{Opt_nosuiddir, "nosuiddir"},
	{Opt_data_writeback, "data=writeback"},
	{Opt_data_ordered, "data=ordered"},
	{Opt_meta, "meta"},
	{Opt_err_withdraw, "errors=withdraw"},
	{Opt_err_panic, "errors=panic"},
	{Opt_statfs_quantum, "statfs_quantum=%d"},
	{Opt_statfs_percent, "statfs_percent=%d"},
	{Opt_quota_quantum, "quota_quantum=%d"},
	{Opt_err, NULL}
};

/**
 * gfs2_mount_args - Parse mount options
 * @sdp:
 * @data:
 *
 * Return: errno
 */

int gfs2_mount_args(struct gfs2_sbd *sdp, struct gfs2_args *args, char *options)
{
	char *o;
	int token;
	substring_t tmp[MAX_OPT_ARGS];
	int rv;

	/* Split the options into tokens with the "," character and
	   process them */

	while(1) {
		o = strsep(&options, ",");
		if (o == NULL)
			break;
		if (*o == '\0')
			continue;

		token = match_token(o, tokens, tmp);
		switch (token) {
		case Opt_lockproto:
			match_strlcpy(args->ar_lockproto, &tmp[0],
				      GFS2_LOCKNAME_LEN);
			break;
		case Opt_locktable:
			match_strlcpy(args->ar_locktable, &tmp[0],
				      GFS2_LOCKNAME_LEN);
			break;
		case Opt_hostdata:
			match_strlcpy(args->ar_hostdata, &tmp[0],
				      GFS2_LOCKNAME_LEN);
			break;
		case Opt_spectator:
			args->ar_spectator = 1;
			break;
		case Opt_ignore_local_fs:
			args->ar_ignore_local_fs = 1;
			break;
		case Opt_localflocks:
			args->ar_localflocks = 1;
			break;
		case Opt_localcaching:
			args->ar_localcaching = 1;
			break;
		case Opt_debug:
			if (args->ar_errors == GFS2_ERRORS_PANIC) {
				printk(KERN_WARNING "GFS2: -o debug and -o errors=panic "
				       "are mutually exclusive.\n");
				return -EINVAL;
			}
			args->ar_debug = 1;
			break;
		case Opt_nodebug:
			args->ar_debug = 0;
			break;
		case Opt_upgrade:
			args->ar_upgrade = 1;
			break;
		case Opt_num_glockd: /* Ignored */
			break;
		case Opt_acl:
			args->ar_posix_acl = 1;
			break;
		case Opt_noacl:
			args->ar_posix_acl = 0;
			break;
		case Opt_quota_off:
		case Opt_noquota:
			args->ar_quota = GFS2_QUOTA_OFF;
			break;
		case Opt_quota_account:
			args->ar_quota = GFS2_QUOTA_ACCOUNT;
			break;
		case Opt_quota_on:
		case Opt_quota:
			args->ar_quota = GFS2_QUOTA_ON;
			break;
		case Opt_suiddir:
			args->ar_suiddir = 1;
			break;
		case Opt_nosuiddir:
			args->ar_suiddir = 0;
			break;
		case Opt_data_writeback:
			args->ar_data = GFS2_DATA_WRITEBACK;
			break;
		case Opt_data_ordered:
			args->ar_data = GFS2_DATA_ORDERED;
			break;
		case Opt_meta:
			args->ar_meta = 1;
			break;
		case Opt_statfs_quantum:
			rv = match_int(&tmp[0], &args->ar_statfs_quantum);
			if (rv || args->ar_statfs_quantum < 0) {
				printk(KERN_WARNING "GFS2: statfs_quantum mount option requires a non-negative numeric argument\n");
				return rv ? rv : -EINVAL;
			}
			break;
		case Opt_quota_quantum:
			rv = match_int(&tmp[0], &args->ar_quota_quantum);
			if (rv || args->ar_quota_quantum <= 0) {
				printk(KERN_WARNING "GFS2: quota_quantum mount option requires a positive numeric argument\n");
				return rv ? rv : -EINVAL;
			}
			break;
		case Opt_statfs_percent:
			rv = match_int(&tmp[0], &args->ar_statfs_percent);
			if (rv || args->ar_statfs_percent < 0 ||
			    args->ar_statfs_percent > 100) {
				printk(KERN_WARNING "GFS2: statfs_percent mount option requires a numeric argument between 0 and 100\n");
				return rv ? rv : -EINVAL;
			}
			break;
		case Opt_err_withdraw:
			args->ar_errors = GFS2_ERRORS_WITHDRAW;
			break;
		case Opt_err_panic:
			if (args->ar_debug) {
				printk(KERN_WARNING "GFS2: -o debug and -o errors=panic "
					"are mutually exclusive.\n");
				return -EINVAL;
			}
			args->ar_errors = GFS2_ERRORS_PANIC;
			break;
		case Opt_err:
		default:
			fs_info(sdp, "invalid mount option: %s\n", o);
			return -EINVAL;
		}
	}

	return 0;
}

