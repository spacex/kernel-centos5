/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2008 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#ifndef __OPS_ADDRESS_DOT_H__
#define __OPS_ADDRESS_DOT_H__

#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/mm.h>

extern struct file gfs2_internal_file_sentinel;
extern void gfs2_page_add_databufs(struct gfs2_inode *ip, struct page *page,
				   unsigned int from, unsigned int to);
extern int gfs2_internal_read(struct gfs2_inode *ip,
                              struct file_ra_state *ra_state,
                              char *buf, loff_t *pos, unsigned size);

extern int gfs2_releasepage(struct page *page, gfp_t gfp_mask);
extern void gfs2_set_aops(struct inode *inode);
extern int gfs2_write_begin(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned flags,
			    struct page **pagep, void **fsdata);
extern int gfs2_write_end(struct file *file, struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned copied,
			  struct page *page, void *fsdata);

#endif /* __OPS_ADDRESS_DOT_H__ */
