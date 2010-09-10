/*
 * Cryptographic API.
 *
 * Cipher operations.
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 *               2002 Adam J. Richter <adam@yggdrasil.com>
 *               2004 Jean-Luc Cooke <jlcooke@certainkey.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <crypto/nscatterwalk.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/scatterlist.h>

static inline void memcpy_dir(void *buf, void *sgdata, size_t nbytes, int out)
{
	void *src = out ? buf : sgdata;
	void *dst = out ? sgdata : buf;

	memcpy(dst, src, nbytes);
}

void nscatterwalk_start(struct nscatter_walk *walk, struct scatterlist *sg)
{
	walk->sg = sg;

	BUG_ON(!sg->length);

	walk->offset = sg->offset;
}
EXPORT_SYMBOL_GPL(nscatterwalk_start);

void *nscatterwalk_map(struct nscatter_walk *walk, int out)
{
	return ncrypto_kmap(nscatterwalk_page(walk), out) +
	       offset_in_page(walk->offset);
}
EXPORT_SYMBOL_GPL(nscatterwalk_map);

static void nscatterwalk_pagedone(struct nscatter_walk *walk, int out,
				  unsigned int more)
{
	if (out) {
		struct page *page;

		page = sg_page(walk->sg) + ((walk->offset - 1) >> PAGE_SHIFT);
		flush_dcache_page(page);
	}

	if (more) {
		walk->offset += PAGE_SIZE - 1;
		walk->offset &= PAGE_MASK;
		if (walk->offset >= walk->sg->offset + walk->sg->length)
			nscatterwalk_start(walk, scatterwalk_sg_next(walk->sg));
	}
}

void nscatterwalk_done(struct nscatter_walk *walk, int out, int more)
{
	if (!offset_in_page(walk->offset) || !more)
		nscatterwalk_pagedone(walk, out, more);
}
EXPORT_SYMBOL_GPL(nscatterwalk_done);

void nscatterwalk_copychunks(void *buf, struct nscatter_walk *walk,
			     size_t nbytes, int out)
{
	for (;;) {
		unsigned int len_this_page = nscatterwalk_pagelen(walk);
		u8 *vaddr;

		if (len_this_page > nbytes)
			len_this_page = nbytes;

		vaddr = nscatterwalk_map(walk, out);
		memcpy_dir(buf, vaddr, len_this_page, out);
		nscatterwalk_unmap(vaddr, out);

		nscatterwalk_advance(walk, len_this_page);

		if (nbytes == len_this_page)
			break;

		buf += len_this_page;
		nbytes -= len_this_page;

		nscatterwalk_pagedone(walk, out, 1);
	}
}
EXPORT_SYMBOL_GPL(nscatterwalk_copychunks);

void nscatterwalk_map_and_copy(void *buf, struct scatterlist *sg,
			       unsigned int start, unsigned int nbytes, int out)
{
	struct nscatter_walk walk;
	unsigned int offset = 0;

	if (!nbytes)
		return;

	for (;;) {
		nscatterwalk_start(&walk, sg);

		if (start < offset + sg->length)
			break;

		offset += sg->length;
		sg = scatterwalk_sg_next(sg);
	}

	nscatterwalk_advance(&walk, start - offset);
	nscatterwalk_copychunks(buf, &walk, nbytes, out);
	nscatterwalk_done(&walk, out, 0);
}
EXPORT_SYMBOL_GPL(nscatterwalk_map_and_copy);
