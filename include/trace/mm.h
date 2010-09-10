#ifndef _TRACE_MM_H
#define _TRACE_MM_H

#undef TRACE_SYSTEM
#define TRACE_SYSTEM mm

#include <linux/tracepoint.h>
#include <linux/mm.h>

DEFINE_TRACE(mm_kernel_pagefault,
	TPPROTO(struct task_struct *task, unsigned long address, unsigned long ip),
	TPARGS(task, address, ip));

DEFINE_TRACE(mm_anon_fault,
	TPPROTO(struct mm_struct *mm, unsigned long address, struct page *page),
	TPARGS(mm, address, page));

DEFINE_TRACE(mm_anon_pgin,
	TPPROTO(struct mm_struct *mm, unsigned long address, struct page *page),
	TPARGS(mm, address, page));

DEFINE_TRACE(mm_anon_cow,
	TPPROTO(struct mm_struct *mm, unsigned long address, struct page *page),
	TPARGS(mm, address, page));

DEFINE_TRACE(mm_anon_userfree,
	TPPROTO(struct mm_struct *mm, unsigned long address, struct page *page),
	TPARGS(mm, address, page));

DEFINE_TRACE(mm_anon_unmap,
	TPPROTO(struct page *page, int success),
	TPARGS(page, success));

DEFINE_TRACE(mm_filemap_fault,
	TPPROTO(struct mm_struct *mm, unsigned long address, struct page *page),
	TPARGS(mm, address, page));

DEFINE_TRACE(mm_filemap_cow,
	TPPROTO(struct mm_struct *mm, unsigned long address, struct page *page),
	TPARGS(mm, address, page));

DEFINE_TRACE(mm_filemap_unmap,
	TPPROTO(struct page *page, int success),
	TPARGS(page, success));

DEFINE_TRACE(mm_filemap_userunmap,
	TPPROTO(struct mm_struct *mm, unsigned long address, struct page *page),
	TPARGS(mm, address, page));

DEFINE_TRACE(mm_pagereclaim_pgout,
	TPPROTO(struct page *page, int anon),
	TPARGS(page, anon));

DEFINE_TRACE(mm_pagereclaim_free,
	TPPROTO(struct page *page, int anon),
	TPARGS(page, anon));

DEFINE_TRACE(mm_pdflush_bgwriteout,
	TPPROTO(unsigned long count),
	TPARGS(count));

DEFINE_TRACE(mm_pdflush_kupdate,
	TPPROTO(unsigned long count),
	TPARGS(count));

DEFINE_TRACE(mm_page_allocation,
	TPPROTO(struct page *page, unsigned long free),
	TPARGS(page, free));

DEFINE_TRACE(mm_kswapd_runs,
	TPPROTO(unsigned long reclaimed),
	TPARGS(reclaimed));

DEFINE_TRACE(mm_directreclaim_reclaimall,
	TPPROTO(unsigned long priority),
	TPARGS(priority));

DEFINE_TRACE(mm_directreclaim_reclaimzone,
	TPPROTO(unsigned long reclaimed),
	TPARGS(reclaimed));

DEFINE_TRACE(mm_pagereclaim_shrinkzone,
	TPPROTO(unsigned long reclaimed),
	TPARGS(reclaimed));

DEFINE_TRACE(mm_pagereclaim_shrinkactive,
	TPPROTO(unsigned long scanned),
	TPARGS(scanned));

DEFINE_TRACE(mm_pagereclaim_shrinkactive_a2a,
	TPPROTO(struct page *page),
	TPARGS(page));

DEFINE_TRACE(mm_pagereclaim_shrinkactive_a2i,
	TPPROTO(struct page *page),
	TPARGS(page));

DEFINE_TRACE(mm_pagereclaim_shrinkinactive,
	TPPROTO(unsigned long reclaimed),
	TPARGS(reclaimed));

DEFINE_TRACE(mm_pagereclaim_shrinkinactive_i2a,
	TPPROTO(struct page *page),
	TPARGS(page));

DEFINE_TRACE(mm_pagereclaim_shrinkinactive_i2i,
	TPPROTO(struct page *page),
	TPARGS(page));

DEFINE_TRACE(mm_page_free,
	TPPROTO(struct page *page),
	TPARGS(page));

#undef TRACE_SYSTEM
#endif
