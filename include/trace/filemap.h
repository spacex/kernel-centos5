#ifndef _TRACE_FILEMAP_H
#define _TRACE_FILEMAP_H

#include <linux/tracepoint.h>
#include <linux/fs.h>

DEFINE_TRACE(add_to_page_cache,
	TPPROTO(struct address_space *mapping, pgoff_t offset),
	TPARGS(mapping, offset));
DEFINE_TRACE(remove_from_page_cache,
	TPPROTO(struct address_space *mapping, pgoff_t offset),
	TPARGS(mapping, offset));

#endif
