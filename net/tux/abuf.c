/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * abuf.c: async buffer-sending
 */

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

char * get_abuf (tux_req_t *req, unsigned int max_size)
{
	threadinfo_t *ti = req->ti;
	struct page *page;
	char *buf;
	unsigned int offset;
	unsigned int left;

	if (req->abuf.page || req->abuf.buf || req->abuf.size)
		TUX_BUG();

	if (max_size > PAGE_SIZE)
		BUG();
	offset = ti->header_offset;
	if (offset > PAGE_SIZE)
		TUX_BUG();
	left = PAGE_SIZE - offset;
	if (!max_size)
		BUG();
	page = ti->header_cache;
	if ((left < max_size) || !page) {
		while (!(page = alloc_pages(GFP_KERNEL, 0))) {
			if (net_ratelimit())
				printk(KERN_WARNING "tux: OOM in get_abuf()!\n");
			current->state = TASK_UNINTERRUPTIBLE;
			schedule_timeout(1);
		}

		if (ti->header_cache)
			__free_page(ti->header_cache);
		ti->header_cache = page;
		ti->header_offset = 0;
		offset = 0;
	}
	buf = page_address(page) + offset;

	if (!page)
		BUG();
	req->abuf.page = page;
	req->abuf.buf = buf;
	req->abuf.size = 0;
	req->abuf.offset = offset;
	req->abuf.flags = 0;
	get_page(req->abuf.page);

	return buf;
}

static void do_send_abuf (tux_req_t *req, int cachemiss);

void send_abuf (tux_req_t *req, unsigned int size, unsigned long flags)
{
	threadinfo_t *ti = req->ti;

	Dprintk("send_abuf(req: %p, sock: %p): %p(%p), size:%d, off:%d, flags:%08lx\n", req, req->sock, req->abuf.page, req->abuf.buf, size, req->abuf.offset, flags);

	ti->header_offset += size;
	if (ti->header_offset > PAGE_SIZE)
		TUX_BUG();
	if (req->abuf.offset + req->abuf.size > PAGE_SIZE)
		TUX_BUG();

	req->abuf.flags = flags | MSG_NOSIGNAL;
	req->abuf.size = size;

	add_tux_atom(req, do_send_abuf);
}

static void do_send_abuf (tux_req_t *req, int cachemiss)
{
	int ret;

	if (req->magic != TUX_MAGIC)
		TUX_BUG();
	if (!req->sock)
		TUX_BUG();
	tcp_sk(req->sock->sk)->nonagle = 2;

repeat:
	Dprintk("do_send_abuf(%p,%d): %p(%p), size:%d, off:%d, flags:%08lx\n",
			req, cachemiss,
			req->abuf.page, req->abuf.buf, req->abuf.size,
			req->abuf.offset, req->abuf.flags);

	if (tux_zerocopy_header)
		ret = tcp_sendpage(req->sock, req->abuf.page,
			req->abuf.offset, req->abuf.size, req->abuf.flags);
	else {
		mm_segment_t oldmm;
		oldmm = get_fs(); set_fs(KERNEL_DS);
		ret = send_sync_buf(req, req->sock, req->abuf.buf,
			req->abuf.size, req->abuf.flags);
		set_fs(oldmm);
	}


	Dprintk("do_send_abuf: ret: %d\n", ret);
	if (!ret)
		TUX_BUG();

	if (ret < 0) {
		if (ret != -EAGAIN) {
			TDprintk("ret: %d, req->error = TUX_ERROR_CONN_CLOSE.\n", ret);
			req->error = TUX_ERROR_CONN_CLOSE;
			req->atom_idx = 0;
			req->in_file->f_pos = 0;
			__free_page(req->abuf.page);
			memset(&req->abuf, 0, sizeof(req->abuf));
			zap_request(req, cachemiss);
			return;
		}
		add_tux_atom(req, do_send_abuf);
		if (add_output_space_event(req, req->sock)) {
			del_tux_atom(req);
			goto repeat;
		}
		return;
	}

	req->abuf.buf += ret;
	req->abuf.offset += ret;
	req->abuf.size -= ret;

	if ((int)req->abuf.size < 0)
		TUX_BUG();
	if (req->abuf.size > 0)
		goto repeat;

	Dprintk("DONE do_send_abuf: %p(%p), size:%d, off:%d, flags:%08lx\n",
			req->abuf.page, req->abuf.buf, req->abuf.size,
			req->abuf.offset, req->abuf.flags);

	if (req->abuf.page)
		__free_page(req->abuf.page);
	else
		if (printk_ratelimit())
			WARN_ON(1);

	memset(&req->abuf, 0, sizeof(req->abuf));

	add_req_to_workqueue(req);
}

void __send_async_message (tux_req_t *req, const char *message,
				int status, unsigned int size, int push)
{
	unsigned int flags;
	char *buf;

	Dprintk("TUX: sending %d reply (%d bytes)!\n", status, size);
	Dprintk("request %p, reply: %s\n", req, message);
	if (!size)
		TUX_BUG();
	buf = get_abuf(req, size);
	memcpy(buf, message, size);

	req->status = status;
	flags = MSG_DONTWAIT;
	if (!push)
		flags |= MSG_MORE;
	send_abuf(req, size, flags);
	add_req_to_workqueue(req);
}
