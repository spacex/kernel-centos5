/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * postpone.c: postpone/continue userspace requests
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

void postpone_request (tux_req_t *req)
{
	if (!req->usermode)
		TUX_BUG();
	INC_STAT(nr_postpone_pending);
	req->postponed = 1;
}

/*
 * Continue a postponed request. The request will show up in the
 * userspace queue and will be handled by the fast thread.
 * A request can only be postponed in a TUX process, but can be
 * continued from any process that has access to the socket file
 * descriptor.
 */
int continue_request (int fd)
{
	threadinfo_t *ti;
	struct socket *sock;
	tux_req_t *req;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock || !sock->sk)
		goto out;
	req = sock->sk->sk_user_data;

	err = -EINVAL;
	if (!req)
		goto out_put;
	ti = req->ti;
	if (!req->postponed)
		goto out_unlock_put;
	if (!req->usermode)
		TUX_BUG();

	req->postponed = 0;
	DEC_STAT(nr_postpone_pending);

	Dprintk("continuing postponed req %p.\n", req);
	add_req_to_workqueue(req);

out_unlock_put:
	err = 0;
out_put:
	fput(sock->file);
out:
	return err;
}

