/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * proto_http.c: HTTP application protocol support
 *
 * Right now we detect simple GET headers, anything more
 * subtle gets redirected to secondary server port.
 */

#include <net/tux.h>
#include "parser.h"

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

/*
 * Parse the HTTP message and put results into the request structure.
 * CISAPI extensions do not see the actual message buffer.
 *
 * Any perceived irregularity is honored with a redirect to the
 * secondary server - which in most cases should be Apache. So
 * if TUX gets confused by some strange request we fall back
 * to Apache to be RFC-correct.
 *
 * The parser is 'optimistic', ie. it's optimized for the case where
 * the whole message is available and correct. The parser is also
 * supposed to be 'robust', ie. it can be called multiple times with
 * an incomplete message, as new packets arrive.
 */

static inline int TOHEX (char c)
{
	switch (c) {
		case '0' ... '9': c -= '0'; break;
		case 'a' ... 'f': c -= 'a'-10; break;
		case 'A' ... 'F': c -= 'A'-10; break;
	default:
		c = -1;
	}
	return c;
}

/*
 * This function determines whether the client supports
 * gzip-type content-encoding.
 */
static int may_gzip (const char *str, int len)
{
	const char *tmp, *curr;
	int i;

	if (len <= 4)
		return 0;
	tmp = str;
	for (i = 0; i <= len-6; i++) {
		Dprintk("gzip-checking: {%s}\n", tmp);
		if (memcmp(tmp, " gzip", 5)) {
			tmp++;
			continue;
		}
		curr = tmp + 5;

		if (*curr == ',' || *curr == '\r')
			return 1;
		if (memcmp(curr, ";q=", 3))
			return 0;
		curr += 3;
		/*
		 * Every qvalue except explicitly zero is accepted.
		 * Zero values are "q=0.0", "q=0.00", "q=0.000".
		 * Parsing is optimized.
		 */
		if (*curr == '0') {
			curr += 2;
			if (*curr == '0') {
				curr++;
				if (*curr == ' ' || *curr == '\r')
					return 0;
				if (*curr == '0') {
					curr++;
					if (*curr == ' ' || *curr == '\r')
						return 0;
					if (*curr == '0') {
						curr++;
						if (*curr == ' ' ||
								*curr == '\r')
							return 0;
					}
				}
			}
		}
		return 1;
	}
	return 0;
}

/*
 * This function strips off 'strip_host_tail' number of hostname
 * components from the tail of the hostname.
 *
 * Eg. with a value of '1', the "somesite.hosting.com" hostname gets
 * transformed into the "somesite" string.
 */
static void strip_hostname(tux_req_t *req)
{
	int strip = strip_host_tail;
	int left = req->host_len;
	int component = 0;

	if (!strip || !left)
		return;

	while (--left) {
		if (req->host[left] != '.')
			continue;
		if (++component == strip)
			break;
	}
	if (!left)
		return;
	req->host[left] = 0;
	req->host_len = left;
}

static void http_lookup_vhost (tux_req_t *req, int cachemiss);
static void http_process_message (tux_req_t *req, int cachemiss);

int parse_http_message (tux_req_t *req, const int total_len)
{
	int hexhex = 0, hex_val_0 = 0, hex_val_1 = 0;
	const char *curr, *uri, *message;
	unsigned int objectname_len, left;
	unsigned int have_r = 0;
	char c;

	left = total_len;
	message = req->headers;
	Dprintk("parsing request:\n---\n%s\n---\n", message);
/*
 * RFC 2616, 5.1:
 *
 *	 Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
 */

	if (!total_len)
		TUX_BUG();

	curr = message;

#define GOTO_INCOMPLETE do { Dprintk("incomplete at %s:%d.\n", __FILE__, __LINE__); goto incomplete_message; } while (0)
#define GOTO_REDIR do { TDprintk("redirect secondary at %s:%d.\n", __FILE__, __LINE__); goto error; } while (0)

#define PRINT_MESSAGE_LEFT \
    Dprintk("message left (%d) at %s:%d:\n--->{%s}<---\n", left, __FILE__, __LINE__, curr)

	switch (*curr) {
		case 'G':
			if (PARSE_METHOD(req,curr,GET,left))
				break;
			GOTO_REDIR;

		case 'H':
			if (PARSE_METHOD(req,curr,HEAD,left))
				break;
			GOTO_REDIR;

		case 'P':
			if (PARSE_METHOD(req,curr,POST,left))
				break;
			if (PARSE_METHOD(req,curr,PUT,left))
				break;
			GOTO_REDIR;

		default:
			GOTO_REDIR;
	}

	req->method_str = message;
	req->method_len = curr-message-1;

	Dprintk("got method %d\n", req->method);

	PRINT_MESSAGE_LEFT;

	/*
	 * Ok, we got one of the methods we can handle, parse
	 * the URI:
	 */

	{
		// Do not allow leading "../" and intermediate "/../"
		int dotdot = 1;
		char *tmp = req->objectname;
		int slashcheck = 1;

		req->uri_str = uri = curr;

		for (;;) {
			c = get_c(curr,left);
			if (slashcheck) {
				if (c == '/')
					continue;
				slashcheck = 0;
			}

			PRINT_MESSAGE_LEFT;
			if (c == ' ' || ((c == '?') && (tux_ignore_query != 1)) || c == '\r' || c == '\n')
				break;
			if (c == '#')
				GOTO_REDIR;

			Dprintk("hexhex: %d.\n", hexhex);
			/*
			 * First handle HEX HEX encoding
			 */
			switch (hexhex) {
				case 0:
					if (c == '%') {
						hexhex = 1;
						goto continue_parsing;
					}
					break;
				case 1:
					hex_val_0 = TOHEX(c);
					if (hex_val_0 < 0)
						GOTO_REDIR;
					hexhex = 2;
					goto continue_parsing;
				case 2:
					hex_val_1 = TOHEX(c);
					if (hex_val_1 < 0)
						GOTO_REDIR;
					c = (hex_val_0 << 4) | hex_val_1;
					if (!c)
						GOTO_REDIR;
					hexhex = 0;
					break;
				default:
					TUX_BUG();
			}
			if (hexhex)
				TUX_BUG();

			switch (dotdot) {
				case 0:
					break;
				case 1:
					if (c == '.')
						dotdot = 2;
					else
						dotdot = 0;
					break;
				case 2:
					if (c == '.')
						dotdot = 3;
					else
						dotdot = 0;
					break;
				case 3:
					if (c == '/')
						GOTO_REDIR;
					else
						dotdot = 0;
					break;
				default:
					TUX_BUG();
			}
			if (!dotdot && (c == '/'))
				dotdot = 1;

			*(tmp++) = c;
continue_parsing:
			if (curr - uri >= MAX_OBJECTNAME_LEN)
				GOTO_REDIR;
		}
		PRINT_MESSAGE_LEFT;
		*tmp = 0;

		// handle trailing "/.."
		if (dotdot == 3)
			GOTO_REDIR;

		objectname_len = tmp - req->objectname;
		req->objectname_len = objectname_len;
	}
	Dprintk("got filename %s (%d)\n", req->objectname, req->objectname_len);

	PRINT_MESSAGE_LEFT;

	/*
	 * Parse optional query string. Copy until end-of-string or space.
	 */
	if (c == '?') {
		int query_len;
		const char *query;

		req->query_str = query = curr;

		for (;;) {
			c = get_c(curr,left);
			if (c == ' ')
				break;
			if (c == '#')
				GOTO_REDIR;
		}
		if (unlikely(tux_ignore_query == 2))
			req->query_str = NULL;
		else {
			query_len = curr-query-1;
			req->query_len = query_len;
		}
	}
	if (req->query_len)
		Dprintk("got query string %s (%d)\n", req->query_str, req->query_len);
	req->uri_len = curr-uri-1;
	if (!req->uri_len)
		GOTO_REDIR;
	Dprintk("got URI %s (%d)\n", req->uri_str, req->uri_len);

	PRINT_MESSAGE_LEFT;
	/*
	 * Parse the HTTP version field:
	 */
	req->version_str = curr;
	if (!PARSE_TOKEN(curr,"HTTP/1.",left))
		GOTO_REDIR;

	switch (get_c(curr,left)) {
		case '0':
			req->version = HTTP_1_0;
			break;
		case '1':
			req->version = HTTP_1_1;
			break;
		default:
			GOTO_REDIR;
	}
	/*
	 * We default to keepalive in the HTTP/1.1 case and default
	 * to non-keepalive in the HTTP/1.0 case. If max_keepalives
	 * is 0 then we do no keepalives.
	 */
	clear_keepalive(req);
	if (tux_max_keepalives && (req->version == HTTP_1_1))
		req->keep_alive = 1;
	req->version_len = curr - req->version_str;

	if (get_c(curr,left) != '\r')
		GOTO_REDIR;
	if (get_c(curr,left) != '\n')
		GOTO_REDIR;

	Dprintk("got version %d [%d]\n", req->version, req->version_len);
	PRINT_MESSAGE_LEFT;

	/*
	 * Now parse (optional) request header fields:
	 */
	for (;;) {
		char c;

		c = get_c(curr,left);
		switch (c) {
		case '\r':
			if (have_r)
				GOTO_REDIR;
			have_r = 1;
			continue;
		case '\n':
			if (!have_r)
				GOTO_REDIR;
			goto out;
		default:
			if (have_r)
				GOTO_REDIR;
		}

#define PARSE_STR_FIELD(char,field,str,len)				\
	if (PARSE_TOKEN(curr,field,left)) {				\
		req->str = curr;					\
		SKIP_LINE(curr,left);					\
		req->len = curr - req->str - 2;				\
		Dprintk(char field "field: %s.\n", req->str);		\
		break;							\
	}

#define ALLOW_UNKNOWN_FIELDS 1
#ifdef ALLOW_UNKNOWN_FIELDS
# define UNKNOWN_FIELD { SKIP_LINE(curr,left); break; }
#else
# define UNKNOWN_FIELD GOTO_REDIR
#endif

		switch (c) {
		case 'A':
			PARSE_STR_FIELD("A","ccept: ",
				accept_str,accept_len);
			if (PARSE_TOKEN(curr,"ccept-Encoding: ",left)) {
				const char *str = curr-1;

				req->accept_encoding_str = curr;
				SKIP_LINE(curr,left);
				req->accept_encoding_len = curr - req->accept_encoding_str - 2;
				Dprintk("Accept-Encoding field: {%s}.\n", str);

				if (tux_compression && may_gzip(str,curr-str)) {
					Dprintk("client accepts gzip!.\n");
					req->may_send_gzip = 1;
				}
				break;
			}
			PARSE_STR_FIELD("A","ccept-Charset: ",
				accept_charset_str,accept_charset_len);
			PARSE_STR_FIELD("A","ccept-Language: ",
				accept_language_str,accept_language_len);
			UNKNOWN_FIELD;

		case 'C':
			if (PARSE_TOKEN(curr,"onnection: ",left)) {
next_token:
			switch (get_c(curr,left)) {
			case 'K':
				if (!PARSE_TOKEN(curr,"eep-Alive",left))
					GOTO_REDIR;
				if (tux_max_keepalives)
					req->keep_alive = 1;
				break;

			case 'C':
			case 'c':
				if (!PARSE_TOKEN(curr,"lose",left))
					GOTO_REDIR;
				clear_keepalive(req);
				break;

			case 'k':
				if (!PARSE_TOKEN(curr,"eep-alive",left))
					GOTO_REDIR;
				if (tux_max_keepalives)
					req->keep_alive = 1;
				break;
			case 'T':
				if (PARSE_TOKEN(curr,"E",left))
					break;
				if (PARSE_TOKEN(curr,"railers",left))
					break;
				if (PARSE_TOKEN(curr,"ransfer-Encoding",left))
					break;
				GOTO_REDIR;
			case 'P':
				if (PARSE_TOKEN(curr,"roxy-Authenticate",left))
					break;
				if (PARSE_TOKEN(curr,"roxy-Authorization",left))
					break;
				GOTO_REDIR;
			case 'U':
				if (!PARSE_TOKEN(curr,"pgrade",left))
					GOTO_REDIR;
				break;
			case ' ':
				PRINT_MESSAGE_LEFT;
				goto next_token;
			case ',':
				PRINT_MESSAGE_LEFT;
				goto next_token;
			default:
				GOTO_REDIR;
			}
			PRINT_MESSAGE_LEFT;
			if (*curr != '\r')
				goto next_token;
			// allow other tokens.
			SKIP_LINE(curr,left);
			break;
			}

			PARSE_STR_FIELD("C","ookie: ",
				cookies_str,cookies_len);
			PARSE_STR_FIELD("C","ontent-Type: ",
				content_type_str,content_type_len);

			if (PARSE_TOKEN(curr,"ontent-Length: ",left) ||
			    PARSE_TOKEN(curr,"ontent-length: ",left)) {
				const char *tmp;
				req->contentlen_str = curr;
				SKIP_LINE(curr,left);
				req->contentlen_len = curr - req->contentlen_str - 2;
				if (req->contentlen_len) {
					tmp = req->contentlen_str;
					req->content_len = simple_strtoul(tmp, NULL, 10);
				}
				Dprintk("Content-Length field: %s [%d].\n", req->contentlen_str, req->contentlen_len);
				Dprintk("Content-Length value: %d.\n", req->content_len);
				break;
			}
			PARSE_STR_FIELD("C","ache-Control: ",
				cache_control_str,cache_control_len);
			UNKNOWN_FIELD;

		case 'H':
			if (PARSE_TOKEN(curr,"ost: ",left)) {
				const char *tmp = curr;
				char *tmp2 = req->host;

				/*
				 * canonize the hostname:
				 *
				 * 1) strip off preceding 'www.' variants,
				 * 2) transform it to lowercase.
				 * 3) strip trailing dots
				 * 4) potentially strip off tail
				 */

#define is_w(n) ((curr[n] == 'w') || (curr[n] == 'W'))

				if ((left > 4) && is_w(0) && is_w(1) &&
						is_w(2) && curr[3] == '.') {
					curr += 4;
					left -= 4;
					tmp = curr;
				}

				COPY_LINE_TOLOWER(curr, tmp2, left, req->host+MAX_HOST_LEN-2);
				req->host_len = curr - tmp - 2;
				while (req->host[req->host_len] == '.') {
					if (!req->host_len)
						break;
					req->host_len--;
				}
				req->host[req->host_len] = 0;
				if (strip_host_tail)
					strip_hostname(req);
				Dprintk("Host field: %s [%d].\n", req->host, req->host_len);
				break;
			}
			UNKNOWN_FIELD;

		case 'I':
			PARSE_STR_FIELD("I","f-None-Match: ",
				if_none_match_str,if_none_match_len);
			PARSE_STR_FIELD("I","f-Modified-Since: ",
				if_modified_since_str,if_modified_since_len);
			PARSE_STR_FIELD("I","f-Range: ",
				if_range_str,if_range_len);
			UNKNOWN_FIELD;

		case 'N':
			PARSE_STR_FIELD("N","egotiate: ",
				negotiate_str,negotiate_len);
			UNKNOWN_FIELD;

		case 'P':
			PARSE_STR_FIELD("P","ragma: ",
				pragma_str,pragma_len);
			UNKNOWN_FIELD;

		case 'R':

			PARSE_STR_FIELD("R","eferer: ",
				referer_str,referer_len);
			if (!PARSE_TOKEN(curr,"ange: bytes=",left))
				UNKNOWN_FIELD;
		{
			const char *tmp = curr;
			char *tmp2 = (char *)curr;
			unsigned int offset_start = 0, offset_end = 0;

			if (*tmp2 != '-')
				offset_start = simple_strtoul(tmp2, &tmp2, 10);
			if (*tmp2 == '-') {
				tmp2++;
				if (*tmp2 != '\r')
					offset_end = simple_strtoul(tmp2, &tmp2, 10) +1;
			}
			curr = tmp2;
			left -= tmp2-tmp;

			req->offset_start = offset_start;
			req->offset_end = offset_end;

			SKIP_LINE(curr,left);
			Dprintk("Range field: %s [%d] (%d-%d).\n", tmp, curr-tmp, offset_start, offset_end);
			break;
		}

		case 'U':
			PARSE_STR_FIELD("U","ser-Agent: ",
				user_agent_str,user_agent_len);
			UNKNOWN_FIELD;

		default:
			UNKNOWN_FIELD;
		}
		PRINT_MESSAGE_LEFT;
	}
out:
	/*
	 * POST data.
	 */
	if ((req->method == METHOD_POST) && req->content_len) {
		PRINT_MESSAGE_LEFT;
		if (curr + req->content_len > message + total_len)
			GOTO_INCOMPLETE;
		req->post_data_str = curr;
		req->post_data_len = req->content_len;
		curr += req->content_len;
		left -= req->content_len;
		Dprintk("POST-ed data: {%s}\n", req->post_data_str);
	}

	switch (req->method) {
		default:
			GOTO_REDIR;
		case METHOD_GET:
		case METHOD_HEAD:
		case METHOD_POST:
		case METHOD_PUT:
			;
	}

#define TUX_SCHEME "http://"
#define TUX_SCHEME_LEN (sizeof(TUX_SCHEME)-1)

	if (!memcmp(req->objectname, TUX_SCHEME, TUX_SCHEME_LEN)) {

		/* http://user:password@host:port/object */

		const char *head, *tail, *end, *host, *port;
		int host_len, objectname_len;

		head = req->objectname + TUX_SCHEME_LEN;
		end = req->objectname + req->objectname_len;

		tail = memchr(head, '/', end - head);
		if (!tail)
			GOTO_REDIR;
		host = memchr(head, '@', tail - head);
		if (!host)
			host = head;
		else
			host++;
		if (!*host)
			GOTO_REDIR;
		port = memchr(host, ':', tail - host);
		if (port)
			host_len = port - host;
		else
			host_len = tail - host;
		if (host_len >= MAX_HOST_LEN)
			GOTO_REDIR;
		memcpy(req->host, host, host_len);
		req->host_len = host_len;
		req->host[host_len] = 0;

		if (*tail != '/')
			TUX_BUG();

		req->uri_str = tail;
		req->uri_len = end - tail;

		tail++;
		while (*tail == '/')
			tail++;

		objectname_len = end - tail;
		memcpy(req->objectname, tail, objectname_len);
		req->objectname_len = objectname_len;
		req->objectname[objectname_len] = 0;
	} else
		if (req->uri_str[0] != '/')
			GOTO_REDIR;

	if ((req->version == HTTP_1_1) && !req->host_len)
		GOTO_REDIR;
	if (req->objectname[0] == '/')
		GOTO_REDIR;
	/*
	 * Lets make sure nobody plays games with the host
	 * header in a virtual hosting environment:
	 */
	if (req->virtual && req->host_len) {
		if (memchr(req->host, '/', req->host_len))
			GOTO_REDIR;
		if (req->host[0] == '.') {
			if (req->host_len == 1)
				GOTO_REDIR;
			if ((req->host_len == 2) && (req->host[0] == '.'))
				GOTO_REDIR;
		}
	}
	/*
	 * From this point on the request is for the main TUX engine:
	 */
	Dprintk("ok, request accepted.\n");

	if (req->keep_alive) {
		req->nr_keepalives++;
		if (req->nr_keepalives == -1)
			req->nr_keepalives--;
		INC_STAT(nr_keepalive_reqs);
	} else
		INC_STAT(nr_nonkeepalive_reqs);
	INC_STAT(keepalive_hist[req->nr_keepalives]);

	PRINT_MESSAGE_LEFT;
	req->parsed_len = curr-message;
	if (req->dentry)
		TUX_BUG();
	req->virtual = tux_virtual_server;
	if (req->virtual)
		add_tux_atom(req, http_lookup_vhost);
	else {
		req->docroot_dentry = dget(req->proto->main_docroot.dentry);
		req->docroot_mnt = mntget(req->proto->main_docroot.mnt);
		add_tux_atom(req, http_process_message);
	}

	return req->parsed_len;

incomplete_message:
	Dprintk("incomplete message!\n");
	PRINT_MESSAGE_LEFT;

	return 0;

error:
	if (total_len > 0)
		req->parsed_len = total_len;
	else
		req->parsed_len = 0;
	PRINT_MESSAGE_LEFT;
	if (tux_TDprintk) {
		TDprintk("redirecting message to secondary server.\n");
		print_req(req);
	}
	return -1;
}

static int lookup_url (tux_req_t *req, const unsigned int flag)
{
	/*
	 * -1 : no previous checks made
	 *  0 : previous check failed, do not check farther,
	 *  1 : previous check successed, check farther
	 */
	int not_modified = -1;
	int perm = 0;
	struct dentry *dentry = NULL;
	struct vfsmount *mnt = NULL;
	struct inode *inode;
	const char *filename;

	/*
	 * Do not do any etag or last_modified header checking
	 * if both unset.
	 */
	if (!tux_generate_etags && !tux_generate_last_mod)
		not_modified = 0;

repeat_lookup:
	if (req->dentry)
		TUX_BUG();

	filename = req->objectname;
	Dprintk("will look up {%s} (%d)\n", filename, req->objectname_len);
	Dprintk("current->fsuid: %d, current->fsgid: %d, ngroups: %d\n",
		current->fsuid, current->fsgid, current->group_info->ngroups);

	dentry = tux_lookup(req, filename, flag, &mnt);

#define INDEX "/index.html"

	if (!dentry || IS_ERR(dentry)) {
		if (PTR_ERR(dentry) == -EWOULDBLOCKIO)
			goto cachemiss;

		if (tux_http_dir_indexing && (req->lookup_dir == 1)) {
			// undo the index.html appending:
			req->objectname_len -= sizeof(INDEX)-1;
			req->objectname[req->objectname_len] = 0;
			req->lookup_dir = 2;
			goto repeat_lookup;
		}
		if (!req->lookup_404) {
			int len = strlen(tux_404_page);
			memcpy(req->objectname, tux_404_page, len);
			req->objectname[len] = 0;
			req->objectname_len = len;
			req->lookup_404 = 1;
			req->status = 404;
			goto repeat_lookup;
		}
		TDprintk("abort - lookup error.\n");
		goto abort;
	}

	Dprintk("SUCCESS, looked up {%s} == dentry %p (inode %p, count %d.)\n", filename, dentry, dentry->d_inode, atomic_read(&dentry->d_count));
	inode = dentry->d_inode;

	/*
	 * At this point we have a real, non-negative dentry.
	 */
	perm = tux_permission(inode);

	if ((perm < 0) || (!S_ISDIR(dentry->d_inode->i_mode)
				&& !S_ISREG(dentry->d_inode->i_mode))) {
		Dprintk("FAILED trusted dentry %p permission %d.\n", dentry, perm);
		req->status = 403;
		goto abort;
	}
	if ((req->lookup_dir != 2) && S_ISDIR(dentry->d_inode->i_mode)) {
		if (req->lookup_dir || (req->objectname_len +
				 sizeof(INDEX) >= MAX_OBJECTNAME_LEN)) {
			req->status = 403;
			goto abort;
		}
		if (req->objectname_len && (req->objectname[req->objectname_len-1] != '/')) {
			dput(dentry);
			mntput(mnt);
			req->lookup_dir = 0;
			return 2;
		}
		memcpy(req->objectname + req->objectname_len,
						INDEX, sizeof(INDEX));
		req->objectname_len += sizeof(INDEX)-1;
		req->lookup_dir = 1;
		dput(dentry);
		mntput(mnt);
		mnt = NULL;
		dentry = NULL;
		goto repeat_lookup;
	}
	if (tux_max_object_size && (inode->i_size > tux_max_object_size)) {
		TDprintk("too big object, %Ld bytes.\n", inode->i_size);
		req->status = 403;
		goto abort;
	}
	req->total_file_len = inode->i_size;
	req->mtime = inode->i_mtime.tv_sec;

	{
		loff_t num = req->total_file_len;
		int nr_digits = 0;
		unsigned long modulo;
		char * etag_p = req->etag;
		char digits [30];

		do {
			modulo = do_div(num, 10);
			digits[nr_digits++] = '0' + modulo;
		} while (num);

		req->lendigits = nr_digits;
		req->etaglen = nr_digits;

		while (nr_digits)
			*etag_p++ = digits[--nr_digits];

		*etag_p++ = '-';
		num = req->mtime;
		nr_digits = 0;

		do {
			digits[nr_digits++] = 'a' + num % 16;
				num /= 16;
		} while (num);
		req->etaglen += nr_digits+1;
		while (nr_digits)
			*etag_p++ = digits[--nr_digits];
		*etag_p = 0;
	}

	if ((req->if_none_match_len >= req->etaglen) && (abs(not_modified) == 1)) {

		char * etag_p = req->etag;
		const char * match_p = req->if_none_match_str;
		int pos = req->etaglen - 1;
		int matchpos = req->etaglen - 1;

		do {
			while (etag_p[matchpos--] == match_p[pos--])
				if (matchpos < 0)
					break;
			if (matchpos < 0)
				pos = req->if_none_match_len;
			else {
				if (match_p[pos+1] == ',')
					pos += req->etaglen + 2;
				else
					pos += req->etaglen-matchpos;
				matchpos = req->etaglen - 1;
			}
		} while (pos < req->if_none_match_len);

		if (matchpos < 0) {
			not_modified = 1;
			TDprintk("Etag matched.\n");
		} else
			not_modified = 0;
	}

        if ((req->if_modified_since_len >= 24) && (abs(not_modified) == 1)) {
                if (parse_time(req->if_modified_since_str, req->if_modified_since_len) >= req->mtime ) {
			not_modified = 1;
                        Dprintk("Last-Modified matched.\n");
                } else
			not_modified = 0;
        }

	if (not_modified == 1) {
		req->status = 304;
		goto abort;
	}

	Dprintk("looked up cached dentry %p, (count %d.)\n", dentry, dentry ? atomic_read(&dentry->d_count) : -1 );

	url_hist_hit(req->total_file_len);
out:
	install_req_dentry(req, dentry, mnt);
	req->lookup_dir = 0;
	return 0;

cachemiss:
	return 1;

abort:
	if (dentry) {
		if (!IS_ERR(dentry))
			dput(dentry);
		dentry = NULL;
	}
	if (mnt) {
		if (!IS_ERR(mnt))
			mntput(mnt);
		mnt = NULL;
	}
#ifdef CONFIG_TUX_DEBUG
	if (!not_modified) {
		TDprintk("req %p has lookup errors!\n", req);
		if (tux_TDprintk)
			print_req(req);
	}
#endif
	req_err(req);
	goto out;
}

int handle_gzip_req (tux_req_t *req, unsigned int flags)
{
	char *curr = req->objectname + req->objectname_len;
	struct dentry *dentry;
	struct vfsmount *mnt = NULL;
	struct inode *inode, *orig_inode;
	loff_t size, orig_size;

	*curr++ = '.';
	*curr++ = 'g';
	*curr++ = 'z';
	*curr++ = 0;
	req->objectname_len += 3;

	dentry = tux_lookup(req, req->objectname, flags, &mnt);

	req->objectname_len -= 3;
	req->objectname[req->objectname_len] = 0;

	if (!dentry)
		return 0;
	if (IS_ERR(dentry)) {
		if (PTR_ERR(dentry) == -EWOULDBLOCKIO) {
			release_req_dentry(req);
			return 1;
		}
		return 0;
	}

	inode = dentry->d_inode;
	size = inode->i_size;
	orig_inode = req->dentry->d_inode;
	orig_size = orig_inode->i_size;

	if (!tux_permission(inode)
			&& (size < orig_size)
			&& (inode->i_mtime.tv_sec >= orig_inode->i_mtime.tv_sec)) {

		release_req_dentry(req);
		install_req_dentry(req, dentry, mnt);
		req->total_file_len = req->output_len = size;
		Dprintk("content WILL be gzipped!\n");
		req->content_gzipped = 1;
	} else {
		dput(dentry);
		mntput(mnt);
	}

	return 0;
}

static DEFINE_SPINLOCK(mimetypes_lock);

static LIST_HEAD(mimetypes_head);

static mimetype_t default_mimetype = { .type = "text/plain", .type_len = 10, .expire_str = "", .expire_str_len = 0 };

#define MAX_MIMETYPE_LEN 128
#define MAX_CACHE_CONTROL_AGE_LEN 30

void add_mimetype (char *new_ext, char *new_type, char *new_expire)
{
	int type_len = strlen(new_type);
	int ext_len = strlen(new_ext);
	int expire_len = strlen(new_expire);
	mimetype_t *mime;
	char *ext, *type, *expire;

        if (type_len > MAX_MIMETYPE_LEN)
                type_len = MAX_MIMETYPE_LEN;
        if (ext_len > MAX_URI_LEN)
                ext_len = MAX_URI_LEN;
        if (expire_len > MAX_CACHE_CONTROL_AGE_LEN)
                expire_len = MAX_CACHE_CONTROL_AGE_LEN;

	mime = tux_kmalloc(sizeof(*mime));
	memset(mime, 0, sizeof(*mime));
	ext = tux_kmalloc(ext_len + 1);
	type = tux_kmalloc(type_len + 1);
	expire = tux_kmalloc(expire_len + 1);

	strncpy(ext, new_ext, ext_len);
	strncpy(type, new_type, type_len);
	strncpy(expire, new_expire, expire_len);

	// in case one of the above parameters was too long :

	ext[ext_len] = '\0';
	type[type_len] = '\0';
	expire[expire_len] = '\0';

	mime->ext = ext;
	mime->ext_len = ext_len;

	mime->type = type;
	mime->type_len = type_len;

	mime->expire_str = expire;
	mime->expire_str_len = expire_len;

	mime->special = NORMAL_MIME_TYPE;
	if (!strcmp(type, "TUX/redirect"))
		mime->special = MIME_TYPE_REDIRECT;
	if (!strcmp(type, "TUX/CGI"))
		mime->special = MIME_TYPE_CGI;
	if (!strcmp(type, "TUX/module"))
		mime->special = MIME_TYPE_MODULE;

	spin_lock(&mimetypes_lock);
	list_add(&mime->list, &mimetypes_head);
	spin_unlock(&mimetypes_lock);
}

static inline int ext_matches (char *file, int len, char *ext, int extlen)
{
	int i;
	char *tmp = file + len-1;
	char *tmp2 = ext + extlen-1;

	if (len < extlen)
		return 0;

	for (i = 0; i < extlen; i++) {
		if (*tmp != *tmp2)
			return 0;
		tmp--;
		tmp2--;
	}
	return 1;
}

/*
 * Overhead is not a problem, we cache the MIME type
 * in the dentry.
 */
static mimetype_t * lookup_mimetype (tux_req_t *req)
{
	char *objectname = req->objectname;
	int len = req->objectname_len;
	mimetype_t *mime = NULL;
	struct list_head *head, *tmp, *tmp1, *tmp2, *tmp3;

	if (!memchr(objectname, '.', len))
		goto out;

	spin_lock(&mimetypes_lock);
	head = &mimetypes_head;
	tmp = head->next;

	while (tmp != head) {
		mime = list_entry(tmp, mimetype_t, list);
		if (ext_matches(objectname, len, mime->ext, mime->ext_len)) {
			/*
			 * Percolate often-used mimetypes up:
			 */
			if (tmp->prev != &mimetypes_head) {
				tmp1 = tmp;
				tmp2 = tmp->prev;
				tmp3 = tmp->prev->prev;
				list_del(tmp1);
				list_del(tmp2);
				list_add(tmp, tmp3);
				list_add(tmp2, tmp);
			}
			break;
		} else
			mime = NULL;
		tmp = tmp->next;
	}
	spin_unlock(&mimetypes_lock);

out:
	if (!mime)
		mime = &default_mimetype;
	return mime;
}

void free_mimetypes (void)
{
	struct list_head *head, *tmp, *next;
	mimetype_t *mime;

	spin_lock(&mimetypes_lock);
	head = &mimetypes_head;
	tmp = head->next;

	while (tmp != head) {
		next = tmp->next;
		mime = list_entry(tmp, mimetype_t, list);
		list_del(tmp);

		kfree(mime->ext);
		mime->ext = NULL;
		kfree(mime->type);
		mime->type = NULL;
		kfree(mime);

		tmp = next;
	}
	spin_unlock(&mimetypes_lock);
}

/*
 * Various constant HTTP responses:
 */

static const char forbidden[] =
	"HTTP/1.1 403 Forbidden\r\n"
	"Connection: Keep-Alive\r\n" \
	"Content-Length: 24\r\n\r\n"
	"<HTML> Forbidden </HTML>";

static const char not_found[] =
	"HTTP/1.1 404 Not Found\r\n"
	"Connection: Keep-Alive\r\n" \
	"Content-Length: 29\r\n\r\n"
	"<HTML> Page Not Found </HTML>";

#define NOTMODIFIED_1 \
	"HTTP/1.1 304 Not Modified\r\n" \
	"Connection: Keep-Alive\r\n" \
	"Date: "

#define NOTMODIFIED_1_LEN (sizeof(NOTMODIFIED_1) - 1)

#define NOTMODIFIED_2 \
	"\r\nETag: \""

#define NOTMODIFIED_2_LEN (sizeof(NOTMODIFIED_2) - 1)

#define NOTMODIFIED_3 \
	"\"\r\n\r\n"

#define NOTMODIFIED_3_LEN (sizeof(NOTMODIFIED_3) - 1)

#define REDIRECT_1 \
	"HTTP/1.1 301 Moved Permanently\r\n" \
	"Location: http://"

#define REDIRECT_1_LEN (sizeof(REDIRECT_1) - 1)

#define REDIRECT_2 \
	"/\r\nContent-Length: 36\r\n" \
	"Connection: Keep-Alive\r\n" \
	"Content-Type: text/html\r\n\r\n" \
	"<HTML> 301 Moved Permanently </HTML>"

#define REDIRECT_2_LEN (sizeof(REDIRECT_2) - 1)

void send_async_err_forbidden (tux_req_t *req)
{
	send_async_message(req, forbidden, 403, 1);
}

void send_async_err_not_found (tux_req_t *req)
{
	send_async_message(req, not_found, 404, 1);
}

static void send_ret_notmodified (tux_req_t *req)
{
	char *buf;
	int size;

	size = NOTMODIFIED_1_LEN + DATE_LEN - 1 + NOTMODIFIED_2_LEN + req->etaglen + NOTMODIFIED_3_LEN;
	buf = get_abuf(req, size);
	memcpy(buf, NOTMODIFIED_1, NOTMODIFIED_1_LEN);
	buf += NOTMODIFIED_1_LEN;
	memcpy(buf, tux_date, DATE_LEN-1);
	buf += DATE_LEN-1;
	memcpy(buf, NOTMODIFIED_2, NOTMODIFIED_2_LEN);
	buf += NOTMODIFIED_2_LEN;
	memcpy(buf, &req->etag, req->etaglen);
	buf += req->etaglen;
	memcpy(buf, NOTMODIFIED_3, NOTMODIFIED_3_LEN);
	buf += NOTMODIFIED_3_LEN;

	req->status = 304;
	send_abuf(req, size, MSG_DONTWAIT);
	add_req_to_workqueue(req);
}

static void send_ret_redirect (tux_req_t *req, int cachemiss)
{
	char *buf;
	unsigned int size;
	unsigned int uts_len = 0;

	size = REDIRECT_1_LEN;
	if (req->host_len)
		size += req->host_len;
	else {
		down_read(&uts_sem);
		uts_len = strlen(system_utsname.nodename);
		size += uts_len;
	}
	if (req->objectname[0] != '/')
		size++;
	size += req->objectname_len;
	size += REDIRECT_2_LEN;

	if (size > PAGE_SIZE) {
		req->error = TUX_ERROR_CONN_CLOSE;
		zap_request(req, cachemiss);
		return;
	}

	buf = get_abuf(req, size);

	memcpy(buf, REDIRECT_1, REDIRECT_1_LEN);
	buf += REDIRECT_1_LEN;

	Dprintk("req %p, host: %s, host_len: %d.\n", req, req->host, req->host_len);
	if (req->host_len) {
		memcpy(buf, req->host, req->host_len);
		buf += req->host_len;
	} else {
		memcpy(buf, system_utsname.nodename, uts_len);
		up_read(&uts_sem);
		buf += uts_len;
	}
	if (req->objectname[0] != '/') {
		buf[0] = '/';
		buf++;
	}

	memcpy(buf, req->objectname, req->objectname_len);
	buf += req->objectname_len;

	memcpy(buf, REDIRECT_2, REDIRECT_2_LEN);
	buf += REDIRECT_2_LEN;

	req->status = 301;
	send_abuf(req, size, MSG_DONTWAIT);
	add_req_to_workqueue(req);
}

static void http_got_request (tux_req_t *req)
{
	req->host[0] = 0;
	req->host_len = 0;
	add_tux_atom(req, parse_request);
	add_req_to_workqueue(req);
}


tux_attribute_t * lookup_tux_attribute (tux_req_t *req)
{
	tux_attribute_t *attr;
	struct inode *inode;
	mimetype_t *mime;

	attr = tux_kmalloc(sizeof(*attr));
	memset(attr, 0, sizeof(*attr));

	mime = lookup_mimetype(req);

	inode = req->dentry->d_inode;
	if (!inode->i_uid && !inode->i_gid) {
		if (mime->special == MIME_TYPE_MODULE) {
			attr->tcapi = lookup_tuxmodule(req->objectname);
			if (!attr->tcapi) {
				req_err(req);
				mime = &default_mimetype;
			}
		}
	} else {
		if (mime->special && (mime->special != MIME_TYPE_REDIRECT))
			mime = &default_mimetype;
	}
	attr->mime = mime;

	return attr;
}

static void handle_range(tux_req_t *req)
{
	if (req->if_range_len) {
		time_t range_time;

		range_time = parse_time(req->if_range_str, req->if_range_len);

		/*
		 * If the file is newer then we send the whole file.
		 */
		if (range_time < req->mtime )
			goto out_no_range;
	}
	/* if no offset_end was specified then default to 'end of file': */
	if (!req->offset_end)
		req->offset_end = req->total_file_len;
	/*
	 * Sanity checks:
	 *
	 *  - is the range between 0...file_len-1 ?
	 *  - is offset_end after offset_start?
	 *
	 * (note that offset_end is higher by 1)
	 */
	if ((req->offset_end > req->total_file_len) ||
			(req->offset_start >= req->total_file_len) ||
			(req->offset_end <= req->offset_start))
		goto out_no_range;
	/*
	 * If the range is 0...file_len-1 then send the whole file:
	 */
	if (!req->offset_start && (req->offset_end == req->total_file_len))
		goto out_no_range;

	/* ok, the range is valid, use it: */

	req->output_len = req->offset_end - req->offset_start;
	req->in_file->f_pos = req->offset_start;
	return;

out_no_range:
	req->offset_start = 0;
	req->offset_end = 0;
}

static void http_pre_header (tux_req_t *req, int push);
static void http_post_header (tux_req_t *req, int cachemiss);
static void http_send_body (tux_req_t *req, int cachemiss);

#define DIRLIST_HEAD_1 "\
<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\
<HTML><HEAD><TITLE>Index of %s</TITLE></HEAD><BODY>\
<H1>Index of %s </H1><PRE><HR>\n%s"

#define DIRLIST_HEAD_2 "\
<IMG SRC=\"/icons/back.gif\"ALT=\"[DIR]\"> <A HREF=\"../\">Parent Directory</A>\n"

#define DIRLIST_HEAD_SIZE (sizeof(DIRLIST_HEAD_1) + sizeof(DIRLIST_HEAD_2))

static void http_dirlist_head (tux_req_t *req, int cachemiss)
{
	char *buf1, *buf2, *path;
	int len;

	buf1 = (char *)__get_free_page(GFP_KERNEL);
	buf2 = (char *)__get_free_page(GFP_KERNEL);
	if (!buf1 || !buf2)
		goto out;
	path = tux_print_path(req, req->dentry, req->mnt, buf1, PAGE_SIZE);
	if (path[0] == '/' && path[1] == '/' && !path[3])
		path = "/";
	if (2*strlen(path) + DIRLIST_HEAD_SIZE >= PAGE_SIZE)
		goto out;
	len = sprintf(buf2, DIRLIST_HEAD_1, path, path, req->dentry == req->docroot_dentry ? "" : DIRLIST_HEAD_2);
	__send_async_message(req, buf2, 200, len, 0);

out:
	if (buf1)
		free_page((unsigned long)buf1);
	if (buf2)
		free_page((unsigned long)buf2);
}

#define DIRLIST_TAIL "\
</PRE><HR><ADDRESS><IMG SRC=\"/icons/tuxlogo.gif\"ALIGN=\"MIDDLE\"ALT=\"[TUX]\">Powered by Linux/TUX 3.0</ADDRESS>\n</BODY></HTML>"

static void http_dirlist_tail (tux_req_t *req, int cachemiss)
{
	__send_async_message(req, DIRLIST_TAIL, 200, sizeof(DIRLIST_TAIL)-1, 1);
}

static void http_dirlist (tux_req_t *req, int cachemiss)
{
	int head = (req->method == METHOD_HEAD);

	req->lookup_dir = 3;
	clear_keepalive(req);
	if (!head) {
		add_tux_atom(req, http_dirlist_tail);
		add_tux_atom(req, list_directory);
		add_tux_atom(req, http_dirlist_head);
	}
	http_pre_header(req, head);
	add_req_to_workqueue(req);
}

static char *host_path_hash(tux_req_t *req, char *tmp)
{
	if (req->host_len < 2)
		return NULL;

	switch (mass_hosting_hash) {
		default:
		case 0:
			return req->host;
		case 1:

			// www.ABCDEFG.com => A/ABCDEFG.com

			tmp[0] = req->host[0];
			tmp[1] = '/';
			memcpy(tmp + 2, req->host, req->host_len);
			tmp[req->host_len + 2] = 0;

			return tmp;
		case 2:
			// www.ABCDEFG.com => A/AB/ABCDEFG.com

			tmp[0] = req->host[0];
			tmp[1] = '/';
			tmp[2] = req->host[0];
			tmp[3] = req->host[1];
			tmp[4] = '/';
			memcpy(tmp + 5, req->host, req->host_len);
			tmp[req->host_len + 5] = 0;

			return tmp;
		case 3:
			// www.ABCDEFG.com => A/AB/ABC/ABCDEFG.com

			tmp[0] = req->host[0];
			tmp[1] = '/';
			tmp[2] = req->host[0];
			tmp[3] = req->host[1];
			tmp[4] = '/';
			tmp[5] = req->host[0];
			tmp[6] = req->host[1];
			tmp[7] = req->host[2];
			tmp[8] = '/';
			memcpy(tmp + 9, req->host, req->host_len);
			tmp[req->host_len + 9] = 0;

			return tmp;
	}
}

static struct dentry * vhost_lookup (tux_req_t *req, struct nameidata* base, struct vfsmount **mnt)
{
	struct dentry *dentry = NULL;
	// 255.255.255.255
	char ip [3+1+3+1+3+1+3 + 2];

	if (req->virtual >= TUX_VHOST_IP) {
		sprintf(ip, "%d.%d.%d.%d",
				NIPQUAD(inet_sk(req->sock->sk)->rcv_saddr));
		dentry = __tux_lookup (req, ip, base, mnt);
		if (!dentry || IS_ERR(dentry)) {
			if (PTR_ERR(dentry) == -EWOULDBLOCKIO)
				return dentry;
			base->dentry = dget(req->proto->main_docroot.dentry);
			base->mnt = mntget(req->proto->main_docroot.mnt);
			goto lookup_default;
		}
		if (req->virtual == TUX_VHOST_IP)
			goto done;

		// fall through in mixed mode:
	}

	if (!req->host_len) {
lookup_default:
		*mnt = NULL;
		dentry = __tux_lookup (req, tux_default_vhost, base, mnt);
	} else {
		char tmp [MAX_HOST_LEN*2];
		char *host_path;

		host_path = host_path_hash(req, tmp);
		Dprintk("host path hash returned: {%s}\n", host_path);

		dentry = NULL;
		if (host_path) {
			*mnt = NULL;
			dentry = __tux_lookup (req, host_path, base, mnt);
		}
		if (!dentry || IS_ERR(dentry)) {
			if (PTR_ERR(dentry) == -EWOULDBLOCKIO)
				return dentry;
			base->dentry = dget(req->proto->main_docroot.dentry);
			base->mnt = mntget(req->proto->main_docroot.mnt);
			if (req->virtual >= TUX_VHOST_IP) {
				*mnt = NULL;
				dentry = __tux_lookup (req, ip, base, mnt);
				if (!dentry || IS_ERR(dentry)) {
					if (PTR_ERR(dentry) == -EWOULDBLOCKIO)
						return dentry;
					base->dentry = dget(req->proto->main_docroot.dentry);
					base->mnt = mntget(req->proto->main_docroot.mnt);
				}
			}
			goto lookup_default;
		}
	}
done:
	return dentry;
}

static void http_lookup_vhost (tux_req_t *req, int cachemiss)
{
	struct dentry *dentry;
	struct nameidata base = { };
	struct vfsmount *mnt = NULL;
	unsigned int flag = cachemiss ? 0 : LOOKUP_ATOMIC;

	Dprintk("http_lookup_vhost(%p, %d, virtual: %d, host: %s (%d).)\n", req, flag, req->virtual, req->host, req->host_len);

	base.flags = LOOKUP_FOLLOW|flag;
	base.last_type = LAST_ROOT;
	base.dentry = dget(req->proto->main_docroot.dentry);
	base.mnt = mntget(req->proto->main_docroot.mnt);

	dentry = vhost_lookup(req, &base, &mnt);

	Dprintk("looked up dentry %p.\n", dentry);

	if (dentry && !IS_ERR(dentry) && !dentry->d_inode)
		TUX_BUG();

	if (!dentry || IS_ERR(dentry)) {
		if (PTR_ERR(dentry) == -EWOULDBLOCKIO) {
			add_tux_atom(req, http_lookup_vhost);
			queue_cachemiss(req);
			return;
		}
		goto abort;
	}

	req->docroot_dentry = dentry;
	req->docroot_mnt = mnt;

	add_tux_atom(req, http_process_message);
	add_req_to_workqueue(req);
	return;
abort:
	if (dentry) {
		if (!IS_ERR(dentry))
			dput(dentry);
		dentry = NULL;
	}
	if (mnt) {
		if (!IS_ERR(mnt))
			mntput(mnt);
		mnt = NULL;
	}
	req_err(req);
	add_req_to_workqueue(req);
}

static void http_process_message (tux_req_t *req, int cachemiss)
{
	tux_attribute_t *attr;
	int missed;
	unsigned int lookup_flag = cachemiss ? 0 : LOOKUP_ATOMIC;

	Dprintk("handling req %p, cachemiss: %d.\n", req, cachemiss);

	/*
	 * URL redirection support - redirect all valid requests
	 * to the first userspace module.
	 */
	if (tux_all_userspace) {
		tcapi_template_t *tcapi = get_first_usermodule();
		if (tcapi) {
			req->usermode = 1;
			req->usermodule_idx = tcapi->userspace_id;
			goto usermode;
		}
	}
	missed = lookup_url(req, lookup_flag);
	if (missed == 2) {
		if (req->query_str) {
			req->error = TUX_ERROR_REDIRECT;
			goto error;
		}
		send_ret_redirect(req, cachemiss);
		return;
	}
	if (req->error)
		goto error;
	if (missed) {
cachemiss:
		if (cachemiss)
			TUX_BUG();
		Dprintk("uncached request.\n");
		INC_STAT(static_lookup_cachemisses);
		if (req->dentry)
			TUX_BUG();
		add_tux_atom(req, http_process_message);
		queue_cachemiss(req);
		return;
	}
	/*
	 * HTML directory indexing.
	 */
	if (S_ISDIR(req->dentry->d_inode->i_mode))
		return http_dirlist(req, cachemiss);
	if (!S_ISREG(req->dentry->d_inode->i_mode))
		TUX_BUG();


	attr = req->dentry->d_extra_attributes;
	if (!attr) {
		attr = lookup_tux_attribute(req);
		if (!attr)
			TUX_BUG();
		req->dentry->d_extra_attributes = attr;
	}
	if (attr->mime)
		Dprintk("using MIME type %s:%s, %d.\n", attr->mime->type, attr->mime->ext, attr->mime->special);
	if (attr->tcapi) {
		req->usermode = 1;
		req->usermodule_idx = attr->tcapi->userspace_id;
		if (req->module_dentry)
			TUX_BUG();
		req->module_dentry = dget(req->dentry);
		release_req_dentry(req);
		goto usermode;
	}

	switch (attr->mime->special) {
		case MIME_TYPE_MODULE:
			req->usermode = 1;
			goto usermode;

		case MIME_TYPE_REDIRECT:
			req->error = TUX_ERROR_REDIRECT;
			goto error;

		case MIME_TYPE_CGI:
#ifdef CONFIG_TUX_EXTCGI
			Dprintk("CGI request %p.\n", req);
			query_extcgi(req);
			return;
#endif

		default:
			if (req->query_str) {
				req->error = TUX_ERROR_REDIRECT;
				goto error;
			}
	}
	req->attr = attr;
	switch (req->method) {
		case METHOD_GET:
		case METHOD_HEAD:
			break;
		default:
			req->error = TUX_ERROR_REDIRECT;
			goto error;
	}
	if (req->usermode)
		TUX_BUG();

	req->output_len = req->total_file_len;
	/*
	 * Do range calculations.
	 */
	if (req->offset_end || req->offset_start)
		handle_range(req);

	if (req->may_send_gzip && !req->offset_start && !req->offset_end) {
		if (handle_gzip_req(req, lookup_flag))
			goto cachemiss;
		if ((tux_compression >= 2) && !req->content_gzipped)
			req->content_gzipped = 2;
	}
	if (req->parsed_len)
		trunc_headers(req);

	if (req->error)
		goto error;

	add_tux_atom(req, http_send_body);
	add_tux_atom(req, http_post_header);

	http_pre_header(req, req->method == METHOD_HEAD);

	add_req_to_workqueue(req);
	return;

error:
	if (req->error)
		zap_request(req, cachemiss);
	return;

usermode:
	add_req_to_workqueue(req);
}

static void http_post_header (tux_req_t *req, int cachemiss)
{
#ifdef CONFIG_TUX_DEBUG
	req->bytes_expected = req->output_len;
#endif
	req->bytes_sent = 0; // data comes now.

	add_req_to_workqueue(req);
}

static void http_send_body (tux_req_t *req, int cachemiss)
{
	int ret;

	Dprintk("SEND req %p <%p> (sock %p, sk %p) (keepalive: %d, status: %d)\n", req, __builtin_return_address(0), req->sock, req->sock->sk, req->keep_alive, req->status);

	SET_TIMESTAMP(req->output_timestamp);

	if (req->error) {
#ifdef CONFIG_TUX_DEBUG
		req->bytes_expected = 0;
#endif
		req->in_file->f_pos = 0;
		/*
		 * We are in the middle of a file transfer,
		 * zap it immediately:
		 */
		TDprintk("req->error = TUX_ERROR_CONN_CLOSE.\n");
		req->error = TUX_ERROR_CONN_CLOSE;
		zap_request(req, cachemiss);
		return;
	}

repeat:
	ret = 0;
	if (!req->status)
		req->status = 200;
	if (req->method != METHOD_HEAD) {
		ret = generic_send_file(req, req->sock, cachemiss);
		Dprintk("body send-file returned: %d.\n", ret);
	} else {
#ifdef CONFIG_TUX_DEBUG
		req->bytes_expected = 0;
#endif
	}

	switch (ret) {
		case -5:
			add_tux_atom(req, http_send_body);
			output_timeout(req);
			break;
		case -4:
			add_tux_atom(req, http_send_body);
			if (add_output_space_event(req, req->sock)) {
				del_tux_atom(req);
				goto repeat;
			}
			break;
		case -3:
			INC_STAT(static_sendfile_cachemisses);
			add_tux_atom(req, http_send_body);
			queue_cachemiss(req);
			break;
		case -1:
			break;
		default:
			req->in_file->f_pos = 0;
			add_req_to_workqueue(req);
			break;
	}
}

#define DEFAULT_DATE "Wed, 01 Jan 1970 00:00:01 GMT"

char tux_date [DATE_LEN] = DEFAULT_DATE;

/*
 * HTTP header
 */

#define HEADER_PART1A \
		"HTTP/1.1 200 OK\r\n" \
		"Content-Type: "

#define HEADER_PART1B \
		"HTTP/1.1 200 OK"

#define HEADER_PART1AP \
		"HTTP/1.1 206 Partial Content\r\n" \
		"Content-Type: "

#define HEADER_PART1BP \
		"HTTP/1.1 206 Partial Content"

#define HEADER_PART1C \
		"HTTP/1.1 404 Page Not Found\r\n" \
		"Content-Type: "

#define HEADER_PART1D \
		"HTTP/1.1 200 OK\r\n" \
		"Content-Type: text/html\r\n" \
		"Connection: close\r\n"

#define HEADER_PART2_keepalive "\r\nConnection: Keep-Alive\r\nDate: "

#define HEADER_PART2_close "\r\nConnection: close\r\nDate: "

#define HEADER_PART2_none "\r\nDate: "

// date "%s"

#define HEADER_PART3A "\r\nContent-Encoding: gzip"
#define HEADER_PART3BX "\r\nContent-Length: "

/*
 * Please acknowledge our hard work by not changing this define, or
 * at least please acknowledge us by leaving "TUX/2.0 (Linux)" in
 * the ID string. Thanks! :-)
 */
#define HEADER_PART3BY "\r\nServer: TUX/2.0 (Linux)\r\nContent-Length: "
#define HEADER_PART3C "\r\nETag: \""
#define HEADER_PART3ACC "\r\nAccept-Ranges: bytes"
#define HEADER_PART3L "\r\nLast-Modified: "
#define HEADER_PART3P "\r\nContent-Range: bytes "
#define HEADER_PART3CA "\r\nCache-Control: max-age="
#define HEADER_PART4 "\r\n\r\n"

#define MAX_OUT_HEADER_LEN (sizeof(HEADER_PART1AP) + MAX_MIMETYPE_LEN + \
		sizeof(HEADER_PART2_keepalive) + DATE_LEN + \
		sizeof(HEADER_PART3A) + sizeof(HEADER_PART3BY) + \
		12 + sizeof(HEADER_PART3C) + 21 + sizeof(HEADER_PART3L) + \
		sizeof(HEADER_PART3P) + 32 + \
		DATE_LEN + sizeof(HEADER_PART4) + sizeof(tux_extra_html_header) \
		+ sizeof(HEADER_PART3CA) + MAX_CACHE_CONTROL_AGE_LEN)

static void http_pre_header (tux_req_t *req, int head)
{
	int partial = req->offset_start | req->offset_end;
	unsigned long flags;
	char *buf, *curr;
	mimetype_t *mime = NULL;
	int size;


	if (MAX_OUT_HEADER_LEN > PAGE_SIZE)
		TUX_BUG();
	if ((req->attr && req->attr->tcapi) || req->usermode)
		TUX_BUG();

#define COPY_STATIC_PART(nr,curr)					\
	do {	\
		memcpy(curr, HEADER_PART##nr, sizeof(HEADER_PART##nr)-1); \
		curr += sizeof(HEADER_PART##nr)-1;			\
	} while (0)

	buf = curr = get_abuf(req, MAX_OUT_HEADER_LEN);

	if (req->lookup_dir) {
		COPY_STATIC_PART(1D, curr);
		goto dir_next;
	}
	mime = req->attr->mime;
	if (!mime)
		TUX_BUG();

	if (req->status == 404) {
		COPY_STATIC_PART(1C, curr);
		memcpy(curr, mime->type, mime->type_len);
		curr += mime->type_len;
	} else {
		if (tux_noid && (mime == &default_mimetype)) {
			if (partial)
				COPY_STATIC_PART(1BP, curr);
			else
				COPY_STATIC_PART(1B, curr);
		} else {
			if (partial)
				COPY_STATIC_PART(1AP, curr);
			else
				COPY_STATIC_PART(1A, curr);
			memcpy(curr, mime->type, mime->type_len);
			curr += mime->type_len;
		}
	}

	if (tux_generate_cache_control && mime->expire_str_len) {
		COPY_STATIC_PART(3CA, curr);
		memcpy(curr, mime->expire_str, mime->expire_str_len);
		curr += mime->expire_str_len;
	}

	if (req->keep_alive /* && (req->version == HTTP_1_0) */)
		COPY_STATIC_PART(2_keepalive, curr);
	else if (!req->keep_alive && (req->version == HTTP_1_1))
		COPY_STATIC_PART(2_close, curr);
	else
		// HTTP/1.0 default means close
		COPY_STATIC_PART(2_none, curr);

dir_next:
	memcpy(curr, tux_date, DATE_LEN-1);
	curr += DATE_LEN-1;

	if (req->content_gzipped)
		COPY_STATIC_PART(3A, curr);

	/*
	 * Content-Length:
	 */
	if (!req->lookup_dir) {
		if (tux_noid)
			COPY_STATIC_PART(3BX, curr);
		else
			COPY_STATIC_PART(3BY, curr);

		if (partial)
			curr += sprintf(curr, "%Ld", req->output_len);
		else {
			if (req->content_gzipped)
				curr += sprintf(curr, "%Ld",
							req->total_file_len);
			else {
				memcpy(curr, &req->etag, req->lendigits);
				curr += req->lendigits;
			}
		}
		if (tux_generate_etags && (req->status != 404)) {
			COPY_STATIC_PART(3C, curr);
			memcpy(curr, &req->etag, req->etaglen);
			curr += req->etaglen;
			curr[0] = '"';
			curr++;
		}
		if (tux_generate_last_mod || tux_generate_etags)
			COPY_STATIC_PART(3ACC, curr);
	}
        if (tux_generate_last_mod && (req->status != 404)) {
                COPY_STATIC_PART(3L, curr);
		last_mod_time(curr, req->mtime);
		curr += DATE_LEN-1;
        }
	if (partial) {
		COPY_STATIC_PART(3P, curr);
		curr += sprintf(curr, "%Ld-%Ld/%Ld", req->offset_start,
				req->offset_end-1, req->total_file_len);
	}
	COPY_STATIC_PART(4, curr);
	/*
	 * Possibly add an extra HTML header:
	 */
	if (tux_extra_html_header_size && mime && !strcmp(mime->type, "text/html")) {
		unsigned int len = tux_extra_html_header_size;

		memcpy(curr, tux_extra_html_header, len);
		curr += len;
	}

	size = curr-buf;

#ifdef CONFIG_TUX_DEBUG
	*curr = 0;
	Dprintk("{%s} [%d/%d]\n", buf, size, strlen(buf));
#endif

	flags = MSG_DONTWAIT;
	if (!head)
		flags |= MSG_MORE;
	send_abuf(req, size, flags);
}

void http_illegal_request (tux_req_t *req, int cachemiss)
{
	if (req->status == 304)
		send_ret_notmodified(req);
	else {
		if (req->status == 403)
			send_async_err_forbidden(req);
		else
			send_async_err_not_found(req);
	}
}

static int http_check_req_err (tux_req_t *req, int cachemiss)
{
	if ((req->sock->sk->sk_state <= TCP_SYN_RECV) &&
		!tcp_sk(req->sock->sk)->urg_data)
			return 0;
	Dprintk("http_check_req_err(%p,%d): 1 (state: %d, urg: %d)\n",
		req, cachemiss, req->sock->sk->sk_state,
		tcp_sk(req->sock->sk)->urg_data);
#ifdef CONFIG_TUX_DEBUG
	req->bytes_expected = 0;
#endif
	req->in_file->f_pos = 0;
	req->error = TUX_ERROR_CONN_CLOSE;
	zap_request(req, cachemiss);

	return 1;
}

#define COPY_STR(str) \
	do { memcpy(tmp, str, sizeof(str)-1); \
	tmp += sizeof(str)-1; } while (0)

static char * http_print_dir_line (tux_req_t *req, char *tmp, char *d_name, int d_len, int d_type, struct dentry *dentry, struct inode *inode)
{
	int len, spaces;
	loff_t size;

	switch (d_type) {
	case DT_DIR:
		COPY_STR("<IMG SRC=\"/icons/dir.gif\" ALT=\"[DIR]\">");
		break;
	case DT_REG:
		if ((d_len >= 3) &&
			(d_name[d_len-3] == '.') &&
			(d_name[d_len-2] == 'g') &&
			(d_name[d_len-1] == 'z'))
			COPY_STR("<IMG SRC=\"/icons/compressed.gif\" ALT=\"[   ]\">");
		else
		if ((d_len >= 4) &&
			(d_name[d_len-4] == '.') &&
			(d_name[d_len-3] == 't') &&
			(d_name[d_len-2] == 'g') &&
			(d_name[d_len-1] == 'z'))
			COPY_STR("<IMG SRC=\"/icons/compressed.gif\" ALT=\"[   ]\">");
		else
		if ((d_len >= 4) &&
			(d_name[d_len-4] == '.') &&
			(d_name[d_len-3] == 't') &&
			(d_name[d_len-2] == 'x') &&
			(d_name[d_len-1] == 't'))
			COPY_STR("<IMG SRC=\"/icons/text.gif\" ALT=\"[   ]\">");
		else
		if ((d_len >= 4) &&
			(d_name[d_len-4] == '.') &&
			(d_name[d_len-3] == 'b') &&
			(d_name[d_len-2] == 'z') &&
			(d_name[d_len-1] == '2'))
			COPY_STR("<IMG SRC=\"/icons/compressed.gif\" ALT=\"[   ]\">");
		else
		if ((d_len >= 4) &&
			(d_name[d_len-4] == '.') &&
			(d_name[d_len-3] == 'z') &&
			(d_name[d_len-2] == 'i') &&
			(d_name[d_len-1] == 'p'))
			COPY_STR("<IMG SRC=\"/icons/compressed.gif\" ALT=\"[   ]\">");
		else
			COPY_STR("<IMG SRC=\"/icons/file.gif\" ALT=\"[   ]\">");
		break;
	case DT_LNK:
		COPY_STR("<IMG SRC=\"/icons/link.gif\" ALT=\"[LNK]\">");
		break;
	default:
		if (tux_hide_unreadable)
			goto out_dput;
		COPY_STR("<IMG SRC=\"/icons/unknown.gif\" ALT=\"[   ]\">");
		break;
	}

#define LIST_1 " <A HREF=\""
#define LIST_2 "\">"
#define LIST_2_DIR "/\">"
#define LIST_3 "</A> "

	COPY_STR(LIST_1);
	memcpy(tmp, d_name, d_len);
	tmp += d_len;
	if (d_type == DT_DIR)
		COPY_STR(LIST_2_DIR);
	else
		COPY_STR(LIST_2);
	spaces = 0;
	len = d_len;

	if (len > 25)
		len = 25;
	memcpy(tmp, d_name, len);
	tmp += len;
	if (len != d_len) {
		*tmp++ = '.';
		*tmp++ = '.';
	} else {
		if (d_type == DT_DIR)
			*tmp++ = '/';
		else
			spaces++;
		spaces++;
	}
	COPY_STR(LIST_3);
	while (spaces) {
		*tmp++ = ' ';
		spaces--;
	}
#define FILL 25
	if (d_len < FILL) {
		memset(tmp, ' ', FILL-d_len);
		tmp += FILL-d_len;
	}

	tmp += time_unix2ls(inode->i_mtime.tv_sec, tmp);
	*tmp++ = ' ';

	if (d_type != DT_REG) {
		COPY_STR("        - ");
		goto out_size;
	}
	size = inode->i_size >> 10;
	if (size < 1024) {
		tmp += sprintf(tmp, "%8Lik ", size);
		goto out_size;
	}
	size >>= 10;
	if (size < 1024) {
		tmp += sprintf(tmp, "%8LiM ", size);
		goto out_size;
	}
	size >>= 10;
	if (size < 1024) {
		tmp += sprintf(tmp, "%8LiG ", size);
		goto out_size;
	}
	size >>= 10;
	if (size < 1024) {
		tmp += sprintf(tmp, "%8LiT ", size);
		goto out_size;
	}
	size >>= 10;
	tmp += sprintf(tmp, "%8LiT ", size);

out_size:
	*tmp++ = '\n';
	*tmp = 0;

	return tmp;
out_dput:
	return NULL;
}

tux_proto_t tux_proto_http = {
	.defer_accept = 1,
	.can_redirect = 1,
	.got_request = http_got_request,
	.parse_message = parse_http_message,
	.illegal_request = http_illegal_request,
	.check_req_err = http_check_req_err,
	.print_dir_line = http_print_dir_line,
	.name = "http",
};

