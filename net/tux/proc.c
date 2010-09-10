/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * proc.c: /proc/sys/tux handling
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

char tux_common_docroot[200] = "/var/www/tux/";
char tux_http_subdocroot[200] = "";
char tux_ftp_subdocroot[200] = "";
char tux_logfile[200] = "/var/log/tux";
char tux_cgiroot[200] = "/var/www/tux/cgiroot/";
char tux_404_page[200] = "404.html";
char tux_default_vhost[200] = "default";
char tux_extra_html_header[600];
unsigned int tux_extra_html_header_size = 0;

int tux_cgi_uid = -1;
int tux_cgi_gid = -1;
unsigned int tux_clientport = 8080;
unsigned int tux_logging = 0;
unsigned int tux_threads = 2;
unsigned int tux_max_connect = 10000;
unsigned int tux_max_keepalives = 10000;
unsigned int tux_max_backlog = 2048;
unsigned int tux_keepalive_timeout = 0;
unsigned int tux_max_output_bandwidth = 0;
unsigned int tux_defer_accept = 1;
unsigned int tux_mode_forbidden = 0 /*S_IXUGO*/; /* do not allow executable (CGI) files */
unsigned int tux_mode_allowed = S_IROTH; /* allow access if read-other is set */
unsigned int tux_virtual_server = 0;
unsigned int tux_ftp_virtual_server = 0;
unsigned int mass_hosting_hash = 0;
unsigned int strip_host_tail = 0;
unsigned int tux_max_object_size = 0;
cpumask_t tux_log_cpu_mask = CPU_MASK_ALL;
unsigned int tux_compression = 0;
unsigned int tux_noid = 0;
unsigned int tux_cgi_inherit_cpu = 0;
cpumask_t tux_cgi_cpu_mask = CPU_MASK_ALL;
unsigned int tux_zerocopy_header = 1;
unsigned int tux_max_free_requests = 1000;
unsigned int tux_ignore_query = 0;
unsigned int tux_all_userspace = 0;
unsigned int tux_redirect_logging = 1;
unsigned int tux_max_header_len = 3000;
unsigned int tux_referer_logging = 0;
unsigned int tux_generate_etags = 1;
unsigned int tux_generate_last_mod = 1;
unsigned int tux_generate_cache_control = 1;
unsigned int tux_ip_logging = 1;
unsigned int tux_ftp_wait_close = 1;
unsigned int tux_ftp_log_retr_only = 0;
unsigned int tux_hide_unreadable = 1;
unsigned int tux_http_dir_indexing = 0;
unsigned int tux_log_incomplete = 0;
unsigned int tux_cpu_offset = 0;
unsigned int tux_ftp_login_message = 0;

static struct ctl_table_header *tux_table_header;

static ctl_table tux_table[] = {
	{	NET_TUX_DOCROOT,
		"documentroot",
		&tux_common_docroot,
		sizeof(tux_common_docroot),
		0644,
		NULL,
		proc_dostring,
		&sysctl_string,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_DOCROOT,
		"http_subdocroot",
		&tux_http_subdocroot,
		sizeof(tux_http_subdocroot),
		0644,
		NULL,
		proc_dostring,
		&sysctl_string,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_DOCROOT,
		"ftp_subdocroot",
		&tux_ftp_subdocroot,
		sizeof(tux_ftp_subdocroot),
		0644,
		NULL,
		proc_dostring,
		&sysctl_string,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_LOGFILE,
		"logfile",
		&tux_logfile,
		sizeof(tux_logfile),
		0644,
		NULL,
		proc_dostring,
		&sysctl_string,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_THREADS,
		"threads",
		&tux_threads,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_KEEPALIVE_TIMEOUT,
		"keepalive_timeout",
		&tux_keepalive_timeout,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_MAX_KEEPALIVE_BW,
		"max_output_bandwidth",
		&tux_max_output_bandwidth,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_DEFER_ACCEPT,
		"defer_accept",
		&tux_defer_accept,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_MAX_BACKLOG,
		"max_backlog",
		&tux_max_backlog,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_MAX_CONNECT,
		"max_connect",
		&tux_max_connect,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_MAX_KEEPALIVES,
		"max_keepalives",
		&tux_max_keepalives,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_MODE_FORBIDDEN,
		"mode_forbidden",
		&tux_mode_forbidden,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_MODE_ALLOWED,
		"mode_allowed",
		&tux_mode_allowed,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_CGI_UID,
		"cgi_uid",
		&tux_cgi_uid,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_CGI_GID,
		"cgi_gid",
		&tux_cgi_gid,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_CGIROOT,
		"cgiroot",
		&tux_cgiroot,
		sizeof(tux_cgiroot),
		0644,
		NULL,
		proc_dostring,
		&sysctl_string,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_404_PAGE,
		"404_page",
		&tux_404_page,
		sizeof(tux_404_page),
		0644,
		NULL,
		proc_dostring,
		&sysctl_string,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_404_PAGE,
		"default_vhost",
		&tux_default_vhost,
		sizeof(tux_default_vhost),
		0644,
		NULL,
		proc_dostring,
		&sysctl_string,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_404_PAGE,
		"extra_html_header",
		&tux_extra_html_header,
		sizeof(tux_extra_html_header),
		0644,
		NULL,
		proc_dostring,
		&sysctl_string,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_CLIENTPORT,
		"extra_html_header_size",
		&tux_extra_html_header_size,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_CLIENTPORT,
		"clientport",
		&tux_clientport,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_CLIENTPORT,
		"generate_etags",
		&tux_generate_etags,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
        {       NET_TUX_CLIENTPORT,
                "generate_last_mod",
                &tux_generate_last_mod,
                sizeof(int),
                0644,
                NULL,
                proc_dointvec,
                &sysctl_intvec,
                NULL,
                NULL,
                NULL
        },
        {       NET_TUX_CLIENTPORT,
                "generate_cache_control",
                &tux_generate_cache_control,
                sizeof(int),
                0644,
                NULL,
                proc_dointvec,
                &sysctl_intvec,
                NULL,
                NULL,
                NULL
        },
	{	NET_TUX_CLIENTPORT,
		"ip_logging",
		&tux_ip_logging,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_CLIENTPORT,
		"ftp_wait_close",
		&tux_ftp_wait_close,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_CLIENTPORT,
		"ftp_log_retr_only",
		&tux_ftp_log_retr_only,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_CLIENTPORT,
		"http_dir_indexing",
		&tux_http_dir_indexing,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_CLIENTPORT,
		"hide_unreadable",
		&tux_hide_unreadable,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_CLIENTPORT,
		"log_incomplete",
		&tux_log_incomplete,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_LOGGING,
		"TDprintk",
		&tux_TDprintk,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_LOGGING,
		"Dprintk",
		&tux_Dprintk,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
#ifdef TUX_DPRINTK
#endif
	{	NET_TUX_LOGGING,
		"logging",
		&tux_logging,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_LOGENTRY_ALIGN_ORDER,
		"logentry_align_order",
		&tux_logentry_align_order,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_ACK_PINGPONG,
		"ack_pingpong",
		&tux_ack_pingpong,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_PUSH_ALL,
		"push_all",
		&tux_push_all,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_ZEROCOPY_PARSE,
		"zerocopy_parse",
		&tux_zerocopy_parse,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_VIRTUAL_SERVER,
		"virtual_server",
		&tux_virtual_server,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_VIRTUAL_SERVER,
		"mass_hosting_hash",
		&mass_hosting_hash,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_VIRTUAL_SERVER,
		"strip_host_tail",
		&strip_host_tail,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_VIRTUAL_SERVER,
		"ftp_virtual_server",
		&tux_ftp_virtual_server,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_MAX_OBJECT_SIZE,
		"max_object_size",
		&tux_max_object_size,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_COMPRESSION,
		"compression",
		&tux_compression,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_NOID,
		"noid",
		&tux_noid,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_CGI_INHERIT_CPU,
		"cgi_inherit_cpu",
		&tux_cgi_inherit_cpu,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_ZEROCOPY_HEADER,
		"zerocopy_header",
		&tux_zerocopy_header,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_ZEROCOPY_SENDFILE,
		"zerocopy_sendfile",
		&tux_zerocopy_sendfile,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_MAX_FREE_REQUESTS,
		"max_free_requests",
		&tux_max_free_requests,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_ALL_USERSPACE,
		"all_userspace",
		&tux_all_userspace,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_REDIRECT_LOGGING,
		"redirect_logging",
		&tux_redirect_logging,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_IGNORE_QUERY,
		"ignore_query",
		&tux_ignore_query,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_REFERER_LOGGING,
		"referer_logging",
		&tux_referer_logging,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_REFERER_LOGGING,
		"cpu_offset",
		&tux_cpu_offset,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_REFERER_LOGGING,
		"ftp_login_message",
		&tux_ftp_login_message,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{	NET_TUX_MAX_HEADER_LEN,
		"max_header_len",
		&tux_max_header_len,
		sizeof(int),
		0644,
		NULL,
		proc_dointvec,
		&sysctl_intvec,
		NULL,
		NULL,
		NULL
	},
	{0, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL} };


static ctl_table tux_dir_table[] = {
	{NET_TUX, "tux", NULL, 0, 0555, tux_table, NULL, NULL, NULL, NULL, NULL},
	{0, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL}
};

static ctl_table tux_root_table[] = {
	{CTL_NET, "net", NULL, 0, 0555, tux_dir_table, NULL, NULL, NULL, NULL, NULL},
	{0, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL}
};


static struct proc_dir_entry * root_tux_dir;
static struct proc_dir_entry * log_cpu_mask_entry;
static struct proc_dir_entry * cgi_cpu_mask_entry;
static struct proc_dir_entry * stat_entry;
static struct proc_dir_entry * tux_dir [CONFIG_TUX_NUMTHREADS];
static struct proc_dir_entry * listen_dir [CONFIG_TUX_NUMTHREADS];

tux_socket_t tux_listen [CONFIG_TUX_NUMTHREADS][CONFIG_TUX_NUMSOCKETS] =
 { [0 ... CONFIG_TUX_NUMTHREADS-1] = { {&tux_proto_http, 0, 80, NULL}, } };

static int cpu_mask_read_proc (char *page, char **start, off_t off,
					int count, int *eof, void *data)
{
	int len = cpumask_scnprintf(page, count, *(cpumask_t *)data);
	if (count - len < 2)
		return -EINVAL;
	len += sprintf(page + len, "\n");
	return len;
}

static int cpu_mask_write_proc (struct file *file,
					const char __user *buffer,
					unsigned long count, void *data)
{
	cpumask_t *mask = (cpumask_t *)data;
	unsigned long full_count = count, err;
	cpumask_t new_value;

	err = cpumask_parse(buffer, count, new_value);
	if (err)
		return err;

	*mask = new_value;
	return full_count;
}

#define LINE_SIZE 1024
#define LINE_MASK (LINE_SIZE-1)

static int print_request_stats (threadinfo_t *ti, char *page, unsigned int skip_count, unsigned int max_count)
{
	struct list_head *head, *curr;
	tux_req_t *req;
	unsigned int count = 0, size, line_off, len;
	char stat_line [LINE_SIZE];

	if (!max_count)
		BUG();

	head = &ti->all_requests;
	curr = head->next;

	while (curr != head) {
		req = list_entry(curr, tux_req_t, all);
		curr = curr->next;
		count++;
		if (count <= skip_count)
			continue;
		line_off = 0;
#define SP(x...) \
	line_off += sprintf(stat_line + line_off, x)

		if (req->proto == &tux_proto_http)
			SP("0 ");
		else
			SP("1 ");

		SP("%p ", req);
		SP("%d ", req->atom_idx);
		if (req->atom_idx >= 1)
			SP("%p ", req->atoms[0]);
		else
			SP("........ ");
		if (req->atom_idx >= 2)
			SP("%p ", req->atoms[1]);
		else
			SP("........ ");
		if (!list_empty(&req->work))	SP("W");	else SP(".");
		if (!list_empty(&req->free))	SP("F");	else SP(".");
		if (!list_empty(&req->lru))	SP("L");	else SP(".");
		if (req->keep_alive)		SP("K");	else SP(".");
		if (req->idle_input)		SP("I");	else SP(".");
		if (timer_pending(&req->keepalive_timer))
						SP("T(%lu/%lu)",jiffies,req->keepalive_timer.expires);	else SP(".");
		if (req->wait_output_space)	SP("O");	else SP(".");
		if (timer_pending(&req->output_timer))
						SP("T");	else SP(".");
		SP(" %d ", req->error);
		SP(" %d ", req->status);

#define SP_HOST(ip,port) \
		SP("%d.%d.%d.%d:%d ",NIPQUAD(ip),port)

		if (req->sock) {
			if (req->sock->sk)
				SP("%d:", req->sock->sk->sk_state);
			else
				SP("-2:");
		} else
			SP("-1:");
		SP_HOST(req->client_addr, req->client_port);

		SP("%Ld ", req->total_file_len);
		SP("%Ld ", req->in_file ? req->in_file->f_pos : -1);
		if (req->proto == &tux_proto_http) {
			SP("%d ", req->method);
			SP("%d ", req->version);
		}
		if (req->proto == &tux_proto_ftp) {
			SP("%d ", req->ftp_command);
			if (req->data_sock) {
				if (req->data_sock->sk)
					SP("%d:",req->data_sock->sk->sk_state);
				else
					SP("-2:");
				if (req->data_sock->sk)
					SP_HOST(inet_sk(req->data_sock->sk)->daddr,
						inet_sk(req->data_sock->sk)->dport);
				else
					SP("-1:-1 ");
			} else
				SP("-1 ");
		}
		SP("%p/%p %p/%p ", req->sock, req->sock ? req->sock->sk : (void *)-1, req->data_sock, req->data_sock ? req->data_sock->sk : (void *)-1);

		SP("%d\n", req->parsed_len);
		len = req->headers_len;
		if (len > 500)
			len = 500;
		SP("\n%d\n", len);
		memcpy(stat_line + line_off, req->headers, len);
		line_off += len;
		len = req->objectname_len;
		if (len > 100)
			len = 100;
		SP("\n%d\n", len);
		memcpy(stat_line + line_off, req->objectname, len);
		line_off += len;
		SP("\n\n<END>");
		if (line_off >= LINE_SIZE)
			BUG();
		Dprintk("printing req %p, count %d, page %p: {%s}.\n", req, count, page, stat_line);
		size = sprintf(page, "%-*s\n", LINE_SIZE-1, stat_line);
		if (size != LINE_SIZE)
			BUG();
		page += LINE_SIZE;
		if (count-skip_count >= max_count)
			break;
	}

	Dprintk("count: %d.\n", count-skip_count);
	return count - skip_count;
}

static int stat_read_proc (char *page, char **start, off_t off,
			int max_size, int *eof, void *data)
{
	unsigned int i, nr_total = 0, nr, nr_off, nr_skip, size = 0, nr_wanted;

	Dprintk("START, page: %p, max_size: %d, off: %ld.\n", page, max_size, off);
	*eof = 1;
	if (max_size & LINE_MASK)
		return 0;
	if (off & LINE_MASK)
		return 0;
	if (!max_size)
		return 0;

	nr_off = off/LINE_SIZE;

	for (i = 0; i < nr_tux_threads; i++) {
		threadinfo_t *ti = threadinfo + i;
		spin_lock_irq(&ti->work_lock);
		nr = ti->nr_requests;
		Dprintk("ti: %p, nr: %d, nr_total: %d, nr_off: %d.\n", ti, nr, nr_total, nr_off);
		nr_total += nr;
		if (nr_off >= nr_total) {
			spin_unlock_irq(&ti->work_lock);
			continue;
		}
		nr_skip = nr_off - (nr_total - nr);
		nr_wanted = (max_size-size) / LINE_SIZE;
		Dprintk("nr_skip: %d, nr_wanted: %d.\n", nr_skip, nr_wanted);
		nr = print_request_stats(ti, page + size, nr_skip, nr_wanted);
		spin_unlock_irq(&ti->work_lock);
		nr_off += nr;
		size += nr * LINE_SIZE;
		Dprintk("ret: %d requests, size: %d.\n", nr, size);
		if (size > max_size)
			BUG();
		if (size == max_size)
			break;
	}
	Dprintk("DONE: size: %d.\n", size);

	*start = page;

	if (size)
		*eof = 0;
	return size;
}

static int stat_write_proc (struct file *file, const char *buffer,
					unsigned long count, void *data)
{
	return -EINVAL;
}

#define MAX_STRING "http://255.255.255.255:65535"
#define MAX_STRINGLEN (sizeof(MAX_STRING))

#define INACTIVE_1 "[inactive]\n"
#define INACTIVE_2 "0\n"

static int listen_read_proc (char *page, char **start, off_t off,
			int count, int *eof, void *data)
{
	tux_socket_t *listen = data;

	if (count < MAX_STRINGLEN)
		return -EINVAL;

	if (!listen->proto)
		return sprintf(page, INACTIVE_1);

	return sprintf (page, "%s://%u.%u.%u.%u:%hu\n", listen->proto->name,
			HIPQUAD(listen->ip), listen->port);
}

static int listen_write_proc (struct file *file, const char *buffer,
					unsigned long count, void *data)
{
	char string [MAX_STRINGLEN];
	unsigned int d1, d2, d3, d4;
	unsigned short port;
	tux_socket_t *listen = data;

	if (!count)
		return -EINVAL;
	if (count > MAX_STRINGLEN)
		count = MAX_STRINGLEN;
	if (copy_from_user(string, buffer, count))
		return -EFAULT;
	string[count] = 0;

	if (!strcmp(string, INACTIVE_1) || !strcmp(string, INACTIVE_2)) {
		listen->proto = NULL;
		listen->ip = 0;
		listen->port = 0;
		return count;
	}

#define MK_IP(a,b,c,d) ((a << 24) | (b << 16) | (c << 8) | d)

        if (sscanf(string, "http://%u.%u.%u.%u:%hu\n",
					&d1, &d2, &d3, &d4, &port) == 5) {
		listen->ip = MK_IP(d1,d2,d3,d4);
		listen->port = port;
		listen->proto = &tux_proto_http;
		return count;
	}

        if (sscanf(string, "ftp://%u.%u.%u.%u:%hu\n",
					&d1, &d2, &d3, &d4, &port) == 5) {
		listen->ip = MK_IP(d1,d2,d3,d4);
		listen->port = port;
		listen->proto = &tux_proto_ftp;
		return count;
	}
	printk(KERN_ERR "tux: invalid listen-socket parameters: %s\n", string);
	return -EINVAL;
}

#define MAX_NAMELEN 10

static void register_tux_proc (unsigned int nr)
{
	struct proc_dir_entry *entry;
	char name [MAX_NAMELEN];
	int i;

	if (!root_tux_dir)
		TUX_BUG();

	sprintf(name, "%d", nr);

	/* create /proc/net/tux/1234/ */
	tux_dir[nr] = proc_mkdir(name, root_tux_dir);

	/* create /proc/net/tux/1234/listen/ */
	listen_dir[nr] = proc_mkdir("listen", tux_dir[nr]);

	/* create /proc/net/tux/1234/listen/ */
	for (i = 0; i < CONFIG_TUX_NUMSOCKETS; i++) {
		sprintf(name, "%d", i);
		entry = create_proc_entry(name, 0700, listen_dir[nr]);

		entry->nlink = 1;
		entry->data = (void *)(tux_listen[nr] + i);
		entry->read_proc = listen_read_proc;
		entry->write_proc = listen_write_proc;
		tux_listen[nr][i].entry = entry;
	}
}

static void unregister_tux_proc (unsigned int nr)
{
	int i;

	for (i = 0; i < CONFIG_TUX_NUMSOCKETS; i++) {
		remove_proc_entry(tux_listen[nr][i].entry->name,listen_dir[nr]);
		tux_listen[nr][i].entry = NULL;
	}

	remove_proc_entry(listen_dir[nr]->name, tux_dir[nr]);

	remove_proc_entry(tux_dir[nr]->name, root_tux_dir);
}

static void cleanup_tux_proc (void)
{
	int i;

	Dprintk("cleaning up /proc/net/tux/\n");

	for (i = 0; i < CONFIG_TUX_NUMTHREADS; i++)
		unregister_tux_proc(i);
	remove_proc_entry(stat_entry->name, root_tux_dir);
	remove_proc_entry(log_cpu_mask_entry->name, root_tux_dir);
	remove_proc_entry(cgi_cpu_mask_entry->name, root_tux_dir);
	remove_proc_entry(root_tux_dir->name, proc_net);
}

static void init_tux_proc (void)
{
	struct proc_dir_entry *entry;
	int i;

	if (root_tux_dir)
		return;

	/* create /proc/net/tux */
	root_tux_dir = proc_mkdir("tux", proc_net);

	entry = create_proc_entry("log_cpu_mask", 0700, root_tux_dir);

	entry->nlink = 1;
	entry->data = (void *)&tux_log_cpu_mask;
	entry->read_proc = cpu_mask_read_proc;
	entry->write_proc = cpu_mask_write_proc;

	log_cpu_mask_entry = entry;

	entry = create_proc_entry("cgi_cpu_mask", 0700, root_tux_dir);

	entry->nlink = 1;
	entry->data = (void *)&tux_cgi_cpu_mask;
	entry->read_proc = cpu_mask_read_proc;
	entry->write_proc = cpu_mask_write_proc;

	cgi_cpu_mask_entry = entry;

	entry = create_proc_entry("stat", 0700, root_tux_dir);

	entry->nlink = 1;
	entry->data = NULL;
	entry->read_proc = stat_read_proc;
	entry->write_proc = stat_write_proc;

	stat_entry = entry;

	/*
	 * Create entries for all existing threads.
	 */
	for (i = 0; i < CONFIG_TUX_NUMTHREADS; i++)
		register_tux_proc(i);
}

void start_sysctl(void)
{
	init_tux_proc();
	tux_table_header = register_sysctl_table(tux_root_table,1);
}

void end_sysctl(void)
{
	cleanup_tux_proc();
	unregister_sysctl_table(tux_table_header);
}


