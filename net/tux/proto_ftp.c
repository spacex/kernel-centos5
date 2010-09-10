/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * ftp_proto.c: FTP application protocol support
 */

#define __KERNEL_SYSCALLS__
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

#define HELLO		"220 Linux/TUX 3.0 FTP server welcomes you!\r\n"
#define WRITE_DONE	"226 Transfer complete.\r\n"
#define BAD_FILENAME	"550 No such file or directory.\r\n"
#define GOOD_DIR	"250 CWD command successful.\r\n"
#define LIST_ERR	"503 LIST without PORT! Closing connection.\r\n"
#define LIST_ERR_MEM	"503 LIST could not allocate memory! Closing connection.\r\n"
#define WRITE_FILE	"150 Opening BINARY mode data connection.\r\n"
#define WRITE_LIST	"150 Opening ASCII mode data connection.\r\n"
#define RETR_ERR	"503 RETR without PORT! Closing connection.\r\n"
#define PORT_OK		"200 PORT command successful.\r\n"
#define LOGIN_OK	"230-There are currently %d users logged in, out of %d maximum.\r\n230-Bandwidth served by TUX currently: %d KB/sec\r\n230 TUX Guest login ok.\r\n"
#define LOGIN_OK_ONE	"230-There is currently 1 user logged in, out of %d maximum.\r\n230-Bandwidth served by TUX currently: %d KB/sec\r\n230 TUX Guest login ok.\r\n"
#define LOGIN_OK_PASS	"230 TUX Guest login ok.\r\n"
#define LOGIN_FORBIDDEN	"530 Sorry, Login Denied!\r\n"
#define TYPE_OK		"200 Type set to I.\r\n"
#define BYE		"221 Thank You for using TUX!\r\n"
#define NOT_IMPLEMENTED	"502 Command not implemented.\r\n"
#define CLOSE_2		"221 Cannot handle request, closing connection!\r\n"
#define CLOSE		"500 Unknown command.\r\n"
#define CLOSE_TIMEOUT	"421 Timeout, closing connection!\r\n"
#define LINUX_SYST	"215 UNIX Type: L8, Linux/TUX/3.0\r\n"
#define COMMAND_OK	"200 Command OK.\r\n"
#define REST_OK		"350 Restart offset OK.\r\n"
#define WRITE_ABORTED	"426 Transfer aborted, data connection closed.\r\n"
#define SITE		"214 No SITE commands are recognized.\r\n"

#define INTERVAL 10

unsigned long last_measurement;
unsigned int ftp_bytes_sent;
unsigned int ftp_bandwidth;

static void __update_bandwidth (tux_req_t *req, unsigned int bytes)
{
	/*
	 * Bandwidth measurement. Not completely accurate,
	 * but it's good enough and lightweight enough.
	 */
	if (jiffies >= last_measurement + INTERVAL*HZ) {
		ftp_bandwidth = (ftp_bytes_sent + 1023)/INTERVAL/1024;
		ftp_bytes_sent = 0;
		last_measurement = jiffies;
	}
	if (bytes)
		atomic_add(bytes, (atomic_t *)&ftp_bytes_sent);
	Dprintk("update_bandwidth(%p,%d), bytes_sent: %d, bandwidth: %d.\n",
		req, bytes, ftp_bytes_sent, ftp_bandwidth);
}

#define update_bandwidth(req,bytes)				\
	do {							\
		if (unlikely(tux_ftp_login_message))		\
			__update_bandwidth(req, bytes);		\
	} while (0)

static inline void __ftp_send_async_message (tux_req_t *req,
		 const char *message, int status, unsigned int size)
{
	update_bandwidth(req, size);
	__send_async_message(req, message, status, size, 1);
}

#define ftp_send_async_message(req,str,status) \
		__ftp_send_async_message(req,str,status,sizeof(str)-1)


static void ftp_flush_req (tux_req_t *req, int cachemiss)
{
	tux_push_pending(req->sock->sk);
	add_req_to_workqueue(req);
}

static void ftp_execute_command (tux_req_t *req, int cachemiss);

static void ftp_lookup_vhost (tux_req_t *req, int cachemiss)
{
	struct dentry *dentry;
	struct nameidata base = { };
	struct vfsmount *mnt = NULL;
	unsigned int flag = cachemiss ? 0 : LOOKUP_ATOMIC;
	char ip[3+1+3+1+3+1+3 + 2];

	sprintf(ip, "%d.%d.%d.%d", NIPQUAD(inet_sk(req->sock->sk)->rcv_saddr));
	Dprintk("ftp_lookup_vhost(%p, %d, virtual: %d, host: %s.)\n",
		req, flag, req->virtual, ip);

	base.flags = LOOKUP_FOLLOW|flag;
	base.last_type = LAST_ROOT;
	base.dentry = dget(req->proto->main_docroot.dentry);
	base.mnt = mntget(req->proto->main_docroot.mnt);

	dentry = __tux_lookup(req, ip, &base, &mnt);

	Dprintk("looked up dentry %p.\n", dentry);
	if (dentry && !IS_ERR(dentry) && !dentry->d_inode)
		TUX_BUG();

	if (!dentry || IS_ERR(dentry)) {
		if (PTR_ERR(dentry) == -EWOULDBLOCKIO) {
			add_tux_atom(req, ftp_lookup_vhost);
			queue_cachemiss(req);
			return;
		}
		goto abort;
	}

	req->docroot_dentry = dentry;
	req->docroot_mnt = mnt;

	add_tux_atom(req, ftp_execute_command);
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

static void ftp_got_request (tux_req_t *req)
{
	add_tux_atom(req, parse_request);
	add_tux_atom(req, ftp_flush_req);
	ftp_send_async_message(req, HELLO, 220);
}

#define GOTO_ERR { TDprintk("FTP protocol error at: %s:%d\n", \
			__FILE__, __LINE__); goto error; }

static void zap_data_socket (tux_req_t *req)
{
	if (!req->data_sock)
		return;
	Dprintk("zapping req %p's data socket %p.\n", req, req->data_sock);

	unlink_tux_data_socket(req);
	sock_release(req->data_sock);
	req->data_sock = NULL;
}

static int parse_ftp_message (tux_req_t *req, const int total_len)
{
	int comm, comm1 = 0, comm2 = 0, comm3 = 0, comm4 = 0;
	int newline_pos, i;
	const char *mess, *curr;

	curr = mess = req->headers;

	Dprintk("FTP parser got %d bytes: --->{%s}<---\n", total_len, curr);

	newline_pos = -1;
	for (i = 0; i < total_len; i++, curr++) {
		if (!*curr)
			GOTO_ERR;
		if (!(*curr == '\r') || !(*(curr+1) == '\n'))
			continue;
		newline_pos = i;
		break;
	}
	Dprintk("Newline pos: %d\n", newline_pos);
	if (newline_pos == -1) {
		Dprintk("incomplete mess on req %p!\n", req);
		return 0;
	}
	if (newline_pos < 3)
		GOTO_ERR;

#define toup(c) ((((c) >= 'a') && ((c) <= 'z')) ? ((c) + 'A' - 'a') : (c))

#define STRING_VAL(c1,c2,c3,c4) \
	(toup(c1) + (toup(c2) << 8) + (toup(c3) << 16) + (toup(c4) << 24))

#define STRING_VAL_STR(str) \
		STRING_VAL(str[0], str[1], str[2], str[3])

	Dprintk("string val (%c%c%c%c): %08x\n",
		mess[0], mess[1], mess[2], mess[3],
		STRING_VAL_STR(mess));

#define PARSE_FTP_COMM(c1,c2,c3,c4,name,num)			\
	if (STRING_VAL_STR(mess) == STRING_VAL(c1,c2,c3,c4))	\
	{							\
		Dprintk("parsed "#name".\n");			\
		comm##num = FTP_COMM_##name;			\
	}

	PARSE_FTP_COMM('A','C','C','T', ACCT,2);
	PARSE_FTP_COMM('C','D','U','P', CDUP,3);
	PARSE_FTP_COMM('S','M','N','T', SMNT,4);
	PARSE_FTP_COMM('Q','U','I','T', QUIT,1);
	PARSE_FTP_COMM('R','E','I','N', REIN,2);
	PARSE_FTP_COMM('P','A','S','V', PASV,3);
	PARSE_FTP_COMM('S','T','R','U', STRU,4);
	PARSE_FTP_COMM('S','T','O','R', STOR,2);
	PARSE_FTP_COMM('S','T','O','U', STOU,3);
	PARSE_FTP_COMM('A','P','P','E', APPE,4);
	PARSE_FTP_COMM('A','L','L','O', ALLO,1);
	PARSE_FTP_COMM('R','N','F','R', RNFR,2);
	PARSE_FTP_COMM('R','N','T','O', RNTO,3);
	PARSE_FTP_COMM('A','B','O','R', ABOR,4);
	PARSE_FTP_COMM('D','E','L','E', DELE,1);
	PARSE_FTP_COMM('R','M','D',' ', RMD, 2);
	PARSE_FTP_COMM('M','K','D',' ', MKD, 3);
	PARSE_FTP_COMM('P','W','D',' ', PWD, 4);
	PARSE_FTP_COMM('S','Y','S','T', SYST,2);
	PARSE_FTP_COMM('N','O','O','P', NOOP,3);
	PARSE_FTP_COMM('F','E','A','T', FEAT,4);

	comm = comm1 | comm2 | comm3 | comm4;

	if (comm) {
		if (newline_pos != 4)
			GOTO_ERR;
		req->ftp_command = comm;
		goto out;
	}

	switch (STRING_VAL(mess[0], mess[1], mess[2], mess[3])) {

#define PARSE_FTP_COMM_3CHAR(c1,c2,c3,name)				\
		case STRING_VAL(c1,c2,c3,'\r'):				\
		{							\
			Dprintk("parsed "#name".\n");			\
			req->ftp_command = FTP_COMM_##name;		\
			if (newline_pos != 3)				\
				GOTO_ERR;				\
		}

#define PARSE_FTP_3CHAR_COMM_IGNORE(c1,c2,c3,name)			\
		case STRING_VAL(c1,c2,c3,' '):				\
		{							\
			Dprintk("parsed "#name".\n");			\
			req->ftp_command = FTP_COMM_##name;		\
		}

#define PARSE_FTP_COMM_IGNORE(c1,c2,c3,c4,name)				\
		case STRING_VAL(c1,c2,c3,c4):				\
		{							\
			Dprintk("parsed "#name".\n");			\
			req->ftp_command = FTP_COMM_##name;		\
		}

#define PARSE_FTP_3CHAR_COMM_1_FIELD(c1,c2,c3,name,field,field_len,max)	\
		case STRING_VAL(c1,c2,c3,' '):				\
		{							\
			Dprintk("parsed "#name".\n");			\
			req->ftp_command = FTP_COMM_##name;		\
			if (newline_pos == 4)				\
				GOTO_ERR;				\
			if (newline_pos >= 5) {				\
				curr = mess + 3;			\
				if (*curr++ != ' ')			\
					GOTO_ERR;			\
				*(field_len) = newline_pos-4;		\
				if (*(field_len) >= max)		\
					GOTO_ERR;			\
				memcpy(field, curr, *(field_len));	\
				(field)[*(field_len)] = 0;		\
			}						\
		}

#define PARSE_FTP_COMM_1_FIELD(c1,c2,c3,c4,name,field,field_len,max)	\
		case STRING_VAL(c1,c2,c3,c4):				\
		{							\
			Dprintk("parsed "#name".\n");			\
			req->ftp_command = FTP_COMM_##name;		\
			if (newline_pos < 4)				\
				GOTO_ERR;				\
			if (newline_pos == 4)				\
				*(field_len) = 0;			\
			else {						\
				curr = mess + 4;			\
				if (*curr++ != ' ')			\
					GOTO_ERR;			\
				*(field_len) = newline_pos-5;		\
				if (*(field_len) >= max)		\
					GOTO_ERR;			\
				memcpy(field, curr, *(field_len));	\
				(field)[*(field_len)] = 0;		\
			}						\
		}

		PARSE_FTP_COMM_1_FIELD('U','S','E','R', USER,
			req->username, &req->username_len,
			MAX_USERNAME_LEN-1);
		if (!req->username_len)
			GOTO_ERR;
		break;

		{
			#define MAX_PASS_LEN 100
			char pass[MAX_PASS_LEN];
			unsigned int pass_len;
			PARSE_FTP_COMM_1_FIELD('P','A','S','S', PASS,
				pass, &pass_len,
				MAX_PASS_LEN-1);
			if (!pass_len)
				GOTO_ERR;
			break;
		}

		PARSE_FTP_3CHAR_COMM_1_FIELD('C','W','D', CWD,
			req->objectname, &req->objectname_len,
			MAX_OBJECTNAME_LEN-1);
		if (!req->objectname_len)
			GOTO_ERR;
		req->uri_str = req->objectname;
		req->uri_len = req->objectname_len;
		break;

		PARSE_FTP_COMM_3CHAR('P','W','D', PWD); break;

		{
			char type[3];
			unsigned int type_len;

			PARSE_FTP_COMM_1_FIELD('T','Y','P','E', TYPE,
				type, &type_len, 2);
			if (!type_len)
				GOTO_ERR;
			if ((type[0] != 'I') && (type[0] != 'A'))
				GOTO_ERR;
		}
		break;

		PARSE_FTP_COMM_1_FIELD('R','E','T','R', RETR,
			req->objectname, &req->objectname_len,
			MAX_OBJECTNAME_LEN-1);
		if (!req->objectname_len) {
			zap_data_socket(req);
			req->ftp_command = FTP_COMM_NONE;
		}
		req->uri_str = req->objectname;
		req->uri_len = req->objectname_len;
		break;

		PARSE_FTP_COMM_1_FIELD('S','I','Z','E', SIZE,
			req->objectname, &req->objectname_len,
			MAX_OBJECTNAME_LEN-1);
		if (!req->objectname_len)
			req->ftp_command = FTP_COMM_NONE;
		req->uri_str = req->objectname;
		req->uri_len = req->objectname_len;
		break;

		PARSE_FTP_COMM_1_FIELD('M','D','T','M', MDTM,
			req->objectname, &req->objectname_len,
			MAX_OBJECTNAME_LEN-1);
		if (!req->objectname_len)
			req->ftp_command = FTP_COMM_NONE;
		req->uri_str = req->objectname;
		req->uri_len = req->objectname_len;
		break;

		PARSE_FTP_COMM_IGNORE('M','O','D','E', MODE);
		break;

		PARSE_FTP_COMM_IGNORE('S','T','A','T', STAT);
		break;

		PARSE_FTP_COMM_IGNORE('S','I','T','E', SITE);
		break;

		PARSE_FTP_COMM_1_FIELD('L','I','S','T', LIST,
			req->objectname, &req->objectname_len,
			MAX_OBJECTNAME_LEN-1);
		if (req->objectname[0] == '-') {
			req->objectname_len = 0;
			req->objectname[0] = 0;
		}
		if (req->objectname_len) {
			req->uri_str = req->objectname;
			req->uri_len = req->objectname_len;
		}
		break;

		PARSE_FTP_COMM_1_FIELD('N','L','S','T', NLST,
			req->objectname, &req->objectname_len,
			MAX_OBJECTNAME_LEN-1);
		if (req->objectname[0] == '-') {
			req->objectname_len = 0;
			req->objectname[0] = 0;
		}
		if (req->objectname_len) {
			req->uri_str = req->objectname;
			req->uri_len = req->objectname_len;
		}
		break;

		PARSE_FTP_COMM_IGNORE('H','E','L','P', HELP);
		break;

		PARSE_FTP_COMM_IGNORE('C','L','N','T', CLNT);
		break;

#define IS_NUM(n) (((n) >= '0') && ((n) <= '9'))

#define GET_DIGIT(curr,n)				\
	n += (*curr) - '0';				\
	curr++;						\
	if (IS_NUM(*curr)) {				\
		n *= 10;

#define PARSE_PORTNUM(curr,n)				\
do {							\
	Dprintk("PORT NUM parser:--->{%s}<---\n", curr);\
	if (!IS_NUM(*curr))				\
		GOTO_ERR;				\
	n = 0;						\
	GET_DIGIT(curr,n);				\
	GET_DIGIT(curr,n);				\
	GET_DIGIT(curr,n);				\
	}}}						\
	if (n > 255)					\
		GOTO_ERR;				\
	Dprintk("PORT NUM parser:--->{%s}<---\n", curr);\
	Dprintk("PORT NUM parser parsed %d.\n", n);	\
} while (0)

#define PARSE_NUM(curr,n)				\
do {							\
	Dprintk("NUM parser:--->{%s}<---\n", curr);	\
	if (!IS_NUM(*curr))				\
		GOTO_ERR;				\
	n = 0;						\
	GET_DIGIT(curr,n);				\
	GET_DIGIT(curr,n);				\
	GET_DIGIT(curr,n);				\
	GET_DIGIT(curr,n);				\
	GET_DIGIT(curr,n);				\
	GET_DIGIT(curr,n);				\
	GET_DIGIT(curr,n);				\
	GET_DIGIT(curr,n);				\
	GET_DIGIT(curr,n);				\
	GET_DIGIT(curr,n);				\
	}}}}}}}}}}					\
	Dprintk("NUM parser:--->{%s}<---\n", curr);	\
	Dprintk("NUM parser parsed %d.\n", n);		\
} while (0)

		case STRING_VAL('P','O','R','T'):
		{
			unsigned int h1, h2, h3, h4, p1, p2;
			if (req->data_sock)
				zap_data_socket(req);
			/*
			 * Minimum size: "PORT 0,0,0,0,0,0", 16 bytes.
			 */
			if (newline_pos < 16)
				GOTO_ERR;
			Dprintk("parsed PORT.\n");
			if (req->data_sock)
				GOTO_ERR;
			curr = mess + 4;
			if (*curr++ != ' ')
				GOTO_ERR;
			PARSE_PORTNUM(curr,h1);
			if (*curr++ != ',')
				GOTO_ERR;
			PARSE_PORTNUM(curr,h2);
			if (*curr++ != ',')
				GOTO_ERR;
			PARSE_PORTNUM(curr,h3);
			if (*curr++ != ',')
				GOTO_ERR;
			PARSE_PORTNUM(curr,h4);
			if (*curr++ != ',')
				GOTO_ERR;
			PARSE_PORTNUM(curr,p1);
			if (*curr++ != ',')
				GOTO_ERR;
			PARSE_PORTNUM(curr,p2);
			if (curr-mess != newline_pos)
				GOTO_ERR;
			req->ftp_command = FTP_COMM_PORT;
			req->ftp_user_addr = (h1<<24) + (h2<<16) + (h3<<8) + h4;
			req->ftp_user_port = (p1<<8) + p2;
			Dprintk("FTP PORT got: %d.%d.%d.%d:%d.\n",
				h1, h2, h3, h4, req->ftp_user_port);
			Dprintk("FTP user-addr: %08x (htonl: %08x), socket: %08x.\n",
				req->ftp_user_addr, htonl(req->ftp_user_addr),
				inet_sk(req->sock->sk)->daddr);
			/*
			 * Do not allow redirection of connections, and do
			 * not allow reserved ports to be accessed.
			 */
			if (inet_sk(req->sock->sk)->daddr != htonl(req->ftp_user_addr))
				GOTO_ERR;
			if (req->ftp_user_port < 1024)
				GOTO_ERR;
			break;
		}
		case STRING_VAL('R','E','S','T'):
		{
			unsigned int offset;

			/*
			 * Minimum size: "REST 0", 6 bytes.
			 */
			if (newline_pos < 6)
				GOTO_ERR;
			Dprintk("parsed REST.\n");
			curr = mess + 4;
			if (*curr++ != ' ')
				GOTO_ERR;
			PARSE_NUM(curr,offset);
			if (curr-mess != newline_pos)
				GOTO_ERR;
			req->ftp_command = FTP_COMM_REST;
			req->ftp_offset_start = offset;
			Dprintk("FTP REST got: %d bytes offset.\n", offset);

			break;
		}
		default:
			req->ftp_command = FTP_COMM_NONE;
			break;
	}

out:
	req->parsed_len = newline_pos + 2;

	req->virtual = tux_ftp_virtual_server;
	if (req->virtual)
		add_tux_atom(req, ftp_lookup_vhost);
	else {
		req->docroot_dentry = dget(req->proto->main_docroot.dentry);
		req->docroot_mnt = mntget(req->proto->main_docroot.mnt);
		add_tux_atom(req, ftp_execute_command);
	}

	return req->parsed_len;
error:
	clear_keepalive(req);
	TDprintk("rejecting FTP session!\n");
	TDprintk("mess     :--->{%s}<---\n", mess);
	TDprintk("mess left:--->{%s}<---\n", curr);
	req_err(req);
	return -1;
}

static void ftp_wait_close (tux_req_t *req, int cachemiss);
static void ftp_wait_syn (tux_req_t *req, int cachemiss);

static int ftp_check_req_err (tux_req_t *req, int cachemiss)
{
	int state = req->sock->sk->sk_state;
	int err = req->sock->sk->sk_err | req->error;
	int urg = tcp_sk(req->sock->sk)->urg_data;

	if (req->data_sock) {
		urg |= tcp_sk(req->data_sock->sk)->urg_data;
		state |= req->data_sock->sk->sk_state;
		err |= req->data_sock->sk->sk_err;
	}

	if ((state <= TCP_SYN_RECV) && !err) {
		if (!urg)
			return 0;
		req->in_file->f_pos = 0;
		add_tux_atom(req, flush_request);
		zap_data_socket(req);
		ftp_send_async_message(req, WRITE_ABORTED, 426);
		return 1;
	}
#ifdef CONFIG_TUX_DEBUG
	req->bytes_expected = 0;
	if (tux_TDprintk)
		dump_stack();
#endif
	req->in_file->f_pos = 0;
	TDprintk("zapping, data sock state: %d (err: %d, urg: %d)\n",
		state, err, urg);
	/*
	 * We are in the middle of a file transfer,
	 * zap it immediately:
	 */
	req->error = TUX_ERROR_CONN_CLOSE;
	zap_request(req, cachemiss);
	return 1;
}

void ftp_send_file (tux_req_t *req, int cachemiss)
{
	int ret;

	SET_TIMESTAMP(req->output_timestamp);
repeat:
	ret = generic_send_file(req, req->data_sock, cachemiss);
	if (req->in_file) {
		update_bandwidth(req, req->in_file->f_pos - req->prev_pos);
		req->prev_pos = req->in_file->f_pos;
	}

	switch (ret) {
		case -5:
			add_tux_atom(req, ftp_send_file);
			output_timeout(req);
			break;
		case -4:
			add_tux_atom(req, ftp_send_file);
			if (add_output_space_event(req, req->data_sock)) {
				del_tux_atom(req);
				goto repeat;
			}
			break;
		case -3:
			add_tux_atom(req, ftp_send_file);
			queue_cachemiss(req);
			break;
		case -1:
			break;
		default:
			if (req->in_file)
				req->in_file->f_pos = 0;

			if (tux_ftp_wait_close) {
				req->data_sock->ops->shutdown(req->data_sock, SEND_SHUTDOWN);
				add_tux_atom(req, ftp_wait_close);
				add_req_to_workqueue(req);
				return;
			}
			Dprintk("FTP send file req %p finished!\n", req);
			zap_data_socket(req);
			add_tux_atom(req, ftp_flush_req);
			if (req->error)
				ftp_send_async_message(req, BAD_FILENAME, 200);
			else
				ftp_send_async_message(req, WRITE_DONE, 200);
			break;
	}
}

#define sk_syn(sk) \
	(!(sk)->sk_err && ((1 << (sk)->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)))
#define req_syn(req) \
	(!(req)->error && sk_syn((req)->data_sock->sk))

static void ftp_wait_syn (tux_req_t *req, int cachemiss)
{
	Dprintk("ftp_wait_syn in: data socket state %d.\n", req->data_sock->state);
	if (req_syn(req)) {
		spin_lock_irq(&req->ti->work_lock);
		add_keepalive_timer(req);
		if (test_and_set_bit(0, &req->idle_input))
			TUX_BUG();
		spin_unlock_irq(&req->ti->work_lock);
		if (req_syn(req)) {
			add_tux_atom(req, ftp_wait_syn);
			return;
		}
		unidle_req(req);
	}
	Dprintk("ftp_wait_syn out: data socket state %d.\n", req->data_sock->state);
	add_req_to_workqueue(req);
}

static void ftp_wait_close (tux_req_t *req, int cachemiss)
{
	struct sock *sk = req->data_sock->sk;

	Dprintk("ftp_wait_close: data socket state %d.\n", sk->sk_state);

	if (!req->error && (sk->sk_state <= TCP_FIN_WAIT1) && !sk->sk_err) {
		spin_lock_irq(&req->ti->work_lock);
		add_keepalive_timer(req);
		if (test_and_set_bit(0, &req->idle_input))
			TUX_BUG();
		spin_unlock_irq(&req->ti->work_lock);
		if (!req->error && (sk->sk_state <= TCP_FIN_WAIT1) && !sk->sk_err) {
			add_tux_atom(req, ftp_wait_close);
			return;
		}
		unidle_req(req);
	}
	zap_data_socket(req);
	add_tux_atom(req, ftp_flush_req);
	if (req->error)
		ftp_send_async_message(req, BAD_FILENAME, 200);
	else
		ftp_send_async_message(req, WRITE_DONE, 200);
}

void ftp_get_size (tux_req_t *req, int cachemiss)
{
	char file_size[200];
	int missed, len;

	if (!req->dentry) {
		missed = lookup_object(req, cachemiss ? 0 : LOOKUP_ATOMIC);
		if (!missed && !req->dentry) {
			ftp_send_async_message(req, BAD_FILENAME, 200);
			return;
		}
		if (missed) {
			if (cachemiss)
				TUX_BUG();
			add_tux_atom(req, ftp_get_size);
			queue_cachemiss(req);
			return;
		}
	}
	req->in_file->f_pos = 0;
	len = sprintf(file_size, "213 %Li\r\n", req->dentry->d_inode->i_size);
	__ftp_send_async_message(req, file_size, 200, len);
}

void ftp_get_mdtm (tux_req_t *req, int cachemiss)
{
	unsigned int flag = cachemiss ? 0 : LOOKUP_ATOMIC;
	struct dentry *dentry;
	struct vfsmount *mnt = NULL;
	char file_mdtm[200];
	unsigned int len;
	int err;

	dentry = tux_lookup(req, req->objectname, flag, &mnt);
	if (!dentry || IS_ERR(dentry)) {
		if (PTR_ERR(dentry) == -EWOULDBLOCKIO) {
			if (cachemiss)
				TUX_BUG();
			add_tux_atom(req, ftp_get_mdtm);
			queue_cachemiss(req);
			return;
		}
		goto out_err;
	}
	err = permission(dentry->d_inode, MAY_READ, NULL);
	if (err)
		goto out_err_put;

	req->in_file->f_pos = 0;
	len = mdtm_time (file_mdtm, dentry->d_inode->i_mtime.tv_sec);
	dput(dentry);
	mntput(mnt);
	__ftp_send_async_message(req, file_mdtm, 200, len);
	return;

out_err_put:
	dput(dentry);
	mntput(mnt);
out_err:
	ftp_send_async_message(req, BAD_FILENAME, 550);
}

static void ftp_get_file (tux_req_t *req, int cachemiss)
{
	int missed;

	if (!req->dentry) {
		missed = lookup_object(req, cachemiss ? 0 : LOOKUP_ATOMIC);
		if (!missed && !req->dentry) {
			ftp_send_async_message(req, BAD_FILENAME, 200);
			return;
		}
		if (missed) {
			if (cachemiss)
				TUX_BUG();
			add_tux_atom(req, ftp_get_file);
			queue_cachemiss(req);
			return;
		}
	}
	Dprintk("ftp_send_file %p, ftp_offset: %Ld, total_len: %Ld.\n", req, req->ftp_offset_start, req->total_file_len);
	req->in_file->f_pos = 0;
	if (req->ftp_offset_start) {
		if (req->ftp_offset_start <= req->total_file_len) {
			req->offset_start = req->ftp_offset_start;
			req->in_file->f_pos = req->offset_start;
		}
		req->ftp_offset_start = 0;
	}
	req->output_len = req->total_file_len - req->offset_start;
	req->prev_pos = req->in_file->f_pos;
	Dprintk("ftp_send_file %p, f_pos: %Ld (out_len: %Ld).\n", req, req->in_file->f_pos, req->output_len);
	add_tux_atom(req, ftp_send_file);
	add_tux_atom(req, ftp_wait_syn);
	add_tux_atom(req, ftp_flush_req);
	ftp_send_async_message(req, WRITE_FILE, 200);
}

static void __exchange_sockets (tux_req_t *req)
{
	struct socket *tmp;

	tmp = req->data_sock;
	req->data_sock = req->sock;
	req->sock = tmp;

	req->in_file->f_pos = 0;
}

static void ftp_do_ls_start (tux_req_t *req, int cachemiss)
{
	Dprintk("ftp_do_ls_start(%p, %d).\n", req, cachemiss);
	if (!req->cwd_dentry)
		TUX_BUG();
	__exchange_sockets(req);
	queue_cachemiss(req);
}

static void ftp_do_ls_end (tux_req_t *req, int cachemiss)
{
	Dprintk("ftp_do_ls_end(%p, %d).\n", req, cachemiss);
	__exchange_sockets(req);
	if (tux_ftp_wait_close) {
		req->data_sock->ops->shutdown(req->data_sock, SEND_SHUTDOWN);
		add_tux_atom(req, ftp_wait_close);
		add_req_to_workqueue(req);
		return;
	}
	zap_data_socket(req);
	add_tux_atom(req, ftp_flush_req);
	if (req->error)
		ftp_send_async_message(req, BAD_FILENAME, 200);
	else
		ftp_send_async_message(req, WRITE_DONE, 200);
}

static void ftp_chdir (tux_req_t *req, int cachemiss)
{
	unsigned int flag = cachemiss ? 0 : LOOKUP_ATOMIC;
	struct dentry *dentry;
	struct vfsmount *mnt = NULL;
	int err;

	Dprintk("ftp_chdir(%p, %d, {%s})\n", req, cachemiss, req->objectname);
	dentry = tux_lookup(req, req->objectname, flag, &mnt);
	if (!dentry || IS_ERR(dentry)) {
		if (PTR_ERR(dentry) == -EWOULDBLOCKIO) {
			if (cachemiss)
				TUX_BUG();
			add_tux_atom(req, ftp_chdir);
			queue_cachemiss(req);
			return;
		}
		goto out_err;
	}
	err = permission(dentry->d_inode, MAY_EXEC, NULL);
	if (err)
		goto out_err_put;
	req->cwd_dentry = dentry;
	req->cwd_mnt = mnt;
	ftp_send_async_message(req, GOOD_DIR, 200);
	return;

out_err_put:
	dput(dentry);
	mntput(mnt);
out_err:
	ftp_send_async_message(req, BAD_FILENAME, 550);
}

void ftp_accept_pasv (tux_req_t *req, int cachemiss)
{
	struct socket *sock, *new_sock = NULL;
	struct inet_connection_sock *icsk1, *icsk2;
	struct tcp_sock *tp1, *tp2;
	int err;

	tp1 = tcp_sk(req->data_sock->sk);
	icsk1 = inet_csk(req->data_sock->sk);

	Dprintk("PASV accept on req %p, accept_queue: %p.\n",
			req, &icsk1->icsk_accept_queue);
	if (req->error || (req->data_sock->sk->sk_state != TCP_LISTEN))
		goto error;
new_socket:
	if (reqsk_queue_empty(&icsk1->icsk_accept_queue)) {
		spin_lock_irq(&req->ti->work_lock);
		add_keepalive_timer(req);
		if (test_and_set_bit(0, &req->idle_input))
			TUX_BUG();
		spin_unlock_irq(&req->ti->work_lock);
		if (reqsk_queue_empty(&icsk1->icsk_accept_queue)) {
			add_tux_atom(req, ftp_accept_pasv);
			return;
		}
		unidle_req(req);
	}
	new_sock = sock_alloc();
	if (!new_sock)
		goto error;
	sock = req->data_sock;
	new_sock->type = sock->type;
	new_sock->ops = sock->ops;

	err = sock->ops->accept(sock, new_sock, O_NONBLOCK);
	Dprintk("PASV accept() returned %d (state %d).\n", err, new_sock->sk->sk_state);
	if (err < 0)
		goto error;
	if (new_sock->sk->sk_state != TCP_ESTABLISHED)
		goto error;
	/*
	 * Do not allow other clients to steal the FTP connection!
	 */
	if (inet_sk(new_sock->sk)->daddr != inet_sk(req->sock->sk)->daddr) {
		Dprintk("PASV: ugh, unauthorized connect?\n");
		sock_release(new_sock);
		new_sock = NULL;
		goto new_socket;
	}
	/*
	 * Zap the listen socket:
	 */
	zap_data_socket(req);

	tp2 = tcp_sk(new_sock->sk);
	icsk2 = inet_csk(new_sock->sk);
	tp2->nonagle = 2;
	icsk2->icsk_ack.pingpong = tux_ack_pingpong;
	new_sock->sk->sk_reuse = 1;
	sock_set_flag(new_sock->sk, SOCK_URGINLINE);
	sock_reset_flag(new_sock->sk, SOCK_LINGER);

	link_tux_data_socket(req, new_sock);
	add_req_to_workqueue(req);
	return;

error:
	if (new_sock)
		sock_release(new_sock);
	req_err(req);
	zap_data_socket(req);
	ftp_send_async_message(req, CLOSE, 500);
}

static char * ftp_print_dir_line (tux_req_t *req, char *tmp, char *d_name, int d_len, int d_type, struct dentry *dentry, struct inode *inode)
{
	char *string0 = tmp;
	unsigned int size;

	if (req->ftp_command == FTP_COMM_NLST) {
		memcpy(tmp, d_name, d_len);
		tmp += d_len;
		*tmp++ = '\r';
		*tmp++ = '\n';
		*tmp = 0;
		return tmp;
	}
	switch (d_type) {
		default:
		case DT_UNKNOWN:
		case DT_WHT:
			if (tux_hide_unreadable)
				goto out_dput;
			*tmp++ = '?';
			break;

		case DT_FIFO:
			if (tux_hide_unreadable)
				goto out_dput;
			*tmp++ = 'p';
			break;

		case DT_CHR:
			if (tux_hide_unreadable)
				goto out_dput;
			*tmp++ = 'c';
			break;

		case DT_DIR:
			*tmp++ = 'd';
			break;

		case DT_BLK:
			if (tux_hide_unreadable)
				goto out_dput;
			*tmp++ = 'b';
			break;

		case DT_REG:
			*tmp++ = '-';
			break;

		case DT_LNK:
			*tmp++ = 'l';
			break;

		case DT_SOCK:
			if (tux_hide_unreadable)
				goto out_dput;
			*tmp++ = 's';
			break;
	}

	if (inode->i_mode & S_IRUSR) *tmp++ = 'r'; else *tmp++ = '-';
	if (inode->i_mode & S_IWUSR) *tmp++ = 'w'; else *tmp++ = '-';
	if (inode->i_mode & S_IXUSR) *tmp++ = 'x'; else *tmp++ = '-';
	if (inode->i_mode & S_IRGRP) *tmp++ = 'r'; else *tmp++ = '-';
	if (inode->i_mode & S_IWGRP) *tmp++ = 'w'; else *tmp++ = '-';
	if (inode->i_mode & S_IXGRP) *tmp++ = 'x'; else *tmp++ = '-';
	if (inode->i_mode & S_IROTH) *tmp++ = 'r'; else *tmp++ = '-';
	if (inode->i_mode & S_IWOTH) *tmp++ = 'w'; else *tmp++ = '-';
	if (inode->i_mode & S_IXOTH) *tmp++ = 'x'; else *tmp++ = '-';

	*tmp++ = ' ';

	size = sprintf(tmp, "%4i %d", inode->i_nlink, inode->i_uid);
	tmp += size;

	size = 14 - size;
	if (size <= 0)
		size = 1;
	memset(tmp, ' ', size);
	tmp += size;

	size = sprintf(tmp, "%d", inode->i_gid);
	tmp += size;

	size = 9 - size;
	if (size <= 0)
		size = 1;
	memset(tmp, ' ', size);
	tmp += size;

	tmp += sprintf(tmp, "%8Li", inode->i_size);
	*tmp++ = ' ';

	tmp += time_unix2ls(inode->i_mtime.tv_sec, tmp);
	*tmp++ = ' ';

	memcpy(tmp, d_name, d_len);
	tmp += d_len;

	if (d_type == DT_LNK) {
		int len = 0, max_len;
		#define ARROW " -> "

		memcpy(tmp, ARROW, sizeof(ARROW)-1);
		tmp += sizeof(ARROW)-1;
		max_len = MAX_OBJECTNAME_LEN-(tmp-string0);
		if (inode->i_op && inode->i_op->readlink) {
			mm_segment_t oldmm;

			oldmm = get_fs(); set_fs(KERNEL_DS);
			set_fs(KERNEL_DS);
			len = inode->i_op->readlink(dentry, tmp, max_len);
			set_fs(oldmm);
		}
		if (len > 0)
			tmp += len;
		else
			Dprintk("hm, readlink() returned %d.\n", len);
	}
	*tmp++ = '\r';
	*tmp++ = '\n';
	*tmp = 0;

	return tmp;
out_dput:
	return NULL;
}

static void ftp_do_ls_onefile (tux_req_t *req, int cachemiss)
{
	char string0[MAX_OBJECTNAME_LEN+200], *tmp;

	tmp = ftp_print_dir_line(req, string0, req->objectname, req->objectname_len,
DT_REG, req->dentry, req->dentry->d_inode);
	if (!tmp) {
		req_err(req);
		add_req_to_workqueue(req);
		return;
	}
	if (tmp - string0 >= MAX_OBJECTNAME_LEN+200)
		BUG();
	__ftp_send_async_message(req, string0, 200, tmp - string0);
}

static void ftp_lookup_listfile (tux_req_t *req, int cachemiss)
{
	unsigned int flag = cachemiss ? 0 : LOOKUP_ATOMIC;
	struct dentry *dentry;
	struct vfsmount *mnt = NULL;
	int err;

	Dprintk("ftp_lookup_listfile(%p, %d, {%s})\n", req, cachemiss, req->objectname);
	dentry = tux_lookup(req, req->objectname, flag, &mnt);
	if (!dentry || IS_ERR(dentry)) {
		if (PTR_ERR(dentry) == -EWOULDBLOCKIO) {
			if (cachemiss)
				TUX_BUG();
			add_tux_atom(req, ftp_lookup_listfile);
			queue_cachemiss(req);
			return;
		}
		goto out_err;
	}

	if (S_ISDIR(dentry->d_inode->i_mode)) {
		err = permission(dentry->d_inode, MAY_EXEC, NULL);
		if (err) {
			Dprintk("Directory permission error: %d.\n", err);
			goto out_err_put;
		}
		install_req_dentry(req, dentry, mnt);

		add_tux_atom(req, ftp_do_ls_end);
		if (!req->cwd_dentry)
			TUX_BUG();
		add_tux_atom(req, list_directory);
	} else {
		install_req_dentry(req, dentry, mnt);

		add_tux_atom(req, ftp_do_ls_end);
		add_tux_atom(req, ftp_do_ls_onefile);
	}

	add_tux_atom(req, ftp_do_ls_start);
	add_tux_atom(req, ftp_wait_syn);
	add_tux_atom(req, ftp_flush_req);
	ftp_send_async_message(req, WRITE_LIST, 200);
	return;

out_err_put:
	dput(dentry);
	mntput(mnt);
out_err:
	ftp_send_async_message(req, BAD_FILENAME, 550);
}

static void ftp_execute_command (tux_req_t *req, int cachemiss)
{
	if (!req->parsed_len)
		TUX_BUG();
	trunc_headers(req);
	req->keep_alive = 1;

	switch (req->ftp_command) {

#define ABORTED \
	"226 Abort successful.\r\n"

	case FTP_COMM_ABOR:
	{
		zap_data_socket(req);
		ftp_send_async_message(req, ABORTED, 226);
		break;
	}

	case FTP_COMM_PWD:
	{
		unsigned int str_len;
		char *buf, *path;

		buf = (char *)__get_free_page(GFP_KERNEL);
		if (!buf) {
			req_err(req);
			ftp_send_async_message(req, LIST_ERR_MEM, 200);
			GOTO_ERR;
		}

		if (!req->cwd_dentry) {
			req->cwd_dentry = dget(req->docroot_dentry);
			req->cwd_mnt = mntget(req->docroot_mnt);
		}

// "257 "/" is current directory.\r\n"

#define PART_1 "257 \""
#define PART_1_LEN (sizeof(PART_1)-1)

#define PART_3 "\" is current directory.\r\n"
#define PART_3_LEN sizeof(PART_3)

		path = tux_print_path(req, req->cwd_dentry, req->cwd_mnt,
			buf+PART_1_LEN, PAGE_SIZE - PART_3_LEN - PART_1_LEN);

		if (path < buf + PART_1_LEN)
			BUG();

		memcpy(path - PART_1_LEN, PART_1, PART_1_LEN);
		memcpy(buf + PAGE_SIZE-PART_3_LEN-1, PART_3, PART_3_LEN);
		str_len = buf + PAGE_SIZE-1 - (path - PART_1_LEN) - 1;

		__ftp_send_async_message(req, path - PART_1_LEN, 226, str_len);
		free_page((unsigned long)buf);
		break;
	}

	case FTP_COMM_CDUP:
	{
		memcpy(req->objectname, "..", 3);
		req->objectname_len = 2;
		req->uri_str = req->objectname;
		req->uri_len = req->objectname_len;

		// fall through to CWD:
	}
	case FTP_COMM_CWD:
	{
		ftp_chdir(req, cachemiss);
		break;
	}

	case FTP_COMM_NLST:
	case FTP_COMM_LIST:
	{
		if (!req->data_sock) {
			req_err(req);
			ftp_send_async_message(req, LIST_ERR, 200);
			GOTO_ERR;
		}
		if (req->dentry)
			TUX_BUG();
		if (!req->cwd_dentry) {
			req->cwd_dentry = dget(req->docroot_dentry);
			req->cwd_mnt = mntget(req->docroot_mnt);
		}
		if (req->objectname_len)
			ftp_lookup_listfile(req, cachemiss);
		else {
			dget(req->cwd_dentry);
			mntget(req->cwd_mnt);
			install_req_dentry(req, req->cwd_dentry, req->cwd_mnt);
			if (!req->dentry)
				TUX_BUG();
			add_tux_atom(req, ftp_do_ls_end);
			if (!req->cwd_dentry)
				TUX_BUG();
			add_tux_atom(req, list_directory);
			add_tux_atom(req, ftp_do_ls_start);
			add_tux_atom(req, ftp_wait_syn);
			add_tux_atom(req, ftp_flush_req);
			ftp_send_async_message(req, WRITE_LIST, 200);
		}
		break;
	}

	case FTP_COMM_RETR:
	{
		if (!req->data_sock) {
			req_err(req);
			ftp_send_async_message(req, RETR_ERR, 200);
			GOTO_ERR;
		}
		ftp_get_file(req, cachemiss);
		break;
	}

	case FTP_COMM_SIZE:
	{
		ftp_get_size(req, cachemiss);
		break;
	}

	case FTP_COMM_MDTM:
	{
		ftp_get_mdtm(req, cachemiss);
		break;
	}

	case FTP_COMM_PASV:
	{
		char buf [36 + 4*3 + 5 + 10];
		struct socket *data_sock;
		struct sockaddr_in addr;
		unsigned int str_len;
		struct tcp_sock *tp;
		struct inet_connection_sock *icsk;
		u32 local_addr;
		int err;

		if (req->data_sock)
			zap_data_socket(req);
		/*
		 * Create FTP data connection to client:
		 */
		err = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_IP, &data_sock);
		if (err < 0) {
			Dprintk("sock create err: %d\n", err);
			req_err(req);
			ftp_send_async_message(req, CLOSE, 500);
			GOTO_ERR;
		}

		local_addr = inet_sk(req->sock->sk)->rcv_saddr;
		addr.sin_family = AF_INET;
		addr.sin_port = 0;
		addr.sin_addr.s_addr = local_addr;
		Dprintk("client address: (%d,%d,%d,%d).\n",
			NIPQUAD(inet_sk(req->sock->sk)->daddr));

		data_sock->sk->sk_reuse = 1;
		sock_set_flag(data_sock->sk, SOCK_URGINLINE);
		sock_reset_flag(data_sock->sk, SOCK_LINGER);

		err = data_sock->ops->bind(data_sock,
				(struct sockaddr*)&addr, sizeof(addr));
		tp = tcp_sk(data_sock->sk);
		icsk = inet_csk(data_sock->sk);

		tp->nonagle = 2;
		Dprintk("PASV bind() ret: %d.\n", err);
		if (err < 0) {
			req_err(req);
			sock_release(data_sock);
			ftp_send_async_message(req, CLOSE, 500);
			GOTO_ERR;
		}

		icsk->icsk_ack.pingpong = tux_ack_pingpong;

		if (!tux_keepalive_timeout)
			tp->linger2 = 0;
		else
			tp->linger2 = tux_keepalive_timeout * HZ;

		err = data_sock->ops->listen(data_sock, 1);
		Dprintk("PASV listen() ret: %d\n", err);
		if (err) {
			req_err(req);
			sock_release(data_sock);
			ftp_send_async_message(req, CLOSE, 500);
			GOTO_ERR;
		}
		link_tux_data_socket(req, data_sock);

		Dprintk("FTP PASV listen sock state: %d, sk state: %d\n",
			data_sock->state, data_sock->sk->sk_state);

		str_len = sprintf(buf,
			"227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n",
				NIPQUAD(local_addr),
				ntohs(inet_sk(data_sock->sk)->sport) / 256,
				ntohs(inet_sk(data_sock->sk)->sport) & 255 );
		Dprintk("PASV mess: {%s}\n", buf);

		add_tux_atom(req, ftp_accept_pasv);
		add_tux_atom(req, ftp_flush_req);
		__ftp_send_async_message(req, buf, 227, str_len);
		break;
	}

	case FTP_COMM_PORT:
	{
		struct socket *data_sock;
		struct sockaddr_in addr;
		kernel_cap_t saved_cap;
		u32 local_addr;
		int err;

		/*
		 * Create FTP data connection to client:
		 */
		err = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_IP, &data_sock);
		if (err < 0) {
			Dprintk("sock create err: %d\n", err);
			req_err(req);
			ftp_send_async_message(req, CLOSE, 500);
			GOTO_ERR;
		}

		local_addr = inet_sk(req->sock->sk)->rcv_saddr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(20);
		addr.sin_addr.s_addr = local_addr;

		Dprintk("data socket address: (%d,%d,%d,%d).\n",
			NIPQUAD(local_addr));

		data_sock->sk->sk_reuse = 1;
		sock_set_flag(data_sock->sk, SOCK_URGINLINE);
		sock_reset_flag(data_sock->sk, SOCK_LINGER);

		saved_cap = current->cap_effective;
		cap_raise (current->cap_effective, CAP_NET_BIND_SERVICE);
		err = data_sock->ops->bind(data_sock,
				(struct sockaddr*)&addr, sizeof(addr));
		current->cap_effective = saved_cap;

		Dprintk("ACTIVE bind() ret: %d.\n", err);
		if (err) {
			sock_release(data_sock);
			req_err(req);
			ftp_send_async_message(req, CLOSE, 500);
			GOTO_ERR;
		}
		tcp_sk(data_sock->sk)->nonagle = 2;

		link_tux_data_socket(req, data_sock);

		addr.sin_family = AF_INET;
		addr.sin_port = htons(req->ftp_user_port);
		addr.sin_addr.s_addr = htonl(req->ftp_user_addr);

		err = data_sock->ops->connect(data_sock, (struct sockaddr *) &addr, sizeof(addr), O_RDWR|O_NONBLOCK);
		if (err && (err != -EINPROGRESS)) {
			Dprintk("connect error: %d\n", err);
			zap_data_socket(req);
			req_err(req);
			ftp_send_async_message(req, CLOSE, 500);
			GOTO_ERR;
		}
		Dprintk("FTP data sock state: %d, sk state: %d\n", data_sock->state, data_sock->sk->sk_state);
		ftp_send_async_message(req, PORT_OK, 200);
		break;
	}

	case FTP_COMM_USER:
	{
		if (!strcmp(req->username, "ftp")
			 || !strcmp(req->username, "FTP")
			 || !strcmp(req->username, "anonymous")
			 || !strcmp(req->username, "ANONYMOUS")) {
			unsigned int str_len;
			char login_ok [200];

			if (!tux_ftp_login_message) {
				ftp_send_async_message(req, LOGIN_OK_PASS, 230);
				break;
			}
			update_bandwidth(req, 0); /* get current bandwidth */
			if (nr_requests_used() == 1)
				str_len = sprintf(login_ok, LOGIN_OK_ONE,
					tux_max_connect, ftp_bandwidth);
			else
				str_len = sprintf(login_ok, LOGIN_OK,
					nr_requests_used(), tux_max_connect, ftp_bandwidth);
			__ftp_send_async_message(req, login_ok, 200, str_len);
		} else {
			clear_keepalive(req);
			ftp_send_async_message(req, LOGIN_FORBIDDEN, 530);
		}
		break;
	}
	case FTP_COMM_PASS:
	{
		ftp_send_async_message(req, LOGIN_OK_PASS, 230);
		break;
	}
	case FTP_COMM_SITE:
	{
		ftp_send_async_message(req, SITE, 214);
		break;
	}
	case FTP_COMM_SYST:
	{
		ftp_send_async_message(req, LINUX_SYST, 200);
		break;
	}
	case FTP_COMM_TYPE:
	{
		ftp_send_async_message(req, TYPE_OK, 200);
		break;
	}
#define EXTRA_FEATURES "211-Extensions supported:\r\n SIZE\r\n MDTM\r\n211 End\r\n"

	case FTP_COMM_FEAT:
	{
		ftp_send_async_message(req, EXTRA_FEATURES, 211);
		break;
	}
	case FTP_COMM_HELP:
	case FTP_COMM_CLNT:
	case FTP_COMM_NOOP:
	{
		ftp_send_async_message(req, COMMAND_OK, 200);
		break;
	}
	case FTP_COMM_REST:
	{
		ftp_send_async_message(req, REST_OK, 200);
		break;
	}
	case FTP_COMM_QUIT:
	{
		clear_keepalive(req);
		ftp_send_async_message(req, BYE, 200);
		break;
	}

	default:
	{
		req->keep_alive = 1;
		ftp_send_async_message(req, CLOSE, 500);
		break;
	}
	}
	return;
error:
	Dprintk("rejecting FTP session!\n");
	return;
}


static void ftp_timeout (tux_req_t *req, int cachemiss)
{
	Dprintk("called ftp_timeout(%p)\n", req);
	if (req->error != TUX_ERROR_CONN_TIMEOUT)
		TUX_BUG();
	ftp_send_async_message(req, CLOSE_TIMEOUT, 421);
}

static void ftp_close (tux_req_t *req, int cachemiss)
{
	Dprintk("called ftp_close(%p)\n", req);
	ftp_send_async_message(req, CLOSE, 500);
}

static void ftp_pre_log (tux_req_t *req)
{
	if (tux_ftp_log_retr_only && (req->ftp_command != FTP_COMM_RETR))
		req->status = 0;
	else
		req->status = req->ftp_command;
}

tux_proto_t tux_proto_ftp = {
	.defer_accept = 0,
	.can_redirect = 0,
	.got_request = ftp_got_request,
	.parse_message = parse_ftp_message,
	.illegal_request = ftp_close,
	.request_timeout = ftp_timeout,
	.pre_log = ftp_pre_log,
	.check_req_err = ftp_check_req_err,
	.print_dir_line = ftp_print_dir_line,
	.name = "ftp",
};

