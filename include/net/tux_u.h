#ifndef _NET_TUX_U_H
#define _NET_TUX_U_H

/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * tux_u.h: HTTP module API - HTTP interface to user-space
 */

/*
 * Different major versions are not compatible.
 * Different minor versions are only downward compatible.
 * Different patchlevel versions are downward and upward compatible.
 */
#define TUX_MAJOR_VERSION		3
#define TUX_MINOR_VERSION		0
#define TUX_PATCHLEVEL_VERSION		0

#define __KERNEL_SYSCALLS__

typedef enum http_versions {
        HTTP_1_0,
        HTTP_1_1
} http_version_t;

/*
 * Request methods known to HTTP:
 */
typedef enum http_methods {
        METHOD_NONE,
        METHOD_GET,
        METHOD_HEAD,
        METHOD_POST,
        METHOD_PUT,
	NR_METHODS
} http_method_t;

enum user_req {
	TUX_ACTION_STARTUP = 1,
	TUX_ACTION_SHUTDOWN = 2,
	TUX_ACTION_STARTTHREAD = 3,
	TUX_ACTION_STOPTHREAD = 4,
	TUX_ACTION_EVENTLOOP = 5,
	TUX_ACTION_GET_OBJECT = 6,
	TUX_ACTION_SEND_OBJECT = 7,
	TUX_ACTION_READ_OBJECT = 8,
	TUX_ACTION_FINISH_REQ = 9,
	TUX_ACTION_FINISH_CLOSE_REQ = 10,
	TUX_ACTION_REGISTER_MODULE = 11,
	TUX_ACTION_UNREGISTER_MODULE = 12,
	TUX_ACTION_CURRENT_DATE = 13,
	TUX_ACTION_REGISTER_MIMETYPE = 14,
	TUX_ACTION_READ_HEADERS = 15,
	TUX_ACTION_POSTPONE_REQ = 16,
	TUX_ACTION_CONTINUE_REQ = 17,
	TUX_ACTION_REDIRECT_REQ = 18,
	TUX_ACTION_READ_POST_DATA = 19,
	TUX_ACTION_SEND_BUFFER = 20,
	TUX_ACTION_WATCH_PROXY_SOCKET = 21,
	TUX_ACTION_WAIT_PROXY_SOCKET = 22,
	TUX_ACTION_QUERY_VERSION = 23,
	MAX_TUX_ACTION
};

enum tux_ret {
	TUX_ERROR = -1,
	TUX_RETURN_USERSPACE_REQUEST = 0,
	TUX_RETURN_EXIT = 1,
	TUX_RETURN_SIGNAL = 2,
	TUX_CONTINUE_EVENTLOOP = 3,
};

#define MAX_URI_LEN 256
#define MAX_COOKIE_LEN 128
#define MAX_FIELD_LEN 64
#define DATE_LEN 30

typedef struct user_req_s {
	u32 version_major;
	u32 version_minor;
	u32 version_patch;
	u32 http_version;
	u32 http_method;
	u32 http_status;

	u32 sock;
	u32 event;
	u32 error;
	u32 thread_nr;
	u32 bytes_sent;
	u32 client_host;
	u32 objectlen;
	u32 module_index;
	u32 keep_alive;
	u32 cookies_len;

	u64 id;
	u64 priv;
	u64 object_addr;

	u8 query[MAX_URI_LEN];
	u8 objectname[MAX_URI_LEN];
	u8 cookies[MAX_COOKIE_LEN];
	u8 content_type[MAX_FIELD_LEN];
	u8 user_agent[MAX_FIELD_LEN];
	u8 accept[MAX_FIELD_LEN];
	u8 accept_charset[MAX_FIELD_LEN];
	u8 accept_encoding[MAX_FIELD_LEN];
	u8 accept_language[MAX_FIELD_LEN];
	u8 cache_control[MAX_FIELD_LEN];
	u8 if_modified_since[MAX_FIELD_LEN];
	u8 negotiate[MAX_FIELD_LEN];
	u8 pragma[MAX_FIELD_LEN];
	u8 referer[MAX_FIELD_LEN];
	u8 new_date[DATE_LEN];
	u8 pad[2];

} user_req_t;

typedef enum ftp_commands {
        FTP_COMM_NONE,
        FTP_COMM_USER,
        FTP_COMM_PASS,
        FTP_COMM_ACCT,
        FTP_COMM_CWD,
        FTP_COMM_CDUP,
        FTP_COMM_SMNT,
        FTP_COMM_QUIT,
        FTP_COMM_REIN,
        FTP_COMM_PORT,
        FTP_COMM_PASV,
        FTP_COMM_TYPE,
        FTP_COMM_STRU,
        FTP_COMM_MODE,
        FTP_COMM_RETR,
        FTP_COMM_SIZE,
        FTP_COMM_MDTM,
        FTP_COMM_STOR,
        FTP_COMM_STOU,
        FTP_COMM_APPE,
        FTP_COMM_ALLO,
        FTP_COMM_REST,
        FTP_COMM_RNFR,
        FTP_COMM_RNTO,
        FTP_COMM_ABOR,
        FTP_COMM_DELE,
        FTP_COMM_RMD,
        FTP_COMM_MKD,
        FTP_COMM_PWD,
        FTP_COMM_LIST,
        FTP_COMM_NLST,
        FTP_COMM_SITE,
        FTP_COMM_SYST,
        FTP_COMM_STAT,
        FTP_COMM_HELP,
        FTP_COMM_NOOP,
        FTP_COMM_FEAT,
        FTP_COMM_CLNT,
} ftp_command_t;

#endif
