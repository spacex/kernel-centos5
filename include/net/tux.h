#ifndef _NET_TUX_H
#define _NET_TUX_H

/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * tux.h: main structure definitions and function prototypes
 */

#define __KERNEL_SYSCALLS__

#include <linux/mm.h>
#include <linux/net.h>
#include <linux/wait.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include <linux/utsname.h>
#include <linux/smp_lock.h>
#include <linux/kernel_stat.h>
#include <linux/kernel_stat.h>
#include <linux/time.h>
#include <asm/div64.h>
#include <asm/unaligned.h>
#include <linux/compiler.h>
#include <linux/mount.h>
#include <linux/zlib.h>
#include <linux/syscalls.h>
#include <linux/cpumask.h>

#include <net/tcp.h>
#include <net/tux_u.h>

/* Maximum number of threads: */
#define CONFIG_TUX_NUMTHREADS 16

/* Number of cachemiss/IO threads: */
#define NR_IO_THREADS 64

/* Maximum number of listen sockets per thread: */
#define CONFIG_TUX_NUMSOCKETS 16

extern spinlock_t tux_module_lock;
extern struct module *tux_module;
extern asmlinkage long (*sys_tux_ptr) (unsigned int action, user_req_t *u_info);

#undef Dprintk

extern int tux_TDprintk;
extern int tux_Dprintk;

#ifdef CONFIG_TUX_DEBUG
# define TUX_BUG() BUG()

# define TUX_DPRINTK 1
# define TDprintk(x...) do { if (tux_TDprintk) { printk("<%ld:%s:%d>: ", jiffies, __FILE__, __LINE__); printk(x); } } while (0)
# define Dprintk(x...) do { if (tux_Dprintk == 1) TDprintk(x); } while (0)
#else
# define TUX_DPRINTK 0
# define Dprintk(x...) do { } while (0)
# define TDprintk(x...) do { } while (0)
//# define TUX_BUG() BUG()
# define TUX_BUG() do { } while (0)
#endif

#if 1
# define INC_STAT(x) do { } while (0)
# define DEC_STAT(x) do { } while (0)
# define ADD_STAT(x,y) do { } while (0)
# define SUB_STAT(x,y) do { } while (0)
#else
# define INC_STAT(x) atomic_inc((atomic_t *)&kstat.x)
# define DEC_STAT(x) atomic_dec((atomic_t *)&kstat.x)
# define ADD_STAT(y,x) atomic_add(y,(atomic_t *)&kstat.x)
# define SUB_STAT(y,x) atomic_sub(y,(atomic_t *)&kstat.x)
#endif

// lru needs this:

# define DEBUG_DEL_LIST(x...) do { INIT_LIST_HEAD((x)); } while (0)


#define LOG_LEN (8*1024*1024UL)

struct tux_req_struct;
typedef struct tux_req_struct tux_req_t;
typedef struct tux_threadinfo threadinfo_t;

extern struct address_space_operations url_aops;

typedef struct tcapi_template_s {
	char *vfs_name;
	struct list_head modules;
	int (*query) (tux_req_t *req);
	struct module *mod;
	unsigned int userspace_id;
} tcapi_template_t;

typedef struct mimetype_s {
	struct list_head list;

	char *ext;
	unsigned int ext_len;
	char *type;
	unsigned int type_len;
	char *expire_str;
	unsigned int expire_str_len;

	unsigned int special;
} mimetype_t;

typedef struct tux_attribute_s {
	mimetype_t *mime;
	tcapi_template_t *tcapi;
} tux_attribute_t;

#define MAX_TUX_ATOMS 8

typedef void (atom_func_t)(tux_req_t *req, int cachemiss);

typedef struct tux_proto_s
{
	unsigned int defer_accept;
	unsigned int can_redirect;
	void (*got_request) (tux_req_t *req);
	int (*parse_message) (tux_req_t *req, const int total_len);
	atom_func_t *illegal_request;
	atom_func_t *request_timeout;
	void (*pre_log) (tux_req_t *req);
	int (*check_req_err) (tux_req_t *req, int cachemiss);
	char * (*print_dir_line) (tux_req_t *req, char *tmp, char *d_name, int d_len, int d_type, struct dentry *dentry, struct inode *inode);
	const char *name;
	struct nameidata main_docroot;
} tux_proto_t;

typedef struct tux_socket_s {
	tux_proto_t *proto;
	unsigned int ip;
	unsigned short port;
	struct proc_dir_entry *entry;
} tux_socket_t;

extern tux_socket_t tux_listen [CONFIG_TUX_NUMTHREADS][CONFIG_TUX_NUMSOCKETS];


typedef struct abuf_s {
	struct page *page;
	char *buf;
	unsigned int size;
	unsigned int max_len;
	unsigned int offset;
	unsigned int left;
	unsigned long flags;
} abuf_t;

struct linux_dirent64 {
	u64		d_ino;
	s64		d_off;
	unsigned short  d_reclen;
	unsigned char   d_type;
	char		d_name[0];
};

struct getdents_callback64 {
	struct linux_dirent64 * current_dir;
	struct linux_dirent64 * previous;
	int count;
	int error;
};

#define TUX_MAGIC 0x12457801

#define MAX_TUX_ATOMS 8

struct tux_req_struct
{
	tux_proto_t *proto;

	int atom_idx;
	atom_func_t *atoms [MAX_TUX_ATOMS];
	struct list_head work;

	struct list_head all;
	struct list_head free;
	struct list_head lru;

	unsigned long idle_input;
	unsigned long wait_output_space;

	struct socket *sock;
	struct dentry *dentry;
	struct vfsmount *mnt;
	struct dentry *docroot_dentry;
	struct vfsmount *docroot_mnt;
	struct dentry *cwd_dentry;
	struct vfsmount *cwd_mnt;

	struct file *in_file;
	int fd;
	read_descriptor_t desc;
	u32 client_addr;
	u32 client_port;
	unsigned int virtual;

	loff_t total_file_len;
	unsigned int lendigits;
	loff_t offset_start;
	loff_t offset_end;
	loff_t output_len;

	loff_t ftp_offset_start;

	time_t mtime;
	unsigned int etaglen;
	char etag [40];

	char usermode;
	unsigned int usermodule_idx;
	struct dentry *module_dentry;
	struct vfsmount *module_mnt;
	char *userbuf;
	unsigned int userlen;

	tux_attribute_t *attr;

	threadinfo_t *ti;
	wait_queue_t sleep;
	wait_queue_t ftp_sleep;

	abuf_t abuf;
	/*
	 * Parsed request fields. In-line strings are zero-delimited.
	 */
	const char *headers;
	unsigned int headers_len;

	unsigned int parsed_len;

	// FTP part
	ftp_command_t ftp_command;
	u32 ftp_user_addr;
	u16 ftp_user_port;

	struct socket *data_sock;
	unsigned int prev_pos;

	// ls handing:
	struct linux_dirent64 *dirp0;
	unsigned int curroff, total;

#define MAX_USERNAME_LEN 16
	char username[MAX_USERNAME_LEN];
	unsigned int username_len;

	// HTTP part
	http_method_t method;
	const char *method_str;
	unsigned int method_len;

	http_version_t version;
	const char *version_str;
	unsigned int version_len;

	/* requested URI: */

	const char *uri_str;
	unsigned int uri_len;

	/* Objectname (filename/scriptname) this URI refers to: */

#define MAX_OBJECTNAME_LEN 256
	char objectname[MAX_OBJECTNAME_LEN + 4]; // space for .gz as well
	unsigned int objectname_len;

	/* Query string within the URI: */

	const char *query_str;
	unsigned int query_len;

	/* Cookies: */

	const char *cookies_str;
	unsigned int cookies_len;
	unsigned int parse_cookies;

	/* Content-TYpe */
	const char *content_type_str;
	unsigned int content_type_len;

	/* Content-Length: */

	const char *contentlen_str;
	unsigned int contentlen_len;
	unsigned int content_len;

	/* User-Agent: */

	const char *user_agent_str;
	unsigned int user_agent_len;

	/* Accept: */

	const char *accept_str;
	unsigned int accept_len;

	/* Accept-Charset: */

	const char *accept_charset_str;
	unsigned int accept_charset_len;

	/* Accept-Language: */

	const char *accept_language_str;
	unsigned int accept_language_len;

	/* Cache-Control: */

	const char *cache_control_str;
	unsigned int cache_control_len;

	/* If-Modified-Since: */

	const char *if_modified_since_str;
	unsigned int if_modified_since_len;

	/* If-None-Match: */
	const char *if_none_match_str;
	unsigned int if_none_match_len;

	/* If-Range: */

	const char *if_range_str;
	unsigned int if_range_len;

	/* Negotiate: */

	const char *negotiate_str;
	unsigned int negotiate_len;

	/* Pragma: */

	const char *pragma_str;
	unsigned int pragma_len;

	/* Referer: */

	const char *referer_str;
	unsigned int referer_len;

	/* Accept-Encoding: */

	const char *accept_encoding_str;
	unsigned int accept_encoding_len;
	unsigned int may_send_gzip;
	unsigned int content_gzipped;

	/* Host */

#define MAX_HOST_LEN 128
	char host[MAX_HOST_LEN];
	unsigned int host_len;

	/* POSTed data: */

	const char *post_data_str;
	unsigned int post_data_len;

	unsigned int status;

	/* the file being sent */

	unsigned int bytes_sent;
#ifdef CONFIG_TUX_DEBUG
	unsigned int bytes_expected;
#endif
	unsigned long first_timestamp;
	unsigned int body_len;

	unsigned int user_error;

	char error;
	char postponed;

	char had_cachemiss;
	char lookup_dir;
	char lookup_404;

	char keep_alive;
	struct timer_list keepalive_timer;
	unsigned int total_bytes;
	struct timer_list output_timer;

	unsigned int nr_keepalives;

	unsigned int event;
	u64 private;

	unsigned int magic;
	void (*real_data_ready)(struct sock *sk, int space);
	void (*real_state_change)(struct sock *sk);
	void (*real_write_space)(struct sock *sk);
	void (*real_error_report)(struct sock *sk);
	void (*real_destruct)(struct sock *sk);

	void (*ftp_real_data_ready)(struct sock *sk, int space);
	void (*ftp_real_state_change)(struct sock *sk);
	void (*ftp_real_write_space)(struct sock *sk);
	void (*ftp_real_error_report)(struct sock *sk);
	void (*ftp_real_create_child)(struct sock *sk, struct sock *newsk);
	void (*ftp_real_destruct)(struct sock *sk);

#ifdef CONFIG_TUX_EXTENDED_LOG
	unsigned long accept_timestamp;
	unsigned long parse_timestamp;
	unsigned long output_timestamp;
	unsigned long flush_timestamp;
# define SET_TIMESTAMP(x) do { (x) = jiffies; } while (0)
#else
# define SET_TIMESTAMP(x) do { } while (0)
#endif

};

extern void add_tux_atom (tux_req_t *req, atom_func_t *event_done);
extern void del_tux_atom (tux_req_t *req);
extern void tux_schedule_atom (tux_req_t *req, int cachemiss);
extern void add_req_to_workqueue (tux_req_t *req);


typedef struct iothread_s
{
	spinlock_t async_lock;
	threadinfo_t *ti;
	struct list_head async_queue;
	wait_queue_head_t async_sleep;
	unsigned int nr_async_pending;
	unsigned int threads;
	unsigned int shutdown;
	wait_queue_head_t wait_shutdown;
} iothread_t;

typedef struct tux_listen_s
{
	tux_proto_t *proto;
	struct socket *sock;
	unsigned int cloned;
} tux_listen_t;

struct tux_threadinfo
{
	tux_req_t *userspace_req;
	unsigned int started;
	struct task_struct *thread;
	iothread_t *iot;
	wait_queue_t wait_event [CONFIG_TUX_NUMSOCKETS];
	wait_queue_t stop;
	unsigned int pid;

	struct page *header_cache;
	unsigned int header_offset;

	unsigned int nr_requests;
	struct list_head all_requests;

	unsigned int nr_free_requests;
	spinlock_t free_requests_lock;
	struct list_head free_requests;

	spinlock_t work_lock;
	struct list_head work_pending;
	struct list_head lru;
	unsigned int nr_lru;

	unsigned int listen_error;
	tux_listen_t listen[CONFIG_TUX_NUMSOCKETS];

	struct semaphore gzip_sem;
	z_stream gzip_state;

	unsigned int cpu;
	unsigned int __padding[16];
};

typedef enum special_mimetypes {
	NORMAL_MIME_TYPE,
	MIME_TYPE_REDIRECT,
	MIME_TYPE_CGI,
	MIME_TYPE_MODULE,
} special_mimetypes_t;

#ifdef CONFIG_TUX_DEBUG
#if 0
extern inline void url_hist_hit (int size)
{
	unsigned int idx = size/1024;

	if (idx >= URL_HIST_SIZE)
		idx = URL_HIST_SIZE-1;
	kstat.url_hist_hits[idx]++;
}
extern inline void url_hist_miss (int size)
{
	unsigned int idx = size/1024;

	if (idx >= URL_HIST_SIZE)
		idx = URL_HIST_SIZE-1;
	kstat.url_hist_misses[idx]++;
}
#endif
extern void __check_req_list (tux_req_t *req, struct list_head *list);
# define check_req_list __check_req_list
#else
# define check_req_list(req, list) do { } while (0)
#endif

#define url_hist_hit(size) do { } while (0)
#define url_hist_miss(size) do { } while (0)

extern char tux_common_docroot[200];
extern char tux_http_subdocroot[200];
extern char tux_ftp_subdocroot[200];
extern char tux_logfile[200];
extern char tux_cgiroot[200];
extern char tux_404_page[200];
extern char tux_default_vhost[200];
extern char tux_extra_html_header[600];
extern unsigned int tux_extra_html_header_size;
extern int tux_cgi_uid;
extern int tux_cgi_gid;
extern unsigned int tux_clientport;
extern unsigned int tux_logging;
extern unsigned int tux_threads;
extern unsigned int tux_keepalive_timeout;
extern unsigned int tux_max_output_bandwidth;
extern unsigned int tux_max_backlog;
extern unsigned int tux_max_connect;
extern unsigned int tux_mode_forbidden;
extern unsigned int tux_mode_allowed;
extern unsigned int tux_logentry_align_order;
extern unsigned int tux_nonagle;
extern unsigned int tux_ack_pingpong;
extern unsigned int tux_push_all;
extern unsigned int tux_zerocopy_parse;
extern unsigned int tux_generate_etags;
extern unsigned int tux_generate_last_mod;
extern unsigned int tux_generate_cache_control;
extern unsigned int tux_ip_logging;
extern unsigned int tux_ftp_wait_close;
extern unsigned int tux_ftp_log_retr_only;
extern unsigned int tux_hide_unreadable;

typedef enum virtual_server {
	TUX_VHOST_NONE,
	TUX_VHOST_HOST,
	TUX_VHOST_IP,
	TUX_VHOST_IP_HOST,
} virtual_server_t;

extern unsigned int tux_virtual_server;
extern unsigned int mass_hosting_hash;
extern unsigned int strip_host_tail;
extern unsigned int tux_ftp_virtual_server;

extern unsigned int tux_max_object_size;
extern unsigned int tux_max_free_requests;
extern unsigned int tux_defer_accept;

extern struct socket * start_listening(tux_socket_t *listen, int nr);
extern void stop_listening(struct socket **sock);
extern void start_sysctl(void);
extern void end_sysctl(void);
extern void flush_request (tux_req_t *req, int cachemiss);
extern void unlink_tux_socket (tux_req_t *req);
extern void unlink_tux_data_socket (tux_req_t *req);
extern void unlink_tux_listen_socket (tux_req_t *req);
extern void link_tux_ftp_accept_socket (tux_req_t *req, struct socket *sock);
extern void link_tux_data_socket (tux_req_t *req, struct socket *sock);
extern void tux_push_req (tux_req_t *req);
extern int send_sync_buf (tux_req_t *req, struct socket *sock, const char *buf, const size_t length, unsigned long flags);
extern void __send_async_message (tux_req_t *req, const char *message, int status, unsigned int size, int push);
#define send_async_message(req,str,status,push) \
		__send_async_message(req,str,status,strlen(str),push)

extern void send_success (tux_req_t *req, struct socket *sock);
extern void send_async_err_not_found (tux_req_t *req);
extern void send_async_timed_out (tux_req_t *req);

extern void kfree_req (tux_req_t *req);
extern int accept_requests (threadinfo_t *ti);
extern int process_requests (threadinfo_t *ti, tux_req_t **user_req);
extern int flush_freequeue (threadinfo_t * ti);
extern int tux_flush_workqueue (threadinfo_t *ti);
extern tux_req_t * pick_userspace_req (threadinfo_t *ti);
extern atom_func_t redirect_request;
extern atom_func_t parse_request;
extern void queue_cachemiss (tux_req_t *req);
extern int start_cachemiss_threads (threadinfo_t *ti);
extern void stop_cachemiss_threads (threadinfo_t *ti);
struct file * tux_open_file(char *filename, int mode);
extern void start_log_thread (void);
extern void stop_log_thread (void);
extern void add_mimetype (char *new_ext, char *new_type, char *new_expire);
extern void free_mimetypes (void);
extern int lookup_object (tux_req_t *req, const unsigned int flag);
extern int handle_gzip_req (tux_req_t *req, unsigned int flags);
extern struct dentry * tux_lookup (tux_req_t *req, const char *filename, const unsigned int flag, struct vfsmount **mnt);
extern tcapi_template_t * lookup_tuxmodule (const char *filename);
extern int register_tuxmodule (tcapi_template_t *tcapi);
extern tcapi_template_t * unregister_tuxmodule (char *vfs_name);
extern tcapi_template_t * get_first_usermodule (void);
extern int user_register_module (user_req_t *u_info);
extern int user_unregister_module (user_req_t *u_info);
extern void unregister_all_tuxmodules (void);

typedef struct exec_param_s {
	char *command;
	char **argv;
	char **envp;
	unsigned int pipe_fds;
} exec_param_t;

extern pid_t tux_exec_process (char *command, char **argv, char **envp, int pipe_fds, exec_param_t *param, int wait);

extern void start_external_cgi (tux_req_t *req);
extern tcapi_template_t extcgi_tcapi;

extern void queue_output_req (tux_req_t *req, threadinfo_t *ti);
extern void queue_userspace_req (tux_req_t *req, threadinfo_t *ti);


extern void __log_request (tux_req_t *req);
extern inline void log_request (tux_req_t *req)
{
	if (tux_logging)
		__log_request(req);
}

extern int __connection_too_fast (tux_req_t *req);

#define connection_too_fast(req)				\
	({							\
		int __ret = 1;					\
		if (unlikely(tux_max_output_bandwidth))		\
			__ret = __connection_too_fast(req);	\
		__ret;						\
	})

extern void trunc_headers (tux_req_t *req);
extern int generic_send_file (tux_req_t *req, struct socket *sock, int cachemiss);
extern int tux_fetch_file (tux_req_t *req, int nonblock);

extern void postpone_request (tux_req_t *req);
extern int continue_request (int fd);
extern void tux_push_pending (struct sock *sk);
extern void zap_request (tux_req_t *req, int cachemiss);
extern int add_output_space_event (tux_req_t *req, struct socket *sock);

extern void reap_kids (void);
extern void unuse_frag (struct sk_buff *skb, skb_frag_t *frag);
extern skb_frag_t * build_dynbuf_frag (tux_req_t *req, unsigned int size);
extern int tux_permission (struct inode *inode);
extern void flush_all_signals (void);

#define D() Dprintk("{%s:%d}\n", __FILE__, __LINE__)

extern int nr_async_io_pending (void);

extern void __add_keepalive_timer (tux_req_t *req);
#define add_keepalive_timer(req)					\
do {									\
	if (tux_keepalive_timeout) {					\
		Dprintk("add_keepalive_timer(%p).\n", (req));		\
		__add_keepalive_timer(req);				\
	}								\
} while (0)
extern void __del_keepalive_timer (tux_req_t *req);
#define del_keepalive_timer(req)					\
do {									\
	if (tux_keepalive_timeout) {					\
		Dprintk("del_keepalive_timer(%p).\n", (req));		\
		__del_keepalive_timer(req);				\
	}								\
} while (0)

extern void del_output_timer (tux_req_t *req);
extern void output_timeout (tux_req_t *req);

extern void print_req (tux_req_t *req);

extern char tux_date [DATE_LEN];


extern int nr_async_io_pending (void);
extern void tux_exit (void);
extern char * get_abuf (tux_req_t *req, unsigned int max_size);
extern void send_abuf (tux_req_t *req, unsigned int size, unsigned long flags);


extern int idle_event (tux_req_t *req);
extern int output_space_event (tux_req_t *req);
extern cpumask_t tux_log_cpu_mask;
extern unsigned int tux_compression;
extern unsigned int tux_noid;
extern unsigned int tux_cgi_inherit_cpu;
extern unsigned int tux_zerocopy_header;
extern unsigned int tux_zerocopy_sendfile;
extern cpumask_t tux_cgi_cpu_mask;
extern tux_proto_t tux_proto_http;
extern tux_proto_t tux_proto_ftp;
extern unsigned int tux_all_userspace;
extern unsigned int tux_ignore_query;
extern unsigned int tux_redirect_logging;
extern unsigned int tux_referer_logging;
extern unsigned int tux_log_incomplete;
extern unsigned int tux_max_header_len;
extern unsigned int tux_cpu_offset;
extern unsigned int tux_ftp_login_message;

extern void drop_permissions (void);
extern int query_extcgi (tux_req_t *req);
extern int tux_chroot (char *dir);

extern void install_req_dentry (tux_req_t *req, struct dentry *dentry, struct vfsmount *mnt);
extern void release_req_dentry (tux_req_t *req);
extern void unidle_req (tux_req_t *req);
extern int nr_requests_used (void);

#define req_err(req) do { (req)->error = 1; Dprintk("request %p error at %s:%d.\n", req, __FILE__, __LINE__); } while (0)

#define enough_wspace(sk) (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk))
#define clear_keepalive(req) do { (req)->keep_alive = 0; Dprintk("keepalive cleared for req %p.\n", req); } while (0)

extern int print_all_requests (threadinfo_t *ti);
extern unsigned int tux_max_keepalives;
extern int time_unix2ls (time_t zulu, char *buf);
extern void last_mod_time(char * curr, const time_t t);
extern int mdtm_time(char * curr, const time_t t);
extern time_t parse_time(const char *str, const int str_len);

extern unsigned int nr_tux_threads;
extern threadinfo_t threadinfo[CONFIG_TUX_NUMTHREADS];

#define switch_docroot(req) do { if (((req)->docroot_dentry != current->fs->root) || ((req)->docroot_mnt != current->fs->rootmnt)) __switch_docroot(req); } while (0)
extern void __switch_docroot(tux_req_t *req);
extern void list_directory (tux_req_t *req, int cachemiss);
extern char * tux_print_path (tux_req_t *req, struct dentry *dentry, struct vfsmount *mnt, char *buf, unsigned int max_len);

extern unsigned int tux_http_dir_indexing;

int tux_gzip_compress (tux_req_t *req, unsigned char *data_in, unsigned char *data_out, __u32 *in_len, __u32 *out_len);

struct dentry * __tux_lookup (tux_req_t *req, const char *filename,
                         struct nameidata *base, struct vfsmount **mnt);

/* error codes for req->error */
#define TUX_ERROR_REDIRECT     1
#define TUX_ERROR_UNUSED       2
#define TUX_ERROR_CONN_CLOSE   3
#define TUX_ERROR_CONN_TIMEOUT 4

extern void __put_data_sock (tux_req_t *req);

static inline void put_data_sock (tux_req_t *req)
{
	if (req->data_sock)
		__put_data_sock(req);
}

#define socket_input(sock) \
	(!skb_queue_empty(&(sock)->sk->sk_receive_queue) || \
		!skb_queue_empty(&(sock)->sk->sk_error_queue))

#define tux_kmalloc(size)						\
({									\
	void *__ptr;							\
									\
	while (!(__ptr = kmalloc(size, GFP_KERNEL))) {			\
		if (net_ratelimit())					\
			printk(KERN_WARNING "tux: OOM at %s:%d (%d bytes).\n", \
				__FILE__, __LINE__, size);		\
		current->state = TASK_UNINTERRUPTIBLE;			\
		schedule_timeout(1);					\
	}								\
	__ptr;								\
})

#define tux_close(fd) sys_close(fd)

extern int init_tux_request_slabs(void);
extern void free_tux_request_slabs(void);

#endif
