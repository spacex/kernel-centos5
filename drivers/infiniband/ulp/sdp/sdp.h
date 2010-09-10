#ifndef _SDP_H_
#define _SDP_H_

#include <linux/workqueue.h>
#include <linux/wait.h>
#include <net/inet_sock.h>
#include <net/tcp.h> /* For urgent data flags */
#include <rdma/ib_verbs.h>

#define sdp_printk(level, sk, format, arg...)                \
	printk(level "sdp_sock(%d:%d): " format,             \
	       (sk) ? inet_sk(sk)->num : -1,                 \
	       (sk) ? ntohs(inet_sk(sk)->dport) : -1, ## arg)
#define sdp_warn(sk, format, arg...)                         \
	sdp_printk(KERN_WARNING, sk, format , ## arg)

#ifdef CONFIG_INFINIBAND_SDP_DEBUG
extern int sdp_debug_level;

#define sdp_dbg(sk, format, arg...)                          \
	do {                                                 \
		if (sdp_debug_level > 0)                     \
		sdp_printk(KERN_DEBUG, sk, format , ## arg); \
	} while (0)
#else /* CONFIG_INFINIBAND_SDP_DEBUG */
#define sdp_dbg(priv, format, arg...)                        \
	do { (void) (priv); } while (0)
#endif /* CONFIG_INFINIBAND_SDP_DEBUG */

#ifdef CONFIG_INFINIBAND_SDP_DEBUG_DATA
extern int sdp_data_debug_level;
#define sdp_dbg_data(sk, format, arg...)                     \
	do {                                                 \
		if (sdp_data_debug_level > 0)                \
		sdp_printk(KERN_DEBUG, sk, format , ## arg); \
	} while (0)
#else
#define sdp_dbg_data(priv, format, arg...)                   \
	do { (void) (priv); } while (0)
#endif

#define SDP_RESOLVE_TIMEOUT 1000
#define SDP_ROUTE_TIMEOUT 1000
#define SDP_RETRY_COUNT 5
#define SDP_KEEPALIVE_TIME (120 * 60 * HZ)

#define SDP_TX_SIZE 0x40
#define SDP_RX_SIZE 0x40

#define SDP_MAX_SEND_SKB_FRAGS (PAGE_SIZE > 0x8000 ? 1 : 0x8000 / PAGE_SIZE)
#define SDP_HEAD_SIZE (PAGE_SIZE / 2 + sizeof(struct sdp_bsdh))
#define SDP_NUM_WC 4

#define SDP_MIN_ZCOPY_THRESH    1024
#define SDP_MAX_ZCOPY_THRESH 1048576

#define SDP_OP_RECV 0x800000000LL
#define SDP_OP_SEND 0x400000000LL

enum sdp_mid {
	SDP_MID_HELLO = 0x0,
	SDP_MID_HELLO_ACK = 0x1,
	SDP_MID_DISCONN = 0x2,
	SDP_MID_CHRCVBUF = 0xB,
	SDP_MID_CHRCVBUF_ACK = 0xC,
	SDP_MID_DATA = 0xFF,
};

enum sdp_flags {
        SDP_OOB_PRES = 1 << 0,
        SDP_OOB_PEND = 1 << 1,
};

enum {
	SDP_MIN_BUFS = 2
};

enum {
	SDP_ERR_ERROR   = -4,
	SDP_ERR_FAULT   = -3,
	SDP_NEW_SEG     = -2,
	SDP_DO_WAIT_MEM = -1
};

struct rdma_cm_id;
struct rdma_cm_event;

struct sdp_bsdh {
	u8 mid;
	u8 flags;
	__u16 bufs;
	__u32 len;
	__u32 mseq;
	__u32 mseq_ack;
};

struct sdp_buf {
        struct sk_buff *skb;
        u64             mapping[SDP_MAX_SEND_SKB_FRAGS + 1];
};

struct sdp_sock {
	/* sk has to be the first member of inet_sock */
	struct inet_sock isk;
	struct list_head sock_list;
	struct list_head accept_queue;
	struct list_head backlog_queue;
	struct sock *parent;

	struct work_struct work;
	wait_queue_head_t wq;

	struct delayed_work time_wait_work;
	struct work_struct destroy_work;

	/* Like tcp_sock */
	u16 urg_data;
	u32 urg_seq;
	u32 copied_seq;
	u32 rcv_nxt;

	int write_seq;
	int snd_una;
	int pushed_seq;
	int xmit_size_goal;
	int nonagle;

	int time_wait;

	unsigned keepalive_time;

	/* tx_head/rx_head when keepalive timer started */
	unsigned keepalive_tx_head;
	unsigned keepalive_rx_head;

	/* Data below will be reset on error */
	/* rdma specific */
	struct rdma_cm_id *id;
	struct ib_qp *qp;
	struct ib_cq *cq;
	struct ib_mr *mr;
	struct ib_device *ib_device;

	/* SDP specific */
	struct sdp_buf *rx_ring;
	struct ib_recv_wr rx_wr;
	unsigned rx_head;
	unsigned rx_tail;
	unsigned mseq_ack;
	unsigned bufs;
	unsigned max_bufs;	/* Initial buffers offered by other side */
	unsigned min_bufs;	/* Low water mark to wake senders */

	int               remote_credits;
	int 		  poll_cq;

	struct sdp_buf   *tx_ring;
	unsigned          tx_head;
	unsigned          tx_tail;
	struct ib_send_wr tx_wr;

	/* SDP slow start */
	int rcvbuf_scale; 	/* local recv buf scale for each socket */
	int sent_request_head; 	/* mark the tx_head of the last send resize
				   request */
	int sent_request; 	/* 0 - not sent yet, 1 - request pending
				   -1 - resize done succesfully */
	int recv_request_head; 	/* mark the rx_head when the resize request
				   was recieved */
	int recv_request; 	/* flag if request to resize was recieved */
	int recv_frags; 	/* max skb frags in recv packets */
	int send_frags; 	/* max skb frags in send packets */

	/* BZCOPY data */
	int   zcopy_thresh;

	struct ib_sge ibsge[SDP_MAX_SEND_SKB_FRAGS + 1];
	struct ib_wc  ibwc[SDP_NUM_WC];
};

/* Context used for synchronous zero copy bcopy (BZCOY) */
struct bzcopy_state {
	unsigned char __user  *u_base;
	int                    u_len;
	int                    left;
	int                    page_cnt;
	int                    cur_page;
	int                    cur_offset;
	int                    busy;
	struct sdp_sock      *ssk;
	struct page         **pages;
};


extern struct proto sdp_proto;
extern struct workqueue_struct *sdp_workqueue;

extern atomic_t sdp_current_mem_usage;
extern spinlock_t sdp_large_sockets_lock;

/* just like TCP fs */
struct sdp_seq_afinfo {
	struct module           *owner;
	char                    *name;
	sa_family_t             family;
	int                     (*seq_show) (struct seq_file *m, void *v);
	struct file_operations  *seq_fops;
};

struct sdp_iter_state {
	sa_family_t             family;
	int                     num;
	struct seq_operations   seq_ops;
};

static inline struct sdp_sock *sdp_sk(const struct sock *sk)
{
	        return (struct sdp_sock *)sk;
}

static inline void sdp_set_error(struct sock *sk, int err)
{
	sk->sk_err = -err;
	if (sk->sk_socket)
		sk->sk_socket->state = SS_UNCONNECTED;

	sk->sk_state = TCP_CLOSE;

	if (sdp_sk(sk)->time_wait) {
		sdp_dbg(sk, "%s: destroy in time wait state\n", __func__);
		sdp_sk(sk)->time_wait = 0;
		queue_work(sdp_workqueue, &sdp_sk(sk)->destroy_work);
	}

	sk->sk_error_report(sk);
}

static inline void sdp_set_state(struct sock *sk, int state)
{
	sk->sk_state = state;
}

extern struct workqueue_struct *sdp_workqueue;

int sdp_cma_handler(struct rdma_cm_id *, struct rdma_cm_event *);
void sdp_reset(struct sock *sk);
void sdp_reset_sk(struct sock *sk, int rc);
void sdp_time_wait_destroy_sk(struct sdp_sock *ssk);
void sdp_completion_handler(struct ib_cq *cq, void *cq_context);
void sdp_work(struct work_struct *work);
int sdp_post_credits(struct sdp_sock *ssk);
void sdp_post_send(struct sdp_sock *ssk, struct sk_buff *skb, u8 mid);
void sdp_post_recvs(struct sdp_sock *ssk);
int sdp_poll_cq(struct sdp_sock *ssk, struct ib_cq *cq);
void sdp_post_sends(struct sdp_sock *ssk, int nonagle);
void sdp_destroy_work(struct work_struct *work);
void sdp_time_wait_work(struct work_struct *work);
struct sk_buff *sdp_recv_completion(struct sdp_sock *ssk, int id);
struct sk_buff *sdp_send_completion(struct sdp_sock *ssk, int mseq);
void sdp_urg(struct sdp_sock *ssk, struct sk_buff *skb);
void sdp_add_sock(struct sdp_sock *ssk);
void sdp_remove_sock(struct sdp_sock *ssk);
void sdp_remove_large_sock(struct sdp_sock *ssk);
int sdp_resize_buffers(struct sdp_sock *ssk, u32 new_size);
void sdp_post_keepalive(struct sdp_sock *ssk);
void sdp_start_keepalive_timer(struct sock *sk);
void sdp_bzcopy_write_space(struct sdp_sock *ssk);

#endif
