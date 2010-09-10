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

#define SDP_TX_SIZE 0x40
#define SDP_RX_SIZE 0x40

#define SDP_MAX_SEND_SKB_FRAGS (PAGE_SIZE > 0x8000 ? 1 : 0x8000 / PAGE_SIZE)

#define SDP_NUM_WC 4

#define SDP_OP_RECV 0x800000000LL

enum sdp_mid {
	SDP_MID_HELLO = 0x0,
	SDP_MID_HELLO_ACK = 0x1,
	SDP_MID_DISCONN = 0x2,
	SDP_MID_DATA = 0xFF,
};

enum sdp_flags {
        SDP_OOB_PRES = 1 << 0,
        SDP_OOB_PEND = 1 << 1,
};

enum {
	SDP_MIN_BUFS = 2
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
        dma_addr_t      mapping[SDP_MAX_SEND_SKB_FRAGS + 1];
};

struct sdp_sock {
	/* sk has to be the first member of inet_sock */
	struct inet_sock isk;
	struct list_head accept_queue;
	struct list_head backlog_queue;
	struct sock *parent;

	struct work_struct work;
	wait_queue_head_t wq;

	struct work_struct time_wait_work;
	struct work_struct destroy_work;

	/* Like tcp_sock */
	u16 urg_data;
	u32 urg_seq;
	u32 copied_seq;
	u32 rcv_nxt;

	int write_seq;
	int pushed_seq;
	int xmit_size_goal;
	int nonagle;

	int time_wait;

	/* Data below will be reset on error */
	/* rdma specific */
	struct rdma_cm_id *id;
	struct ib_qp *qp;
	struct ib_cq *cq;
	struct ib_mr *mr;
	struct device *dma_device;

	/* SDP specific */
	struct sdp_buf *rx_ring;
	struct ib_recv_wr rx_wr;
	unsigned rx_head;
	unsigned rx_tail;
	unsigned mseq_ack;
	unsigned bufs;

	int               remote_credits;
	int 		  poll_cq;

	struct sdp_buf   *tx_ring;
	unsigned          tx_head;
	unsigned          tx_tail;
	struct ib_send_wr tx_wr;

	struct ib_sge ibsge[SDP_MAX_SEND_SKB_FRAGS + 1];
	struct ib_wc  ibwc[SDP_NUM_WC];
};

extern struct proto sdp_proto;
extern struct workqueue_struct *sdp_workqueue;

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
void sdp_work(void *);
int sdp_post_credits(struct sdp_sock *ssk);
void sdp_post_send(struct sdp_sock *ssk, struct sk_buff *skb, u8 mid);
void sdp_post_recvs(struct sdp_sock *ssk);
int sdp_poll_cq(struct sdp_sock *ssk, struct ib_cq *cq);
void sdp_post_sends(struct sdp_sock *ssk, int nonagle);
void sdp_destroy_work(void *data);
void sdp_time_wait_work(void *data);
struct sk_buff *sdp_recv_completion(struct sdp_sock *ssk, int id);
struct sk_buff *sdp_send_completion(struct sdp_sock *ssk, int mseq);
void sdp_urg(struct sdp_sock *ssk, struct sk_buff *skb);

#endif
