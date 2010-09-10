/*
 * Copyright 2008 Cisco Systems, Inc.  All rights reserved.
 * Copyright 2007 Nuova Systems, Inc.  All rights reserved.
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef _FNIC_H_
#define _FNIC_H_

#include <linux/mempool.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_transport_fc.h>
#include <scsi/libfc.h>
#include "fnic_io.h"
#include "fnic_res.h"
#include "vnic_dev.h"
#include "vnic_wq.h"
#include "vnic_rq.h"
#include "vnic_cq.h"
#include "vnic_wq_copy.h"
#include "vnic_intr.h"
#include "vnic_stats.h"
#include "vnic_scsi.h"

#define DRV_NAME		"fnic"
#define DRV_DESCRIPTION		"Cisco FCoE HBA Driver"
#define DRV_VERSION		"1.0.0"
#define PFX			DRV_NAME ": "
#define DFX                     DRV_NAME "%d: "

/* Define FNIC_DEBUG to turn debugging on */
#ifdef FNIC_DEBUG
#define FNIC_DBG(fmt, args...)						\
	do {								\
		printk(KERN_DEBUG fmt, ##args);		                \
	} while (0)
#else
#define FNIC_DBG(fmt, args...)
#endif

#define vnic_fc_config  vnic_scsi_config

#define DESC_CLEAN_LOW_WATERMARK 8
#define FNIC_MAX_IO_REQ		2048		/* scsi_cmnd tag map entries */
#define	FNIC_IO_LOCKS		32		/* I/O locks: power of 2 */
#define FNIC_DFLT_QUEUE_DEPTH	32
#define	FNIC_STATS_RATE_LIMIT	4		/* max stats requests per sec */

/*
 * Tag bits used for special requests.
 */
#define BIT(nr)			(1UL << (nr))
#define FNIC_TAG_ABORT		BIT(30)		/* tag bit indicating abort */
#define FNIC_TAG_DEV_RST	BIT(29)		/* indicates device reset */
#define FNIC_TAG_MASK		(BIT(24) - 1)	/* mask for lookup */
#define FNIC_NO_TAG             -1

/*
 * Usage of the scsi_cmnd scratchpad.
 * These fields are locked by the hashed io_req_lock.
 */
#define CMD_SP(Cmnd)		((Cmnd)->SCp.ptr)
#define CMD_STATE(Cmnd)		((Cmnd)->SCp.phase)
#define CMD_ABTS_STATUS(Cmnd)	((Cmnd)->SCp.Message)
#define CMD_LR_STATUS(Cmnd)	((Cmnd)->SCp.have_data_in)
#define CMD_TAG(Cmnd)           ((Cmnd)->SCp.sent_command)

#define FCPIO_INVALID_CODE 0x100 /* hdr_status value unused by firmware */

#define FNIC_LUN_RESET_TIMEOUT	     10000	/* mSec */
#define FNIC_HOST_RESET_TIMEOUT	     10000	/* mSec */
#define FNIC_RMDEVICE_TIMEOUT        1000       /* mSec */
#define FNIC_HOST_RESET_SETTLE_TIME  30         /* Sec */

#define	FNIC_MAX_LUN            1023
#define FNIC_MAX_FCP_TARGET     256

extern const char *fnic_state_str[];

enum fnic_intx_intr_index {
	FNIC_INTX_WQ_RQ_COPYWQ,
	FNIC_INTX_ERR,
	FNIC_INTX_NOTIFY,
	FNIC_INTX_INTR_MAX,
};

enum fnic_msix_intr_index {
	FNIC_MSIX_RQ,
	FNIC_MSIX_WQ,
	FNIC_MSIX_WQ_COPY,
	FNIC_MSIX_ERR_NOTIFY,
	FNIC_MSIX_INTR_MAX,
};

struct pt_regs;

struct fnic_msix_entry {
	int requested;
	char devname[IFNAMSIZ];
	irqreturn_t (*isr)(int, void *, struct pt_regs *);
	void *devid;
};

enum fnic_state {
	FNIC_IN_FC_MODE = 0,
	FNIC_IN_FC_TRANS_ETH_MODE,
	FNIC_IN_ETH_MODE,
	FNIC_IN_ETH_TRANS_FC_MODE,
};

#define FNIC_WQ_COPY_MAX 1
#define FNIC_WQ_MAX 1
#define FNIC_RQ_MAX 1
#define FNIC_CQ_MAX (FNIC_WQ_COPY_MAX + FNIC_WQ_MAX + FNIC_RQ_MAX)

/* Per-instance private data structure */
struct fnic {
	struct fc_lport *lport;
	struct vnic_dev_bar bar0;

	struct msix_entry msix_entry[FNIC_MSIX_INTR_MAX];
	struct fnic_msix_entry msix[FNIC_MSIX_INTR_MAX];

	struct vnic_stats *stats;
	unsigned long stats_time;	/* time of stats update */
	struct vnic_nic_cfg *nic_cfg;
	char name[IFNAMSIZ];
	u32 fnic_no;
	struct timer_list notify_timer; /* used for MSI interrupts */

	unsigned int err_intr_offset;
	unsigned int link_intr_offset;

	unsigned int wq_count;
	unsigned int cq_count;

	u32 fcoui_mode:1;		/* use fcoui address*/
	u32 vlan_hw_insert:1;	        /* let hw insert the tag */
	u32 in_remove:1;                /* fnic device in removal */

	struct completion *remove_wait; /* device remove thread blocks */
	struct completion *reset_wait;  /* host reset thread blocks */

	struct fc_frame *flogi;
	struct fc_frame *flogi_resp;
	u16 flogi_oxid;
	unsigned long s_id;
	enum fnic_state state;
	spinlock_t fnic_lock;

	u16 vlan_id;	                /* VLAN tag including priority */
	u8 mac_addr[ETH_ALEN];
	u8 dest_addr[ETH_ALEN];
	u8 data_src_addr[ETH_ALEN];
	u64 fcp_input_bytes;		/* internal statistic */
	u64 fcp_output_bytes;		/* internal statistic */

	struct pci_dev *pdev;
	struct vnic_fc_config config;
	struct vnic_dev *vdev;
	unsigned int raw_wq_count;
	unsigned int wq_copy_count;
	unsigned int rq_count;
	int fw_ack_index[FNIC_WQ_COPY_MAX];
	unsigned short fw_ack_recd[FNIC_WQ_COPY_MAX];
	unsigned short wq_copy_desc_low[FNIC_WQ_COPY_MAX];
	unsigned int intr_count;
	u32 __iomem *legacy_pba;
	struct fnic_host_tag *tags;
	mempool_t *io_req_pool;
	mempool_t *io_sgl_pool[FNIC_SGL_NUM_CACHES];
	spinlock_t io_req_lock[FNIC_IO_LOCKS];	/* locks for scsi cmnds */

	/* copy work queue cache line section */
	____cacheline_aligned struct vnic_wq_copy wq_copy[FNIC_WQ_COPY_MAX];
	/* completion queue cache line section */
	____cacheline_aligned struct vnic_cq cq[FNIC_CQ_MAX];

	spinlock_t wq_copy_lock[FNIC_WQ_COPY_MAX];

	/* work queue cache line section */
	____cacheline_aligned struct vnic_wq wq[FNIC_WQ_MAX];
	spinlock_t wq_lock[FNIC_WQ_MAX];

	/* receive queue cache line section */
	____cacheline_aligned struct vnic_rq rq[FNIC_RQ_MAX];

	/* interrupt resource cache line section */
	____cacheline_aligned struct vnic_intr intr[FNIC_MSIX_INTR_MAX];
};

/* This is used to pass incoming frames, link notifications from ISR
 * to fnic thread
 */
enum fnic_thread_event_type {
	EV_TYPE_LINK_DOWN = 0,
	EV_TYPE_LINK_UP,
	EV_TYPE_FRAME,
};

/* ISR allocates and inserts an event into a list.
 * Fnic thread processes the event
 */
struct fnic_event {
	/* list head has to the first field*/
	struct list_head list;
	struct fc_frame *fp;
	struct fnic *fnic;
	enum   fnic_thread_event_type ev_type;
	u32    is_flogi_resp_frame:1;
};

static inline void fnic_fc_frame_free_irq(struct fc_frame *fp)
{
	dev_kfree_skb_irq(fp_skb(fp));
}

static inline void fnic_fc_frame_free(struct fc_frame *fp)
{
	dev_kfree_skb(fp_skb(fp));
}

static inline void fnic_fc_frame_free_any(struct fc_frame *fp)
{
	dev_kfree_skb_any(fp_skb(fp));
}

/* Fnic Thread for handling FCS Rx Frames*/
extern struct task_struct *fnic_thread;
extern struct list_head   fnic_eventlist;
extern spinlock_t         fnic_eventlist_lock;
extern struct kmem_cache   *fnic_ev_cache;
extern struct kmem_cache   *fnic_fc_frame_cache;
extern struct class_device_attribute *fnic_attrs[];

void fnic_clear_intr_mode(struct fnic *fnic);
int fnic_set_intr_mode(struct fnic *fnic);
void fnic_free_intr(struct fnic *fnic);
int fnic_request_intr(struct fnic *fnic);

int fnic_send(struct fc_lport *, struct fc_frame *);
int fnic_queuecommand(struct scsi_cmnd *, void (*done)(struct scsi_cmnd *));
int fnic_abort_cmd(struct scsi_cmnd *);
int fnic_device_reset(struct scsi_cmnd *);
int fnic_host_reset(struct scsi_cmnd *);
int fnic_reset(struct Scsi_Host *);
void fnic_scsi_cleanup(struct fc_lport *);
void fnic_scsi_abort_io(struct fc_lport *);
int fnic_wq_copy_cmpl_handler(struct fnic *fnic, int);
int fnic_wq_cmpl_handler(struct fnic *fnic, int);
int fnic_flogi_reg_handler(struct fnic *fnic);
void fnic_wq_copy_cleanup_handler(struct vnic_wq_copy *wq,
				  struct fcpio_host_req *desc);
int fnic_fw_reset_handler(struct fnic *fnic);

void fnic_free_wq_buf(struct vnic_wq *wq, struct vnic_wq_buf *buf);

int fnic_fc_thread(void *arg);
int fnic_rq_cmpl_handler(struct fnic *fnic, int);
int fnic_alloc_rq_frame(struct vnic_rq *rq);
void fnic_free_rq_buf(struct vnic_rq *rq, struct vnic_rq_buf *buf);

void fnic_log_q_error(struct fnic *fnic);
void fnic_notify_check(struct fnic *fnic);
int fnic_send_frame(struct fnic *fnic, struct fc_frame *fp);

#endif /* _FNIC_H_ */
