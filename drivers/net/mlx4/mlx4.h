/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2005, 2006, 2007 Cisco Systems.  All rights reserved.
 * Copyright (c) 2005, 2006, 2007, 2008 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2004 Voltaire, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
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

#ifndef MLX4_H
#define MLX4_H

#include <linux/mutex.h>
#include <linux/radix-tree.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <linux/workqueue.h>

#include <linux/mlx4/device.h>
#include <linux/mlx4/driver.h>
#include <linux/mlx4/doorbell.h>
#include <linux/mlx4/cmd.h>
#include <rdma/ib_verbs.h>

#define DRV_NAME	"mlx4_core"
#define PFX		DRV_NAME ": "
#define DRV_VERSION	"1.0"
#define DRV_RELDATE	"April 4, 2008"

enum {
	MLX4_HCR_BASE		= 0x80680,
	MLX4_HCR_SRIOV_BASE	= 0x4080680, /* good for SRIOV FW ony */
	MLX4_HCR_SIZE		= 0x0001c,
	MLX4_CLR_INT_SIZE	= 0x00008,
	MLX4_SLAVE_COMM_BASE	= 0x0,
	MLX4_COMM_PAGESIZE	= 0x1000
};

enum {
	MLX4_MGM_ENTRY_SIZE	=  0x100,
	MLX4_QP_PER_MGM		= 4 * (MLX4_MGM_ENTRY_SIZE / 16 - 2),
	MLX4_MTT_ENTRY_PER_SEG	= 8
};

enum {
	MLX4_NUM_PDS		= 1 << 15,
	MLX4_SLAVE_PD_SHIFT	= 17, /* the 7 msbs encode the slave id */
};

enum {
	MLX4_CMPT_TYPE_QP	= 0,
	MLX4_CMPT_TYPE_SRQ	= 1,
	MLX4_CMPT_TYPE_CQ	= 2,
	MLX4_CMPT_TYPE_EQ	= 3,
	MLX4_CMPT_NUM_TYPE
};

enum {
	MLX4_CMPT_SHIFT		= 24,
	MLX4_NUM_CMPTS		= MLX4_CMPT_NUM_TYPE << MLX4_CMPT_SHIFT
};

#define MLX4_COMM_TIME		10000
enum {
	MLX4_COMM_CMD_RESET,
	MLX4_COMM_CMD_VHCR0,
	MLX4_COMM_CMD_VHCR1,
	MLX4_COMM_CMD_VHCR2,
	MLX4_COMM_CMD_VHCR_EN,
	MLX4_COMM_CMD_VHCR_POST
};

enum mlx4_resource {
	RES_QP,
	RES_CQ,
	RES_SRQ,
	RES_MPT,
	RES_MTT,
	RES_MAC,
	RES_VLAN,
	RES_MCAST
};

enum mlx4_alloc_mode {
	ICM_RESERVE_AND_ALLOC,
	ICM_RESERVE,
	ICM_ALLOC,
	ICM_MAC_VLAN,
};

enum {
	MLX4_MFUNC_MAX		= 64,
	MLX4_MFUNC_EQ_NUM	= 4,
	MLX4_MFUNC_MAX_EQES     = 8,
	MLX4_MFUNC_EQE_MASK     = (MLX4_MFUNC_MAX_EQES - 1)
};

#ifdef CONFIG_MLX4_DEBUG
extern int mlx4_debug_level;

#define mlx4_dbg(mdev, format, arg...)					\
	do {								\
		if (mlx4_debug_level)					\
			dev_printk(KERN_DEBUG, &mdev->pdev->dev, format, ## arg); \
	} while (0)

#else /* CONFIG_MLX4_DEBUG */

#define mlx4_dbg(mdev, format, arg...) do { (void) mdev; } while (0)

#endif /* CONFIG_MLX4_DEBUG */

#define mlx4_err(mdev, format, arg...) \
	dev_err(&mdev->pdev->dev, format, ## arg)
#define mlx4_info(mdev, format, arg...) \
	dev_info(&mdev->pdev->dev, format, ## arg)
#define mlx4_warn(mdev, format, arg...) \
	dev_warn(&mdev->pdev->dev, format, ## arg)

extern int mlx4_blck_lb;

#define MLX4_VF					(1 << 0)
#define MLX4_VDEVICE(vendor, device, flags)	\
	PCI_VDEVICE(vendor, device), (flags)

#define MLX4_MAX_NUM_PF		16
#define MLX4_MAX_NUM_VF		64
#define MLX4_MAX_NUM_SLAVES	(MLX4_MAX_NUM_PF + MLX4_MAX_NUM_VF)

struct mlx4_bitmap {
	u32			last;
	u32			top;
	u32			max;
	u32                     reserved_top;
	u32			mask;
	spinlock_t		lock;
	unsigned long	       *table;
};

struct mlx4_buddy {
	unsigned long	      **bits;
	unsigned int	       *num_free;
	int			max_order;
	spinlock_t		lock;
};

struct mlx4_icm;

struct mlx4_icm_table {
	u64			virt;
	int			num_icm;
	int			num_obj;
	int			obj_size;
	int			lowmem;
	int			coherent;
	struct mutex		mutex;
	struct mlx4_icm	      **icm;
};

struct mlx4_eq {
	struct mlx4_dev	       *dev;
	void __iomem	       *doorbell;
	int			eqn;
	u32			cons_index;
	u16			irq;
	u16			have_irq;
	int			nent;
	int			load;
	struct mlx4_buf_list   *page_list;
	struct mlx4_mtt		mtt;
};

struct mlx4_profile {
	int			num_qp;
	int			rdmarc_per_qp;
	int			num_srq;
	int			num_cq;
	int			num_mcg;
	int			num_mpt;
	int			num_mtt;
};

struct mlx4_fw {
	u64			clr_int_base;
	u64			catas_offset;
	u64			comm_base;
	struct mlx4_icm	       *fw_icm;
	struct mlx4_icm	       *aux_icm;
	u32			catas_size;
	u16			fw_pages;
	u8			clr_int_bar;
	u8			catas_bar;
	u8			comm_bar;
};

struct mlx4_comm {
	u32			slave_write;
	u32			slave_read;
};

struct mlx4_slave_eqe {
	u8 type;
	u8 port;
	u32 param;
};

struct mlx4_mcast_entry {
	struct list_head list;
	u64 addr;
};

#define VLAN_FLTR_SIZE	128
struct mlx4_vlan_fltr {
	__be32 entry[VLAN_FLTR_SIZE];
};

struct mlx4_slave_state {
	u8 comm_toggle;
	u8 last_cmd;
	u8 init_port_mask;
	u8 pf_num;
	dma_addr_t vhcr_dma;
	u16 mtu[MLX4_MAX_PORTS + 1];
	__be32 ib_cap_mask[MLX4_MAX_PORTS + 1];
	struct mlx4_slave_eqe eq[MLX4_MFUNC_MAX_EQES];
	struct list_head mcast_filters[MLX4_MAX_PORTS + 1];
	struct mlx4_vlan_fltr *vlan_filter[MLX4_MAX_PORTS + 1];
	u16 eq_pi;
	u16 eq_ci;
	int sqp_start;
	spinlock_t lock;
};

struct mlx4_mfunc_master_ctx {
	struct mlx4_slave_state *slave_state;
	int			init_port_ref[MLX4_MAX_PORTS + 1];
	u16			max_mtu[MLX4_MAX_PORTS + 1];
	int			disable_mcast_ref[MLX4_MAX_PORTS + 1];
};

struct mlx4_vhcr {
	u64	in_param;
	u64	out_param;
	u32	in_modifier;
	u32	timeout;
	u16	op;
	u16	token;
	u8	op_modifier;
	int	errno;
};

struct mlx4_mfunc {
	struct mlx4_comm __iomem       *comm;
	struct workqueue_struct	       *comm_wq;
	struct delayed_work	        comm_work;
	struct mlx4_vhcr	       *vhcr;
	dma_addr_t			vhcr_dma;

	struct mlx4_mfunc_master_ctx	master;
	u32				demux_sqp[MLX4_MFUNC_MAX];
};

struct mlx4_cmd {
	struct pci_pool	       *pool;
	void __iomem	       *hcr;
	struct mutex		hcr_mutex;
	struct semaphore	poll_sem;
	struct semaphore	event_sem;
	int			max_cmds;
	spinlock_t		context_lock;
	int			free_head;
	struct mlx4_cmd_context *context;
	u16			token_mask;
	u8			use_events;
	u8			toggle;
	u8			comm_toggle;
};

struct mlx4_uar_table {
	struct mlx4_bitmap	bitmap;
};

struct mlx4_mr_table {
	struct mlx4_bitmap	mpt_bitmap;
	struct mlx4_buddy	mtt_buddy;
	u64			mtt_base;
	u64			mpt_base;
	struct mlx4_icm_table	mtt_table;
	struct mlx4_icm_table	dmpt_table;
};

struct mlx4_cq_table {
	struct mlx4_bitmap	bitmap;
	spinlock_t		lock;
	struct radix_tree_root	tree;
	struct mlx4_icm_table	table;
	struct mlx4_icm_table	cmpt_table;
};

struct mlx4_eq_table {
	struct mlx4_bitmap	bitmap;
	char		       *irq_names;
	void __iomem	       *clr_int;
	void __iomem	      **uar_map;
	u32			clr_mask;
	struct mlx4_eq	       *eq;
	struct mlx4_icm_table	table;
	struct mlx4_icm_table	cmpt_table;
	int			have_irq;
	u8			inta_pin;
};

struct mlx4_srq_table {
	struct mlx4_bitmap	bitmap;
	spinlock_t		lock;
	struct radix_tree_root	tree;
	struct mlx4_icm_table	table;
	struct mlx4_icm_table	cmpt_table;
};

struct mlx4_qp_table {
	struct mlx4_bitmap	bitmap;
	u32			rdmarc_base;
	int			rdmarc_shift;
	spinlock_t		lock;
	struct mlx4_icm_table	qp_table;
	struct mlx4_icm_table	auxc_table;
	struct mlx4_icm_table	altc_table;
	struct mlx4_icm_table	rdmarc_table;
	struct mlx4_icm_table	cmpt_table;
};

struct mlx4_mcg_table {
	struct mutex		mutex;
	struct mlx4_bitmap	bitmap;
	struct mlx4_icm_table	table;
};

struct mlx4_catas_err {
	u32 __iomem	       *map;
	struct timer_list	timer;
	struct list_head	list;
};

struct mlx4_mac_table {
#define MLX4_MAX_MAC_NUM	128
#define MLX4_MAC_TABLE_SIZE	(MLX4_MAX_MAC_NUM << 3)
	__be64 entries[MLX4_MAX_MAC_NUM];
	struct mutex mutex;
	int total;
	int max;
};

struct mlx4_vlan_table {
#define MLX4_MAX_VLAN_NUM	128
#define MLX4_VLAN_TABLE_SIZE	(MLX4_MAX_VLAN_NUM << 2)
	__be32 entries[MLX4_MAX_VLAN_NUM];
	int refs[MLX4_MAX_VLAN_NUM];
	struct semaphore vlan_sem;
	int total;
	int max;
};



#define SET_PORT_GEN_ALL_VALID		0x7
#define SET_PORT_PROMISC_SHIFT		31
#define SET_PORT_MC_PROMISC_SHIFT	30

enum {
	MCAST_DIRECT_ONLY	= 0,
	MCAST_DIRECT		= 1,
	MCAST_DEFAULT		= 2
};


struct mlx4_set_port_general_context {
	u8 reserved[3];
	u8 flags;
	u16 reserved2;
	__be16 mtu;
	u8 pptx;
	u8 pfctx;
	u16 reserved3;
	u8 pprx;
	u8 pfcrx;
	u16 reserved4;
};

struct mlx4_set_port_rqp_calc_context {
	__be32 base_qpn;
	u8 rererved;
	u8 n_mac;
	u8 n_vlan;
	u8 n_prio;
	u8 reserved2[3];
	u8 mac_miss;
	u8 intra_no_vlan;
	u8 no_vlan;
	u8 intra_vlan_miss;
	u8 vlan_miss;
	u8 reserved3[3];
	u8 no_vlan_prio;
	__be32 promisc;
	__be32 mcast;
};

struct mlx4_port_info {
	struct mlx4_dev		*dev;
	int			port;
	char			dev_name[16];
	struct device_attribute port_attr;
	enum mlx4_port_type	tmp_type;
	struct mlx4_mac_table	mac_table;
	struct mlx4_vlan_table	vlan_table;
	int			base_qpn;
};

struct mlx4_sense {
	struct mlx4_dev		*dev;
	u8			do_sense_port[MLX4_MAX_PORTS + 1];
	u8			sense_allowed[MLX4_MAX_PORTS + 1];
	struct delayed_work	sense_poll;
	struct workqueue_struct	*sense_wq;
	u32			resched;
};

extern struct mutex drv_mutex;

struct mlx4_priv {
	struct mlx4_dev		dev;

	struct list_head	dev_list;
	struct list_head	ctx_list;
	spinlock_t		ctx_lock;

	struct list_head        pgdir_list;
	struct mutex            pgdir_mutex;

	struct mlx4_fw		fw;
	struct mlx4_cmd		cmd;
	struct mlx4_mfunc	mfunc;

	struct mlx4_bitmap	pd_bitmap;
	struct mlx4_uar_table	uar_table;
	struct mlx4_mr_table	mr_table;
	struct mlx4_cq_table	cq_table;
	struct mlx4_eq_table	eq_table;
	struct mlx4_srq_table	srq_table;
	struct mlx4_qp_table	qp_table;
	struct mlx4_mcg_table	mcg_table;

	struct mlx4_catas_err	catas_err;
	u32			catas_state;
	u32			tout_counter;

	void __iomem	       *clr_base;

	struct mlx4_port_info	port[MLX4_MAX_PORTS + 1];
	struct device_attribute trigger_attr;
	int                     trig;
	int                     changed_ports;
	struct mlx4_sense       sense;
	struct mutex		port_mutex;
};

static inline struct mlx4_priv *mlx4_priv(struct mlx4_dev *dev)
{
	return container_of(dev, struct mlx4_priv, dev);
}

#define MLX4_SENSE_RANGE	(HZ * 3)

u32 mlx4_bitmap_alloc(struct mlx4_bitmap *bitmap);
void mlx4_bitmap_free(struct mlx4_bitmap *bitmap, u32 obj);
u32 mlx4_bitmap_alloc_range(struct mlx4_bitmap *bitmap, int cnt, int align);
void mlx4_bitmap_free_range(struct mlx4_bitmap *bitmap, u32 obj, int cnt);
int mlx4_bitmap_init(struct mlx4_bitmap *bitmap, u32 num, u32 mask,
		     u32 reserved_bot, u32 resetrved_top);
int mlx4_bitmap_init_no_mask(struct mlx4_bitmap *bitmap, u32 num,
			     u32 reserved_bot, u32 reserved_top);
void mlx4_bitmap_cleanup(struct mlx4_bitmap *bitmap);

int mlx4_reset(struct mlx4_dev *dev);

int mlx4_alloc_eq_table(struct mlx4_dev *dev);
void mlx4_free_eq_table(struct mlx4_dev *dev);
void mlx4_slave_event(struct mlx4_dev *dev, int slave, u8 type, u8 port, u32 param);
int mlx4_GET_EVENT_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
						 struct mlx4_cmd_mailbox *inbox,
						 struct mlx4_cmd_mailbox *outbox);

int mlx4_init_pd_table(struct mlx4_dev *dev);
int mlx4_init_uar_table(struct mlx4_dev *dev);
int mlx4_init_mr_table(struct mlx4_dev *dev);
int mlx4_init_eq_table(struct mlx4_dev *dev);
int mlx4_init_cq_table(struct mlx4_dev *dev);
int mlx4_init_qp_table(struct mlx4_dev *dev);
int mlx4_init_srq_table(struct mlx4_dev *dev);
int mlx4_init_mcg_table(struct mlx4_dev *dev);

void mlx4_cleanup_pd_table(struct mlx4_dev *dev);
void mlx4_cleanup_uar_table(struct mlx4_dev *dev);
void mlx4_cleanup_mr_table(struct mlx4_dev *dev);
void mlx4_cleanup_eq_table(struct mlx4_dev *dev);
void mlx4_cleanup_cq_table(struct mlx4_dev *dev);
void mlx4_cleanup_qp_table(struct mlx4_dev *dev);
void mlx4_cleanup_srq_table(struct mlx4_dev *dev);
void mlx4_cleanup_mcg_table(struct mlx4_dev *dev);

int mlx4_qp_alloc_icm(struct mlx4_dev *dev, int qpn);
void mlx4_qp_free_icm(struct mlx4_dev *dev, int qpn);
int mlx4_cq_alloc_icm(struct mlx4_dev *dev, int *cqn);
void mlx4_cq_free_icm(struct mlx4_dev *dev, int cqn);
int mlx4_srq_alloc_icm(struct mlx4_dev *dev, int *srqn);
void mlx4_srq_free_icm(struct mlx4_dev *dev, int srqn);
int mlx4_mr_reserve(struct mlx4_dev *dev);
void mlx4_mr_release(struct mlx4_dev *dev, u32 index);
int mlx4_mr_alloc_icm(struct mlx4_dev *dev, u32 index);
void mlx4_mr_free_icm(struct mlx4_dev *dev, u32 index);
u32 mlx4_alloc_mtt_range(struct mlx4_dev *dev, int order);
void mlx4_free_mtt_range(struct mlx4_dev *dev, u32 first_seg, int order);
int mlx4_WRITE_MTT_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
						 struct mlx4_cmd_mailbox *inbox,
						 struct mlx4_cmd_mailbox *outbox);

void mlx4_start_catas_poll(struct mlx4_dev *dev);
void mlx4_stop_catas_poll(struct mlx4_dev *dev);
int mlx4_catas_init(void);
void mlx4_catas_cleanup(void);
int mlx4_restart_one(struct pci_dev *pdev);
int mlx4_register_device(struct mlx4_dev *dev);
void mlx4_unregister_device(struct mlx4_dev *dev);
void mlx4_dispatch_event(struct mlx4_dev *dev, enum mlx4_dev_event type, int port);

struct mlx4_dev_cap;
struct mlx4_init_hca_param;

u64 mlx4_make_profile(struct mlx4_dev *dev,
		      struct mlx4_profile *request,
		      struct mlx4_dev_cap *dev_cap,
		      struct mlx4_init_hca_param *init_hca);

void mlx4_slave_async_eq_poll(struct work_struct *work);

int mlx4_cmd_init(struct mlx4_dev *dev);
void mlx4_cmd_cleanup(struct mlx4_dev *dev);
int mlx4_multi_func_init(struct mlx4_dev *dev);
void mlx4_multi_func_cleanup(struct mlx4_dev *dev);
void mlx4_cmd_event(struct mlx4_dev *dev, u16 token, u8 status, u64 out_param);
int mlx4_cmd_use_events(struct mlx4_dev *dev);
void mlx4_cmd_use_polling(struct mlx4_dev *dev);

int mlx4_comm_cmd(struct mlx4_dev *dev, u8 cmd, u16 param, unsigned long timeout);

void mlx4_cq_completion(struct mlx4_dev *dev, u32 cqn);
void mlx4_cq_event(struct mlx4_dev *dev, u32 cqn, int event_type);

void mlx4_qp_event(struct mlx4_dev *dev, u32 qpn, int event_type);

void mlx4_srq_event(struct mlx4_dev *dev, u32 srqn, int event_type);

void mlx4_handle_catas_err(struct mlx4_dev *dev);

void mlx4_do_sense_ports(struct mlx4_dev *dev,
			 enum mlx4_port_type *stype,
			 enum mlx4_port_type *defaults);
void mlx4_start_sense(struct mlx4_dev *dev);
void mlx4_stop_sense(struct mlx4_dev *dev);
int mlx4_sense_init(struct mlx4_dev *dev);
void mlx4_sense_cleanup(struct mlx4_dev *dev);
int mlx4_check_port_params(struct mlx4_dev *dev,
			   enum mlx4_port_type *port_type);
int mlx4_change_port_types(struct mlx4_dev *dev,
			   enum mlx4_port_type *port_types);
void mlx4_set_port_mask(struct mlx4_dev *dev, struct mlx4_caps *caps, int function);

void mlx4_init_mac_table(struct mlx4_dev *dev, struct mlx4_mac_table *table);
void mlx4_init_vlan_table(struct mlx4_dev *dev, struct mlx4_vlan_table *table);

int mlx4_SET_PORT(struct mlx4_dev *dev, u8 port);
int mlx4_SET_PORT_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
							struct mlx4_cmd_mailbox *inbox,
							struct mlx4_cmd_mailbox *outbox);
int mlx4_INIT_PORT_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
							 struct mlx4_cmd_mailbox *inbox,
							 struct mlx4_cmd_mailbox *outbox);
int mlx4_CLOSE_PORT_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
							  struct mlx4_cmd_mailbox *inbox,
							  struct mlx4_cmd_mailbox *outbox);
int mlx4_QUERY_PORT_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
							  struct mlx4_cmd_mailbox *inbox,
							  struct mlx4_cmd_mailbox *outbox);
int mlx4_get_port_ib_caps(struct mlx4_dev *dev, u8 port, __be32 *caps);

int mlx4_QP_MODIFY_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
			   struct mlx4_cmd_mailbox *inbox, struct mlx4_cmd_mailbox *outbox);
int mlx4_CONF_SPECIAL_QP_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
						       struct mlx4_cmd_mailbox *inbox,
						       struct mlx4_cmd_mailbox *outbox);
int mlx4_GET_SLAVE_SQP(struct mlx4_dev *dev, u32 *sqp, int num);
int mlx4_GET_SLAVE_SQP_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
							  struct mlx4_cmd_mailbox *inbox,
							  struct mlx4_cmd_mailbox *outbox);

int mlx4_MCAST_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
						     struct mlx4_cmd_mailbox *inbox,
						     struct mlx4_cmd_mailbox *outbox);
int mlx4_SET_MCAST_FLTR_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
				struct mlx4_cmd_mailbox *inbox,
				struct mlx4_cmd_mailbox *outbox);
int mlx4_SET_VLAN_FLTR_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
				struct mlx4_cmd_mailbox *inbox,
				struct mlx4_cmd_mailbox *outbox);

#endif /* MLX4_H */
