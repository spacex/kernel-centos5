/*
 * QLogic iSCSI HBA Driver
 * Copyright (c)  2003-2010 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 */
#include <linux/moduleparam.h>

#include <scsi/scsi_tcq.h>
#include <scsi/scsicam.h>
#include <scsi/iscsi_proto.h>
#include <scsi/scsi_eh.h>

#include <linux/klist.h>
#include "ql4_def.h"
#include "ql4_version.h"
#include "ql4_glbl.h"
#include "ql4_dbg.h"
#include "ql4_inline.h"

/*
 * Driver version
 */
static char qla4xxx_version_str[64];
EXPORT_SYMBOL_GPL(qla4xxx_version_str);

/*
 * List of host adapters
 */
struct klist qla4xxx_hostlist;

struct klist *qla4xxx_hostlist_ptr = &qla4xxx_hostlist;
EXPORT_SYMBOL_GPL(qla4xxx_hostlist_ptr);

static atomic_t qla4xxx_hba_count;

/*
 * SRB allocation cache
 */
static struct kmem_cache *srb_cachep;

/*
 * Module parameter information and variables
 */
int ql4xdiscoverywait = 10;
module_param(ql4xdiscoverywait, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ql4xdiscoverywait, "Discovery wait time");
int ql4xdontresethba = 0;
module_param(ql4xdontresethba, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ql4xdontresethba,
		 " Don't reset the HBA for driver recovery\n"
		 " \t\t 0 - It will reset HBA (Default)\n"
		 " \t\t 1 - It will NOT reset HBA");

int ql4xextended_error_logging = 0; /* 0 = off, 1 = log errors */
module_param(ql4xextended_error_logging, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ql4xextended_error_logging,
		 " Option to enable extended error logging,\n"
		 "\t\t 0 - no logging (Default).\n"
		 "\t\t 2 - debug logging");

int ql4xenablemsix = 1;
module_param(ql4xenablemsix, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(ql4xenablemsix,
		 " Set to enable MSI or MSI-X interrupt mechanism.\n"
		 "\t\t 0 = enable INTx interrupt mechanism.\n"
		 "\t\t 1 = enable MSI-X interrupt mechanism.\n"
		 "\t\t 2 = enable MSI interrupt mechanism.");

#define QL4_DEF_QDEPTH 32
static int ql4xmaxqdepth = QL4_DEF_QDEPTH;
module_param(ql4xmaxqdepth, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(ql4xmaxqdepth,
		"Maximum queue depth to report for target devices.\n"
		"\t\t   Default: 32");

static int ql4xkeepalive = QL4_SESS_RECOVERY_TMO;
module_param(ql4xkeepalive, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ql4xkeepalive,
		"Target Session Recovery Timeout.\n"
		" Default: 30 sec.");

/*
 * SCSI host template entry points
 */

static void qla4xxx_config_dma_addressing(struct scsi_qla_host *ha);

/*
 * iSCSI template entry points
 */

static int qla4xxx_tgt_dscvr(struct Scsi_Host *shost,
			     enum iscsi_tgt_dscvr type,
			     uint32_t enable, struct sockaddr *dst_addr);

static int qla4xxx_host_get_param(struct Scsi_Host *,
			enum iscsi_host_param, char *);
static int qla4xxx_conn_get_param(struct iscsi_cls_conn *conn,
				  enum iscsi_param param, char *buf);
static int qla4xxx_sess_get_param(struct iscsi_cls_session *sess,
				  enum iscsi_param param, char *buf);
static void qla4xxx_recovery_timedout(struct iscsi_cls_session *session);

/*
 * SCSI host template entry points
 */
static int qla4xxx_queuecommand(struct scsi_cmnd *cmd,
				void (*done) (struct scsi_cmnd *));
static int qla4xxx_eh_abort(struct scsi_cmnd *cmd);
static int qla4xxx_eh_device_reset(struct scsi_cmnd *cmd);
static int qla4xxx_eh_host_reset(struct scsi_cmnd *cmd);
static int qla4xxx_slave_alloc(struct scsi_device *device);
static void qla4xxx_slave_destroy(struct scsi_device *sdev);
static int qla4xxx_slave_configure(struct scsi_device *device);

static struct scsi_host_template qla4xxx_driver_template = {
	.module				= THIS_MODULE,
	.name				= DRIVER_NAME,
	.proc_name			= DRIVER_NAME,
	.queuecommand		= qla4xxx_queuecommand,

	.eh_abort_handler	= qla4xxx_eh_abort,
	.eh_device_reset_handler = qla4xxx_eh_device_reset,
	.eh_host_reset_handler	= qla4xxx_eh_host_reset,

	.slave_configure	= qla4xxx_slave_configure,
	.slave_alloc		= qla4xxx_slave_alloc,
	.slave_destroy		= qla4xxx_slave_destroy,

	.this_id		= -1,
	.cmd_per_lun		= 3,
	.use_clustering		= ENABLE_CLUSTERING,
	.sg_tablesize		= SG_ALL,

	.max_sectors		= 0xFFFF,
};

static struct iscsi_transport qla4xxx_iscsi_transport = {
	.owner				= THIS_MODULE,
	.name				= DRIVER_NAME,
	.caps				= CAP_FW_DB | CAP_SENDTARGETS_OFFLOAD |
						CAP_DATA_PATH_OFFLOAD,
	.param_mask			= ISCSI_CONN_PORT |
						ISCSI_CONN_ADDRESS |
						ISCSI_TARGET_NAME |
						ISCSI_TPGT,
	.host_param_mask	= ISCSI_HOST_HWADDRESS |
						ISCSI_HOST_IPADDRESS |
						ISCSI_HOST_INITIATOR_NAME,
	.tgt_dscvr		= qla4xxx_tgt_dscvr,
	.get_host_param		= qla4xxx_host_get_param,
	.get_conn_param		= qla4xxx_conn_get_param,
	.get_session_param	= qla4xxx_sess_get_param,
	.session_recovery_timedout = qla4xxx_recovery_timedout,
};

static struct scsi_transport_template *qla4xxx_scsi_transport;

static void qla4xxx_recovery_timedout(struct iscsi_cls_session *session)
{
	struct ddb_entry *ddb_entry = session->dd_data;
	struct scsi_qla_host *ha = ddb_entry->ha;

	if (atomic_read(&ddb_entry->state) != DDB_STATE_ONLINE) {
		atomic_set(&ddb_entry->state, DDB_STATE_DEAD);

		DEBUG2(printk("scsi%ld: %s: ddb [%d] session recovery timeout "
			      "of (%d) secs exhausted, marking device DEAD.\n",
			      ha->host_no, __func__, ddb_entry->fw_ddb_index,
			      ddb_entry->sess->recovery_tmo));
	}
}

int qla4xxx_conn_start(struct iscsi_cls_conn *conn)
{
	struct iscsi_cls_session *session;
	struct ddb_entry *ddb_entry;

	session = iscsi_dev_to_session(conn->dev.parent);
	ddb_entry = session->dd_data;

	DEBUG2(printk("scsi%ld: %s: ddb [%d] starting conn\n",
			ddb_entry->ha->host_no, __func__,
			ddb_entry->fw_ddb_index));
	iscsi2_unblock_session(session);
	return 0;
}

static void qla4xxx_conn_stop(struct iscsi_cls_conn *conn, int flag)
{
	struct iscsi_cls_session *session;
	struct ddb_entry *ddb_entry;

	session = iscsi_dev_to_session(conn->dev.parent);

	if (session == NULL) {
		printk("session is  NULL \n");
		return;
	}

	ddb_entry = session->dd_data;

	DEBUG2(printk("scsi%ld: %s: ddb [%d] stopping conn\n",
			ddb_entry->ha->host_no, __func__,
			ddb_entry->fw_ddb_index));
	if (flag == STOP_CONN_RECOVER)
		iscsi2_block_session(session);
	else
		printk(KERN_ERR "iscsi: invalid stop flag %d\n", flag);
}

static int qla4xxx_sess_get_param(struct iscsi_cls_session *sess,
				  enum iscsi_param param, char *buf)
{
	struct ddb_entry *ddb_entry = sess->dd_data;
	int len;

	switch (param) {
	case ISCSI_PARAM_TARGET_NAME:
		len = snprintf(buf, PAGE_SIZE - 1, "%s\n",
				ddb_entry->iscsi_name);
		break;
	case ISCSI_PARAM_TPGT:
		len = sprintf(buf, "%u\n", ddb_entry->tpgt);
		break;
	default:
		return -ENOSYS;
	}

	return len;
}

static ssize_t format_addr(char *buf, const unsigned char *addr, int len)
{
	int i;
	char *cp = buf;

	for (i = 0; i < len; i++)
		cp += sprintf(cp, "%02x%c", addr[i],
			i == (len - 1) ? '\n' : ':');
	return cp - buf;
}

static int qla4xxx_host_get_param(struct Scsi_Host *shost,
			enum iscsi_host_param param, char *buf)
{
	struct scsi_qla_host *ha = to_qla_host(shost);
	int len;

	switch (param) {
	case ISCSI_HOST_PARAM_HWADDRESS:
		len = format_addr(buf, ha->my_mac, MAC_ADDR_LEN);
		break;
	case ISCSI_HOST_PARAM_IPADDRESS:
		len = sprintf(buf, "%d.%d.%d.%d", ha->ip_address[0],
				ha->ip_address[1], ha->ip_address[2],
				ha->ip_address[3]);
		break;
	case ISCSI_HOST_PARAM_INITIATOR_NAME:
		len = sprintf(buf, "%s", ha->name_string);
		break;
	default:
		return -ENOSYS;
	}

	return len;
}

static int qla4xxx_conn_get_param(struct iscsi_cls_conn *conn,
				  enum iscsi_param param, char *buf)
{
	struct iscsi_cls_session *session;
	struct ddb_entry *ddb_entry;
	int len;

	session = iscsi_dev_to_session(conn->dev.parent);
	ddb_entry = session->dd_data;

	switch (param) {
	case ISCSI_PARAM_CONN_PORT:
		len = sprintf(buf, "%hu\n", ddb_entry->port);
		break;
	case ISCSI_PARAM_CONN_ADDRESS:
		len = sprintf(buf, "%pI4\n",
			      ddb_entry->ip_addr);
		break;
	default:
		return -ENOSYS;
	}

	return len;
}

static int qla4xxx_tgt_dscvr(struct Scsi_Host *shost,
			     enum iscsi_tgt_dscvr type,
			     uint32_t enable, struct sockaddr *dst_addr)
{
	struct scsi_qla_host *ha;
	struct sockaddr_in *addr;
	struct sockaddr_in6 *addr6;
	int ret = 0;

	ha = (struct scsi_qla_host *) shost->hostdata;

	switch (type) {
	case ISCSI_TGT_DSCVR_SEND_TARGETS:
		if (dst_addr->sa_family == AF_INET) {
			addr = (struct sockaddr_in *)dst_addr;
			if (qla4xxx_send_tgts(ha, (char *)&addr->sin_addr,
					      addr->sin_port) != QLA_SUCCESS)
				ret = -EIO;
		} else if (dst_addr->sa_family == AF_INET6) {
			/*
			 * TODO: fix qla4xxx_send_tgts
			 */
			addr6 = (struct sockaddr_in6 *)dst_addr;
			if (qla4xxx_send_tgts(ha, (char *)&addr6->sin6_addr,
					      addr6->sin6_port) != QLA_SUCCESS)
				ret = -EIO;
		} else
			ret = -ENOSYS;
		break;
	default:
		ret = -ENOSYS;
	}

	return ret;
}

void qla4xxx_destroy_sess(struct ddb_entry *ddb_entry)
{
	if (!ddb_entry->sess)
		return;

	if (ddb_entry->conn) {
		atomic_set(&ddb_entry->state, DDB_STATE_DEAD);
		iscsi2_destroy_conn(ddb_entry->conn);
		iscsi2_remove_session(ddb_entry->sess);
	}

	iscsi2_free_session(ddb_entry->sess);
}

int qla4xxx_add_sess(struct ddb_entry *ddb_entry, int scan)
{
	int err;

	err = iscsi2_add_session(ddb_entry->sess, ddb_entry->fw_ddb_index);
	if (err) {
		DEBUG2(printk(KERN_ERR "Could not add session.\n"));
		return err;
	}

	ddb_entry->conn = iscsi2_create_conn(ddb_entry->sess, 0, 0);

	if (!ddb_entry->conn) {
		iscsi2_remove_session(ddb_entry->sess);
		DEBUG2(printk(KERN_ERR "Could not add connection.\n"));
		return -ENOMEM;
	}

	iscsi2_unblock_session(ddb_entry->sess);

	ddb_entry->sess->recovery_tmo = ql4xkeepalive;
	if (scan)
		if (test_bit(AF_ONLINE, &ddb_entry->ha->flags))
			scsi_scan_target(&ddb_entry->sess->dev, 0,
				 ddb_entry->sess->target_id,
				 SCAN_WILD_CARD, 0);
	return 0;
}

struct ddb_entry *qla4xxx_alloc_sess(struct scsi_qla_host *ha)
{
	struct ddb_entry *ddb_entry;
	struct iscsi_cls_session *sess;

	sess = iscsi2_alloc_session(ha->host, &qla4xxx_iscsi_transport,
				    sizeof(*ddb_entry));
	if (!sess)
		return NULL;

	ddb_entry = sess->dd_data;
	memset(ddb_entry, 0, sizeof(*ddb_entry));
	ddb_entry->ha = ha;
	ddb_entry->sess = sess;
	return ddb_entry;
}

/*
 * Timer routines
 */

static void qla4xxx_start_timer(struct scsi_qla_host *ha, void *func,
				unsigned long interval)
{
	DEBUG(printk("scsi: %s: Starting timer thread for adapter %d\n",
			__func__, ha->host->host_no));
	init_timer(&ha->timer);
	ha->timer.expires = jiffies + interval * HZ;
	ha->timer.data = (unsigned long)ha;
	ha->timer.function = (void (*)(unsigned long))func;
	add_timer(&ha->timer);
	ha->timer_active = 1;
}

static void qla4xxx_stop_timer(struct scsi_qla_host *ha)
{
	del_timer_sync(&ha->timer);
	ha->timer_active = 0;
}

/**
 * qla4xxx_mark_device_missing - mark a device as missing.
 * @ha: Pointer to host adapter structure.
 * @ddb_entry: Pointer to device database entry
 *
 * This routine marks a device missing and closes the connection
 **/
void qla4xxx_mark_device_missing(struct scsi_qla_host *ha,
				 struct ddb_entry *ddb_entry)
{
	if ((atomic_read(&ddb_entry->state) != DDB_STATE_DEAD)) {
		atomic_set(&ddb_entry->state, DDB_STATE_MISSING);
		DEBUG2(printk(KERN_INFO "scsi%ld: ddb [%d] marked MISSING\n",
		    ha->host_no, ddb_entry->fw_ddb_index));
	} else
		DEBUG2(printk(KERN_INFO "scsi%ld: ddb [%d] DEAD\n",
		    ha->host_no, ddb_entry->fw_ddb_index))

	if (ddb_entry->conn)
		qla4xxx_conn_stop(ddb_entry->conn, STOP_CONN_RECOVER);
}

/**
 * qla4xxx_mark_all_devices_missing - mark all devices as missing.
 * @ha: Pointer to host adapter structure.
 *
 * This routine marks a device missing and resets the relogin retry count.
 **/
void qla4xxx_mark_all_devices_missing(struct scsi_qla_host *ha)
{
	struct ddb_entry *ddb_entry, *ddbtemp;
	list_for_each_entry_safe(ddb_entry, ddbtemp, &ha->ddb_list, list) {
		qla4xxx_mark_device_missing(ha, ddb_entry);
	}
}

/***
 * qla4xxx_get_new_srb - Allocate memory for a local srb.
 * @ha: Pointer to host adapter structure.
 * @ddb_entry: Pointer to device database entry
 * @cmd: Pointer to Linux's SCSI command structure
 * @done: Pointer to Linux's SCSI mid-layer done function
 *
 * NOTE: Sets te ref_count for non-NULL srb to one,
 *       and initializes some fields.
 **/
static struct srb* qla4xxx_get_new_srb(struct scsi_qla_host *ha,
				       struct ddb_entry *ddb_entry,
				       struct scsi_cmnd *cmd,
				       void (*done)(struct scsi_cmnd *))
{
	struct srb *srb;

	srb = mempool_alloc(ha->srb_mempool, GFP_ATOMIC);
	if (!srb)
		return srb;

	kref_init(&srb->srb_ref);
	srb->ha = ha;
	srb->ddb = ddb_entry;
	srb->cmd = cmd;
	srb->flags = 0;
	CMD_SP(cmd) = (void *)srb;
	cmd->scsi_done = done;

	return srb;
}

static void qla4xxx_srb_free_dma(struct scsi_qla_host *ha, struct srb *srb)
{
	struct scsi_cmnd *cmd = srb->cmd;

	if (srb->flags & SRB_DMA_VALID) {
		if (cmd->use_sg) {
			pci_unmap_sg(ha->pdev, cmd->request_buffer,
				     cmd->use_sg, cmd->sc_data_direction);
		} else if (cmd->request_bufflen) {
			pci_unmap_single(ha->pdev, srb->dma_handle,
					 cmd->request_bufflen,
					 cmd->sc_data_direction);
		}
		srb->flags &= ~SRB_DMA_VALID;
	}
	CMD_SP(cmd) = NULL;
}

void qla4xxx_srb_compl(struct kref *ref)
{
	struct srb *srb = container_of(ref, struct srb, srb_ref);
	struct scsi_cmnd *cmd = srb->cmd;
	struct scsi_qla_host *ha = srb->ha;

	if (!(srb->flags & SRB_SCSI_PASSTHRU)) {
		qla4xxx_srb_free_dma(ha, srb);
		mempool_free(srb, ha->srb_mempool);
	}
	cmd->scsi_done(cmd);
}

/**
 * qla4xxx_queuecommand - scsi layer issues scsi command to driver.
 * @cmd: Pointer to Linux's SCSI command structure
 * @done_fn: Function that the driver calls to notify the SCSI mid-layer
 * that the command has been processed.
 *
 * Remarks:
 * This routine is invoked by Linux to send a SCSI command to the driver.
 * The mid-level driver tries to ensure that queuecommand never gets
 * invoked concurrently with itself or the interrupt handler (although
 * the interrupt handler may call this routine as part of request-
 * completion handling).  Unfortunely, it sometimes calls the scheduler
 * in interrupt context which is a big NO! NO!.
 **/
static int qla4xxx_queuecommand(struct scsi_cmnd *cmd,
				void (*done)(struct scsi_cmnd *))
{
	struct scsi_qla_host *ha = to_qla_host(cmd->device->host);
	struct ddb_entry *ddb_entry = cmd->device->hostdata;
	struct iscsi_cls_session *sess = ddb_entry->sess;
	struct srb *srb;
	int rval = -1;

	if (test_bit(AF_EEH_BUSY, &ha->flags)) {
		if (test_bit(AF_PCI_CHANNEL_IO_PERM_FAILURE, &ha->flags))
			cmd->result = DID_NO_CONNECT << 16;
		else
			cmd->result = DID_REQUEUE << 16;
		goto qc_fail_command;
	}

	if (!sess) {
		cmd->result = DID_IMM_RETRY << 16;
		goto qc_fail_command;
	}

	rval = iscsi2_session_chkready(sess);
	if (rval) {
		cmd->result = rval;
		goto qc_fail_command;
	}

	if (atomic_read(&ddb_entry->state) != DDB_STATE_ONLINE) {
		if (atomic_read(&ddb_entry->state) == DDB_STATE_DEAD) {
			cmd->result = DID_NO_CONNECT << 16;
			goto qc_fail_command;
		}
		goto qc_host_busy;
	}

	if (test_bit(DPC_RESET_HA_INTR, &ha->dpc_flags) ||
	    test_bit(DPC_RESET_ACTIVE, &ha->dpc_flags) ||
	    test_bit(DPC_RESET_HA, &ha->dpc_flags) ||
		test_bit(DPC_HA_UNRECOVERABLE, &ha->dpc_flags) ||
	    test_bit(DPC_HA_NEED_QUIESCENT, &ha->dpc_flags) ||
		!test_bit(AF_ONLINE, &ha->flags) ||
	    test_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags))
		goto qc_host_busy;

	spin_unlock_irq(ha->host->host_lock);

	srb = qla4xxx_get_new_srb(ha, ddb_entry, cmd, done);
	if (!srb)
		goto qc_host_busy_lock;

	rval = qla4xxx_send_command_to_isp(ha, srb);
	if (rval != QLA_SUCCESS)
		goto qc_host_busy_free_sp;

	spin_lock_irq(ha->host->host_lock);
	return 0;

qc_host_busy_free_sp:
	qla4xxx_srb_free_dma(ha, srb);
	mempool_free(srb, ha->srb_mempool);

qc_host_busy_lock:
	spin_lock_irq(ha->host->host_lock);

qc_host_busy:
	return SCSI_MLQUEUE_HOST_BUSY;

qc_fail_command:
	done(cmd);

	return 0;
}

/**
 * qla4xxx_mem_free - frees memory allocated to adapter
 * @ha: Pointer to host adapter structure.
 *
 * Frees memory previously allocated by qla4xxx_mem_alloc
 **/
static void qla4xxx_mem_free(struct scsi_qla_host *ha)
{
	struct list_head *ptr;
	struct async_msg_pdu_iocb *apdu_iocb;

	if (ha->queues)
		dma_free_coherent(&ha->pdev->dev, ha->queues_len, ha->queues,
				  ha->queues_dma);

	if (ha->gen_req_rsp_iocb)
		dma_free_coherent(&ha->pdev->dev, PAGE_SIZE,
			ha->gen_req_rsp_iocb, ha->gen_req_rsp_iocb_dma);

	while (!list_empty(&ha->async_iocb_list)) {
		ptr = ha->async_iocb_list.next;
		apdu_iocb = list_entry(ptr, struct async_msg_pdu_iocb, list);
		list_del_init(&apdu_iocb->list);
		kfree(apdu_iocb);
	}

	ha->queues_len = 0;
	ha->queues = NULL;
	ha->queues_dma = 0;
	ha->request_ring = NULL;
	ha->request_dma = 0;
	ha->response_ring = NULL;
	ha->response_dma = 0;
	ha->shadow_regs = NULL;
	ha->shadow_regs_dma = 0;

	/* Free srb pool. */
	if (ha->srb_mempool)
		mempool_destroy(ha->srb_mempool);

	ha->srb_mempool = NULL;

	/* release io space registers  */
	if (is_qla8022(ha)) {
		if (ha->nx_pcibase)
			iounmap((struct device_reg_82xx __iomem *)ha->nx_pcibase);
	} else if (ha->reg)
		iounmap(ha->reg);
	pci_release_regions(ha->pdev);
}

/**
 * qla4xxx_mem_alloc - allocates memory for use by adapter.
 * @ha: Pointer to host adapter structure
 *
 * Allocates DMA memory for request and response queues. Also allocates memory
 * for srbs.
 **/
static int qla4xxx_mem_alloc(struct scsi_qla_host *ha)
{
	unsigned long align;

	/* Allocate contiguous block of DMA memory for queues. */
	ha->queues_len = ((REQUEST_QUEUE_DEPTH * QUEUE_SIZE) +
			  (RESPONSE_QUEUE_DEPTH * QUEUE_SIZE) +
			  sizeof(struct shadow_regs) +
			  MEM_ALIGN_VALUE +
			  (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
	ha->queues = dma_alloc_coherent(&ha->pdev->dev, ha->queues_len,
					&ha->queues_dma, GFP_KERNEL);
	if (ha->queues == NULL) {
		dev_warn(&ha->pdev->dev,
			"Memory Allocation failed - queues.\n");

		goto mem_alloc_error_exit;
	}
	memset(ha->queues, 0, ha->queues_len);

	/*
	 * As per RISC alignment requirements -- the bus-address must be a
	 * multiple of the request-ring size (in bytes).
	 */
	align = 0;
	if ((unsigned long)ha->queues_dma & (MEM_ALIGN_VALUE - 1))
		align = MEM_ALIGN_VALUE - ((unsigned long)ha->queues_dma &
					   (MEM_ALIGN_VALUE - 1));

	/* Update request and response queue pointers. */
	ha->request_dma = ha->queues_dma + align;
	ha->request_ring = (struct queue_entry *) (ha->queues + align);
	ha->response_dma = ha->queues_dma + align +
		(REQUEST_QUEUE_DEPTH * QUEUE_SIZE);
	ha->response_ring = (struct queue_entry *) (ha->queues + align +
							(REQUEST_QUEUE_DEPTH *
							QUEUE_SIZE));
	ha->shadow_regs_dma = ha->queues_dma + align +
		(REQUEST_QUEUE_DEPTH * QUEUE_SIZE) +
		(RESPONSE_QUEUE_DEPTH * QUEUE_SIZE);
	ha->shadow_regs = (struct shadow_regs *) (ha->queues + align +
						  (REQUEST_QUEUE_DEPTH *
						   QUEUE_SIZE) +
						  (RESPONSE_QUEUE_DEPTH *
						   QUEUE_SIZE));

	/* Allocate memory for srb pool. */
	ha->srb_mempool = mempool_create(SRB_MIN_REQ, mempool_alloc_slab,
					 mempool_free_slab, srb_cachep);
	if (ha->srb_mempool == NULL) {
		dev_warn(&ha->pdev->dev,
			"Memory Allocation failed - SRB Pool.\n");

		goto mem_alloc_error_exit;
	}

	ha->gen_req_rsp_iocb = dma_alloc_coherent(&ha->pdev->dev, PAGE_SIZE,
					&ha->gen_req_rsp_iocb_dma, GFP_KERNEL);
	if (ha->gen_req_rsp_iocb == NULL) {
		dev_warn(&ha->pdev->dev,
			 "Memory Allocation failed - gen_req_rsp_iocb.\n");

		goto mem_alloc_error_exit;
	}

	return QLA_SUCCESS;

mem_alloc_error_exit:
	qla4xxx_mem_free(ha);
	return QLA_ERROR;
}

/**
 * qla4_8xxx_check_fw_alive - Check firmware health
 * @ha: Pointer to host adapter structure.
 *
 * Context: Interrupt
 **/
static void
qla4_8xxx_check_fw_alive(struct scsi_qla_host *ha)
{
	uint32_t fw_heartbeat_counter, halt_status;

	fw_heartbeat_counter = qla4_8xxx_rd_32(ha, QLA82XX_PEG_ALIVE_COUNTER);
	/* If PEG_ALIVE_COUNTER is 0xffffffff, AER/EEH is in progress, ignore */
	if (fw_heartbeat_counter == 0xffffffff) {
		DEBUG2(printk("scsi%ld: %s: Device in frozen state, "
			"QLA82XX_PEG_ALIVE_COUNTER is 0xffffffff\n",
			ha->host_no, __func__));
			return;
	}

	if (ha->fw_heartbeat_counter == fw_heartbeat_counter) {
		ha->seconds_since_last_heartbeat++;

		/* FW not alive after 2 seconds */
		if (ha->seconds_since_last_heartbeat == 2) {
			ha->seconds_since_last_heartbeat = 0;
			halt_status = qla4_8xxx_rd_32(ha, QLA82XX_PEG_HALT_STATUS1);
			/* Since we cannot change dev_state in interrupt
			 * context, set appropriate DPC flag then wakeup
			 * DPC */
			if (halt_status & HALT_STATUS_UNRECOVERABLE)
				set_bit(DPC_HA_UNRECOVERABLE, &ha->dpc_flags);
			else
				set_bit(DPC_RESET_HA, &ha->dpc_flags);

			qla4xxx_wake_dpc(ha);
			qla4xxx_mailbox_premature_completion(ha);
		}
	} else
		ha->seconds_since_last_heartbeat = 0;

	ha->fw_heartbeat_counter = fw_heartbeat_counter;
}

/**
 * qla4_8xxx_watchdog - Poll dev state
 * @ha: Pointer to host adapter structure.
 *
 * Context: Interrupt
 **/
void qla4_8xxx_watchdog(struct scsi_qla_host *ha)
{
	uint32_t dev_state;

	dev_state = qla4_8xxx_rd_32(ha, QLA82XX_CRB_DEV_STATE);

	/* don't poll if reset is going on */
	if (!(test_bit(DPC_RETRY_RESET_HA, &ha->dpc_flags) ||
	    test_bit(DPC_RESET_HA, &ha->dpc_flags) ||
	    test_bit(DPC_RESET_ACTIVE, &ha->dpc_flags))) {
		if (dev_state == QLA82XX_DEV_NEED_RESET &&
		    !test_bit(DPC_RESET_HA, &ha->dpc_flags) &&
		    !test_bit(DPC_RETRY_RESET_HA, &ha->dpc_flags)) {
			printk("scsi%ld: %s: detect HA Reset needed!\n",
				ha->host_no, __func__);
			set_bit(DPC_RESET_HA, &ha->dpc_flags);
			qla4xxx_wake_dpc(ha);
			qla4xxx_mailbox_premature_completion(ha);
		} else if (dev_state == QLA82XX_DEV_NEED_QUIESCENT) {
			printk("HW State: NEED QUIESCENT detected\n");
			set_bit(DPC_HA_NEED_QUIESCENT, &ha->dpc_flags);
			qla4xxx_wake_dpc(ha);
		} else {
			/* Check firmware health */
			qla4_8xxx_check_fw_alive(ha);
		}
	}
}

/**
 * qla4xxx_timer - checks every second for work to do.
 * @ha: Pointer to host adapter structure.
 **/
static void qla4xxx_timer(struct scsi_qla_host *ha)
{
	struct ddb_entry *ddb_entry, *dtemp;
	int start_dpc = 0;
	uint16_t        w;

	/* If we are in the middle of AER/EEH processing
	 * skip any processing and reschedule the timer
	 */
	if (test_bit(AF_EEH_BUSY, &ha->flags)) {
		mod_timer(&ha->timer, jiffies + HZ);
		return;
	}

	/* Hardware read to trigger an EEH error during mailbox waits. */
	if (!pci_channel_offline(ha->pdev))
		pci_read_config_word(ha->pdev, PCI_VENDOR_ID, &w);

	if (is_qla8022(ha)) {
		qla4_8xxx_watchdog(ha);
	}

	/* Search for relogin's to time-out and port down retry. */
	list_for_each_entry_safe(ddb_entry, dtemp, &ha->ddb_list, list) {

		/* Count down time between sending relogins */
		if (adapter_up(ha) &&
		    !test_bit(DF_RELOGIN, &ddb_entry->flags) &&
		    atomic_read(&ddb_entry->state) != DDB_STATE_ONLINE) {
			if (atomic_read(&ddb_entry->retry_relogin_timer) !=
			    INVALID_ENTRY) {
				if (atomic_read(&ddb_entry->retry_relogin_timer)
				    		== 0) {
					atomic_set(&ddb_entry->
						retry_relogin_timer,
						INVALID_ENTRY);
					set_bit(DPC_RELOGIN_DEVICE,
						&ha->dpc_flags);
					set_bit(DF_RELOGIN, &ddb_entry->flags);
					DEBUG2(printk("scsi%ld: %s: ddb [%d]"
						      " login device\n",
						      ha->host_no, __func__,
						      ddb_entry->fw_ddb_index));
				} else
					atomic_dec(&ddb_entry->
							retry_relogin_timer);
			}
		}

		/* Wait for relogin to timeout */
		if (atomic_read(&ddb_entry->relogin_timer) &&
		    (atomic_dec_and_test(&ddb_entry->relogin_timer) != 0)) {
			/*
			 * If the relogin times out and the device is
			 * still NOT ONLINE then try and relogin again.
			 */
			if (atomic_read(&ddb_entry->state) != DDB_STATE_ONLINE &&
			    ddb_entry->fw_ddb_device_state == DDB_DS_SESSION_FAILED) {
				/* Reset retry relogin timer */
				atomic_inc(&ddb_entry->relogin_retry_count);
				DEBUG2(printk("scsi%ld: index[%d] relogin timed out-retrying"
					      " relogin (%d)\n",
					      ha->host_no, ddb_entry->fw_ddb_index,
					      atomic_read(&ddb_entry->relogin_retry_count))
					);
				start_dpc++;
				DEBUG(printk("scsi%ld:%d:%d: index [%d] initate relogin after"
					     " %d seconds\n",
					     ha->host_no, ddb_entry->bus, ddb_entry->target,
					     ddb_entry->fw_ddb_index, ddb_entry->default_time2wait + 4)
					);

				atomic_set(&ddb_entry->retry_relogin_timer,
					   ddb_entry->default_time2wait + 4);
			}
		}
	}

	/* Check for heartbeat interval. */
	if (!is_qla8022(ha)) {
		if (ha->firmware_options & FWOPT_HEARTBEAT_ENABLE &&
		    ha->heartbeat_interval != 0) {
			ha->seconds_since_last_heartbeat++;
			if (ha->seconds_since_last_heartbeat >
			    ha->heartbeat_interval + 2) {
				dev_info(&ha->pdev->dev, "scsi%ld: %s: "
					"RESET_HA: heartbeat %d!\n",
					ha->host_no, __func__,
					ha->seconds_since_last_heartbeat);
				set_bit(DPC_RESET_HA, &ha->dpc_flags);
			}
		}
	}

	/* Wakeup the dpc routine for this adapter, if needed. */
	if ((start_dpc ||
	     test_bit(DPC_RESET_HA, &ha->dpc_flags) ||
	     test_bit(DPC_RETRY_RESET_HA, &ha->dpc_flags) ||
	     test_bit(DPC_RELOGIN_DEVICE, &ha->dpc_flags) ||
	     test_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags) ||
	     test_bit(DPC_RESET_HA_INTR, &ha->dpc_flags) ||
	     test_bit(DPC_GET_DHCP_IP_ADDR, &ha->dpc_flags) ||
	     test_bit(DPC_REMOVE_DEVICE, &ha->dpc_flags) ||
		 test_bit(DPC_HA_UNRECOVERABLE, &ha->dpc_flags) ||
	     test_bit(DPC_HA_NEED_QUIESCENT, &ha->dpc_flags) ||
		 test_bit(DPC_DYNAMIC_LUN_SCAN, &ha->dpc_flags) ||
	     test_bit(DPC_AEN, &ha->dpc_flags) ||
		 test_bit(DPC_LINK_CHANGED, &ha->dpc_flags) ||
	     test_bit(DPC_ASYNC_MSG_PDU, &ha->dpc_flags)) &&
	    !test_bit(AF_DPC_SCHEDULED, &ha->flags) &&
		ha->dpc_thread) {
		DEBUG2(printk("scsi%ld: %s: scheduling dpc routine"
			      " - dpc flags = 0x%lx\n",
			      ha->host_no, __func__, ha->dpc_flags));
		qla4xxx_wake_dpc(ha);
	}

	/* Reschedule timer thread to call us back in one second */
	mod_timer(&ha->timer, jiffies + HZ);

	DEBUG2(ha->seconds_since_last_intr++);
}

/**
 * qla4xxx_cmd_wait - waits for all outstanding commands to complete
 * @ha: Pointer to host adapter structure.
 *
 * This routine stalls the driver until all outstanding commands are returned.
 * Caller must release the Hardware Lock prior to calling this routine.
 **/
static int qla4xxx_cmd_wait(struct scsi_qla_host *ha)
{
	uint32_t index = 0;
	unsigned long flags;
	unsigned long wtime = jiffies + (WAIT_CMD_TOV * HZ);

	DEBUG2(printk(KERN_INFO "Wait up to %d seconds for cmds to complete\n", WAIT_CMD_TOV));

	while (!time_after_eq(jiffies, wtime)) {
		spin_lock_irqsave(&ha->hardware_lock, flags);
		/* Find a command that hasn't completed. */
		for (index = 1; index < MAX_SRBS; index++) {
			if (ha->active_srb_array[index] != NULL)
				break;
		}
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		/* If No Commands are pending, wait is complete */
		if (index == MAX_SRBS)
			return QLA_SUCCESS;

		msleep(1000);

	} /* End of While (wait_cnt) */

	/* If we timed out on waiting for commands to come back
	 * return ERROR. */

	return QLA_ERROR;
}

int qla4xxx_hw_reset(struct scsi_qla_host *ha)
{
	uint32_t ctrl_status;
	unsigned long flags = 0;

	DEBUG2(printk(KERN_ERR "scsi%ld: %s\n", ha->host_no, __func__));

	if (ql4xxx_lock_drvr_wait(ha) != QLA_SUCCESS)
		return QLA_ERROR;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	/*
	 * If the SCSI Reset Interrupt bit is set, clear it.
	 * Otherwise, the Soft Reset won't work.
	 */
	ctrl_status = readw(&ha->reg->ctrl_status);
	if ((ctrl_status & CSR_SCSI_RESET_INTR) != 0)
		writel(set_rmask(CSR_SCSI_RESET_INTR), &ha->reg->ctrl_status);

	/* Issue Soft Reset */
	writel(set_rmask(CSR_SOFT_RESET), &ha->reg->ctrl_status);
	readl(&ha->reg->ctrl_status);

	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	return QLA_SUCCESS;
}

/**
 * qla4xxx_soft_reset - performs soft reset.
 * @ha: Pointer to host adapter structure.
 **/
int qla4xxx_soft_reset(struct scsi_qla_host *ha)
{
	uint32_t max_wait_time;
	unsigned long flags = 0;
	int status = QLA_ERROR;
	uint32_t ctrl_status;

	if (qla4xxx_hw_reset(ha) != QLA_SUCCESS)
		return QLA_ERROR;

	/* Wait until the Network Reset Intr bit is cleared */
	max_wait_time = RESET_INTR_TOV;
	do {
		spin_lock_irqsave(&ha->hardware_lock, flags);
		ctrl_status = readw(&ha->reg->ctrl_status);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		if ((ctrl_status & CSR_NET_RESET_INTR) == 0)
			break;

		msleep(1000);
	} while ((--max_wait_time));

	if ((ctrl_status & CSR_NET_RESET_INTR) != 0) {
		DEBUG2(printk(KERN_WARNING
			      "scsi%ld: Network Reset Intr not cleared by "
			      "Network function, clearing it now!\n",
			      ha->host_no));
		spin_lock_irqsave(&ha->hardware_lock, flags);
		writel(set_rmask(CSR_NET_RESET_INTR), &ha->reg->ctrl_status);
		readl(&ha->reg->ctrl_status);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);
	}

	/* Wait until the firmware tells us the Soft Reset is done */
	max_wait_time = SOFT_RESET_TOV;
	do {
		spin_lock_irqsave(&ha->hardware_lock, flags);
		ctrl_status = readw(&ha->reg->ctrl_status);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		if ((ctrl_status & CSR_SOFT_RESET) == 0) {
			status = QLA_SUCCESS;
			break;
		}

		msleep(1000);
	} while ((--max_wait_time));

	/*
	 * Also, make sure that the SCSI Reset Interrupt bit has been cleared
	 * after the soft reset has taken place.
	 */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	ctrl_status = readw(&ha->reg->ctrl_status);
	if ((ctrl_status & CSR_SCSI_RESET_INTR) != 0) {
		writel(set_rmask(CSR_SCSI_RESET_INTR), &ha->reg->ctrl_status);
		readl(&ha->reg->ctrl_status);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	/* If soft reset fails then most probably the bios on other
	 * function is also enabled.
	 * Since the initialization is sequential the other fn
	 * wont be able to acknowledge the soft reset.
	 * Issue a force soft reset to workaround this scenario.
	 */
	if (max_wait_time == 0) {
		/* Issue Force Soft Reset */
		spin_lock_irqsave(&ha->hardware_lock, flags);
		writel(set_rmask(CSR_FORCE_SOFT_RESET), &ha->reg->ctrl_status);
		readl(&ha->reg->ctrl_status);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);
		/* Wait until the firmware tells us the Soft Reset is done */
		max_wait_time = SOFT_RESET_TOV;
		do {
			spin_lock_irqsave(&ha->hardware_lock, flags);
			ctrl_status = readw(&ha->reg->ctrl_status);
			spin_unlock_irqrestore(&ha->hardware_lock, flags);

			if ((ctrl_status & CSR_FORCE_SOFT_RESET) == 0) {
				status = QLA_SUCCESS;
				break;
			}

			msleep(1000);
		} while ((--max_wait_time));
	}

	return status;
}

/**
 * qla4xxx_abort_active_cmds - returns all outstanding i/o requests to O.S.
 * @ha: Pointer to host adapter structure.
 * @res: Command Return Code.
 *
 * This routine is called just prior to a HARD RESET to return all
 * outstanding commands back to the Operating System.
 * Caller should make sure that the following locks are released
 * before this calling routine: Hardware lock, and io_request_lock.
 **/
void qla4xxx_abort_active_cmds(struct scsi_qla_host *ha, int res)
{
	struct srb *srb;
	int i;
	unsigned long flags;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	for (i = 1; i < MAX_SRBS; i++) {
		if ((srb = ha->active_srb_array[i]) != NULL) {
			qla4xxx_del_from_active_array(ha, i);
			srb->cmd->result = res;
			kref_put(&srb->srb_ref, qla4xxx_srb_compl);
		}
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

}

/**
 *  qla4xxx_dead_adapter_cleanup - Cleanup perermanently disable HA
 *  @ha: pointer to adapter structure
 **/
void
qla4xxx_dead_adapter_cleanup(struct scsi_qla_host *ha)
{
	/* Disable the board */
	DEBUG2(printk(KERN_INFO"Disabling the board\n"));

	qla4xxx_abort_active_cmds(ha, DID_NO_CONNECT << 16);
	qla4xxx_mark_all_devices_missing(ha);

	clear_bit(AF_ONLINE, &ha->flags);
	clear_bit(AF_INIT_DONE, &ha->flags);
}

/**
 * qla4xxx_recover_adapter - recovers adapter after a fatal error
 * @ha: Pointer to host adapter structure.
 **/
static int qla4xxx_recover_adapter(struct scsi_qla_host *ha)
{
	int status = QLA_ERROR;
	uint8_t reset_chip = 0;

	/* Stall incoming I/O until we are done */
	DEBUG2(printk("scsi%ld: recover adapter .. BEGIN\n", ha->host_no));
	dev_info(&ha->pdev->dev, "%s: adapter OFFLINE\n", __func__);
	scsi_block_requests(ha->host);
	clear_bit(AF_ONLINE, &ha->flags);

	DEBUG2(printk("scsi%ld: %s calling qla4xxx_cmd_wait\n", ha->host_no,
		      __func__));

	set_bit(DPC_RESET_ACTIVE, &ha->dpc_flags);

	if (test_bit(DPC_RESET_HA, &ha->dpc_flags))
		reset_chip = 1;

	/* For the DPC_RESET_HA_INTR case (ISP-4xxx specific)
	 * do not reset adapter, jump to initialize_adapter */
	if (test_bit(DPC_RESET_HA_INTR, &ha->dpc_flags)) {
		status = QLA_SUCCESS;
		goto recover_ha_init_adapter;
	}

	/* For the ISP-802x adapter, issue a stop_firmware if invoked
	 * from eh_host_reset or ioctl module */
	if (is_qla8022(ha) && !reset_chip &&
		test_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags)) {
			DEBUG2(dev_info(&ha->pdev->dev,
				"scsi%ld: %s - Performing stop_firmware...\n",
				ha->host_no, __func__));
			status = ha->isp_ops->reset_firmware(ha);
			if (status == QLA_SUCCESS) {
				if (!test_bit(AF_FW_RECOVERY, &ha->flags))
					qla4xxx_cmd_wait(ha);
				ha->isp_ops->disable_intrs(ha);
				qla4xxx_process_aen(ha, FLUSH_DDB_CHANGED_AENS);
				qla4xxx_abort_active_cmds(ha, DID_RESET << 16);
			} else {
				/* If the stop_firmware fails then
				 * reset the entire chip */
				reset_chip = 1;
				clear_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags);
				set_bit(DPC_RESET_HA, &ha->dpc_flags);
			}
	}

	/* Issue full chip reset if recovering from a catastrophic error,
	 * or if stop_firmware fails for ISP-802x.
	 * This is the default case for ISP-4xxx */
	if (!is_qla8022(ha) || reset_chip) {
		if (!test_bit(AF_FW_RECOVERY, &ha->flags))
			qla4xxx_cmd_wait(ha);
		qla4xxx_process_aen(ha, FLUSH_DDB_CHANGED_AENS);
		qla4xxx_abort_active_cmds(ha, DID_RESET << 16);
		DEBUG2(dev_info(&ha->pdev->dev,
			"scsi%ld: %s - Performing chip reset..\n",
			ha->host_no, __func__));
		status = ha->isp_ops->reset_chip(ha);
	}

	/* Flush any pending ddb changed AENs */
	qla4xxx_process_aen(ha, FLUSH_DDB_CHANGED_AENS);

recover_ha_init_adapter:
	/* Upon successful firmware/chip reset, re-initialize the adapter */
	if (status == QLA_SUCCESS) {
		DEBUG2(printk("scsi%ld: %s - Initializing adapter..\n",
			ha->host_no, __func__));

		/* For ISP-4xxx, force function 1 to always initialize
		 * before function 3 to prevent both funcions from
		 * stepping on top of the other */
		if (!is_qla8022(ha) && (ha->mac_index == 3))
			ssleep(6);

		/* NOTE: AF_ONLINE flag set upon successful completion of
		 * 		qla4xxx_initialize_adapter */
		status = qla4xxx_initialize_adapter(ha, PRESERVE_DDB_LIST);
	}

	/* Retry failed adapter initialization, if necessary
	 * Do not retry initialize_adapter for RESET_HA_INTR (ISP-4xxx specific)
	 * case to prevent ping-pong resets between functions */
	if (!test_bit(DPC_RESET_HA_INTR, &ha->dpc_flags) &&
		!test_bit(AF_ONLINE, &ha->flags)) {
		/* Adapter initialization failed, see if we can retry
		 * resetting the ha.
		 * Since we don't want to block the DPC for too long
		 * with multiple resets in the same thread,
		 * utilize DPC to retry */
		if (!test_bit(DPC_RETRY_RESET_HA, &ha->dpc_flags)) {
			ha->retry_reset_ha_cnt = MAX_RESET_HA_RETRIES;
			DEBUG2(printk("scsi%ld: recover adapter - retrying "
				"(%d) more times\n", ha->host_no, ha->retry_reset_ha_cnt));
			set_bit(DPC_RETRY_RESET_HA, &ha->dpc_flags);
			status = QLA_ERROR;
		} else {
			if (ha->retry_reset_ha_cnt > 0) {
				/* Schedule another Reset HA--DPC will retry */
				ha->retry_reset_ha_cnt--;
				DEBUG2(printk("scsi%ld: recover adapter - retry remaining %d\n",
					ha->host_no, ha->retry_reset_ha_cnt));
				status = QLA_ERROR;
			}

			if (ha->retry_reset_ha_cnt == 0) {
				/* Recover adapter retries have been exhausted.
				 * Adapter DEAD */
				DEBUG2(printk("scsi%ld: recover adapter "
					"failed - board disabled\n",
					ha->host_no));
				qla4xxx_dead_adapter_cleanup(ha);
				clear_bit(DPC_RETRY_RESET_HA, &ha->dpc_flags);
				clear_bit(DPC_RESET_HA, &ha->dpc_flags);
				clear_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags);
				status = QLA_ERROR;
			}
		}
	} else {
		clear_bit(DPC_RESET_HA, &ha->dpc_flags);
		clear_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags);
		clear_bit(DPC_RETRY_RESET_HA, &ha->dpc_flags);
	}

	ha->adapter_error_count++;

	if (test_bit(AF_ONLINE, &ha->flags)) {
		ha->isp_ops->enable_intrs(ha);
		DEBUG2(printk("%s: scsi_unblock_requests\n", __func__));
		scsi_unblock_requests(ha->host);
		status = QLA_SUCCESS;
	}

	clear_bit(DPC_RESET_ACTIVE, &ha->dpc_flags);
	DEBUG2(printk("scsi%ld: recover adapter .. DONE (status=%d)\n",
		ha->host_no, status));

	return status;
}

static void qla4xxx_relogin_all_devices(struct scsi_qla_host *ha)
{
	struct ddb_entry *ddb_entry, *dtemp;

	list_for_each_entry_safe(ddb_entry, dtemp, &ha->ddb_list, list) {
		if ((atomic_read(&ddb_entry->state) == DDB_STATE_MISSING) ||
		    (atomic_read(&ddb_entry->state) == DDB_STATE_DEAD)) {
			if (ddb_entry->fw_ddb_device_state ==
			    DDB_DS_SESSION_ACTIVE && ddb_entry->conn) {
				atomic_set(&ddb_entry->state, DDB_STATE_ONLINE);
				ql4_printk(KERN_INFO, ha, "scsi%ld: %s: ddb[%d]"
				    " marked ONLINE\n",	ha->host_no, __func__,
				    ddb_entry->fw_ddb_index);

				iscsi2_unblock_session(ddb_entry->sess);
			} else
				qla4xxx_relogin_device(ha, ddb_entry);
		}
	}
}

void qla4xxx_wake_dpc(struct scsi_qla_host *ha)
{
	if (ha->dpc_thread &&
	    !test_bit(AF_DPC_SCHEDULED, &ha->flags)) {
		set_bit(AF_DPC_SCHEDULED, &ha->flags);
		queue_work(ha->dpc_thread, &ha->dpc_work);
	}
}

/*
 * qla4xxx_async_iocbs - processes ASYNC PDU IOCBS, if they are greater in
 * length than 48 bytes (i.e., more than just the iscsi header). Used for
 * unsolicited pdus received from target.
 */
static void qla4xxx_async_iocbs(struct scsi_qla_host *ha,
			struct async_msg_pdu_iocb *amsg_pdu_iocb)
{
	struct iscsi_hdr *hdr;
	struct async_pdu_iocb *apdu;
	uint32_t len;
	void *buf_addr;
	dma_addr_t buf_addr_dma;
	uint32_t offset;
	struct passthru0 *pthru0_iocb;
	struct ddb_entry *ddb_entry = NULL;
	struct async_pdu_sense *pdu_sense;

	uint8_t using_prealloc = 1;
	uint8_t async_event_type;

	apdu = (struct async_pdu_iocb *)amsg_pdu_iocb->iocb;
	hdr = (struct iscsi_hdr *)apdu->iscsi_pdu_hdr;
	len = hdr->hlength + hdr->dlength[2] +
		(hdr->dlength[1]<<8) + (hdr->dlength[0]<<16);

	offset = sizeof(struct passthru0) + sizeof(struct passthru_status);
	if (len <= (PAGE_SIZE - offset)) {
		buf_addr_dma = ha->gen_req_rsp_iocb_dma + offset;
		buf_addr = (uint8_t *)ha->gen_req_rsp_iocb + offset;
	} else {
		using_prealloc = 0;
		buf_addr = dma_alloc_coherent(&ha->pdev->dev, len,
					&buf_addr_dma, GFP_KERNEL);
		if (!buf_addr) {
			dev_info(&ha->pdev->dev,
				"%s: dma_alloc_coherent failed\n", __func__);
			return;
		}
	}
	/* Create the pass-thru0 iocb */
	pthru0_iocb = ha->gen_req_rsp_iocb;
	memset(pthru0_iocb, 0, offset);

	pthru0_iocb->hdr.entryType = ET_PASSTHRU0;
	pthru0_iocb->hdr.entryCount = 1;
	pthru0_iocb->target = cpu_to_le16(apdu->target_id);
	pthru0_iocb->controlFlags =
		cpu_to_le16(PT_FLAG_ISCSI_PDU | PT_FLAG_WAIT_4_RESPONSE);
	pthru0_iocb->timeout = cpu_to_le16(PT_DEFAULT_TIMEOUT);
	pthru0_iocb->inDataSeg64.base.addrHigh =
		cpu_to_le32(MSDW(buf_addr_dma));
	pthru0_iocb->inDataSeg64.base.addrLow =
		cpu_to_le32(LSDW(buf_addr_dma));
	pthru0_iocb->inDataSeg64.count = cpu_to_le32(len);
	pthru0_iocb->async_pdu_handle = cpu_to_le32(apdu->async_pdu_handle);

	dev_info(&ha->pdev->dev,
			"%s: qla4xxx_issue_iocb\n", __func__);

	if (qla4xxx_issue_iocb(ha, sizeof(struct passthru0),
		ha->gen_req_rsp_iocb_dma) != QLA_SUCCESS) {
		dev_info(&ha->pdev->dev,
			"%s: qla4xxx_issue_iocb failed\n", __func__);
		goto exit_async_pdu_iocb;
	}

	async_event_type = ((struct iscsi_async *)hdr)->async_event;
	pdu_sense = (struct async_pdu_sense *)buf_addr;

	switch (async_event_type) {
	case ISCSI_ASYNC_MSG_SCSI_EVENT:
		dev_info(&ha->pdev->dev,
				"%s: async msg event 0x%x processed\n"
				, __func__, async_event_type);

		qla4xxx_dump_buffer(buf_addr, len);

		if (pdu_sense->sense_data[12] == 0x3F) {
			if (pdu_sense->sense_data[13] == 0x0E) {
				/* reported luns data has changed */
				uint16_t fw_index = apdu->target_id;

				ddb_entry = qla4xxx_lookup_ddb_by_fw_index(ha, fw_index);
				if (ddb_entry == NULL) {
					dev_info(&ha->pdev->dev,
						 "%s: No DDB entry for index [%d]\n"
						 , __func__, fw_index);
					goto exit_async_pdu_iocb;
				}
				if (ddb_entry->fw_ddb_device_state != DDB_DS_SESSION_ACTIVE) {
					dev_info(&ha->pdev->dev,
						 "scsi%ld: %s: No Active Session for index [%d]\n",
						 ha->host_no, __func__, fw_index);
					goto exit_async_pdu_iocb;
				}

				/* report new lun to kernel */
				if (test_bit(AF_ONLINE, &ha->flags))
					scsi_scan_target(&ddb_entry->sess->dev,
						0, ddb_entry->sess->target_id,
						SCAN_WILD_CARD, 0);
			}
		}

		break;
	case ISCSI_ASYNC_MSG_REQUEST_LOGOUT:
	case ISCSI_ASYNC_MSG_DROPPING_CONNECTION:
	case ISCSI_ASYNC_MSG_DROPPING_ALL_CONNECTIONS:
	case ISCSI_ASYNC_MSG_PARAM_NEGOTIATION:
		dev_info(&ha->pdev->dev,
				"%s: async msg event 0x%x processed\n"
				, __func__, async_event_type);
		qla4xxx_conn_close_sess_logout(ha, apdu->target_id, 0, 0);
		break;
	default:
		dev_info(&ha->pdev->dev,
			"%s: async msg event 0x%x not processed\n",
			__func__, async_event_type);
		break;
	};

exit_async_pdu_iocb:
	if (!using_prealloc)
		dma_free_coherent(&ha->pdev->dev, len,
			buf_addr, buf_addr_dma);

	return;
}

/**
 * qla4xxx_do_dpc - dpc routine
 * @data: in our case pointer to adapter structure
 *
 * This routine is a task that is schedule by the interrupt handler
 * to perform the background processing for interrupts.  We put it
 * on a task queue that is consumed whenever the scheduler runs; that's
 * so you can do anything (i.e. put the process to sleep etc).  In fact,
 * the mid-level tries to sleep when it reaches the driver threshold
 * "host->can_queue". This can cause a panic if we were in our interrupt code.
 **/
static void qla4xxx_do_dpc(void *data)
{
	struct scsi_qla_host *ha = (struct scsi_qla_host *) data;
	struct ddb_entry *ddb_entry, *dtemp;
	struct async_msg_pdu_iocb *apdu_iocb, *apdu_iocb_tmp;
	int status = QLA_ERROR;

	DEBUG2(printk("scsi%ld: %s: DPC handler waking up."
		"ha->flags=0x%08lx ha->dpc_flags=0x%08lx\n",
		ha->host_no, __func__, ha->flags, ha->dpc_flags));

	/* Initialization not yet finished. Don't do anything yet. */
	if (!test_bit(AF_INIT_DONE, &ha->flags))
		return;

	if (test_bit(AF_EEH_BUSY, &ha->flags)) {
		DEBUG2(printk(KERN_INFO "scsi%ld: %s: flags = %lx\n",
			ha->host_no, __func__, ha->flags));
		goto do_dpc_exit;
	}

	if (is_qla8022(ha)) {
		if (test_bit(DPC_HA_UNRECOVERABLE, &ha->dpc_flags)) {
			qla4_8xxx_idc_lock(ha);
			qla4_8xxx_wr_32(ha, QLA82XX_CRB_DEV_STATE,
				QLA82XX_DEV_FAILED);
			qla4_8xxx_idc_unlock(ha);
			DEBUG2(printk(KERN_INFO"HW State: FAILED\n"));
			qla4_8xxx_device_state_handler(ha);
		}
		if (test_and_clear_bit(DPC_HA_NEED_QUIESCENT, &ha->dpc_flags)) {
			qla4_8xxx_need_qsnt_handler(ha);
		}
	}

	if ((!test_bit(DPC_RESET_ACTIVE, &ha->dpc_flags)) &&
	    (test_bit(DPC_RESET_HA, &ha->dpc_flags) ||
	    test_bit(DPC_RESET_HA_INTR, &ha->dpc_flags) ||
	    test_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags))) {
		if (ql4xdontresethba) {
				DEBUG2(printk("%s: Don't Reset HBA\n",
						__func__));
				clear_bit(DPC_RESET_HA, &ha->dpc_flags);
				clear_bit(DPC_RESET_HA_INTR, &ha->dpc_flags);
				clear_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags);
				goto dpc_post_reset_ha;
		}
		if (test_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags) ||
			test_bit(DPC_RESET_HA, &ha->dpc_flags)) {
				qla4xxx_recover_adapter(ha);
		}

		/* ISP-4xxx Specific */
		if (test_bit(DPC_RESET_HA_INTR, &ha->dpc_flags)) {
			uint8_t wait_time = RESET_INTR_TOV;

			while ((readw(&ha->reg->ctrl_status) &
				(CSR_SOFT_RESET | CSR_FORCE_SOFT_RESET)) != 0) {
				if (--wait_time == 0)
					break;
				msleep(1000);
			}

			if (wait_time == 0)
				DEBUG2(printk("scsi%ld: %s: SR|FSR "
					      "bit not cleared-- resetting\n",
					      ha->host_no, __func__));
			qla4xxx_abort_active_cmds(ha, DID_RESET << 16);
			if (ql4xxx_lock_drvr_wait(ha) == QLA_SUCCESS) {
				qla4xxx_process_aen(ha, FLUSH_DDB_CHANGED_AENS);
				status = qla4xxx_recover_adapter(ha);
			}
			clear_bit(DPC_RESET_HA_INTR, &ha->dpc_flags);
			if (status == QLA_SUCCESS)
				ha->isp_ops->enable_intrs(ha);
		}
	}

dpc_post_reset_ha:
	/* ---- process AEN? --- */
	if (test_and_clear_bit(DPC_AEN, &ha->dpc_flags))
		qla4xxx_process_aen(ha, PROCESS_ALL_AENS);

	/* ---- Get DHCP IP Address? --- */
	if (test_and_clear_bit(DPC_GET_DHCP_IP_ADDR, &ha->dpc_flags))
		qla4xxx_get_dhcp_ip_address(ha);

	/* ---- Link Change? --- */
	if (test_and_clear_bit(DPC_LINK_CHANGED, &ha->dpc_flags)) {
		if (!test_bit(AF_LINK_UP, &ha->flags)) {
			/* ---- link down? --- */
			qla4xxx_mark_all_devices_missing(ha);
		} else {
			/* ---- link up? ---
			 * F/W will auto login to all devices ONLY ONCE after
			 * link up during driver initialization and runtime
			 * fatal error recovery.  Therefore, the driver must
			 * manually relogin to devices when recovering from
			 * connection failures, logouts, expired KATO, etc. */

			qla4xxx_relogin_all_devices(ha);
		}
	}

	/* ---- remove device ? ---- */
	if (test_and_clear_bit(DPC_REMOVE_DEVICE, &ha->dpc_flags)) {
		list_for_each_entry_safe(ddb_entry, dtemp,
			&ha->ddb_list, list) {
			if (test_and_clear_bit(DF_REMOVE, &ddb_entry->flags)) {
				printk(KERN_INFO
					"%s: ddb[%d] os[%d] - removed\n",
					__func__, ddb_entry->fw_ddb_index,
					ddb_entry->os_target_id);
				qla4xxx_free_ddb(ha, ddb_entry);
			}
		}
	}

	/* ---- relogin device? --- */
	if (adapter_up(ha) &&
	    test_and_clear_bit(DPC_RELOGIN_DEVICE, &ha->dpc_flags)) {
		list_for_each_entry_safe(ddb_entry, dtemp,
					 &ha->ddb_list, list) {
			if (test_and_clear_bit(DF_RELOGIN, &ddb_entry->flags) &&
			    atomic_read(&ddb_entry->state) != DDB_STATE_ONLINE)
				qla4xxx_relogin_device(ha, ddb_entry);

			/*
			 * If mbx cmd times out there is no point
			 * in continuing further.
			 * With large no of targets this can hang
			 * the system.
			 */
			if (test_bit(DPC_RESET_HA, &ha->dpc_flags)) {
				printk(KERN_WARNING "scsi%ld: %s: "
				       "need to reset hba\n",
				       ha->host_no, __func__);
				break;
			}
		}
	}

	/* ---- perform dynamic lun scan? --- */
	if (adapter_up(ha) &&
		test_and_clear_bit(DPC_DYNAMIC_LUN_SCAN, &ha->dpc_flags)) {
		list_for_each_entry_safe(ddb_entry, dtemp,
		&ha->ddb_list, list) {
			if (test_and_clear_bit(DF_DYNAMIC_LUN_SCAN_NEEDED,
				&ddb_entry->flags)) {
				dev_info(&ha->pdev->dev, "%s: ddb[%d] os[%d] "
					"perform dynamic lun scan\n",
					__func__, ddb_entry->fw_ddb_index,
					ddb_entry->os_target_id);
				/* report new lun to kernel */
				if (test_bit(AF_ONLINE, &ha->flags))
					scsi_scan_target(&ddb_entry->sess->dev,
						0, ddb_entry->sess->target_id,
						SCAN_WILD_CARD, 0);
			}
		}
	}

	/* Check for ASYNC PDU IOCBs */
	if (adapter_up(ha) &&
		test_bit(DPC_ASYNC_MSG_PDU, &ha->dpc_flags)) {

		list_for_each_entry_safe(apdu_iocb, apdu_iocb_tmp,
					 &ha->async_iocb_list, list) {
			qla4xxx_async_iocbs(ha, apdu_iocb);
			list_del_init(&apdu_iocb->list);
			kfree(apdu_iocb);
		}
		clear_bit(DPC_ASYNC_MSG_PDU, &ha->dpc_flags);
	}
do_dpc_exit:
	clear_bit(AF_DPC_SCHEDULED, &ha->flags);
}

/**
 * qla4xxx_free_adapter - release the adapter
 * @ha: pointer to adapter structure
 * @rm_host: Also call scsi_remove_host & free ddb list
 **/
static void qla4xxx_free_adapter(struct scsi_qla_host *ha, int rm_host)
{

	if (test_bit(AF_INTERRUPTS_ON, &ha->flags)) {
		/* Turn-off interrupts on the card. */
		ha->isp_ops->disable_intrs(ha);
	}

	/* Remove timer thread, if present */
	if (ha->timer_active)
		qla4xxx_stop_timer(ha);

	/* Kill the kernel thread for this host */
	if (ha->dpc_thread)
		destroy_workqueue(ha->dpc_thread);

	if (rm_host) {
		/* remove devs from iscsi_sessions to scsi_devices */
		qla4xxx_free_ddb_list(ha);
		scsi_remove_host(ha->host);
	}

	/* Put firmware in a known state */
	ha->isp_ops->reset_firmware(ha);
	if (is_qla8022(ha)) {
		qla4_8xxx_idc_lock(ha);
		qla4_8xxx_clear_drv_active(ha);
		qla4_8xxx_idc_unlock(ha);
	}

	/* Detach interrupts */
	if (test_and_clear_bit(AF_IRQ_ATTACHED, &ha->flags))
		qla4xxx_free_irqs(ha);

	/* free extra memory */
	qla4xxx_mem_free(ha);
}

int qla4_8xxx_iospace_config(struct scsi_qla_host *ha)
{
	int status = 0;
	uint8_t revision_id;
	unsigned long mem_base, mem_len, db_base, db_len;
	struct pci_dev *pdev = ha->pdev;

	status = pci_request_regions(pdev, DRIVER_NAME);
	if (status) {
		printk(KERN_WARNING
				"scsi(%ld) Failed to reserve PIO regions (%s) status=%d\n",
				ha->host_no, pci_name(pdev), status);
		goto iospace_error_exit;
	}

	pci_read_config_byte(pdev, PCI_REVISION_ID, &revision_id);
	DEBUG2(printk(KERN_INFO "%s: revision-id=%d\n",
					__func__, revision_id));
	ha->revision_id = revision_id;

	/* remap phys address */
	mem_base = pci_resource_start(pdev, 0); /* 0 is for BAR 0 */
	mem_len = pci_resource_len(pdev, 0);
	DEBUG2(printk(KERN_INFO "%s: ioremap from %lx a size of %lx\n",
					__func__, mem_base, mem_len));

	/* mapping of pcibase pointer */
	ha->nx_pcibase = (unsigned long)ioremap(mem_base, mem_len);
	if (!ha->nx_pcibase) {
		printk(KERN_ERR
			"cannot remap MMIO (%s), aborting\n", pci_name(pdev));
		pci_release_regions(ha->pdev);
		goto iospace_error_exit;
	}

	/* Mapping of IO base pointer, door bell read and write pointer */

	/* mapping of IO base pointer */
	ha->qla4_8xxx_reg = (struct device_reg_82xx  __iomem *)((uint8_t *)ha->nx_pcibase +
			0xbc000 + (ha->pdev->devfn << 11));

	db_base = pci_resource_start(pdev, 4);  /* doorbell is on bar 4 */
	db_len = pci_resource_len(pdev, 4);

	ha->nx_db_wr_ptr = (ha->pdev->devfn == 4 ? QLA82XX_CAM_RAM_DB1 :
		QLA82XX_CAM_RAM_DB2);

	return 0;

iospace_error_exit:
	return -ENOMEM;
}

/***
 * qla4xxx_iospace_config - maps registers
 * @ha: pointer to adapter structure
 *
 * This routines maps HBA's registers from the pci address space
 * into the kernel virtual address space for memory mapped i/o.
 **/
int qla4xxx_iospace_config(struct scsi_qla_host *ha)
{
	unsigned long pio, pio_len, pio_flags;
	unsigned long mmio, mmio_len, mmio_flags;

	pio = pci_resource_start(ha->pdev, 0);
	pio_len = pci_resource_len(ha->pdev, 0);
	pio_flags = pci_resource_flags(ha->pdev, 0);
	if (pio_flags & IORESOURCE_IO) {
		if (pio_len < MIN_IOBASE_LEN) {
			dev_warn(&ha->pdev->dev,
				"Invalid PCI I/O region size\n");
			pio = 0;
		}
	} else {
		dev_warn(&ha->pdev->dev, "region #0 not a PIO resource\n");
		pio = 0;
	}

	/* Use MMIO operations for all accesses. */
	mmio = pci_resource_start(ha->pdev, 1);
	mmio_len = pci_resource_len(ha->pdev, 1);
	mmio_flags = pci_resource_flags(ha->pdev, 1);

	if (!(mmio_flags & IORESOURCE_MEM)) {
		dev_err(&ha->pdev->dev,
			"region #0 not an MMIO resource, aborting\n");
		goto iospace_error_exit;
	}
	if (mmio_len < MIN_IOBASE_LEN) {
		dev_err(&ha->pdev->dev,
			"Invalid PCI mem region size, aborting\n");
		goto iospace_error_exit;
	}

	if (pci_request_regions(ha->pdev, DRIVER_NAME)) {
		dev_warn(&ha->pdev->dev,
			"Failed to reserve PIO/MMIO regions\n");

		goto iospace_error_exit;
	}

	ha->pio_address = pio;
	ha->pio_length = pio_len;
	ha->reg = ioremap(mmio, MIN_IOBASE_LEN);
	if (!ha->reg) {
		dev_err(&ha->pdev->dev,
			"cannot remap MMIO, aborting\n");

		goto iospace_error_exit;
	}

	return 0;

iospace_error_exit:
	return -ENOMEM;
}

struct isp_operations qla4xxx_isp_ops = {
	.iospace_config		= qla4xxx_iospace_config,
	.pci_config		= qla4xxx_pci_config,
	.disable_intrs		= qla4xxx_disable_intrs,
	.enable_intrs		= qla4xxx_enable_intrs,
	.start_firmware		= qla4xxx_start_firmware,
	.intr_handler		= qla4xxx_intr_handler,
	.interrupt_service_routine = qla4xxx_interrupt_service_routine,
	.reset_chip		= qla4xxx_soft_reset,
	.reset_firmware		= qla4xxx_hw_reset,
	.queue_iocb		= qla4xxx_queue_iocb,
	.complete_iocb		= qla4xxx_complete_iocb,
	.rd_shdw_req_q_out	= qla4xxx_rd_shdw_req_q_out,
	.rd_shdw_rsp_q_in	= qla4xxx_rd_shdw_rsp_q_in,
	.get_sys_info		= qla4xxx_get_sys_info,
};
struct isp_operations qla4_8xxx_isp_ops = {
	.iospace_config		= qla4_8xxx_iospace_config,
	.pci_config		= qla4_8xxx_pci_config,
	.disable_intrs		= qla4_8xxx_disable_intrs,
	.enable_intrs		= qla4_8xxx_enable_intrs,
	.start_firmware		= qla4_8xxx_load_risc,
	.intr_handler		= qla4_8xxx_intr_handler,
	.interrupt_service_routine = qla4_8xxx_interrupt_service_routine,
	.reset_chip			= qla4_8xxx_isp_reset,
	.reset_firmware		= qla4_8xxx_stop_firmware,
	.queue_iocb		= qla4_8xxx_queue_iocb,
	.complete_iocb		= qla4_8xxx_complete_iocb,
	.rd_shdw_req_q_out	= qla4_8xxx_rd_shdw_req_q_out,
	.rd_shdw_rsp_q_in	= qla4_8xxx_rd_shdw_rsp_q_in,
	.get_sys_info		= qla4_8xxx_get_sys_info,
};

uint16_t qla4xxx_rd_shdw_req_q_out(struct scsi_qla_host *ha)
{
	return (uint16_t) le32_to_cpu(ha->shadow_regs->req_q_out);
}

uint16_t qla4_8xxx_rd_shdw_req_q_out(struct scsi_qla_host *ha)
{
	return (uint16_t) le32_to_cpu(readl(&ha->qla4_8xxx_reg->req_q_out));
}

uint16_t qla4xxx_rd_shdw_rsp_q_in(struct scsi_qla_host *ha)
{
	return (uint16_t) le32_to_cpu(ha->shadow_regs->rsp_q_in);
}

uint16_t qla4_8xxx_rd_shdw_rsp_q_in(struct scsi_qla_host *ha)
{
	return (uint16_t) le32_to_cpu(readl(&ha->qla4_8xxx_reg->rsp_q_in));
}

static void ql4_get_aen_log(struct scsi_qla_host *ha, struct ql4_aen_log *aenl)
{
	if (aenl) {
		memcpy(aenl, &ha->aen_log, sizeof (ha->aen_log));
		ha->aen_log.count = 0;
	}
}

/**
 * qla4xxx_probe_adapter - callback function to probe HBA
 * @pdev: pointer to pci_dev structure
 * @pci_device_id: pointer to pci_device entry
 *
 * This routine will probe for Qlogic 4xxx iSCSI host adapters.
 * It returns zero if successful. It also initializes all data necessary for
 * the driver.
 **/
static int __devinit qla4xxx_probe_adapter(struct pci_dev *pdev,
											const struct pci_device_id *ent)
{
	int ret = -ENODEV;
	int status = -1;
	struct Scsi_Host *host;
	struct scsi_qla_host *ha;
	struct ddb_entry *ddb_entry, *ddbtemp;
	uint16_t fw_ddb_index;
	uint8_t i;
	char buf[34];
	int rm_host = 0;
	uint32_t dev_state;

	if (pci_enable_device(pdev))
		return -1;

	host = scsi_host_alloc(&qla4xxx_driver_template, sizeof(*ha));
	if (host == NULL) {
		printk(KERN_WARNING
		       "qla4xxx: Couldn't allocate host from scsi layer!\n");
		goto probe_disable_device;
	}

	/* Clear our data area */
	ha = (struct scsi_qla_host *) host->hostdata;
	memset(ha, 0, sizeof(*ha));

	for (fw_ddb_index = 0; fw_ddb_index < MAX_DDB_ENTRIES; fw_ddb_index++)
		ha->fw_ddb_index_map[fw_ddb_index] =
			(struct ddb_entry *)INVALID_ENTRY;

	/* Save the information from PCI BIOS.	*/
	ha->pdev = pdev;
	ha->host = host;
	ha->host_no = host->host_no;

	pci_enable_pcie_error_reporting(pdev);

	/* Setup Runtime configurable options */
	if (is_qla8022(ha))
		ha->isp_ops = &qla4_8xxx_isp_ops;
	else
		ha->isp_ops = &qla4xxx_isp_ops;


	/* ISP 8022 initializations */
	if (is_qla8022(ha)) {
		qla4_8xxx_init_local_data(ha);
	}

	ha->ql4mbx = qla4xxx_mailbox_command;
	ha->ql4cmd = qla4xxx_send_command_to_isp;
	ha->ql4getaenlog = ql4_get_aen_log;

	/* Configure PCI I/O space. */
	ret = ha->isp_ops->iospace_config(ha);
	if (ret)
		goto probe_failed_iospace_config;

	dev_info(&ha->pdev->dev, "Found an ISP%04x, irq %d, iobase 0x%p\n",
		   pdev->device, pdev->irq, ha->reg);

	qla4xxx_config_dma_addressing(ha);

	/* Initialize lists and spinlocks. */
	INIT_LIST_HEAD(&ha->ddb_list);
	INIT_LIST_HEAD(&ha->free_srb_q);
	INIT_LIST_HEAD(&ha->async_iocb_list);

	mutex_init(&ha->mbox_sem);
	init_completion(&ha->mbx_intr_comp);

	spin_lock_init(&ha->hardware_lock);
	spin_lock_init(&ha->list_lock);

	/* Allocate dma buffers */
	if (qla4xxx_mem_alloc(ha)) {
		dev_warn(&ha->pdev->dev,
			   "[ERROR] Failed to allocate memory for adapter\n");

		ret = -ENOMEM;
		goto probe_failed;
	}

	if (is_qla8022(ha))
		(void) qla4_8xxx_get_flash_info(ha);

	/*
	 * Initialize the Host adapter request/response queues and firmware
	 * NOTE: AF_ONLINE flag set upon successful completion of
	 *       qla4xxx_initialize_adapter
	 */
	status = qla4xxx_initialize_adapter(ha, REBUILD_DDB_LIST);

	for (i = 1; !test_bit(AF_ONLINE, &ha->flags) && i <= MAX_INIT_RETRIES; i++) {
		if (is_qla8022(ha)) {
			qla4_8xxx_idc_lock(ha);
			dev_state = qla4_8xxx_rd_32(ha, QLA82XX_CRB_DEV_STATE);
			qla4_8xxx_idc_unlock(ha);
			if (dev_state == QLA82XX_DEV_FAILED) {
				dev_info(&ha->pdev->dev, "%s: don't retry "
						"adapter init. H/W is in "
						"Failed state\n", __func__);
				break;
			}
		}

		DEBUG2(dev_info(&ha->pdev->dev, "%s: retry adapter init %d\n",
			__func__, i));

		if (ha->isp_ops->reset_chip(ha) == QLA_ERROR)
			continue;

		status = qla4xxx_initialize_adapter(ha, REBUILD_DDB_LIST);
	}
	if (!test_bit(AF_ONLINE, &ha->flags)) {
		dev_warn(&ha->pdev->dev, "Failed to initialize adapter\n");

		if (is_qla8022(ha)) {
			/* Put the device in failed state. */
			qla4_8xxx_idc_lock(ha);
			qla4_8xxx_clear_drv_active(ha);
			if (ql4xdontresethba == 1) {
				dev_info(&ha->pdev->dev, "%s: HW State: "
					"setting to failed\n", __func__);
				qla4_8xxx_wr_32(ha, QLA82XX_CRB_DEV_STATE,
					QLA82XX_DEV_FAILED);
			}
			qla4_8xxx_idc_unlock(ha);
		}
		ret = -ENODEV;
		goto probe_failed;
	}

	host->cmd_per_lun = 3;
	host->max_channel = 0;
	host->max_lun = MAX_LUNS - 1;
	host->max_id = MAX_TARGETS;
	host->max_cmd_len = IOCB_MAX_CDB_LEN;
	host->can_queue = REQUEST_QUEUE_DEPTH + 128;
	host->transportt = qla4xxx_scsi_transport;

	/* Startup the kernel thread for this host adapter. */
	DEBUG2(printk("scsi: %s: Starting kernel thread for "
		      "qla4xxx_dpc\n", __func__));
	sprintf(buf, "qla4xxx_%lu_dpc", ha->host_no);
	ha->dpc_thread = create_singlethread_workqueue(buf);
	if (!ha->dpc_thread) {
		dev_warn(&ha->pdev->dev, "Unable to start DPC thread!\n");
		ret = -ENODEV;
		goto probe_failed;
	}
	INIT_WORK(&ha->dpc_work, qla4xxx_do_dpc, ha);

	if (!is_qla8022(ha)) {
		ret = qla4xxx_request_irqs(ha);
		if (ret) {
			dev_warn(&ha->pdev->dev, "Failed to reserve interrupt %d"
				" already in use.\n", pdev->irq);
			goto probe_failed;
		}
	}

	ha->isp_ops->enable_intrs(ha);

	pci_save_state(ha->pdev);

	/* Start timer thread. */
	qla4xxx_start_timer(ha, qla4xxx_timer, 1);

	set_bit(AF_INIT_DONE, &ha->flags);

	pci_set_drvdata(pdev, ha);

	ret = scsi_add_host(host, &pdev->dev);
	if (ret)
		goto probe_failed;

	/* Update transport device information for all devices. */
	list_for_each_entry_safe(ddb_entry, ddbtemp, &ha->ddb_list, list) {
		if (ddb_entry->fw_ddb_device_state == DDB_DS_SESSION_ACTIVE)
			if (qla4xxx_add_sess(ddb_entry, 1))
				goto remove_host;
	}

	set_bit(AF_PROBE_DONE, &ha->flags);

	printk(KERN_INFO
	       " QLogic iSCSI HBA Driver version: %s\n"
	       "  QLogic ISP%04x @ %s, pdev = %p host#=%ld, fw=%02d.%02d.%02d.%02d\n",
	       qla4xxx_version_str, ha->pdev->device, pci_name(ha->pdev), pdev,
	       ha->host_no, ha->firmware_version[0], ha->firmware_version[1],
	       ha->patch_number, ha->build_number);

        /* Insert new entry into the list of adapters. */
	klist_add_tail(&ha->node, &qla4xxx_hostlist);
	ha->instance = atomic_inc_return(&qla4xxx_hba_count) - 1;

        DEBUG2(printk("qla4xxx: listhead=%p, done adding ha=%p i=%d\n",
            &qla4xxx_hostlist, &ha->node, ha->instance));

	return 0;

remove_host:
	rm_host = 1;

probe_failed:
	qla4xxx_free_adapter(ha, rm_host);

probe_failed_iospace_config:
	pci_disable_pcie_error_reporting(pdev);
	scsi_host_put(ha->host);

probe_disable_device:
	pci_disable_device(pdev);

	return ret;
}

/**
 * qla4xxx_prevent_other_port_reinit - Mark the other ISP-4xxx port to indicate
 * that the driver is being removed, so that the other port will not
 * re-initialize while in the process of removing the ha due to driver unload
 * or hba hotplug.
 * @ha: pointer to adapter structure
 **/
static void qla4xxx_prevent_other_port_reinit(struct scsi_qla_host *ha)
{
	struct scsi_qla_host *ha_listp;
	struct klist_iter i;
	struct klist_node *n;

	klist_iter_init(&qla4xxx_hostlist, &i);
	while ((n = klist_next(&i)) != NULL) {
		ha_listp = container_of(n, struct scsi_qla_host, node);
		if (ha == ha_listp)
			continue;

		if ((pci_domain_nr(ha->pdev->bus) ==
			pci_domain_nr(ha_listp->pdev->bus)) &&
			(ha->pdev->bus->number ==
			ha_listp->pdev->bus->number) &&
			(PCI_SLOT(ha->pdev->devfn) ==
			PCI_SLOT(ha_listp->pdev->devfn))) {
			set_bit(AF_HA_REMOVAL, &ha_listp->flags);
			DEBUG2(printk(KERN_INFO
				"iscsi%ld %s: Prevent %s reinit\n",
				ha->host_no, __func__,
				kobject_name(&((ha_listp)->pdev->dev).kobj)));
		}
	}
	klist_iter_exit(&i);
}

/**
 * qla4xxx_remove_adapter - calback function to remove adapter.
 * @pci_dev: PCI device pointer
 **/
static void __devexit qla4xxx_remove_adapter(struct pci_dev *pdev)
{
	struct scsi_qla_host *ha;
	int rm_host = 1;

	ha = pci_get_drvdata(pdev);

	dev_info(&ha->pdev->dev, "scsi%d: %s:\n", ha->host->host_no, __func__);

	ha->isp_ops->disable_intrs(ha);

	if (!is_qla8022(ha))
		qla4xxx_prevent_other_port_reinit(ha);

	klist_remove(&ha->node);
	atomic_dec(&qla4xxx_hba_count);

	qla4xxx_free_adapter(ha, rm_host);

	scsi_host_put(ha->host);

	pci_disable_pcie_error_reporting(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

/**
 * qla4xxx_config_dma_addressing() - Configure OS DMA addressing method.
 * @ha: HA context
 *
 * At exit, the @ha's flags.enable_64bit_addressing set to indicated
 * supported addressing method.
 */
static void qla4xxx_config_dma_addressing(struct scsi_qla_host *ha)
{
	int retval;

	/* Update our PCI device dma_mask for full 64 bit mask */
	if (pci_set_dma_mask(ha->pdev, DMA_64BIT_MASK) == 0) {
		if (pci_set_consistent_dma_mask(ha->pdev, DMA_64BIT_MASK)) {
			dev_dbg(&ha->pdev->dev,
				  "Failed to set 64 bit PCI consistent mask; "
				   "using 32 bit.\n");
			retval = pci_set_consistent_dma_mask(ha->pdev,
							     DMA_32BIT_MASK);
		}
	} else
		retval = pci_set_dma_mask(ha->pdev, DMA_32BIT_MASK);
}

static int qla4xxx_slave_alloc(struct scsi_device *sdev)
{
	struct iscsi_cls_session *sess = starget_to_session(sdev->sdev_target);

	if (sess) {
		sdev->hostdata = sess->dd_data;
		return 0;
	}
	return FAILED;
}

static int qla4xxx_slave_configure(struct scsi_device *sdev)
{
	int queue_depth = QL4_DEF_QDEPTH;

	if (ql4xmaxqdepth != 0 && ql4xmaxqdepth <= 0xffffU)
		queue_depth = ql4xmaxqdepth;

	if (sdev->tagged_supported)
		scsi_activate_tcq(sdev, queue_depth);
	else
		scsi_deactivate_tcq(sdev, queue_depth);

	return 0;
}

static void qla4xxx_slave_destroy(struct scsi_device *sdev)
{
	sdev->hostdata = NULL;
}

/**
 * qla4xxx_del_from_active_array - returns an active srb
 * @ha: Pointer to host adapter structure.
 * @index: index into to the active_array
 *
 * This routine removes and returns the srb at the specified index
 **/
struct srb *qla4xxx_del_from_active_array(struct scsi_qla_host *ha, uint32_t index)
{
	struct srb *srb = NULL;

	/* validate handle and remove from active array */
	if (index >= MAX_SRBS)
		return srb;

	srb = ha->active_srb_array[index];
	ha->active_srb_array[index] = NULL;
	if (!srb)
		return srb;

	/* update counters */
	if (srb->flags & SRB_DMA_VALID) {
		ha->req_q_count += srb->iocb_cnt;
		ha->iocb_cnt -= srb->iocb_cnt;
		if (srb->cmd)
			srb->cmd->host_scribble = NULL;
	}
	return srb;
}

/**
 * qla4xxx_eh_wait_on_command - waits for command to be returned by firmware
 * @ha: actual ha whose done queue will contain the comd returned by firmware.
 * @cmd: Scsi Command to wait on.
 * @got_ref: Additional reference retrieved by caller.
 *
 * This routine waits for the command to be returned by the Firmware
 * for some max time.
 **/
static int qla4xxx_eh_wait_on_command(struct scsi_qla_host *ha,
				      struct scsi_cmnd *cmd, int got_ref)
{
	int done = 0;
	struct srb *rp;
	uint32_t max_wait_time = EH_WAIT_CMD_TOV;
	int ret = SUCCESS;

	/* Dont wait on command if PCI error is being handled
	 * by PCI AER driver
	 */
	if (unlikely(pci_channel_offline(ha->pdev)) ||
			(test_bit(AF_EEH_BUSY, &ha->flags))) {
		dev_warn(&ha->pdev->dev, "scsi%ld: Return from %s\n",
				ha->host_no, __func__);
		return ret;
	}


	do {
		/* Checking to see if its returned to OS */
		rp = (struct srb *) CMD_SP(cmd);
		if (rp == NULL) {
			done++;
			break;
		}

		msleep(2000);
	} while (max_wait_time--);

	return done;
}

/**
 * qla4xxx_wait_for_hba_online - waits for HBA to come online
 * @ha: Pointer to host adapter structure
 **/
static int qla4xxx_wait_for_hba_online(struct scsi_qla_host *ha)
{
	unsigned long wait_online;

	wait_online = jiffies + (HBA_ONLINE_TOV * HZ);
	while (time_before(jiffies, wait_online)) {

		if (test_bit(AF_ONLINE, &ha->flags) != 0)
			return QLA_SUCCESS;

		msleep(2000);
	}

	return QLA_ERROR;
}

/**
 * qla4xxx_eh_wait_for_active_target_commands - wait for active cmds to finish.
 * @ha: pointer to to HBA
 * @t: target id
 * @l: lun id
 *
 * This function waits for all outstanding commands to a lun to complete. It
 * returns 0 if all pending commands are returned and 1 otherwise.
 **/
static int qla4xxx_eh_wait_for_active_target_commands(struct scsi_qla_host *ha,
						 int t, int l)
{
	int cnt;
	int status;
	struct srb *sp;
	struct scsi_cmnd *cmd;
	unsigned long flags;

	/*
	 * Waiting for all commands for the designated target in the active
	 * array
	 */
	status = 0;
	for (cnt = 1; cnt < MAX_SRBS; cnt++) {
		spin_lock_irqsave(&ha->hardware_lock, flags);
		sp = ha->active_srb_array[cnt];
		if (sp) {
			cmd = sp->cmd;
			spin_unlock_irqrestore(&ha->hardware_lock, flags);
			if (cmd->device->id == t && cmd->device->lun == l) {
				if (!qla4xxx_eh_wait_on_command(ha, cmd, 0)) {
					status++;
					break;
				}
			}
		} else {
			spin_unlock_irqrestore(&ha->hardware_lock, flags);
		}
	}
	return status;
}

/**
 * qla4xxx_eh_abort - callback for abort task.
 * @cmd: Pointer to Linux's SCSI command structure
 *
 * This routine is called by the Linux OS to abort the specified
 * command.
 **/
static int qla4xxx_eh_abort(struct scsi_cmnd *cmd)
{
	struct scsi_qla_host *ha = to_qla_host(cmd->device->host);
	struct srb *srb = NULL;
	struct ddb_entry *ddb_entry = cmd->device->hostdata;
	int ret = FAILED;
	unsigned int channel = cmd->device->channel;
	unsigned int id = cmd->device->id;
	unsigned int lun = cmd->device->lun;
	unsigned long serial = cmd->serial_number;
	int i = 0;
	int got_ref = 0;
	unsigned long flags = 0;
	unsigned long wait_online;

	if (!ddb_entry) {
		DEBUG2(printk("scsi%ld: ABORT - NULL ddb entry.\n", ha->host_no));
		return FAILED;
	}

	if (cmd == NULL) {
		DEBUG2(printk("scsi%ld: ABORT - **** SCSI mid-layer passing in NULL cmd\n",
				ha->host_no));
		return SUCCESS;
	}

	spin_lock_irqsave(&ha->hardware_lock, flags);
	srb = (struct srb *) CMD_SP(cmd);
	if (!srb) {
		DEBUG2(printk("scsi%ld: ABORT - cmd already completed.\n",
				ha->host_no));
		spin_unlock_irqrestore(&ha->hardware_lock, flags);
		return SUCCESS;
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	dev_info(&ha->pdev->dev, "scsi%ld:%d:%d:%d: ABORT ISSUED "
		 "cmd=%p, pid=%ld, ref=%d\n", ha->host_no, channel, id, lun,
		 cmd, serial, atomic_read(&srb->srb_ref.refcount));

	if (qla4xxx_wait_for_hba_online(ha) != QLA_SUCCESS) {
		DEBUG2(printk("scsi%ld:%d: %s: Unable to abort task. Adapter "
				"DEAD.\n", ha->host_no, cmd->device->channel
				, __func__));

		return FAILED;
	}

	/* Check active list for command */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	for (i = 1; i < MAX_SRBS; i++) {
		srb =  ha->active_srb_array[i];

		if (srb == NULL)
			continue;

		if (srb->cmd != cmd)
			continue;

		DEBUG2(printk("scsi%ld:%d:%d:%d %s: aborting srb %p from RISC. "
			      "pid=%ld.\n", ha->host_no, channel, id, lun,
			      __func__, srb, serial));
		DEBUG3(qla4xxx_print_scsi_cmd(cmd));

		/* Get a reference to the sp and drop the lock.*/
		kref_get(&srb->srb_ref);
		got_ref++;
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		/*
		 * If device is not online wait for 10 sec for device to come online,
		 * else return error and do not issue abort task.
		 */
		if (atomic_read(&ddb_entry->state) != DDB_STATE_ONLINE) {
			wait_online = jiffies + (DEVICE_ONLINE_TOV * HZ);
			while (time_before(jiffies, wait_online)) {
				set_current_state(TASK_INTERRUPTIBLE);
				schedule_timeout(HZ);
				if (atomic_read(&ddb_entry->state) == DDB_STATE_ONLINE)
					break;
			}
			if (atomic_read(&ddb_entry->state) != DDB_STATE_ONLINE) {
				DEBUG2(printk("scsi%ld:%d: %s: Unable to abort task."
					      "Device is not online.\n", ha->host_no
					      , cmd->device->channel, __func__));
				kref_put(&srb->srb_ref, qla4xxx_srb_compl);
				goto exit_qla4xxx_eh_abort;
			}
		}

		if (qla4xxx_abort_task(ha, srb) != QLA_SUCCESS) {
			dev_info(&ha->pdev->dev,
				"scsi%ld:%d:%d:%d: ABORT TASK - FAILED.\n",
				ha->host_no, channel, id, lun);
		} else {
			dev_info(&ha->pdev->dev,
				"scsi%ld:%d:%d:%d: ABORT TASK - mbx success.\n",
				ha->host_no, channel, id, lun);
		}
		spin_lock_irqsave(&ha->hardware_lock, flags);
		break;
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (i < MAX_SRBS) {
		if (qla4xxx_eh_wait_on_command(ha, cmd, got_ref)) {
			dev_info(&ha->pdev->dev,
				 "scsi%ld:%d:%d:%d: ABORT SUCCEEDED - "
				 "cmd returned back to OS.\n",
				 ha->host_no, channel, id, lun);
			ret = SUCCESS;
		}
		DEBUG2(printk("scsi%ld:%d:%d:%d: ABORT cmd=%p, pid=%ld, ref=%d, "
			"ret=%x\n", ha->host_no, channel, id, lun, cmd,
			serial, atomic_read(&srb->srb_ref.refcount), ret));
		kref_put(&srb->srb_ref, qla4xxx_srb_compl);
	} else {
		dev_info(&ha->pdev->dev, "scsi%ld:%d:%d:%d: ABORT FAILED",
			ha->host_no, channel, id, lun);
		ret = FAILED;
	}

exit_qla4xxx_eh_abort:
	return ret;
}

/**
 * qla4xxx_eh_device_reset - callback for target reset.
 * @cmd: Pointer to Linux's SCSI command structure
 *
 * This routine is called by the Linux OS to reset all luns on the
 * specified target.
 **/
static int qla4xxx_eh_device_reset(struct scsi_cmnd *cmd)
{
	struct scsi_qla_host *ha;
	struct ddb_entry *ddb_entry;
	int ret = FAILED, stat;
	struct Scsi_Host *h;
	unsigned int b, t, l;

	if (cmd == NULL) {
		DEBUG2(printk("%s: **** SCSI mid-layer passing in NULL cmd"
				"DEVICE RESET - cmd already completed.\n",
				__func__));
		return SUCCESS;
	}

	h = cmd->device->host;
	b = cmd->device->channel;
	t = cmd->device->id;
	l = cmd->device->lun;
	ha = to_qla_host(cmd->device->host);
	ddb_entry = cmd->device->hostdata;
	if (!ddb_entry) {
		DEBUG2(printk("scsi%ld: DEVICE RESET - NULL ddb entry.\n", ha->host_no));
		return ret;
	}

	if (test_bit(DPC_RESET_ACTIVE, &ha->dpc_flags)) {
		DEBUG2(printk("scsi%ld: %s: Don't Reset.  "
			      "HBA Reset Active!\n", ha->host_no, __func__));
		return FAILED;
	}
	dev_info(&ha->pdev->dev,
		   "scsi%ld:%d:%d:%d: DEVICE RESET ISSUED.\n", ha->host_no, b, t, l);

	DEBUG2(printk(KERN_INFO
		      "scsi%ld: DEVICE_RESET cmd=%p jiffies = 0x%lx, to=%x,"
		      "dpc_flags=%lx, status=%x allowed=%d\n", ha->host_no,
		      cmd, jiffies, cmd->timeout_per_command / HZ,
		      ha->dpc_flags, cmd->result, cmd->allowed));

	if (qla4xxx_wait_for_hba_online(ha) != QLA_SUCCESS) {
		DEBUG2(printk("scsi%ld:%d: %s: DEVICE RESET. Adapter "
				"Offline.\n", ha->host_no, b, __func__));

		return FAILED;
	}

	stat = qla4xxx_reset_lun(ha, ddb_entry, l);
	if (stat != QLA_SUCCESS) {
		dev_info(&ha->pdev->dev, "DEVICE RESET FAILED. %d\n", stat);
		goto eh_dev_reset_done;
	}

	/*
	 * If we are coming down the EH path, wait for all commands to complete
	 * for the device.
	 */
	if (cmd->device->host->shost_state == SHOST_RECOVERY) {
		if (qla4xxx_eh_wait_for_active_target_commands(ha, t, l)) {
			dev_info(&ha->pdev->dev,
				   "DEVICE RESET FAILED - waiting for "
				   "commands.\n");
			goto eh_dev_reset_done;
		}
	}
	if (qla4xxx_send_marker_iocb(ha, ddb_entry, l) != QLA_SUCCESS)
		goto eh_dev_reset_done;

	dev_info(&ha->pdev->dev,
		   "scsi(%ld:%d:%d:%d): DEVICE RESET SUCCEEDED.\n", ha->host_no, b, t, l);

	ret = SUCCESS;

eh_dev_reset_done:

	return ret;
}

/**
 * qla4xxx_eh_host_reset - kernel callback
 * @cmd: Pointer to Linux's SCSI command structure
 *
 * This routine is invoked by the Linux kernel to perform fatal error
 * recovery on the specified adapter.
 **/
static int qla4xxx_eh_host_reset(struct scsi_cmnd *cmd)
{
	int return_status = FAILED;
	struct scsi_qla_host *ha;

	if (cmd == NULL) {
		DEBUG2(printk("%s: **** SCSI mid-layer passing in NULL cmd"
				"HOST RESET - cmd already completed.\n",
				__func__));
		return SUCCESS;
	}

	ha = (struct scsi_qla_host *) cmd->device->host->hostdata;

	dev_info(&ha->pdev->dev,
		   "scsi(%ld:%d:%d:%d): HOST RESET ISSUED.\n", ha->host_no,
		   cmd->device->channel, cmd->device->id, cmd->device->lun);

	if (ql4xdontresethba) {
			DEBUG2(printk("%s: Don't Reset HBA\n", __func__));
			return FAILED;
	}

	if (qla4xxx_wait_for_hba_online(ha) != QLA_SUCCESS) {
		DEBUG2(printk("scsi%ld:%d: %s: Unable to reset host.  Adapter "
			      "DEAD.\n", ha->host_no, cmd->device->channel,
			      __func__));

		return FAILED;
	}

	if (!test_bit(DPC_RESET_HA, &ha->dpc_flags)) {
		(is_qla8022(ha)) ?
			set_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags) :
			set_bit(DPC_RESET_HA, &ha->dpc_flags);
	}

	if (qla4xxx_recover_adapter(ha) == QLA_SUCCESS)
		return_status = SUCCESS;

	dev_info(&ha->pdev->dev, "HOST RESET %s.\n",
		   return_status == FAILED ? "FAILED" : "SUCCEDED");

	return return_status;
}

/* PCI AER driver recovers from all correctable errors w/o
 * driver intervention. For uncorrectable errors PCI AER
 * driver calls the following device driver's callbacks
 *
 * - Fatal Errors - link_reset
 * - Non-Fatal Errors - driver's pci_error_detected() which
 * returns CAN_RECOVER, NEED_RESET or DISCONNECT.
 *
 * PCI AER driver calls
 * CAN_RECOVER - driver's pci_mmio_enabled(), mmio_enabled
 *               returns RECOVERED or NEED_RESET if fw_hung
 * NEED_RESET - driver's slot_reset()
 * DISCONNECT - device is dead & cannot recover
 * RECOVERED - driver's pci_resume()
 */
static pci_ers_result_t
qla4xxx_pci_error_detected(struct pci_dev *pdev, pci_channel_state_t state)
{
	struct scsi_qla_host *ha = pci_get_drvdata(pdev);

	printk(KERN_WARNING "scsi%ld: func %x: %s: error detected:state %x\n",
		ha->host_no, PCI_FUNC(pdev->devfn), __func__, state);

	if (!is_aer_supported(ha))
		return PCI_ERS_RESULT_NONE;

	switch (state) {
	case pci_channel_io_normal:
		clear_bit(AF_EEH_BUSY, &ha->flags);
		return PCI_ERS_RESULT_CAN_RECOVER;
	case pci_channel_io_frozen:
		set_bit(AF_EEH_BUSY, &ha->flags);
		qla4xxx_mailbox_premature_completion(ha);
		qla4xxx_free_irqs(ha);
		pci_disable_device(pdev);
		/* Abort all active commands */
		qla4xxx_abort_active_cmds(ha, DID_RESET << 16);
		return PCI_ERS_RESULT_NEED_RESET;
	case pci_channel_io_perm_failure:
		set_bit(AF_EEH_BUSY, &ha->flags);
		set_bit(AF_PCI_CHANNEL_IO_PERM_FAILURE, &ha->flags);
		qla4xxx_abort_active_cmds(ha, DID_NO_CONNECT << 16);
		return PCI_ERS_RESULT_DISCONNECT;
	}
	return PCI_ERS_RESULT_NEED_RESET;
}

/* qla4xxx_pci_mmio_enabled() gets called if
 * qla4xxx_pci_error_detected() returns PCI_ERS_RESULT_CAN_RECOVER
 * and read/write to the device still works.
 */
static pci_ers_result_t
qla4xxx_pci_mmio_enabled(struct pci_dev *pdev)
{
	struct scsi_qla_host *ha = pci_get_drvdata(pdev);

	if (!is_aer_supported(ha))
		return PCI_ERS_RESULT_NONE;

	return PCI_ERS_RESULT_RECOVERED;
}

static uint32_t qla4_8xxx_error_recovery(struct scsi_qla_host *ha)
{
	uint32_t rval = QLA_ERROR;
	uint32_t ret = 0;
	int fn;
	struct pci_dev *other_pdev = NULL;

	printk(KERN_WARNING "scsi%ld func %x: In %s\n",
		ha->host_no, PCI_FUNC(ha->pdev->devfn), __func__);

	set_bit(DPC_RESET_ACTIVE, &ha->dpc_flags);

	if (test_bit(AF_ONLINE, &ha->flags)) {
		clear_bit(AF_ONLINE, &ha->flags);
		qla4xxx_mark_all_devices_missing(ha);
		qla4xxx_process_aen(ha, FLUSH_DDB_CHANGED_AENS);
	}

	fn = PCI_FUNC(ha->pdev->devfn);
	while (fn > 0) {
		fn--;
		printk(KERN_INFO "scsi%ld: %s: Finding PCI device at "
			"func %x\n", ha->host_no, __func__, fn);
		/* Get the pci device given the domain, bus,
		 * slot/function number */
		other_pdev =
		    pci_get_domain_bus_and_slot(pci_domain_nr(ha->pdev->bus),
		    ha->pdev->bus->number, PCI_DEVFN(PCI_SLOT(ha->pdev->devfn),
		    fn));

		if (other_pdev && other_pdev->is_enabled) {
			printk(KERN_INFO "scsi%ld: %s: Found PCI func in "
			    "enabled state%x\n", ha->host_no, __func__, fn);
			pci_dev_put(other_pdev);
			break;
		}
		pci_dev_put(other_pdev);
	}

	/* The first function on the card, the reset owner will
	 * start & initialize the firmware. The other functions
	 * on the card will reset the firmware context
	 */
	if (!fn) {
		printk(KERN_INFO "scsi%ld: %s: devfn being reset 0x%x is the "
			"owner\n", ha->host_no, __func__, ha->pdev->devfn);

		qla4_8xxx_idc_lock(ha);
		qla4_8xxx_wr_32(ha, QLA82XX_CRB_DEV_STATE, QLA82XX_DEV_COLD);

		qla4_8xxx_wr_32(ha, QLA82XX_CRB_DRV_IDC_VERSION,
						QLA82XX_IDC_VERSION);

		qla4_8xxx_idc_unlock(ha);

		clear_bit(AF_FW_RECOVERY, &ha->flags);

		rval = qla4xxx_initialize_adapter(ha, PRESERVE_DDB_LIST);
		qla4_8xxx_idc_lock(ha);
		if (rval != QLA_SUCCESS) {
			printk(KERN_INFO "scsi%ld: %s: hw state: failed \n",
				ha->host_no, __func__);
			qla4_8xxx_clear_drv_active(ha);
			qla4_8xxx_wr_32(ha, QLA82XX_CRB_DEV_STATE,
				QLA82XX_DEV_FAILED);
		} else {
			printk(KERN_INFO "scsi%ld: %s: hw state: ready \n",
				ha->host_no, __func__);
			qla4_8xxx_wr_32(ha, QLA82XX_CRB_DEV_STATE,
				QLA82XX_DEV_READY);
			/* clear driver state register */
			qla4_8xxx_wr_32(ha, QLA82XX_CRB_DRV_STATE, 0);
			qla4_8xxx_set_drv_active(ha);
			ret = qla4xxx_request_irqs(ha);
			if (ret) {
				ql4_printk(KERN_WARNING, ha, "Failed to "
				    "reserve interrupt %d already in use.\n",
				    ha->pdev->irq);
				rval = QLA_ERROR;
			} else {
				ha->isp_ops->enable_intrs(ha);
				rval = QLA_SUCCESS;
			}
		}
		qla4_8xxx_idc_unlock(ha);
	} else {
		printk(KERN_INFO "scsi%ld: %s: devfn 0x%x is not the "
			"reset owner\n", ha->host_no, __func__,
			ha->pdev->devfn);
		if ((qla4_8xxx_rd_32(ha, QLA82XX_CRB_DEV_STATE) ==
			QLA82XX_DEV_READY)) {
			clear_bit(AF_FW_RECOVERY, &ha->flags);
			/* Firmware has been loaded & started by the
			 * first function Initialize the firmware and
			 * ddb list
			 */
			rval = qla4xxx_initialize_adapter(ha,
			    PRESERVE_DDB_LIST);
			if (rval == QLA_SUCCESS) {
				ret = qla4xxx_request_irqs(ha);
				if (ret) {
					ql4_printk(KERN_WARNING, ha, "Failed to"
					    " reserve interrupt %d already in"
					    " use.\n", ha->pdev->irq);
					rval = QLA_ERROR;
				} else {
					ha->isp_ops->enable_intrs(ha);
					rval = QLA_SUCCESS;
				}
			}
			qla4_8xxx_idc_lock(ha);
			qla4_8xxx_set_drv_active(ha);
			qla4_8xxx_idc_unlock(ha);
		}
	}
	clear_bit(DPC_RESET_ACTIVE, &ha->dpc_flags);
	return rval;
}

static pci_ers_result_t
qla4xxx_pci_slot_reset(struct pci_dev *pdev)
{
	pci_ers_result_t ret = PCI_ERS_RESULT_DISCONNECT;
	struct scsi_qla_host *ha = pci_get_drvdata(pdev);
	int rc;

	printk(KERN_WARNING "scsi%ld: func %x: %s: slot_reset \n",
		ha->host_no, PCI_FUNC(pdev->devfn), __func__);

	if (!is_aer_supported(ha))
		return PCI_ERS_RESULT_NONE;

	/* Workaround to properly reflect error_state as
	 * pci_channel_io_online as result of eeh_reset_device()
	 * called just prior to this callback.
	 * eeh_driver.c delays updating error_state until
	 * report_resume callback which is too late for
	 * qla2xxx driver which access hardware earlier.
	 * Can be removed when fixed in mainline.
	 */
	pdev->error_state = pci_channel_io_normal;

	/* Restore the saved state of PCIe device -
	 * Bar registers, pci config space, PCIx, MSI,
	 * IOV states
	 */
	pci_restore_state(pdev);

	/* pci_restore_state() clears the saved_state flag of the device
	 * save restored state which resets saved_state flag.
	 */
	pci_save_state(pdev);

	/* initialize device or resume if in suspended state */
	rc = pci_enable_device(pdev);
	if (rc) {
		printk(KERN_WARNING "scsi%ld: %s: Cant re-enable "
			"device after reset\n", ha->host_no, __func__);
		goto exit_slot_reset;
	}

	ha->isp_ops->disable_intrs(ha);

	if (is_qla8022(ha)) {
		if (qla4_8xxx_error_recovery(ha) == QLA_SUCCESS) {
			ret = PCI_ERS_RESULT_RECOVERED;
			goto exit_slot_reset;
		} else
			goto exit_slot_reset;
	}

exit_slot_reset:
	printk(KERN_WARNING "scsi%ld: func %x: %s: Return=%x \n"
		"device after reset\n",
		ha->host_no, PCI_FUNC(pdev->devfn), __func__, ret);
	return ret;
}

static void
qla4xxx_pci_resume(struct pci_dev *pdev)
{
	struct scsi_qla_host *ha = pci_get_drvdata(pdev);
	int ret;

	printk(KERN_WARNING "scsi%ld: func %x: %s: pci_resume \n",
		ha->host_no, PCI_FUNC(pdev->devfn), __func__);

	ret = qla4xxx_wait_for_hba_online(ha);
	if (ret != QLA_SUCCESS) {
		printk(KERN_ERR "scsi%ld: func %x: %s:"
			"the device failed to resume i/o "
			"from slot/link_reset\n",
			ha->host_no, PCI_FUNC(pdev->devfn), __func__);
	}

	pci_cleanup_aer_uncorrect_error_status(pdev);
	clear_bit(AF_EEH_BUSY, &ha->flags);
}

static struct pci_error_handlers qla4xxx_err_handler = {
	.error_detected	= qla4xxx_pci_error_detected,
	.mmio_enabled	= qla4xxx_pci_mmio_enabled,
	.slot_reset	= qla4xxx_pci_slot_reset,
	.resume		= qla4xxx_pci_resume,
};


static struct pci_device_id qla4xxx_pci_tbl[] = {
	{
		.vendor		= PCI_VENDOR_ID_QLOGIC,
		.device		= PCI_DEVICE_ID_QLOGIC_ISP4010,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
	},
	{
		.vendor		= PCI_VENDOR_ID_QLOGIC,
		.device		= PCI_DEVICE_ID_QLOGIC_ISP4022,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
	},
	{
		.vendor		= PCI_VENDOR_ID_QLOGIC,
		.device		= PCI_DEVICE_ID_QLOGIC_ISP4032,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
	},
	{
		.vendor		= PCI_VENDOR_ID_QLOGIC,
		.device		= PCI_DEVICE_ID_QLOGIC_ISP8022,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
	},
	{0, 0},
};
MODULE_DEVICE_TABLE(pci, qla4xxx_pci_tbl);

struct pci_driver qla4xxx_pci_driver = {
	.name		= DRIVER_NAME,
	.id_table	= qla4xxx_pci_tbl,
	.probe		= qla4xxx_probe_adapter,
	.remove		= qla4xxx_remove_adapter,
	.err_handler	= &qla4xxx_err_handler,
};

static int __init qla4xxx_module_init(void)
{
	int ret;

	atomic_set(&qla4xxx_hba_count, 0);
	klist_init(&qla4xxx_hostlist, NULL, NULL);
	/* Allocate cache for SRBs. */
	srb_cachep = kmem_cache_create("qla4xxx_srbs", sizeof(struct srb), 0,
				       SLAB_HWCACHE_ALIGN, NULL, NULL);
	if (srb_cachep == NULL) {
		printk(KERN_ERR
		       "%s: Unable to allocate SRB cache..."
		       "Failing load!\n", DRIVER_NAME);
		ret = -ENOMEM;
		goto no_srp_cache;
	}

	/* Derive version string. */
	strcpy(qla4xxx_version_str, QLA4XXX_DRIVER_VERSION);
	if (ql4xextended_error_logging)
		strcat(qla4xxx_version_str, "-debug");

	qla4xxx_scsi_transport =
		iscsi2_register_transport(&qla4xxx_iscsi_transport);
	if (!qla4xxx_scsi_transport){
		ret = -ENODEV;
		goto release_srb_cache;
	}

	printk(KERN_INFO "QLogic iSCSI HBA Driver\n");
	ret = pci_register_driver(&qla4xxx_pci_driver);
	if (ret)
		goto unregister_transport;

	printk(KERN_INFO "QLogic iSCSI HBA Driver\n");
	return 0;
unregister_transport:
	iscsi2_unregister_transport(&qla4xxx_iscsi_transport);
release_srb_cache:
	kmem_cache_destroy(srb_cachep);
no_srp_cache:
	return ret;
}

static void __exit qla4xxx_module_exit(void)
{
	pci_unregister_driver(&qla4xxx_pci_driver);
	iscsi2_unregister_transport(&qla4xxx_iscsi_transport);
	kmem_cache_destroy(srb_cachep);
}

module_init(qla4xxx_module_init);
module_exit(qla4xxx_module_exit);

MODULE_AUTHOR("QLogic Corporation");
MODULE_DESCRIPTION("QLogic iSCSI HBA Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(QLA4XXX_DRIVER_VERSION);
