/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"

#include <linux/delay.h>
#include <scsi/scsi_tcq.h>

static void qla2x00_mbx_completion(scsi_qla_host_t *, uint16_t);
static void qla2x00_process_completed_request(struct scsi_qla_host *, uint32_t);
static void qla2x00_status_entry(scsi_qla_host_t *, void *);
static void qla2x00_status_cont_entry(scsi_qla_host_t *, sts_cont_entry_t *);
static void qla2x00_error_entry(scsi_qla_host_t *, sts_entry_t *);
static void qla2x00_ms_entry(scsi_qla_host_t *, ms_iocb_entry_t *);

static void qla24xx_ms_entry(scsi_qla_host_t *, struct ct_entry_24xx *);

/**
 * qla2100_intr_handler() - Process interrupts for the ISP2100 and ISP2200.
 * @irq:
 * @dev_id: SCSI driver HA context
 * @regs:
 *
 * Called by system whenever the host adapter generates an interrupt.
 *
 * Returns handled flag.
 */
irqreturn_t
qla2100_intr_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	scsi_qla_host_t	*ha;
	struct device_reg_2xxx __iomem *reg;
	int		status;
	unsigned long	flags;
	unsigned long	iter;
	uint16_t        hccr;
	uint16_t	mb[4];

	ha = (scsi_qla_host_t *) dev_id;
	if (!ha) {
		printk(KERN_INFO
		    "%s(): NULL host pointer\n", __func__);
		return (IRQ_NONE);
	}

	reg = &ha->iobase->isp;
	status = 0;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	for (iter = 50; iter--; ) {
		hccr = RD_REG_WORD(&reg->hccr);
		if (hccr & HCCR_RISC_PAUSE) {
			if (pci_channel_offline(ha->pdev))
				break;

			/*
			 * Issue a "HARD" reset in order for the RISC interrupt
			 * bit to be cleared.  Schedule a big hammmer to get
			 * out of the RISC PAUSED state.
			 */
			WRT_REG_WORD(&reg->hccr, HCCR_RESET_RISC);
			RD_REG_WORD(&reg->hccr);

			ha->isp_ops->fw_dump(ha, 1);
			set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
			break;
		} else if ((RD_REG_WORD(&reg->istatus) & ISR_RISC_INT) == 0)
			break;

		if (RD_REG_WORD(&reg->semaphore) & BIT_0) {
			WRT_REG_WORD(&reg->hccr, HCCR_CLR_RISC_INT);
			RD_REG_WORD(&reg->hccr);

			/* Get mailbox data. */
			mb[0] = RD_MAILBOX_REG(ha, reg, 0);
			if (mb[0] > 0x3fff && mb[0] < 0x8000) {
				qla2x00_mbx_completion(ha, mb[0]);
				status |= MBX_INTERRUPT;
			} else if (mb[0] > 0x7fff && mb[0] < 0xc000) {
				mb[1] = RD_MAILBOX_REG(ha, reg, 1);
				mb[2] = RD_MAILBOX_REG(ha, reg, 2);
				mb[3] = RD_MAILBOX_REG(ha, reg, 3);
				qla2x00_async_event(ha, mb);
			} else {
				/*EMPTY*/
				DEBUG2(printk("scsi(%ld): Unrecognized "
				    "interrupt type (%d).\n",
				    ha->host_no, mb[0]));
			}
			/* Release mailbox registers. */
			WRT_REG_WORD(&reg->semaphore, 0);
			RD_REG_WORD(&reg->semaphore);
		} else {
			qla2x00_process_response_queue(ha);

			WRT_REG_WORD(&reg->hccr, HCCR_CLR_RISC_INT);
			RD_REG_WORD(&reg->hccr);
		}
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (test_bit(MBX_INTR_WAIT, &ha->mbx_cmd_flags) &&
	    (status & MBX_INTERRUPT) && ha->flags.mbox_int) {
		set_bit(MBX_INTERRUPT, &ha->mbx_cmd_flags);
		complete(&ha->mbx_intr_comp);
	}

	return (IRQ_HANDLED);
}

/**
 * qla2300_intr_handler() - Process interrupts for the ISP23xx and ISP63xx.
 * @irq:
 * @dev_id: SCSI driver HA context
 * @regs:
 *
 * Called by system whenever the host adapter generates an interrupt.
 *
 * Returns handled flag.
 */
irqreturn_t
qla2300_intr_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	scsi_qla_host_t	*ha;
	struct device_reg_2xxx __iomem *reg;
	int		status;
	unsigned long	flags;
	unsigned long	iter;
	uint32_t	stat;
	uint16_t	hccr;
	uint16_t	mb[4];

	ha = (scsi_qla_host_t *) dev_id;
	if (!ha) {
		printk(KERN_INFO
		    "%s(): NULL host pointer\n", __func__);
		return (IRQ_NONE);
	}

	reg = &ha->iobase->isp;
	status = 0;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	for (iter = 50; iter--; ) {
		stat = RD_REG_DWORD(&reg->u.isp2300.host_status);
		if (stat & HSR_RISC_PAUSED) {
			if (pci_channel_offline(ha->pdev))
				break;

			hccr = RD_REG_WORD(&reg->hccr);
			if (hccr & (BIT_15 | BIT_13 | BIT_11 | BIT_8))
				qla_printk(KERN_INFO, ha, "Parity error -- "
				    "HCCR=%x, Dumping firmware!\n", hccr);
			else
				qla_printk(KERN_INFO, ha, "RISC paused -- "
				    "HCCR=%x, Dumping firmware!\n", hccr);

			/*
			 * Issue a "HARD" reset in order for the RISC
			 * interrupt bit to be cleared.  Schedule a big
			 * hammmer to get out of the RISC PAUSED state.
			 */
			WRT_REG_WORD(&reg->hccr, HCCR_RESET_RISC);
			RD_REG_WORD(&reg->hccr);

			ha->isp_ops->fw_dump(ha, 1);
			set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
			break;
		} else if ((stat & HSR_RISC_INT) == 0)
			break;

		switch (stat & 0xff) {
		case 0x1:
		case 0x2:
		case 0x10:
		case 0x11:
			qla2x00_mbx_completion(ha, MSW(stat));
			status |= MBX_INTERRUPT;

			/* Release mailbox registers. */
			WRT_REG_WORD(&reg->semaphore, 0);
			break;
		case 0x12:
			mb[0] = MSW(stat);
			mb[1] = RD_MAILBOX_REG(ha, reg, 1);
			mb[2] = RD_MAILBOX_REG(ha, reg, 2);
			mb[3] = RD_MAILBOX_REG(ha, reg, 3);
			qla2x00_async_event(ha, mb);
			break;
		case 0x13:
			qla2x00_process_response_queue(ha);
			break;
		case 0x15:
			mb[0] = MBA_CMPLT_1_16BIT;
			mb[1] = MSW(stat);
			qla2x00_async_event(ha, mb);
			break;
		case 0x16:
			mb[0] = MBA_SCSI_COMPLETION;
			mb[1] = MSW(stat);
			mb[2] = RD_MAILBOX_REG(ha, reg, 2);
			qla2x00_async_event(ha, mb);
			break;
		default:
			DEBUG2(printk("scsi(%ld): Unrecognized interrupt type "
			    "(%d).\n",
			    ha->host_no, stat & 0xff));
			break;
		}
		WRT_REG_WORD(&reg->hccr, HCCR_CLR_RISC_INT);
		RD_REG_WORD_RELAXED(&reg->hccr);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (test_bit(MBX_INTR_WAIT, &ha->mbx_cmd_flags) &&
	    (status & MBX_INTERRUPT) && ha->flags.mbox_int) {
		set_bit(MBX_INTERRUPT, &ha->mbx_cmd_flags);
		complete(&ha->mbx_intr_comp);
	}

	return (IRQ_HANDLED);
}

/**
 * qla2x00_mbx_completion() - Process mailbox command completions.
 * @ha: SCSI driver HA context
 * @mb0: Mailbox0 register
 */
static void
qla2x00_mbx_completion(scsi_qla_host_t *ha, uint16_t mb0)
{
	uint16_t	cnt;
	uint16_t __iomem *wptr;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	/* Load return mailbox registers. */
	ha->flags.mbox_int = 1;
	ha->mailbox_out[0] = mb0;
	wptr = (uint16_t __iomem *)MAILBOX_REG(ha, reg, 1);

	for (cnt = 1; cnt < ha->mbx_count; cnt++) {
		if (IS_QLA2200(ha) && cnt == 8)
			wptr = (uint16_t __iomem *)MAILBOX_REG(ha, reg, 8);
		if (cnt == 4 || cnt == 5)
			ha->mailbox_out[cnt] = qla2x00_debounce_register(wptr);
		else
			ha->mailbox_out[cnt] = RD_REG_WORD(wptr);

		wptr++;
	}

	if (ha->mcp) {
		DEBUG3(printk("%s(%ld): Got mailbox completion. cmd=%x.\n",
		    __func__, ha->host_no, ha->mcp->mb[0]));
	} else {
		DEBUG2_3(printk("%s(%ld): MBX pointer ERROR!\n",
		    __func__, ha->host_no));
	}
}

static void
qla81xx_idc_event(scsi_qla_host_t *ha, uint16_t aen, uint16_t descr)
{

	int rval = 0;
	scsi_qla_host_t *pha = to_qla_parent(ha);

	static char *event[] =
	    { "Complete", "Request Notification", "Time Extension" };
	struct device_reg_24xx __iomem *reg24 = &pha->iobase->isp24;
	uint16_t __iomem *wptr;
	uint16_t cnt, timeout, mb[QLA_IDC_ACK_REGS];

	/* Seed data -- mailbox1 -> mailbox7. */
	wptr = (uint16_t __iomem *)&reg24->mailbox1;
	for (cnt = 0; cnt < QLA_IDC_ACK_REGS; cnt++, wptr++)
		mb[cnt] = RD_REG_WORD(wptr);

	DEBUG2(printk("scsi(%ld): Inter-Driver Commucation %s -- "
	    "%04x %04x %04x %04x %04x %04x %04x.\n", ha->host_no,
	    event[aen & 0xff],
	    mb[0], mb[1], mb[2], mb[3], mb[4], mb[5], mb[6]));

	/* Acknowledgement needed? [Notify && non-zero timeout]. */
	timeout = (descr >> 8) & 0xf;
	if (aen != MBA_IDC_NOTIFY || !timeout)
		return;

	DEBUG2(printk("scsi(%ld): Inter-Driver Commucation %s -- "
	     "ACK timeout=%d.\n", ha->host_no, event[aen & 0xff], timeout));

	rval = qla2x00_post_idc_ack_work(ha, mb);
	if (rval != QLA_SUCCESS)
		qla_printk(KERN_WARNING, ha,
				"IDC failed to post ACK.\n");
}

/**
 * qla2x00_async_event() - Process aynchronous events.
 * @ha: SCSI driver HA context
 * @mb: Mailbox registers (0 - 3)
 */
void
qla2x00_async_event(scsi_qla_host_t *ha, uint16_t *mb)
{
#define LS_UNKNOWN	2
#define LS_10GB_INDEX	5
	static char	*link_speeds[6] = { "1", "2", "?", "4", "8", "10"};
	char		*link_speed;
	uint16_t	handle_cnt;
	uint16_t	cnt;
	uint32_t	handles[5];
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;
	uint32_t	rscn_entry, host_pid;
	uint8_t		rscn_queue_index;
	unsigned long	flags;

	qla2xxx_log_aen(ha, mb[0], mb[1], mb[2], mb[3]);

	/* Setup to process RIO completion. */
	handle_cnt = 0;
	if (IS_QLA8XXX_TYPE(ha))
		goto skip_rio;
	switch (mb[0]) {
	case MBA_SCSI_COMPLETION:
		handles[0] = le32_to_cpu((uint32_t)((mb[2] << 16) | mb[1]));
		handle_cnt = 1;
		break;
	case MBA_CMPLT_1_16BIT:
		handles[0] = mb[1];
		handle_cnt = 1;
		mb[0] = MBA_SCSI_COMPLETION;
		break;
	case MBA_CMPLT_2_16BIT:
		handles[0] = mb[1];
		handles[1] = mb[2];
		handle_cnt = 2;
		mb[0] = MBA_SCSI_COMPLETION;
		break;
	case MBA_CMPLT_3_16BIT:
		handles[0] = mb[1];
		handles[1] = mb[2];
		handles[2] = mb[3];
		handle_cnt = 3;
		mb[0] = MBA_SCSI_COMPLETION;
		break;
	case MBA_CMPLT_4_16BIT:
		handles[0] = mb[1];
		handles[1] = mb[2];
		handles[2] = mb[3];
		handles[3] = (uint32_t)RD_MAILBOX_REG(ha, reg, 6);
		handle_cnt = 4;
		mb[0] = MBA_SCSI_COMPLETION;
		break;
	case MBA_CMPLT_5_16BIT:
		handles[0] = mb[1];
		handles[1] = mb[2];
		handles[2] = mb[3];
		handles[3] = (uint32_t)RD_MAILBOX_REG(ha, reg, 6);
		handles[4] = (uint32_t)RD_MAILBOX_REG(ha, reg, 7);
		handle_cnt = 5;
		mb[0] = MBA_SCSI_COMPLETION;
		break;
	case MBA_CMPLT_2_32BIT:
		handles[0] = le32_to_cpu((uint32_t)((mb[2] << 16) | mb[1]));
		handles[1] = le32_to_cpu(
		    ((uint32_t)(RD_MAILBOX_REG(ha, reg, 7) << 16)) |
		    RD_MAILBOX_REG(ha, reg, 6));
		handle_cnt = 2;
		mb[0] = MBA_SCSI_COMPLETION;
		break;
	default:
		break;
	}
skip_rio:
	switch (mb[0]) {
	case MBA_SCSI_COMPLETION:	/* Fast Post */
		if (!ha->flags.online)
			break;

		for (cnt = 0; cnt < handle_cnt; cnt++)
			qla2x00_process_completed_request(ha, handles[cnt]);
		break;

	case MBA_RESET:			/* Reset */
		DEBUG2(printk("scsi(%ld): Asynchronous RESET.\n", ha->host_no));

		set_bit(RESET_MARKER_NEEDED, &ha->dpc_flags);
		break;

	case MBA_SYSTEM_ERR:		/* System Error */
		qla_printk(KERN_INFO, ha,
		    "ISP System Error - mbx1=%xh mbx2=%xh mbx3=%xh.\n",
		    mb[1], mb[2], mb[3]);

		ha->isp_ops->fw_dump(ha, 1);

		if (IS_FWI2_CAPABLE(ha)) {
			if (mb[1] == 0 && mb[2] == 0) {
				qla_printk(KERN_ERR, ha,
				    "Unrecoverable Hardware Error: adapter "
				    "marked OFFLINE!\n");
				ha->flags.online = 0;
			} else
				set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		} else if (mb[1] == 0) {
			qla_printk(KERN_INFO, ha,
			    "Unrecoverable Hardware Error: adapter marked "
			    "OFFLINE!\n");
			ha->flags.online = 0;
		} else
			set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		break;

	case MBA_REQ_TRANSFER_ERR:	/* Request Transfer Error */
		DEBUG2(printk("scsi(%ld): ISP Request Transfer Error.\n",
		    ha->host_no));
		qla_printk(KERN_WARNING, ha, "ISP Request Transfer Error.\n");

		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		break;

	case MBA_RSP_TRANSFER_ERR:	/* Response Transfer Error */
		DEBUG2(printk("scsi(%ld): ISP Response Transfer Error.\n",
		    ha->host_no));
		qla_printk(KERN_WARNING, ha, "ISP Response Transfer Error.\n");

		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		break;

	case MBA_WAKEUP_THRES:		/* Request Queue Wake-up */
		DEBUG2(printk("scsi(%ld): Asynchronous WAKEUP_THRES.\n",
		    ha->host_no));
		break;

	case MBA_LIP_OCCURRED:		/* Loop Initialization Procedure */
		DEBUG2(printk("scsi(%ld): LIP occured (%x).\n", ha->host_no,
		    mb[1]));
		qla_printk(KERN_INFO, ha, "LIP occured (%x).\n", mb[1]);

		if (atomic_read(&ha->loop_state) != LOOP_DOWN) {
			atomic_set(&ha->loop_state, LOOP_DOWN);
			atomic_set(&ha->loop_down_timer, LOOP_DOWN_TIME);
			qla2x00_mark_all_devices_lost(ha, 1);
		}

		if (ha->parent) {
			atomic_set(&ha->vp_state, VP_FAILED);
			atomic_set(&ha->vport_last_state,
			    atomic_read(&ha->vport_state));
			atomic_set(&ha->vport_state, FC_VPORT_FAILED);
		}

		set_bit(REGISTER_FC4_NEEDED, &ha->dpc_flags);

		ha->flags.management_server_logged_in = 0;
		break;

	case MBA_LOOP_UP:		/* Loop Up Event */
		if (IS_QLA2100(ha) || IS_QLA2200(ha)) {
			link_speed = link_speeds[0];
			ha->link_data_rate = PORT_SPEED_1GB;
		} else {
			link_speed = link_speeds[LS_UNKNOWN];
			if (mb[1] < 5)
				link_speed = link_speeds[mb[1]];
			else if (mb[1] == PORT_SPEED_10GB)
				link_speed = link_speeds[LS_10GB_INDEX];
			ha->link_data_rate = mb[1];
		}

		DEBUG2(printk("scsi(%ld): Asynchronous LOOP UP (%s Gbps).\n",
		    ha->host_no, link_speed));
		qla_printk(KERN_INFO, ha, "LOOP UP detected (%s Gbps).\n",
		    link_speed);

		ha->flags.management_server_logged_in = 0;
		break;

	case MBA_LOOP_DOWN:		/* Loop Down Event */
		ha->current_topology = 0;
		DEBUG2(printk(KERN_INFO
		    "scsi(%ld): Asynchronous LOOP DOWN "
		    "(%x %x %x).\n", ha->host_no, mb[1], mb[2], mb[3]));
		qla_printk(KERN_INFO, ha, "LOOP DOWN detected (%x %x %x).\n",
		    mb[1], mb[2], mb[3]);
		qla2x00_set_loop_down( ha, mb );
		if (ql2xfdmienable)
			set_bit(REGISTER_FDMI_NEEDED, &ha->dpc_flags);
		break;

	case MBA_LIP_RESET:		/* LIP reset occurred */
		DEBUG2(printk("scsi(%ld): Asynchronous LIP RESET (%x).\n",
		    ha->host_no, mb[1]));
		qla_printk(KERN_INFO, ha,
		    "LIP reset occured (%x).\n", mb[1]);

		if (atomic_read(&ha->loop_state) != LOOP_DOWN) {
			atomic_set(&ha->loop_state, LOOP_DOWN);
			atomic_set(&ha->loop_down_timer, LOOP_DOWN_TIME);
			qla2x00_mark_all_devices_lost(ha, 1);
		}

		if (ha->parent) {
			atomic_set(&ha->vp_state, VP_FAILED);
			atomic_set(&ha->vport_last_state,
			    atomic_read(&ha->vport_state));
			atomic_set(&ha->vport_state, FC_VPORT_FAILED);
		}

		set_bit(RESET_MARKER_NEEDED, &ha->dpc_flags);

		ha->operating_mode = LOOP;
		ha->flags.management_server_logged_in = 0;
		break;

	case MBA_POINT_TO_POINT:	/* Point-to-Point */
		if (IS_QLA2100(ha))
			break;

		if (IS_QLA8XXX_TYPE(ha)) {
			DEBUG2(printk("scsi(%ld): DCBX Completed -- %04x %04x "
			    "%04x\n", ha->host_no, mb[1], mb[2], mb[3]));
			if (ha->notify_dcbx_comp)
				complete(&ha->dcbx_comp);
		} else
			DEBUG2(printk("scsi(%ld): Asynchronous P2P MODE "
			    "received.\n", ha->host_no));
		/*
		 * Until there's a transition from loop down to loop up, treat
		 * this as loop down only.
		 */
		if (atomic_read(&ha->loop_state) != LOOP_DOWN) {
			atomic_set(&ha->loop_state, LOOP_DOWN);
			if (!atomic_read(&ha->loop_down_timer))
				atomic_set(&ha->loop_down_timer,
				    LOOP_DOWN_TIME);
			qla2x00_mark_all_devices_lost(ha, 1);
		}

		if (ha->parent) {
			atomic_set(&ha->vp_state, VP_FAILED);
			atomic_set(&ha->vport_last_state,
			    atomic_read(&ha->vport_state));
			atomic_set(&ha->vport_state, FC_VPORT_FAILED);
		}

		if (!(test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags))) {
			set_bit(RESET_MARKER_NEEDED, &ha->dpc_flags);
		}
		set_bit(REGISTER_FC4_NEEDED, &ha->dpc_flags);

		ha->flags.gpsc_supported = 1;
		ha->flags.management_server_logged_in = 0;
		break;

	case MBA_CHG_IN_CONNECTION:	/* Change in connection mode */
		if (IS_QLA2100(ha))
			break;

		DEBUG2(printk("scsi(%ld): Asynchronous Change In Connection "
		    "received.\n",
		    ha->host_no));
		qla_printk(KERN_INFO, ha,
		    "Configuration change detected: value=%x.\n", mb[1]);

		if (atomic_read(&ha->loop_state) != LOOP_DOWN) {
			atomic_set(&ha->loop_state, LOOP_DOWN);
			if (!atomic_read(&ha->loop_down_timer))
				atomic_set(&ha->loop_down_timer,
				    LOOP_DOWN_TIME);
			qla2x00_mark_all_devices_lost(ha, 1);
		}

		if (ha->parent) {
			atomic_set(&ha->vp_state, VP_FAILED);
			atomic_set(&ha->vport_last_state,
			    atomic_read(&ha->vport_state));
			atomic_set(&ha->vport_state, FC_VPORT_FAILED);
		}

		set_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags);
		set_bit(LOCAL_LOOP_UPDATE, &ha->dpc_flags);
		break;

	case MBA_PORT_UPDATE:
		/*
		 * Handle only global and vn-port update events
		 *
		 * Relevant inputs:
		 * mb[1] = N_Port handle of changed port
		 *         OR 0xffff for global event
		 * mb[2] = New login state
		 *         7 = Port logged out
		 * mb[3] = LSB is vp_idx, 0xff = all vps
		 *
		 * Skip processing if:
		 *       Event is global, vp_idx is NOT all vps,
		 *           vp_idx does not match
		 *       Event is not global, vp_idx does not match
		 */

		if (IS_QLA2XXX_MIDTYPE(ha) &&
		    ((mb[1] == 0xffff && (mb[3] & 0xff) != 0xff) ||
		    (mb[1] != 0xffff)) && ha->vp_idx != (mb[3] & 0xff))
			break;

                /* Global event -- port logout or port unavailable. */
                if (mb[1] == 0xffff && mb[2] == 0x7) {
			DEBUG2(printk(KERN_INFO
			    "scsi(%ld): Asynchronous PORT UPDATE "
			    "(%x %x %x).\n", ha->host_no, mb[1], mb[2], mb[3]));
			qla_printk(KERN_INFO, ha,
			    "Port database changed (%x %x %x).\n",
			    mb[1], mb[2], mb[3]);
			qla2x00_set_loop_down( ha, mb );
			break;
                }

		/*
		 * If PORT UPDATE is global (recieved LIP_OCCURED/LIP_RESET
		 * event etc. earlier indicating loop is down) then process
		 * it.  Otherwise ignore it and Wait for RSCN to come in.
		 */
		atomic_set(&ha->loop_down_timer, 0);
		if (atomic_read(&ha->loop_state) != LOOP_DOWN &&
		    atomic_read(&ha->loop_state) != LOOP_DEAD) {
			DEBUG2(printk("scsi(%ld): Asynchronous PORT UPDATE "
			    "ignored %04x/%04x/%04x.\n", ha->host_no, mb[1],
			    mb[2], mb[3]));
			break;
		}

		DEBUG2(printk("scsi(%ld): Asynchronous PORT UPDATE.\n",
		    ha->host_no));
		DEBUG(printk(KERN_INFO
		    "scsi(%ld): Port database changed %04x %04x %04x.\n",
		    ha->host_no, mb[1], mb[2], mb[3]));

		/*
		 * Mark all devices as missing so we will login again.
		 */
		atomic_set(&ha->loop_state, LOOP_UP);

		qla2x00_mark_all_devices_lost(ha, 1);

		ha->flags.rscn_queue_overflow = 1;

		set_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags);
		set_bit(LOCAL_LOOP_UPDATE, &ha->dpc_flags);
		break;

	case MBA_RSCN_UPDATE:		/* State Change Registration */
		/* Check if the Vport has issued a SCR */
		if (ha->parent && test_bit(VP_SCR_NEEDED, &ha->vp_flags))
			break;
		/* Only handle SCNs for our Vport index. */
		if (ha->flags.npiv_supported && ha->vp_idx != mb[3])
			break;

		DEBUG2(printk("scsi(%ld): Asynchronous RSCR UPDATE.\n",
		    ha->host_no));
		DEBUG(printk(KERN_INFO
		    "scsi(%ld): RSCN database changed -- %04x %04x %04x.\n",
		    ha->host_no, mb[1], mb[2], mb[3]));

		rscn_entry = (mb[1] << 16) | mb[2];
		host_pid = (ha->d_id.b.domain << 16) | (ha->d_id.b.area << 8) |
		    ha->d_id.b.al_pa;
		if (rscn_entry == host_pid) {
			DEBUG(printk(KERN_INFO
			    "scsi(%ld): Ignoring RSCN update to local host "
			    "port ID (%06x)\n",
			    ha->host_no, host_pid));
			break;
		}

		rscn_queue_index = ha->rscn_in_ptr + 1;
		if (rscn_queue_index == MAX_RSCN_COUNT)
			rscn_queue_index = 0;
		if (rscn_queue_index != ha->rscn_out_ptr) {
			ha->rscn_queue[ha->rscn_in_ptr] = rscn_entry;
			ha->rscn_in_ptr = rscn_queue_index;
		} else {
			ha->flags.rscn_queue_overflow = 1;
		}

		atomic_set(&ha->loop_state, LOOP_UPDATE);
		atomic_set(&ha->loop_down_timer, 0);
		ha->flags.management_server_logged_in = 0;

		set_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags);
		set_bit(RSCN_UPDATE, &ha->dpc_flags);
		break;

	/* case MBA_RIO_RESPONSE: */
	case MBA_ZIO_RESPONSE:
		DEBUG2(printk("scsi(%ld): [R|Z]IO update completion.\n",
		    ha->host_no));
		DEBUG(printk(KERN_INFO
		    "scsi(%ld): [R|Z]IO update completion.\n",
		    ha->host_no));

		if (IS_FWI2_CAPABLE(ha))
			qla24xx_process_response_queue(ha);
		else
			qla2x00_process_response_queue(ha);
		break;

	case MBA_DISCARD_RND_FRAME:
		DEBUG2(printk("scsi(%ld): Discard RND Frame -- %04x %04x "
		    "%04x.\n", ha->host_no, mb[1], mb[2], mb[3]));
		break;

	case MBA_TRACE_NOTIFICATION:
		DEBUG2(printk("scsi(%ld): Trace Notification -- %04x %04x.\n",
		ha->host_no, mb[1], mb[2]));
		break;

	case MBA_ISP84XX_ALERT:
		DEBUG2(printk("scsi(%ld): ISP84XX Alert Notification -- "
		    "%04x %04x %04x\n", ha->host_no, mb[1], mb[2], mb[3]));

		/* not initialized, so don't use it. */
		if (ha->cs84xx) {
			spin_lock_irqsave(&ha->cs84xx->access_lock, flags);
			switch (mb[1]) {
			case A84_PANIC_RECOVERY:
				qla_printk(KERN_INFO, ha, "Alert 84XX: panic recovery "
			    	"%04x %04x\n", mb[2], mb[3]);
				break;
			case A84_OP_LOGIN_COMPLETE:
				ha->cs84xx->op_fw_version = mb[3] << 16 | mb[2];
				DEBUG2(qla_printk(KERN_INFO, ha, "Alert 84XX:"
			    	"firmware version %x\n", ha->cs84xx->op_fw_version));
				break;
			case A84_DIAG_LOGIN_COMPLETE:
				ha->cs84xx->diag_fw_version = mb[3] << 16 | mb[2];
				DEBUG2(qla_printk(KERN_INFO, ha, "Alert 84XX:"
			    	"diagnostic firmware version %x\n",
			    	ha->cs84xx->diag_fw_version));
				break;
			case A84_GOLD_LOGIN_COMPLETE:
				ha->cs84xx->diag_fw_version = mb[3] << 16 | mb[2];
				ha->cs84xx->fw_update = 1;
				DEBUG2(qla_printk(KERN_INFO, ha, "Alert 84XX: gold "
			    	"firmware version %x\n",
			    	ha->cs84xx->gold_fw_version));
				break;
			default:
				qla_printk(KERN_ERR, ha,
			    	"Alert 84xx: Invalid Alert %04x %04x %04x\n",
			    	mb[1], mb[2], mb[3]);
			}
			spin_unlock_irqrestore(&ha->cs84xx->access_lock, flags);
		}
		break;
	case MBA_DCBX_START:
		DEBUG2(printk("scsi(%ld): DCBX Started -- %04x %04x %04x\n",
		    ha->host_no, mb[1], mb[2], mb[3]));
		break;
	case MBA_DCBX_PARAM_UPDATE:
		DEBUG2(printk("scsi(%ld): DCBX Parameters Updated -- "
		    "%04x %04x %04x\n", ha->host_no, mb[1], mb[2], mb[3]));
		break;
	case MBA_FCF_CONF_ERR:
		DEBUG2(printk("scsi(%ld): FCF Configuration Error -- "
		    "%04x %04x %04x\n", ha->host_no, mb[1], mb[2], mb[3]));
		break;
	case MBA_IDC_COMPLETE:
	case MBA_IDC_NOTIFY:
	case MBA_IDC_TIME_EXT:
		 qla81xx_idc_event(ha, mb[0], mb[1]);
		break;
	}

	if (!ha->vp_idx && ha->num_vhosts)
                qla2x00_alert_all_vps(ha, mb);
}

static void
qla2x00_adjust_sdev_qdepth_up(struct scsi_device *sdev, void *data)
{
	fc_port_t *fcport = data;

	if (fcport->ha->max_q_depth <= sdev->queue_depth)
		return;

	if (sdev->ordered_tags)
		scsi_adjust_queue_depth(sdev, MSG_ORDERED_TAG,
		    sdev->queue_depth + 1);
	else
		scsi_adjust_queue_depth(sdev, MSG_SIMPLE_TAG,
		    sdev->queue_depth + 1);

	fcport->last_ramp_up = jiffies;

	DEBUG2(qla_printk(KERN_INFO, fcport->ha,
	    "scsi(%ld:%d:%d:%d): Queue depth adjusted-up to %d.\n",
	    fcport->ha->host_no, sdev->channel, sdev->id, sdev->lun,
	    sdev->queue_depth));
}

static void
qla2x00_adjust_sdev_qdepth_down(struct scsi_device *sdev, void *data)
{
	fc_port_t *fcport = data;

	if (!scsi_track_queue_full(sdev, sdev->queue_depth - 1))
		return;

	DEBUG2(qla_printk(KERN_INFO, fcport->ha,
	    "scsi(%ld:%d:%d:%d): Queue depth adjusted-down to %d.\n",
	    fcport->ha->host_no, sdev->channel, sdev->id, sdev->lun,
	    sdev->queue_depth));
}

static inline void
qla2x00_ramp_up_queue_depth(scsi_qla_host_t *ha, srb_t *sp)
{
	fc_port_t *fcport;
	struct scsi_device *sdev;

        if (!ql2xqfulltracking)
                return;

	sdev = sp->cmd->device;
	if (sdev->queue_depth >= ha->max_q_depth)
		return;

	fcport = sp->fcport;
	if (time_before(jiffies,
	    fcport->last_ramp_up + ql2xqfullrampup * HZ))
		return;
	if (time_before(jiffies,
	    fcport->last_queue_full + ql2xqfullrampup * HZ))
		return;

	starget_for_each_device(sdev->sdev_target, fcport,
	    qla2x00_adjust_sdev_qdepth_up);
}

/**
 * qla2x00_process_completed_request() - Process a Fast Post response.
 * @ha: SCSI driver HA context
 * @index: SRB index
 */
static void
qla2x00_process_completed_request(struct scsi_qla_host *ha, uint32_t index)
{
	srb_t *sp;

	/* Validate handle. */
	if (index >= MAX_OUTSTANDING_COMMANDS) {
		DEBUG2(printk("scsi(%ld): Invalid SCSI completion handle %d.\n",
		    ha->host_no, index));
		qla_printk(KERN_WARNING, ha,
		    "Invalid SCSI completion handle %d.\n", index);

		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		return;
	}

	sp = ha->outstanding_cmds[index];
	if (sp) {
		/* Free outstanding command slot. */
		ha->outstanding_cmds[index] = NULL;

		CMD_COMPL_STATUS(sp->cmd) = 0L;
		CMD_SCSI_STATUS(sp->cmd) = 0L;

		/* Save ISP completion status */
		sp->cmd->result = DID_OK << 16;

		qla2x00_ramp_up_queue_depth(ha, sp);
		qla2x00_sp_compl(ha, sp);
	} else {
		DEBUG2(printk("scsi(%ld): Invalid ISP SCSI completion handle\n",
		    ha->host_no));
		qla_printk(KERN_WARNING, ha,
		    "Invalid ISP SCSI completion handle\n");

		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
	}
}

/**
 * qla2x00_process_response_queue() - Process response queue entries.
 * @ha: SCSI driver HA context
 */
void
qla2x00_process_response_queue(struct scsi_qla_host *ha)
{
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;
	sts_entry_t	*pkt;
	uint16_t        handle_cnt;
	uint16_t        cnt;

	if (!ha->flags.online)
		return;

	while (ha->response_ring_ptr->signature != RESPONSE_PROCESSED) {
		pkt = (sts_entry_t *)ha->response_ring_ptr;

		ha->rsp_ring_index++;
		if (ha->rsp_ring_index == ha->response_q_length) {
			ha->rsp_ring_index = 0;
			ha->response_ring_ptr = ha->response_ring;
		} else {
			ha->response_ring_ptr++;
		}

		if (pkt->entry_status != 0) {
			DEBUG3(printk(KERN_INFO
			    "scsi(%ld): Process error entry.\n", ha->host_no));

			qla2x00_error_entry(ha, pkt);
			((response_t *)pkt)->signature = RESPONSE_PROCESSED;
			wmb();
			continue;
		}

		switch (pkt->entry_type) {
		case STATUS_TYPE:
			qla2x00_status_entry(ha, pkt);
			break;
		case STATUS_TYPE_21:
			handle_cnt = ((sts21_entry_t *)pkt)->handle_count;
			for (cnt = 0; cnt < handle_cnt; cnt++) {
				qla2x00_process_completed_request(ha,
				    ((sts21_entry_t *)pkt)->handle[cnt]);
			}
			break;
		case STATUS_TYPE_22:
			handle_cnt = ((sts22_entry_t *)pkt)->handle_count;
			for (cnt = 0; cnt < handle_cnt; cnt++) {
				qla2x00_process_completed_request(ha,
				    ((sts22_entry_t *)pkt)->handle[cnt]);
			}
			break;
		case STATUS_CONT_TYPE:
			qla2x00_status_cont_entry(ha, (sts_cont_entry_t *)pkt);
			break;
		case MS_IOCB_TYPE:
			if (ha->outstanding_cmds[pkt->handle])
				qla2x00_ms_entry(ha, (ms_iocb_entry_t *)pkt);
			else {
				if (ha->pass_thru_cmd_result)
					qla_printk(KERN_INFO, ha,
					    "Passthru cmd result on.\n");
				if (!ha->pass_thru_cmd_in_process)
					qla_printk(KERN_INFO, ha,
					    "Passthru in process off.\n");

				ha->pass_thru_cmd_result = 1;
				complete(&ha->pass_thru_intr_comp);
			}
			break;
		default:
			/* Type Not Supported. */
			DEBUG4(printk(KERN_WARNING
			    "scsi(%ld): Received unknown response pkt type %x "
			    "entry status=%x.\n",
			    ha->host_no, pkt->entry_type, pkt->entry_status));
			break;
		}
		((response_t *)pkt)->signature = RESPONSE_PROCESSED;
		wmb();
	}

	/* Adjust ring index */
	WRT_REG_WORD(ISP_RSP_Q_OUT(ha, reg), ha->rsp_ring_index);
}

static inline void
qla2x00_handle_sense(srb_t *sp, uint8_t *sense_data, uint32_t par_sense_len,
    uint32_t sense_len)
{
	struct scsi_cmnd *cp = sp->cmd;

	if (sense_len >= SCSI_SENSE_BUFFERSIZE)
		sense_len = SCSI_SENSE_BUFFERSIZE;

	CMD_ACTUAL_SNSLEN(cp) = sense_len;
	sp->request_sense_length = sense_len;
	sp->request_sense_ptr = cp->sense_buffer;
	if (sp->request_sense_length > par_sense_len)
		sense_len = par_sense_len;

	memcpy(cp->sense_buffer, sense_data, sense_len);

	sp->request_sense_ptr += sense_len;
	sp->request_sense_length -= sense_len;
	if (sp->request_sense_length != 0)
		sp->ha->status_srb = sp;

	DEBUG5(printk("%s(): Check condition Sense data, scsi(%ld:%d:%d:%d) "
	    "cmd=%p pid=%ld\n", __func__, sp->ha->host_no, cp->device->channel,
	    cp->device->id, cp->device->lun, cp, cp->serial_number));
	if (sense_len)
		DEBUG5(qla2x00_dump_buffer(cp->sense_buffer,
		    CMD_ACTUAL_SNSLEN(cp)));
}

/**
 * qla2x00_status_entry() - Process a Status IOCB entry.
 * @ha: SCSI driver HA context
 * @pkt: Entry pointer
 */
static void
qla2x00_status_entry(scsi_qla_host_t *ha, void *pkt)
{
	srb_t		*sp;
	fc_port_t	*fcport;
	struct scsi_cmnd *cp;
	sts_entry_t *sts;
	struct sts_entry_24xx *sts24;
	uint16_t	comp_status;
	uint16_t	scsi_status;
	uint16_t	ox_id;
	uint8_t		lscsi_status;
	int32_t		resid;
	uint32_t	sense_len, par_sense_len, rsp_info_len, resid_len;
	uint32_t	fw_resid_len;
	uint8_t		*rsp_info, *sense_data;
	int logit = 1;

	sts = (sts_entry_t *) pkt;
	sts24 = (struct sts_entry_24xx *) pkt;
	if (IS_FWI2_CAPABLE(ha)) {
		comp_status = le16_to_cpu(sts24->comp_status);
		scsi_status = le16_to_cpu(sts24->scsi_status) & SS_MASK;
	} else {
		comp_status = le16_to_cpu(sts->comp_status);
		scsi_status = le16_to_cpu(sts->scsi_status) & SS_MASK;
	}

	/* Fast path completion. */
	if (comp_status == CS_COMPLETE && scsi_status == 0) {
		qla2x00_process_completed_request(ha, sts->handle);

		return;
	}

	/* Validate handle. */
	if (sts->handle < MAX_OUTSTANDING_COMMANDS) {
		sp = ha->outstanding_cmds[sts->handle];
		ha->outstanding_cmds[sts->handle] = NULL;
	} else
		sp = NULL;

	if (sp == NULL) {
		qla_printk(KERN_WARNING, ha,
		    "scsi(%ld): Invalid status handle (0x%x).\n", ha->host_no,
		    sts->handle);

		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		qla2xxx_wake_dpc(ha);
		return;
	}
	cp = sp->cmd;
	if (cp == NULL) {
		qla_printk(KERN_WARNING, ha,
		    "scsi(%ld): Command already returned (0x%x/%p).\n",
		    ha->host_no, sts->handle, sp);

		return;
	}

  	lscsi_status = scsi_status & STATUS_MASK;
	CMD_ENTRY_STATUS(cp) = sts->entry_status;
	CMD_COMPL_STATUS(cp) = comp_status;
	CMD_SCSI_STATUS(cp) = scsi_status;

	fcport = sp->fcport;

	ox_id = 0;
	sense_len = par_sense_len = rsp_info_len = resid_len = fw_resid_len = 0;
	if (IS_FWI2_CAPABLE(ha)) {
		if (scsi_status & SS_SENSE_LEN_VALID)
			sense_len = le32_to_cpu(sts24->sense_len);
		if (scsi_status & SS_RESPONSE_INFO_LEN_VALID)
			rsp_info_len = le32_to_cpu(sts24->rsp_data_len);
		if (scsi_status & (SS_RESIDUAL_UNDER | SS_RESIDUAL_OVER))
			resid_len = le32_to_cpu(sts24->rsp_residual_count);
		if (comp_status == CS_DATA_UNDERRUN)
			fw_resid_len = le32_to_cpu(sts24->residual_len);
		rsp_info = sts24->data;
		sense_data = sts24->data;
		host_to_fcp_swap(sts24->data, sizeof(sts24->data));
		ox_id = le16_to_cpu(sts24->ox_id);
		par_sense_len = sizeof(sts24->data);
	} else {
		if (scsi_status & SS_SENSE_LEN_VALID)
			sense_len = le16_to_cpu(sts->req_sense_length);
		if (scsi_status & SS_RESPONSE_INFO_LEN_VALID)
			rsp_info_len = le16_to_cpu(sts->rsp_info_len);
		resid_len = le32_to_cpu(sts->residual_length);
		rsp_info = sts->rsp_info;
		sense_data = sts->req_sense_data;
		par_sense_len = sizeof(sts->req_sense_data);
	}

	/* Check for any FCP transport errors. */
	if (scsi_status & SS_RESPONSE_INFO_LEN_VALID) {
		/* Sense data lies beyond any FCP RESPONSE data. */
		if (IS_FWI2_CAPABLE(ha)) {
			sense_data += rsp_info_len;
			par_sense_len -= rsp_info_len;
		}
		if (rsp_info_len > 3 && rsp_info[3]) {
			DEBUG2(qla_printk(KERN_INFO, ha,
			    "scsi(%ld:%d:%d): FCP I/O protocol failure "
			    "(0x%x/0x%x).\n", ha->host_no, cp->device->id,
			    cp->device->lun, rsp_info_len, rsp_info[3]));

			cp->result = DID_BUS_BUSY << 16;
			goto out;
		}
	}

	/* Check for overrun. */
	if (IS_FWI2_CAPABLE(ha) && comp_status == CS_COMPLETE &&
	    scsi_status & SS_RESIDUAL_OVER)
		comp_status = CS_DATA_OVERRUN;

	/*
	 * Based on Host and scsi status generate status code for Linux
	 */
	switch (comp_status) {
	case CS_COMPLETE:
	case CS_QUEUE_FULL:
		if (scsi_status == 0) {
			cp->result = DID_OK << 16;
			break;
		}
		if (scsi_status & (SS_RESIDUAL_UNDER | SS_RESIDUAL_OVER)) {
			resid = resid_len;
			scsi_set_resid(cp, resid);
			CMD_RESID_LEN(cp) = resid;

			if (!lscsi_status &&
			    ((unsigned)(scsi_bufflen(cp) - resid) <
			     cp->underflow)) {
				qla_printk(KERN_INFO, ha,
				    "scsi(%ld:%d:%d): Mid-layer underflow "
				    "detected (0x%x of 0x%x bytes).\n",
				    ha->host_no, cp->device->id,
				    cp->device->lun, resid,
				    scsi_bufflen(cp));

				cp->result = DID_ERROR << 16;
				break;
			}
		}
		cp->result = DID_OK << 16 | lscsi_status;

		if (lscsi_status == SAM_STAT_TASK_SET_FULL) {
			DEBUG2(qla_printk(KERN_INFO, ha,
			    "scsi(%ld:%d:%d) QUEUE FULL detected.\n",
			    ha->host_no, cp->device->id, cp->device->lun));

			/* Adjust queue depth for all luns on the port. */
			if (!ql2xqfulltracking)
				break;
			fcport->last_queue_full = jiffies;
			starget_for_each_device(cp->device->sdev_target,
			    fcport, qla2x00_adjust_sdev_qdepth_down);
			break;
		}
		logit = 0;
		if (lscsi_status != SS_CHECK_CONDITION)
			break;

		memset(cp->sense_buffer, 0, sizeof(cp->sense_buffer));
		if (!(scsi_status & SS_SENSE_LEN_VALID))
			break;

		qla2x00_handle_sense(sp, sense_data, par_sense_len, sense_len);
		break;

	case CS_DATA_UNDERRUN:
		/* Use F/W calculated residual length. */
		resid = IS_FWI2_CAPABLE(ha) ? fw_resid_len : resid_len;
		scsi_set_resid(cp, resid);
		if (scsi_status & SS_RESIDUAL_UNDER) {
			CMD_RESID_LEN(cp) = resid;
			if (IS_FWI2_CAPABLE(ha) && fw_resid_len != resid_len) {
				DEBUG2(qla_printk(KERN_INFO, ha,
				    "scsi(%ld:%d:%d) Dropped frame(s) detected "
				    "(0x%x of 0x%x bytes), residual length "
				    "mismatch.\n", ha->host_no, cp->device->id,
				    cp->device->lun, resid, scsi_bufflen(cp)));

				cp->result = DID_ERROR << 16 | lscsi_status;
				break;
			}

			if (!lscsi_status &&
			    ((unsigned)(scsi_bufflen(cp) - resid) <
			    cp->underflow)) {
				qla_printk(KERN_INFO, ha,
				    "scsi(%ld:%d:%d): Mid-layer underflow "
				    "detected (0x%x of 0x%x bytes).\n",
				     ha->host_no, cp->device->id,
				     cp->device->lun, resid, scsi_bufflen(cp));

				cp->result = DID_ERROR << 16;
				break;
			}
		} else {
			/*
			 * If RISC reports underrun and target does not report
			 * it then we must have a lost frame, so tell upper
			 * layer to retry it by reporting an error.
			 */
			DEBUG2(qla_printk(KERN_INFO, ha,
			    "scsi(%ld:%d:%d) Dropped frame(s) detected (0x%x "
			    "of 0x%x bytes), firmware reported underrun.\n",
			    ha->host_no, cp->device->id, cp->device->lun,
			    resid, scsi_bufflen(cp)));

			cp->result = DID_ERROR << 16 | lscsi_status;
			goto check_scsi_status;
		}

		cp->result = DID_OK << 16 | lscsi_status;
		logit = 0;

check_scsi_status:
		/*
		 * Check to see if SCSI Status is non zero. If so report SCSI
		 * Status.
		 */
		if (lscsi_status != 0) {

			if (lscsi_status == SAM_STAT_TASK_SET_FULL) {
				DEBUG2(qla_printk(KERN_INFO, ha,
				    "scsi(%ld:%d:%d) QUEUE FULL detected.\n",
				    ha->host_no, cp->device->id,
				    cp->device->lun));
				logit = 1;

				/*
				 * Adjust queue depth for all luns on the
				 * port.
				 */
				if (!ql2xqfulltracking)
					break;

				fcport->last_queue_full = jiffies;
				starget_for_each_device(
				    cp->device->sdev_target, fcport,
				    qla2x00_adjust_sdev_qdepth_down);
				break;
			}
			if (lscsi_status != SS_CHECK_CONDITION)
				break;

			memset(cp->sense_buffer, 0, sizeof(cp->sense_buffer));
			if (!(scsi_status & SS_SENSE_LEN_VALID))
				break;

			qla2x00_handle_sense(sp, sense_data, par_sense_len,
			    sense_len);
		}
		break;

	case CS_PORT_LOGGED_OUT:
	case CS_PORT_CONFIG_CHG:
	case CS_PORT_BUSY:
	case CS_INCOMPLETE:
	case CS_PORT_UNAVAILABLE:
	case CS_TIMEOUT:
		/*
		 * We are going to have the fc class block the rport
		 * while we try to recover so instruct the mid layer
		 * to requeue until the class decides how to handle this.
		 */
		cp->result = DID_TRANSPORT_DISRUPTED << 16;

		if (comp_status == CS_TIMEOUT) {
			if (IS_FWI2_CAPABLE(ha))
				break;
			else if ((le16_to_cpu(sts->status_flags) &
			    SF_LOGOUT_SENT) == 0)
				break;
		}

		DEBUG2(qla_printk(KERN_INFO, ha,
		    "scsi(%ld:%d:%d) Port down status: port-state=0x%x\n",
		     ha->host_no, cp->device->id, cp->device->lun,
		     atomic_read(&fcport->state)));

		if (atomic_read(&fcport->state) == FCS_ONLINE) {
			qla2x00_mark_device_lost(ha, fcport, 1, 1);
		}
		break;

	case CS_RESET:
	case CS_ABORTED:
		cp->result = DID_RESET << 16;
		break;

	default:
		cp->result = DID_ERROR << 16;
		break;
	}

out:
	if (logit)
		DEBUG2(qla_printk(KERN_INFO, ha,
		    "scsi(%ld:%d:%d) FCP command status: 0x%x-0x%x (0x%x) "
		    "oxid=0x%x ser=0x%lx cdb=%02x%02x%02x len=0x%x "
		    "rsp_info=0x%x resid=0x%x fw_resid=0x%x\n", ha->host_no,
		    cp->device->id, cp->device->lun, comp_status, scsi_status,
		    cp->result, ox_id, cp->serial_number, cp->cmnd[0],
		    cp->cmnd[1], cp->cmnd[2], scsi_bufflen(cp), rsp_info_len,
		    resid_len, fw_resid_len));

	if (ha->status_srb == NULL)
		qla2x00_sp_compl(ha, sp);
}

/**
 * qla2x00_status_cont_entry() - Process a Status Continuations entry.
 * @ha: SCSI driver HA context
 * @pkt: Entry pointer
 *
 * Extended sense data.
 */
static void
qla2x00_status_cont_entry(scsi_qla_host_t *ha, sts_cont_entry_t *pkt)
{
	uint8_t		sense_sz = 0;
	srb_t		*sp = ha->status_srb;
	struct scsi_cmnd *cp;

	if (sp != NULL && sp->request_sense_length != 0) {
		cp = sp->cmd;
		if (cp == NULL) {
			DEBUG2(printk("%s(): Cmd already returned back to OS "
			    "sp=%p.\n", __func__, sp));
			qla_printk(KERN_INFO, ha,
			    "cmd is NULL: already returned to OS (sp=%p)\n",
			    sp);

			ha->status_srb = NULL;
			return;
		}

		if (sp->request_sense_length > sizeof(pkt->data)) {
			sense_sz = sizeof(pkt->data);
		} else {
			sense_sz = sp->request_sense_length;
		}

		/* Move sense data. */
		if (IS_FWI2_CAPABLE(ha))
			host_to_fcp_swap(pkt->data, sizeof(pkt->data));
		memcpy(sp->request_sense_ptr, pkt->data, sense_sz);
		DEBUG5(qla2x00_dump_buffer(sp->request_sense_ptr, sense_sz));

		sp->request_sense_ptr += sense_sz;
		sp->request_sense_length -= sense_sz;

		/* Place command on done queue. */
		if (sp->request_sense_length == 0) {
			ha->status_srb = NULL;
			qla2x00_sp_compl(ha, sp);
		}
	}
}

/**
 * qla2x00_error_entry() - Process an error entry.
 * @ha: SCSI driver HA context
 * @pkt: Entry pointer
 */
static void
qla2x00_error_entry(scsi_qla_host_t *ha, sts_entry_t *pkt)
{
	srb_t *sp;

#if defined(QL_DEBUG_LEVEL_2)
	if (pkt->entry_status & RF_INV_E_ORDER)
		qla_printk(KERN_ERR, ha, "%s: Invalid Entry Order\n", __func__);
	else if (pkt->entry_status & RF_INV_E_COUNT)
		qla_printk(KERN_ERR, ha, "%s: Invalid Entry Count\n", __func__);
	else if (pkt->entry_status & RF_INV_E_PARAM)
		qla_printk(KERN_ERR, ha,
		    "%s: Invalid Entry Parameter\n", __func__);
	else if (pkt->entry_status & RF_INV_E_TYPE)
		qla_printk(KERN_ERR, ha, "%s: Invalid Entry Type\n", __func__);
	else if (pkt->entry_status & RF_BUSY)
		qla_printk(KERN_ERR, ha, "%s: Busy\n", __func__);
	else
		qla_printk(KERN_ERR, ha, "%s: UNKNOWN flag error\n", __func__);
#endif

	/* Validate handle. */
	if (pkt->handle < MAX_OUTSTANDING_COMMANDS)
		sp = ha->outstanding_cmds[pkt->handle];
	else
		sp = NULL;

	if (sp) {
		/* Free outstanding command slot. */
		ha->outstanding_cmds[pkt->handle] = NULL;

		/* Bad payload or header */
		if (pkt->entry_status &
		    (RF_INV_E_ORDER | RF_INV_E_COUNT |
		     RF_INV_E_PARAM | RF_INV_E_TYPE)) {
			sp->cmd->result = DID_ERROR << 16;
		} else if (pkt->entry_status & RF_BUSY) {
			sp->cmd->result = DID_BUS_BUSY << 16;
		} else {
			sp->cmd->result = DID_ERROR << 16;
		}
		qla2x00_sp_compl(ha, sp);

	} else if (pkt->entry_type == COMMAND_A64_TYPE || pkt->entry_type ==
	    COMMAND_TYPE || pkt->entry_type == COMMAND_TYPE_7) {
		DEBUG2(printk("scsi(%ld): Error entry - invalid handle\n",
		    ha->host_no));
		qla_printk(KERN_WARNING, ha,
		    "Error entry - invalid handle\n");

		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		qla2xxx_wake_dpc(ha);
	}
}

/**
 * qla2x00_ms_entry() - Process a Management Server entry.
 * @ha: SCSI driver HA context
 * @index: Response queue out pointer
 */
static void
qla2x00_ms_entry(scsi_qla_host_t *ha, ms_iocb_entry_t *pkt)
{
	srb_t          *sp;

	DEBUG3(printk("%s(%ld): pkt=%p pkthandle=%d.\n",
	    __func__, ha->host_no, pkt, pkt->handle1));

	/* Validate handle. */
 	if (pkt->handle1 < MAX_OUTSTANDING_COMMANDS)
 		sp = ha->outstanding_cmds[pkt->handle1];
	else
		sp = NULL;

	if (sp == NULL) {
		DEBUG2(printk("scsi(%ld): MS entry - invalid handle\n",
		    ha->host_no));
		qla_printk(KERN_WARNING, ha, "MS entry - invalid handle\n");

		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		return;
	}

	CMD_COMPL_STATUS(sp->cmd) = le16_to_cpu(pkt->status);
	CMD_ENTRY_STATUS(sp->cmd) = pkt->entry_status;

	/* Free outstanding command slot. */
	ha->outstanding_cmds[pkt->handle1] = NULL;

	qla2x00_sp_compl(ha, sp);
}


/**
 * qla24xx_mbx_completion() - Process mailbox command completions.
 * @ha: SCSI driver HA context
 * @mb0: Mailbox0 register
 */
static void
qla24xx_mbx_completion(scsi_qla_host_t *ha, uint16_t mb0)
{
	uint16_t	cnt;
	uint16_t __iomem *wptr;
	struct device_reg_24xx __iomem *reg = &ha->iobase->isp24;

	/* Load return mailbox registers. */
	ha->flags.mbox_int = 1;
	ha->mailbox_out[0] = mb0;
	wptr = (uint16_t __iomem *)&reg->mailbox1;

	for (cnt = 1; cnt < ha->mbx_count; cnt++) {
		ha->mailbox_out[cnt] = RD_REG_WORD(wptr);
		wptr++;
	}

	if (ha->mcp) {
		DEBUG3(printk("%s(%ld): Got mailbox completion. cmd=%x.\n",
		    __func__, ha->host_no, ha->mcp->mb[0]));
	} else {
		DEBUG2_3(printk("%s(%ld): MBX pointer ERROR!\n",
		    __func__, ha->host_no));
	}
}

/**
 * qla24xx_process_response_queue() - Process response queue entries.
 * @ha: SCSI driver HA context
 */
void
qla24xx_process_response_queue(struct scsi_qla_host *ha)
{
	struct device_reg_24xx __iomem *reg = &ha->iobase->isp24;
	struct sts_entry_24xx *pkt;

	if (!ha->flags.online)
		return;

	while (ha->response_ring_ptr->signature != RESPONSE_PROCESSED) {
		pkt = (struct sts_entry_24xx *)ha->response_ring_ptr;

		ha->rsp_ring_index++;
		if (ha->rsp_ring_index == ha->response_q_length) {
			ha->rsp_ring_index = 0;
			ha->response_ring_ptr = ha->response_ring;
		} else {
			ha->response_ring_ptr++;
		}

		if (pkt->entry_status != 0) {
			DEBUG3(printk(KERN_INFO
			    "scsi(%ld): Process error entry.\n", ha->host_no));

			qla2x00_error_entry(ha, (sts_entry_t *) pkt);
			((response_t *)pkt)->signature = RESPONSE_PROCESSED;
			wmb();
			continue;
		}

		switch (pkt->entry_type) {
		case STATUS_TYPE:
			qla2x00_status_entry(ha, pkt);
			break;
		case STATUS_CONT_TYPE:
			qla2x00_status_cont_entry(ha, (sts_cont_entry_t *)pkt);
			break;
		case MS_IOCB_TYPE:
			if (ha->outstanding_cmds[pkt->handle])
				qla24xx_ms_entry(ha, (void *)pkt);
			else {
				if (ha->pass_thru_cmd_result)
					qla_printk(KERN_INFO, ha,
					    "Passthru cmd result on.\n");
				if (!ha->pass_thru_cmd_in_process)
					qla_printk(KERN_INFO, ha,
					    "Passthru in process off.\n");

				ha->pass_thru_cmd_result = 1;
				complete(&ha->pass_thru_intr_comp);
			}
			break;
		case ELS_IOCB_TYPE:
			if (ha->pass_thru_cmd_result)
				qla_printk(KERN_INFO, ha,
				    "Passthru cmd result on.\n");
			if (!ha->pass_thru_cmd_in_process)
				qla_printk(KERN_INFO, ha,
				    "Passthru in process off.\n");

			ha->pass_thru_cmd_result = 1;
			complete(&ha->pass_thru_intr_comp);
			break;
		case VP_RPT_ID_IOCB_TYPE:
			qla24xx_report_id_acquisition(ha,
			    (struct vp_rpt_id_entry_24xx *)pkt);
			break;
		default:
			/* Type Not Supported. */
			DEBUG4(printk(KERN_WARNING
			    "scsi(%ld): Received unknown response pkt type %x "
			    "entry status=%x.\n",
			    ha->host_no, pkt->entry_type, pkt->entry_status));
			break;
		}
		((response_t *)pkt)->signature = RESPONSE_PROCESSED;
		wmb();
	}

	/* Adjust ring index */
	if (IS_QLA82XX(ha)) {
		struct device_reg_82xx __iomem *reg = &ha->iobase->isp82;
		WRT_REG_DWORD(&reg->rsp_q_out[0], ha->rsp_ring_index);
	} else
		WRT_REG_DWORD(&reg->rsp_q_out, ha->rsp_ring_index);
}

static void
qla2xxx_check_risc_status(scsi_qla_host_t *ha)
{
	int rval;
	uint32_t cnt;
	struct device_reg_24xx __iomem *reg = &ha->iobase->isp24;

	if (!IS_QLA25XX(ha) && !IS_QLA81XX(ha))
		return;

	rval = QLA_SUCCESS;
	WRT_REG_DWORD(&reg->iobase_addr, 0x7C00);
	RD_REG_DWORD(&reg->iobase_addr);
	WRT_REG_DWORD(&reg->iobase_window, 0x0001);
	for (cnt = 10000; (RD_REG_DWORD(&reg->iobase_window) & BIT_0) == 0 &&
	    rval == QLA_SUCCESS; cnt--) {
		if (cnt) {
			WRT_REG_DWORD(&reg->iobase_window, 0x0001);
			udelay(10);
		} else
			rval = QLA_FUNCTION_TIMEOUT;
	}
	if (rval == QLA_SUCCESS)
		goto next_test;

	WRT_REG_DWORD(&reg->iobase_window, 0x0003);
	for (cnt = 100; (RD_REG_DWORD(&reg->iobase_window) & BIT_0) == 0 &&
	    rval == QLA_SUCCESS; cnt--) {
		if (cnt) {
			WRT_REG_DWORD(&reg->iobase_window, 0x0003);
			udelay(10);
		} else
			rval = QLA_FUNCTION_TIMEOUT;
	}
	if (rval != QLA_SUCCESS)
		goto done;

next_test:
	if (RD_REG_DWORD(&reg->iobase_c8) & BIT_3)
		qla_printk(KERN_INFO, ha, "Additional code -- 0x55AA.\n");

done:
	WRT_REG_DWORD(&reg->iobase_window, 0x0000);
	RD_REG_DWORD(&reg->iobase_window);
}

/**
 * qla24xx_intr_handler() - Process interrupts for the ISP23xx and ISP63xx.
 * @irq:
 * @dev_id: SCSI driver HA context
 * @regs:
 *
 * Called by system whenever the host adapter generates an interrupt.
 *
 * Returns handled flag.
 */
irqreturn_t
qla24xx_intr_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	scsi_qla_host_t	*ha;
	struct device_reg_24xx __iomem *reg;
	int		status;
	unsigned long	flags;
	unsigned long	iter;
	uint32_t	stat;
	uint32_t	hccr;
	uint16_t	mb[4];

	ha = (scsi_qla_host_t *) dev_id;
	if (!ha) {
		printk(KERN_INFO
		    "%s(): NULL host pointer\n", __func__);
		return IRQ_NONE;
	}

	reg = &ha->iobase->isp24;
	status = 0;

	if (unlikely(pci_channel_offline(ha->pdev)))
		return IRQ_HANDLED;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	for (iter = 50; iter--; ) {
		stat = RD_REG_DWORD(&reg->host_status);
		if (stat & HSRX_RISC_PAUSED) {
			if (pci_channel_offline(ha->pdev))
				break;

			hccr = RD_REG_DWORD(&reg->hccr);

			qla_printk(KERN_INFO, ha, "RISC paused -- HCCR=%x, "
			    "Dumping firmware!\n", hccr);

			qla2xxx_check_risc_status(ha);

			ha->isp_ops->fw_dump(ha, 1);
			set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
			break;
		} else if ((stat & HSRX_RISC_INT) == 0)
			break;

		switch (stat & 0xff) {
		case 0x1:
		case 0x2:
		case 0x10:
		case 0x11:
			qla24xx_mbx_completion(ha, MSW(stat));
			status |= MBX_INTERRUPT;

			break;
		case 0x12:
			mb[0] = MSW(stat);
			mb[1] = RD_REG_WORD(&reg->mailbox1);
			mb[2] = RD_REG_WORD(&reg->mailbox2);
			mb[3] = RD_REG_WORD(&reg->mailbox3);
			qla2x00_async_event(ha, mb);
			break;
		case 0x13:
			qla24xx_process_response_queue(ha);
			break;
		default:
			DEBUG2(printk("scsi(%ld): Unrecognized interrupt type "
			    "(%d).\n",
			    ha->host_no, stat & 0xff));
			break;
		}
		WRT_REG_DWORD(&reg->hccr, HCCRX_CLR_RISC_INT);
		RD_REG_DWORD_RELAXED(&reg->hccr);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

#ifdef QL_DEBUG_LEVEL_17
	if (!irq && ha->flags.eeh_busy)
		qla_printk(KERN_WARNING, ha,
		    "isr: status %x, cmd_flags %lx, mbox_int %x, stat %x\n",
		    status, ha->mbx_cmd_flags, ha->flags.mbox_int, stat);
#endif

	if (test_bit(MBX_INTR_WAIT, &ha->mbx_cmd_flags) &&
	    (status & MBX_INTERRUPT) && ha->flags.mbox_int) {
		set_bit(MBX_INTERRUPT, &ha->mbx_cmd_flags);
		complete(&ha->mbx_intr_comp);
	}

	return IRQ_HANDLED;
}

/**
 * qla24xx_ms_entry() - Process a Management Server entry.
 * @ha: SCSI driver HA context
 * @index: Response queue out pointer
 */
static void
qla24xx_ms_entry(scsi_qla_host_t *ha, struct ct_entry_24xx *pkt)
{
	srb_t          *sp;

	DEBUG3(printk("%s(%ld): pkt=%p pkthandle=%d.\n",
	    __func__, ha->host_no, pkt, pkt->handle));

	DEBUG9(printk("%s: ct pkt dump:\n", __func__));
	DEBUG9(qla2x00_dump_buffer((void *)pkt, sizeof(struct ct_entry_24xx)));

	/* Validate handle. */
 	if (pkt->handle < MAX_OUTSTANDING_COMMANDS)
 		sp = ha->outstanding_cmds[pkt->handle];
	else
		sp = NULL;

	if (sp == NULL) {
		DEBUG2(printk("scsi(%ld): MS entry - invalid handle\n",
		    ha->host_no));
		DEBUG10(printk("scsi(%ld): MS entry - invalid handle\n",
		    ha->host_no));
		qla_printk(KERN_WARNING, ha, "MS entry - invalid handle %d\n",
		    pkt->handle);

		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		return;
	}

	CMD_COMPL_STATUS(sp->cmd) = le16_to_cpu(pkt->comp_status);
	CMD_ENTRY_STATUS(sp->cmd) = pkt->entry_status;

	/* Free outstanding command slot. */
	ha->outstanding_cmds[pkt->handle] = NULL;

	qla2x00_sp_compl(ha, sp);
}

static irqreturn_t
qla24xx_msix_rsp_q(int irq, void *dev_id, struct pt_regs *regs)
{
	scsi_qla_host_t	*ha;
	struct device_reg_24xx __iomem *reg;
	unsigned long flags;

	ha = dev_id;
	reg = &ha->iobase->isp24;

	spin_lock_irqsave(&ha->hardware_lock, flags);

	qla24xx_process_response_queue(ha);

	WRT_REG_DWORD(&reg->hccr, HCCRX_CLR_RISC_INT);

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return IRQ_HANDLED;
}

static irqreturn_t
qla24xx_msix_default(int irq, void *dev_id, struct pt_regs *regs)
{
	scsi_qla_host_t	*ha;
	struct device_reg_24xx __iomem *reg;
	int		status;
	unsigned long	flags;
	uint32_t	stat;
	uint32_t	hccr;
	uint16_t	mb[4];

	ha = dev_id;
	reg = &ha->iobase->isp24;
	status = 0;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	do {
		stat = RD_REG_DWORD(&reg->host_status);
		if (stat & HSRX_RISC_PAUSED) {
			if (pci_channel_offline(ha->pdev))
				break;

			hccr = RD_REG_DWORD(&reg->hccr);

			qla_printk(KERN_INFO, ha, "RISC paused -- HCCR=%x, "
			    "Dumping firmware!\n", hccr);

			qla2xxx_check_risc_status(ha);

			ha->isp_ops->fw_dump(ha, 1);
			set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
			break;
		} else if ((stat & HSRX_RISC_INT) == 0)
			break;

		switch (stat & 0xff) {
		case 0x1:
		case 0x2:
		case 0x10:
		case 0x11:
			qla24xx_mbx_completion(ha, MSW(stat));
			status |= MBX_INTERRUPT;

			break;
		case 0x12:
			mb[0] = MSW(stat);
			mb[1] = RD_REG_WORD(&reg->mailbox1);
			mb[2] = RD_REG_WORD(&reg->mailbox2);
			mb[3] = RD_REG_WORD(&reg->mailbox3);
			qla2x00_async_event(ha, mb);
			break;
		case 0x13:
			qla24xx_process_response_queue(ha);
			break;
		default:
			DEBUG2(printk("scsi(%ld): Unrecognized interrupt type "
			    "(%d).\n",
			    ha->host_no, stat & 0xff));
			break;
		}
		WRT_REG_DWORD(&reg->hccr, HCCRX_CLR_RISC_INT);
	} while (0);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (test_bit(MBX_INTR_WAIT, &ha->mbx_cmd_flags) &&
	    (status & MBX_INTERRUPT) && ha->flags.mbox_int) {
		set_bit(MBX_INTERRUPT, &ha->mbx_cmd_flags);
		complete(&ha->mbx_intr_comp);
	}

	return IRQ_HANDLED;
}

/* Interrupt handling helpers. */

struct qla_init_msix_entry {
	uint16_t entry;
	uint16_t index;
	const char *name;
	irq_handler_t handler;
};

static struct qla_init_msix_entry qla24xx_msix_entries[QLA_MSIX_ENTRIES] = {
	{ QLA_MSIX_DEFAULT, QLA_MIDX_DEFAULT,
		"qla2xxx (default)", qla24xx_msix_default },

	{ QLA_MSIX_RSP_Q, QLA_MIDX_RSP_Q,
		"qla2xxx (rsp_q)", qla24xx_msix_rsp_q },
};

static struct qla_init_msix_entry qla82xx_msix_entries[QLA_MSIX_ENTRIES] = {
	{ QLA_MSIX_DEFAULT, QLA_MIDX_DEFAULT,
		"qla2xxx (default)", qla82xx_msix_default },

	{ QLA_MSIX_RSP_Q, QLA_MIDX_RSP_Q,
		"qla2xxx (rsp_q)", qla82xx_msix_rsp_q },
};

static void
qla24xx_disable_msix(scsi_qla_host_t *ha)
{
	int i;
	struct qla_msix_entry *qentry;

	for (i = 0; i < QLA_MSIX_ENTRIES; i++) {
		if (IS_QLA82XX(ha))
			qentry =
			    &ha->msix_entries[qla82xx_msix_entries[i].index];
		else
			qentry =
			    &ha->msix_entries[qla24xx_msix_entries[i].index];

		if (qentry->have_irq)
			free_irq(qentry->msix_vector, ha);
	}
	pci_disable_msix(ha->pdev);
}

static int
qla24xx_enable_msix(scsi_qla_host_t *ha)
{
	int i, ret;
	struct msix_entry entries[QLA_MSIX_ENTRIES];
	struct qla_msix_entry *qentry;

	for (i = 0; i < QLA_MSIX_ENTRIES; i++) {
		if (IS_QLA82XX(ha))
			entries[i].entry = qla82xx_msix_entries[i].entry;
		else
			entries[i].entry = qla24xx_msix_entries[i].entry;
	}

	ret = pci_enable_msix(ha->pdev, entries, ARRAY_SIZE(entries));
	if (ret) {
		qla_printk(KERN_WARNING, ha,
		    "MSI-X: Failed to enable support -- %d/%d\n",
		    QLA_MSIX_ENTRIES, ret);
		goto msix_out;
	}
	ha->flags.msix_enabled = 1;

	for (i = 0; i < QLA_MSIX_ENTRIES; i++) {
		if (IS_QLA82XX(ha))
			qentry =
			    &ha->msix_entries[qla82xx_msix_entries[i].index];
		else
			qentry =
			    &ha->msix_entries[qla24xx_msix_entries[i].index];
		qentry->msix_vector = entries[i].vector;
		qentry->msix_entry = entries[i].entry;
		qentry->have_irq = 0;
		if (IS_QLA82XX(ha)) {
			ret = request_irq(qentry->msix_vector,
			    qla82xx_msix_entries[i].handler, 0,
			    qla82xx_msix_entries[i].name, ha);
		} else {
			ret = request_irq(qentry->msix_vector,
			    qla24xx_msix_entries[i].handler, 0,
			    qla24xx_msix_entries[i].name, ha);
		}
		if (ret) {
			qla_printk(KERN_WARNING, ha,
			    "MSI-X: Unable to register handler -- %x/%d.\n",
			    qla24xx_msix_entries[i].index, ret);
			qla24xx_disable_msix(ha);
			goto msix_out;
		}
		qentry->have_irq = 1;
	}

msix_out:
	return ret;
}

int
qla2x00_request_irqs(scsi_qla_host_t *ha)
{
	int ret;

	/* If possible, enable MSI-X, MSI. */
	if ( ql2xenablemsix == 0 || (!IS_QLA2432(ha) && !IS_QLA2532(ha)
	    && !IS_QLA8432(ha) && !IS_QLA8XXX_TYPE(ha)))
		goto skip_msi;

	if (ha->pdev->subsystem_vendor == PCI_VENDOR_ID_HP &&
	    (ha->pdev->subsystem_device == 0x7040 ||
	    ha->pdev->subsystem_device == 0x7041 ||
	    ha->pdev->subsystem_device == 0x1705)) {
		DEBUG2(qla_printk(KERN_WARNING, ha,
		    "MSI-X: Unsupported ISP2432 SSVID/SSDID (0x%X, 0x%X).\n",
		    ha->pdev->subsystem_vendor,
		    ha->pdev->subsystem_device));
		goto skip_msi;
	}

	if (ql2xenablemsix == 2)
		goto skip_msix;

	if (IS_QLA2432(ha) && (ha->chip_revision < QLA_MSIX_CHIP_REV_24XX ||
	    !QLA_MSIX_FW_MODE_1(ha->fw_attributes))) {
		DEBUG2(qla_printk(KERN_WARNING, ha,
		    "MSI-X: Unsupported ISP2432 (0x%X, 0x%X).\n",
		    ha->chip_revision, ha->fw_attributes));
		goto skip_msix;
	}

	ret = qla24xx_enable_msix(ha);
	if (!ret) {
		DEBUG2(qla_printk(KERN_INFO, ha,
		    "MSI-X: Enabled (0x%X, 0x%X).\n", ha->chip_revision,
		    ha->fw_attributes));
		return ret;
	}
	qla_printk(KERN_WARNING, ha,
	    "MSI-X: Falling back-to MSI mode -- %d.\n", ret);

skip_msix:
	ret = pci_enable_msi(ha->pdev);
	if (!ret) {
		DEBUG2(qla_printk(KERN_INFO, ha, "MSI: Enabled.\n"));
		ha->flags.msi_enabled = 1;
	} else
		qla_printk(KERN_WARNING, ha,
		    "MSI: Falling back-to INTa mode -- %d.\n", ret);
skip_msi:
	ret = request_irq(ha->pdev->irq, ha->isp_ops->intr_handler,
	    IRQF_DISABLED|IRQF_SHARED, QLA2XXX_DRIVER_NAME, ha);
	if (!ret) {
		ha->flags.inta_enabled = 1;
		ha->host->irq = ha->pdev->irq;
	} else {
		qla_printk(KERN_WARNING, ha,
		    "Failed to reserve interrupt %d already in use.\n",
		    ha->pdev->irq);
	}

	return ret;
}

void
qla2x00_free_irqs(scsi_qla_host_t *ha)
{
	if (ha->flags.msix_enabled)
		qla24xx_disable_msix(ha);
	else if (ha->flags.msi_enabled) {
		free_irq(ha->host->irq, ha);
		pci_disable_msi(ha->pdev);
	} else
		free_irq(ha->host->irq, ha);
}
