/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2011 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"

#include <linux/blkdev.h>
#include <linux/delay.h>

#include <scsi/scsi_tcq.h>

static inline uint16_t qla2x00_get_cmd_direction(srb_t *);
static inline cont_entry_t *qla2x00_prep_cont_type0_iocb(scsi_qla_host_t *);
static inline cont_a64_entry_t *qla2x00_prep_cont_type1_iocb(scsi_qla_host_t *);

/**
 * qla2x00_get_cmd_direction() - Determine control_flag data direction.
 * @sp: srb_t *
 *
 * Returns the proper CF_* direction based on CDB.
 */
static inline uint16_t
qla2x00_get_cmd_direction(srb_t *sp)
{
	uint16_t cflags;

	cflags = 0;

	/* Set transfer direction */
	if (sp->cmd->sc_data_direction == DMA_TO_DEVICE) {
		cflags = CF_WRITE;
		sp->ha->qla_stats.output_bytes += scsi_bufflen(sp->cmd);
	} else if (sp->cmd->sc_data_direction == DMA_FROM_DEVICE) {
		cflags = CF_READ;
		sp->ha->qla_stats.input_bytes += scsi_bufflen(sp->cmd);
	}
	return (cflags);
}

/**
 * qla2x00_calc_iocbs_32() - Determine number of Command Type 2 and
 * Continuation Type 0 IOCBs to allocate.
 *
 * @dsds: number of data segment descriptors needed
 *
 * Returns the number of IOCB entries needed to store @dsds.
 */
uint16_t
qla2x00_calc_iocbs_32(uint16_t dsds)
{
	uint16_t iocbs;

	iocbs = 1;
	if (dsds > 3) {
		iocbs += (dsds - 3) / 7;
		if ((dsds - 3) % 7)
			iocbs++;
	}
	return (iocbs);
}

/**
 * qla2x00_calc_iocbs_64() - Determine number of Command Type 3 and
 * Continuation Type 1 IOCBs to allocate.
 *
 * @dsds: number of data segment descriptors needed
 *
 * Returns the number of IOCB entries needed to store @dsds.
 */
uint16_t
qla2x00_calc_iocbs_64(uint16_t dsds)
{
	uint16_t iocbs;

	iocbs = 1;
	if (dsds > 2) {
		iocbs += (dsds - 2) / 5;
		if ((dsds - 2) % 5)
			iocbs++;
	}
	return (iocbs);
}

/**
 * qla2x00_prep_cont_type0_iocb() - Initialize a Continuation Type 0 IOCB.
 * @ha: HA context
 *
 * Returns a pointer to the Continuation Type 0 IOCB packet.
 */
static inline cont_entry_t *
qla2x00_prep_cont_type0_iocb(scsi_qla_host_t *ha)
{
	cont_entry_t *cont_pkt;

	/* Adjust ring index. */
	ha->req_ring_index++;
	if (ha->req_ring_index == ha->request_q_length) {
		ha->req_ring_index = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else {
		ha->request_ring_ptr++;
	}

	cont_pkt = (cont_entry_t *)ha->request_ring_ptr;

	/* Load packet defaults. */
	*((uint32_t *)(&cont_pkt->entry_type)) =
	    __constant_cpu_to_le32(CONTINUE_TYPE);

	return (cont_pkt);
}

/**
 * qla2x00_prep_cont_type1_iocb() - Initialize a Continuation Type 1 IOCB.
 * @ha: HA context
 *
 * Returns a pointer to the continuation type 1 IOCB packet.
 */
static inline cont_a64_entry_t *
qla2x00_prep_cont_type1_iocb(scsi_qla_host_t *ha)
{
	cont_a64_entry_t *cont_pkt;

	/* Adjust ring index. */
	ha->req_ring_index++;
	if (ha->req_ring_index == ha->request_q_length) {
		ha->req_ring_index = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else {
		ha->request_ring_ptr++;
	}

	cont_pkt = (cont_a64_entry_t *)ha->request_ring_ptr;

	/* Load packet defaults. */
	*((uint32_t *)(&cont_pkt->entry_type)) =
	    __constant_cpu_to_le32(CONTINUE_A64_TYPE);

	return (cont_pkt);
}

/**
 * qla2x00_build_scsi_iocbs_32() - Build IOCB command utilizing 32bit
 * capable IOCB types.
 *
 * @sp: SRB command to process
 * @cmd_pkt: Command type 2 IOCB
 * @tot_dsds: Total number of segments to transfer
 */
void qla2x00_build_scsi_iocbs_32(srb_t *sp, cmd_entry_t *cmd_pkt,
    uint16_t tot_dsds)
{
	uint16_t	avail_dsds;
	uint32_t	*cur_dsd;
	scsi_qla_host_t	*ha;
	struct scsi_cmnd *cmd;

	cmd = sp->cmd;

	/* Update entry type to indicate Command Type 2 IOCB */
	*((uint32_t *)(&cmd_pkt->entry_type)) =
	    __constant_cpu_to_le32(COMMAND_TYPE);

	/* No data transfer */
	if (!scsi_bufflen(cmd) || cmd->sc_data_direction == DMA_NONE) {
		cmd_pkt->byte_count = __constant_cpu_to_le32(0);
		return;
	}

	ha = sp->ha;

	cmd_pkt->control_flags |= cpu_to_le16(qla2x00_get_cmd_direction(sp));

	/* Three DSDs are available in the Command Type 2 IOCB */
	avail_dsds = 3;
	cur_dsd = (uint32_t *)&cmd_pkt->dseg_0_address;

	/* Load data segments */
	if (scsi_sg_count(cmd) != 0) {
		struct	scatterlist *cur_seg;
		struct	scatterlist *end_seg;

		cur_seg = scsi_sglist(cmd);
		end_seg = cur_seg + tot_dsds;
		while (cur_seg < end_seg) {
			cont_entry_t	*cont_pkt;

			/* Allocate additional continuation packets? */
			if (avail_dsds == 0) {
				/*
				 * Seven DSDs are available in the Continuation
				 * Type 0 IOCB.
				 */
				cont_pkt = qla2x00_prep_cont_type0_iocb(ha);
				cur_dsd = (uint32_t *)&cont_pkt->dseg_0_address;
				avail_dsds = 7;
			}

			*cur_dsd++ = cpu_to_le32(sg_dma_address(cur_seg));
			*cur_dsd++ = cpu_to_le32(sg_dma_len(cur_seg));
			avail_dsds--;

			cur_seg++;
		}
	} else {
		*cur_dsd++ = cpu_to_le32(sp->dma_handle);
		*cur_dsd++ = cpu_to_le32(scsi_bufflen(cmd));
	}
}

/**
 * qla2x00_build_scsi_iocbs_64() - Build IOCB command utilizing 64bit
 * capable IOCB types.
 *
 * @sp: SRB command to process
 * @cmd_pkt: Command type 3 IOCB
 * @tot_dsds: Total number of segments to transfer
 */
void qla2x00_build_scsi_iocbs_64(srb_t *sp, cmd_entry_t *cmd_pkt,
    uint16_t tot_dsds)
{
	uint16_t	avail_dsds;
	uint32_t	*cur_dsd;
	scsi_qla_host_t	*ha;
	struct scsi_cmnd *cmd;

	cmd = sp->cmd;

	/* Update entry type to indicate Command Type 3 IOCB */
	*((uint32_t *)(&cmd_pkt->entry_type)) =
	    __constant_cpu_to_le32(COMMAND_A64_TYPE);

	/* No data transfer */
	if (!scsi_bufflen(cmd) || cmd->sc_data_direction == DMA_NONE) {
		cmd_pkt->byte_count = __constant_cpu_to_le32(0);
		return;
	}

	ha = sp->ha;

	cmd_pkt->control_flags |= cpu_to_le16(qla2x00_get_cmd_direction(sp));

	/* Two DSDs are available in the Command Type 3 IOCB */
	avail_dsds = 2;
	cur_dsd = (uint32_t *)&cmd_pkt->dseg_0_address;

	/* Load data segments */
	if (scsi_sg_count(cmd) != 0) {
		struct	scatterlist *cur_seg;
		struct	scatterlist *end_seg;

		cur_seg = scsi_sglist(cmd);
		end_seg = cur_seg + tot_dsds;
		while (cur_seg < end_seg) {
			dma_addr_t	sle_dma;
			cont_a64_entry_t *cont_pkt;

			/* Allocate additional continuation packets? */
			if (avail_dsds == 0) {
				/*
				 * Five DSDs are available in the Continuation
				 * Type 1 IOCB.
				 */
				cont_pkt = qla2x00_prep_cont_type1_iocb(ha);
				cur_dsd = (uint32_t *)cont_pkt->dseg_0_address;
				avail_dsds = 5;
			}

			sle_dma = sg_dma_address(cur_seg);
			*cur_dsd++ = cpu_to_le32(LSD(sle_dma));
			*cur_dsd++ = cpu_to_le32(MSD(sle_dma));
			*cur_dsd++ = cpu_to_le32(sg_dma_len(cur_seg));
			avail_dsds--;

			cur_seg++;
		}
	} else {
		*cur_dsd++ = cpu_to_le32(LSD(sp->dma_handle));
		*cur_dsd++ = cpu_to_le32(MSD(sp->dma_handle));
		*cur_dsd++ = cpu_to_le32(scsi_bufflen(cmd));
	}
}

/**
 * qla2x00_start_scsi() - Send a SCSI command to the ISP
 * @sp: command to send to the ISP
 *
 * Returns non-zero if a failure occured, else zero.
 */
int
qla2x00_start_scsi(srb_t *sp)
{
	int		ret;
	unsigned long   flags;
	scsi_qla_host_t	*ha;
	struct scsi_cmnd *cmd;
	uint32_t	*clr_ptr;
	uint32_t        index;
	uint32_t	handle;
	cmd_entry_t	*cmd_pkt;
	struct scatterlist *sg;
	uint16_t	cnt;
	uint16_t	req_cnt;
	uint16_t	tot_dsds;
	struct device_reg_2xxx __iomem *reg;
	char		tag[2];

	/* Setup device pointers. */
	ret = 0;
	ha = sp->ha;
	reg = &ha->iobase->isp;
	cmd = sp->cmd;
	/* So we know we haven't pci_map'ed anything yet */
	tot_dsds = 0;

	/* Send marker if required */
	if (ha->marker_needed != 0) {
		if (qla2x00_marker(ha, 0, 0, MK_SYNC_ALL) != QLA_SUCCESS) {
			return (QLA_FUNCTION_FAILED);
		}
		ha->marker_needed = 0;
	}

	/* Acquire ring specific lock */
	spin_lock_irqsave(&ha->hardware_lock, flags);

	/* Check for room in outstanding command list. */
	handle = ha->current_outstanding_cmd;
	for (index = 1; index < MAX_OUTSTANDING_COMMANDS; index++) {
		handle++;
		if (handle == MAX_OUTSTANDING_COMMANDS)
			handle = 1;
		if (!ha->outstanding_cmds[handle])
			break;
	}
	if (index == MAX_OUTSTANDING_COMMANDS)
		goto queuing_error;

	/* Map the sg table so we have an accurate count of sg entries needed */
	if (scsi_sg_count(cmd)) {
		sg = scsi_sglist(cmd);
		tot_dsds = pci_map_sg(ha->pdev, sg, scsi_sg_count(cmd),
		    cmd->sc_data_direction);
		if (tot_dsds == 0)
			goto queuing_error;
	} else if (scsi_bufflen(cmd)) {
		dma_addr_t	req_dma;

		req_dma = pci_map_single(ha->pdev, scsi_sglist(cmd),
		    scsi_bufflen(cmd), cmd->sc_data_direction);
		if (dma_mapping_error(req_dma))
			goto queuing_error;

		sp->dma_handle = req_dma;
		tot_dsds = 1;
	}

	/* Calculate the number of request entries needed. */
	req_cnt = ha->isp_ops->calc_req_entries(tot_dsds);
	if (ha->req_q_cnt < (req_cnt + 2)) {
		cnt = RD_REG_WORD_RELAXED(ISP_REQ_Q_OUT(ha, reg));
		if (ha->req_ring_index < cnt)
			ha->req_q_cnt = cnt - ha->req_ring_index;
		else
			ha->req_q_cnt = ha->request_q_length -
			    (ha->req_ring_index - cnt);
	}
	if (ha->req_q_cnt < (req_cnt + 2))
		goto queuing_error;

	/* Build command packet */
	ha->current_outstanding_cmd = handle;
	ha->outstanding_cmds[handle] = sp;
	sp->ha = ha;
	sp->cmd->host_scribble = (unsigned char *)(unsigned long)handle;
	ha->req_q_cnt -= req_cnt;

	cmd_pkt = (cmd_entry_t *)ha->request_ring_ptr;
	cmd_pkt->handle = handle;
	/* Zero out remaining portion of packet. */
	clr_ptr = (uint32_t *)cmd_pkt + 2;
	memset(clr_ptr, 0, REQUEST_ENTRY_SIZE - 8);
	cmd_pkt->dseg_count = cpu_to_le16(tot_dsds);

	/* Set target ID and LUN number*/
	SET_TARGET_ID(ha, cmd_pkt->target, sp->fcport->loop_id);
	cmd_pkt->lun = cpu_to_le16(sp->cmd->device->lun);

	/* Update tagged queuing modifier */
	if (scsi_populate_tag_msg(cmd, tag)) {
		switch (tag[0]) {
		case HEAD_OF_QUEUE_TAG:
			cmd_pkt->control_flags =
			    __constant_cpu_to_le16(CF_HEAD_TAG);
			break;
		case ORDERED_QUEUE_TAG:
			cmd_pkt->control_flags =
			    __constant_cpu_to_le16(CF_ORDERED_TAG);
			break;
		default:
			cmd_pkt->control_flags =
			    __constant_cpu_to_le16(CF_SIMPLE_TAG);
			break;
		}
	}

	/* Load SCSI command packet. */
	memcpy(cmd_pkt->scsi_cdb, cmd->cmnd, cmd->cmd_len);
	cmd_pkt->byte_count = cpu_to_le32((uint32_t)scsi_bufflen(cmd));

	/* Build IOCB segments */
	ha->isp_ops->build_iocbs(sp, cmd_pkt, tot_dsds);

	/* Set total data segment count. */
	cmd_pkt->entry_count = (uint8_t)req_cnt;
	wmb();

	/* Adjust ring index. */
	ha->req_ring_index++;
	if (ha->req_ring_index == ha->request_q_length) {
		ha->req_ring_index = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else
		ha->request_ring_ptr++;

	sp->flags |= SRB_DMA_VALID;

	/* Set chip new ring index. */
	WRT_REG_WORD(ISP_REQ_Q_IN(ha, reg), ha->req_ring_index);
	RD_REG_WORD_RELAXED(ISP_REQ_Q_IN(ha, reg));	/* PCI Posting. */

	/* Manage unprocessed RIO/ZIO commands in response queue. */
	if (ha->flags.process_response_queue &&
	    ha->response_ring_ptr->signature != RESPONSE_PROCESSED)
		qla2x00_process_response_queue(ha);

	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	return (QLA_SUCCESS);

queuing_error:
	if (scsi_sg_count(cmd) && tot_dsds) {
		sg = scsi_sglist(cmd);
		pci_unmap_sg(ha->pdev, sg, scsi_sg_count(cmd),
		    cmd->sc_data_direction);
	} else if (tot_dsds) {
		pci_unmap_single(ha->pdev, sp->dma_handle,
		    scsi_bufflen(cmd), cmd->sc_data_direction);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return (QLA_FUNCTION_FAILED);
}

/**
 * qla2x00_marker() - Send a marker IOCB to the firmware.
 * @ha: HA context
 * @loop_id: loop ID
 * @lun: LUN
 * @type: marker modifier
 *
 * Can be called from both normal and interrupt context.
 *
 * Returns non-zero if a failure occured, else zero.
 */
int
__qla2x00_marker(scsi_qla_host_t *ha, uint16_t loop_id, uint16_t lun,
    uint8_t type)
{
	mrk_entry_t *mrk;
	struct mrk_entry_24xx *mrk24;
	scsi_qla_host_t *pha = to_qla_parent(ha);

	mrk24 = NULL;
	mrk = (mrk_entry_t *)qla2x00_req_pkt(pha);
	if (mrk == NULL) {
		DEBUG2_3(printk("%s(%ld): failed to allocate Marker IOCB.\n",
		    __func__, ha->host_no));

		return (QLA_FUNCTION_FAILED);
	}

	mrk->entry_type = MARKER_TYPE;
	mrk->modifier = type;
	if (type != MK_SYNC_ALL) {
		if (IS_FWI2_CAPABLE(ha)) {
			mrk24 = (struct mrk_entry_24xx *) mrk;
			mrk24->nport_handle = cpu_to_le16(loop_id);
			mrk24->lun[1] = LSB(lun);
			mrk24->lun[2] = MSB(lun);
			host_to_fcp_swap(mrk24->lun, sizeof(mrk24->lun));
			mrk24->vp_index = ha->vp_idx;
		} else {
			SET_TARGET_ID(ha, mrk->target, loop_id);
			mrk->lun = cpu_to_le16(lun);
		}
	}
	wmb();

	qla2x00_isp_cmd(pha);

	return (QLA_SUCCESS);
}

int
qla2x00_marker(scsi_qla_host_t *ha, uint16_t loop_id, uint16_t lun,
    uint8_t type)
{
	int ret;
	unsigned long flags = 0;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	ret = __qla2x00_marker(ha, loop_id, lun, type);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return (ret);
}

/**
 * qla2x00_req_pkt() - Retrieve a request packet from the request ring.
 * @ha: HA context
 *
 * Note: The caller must hold the hardware lock before calling this routine.
 *
 * Returns NULL if function failed, else, a pointer to the request packet.
 */
request_t *
qla2x00_req_pkt(scsi_qla_host_t *ha)
{
	device_reg_t __iomem *reg = ha->iobase;
	request_t	*pkt = NULL;
	uint16_t	cnt;
	uint32_t	*dword_ptr;
	uint32_t	timer;
	uint16_t	req_cnt = 1;

	/* Wait 1 second for slot. */
	for (timer = HZ; timer; timer--) {
		if ((req_cnt + 2) >= ha->req_q_cnt) {
			/* Calculate number of free request entries. */
			if (IS_QLA82XX(ha))
				cnt = (uint16_t)RD_REG_DWORD(
				    &reg->isp82.req_q_out);
			else if (IS_FWI2_CAPABLE(ha))
				cnt = (uint16_t)RD_REG_DWORD(
				    &reg->isp24.req_q_out);
			else
				cnt = qla2x00_debounce_register(
				    ISP_REQ_Q_OUT(ha, &reg->isp));
			if  (ha->req_ring_index < cnt)
				ha->req_q_cnt = cnt - ha->req_ring_index;
			else
				ha->req_q_cnt = ha->request_q_length -
				    (ha->req_ring_index - cnt);
		}
		/* If room for request in request ring. */
		if ((req_cnt + 2) < ha->req_q_cnt) {
			ha->req_q_cnt--;
			pkt = ha->request_ring_ptr;

			/* Zero out packet. */
			dword_ptr = (uint32_t *)pkt;
			for (cnt = 0; cnt < REQUEST_ENTRY_SIZE / 4; cnt++)
				*dword_ptr++ = 0;

			/* Set system defined field. */
			pkt->sys_define = (uint8_t)ha->req_ring_index;

			/* Set entry count. */
			pkt->entry_count = 1;

			break;
		}

		/* Release ring specific lock */
		spin_unlock(&ha->hardware_lock);

		udelay(2);   /* 2 us */

		/* Check for pending interrupts. */
		/* During init we issue marker directly */
		if (!ha->marker_needed && !ha->flags.init_done)
			qla2x00_poll(ha);

		spin_lock_irq(&ha->hardware_lock);
	}
	if (!pkt) {
		DEBUG2_3(printk("%s(): **** FAILED ****\n", __func__));
	}

	return (pkt);
}

/**
 * qla2x00_isp_cmd() - Modify the request ring pointer.
 * @ha: HA context
 *
 * Note: The caller must hold the hardware lock before calling this routine.
 */
void
qla2x00_isp_cmd(scsi_qla_host_t *ha)
{
	device_reg_t __iomem *reg = ha->iobase;

	DEBUG5(printk("%s(): IOCB data:\n", __func__));
	DEBUG5(qla2x00_dump_buffer(
	    (uint8_t *)ha->request_ring_ptr, REQUEST_ENTRY_SIZE));

	/* Adjust ring index. */
	ha->req_ring_index++;
	if (ha->req_ring_index == ha->request_q_length) {
		ha->req_ring_index = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else
		ha->request_ring_ptr++;

	/* Set chip new ring index. */
	if (IS_QLA82XX(ha)) {
		uint32_t dbval = 0x04 | (ha->portnum << 5);

		/* write, read and verify logic */
		/* dbval = dbval | (req->id << 8) | (ha->ring_index << 16); */
		dbval = dbval | (0 << 8) | (ha->req_ring_index << 16);
		if (ql2xdbwr)
			qla82xx_wr_32(ha, ha->nxdb_wr_ptr, dbval);
		else {
			WRT_REG_DWORD((unsigned long __iomem *)ha->nxdb_wr_ptr,
			    dbval);
			wmb();
			while (RD_REG_DWORD(ha->nxdb_rd_ptr) != dbval) {
				WRT_REG_DWORD(
				    (unsigned long  __iomem *)ha->nxdb_wr_ptr,
				    dbval);
				wmb();
			}
		}
	} else if (IS_FWI2_CAPABLE(ha)) {
		WRT_REG_DWORD(&reg->isp24.req_q_in, ha->req_ring_index);
		RD_REG_DWORD_RELAXED(&reg->isp24.req_q_in);
	} else {
		WRT_REG_WORD(ISP_REQ_Q_IN(ha, &reg->isp), ha->req_ring_index);
		RD_REG_WORD_RELAXED(ISP_REQ_Q_IN(ha, &reg->isp));
	}
}

/**
 * qla24xx_calc_iocbs() - Determine number of Command Type 3 and
 * Continuation Type 1 IOCBs to allocate.
 *
 * @dsds: number of data segment descriptors needed
 *
 * Returns the number of IOCB entries needed to store @dsds.
 */
static inline uint16_t
qla24xx_calc_iocbs(uint16_t dsds)
{
	uint16_t iocbs;

	iocbs = 1;
	if (dsds > 1) {
		iocbs += (dsds - 1) / 5;
		if ((dsds - 1) % 5)
			iocbs++;
	}
	return iocbs;
}

/**
 * qla24xx_build_scsi_iocbs() - Build IOCB command utilizing Command Type 7
 * IOCB types.
 *
 * @sp: SRB command to process
 * @cmd_pkt: Command type 3 IOCB
 * @tot_dsds: Total number of segments to transfer
 */
static inline void
qla24xx_build_scsi_iocbs(srb_t *sp, struct cmd_type_7 *cmd_pkt,
    uint16_t tot_dsds)
{
	uint16_t	avail_dsds;
	uint32_t	*cur_dsd;
	scsi_qla_host_t	*ha;
	struct scsi_cmnd *cmd;

	cmd = sp->cmd;

	/* Update entry type to indicate Command Type 3 IOCB */
	*((uint32_t *)(&cmd_pkt->entry_type)) =
	    __constant_cpu_to_le32(COMMAND_TYPE_7);

	/* No data transfer */
	if (!scsi_bufflen(cmd) || cmd->sc_data_direction == DMA_NONE) {
		cmd_pkt->byte_count = __constant_cpu_to_le32(0);
		return;
	}

	ha = sp->ha;

	/* Set transfer direction */
	if (cmd->sc_data_direction == DMA_TO_DEVICE) {
		cmd_pkt->task_mgmt_flags =
		    __constant_cpu_to_le16(TMF_WRITE_DATA);
		ha->qla_stats.output_bytes += scsi_bufflen(cmd);
	} else if (cmd->sc_data_direction == DMA_FROM_DEVICE) {
		cmd_pkt->task_mgmt_flags =
		    __constant_cpu_to_le16(TMF_READ_DATA);
		ha->qla_stats.input_bytes += scsi_bufflen(cmd);
	}

	/* One DSD is available in the Command Type 3 IOCB */
	avail_dsds = 1;
	cur_dsd = (uint32_t *)&cmd_pkt->dseg_0_address;

	/* Load data segments */
	if (scsi_sg_count(cmd) != 0) {
		struct	scatterlist *cur_seg;
		struct	scatterlist *end_seg;

		cur_seg = scsi_sglist(cmd);
		end_seg = cur_seg + tot_dsds;
		while (cur_seg < end_seg) {
			dma_addr_t	sle_dma;
			cont_a64_entry_t *cont_pkt;

			/* Allocate additional continuation packets? */
			if (avail_dsds == 0) {
				/*
				 * Five DSDs are available in the Continuation
				 * Type 1 IOCB.
				 */
				cont_pkt = qla2x00_prep_cont_type1_iocb(ha);
				cur_dsd = (uint32_t *)cont_pkt->dseg_0_address;
				avail_dsds = 5;
			}

			sle_dma = sg_dma_address(cur_seg);
			*cur_dsd++ = cpu_to_le32(LSD(sle_dma));
			*cur_dsd++ = cpu_to_le32(MSD(sle_dma));
			*cur_dsd++ = cpu_to_le32(sg_dma_len(cur_seg));
			avail_dsds--;

			cur_seg++;
		}
	} else {
		*cur_dsd++ = cpu_to_le32(LSD(sp->dma_handle));
		*cur_dsd++ = cpu_to_le32(MSD(sp->dma_handle));
		*cur_dsd++ = cpu_to_le32(scsi_bufflen(cmd));
	}
}


/**
 * qla24xx_start_scsi() - Send a SCSI command to the ISP
 * @sp: command to send to the ISP
 *
 * Returns non-zero if a failure occured, else zero.
 */
int
qla24xx_start_scsi(srb_t *sp)
{
	int		ret;
	unsigned long   flags;
	scsi_qla_host_t	*ha;
	struct scsi_cmnd *cmd;
	uint32_t	*clr_ptr;
	uint32_t        index;
	uint32_t	handle;
	struct cmd_type_7 *cmd_pkt;
	struct scatterlist *sg;
	uint16_t	cnt;
	uint16_t	req_cnt;
	uint16_t	tot_dsds;
	struct device_reg_24xx __iomem *reg;
	char		tag[2];

	/* Setup device pointers. */
	ret = 0;
	ha = sp->ha;
	reg = &ha->iobase->isp24;
	cmd = sp->cmd;
	/* So we know we haven't pci_map'ed anything yet */
	tot_dsds = 0;

	/* Send marker if required */
	if (ha->marker_needed != 0) {
		if (qla2x00_marker(ha, 0, 0, MK_SYNC_ALL) != QLA_SUCCESS) {
			return QLA_FUNCTION_FAILED;
		}
		ha->marker_needed = 0;
	}

	/* Acquire ring specific lock */
	spin_lock_irqsave(&ha->hardware_lock, flags);

	/* Check for room in outstanding command list. */
	handle = ha->current_outstanding_cmd;
	for (index = 1; index < MAX_OUTSTANDING_COMMANDS; index++) {
		handle++;
		if (handle == MAX_OUTSTANDING_COMMANDS)
			handle = 1;
		if (!ha->outstanding_cmds[handle])
			break;
	}
	if (index == MAX_OUTSTANDING_COMMANDS)
		goto queuing_error;

	/* Map the sg table so we have an accurate count of sg entries needed */
	if (scsi_sg_count(cmd)) {
		sg = scsi_sglist(cmd);
		tot_dsds = pci_map_sg(ha->pdev, sg, scsi_sg_count(cmd),
		    cmd->sc_data_direction);
		if (tot_dsds == 0)
			goto queuing_error;
	} else if (scsi_bufflen(cmd)) {
		dma_addr_t      req_dma;

		req_dma = pci_map_single(ha->pdev, cmd->request_buffer,
		    scsi_bufflen(cmd), cmd->sc_data_direction);
		if (dma_mapping_error(req_dma))
			goto queuing_error;

		sp->dma_handle = req_dma;
		tot_dsds = 1;
	}

	req_cnt = qla24xx_calc_iocbs(tot_dsds);
	if (ha->req_q_cnt < (req_cnt + 2)) {
		cnt = (uint16_t)RD_REG_DWORD_RELAXED(&reg->req_q_out);
		if (ha->req_ring_index < cnt)
			ha->req_q_cnt = cnt - ha->req_ring_index;
		else
			ha->req_q_cnt = ha->request_q_length -
				(ha->req_ring_index - cnt);
	}
	if (ha->req_q_cnt < (req_cnt + 2))
		goto queuing_error;

	/* Build command packet. */
	ha->current_outstanding_cmd = handle;
	ha->outstanding_cmds[handle] = sp;
	sp->ha = ha;
	sp->cmd->host_scribble = (unsigned char *)(unsigned long)handle;
	ha->req_q_cnt -= req_cnt;

	cmd_pkt = (struct cmd_type_7 *)ha->request_ring_ptr;
	cmd_pkt->handle = handle;

	/* Zero out remaining portion of packet. */
	/*    tagged queuing modifier -- default is TSK_SIMPLE (0). */
	clr_ptr = (uint32_t *)cmd_pkt + 2;
	memset(clr_ptr, 0, REQUEST_ENTRY_SIZE - 8);
	cmd_pkt->dseg_count = cpu_to_le16(tot_dsds);

	/* Set NPORT-ID and LUN number*/
	cmd_pkt->nport_handle = cpu_to_le16(sp->fcport->loop_id);
	cmd_pkt->port_id[0] = sp->fcport->d_id.b.al_pa;
	cmd_pkt->port_id[1] = sp->fcport->d_id.b.area;
	cmd_pkt->port_id[2] = sp->fcport->d_id.b.domain;
	cmd_pkt->vp_index = sp->fcport->vp_idx;

	int_to_scsilun(sp->cmd->device->lun, &cmd_pkt->lun);
	host_to_fcp_swap((uint8_t *)&cmd_pkt->lun, sizeof(cmd_pkt->lun));

	/* Update tagged queuing modifier -- default is TSK_SIMPLE (0). */
	if (scsi_populate_tag_msg(cmd, tag)) {
		switch (tag[0]) {
		case HEAD_OF_QUEUE_TAG:
			cmd_pkt->task = TSK_HEAD_OF_QUEUE;
			break;
		case ORDERED_QUEUE_TAG:
			cmd_pkt->task = TSK_ORDERED;
			break;
		}
	}

	/* Load SCSI command packet. */
	memcpy(cmd_pkt->fcp_cdb, cmd->cmnd, cmd->cmd_len);
	host_to_fcp_swap(cmd_pkt->fcp_cdb, sizeof(cmd_pkt->fcp_cdb));

	cmd_pkt->byte_count = cpu_to_le32((uint32_t)scsi_bufflen(cmd));

	/* Build IOCB segments */
	qla24xx_build_scsi_iocbs(sp, cmd_pkt, tot_dsds);

	/* Set total data segment count. */
	cmd_pkt->entry_count = (uint8_t)req_cnt;
	wmb();

	/* Adjust ring index. */
	ha->req_ring_index++;
	if (ha->req_ring_index == ha->request_q_length) {
		ha->req_ring_index = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else
		ha->request_ring_ptr++;

	sp->flags |= SRB_DMA_VALID;

	/* Set chip new ring index. */
	WRT_REG_DWORD(&reg->req_q_in, ha->req_ring_index);
	RD_REG_DWORD_RELAXED(&reg->req_q_in);		/* PCI Posting. */

	/* Manage unprocessed RIO/ZIO commands in response queue. */
	if (ha->flags.process_response_queue &&
	    ha->response_ring_ptr->signature != RESPONSE_PROCESSED)
		qla24xx_process_response_queue(ha);

	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	return QLA_SUCCESS;

queuing_error:
	if (scsi_sg_count(cmd) && tot_dsds) {
		sg = scsi_sglist(cmd);
		pci_unmap_sg(ha->pdev, sg, scsi_sg_count(cmd),
		    cmd->sc_data_direction);
	} else if (tot_dsds) {
		pci_unmap_single(ha->pdev, sp->dma_handle,
		    scsi_bufflen(cmd), cmd->sc_data_direction);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return QLA_FUNCTION_FAILED;
}

static inline int
qla2xx_build_scsi_type_6_iocbs(srb_t *sp, struct cmd_type_6 *cmd_pkt,
    uint16_t tot_dsds)
{
	uint32_t	*cur_dsd = NULL;
	scsi_qla_host_t	*ha;
	struct scsi_cmnd *cmd;
	struct	scatterlist *cur_seg;
	uint32_t *dsd_seg;
	void *next_dsd;
	uint8_t avail_dsds;
	uint8_t first_iocb = 1;
	uint32_t dsd_list_len;
	struct dsd_dma *dsd_ptr;
	struct ct6_dsd *ctx;

	cmd = sp->cmd;

	*((uint32_t *)(&cmd_pkt->entry_type)) =
	    __constant_cpu_to_le32(COMMAND_TYPE_6);

	/* No data transfer */
	if (!scsi_bufflen(cmd) || cmd->sc_data_direction == DMA_NONE) {
		cmd_pkt->byte_count = __constant_cpu_to_le32(0);
		return 0;
	}

	ha = sp->ha;

	/* Set transfer direction */
	if (cmd->sc_data_direction == DMA_TO_DEVICE) {
		cmd_pkt->control_flags =
		    __constant_cpu_to_le16(CF_WRITE_DATA);
		ha->qla_stats.output_bytes += scsi_bufflen(cmd);
	} else if (cmd->sc_data_direction == DMA_FROM_DEVICE) {
		cmd_pkt->control_flags =
		    __constant_cpu_to_le16(CF_READ_DATA);
		ha->qla_stats.input_bytes += scsi_bufflen(cmd);
	}

	cur_seg = scsi_sglist(cmd);
	ctx = sp->ctx;

	while (tot_dsds) {
		avail_dsds = (tot_dsds > QLA_DSDS_PER_IOCB) ?
		    QLA_DSDS_PER_IOCB : tot_dsds;
		tot_dsds -= avail_dsds;
		dsd_list_len = (avail_dsds + 1) * QLA_DSD_SIZE;
		dsd_ptr = list_first_entry(&ha->gbl_dsd_list,
		    struct dsd_dma, list);
		next_dsd = dsd_ptr->dsd_addr;
		list_del(&dsd_ptr->list);
		ha->gbl_dsd_avail--;
		list_add_tail(&dsd_ptr->list, &ctx->dsd_list);

		ctx->dsd_use_cnt++;
		ha->gbl_dsd_inuse++;

		if (first_iocb) {
			first_iocb = 0;
			dsd_seg = (uint32_t *)&cmd_pkt->fcp_data_dseg_address;
			*dsd_seg++ = cpu_to_le32(LSD(dsd_ptr->dsd_list_dma));
			*dsd_seg++ = cpu_to_le32(MSD(dsd_ptr->dsd_list_dma));
			*dsd_seg++ = cpu_to_le32(dsd_list_len);
		} else {
			*cur_dsd++ = cpu_to_le32(LSD(dsd_ptr->dsd_list_dma));
			*cur_dsd++ = cpu_to_le32(MSD(dsd_ptr->dsd_list_dma));
			*cur_dsd++ = cpu_to_le32(dsd_list_len);
		}
		cur_dsd = (uint32_t *)next_dsd;
		while (avail_dsds) {
			dma_addr_t	sle_dma;

			sle_dma = sg_dma_address(cur_seg);
			*cur_dsd++ = cpu_to_le32(LSD(sle_dma));
			*cur_dsd++ = cpu_to_le32(MSD(sle_dma));
			*cur_dsd++ = cpu_to_le32(sg_dma_len(cur_seg));
			cur_seg++;
			avail_dsds--;
		}
	}

	/* Null termination */
	*cur_dsd++ =  0;
	*cur_dsd++ = 0;
	*cur_dsd++ = 0;
	cmd_pkt->control_flags |= CF_DATA_SEG_DESCR_ENABLE;
	return 0;
}

/*
 * qla82xx_calc_dsd_lists() - Determine number of DSD list required
 * for Command Type 6.
 *
 * @dsds: number of data segment descriptors needed
 *
 * Returns the number of dsd list needed to store @dsds.
 */
inline uint16_t
qla82xx_calc_dsd_lists(uint16_t dsds)
{
	uint16_t dsd_lists = 0;

	dsd_lists = dsds / QLA_DSDS_PER_IOCB;
	if (dsds % QLA_DSDS_PER_IOCB)
		dsd_lists++;
	return dsd_lists;
}


/**
 * qla82xx_start_scsi() - Send a SCSI command to the ISP
 * @sp: command to send to the ISP
 *
 * Returns non-zero if a failure occurred, else zero.
 */
int
qla82xx_start_scsi(srb_t *sp)
{
	int		ret;
	unsigned long   flags;
	scsi_qla_host_t	*ha;
	struct scsi_cmnd *cmd;
	uint32_t	*clr_ptr;
	uint32_t        index;
	uint32_t	handle;
	struct scatterlist *sg;
	uint16_t	cnt;
	uint16_t	req_cnt;
	uint16_t	tot_dsds;
	struct device_reg_82xx __iomem *reg;
	uint32_t dbval;
	uint32_t *fcp_dl;
	uint8_t additional_cdb_len;
	struct ct6_dsd *ctx;
	char		tag[2];

	/* Setup device pointers. */
	ret = 0;
	ha = sp->ha;
	reg = &ha->iobase->isp82;
	cmd = sp->cmd;
	/* So we know we haven't pci_map'ed anything yet */
	tot_dsds = 0;

	dbval = 0x04 | (ha->portnum << 5);

	/* Send marker if required */
	if (ha->marker_needed != 0) {
		if (qla2x00_marker(ha, 0, 0, MK_SYNC_ALL) != QLA_SUCCESS)
			return QLA_FUNCTION_FAILED;
		ha->marker_needed = 0;
	}

	/* Acquire ring specific lock */
	spin_lock_irqsave(&ha->hardware_lock, flags);

	/* Check for room in outstanding command list. */
	handle = ha->current_outstanding_cmd;
	for (index = 1; index < MAX_OUTSTANDING_COMMANDS; index++) {
		handle++;
		if (handle == MAX_OUTSTANDING_COMMANDS)
			handle = 1;
		if (!ha->outstanding_cmds[handle])
			break;
	}
	if (index == MAX_OUTSTANDING_COMMANDS)
		goto queuing_error;

	/* Map the sg table so we have an accurate count of sg entries needed */
	if (scsi_sg_count(cmd)) {
		sg = scsi_sglist(cmd);
		tot_dsds = pci_map_sg(ha->pdev, sg, scsi_sg_count(cmd),
		    cmd->sc_data_direction);
		if (tot_dsds == 0)
			goto queuing_error;
	} else if (scsi_bufflen(cmd)) {
		dma_addr_t      req_dma;

		req_dma = pci_map_single(ha->pdev, cmd->request_buffer,
		    scsi_bufflen(cmd), cmd->sc_data_direction);
		if (dma_mapping_error(req_dma))
			goto queuing_error;

		sp->dma_handle = req_dma;
		tot_dsds = 1;
	}

	if (tot_dsds > ql2xshiftctondsd) {
		struct cmd_type_6 *cmd_pkt;
		uint16_t more_dsd_lists = 0;
		struct dsd_dma *dsd_ptr;
		uint16_t i;

		more_dsd_lists = qla82xx_calc_dsd_lists(tot_dsds);

		if ((more_dsd_lists + ha->gbl_dsd_inuse) >= NUM_DSD_CHAIN)
			goto queuing_error;

		if (more_dsd_lists <= ha->gbl_dsd_avail)
			goto sufficient_dsds;
		else
			more_dsd_lists -= ha->gbl_dsd_avail;

		for (i = 0; i < more_dsd_lists; i++) {
			dsd_ptr = kzalloc(sizeof(struct dsd_dma), GFP_ATOMIC);
			if (!dsd_ptr)
				goto queuing_error;

			dsd_ptr->dsd_addr = dma_pool_alloc(ha->dl_dma_pool,
			    GFP_ATOMIC, &dsd_ptr->dsd_list_dma);
			if (!dsd_ptr->dsd_addr) {
				kfree(dsd_ptr);
				goto queuing_error;
			}
			list_add_tail(&dsd_ptr->list, &ha->gbl_dsd_list);
			ha->gbl_dsd_avail++;
		}

sufficient_dsds:
		req_cnt = 1;
		if (ha->req_q_cnt < (req_cnt + 2)) {
			cnt = (uint16_t)RD_REG_DWORD_RELAXED(
					&reg->req_q_out[0]);
			if (ha->req_ring_index < cnt)
				ha->req_q_cnt = cnt - ha->req_ring_index;
			else
				ha->req_q_cnt = ha->request_q_length -
					(ha->req_ring_index - cnt);
		}
		if (ha->req_q_cnt < (req_cnt + 2))
			goto queuing_error;

		ctx = sp->ctx = mempool_alloc(ha->ctx_mempool, GFP_ATOMIC);
		if (!sp->ctx) {
			DEBUG2_3(qla_printk(KERN_ERR, ha,
			    "%s(%ld): failed to allocate ctx.\n", __func__,
			    ha->host_no));
			goto queuing_error;
		}
		memset(ctx, 0, sizeof(struct ct6_dsd));
		ctx->fcp_cmnd = dma_pool_alloc(ha->fcp_cmnd_dma_pool,
			    GFP_ATOMIC, &ctx->fcp_cmnd_dma);
		if (!ctx->fcp_cmnd) {
			DEBUG2_3(qla_printk(KERN_ERR, ha,
			    "%s(%ld): failed to allocate"
			    " fcp_cmnd.\n", __func__, ha->host_no));
			goto queuing_error;
		}

		/* Initialize the DSD list and dma handle */
		INIT_LIST_HEAD(&ctx->dsd_list);
		sp->dma_handle = 0;
		ctx->dsd_use_cnt = 0;

		if (cmd->cmd_len > 16) {
			additional_cdb_len = cmd->cmd_len - 16;
			if ((cmd->cmd_len % 4) != 0) {
				/* SCSI command bigger than 16 bytes must be
				 * multiple of 4
				 */
				goto queuing_error_fcp_cmnd;
			}
			ctx->fcp_cmnd_len = 12 + cmd->cmd_len + 4;
		} else {
			additional_cdb_len = 0;
			ctx->fcp_cmnd_len = 12 + 16 + 4;
		}

		cmd_pkt = (struct cmd_type_6 *)ha->request_ring_ptr;

		/* Zero out remaining portion of packet. */
		/*    tagged queuing modifier -- default is TSK_SIMPLE (0). */
		clr_ptr = (uint32_t *)cmd_pkt + 2;
		memset(clr_ptr, 0, REQUEST_ENTRY_SIZE - 8);
		cmd_pkt->dseg_count = cpu_to_le16(tot_dsds);
		cmd_pkt->handle = handle;

		/* Build IOCB segments */
		if (qla2xx_build_scsi_type_6_iocbs(sp, cmd_pkt, tot_dsds))
			goto queuing_error_fcp_cmnd;

		int_to_scsilun(sp->cmd->device->lun, &cmd_pkt->lun);

		/* build FCP_CMND IU */
		memset(ctx->fcp_cmnd, 0, sizeof(struct fcp_cmnd));
		int_to_scsilun(sp->cmd->device->lun, &ctx->fcp_cmnd->lun);
		ctx->fcp_cmnd->additional_cdb_len = additional_cdb_len;

		if (cmd->sc_data_direction == DMA_TO_DEVICE)
			ctx->fcp_cmnd->additional_cdb_len |= 1;
		else if (cmd->sc_data_direction == DMA_FROM_DEVICE)
			ctx->fcp_cmnd->additional_cdb_len |= 2;

		/*
		 * Update tagged queuing modifier -- default is TSK_SIMPLE (0).
		 */
		if (scsi_populate_tag_msg(cmd, tag)) {
			switch (tag[0]) {
			case HEAD_OF_QUEUE_TAG:
				ctx->fcp_cmnd->task_attribute =
				    TSK_HEAD_OF_QUEUE;
				break;
			case ORDERED_QUEUE_TAG:
				ctx->fcp_cmnd->task_attribute =
				    TSK_ORDERED;
				break;
			}
		}

		memcpy(ctx->fcp_cmnd->cdb, cmd->cmnd, cmd->cmd_len);

		fcp_dl = (uint32_t *)(ctx->fcp_cmnd->cdb + 16 +
		    additional_cdb_len);
		*fcp_dl = htonl((uint32_t)scsi_bufflen(cmd));

		cmd_pkt->fcp_cmnd_dseg_len = cpu_to_le16(ctx->fcp_cmnd_len);
		cmd_pkt->fcp_cmnd_dseg_address[0] =
		    cpu_to_le32(LSD(ctx->fcp_cmnd_dma));
		cmd_pkt->fcp_cmnd_dseg_address[1] =
		    cpu_to_le32(MSD(ctx->fcp_cmnd_dma));

		sp->flags |= SRB_FCP_CMND_DMA_VALID;
		cmd_pkt->byte_count = cpu_to_le32((uint32_t)scsi_bufflen(cmd));

		/* Set NPORT-ID and LUN number*/
		cmd_pkt->nport_handle = cpu_to_le16(sp->fcport->loop_id);
		cmd_pkt->port_id[0] = sp->fcport->d_id.b.al_pa;
		cmd_pkt->port_id[1] = sp->fcport->d_id.b.area;
		cmd_pkt->port_id[2] = sp->fcport->d_id.b.domain;
		cmd_pkt->vp_index = sp->fcport->vp_idx;

		/* Set total data segment count. */
		cmd_pkt->entry_count = (uint8_t)req_cnt;
#ifdef QL_DEBUG_LEVEL_3
		{
			int i;
			uint16_t *ptr = (struct cmd_type_6 *)cmd_pkt;
			printk(KERN_INFO "Dump Command type 6 IOCB\n");
			for (i = 0; i < sizeof(struct cmd_type_6)/2; i++) {
				printk(KERN_INFO
				    "CT6-IOCB[%x]: 0x%x\n", (i*2), *ptr);
				ptr++;
			}
		}
#endif
	} else {
		struct cmd_type_7 *cmd_pkt;
		req_cnt = qla24xx_calc_iocbs(tot_dsds);
		if (ha->req_q_cnt < (req_cnt + 2)) {
			cnt = (uint16_t)RD_REG_DWORD_RELAXED(
			    &reg->req_q_out[0]);
			if (ha->req_ring_index < cnt)
				ha->req_q_cnt = cnt - ha->req_ring_index;
			else
				ha->req_q_cnt = ha->request_q_length -
					(ha->req_ring_index - cnt);
		}
		if (ha->req_q_cnt < (req_cnt + 2))
			goto queuing_error;

		cmd_pkt = (struct cmd_type_7 *)ha->request_ring_ptr;

		/* Zero out remaining portion of packet. */
		/* tagged queuing modifier -- default is TSK_SIMPLE (0).*/
		clr_ptr = (uint32_t *)cmd_pkt + 2;
		memset(clr_ptr, 0, REQUEST_ENTRY_SIZE - 8);
		cmd_pkt->dseg_count = cpu_to_le16(tot_dsds);
		cmd_pkt->handle = handle;

		int_to_scsilun(sp->cmd->device->lun, &cmd_pkt->lun);
		host_to_fcp_swap((uint8_t *)&cmd_pkt->lun,
		    sizeof(cmd_pkt->lun));

		/*
		 * Update tagged queuing modifier -- default is TSK_SIMPLE (0).
		 */
		if (scsi_populate_tag_msg(cmd, tag)) {
			switch (tag[0]) {
			case HEAD_OF_QUEUE_TAG:
				cmd_pkt->task = TSK_HEAD_OF_QUEUE;
				break;
			case ORDERED_QUEUE_TAG:
				cmd_pkt->task = TSK_ORDERED;
				break;
			}
		}

		/* Load SCSI command packet. */
		memcpy(cmd_pkt->fcp_cdb, cmd->cmnd, cmd->cmd_len);
		host_to_fcp_swap(cmd_pkt->fcp_cdb, sizeof(cmd_pkt->fcp_cdb));

		cmd_pkt->byte_count = cpu_to_le32((uint32_t)scsi_bufflen(cmd));

		/* Build IOCB segments */
		qla24xx_build_scsi_iocbs(sp, cmd_pkt, tot_dsds);

		/* Set NPORT-ID and LUN number*/
		cmd_pkt->nport_handle = cpu_to_le16(sp->fcport->loop_id);
		cmd_pkt->port_id[0] = sp->fcport->d_id.b.al_pa;
		cmd_pkt->port_id[1] = sp->fcport->d_id.b.area;
		cmd_pkt->port_id[2] = sp->fcport->d_id.b.domain;
		cmd_pkt->vp_index = sp->fcport->vp_idx;

		/* Set total data segment count. */
		cmd_pkt->entry_count = (uint8_t)req_cnt;
#ifdef QL_DEBUG_LEVEL_3
		{
			int i;
			uint16_t *ptr = (struct cmd_type_7 *)cmd_pkt;
			printk(KERN_INFO "Dump Command type 7 IOCB\n");
			for (i = 0; i < sizeof(struct cmd_type_7)/2; i++) {
				printk(KERN_INFO
				    "CT7-IOCB[%x]: 0x%x\n", (i * 2), *ptr);
				ptr++;
			}
		}
#endif
	}

	/* Build command packet. */
	ha->current_outstanding_cmd = handle;
	ha->outstanding_cmds[handle] = sp;
	sp->ha = ha;
	sp->cmd->host_scribble = (unsigned char *)(unsigned long)handle;
	ha->req_q_cnt -= req_cnt;
	wmb();

	/* Adjust ring index. */
	ha->req_ring_index++;
	if (ha->req_ring_index == ha->request_q_length) {
		ha->req_ring_index = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else
		ha->request_ring_ptr++;

	sp->flags |= SRB_DMA_VALID;

	/* Set chip new ring index. */
	/* write, read and verify logic */
	/* dbval = dbval | (req->id << 8) | (ha->ring_index << 16); */
	/* TODO - hardcoded the request queue ID to 0 -
	 * Need to pass proper value
	 */
	dbval = dbval | (0 << 8) | (ha->req_ring_index << 16);
	if (ql2xdbwr)
		qla82xx_wr_32(ha, ha->nxdb_wr_ptr, dbval);
	else {
		WRT_REG_DWORD((unsigned long __iomem *)ha->nxdb_wr_ptr, dbval);
		wmb();
		while (RD_REG_DWORD(ha->nxdb_rd_ptr) != dbval) {
			WRT_REG_DWORD((unsigned long  __iomem *)ha->nxdb_wr_ptr,
			    dbval);
			wmb();
		}
	}

	/* Manage unprocessed RIO/ZIO commands in response queue. */
	if (ha->flags.process_response_queue &&
	    ha->response_ring_ptr->signature != RESPONSE_PROCESSED)
		qla24xx_process_response_queue(ha);

	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	return QLA_SUCCESS;

queuing_error_fcp_cmnd:
	dma_pool_free(ha->fcp_cmnd_dma_pool, ctx->fcp_cmnd, ctx->fcp_cmnd_dma);
queuing_error:
	if (scsi_sg_count(cmd) && tot_dsds) {
		sg = scsi_sglist(cmd);
		pci_unmap_sg(ha->pdev, sg, scsi_sg_count(cmd),
		    cmd->sc_data_direction);
	} else if (tot_dsds) {
		pci_unmap_single(ha->pdev, sp->dma_handle,
		    scsi_bufflen(cmd), cmd->sc_data_direction);
	}
	if (sp->ctx) {
		mempool_free(sp->ctx, ha->ctx_mempool);
		sp->ctx = NULL;
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return QLA_FUNCTION_FAILED;
}
