/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"

#include <linux/vmalloc.h>

static ssize_t qla24xx_vport_disable(struct class_device *, const char *, size_t);

/* SYSFS attributes --------------------------------------------------------- */

static ssize_t
qla2x00_sysfs_read_fw_dump(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	char *rbuf = (char *)ha->fw_dump;

	if (ha->fw_dump_reading == 0)
		return 0;
	if (off > ha->fw_dump_len)
                return 0;
	if (off + count > ha->fw_dump_len)
		count = ha->fw_dump_len - off;

	memcpy(buf, &rbuf[off], count);

	return (count);
}

static ssize_t
qla2x00_sysfs_write_fw_dump(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	int reading;

	if (off != 0)
		return (0);

	reading = simple_strtol(buf, NULL, 10);
	switch (reading) {
	case 0:
		if (!ha->fw_dump_reading)
			break;

		qla_printk(KERN_INFO, ha,
		    "Firmware dump cleared on (%ld).\n", ha->host_no);

		ha->fw_dump_reading = 0;
		ha->fw_dumped = 0;
		break;
	case 1:
		if (ha->fw_dumped && !ha->fw_dump_reading) {
			ha->fw_dump_reading = 1;

			qla_printk(KERN_INFO, ha,
			    "Raw firmware dump ready for read on (%ld).\n",
			    ha->host_no);
		}
		break;
	case 2:
		qla2x00_alloc_fw_dump(ha);
		break;
	case 3:
		qla2x00_system_error(ha);
		break;
	}
	return (count);
}

static struct bin_attribute sysfs_fw_dump_attr = {
	.attr = {
		.name = "fw_dump",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 0,
	.read = qla2x00_sysfs_read_fw_dump,
	.write = qla2x00_sysfs_write_fw_dump,
};

static ssize_t
qla2x00_sysfs_read_nvram(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	int		size = ha->nvram_size;
	char		*nvram_cache = ha->nvram;

	if (!capable(CAP_SYS_ADMIN) || off > size || count == 0)
		return 0;
	if (off + count > size) {
		size -= off;
		count = size;
	}

	/* Read NVRAM data from cache. */
	memcpy(buf, &nvram_cache[off], count);

	return count;
}

static ssize_t
qla2x00_sysfs_write_nvram(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	uint16_t	cnt;

	if (!capable(CAP_SYS_ADMIN) || off != 0 || count != ha->nvram_size)
		return 0;

	/* Checksum NVRAM. */
	if (IS_FWI2_CAPABLE(ha)) {
		uint32_t *iter;
		uint32_t chksum;

		iter = (uint32_t *)buf;
		chksum = 0;
		for (cnt = 0; cnt < ((count >> 2) - 1); cnt++)
			chksum += le32_to_cpu(*iter++);
		chksum = ~chksum + 1;
		*iter = cpu_to_le32(chksum);
	} else {
		uint8_t *iter;
		uint8_t chksum;

		iter = (uint8_t *)buf;
		chksum = 0;
		for (cnt = 0; cnt < count - 1; cnt++)
			chksum += *iter++;
		chksum = ~chksum + 1;
		*iter = chksum;
	}

	/* Write NVRAM. */
	ha->isp_ops->write_nvram(ha, (uint8_t *)buf, ha->nvram_base, count);
	ha->isp_ops->read_nvram(ha, (uint8_t *)ha->nvram, ha->nvram_base,
	    count);

	set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);

	return (count);
}

static struct bin_attribute sysfs_nvram_attr = {
	.attr = {
		.name = "nvram",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 512,
	.read = qla2x00_sysfs_read_nvram,
	.write = qla2x00_sysfs_write_nvram,
};

static ssize_t
qla2x00_sysfs_read_optrom(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));

	if (ha->optrom_state != QLA_SREADING)
		return 0;
	if (off > ha->optrom_region_size)
		return 0;
	if (off + count > ha->optrom_region_size)
		count = ha->optrom_region_size - off;

	memcpy(buf, &ha->optrom_buffer[off], count);

	return count;
}

static ssize_t
qla2x00_sysfs_write_optrom(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));

	if (ha->optrom_state != QLA_SWRITING)
		return -EINVAL;
	if (off > ha->optrom_region_size)
		return -ERANGE;
	if (off + count > ha->optrom_region_size)
		count = ha->optrom_region_size - off;

	memcpy(&ha->optrom_buffer[off], buf, count);

	return count;
}

static struct bin_attribute sysfs_optrom_attr = {
	.attr = {
		.name = "optrom",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 0,
	.read = qla2x00_sysfs_read_optrom,
	.write = qla2x00_sysfs_write_optrom,
};

static ssize_t
qla2x00_sysfs_write_optrom_ctl(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	uint32_t start = 0;
	uint32_t size = ha->optrom_size;
	int val, valid;

	if (off)
		return 0;

	if (sscanf(buf, "%d:%x:%x", &val, &start, &size) < 1)
		return -EINVAL;
	if (start > ha->optrom_size)
		return -EINVAL;

	switch (val) {
	case 0:
		if (ha->optrom_state != QLA_SREADING &&
		    ha->optrom_state != QLA_SWRITING)
			break;

		ha->optrom_state = QLA_SWAITING;

		DEBUG2(qla_printk(KERN_INFO, ha,
		    "Freeing flash region allocation -- 0x%x bytes.\n",
		    ha->optrom_region_size));

		vfree(ha->optrom_buffer);
		ha->optrom_buffer = NULL;
		break;
	case 1:
		if (ha->optrom_state != QLA_SWAITING)
			break;

		if (start & 0xfff) {
			qla_printk(KERN_WARNING, ha,
			    "Invalid start region 0x%x/0x%x.\n", start, size);
			return -EINVAL;
		}

		ha->optrom_region_start = start;
		ha->optrom_region_size = start + size > ha->optrom_size ?
		    ha->optrom_size - start : size;

		ha->optrom_state = QLA_SREADING;
		ha->optrom_buffer = vmalloc(ha->optrom_region_size);
		if (ha->optrom_buffer == NULL) {
			qla_printk(KERN_WARNING, ha,
			    "Unable to allocate memory for optrom retrieval "
			    "(%x).\n", ha->optrom_region_size);

			ha->optrom_state = QLA_SWAITING;
			return count;
		}

		DEBUG2(qla_printk(KERN_INFO, ha,
		    "Reading flash region -- 0x%x/0x%x.\n",
		    ha->optrom_region_start, ha->optrom_region_size));

		memset(ha->optrom_buffer, 0, ha->optrom_region_size);
		ha->isp_ops->read_optrom(ha, ha->optrom_buffer,
		    ha->optrom_region_start, ha->optrom_region_size);
		break;
	case 2:
		if (ha->optrom_state != QLA_SWAITING)
			break;

		/*
		 * We need to be more restrictive on which FLASH regions are
		 * allowed to be updated via user-space.  Regions accessible
		 * via this method include:
		 *
		 * ISP21xx/ISP22xx/ISP23xx type boards:
		 *
		 * 	0x000000 -> 0x020000 -- Boot code.
		 *
		 * ISP2322/ISP24xx type boards:
		 *
		 * 	0x000000 -> 0x07ffff -- Boot code.
		 * 	0x080000 -> 0x0fffff -- Firmware.
		 *
		 * ISP25xx type boards:
		 *
		 * 	0x000000 -> 0x07ffff -- Boot code.
		 * 	0x080000 -> 0x0fffff -- Firmware.
		 * 	0x120000 -> 0x12ffff -- VPD and HBA parameters.
		 */
		valid = 0;
		if (ha->optrom_size == OPTROM_SIZE_2300 && start == 0)
			valid = 1;
		else if (start == (ha->flt_region_boot * 4) ||
		    start == (ha->flt_region_fw * 4))
			valid = 1;
		else if (IS_QLA25XX(ha) &&
		    start == (ha->flt_region_vpd_nvram * 4))
		    valid = 1;
		if (!valid) {
			qla_printk(KERN_WARNING, ha,
			    "Invalid start region 0x%x/0x%x.\n", start, size);
			return -EINVAL;
		}

		ha->optrom_region_start = start;
		ha->optrom_region_size = start + size > ha->optrom_size ?
		    ha->optrom_size - start : size;

		ha->optrom_state = QLA_SWRITING;
		ha->optrom_buffer = vmalloc(ha->optrom_region_size);
		if (ha->optrom_buffer == NULL) {
			qla_printk(KERN_WARNING, ha,
			    "Unable to allocate memory for optrom update "
			    "(%x).\n", ha->optrom_region_size);

			ha->optrom_state = QLA_SWAITING;
			return count;
		}

		DEBUG2(qla_printk(KERN_INFO, ha,
		    "Staging flash region write -- 0x%x/0x%x.\n",
		    ha->optrom_region_start, ha->optrom_region_size));

		memset(ha->optrom_buffer, 0, ha->optrom_region_size);
		break;
	case 3:
		if (ha->optrom_state != QLA_SWRITING)
			break;

		DEBUG2(qla_printk(KERN_INFO, ha,
		    "Writing flash region -- 0x%x/0x%x.\n",
		    ha->optrom_region_start, ha->optrom_region_size));

		ha->isp_ops->write_optrom(ha, ha->optrom_buffer,
		    ha->optrom_region_start, ha->optrom_region_size);
		break;
	default:
		count = -EINVAL;
	}
	return count;
}

static struct bin_attribute sysfs_optrom_ctl_attr = {
	.attr = {
		.name = "optrom_ctl",
		.mode = S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 0,
	.write = qla2x00_sysfs_write_optrom_ctl,
};

static ssize_t
qla2x00_sysfs_read_vpd(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	int           size = ha->vpd_size;
	char          *vpd_cache = ha->vpd;

	if (!capable(CAP_SYS_ADMIN) || off > size || count == 0)
		return 0;
	if (off + count > size) {
		size -= off;
		count = size;
	}

	/* Read NVRAM data from cache. */
	memcpy(buf, &vpd_cache[off], count);

	return count;
}

static ssize_t
qla2x00_sysfs_write_vpd(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));

	if (!capable(CAP_SYS_ADMIN) || off != 0 || count != ha->vpd_size)
		return 0;

	/* Write NVRAM. */
	ha->isp_ops->write_nvram(ha, (uint8_t *)buf, ha->vpd_base, count);
	ha->isp_ops->read_nvram(ha, (uint8_t *)ha->vpd, ha->vpd_base, count);

	return count;
}

static struct bin_attribute sysfs_vpd_attr = {
	.attr = {
		.name = "vpd",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 0,
	.read = qla2x00_sysfs_read_vpd,
	.write = qla2x00_sysfs_write_vpd,
};

static ssize_t
qla2x00_sysfs_read_sfp(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	uint16_t iter, addr, offset;
	int rval;

	if (!capable(CAP_SYS_ADMIN) || off != 0 || count != SFP_DEV_SIZE * 2)
		return 0;

	addr = 0xa0;
	for (iter = 0, offset = 0; iter < (SFP_DEV_SIZE * 2) / SFP_BLOCK_SIZE;
	    iter++, offset += SFP_BLOCK_SIZE) {
		if (iter == 4) {
			/* Skip to next device address. */
			addr = 0xa2;
			offset = 0;
		}

		rval = qla2x00_read_sfp(ha, ha->sfp_data_dma, addr, offset,
		    SFP_BLOCK_SIZE);
		if (rval != QLA_SUCCESS) {
			qla_printk(KERN_WARNING, ha,
			    "Unable to read SFP data (%x/%x/%x).\n", rval,
			    addr, offset);
			count = 0;
			break;
		}
		memcpy(buf, ha->sfp_data, SFP_BLOCK_SIZE);
		buf += SFP_BLOCK_SIZE;
	}

	return count;
}

static struct bin_attribute sysfs_sfp_attr = {
	.attr = {
		.name = "sfp",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = SFP_DEV_SIZE * 2,
	.read = qla2x00_sysfs_read_sfp,
};

static fc_port_t *
qla2x00_find_port(struct scsi_qla_host *ha, uint8_t *pn)
{
	fc_port_t *fcport;

	list_for_each_entry(fcport, &ha->fcports, list)
		if (!memcmp(pn, fcport->port_name, sizeof(fcport->port_name)))
			return fcport;

	return NULL;
}

static void
qla2x00_wait_for_passthru_completion(struct scsi_qla_host *ha)
{
	if (wait_for_completion_timeout(&ha->pass_thru_intr_comp, 10 * HZ))
		qla_printk(KERN_INFO, ha, "Passthru request completed.\n");
	else {
		qla_printk(KERN_WARNING, ha, "Passthru request timed out.\n");
		ha->isp_ops->fw_dump(ha, 0);
	}
}

static ssize_t
qla2x00_sysfs_read_els(struct kobject *kobj, char *buf, loff_t off, 
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(
	    container_of(kobj, struct device, kobj)));

	if (!ha->pass_thru_cmd_in_process || !ha->pass_thru_cmd_result) {
		qla_printk(KERN_WARNING, ha,
		    "Passthru ELS response is not available.\n");
		return 0;
	}

	memcpy(buf, ha->pass_thru, count);

	qla_printk(KERN_INFO, ha, "Passthru ELS response %X:\n", 
	    ((ct_iu_t *)buf)->command);
	qla2x00_print_byte_buf(buf, min(count, (size_t)64), 16);

	ha->pass_thru_cmd_result = 0;
	ha->pass_thru_cmd_in_process = 0;

	return count;
}

static ssize_t
qla2x00_sysfs_write_els(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(
	    container_of(kobj, struct device, kobj)));
	els_request_t *request = (void *)buf;
	struct els_entry_24xx *els_iocb;
	unsigned long flags;
	uint16_t nextlid = 0;
	fc_port_t *fcport;

	count -= sizeof(request->header);

	if (count < sizeof(request->ct_iu)) {
		qla_printk(KERN_WARNING, ha,
		    "Passthru ELS buffer insufficient size %d...\n",
                    (int)count);
		goto els_error0;
	}

	if (ha->pass_thru_cmd_in_process || ha->pass_thru_cmd_result) {
		qla_printk(KERN_WARNING, ha,
		    "Passthru ELS request is already progress\n");
		goto els_error0;
	}

	fcport = qla2x00_find_port(ha, request->header.WWPN);
	if (!fcport) {
		qla_printk(KERN_WARNING, ha,
		    "Passthru ELS request failed find port\n");
		goto els_error0;
	}

	if (qla2x00_fabric_login(ha, fcport, &nextlid)) {
		qla_printk(KERN_WARNING, ha,
		    "Passthru ELS request failed to login port %06X\n",
		    fcport->d_id.b24);
		goto els_error0;
	}

	ha->pass_thru_cmd_in_process = 1;
	spin_lock_irqsave(&ha->hardware_lock, flags);

	els_iocb = (void *)qla2x00_req_pkt(ha);
	if (els_iocb == NULL) {
		qla_printk(KERN_WARNING, ha,
		    "Passthru ELS request failed to get request packet\n");
		goto els_error1;
	}

	if (count > PAGE_SIZE) {
		qla_printk(KERN_INFO, ha,
		    "Passthru ELS request excessive size %d...\n",
                    (int)count);
		count = PAGE_SIZE;
	}

	memset(ha->pass_thru, 0, PAGE_SIZE);
	memcpy(ha->pass_thru, &request->ct_iu, count);

	els_iocb->entry_type = ELS_IOCB_TYPE;
	els_iocb->entry_count = 1;
	els_iocb->sys_define = 0;
	els_iocb->entry_status = 0;
	els_iocb->nport_handle = cpu_to_le16(fcport->loop_id);
	els_iocb->tx_dsd_count = __constant_cpu_to_le16(1);
	els_iocb->vp_index = ha->vp_idx;
	els_iocb->sof_type = EST_SOFI3;
	els_iocb->rx_dsd_count = __constant_cpu_to_le16(1);
	els_iocb->opcode = 0;
	els_iocb->port_id[0] = fcport->d_id.b.al_pa;
	els_iocb->port_id[1] = fcport->d_id.b.area;
	els_iocb->port_id[2] = fcport->d_id.b.domain;
	els_iocb->control_flags = __constant_cpu_to_le16(0);
	els_iocb->rx_byte_count = cpu_to_le32(PAGE_SIZE);
	els_iocb->tx_byte_count = cpu_to_le32(count);
	els_iocb->tx_address[0] = cpu_to_le32(LSD(ha->pass_thru_dma));
	els_iocb->tx_address[1] = cpu_to_le32(MSD(ha->pass_thru_dma));
	els_iocb->tx_len = els_iocb->tx_byte_count;
	els_iocb->rx_address[0] = cpu_to_le32(LSD(ha->pass_thru_dma));
	els_iocb->rx_address[1] = cpu_to_le32(MSD(ha->pass_thru_dma));
	els_iocb->rx_len = els_iocb->rx_byte_count;

	qla_printk(KERN_INFO, ha, "Passthru ELS request:\n");
	qla2x00_print_byte_buf(ha->pass_thru, min(count, (size_t)32), 16);

	qla_printk(KERN_INFO, ha, "Passthru ELS IOCB:\n");
	qla2x00_print_word_buf(els_iocb, sizeof(*els_iocb), 8);

	wmb();
	qla2x00_isp_cmd(ha);

	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	qla2x00_wait_for_passthru_completion(ha);

	return count;

els_error1:
	ha->pass_thru_cmd_in_process = 0;
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
els_error0:
	qla_printk(KERN_WARNING, ha, "Passthru ELS failed\n");
	return 0;
}

static struct bin_attribute sysfs_els_attr = {
	.attr = {
		.name = "els",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 0,
	.read = qla2x00_sysfs_read_els,
	.write = qla2x00_sysfs_write_els,
};

static ssize_t
qla2x00_sysfs_read_ct(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(
	    container_of(kobj, struct device, kobj)));

	if (!ha->pass_thru_cmd_in_process || !ha->pass_thru_cmd_result) {
		qla_printk(KERN_WARNING, ha,
		    "Passthru CT response is not available.\n");
		return 0;
	}

	memcpy(buf, ha->pass_thru, count);

	qla_printk(KERN_INFO, ha, "Passthru CT response %X:\n", 
	    ((ct_iu_t *)buf)->command);
	qla2x00_print_byte_buf(buf, min(count, (size_t)64), 16);

	ha->pass_thru_cmd_result = 0;
	ha->pass_thru_cmd_in_process = 0;

	return count;
}

static ssize_t
qla2x00_sysfs_write_ct(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(
	    container_of(kobj, struct device, kobj)));
	fc_ct_request_t *request = (void *)buf;
	struct ct_entry_24xx *ct_iocb;
	unsigned long flags;

	if (count < sizeof(request->ct_iu)) {
		qla_printk(KERN_WARNING, ha,
		    "Passthru CT buffer insufficient size %d...\n",
                    (int)count);
		goto ct_error0;
	}

	if (ha->pass_thru_cmd_in_process || ha->pass_thru_cmd_result) {
		qla_printk(KERN_WARNING, ha,
		    "Passthru CT request is already progress\n");
		goto ct_error0;
	}

	if (qla2x00_mgmt_svr_login(ha)) {
		qla_printk(KERN_WARNING, ha,
		    "Passthru CT request failed to login management server\n");
		goto ct_error0;
	}

	ha->pass_thru_cmd_in_process = 1;
	spin_lock_irqsave(&ha->hardware_lock, flags);

	ct_iocb = (void *)qla2x00_req_pkt(ha);
	if (ct_iocb == NULL) {
		qla_printk(KERN_WARNING, ha,
		    "Passthru CT request failed to get request packet\n");
		goto ct_error1;
	}

	if (count > PAGE_SIZE) {
		qla_printk(KERN_INFO, ha,
		    "Passthru CT request excessive size %d...\n",
		    (int)count);
		count = PAGE_SIZE;
	}

	memset(ha->pass_thru, 0, PAGE_SIZE);
	memcpy(ha->pass_thru, &request->ct_iu, count);

	ct_iocb->entry_type = CT_IOCB_TYPE;
	ct_iocb->entry_count = 1;
	ct_iocb->entry_status = 0;
	ct_iocb->comp_status = __constant_cpu_to_le16(0);
	ct_iocb->nport_handle = cpu_to_le16(ha->mgmt_svr_loop_id);
	ct_iocb->cmd_dsd_count = __constant_cpu_to_le16(1);
	ct_iocb->vp_index = ha->vp_idx;
	ct_iocb->timeout = __constant_cpu_to_le16(25);
	ct_iocb->rsp_dsd_count = __constant_cpu_to_le16(1);
	ct_iocb->rsp_byte_count = cpu_to_le32(PAGE_SIZE);
	ct_iocb->cmd_byte_count = cpu_to_le32(count);
	ct_iocb->dseg_0_address[0] = cpu_to_le32(LSD(ha->pass_thru_dma));
	ct_iocb->dseg_0_address[1] = cpu_to_le32(MSD(ha->pass_thru_dma));
	ct_iocb->dseg_0_len = ct_iocb->cmd_byte_count;
	ct_iocb->dseg_1_address[0] = cpu_to_le32(LSD(ha->pass_thru_dma));
	ct_iocb->dseg_1_address[1] = cpu_to_le32(MSD(ha->pass_thru_dma));
	ct_iocb->dseg_1_len = ct_iocb->rsp_byte_count;

	qla_printk(KERN_INFO, ha, "Passthru CT request:\n");
	qla2x00_print_byte_buf(ha->pass_thru, min(count, (size_t)32), 16);

	qla_printk(KERN_INFO, ha, "Passthru CT IOCB:\n");
	qla2x00_print_word_buf(ct_iocb, sizeof(*ct_iocb), 8);

	wmb();
	qla2x00_isp_cmd(ha);

	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	qla2x00_wait_for_passthru_completion(ha);

	return count;

ct_error1:
	ha->pass_thru_cmd_in_process = 0;
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
ct_error0:
	qla_printk(KERN_WARNING, ha, "Passthru CT failed\n");
	return 0;
}

static struct bin_attribute sysfs_ct_attr = {
	.attr = {
		.name = "ct",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 0,
	.read = qla2x00_sysfs_read_ct,
	.write = qla2x00_sysfs_write_ct,
};

static struct sysfs_entry {
	char *name;
	struct bin_attribute *attr;
	int is4GBp_only;
} bin_file_entries[] = {
	{ "fw_dump", &sysfs_fw_dump_attr, },
	{ "nvram", &sysfs_nvram_attr, },
	{ "optrom", &sysfs_optrom_attr, },
	{ "optrom_ctl", &sysfs_optrom_ctl_attr, },
	{ "vpd", &sysfs_vpd_attr, 1 },
	{ "sfp", &sysfs_sfp_attr, 1 },
	{ "els", &sysfs_els_attr, 1 },
	{ "ct", &sysfs_ct_attr, 1 },
	{ NULL },
};

void
qla2x00_alloc_sysfs_attr(scsi_qla_host_t *ha)
{
	struct Scsi_Host *host = ha->host;
	struct sysfs_entry *iter;
	int ret;

	for (iter = bin_file_entries; iter->name; iter++) {
		if (iter->is4GBp_only && !IS_FWI2_CAPABLE(ha))
			continue;

		ret = sysfs_create_bin_file(&host->shost_gendev.kobj,
		    iter->attr);
		if (ret)
			qla_printk(KERN_INFO, ha,
			    "Unable to create sysfs %s binary attribute "
			    "(%d).\n", iter->name, ret);
	}
}

void
qla2x00_free_sysfs_attr(scsi_qla_host_t *ha)
{
	struct Scsi_Host *host = ha->host;
	struct sysfs_entry *iter;

	for (iter = bin_file_entries; iter->name; iter++) {
		if (iter->is4GBp_only && !IS_FWI2_CAPABLE(ha))
			continue;

		sysfs_remove_bin_file(&host->shost_gendev.kobj,
		    iter->attr);
	}

	if (ha->beacon_blink_led == 1)
		ha->isp_ops->beacon_off(ha);
}

/* Scsi_Host attributes. */

static ssize_t
qla2x00_drvr_version_show(struct class_device *cdev, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", qla2x00_version_str);
}

static ssize_t
qla2x00_fw_version_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	char fw_str[30];

	return snprintf(buf, PAGE_SIZE, "%s\n",
	    ha->isp_ops->fw_version_str(ha, fw_str));
}

static ssize_t
qla2x00_serial_num_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	uint32_t sn;

	if (IS_FWI2_CAPABLE(ha))
		return snprintf(buf, PAGE_SIZE, "\n");

	sn = ((ha->serial0 & 0x1f) << 16) | (ha->serial2 << 8) | ha->serial1;
	return snprintf(buf, PAGE_SIZE, "%c%05d\n", 'A' + sn / 100000,
	    sn % 100000);
}

static ssize_t
qla2x00_isp_name_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	return snprintf(buf, PAGE_SIZE, "ISP%04X\n", ha->pdev->device);
}

static ssize_t
qla2x00_isp_id_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	return snprintf(buf, PAGE_SIZE, "%04x %04x %04x %04x\n",
	    ha->product_id[0], ha->product_id[1], ha->product_id[2],
	    ha->product_id[3]);
}

static ssize_t
qla2x00_model_name_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	return snprintf(buf, PAGE_SIZE, "%s\n", ha->model_number);
}

static ssize_t
qla2x00_model_desc_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	return snprintf(buf, PAGE_SIZE, "%s\n",
	    ha->model_desc ? ha->model_desc: "");
}

static ssize_t
qla2x00_pci_info_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	char pci_info[30];

	return snprintf(buf, PAGE_SIZE, "%s\n",
	    ha->isp_ops->pci_info_str(ha, pci_info));
}

static ssize_t
qla2x00_state_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int len = 0;

	if (atomic_read(&ha->loop_state) == LOOP_DOWN ||
	    atomic_read(&ha->loop_state) == LOOP_DEAD)
		len = snprintf(buf, PAGE_SIZE, "Link Down\n");
	else if (atomic_read(&ha->loop_state) != LOOP_READY ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags))
		len = snprintf(buf, PAGE_SIZE, "Unknown Link State\n");
	else {
		len = snprintf(buf, PAGE_SIZE, "Link Up - ");

		switch (ha->current_topology) {
		case ISP_CFG_NL:
			len += snprintf(buf + len, PAGE_SIZE-len, "Loop\n");
			break;
		case ISP_CFG_FL:
			len += snprintf(buf + len, PAGE_SIZE-len, "FL_Port\n");
			break;
		case ISP_CFG_N:
			len += snprintf(buf + len, PAGE_SIZE-len,
			    "N_Port to N_Port\n");
			break;
		case ISP_CFG_F:
			len += snprintf(buf + len, PAGE_SIZE-len, "F_Port\n");
			break;
		default:
			len += snprintf(buf + len, PAGE_SIZE-len, "Loop\n");
			break;
		}
	}
	return len;
}

static ssize_t
qla2x00_zio_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int len = 0;

	switch (ha->zio_mode) {
	case QLA_ZIO_MODE_6:
		len += snprintf(buf + len, PAGE_SIZE-len, "Mode 6\n");
		break;
	case QLA_ZIO_DISABLED:
		len += snprintf(buf + len, PAGE_SIZE-len, "Disabled\n");
		break;
	}
	return len;
}

static ssize_t
qla2x00_zio_store(struct class_device *cdev, const char *buf, size_t count)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int val = 0;
	uint16_t zio_mode;

	if (!IS_ZIO_SUPPORTED(ha))
		return -ENOTSUPP;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	if (val)
		zio_mode = QLA_ZIO_MODE_6;
	else
		zio_mode = QLA_ZIO_DISABLED;

	/* Update per-hba values and queue a reset. */
	if (zio_mode != QLA_ZIO_DISABLED || ha->zio_mode != QLA_ZIO_DISABLED) {
		ha->zio_mode = zio_mode;
		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
	}
	return strlen(buf);
}

static ssize_t
qla2x00_zio_timer_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));

	return snprintf(buf, PAGE_SIZE, "%d us\n", ha->zio_timer * 100);
}

static ssize_t
qla2x00_zio_timer_store(struct class_device *cdev, const char *buf,
    size_t count)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int val = 0;
	uint16_t zio_timer;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;
	if (val > 25500 || val < 100)
		return -ERANGE;

	zio_timer = (uint16_t)(val / 100);
	ha->zio_timer = zio_timer;

	return strlen(buf);
}

static ssize_t
qla2x00_beacon_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int len = 0;

	if (ha->beacon_blink_led)
		len += snprintf(buf + len, PAGE_SIZE-len, "Enabled\n");
	else
		len += snprintf(buf + len, PAGE_SIZE-len, "Disabled\n");
	return len;
}

static ssize_t
qla2x00_beacon_store(struct class_device *cdev, const char *buf,
    size_t count)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int val = 0;
	int rval;

	if (IS_QLA2100(ha) || IS_QLA2200(ha))
		return -EPERM;

	if (test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags)) {
		qla_printk(KERN_WARNING, ha,
		    "Abort ISP active -- ignoring beacon request.\n");
		return -EBUSY;
	}

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	if (val)
		rval = ha->isp_ops->beacon_on(ha);
	else
		rval = ha->isp_ops->beacon_off(ha);

	if (rval != QLA_SUCCESS)
		count = 0;

	return count;
}

static ssize_t
qla2x00_optrom_bios_version_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));

	return snprintf(buf, PAGE_SIZE, "%d.%02d\n", ha->bios_revision[1],
	    ha->bios_revision[0]);
}

static ssize_t
qla2x00_optrom_efi_version_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));

	return snprintf(buf, PAGE_SIZE, "%d.%02d\n", ha->efi_revision[1],
	    ha->efi_revision[0]);
}

static ssize_t
qla2x00_optrom_fcode_version_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));

	return snprintf(buf, PAGE_SIZE, "%d.%02d\n", ha->fcode_revision[1],
	    ha->fcode_revision[0]);
}

static ssize_t
qla2x00_optrom_fw_version_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));

	return snprintf(buf, PAGE_SIZE, "%d.%02d.%02d %d\n",
	    ha->fw_revision[0], ha->fw_revision[1], ha->fw_revision[2],
	    ha->fw_revision[3]);
}

static ssize_t
qla2x00_total_isp_aborts_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));

	return snprintf(buf, PAGE_SIZE, "%d\n",
	    ha->qla_stats.total_isp_aborts);
}

static ssize_t
qla24xx_84xx_fw_version_show(struct class_device *cdev, char *buf)
{
	int rval = QLA_SUCCESS;
	uint16_t status[2] = {0, 0};
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));

	if (IS_QLA84XX(ha) && ha->cs84xx) {
		if (ha->cs84xx->op_fw_version == 0) {
			rval = qla84xx_verify_chip(ha, status);
		}

		if ((rval == QLA_SUCCESS) && (status[0] == 0))
			return snprintf(buf, PAGE_SIZE, "%u\n",
			    (uint32_t)ha->cs84xx->op_fw_version);
	}

	return snprintf(buf, PAGE_SIZE, "\n");
}

scsi_qla_host_t *
qla24xx_vport_create(scsi_qla_host_t *ha, uint64_t fc_wwpn, uint64_t fc_wwnn)
{
	int	ret = 0;
	scsi_qla_host_t *vha;

	ret = qla24xx_vport_create_req_sanity_check(ha, fc_wwpn, fc_wwnn);
	if (ret) {
		DEBUG15(printk("qla24xx_vport_create_req_sanity_check failed, "
		    "status %x\n", ret));
		return NULL;
	}

	vha = qla24xx_create_vhost(ha, fc_wwpn, fc_wwnn);
	if (vha == NULL) {
		DEBUG15(printk ("qla24xx_create_vhost failed, vha = %p\n",
		    vha));
		return NULL;
	}

	atomic_set(&vha->vp_state, VP_FAILED);

	/* ready to create vport */
	qla_printk(KERN_INFO, vha, "VP entry id %d assigned.\n", vha->vp_idx);

	/* initialized vport states */
	atomic_set(&vha->loop_state, LOOP_DOWN);
	vha->vp_err_state = VP_ERR_PORTDWN;
	vha->vp_prev_err_state = VP_ERR_UNKWN;
	/* Check if physical ha port is Up */
	if (atomic_read(&ha->loop_state) == LOOP_DOWN ||
	    atomic_read(&ha->loop_state) == LOOP_DEAD) {
		/* Don't retry or attempt login of this virtual port */
		DEBUG15(printk ("scsi(%ld): pport loop_state is not UP.\n",
		    vha->host_no));
		atomic_set(&vha->loop_state, LOOP_DEAD);
	}

	if (scsi_add_host(vha->host, &ha->pdev->dev)) {
		DEBUG15(printk("scsi(%ld): scsi_add_host failure for VP[%d].\n",
			vha->host_no, vha->vp_idx));
		goto vport_create_failed_2;
	}

	/* initialize attributes */
	fc_host_node_name(vha->host) = wwn_to_u64(vha->node_name);
	fc_host_port_name(vha->host) = wwn_to_u64(vha->port_name);
	fc_host_supported_classes(vha->host) =
		fc_host_supported_classes(ha->host);
	fc_host_supported_speeds(vha->host) =
		fc_host_supported_speeds(ha->host);

	qla24xx_enable_vp(vha);

	return vha;
vport_create_failed_2:

	qla24xx_disable_vp(vha);
	qla24xx_deallocate_vp_id(vha);
	kfree(vha->port_name);
	kfree(vha->node_name);
	scsi_host_put(vha->host);
	return NULL;
}

static ssize_t
qla24xx_vport_create_cdev(struct class_device *cdev, const char *buf,
    size_t count)
{
	int	cnt = count;
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	uint64_t fc_wwpn;
	uint64_t fc_wwnn;

	/* count may include a LF at end of string */
	if (buf[cnt-1] == '\n')
		cnt--;

	/* validate we have enough characters for WWPN */
	if ((cnt != (16+1+16)) || (buf[16] != ':'))
		return -EINVAL;

	if (fc_parse_wwn(&buf[0], &fc_wwpn))
		return -EINVAL;

	if (fc_parse_wwn(&buf[17], &fc_wwnn))
		return -EINVAL;

	return qla24xx_vport_create(ha, fc_wwpn, fc_wwnn) ? count: -EINVAL;
}

static ssize_t
qla24xx_vport_delete(struct class_device *cdev, const char *buf, size_t count)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	scsi_qla_host_t *vha;
	int	cnt = count;
	uint64_t	fc_wwpn;
	uint8_t		port_name[WWN_SIZE];

	/* count may include a LF at end of string */
	if (buf[cnt-1] == '\n')
		cnt--;

	/* validate we have enough characters for WWPN */
	if ((cnt != (16+1+16)) || (buf[16] != ':'))
		return -EINVAL;

	if (fc_parse_wwn(&buf[0], &fc_wwpn))
		return -EINVAL;

	u64_to_wwn(fc_wwpn, port_name);

	vha = qla24xx_find_vhost_by_name(ha, port_name);
	if (!vha)
		return VP_RET_CODE_WWPN;

	qla24xx_disable_vp(vha);
	qla24xx_deallocate_vp_id(vha);

	down(&ha->vport_sem);
	ha->cur_vport_count--;
	clear_bit(vha->vp_idx, ha->vp_idx_map);
	up(&ha->vport_sem);

	kfree(vha->node_name);
	kfree(vha->port_name);

	if (vha->timer_active) {
		qla2x00_vp_stop_timer(vha);
		DEBUG15(printk ("scsi(%ld): timer for the vport[%d] = %p "
		    "has stopped\n",
		    vha->host_no, vha->vp_idx, vha));
        }

	fc_remove_host(vha->host);

	scsi_remove_host(vha->host);

	scsi_host_put(vha->host);

	return count;
}

static ssize_t
qla24xx_max_npiv_vports_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));

	return snprintf(buf, PAGE_SIZE, "%d\n", ha->max_npiv_vports);
}

static ssize_t
qla24xx_npiv_vports_inuse_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));

	return snprintf(buf, PAGE_SIZE, "%d\n", ha->cur_vport_count);
}

static ssize_t
qla24xx_node_name(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	uint8_t fc_wwnn_str[16];

	fc_convert_hex_char(ha->node_name, fc_wwnn_str, WWN_SIZE);

	return snprintf(buf, PAGE_SIZE, "%s\n", fc_wwnn_str);
}

static ssize_t
qla24xx_port_name(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	uint8_t fc_wwpn_str[16];

	fc_convert_hex_char(ha->port_name, fc_wwpn_str, WWN_SIZE);

	return snprintf(buf, PAGE_SIZE, "%s\n", fc_wwpn_str);
}

static ssize_t
qla24xx_vport_id_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	uint8_t fc_vport_id[2];
	uint8_t fc_vport_id_str[4];
	
	fc_vport_id[0] = (ha->vp_idx & 0xff00) >> 0x08;
	fc_vport_id[1] = ha->vp_idx & 0xff;

	fc_convert_hex_char(fc_vport_id, fc_vport_id_str, sizeof (ha->vp_idx));

	return snprintf(buf, PAGE_SIZE, "%s\n", fc_vport_id_str);
}

static ssize_t
qla24xx_vport_id_store(struct class_device *cdev, const char *buf,
    size_t count)
{
	int vport_id;
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));

	if (sscanf(buf, "%d", &vport_id) != 1)
		return -EINVAL;

	ha->vp_idx = vport_id;

	return count;
}

static ssize_t
qla24xx_vport_disable(struct class_device *cdev, const char *buf,
    size_t count)
{
	int disable = 0;

	scsi_qla_host_t *vha = to_qla_host(class_to_shost(cdev));

	if (sscanf(buf, "%d", &disable) != 1)
		return -EINVAL;

	if (disable)
		qla24xx_disable_vp(vha);
	else
		qla24xx_enable_vp(vha);

	return count;
}

static ssize_t
qla24xx_symbolic_port_name_show(struct class_device *cdev, char *buf)
{
	int	len = 0;
	char	fw_str[30];
	char	fc_vp_idx_str[4];
	uint8_t	vp_idx[2];

	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));

	len = snprintf(buf, PAGE_SIZE, ha->model_number);
	len += snprintf(buf + len, PAGE_SIZE, " FW:");
	len += snprintf(buf + len, PAGE_SIZE,
	    ha->isp_ops->fw_version_str(ha, fw_str));
	len += snprintf(buf + len, PAGE_SIZE, " DVR:");
	len += snprintf(buf + len, PAGE_SIZE, qla2x00_version_str);
	len += snprintf(buf + len, PAGE_SIZE-len, " VPORT <");

	vp_idx[0] = (ha->vp_idx & 0xff00) >> 8;
	vp_idx[1] = ha->vp_idx & 0xff;
	fc_convert_hex_char(vp_idx, fc_vp_idx_str, 2);
	len += snprintf(buf + len, PAGE_SIZE, fc_vp_idx_str);
	len += snprintf(buf + len, PAGE_SIZE, ">\n");

	return len;
}

static ssize_t
qla24xx_symbolic_port_name_store(struct class_device *cdev, const char *buf,
    size_t count)
{
	printk("NPIV-DGB: %s: under construction...\n", __func__);

	return count;
}

static ssize_t
qla24xx_vport_state_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int len = 0;

	switch (atomic_read(&ha->vport_state)) {
	case FC_VPORT_UNKNOWN:
		len = snprintf(buf, PAGE_SIZE, "Unknown\n");
		break;
	case FC_VPORT_INITIALIZING:
		len = snprintf(buf, PAGE_SIZE, "Initializing\n");
		break;
	case FC_VPORT_ACTIVE:
		len = snprintf(buf, PAGE_SIZE, "Active\n");
		break;
	case FC_VPORT_DISABLED:
		len = snprintf(buf, PAGE_SIZE, "Disabled\n");
		break;
	case FC_VPORT_LOGOUT:
		len = snprintf(buf, PAGE_SIZE, "Fabric Logout\n");
		break;
	case FC_VPORT_LINKDOWN:
		len = snprintf(buf, PAGE_SIZE, "Linkdown\n");
		break;
	case FC_VPORT_NO_FABRIC_SUPP:
		len = snprintf(buf, PAGE_SIZE, "No Fabric Support\n");
		break;
	case FC_VPORT_NO_FABRIC_RSCS:
		len = snprintf(buf, PAGE_SIZE, "No Fabric Resources\n");
		break;
	case FC_VPORT_FAILED:
		len = snprintf(buf, PAGE_SIZE, "Vport Failed\n");
		break;
	default:
		len = snprintf(buf, PAGE_SIZE, "Vport State Invalid\n");
		break;
	}

	return len;
}

static ssize_t
qla24xx_vport_last_state_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int len = 0;

	switch (atomic_read(&ha->vport_last_state)) {
	case FC_VPORT_UNKNOWN:
		len = snprintf(buf, PAGE_SIZE, "Unknown\n");
		break;
	case FC_VPORT_INITIALIZING:
		len = snprintf(buf, PAGE_SIZE, "Initializing\n");
		break;
	case FC_VPORT_ACTIVE:
		len = snprintf(buf, PAGE_SIZE, "Active\n");
		break;
	case FC_VPORT_DISABLED:
		len = snprintf(buf, PAGE_SIZE, "Disabled\n");
		break;
	case FC_VPORT_LOGOUT:
		len = snprintf(buf, PAGE_SIZE, "Fabric Logout\n");
		break;
	case FC_VPORT_LINKDOWN:
		len = snprintf(buf, PAGE_SIZE, "Linkdown\n");
		break;
	case FC_VPORT_NO_FABRIC_SUPP:
		len = snprintf(buf, PAGE_SIZE, "No Fabric Support\n");
		break;
	case FC_VPORT_NO_FABRIC_RSCS:
		len = snprintf(buf, PAGE_SIZE, "No Fabric Resources\n");
		break;
	case FC_VPORT_FAILED:
		len = snprintf(buf, PAGE_SIZE, "Vport Failed\n");
		break;
	default:
		len = snprintf(buf, PAGE_SIZE, "Vport State Invalid\n");
		break;
	}

	return len;
}

static CLASS_DEVICE_ATTR(driver_version, S_IRUGO, qla2x00_drvr_version_show,
	NULL);
static CLASS_DEVICE_ATTR(fw_version, S_IRUGO, qla2x00_fw_version_show, NULL);
static CLASS_DEVICE_ATTR(serial_num, S_IRUGO, qla2x00_serial_num_show, NULL);
static CLASS_DEVICE_ATTR(isp_name, S_IRUGO, qla2x00_isp_name_show, NULL);
static CLASS_DEVICE_ATTR(isp_id, S_IRUGO, qla2x00_isp_id_show, NULL);
static CLASS_DEVICE_ATTR(model_name, S_IRUGO, qla2x00_model_name_show, NULL);
static CLASS_DEVICE_ATTR(model_desc, S_IRUGO, qla2x00_model_desc_show, NULL);
static CLASS_DEVICE_ATTR(pci_info, S_IRUGO, qla2x00_pci_info_show, NULL);
static CLASS_DEVICE_ATTR(state, S_IRUGO, qla2x00_state_show, NULL);
static CLASS_DEVICE_ATTR(zio, S_IRUGO | S_IWUSR, qla2x00_zio_show,
    qla2x00_zio_store);
static CLASS_DEVICE_ATTR(zio_timer, S_IRUGO | S_IWUSR, qla2x00_zio_timer_show,
    qla2x00_zio_timer_store);
static CLASS_DEVICE_ATTR(beacon, S_IRUGO | S_IWUSR, qla2x00_beacon_show,
    qla2x00_beacon_store);
static CLASS_DEVICE_ATTR(optrom_bios_version, S_IRUGO,
    qla2x00_optrom_bios_version_show, NULL);
static CLASS_DEVICE_ATTR(optrom_efi_version, S_IRUGO,
    qla2x00_optrom_efi_version_show, NULL);
static CLASS_DEVICE_ATTR(optrom_fcode_version, S_IRUGO,
    qla2x00_optrom_fcode_version_show, NULL);
static CLASS_DEVICE_ATTR(optrom_fw_version, S_IRUGO,
    qla2x00_optrom_fw_version_show, NULL);
static CLASS_DEVICE_ATTR(total_isp_aborts, S_IRUGO,
    qla2x00_total_isp_aborts_show, NULL);
static CLASS_DEVICE_ATTR(84xx_fw_version, S_IRUGO,
    qla24xx_84xx_fw_version_show, NULL);
static CLASS_DEVICE_ATTR(vport_create, S_IWUGO, NULL, qla24xx_vport_create_cdev);
static CLASS_DEVICE_ATTR(vport_delete, S_IWUGO, NULL, qla24xx_vport_delete);
static CLASS_DEVICE_ATTR(max_npiv_vports, S_IRUGO,
	qla24xx_max_npiv_vports_show, NULL);
static CLASS_DEVICE_ATTR(npiv_vports_inuse, S_IRUGO,
	qla24xx_npiv_vports_inuse_show, NULL);
static CLASS_DEVICE_ATTR(node_name, S_IRUGO, qla24xx_node_name,
	NULL);
static CLASS_DEVICE_ATTR(port_name, S_IRUGO, qla24xx_port_name,
	NULL);
static CLASS_DEVICE_ATTR(vport_id, S_IRUGO|S_IWUGO, qla24xx_vport_id_show,
	qla24xx_vport_id_store);
static CLASS_DEVICE_ATTR(vport_disable, S_IWUGO, NULL, qla24xx_vport_disable);
static CLASS_DEVICE_ATTR(symbolic_port_name, S_IRUGO|S_IWUGO,
	qla24xx_symbolic_port_name_show, qla24xx_symbolic_port_name_store);
static CLASS_DEVICE_ATTR(vport_state, S_IRUGO, qla24xx_vport_state_show,
	NULL);
static CLASS_DEVICE_ATTR(vport_last_state, S_IRUGO,
	qla24xx_vport_last_state_show, NULL);

struct class_device_attribute *qla2x00_host_attrs[] = {
	&class_device_attr_driver_version,
	&class_device_attr_fw_version,
	&class_device_attr_serial_num,
	&class_device_attr_isp_name,
	&class_device_attr_isp_id,
	&class_device_attr_model_name,
	&class_device_attr_model_desc,
	&class_device_attr_pci_info,
	&class_device_attr_state,
	&class_device_attr_zio,
	&class_device_attr_zio_timer,
	&class_device_attr_beacon,
	&class_device_attr_optrom_bios_version,
	&class_device_attr_optrom_efi_version,
	&class_device_attr_optrom_fcode_version,
	&class_device_attr_optrom_fw_version,
	&class_device_attr_total_isp_aborts,
	NULL,
};

struct class_device_attribute *qla24xx_host_attrs[] = {
	&class_device_attr_driver_version,
	&class_device_attr_fw_version,
	&class_device_attr_serial_num,
	&class_device_attr_isp_name,
	&class_device_attr_isp_id,
	&class_device_attr_model_name,
	&class_device_attr_model_desc,
	&class_device_attr_pci_info,
	&class_device_attr_state,
	&class_device_attr_zio,
	&class_device_attr_zio_timer,
	&class_device_attr_beacon,
	&class_device_attr_optrom_bios_version,
	&class_device_attr_optrom_efi_version,
	&class_device_attr_optrom_fcode_version,
	&class_device_attr_optrom_fw_version,
	&class_device_attr_total_isp_aborts,
	&class_device_attr_84xx_fw_version,
	&class_device_attr_vport_create,
	&class_device_attr_vport_delete,
	&class_device_attr_max_npiv_vports,
	&class_device_attr_npiv_vports_inuse,
	NULL,
};

struct class_device_attribute *qla24xx_host_vport_attrs[] = {
	&class_device_attr_driver_version,
	&class_device_attr_fw_version,
	&class_device_attr_serial_num,
	&class_device_attr_isp_name,
	&class_device_attr_isp_id,
	&class_device_attr_model_name,
	&class_device_attr_model_desc,
	&class_device_attr_pci_info,
	&class_device_attr_state,
	&class_device_attr_zio,
	&class_device_attr_zio_timer,
	&class_device_attr_beacon,
	&class_device_attr_optrom_bios_version,
	&class_device_attr_optrom_efi_version,
	&class_device_attr_optrom_fcode_version,
	&class_device_attr_optrom_fw_version,
	&class_device_attr_total_isp_aborts,
	&class_device_attr_84xx_fw_version,
	&class_device_attr_node_name,
	&class_device_attr_port_name,
	&class_device_attr_vport_id,
	&class_device_attr_vport_disable,
	&class_device_attr_symbolic_port_name,
	&class_device_attr_vport_state,
	&class_device_attr_vport_last_state,
	NULL,
};

/* Host attributes. */

static void
qla2x00_get_host_port_id(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);

	fc_host_port_id(shost) = ha->d_id.b.domain << 16 |
	    ha->d_id.b.area << 8 | ha->d_id.b.al_pa;
}

static void
qla2x00_get_host_speed(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);
	uint32_t speed = 0;

	switch (ha->link_data_rate) {
	case PORT_SPEED_1GB:
		speed = 1;
		break;
	case PORT_SPEED_2GB:
		speed = 2;
		break;
	case PORT_SPEED_4GB:
		speed = 4;
		break;
	}
	fc_host_speed(shost) = speed;
}

static void
qla2x00_get_host_port_type(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);
	uint32_t port_type = FC_PORTTYPE_UNKNOWN;

	switch (ha->current_topology) {
	case ISP_CFG_NL:
		port_type = FC_PORTTYPE_LPORT;
		break;
	case ISP_CFG_FL:
		port_type = FC_PORTTYPE_NLPORT;
		break;
	case ISP_CFG_N:
		port_type = FC_PORTTYPE_PTP;
		break;
	case ISP_CFG_F:
		port_type = FC_PORTTYPE_NPORT;
		break;
	}
	fc_host_port_type(shost) = port_type;
}

static void
qla2x00_get_starget_node_name(struct scsi_target *starget)
{
	struct Scsi_Host *host = dev_to_shost(starget->dev.parent);
	scsi_qla_host_t *ha = to_qla_host(host);
	fc_port_t *fcport;
	u64 node_name = 0;

	list_for_each_entry(fcport, &ha->fcports, list) {
		if (starget->id == fcport->os_target_id) {
			node_name = wwn_to_u64(fcport->node_name);
			break;
		}
	}

	fc_starget_node_name(starget) = node_name;
}

static void
qla2x00_get_starget_port_name(struct scsi_target *starget)
{
	struct Scsi_Host *host = dev_to_shost(starget->dev.parent);
	scsi_qla_host_t *ha = to_qla_host(host);
	fc_port_t *fcport;
	u64 port_name = 0;

	list_for_each_entry(fcport, &ha->fcports, list) {
		if (starget->id == fcport->os_target_id) {
			port_name = wwn_to_u64(fcport->port_name);
			break;
		}
	}

	fc_starget_port_name(starget) = port_name;
}

static void
qla2x00_get_starget_port_id(struct scsi_target *starget)
{
	struct Scsi_Host *host = dev_to_shost(starget->dev.parent);
	scsi_qla_host_t *ha = to_qla_host(host);
	fc_port_t *fcport;
	uint32_t port_id = ~0U;

	list_for_each_entry(fcport, &ha->fcports, list) {
		if (starget->id == fcport->os_target_id) {
			port_id = fcport->d_id.b.domain << 16 |
			    fcport->d_id.b.area << 8 | fcport->d_id.b.al_pa;
			break;
		}
	}

	fc_starget_port_id(starget) = port_id;
}

static void
qla2x00_set_rport_loss_tmo(struct fc_rport *rport, uint32_t timeout)
{
	if (timeout)
		rport->dev_loss_tmo = timeout;
	else
		rport->dev_loss_tmo = 1;
}

static void
qla2x00_dev_loss_tmo_callbk(struct fc_rport *rport)
{
	struct Scsi_Host *host = rport_to_shost(rport);
	fc_port_t *fcport = *(fc_port_t **)rport->dd_data;

	qla2x00_abort_fcport_cmds(fcport);

	/*
	 * Transport has effectively 'deleted' the rport, clear
	 * all local references.
	 */
	spin_lock_irq(host->host_lock);
	fcport->rport = NULL;
	*((fc_port_t **)rport->dd_data) = NULL;
	spin_unlock_irq(host->host_lock);
}

static void
qla2x00_terminate_rport_io(struct fc_rport *rport)
{
	fc_port_t *fcport = *(fc_port_t **)rport->dd_data;

	qla2x00_abort_fcport_cmds(fcport);
	scsi_target_unblock(&rport->dev);
}

static int
qla2x00_issue_lip(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);

	qla2x00_loop_reset(ha);
	return 0;
}

static struct fc_host_statistics *
qla2x00_get_fc_host_stats(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);
	int rval;
	struct link_statistics *stats;
	dma_addr_t stats_dma;
	struct fc_host_statistics *pfc_host_stat;

	pfc_host_stat = &ha->fc_host_stat;
	memset(pfc_host_stat, -1, sizeof(struct fc_host_statistics));

	stats = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &stats_dma);
	if (stats == NULL) {
		DEBUG2_3_11(printk("%s(%ld): Failed to allocate memory.\n",
		    __func__, ha->host_no));
		goto done;
	}
	memset(stats, 0, DMA_POOL_SIZE);

	rval = QLA_FUNCTION_FAILED;
	if (IS_FWI2_CAPABLE(ha)) {
		rval = qla24xx_get_isp_stats(ha, stats, stats_dma);
	} else if (atomic_read(&ha->loop_state) == LOOP_READY &&
		    !test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) &&
		    !test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags) &&
		    !ha->dpc_active) {
		/* Must be in a 'READY' state for statistics retrieval. */
		rval = qla2x00_get_link_status(ha, ha->loop_id, stats,
		    stats_dma);
	}

	if (rval != QLA_SUCCESS)
		goto done_free;

	pfc_host_stat->link_failure_count = stats->link_fail_cnt;
	pfc_host_stat->loss_of_sync_count = stats->loss_sync_cnt;
	pfc_host_stat->loss_of_signal_count = stats->loss_sig_cnt;
	pfc_host_stat->prim_seq_protocol_err_count = stats->prim_seq_err_cnt;
	pfc_host_stat->invalid_tx_word_count = stats->inval_xmit_word_cnt;
	pfc_host_stat->invalid_crc_count = stats->inval_crc_cnt;
	if (IS_FWI2_CAPABLE(ha)) {
		pfc_host_stat->lip_count = stats->lip_cnt;
		pfc_host_stat->tx_frames = stats->tx_frames;
		pfc_host_stat->rx_frames = stats->rx_frames;
		pfc_host_stat->dumped_frames = stats->dumped_frames;
		pfc_host_stat->nos_count = stats->nos_rcvd;
	}

done_free:
        dma_pool_free(ha->s_dma_pool, stats, stats_dma);
done:
	return pfc_host_stat;
}

static void
qla2x00_get_host_symbolic_name(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);

	qla2x00_get_sym_node_name(ha, fc_host_symbolic_name(shost));
}

static void
qla2x00_set_host_system_hostname(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);

	set_bit(REGISTER_FDMI_NEEDED, &ha->dpc_flags);
}

static void
qla2x00_get_host_fabric_name(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);
	u64 node_name;

	if (ha->device_flags & SWITCH_FOUND)
		node_name = wwn_to_u64(ha->fabric_node_name);
	else
		node_name = wwn_to_u64(ha->node_name);

	fc_host_fabric_name(shost) = node_name;
}

static void
qla2x00_get_host_port_state(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);

	if (!ha->flags.online)
		fc_host_port_state(shost) = FC_PORTSTATE_OFFLINE;
	else if (atomic_read(&ha->loop_state) == LOOP_TIMEOUT)
		fc_host_port_state(shost) = FC_PORTSTATE_UNKNOWN;
	else
		fc_host_port_state(shost) = FC_PORTSTATE_ONLINE;
}

struct fc_function_template qla2xxx_transport_functions = {

	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,

	.get_host_port_id = qla2x00_get_host_port_id,
	.show_host_port_id = 1,
	.get_host_speed = qla2x00_get_host_speed,
	.show_host_speed = 1,
	.get_host_port_type = qla2x00_get_host_port_type,
	.show_host_port_type = 1,
	.get_host_symbolic_name = qla2x00_get_host_symbolic_name,
	.show_host_symbolic_name = 1,
	.set_host_system_hostname = qla2x00_set_host_system_hostname,
	.show_host_system_hostname = 1,
	.get_host_fabric_name = qla2x00_get_host_fabric_name,
	.show_host_fabric_name = 1,
	.get_host_port_state = qla2x00_get_host_port_state,
	.show_host_port_state = 1,

	.dd_fcrport_size = sizeof(struct fc_port *),
	.show_rport_supported_classes = 1,

	.get_starget_node_name = qla2x00_get_starget_node_name,
	.show_starget_node_name = 1,
	.get_starget_port_name = qla2x00_get_starget_port_name,
	.show_starget_port_name = 1,
	.get_starget_port_id  = qla2x00_get_starget_port_id,
	.show_starget_port_id = 1,

	.set_rport_dev_loss_tmo = qla2x00_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 1,

	.issue_fc_host_lip = qla2x00_issue_lip,
	.dev_loss_tmo_callbk = qla2x00_dev_loss_tmo_callbk,
	.terminate_rport_io = qla2x00_terminate_rport_io,
	.get_fc_host_stats = qla2x00_get_fc_host_stats,
};

void
qla2x00_init_host_attr(scsi_qla_host_t *ha)
{
	u32 speed = FC_PORTSPEED_UNKNOWN;

	fc_host_node_name(ha->host) = wwn_to_u64(ha->node_name);
	fc_host_port_name(ha->host) = wwn_to_u64(ha->port_name);
	fc_host_supported_classes(ha->host) = FC_COS_CLASS3;

	if (IS_QLA25XX(ha))
		speed = FC_PORTSPEED_8GBIT | FC_PORTSPEED_4GBIT |
			FC_PORTSPEED_2GBIT | FC_PORTSPEED_1GBIT;
	else if (IS_QLA24XX_TYPE(ha))
		speed = FC_PORTSPEED_4GBIT | FC_PORTSPEED_2GBIT |
			FC_PORTSPEED_1GBIT;
	else if (IS_QLA23XX(ha))
		speed = FC_PORTSPEED_2GBIT | FC_PORTSPEED_1GBIT;
	else
		speed = FC_PORTSPEED_1GBIT;
	fc_host_supported_speeds(ha->host) = speed;
}
