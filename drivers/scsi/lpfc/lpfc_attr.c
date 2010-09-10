/*******************************************************************
 * This file is part of the Emulex Linux Device Driver for         *
 * Fibre Channel Host Bus Adapters.                                *
 * Copyright (C) 2004-2008 Emulex.  All rights reserved.           *
 * EMULEX and SLI are trademarks of Emulex.                        *
 * www.emulex.com                                                  *
 * Portions Copyright (C) 2004-2005 Christoph Hellwig              *
 *                                                                 *
 * This program is free software; you can redistribute it and/or   *
 * modify it under the terms of version 2 of the GNU General       *
 * Public License as published by the Free Software Foundation.    *
 * This program is distributed in the hope that it will be useful. *
 * ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND          *
 * WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY,  *
 * FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT, ARE      *
 * DISCLAIMED, EXCEPT TO THE EXTENT THAT SUCH DISCLAIMERS ARE HELD *
 * TO BE LEGALLY INVALID.  See the GNU General Public License for  *
 * more details, a copy of which can be found in the file COPYING  *
 * included with this package.                                     *
 *******************************************************************/

#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/interrupt.h>

#if defined(CONFIG_PCIEAER)
#include <linux/aer.h>
#endif

#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_transport_fc.h>
#include <scsi/fc/fc_fs.h>

#include "lpfc_hw4.h"
#include "lpfc_hw.h"
#include "lpfc_sli.h"
#include "lpfc_sli4.h"
#include "lpfc_nl.h"
#include "lpfc_disc.h"
#include "lpfc_scsi.h"
#include "lpfc.h"
#include "lpfc_logmsg.h"
#include "lpfc_version.h"
#include "lpfc_compat.h"
#include "lpfc_crtn.h"
#include "lpfc_vport.h"
#include "lpfc_auth_access.h"

#define LPFC_DEF_DEVLOSS_TMO 30
#define LPFC_MIN_DEVLOSS_TMO 1
#define LPFC_MAX_DEVLOSS_TMO 255

#define LPFC_MAX_LINK_SPEED 8
#define LPFC_LINK_SPEED_BITMAP 0x00000117
#define LPFC_LINK_SPEED_STRING "0, 1, 2, 4, 8"

extern struct bin_attribute sysfs_menlo_attr;

/*
 * Write key size should be multiple of 4. If write key is changed
 * make sure that library write key is also changed.
 */
#define LPFC_REG_WRITE_KEY_SIZE	4
#define LPFC_REG_WRITE_KEY	"EMLX"

/**
 * lpfc_jedec_to_ascii - Hex to ascii convertor according to JEDEC rules
 * @incr: integer to convert.
 * @hdw: ascii string holding converted integer plus a string terminator.
 *
 * Description:
 * JEDEC Joint Electron Device Engineering Council.
 * Convert a 32 bit integer composed of 8 nibbles into an 8 byte ascii
 * character string. The string is then terminated with a NULL in byte 9.
 * Hex 0-9 becomes ascii '0' to '9'.
 * Hex a-f becomes ascii '=' to 'B' capital B.
 *
 * Notes:
 * Coded for 32 bit integers only.
 **/
static void
lpfc_jedec_to_ascii(int incr, char hdw[])
{
	int i, j;
	for (i = 0; i < 8; i++) {
		j = (incr & 0xf);
		if (j <= 9)
			hdw[7 - i] = 0x30 +  j;
		 else
			hdw[7 - i] = 0x61 + j - 10;
		incr = (incr >> 4);
	}
	hdw[8] = 0;
	return;
}

/**
 * lpfc_drvr_version_show - Return the Emulex driver string with version number
 * @dev: class unused variable.
 * @attr: device attribute, not used.
 * @buf: on return contains the module description text.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_drvr_version_show(struct class_device *cdev, char *buf)
{
	return snprintf(buf, PAGE_SIZE, LPFC_MODULE_DESC "\n");
}

/**
 * lpfc_enable_fip_show - Return the fip mode of the HBA
 * @dev: class unused variable.
 * @attr: device attribute, not used.
 * @buf: on return contains the module description text.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_enable_fip_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	if (phba->hba_flag & HBA_FIP_SUPPORT)
		return snprintf(buf, PAGE_SIZE, "1\n");
	else
		return snprintf(buf, PAGE_SIZE, "0\n");
}

static ssize_t
management_version_show(struct class_device *cdev, char *buf)
{
	return snprintf(buf, PAGE_SIZE, DFC_API_VERSION "\n");
}

/**
 * lpfc_info_show - Return some pci info about the host in ascii
 * @dev: class converted to a Scsi_host structure.
 * @attr: device attribute, not used.
 * @buf: on return contains the formatted text from lpfc_info().
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_info_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);

	return snprintf(buf, PAGE_SIZE, "%s\n",lpfc_info(shost));
}

/**
 * lpfc_serialnum_show - Return the hba serial number in ascii
 * @dev: class converted to a Scsi_host structure.
 * @attr: device attribute, not used.
 * @buf: on return contains the formatted text serial number.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_serialnum_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	return snprintf(buf, PAGE_SIZE, "%s\n",phba->SerialNumber);
}

/**
 * lpfc_temp_sensor_show - Return the temperature sensor level
 * @dev: class converted to a Scsi_host structure.
 * @attr: device attribute, not used.
 * @buf: on return contains the formatted support level.
 *
 * Description:
 * Returns a number indicating the temperature sensor level currently
 * supported, zero or one in ascii.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_temp_sensor_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	return snprintf(buf, PAGE_SIZE, "%d\n",phba->temp_sensor_support);
}

/**
 * lpfc_modeldesc_show - Return the model description of the hba
 * @dev: class converted to a Scsi_host structure.
 * @attr: device attribute, not used.
 * @buf: on return contains the scsi vpd model description.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_modeldesc_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	return snprintf(buf, PAGE_SIZE, "%s\n",phba->ModelDesc);
}

/**
 * lpfc_modelname_show - Return the model name of the hba
 * @dev: class converted to a Scsi_host structure.
 * @attr: device attribute, not used.
 * @buf: on return contains the scsi vpd model name.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_modelname_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	return snprintf(buf, PAGE_SIZE, "%s\n",phba->ModelName);
}

/**
 * lpfc_programtype_show - Return the program type of the hba
 * @dev: class converted to a Scsi_host structure.
 * @attr: device attribute, not used.
 * @buf: on return contains the scsi vpd program type.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_programtype_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	return snprintf(buf, PAGE_SIZE, "%s\n",phba->ProgramType);
}

/**
 * lpfc_mlomgmt_show - Return the Menlo Maintenance sli flag
 * @dev: class converted to a Scsi_host structure.
 * @attr: device attribute, not used.
 * @buf: on return contains the Menlo Maintenance sli flag.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_mlomgmt_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	return snprintf(buf, PAGE_SIZE, "%d\n",
		(phba->sli.sli_flag & LPFC_MENLO_MAINT));
}

/**
 * lpfc_vportnum_show - Return the port number in ascii of the hba
 * @dev: class converted to a Scsi_host structure.
 * @attr: device attribute, not used.
 * @buf: on return contains scsi vpd program type.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_vportnum_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	return snprintf(buf, PAGE_SIZE, "%s\n",phba->Port);
}

/**
 * lpfc_fwrev_show - Return the firmware rev running in the hba
 * @dev: class converted to a Scsi_host structure.
 * @attr: device attribute, not used.
 * @buf: on return contains the scsi vpd program type.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_fwrev_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	char fwrev[32];

	lpfc_decode_firmware_rev(phba, fwrev, 1);
	return snprintf(buf, PAGE_SIZE, "%s, sli-%d\n", fwrev, phba->sli_rev);
}

/**
 * lpfc_hdw_show - Return the jedec information about the hba
 * @dev: class converted to a Scsi_host structure.
 * @attr: device attribute, not used.
 * @buf: on return contains the scsi vpd program type.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_hdw_show(struct class_device *cdev, char *buf)
{
	char hdw[9];
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	lpfc_vpd_t *vp = &phba->vpd;

	lpfc_jedec_to_ascii(vp->rev.biuRev, hdw);
	return snprintf(buf, PAGE_SIZE, "%s\n", hdw);
}

/**
 * lpfc_option_rom_version_show - Return the adapter ROM FCode version
 * @dev: class converted to a Scsi_host structure.
 * @attr: device attribute, not used.
 * @buf: on return contains the ROM and FCode ascii strings.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_option_rom_version_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	return snprintf(buf, PAGE_SIZE, "%s\n", phba->OptionROMVersion);
}

/**
 * lpfc_state_show - Return the link state of the port
 * @dev: class converted to a Scsi_host structure.
 * @attr: device attribute, not used.
 * @buf: on return contains text describing the state of the link.
 *
 * Notes:
 * The switch statement has no default so zero will be returned.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_state_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	int  len = 0;

	switch (phba->link_state) {
	case LPFC_LINK_UNKNOWN:
	case LPFC_WARM_START:
	case LPFC_INIT_START:
	case LPFC_INIT_MBX_CMDS:
	case LPFC_LINK_DOWN:
	case LPFC_HBA_ERROR:
		if (phba->hba_flag & LINK_DISABLED)
			len += snprintf(buf + len, PAGE_SIZE-len,
				"Link Down - User disabled\n");
		else
			len += snprintf(buf + len, PAGE_SIZE-len,
				"Link Down\n");
		break;
	case LPFC_LINK_UP:
	case LPFC_CLEAR_LA:
	case LPFC_HBA_READY:
		len += snprintf(buf + len, PAGE_SIZE-len, "Link Up - ");

		switch (vport->port_state) {
		case LPFC_LOCAL_CFG_LINK:
			len += snprintf(buf + len, PAGE_SIZE-len,
					"Configuring Link\n");
			break;
		case LPFC_FDISC:
		case LPFC_FLOGI:
		case LPFC_FABRIC_CFG_LINK:
		case LPFC_NS_REG:
		case LPFC_NS_QRY:
		case LPFC_BUILD_DISC_LIST:
		case LPFC_DISC_AUTH:
			len += snprintf(buf + len, PAGE_SIZE - len,
					"Discovery\n");
			break;
		case LPFC_VPORT_READY:
			len += snprintf(buf + len, PAGE_SIZE - len, "Ready\n");
			break;

		case LPFC_VPORT_FAILED:
			len += snprintf(buf + len, PAGE_SIZE - len, "Failed\n");
			break;

		case LPFC_VPORT_UNKNOWN:
			len += snprintf(buf + len, PAGE_SIZE - len,
					"Unknown\n");
			break;
		}
		if (phba->sli.sli_flag & LPFC_MENLO_MAINT)
			len += snprintf(buf + len, PAGE_SIZE-len,
					"   Menlo Maint Mode\n");
		else if (phba->fc_topology == TOPOLOGY_LOOP) {
			if (vport->fc_flag & FC_PUBLIC_LOOP)
				len += snprintf(buf + len, PAGE_SIZE-len,
						"   Public Loop\n");
			else
				len += snprintf(buf + len, PAGE_SIZE-len,
						"   Private Loop\n");
		} else {
			if (vport->fc_flag & FC_FABRIC)
				len += snprintf(buf + len, PAGE_SIZE-len,
						"   Fabric\n");
			else
				len += snprintf(buf + len, PAGE_SIZE-len,
						"   Point-2-Point\n");
		}
	}

	return len;
}

/**
 * lpfc_num_discovered_ports_show - Return sum of mapped and unmapped vports
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the sum of fc mapped and unmapped.
 *
 * Description:
 * Returns the ascii text number of the sum of the fc mapped and unmapped
 * vport counts.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_num_discovered_ports_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;

	return snprintf(buf, PAGE_SIZE, "%d\n",
			vport->fc_map_cnt + vport->fc_unmap_cnt);
}

/**
 * lpfc_issue_lip - Misnomer, name carried over from long ago
 * @shost: Scsi_Host pointer.
 *
 * Description:
 * Bring the link down gracefully then re-init the link. The firmware will
 * re-init the fiber channel interface as required. Does not issue a LIP.
 *
 * Returns:
 * -EPERM port offline or management commands are being blocked
 * -ENOMEM cannot allocate memory for the mailbox command
 * -EIO error sending the mailbox command
 * zero for success
 **/
static int
lpfc_issue_lip(struct Scsi_Host *shost)
{
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	LPFC_MBOXQ_t *pmboxq;
	int mbxstatus = MBXERR_ERROR;

	if ((vport->fc_flag & FC_OFFLINE_MODE) ||
	    (phba->sli.sli_flag & LPFC_BLOCK_MGMT_IO))
		return -EPERM;

	pmboxq = mempool_alloc(phba->mbox_mem_pool,GFP_KERNEL);

	if (!pmboxq)
		return -ENOMEM;

	memset((void *)pmboxq, 0, sizeof (LPFC_MBOXQ_t));
	pmboxq->u.mb.mbxCommand = MBX_DOWN_LINK;
	pmboxq->u.mb.mbxOwner = OWN_HOST;

	mbxstatus = lpfc_sli_issue_mbox_wait(phba, pmboxq, LPFC_MBOX_TMO * 2);

	if ((mbxstatus == MBX_SUCCESS) &&
	    (pmboxq->u.mb.mbxStatus == 0 ||
	     pmboxq->u.mb.mbxStatus == MBXERR_LINK_DOWN)) {
		memset((void *)pmboxq, 0, sizeof (LPFC_MBOXQ_t));
		lpfc_init_link(phba, pmboxq, phba->cfg_topology,
			       phba->cfg_link_speed);
		mbxstatus = lpfc_sli_issue_mbox_wait(phba, pmboxq,
						     phba->fc_ratov * 2);
	}

	lpfc_set_loopback_flag(phba);
	if (mbxstatus != MBX_TIMEOUT)
		mempool_free(pmboxq, phba->mbox_mem_pool);

	if (mbxstatus == MBXERR_ERROR)
		return -EIO;

	return 0;
}

/**
 * lpfc_do_offline - Issues a mailbox command to bring the link down
 * @phba: lpfc_hba pointer.
 * @type: LPFC_EVT_OFFLINE, LPFC_EVT_WARM_START, LPFC_EVT_KILL.
 *
 * Notes:
 * Assumes any error from lpfc_do_offline() will be negative.
 * Can wait up to 5 seconds for the port ring buffers count
 * to reach zero, prints a warning if it is not zero and continues.
 * lpfc_workq_post_event() returns a non-zero return code if call fails.
 *
 * Returns:
 * -EIO error posting the event
 * zero for success
 **/
static int
lpfc_do_offline(struct lpfc_hba *phba, uint32_t type)
{
	struct completion online_compl;
	struct lpfc_sli_ring *pring;
	struct lpfc_sli *psli;
	int status = 0;
	int cnt = 0;
	int i;

	init_completion(&online_compl);
	lpfc_workq_post_event(phba, &status, &online_compl,
			      LPFC_EVT_OFFLINE_PREP);
	wait_for_completion(&online_compl);

	if (status != 0)
		return -EIO;

	psli = &phba->sli;

	/* Wait a little for things to settle down, but not
	 * long enough for dev loss timeout to expire.
	 */
	for (i = 0; i < psli->num_rings; i++) {
		pring = &psli->ring[i];
		while (pring->txcmplq_cnt) {
			msleep(10);
			if (cnt++ > 500) {  /* 5 secs */
				lpfc_printf_log(phba,
					KERN_WARNING, LOG_INIT,
					"0466 Outstanding IO when "
					"bringing Adapter offline\n");
				break;
			}
		}
	}

	init_completion(&online_compl);
	lpfc_workq_post_event(phba, &status, &online_compl, type);
	wait_for_completion(&online_compl);

	if (status != 0)
		return -EIO;

	return 0;
}

/**
 * lpfc_selective_reset - Offline then onlines the port
 * @phba: lpfc_hba pointer.
 *
 * Description:
 * If the port is configured to allow a reset then the hba is brought
 * offline then online.
 *
 * Notes:
 * Assumes any error from lpfc_do_offline() will be negative.
 *
 * Returns:
 * lpfc_do_offline() return code if not zero
 * -EIO reset not configured or error posting the event
 * zero for success
 **/
int
lpfc_selective_reset(struct lpfc_hba *phba)
{
	struct completion online_compl;
	int status = 0;

	if (!phba->cfg_enable_hba_reset)
		return -EIO;

	status = lpfc_do_offline(phba, LPFC_EVT_OFFLINE);

	if (status != 0)
		return status;

	init_completion(&online_compl);
	lpfc_workq_post_event(phba, &status, &online_compl, LPFC_EVT_ONLINE);
	wait_for_completion(&online_compl);

	if (status != 0)
		return -EIO;

	return 0;
}

/**
 * lpfc_issue_reset - Selectively resets an adapter
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: containing the string "selective".
 * @count: unused variable.
 *
 * Description:
 * If the buf contains the string "selective" then lpfc_selective_reset()
 * is called to perform the reset.
 *
 * Notes:
 * Assumes any error from lpfc_selective_reset() will be negative.
 * If lpfc_selective_reset() returns zero then the length of the buffer
 * is returned which indicates succcess
 *
 * Returns:
 * -EINVAL if the buffer does not contain the string "selective"
 * length of buf if lpfc-selective_reset() if the call succeeds
 * return value of lpfc_selective_reset() if the call fails
**/
static ssize_t
lpfc_issue_reset(struct class_device *cdev, const char *buf, size_t count)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	int status = -EINVAL;

	if (strncmp(buf, "selective", sizeof("selective") - 1) == 0)
		status = lpfc_selective_reset(phba);

	if (status == 0)
		return strlen(buf);
	else
		return status;
}

/**
 * lpfc_nport_evt_cnt_show - Return the number of nport events
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the ascii number of nport events.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_nport_evt_cnt_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	return snprintf(buf, PAGE_SIZE, "%d\n", phba->nport_event_cnt);
}

/**
 * lpfc_board_mode_show - Return the state of the board
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the state of the adapter.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_board_mode_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	char  * state;

	if (phba->link_state == LPFC_HBA_ERROR)
		state = "error";
	else if (phba->link_state == LPFC_WARM_START)
		state = "warm start";
	else if (phba->link_state == LPFC_INIT_START)
		state = "offline";
	else
		state = "online";

	return snprintf(buf, PAGE_SIZE, "%s\n", state);
}

/**
 * lpfc_board_mode_store - Puts the hba in online, offline, warm or error state
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: containing one of the strings "online", "offline", "warm" or "error".
 * @count: unused variable.
 *
 * Returns:
 * -EACCES if enable hba reset not enabled
 * -EINVAL if the buffer does not contain a valid string (see above)
 * -EIO if lpfc_workq_post_event() or lpfc_do_offline() fails
 * buf length greater than zero indicates success
 **/
static ssize_t
lpfc_board_mode_store(struct class_device *cdev, const char *buf, size_t count)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	struct completion online_compl;
	int status=0;

	if (!phba->cfg_enable_hba_reset)
		return -EACCES;
	init_completion(&online_compl);

	if(strncmp(buf, "online", sizeof("online") - 1) == 0) {
		lpfc_workq_post_event(phba, &status, &online_compl,
				      LPFC_EVT_ONLINE);
		wait_for_completion(&online_compl);
	} else if (strncmp(buf, "offline", sizeof("offline") - 1) == 0)
		status = lpfc_do_offline(phba, LPFC_EVT_OFFLINE);
	else if (strncmp(buf, "warm", sizeof("warm") - 1) == 0)
		if (phba->sli_rev == LPFC_SLI_REV4)
			return -EINVAL;
		else
			status = lpfc_do_offline(phba, LPFC_EVT_WARM_START);
	else if (strncmp(buf, "error", sizeof("error") - 1) == 0)
		if (phba->sli_rev == LPFC_SLI_REV4)
			return -EINVAL;
		else
			status = lpfc_do_offline(phba, LPFC_EVT_KILL);
	else if (strncmp(buf, "remove", sizeof("remove") - 1) == 0 &&
		 vport != phba->pport) {
		status = lpfc_vport_delete(shost);
		complete(&online_compl);
	}
	else
		return -EINVAL;

	if (!status)
		return strlen(buf);
	else
		return -EIO;
}

/**
 * lpfc_get_hba_info - Return various bits of informaton about the adapter
 * @phba: pointer to the adapter structure.
 * @mxri: max xri count.
 * @axri: available xri count.
 * @mrpi: max rpi count.
 * @arpi: available rpi count.
 * @mvpi: max vpi count.
 * @avpi: available vpi count.
 *
 * Description:
 * If an integer pointer for an count is not null then the value for the
 * count is returned.
 *
 * Returns:
 * zero on error
 * one for success
 **/
static int
lpfc_get_hba_info(struct lpfc_hba *phba,
		  uint32_t *mxri, uint32_t *axri,
		  uint32_t *mrpi, uint32_t *arpi,
		  uint32_t *mvpi, uint32_t *avpi)
{
	struct lpfc_sli *psli = &phba->sli;
	struct lpfc_mbx_read_config *rd_config;
	LPFC_MBOXQ_t *pmboxq;
	MAILBOX_t *pmb;
	int rc = 0;

	/*
	 * prevent udev from issuing mailbox commands until the port is
	 * configured.
	 */
	if (phba->link_state < LPFC_LINK_DOWN ||
	    !phba->mbox_mem_pool ||
	    (phba->sli.sli_flag & LPFC_SLI_ACTIVE) == 0)
		return 0;

	if (phba->sli.sli_flag & LPFC_BLOCK_MGMT_IO)
		return 0;

	pmboxq = mempool_alloc(phba->mbox_mem_pool, GFP_KERNEL);
	if (!pmboxq)
		return 0;
	memset(pmboxq, 0, sizeof (LPFC_MBOXQ_t));

	pmb = &pmboxq->u.mb;
	pmb->mbxCommand = MBX_READ_CONFIG;
	pmb->mbxOwner = OWN_HOST;
	pmboxq->context1 = NULL;

	if ((phba->pport->fc_flag & FC_OFFLINE_MODE) ||
		(!(psli->sli_flag & LPFC_SLI_ACTIVE)))
		rc = MBX_NOT_FINISHED;
	else
		rc = lpfc_sli_issue_mbox_wait(phba, pmboxq, phba->fc_ratov * 2);

	if (rc != MBX_SUCCESS) {
		if (rc != MBX_TIMEOUT)
			mempool_free(pmboxq, phba->mbox_mem_pool);
		return 0;
	}

	if (phba->sli_rev == LPFC_SLI_REV4) {
		rd_config = &pmboxq->u.mqe.un.rd_config;
		if (mrpi)
			*mrpi = bf_get(lpfc_mbx_rd_conf_rpi_count, rd_config);
		if (arpi)
			*arpi = bf_get(lpfc_mbx_rd_conf_rpi_count, rd_config) -
					phba->sli4_hba.max_cfg_param.rpi_used;
		if (mxri)
			*mxri = bf_get(lpfc_mbx_rd_conf_xri_count, rd_config);
		if (axri)
			*axri = bf_get(lpfc_mbx_rd_conf_xri_count, rd_config) -
					phba->sli4_hba.max_cfg_param.xri_used;
		if (mvpi)
			*mvpi = bf_get(lpfc_mbx_rd_conf_vpi_count, rd_config);
		if (avpi)
			*avpi = bf_get(lpfc_mbx_rd_conf_vpi_count, rd_config) -
					phba->sli4_hba.max_cfg_param.vpi_used;
	} else {
		if (mrpi)
			*mrpi = pmb->un.varRdConfig.max_rpi;
		if (arpi)
			*arpi = pmb->un.varRdConfig.avail_rpi;
		if (mxri)
			*mxri = pmb->un.varRdConfig.max_xri;
		if (axri)
			*axri = pmb->un.varRdConfig.avail_xri;
		if (mvpi)
			*mvpi = pmb->un.varRdConfig.max_vpi;
		if (avpi)
			*avpi = pmb->un.varRdConfig.avail_vpi;
	}

	mempool_free(pmboxq, phba->mbox_mem_pool);
	return 1;
}

/**
 * lpfc_max_rpi_show - Return maximum rpi
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the maximum rpi count in decimal or "Unknown".
 *
 * Description:
 * Calls lpfc_get_hba_info() asking for just the mrpi count.
 * If lpfc_get_hba_info() returns zero (failure) the buffer text is set
 * to "Unknown" and the buffer length is returned, therefore the caller
 * must check for "Unknown" in the buffer to detect a failure.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_max_rpi_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	uint32_t cnt;

	if (lpfc_get_hba_info(phba, NULL, NULL, &cnt, NULL, NULL, NULL))
		return snprintf(buf, PAGE_SIZE, "%d\n", cnt);
	return snprintf(buf, PAGE_SIZE, "Unknown\n");
}

/**
 * lpfc_used_rpi_show - Return maximum rpi minus available rpi
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: containing the used rpi count in decimal or "Unknown".
 *
 * Description:
 * Calls lpfc_get_hba_info() asking for just the mrpi and arpi counts.
 * If lpfc_get_hba_info() returns zero (failure) the buffer text is set
 * to "Unknown" and the buffer length is returned, therefore the caller
 * must check for "Unknown" in the buffer to detect a failure.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_used_rpi_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	uint32_t cnt, acnt;

	if (lpfc_get_hba_info(phba, NULL, NULL, &cnt, &acnt, NULL, NULL))
		return snprintf(buf, PAGE_SIZE, "%d\n", (cnt - acnt));
	return snprintf(buf, PAGE_SIZE, "Unknown\n");
}

/**
 * lpfc_max_xri_show - Return maximum xri
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the maximum xri count in decimal or "Unknown".
 *
 * Description:
 * Calls lpfc_get_hba_info() asking for just the mrpi count.
 * If lpfc_get_hba_info() returns zero (failure) the buffer text is set
 * to "Unknown" and the buffer length is returned, therefore the caller
 * must check for "Unknown" in the buffer to detect a failure.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_max_xri_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	uint32_t cnt;

	if (lpfc_get_hba_info(phba, &cnt, NULL, NULL, NULL, NULL, NULL))
		return snprintf(buf, PAGE_SIZE, "%d\n", cnt);
	return snprintf(buf, PAGE_SIZE, "Unknown\n");
}

/**
 * lpfc_used_xri_show - Return maximum xpi minus the available xpi
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the used xri count in decimal or "Unknown".
 *
 * Description:
 * Calls lpfc_get_hba_info() asking for just the mxri and axri counts.
 * If lpfc_get_hba_info() returns zero (failure) the buffer text is set
 * to "Unknown" and the buffer length is returned, therefore the caller
 * must check for "Unknown" in the buffer to detect a failure.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_used_xri_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	uint32_t cnt, acnt;

	if (lpfc_get_hba_info(phba, &cnt, &acnt, NULL, NULL, NULL, NULL))
		return snprintf(buf, PAGE_SIZE, "%d\n", (cnt - acnt));
	return snprintf(buf, PAGE_SIZE, "Unknown\n");
}

/**
 * lpfc_max_vpi_show - Return maximum vpi
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the maximum vpi count in decimal or "Unknown".
 *
 * Description:
 * Calls lpfc_get_hba_info() asking for just the mvpi count.
 * If lpfc_get_hba_info() returns zero (failure) the buffer text is set
 * to "Unknown" and the buffer length is returned, therefore the caller
 * must check for "Unknown" in the buffer to detect a failure.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_max_vpi_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	uint32_t cnt;

	if (lpfc_get_hba_info(phba, NULL, NULL, NULL, NULL, &cnt, NULL))
		return snprintf(buf, PAGE_SIZE, "%d\n", cnt);
	return snprintf(buf, PAGE_SIZE, "Unknown\n");
}

/**
 * lpfc_used_vpi_show - Return maximum vpi minus the available vpi
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the used vpi count in decimal or "Unknown".
 *
 * Description:
 * Calls lpfc_get_hba_info() asking for just the mvpi and avpi counts.
 * If lpfc_get_hba_info() returns zero (failure) the buffer text is set
 * to "Unknown" and the buffer length is returned, therefore the caller
 * must check for "Unknown" in the buffer to detect a failure.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_used_vpi_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	uint32_t cnt, acnt;

	if (lpfc_get_hba_info(phba, NULL, NULL, NULL, NULL, &cnt, &acnt))
		return snprintf(buf, PAGE_SIZE, "%d\n", (cnt - acnt));
	return snprintf(buf, PAGE_SIZE, "Unknown\n");
}

/**
 * lpfc_npiv_info_show - Return text about NPIV support for the adapter
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: text that must be interpreted to determine if npiv is supported.
 *
 * Description:
 * Buffer will contain text indicating npiv is not suppoerted on the port,
 * the port is an NPIV physical port, or it is an npiv virtual port with
 * the id of the vport.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_npiv_info_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	if (!(phba->max_vpi))
		return snprintf(buf, PAGE_SIZE, "NPIV Not Supported\n");
	if (vport->port_type == LPFC_PHYSICAL_PORT)
		return snprintf(buf, PAGE_SIZE, "NPIV Physical\n");
	return snprintf(buf, PAGE_SIZE, "NPIV Virtual (VPI %d)\n", vport->vpi);
}

/**
 * lpfc_poll_show - Return text about poll support for the adapter
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the cfg_poll in hex.
 *
 * Notes:
 * cfg_poll should be a lpfc_polling_flags type.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_poll_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	return snprintf(buf, PAGE_SIZE, "%#x\n", phba->cfg_poll);
}

/**
 * lpfc_poll_store - Set the value of cfg_poll for the adapter
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: one or more lpfc_polling_flags values.
 * @count: not used.
 *
 * Notes:
 * buf contents converted to integer and checked for a valid value.
 *
 * Returns:
 * -EINVAL if the buffer connot be converted or is out of range
 * length of the buf on success
 **/
static ssize_t
lpfc_poll_store(struct class_device *cdev, const char *buf,
		size_t count)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	uint32_t creg_val;
	uint32_t old_val;
	int val=0;

	if (!isdigit(buf[0]))
		return -EINVAL;

	if (sscanf(buf, "%i", &val) != 1)
		return -EINVAL;

	if ((val & 0x3) != val)
		return -EINVAL;

	if (phba->sli_rev == LPFC_SLI_REV4)
		val = 0;

	spin_lock_irq(&phba->hbalock);

	old_val = phba->cfg_poll;

	if (val & ENABLE_FCP_RING_POLLING) {
		if ((val & DISABLE_FCP_RING_INT) &&
		    !(old_val & DISABLE_FCP_RING_INT)) {
			creg_val = readl(phba->HCregaddr);
			creg_val &= ~(HC_R0INT_ENA << LPFC_FCP_RING);
			writel(creg_val, phba->HCregaddr);
			readl(phba->HCregaddr); /* flush */

			lpfc_poll_start_timer(phba);
		}
	} else if (val != 0x0) {
		spin_unlock_irq(&phba->hbalock);
		return -EINVAL;
	}

	if (!(val & DISABLE_FCP_RING_INT) &&
	    (old_val & DISABLE_FCP_RING_INT))
	{
		spin_unlock_irq(&phba->hbalock);
		del_timer(&phba->fcp_poll_timer);
		spin_lock_irq(&phba->hbalock);
		creg_val = readl(phba->HCregaddr);
		creg_val |= (HC_R0INT_ENA << LPFC_FCP_RING);
		writel(creg_val, phba->HCregaddr);
		readl(phba->HCregaddr); /* flush */
	}

	phba->cfg_poll = val;

	spin_unlock_irq(&phba->hbalock);

	return strlen(buf);
}

static ssize_t
lpfc_auth_state_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	switch (vport->auth.auth_state) {
	case LPFC_AUTH_UNKNOWN:
		if (vport->auth.auth_msg_state == LPFC_AUTH_NEGOTIATE ||
		    vport->auth.auth_msg_state == LPFC_DHCHAP_CHALLENGE ||
		    vport->auth.auth_msg_state == LPFC_DHCHAP_REPLY ||
		    vport->auth.auth_msg_state == LPFC_DHCHAP_SUCCESS_REPLY)
			return snprintf(buf, PAGE_SIZE, "Authenticating\n");
		else
			return snprintf(buf, PAGE_SIZE, "Not Authenticated\n");
	case LPFC_AUTH_FAIL:
		return snprintf(buf, PAGE_SIZE, "Failed\n");
	case LPFC_AUTH_SUCCESS:
		if (vport->auth.auth_msg_state == LPFC_AUTH_NEGOTIATE ||
		    vport->auth.auth_msg_state == LPFC_DHCHAP_CHALLENGE ||
		    vport->auth.auth_msg_state == LPFC_DHCHAP_REPLY ||
		    vport->auth.auth_msg_state == LPFC_DHCHAP_SUCCESS_REPLY)
			return snprintf(buf, PAGE_SIZE, "Authenticating\n");
		else if (vport->auth.auth_msg_state == LPFC_DHCHAP_SUCCESS)
			return snprintf(buf, PAGE_SIZE, "Authenticated\n");
	}
	return snprintf(buf, PAGE_SIZE, "Unknown\n");
}

static ssize_t
lpfc_auth_dir_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	if (!vport->cfg_enable_auth ||
	    vport->auth.auth_state != LPFC_AUTH_SUCCESS)
		return snprintf(buf, PAGE_SIZE, "Unknown\n");
	if (vport->auth.direction == AUTH_DIRECTION_LOCAL)
		return snprintf(buf, PAGE_SIZE, "Local Authenticated\n");
	else if (vport->auth.direction == AUTH_DIRECTION_REMOTE)
		return snprintf(buf, PAGE_SIZE, "Remote Authenticated\n");
	else if (vport->auth.direction == AUTH_DIRECTION_BIDI)
		return snprintf(buf, PAGE_SIZE, "Bidi Authentication\n");
	return snprintf(buf, PAGE_SIZE, "Unknown\n");
}

static ssize_t
lpfc_auth_protocol_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	if (vport->cfg_enable_auth &&
	    vport->auth.auth_state == LPFC_AUTH_SUCCESS)
		return snprintf(buf, PAGE_SIZE, "1 (DH-CHAP)\n");
	else
		return snprintf(buf, PAGE_SIZE, "Unknown\n");
}

static ssize_t
lpfc_auth_dhgroup_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	if (!vport->cfg_enable_auth ||
	    vport->auth.auth_state != LPFC_AUTH_SUCCESS)
		return snprintf(buf, PAGE_SIZE, "Unknown\n");
	switch (vport->auth.group_id) {
	case DH_GROUP_NULL:
		return snprintf(buf, PAGE_SIZE, "0 (NULL)\n");
	case DH_GROUP_1024:
		return snprintf(buf, PAGE_SIZE, "1 (1024)\n");
	case DH_GROUP_1280:
		return snprintf(buf, PAGE_SIZE, "2 (1280)\n");
	case DH_GROUP_1536:
		return snprintf(buf, PAGE_SIZE, "3 (1536)\n");
	case DH_GROUP_2048:
		return snprintf(buf, PAGE_SIZE, "4 (2048)\n");
	}
	return snprintf(buf, PAGE_SIZE, "%d (Unrecognized)\n",
			vport->auth.group_id);
}

static ssize_t
lpfc_auth_hash_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	if (!vport->cfg_enable_auth ||
	    vport->auth.auth_state != LPFC_AUTH_SUCCESS)
		return snprintf(buf, PAGE_SIZE, "Unknown\n");
	switch (vport->auth.hash_id) {
	case FC_SP_HASH_MD5:
		return snprintf(buf, PAGE_SIZE, "5 (MD5)\n");
	case FC_SP_HASH_SHA1:
		return snprintf(buf, PAGE_SIZE, "6 (SHA1)\n");
	}
	return snprintf(buf, PAGE_SIZE, "%d (Unrecognized)\n",
			vport->auth.hash_id);
}
static ssize_t
lpfc_auth_last_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct timeval last_time;
	if (!vport->cfg_enable_auth || vport->auth.last_auth == 0)
		return snprintf(buf, PAGE_SIZE, "%d\n", -1);
	jiffies_to_timeval((jiffies - vport->auth.last_auth), &last_time);
	return snprintf(buf, PAGE_SIZE, "%ld\n", last_time.tv_sec);
}

static ssize_t
lpfc_auth_next_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	unsigned long next_jiff;
	struct timeval next_time;
	if (!vport->cfg_enable_auth ||
	    vport->auth.last_auth == 0 ||
	    vport->auth.reauth_interval == 0)
		return snprintf(buf, PAGE_SIZE, "%d\n", -1);
	/* calculate the amount of time left until next auth */
	next_jiff = (msecs_to_jiffies(vport->auth.reauth_interval * 60000) +
		     vport->auth.last_auth) - jiffies;
	jiffies_to_timeval(next_jiff, &next_time);
	return snprintf(buf, PAGE_SIZE, "%ld\n", next_time.tv_sec);
}

/**
 * lpfc_param_show - Return a cfg attribute value in decimal
 *
 * Description:
 * Macro that given an attr e.g. hba_queue_depth expands
 * into a function with the name lpfc_hba_queue_depth_show.
 *
 * lpfc_##attr##_show: Return the decimal value of an adapters cfg_xxx field.
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the attribute value in decimal.
 *
 * Returns: size of formatted string.
 **/
#define lpfc_param_show(attr)	\
static ssize_t \
lpfc_##attr##_show(struct class_device *cdev, char *buf) \
{ \
	struct Scsi_Host  *shost = class_to_shost(cdev);\
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;\
	struct lpfc_hba   *phba = vport->phba;\
	int val = 0;\
	val = phba->cfg_##attr;\
	return snprintf(buf, PAGE_SIZE, "%d\n",\
			phba->cfg_##attr);\
}

/**
 * lpfc_param_hex_show - Return a cfg attribute value in hex
 *
 * Description:
 * Macro that given an attr e.g. hba_queue_depth expands
 * into a function with the name lpfc_hba_queue_depth_show
 *
 * lpfc_##attr##_show: Return the hex value of an adapters cfg_xxx field.
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the attribute value in hexadecimal.
 *
 * Returns: size of formatted string.
 **/
#define lpfc_param_hex_show(attr)	\
static ssize_t \
lpfc_##attr##_show(struct class_device *cdev, char *buf) \
{ \
	struct Scsi_Host  *shost = class_to_shost(cdev);\
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;\
	struct lpfc_hba   *phba = vport->phba;\
	int val = 0;\
	val = phba->cfg_##attr;\
	return snprintf(buf, PAGE_SIZE, "%#x\n",\
			phba->cfg_##attr);\
}

/**
 * lpfc_param_init - Intializes a cfg attribute
 *
 * Description:
 * Macro that given an attr e.g. hba_queue_depth expands
 * into a function with the name lpfc_hba_queue_depth_init. The macro also
 * takes a default argument, a minimum and maximum argument.
 *
 * lpfc_##attr##_init: Initializes an attribute.
 * @phba: pointer the the adapter structure.
 * @val: integer attribute value.
 *
 * Validates the min and max values then sets the adapter config field
 * accordingly, or uses the default if out of range and prints an error message.
 *
 * Returns:
 * zero on success
 * -EINVAL if default used
 **/
#define lpfc_param_init(attr, default, minval, maxval)	\
static int \
lpfc_##attr##_init(struct lpfc_hba *phba, int val) \
{ \
	if (val >= minval && val <= maxval) {\
		phba->cfg_##attr = val;\
		return 0;\
	}\
	lpfc_printf_log(phba, KERN_ERR, LOG_INIT, \
			"0449 lpfc_"#attr" attribute cannot be set to %d, "\
			"allowed range is ["#minval", "#maxval"]\n", val); \
	phba->cfg_##attr = default;\
	return -EINVAL;\
}

/**
 * lpfc_param_set - Set a cfg attribute value
 *
 * Description:
 * Macro that given an attr e.g. hba_queue_depth expands
 * into a function with the name lpfc_hba_queue_depth_set
 *
 * lpfc_##attr##_set: Sets an attribute value.
 * @phba: pointer the the adapter structure.
 * @val: integer attribute value.
 *
 * Description:
 * Validates the min and max values then sets the
 * adapter config field if in the valid range. prints error message
 * and does not set the parameter if invalid.
 *
 * Returns:
 * zero on success
 * -EINVAL if val is invalid
 **/
#define lpfc_param_set(attr, default, minval, maxval)	\
static int \
lpfc_##attr##_set(struct lpfc_hba *phba, int val) \
{ \
	if (val >= minval && val <= maxval) {\
		phba->cfg_##attr = val;\
		return 0;\
	}\
	lpfc_printf_log(phba, KERN_ERR, LOG_INIT, \
			"0450 lpfc_"#attr" attribute cannot be set to %d, "\
			"allowed range is ["#minval", "#maxval"]\n", val); \
	return -EINVAL;\
}

/**
 * lpfc_param_store - Set a vport attribute value
 *
 * Description:
 * Macro that given an attr e.g. hba_queue_depth expands
 * into a function with the name lpfc_hba_queue_depth_store.
 *
 * lpfc_##attr##_store: Set an sttribute value.
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: contains the attribute value in ascii.
 * @count: not used.
 *
 * Description:
 * Convert the ascii text number to an integer, then
 * use the lpfc_##attr##_set function to set the value.
 *
 * Returns:
 * -EINVAL if val is invalid or lpfc_##attr##_set() fails
 * length of buffer upon success.
 **/
#define lpfc_param_store(attr)	\
static ssize_t \
lpfc_##attr##_store(struct class_device *cdev, const char *buf, size_t count) \
{ \
	struct Scsi_Host  *shost = class_to_shost(cdev);\
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;\
	struct lpfc_hba   *phba = vport->phba;\
	int val=0;\
	if (!isdigit(buf[0]))\
		return -EINVAL;\
	if (sscanf(buf, "%i", &val) != 1)\
		return -EINVAL;\
	if (lpfc_##attr##_set(phba, val) == 0) \
		return strlen(buf);\
	else \
		return -EINVAL;\
}

/**
 * lpfc_vport_param_show - Return decimal formatted cfg attribute value
 *
 * Description:
 * Macro that given an attr e.g. hba_queue_depth expands
 * into a function with the name lpfc_hba_queue_depth_show
 *
 * lpfc_##attr##_show: prints the attribute value in decimal.
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the attribute value in decimal.
 *
 * Returns: length of formatted string.
 **/
#define lpfc_vport_param_show(attr)	\
static ssize_t \
lpfc_##attr##_show(struct class_device *cdev, char *buf) \
{ \
	struct Scsi_Host  *shost = class_to_shost(cdev);\
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;\
	int val = 0;\
	val = vport->cfg_##attr;\
	return snprintf(buf, PAGE_SIZE, "%d\n", vport->cfg_##attr);\
}

/**
 * lpfc_vport_param_hex_show - Return hex formatted attribute value
 *
 * Description:
 * Macro that given an attr e.g.
 * hba_queue_depth expands into a function with the name
 * lpfc_hba_queue_depth_show
 *
 * lpfc_##attr##_show: prints the attribute value in hexadecimal.
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the attribute value in hexadecimal.
 *
 * Returns: length of formatted string.
 **/
#define lpfc_vport_param_hex_show(attr)	\
static ssize_t \
lpfc_##attr##_show(struct class_device *cdev, char *buf) \
{ \
	struct Scsi_Host  *shost = class_to_shost(cdev);\
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;\
	int val = 0;\
	val = vport->cfg_##attr;\
	return snprintf(buf, PAGE_SIZE, "%#x\n", vport->cfg_##attr);\
}

/**
 * lpfc_vport_param_init - Initialize a vport cfg attribute
 *
 * Description:
 * Macro that given an attr e.g. hba_queue_depth expands
 * into a function with the name lpfc_hba_queue_depth_init. The macro also
 * takes a default argument, a minimum and maximum argument.
 *
 * lpfc_##attr##_init: validates the min and max values then sets the
 * adapter config field accordingly, or uses the default if out of range
 * and prints an error message.
 * @phba: pointer the the adapter structure.
 * @val: integer attribute value.
 *
 * Returns:
 * zero on success
 * -EINVAL if default used
 **/
#define lpfc_vport_param_init(attr, default, minval, maxval)	\
static int \
lpfc_##attr##_init(struct lpfc_vport *vport, int val) \
{ \
	if (val >= minval && val <= maxval) {\
		vport->cfg_##attr = val;\
		return 0;\
	}\
	lpfc_printf_vlog(vport, KERN_ERR, LOG_INIT, \
			 "0423 lpfc_"#attr" attribute cannot be set to %d, "\
			 "allowed range is ["#minval", "#maxval"]\n", val); \
	vport->cfg_##attr = default;\
	return -EINVAL;\
}

/**
 * lpfc_vport_param_set - Set a vport cfg attribute
 *
 * Description:
 * Macro that given an attr e.g. hba_queue_depth expands
 * into a function with the name lpfc_hba_queue_depth_set
 *
 * lpfc_##attr##_set: validates the min and max values then sets the
 * adapter config field if in the valid range. prints error message
 * and does not set the parameter if invalid.
 * @phba: pointer the the adapter structure.
 * @val:	integer attribute value.
 *
 * Returns:
 * zero on success
 * -EINVAL if val is invalid
 **/
#define lpfc_vport_param_set(attr, default, minval, maxval)	\
static int \
lpfc_##attr##_set(struct lpfc_vport *vport, int val) \
{ \
	if (val >= minval && val <= maxval) {\
		vport->cfg_##attr = val;\
		return 0;\
	}\
	lpfc_printf_vlog(vport, KERN_ERR, LOG_INIT, \
			 "0424 lpfc_"#attr" attribute cannot be set to %d, "\
			 "allowed range is ["#minval", "#maxval"]\n", val); \
	return -EINVAL;\
}

/**
 * lpfc_vport_param_store - Set a vport attribute
 *
 * Description:
 * Macro that given an attr e.g. hba_queue_depth
 * expands into a function with the name lpfc_hba_queue_depth_store
 *
 * lpfc_##attr##_store: convert the ascii text number to an integer, then
 * use the lpfc_##attr##_set function to set the value.
 * @cdev: class device that is converted into a Scsi_host.
 * @buf:	contains the attribute value in decimal.
 * @count: not used.
 *
 * Returns:
 * -EINVAL if val is invalid or lpfc_##attr##_set() fails
 * length of buffer upon success.
 **/
#define lpfc_vport_param_store(attr)	\
static ssize_t \
lpfc_##attr##_store(struct class_device *cdev, const char *buf, size_t count) \
{ \
	struct Scsi_Host  *shost = class_to_shost(cdev);\
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;\
	int val=0;\
	if (!isdigit(buf[0]))\
		return -EINVAL;\
	if (sscanf(buf, "%i", &val) != 1)\
		return -EINVAL;\
	if (lpfc_##attr##_set(vport, val) == 0) \
		return strlen(buf);\
	else \
		return -EINVAL;\
}

/*
# lpfc_exclude_hba: This parameter contain a list of PCI slots with lpfc HBAs
# 	which need to be excluded from initializing by the driver.
#  Format: <bus>:<slot>.<func>[|<bus>:<slot>.<func>...]
*/
char *lpfc_exclude_hba;
module_param(lpfc_exclude_hba, charp, S_IRUGO);
MODULE_PARM_DESC(lpfc_exclude_hba, "list of lpfc HBA PCI locations"
	" to be excluded from initializing '<bus>:<slot>.<func>' separated by"
	" | character");
static ssize_t
lpfc_exclude_hba_show(struct class_device *dev,	char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n",
		(lpfc_exclude_hba == NULL) ? "" : lpfc_exclude_hba);
}

static CLASS_DEVICE_ATTR(lpfc_exclude_hba, S_IRUGO, lpfc_exclude_hba_show,
		NULL);

#define LPFC_ATTR(name, defval, minval, maxval, desc) \
static int lpfc_##name = defval;\
module_param(lpfc_##name, int, 0);\
MODULE_PARM_DESC(lpfc_##name, desc);\
lpfc_param_init(name, defval, minval, maxval)

#define LPFC_ATTR_R(name, defval, minval, maxval, desc) \
static int lpfc_##name = defval;\
module_param(lpfc_##name, int, 0);\
MODULE_PARM_DESC(lpfc_##name, desc);\
lpfc_param_show(name)\
lpfc_param_init(name, defval, minval, maxval)\
static CLASS_DEVICE_ATTR(lpfc_##name, S_IRUGO , lpfc_##name##_show, NULL)

#define LPFC_ATTR_RW(name, defval, minval, maxval, desc) \
static int lpfc_##name = defval;\
module_param(lpfc_##name, int, 0);\
MODULE_PARM_DESC(lpfc_##name, desc);\
lpfc_param_show(name)\
lpfc_param_init(name, defval, minval, maxval)\
lpfc_param_set(name, defval, minval, maxval)\
lpfc_param_store(name)\
static CLASS_DEVICE_ATTR(lpfc_##name, S_IRUGO | S_IWUSR,\
			 lpfc_##name##_show, lpfc_##name##_store)

#define LPFC_ATTR_HEX_R(name, defval, minval, maxval, desc) \
static int lpfc_##name = defval;\
module_param(lpfc_##name, int, 0);\
MODULE_PARM_DESC(lpfc_##name, desc);\
lpfc_param_hex_show(name)\
lpfc_param_init(name, defval, minval, maxval)\
static CLASS_DEVICE_ATTR(lpfc_##name, S_IRUGO , lpfc_##name##_show, NULL)

#define LPFC_ATTR_HEX_RW(name, defval, minval, maxval, desc) \
static int lpfc_##name = defval;\
module_param(lpfc_##name, int, 0);\
MODULE_PARM_DESC(lpfc_##name, desc);\
lpfc_param_hex_show(name)\
lpfc_param_init(name, defval, minval, maxval)\
lpfc_param_set(name, defval, minval, maxval)\
lpfc_param_store(name)\
static CLASS_DEVICE_ATTR(lpfc_##name, S_IRUGO | S_IWUSR,\
			 lpfc_##name##_show, lpfc_##name##_store)

#define LPFC_VPORT_ATTR(name, defval, minval, maxval, desc) \
static int lpfc_##name = defval;\
module_param(lpfc_##name, int, 0);\
MODULE_PARM_DESC(lpfc_##name, desc);\
lpfc_vport_param_init(name, defval, minval, maxval)

#define LPFC_VPORT_ATTR_R(name, defval, minval, maxval, desc) \
static int lpfc_##name = defval;\
module_param(lpfc_##name, int, 0);\
MODULE_PARM_DESC(lpfc_##name, desc);\
lpfc_vport_param_show(name)\
lpfc_vport_param_init(name, defval, minval, maxval)\
static CLASS_DEVICE_ATTR(lpfc_##name, S_IRUGO , lpfc_##name##_show, NULL)

#define LPFC_VPORT_ATTR_RW(name, defval, minval, maxval, desc) \
static int lpfc_##name = defval;\
module_param(lpfc_##name, int, 0);\
MODULE_PARM_DESC(lpfc_##name, desc);\
lpfc_vport_param_show(name)\
lpfc_vport_param_init(name, defval, minval, maxval)\
lpfc_vport_param_set(name, defval, minval, maxval)\
lpfc_vport_param_store(name)\
static CLASS_DEVICE_ATTR(lpfc_##name, S_IRUGO | S_IWUSR,\
			 lpfc_##name##_show, lpfc_##name##_store)

#define LPFC_VPORT_ATTR_HEX_R(name, defval, minval, maxval, desc) \
static int lpfc_##name = defval;\
module_param(lpfc_##name, int, 0);\
MODULE_PARM_DESC(lpfc_##name, desc);\
lpfc_vport_param_hex_show(name)\
lpfc_vport_param_init(name, defval, minval, maxval)\
static CLASS_DEVICE_ATTR(lpfc_##name, S_IRUGO , lpfc_##name##_show, NULL)

#define LPFC_VPORT_ATTR_HEX_RW(name, defval, minval, maxval, desc) \
static int lpfc_##name = defval;\
module_param(lpfc_##name, int, 0);\
MODULE_PARM_DESC(lpfc_##name, desc);\
lpfc_vport_param_hex_show(name)\
lpfc_vport_param_init(name, defval, minval, maxval)\
lpfc_vport_param_set(name, defval, minval, maxval)\
lpfc_vport_param_store(name)\
static CLASS_DEVICE_ATTR(lpfc_##name, S_IRUGO | S_IWUSR,\
			 lpfc_##name##_show, lpfc_##name##_store)

static CLASS_DEVICE_ATTR(info, S_IRUGO, lpfc_info_show, NULL);
static CLASS_DEVICE_ATTR(serialnum, S_IRUGO, lpfc_serialnum_show, NULL);
static CLASS_DEVICE_ATTR(modeldesc, S_IRUGO, lpfc_modeldesc_show, NULL);
static CLASS_DEVICE_ATTR(modelname, S_IRUGO, lpfc_modelname_show, NULL);
static CLASS_DEVICE_ATTR(programtype, S_IRUGO, lpfc_programtype_show, NULL);
static CLASS_DEVICE_ATTR(portnum, S_IRUGO, lpfc_vportnum_show, NULL);
static CLASS_DEVICE_ATTR(fwrev, S_IRUGO, lpfc_fwrev_show, NULL);
static CLASS_DEVICE_ATTR(hdw, S_IRUGO, lpfc_hdw_show, NULL);
static CLASS_DEVICE_ATTR(state, S_IRUGO, lpfc_state_show, NULL);
static CLASS_DEVICE_ATTR(option_rom_version, S_IRUGO,
					lpfc_option_rom_version_show, NULL);
static CLASS_DEVICE_ATTR(num_discovered_ports, S_IRUGO,
					lpfc_num_discovered_ports_show, NULL);
static CLASS_DEVICE_ATTR(menlo_mgmt_mode, S_IRUGO, lpfc_mlomgmt_show, NULL);
static CLASS_DEVICE_ATTR(nport_evt_cnt, S_IRUGO, lpfc_nport_evt_cnt_show, NULL);
static CLASS_DEVICE_ATTR(lpfc_drvr_version, S_IRUGO, lpfc_drvr_version_show,
			 NULL);
static CLASS_DEVICE_ATTR(management_version, S_IRUGO, management_version_show,
			 NULL);
static CLASS_DEVICE_ATTR(board_mode, S_IRUGO | S_IWUSR,
			 lpfc_board_mode_show, lpfc_board_mode_store);
static CLASS_DEVICE_ATTR(issue_reset, S_IWUSR, NULL, lpfc_issue_reset);
static CLASS_DEVICE_ATTR(max_vpi, S_IRUGO, lpfc_max_vpi_show, NULL);
static CLASS_DEVICE_ATTR(used_vpi, S_IRUGO, lpfc_used_vpi_show, NULL);
static CLASS_DEVICE_ATTR(max_rpi, S_IRUGO, lpfc_max_rpi_show, NULL);
static CLASS_DEVICE_ATTR(used_rpi, S_IRUGO, lpfc_used_rpi_show, NULL);
static CLASS_DEVICE_ATTR(max_xri, S_IRUGO, lpfc_max_xri_show, NULL);
static CLASS_DEVICE_ATTR(used_xri, S_IRUGO, lpfc_used_xri_show, NULL);
static CLASS_DEVICE_ATTR(npiv_info, S_IRUGO, lpfc_npiv_info_show, NULL);
static CLASS_DEVICE_ATTR(lpfc_temp_sensor, S_IRUGO, lpfc_temp_sensor_show,
			 NULL);
static CLASS_DEVICE_ATTR(auth_state, S_IRUGO, lpfc_auth_state_show, NULL);
static CLASS_DEVICE_ATTR(auth_dir, S_IRUGO, lpfc_auth_dir_show, NULL);
static CLASS_DEVICE_ATTR(auth_protocol, S_IRUGO, lpfc_auth_protocol_show, NULL);
static CLASS_DEVICE_ATTR(auth_dhgroup, S_IRUGO, lpfc_auth_dhgroup_show, NULL);
static CLASS_DEVICE_ATTR(auth_hash, S_IRUGO, lpfc_auth_hash_show, NULL);
static CLASS_DEVICE_ATTR(auth_last, S_IRUGO, lpfc_auth_last_show, NULL);
static CLASS_DEVICE_ATTR(auth_next, S_IRUGO, lpfc_auth_next_show, NULL);
static CLASS_DEVICE_ATTR(lpfc_enable_fip, S_IRUGO, lpfc_enable_fip_show, NULL);

static int
lpfc_parse_wwn(const char *ns, uint8_t *nm)
{
	unsigned int i, j;
	memset(nm, 0, 8);

	/* Validate and store the new name */
	for (i=0, j=0; i < 16; i++) {
		if ((*ns >= 'a') && (*ns <= 'f'))
			j = ((j << 4) | ((*ns++ -'a') + 10));
		else if ((*ns >= 'A') && (*ns <= 'F'))
			j = ((j << 4) | ((*ns++ -'A') + 10));
		else if ((*ns >= '0') && (*ns <= '9'))
			j = ((j << 4) | (*ns++ -'0'));
		else
			return -EINVAL;
		if (i % 2) {
			nm[i/2] = j & 0xff;
			j = 0;
		}
	}

	return 0;
}

static ssize_t
lpfc_create_vport(struct class_device *cdev, const char *buf, size_t count)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	uint8_t wwnn[8];
	uint8_t wwpn[8];
	char vname[LPFC_VNAME_LEN + 1];
	uint8_t stat;
	int i = 0;
	int vname_length = 0;

	stat = lpfc_parse_wwn(&buf[i], wwpn);
	if (stat)
		return stat;
	/* The wwnn starts one character after the wwpn */
	i += (sizeof(wwpn) * 2) + 1;
	stat = lpfc_parse_wwn(&buf[i], wwnn);
	if (stat)
		return stat;
	/* The vname starts one character after the wwnn */
	i += (sizeof(wwpn) * 2) + 1;
	/* Skip the null terminator at the end and see how long the vname is */
	if (count > (i + 1)) {
		vname_length = count - (i + 1);
		if (vname_length > LPFC_VNAME_LEN)
			vname_length = LPFC_VNAME_LEN;
		memcpy(vname, &buf[i], vname_length);
	}
	vname[vname_length] = '\0';
	if (lpfc_vport_create(shost, wwnn, wwpn, vname))
		return -EIO;
	return count;
}

static CLASS_DEVICE_ATTR(vport_create, S_IWUSR, NULL, lpfc_create_vport);

static ssize_t
lpfc_delete_vport(struct class_device *cdev, const char *buf, size_t count)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_hba   *phba = ((struct lpfc_vport *)shost->hostdata)->phba;
	uint8_t stat, match;
	uint8_t wwnn[8];
	uint8_t wwpn[8];
	struct lpfc_vport *vport;
	int i = 0;

	stat = lpfc_parse_wwn(&buf[i], wwpn);
	if (stat)
		return stat;
	/* The wwnn starts one character after the wwpn */
	i += (sizeof(wwpn) * 2) + 1;
	stat = lpfc_parse_wwn(&buf[i], wwnn);
	if (stat)
		return stat;

	match = 0;
	spin_lock_irq(&phba->hbalock);
	list_for_each_entry(vport, &phba->port_list, listentry) {
		if ((memcmp(&vport->fc_nodename, &wwnn,
			    sizeof(struct lpfc_name)) == 0) &&
		    (memcmp(&vport->fc_portname, &wwpn,
			    sizeof(struct lpfc_name)) == 0)) {
			match = 1;
			break;
		}
	}
	spin_unlock_irq(&phba->hbalock);
	if (!match)
		return -ENODEV;

	stat = lpfc_vport_delete(lpfc_shost_from_vport(vport));
	return stat ? stat : count;
}

static CLASS_DEVICE_ATTR(vport_delete, S_IWUSR, NULL, lpfc_delete_vport);

static ssize_t
lpfc_npiv_vports_inuse_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_hba   *phba = ((struct lpfc_vport *) shost->hostdata)->phba;
	struct lpfc_vport *vport_curr;
	uint32_t inuse = 0;

	spin_lock_irq(&phba->hbalock);
	list_for_each_entry(vport_curr, &phba->port_list, listentry) {
		if (vport_curr == phba->pport)
			continue;
		inuse++;
	}
	spin_unlock_irq(&phba->hbalock);
	return snprintf(buf, PAGE_SIZE, "%d\n", inuse);
}

static CLASS_DEVICE_ATTR(npiv_vports_inuse, S_IRUGO,
			 lpfc_npiv_vports_inuse_show, NULL);
static CLASS_DEVICE_ATTR(max_npiv_vports, S_IRUGO, lpfc_max_vpi_show, NULL);

static ssize_t
lpfc_symbolic_name_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	int length;
	char symbname[256];

	length = lpfc_vport_symbolic_port_name(vport, symbname, 256);
	return snprintf(buf, PAGE_SIZE, "%s\n", symbname);
}

static CLASS_DEVICE_ATTR(lpfc_symbolic_name, S_IRUGO,
			 lpfc_symbolic_name_show, NULL);

static char *lpfc_soft_wwn_key = "C99G71SL8032A";

/**
 * lpfc_soft_wwn_enable_store - Allows setting of the wwn if the key is valid
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: containing the string lpfc_soft_wwn_key.
 * @count: must be size of lpfc_soft_wwn_key.
 *
 * Returns:
 * -EINVAL if the buffer does not contain lpfc_soft_wwn_key
 * length of buf indicates success
 **/
static ssize_t
lpfc_soft_wwn_enable_store(struct class_device *cdev, const char *buf,
				size_t count)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	unsigned int cnt = count;

	/*
	 * We're doing a simple sanity check for soft_wwpn setting.
	 * We require that the user write a specific key to enable
	 * the soft_wwpn attribute to be settable. Once the attribute
	 * is written, the enable key resets. If further updates are
	 * desired, the key must be written again to re-enable the
	 * attribute.
	 *
	 * The "key" is not secret - it is a hardcoded string shown
	 * here. The intent is to protect against the random user or
	 * application that is just writing attributes.
	 */

	/* count may include a LF at end of string */
	if (buf[cnt-1] == '\n')
		cnt--;

	if ((cnt != strlen(lpfc_soft_wwn_key)) ||
	    (strncmp(buf, lpfc_soft_wwn_key, strlen(lpfc_soft_wwn_key)) != 0))
		return -EINVAL;

	phba->soft_wwn_enable = 1;
	return count;
}
static CLASS_DEVICE_ATTR(lpfc_soft_wwn_enable, S_IWUSR, NULL,
				lpfc_soft_wwn_enable_store);

/**
 * lpfc_soft_wwpn_show - Return the cfg soft ww port name of the adapter
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the wwpn in hexadecimal.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_soft_wwpn_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	return snprintf(buf, PAGE_SIZE, "0x%llx\n",
			(unsigned long long)phba->cfg_soft_wwpn);
}

/**
 * lpfc_soft_wwpn_store - Set the ww port name of the adapter
 * @dev class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: contains the wwpn in hexadecimal.
 * @count: number of wwpn bytes in buf
 *
 * Returns:
 * -EACCES hba reset not enabled, adapter over temp
 * -EINVAL soft wwn not enabled, count is invalid, invalid wwpn byte invalid
 * -EIO error taking adapter offline or online
 * value of count on success
 **/
static ssize_t
lpfc_soft_wwpn_store(struct class_device *cdev, const char *buf, size_t count)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	struct completion online_compl;
	int stat1=0, stat2=0;
	unsigned int i, j, cnt=count;
	u8 wwpn[8];

	if (!phba->cfg_enable_hba_reset)
		return -EACCES;
	spin_lock_irq(&phba->hbalock);
	if (phba->over_temp_state == HBA_OVER_TEMP) {
		spin_unlock_irq(&phba->hbalock);
		return -EACCES;
	}
	spin_unlock_irq(&phba->hbalock);
	/* count may include a LF at end of string */
	if (buf[cnt-1] == '\n')
		cnt--;

	if (!phba->soft_wwn_enable || (cnt < 16) || (cnt > 18) ||
	    ((cnt == 17) && (*buf++ != 'x')) ||
	    ((cnt == 18) && ((*buf++ != '0') || (*buf++ != 'x'))))
		return -EINVAL;

	phba->soft_wwn_enable = 0;

	memset(wwpn, 0, sizeof(wwpn));

	/* Validate and store the new name */
	for (i=0, j=0; i < 16; i++) {
		if ((*buf >= 'a') && (*buf <= 'f'))
			j = ((j << 4) | ((*buf++ -'a') + 10));
		else if ((*buf >= 'A') && (*buf <= 'F'))
			j = ((j << 4) | ((*buf++ -'A') + 10));
		else if ((*buf >= '0') && (*buf <= '9'))
			j = ((j << 4) | (*buf++ -'0'));
		else
			return -EINVAL;
		if (i % 2) {
			wwpn[i/2] = j & 0xff;
			j = 0;
		}
	}
	phba->cfg_soft_wwpn = wwn_to_u64(wwpn);
	fc_host_port_name(shost) = phba->cfg_soft_wwpn;
	if (phba->cfg_soft_wwnn)
		fc_host_node_name(shost) = phba->cfg_soft_wwnn;

	dev_printk(KERN_NOTICE, &phba->pcidev->dev,
		   "lpfc%d: Reinitializing to use soft_wwpn\n", phba->brd_no);

	stat1 = lpfc_do_offline(phba, LPFC_EVT_OFFLINE);
	if (stat1)
		lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
				"0463 lpfc_soft_wwpn attribute set failed to "
				"reinit adapter - %d\n", stat1);
	init_completion(&online_compl);
	lpfc_workq_post_event(phba, &stat2, &online_compl, LPFC_EVT_ONLINE);
	wait_for_completion(&online_compl);
	if (stat2)
		lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
				"0464 lpfc_soft_wwpn attribute set failed to "
				"reinit adapter - %d\n", stat2);
	return (stat1 || stat2) ? -EIO : count;
}
static CLASS_DEVICE_ATTR(lpfc_soft_wwpn, S_IRUGO | S_IWUSR,\
			 lpfc_soft_wwpn_show, lpfc_soft_wwpn_store);

/**
 * lpfc_soft_wwnn_show - Return the cfg soft ww node name for the adapter
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: on return contains the wwnn in hexadecimal.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_soft_wwnn_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct lpfc_hba *phba = ((struct lpfc_vport *)shost->hostdata)->phba;
	return snprintf(buf, PAGE_SIZE, "0x%llx\n",
			(unsigned long long)phba->cfg_soft_wwnn);
}

/**
 * lpfc_soft_wwnn_store - sets the ww node name of the adapter
 * @cdev: class device that is converted into a Scsi_host.
 * @buf: contains the ww node name in hexadecimal.
 * @count: number of wwnn bytes in buf.
 *
 * Returns:
 * -EINVAL soft wwn not enabled, count is invalid, invalid wwnn byte invalid
 * value of count on success
 **/
static ssize_t
lpfc_soft_wwnn_store(struct class_device *cdev, const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct lpfc_hba *phba = ((struct lpfc_vport *)shost->hostdata)->phba;
	unsigned int i, j, cnt=count;
	u8 wwnn[8];

	/* count may include a LF at end of string */
	if (buf[cnt-1] == '\n')
		cnt--;

	if (!phba->soft_wwn_enable || (cnt < 16) || (cnt > 18) ||
	    ((cnt == 17) && (*buf++ != 'x')) ||
	    ((cnt == 18) && ((*buf++ != '0') || (*buf++ != 'x'))))
		return -EINVAL;

	/*
	 * Allow wwnn to be set many times, as long as the enable is set.
	 * However, once the wwpn is set, everything locks.
	 */

	memset(wwnn, 0, sizeof(wwnn));

	/* Validate and store the new name */
	for (i=0, j=0; i < 16; i++) {
		if ((*buf >= 'a') && (*buf <= 'f'))
			j = ((j << 4) | ((*buf++ -'a') + 10));
		else if ((*buf >= 'A') && (*buf <= 'F'))
			j = ((j << 4) | ((*buf++ -'A') + 10));
		else if ((*buf >= '0') && (*buf <= '9'))
			j = ((j << 4) | (*buf++ -'0'));
		else
			return -EINVAL;
		if (i % 2) {
			wwnn[i/2] = j & 0xff;
			j = 0;
		}
	}
	phba->cfg_soft_wwnn = wwn_to_u64(wwnn);

	dev_printk(KERN_NOTICE, &phba->pcidev->dev,
		   "lpfc%d: soft_wwnn set. Value will take effect upon "
		   "setting of the soft_wwpn\n", phba->brd_no);

	return count;
}
static CLASS_DEVICE_ATTR(lpfc_soft_wwnn, S_IRUGO | S_IWUSR,\
			 lpfc_soft_wwnn_show, lpfc_soft_wwnn_store);


static int lpfc_poll = 0;
module_param(lpfc_poll, int, 0);
MODULE_PARM_DESC(lpfc_poll, "FCP ring polling mode control:"
		 " 0 - none,"
		 " 1 - poll with interrupts enabled"
		 " 3 - poll and disable FCP ring interrupts");

static CLASS_DEVICE_ATTR(lpfc_poll, S_IRUGO | S_IWUSR,
			 lpfc_poll_show, lpfc_poll_store);

int  lpfc_sli_mode = 0;
module_param(lpfc_sli_mode, int, 0);
MODULE_PARM_DESC(lpfc_sli_mode, "SLI mode selector:"
		 " 0 - auto (SLI-3 if supported),"
		 " 2 - select SLI-2 even on SLI-3 capable HBAs,"
		 " 3 - select SLI-3");

int lpfc_enable_npiv = 0;
module_param(lpfc_enable_npiv, int, 0);
MODULE_PARM_DESC(lpfc_enable_npiv, "Enable NPIV functionality");
lpfc_param_show(enable_npiv);
lpfc_param_init(enable_npiv, 0, 0, 1);
static CLASS_DEVICE_ATTR(lpfc_enable_npiv, S_IRUGO,
			 lpfc_enable_npiv_show, NULL);

/*
# lpfc_nodev_tmo: If set, it will hold all I/O errors on devices that disappear
# until the timer expires. Value range is [0,255]. Default value is 30.
*/
static int lpfc_nodev_tmo = LPFC_DEF_DEVLOSS_TMO;
static int lpfc_devloss_tmo = LPFC_DEF_DEVLOSS_TMO;
module_param(lpfc_nodev_tmo, int, 0);
MODULE_PARM_DESC(lpfc_nodev_tmo,
		 "Seconds driver will hold I/O waiting "
		 "for a device to come back");

/**
 * lpfc_nodev_tmo_show - Return the hba dev loss timeout value
 * @dev: class converted to a Scsi_host structure.
 * @attr: device attribute, not used.
 * @buf: on return contains the dev loss timeout in decimal.
 *
 * Returns: size of formatted string.
 **/
static ssize_t
lpfc_nodev_tmo_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	int val = 0;
	val = vport->cfg_devloss_tmo;
	return snprintf(buf, PAGE_SIZE, "%d\n",	vport->cfg_devloss_tmo);
}

/**
 * lpfc_nodev_tmo_init - Set the hba nodev timeout value
 * @vport: lpfc vport structure pointer.
 * @val: contains the nodev timeout value.
 *
 * Description:
 * If the devloss tmo is already set then nodev tmo is set to devloss tmo,
 * a kernel error message is printed and zero is returned.
 * Else if val is in range then nodev tmo and devloss tmo are set to val.
 * Otherwise nodev tmo is set to the default value.
 *
 * Returns:
 * zero if already set or if val is in range
 * -EINVAL val out of range
 **/
static int
lpfc_nodev_tmo_init(struct lpfc_vport *vport, int val)
{
	if (vport->cfg_devloss_tmo != LPFC_DEF_DEVLOSS_TMO) {
		vport->cfg_nodev_tmo = vport->cfg_devloss_tmo;
		if (val != LPFC_DEF_DEVLOSS_TMO)
			lpfc_printf_vlog(vport, KERN_ERR, LOG_INIT,
					 "0407 Ignoring nodev_tmo module "
					 "parameter because devloss_tmo is "
					 "set.\n");
		return 0;
	}

	if (val >= LPFC_MIN_DEVLOSS_TMO && val <= LPFC_MAX_DEVLOSS_TMO) {
		vport->cfg_nodev_tmo = val;
		vport->cfg_devloss_tmo = val;
		return 0;
	}
	lpfc_printf_vlog(vport, KERN_ERR, LOG_INIT,
			 "0400 lpfc_nodev_tmo attribute cannot be set to"
			 " %d, allowed range is [%d, %d]\n",
			 val, LPFC_MIN_DEVLOSS_TMO, LPFC_MAX_DEVLOSS_TMO);
	vport->cfg_nodev_tmo = LPFC_DEF_DEVLOSS_TMO;
	return -EINVAL;
}

/**
 * lpfc_update_rport_devloss_tmo - Update dev loss tmo value
 * @vport: lpfc vport structure pointer.
 *
 * Description:
 * Update all the ndlp's dev loss tmo with the vport devloss tmo value.
 **/
static void
lpfc_update_rport_devloss_tmo(struct lpfc_vport *vport)
{
	struct Scsi_Host  *shost;
	struct lpfc_nodelist  *ndlp;

	shost = lpfc_shost_from_vport(vport);
	spin_lock_irq(shost->host_lock);
	list_for_each_entry(ndlp, &vport->fc_nodes, nlp_listp)
		if (NLP_CHK_NODE_ACT(ndlp) && ndlp->rport)
			ndlp->rport->dev_loss_tmo = vport->cfg_devloss_tmo;
	spin_unlock_irq(shost->host_lock);
}

/**
 * lpfc_nodev_tmo_set - Set the vport nodev tmo and devloss tmo values
 * @vport: lpfc vport structure pointer.
 * @val: contains the tmo value.
 *
 * Description:
 * If the devloss tmo is already set or the vport dev loss tmo has changed
 * then a kernel error message is printed and zero is returned.
 * Else if val is in range then nodev tmo and devloss tmo are set to val.
 * Otherwise nodev tmo is set to the default value.
 *
 * Returns:
 * zero if already set or if val is in range
 * -EINVAL val out of range
 **/
static int
lpfc_nodev_tmo_set(struct lpfc_vport *vport, int val)
{
	if (vport->dev_loss_tmo_changed ||
	    (lpfc_devloss_tmo != LPFC_DEF_DEVLOSS_TMO)) {
		lpfc_printf_vlog(vport, KERN_ERR, LOG_INIT,
				 "0401 Ignoring change to nodev_tmo "
				 "because devloss_tmo is set.\n");
		return 0;
	}
	if (val >= LPFC_MIN_DEVLOSS_TMO && val <= LPFC_MAX_DEVLOSS_TMO) {
		vport->cfg_nodev_tmo = val;
		vport->cfg_devloss_tmo = val;
		lpfc_update_rport_devloss_tmo(vport);
		return 0;
	}
	lpfc_printf_vlog(vport, KERN_ERR, LOG_INIT,
			 "0403 lpfc_nodev_tmo attribute cannot be set to"
			 "%d, allowed range is [%d, %d]\n",
			 val, LPFC_MIN_DEVLOSS_TMO, LPFC_MAX_DEVLOSS_TMO);
	return -EINVAL;
}
lpfc_vport_param_store(nodev_tmo)
static CLASS_DEVICE_ATTR(lpfc_nodev_tmo, S_IRUGO | S_IWUSR,
			 lpfc_nodev_tmo_show, lpfc_nodev_tmo_store);

static ssize_t
lpfc_authenticate (struct class_device *cdev, const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *)shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	struct lpfc_nodelist *ndlp;
	int status;
	struct lpfc_name wwpn;

	if (lpfc_parse_wwn(buf, wwpn.u.wwn))
		return -EINVAL;

	if (vport->port_state == LPFC_VPORT_FAILED) {
		lpfc_issue_lip(shost);
		return strlen(buf);
	}
	if ((vport->fc_flag & FC_OFFLINE_MODE) ||
	    (phba->sli.sli_flag & LPFC_BLOCK_MGMT_IO) ||
	    (!vport->cfg_enable_auth))
		return -EPERM;

	/* If vport already in the middle of authentication do not restart */
	if ((vport->auth.auth_msg_state == LPFC_AUTH_NEGOTIATE) ||
	    (vport->auth.auth_msg_state == LPFC_DHCHAP_CHALLENGE) ||
	    (vport->auth.auth_msg_state == LPFC_DHCHAP_REPLY))
		return -EAGAIN;

	if (wwn_to_u64(wwpn.u.wwn) == AUTH_FABRIC_WWN)
		ndlp = lpfc_findnode_did(vport, Fabric_DID);
	else
		ndlp = lpfc_findnode_wwnn(vport, &wwpn);
	if (!ndlp || !NLP_CHK_NODE_ACT(ndlp))
		return -EPERM;
	status = lpfc_start_node_authentication(ndlp);
	if (status)
		return status;
	return strlen(buf);
}
static CLASS_DEVICE_ATTR(lpfc_authenticate, S_IRUGO | S_IWUSR,
			 NULL, lpfc_authenticate);

static ssize_t
lpfc_update_auth_config (struct class_device *cdev, const char *buf,
			 size_t count)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *)shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	struct lpfc_nodelist *ndlp;
	struct lpfc_name wwpn;
	int status;

	if (lpfc_parse_wwn(buf, wwpn.u.wwn))
		return -EINVAL;

	if ((vport->fc_flag & FC_OFFLINE_MODE) ||
	    (phba->sli.sli_flag & LPFC_BLOCK_MGMT_IO) ||
	    (!vport->cfg_enable_auth))
		return -EPERM;

	/* If vport already in the middle of authentication do not restart */
	if ((vport->auth.auth_msg_state == LPFC_AUTH_NEGOTIATE) ||
	    (vport->auth.auth_msg_state == LPFC_DHCHAP_CHALLENGE) ||
	    (vport->auth.auth_msg_state == LPFC_DHCHAP_REPLY))
		return -EAGAIN;

	if (wwn_to_u64(wwpn.u.wwn) == AUTH_FABRIC_WWN)
		ndlp = lpfc_findnode_did(vport, Fabric_DID);
	else
		ndlp = lpfc_findnode_wwnn(vport, &wwpn);
	if (!ndlp || !NLP_CHK_NODE_ACT(ndlp))
		return -EPERM;
	status = lpfc_get_auth_config(ndlp, &wwpn);
	if (status)
		return -EPERM;
	return strlen(buf);
}
static CLASS_DEVICE_ATTR(lpfc_update_auth_config, S_IRUGO | S_IWUSR,
			 NULL, lpfc_update_auth_config);

/*
# lpfc_devloss_tmo: If set, it will hold all I/O errors on devices that
# disappear until the timer expires. Value range is [0,255]. Default
# value is 30.
*/
module_param(lpfc_devloss_tmo, int, 0);
MODULE_PARM_DESC(lpfc_devloss_tmo,
		 "Seconds driver will hold I/O waiting "
		 "for a device to come back");
lpfc_vport_param_init(devloss_tmo, LPFC_DEF_DEVLOSS_TMO,
		      LPFC_MIN_DEVLOSS_TMO, LPFC_MAX_DEVLOSS_TMO)
lpfc_vport_param_show(devloss_tmo)

/**
 * lpfc_devloss_tmo_set - Sets vport nodev tmo, devloss tmo values, changed bit
 * @vport: lpfc vport structure pointer.
 * @val: contains the tmo value.
 *
 * Description:
 * If val is in a valid range then set the vport nodev tmo,
 * devloss tmo, also set the vport dev loss tmo changed flag.
 * Else a kernel error message is printed.
 *
 * Returns:
 * zero if val is in range
 * -EINVAL val out of range
 **/
static int
lpfc_devloss_tmo_set(struct lpfc_vport *vport, int val)
{
	if (val >= LPFC_MIN_DEVLOSS_TMO && val <= LPFC_MAX_DEVLOSS_TMO) {
		vport->cfg_nodev_tmo = val;
		vport->cfg_devloss_tmo = val;
		vport->dev_loss_tmo_changed = 1;
		lpfc_update_rport_devloss_tmo(vport);
		return 0;
	}

	lpfc_printf_vlog(vport, KERN_ERR, LOG_INIT,
			 "0404 lpfc_devloss_tmo attribute cannot be set to"
			 " %d, allowed range is [%d, %d]\n",
			 val, LPFC_MIN_DEVLOSS_TMO, LPFC_MAX_DEVLOSS_TMO);
	return -EINVAL;
}

lpfc_vport_param_store(devloss_tmo)
static CLASS_DEVICE_ATTR(lpfc_devloss_tmo, S_IRUGO | S_IWUSR,
	lpfc_devloss_tmo_show, lpfc_devloss_tmo_store);

/*
# lpfc_log_verbose: Only turn this flag on if you are willing to risk being
# deluged with LOTS of information.
# You can set a bit mask to record specific types of verbose messages:
#
# LOG_ELS                       0x1        ELS events
# LOG_DISCOVERY                 0x2        Link discovery events
# LOG_MBOX                      0x4        Mailbox events
# LOG_INIT                      0x8        Initialization events
# LOG_LINK_EVENT                0x10       Link events
# LOG_FCP                       0x40       FCP traffic history
# LOG_NODE                      0x80       Node table events
# LOG_MISC                      0x400      Miscellaneous events
# LOG_SLI                       0x800      SLI events
# LOG_FCP_ERROR                 0x1000     Only log FCP errors
# LOG_LIBDFC                    0x2000     LIBDFC events
# LOG_ALL_MSG                   0xffff     LOG all messages
*/
LPFC_VPORT_ATTR_HEX_RW(log_verbose, 0x0, 0x0, 0xffff,
		       "Verbose logging bit-mask");

/*
# lpfc_enable_da_id: This turns on the DA_ID CT command that deregisters
# objects that have been registered with the nameserver after login.
*/
LPFC_VPORT_ATTR_R(enable_da_id, 0, 0, 1,
		  "Deregister nameserver objects before LOGO");

/*
# lun_queue_depth:  This parameter is used to limit the number of outstanding
# commands per FCP LUN. Value range is [1,128]. Default value is 30.
*/
LPFC_VPORT_ATTR_R(lun_queue_depth, 30, 1, 128,
		  "Max number of FCP commands we can queue to a specific LUN");

/*
# hostmem_hgp:  This parameter is used to force driver to keep host group
# pointers in host memory. When the parameter is set to zero, the driver
# keeps the host group pointers in HBA memory otherwise the host group
# pointers are kept in the host memory. Value range is [0,1]. Default value
# is 0.
*/
LPFC_ATTR_R(hostmem_hgp, 0, 0, 1,
	"Use host memory for host group pointers.");

/*
# hba_queue_depth:  This parameter is used to limit the number of outstanding
# commands per lpfc HBA. Value range is [32,8192]. If this parameter
# value is greater than the maximum number of exchanges supported by the HBA,
# then maximum number of exchanges supported by the HBA is used to determine
# the hba_queue_depth.
*/
LPFC_ATTR_R(hba_queue_depth, 8192, 32, 8192,
	    "Max number of FCP commands we can queue to a lpfc HBA");

/*
# peer_port_login:  This parameter allows/prevents logins
# between peer ports hosted on the same physical port.
# When this parameter is set 0 peer ports of same physical port
# are not allowed to login to each other.
# When this parameter is set 1 peer ports of same physical port
# are allowed to login to each other.
# Default value of this parameter is 0.
*/
LPFC_VPORT_ATTR_R(peer_port_login, 0, 0, 1,
		  "Allow peer ports on the same physical port to login to each "
		  "other.");

/*
# restrict_login:  This parameter allows/prevents logins
# between Virtual Ports and remote initiators.
# When this parameter is not set (0) Virtual Ports will accept PLOGIs from
# other initiators and will attempt to PLOGI all remote ports.
# When this parameter is set (1) Virtual Ports will reject PLOGIs from
# remote ports and will not attempt to PLOGI to other initiators.
# This parameter does not restrict to the physical port.
# This parameter does not restrict logins to Fabric resident remote ports.
# Default value of this parameter is 1.
*/
static int lpfc_restrict_login = 1;
module_param(lpfc_restrict_login, int, 0);
MODULE_PARM_DESC(lpfc_restrict_login,
		 "Restrict virtual ports login to remote initiators.");
lpfc_vport_param_show(restrict_login);

/**
 * lpfc_restrict_login_init - Set the vport restrict login flag
 * @vport: lpfc vport structure pointer.
 * @val: contains the restrict login value.
 *
 * Description:
 * If val is not in a valid range then log a kernel error message and set
 * the vport restrict login to one.
 * If the port type is physical clear the restrict login flag and return.
 * Else set the restrict login flag to val.
 *
 * Returns:
 * zero if val is in range
 * -EINVAL val out of range
 **/
static int
lpfc_restrict_login_init(struct lpfc_vport *vport, int val)
{
	if (val < 0 || val > 1) {
		lpfc_printf_vlog(vport, KERN_ERR, LOG_INIT,
				 "0422 lpfc_restrict_login attribute cannot "
				 "be set to %d, allowed range is [0, 1]\n",
				 val);
		vport->cfg_restrict_login = 1;
		return -EINVAL;
	}
	if (vport->port_type == LPFC_PHYSICAL_PORT) {
		vport->cfg_restrict_login = 0;
		return 0;
	}
	vport->cfg_restrict_login = val;
	return 0;
}

/**
 * lpfc_restrict_login_set - Set the vport restrict login flag
 * @vport: lpfc vport structure pointer.
 * @val: contains the restrict login value.
 *
 * Description:
 * If val is not in a valid range then log a kernel error message and set
 * the vport restrict login to one.
 * If the port type is physical and the val is not zero log a kernel
 * error message, clear the restrict login flag and return zero.
 * Else set the restrict login flag to val.
 *
 * Returns:
 * zero if val is in range
 * -EINVAL val out of range
 **/
static int
lpfc_restrict_login_set(struct lpfc_vport *vport, int val)
{
	if (val < 0 || val > 1) {
		lpfc_printf_vlog(vport, KERN_ERR, LOG_INIT,
				 "0425 lpfc_restrict_login attribute cannot "
				 "be set to %d, allowed range is [0, 1]\n",
				 val);
		vport->cfg_restrict_login = 1;
		return -EINVAL;
	}
	if (vport->port_type == LPFC_PHYSICAL_PORT && val != 0) {
		lpfc_printf_vlog(vport, KERN_ERR, LOG_INIT,
				 "0468 lpfc_restrict_login must be 0 for "
				 "Physical ports.\n");
		vport->cfg_restrict_login = 0;
		return 0;
	}
	vport->cfg_restrict_login = val;
	return 0;
}
lpfc_vport_param_store(restrict_login);
static CLASS_DEVICE_ATTR(lpfc_restrict_login, S_IRUGO | S_IWUSR,
			 lpfc_restrict_login_show, lpfc_restrict_login_store);

/*
# Some disk devices have a "select ID" or "select Target" capability.
# From a protocol standpoint "select ID" usually means select the
# Fibre channel "ALPA".  In the FC-AL Profile there is an "informative
# annex" which contains a table that maps a "select ID" (a number
# between 0 and 7F) to an ALPA.  By default, for compatibility with
# older drivers, the lpfc driver scans this table from low ALPA to high
# ALPA.
#
# Turning on the scan-down variable (on  = 1, off = 0) will
# cause the lpfc driver to use an inverted table, effectively
# scanning ALPAs from high to low. Value range is [0,1]. Default value is 1.
#
# (Note: This "select ID" functionality is a LOOP ONLY characteristic
# and will not work across a fabric. Also this parameter will take
# effect only in the case when ALPA map is not available.)
*/
LPFC_VPORT_ATTR_R(scan_down, 1, 0, 1,
		  "Start scanning for devices from highest ALPA to lowest");

/*
# lpfc_topology:  link topology for init link
#            0x0  = attempt loop mode then point-to-point
#            0x01 = internal loopback mode
#            0x02 = attempt point-to-point mode only
#            0x04 = attempt loop mode only
#            0x06 = attempt point-to-point mode then loop
# Set point-to-point mode if you want to run as an N_Port.
# Set loop mode if you want to run as an NL_Port. Value range is [0,0x6].
# Default value is 0.
*/

/**
 * lpfc_topology_set - Set the adapters topology field
 * @phba: lpfc_hba pointer.
 * @val: topology value.
 *
 * Description:
 * If val is in a valid range then set the adapter's topology field and
 * issue a lip; if the lip fails reset the topology to the old value.
 *
 * If the value is not in range log a kernel error message and return an error.
 *
 * Returns:
 * zero if val is in range and lip okay
 * non-zero return value from lpfc_issue_lip()
 * -EINVAL val out of range
 **/
static ssize_t
lpfc_topology_store(struct class_device *cdev, const char *buf, size_t count)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	int val = 0;
	int nolip = 0;
	const char *val_buf = buf;
	int err;
	uint32_t prev_val;

	if (!strncmp(buf, "nolip ", strlen("nolip "))) {
		nolip = 1;
		val_buf = &buf[strlen("nolip ")];
	}

	if (!isdigit(val_buf[0]))
		return -EINVAL;
	if (sscanf(val_buf, "%i", &val) != 1)
		return -EINVAL;

	if (val >= 0 && val <= 6) {
		prev_val = phba->cfg_topology;
		phba->cfg_topology = val;
		if (nolip)
			return strlen(buf);

		err = lpfc_issue_lip(lpfc_shost_from_vport(phba->pport));
		if (err) {
			phba->cfg_topology = prev_val;
			return -EINVAL;
		} else
			return strlen(buf);
	}
	lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
		"%d:0467 lpfc_topology attribute cannot be set to %d, "
		"allowed range is [0, 6]\n",
		phba->brd_no, val);
	return -EINVAL;
}
static int lpfc_topology = 0;
module_param(lpfc_topology, int, 0);
MODULE_PARM_DESC(lpfc_topology, "Select Fibre Channel topology");
lpfc_param_show(topology)
lpfc_param_init(topology, 0, 0, 6)
static CLASS_DEVICE_ATTR(lpfc_topology, S_IRUGO | S_IWUSR,
		lpfc_topology_show, lpfc_topology_store);

/**
 * lpfc_static_vport_show: Read callback function for
 *   lpfc_static_vport sysfs file.
 * @dev: Pointer to class device object.
 * @attr: device attribute structure.
 * @buf: Data buffer.
 *
 * This function is the read call back function for
 * lpfc_static_vport sysfs file. The lpfc_static_vport
 * sysfs file report the mageability of the vport.
 **/
static ssize_t
lpfc_static_vport_show(struct class_device *dev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(dev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	if (vport->vport_flag & STATIC_VPORT)
		sprintf(buf, "1\n");
	else
		sprintf(buf, "0\n");

	return strlen(buf);
}

/*
 * Sysfs attribute to control the statistical data collection.
 */
static CLASS_DEVICE_ATTR(lpfc_static_vport, S_IRUGO,
		   lpfc_static_vport_show, NULL);

/**
 * lpfc_stat_data_ctrl_store - write call back for lpfc_stat_data_ctrl sysfs file
 * @cdev: Pointer to class device.
 * @buf: Data buffer.
 * @count: Size of the data buffer.
 *
 * This function get called when an user write to the lpfc_stat_data_ctrl
 * sysfs file. This function parse the command written to the sysfs file
 * and take appropriate action. These commands are used for controlling
 * driver statistical data collection.
 * Following are the command this function handles.
 *
 *    setbucket <bucket_type> <base> <step>
 *			       = Set the latency buckets.
 *    destroybucket            = destroy all the buckets.
 *    start                    = start data collection
 *    stop                     = stop data collection
 *    reset                    = reset the collected data
 **/
static ssize_t
lpfc_stat_data_ctrl_store(struct class_device *cdev, const char *buf,
		size_t count)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
#define LPFC_MAX_DATA_CTRL_LEN 1024
	static char bucket_data[LPFC_MAX_DATA_CTRL_LEN];
	unsigned long i;
	char *str_ptr, *token;
	struct lpfc_vport **vports;
	struct Scsi_Host *v_shost;
	char *bucket_type_str, *base_str, *step_str;
	unsigned long base, step, bucket_type;

	if (!strncmp(buf, "setbucket", strlen("setbucket"))) {
		if (strlen(buf) > (LPFC_MAX_DATA_CTRL_LEN - 1))
			return -EINVAL;

		strcpy(bucket_data, buf);
		str_ptr = &bucket_data[0];
		/* Ignore this token - this is command token */
		token = strsep(&str_ptr, "\t ");
		if (!token)
			return -EINVAL;

		bucket_type_str = strsep(&str_ptr, "\t ");
		if (!bucket_type_str)
			return -EINVAL;

		if (!strncmp(bucket_type_str, "linear", strlen("linear")))
			bucket_type = LPFC_LINEAR_BUCKET;
		else if (!strncmp(bucket_type_str, "power2", strlen("power2")))
			bucket_type = LPFC_POWER2_BUCKET;
		else
			return -EINVAL;

		base_str = strsep(&str_ptr, "\t ");
		if (!base_str)
			return -EINVAL;
		base = simple_strtoul(base_str, NULL, 0);

		step_str = strsep(&str_ptr, "\t ");
		if (!step_str)
			return -EINVAL;
		step = simple_strtoul(step_str, NULL, 0);
		if (!step)
			return -EINVAL;

		/* Block the data collection for every vport */
		vports = lpfc_create_vport_work_array(phba);
		if (vports == NULL)
			return -ENOMEM;

		for (i = 0; i <= phba->max_vports && vports[i] != NULL; i++) {
			v_shost = lpfc_shost_from_vport(vports[i]);
			spin_lock_irq(v_shost->host_lock);
			/* Block and reset data collection */
			vports[i]->stat_data_blocked = 1;
			if (vports[i]->stat_data_enabled)
				lpfc_vport_reset_stat_data(vports[i]);
			spin_unlock_irq(v_shost->host_lock);
		}

		/* Set the bucket attributes */
		phba->bucket_type = bucket_type;
		phba->bucket_base = base;
		phba->bucket_step = step;

		for (i = 0; i <= phba->max_vports && vports[i] != NULL; i++) {
			v_shost = lpfc_shost_from_vport(vports[i]);

			/* Unblock data collection */
			spin_lock_irq(v_shost->host_lock);
			vports[i]->stat_data_blocked = 0;
			spin_unlock_irq(v_shost->host_lock);
		}
		lpfc_destroy_vport_work_array(phba, vports);
		return strlen(buf);
	}

	if (!strncmp(buf, "destroybucket", strlen("destroybucket"))) {
		vports = lpfc_create_vport_work_array(phba);
		if (vports == NULL)
			return -ENOMEM;

		for (i = 0; i <= phba->max_vports && vports[i] != NULL; i++) {
			v_shost = lpfc_shost_from_vport(vports[i]);
			spin_lock_irq(shost->host_lock);
			vports[i]->stat_data_blocked = 1;
			lpfc_free_bucket(vport);
			vport->stat_data_enabled = 0;
			vports[i]->stat_data_blocked = 0;
			spin_unlock_irq(shost->host_lock);
		}
		lpfc_destroy_vport_work_array(phba, vports);
		phba->bucket_type = LPFC_NO_BUCKET;
		phba->bucket_base = 0;
		phba->bucket_step = 0;
		return strlen(buf);
	}

	if (!strncmp(buf, "start", strlen("start"))) {
		/* If no buckets configured return error */
		if (phba->bucket_type == LPFC_NO_BUCKET)
			return -EINVAL;
		spin_lock_irq(shost->host_lock);
		if (vport->stat_data_enabled) {
			spin_unlock_irq(shost->host_lock);
			return strlen(buf);
		}
		lpfc_alloc_bucket(vport);
		vport->stat_data_enabled = 1;
		spin_unlock_irq(shost->host_lock);
		return strlen(buf);
	}

	if (!strncmp(buf, "stop", strlen("stop"))) {
		spin_lock_irq(shost->host_lock);
		if (vport->stat_data_enabled == 0) {
			spin_unlock_irq(shost->host_lock);
			return strlen(buf);
		}
		lpfc_free_bucket(vport);
		vport->stat_data_enabled = 0;
		spin_unlock_irq(shost->host_lock);
		return strlen(buf);
	}

	if (!strncmp(buf, "reset", strlen("reset"))) {
		if ((phba->bucket_type == LPFC_NO_BUCKET)
			|| !vport->stat_data_enabled)
			return strlen(buf);
		spin_lock_irq(shost->host_lock);
		vport->stat_data_blocked = 1;
		lpfc_vport_reset_stat_data(vport);
		vport->stat_data_blocked = 0;
		spin_unlock_irq(shost->host_lock);
		return strlen(buf);
	}
	return -EINVAL;
}


/**
 * lpfc_stat_data_ctrl_show - Read function for lpfc_stat_data_ctrl sysfs file
 * @cdev: Pointer to class device object.
 * @buf: Data buffer.
 *
 * This function is the read call back function for
 * lpfc_stat_data_ctrl sysfs file. This function report the
 * current statistical data collection state.
 **/
static ssize_t
lpfc_stat_data_ctrl_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	int index = 0;
	int i;
	char *bucket_type;
	unsigned long bucket_value;

	switch (phba->bucket_type) {
	case LPFC_LINEAR_BUCKET:
		bucket_type = "linear";
		break;
	case LPFC_POWER2_BUCKET:
		bucket_type = "power2";
		break;
	default:
		bucket_type = "No Bucket";
		break;
	}

	sprintf(&buf[index], "Statistical Data enabled :%d, "
		"blocked :%d, Bucket type :%s, Bucket base :%d,"
		" Bucket step :%d\nLatency Ranges :",
		vport->stat_data_enabled, vport->stat_data_blocked,
		bucket_type, phba->bucket_base, phba->bucket_step);
	index = strlen(buf);
	if (phba->bucket_type != LPFC_NO_BUCKET) {
		for (i = 0; i < LPFC_MAX_BUCKET_COUNT; i++) {
			if (phba->bucket_type == LPFC_LINEAR_BUCKET)
				bucket_value = phba->bucket_base +
					phba->bucket_step * i;
			else
				bucket_value = phba->bucket_base +
				(1 << i) * phba->bucket_step;

			if (index + 10 > PAGE_SIZE)
				break;
			sprintf(&buf[index], "%08ld ", bucket_value);
			index = strlen(buf);
		}
	}
	sprintf(&buf[index], "\n");
	return strlen(buf);
}

/*
 * Sysfs attribute to control the statistical data collection.
 */
static CLASS_DEVICE_ATTR(lpfc_stat_data_ctrl, S_IRUGO | S_IWUSR,
		   lpfc_stat_data_ctrl_show, lpfc_stat_data_ctrl_store);

/*
 * lpfc_drvr_stat_data: sysfs attr to get driver statistical data.
 */

/*
 * Each Bucket takes 11 characters and 1 new line + 17 bytes WWN
 * for each target.
 */
#define STAT_DATA_SIZE_PER_TARGET(NUM_BUCKETS) ((NUM_BUCKETS) * 11 + 18)
#define MAX_STAT_DATA_SIZE_PER_TARGET \
	STAT_DATA_SIZE_PER_TARGET(LPFC_MAX_BUCKET_COUNT)


/**
 * sysfs_drvr_stat_data_read - Read function for lpfc_drvr_stat_data attribute
 * @kobj: Pointer to the kernel object
 * @bin_attr: Attribute object
 * @buff: Buffer pointer
 * @off: File offset
 * @count: Buffer size
 *
 * This function is the read call back function for lpfc_drvr_stat_data
 * sysfs file. This function export the statistical data to user
 * applications.
 **/
static ssize_t
sysfs_drvr_stat_data_read(struct kobject *kobj, char *buf,
		loff_t off, size_t count)
{
	struct class_device *cdev = container_of(kobj, struct class_device,
		kobj);
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	int i = 0, index = 0;
	unsigned long nport_index;
	struct lpfc_nodelist *ndlp = NULL;
	nport_index = (unsigned long)off /
		MAX_STAT_DATA_SIZE_PER_TARGET;

	if (!vport->stat_data_enabled || vport->stat_data_blocked
		|| (phba->bucket_type == LPFC_NO_BUCKET))
		return 0;

	spin_lock_irq(shost->host_lock);
	list_for_each_entry(ndlp, &vport->fc_nodes, nlp_listp) {
		if (!NLP_CHK_NODE_ACT(ndlp) || !ndlp->lat_data)
			continue;

		if (nport_index > 0) {
			nport_index--;
			continue;
		}

		if ((index + MAX_STAT_DATA_SIZE_PER_TARGET)
			> count)
			break;

		if (!ndlp->lat_data)
			continue;

		/* Print the WWN */
		sprintf(&buf[index], "%02x%02x%02x%02x%02x%02x%02x%02x:",
			ndlp->nlp_portname.u.wwn[0],
			ndlp->nlp_portname.u.wwn[1],
			ndlp->nlp_portname.u.wwn[2],
			ndlp->nlp_portname.u.wwn[3],
			ndlp->nlp_portname.u.wwn[4],
			ndlp->nlp_portname.u.wwn[5],
			ndlp->nlp_portname.u.wwn[6],
			ndlp->nlp_portname.u.wwn[7]);

		index = strlen(buf);

		for (i = 0; i < LPFC_MAX_BUCKET_COUNT; i++) {
			sprintf(&buf[index], "%010u,",
				ndlp->lat_data[i].cmd_count);
			index = strlen(buf);
		}
		sprintf(&buf[index], "\n");
		index = strlen(buf);
	}
	spin_unlock_irq(shost->host_lock);
	return index;
}

static struct bin_attribute sysfs_drvr_stat_data_attr = {
	.attr = {
		.name = "lpfc_drvr_stat_data",
		.mode = S_IRUSR,
		.owner = THIS_MODULE,
	},
	.size = LPFC_MAX_TARGET * MAX_STAT_DATA_SIZE_PER_TARGET,
	.read = sysfs_drvr_stat_data_read,
	.write = NULL,
};

/*
# lpfc_link_speed: Link speed selection for initializing the Fibre Channel
# connection.
#       0  = auto select (default)
#       1  = 1 Gigabaud
#       2  = 2 Gigabaud
#       4  = 4 Gigabaud
#       8  = 8 Gigabaud
# Value range is [0,8]. Default value is 0.
*/

/**
 * lpfc_link_speed_set - Set the adapters link speed
 * @phba: lpfc_hba pointer.
 * @val: link speed value.
 *
 * Description:
 * If val is in a valid range then set the adapter's link speed field and
 * issue a lip; if the lip fails reset the link speed to the old value.
 *
 * Notes:
 * If the value is not in range log a kernel error message and return an error.
 *
 * Returns:
 * zero if val is in range and lip okay.
 * non-zero return value from lpfc_issue_lip()
 * -EINVAL val out of range
 **/
static ssize_t
lpfc_link_speed_store(struct class_device *cdev, const char *buf, size_t count)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	int val = 0;
	int nolip = 0;
	const char *val_buf = buf;
	int err;
	uint32_t prev_val;

	if (!strncmp(buf, "nolip ", strlen("nolip "))) {
		nolip = 1;
		val_buf = &buf[strlen("nolip ")];
	}

	if (!isdigit(val_buf[0]))
		return -EINVAL;
	if (sscanf(val_buf, "%i", &val) != 1)
		return -EINVAL;

	if (((val == LINK_SPEED_1G) && !(phba->lmt & LMT_1Gb)) ||
		((val == LINK_SPEED_2G) && !(phba->lmt & LMT_2Gb)) ||
		((val == LINK_SPEED_4G) && !(phba->lmt & LMT_4Gb)) ||
		((val == LINK_SPEED_8G) && !(phba->lmt & LMT_8Gb)) ||
		((val == LINK_SPEED_10G) && !(phba->lmt & LMT_10Gb)))
		return -EINVAL;

	if ((val >= 0 && val <= 8)
		&& (LPFC_LINK_SPEED_BITMAP & (1 << val))) {
		prev_val = phba->cfg_link_speed;
		phba->cfg_link_speed = val;
		if (nolip)
			return strlen(buf);

		err = lpfc_issue_lip(lpfc_shost_from_vport(phba->pport));
		if (err) {
			phba->cfg_link_speed = prev_val;
			return -EINVAL;
		} else
			return strlen(buf);
	}

	lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
		"%d:0469 lpfc_link_speed attribute cannot be set to %d, "
		"allowed range is [0, 8]\n",
		phba->brd_no, val);
	return -EINVAL;
}

static int lpfc_link_speed = 0;
module_param(lpfc_link_speed, int, 0);
MODULE_PARM_DESC(lpfc_link_speed, "Select link speed");
lpfc_param_show(link_speed)

/**
 * lpfc_link_speed_init - Set the adapters link speed
 * @phba: lpfc_hba pointer.
 * @val: link speed value.
 *
 * Description:
 * If val is in a valid range then set the adapter's link speed field.
 *
 * Notes:
 * If the value is not in range log a kernel error message, clear the link
 * speed and return an error.
 *
 * Returns:
 * zero if val saved.
 * -EINVAL val out of range
 **/
static int
lpfc_link_speed_init(struct lpfc_hba *phba, int val)
{
	if ((val >= 0 && val <= LPFC_MAX_LINK_SPEED)
		&& (LPFC_LINK_SPEED_BITMAP & (1 << val))) {
		phba->cfg_link_speed = val;
		return 0;
	}
	lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
			"0405 lpfc_link_speed attribute cannot "
			"be set to %d, allowed values are "
			"["LPFC_LINK_SPEED_STRING"]\n", val);
	phba->cfg_link_speed = 0;
	return -EINVAL;
}

static CLASS_DEVICE_ATTR(lpfc_link_speed, S_IRUGO | S_IWUSR,
		lpfc_link_speed_show, lpfc_link_speed_store);

/*
# lpfc_aer_support: Support PCIe device Advanced Error Reporting (AER)
#       0  = aer disabled or not supported
#       1  = aer supported and enabled (default)
# Value range is [0,1]. Default value is 1.
*/

/**
 * lpfc_aer_support_store - Set the adapter for aer support
 *
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: containing the string "selective".
 * @count: unused variable.
 *
 * Description:
 * If the val is 1 and currently the device's AER capability was not
 * enabled, invoke the kernel's enable AER helper routine, trying to
 * enable the device's AER capability. If the helper routine enabling
 * AER returns success, update the device's cfg_aer_support flag to
 * indicate AER is supported by the device; otherwise, if the device
 * AER capability is already enabled to support AER, then do nothing.
 *
 * If the val is 0 and currently the device's AER support was enabled,
 * invoke the kernel's disable AER helper routine. After that, update
 * the device's cfg_aer_support flag to indicate AER is not supported
 * by the device; otherwise, if the device AER capability is already
 * disabled from supporting AER, then do nothing.
 *
 * Returns:
 * length of the buf on success if val is in range the intended mode
 * is supported.
 * -EINVAL if val out of range or intended mode is not supported.
 **/
static ssize_t
lpfc_aer_support_store(struct class_device *dev, const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	struct lpfc_vport *vport = (struct lpfc_vport *)shost->hostdata;
	struct lpfc_hba *phba = vport->phba;
	int val = 0, rc = -EINVAL;

	/* AER not supported on OC devices yet */
	if (phba->pci_dev_grp == LPFC_PCI_DEV_OC)
		return -EPERM;
	if (!isdigit(buf[0]))
		return -EINVAL;
	if (sscanf(buf, "%i", &val) != 1)
		return -EINVAL;

	switch (val) {
	case 0:
		if (phba->hba_flag & HBA_AER_ENABLED) {
			rc = pci_disable_pcie_error_reporting(phba->pcidev);
			if (!rc) {
				spin_lock_irq(&phba->hbalock);
				phba->hba_flag &= ~HBA_AER_ENABLED;
				spin_unlock_irq(&phba->hbalock);
				phba->cfg_aer_support = 0;
				rc = strlen(buf);
			} else
				rc = -EPERM;
		} else {
			phba->cfg_aer_support = 0;
			rc = strlen(buf);
		}
		break;
	case 1:
		if (!(phba->hba_flag & HBA_AER_ENABLED)) {
			rc = pci_enable_pcie_error_reporting(phba->pcidev);
			if (!rc) {
				spin_lock_irq(&phba->hbalock);
				phba->hba_flag |= HBA_AER_ENABLED;
				spin_unlock_irq(&phba->hbalock);
				phba->cfg_aer_support = 1;
				rc = strlen(buf);
			} else
				 rc = -EPERM;
		} else {
			phba->cfg_aer_support = 1;
			rc = strlen(buf);
		}
		break;
	default:
		rc = -EINVAL;
		break;
	}
	return rc;
}

static int lpfc_aer_support = 1;
module_param(lpfc_aer_support, int, 1);
MODULE_PARM_DESC(lpfc_aer_support, "Enable PCIe device AER support");
lpfc_param_show(aer_support)

/**
 * lpfc_aer_support_init - Set the initial adapters aer support flag
 * @phba: lpfc_hba pointer.
 * @val: link speed value.
 *
 * Description:
 * If val is in a valid range [0,1], then set the adapter's initial
 * cfg_aer_support field. It will be up to the driver's probe_one
 * routine to determine whether the device's AER support can be set
 * or not.
 *
 * Notes:
 * If the value is not in range log a kernel error message, and
 * choose the default value of setting AER support and return.
 *
 * Returns:
 * zero if val saved.
 * -EINVAL val out of range
 **/
static int
lpfc_aer_support_init(struct lpfc_hba *phba, int val)
{
	/* AER not supported on OC devices yet */
	if (phba->pci_dev_grp == LPFC_PCI_DEV_OC) {
		phba->cfg_aer_support = 0;
		return -EPERM;
	}

	if (val == 0 || val == 1) {
		phba->cfg_aer_support = val;
		return 0;
	}
	lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
			"2712 lpfc_aer_support attribute value %d out "
			"of range, allowed values are 0|1, setting it "
			"to default value of 1\n", val);
	/* By default, try to enable AER on a device */
	phba->cfg_aer_support = 1;
	return -EINVAL;
}

static CLASS_DEVICE_ATTR(lpfc_aer_support, S_IRUGO | S_IWUSR,
			 lpfc_aer_support_show, lpfc_aer_support_store);

/**
 * lpfc_aer_cleanup_state - Clean up aer state to the aer enabled device
 * @dev: class device that is converted into a Scsi_host.
 * @attr: device attribute, not used.
 * @buf: containing the string "selective".
 * @count: unused variable.
 *
 * Description:
 * If the @buf contains 1 and the device currently has the AER support
 * enabled, then invokes the kernel AER helper routine
 * pci_cleanup_aer_uncorrect_error_status to clean up the uncorrectable
 * error status register.
 *
 * Notes:
 *
 * Returns:
 * -EINVAL if the buf does not contain the 1 or the device is not currently
 * enabled with the AER support.
 **/
static ssize_t
lpfc_aer_cleanup_state(struct class_device *dev, const char *buf, size_t count)
{
	struct Scsi_Host  *shost = class_to_shost(dev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	int val, rc = -1;

	/* AER not supported on OC devices yet */
	if (phba->pci_dev_grp == LPFC_PCI_DEV_OC)
		return -EPERM;
	if (!isdigit(buf[0]))
		return -EINVAL;
	if (sscanf(buf, "%i", &val) != 1)
		return -EINVAL;
	if (val != 1)
		return -EINVAL;

	if (phba->hba_flag & HBA_AER_ENABLED)
		rc = pci_cleanup_aer_uncorrect_error_status(phba->pcidev);

	if (rc == 0)
		return strlen(buf);
	else
		return -EPERM;
}

static CLASS_DEVICE_ATTR(lpfc_aer_state_cleanup, S_IWUSR, NULL,
			 lpfc_aer_cleanup_state);

/*
# lpfc_fcp_class:  Determines FC class to use for the FCP protocol.
# Value range is [2,3]. Default value is 3.
*/
LPFC_VPORT_ATTR_R(fcp_class, 3, 2, 3,
		  "Select Fibre Channel class of service for FCP sequences");

/*
# lpfc_use_adisc: Use ADISC for FCP rediscovery instead of PLOGI. Value range
# is [0,1]. Default value is 0.
*/
LPFC_VPORT_ATTR_RW(use_adisc, 0, 0, 1,
		   "Use ADISC on rediscovery to authenticate FCP devices");

/*
# lpfc_max_scsicmpl_time: Use scsi command completion time to control I/O queue
# depth. Default value is 0. When the value of this parameter is zero the
# SCSI command completion time is not used for controlling I/O queue depth. When
# the parameter is set to a non-zero value, the I/O queue depth is controlled
# to limit the I/O completion time to the parameter value.
# The value is set in milliseconds.
*/
static int lpfc_max_scsicmpl_time = 0;
module_param(lpfc_max_scsicmpl_time, int, 0);
MODULE_PARM_DESC(lpfc_max_scsicmpl_time,
	"Use command completion time to control queue depth");
lpfc_vport_param_show(max_scsicmpl_time);
lpfc_vport_param_init(max_scsicmpl_time, 0, 0, 60000);
static int
lpfc_max_scsicmpl_time_set(struct lpfc_vport *vport, int val)
{
	struct Scsi_Host *shost = lpfc_shost_from_vport(vport);
	struct lpfc_nodelist *ndlp, *next_ndlp;

	if (val == vport->cfg_max_scsicmpl_time)
		return 0;
	if ((val < 0) || (val > 60000))
		return -EINVAL;
	vport->cfg_max_scsicmpl_time = val;

	spin_lock_irq(shost->host_lock);
	list_for_each_entry_safe(ndlp, next_ndlp, &vport->fc_nodes, nlp_listp) {
		if (!NLP_CHK_NODE_ACT(ndlp))
			continue;
		if (ndlp->nlp_state == NLP_STE_UNUSED_NODE)
			continue;
		ndlp->cmd_qdepth = LPFC_MAX_TGT_QDEPTH;
	}
	spin_unlock_irq(shost->host_lock);
	return 0;
}
lpfc_vport_param_store(max_scsicmpl_time);
static CLASS_DEVICE_ATTR(lpfc_max_scsicmpl_time, S_IRUGO | S_IWUSR,
			 lpfc_max_scsicmpl_time_show,
			 lpfc_max_scsicmpl_time_store);

/*
# lpfc_ack0: Use ACK0, instead of ACK1 for class 2 acknowledgement. Value
# range is [0,1]. Default value is 0.
*/
LPFC_ATTR_R(ack0, 0, 0, 1, "Enable ACK0 support");

/*
# lpfc_cr_delay & lpfc_cr_count: Default values for I/O colaesing
# cr_delay (msec) or cr_count outstanding commands. cr_delay can take
# value [0,63]. cr_count can take value [1,255]. Default value of cr_delay
# is 0. Default value of cr_count is 1. The cr_count feature is disabled if
# cr_delay is set to 0.
*/
LPFC_ATTR_RW(cr_delay, 0, 0, 63, "A count of milliseconds after which an "
		"interrupt response is generated");

LPFC_ATTR_RW(cr_count, 1, 1, 255, "A count of I/O completions after which an "
		"interrupt response is generated");

/*
# lpfc_multi_ring_support:  Determines how many rings to spread available
# cmd/rsp IOCB entries across.
# Value range is [1,2]. Default value is 1.
*/
LPFC_ATTR_R(multi_ring_support, 1, 1, 2, "Determines number of primary "
		"SLI rings to spread IOCB entries across");

/*
# lpfc_multi_ring_rctl:  If lpfc_multi_ring_support is enabled, this
# identifies what rctl value to configure the additional ring for.
# Value range is [1,0xff]. Default value is 4 (Unsolicated Data).
*/
LPFC_ATTR_R(multi_ring_rctl, FC_RCTL_DD_UNSOL_DATA, 1,
	     255, "Identifies RCTL for additional ring configuration");

/*
# lpfc_multi_ring_type:  If lpfc_multi_ring_support is enabled, this
# identifies what type value to configure the additional ring for.
# Value range is [1,0xff]. Default value is 5 (LLC/SNAP).
*/
LPFC_ATTR_R(multi_ring_type, FC_TYPE_IP, 1,
	     255, "Identifies TYPE for additional ring configuration");

/*
# lpfc_fdmi_on: controls FDMI support.
#       0 = no FDMI support
#       1 = support FDMI without attribute of hostname
#       2 = support FDMI with attribute of hostname
# Value range [0,2]. Default value is 0.
*/
LPFC_VPORT_ATTR_RW(fdmi_on, 0, 0, 2, "Enable FDMI support");

/*
# Specifies the maximum number of ELS cmds we can have outstanding (for
# discovery). Value range is [1,64]. Default value = 32.
*/
LPFC_VPORT_ATTR(discovery_threads, 32, 1, 64, "Maximum number of ELS commands "
		 "during discovery");

/*
# lpfc_max_luns: maximum allowed LUN.
# Value range is [0,65535]. Default value is 255.
# NOTE: The SCSI layer might probe all allowed LUN on some old targets.
*/
LPFC_VPORT_ATTR_R(max_luns, 255, 0, 65535, "Maximum allowed LUN");

/*
# lpfc_poll_tmo: .Milliseconds driver will wait between polling FCP ring.
# Value range is [1,255], default value is 10.
*/
LPFC_ATTR_RW(poll_tmo, 10, 1, 255,
	     "Milliseconds driver will wait between polling FCP ring");

/*
# lpfc_use_msi: Use MSI (Message Signaled Interrupts) in systems that
#		support this feature
#       0  = MSI disabled (default)
#       1  = MSI enabled
#       2  = MSI-X enabled
# Value range is [0,2]. Default value is 2.
*/
LPFC_ATTR_R(use_msi, 0, 0, 2, "Use Message Signaled Interrupts (1) or "
	    "MSI-X (2), if possible");

/*
# lpfc_enable_auth: controls FC Authentication.
#       0 = Authentication OFF
#       1 = Authentication ON
# Value range [0,1]. Default value is 0.
*/
static int lpfc_enable_auth = 0;
module_param(lpfc_enable_auth, int, 0);
MODULE_PARM_DESC(lpfc_enable_auth, "Enable FC Authentication");
lpfc_vport_param_show(enable_auth);
lpfc_vport_param_init(enable_auth, 0, 0, 1);
static int
lpfc_enable_auth_set(struct lpfc_vport *vport, int val)
{
	if (val == vport->cfg_enable_auth)
		return 0;
	if (val == 0) {
		spin_lock_irq(&fc_security_user_lock);
		list_del(&vport->sc_users);
		spin_unlock_irq(&fc_security_user_lock);
		vport->cfg_enable_auth = val;
		lpfc_fc_queue_security_work(vport,
					    &vport->sc_offline_work);
		return 0;
	} else if (val == 1) {
		spin_lock_irq(&fc_security_user_lock);
		list_add_tail(&vport->sc_users, &fc_security_user_list);
		spin_unlock_irq(&fc_security_user_lock);
		vport->cfg_enable_auth = val;
		lpfc_fc_queue_security_work(vport,
					    &vport->sc_online_work);
		return 0;
	}
	lpfc_printf_vlog(vport, KERN_ERR, LOG_INIT,
			 "0560 lpfc_enable_auth attribute cannot be set to %d, "
			 "allowed range is [0, 1]\n", val);
	return -EINVAL;
}
lpfc_vport_param_store(enable_auth);
static CLASS_DEVICE_ATTR(lpfc_enable_auth, S_IRUGO | S_IWUSR,
			 lpfc_enable_auth_show, lpfc_enable_auth_store);

/*
# lpfc_fcp_imax: Set the maximum number of fast-path FCP interrupts per second
#
# Value range is [636,651042]. Default value is 10000.
*/
LPFC_ATTR_R(fcp_imax, LPFC_FP_DEF_IMAX, LPFC_MIM_IMAX, LPFC_DMULT_CONST,
	    "Set the maximum number of fast-path FCP interrupts per second");

/*
# lpfc_fcp_wq_count: Set the number of fast-path FCP work queues
#
# Value range is [1,31]. Default value is 4.
*/
LPFC_ATTR_R(fcp_wq_count, LPFC_FP_WQN_DEF, LPFC_FP_WQN_MIN, LPFC_FP_WQN_MAX,
	    "Set the number of fast-path FCP work queues, if possible");

/*
# lpfc_fcp_eq_count: Set the number of fast-path FCP event queues
#
# Value range is [1,7]. Default value is 4.
*/
LPFC_ATTR_R(fcp_eq_count, LPFC_FP_EQN_DEF, LPFC_FP_EQN_MIN, LPFC_FP_EQN_MAX,
	    "Set the number of fast-path FCP event queues, if possible");

/*
# lpfc_enable_hba_reset: Allow or prevent HBA resets to the hardware.
#       0  = HBA resets disabled
#       1  = HBA resets enabled (default)
# Value range is [0,1]. Default value is 1.
*/
LPFC_ATTR_R(enable_hba_reset, 1, 0, 1, "Enable HBA resets from the driver.");

/*
# lpfc_enable_hba_heartbeat: Enable HBA heartbeat timer..
#       0  = HBA Heartbeat disabled
#       1  = HBA Heartbeat enabled (default)
# Value range is [0,1]. Default value is 1.
*/
LPFC_ATTR_R(enable_hba_heartbeat, 1, 0, 1, "Enable HBA Heartbeat.");

/*
 * lpfc_sg_seg_cnt: Initial Maximum DMA Segment Count
 * This value can be set to values between 64 and 256. The default value is
 * 64, but may be increased to allow for larger Max I/O sizes. The scsi layer
 * will be allowed to request I/Os of sizes up to (MAX_SEG_COUNT * SEG_SIZE).
 */
LPFC_ATTR_R(sg_seg_cnt, LPFC_DEFAULT_SG_SEG_CNT, LPFC_DEFAULT_SG_SEG_CNT,
	    LPFC_MAX_SG_SEG_CNT, "Max Scatter Gather Segment Count");

/*
# lpfc_pci_max_read:  Maximum DMA read byte count. This parameter can have
# values 512, 1024, 2048, 4096. Default value is 2048.
*/
static int lpfc_pci_max_read = 2048;
module_param(lpfc_pci_max_read, int, 0);
MODULE_PARM_DESC(lpfc_pci_max_read,
	"Maximum DMA read byte count. Allowed values:"
		" 512,1024,2048,4096." );
static ssize_t
lpfc_pci_max_read_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_hba   *phba = ((struct lpfc_vport *) shost->hostdata)->phba;
	uint32_t val = 0;
	val = phba->cfg_pci_max_read;
	return snprintf(buf, PAGE_SIZE, "%d\n", val);
}

static int
lpfc_pci_max_read_init(struct lpfc_hba *phba, int val)
{
	phba->cfg_pci_max_read = 2048;
	if ((val == 512) || (val == 1024) || (val == 2048)
		|| (val == 4096))
		phba->cfg_pci_max_read = val;
	return 0;
}

static int
lpfc_pci_max_read_set(struct lpfc_hba *phba, int val)
{
	uint32_t prev_val;
	int ret;

	prev_val = phba->cfg_pci_max_read;
	phba->cfg_pci_max_read = val;
	if ((ret = lpfc_sli_set_dma_length(phba, 0))) {
		phba->cfg_pci_max_read = prev_val;
		return ret;
	} else
		return 0;
}

lpfc_param_store(pci_max_read)

static CLASS_DEVICE_ATTR(lpfc_pci_max_read, S_IRUGO | S_IWUSR,
		lpfc_pci_max_read_show, lpfc_pci_max_read_store);

/*
# lpfc_dev_loss_initiator: FC transport layer waits for dev_loss timer to
#	expire for FC Initiators before calling rport dev_loss callback routine
#       0  = disabled (dev_loss callback called immediately after rport delete)
#       1  = enabled  (dev_loss callback is called after dev_loss timer expires)
# Value range is [0,1]. Default value is 0.
*/
LPFC_ATTR_R(dev_loss_initiator, 0, 0, 1,
		"FC Tranport dev_loss behavior for Initiators");

struct class_device_attribute *lpfc_hba_attrs[] = {
	&class_device_attr_info,
	&class_device_attr_serialnum,
	&class_device_attr_modeldesc,
	&class_device_attr_modelname,
	&class_device_attr_programtype,
	&class_device_attr_portnum,
	&class_device_attr_fwrev,
	&class_device_attr_hdw,
	&class_device_attr_option_rom_version,
	&class_device_attr_state,
	&class_device_attr_num_discovered_ports,
	&class_device_attr_menlo_mgmt_mode,
	&class_device_attr_lpfc_drvr_version,
	&class_device_attr_lpfc_enable_fip,
	&class_device_attr_lpfc_temp_sensor,
	&class_device_attr_lpfc_log_verbose,
	&class_device_attr_lpfc_lun_queue_depth,
	&class_device_attr_lpfc_hba_queue_depth,
	&class_device_attr_lpfc_pci_max_read,
	&class_device_attr_lpfc_peer_port_login,
	&class_device_attr_lpfc_nodev_tmo,
	&class_device_attr_lpfc_devloss_tmo,
	&class_device_attr_lpfc_fcp_class,
	&class_device_attr_lpfc_use_adisc,
	&class_device_attr_lpfc_ack0,
	&class_device_attr_lpfc_topology,
	&class_device_attr_lpfc_scan_down,
	&class_device_attr_lpfc_link_speed,
	&class_device_attr_lpfc_cr_delay,
	&class_device_attr_lpfc_cr_count,
	&class_device_attr_lpfc_multi_ring_support,
	&class_device_attr_lpfc_multi_ring_rctl,
	&class_device_attr_lpfc_multi_ring_type,
	&class_device_attr_lpfc_fdmi_on,
	&class_device_attr_lpfc_max_luns,
	&class_device_attr_lpfc_enable_npiv,
	&class_device_attr_nport_evt_cnt,
	&class_device_attr_management_version,
	&class_device_attr_board_mode,
	&class_device_attr_max_vpi,
	&class_device_attr_used_vpi,
	&class_device_attr_max_rpi,
	&class_device_attr_used_rpi,
	&class_device_attr_max_xri,
	&class_device_attr_used_xri,
	&class_device_attr_npiv_info,
	&class_device_attr_issue_reset,
	&class_device_attr_lpfc_poll,
	&class_device_attr_lpfc_poll_tmo,
	&class_device_attr_lpfc_use_msi,
	&class_device_attr_lpfc_enable_auth,
	&class_device_attr_lpfc_authenticate,
	&class_device_attr_lpfc_update_auth_config,
	&class_device_attr_lpfc_dev_loss_initiator,
	&class_device_attr_npiv_vports_inuse,
	&class_device_attr_max_npiv_vports,
	&class_device_attr_vport_delete,
	&class_device_attr_vport_create,
	&class_device_attr_auth_state,
	&class_device_attr_auth_dir,
	&class_device_attr_auth_protocol,
	&class_device_attr_auth_dhgroup,
	&class_device_attr_auth_hash,
	&class_device_attr_auth_last,
	&class_device_attr_auth_next,
	&class_device_attr_lpfc_symbolic_name,
	&class_device_attr_lpfc_soft_wwnn,
	&class_device_attr_lpfc_soft_wwpn,
	&class_device_attr_lpfc_soft_wwn_enable,
	&class_device_attr_lpfc_fcp_imax,
	&class_device_attr_lpfc_fcp_wq_count,
	&class_device_attr_lpfc_fcp_eq_count,
	&class_device_attr_lpfc_enable_hba_reset,
	&class_device_attr_lpfc_enable_hba_heartbeat,
	&class_device_attr_lpfc_sg_seg_cnt,
	&class_device_attr_lpfc_max_scsicmpl_time,
	&class_device_attr_lpfc_stat_data_ctrl,
	&class_device_attr_lpfc_hostmem_hgp,
	&class_device_attr_lpfc_aer_support,
	&class_device_attr_lpfc_aer_state_cleanup,
	NULL,
};

struct class_device_attribute *lpfc_hba_attrs_no_npiv[] = {
	&class_device_attr_info,
	&class_device_attr_serialnum,
	&class_device_attr_modeldesc,
	&class_device_attr_modelname,
	&class_device_attr_programtype,
	&class_device_attr_portnum,
	&class_device_attr_fwrev,
	&class_device_attr_hdw,
	&class_device_attr_option_rom_version,
	&class_device_attr_state,
	&class_device_attr_num_discovered_ports,
	&class_device_attr_menlo_mgmt_mode,
	&class_device_attr_lpfc_drvr_version,
	&class_device_attr_lpfc_temp_sensor,
	&class_device_attr_lpfc_log_verbose,
	&class_device_attr_lpfc_lun_queue_depth,
	&class_device_attr_lpfc_hba_queue_depth,
	&class_device_attr_lpfc_pci_max_read,
	&class_device_attr_lpfc_peer_port_login,
	&class_device_attr_lpfc_nodev_tmo,
	&class_device_attr_lpfc_devloss_tmo,
	&class_device_attr_lpfc_enable_fip,
	&class_device_attr_lpfc_fcp_class,
	&class_device_attr_lpfc_use_adisc,
	&class_device_attr_lpfc_ack0,
	&class_device_attr_lpfc_topology,
	&class_device_attr_lpfc_scan_down,
	&class_device_attr_lpfc_link_speed,
	&class_device_attr_lpfc_cr_delay,
	&class_device_attr_lpfc_cr_count,
	&class_device_attr_lpfc_multi_ring_support,
	&class_device_attr_lpfc_multi_ring_rctl,
	&class_device_attr_lpfc_multi_ring_type,
	&class_device_attr_lpfc_fdmi_on,
	&class_device_attr_lpfc_max_luns,
	&class_device_attr_lpfc_enable_npiv,
	&class_device_attr_nport_evt_cnt,
	&class_device_attr_management_version,
	&class_device_attr_board_mode,
	&class_device_attr_max_vpi,
	&class_device_attr_used_vpi,
	&class_device_attr_max_rpi,
	&class_device_attr_used_rpi,
	&class_device_attr_max_xri,
	&class_device_attr_used_xri,
	&class_device_attr_npiv_info,
	&class_device_attr_issue_reset,
	&class_device_attr_lpfc_poll,
	&class_device_attr_lpfc_poll_tmo,
	&class_device_attr_lpfc_use_msi,
	&class_device_attr_lpfc_enable_auth,
	&class_device_attr_lpfc_authenticate,
	&class_device_attr_lpfc_update_auth_config,
	&class_device_attr_lpfc_dev_loss_initiator,
	&class_device_attr_lpfc_soft_wwnn,
	&class_device_attr_lpfc_soft_wwpn,
	&class_device_attr_lpfc_soft_wwn_enable,
	&class_device_attr_auth_state,
	&class_device_attr_auth_dir,
	&class_device_attr_auth_protocol,
	&class_device_attr_auth_dhgroup,
	&class_device_attr_auth_hash,
	&class_device_attr_auth_last,
	&class_device_attr_auth_next,
	&class_device_attr_lpfc_symbolic_name,
	&class_device_attr_lpfc_max_scsicmpl_time,
	&class_device_attr_lpfc_stat_data_ctrl,
	&class_device_attr_lpfc_hostmem_hgp,
	&class_device_attr_lpfc_enable_hba_heartbeat,
	&class_device_attr_lpfc_fcp_imax,
	&class_device_attr_lpfc_fcp_wq_count,
	&class_device_attr_lpfc_fcp_eq_count,
	&class_device_attr_lpfc_enable_hba_reset,
	&class_device_attr_lpfc_exclude_hba,
	&class_device_attr_lpfc_aer_support,
	&class_device_attr_lpfc_aer_state_cleanup,
	NULL,
};

struct class_device_attribute *lpfc_vport_attrs[] = {
	&class_device_attr_info,
	&class_device_attr_state,
	&class_device_attr_num_discovered_ports,
	&class_device_attr_lpfc_drvr_version,
	&class_device_attr_lpfc_enable_auth,
	&class_device_attr_lpfc_log_verbose,
	&class_device_attr_lpfc_lun_queue_depth,
	&class_device_attr_lpfc_nodev_tmo,
	&class_device_attr_lpfc_devloss_tmo,
	&class_device_attr_lpfc_hba_queue_depth,
	&class_device_attr_lpfc_peer_port_login,
	&class_device_attr_lpfc_restrict_login,
	&class_device_attr_lpfc_fcp_class,
	&class_device_attr_lpfc_use_adisc,
	&class_device_attr_lpfc_fdmi_on,
	&class_device_attr_lpfc_max_luns,
	&class_device_attr_nport_evt_cnt,
	&class_device_attr_management_version,
	&class_device_attr_npiv_info,
	&class_device_attr_lpfc_enable_da_id,
	&class_device_attr_lpfc_max_scsicmpl_time,
	&class_device_attr_lpfc_dev_loss_initiator,
	&class_device_attr_auth_state,
	&class_device_attr_auth_dir,
	&class_device_attr_auth_protocol,
	&class_device_attr_auth_dhgroup,
	&class_device_attr_auth_hash,
	&class_device_attr_auth_last,
	&class_device_attr_auth_next,
	&class_device_attr_lpfc_symbolic_name,
	&class_device_attr_lpfc_stat_data_ctrl,
	&class_device_attr_lpfc_hostmem_hgp,
	&class_device_attr_lpfc_static_vport,
	NULL,
};

/**
 * sysfs_ctlreg_write - Write method for writing to ctlreg
 * @kobj: kernel kobject that contains the kernel class device.
 * @bin_attr: kernel attributes passed to us.
 * @buf: contains the data to be written to the adapter IOREG space.
 * @off: offset into buffer to beginning of data.
 * @count: bytes to transfer.
 *
 * Description:
 * Accessed via /sys/class/scsi_host/hostxxx/ctlreg.
 * Uses the adapter io control registers to send buf contents to the adapter.
 *
 * Returns:
 * -ERANGE off and count combo out of range
 * -EINVAL off, count or buff address invalid
 * -EPERM adapter is offline
 * value of count, buf contents written
 **/
static ssize_t
sysfs_ctlreg_write(struct kobject *kobj, char *buf, loff_t off, size_t count)
{
	size_t buf_off;
	struct class_device *cdev = container_of(kobj, struct class_device,
						 kobj);
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	if (phba->sli_rev >= LPFC_SLI_REV4)
		return -EPERM;

	if ((off + count) > FF_REG_AREA_SIZE)
		return -ERANGE;

	if (count <= LPFC_REG_WRITE_KEY_SIZE)
		return 0;

	if (off % 4 || count % 4 || (unsigned long)buf % 4)
		return -EINVAL;

	/* This is to protect HBA registers from accidental writes. */
	if (memcmp(buf, LPFC_REG_WRITE_KEY, LPFC_REG_WRITE_KEY_SIZE))
		return -EINVAL;

	spin_lock_irq(&phba->hbalock);
	for (buf_off = 0; buf_off < count - LPFC_REG_WRITE_KEY_SIZE;
			buf_off += sizeof(uint32_t))
		writel(*((uint32_t *)(buf + buf_off + LPFC_REG_WRITE_KEY_SIZE)),
		       phba->ctrl_regs_memmap_p + off + buf_off);

	spin_unlock_irq(&phba->hbalock);

	return count;
}

/**
 * sysfs_ctlreg_read - Read method for reading from ctlreg
 * @kobj: kernel kobject that contains the kernel class device.
 * @bin_attr: kernel attributes passed to us.
 * @buf: if succesful contains the data from the adapter IOREG space.
 * @off: offset into buffer to beginning of data.
 * @count: bytes to transfer.
 *
 * Description:
 * Accessed via /sys/class/scsi_host/hostxxx/ctlreg.
 * Uses the adapter io control registers to read data into buf.
 *
 * Returns:
 * -ERANGE off and count combo out of range
 * -EINVAL off, count or buff address invalid
 * value of count, buf contents read
 **/
static ssize_t
sysfs_ctlreg_read(struct kobject *kobj, char *buf, loff_t off, size_t count)
{
	size_t buf_off;
	uint32_t * tmp_ptr;
	struct class_device *cdev = container_of(kobj, struct class_device,
						 kobj);
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	if (phba->sli_rev >= LPFC_SLI_REV4)
		return -EPERM;

	if (off > FF_REG_AREA_SIZE)
		return -ERANGE;

	if ((off + count) > FF_REG_AREA_SIZE)
		count = FF_REG_AREA_SIZE - off;

	if (count == 0) return 0;

	if (off % 4 || count % 4 || (unsigned long)buf % 4)
		return -EINVAL;

	spin_lock_irq(&phba->hbalock);

	for (buf_off = 0; buf_off < count; buf_off += sizeof(uint32_t)) {
		tmp_ptr = (uint32_t *)(buf + buf_off);
		*tmp_ptr = readl(phba->ctrl_regs_memmap_p + off + buf_off);
	}

	spin_unlock_irq(&phba->hbalock);

	return count;
}

static struct bin_attribute sysfs_ctlreg_attr = {
	.attr = {
		.name = "ctlreg",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 256,
	.read = sysfs_ctlreg_read,
	.write = sysfs_ctlreg_write,
};

static struct lpfc_sysfs_mbox *
lpfc_get_sysfs_mbox(struct lpfc_hba *phba, uint8_t create)
{
	struct lpfc_sysfs_mbox *sysfs_mbox;
	pid_t pid;

	pid = current->pid;

	spin_lock_irq(&phba->hbalock);
	list_for_each_entry(sysfs_mbox, &phba->sysfs_mbox_list, list) {
		if (sysfs_mbox->pid == pid) {
			spin_unlock_irq(&phba->hbalock);
			return sysfs_mbox;
		}
	}
	if (!create) {
		spin_unlock_irq(&phba->hbalock);
		return NULL;
	}
	spin_unlock_irq(&phba->hbalock);
	sysfs_mbox = kzalloc(sizeof(struct lpfc_sysfs_mbox),
			GFP_KERNEL);
	if (!sysfs_mbox)
		return NULL;
	sysfs_mbox->state = SMBOX_IDLE;
	sysfs_mbox->pid = pid;
	spin_lock_irq(&phba->hbalock);
	list_add_tail(&sysfs_mbox->list, &phba->sysfs_mbox_list);

	spin_unlock_irq(&phba->hbalock);
	return sysfs_mbox;

}

/**
 * sysfs_mbox_idle - frees the sysfs mailbox
 * @phba: lpfc_hba pointer
 **/
static void
sysfs_mbox_idle(struct lpfc_hba *phba,
		struct lpfc_sysfs_mbox *sysfs_mbox)
{
	list_del_init(&sysfs_mbox->list);
	if (sysfs_mbox->mbox) {
		mempool_free(sysfs_mbox->mbox,
			     phba->mbox_mem_pool);
	}

	if (sysfs_mbox->mbext)
		kfree(sysfs_mbox->mbext);

	/* If txmit buffer allocated free txmit buffer */
	if (sysfs_mbox->txmit_buff) {
		if (sysfs_mbox->txmit_buff->virt)
			__lpfc_mbuf_free(phba,
				sysfs_mbox->txmit_buff->virt,
				sysfs_mbox->txmit_buff->phys);
		kfree(sysfs_mbox->txmit_buff);
	}

	/* If rcv buffer allocated free txmit buffer */
	if (sysfs_mbox->rcv_buff) {
		if (sysfs_mbox->rcv_buff->virt)
			__lpfc_mbuf_free(phba,
				sysfs_mbox->rcv_buff->virt,
				sysfs_mbox->rcv_buff->phys);
		kfree(sysfs_mbox->rcv_buff);
	}

	kfree(sysfs_mbox);
}

static size_t
lpfc_syfs_mbox_copy_rcv_buff(struct lpfc_hba *phba,
		struct lpfc_sysfs_mbox *sysfs_mbox,
		char *buf, loff_t off, size_t count)
{
	uint32_t size;
	spin_lock_irq(&phba->hbalock);
	if (!sysfs_mbox->mbox) {
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -EAGAIN;
	}

	if (sysfs_mbox->mbox->u.mb.mbxCommand == MBX_READ_EVENT_LOG)
		size = sysfs_mbox->mbox->u.mb.un.
			varRdEventLog.rcv_bde64.tus.f.bdeSize;
	else
		size = sysfs_mbox->mbox->u.mb.un.
			varBIUdiag.un.s2.rcv_bde64.tus.f.bdeSize;


	if ((count + off) > size) {
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -ERANGE;
	}
	if (count > LPFC_BPL_SIZE) {
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -ERANGE;
	}
	if (sysfs_mbox->extoff != off) {
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -EAGAIN;
	}

	memcpy(buf, (uint8_t *) sysfs_mbox->rcv_buff->virt + off, count);
	sysfs_mbox->extoff = off + count;

	if (sysfs_mbox->extoff >= size)
		sysfs_mbox_idle(phba, sysfs_mbox);

	spin_unlock_irq(&phba->hbalock);

	return count;
}

static size_t
lpfc_syfs_mbox_copy_extdata(struct lpfc_hba *phba,
		struct lpfc_sysfs_mbox * sysfs_mbox,
		char *buf, loff_t off, size_t count)
{
	uint32_t size;

	spin_lock_irq(&phba->hbalock);
	if (!sysfs_mbox->mbox) {
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -EAGAIN;
	}

	size = sysfs_mbox->mbox_data.out_ext_wlen * sizeof(uint32_t);

	if ((count + off) > size) {
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -ERANGE;
	}

	if (size > MAILBOX_EXT_SIZE) {
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -ERANGE;
	}

	if (sysfs_mbox->extoff != off) {
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -EAGAIN;
	}

	memcpy(buf, (uint8_t *) sysfs_mbox->mbext + off, count);
	sysfs_mbox->extoff = off + count;

	if (sysfs_mbox->extoff >= size)
		sysfs_mbox_idle(phba, sysfs_mbox);

	spin_unlock_irq(&phba->hbalock);

	return count;
}

static size_t
lpfc_syfs_mbox_copy_txmit_buff(struct lpfc_hba *phba,
		struct lpfc_sysfs_mbox *sysfs_mbox,
		char *buf, loff_t off, size_t count)
{
	uint32_t size;
	spin_lock_irq(&phba->hbalock);
	if (!sysfs_mbox->mbox ||
		(sysfs_mbox->offset != sizeof(struct lpfc_sysfs_mbox_data))) {
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -EAGAIN;
	}

	size = sysfs_mbox->mbox->u.mb.un.varBIUdiag.un.s2.xmit_bde64.
			tus.f.bdeSize;

	if ((count + off) > size) {
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -ERANGE;
	}

	if (size > LPFC_BPL_SIZE) {
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -ERANGE;
	}

	if (sysfs_mbox->extoff != off) {
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -EAGAIN;
	}

	memcpy((uint8_t *) sysfs_mbox->txmit_buff->virt + off, buf, count);
	sysfs_mbox->extoff = off + count;

	spin_unlock_irq(&phba->hbalock);

	return count;
}

/**
 * sysfs_mbox_write - Write method for writing information via mbox
 * @kobj: kernel kobject that contains the kernel class device.
 * @bin_attr: kernel attributes passed to us.
 * @buf: contains the data to be written to sysfs mbox.
 * @off: offset into buffer to beginning of data.
 * @count: bytes to transfer.
 *
 * Description:
 * Accessed via /sys/class/scsi_host/hostxxx/mbox.
 * Uses the sysfs mbox to send buf contents to the adapter.
 *
 * Returns:
 * -ERANGE off and count combo out of range
 * -EINVAL off, count or buff address invalid
 * zero if count is zero
 * -EPERM adapter is offline
 * -ENOMEM failed to allocate memory for the mail box
 * -EAGAIN offset, state or mbox is NULL
 * count number of bytes transferred
 **/
static ssize_t
sysfs_mbox_write(struct kobject *kobj, char *buf, loff_t off, size_t count)
{
	struct class_device *cdev = container_of(kobj, struct class_device,
						 kobj);
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	struct lpfcMboxq  *mbox = NULL;
	struct lpfc_sysfs_mbox *sysfs_mbox;
	uint8_t *ext;
	uint32_t size;

	if (off % 4 ||  count % 4 || (unsigned long)buf % 4)
		return -EINVAL;

	if (count == 0)
		return 0;

	if (off == 0) {
		sysfs_mbox = lpfc_get_sysfs_mbox(phba, 1);
		if (sysfs_mbox == NULL)
			return -ENOMEM;
		/*
		 * If sysfs expect the reading of buffer and
		 * app doesnot know how to do it, use a different
		 * context.
		 */
		if (sysfs_mbox->state == SMBOX_READING_BUFF ||
		    sysfs_mbox->state == SMBOX_READING_MBEXT) {
			spin_lock_irq(&phba->hbalock);
			sysfs_mbox_idle(phba, sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			sysfs_mbox = lpfc_get_sysfs_mbox(phba, 1);
			if (sysfs_mbox == NULL)
				return -ENOMEM;
		}
	} else {
		sysfs_mbox = lpfc_get_sysfs_mbox(phba, 0);
		if (sysfs_mbox == NULL)
			return -EAGAIN;
	}

	spin_lock_irq(&phba->hbalock);

	if (sysfs_mbox->state == SMBOX_WRITING_MBEXT) {
		if (!sysfs_mbox->mbox ||
		    (sysfs_mbox->offset !=
			sizeof(struct lpfc_sysfs_mbox_data))) {
			sysfs_mbox_idle(phba, sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			return -EAGAIN;
		}

		size = sysfs_mbox->mbox_data.in_ext_wlen * sizeof(uint32_t);

		if ((count + sysfs_mbox->extoff) > size) {
			sysfs_mbox_idle(phba, sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			return -ERANGE;
		}

		if (size > MAILBOX_EXT_SIZE) {
			sysfs_mbox_idle(phba, sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			return -ERANGE;
		}

		if (!sysfs_mbox->mbext) {
			spin_unlock_irq(&phba->hbalock);

			ext = kzalloc(MAILBOX_EXT_SIZE, GFP_KERNEL);
			if (!ext) {
				spin_lock_irq(&phba->hbalock);
				sysfs_mbox_idle(phba, sysfs_mbox);
				spin_unlock_irq(&phba->hbalock);
				return -ENOMEM;
			}

			spin_lock_irq(&phba->hbalock);
			sysfs_mbox->mbext = ext;
		}

		if (sysfs_mbox->extoff != off) {
			sysfs_mbox_idle(phba, sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			return -EAGAIN;
		}

		memcpy((uint8_t *) sysfs_mbox->mbext + off, buf, count);
		sysfs_mbox->extoff = off + count;

		spin_unlock_irq(&phba->hbalock);

		return count;
	}

	spin_unlock_irq(&phba->hbalock);

	if (sysfs_mbox->state == SMBOX_WRITING_BUFF)
		return lpfc_syfs_mbox_copy_txmit_buff(phba,
				sysfs_mbox, buf, off, count);

	if ((count + off) > sizeof(struct lpfc_sysfs_mbox_data)) {
		spin_lock_irq(&phba->hbalock);
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -ERANGE;
	}

	if (off == 0) {
		mbox = mempool_alloc(phba->mbox_mem_pool, GFP_KERNEL);
		if (!mbox) {
			spin_lock_irq(&phba->hbalock);
			sysfs_mbox_idle(phba, sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			return -ENOMEM;
		}
		memset(mbox, 0, sizeof (LPFC_MBOXQ_t));
	}

	spin_lock_irq(&phba->hbalock);

	if (off == 0) {
		if (sysfs_mbox->mbox)
			mempool_free(mbox, phba->mbox_mem_pool);
		else
			sysfs_mbox->mbox = mbox;
		sysfs_mbox->state = SMBOX_WRITING;
	} else {
		if (sysfs_mbox->state  != SMBOX_WRITING ||
		    sysfs_mbox->offset != off           ||
		    sysfs_mbox->mbox   == NULL) {
			sysfs_mbox_idle(phba, sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			return -EAGAIN;
		}
	}

	memcpy((uint8_t *) & sysfs_mbox->mbox_data + off,
	       buf, count);

	sysfs_mbox->offset = off + count;

	if (sysfs_mbox->offset == sizeof(struct lpfc_sysfs_mbox_data)) {
		memcpy((uint8_t *) & sysfs_mbox->mbox->u.mb,
			(uint8_t *) &sysfs_mbox->mbox_data.mbox,
			sizeof(MAILBOX_t));
	}

	if ((sysfs_mbox->offset == sizeof(struct lpfc_sysfs_mbox_data)) &&
		(sysfs_mbox->mbox_data.in_ext_wlen ||
		sysfs_mbox->mbox_data.out_ext_wlen)) {

		if (!sysfs_mbox->mbext) {
			spin_unlock_irq(&phba->hbalock);

			ext = kzalloc(MAILBOX_EXT_SIZE, GFP_KERNEL);
			if (!ext) {
				spin_lock_irq(&phba->hbalock);
				sysfs_mbox_idle(phba, sysfs_mbox);
				spin_unlock_irq(&phba->hbalock);
				return -ENOMEM;
			}

			spin_lock_irq(&phba->hbalock);
			sysfs_mbox->mbext = ext;
		}
	}

	if ((sysfs_mbox->offset == sizeof(struct lpfc_sysfs_mbox_data)) &&
		(sysfs_mbox->mbox_data.in_ext_wlen)) {
		sysfs_mbox->state = SMBOX_WRITING_MBEXT;
	}

	if ((sysfs_mbox->offset == sizeof(struct lpfc_sysfs_mbox_data)) &&
		(sysfs_mbox->mbox->u.mb.mbxCommand == MBX_RUN_BIU_DIAG64)) {
			sysfs_mbox->state = SMBOX_WRITING_BUFF;
			spin_unlock_irq(&phba->hbalock);

			/* Allocate txmit buffer */
			sysfs_mbox->txmit_buff =
				kzalloc(sizeof(struct lpfc_dmabuf), GFP_KERNEL);
			if (!sysfs_mbox->txmit_buff) {
				spin_lock_irq(&phba->hbalock);
				sysfs_mbox_idle(phba, sysfs_mbox);
				spin_unlock_irq(&phba->hbalock);
				return -ENOMEM;
			}
			INIT_LIST_HEAD(&sysfs_mbox->txmit_buff->list);
			sysfs_mbox->txmit_buff->virt =
				lpfc_mbuf_alloc(phba, 0,
					&(sysfs_mbox->txmit_buff->phys));
			if (!sysfs_mbox->txmit_buff->virt) {
				spin_lock_irq(&phba->hbalock);
				sysfs_mbox_idle(phba, sysfs_mbox);
				spin_unlock_irq(&phba->hbalock);
				return -ENOMEM;
			}

			/* Allocate rcv buffer */
			sysfs_mbox->rcv_buff =
				kzalloc(sizeof(struct lpfc_dmabuf), GFP_KERNEL);
			if (!sysfs_mbox->rcv_buff) {
				spin_lock_irq(&phba->hbalock);
				sysfs_mbox_idle(phba, sysfs_mbox);
				spin_unlock_irq(&phba->hbalock);
				return -ENOMEM;
			}
			INIT_LIST_HEAD(&sysfs_mbox->rcv_buff->list);
			sysfs_mbox->rcv_buff->virt =
				lpfc_mbuf_alloc(phba, 0,
					&(sysfs_mbox->rcv_buff->phys));
			if (!sysfs_mbox->rcv_buff->virt) {
				spin_lock_irq(&phba->hbalock);
				sysfs_mbox_idle(phba, sysfs_mbox);
				spin_unlock_irq(&phba->hbalock);
				return -ENOMEM;
			}
			return count;
	}
	if ((sysfs_mbox->offset == sizeof(struct lpfc_sysfs_mbox_data)) &&
		(sysfs_mbox->mbox->u.mb.mbxCommand == MBX_READ_EVENT_LOG)) {
		sysfs_mbox->state = SMBOX_WRITING;
		spin_unlock_irq(&phba->hbalock);


		/* Allocate rcv buffer */
		sysfs_mbox->rcv_buff =
			kzalloc(sizeof(struct lpfc_dmabuf), GFP_KERNEL);
		if (!sysfs_mbox->rcv_buff) {
			spin_lock_irq(&phba->hbalock);
			sysfs_mbox_idle(phba, sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			return -ENOMEM;
		}
		INIT_LIST_HEAD(&sysfs_mbox->rcv_buff->list);
		sysfs_mbox->rcv_buff->virt =
			lpfc_mbuf_alloc(phba, 0,
				&(sysfs_mbox->rcv_buff->phys));
		if (!sysfs_mbox->rcv_buff->virt) {
			spin_lock_irq(&phba->hbalock);
			sysfs_mbox_idle(phba, sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			return -ENOMEM;
		}
		return count;
	}

	spin_unlock_irq(&phba->hbalock);

	return count;
}

static int
lpfc_copy_sli4_bde_fromuser(struct lpfc_hba *phba,
		struct lpfc_sysfs_mbox *sysfs_mbox)
{
	struct lpfc_mbx_sli4_config *sli4_config;
	struct lpfc_mbx_sge mbx_sge;
	uint64_t user_ptr;
	unsigned long data_length;
	MAILBOX_t *mb;
	struct ulp_bde64 *bde;

	if (phba->sli_rev != LPFC_SLI_REV4)
		return 0;

	mb = &sysfs_mbox->mbox->u.mb;

	switch (sysfs_mbox->mbox->u.mb.mbxCommand) {
	case MBX_UPDATE_CFG:
		/* If the DI bit is cleared, do nothing */
		if (!sysfs_mbox->mbox->u.mb.un.varUpdateCfg.co)
			return 0;
		bde = (struct ulp_bde64 *) &mb->un.varWords[4];
		user_ptr = bde->addrHigh;
		user_ptr = user_ptr << 32 | bde->addrLow;
		data_length = bde->tus.f.bdeSize;
		sysfs_mbox->txmit_buff =
			kzalloc(sizeof(struct lpfc_dmabuf), GFP_KERNEL);
		if (!sysfs_mbox->txmit_buff)
			return -ENOMEM;
		INIT_LIST_HEAD(&sysfs_mbox->txmit_buff->list);
		sysfs_mbox->txmit_buff->virt =
			lpfc_mbuf_alloc(phba, 0,
				&(sysfs_mbox->txmit_buff->phys));
		if (!sysfs_mbox->txmit_buff->virt)
			return -ENOMEM;
		if (copy_from_user(sysfs_mbox->txmit_buff->virt,
			(void __user *) (unsigned long)user_ptr,
			data_length))
			return -ENOMEM;
		sysfs_mbox->user_ptr = user_ptr;
		sysfs_mbox->data_length = data_length;
		bde->addrLow = putPaddrLow(sysfs_mbox->txmit_buff->phys);
		bde->addrHigh = putPaddrHigh(sysfs_mbox->txmit_buff->phys);
		return 0;
	case MBX_SLI4_CONFIG:
		sli4_config = &sysfs_mbox->mbox->u.mqe.un.sli4_config;
		/* If this is embedded do nothing. */
		if (bf_get(lpfc_mbox_hdr_emb, &sli4_config->header.cfg_mhdr))
			return 0;
		lpfc_sli4_mbx_sge_get(sysfs_mbox->mbox, 0, &mbx_sge);
		user_ptr = mbx_sge.pa_hi;
		user_ptr = user_ptr << 32 | mbx_sge.pa_lo;
		data_length = mbx_sge.length;
		sysfs_mbox->txmit_buff =
			kzalloc(sizeof(struct lpfc_dmabuf), GFP_KERNEL);
		if (!sysfs_mbox->txmit_buff)
			return -ENOMEM;
		INIT_LIST_HEAD(&sysfs_mbox->txmit_buff->list);
		sysfs_mbox->txmit_buff->virt =
			lpfc_mbuf_alloc(phba, 0,
				&(sysfs_mbox->txmit_buff->phys));
		if (!sysfs_mbox->txmit_buff->virt)
			return -ENOMEM;
		if (copy_from_user(sysfs_mbox->txmit_buff->virt,
			(void __user *) (unsigned long)user_ptr,
			data_length))
			return -ENOMEM;
		sysfs_mbox->user_ptr = user_ptr;
		sysfs_mbox->data_length = data_length;
		lpfc_sli4_mbx_sge_set(sysfs_mbox->mbox, 0,
			sysfs_mbox->txmit_buff->phys,
			data_length);
		return 0;

	case MBX_DUMP_MEMORY:
		user_ptr = mb->un.varWords[4];
		user_ptr = user_ptr << 32 | mb->un.varWords[3];
		data_length = mb->un.varDmp.sli4_length;
		sysfs_mbox->txmit_buff =
			kzalloc(sizeof(struct lpfc_dmabuf), GFP_KERNEL);
		if (!sysfs_mbox->txmit_buff)
			return -ENOMEM;
		INIT_LIST_HEAD(&sysfs_mbox->txmit_buff->list);
		sysfs_mbox->txmit_buff->virt =
			lpfc_mbuf_alloc(phba, 0,
				&(sysfs_mbox->txmit_buff->phys));
		if (!sysfs_mbox->txmit_buff->virt)
			return -ENOMEM;
		if (copy_from_user(sysfs_mbox->txmit_buff->virt,
			(void __user *) (unsigned long)user_ptr,
			data_length))
			return -ENOMEM;
		sysfs_mbox->user_ptr = user_ptr;
		sysfs_mbox->data_length = data_length;
		mb->un.varWords[3] = putPaddrLow(sysfs_mbox->txmit_buff->phys);
		mb->un.varWords[4] = putPaddrHigh(sysfs_mbox->txmit_buff->phys);
		return 0;

	default:
		return 0;
	}
	return 0;
}

static int
lpfc_copy_sli4_bde_touser(struct lpfc_hba *phba,
		struct lpfc_sysfs_mbox *sysfs_mbox)
{
	struct lpfc_mbx_sli4_config *sli4_config;

	if (phba->sli_rev != LPFC_SLI_REV4)
		return 0;

	switch (sysfs_mbox->mbox->u.mb.mbxCommand) {
	case MBX_DUMP_MEMORY:
		if (!sysfs_mbox->txmit_buff ||
			!sysfs_mbox->txmit_buff->virt)
			return -EIO;

		if (copy_to_user((void __user *)
			(unsigned long)sysfs_mbox->user_ptr,
			sysfs_mbox->txmit_buff->virt,
			sysfs_mbox->data_length))
			return -EIO;
		else
			return 0;
	case MBX_SLI4_CONFIG:
		sli4_config = &sysfs_mbox->mbox->u.mqe.un.sli4_config;
		/* If this is embedded do nothing. */
		if (bf_get(lpfc_mbox_hdr_emb, &sli4_config->header.cfg_mhdr))
			return 0;
		if (!sysfs_mbox->txmit_buff ||
			!sysfs_mbox->txmit_buff->virt)
			return -EIO;
		if (copy_to_user((void __user *)
			(unsigned long)sysfs_mbox->user_ptr,
			sysfs_mbox->txmit_buff->virt,
			sysfs_mbox->data_length))
			return -EIO;
		else
			return 0;

	default:
		return 0;
	}

	return 0;
}


/**
 * sysfs_mbox_read - Read method for reading information via mbox
 * @kobj: kernel kobject that contains the kernel class device.
 * @bin_attr: kernel attributes passed to us.
 * @buf: contains the data to be read from sysfs mbox.
 * @off: offset into buffer to beginning of data.
 * @count: bytes to transfer.
 *
 * Description:
 * Accessed via /sys/class/scsi_host/hostxxx/mbox.
 * Uses the sysfs mbox to receive data from to the adapter.
 *
 * Returns:
 * -ERANGE off greater than mailbox command size
 * -EINVAL off, count or buff address invalid
 * zero if off and count are zero
 * -EACCES adapter over temp
 * -EPERM garbage can value to catch a multitude of errors
 * -EAGAIN management IO not permitted, state or off error
 * -ETIME mailbox timeout
 * -ENODEV mailbox error
 * count number of bytes transferred
 **/
static ssize_t
sysfs_mbox_read(struct kobject *kobj, char *buf, loff_t off, size_t count)
{
	struct class_device *cdev = container_of(kobj, struct class_device,
						 kobj);
	struct Scsi_Host  *shost = class_to_shost(cdev);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	int rc;
	int wait_4_menlo_maint = 0;
	struct lpfc_sysfs_mbox *sysfs_mbox;
	ssize_t ret;
	sysfs_mbox = lpfc_get_sysfs_mbox(phba, 0);

	if (!sysfs_mbox)
		return -EPERM;

	/*
	 * If sysfs expect the writing of buffer and
	 * app doesnot know how to do it, fail the mailbox
	 * command.
	 */
	if ((sysfs_mbox->state == SMBOX_WRITING_BUFF) &&
		(sysfs_mbox->extoff == 0)) {
		spin_lock_irq(&phba->hbalock);
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -EINVAL;
	}
	if (sysfs_mbox->state == SMBOX_READING_BUFF) {
		ret = lpfc_syfs_mbox_copy_rcv_buff(phba, sysfs_mbox,
					buf, off, count);
		lpfc_printf_log(phba, KERN_INFO, LOG_INIT,
				"1245 mbox: cmd 0x%x, 0x%x ret %x\n",
				sysfs_mbox->mbox->u.mb.mbxCommand,
				sysfs_mbox->mbox->u.mb.un.varWords[0],
				(uint32_t)ret);
		return ret;
	}

	if (sysfs_mbox->state == SMBOX_READING_MBEXT) {
		ret = lpfc_syfs_mbox_copy_extdata(phba, sysfs_mbox,
					buf, off, count);
		return ret;
	}

	if (off > MAILBOX_CMD_SIZE)
		return -ERANGE;

	if ((count + off) > MAILBOX_CMD_SIZE)
		count = MAILBOX_CMD_SIZE - off;

	if (off % 4 ||  count % 4 || (unsigned long)buf % 4)
		return -EINVAL;

	if (off && count == 0)
		return 0;

	if (lpfc_copy_sli4_bde_fromuser(phba, sysfs_mbox)) {
		spin_lock_irq(&phba->hbalock);
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return  -EACCES;
	}

	spin_lock_irq(&phba->hbalock);

	if (phba->over_temp_state == HBA_OVER_TEMP) {
		sysfs_mbox_idle(phba, sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return  -EACCES;
	}

	if (off == 0 &&
	    ((sysfs_mbox->state  == SMBOX_WRITING)  ||
	    (sysfs_mbox->state  == SMBOX_WRITING_MBEXT) ||
	    (sysfs_mbox->state  == SMBOX_WRITING_BUFF) ) &&
	    sysfs_mbox->offset >= 2 * sizeof(uint32_t)) {

		switch (sysfs_mbox->mbox->u.mb.mbxCommand) {
			/* Offline only */
		case MBX_INIT_LINK:
		case MBX_DOWN_LINK:
		case MBX_CONFIG_LINK:
		case MBX_CONFIG_RING:
		case MBX_RESET_RING:
		case MBX_UNREG_LOGIN:
		case MBX_CLEAR_LA:
		case MBX_DUMP_CONTEXT:
		case MBX_RUN_DIAGS:
		case MBX_RESTART:
		case MBX_SET_MASK:
			if (!(vport->fc_flag & FC_OFFLINE_MODE)) {
				printk(KERN_WARNING "mbox_read:Command 0x%x "
				       "is illegal in on-line state\n",
				       sysfs_mbox->mbox->u.mb.mbxCommand);
				sysfs_mbox_idle(phba,sysfs_mbox);
				spin_unlock_irq(&phba->hbalock);
				return -EPERM;
			}
		case MBX_WRITE_NV:
		case MBX_WRITE_VPARMS:
		case MBX_LOAD_SM:
		case MBX_READ_NV:
		case MBX_READ_CONFIG:
		case MBX_READ_RCONFIG:
		case MBX_READ_STATUS:
		case MBX_READ_XRI:
		case MBX_READ_REV:
		case MBX_READ_LNK_STAT:
		case MBX_DUMP_MEMORY:
		case MBX_DOWN_LOAD:
		case MBX_KILL_BOARD:
		case MBX_LOAD_AREA:
		case MBX_LOAD_EXP_ROM:
		case MBX_BEACON:
		case MBX_DEL_LD_ENTRY:
		case MBX_SET_DEBUG:
		case MBX_SLI4_CONFIG:
		case MBX_READ_EVENT_LOG_STATUS:
			break;
		case MBX_SET_VARIABLE:
			lpfc_printf_log(phba, KERN_INFO, LOG_INIT,
				"1226 mbox: set_variable 0x%x, 0x%x\n",
				sysfs_mbox->mbox->u.mb.un.varWords[0],
				sysfs_mbox->mbox->u.mb.un.varWords[1]);
			if ((sysfs_mbox->mbox->u.mb.un.varWords[0]
				== SETVAR_MLOMNT)
				&& (sysfs_mbox->mbox->u.mb.un.varWords[1]
				== 1)) {
				wait_4_menlo_maint = 1;
				phba->wait_4_mlo_maint_flg = 1;
			} else if (sysfs_mbox->mbox->u.mb.un.varWords[0] ==
					SETVAR_MLORST) {
				phba->link_flag &= ~LS_LOOPBACK_MODE;
				phba->fc_topology = TOPOLOGY_PT_PT;
			}
		case MBX_WRITE_WWN:
		case MBX_UPDATE_CFG:
		case MBX_PORT_CAPABILITIES:
		case MBX_PORT_IOV_CONTROL:
			break;
		case MBX_RUN_BIU_DIAG64:
			if (sysfs_mbox->mbox->u.mb.un.varBIUdiag.un.s2.
				xmit_bde64.tus.f.bdeSize) {
				sysfs_mbox->mbox->u.mb.un.varBIUdiag.un.s2.
					xmit_bde64.addrHigh =
					putPaddrHigh(sysfs_mbox->
						txmit_buff->phys);
				sysfs_mbox->mbox->u.mb.un.varBIUdiag.un.s2.
					xmit_bde64.addrLow =
					putPaddrLow(sysfs_mbox->
						txmit_buff->phys);
			}

			if (sysfs_mbox->mbox->u.mb.un.varBIUdiag.un.s2.
				rcv_bde64.tus.f.bdeSize) {
				sysfs_mbox->mbox->u.mb.un.varBIUdiag.un.s2.
					rcv_bde64.addrHigh =
					putPaddrHigh(sysfs_mbox->
						rcv_buff->phys);
				sysfs_mbox->mbox->u.mb.un.varBIUdiag.un.s2.
				rcv_bde64.addrLow =
				putPaddrLow(sysfs_mbox->rcv_buff->phys);
			}
			break;
		case MBX_WRITE_EVENT_LOG:
			break;
		case MBX_READ_EVENT_LOG:

			if (sysfs_mbox->mbox->u.mb.un.varRdEventLog.
				rcv_bde64.tus.f.bdeSize) {
				sysfs_mbox->mbox->u.mb.un.varRdEventLog.
					rcv_bde64.addrHigh =
					putPaddrHigh(sysfs_mbox->
						rcv_buff->phys);
				sysfs_mbox->mbox->u.mb.un.varRdEventLog.
				rcv_bde64.addrLow =
				putPaddrLow(sysfs_mbox->rcv_buff->phys);
			}
			break;

		case MBX_READ_SPARM64:
		case MBX_READ_LA:
		case MBX_READ_LA64:
		case MBX_REG_LOGIN:
		case MBX_REG_LOGIN64:
		case MBX_CONFIG_PORT:
		case MBX_RUN_BIU_DIAG:
			printk(KERN_WARNING "mbox_read: Illegal Command 0x%x\n",
			       sysfs_mbox->mbox->u.mb.mbxCommand);
			sysfs_mbox_idle(phba,sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			return -EPERM;
		default:
			printk(KERN_WARNING "mbox_read: Unknown Command 0x%x\n",
			       sysfs_mbox->mbox->u.mb.mbxCommand);
			sysfs_mbox_idle(phba,sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			return -EPERM;
		}

		if (sysfs_mbox->mbox_data.in_ext_wlen ||
			sysfs_mbox->mbox_data.out_ext_wlen) {
			sysfs_mbox->mbox->context2 = sysfs_mbox->mbext;
			sysfs_mbox->mbox->in_ext_byte_len =
				sysfs_mbox->mbox_data.in_ext_wlen *
				sizeof(uint32_t);
			sysfs_mbox->mbox->out_ext_byte_len =
				sysfs_mbox->mbox_data.out_ext_wlen *
				sizeof(uint32_t);
			sysfs_mbox->mbox->mbox_offset_word =
				sysfs_mbox->mbox_data.mboffset;
		}

		/* If HBA encountered an error attention, allow only DUMP
		 * or RESTART mailbox commands until the HBA is restarted.
		 */
		if (phba->pport->stopped &&
		    sysfs_mbox->mbox->u.mb.mbxCommand != MBX_DUMP_MEMORY &&
		    sysfs_mbox->mbox->u.mb.mbxCommand != MBX_RESTART &&
		    sysfs_mbox->mbox->u.mb.mbxCommand != MBX_WRITE_VPARMS &&
		    sysfs_mbox->mbox->u.mb.mbxCommand != MBX_WRITE_WWN)
			lpfc_printf_log(phba, KERN_WARNING, LOG_MBOX,
					"1259 mbox: Issued mailbox cmd "
					"0x%x while in stopped state.\n",
					sysfs_mbox->mbox->u.mb.mbxCommand);

		sysfs_mbox->mbox->vport = vport;

		/* Don't allow mailbox commands to be sent when blocked
		 * or when in the middle of discovery
		 */
		if (phba->sli.sli_flag & LPFC_BLOCK_MGMT_IO) {
			sysfs_mbox_idle(phba,sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			return  -EAGAIN;
		}

		if ((vport->fc_flag & FC_OFFLINE_MODE) ||
		    (!(phba->sli.sli_flag & LPFC_SLI_ACTIVE))) {

			spin_unlock_irq(&phba->hbalock);
			rc = lpfc_sli_issue_mbox (phba,
						  sysfs_mbox->mbox,
						  MBX_POLL);
			spin_lock_irq(&phba->hbalock);

		} else {
			spin_unlock_irq(&phba->hbalock);
			rc = lpfc_sli_issue_mbox_wait (phba,
						       sysfs_mbox->mbox,
				lpfc_mbox_tmo_val(phba,
				    sysfs_mbox->mbox->u.mb.mbxCommand) * HZ);
			spin_lock_irq(&phba->hbalock);
		}

		if (rc != MBX_SUCCESS) {
			if (rc == MBX_TIMEOUT) {
				sysfs_mbox->mbox = NULL;
			}
			sysfs_mbox_idle(phba,sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			return  (rc == MBX_TIMEOUT) ? -ETIME : -ENODEV;
		}

		if (lpfc_copy_sli4_bde_touser(phba, sysfs_mbox)) {
			spin_lock_irq(&phba->hbalock);
			sysfs_mbox_idle(phba, sysfs_mbox);
			spin_unlock_irq(&phba->hbalock);
			return  -EACCES;
		}

		if (wait_4_menlo_maint) {
			lpfc_printf_log(phba, KERN_WARNING, LOG_LIBDFC,
				"1229 waiting for menlo mnt\n");
			spin_unlock_irq(&phba->hbalock);
			if (phba->wait_4_mlo_maint_flg)
				wait_event_interruptible_timeout(
					phba->wait_4_mlo_m_q,
					phba->wait_4_mlo_maint_flg ==0,
					60 * HZ);
			spin_lock_irq(&phba->hbalock);
			if (phba->wait_4_mlo_maint_flg) {
				sysfs_mbox_idle(phba,sysfs_mbox);
				phba->wait_4_mlo_maint_flg = 0;
				spin_unlock_irq(&phba->hbalock);
				return -EINTR;
			} else
				spin_unlock_irq(&phba->hbalock);

			spin_lock_irq(&phba->hbalock);
			if (phba->wait_4_mlo_maint_flg != 0) {
				sysfs_mbox_idle(phba,sysfs_mbox);
				phba->wait_4_mlo_maint_flg = 0;
				spin_unlock_irq(&phba->hbalock);
				return -ETIME;
			}

		}
		sysfs_mbox->state = SMBOX_READING;
	}
	else if (sysfs_mbox->offset != off ||
		 sysfs_mbox->state  != SMBOX_READING) {
		sysfs_mbox_idle(phba,sysfs_mbox);
		spin_unlock_irq(&phba->hbalock);
		return -EAGAIN;
	}

	memcpy(buf, (uint8_t *) & sysfs_mbox->mbox->u.mb + off, count);

	sysfs_mbox->offset = off + count;

	if ((sysfs_mbox->offset == MAILBOX_CMD_SIZE) &&
		((sysfs_mbox->mbox->u.mb.mbxCommand == MBX_RUN_BIU_DIAG64) ||
		(sysfs_mbox->mbox->u.mb.mbxCommand == MBX_READ_EVENT_LOG))) {
		sysfs_mbox->state  = SMBOX_READING_BUFF;
		sysfs_mbox->extoff = 0;
		spin_unlock_irq(&phba->hbalock);
		return count;
	}

	if ((sysfs_mbox->offset == MAILBOX_CMD_SIZE) &&
	     sysfs_mbox->mbox_data.out_ext_wlen) {
		sysfs_mbox->state  = SMBOX_READING_MBEXT;
		sysfs_mbox->extoff = 0;
		spin_unlock_irq(&phba->hbalock);
		return count;
	}

	if (sysfs_mbox->offset == MAILBOX_CMD_SIZE)
		sysfs_mbox_idle(phba,sysfs_mbox);

	spin_unlock_irq(&phba->hbalock);

	return count;
}

static struct bin_attribute sysfs_mbox_attr = {
	.attr = {
		.name = "mbox",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = MAILBOX_MAX_XMIT_SIZE,
	.read = sysfs_mbox_read,
	.write = sysfs_mbox_write,
};

/**
 * lpfc_alloc_sysfs_attr - Creates the ctlreg and mbox entries
 * @vport: address of lpfc vport structure.
 *
 * Return codes:
 * zero on success
 * error return code from sysfs_create_bin_file()
 **/
int
lpfc_alloc_sysfs_attr(struct lpfc_vport *vport)
{
	struct Scsi_Host *shost = lpfc_shost_from_vport(vport);
	int error;

	error = sysfs_create_bin_file(&shost->shost_classdev.kobj,
				      &sysfs_drvr_stat_data_attr);

	/* Virtual ports do not need ctrl_reg and mbox */
	if (error || vport->port_type == LPFC_NPIV_PORT)
		goto out;

	error = sysfs_create_bin_file(&shost->shost_classdev.kobj,
				      &sysfs_ctlreg_attr);
	if (error)
		goto out_remove_stat_attr;

	error = sysfs_create_bin_file(&shost->shost_classdev.kobj,
				      &sysfs_mbox_attr);
	if (error)
		goto out_remove_ctlreg_attr;

	error = sysfs_create_bin_file(&shost->shost_classdev.kobj,
				      &sysfs_menlo_attr);
	if (error)
		goto out_remove_mbox_attr;

	return 0;
out_remove_mbox_attr:
	sysfs_remove_bin_file(&shost->shost_classdev.kobj, &sysfs_mbox_attr);
out_remove_ctlreg_attr:
	sysfs_remove_bin_file(&shost->shost_classdev.kobj, &sysfs_ctlreg_attr);
out_remove_stat_attr:
	sysfs_remove_bin_file(&shost->shost_classdev.kobj,
			&sysfs_drvr_stat_data_attr);
out:
	return error;
}

/**
 * lpfc_free_sysfs_attr - Removes the ctlreg and mbox entries
 * @vport: address of lpfc vport structure.
 **/
void
lpfc_free_sysfs_attr(struct lpfc_vport *vport)
{
	struct Scsi_Host *shost = lpfc_shost_from_vport(vport);
	sysfs_remove_bin_file(&shost->shost_classdev.kobj,
		&sysfs_drvr_stat_data_attr);
	/* Virtual ports do not need ctrl_reg and mbox */
	if (vport->port_type == LPFC_NPIV_PORT)
		return;
	sysfs_remove_bin_file(&shost->shost_classdev.kobj, &sysfs_mbox_attr);
	sysfs_remove_bin_file(&shost->shost_classdev.kobj, &sysfs_ctlreg_attr);
	sysfs_remove_bin_file(&shost->shost_classdev.kobj, &sysfs_menlo_attr);
}


/*
 * Dynamic FC Host Attributes Support
 */

/**
 * lpfc_get_host_port_id - Copy the vport DID into the scsi host port id
 * @shost: kernel scsi host pointer.
 **/
static void
lpfc_get_host_port_id(struct Scsi_Host *shost)
{
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;

	/* note: fc_myDID already in cpu endianness */
	fc_host_port_id(shost) = vport->fc_myDID;
}

/**
 * lpfc_get_host_port_type - Set the value of the scsi host port type
 * @shost: kernel scsi host pointer.
 **/
static void
lpfc_get_host_port_type(struct Scsi_Host *shost)
{
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	spin_lock_irq(shost->host_lock);

	if (vport->port_type == LPFC_NPIV_PORT) {
		fc_host_port_type(shost) = FC_PORTTYPE_NPORT;
	} else if (lpfc_is_link_up(phba)) {
		if (phba->fc_topology == TOPOLOGY_LOOP) {
			if (vport->fc_flag & FC_PUBLIC_LOOP)
				fc_host_port_type(shost) = FC_PORTTYPE_NLPORT;
			else
				fc_host_port_type(shost) = FC_PORTTYPE_LPORT;
		} else {
			if (vport->fc_flag & FC_FABRIC)
				fc_host_port_type(shost) = FC_PORTTYPE_NPORT;
			else
				fc_host_port_type(shost) = FC_PORTTYPE_PTP;
		}
	} else
		fc_host_port_type(shost) = FC_PORTTYPE_UNKNOWN;

	spin_unlock_irq(shost->host_lock);
}

/**
 * lpfc_get_host_port_state - Set the value of the scsi host port state
 * @shost: kernel scsi host pointer.
 **/
static void
lpfc_get_host_port_state(struct Scsi_Host *shost)
{
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	spin_lock_irq(shost->host_lock);

	if (vport->fc_flag & FC_OFFLINE_MODE)
		fc_host_port_state(shost) = FC_PORTSTATE_OFFLINE;
	else {
		switch (phba->link_state) {
		case LPFC_LINK_UNKNOWN:
		case LPFC_LINK_DOWN:
			fc_host_port_state(shost) = FC_PORTSTATE_LINKDOWN;
			break;
		case LPFC_LINK_UP:
		case LPFC_CLEAR_LA:
		case LPFC_HBA_READY:
			/* Links up, beyond this port_type reports state */
			fc_host_port_state(shost) = FC_PORTSTATE_ONLINE;
			break;
		case LPFC_HBA_ERROR:
			fc_host_port_state(shost) = FC_PORTSTATE_ERROR;
			break;
		default:
			fc_host_port_state(shost) = FC_PORTSTATE_UNKNOWN;
			break;
		}
	}

	spin_unlock_irq(shost->host_lock);
}

/**
 * lpfc_get_host_speed - Set the value of the scsi host speed
 * @shost: kernel scsi host pointer.
 **/
static void
lpfc_get_host_speed(struct Scsi_Host *shost)
{
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;

	spin_lock_irq(shost->host_lock);

	if (lpfc_is_link_up(phba)) {
		switch(phba->fc_linkspeed) {
			case LA_1GHZ_LINK:
				fc_host_speed(shost) = FC_PORTSPEED_1GBIT;
			break;
			case LA_2GHZ_LINK:
				fc_host_speed(shost) = FC_PORTSPEED_2GBIT;
			break;
			case LA_4GHZ_LINK:
				fc_host_speed(shost) = FC_PORTSPEED_4GBIT;
			break;
			case LA_8GHZ_LINK:
				fc_host_speed(shost) = FC_PORTSPEED_8GBIT;
			break;
			case LA_10GHZ_LINK:
				fc_host_speed(shost) = FC_PORTSPEED_10GBIT;
			break;
			default:
				fc_host_speed(shost) = FC_PORTSPEED_UNKNOWN;
			break;
		}
	} else
		fc_host_speed(shost) = FC_PORTSPEED_UNKNOWN;

	spin_unlock_irq(shost->host_lock);
}

/**
 * lpfc_get_host_fabric_name - Set the value of the scsi host fabric name
 * @shost: kernel scsi host pointer.
 **/
static void
lpfc_get_host_fabric_name (struct Scsi_Host *shost)
{
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	u64 node_name;

	spin_lock_irq(shost->host_lock);

	if ((vport->fc_flag & FC_FABRIC) ||
	    ((phba->fc_topology == TOPOLOGY_LOOP) &&
	     (vport->fc_flag & FC_PUBLIC_LOOP)))
		node_name = wwn_to_u64(phba->fc_fabparam.nodeName.u.wwn);
	else
		/* fabric is local port if there is no F/FL_Port */
		node_name = 0;

	spin_unlock_irq(shost->host_lock);

	fc_host_fabric_name(shost) = node_name;
}

/**
 * lpfc_get_stats - Return statistical information about the adapter
 * @shost: kernel scsi host pointer.
 *
 * Notes:
 * NULL on error for link down, no mbox pool, sli2 active,
 * management not allowed, memory allocation error, or mbox error.
 *
 * Returns:
 * NULL for error
 * address of the adapter host statistics
 **/
static struct fc_host_statistics *
lpfc_get_stats(struct Scsi_Host *shost)
{
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	struct lpfc_sli   *psli = &phba->sli;
	struct fc_host_statistics *hs = &phba->link_stats;
	struct lpfc_lnk_stat * lso = &psli->lnk_stat_offsets;
	LPFC_MBOXQ_t *pmboxq;
	MAILBOX_t *pmb;
	unsigned long seconds;
	int rc = 0;

	/*
	 * prevent udev from issuing mailbox commands until the port is
	 * configured.
	 */
	if (phba->link_state < LPFC_LINK_DOWN ||
	    !phba->mbox_mem_pool ||
	    (phba->sli.sli_flag & LPFC_SLI_ACTIVE) == 0)
		return NULL;

	if (phba->sli.sli_flag & LPFC_BLOCK_MGMT_IO)
		return NULL;

	pmboxq = mempool_alloc(phba->mbox_mem_pool, GFP_KERNEL);
	if (!pmboxq)
		return NULL;
	memset(pmboxq, 0, sizeof (LPFC_MBOXQ_t));

	pmb = &pmboxq->u.mb;
	pmb->mbxCommand = MBX_READ_STATUS;
	pmb->mbxOwner = OWN_HOST;
	pmboxq->context1 = NULL;
	pmboxq->vport = vport;

	if ((vport->fc_flag & FC_OFFLINE_MODE) ||
		(!(psli->sli_flag & LPFC_SLI_ACTIVE)))
		rc = lpfc_sli_issue_mbox(phba, pmboxq, MBX_POLL);
	else
		rc = lpfc_sli_issue_mbox_wait(phba, pmboxq, phba->fc_ratov * 2);

	if (rc != MBX_SUCCESS) {
		if (rc != MBX_TIMEOUT)
			mempool_free(pmboxq, phba->mbox_mem_pool);
		return NULL;
	}

	memset(hs, 0, sizeof (struct fc_host_statistics));

	hs->tx_frames = pmb->un.varRdStatus.xmitFrameCnt;
	hs->tx_words = (pmb->un.varRdStatus.xmitByteCnt * 256);
	hs->rx_frames = pmb->un.varRdStatus.rcvFrameCnt;
	hs->rx_words = (pmb->un.varRdStatus.rcvByteCnt * 256);

	memset(pmboxq, 0, sizeof (LPFC_MBOXQ_t));
	pmb->mbxCommand = MBX_READ_LNK_STAT;
	pmb->mbxOwner = OWN_HOST;
	pmboxq->context1 = NULL;
	pmboxq->vport = vport;

	if ((vport->fc_flag & FC_OFFLINE_MODE) ||
	    (!(psli->sli_flag & LPFC_SLI_ACTIVE)))
		rc = lpfc_sli_issue_mbox(phba, pmboxq, MBX_POLL);
	else
		rc = lpfc_sli_issue_mbox_wait(phba, pmboxq, phba->fc_ratov * 2);

	if (rc != MBX_SUCCESS) {
		if (rc != MBX_TIMEOUT)
			mempool_free(pmboxq, phba->mbox_mem_pool);
		return NULL;
	}

	hs->link_failure_count = pmb->un.varRdLnk.linkFailureCnt;
	hs->loss_of_sync_count = pmb->un.varRdLnk.lossSyncCnt;
	hs->loss_of_signal_count = pmb->un.varRdLnk.lossSignalCnt;
	hs->prim_seq_protocol_err_count = pmb->un.varRdLnk.primSeqErrCnt;
	hs->invalid_tx_word_count = pmb->un.varRdLnk.invalidXmitWord;
	hs->invalid_crc_count = pmb->un.varRdLnk.crcCnt;
	hs->error_frames = pmb->un.varRdLnk.crcCnt;

	hs->link_failure_count -= lso->link_failure_count;
	hs->loss_of_sync_count -= lso->loss_of_sync_count;
	hs->loss_of_signal_count -= lso->loss_of_signal_count;
	hs->prim_seq_protocol_err_count -= lso->prim_seq_protocol_err_count;
	hs->invalid_tx_word_count -= lso->invalid_tx_word_count;
	hs->invalid_crc_count -= lso->invalid_crc_count;
	hs->error_frames -= lso->error_frames;

	if (phba->hba_flag & HBA_FCOE_SUPPORT) {
		hs->lip_count = -1;
		hs->nos_count = (phba->link_events >> 1);
		hs->nos_count -= lso->link_events;
	} else if (phba->fc_topology == TOPOLOGY_LOOP) {
		hs->lip_count = (phba->fc_eventTag >> 1);
		hs->lip_count -= lso->link_events;
		hs->nos_count = -1;
	} else {
		hs->lip_count = -1;
		hs->nos_count = (phba->fc_eventTag >> 1);
		hs->nos_count -= lso->link_events;
	}

	hs->dumped_frames = -1;

	seconds = get_seconds();
	if (seconds < psli->stats_start)
		hs->seconds_since_last_reset = seconds +
				((unsigned long)-1 - psli->stats_start);
	else
		hs->seconds_since_last_reset = seconds - psli->stats_start;

	mempool_free(pmboxq, phba->mbox_mem_pool);

	return hs;
}

/**
 * lpfc_reset_stats - Copy the adapter link stats information
 * @shost: kernel scsi host pointer.
 **/
static void
lpfc_reset_stats(struct Scsi_Host *shost)
{
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_hba   *phba = vport->phba;
	struct lpfc_sli   *psli = &phba->sli;
	struct lpfc_lnk_stat *lso = &psli->lnk_stat_offsets;
	LPFC_MBOXQ_t *pmboxq;
	MAILBOX_t *pmb;
	int rc = 0;

	if (phba->sli.sli_flag & LPFC_BLOCK_MGMT_IO)
		return;

	pmboxq = mempool_alloc(phba->mbox_mem_pool, GFP_KERNEL);
	if (!pmboxq)
		return;
	memset(pmboxq, 0, sizeof(LPFC_MBOXQ_t));

	pmb = &pmboxq->u.mb;
	pmb->mbxCommand = MBX_READ_STATUS;
	pmb->mbxOwner = OWN_HOST;
	pmb->un.varWords[0] = 0x1; /* reset request */
	pmboxq->context1 = NULL;
	pmboxq->vport = vport;

	if ((vport->fc_flag & FC_OFFLINE_MODE) ||
		(!(psli->sli_flag & LPFC_SLI_ACTIVE)))
		rc = lpfc_sli_issue_mbox(phba, pmboxq, MBX_POLL);
	else
		rc = lpfc_sli_issue_mbox_wait(phba, pmboxq, phba->fc_ratov * 2);

	if (rc != MBX_SUCCESS) {
		if (rc != MBX_TIMEOUT)
			mempool_free(pmboxq, phba->mbox_mem_pool);
		return;
	}

	memset(pmboxq, 0, sizeof(LPFC_MBOXQ_t));
	pmb->mbxCommand = MBX_READ_LNK_STAT;
	pmb->mbxOwner = OWN_HOST;
	pmboxq->context1 = NULL;
	pmboxq->vport = vport;

	if ((vport->fc_flag & FC_OFFLINE_MODE) ||
	    (!(psli->sli_flag & LPFC_SLI_ACTIVE)))
		rc = lpfc_sli_issue_mbox(phba, pmboxq, MBX_POLL);
	else
		rc = lpfc_sli_issue_mbox_wait(phba, pmboxq, phba->fc_ratov * 2);

	if (rc != MBX_SUCCESS) {
		if (rc != MBX_TIMEOUT)
			mempool_free( pmboxq, phba->mbox_mem_pool);
		return;
	}

	lso->link_failure_count = pmb->un.varRdLnk.linkFailureCnt;
	lso->loss_of_sync_count = pmb->un.varRdLnk.lossSyncCnt;
	lso->loss_of_signal_count = pmb->un.varRdLnk.lossSignalCnt;
	lso->prim_seq_protocol_err_count = pmb->un.varRdLnk.primSeqErrCnt;
	lso->invalid_tx_word_count = pmb->un.varRdLnk.invalidXmitWord;
	lso->invalid_crc_count = pmb->un.varRdLnk.crcCnt;
	lso->error_frames = pmb->un.varRdLnk.crcCnt;
	if (phba->hba_flag & HBA_FCOE_SUPPORT)
		lso->link_events = (phba->link_events >> 1);
	else
		lso->link_events = (phba->fc_eventTag >> 1);

	psli->stats_start = get_seconds();

	mempool_free(pmboxq, phba->mbox_mem_pool);

	return;
}

/*
 * The LPFC driver treats linkdown handling as target loss events so there
 * are no sysfs handlers for link_down_tmo.
 */

/**
 * lpfc_get_node_by_target - Return the nodelist for a target
 * @starget: kernel scsi target pointer.
 *
 * Returns:
 * address of the node list if found
 * NULL target not found
 **/
static struct lpfc_nodelist *
lpfc_get_node_by_target(struct scsi_target *starget)
{
	struct Scsi_Host  *shost = dev_to_shost(starget->dev.parent);
	struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata;
	struct lpfc_nodelist *ndlp;

	spin_lock_irq(shost->host_lock);
	/* Search for this, mapped, target ID */
	list_for_each_entry(ndlp, &vport->fc_nodes, nlp_listp) {
		if (NLP_CHK_NODE_ACT(ndlp) &&
		    ndlp->nlp_state == NLP_STE_MAPPED_NODE &&
		    starget->id == ndlp->nlp_sid) {
			spin_unlock_irq(shost->host_lock);
			return ndlp;
		}
	}
	spin_unlock_irq(shost->host_lock);
	return NULL;
}

/**
 * lpfc_get_starget_port_id - Set the target port id to the ndlp DID or -1
 * @starget: kernel scsi target pointer.
 **/
static void
lpfc_get_starget_port_id(struct scsi_target *starget)
{
	struct lpfc_nodelist *ndlp = lpfc_get_node_by_target(starget);

	fc_starget_port_id(starget) = ndlp ? ndlp->nlp_DID : -1;
}

/**
 * lpfc_get_starget_node_name - Set the target node name
 * @starget: kernel scsi target pointer.
 *
 * Description: Set the target node name to the ndlp node name wwn or zero.
 **/
static void
lpfc_get_starget_node_name(struct scsi_target *starget)
{
	struct lpfc_nodelist *ndlp = lpfc_get_node_by_target(starget);

	fc_starget_node_name(starget) =
		ndlp ? wwn_to_u64(ndlp->nlp_nodename.u.wwn) : 0;
}

/**
 * lpfc_get_starget_port_name - Set the target port name
 * @starget: kernel scsi target pointer.
 *
 * Description:  set the target port name to the ndlp port name wwn or zero.
 **/
static void
lpfc_get_starget_port_name(struct scsi_target *starget)
{
	struct lpfc_nodelist *ndlp = lpfc_get_node_by_target(starget);

	fc_starget_port_name(starget) =
		ndlp ? wwn_to_u64(ndlp->nlp_portname.u.wwn) : 0;
}

/**
 * lpfc_set_rport_loss_tmo - Set the rport dev loss tmo
 * @rport: fc rport address.
 * @timeout: new value for dev loss tmo.
 *
 * Description:
 * If timeout is non zero set the dev_loss_tmo to timeout, else set
 * dev_loss_tmo to one.
 **/
static void
lpfc_set_rport_loss_tmo(struct fc_rport *rport, uint32_t timeout)
{
	if (timeout)
		rport->dev_loss_tmo = timeout;
	else
		rport->dev_loss_tmo = 1;
}

/**
 * lpfc_rport_show_function - Return rport target information
 *
 * Description:
 * Macro that uses field to generate a function with the name lpfc_show_rport_
 *
 * lpfc_show_rport_##field: returns the bytes formatted in buf
 * @cdev: class converted to an fc_rport.
 * @buf: on return contains the target_field or zero.
 *
 * Returns: size of formatted string.
 **/
#define lpfc_rport_show_function(field, format_string, sz, cast)	\
static ssize_t								\
lpfc_show_rport_##field (struct class_device *cdev, char *buf)		\
{									\
	struct fc_rport *rport = transport_class_to_rport(cdev);	\
	struct lpfc_rport_data *rdata = rport->hostdata;		\
	return snprintf(buf, sz, format_string,				\
		(rdata->target) ? cast rdata->target->field : 0);	\
}

#define lpfc_rport_rd_attr(field, format_string, sz)			\
	lpfc_rport_show_function(field, format_string, sz, )		\
static FC_RPORT_ATTR(field, S_IRUGO, lpfc_show_rport_##field, NULL)

/**
 * lpfc_hba_log_verbose_init - Set hba's log verbose level
 * @phba: Pointer to lpfc_hba struct.
 *
 * This function is called by the lpfc_get_cfgparam() routine to set the
 * module lpfc_log_verbose into the @phba cfg_log_verbose for use with
 * log messsage according to the module's lpfc_log_verbose parameter setting
 * before hba port or vport created.
 **/
static void
lpfc_hba_log_verbose_init(struct lpfc_hba *phba, uint32_t verbose)
{
	phba->cfg_log_verbose = verbose;
}

struct fc_function_template lpfc_transport_functions = {
	/* fixed attributes the driver supports */
	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,
	.show_host_supported_fc4s = 1,
	.show_host_supported_speeds = 1,
	.show_host_maxframe_size = 1,

	/* dynamic attributes the driver supports */
	.get_host_port_id = lpfc_get_host_port_id,
	.show_host_port_id = 1,

	.get_host_port_type = lpfc_get_host_port_type,
	.show_host_port_type = 1,

	.get_host_port_state = lpfc_get_host_port_state,
	.show_host_port_state = 1,

	/* active_fc4s is shown but doesn't change (thus no get function) */
	.show_host_active_fc4s = 1,

	.get_host_speed = lpfc_get_host_speed,
	.show_host_speed = 1,

	.get_host_fabric_name = lpfc_get_host_fabric_name,
	.show_host_fabric_name = 1,

	/*
	 * The LPFC driver treats linkdown handling as target loss events
	 * so there are no sysfs handlers for link_down_tmo.
	 */

	.get_fc_host_stats = lpfc_get_stats,
	.reset_fc_host_stats = lpfc_reset_stats,

	.dd_fcrport_size = sizeof(struct lpfc_rport_data),
	.show_rport_maxframe_size = 1,
	.show_rport_supported_classes = 1,

	.set_rport_dev_loss_tmo = lpfc_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 1,

	.get_starget_port_id  = lpfc_get_starget_port_id,
	.show_starget_port_id = 1,

	.get_starget_node_name = lpfc_get_starget_node_name,
	.show_starget_node_name = 1,

	.get_starget_port_name = lpfc_get_starget_port_name,
	.show_starget_port_name = 1,

	.issue_fc_host_lip = lpfc_issue_lip,
	.dev_loss_tmo_callbk = lpfc_dev_loss_tmo_callbk,
	.terminate_rport_io = lpfc_terminate_rport_io,

};

struct fc_function_template lpfc_vport_transport_functions = {
	/* fixed attributes the driver supports */
	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,
	.show_host_supported_fc4s = 1,
	.show_host_supported_speeds = 1,
	.show_host_maxframe_size = 1,

	/* dynamic attributes the driver supports */
	.get_host_port_id = lpfc_get_host_port_id,
	.show_host_port_id = 1,

	.get_host_port_type = lpfc_get_host_port_type,
	.show_host_port_type = 1,

	.get_host_port_state = lpfc_get_host_port_state,
	.show_host_port_state = 1,

	/* active_fc4s is shown but doesn't change (thus no get function) */
	.show_host_active_fc4s = 1,

	.get_host_speed = lpfc_get_host_speed,
	.show_host_speed = 1,

	.get_host_fabric_name = lpfc_get_host_fabric_name,
	.show_host_fabric_name = 1,

	/*
	 * The LPFC driver treats linkdown handling as target loss events
	 * so there are no sysfs handlers for link_down_tmo.
	 */

	.get_fc_host_stats = lpfc_get_stats,
	.reset_fc_host_stats = lpfc_reset_stats,

	.dd_fcrport_size = sizeof(struct lpfc_rport_data),
	.show_rport_maxframe_size = 1,
	.show_rport_supported_classes = 1,

	.set_rport_dev_loss_tmo = lpfc_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 1,

	.get_starget_port_id  = lpfc_get_starget_port_id,
	.show_starget_port_id = 1,

	.get_starget_node_name = lpfc_get_starget_node_name,
	.show_starget_node_name = 1,

	.get_starget_port_name = lpfc_get_starget_port_name,
	.show_starget_port_name = 1,

	.dev_loss_tmo_callbk = lpfc_dev_loss_tmo_callbk,
	.terminate_rport_io = lpfc_terminate_rport_io,

};

/**
 * lpfc_get_cfgparam - Used during probe_one to init the adapter structure
 * @phba: lpfc_hba pointer.
 **/
void
lpfc_get_cfgparam(struct lpfc_hba *phba)
{
	lpfc_cr_delay_init(phba, lpfc_cr_delay);
	lpfc_cr_count_init(phba, lpfc_cr_count);
	lpfc_multi_ring_support_init(phba, lpfc_multi_ring_support);
	lpfc_multi_ring_rctl_init(phba, lpfc_multi_ring_rctl);
	lpfc_multi_ring_type_init(phba, lpfc_multi_ring_type);
	lpfc_ack0_init(phba, lpfc_ack0);
	lpfc_topology_init(phba, lpfc_topology);
	lpfc_pci_max_read_init(phba, lpfc_pci_max_read);
	lpfc_link_speed_init(phba, lpfc_link_speed);
	lpfc_poll_tmo_init(phba, lpfc_poll_tmo);
	lpfc_enable_npiv_init(phba, lpfc_enable_npiv);
	lpfc_use_msi_init(phba, lpfc_use_msi);
	lpfc_fcp_imax_init(phba, lpfc_fcp_imax);
	lpfc_fcp_wq_count_init(phba, lpfc_fcp_wq_count);
	lpfc_fcp_eq_count_init(phba, lpfc_fcp_eq_count);
	lpfc_enable_hba_reset_init(phba, lpfc_enable_hba_reset);
	lpfc_enable_hba_heartbeat_init(phba, lpfc_enable_hba_heartbeat);
	lpfc_hostmem_hgp_init(phba, lpfc_hostmem_hgp);
	lpfc_dev_loss_initiator_init(phba, lpfc_dev_loss_initiator);
	if (phba->sli_rev == LPFC_SLI_REV4)
		phba->cfg_poll = 0;
	else
		phba->cfg_poll = lpfc_poll;
	phba->cfg_soft_wwnn = 0L;
	phba->cfg_soft_wwpn = 0L;
	lpfc_sg_seg_cnt_init(phba, lpfc_sg_seg_cnt);
	/* Also reinitialize the host templates with new values. */
	lpfc_vport_template.sg_tablesize = phba->cfg_sg_seg_cnt;
	lpfc_template.sg_tablesize = phba->cfg_sg_seg_cnt;
	lpfc_hba_queue_depth_init(phba, lpfc_hba_queue_depth);
	lpfc_hba_log_verbose_init(phba, lpfc_log_verbose);
	lpfc_aer_support_init(phba, lpfc_aer_support);

	return;
}

/**
 * lpfc_get_vport_cfgparam - Used during port create, init the vport structure
 * @vport: lpfc_vport pointer.
 **/
void
lpfc_get_vport_cfgparam(struct lpfc_vport *vport)
{
	lpfc_log_verbose_init(vport, lpfc_log_verbose);
	lpfc_lun_queue_depth_init(vport, lpfc_lun_queue_depth);
	lpfc_devloss_tmo_init(vport, lpfc_devloss_tmo);
	lpfc_nodev_tmo_init(vport, lpfc_nodev_tmo);
	lpfc_peer_port_login_init(vport, lpfc_peer_port_login);
	lpfc_restrict_login_init(vport, lpfc_restrict_login);
	lpfc_fcp_class_init(vport, lpfc_fcp_class);
	lpfc_use_adisc_init(vport, lpfc_use_adisc);
	lpfc_max_scsicmpl_time_init(vport, lpfc_max_scsicmpl_time);
	lpfc_fdmi_on_init(vport, lpfc_fdmi_on);
	lpfc_discovery_threads_init(vport, lpfc_discovery_threads);
	lpfc_max_luns_init(vport, lpfc_max_luns);
	lpfc_scan_down_init(vport, lpfc_scan_down);
	lpfc_enable_da_id_init(vport, lpfc_enable_da_id);
	if (vport->phba->sli_rev != LPFC_SLI_REV4)
		lpfc_enable_auth_init(vport, lpfc_enable_auth);
	else
		lpfc_enable_auth_init(vport, 0);
	return;
}
