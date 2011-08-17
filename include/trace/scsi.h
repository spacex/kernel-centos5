
#ifndef _TRACE_SCSI_H
#define _TRACE_SCSI_H

#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <linux/tracepoint.h>

DEFINE_TRACE(scsi_dispatch_cmd_start,
	TPPROTO(struct scsi_cmnd *cmd),
	TPARGS(cmd));

DEFINE_TRACE(scsi_dispatch_cmd_error,
	TPPROTO(struct scsi_cmnd *cmd, int rtn),
	TPARGS(cmd, rtn));

DEFINE_TRACE(scsi_dispatch_cmd_done,
	TPPROTO(struct scsi_cmnd *cmd),
	TPARGS(cmd));

DEFINE_TRACE(scsi_dispatch_cmd_timeout,
	TPPROTO(struct scsi_cmnd *cmd),
	TPARGS(cmd));

DEFINE_TRACE(scsi_eh_wakeup,
	TPPROTO(struct Scsi_Host *shost),
	TPARGS(shost));

#endif /*  _TRACE_SCSI_H */
