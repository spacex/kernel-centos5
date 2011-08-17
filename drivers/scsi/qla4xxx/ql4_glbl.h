/*
 * QLogic iSCSI HBA Driver
 * Copyright (c)  2003-2010 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 */

#ifndef __QLA4x_GBL_H
#define	__QLA4x_GBL_H

struct iscsi_cls_conn;

int qla4xxx_hw_reset(struct scsi_qla_host *ha);
int ql4xxx_lock_drvr_wait(struct scsi_qla_host *a);
int qla4xxx_conn_start(struct iscsi_cls_conn *conn);
int qla4xxx_send_tgts(struct scsi_qla_host *ha, char *ip, uint16_t port);
int qla4xxx_send_command_to_isp(struct scsi_qla_host *ha, struct srb * srb);
int qla4xxx_initialize_adapter(struct scsi_qla_host *ha,
			       uint8_t renew_ddb_list);
int qla4xxx_soft_reset(struct scsi_qla_host *ha);

void qla4xxx_free_ddb(struct scsi_qla_host *ha, struct ddb_entry *ddb_entry);
void qla4xxx_free_ddb_list(struct scsi_qla_host *ha);
void qla4xxx_process_aen(struct scsi_qla_host *ha, uint8_t process_aen);

int qla4xxx_get_dhcp_ip_address(struct scsi_qla_host *ha);
int qla4xxx_relogin_device(struct scsi_qla_host *ha,
			   struct ddb_entry *ddb_entry);
int qla4xxx_abort_task(struct scsi_qla_host *ha, struct srb *srb);
int qla4xxx_reset_lun(struct scsi_qla_host *ha, struct ddb_entry * ddb_entry,
		      int lun);
int qla4xxx_get_flash(struct scsi_qla_host *ha, dma_addr_t dma_addr,
		      uint32_t offset, uint32_t len);
int qla4xxx_issue_iocb(struct scsi_qla_host *ha, uint32_t comp_offset,
			dma_addr_t phys_addr);
int qla4xxx_get_firmware_status(struct scsi_qla_host *ha);
int qla4xxx_get_firmware_state(struct scsi_qla_host *ha);
int qla4xxx_initialize_fw_cb(struct scsi_qla_host *ha);

/* FIXME: Goodness!  this really wants a small struct to hold the
 * parameters. On x86 the args will get passed on the stack! */
int qla4xxx_get_fwddb_entry(struct scsi_qla_host *ha,
			    uint16_t fw_ddb_index,
			    struct dev_db_entry *fw_ddb_entry,
			    dma_addr_t fw_ddb_entry_dma,
			    uint32_t *num_valid_ddb_entries,
			    uint32_t *next_ddb_index,
			    uint32_t *fw_ddb_device_state,
			    uint32_t *conn_err_detail,
			    uint16_t *tcp_source_port_num,
			    uint16_t *connection_id);

struct ddb_entry *qla4xxx_alloc_ddb(struct scsi_qla_host *ha,
				     uint32_t fw_ddb_index);
int qla4xxx_set_ddb_entry(struct scsi_qla_host *ha, uint16_t fw_ddb_index,
			  dma_addr_t fw_ddb_entry_dma);

void qla4xxx_mark_device_missing(struct scsi_qla_host *ha,
				 struct ddb_entry *ddb_entry);
u16 rd_nvram_word(struct scsi_qla_host *ha, int offset);
void qla4xxx_get_crash_record(struct scsi_qla_host *ha);
struct ddb_entry *qla4xxx_alloc_sess(struct scsi_qla_host *ha);
int qla4xxx_add_sess(struct ddb_entry *, int);
void qla4xxx_destroy_sess(struct ddb_entry *ddb_entry);
int qla4xxx_conn_close_sess_logout(struct scsi_qla_host *ha,
				   uint16_t fw_ddb_index,
				   uint16_t connection_id,
				   uint16_t option);
int qla4xxx_clear_database_entry(struct scsi_qla_host *ha,
				 uint16_t fw_ddb_index);
int qla4xxx_is_nvram_configuration_valid(struct scsi_qla_host *ha);
int qla4xxx_get_fw_version(struct scsi_qla_host *ha);
void qla4xxx_interrupt_service_routine(struct scsi_qla_host *ha,
				       uint32_t intr_status);
int qla4xxx_init_rings(struct scsi_qla_host *ha);
void qla4xxx_dump_buffer(void *b, uint32_t size);
struct srb *qla4xxx_del_from_active_array(struct scsi_qla_host *ha, uint32_t index);
void qla4xxx_srb_compl(struct kref *ref);
int qla4xxx_reinitialize_ddb_list(struct scsi_qla_host * ha);
int qla4xxx_process_ddb_changed(struct scsi_qla_host *ha, uint32_t fw_ddb_index,
				uint32_t state, uint32_t conn_error);

int qla4xxx_mailbox_command(struct scsi_qla_host *ha, uint8_t inCount,
			uint8_t outCount, uint32_t *mbx_cmd, uint32_t *mbx_sts);
extern void qla4xxx_queue_iocb(struct scsi_qla_host *ha);
extern void qla4xxx_complete_iocb(struct scsi_qla_host *ha);
void qla4xxx_mailbox_premature_completion(struct scsi_qla_host *ha);
void qla4xxx_dump_registers(struct scsi_qla_host *ha);
void qla4xxx_get_sys_info(struct scsi_qla_host *ha);
extern int qla4xxx_iospace_config(struct scsi_qla_host *ha);
extern void qla4xxx_pci_config(struct scsi_qla_host *ha);
extern uint32_t *qla4xxx_isp_mbx_out(struct scsi_qla_host *ha);
extern int qla4xxx_start_firmware(struct scsi_qla_host *ha);
extern irqreturn_t qla4xxx_intr_handler(int irq, void *dev_id, struct pt_regs *regs);
extern uint16_t qla4xxx_rd_shdw_req_q_out(struct scsi_qla_host *ha);
extern uint16_t qla4xxx_rd_shdw_rsp_q_in(struct scsi_qla_host *ha);
void qla4xxx_dump_bytes(void *buffer, uint32_t size);
int qla4xxx_mbx_reg_test(struct scsi_qla_host *ha);
int qla4xxx_request_irqs(struct scsi_qla_host *ha);
void qla4xxx_free_irqs(struct scsi_qla_host *ha);
void qla4xxx_process_response_queue(struct scsi_qla_host *ha);
void qla4xxx_isr_decode_mailbox(struct scsi_qla_host *ha, uint32_t mbox_status);
void qla4xxx_wake_dpc(struct scsi_qla_host *ha);

/* ISP 3031 related functions */
extern void qla4_8xxx_pci_config(struct scsi_qla_host *);
extern void qla4_8xxx_reset_chip(struct scsi_qla_host *);
extern int qla4_8xxx_iospace_config(struct scsi_qla_host *ha);
extern void qla4_8xxx_reset_adapter(struct scsi_qla_host *);
extern int qla4_8xxx_nvram_config(struct scsi_qla_host *);
extern int qla4_8xxx_load_risc(struct scsi_qla_host *);
extern char *qla4_8xxx_get_fw_version_str(struct scsi_qla_host *, char *);
extern int qla4_8xxx_abort_command(struct srb *);
extern int qla4_8xxx_start_scsi(struct srb *);
extern irqreturn_t qla4_8xxx_intr_handler(int irq, void *dev_id, struct pt_regs *regs);
extern void qla4_8xxx_queue_iocb(struct scsi_qla_host *ha);
extern void qla4_8xxx_complete_iocb(struct scsi_qla_host *ha);

extern int qla4_8xxx_crb_win_lock(struct scsi_qla_host *);
extern void qla4_8xxx_crb_win_unlock(struct scsi_qla_host *);
extern int qla4_8xxx_pci_get_crb_addr_2M(struct scsi_qla_host *, u64 *);
extern void qla4_8xxx_wr_32(struct scsi_qla_host *, u64, u32);
extern int qla4_8xxx_rd_32(struct scsi_qla_host *, u64);
extern int QLA30XX_RDMEM(struct scsi_qla_host *, u64, void *, int);
extern int QLA30XX_WRMEM(struct scsi_qla_host *, u64, void *, int);
extern int check_for_bad_spd(struct scsi_qla_host *);
extern void load_fw (struct scsi_qla_host *);
extern int rom_lock(struct scsi_qla_host *);
extern void rom_unlock(struct scsi_qla_host *);
extern int rom_fast_read(struct scsi_qla_host *, int , int*);
extern int qla4_8xxx_pci_mem_read_2M(struct scsi_qla_host *, u64, void*, int);
extern int qla4_8xxx_pci_mem_write_2M(struct scsi_qla_host *ha, u64, void*, int);
extern int qla4_8xxx_pci_write_immediate_2M(struct scsi_qla_host *, u64, u32);
extern u32 qla4_8xxx_pci_read_immediate_2M(struct scsi_qla_host *, u64);
extern void qla80xx_update_crb_int_ptr(struct scsi_qla_host *);

extern int qla4_8xxx_isp_reset(struct scsi_qla_host *ha);
extern uint16_t qla4xxx_rd_shdw_req_q_out(struct scsi_qla_host *ha);
extern uint16_t qla4_8xxx_rd_shdw_req_q_out(struct scsi_qla_host *ha);
extern uint16_t qla4_8xxx_rd_shdw_rsp_q_in(struct scsi_qla_host *ha);
void qla4_8xxx_interrupt_service_routine(struct scsi_qla_host *ha, uint32_t intr_status);
void qla4_8xxx_get_sys_info(struct scsi_qla_host *ha);
void qla4_8xxx_init_local_data(struct scsi_qla_host *ha);
void qla4_8xxx_watchdog(struct scsi_qla_host *ha);
int qla4_8xxx_stop_firmware(struct scsi_qla_host *ha);
void qla4_8xxx_restore_known_fw_state(struct scsi_qla_host *ha);

int qla4xxx_send_marker_iocb(struct scsi_qla_host *ha,
	struct ddb_entry *ddb_entry, int lun);
int qla4_is_relogin_allowed(struct scsi_qla_host *ha, uint32_t conn_err);

int qla4_8xxx_get_flash_info(struct scsi_qla_host *ha);
void qla4_8xxx_enable_intrs(struct scsi_qla_host *ha);
void qla4_8xxx_disable_intrs(struct scsi_qla_host *ha);
int qla4_8xxx_enable_msix(struct scsi_qla_host *ha);
void qla4_8xxx_disable_msix(struct scsi_qla_host *ha);
irqreturn_t qla4_8xxx_msi_handler(int irq, void *dev_id, struct pt_regs *regs);
irqreturn_t qla4_8xxx_default_intr_handler(int irq, void *dev_id, struct pt_regs *regs);
irqreturn_t qla4_8xxx_msix_rsp_q(int irq, void *dev_id);
void qla4xxx_abort_active_cmds(struct scsi_qla_host *ha, int res);
void qla4xxx_mark_all_devices_missing(struct scsi_qla_host *ha);
void qla4xxx_dead_adapter_cleanup(struct scsi_qla_host *ha);
int qla4_8xxx_idc_lock(struct scsi_qla_host *ha);
void qla4_8xxx_idc_unlock(struct scsi_qla_host *ha);
int qla4_8xxx_device_state_handler(struct scsi_qla_host *ha);
void qla4_8xxx_need_qsnt_handler(struct scsi_qla_host *ha);
void qla4_8xxx_set_drv_active(struct scsi_qla_host *ha);
void qla4_8xxx_clear_drv_active(struct scsi_qla_host *ha);
extern int qla4_8xxx_start_firmware(struct scsi_qla_host *, uint32_t);
extern int qla4xxx_init_firmware(struct scsi_qla_host *);
extern int qla4xxx_initialize_ddb_list(struct scsi_qla_host *);

extern int ql4xextended_error_logging;
extern int ql4xdiscoverywait;
extern int ql4xdontresethba;
extern int ql4_demo_code;
extern int ql4xenablemsix;
#endif				/* _QLA4x_GBL_H */
