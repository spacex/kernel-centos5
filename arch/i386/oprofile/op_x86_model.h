/**
 * @file op_x86_model.h
 * interface to x86 model-specific MSR operations
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Graydon Hoare
 */

#ifndef OP_X86_MODEL_H
#define OP_X86_MODEL_H

struct op_saved_msr {
	unsigned int high;
	unsigned int low;
};

struct op_msr {
	unsigned long addr;
	struct op_saved_msr saved;
};

struct op_msrs {
	struct op_msr * counters;
	struct op_msr * controls;
};

struct ibs_fetch_sample {
	/* MSRC001_1031 IBS Fetch Linear Address Register */
	unsigned int ibs_fetch_lin_addr_low;
	unsigned int ibs_fetch_lin_addr_high;
	/* MSRC001_1030 IBS Fetch Control Register */
	unsigned int ibs_fetch_ctl_low;
	unsigned int ibs_fetch_ctl_high;
	/* MSRC001_1032 IBS Fetch Physical Address Register */
	unsigned int ibs_fetch_phys_addr_low;
	unsigned int ibs_fetch_phys_addr_high;
};

struct ibs_op_sample {
	/* MSRC001_1034 IBS Op Logical Address Register (IbsRIP) */
	unsigned int ibs_op_rip_low;
	unsigned int ibs_op_rip_high;
	/* MSRC001_1035 IBS Op Data Register */
	unsigned int ibs_op_data1_low;
	unsigned int ibs_op_data1_high;
	/* MSRC001_1036 IBS Op Data 2 Register */
	unsigned int ibs_op_data2_low;
	unsigned int ibs_op_data2_high;
	/* MSRC001_1037 IBS Op Data 3 Register */
	unsigned int ibs_op_data3_low;
	unsigned int ibs_op_data3_high;
	/* MSRC001_1038 IBS DC Linear Address Register (IbsDcLinAd) */
	unsigned int ibs_dc_linear_low;
	unsigned int ibs_dc_linear_high;
	/* MSRC001_1039 IBS DC Physical Address Register (IbsDcPhysAd) */
	unsigned int ibs_dc_phys_low;
	unsigned int ibs_dc_phys_high;
};
struct pt_regs;

/* The model vtable abstracts the differences between
 * various x86 CPU model's perfctr support.
 */
struct op_x86_model_spec {
	unsigned int const num_counters;
	unsigned int const num_controls;
	void (*fill_in_addresses)(struct op_msrs * const msrs);
	void (*setup_ctrs)(struct op_msrs const * const msrs);
	int (*check_ctrs)(struct pt_regs * const regs,
		struct op_msrs const * const msrs);
	void (*start)(struct op_msrs const * const msrs);
	void (*stop)(struct op_msrs const * const msrs);
};

extern struct op_x86_model_spec const op_ppro_spec;
extern struct op_x86_model_spec const op_p4_spec;
extern struct op_x86_model_spec const op_p4_ht2_spec;
extern struct op_x86_model_spec const op_athlon_spec;

/* setup AMD Family 10H IBS IRQ if needed */
extern void setup_ibs_nmi(void);
/* clearp AMD Family 10H IBS IRQ if needed */
extern void clear_ibs_nmi(void);
#endif /* OP_X86_MODEL_H */
