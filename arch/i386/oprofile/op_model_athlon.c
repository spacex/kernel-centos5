/**
 * @file op_model_athlon.h
 * athlon / K7 / K8 / Family 10h model-specific MSR operations
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 * @author Philippe Elie
 * @author Graydon Hoare
 * @author Barry Kasindorf
 */

#include <linux/oprofile.h>
#include <linux/device.h>
#include <linux/pci.h>

#include <asm/ptrace.h>
#include <asm/msr.h>
#include <asm/nmi.h>
 
#include "op_x86_model.h"
#include "op_counter.h"

#define NUM_COUNTERS 4
#define NUM_CONTROLS 4

#define CTR_IS_RESERVED(msrs,c) (msrs->counters[(c)].addr ? 1 : 0)
#define CTR_READ(l,h,msrs,c) do {rdmsr(msrs->counters[(c)].addr, (l), (h));} while (0)
#define CTR_WRITE(l,msrs,c) do {wrmsr(msrs->counters[(c)].addr, -(unsigned int)(l), -1);} while (0)
#define CTR_OVERFLOWED(n) (!((n) & (1U<<31)))

#define CTRL_IS_RESERVED(msrs,c) (msrs->controls[(c)].addr ? 1 : 0)
#define CTRL_READ(l,h,msrs,c) do {rdmsr(msrs->controls[(c)].addr, (l), (h));} while (0)
#define CTRL_WRITE(l,h,msrs,c) do {wrmsr(msrs->controls[(c)].addr, (l), (h));} while (0)
#define CTRL_SET_ACTIVE(n) (n |= (1<<22))
#define CTRL_SET_INACTIVE(n) (n &= ~(1<<22))
#define CTRL_CLEAR_LO(x) (x &= (1<<21))
#define CTRL_CLEAR_HI(x) ( x &= 0xfffffcf0 )
#define CTRL_SET_ENABLE(val) (val |= 1<<20)
#define CTRL_SET_USR(val,u) (val |= ((u & 1) << 16))
#define CTRL_SET_KERN(val,k) (val |= ((k & 1) << 17))
#define CTRL_SET_UM(val, m) (val |= (m << 8))
#define CTRL_SET_EVENT_LOW(val, e) (val |= (e & 0xff))
#define CTRL_SET_EVENT_HIGH(val,e) (val |= ((e >> 8) & 0xf))
#define CTRL_SET_HOST_ONLY(val, h) (val |= ((h & 1) << 9))
#define CTRL_SET_GUEST_ONLY(val, h) (val |= ((h & 1) << 8))

#ifndef MSR_AMD64_NB_CFG
/* this is here in case the Perfmon2 patch was not applied yet */
#define MSR_AMD64_NB_CFG		0xc001001f

/* Definition of Family10h IBS register Addresses */
#define MSR_AMD64_IBSFETCHCTL		0xc0011030
#define MSR_AMD64_IBSFETCHLINAD		0xc0011031
#define MSR_AMD64_IBSFETCHPHYSAD	0xc0011032
#define MSR_AMD64_IBSOPCTL		0xc0011033
#define MSR_AMD64_IBSOPRIP		0xc0011034
#define MSR_AMD64_IBSOPDATA		0xc0011035
#define MSR_AMD64_IBSOPDATA2		0xc0011036
#define MSR_AMD64_IBSOPDATA3		0xc0011037
#define MSR_AMD64_IBSDCLINAD		0xc0011038
#define MSR_AMD64_IBSDCPHYSAD		0xc0011039
#define MSR_AMD64_IBSCTL		0xc001103a
#endif

/* high dword IbsFetchCtl[bit 49] */
#define IBS_FETCH_VALID_BIT		0x00020000
/* high dword IbsFetchCtl[bit 52] */
#define IBS_FETCH_PHY_ADDR_VALID_BIT 	0x00100000
#define IBS_FETCH_CTL_HIGH_MASK		0xFFFFFFFF
/* high dword IbsFetchCtl[bit 48] */
#define IBS_FETCH_ENABLE		0x00010000
#define IBS_FETCH_CTL_CNT_MASK 		0x00000000FFFF0000
#define IBS_FETCH_CTL_MAX_CNT_MASK 	0x000000000000FFFF

/*IbsOpCtl masks/bits */
#define IBS_OP_VALID_BIT 	0x0000000000040000 /* IbsOpCtl[bit18] */
#define IBS_OP_ENABLE 		0x0000000000020000 /* IBS_OP_ENABLE[bit17]*/

/*IbsOpData masks */
#define IBS_OP_DATA_BRANCH_MASK	   0x3F00000000		/* IbsOpData[32:37] */
#define IBS_OP_DATA_HIGH_MASK	   0x0000FFFF00000000	/* IbsOpData[32:47] */
#define IBS_OP_DATA_LOW_MASK	   0x00000000FFFFFFFF	/*IbsOpData[0:31] */

/*IbsOpData2 masks */
#define IBS_OP_DATA2_MASK	   0x000000000000002F

/*IbsOpData3 masks */
#define IBS_OP_DATA3_LS_MASK	   0x0000000003

#define IBS_OP_DATA3_PHY_ADDR_VALID_BIT 0x0000000000040000
#define IBS_OP_DATA3_LIN_ADDR_VALID_BIT 0x0000000000020000
#define IBS_CTL_LVT_OFFSET_VALID_BIT	0x100
/* AMD ext internal APIC Local Vectors */
#define APIC_IELVT			0x500
/* number of APIC Entries for ieLVT */
#define NUM_APIC_IELVT			4

/*PCI Extended Configuration Constants */
/* Northbridge Configuration Register */
#define NB_CFG_MSR			0xC001001F
/* Bit 46, EnableCf8ExtCfg: enable CF8 extended configuration cycles */
#define ENABLE_CF8_EXT_CFG_MASK		0x4000
/* MSR to set the IBS control register APIC LVT offset */
#define IBS_LVT_OFFSET_PCI		0x1CC

/* IBS rev [bit 10] 1 = IBS Rev B */
#define IBS_REV_MASK			0x400

/* When pci_ids.h gets caught up remove this */
#ifndef PCI_DEVICE_ID_AMD_FAMILY10H_NB
#define PCI_DEVICE_ID_AMD_FAMILY10H_NB	0x1200
#endif

/**
 * Add an AMD IBS  sample. This may be called from any context. Pass
 * smp_processor_id() as cpu. Passes IBS registers as a unsigned int[8]
 */
void oprofile_add_ibs_op_sample(struct pt_regs * const regs, unsigned int * const ibs_op);

void oprofile_add_ibs_fetch_sample(struct pt_regs * const regs, unsigned int * const ibs_fetch);
static unsigned long reset_value[NUM_COUNTERS];
extern int ibs_allowed;		/* AMD Family 10h+ */
static int Extended_PCI_Enabled = 0;
 
static void athlon_fill_in_addresses(struct op_msrs * const msrs)
{
	int i;

	for (i=0; i < NUM_COUNTERS; i++) {
		if (reserve_perfctr_nmi(MSR_K7_PERFCTR0 + i))
			msrs->counters[i].addr = MSR_K7_PERFCTR0 + i;
		else
			msrs->counters[i].addr = 0;
	}

	for (i=0; i < NUM_CONTROLS; i++) {
		if (reserve_evntsel_nmi(MSR_K7_EVNTSEL0 + i))
			msrs->controls[i].addr = MSR_K7_EVNTSEL0 + i;
		else
			msrs->controls[i].addr = 0;
	}
}

 
static void athlon_setup_ctrs(struct op_msrs const * const msrs)
{
	unsigned int low, high;
	int i;
 
	/* clear all counters */
	for (i = 0 ; i < NUM_CONTROLS; ++i) {
		if (unlikely(!CTRL_IS_RESERVED(msrs,i)))
			continue;
		CTRL_READ(low, high, msrs, i);
		CTRL_CLEAR_LO(low);
		CTRL_CLEAR_HI(high);
		CTRL_WRITE(low, high, msrs, i);
	}

	/* avoid a false detection of ctr overflows in NMI handler */
	for (i = 0; i < NUM_COUNTERS; ++i) {
		if (unlikely(!CTR_IS_RESERVED(msrs,i)))
			continue;
		CTR_WRITE(1, msrs, i);
	}

	/* enable active counters */
	for (i = 0; i < NUM_COUNTERS; ++i) {
		if ((counter_config[i].enabled) && (CTR_IS_RESERVED(msrs,i))) {
			reset_value[i] = counter_config[i].count;

			CTR_WRITE(counter_config[i].count, msrs, i);

			CTRL_READ(low, high, msrs, i);
			CTRL_CLEAR_LO(low);
			CTRL_CLEAR_HI(high);
			CTRL_SET_ENABLE(low);
			CTRL_SET_USR(low, counter_config[i].user);
			CTRL_SET_KERN(low, counter_config[i].kernel);
			CTRL_SET_UM(low, counter_config[i].unit_mask);
			CTRL_SET_EVENT_LOW(low, counter_config[i].event);
			CTRL_SET_EVENT_HIGH(high, counter_config[i].event);
			CTRL_SET_HOST_ONLY(high, 0);
			CTRL_SET_GUEST_ONLY(high, 0);
			CTRL_WRITE(low, high, msrs, i);
		} else {
			reset_value[i] = 0;
		}
	}
}

 
static int athlon_check_ctrs(struct pt_regs * const regs,
			     struct op_msrs const * const msrs)
{
	unsigned int low, high;
	int i;
	struct ibs_fetch_sample ibs_fetch;
	struct ibs_op_sample ibs_op;

	for (i = 0 ; i < NUM_COUNTERS; ++i) {
		if (!reset_value[i])
			continue;
		CTR_READ(low, high, msrs, i);
		if (CTR_OVERFLOWED(low)) {
			oprofile_add_sample(regs, i);
			CTR_WRITE(reset_value[i], msrs, i);
		}
	}

	/*If AMD and IBS is available */
	if (ibs_allowed && ibs_config.FETCH_enabled ) {
		rdmsr(MSR_AMD64_IBSFETCHCTL, low, high);
		if ( high & IBS_FETCH_VALID_BIT) {
			ibs_fetch.ibs_fetch_ctl_high = high;
			ibs_fetch.ibs_fetch_ctl_low = low;
			rdmsr(MSR_AMD64_IBSFETCHLINAD, low, high);
			ibs_fetch.ibs_fetch_lin_addr_high = high;
			ibs_fetch.ibs_fetch_lin_addr_low = low;
			rdmsr(MSR_AMD64_IBSFETCHPHYSAD, low, high);
			ibs_fetch.ibs_fetch_phys_addr_high = high;
			ibs_fetch.ibs_fetch_phys_addr_low = low;

			oprofile_add_ibs_fetch_sample(regs,
						 (unsigned int *)&ibs_fetch);

			/*reenable the IRQ */
			rdmsr(MSR_AMD64_IBSFETCHCTL, low, high);
			high &= ~(IBS_FETCH_VALID_BIT);
			high |= IBS_FETCH_ENABLE;
			low &= IBS_FETCH_CTL_MAX_CNT_MASK;
			wrmsr(MSR_AMD64_IBSFETCHCTL, low, high);
		}
	}

	if (ibs_allowed && ibs_config.OP_enabled ) {
		rdmsr(MSR_AMD64_IBSOPCTL, low, high);
		if (low & IBS_OP_VALID_BIT) {
			rdmsr(MSR_AMD64_IBSOPRIP, low, high);
			ibs_op.ibs_op_rip_low = low;
			ibs_op.ibs_op_rip_high = high;
			rdmsr(MSR_AMD64_IBSOPDATA, low, high);
			ibs_op.ibs_op_data1_low = low;
			ibs_op.ibs_op_data1_high = high;
			rdmsr(MSR_AMD64_IBSOPDATA2, low, high);
			ibs_op.ibs_op_data2_low = low;
			ibs_op.ibs_op_data2_high = high;
			rdmsr(MSR_AMD64_IBSOPDATA3, low, high);
			ibs_op.ibs_op_data3_low = low;
			ibs_op.ibs_op_data3_high = high;
			rdmsr(MSR_AMD64_IBSDCLINAD, low, high);
			ibs_op.ibs_dc_linear_low = low;
			ibs_op.ibs_dc_linear_high = high;
			rdmsr(MSR_AMD64_IBSDCPHYSAD, low, high);
			ibs_op.ibs_dc_phys_low = low;
			ibs_op.ibs_dc_phys_high = high;

			/* reenable the IRQ */
			oprofile_add_ibs_op_sample(regs,
						 (unsigned int *)&ibs_op);
			rdmsr(MSR_AMD64_IBSOPCTL, low, high);
			low &= ~(IBS_OP_VALID_BIT);
			low |= IBS_OP_ENABLE;
			wrmsr(MSR_AMD64_IBSOPCTL, low, high);
		}
	}

	/* See op_model_ppro.c */
	return 1;
}

 
static void athlon_start(struct op_msrs const * const msrs)
{
	unsigned int low, high;
	int i;
	for (i = 0 ; i < NUM_COUNTERS ; ++i) {
		if (reset_value[i]) {
			CTRL_READ(low, high, msrs, i);
			CTRL_SET_ACTIVE(low);
			CTRL_WRITE(low, high, msrs, i);
		}
	}
	if (ibs_allowed && ibs_config.FETCH_enabled ) {
		low = (ibs_config.max_cnt_fetch >> 4) & 0xFFFF;
		high =  ((ibs_config.rand_en & 0x1) << 25)  + IBS_FETCH_ENABLE;
		wrmsr(MSR_AMD64_IBSFETCHCTL, low, high);
	}

	if (ibs_allowed && ibs_config.OP_enabled ) {
		low = ((ibs_config.max_cnt_op >> 4) & 0xFFFF) +
			((ibs_config.dispatched_ops & 0x1) << 19) + IBS_OP_ENABLE;
		high = 0;
		wrmsr(MSR_AMD64_IBSOPCTL, low, high);
	}
}

static void athlon_stop(struct op_msrs const * const msrs)
{
	unsigned int low,high;
	int i;

	/* Subtle: stop on all counters to avoid race with
	 * setting our pm callback */
	for (i = 0 ; i < NUM_COUNTERS ; ++i) {
		if (!reset_value[i])
			continue;
		CTRL_READ(low, high, msrs, i);
		CTRL_SET_INACTIVE(low);
		CTRL_WRITE(low, high, msrs, i);
	}
	if (ibs_allowed && ibs_config.FETCH_enabled ) {
		low = 0;		/* clear max count and enable */
		high = 0;
		wrmsr(MSR_AMD64_IBSFETCHCTL, low, high);
	}

	if (ibs_allowed && ibs_config.OP_enabled ) {
		low = 0;		/* clear max count and enable */
		high = 0;
		wrmsr(MSR_AMD64_IBSOPCTL, low, high);
	}
}

static void
	Enable_Extended_PCI_Config(void)
{
	unsigned int low, high;
	rdmsr(MSR_AMD64_NB_CFG, low, high);
	Extended_PCI_Enabled = high  & ENABLE_CF8_EXT_CFG_MASK;
	high |= ENABLE_CF8_EXT_CFG_MASK;
	wrmsr(MSR_AMD64_NB_CFG, low, high);
}

/*
 *	Disable AMD extended PCI config space thru IO
 *	restore to previous state
 */
static void
	Disable_Extended_PCI_Config(void)
{
	unsigned int low, high;
	rdmsr(MSR_AMD64_NB_CFG, low, high);
	high &= ~ENABLE_CF8_EXT_CFG_MASK;
	high |= Extended_PCI_Enabled;
	wrmsr(MSR_AMD64_NB_CFG, low, high);
}

/*
 * Modified to use AMD extended PCI config space thru IO
 * these 2 I/Os should be atomic but there is no easy way to do that.
 * Should use the MMio version, will when it is fixed
 */

static void
	PCI_Extended_Write(struct pci_dev *dev, unsigned int offset,
						 unsigned long val)
{
	outl(0x80000000 | (((offset >> 8)  & 0x0f) << 24) |
		((dev->bus->number & 0xff) << 16) | ((dev->devfn | 3) << 8)
		 | (offset & 0x0fc), 0x0cf8);

	outl(val, 0xcfc);
}

static inline void APIC_init_per_cpu(void *arg)
{
	 unsigned long i =  *(unsigned long *)arg;

	apic_write(APIC_IELVT + (i << 4), APIC_DM_NMI);
}

static inline void APIC_clear_per_cpu(void *arg)
{
	 unsigned long i =  *(unsigned long *)arg;

	apic_write(APIC_IELVT + (i << 4), APIC_LVT_MASKED);
}

/*
 * initialize the APIC for the IBS interrupts
 * if needed on AMD Family10h rev B0 and later
 */
void setup_ibs_nmi(void)
{
	struct pci_dev *gh_device = NULL;
	//u32 low, high;

	unsigned long i;
	unsigned long	apicLVT;

#if 0	//Recent BIOS broke this
	/*see if the IBS control register is already set */
	rdmsr(MSR_AMD64_IBSCTL, low, high);
	if (low & IBS_CTL_LVT_OFFSET_VALID_BIT)
		/*nothing to do it is already setup correctly*/
		return;
#endif
	for (i = 0; i < NUM_APIC_IELVT; i++) {
		/* get ieLVT contents */
		apicLVT = apic_read(APIC_IELVT + (i << 4));
		if ( (apicLVT & APIC_LVT_MASKED) != 0 )
			/* This slot is disabled, so we can use it */
			break;
	}

	Enable_Extended_PCI_Config();

	/**** Be sure to run loop until NULL is returned to
	decrement reference count on any pci_dev structures returned ****/
	while ( (gh_device = pci_get_device(PCI_VENDOR_ID_AMD,
		 PCI_DEVICE_ID_AMD_FAMILY10H_NB, gh_device)) != NULL ) {
		/* This code may change if we can find a proper
		 * way to get at the PCI extended config space */
		PCI_Extended_Write(
			gh_device, IBS_LVT_OFFSET_PCI,
			(i | IBS_CTL_LVT_OFFSET_VALID_BIT) );
	
	}
	Disable_Extended_PCI_Config();
	on_each_cpu(APIC_init_per_cpu, (void *)&i, 1, 1);
}

/*
 * unitialize the APIC for the IBS interrupts if needed on AMD Family10h
 * rev B0 and later */
void clear_ibs_nmi(void)
{
	unsigned long low, high;
	struct pci_dev *gh_device = NULL;
	unsigned long i;

	/*see if the IBS control register is already set */
	rdmsr(MSR_AMD64_IBSCTL, low, high);
	if ( (low & IBS_CTL_LVT_OFFSET_VALID_BIT) == 0)
	/*nothing to do it is already cleared
	 *(assume on all CPUS if any is done)
	 */
		return;

	i = low & 0x3;	//get LVT vector number

	on_each_cpu(APIC_clear_per_cpu, (void *)&i, 1, 1);
	/**** Be sure to run loop until NULL is returned
	 * to decrement reference count on any pci_dev structures returned */
	Enable_Extended_PCI_Config();
	while ( (gh_device = pci_get_device(PCI_VENDOR_ID_AMD,
		PCI_DEVICE_ID_AMD_FAMILY10H_NB, gh_device)) != NULL ) {
		/* free the LVT entry */
		PCI_Extended_Write(gh_device, IBS_LVT_OFFSET_PCI, ( 0 ));
	}
	Disable_Extended_PCI_Config();
}

static void athlon_shutdown(struct op_msrs const * const msrs)
{
	int i;

	for (i = 0 ; i < NUM_COUNTERS ; ++i) {
		if (CTR_IS_RESERVED(msrs,i))
			release_perfctr_nmi(MSR_K7_PERFCTR0 + i);
	}
	for (i = 0 ; i < NUM_CONTROLS ; ++i) {
		if (CTRL_IS_RESERVED(msrs,i))
			release_evntsel_nmi(MSR_K7_EVNTSEL0 + i);
	}
}

struct op_x86_model_spec const op_athlon_spec = {
	.num_counters = NUM_COUNTERS,
	.num_controls = NUM_CONTROLS,
	.fill_in_addresses = &athlon_fill_in_addresses,
	.setup_ctrs = &athlon_setup_ctrs,
	.check_ctrs = &athlon_check_ctrs,
	.start = &athlon_start,
	.stop = &athlon_stop,
	.shutdown = &athlon_shutdown
};
