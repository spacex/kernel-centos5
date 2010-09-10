#ifndef _CC_INTERFACE_H
#define _CC_INTERFACE_H

// Clear the entire Host BIOS vector
#define CC_HBV_MEMSET 			1	
// Read/Write from page 0 (HBV or DUMP)
#define CC_RW_REGION			2
// Trigger SMI through local apic
#define CC_TRIGGER_SMI			3
// Return local cpu apic id
#define CC_LAPIC_ID			4
// Get/Set CR4.
#define CC_CR4				5
// Get cpuid
#define CC_CPUID			6
// Read/Write MSRs
#define CC_RW_MSR			7
// Are we on a Stratus box?
#define CC_VALIDATE_PLATFORM		8

// Page 0 regions to read/write (host bios vector or dump vector signature).
#define	RW_HBV		1
#define	RW_DUMPVEC	2

struct cr4_struct {
	int rw;		// 0 = read, 1 = write.
	unsigned long cr4;
};

struct cpuid_struct {
	unsigned int op;
	unsigned int eax, ebx, ecx, edx;	
};

struct msr_struct {
	int rw;
	unsigned int msr;
	unsigned long val;
};

struct lapic_struct {
	int id;
};

struct rw_struct {
	int rw;			// 0 = read, 1 = write
	int region;		// RW_HBV or RW_CONTIG
	void *data;
	unsigned long where;	// offset in region
	int size;
};

struct smi_struct {
	unsigned int dest;
};

struct hbv_memset_struct {
	int val;
	int size;
};

struct xenpf_stratus_call {
	int cmd;
	int ret;
	union {
		struct smi_struct smi;
		struct hbv_memset_struct hbv_m;
		struct rw_struct rw;
		struct lapic_struct ls;
		struct cr4_struct cr4;
		struct cpuid_struct cpuid;
		struct msr_struct msr;
	} u;
};

#endif
