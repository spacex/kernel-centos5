/******************************************************************************
 * dom0_ops.h
 * 
 * Process command requests from domain-0 guest OS.
 * 
 * Copyright (c) 2002-2003, B Dragovic
 * Copyright (c) 2002-2006, K Fraser
 */

#ifndef __XEN_PUBLIC_DOM0_OPS_H__
#define __XEN_PUBLIC_DOM0_OPS_H__

#include "xen.h"
#include "platform.h"

#if __XEN_INTERFACE_VERSION__ >= 0x00030204
#error "dom0_ops.h is a compatibility interface only"
#endif

#define DOM0_INTERFACE_VERSION XENPF_INTERFACE_VERSION

#define DOM0_SETTIME          XENPF_settime
#define dom0_settime          xenpf_settime
#define dom0_settime_t        xenpf_settime_t

#define DOM0_ADD_MEMTYPE      XENPF_add_memtype
#define dom0_add_memtype      xenpf_add_memtype
#define dom0_add_memtype_t    xenpf_add_memtype_t

#define DOM0_DEL_MEMTYPE      XENPF_del_memtype
#define dom0_del_memtype      xenpf_del_memtype
#define dom0_del_memtype_t    xenpf_del_memtype_t

#define DOM0_READ_MEMTYPE     XENPF_read_memtype
#define dom0_read_memtype     xenpf_read_memtype
#define dom0_read_memtype_t   xenpf_read_memtype_t

#define DOM0_MICROCODE        XENPF_microcode_update
#define dom0_microcode        xenpf_microcode_update
#define dom0_microcode_t      xenpf_microcode_update_t

#define DOM0_PLATFORM_QUIRK   XENPF_platform_quirk
#define dom0_platform_quirk   xenpf_platform_quirk
#define dom0_platform_quirk_t xenpf_platform_quirk_t

typedef uint64_t cpumap_t;

/* Unsupported legacy operation -- defined for API compatibility. */
#define DOM0_MSR                 15
struct dom0_msr {
    /* IN variables. */
    uint32_t write;
    cpumap_t cpu_mask;
    uint32_t msr;
    uint32_t in1;
    uint32_t in2;
    /* OUT variables. */
    uint32_t out1;
    uint32_t out2;
};
typedef struct dom0_msr dom0_msr_t;
DEFINE_XEN_GUEST_HANDLE(dom0_msr_t);

/* Unsupported legacy operation -- defined for API compatibility. */
#define DOM0_PHYSICAL_MEMORY_MAP 40
struct dom0_memory_map_entry {
    uint64_t start, end;
    uint32_t flags; /* reserved */
    uint8_t  is_ram;
};
typedef struct dom0_memory_map_entry dom0_memory_map_entry_t;
DEFINE_XEN_GUEST_HANDLE(dom0_memory_map_entry_t);

#define DOM0_change_freq         52
struct dom0_change_freq {
    /* IN variables */
    uint32_t flags; /* Must be zero. */
    uint32_t cpu;   /* Physical cpu. */
    uint64_t freq;  /* New frequency (Hz). */
};
typedef struct dom0_change_freq dom0_change_freq_t;
DEFINE_XEN_GUEST_HANDLE(dom0_change_freq_t);

/*
 * Get idle times (nanoseconds since boot) for physical CPUs specified in the
 * @cpumap_bitmap with range [0..@cpumap_nr_cpus-1]. The @idletime array is
 * indexed by CPU number; only entries with the corresponding @cpumap_bitmap
 * bit set are written to. On return, @cpumap_bitmap is modified so that any
 * non-existent CPUs are cleared. Such CPUs have their @idletime array entry
 * cleared.
 */
#define DOM0_getidletime         53
struct dom0_getidletime {
    /* IN/OUT variables */
    /* IN: CPUs to interrogate; OUT: subset of IN which are present */
    XEN_GUEST_HANDLE(uint8_t) cpumap_bitmap;
    /* IN variables */
    /* Size of cpumap bitmap. */
    uint32_t cpumap_nr_cpus;
    /* Must be indexable for every cpu in cpumap_bitmap. */
    XEN_GUEST_HANDLE(uint64_t) idletime;
    /* OUT variables */
    /* System time when the idletime snapshots were taken. */
    uint64_t now;
};
typedef struct dom0_getidletime dom0_getidletime_t;
DEFINE_XEN_GUEST_HANDLE(dom0_getidletime_t);

struct dom0_op {
    uint32_t cmd;
    uint32_t interface_version; /* DOM0_INTERFACE_VERSION */
    union {
        struct dom0_msr               msr;
        struct dom0_settime           settime;
        struct dom0_add_memtype       add_memtype;
        struct dom0_del_memtype       del_memtype;
        struct dom0_read_memtype      read_memtype;
        struct dom0_microcode         microcode;
        struct dom0_platform_quirk    platform_quirk;
        struct dom0_memory_map_entry  physical_memory_map;
	struct dom0_change_freq       change_freq;
	struct dom0_getidletime       getidletime;
#ifdef CONFIG_X86_64
	struct xenpf_stratus_call     stratus_call;
#endif
        uint8_t                       pad[128];
    } u;
};
typedef struct dom0_op dom0_op_t;
DEFINE_XEN_GUEST_HANDLE(dom0_op_t);

#endif /* __XEN_PUBLIC_DOM0_OPS_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
