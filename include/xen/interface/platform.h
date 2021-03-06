/******************************************************************************
 * platform.h
 * 
 * Hardware platform operations. Intended for use by domain-0 kernel.
 * 
 * Copyright (c) 2002-2006, K Fraser
 */

#ifndef __XEN_PUBLIC_PLATFORM_H__
#define __XEN_PUBLIC_PLATFORM_H__

#include "xen.h"
#ifdef CONFIG_X86_64
#include "stratus.h"
#endif

#define XENPF_INTERFACE_VERSION 0x03000001

/*
 * Set clock such that it would read <secs,nsecs> after 00:00:00 UTC,
 * 1 January, 1970 if the current system time was <system_time>.
 */
#define XENPF_settime             17
struct xenpf_settime {
    /* IN variables. */
    uint32_t secs;
    uint32_t nsecs;
    uint64_t system_time;
};
typedef struct xenpf_settime xenpf_settime_t;
DEFINE_XEN_GUEST_HANDLE(xenpf_settime_t);

/*
 * Request memory range (@mfn, @mfn+@nr_mfns-1) to have type @type.
 * On x86, @type is an architecture-defined MTRR memory type.
 * On success, returns the MTRR that was used (@reg) and a handle that can
 * be passed to XENPF_DEL_MEMTYPE to accurately tear down the new setting.
 * (x86-specific).
 */
#define XENPF_add_memtype         31
struct xenpf_add_memtype {
    /* IN variables. */
    xen_pfn_t mfn;
    uint64_t nr_mfns;
    uint32_t type;
    /* OUT variables. */
    uint32_t handle;
    uint32_t reg;
};
typedef struct xenpf_add_memtype xenpf_add_memtype_t;
DEFINE_XEN_GUEST_HANDLE(xenpf_add_memtype_t);

/*
 * Tear down an existing memory-range type. If @handle is remembered then it
 * should be passed in to accurately tear down the correct setting (in case
 * of overlapping memory regions with differing types). If it is not known
 * then @handle should be set to zero. In all cases @reg must be set.
 * (x86-specific).
 */
#define XENPF_del_memtype         32
struct xenpf_del_memtype {
    /* IN variables. */
    uint32_t handle;
    uint32_t reg;
};
typedef struct xenpf_del_memtype xenpf_del_memtype_t;
DEFINE_XEN_GUEST_HANDLE(xenpf_del_memtype_t);

/* Read current type of an MTRR (x86-specific). */
#define XENPF_read_memtype        33
struct xenpf_read_memtype {
    /* IN variables. */
    uint32_t reg;
    /* OUT variables. */
    xen_pfn_t mfn;
    uint64_t nr_mfns;
    uint32_t type;
};
typedef struct xenpf_read_memtype xenpf_read_memtype_t;
DEFINE_XEN_GUEST_HANDLE(xenpf_read_memtype_t);

#define XENPF_microcode_update    35
struct xenpf_microcode_update {
    /* IN variables. */
    XEN_GUEST_HANDLE(void) data;      /* Pointer to microcode data */
    uint32_t length;                  /* Length of microcode data. */
};
typedef struct xenpf_microcode_update xenpf_microcode_update_t;
DEFINE_XEN_GUEST_HANDLE(xenpf_microcode_update_t);

#define XENPF_platform_quirk      39
#define QUIRK_NOIRQBALANCING      1 /* Do not restrict IO-APIC RTE targets */
#define QUIRK_IOAPIC_BAD_REGSEL   2 /* IO-APIC REGSEL forgets its value    */
#define QUIRK_IOAPIC_GOOD_REGSEL  3 /* IO-APIC REGSEL behaves properly     */
struct xenpf_platform_quirk {
    /* IN variables. */
    uint32_t quirk_id;
};
typedef struct xenpf_platform_quirk xenpf_platform_quirk_t;
DEFINE_XEN_GUEST_HANDLE(xenpf_platform_quirk_t);

#define XENPF_change_freq         52
struct xenpf_change_freq {
    /* IN variables */
    uint32_t flags; /* Must be zero. */
    uint32_t cpu;   /* Physical cpu. */
    uint64_t freq;  /* New frequency (Hz). */
};
typedef struct xenpf_change_freq xenpf_change_freq_t;
DEFINE_XEN_GUEST_HANDLE(xenpf_change_freq_t);

/*
 * Get idle times (nanoseconds since boot) for physical CPUs specified in the
 * @cpumap_bitmap with range [0..@cpumap_nr_cpus-1]. The @idletime array is
 * indexed by CPU number; only entries with the corresponding @cpumap_bitmap
 * bit set are written to. On return, @cpumap_bitmap is modified so that any
 * non-existent CPUs are cleared. Such CPUs have their @idletime array entry
 * cleared.
 */
#define XENPF_getidletime         53
struct xenpf_getidletime {
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
typedef struct xenpf_getidletime xenpf_getidletime_t;
DEFINE_XEN_GUEST_HANDLE(xenpf_getidletime_t);

struct xen_platform_op {
    uint32_t cmd;
    uint32_t interface_version; /* XENPF_INTERFACE_VERSION */
    union {
        struct xenpf_settime           settime;
        struct xenpf_add_memtype       add_memtype;
        struct xenpf_del_memtype       del_memtype;
        struct xenpf_read_memtype      read_memtype;
        struct xenpf_microcode_update  microcode;
        struct xenpf_platform_quirk    platform_quirk;
        struct xenpf_change_freq       change_freq;
        struct xenpf_getidletime       getidletime;
        uint8_t                        pad[128];
    } u;
};
typedef struct xen_platform_op xen_platform_op_t;
DEFINE_XEN_GUEST_HANDLE(xen_platform_op_t);

#ifdef CONFIG_X86_64
#define XENPF_stratus_call	0xffffffff
typedef struct xenpf_stratus_call xenpf_stratus_call_t;
DEFINE_XEN_GUEST_HANDLE(xenpf_stratus_call_t);
#endif

#endif /* __XEN_PUBLIC_PLATFORM_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
