/******************************************************************************
 * sysctl.h
 * 
 * System management operations. For use by node control stack.
 * 
 * Copyright (c) 2002-2006, K Fraser
 */

#ifndef __XEN_PUBLIC_SYSCTL_H__
#define __XEN_PUBLIC_SYSCTL_H__

#if !defined(__XEN__) && !defined(__XEN_TOOLS__)
#error "sysctl operations are intended for use by node control tools only"
#endif

#include "xen.h"
#include "domctl.h"

#define XEN_SYSCTL_INTERFACE_VERSION 0x00000003

/*
 * Read console content from Xen buffer ring.
 */
#define XEN_SYSCTL_readconsole       1
struct xen_sysctl_readconsole {
    /* IN variables. */
    uint32_t clear;                /* Non-zero -> clear after reading. */
    XEN_GUEST_HANDLE(char) buffer; /* Buffer start */
    /* IN/OUT variables. */
    uint32_t count;            /* In: Buffer size;  Out: Used buffer size  */
};
typedef struct xen_sysctl_readconsole xen_sysctl_readconsole_t;
DEFINE_XEN_GUEST_HANDLE(xen_sysctl_readconsole_t);

/* Get trace buffers machine base address */
#define XEN_SYSCTL_tbuf_op           2
struct xen_sysctl_tbuf_op {
    /* IN variables */
#define XEN_SYSCTL_TBUFOP_get_info     0
#define XEN_SYSCTL_TBUFOP_set_cpu_mask 1
#define XEN_SYSCTL_TBUFOP_set_evt_mask 2
#define XEN_SYSCTL_TBUFOP_set_size     3
#define XEN_SYSCTL_TBUFOP_enable       4
#define XEN_SYSCTL_TBUFOP_disable      5
    uint32_t cmd;
    /* IN/OUT variables */
    struct xenctl_cpumap cpu_mask;
    uint32_t             evt_mask;
    /* OUT variables */
    uint64_t buffer_mfn;
    uint32_t size;
};
typedef struct xen_sysctl_tbuf_op xen_sysctl_tbuf_op_t;
DEFINE_XEN_GUEST_HANDLE(xen_sysctl_tbuf_op_t);

/*
 * Get physical information about the host machine
 */
#define XEN_SYSCTL_physinfo          3
struct xen_sysctl_physinfo {
    /* IN variables. */
    uint32_t threads_per_core;
    uint32_t cores_per_socket;
    uint32_t sockets_per_node;
    uint32_t nr_nodes;
    uint32_t cpu_khz;
    uint64_t total_pages;
    uint64_t free_pages;
    uint64_t scrub_pages;
    uint32_t hw_cap[8];

    /* IN/OUT variables. */
    /*
     * IN: maximum addressable entry in the caller-provided cpu_to_node array.
     * OUT: largest cpu identifier in the system.
     * If OUT is greater than IN then the cpu_to_node array is truncated!
     */
    uint32_t max_cpu_id;
    /*
     * If not NULL, this array is filled with node identifier for each cpu.
     * If a cpu has no node information (e.g., cpu not present) then the
     * sentinel value ~0u is written.
     * The size of this array is specified by the caller in @max_cpu_id.
     * If the actual @max_cpu_id is smaller than the array then the trailing
     * elements of the array will not be written by the sysctl.
     */
    XEN_GUEST_HANDLE_64(uint32_t) cpu_to_node;
};
typedef struct xen_sysctl_physinfo xen_sysctl_physinfo_t;
DEFINE_XEN_GUEST_HANDLE(xen_sysctl_physinfo_t);

/*
 * Get the ID of the current scheduler.
 */
#define XEN_SYSCTL_sched_id          4
struct xen_sysctl_sched_id {
    /* OUT variable */
    uint32_t sched_id;
};
typedef struct xen_sysctl_sched_id xen_sysctl_sched_id_t;
DEFINE_XEN_GUEST_HANDLE(xen_sysctl_sched_id_t);

/* Interface for controlling Xen software performance counters. */
#define XEN_SYSCTL_perfc_op          5
/* Sub-operations: */
#define XEN_SYSCTL_PERFCOP_reset 1   /* Reset all counters to zero. */
#define XEN_SYSCTL_PERFCOP_query 2   /* Get perfctr information. */
struct xen_sysctl_perfc_desc {
    char         name[80];             /* name of perf counter */
    uint32_t     nr_vals;              /* number of values for this counter */
};
typedef struct xen_sysctl_perfc_desc xen_sysctl_perfc_desc_t;
DEFINE_XEN_GUEST_HANDLE(xen_sysctl_perfc_desc_t);
typedef uint32_t xen_sysctl_perfc_val_t;
DEFINE_XEN_GUEST_HANDLE(xen_sysctl_perfc_val_t);

struct xen_sysctl_perfc_op {
    /* IN variables. */
    uint32_t       cmd;                /*  XEN_SYSCTL_PERFCOP_??? */
    /* OUT variables. */
    uint32_t       nr_counters;       /*  number of counters description  */
    uint32_t       nr_vals;			  /*  number of values  */
    /* counter information (or NULL) */
    XEN_GUEST_HANDLE(xen_sysctl_perfc_desc_t) desc;
    /* counter values (or NULL) */
    XEN_GUEST_HANDLE(xen_sysctl_perfc_val_t) val;
};
typedef struct xen_sysctl_perfc_op xen_sysctl_perfc_op_t;
DEFINE_XEN_GUEST_HANDLE(xen_sysctl_perfc_op_t);

#define XEN_SYSCTL_getdomaininfolist 6
struct xen_sysctl_getdomaininfolist {
    /* IN variables. */
    domid_t               first_domain;
    uint32_t              max_domains;
    XEN_GUEST_HANDLE(xen_domctl_getdomaininfo_t) buffer;
    /* OUT variables. */
    uint32_t              num_domains;
};
typedef struct xen_sysctl_getdomaininfolist xen_sysctl_getdomaininfolist_t;
DEFINE_XEN_GUEST_HANDLE(xen_sysctl_getdomaininfolist_t);

struct xen_sysctl {
    uint32_t cmd;
    uint32_t interface_version; /* XEN_SYSCTL_INTERFACE_VERSION */
    union {
        struct xen_sysctl_readconsole       readconsole;
        struct xen_sysctl_tbuf_op           tbuf_op;
        struct xen_sysctl_physinfo          physinfo;
        struct xen_sysctl_sched_id          sched_id;
        struct xen_sysctl_perfc_op          perfc_op;
        struct xen_sysctl_getdomaininfolist getdomaininfolist;
        uint8_t                             pad[128];
    } u;
};
typedef struct xen_sysctl xen_sysctl_t;
DEFINE_XEN_GUEST_HANDLE(xen_sysctl_t);

#endif /* __XEN_PUBLIC_SYSCTL_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
