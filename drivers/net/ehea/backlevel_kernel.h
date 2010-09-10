#ifndef __BACKLEVEL_KERNEL_H__
#define __BACKLEVEL_KERNEL_H__

#define NET_IP_ALIGN 0

#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/kthread.h>
#include <asm/semaphore.h>
#include <asm/current.h>
#include <asm/of_device.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
#define vlan_group_set_device(vlan_group, vlan_id, net_device)	\
{								\
	if (vlan_group)						\
		vlan_group->vlan_devices[vlan_id] = net_device; \
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#define netdev_alloc_skb(dev, len) old_dev_alloc_skb(dev, len)

static inline struct sk_buff *old_dev_alloc_skb(struct net_device *dev,
						unsigned int length)
{
	struct sk_buff *skb = dev_alloc_skb(length);
	skb->dev = dev;
	return skb;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#include <linux/delay.h>
#define gso_size tso_size
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
static inline void* kzalloc(size_t size, unsigned int flags)
{
	void* ptr = kmalloc(size, flags);
	if (likely(ptr))
		memset(ptr, 0, size);
	return ptr;
}
#endif

#define H_LONG_BUSY_START_RANGE		9900  /* Start of long busy range */
#define H_LONG_BUSY_ORDER_1_MSEC	9900  /* Long busy, hint that 1msec \
						 is a good time to retry */
#define H_LONG_BUSY_ORDER_10_MSEC	9901  /* Long busy, hint that 10msec \
						 is a good time to retry */
#define H_LONG_BUSY_ORDER_100_MSEC 	9902  /* Long busy, hint that 100msec \
						 is a good time to retry */
#define H_LONG_BUSY_ORDER_1_SEC		9903  /* Long busy, hint that 1sec \
						 is a good time to retry */
#define H_LONG_BUSY_ORDER_10_SEC	9904  /* Long busy, hint that 10sec \
						 is a good time to retry */
#define H_LONG_BUSY_ORDER_100_SEC	9905  /* Long busy, hint that 100sec \
						 is a good time to retry */
#define H_LONG_BUSY_END_RANGE		9905  /* End of long busy range */


#define H_IS_LONG_BUSY(x)  ((x >= H_LONG_BUSY_START_RANGE) && \
			    (x <= H_LONG_BUSY_END_RANGE))


#if !defined(_PPC64_HVCALL_H) || (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10))
/* /usr/src/linux/include/asm-ppc64/hvcall.h */
#define H_SUCCESS		 0
#define H_HARDWARE              -1
#define H_FUNCTION              -2
#define H_PRIVILEGE             -3
#define H_PARAMETER             -4
#define H_BAD_MODE              -5
#define H_PTEG_FULL             -6
#define H_NOT_FOUND             -7
#define H_RESERVED_DABR         -8
#define H_NOMEM                 -9
#define H_AUTHORITY            -10
#define H_PERMISSION           -11
#define H_DROPPED              -12
#define H_SOURCEPARM           -13
#define H_DESTPARM             -14
#define H_REMOTEPARM           -15
#define H_RESOURCE             -16
#define H_ADAPTER_PARM         -17
#define H_RH_PARM              -18
#define H_RCQ_PARM             -19
#define H_SCQ_PARM             -20
#define H_EQ_PARM              -21
#define H_RT_PARM              -22
#define H_ST_PARM              -23
#define H_SIGT_PARM            -24
#define H_TOKEN_PARM           -25
#define H_MLENGTH_PARM         -27
#define H_MEM_PARM             -28
#define H_MEM_ACCESS_PARM      -29
#define H_ATTR_PARM            -30
#define H_PORT_PARM            -31
#define H_MCG_PARM             -32
#define H_VL_PARM              -33
#define H_TSIZE_PARM           -34
#define H_TRACE_PARM           -35
#define H_MASK_PARM            -37
#define H_MCG_FULL             -38
#define H_ALIAS_EXIST          -39
#define H_P_COUNTER            -40
#define H_TABLE_FULL           -41
#define H_ALT_TABLE            -42
#define H_MR_CONDITION         -43
#define H_NOT_ENOUGH_RESOURCES -44
#define H_R_STATE              -45
#define H_RESCINDEND           -46

#define H_BUSY                   1
#define H_CLOSED                 2
#define H_NOT_AVAILABLE          3
#define H_CONSTRAINED            4
#define H_PARTIAL                5
#define H_SENSVAL_CRIT_LOW       9
#define H_SENSVAL_WARN_LOW      10
#define H_SENSVAL_NORMAL        11
#define H_SENSVAL_WARN_HIGH     12
#define H_SENSVAL_CRIT_HIGH     13
#define H_IN_PROGRESS           14
#define H_PAGE_REGISTERED       15
#define H_PARTIAL_STORE         16
#define H_PENDING               17

/* Hcall defines to be moved to kernel */
#define H_RESET_EVENTS         0x15C
#define H_ALLOC_RESOURCE       0x160
#define H_FREE_RESOURCE        0x164
#define H_MODIFY_QP            0x168
#define H_QUERY_QP             0x16C
#define H_REREGISTER_PMR       0x170
#define H_REGISTER_SMR         0x174
#define H_QUERY_MR             0x178
#define H_QUERY_MW             0x17C
#define H_QUERY_HCA            0x180
#define H_QUERY_PORT           0x184
#define H_MODIFY_PORT          0x188
#define H_DEFINE_AQP1          0x18C
#define H_GET_TRACE_BUFFER     0x190
#define H_DEFINE_AQP0          0x194
#define H_RESIZE_MR            0x198
#define H_ATTACH_MCQP          0x19C
#define H_DETACH_MCQP          0x1A0
#define H_CREATE_RPT           0x1A4
#define H_REMOVE_RPT           0x1A8
#define H_REGISTER_RPAGES      0x1AC
#define H_DISABLE_AND_GETC     0x1B0
#define H_ERROR_DATA           0x1B4
#define H_GET_HCA_INFO         0x1B8
#define H_GET_PERF_COUNT       0x1BC
#define H_MANAGE_TRACE         0x1C0
#define H_QUERY_INT_STATE      0x1E4

#endif

/* Hcall defines for EHEA */
#define H_ALLOC_HEA_RESOURCE   0x278
#define H_MODIFY_HEA_QP        0x250
#define H_QUERY_HEA_QP         0x254
#define H_QUERY_HEA            0x258
#define H_QUERY_HEA_PORT       0x25C
#define H_MODIFY_HEA_PORT      0x260
#define H_REG_BCMC             0x264
#define H_DEREG_BCMC           0x268
#define H_REGISTER_HEA_RPAGES  0x26C
#define H_DISABLE_AND_GET_HEA  0x270
#define H_GET_HEA_INFO         0x274
#define H_ADD_CONN             0x284
#define H_DEL_CONN             0x288


#ifndef NETDEV_TX_BUSY
#define NETDEV_TX_BUSY 1
#endif

#define  NETDEV_TX_LOCKED -1
#define  NETDEV_TX_OK 0

struct hcall {
	u64 regs[11];
};


inline static long plpar_hcall_7arg_7ret(unsigned long opcode,
					 unsigned long arg1,    /* <R4  */
					 unsigned long arg2,	/* <R5  */
					 unsigned long arg3,	/* <R6  */
					 unsigned long arg4,	/* <R7  */
					 unsigned long arg5,	/* <R8  */
					 unsigned long arg6,	/* <R9  */
					 unsigned long arg7,	/* <R10 */
					 unsigned long *out1,	/* <R4  */
					 unsigned long *out2,	/* <R5  */
					 unsigned long *out3,	/* <R6  */
					 unsigned long *out4,	/* <R7  */
					 unsigned long *out5,	/* <R8  */
					 unsigned long *out6,	/* <R9  */
					 unsigned long *out7	/* <R10 */
	)
{
	struct hcall hcall_in = {
		.regs[0] = opcode,
		.regs[1] = arg1,
		.regs[2] = arg2,
		.regs[3] = arg3,
		.regs[4] = arg4,
		.regs[5] = arg5,
		.regs[6] = arg6,
		.regs[7] = arg7	/*,
				  .regs[8]=arg8 */
	};
	struct hcall hcall = hcall_in;
	long ret;

#ifdef DEBUG
	ehea_info("HCALL77_IN r3=%lx r4=%lx r5=%lx r6=%lx r7=%lx r8=%lx"
	     " r9=%lx r10=%lx r11=%lx", hcall.regs[0], hcall.regs[1],
	     hcall.regs[2], hcall.regs[3], hcall.regs[4], hcall.regs[5],
	     hcall.regs[6], hcall.regs[7], hcall.regs[8]);
#endif

	/* if phype returns LongBusyXXX,
	 * we retry several times, but not forever */
	__asm__ __volatile__("mr 3,%10\n"
			     "mr 4,%11\n"
			     "mr 5,%12\n"
			     "mr 6,%13\n"
			     "mr 7,%14\n"
			     "mr 8,%15\n"
			     "mr 9,%16\n"
			     "mr 10,%17\n"
			     "mr 11,%18\n"
			     "mr 12,%19\n"
			     ".long 0x44000022\n"
			     "mr %0,3\n"
			     "mr %1,4\n"
			     "mr %2,5\n"
			     "mr %3,6\n"
			     "mr %4,7\n"
			     "mr %5,8\n"
			     "mr %6,9\n"
			     "mr %7,10\n"
			     "mr %8,11\n"
			     "mr %9,12\n":"=r"(hcall.regs[0]),
			     "=r"(hcall.regs[1]), "=r"(hcall.regs[2]),
			     "=r"(hcall.regs[3]), "=r"(hcall.regs[4]),
			     "=r"(hcall.regs[5]), "=r"(hcall.regs[6]),
			     "=r"(hcall.regs[7]), "=r"(hcall.regs[8]),
			     "=r"(hcall.regs[9])
			     :"r"(hcall.regs[0]), "r"(hcall.regs[1]),
			     "r"(hcall.regs[2]), "r"(hcall.regs[3]),
			     "r"(hcall.regs[4]), "r"(hcall.regs[5]),
			     "r"(hcall.regs[6]), "r"(hcall.regs[7]),
			     "r"(hcall.regs[8]), "r"(hcall.regs[9])
			     :"r0", "r2", "r3", "r4", "r5", "r6", "r7",
			     "r8", "r9", "r10", "r11", "r12", "cc",
			     "xer", "ctr", "lr", "cr0", "cr1", "cr5",
			     "cr6", "cr7");

#ifdef DEBUG
	ehea_info("HCALL77_OUT r3=%lx r4=%lx r5=%lx r6=%lx r7=%lx r8=%lx"
	     "r9=%lx r10=%lx r11=%lx", hcall.regs[0], hcall.regs[1],
	     hcall.regs[2], hcall.regs[3], hcall.regs[4], hcall.regs[5],
	     hcall.regs[6], hcall.regs[7], hcall.regs[8]);
#endif
	ret = hcall.regs[0];
	*out1 = hcall.regs[1];
	*out2 = hcall.regs[2];
	*out3 = hcall.regs[3];
	*out4 = hcall.regs[4];
	*out5 = hcall.regs[5];
	*out6 = hcall.regs[6];
	*out7 = hcall.regs[7];

	return ret;
}

inline static long plpar_hcall_9arg_9ret(unsigned long opcode,
					 unsigned long arg1,	/* <R4  */
					 unsigned long arg2,	/* <R5  */
					 unsigned long arg3,	/* <R6  */
					 unsigned long arg4,	/* <R7  */
					 unsigned long arg5,	/* <R8  */
					 unsigned long arg6,	/* <R9  */
					 unsigned long arg7,	/* <R10 */
					 unsigned long arg8,	/* <R11 */
					 unsigned long arg9,	/* <R12 */
					 unsigned long *out1,	/* <R4  */
					 unsigned long *out2,	/* <R5  */
					 unsigned long *out3,	/* <R6  */
					 unsigned long *out4,	/* <R7  */
					 unsigned long *out5,	/* <R8  */
					 unsigned long *out6,	/* <R9  */
					 unsigned long *out7,	/* <R10 */
					 unsigned long *out8,	/* <R11 */
					 unsigned long *out9	/* <R12 */
	)
{
	struct hcall hcall_in = {
		.regs[0] = opcode,
		.regs[1] = arg1,
		.regs[2] = arg2,
		.regs[3] = arg3,
		.regs[4] = arg4,
		.regs[5] = arg5,
		.regs[6] = arg6,
		.regs[7] = arg7,
		.regs[8] = arg8,
		.regs[9] = arg9,
	};
	struct hcall hcall = hcall_in;
	long ret;
#ifdef DEBUG
	ehea_info("HCALL99_IN  r3=%lx r4=%lx r5=%lx r6=%lx r7=%lx r8=%lx r9=%lx"
	     " r10=%lx r11=%lx r12=%lx",
	     hcall.regs[0], hcall.regs[1], hcall.regs[2], hcall.regs[3],
	     hcall.regs[4], hcall.regs[5], hcall.regs[6], hcall.regs[7],
	     hcall.regs[8], hcall.regs[9]);
#endif

	/* if phype returns LongBusyXXX, we retry several times, but not forever */
	__asm__ __volatile__("mr 3,%10\n"
			     "mr 4,%11\n"
			     "mr 5,%12\n"
			     "mr 6,%13\n"
			     "mr 7,%14\n"
			     "mr 8,%15\n"
			     "mr 9,%16\n"
			     "mr 10,%17\n"
			     "mr 11,%18\n"
			     "mr 12,%19\n"
			     ".long 0x44000022\n"
			     "mr %0,3\n"
			     "mr %1,4\n"
			     "mr %2,5\n"
			     "mr %3,6\n"
			     "mr %4,7\n"
			     "mr %5,8\n"
			     "mr %6,9\n"
			     "mr %7,10\n"
			     "mr %8,11\n"
			     "mr %9,12\n":"=r"(hcall.regs[0]),
			     "=r"(hcall.regs[1]), "=r"(hcall.regs[2]),
			     "=r"(hcall.regs[3]), "=r"(hcall.regs[4]),
			     "=r"(hcall.regs[5]), "=r"(hcall.regs[6]),
			     "=r"(hcall.regs[7]), "=r"(hcall.regs[8]),
			     "=r"(hcall.regs[9])
			     :"r"(hcall.regs[0]), "r"(hcall.regs[1]),
			     "r"(hcall.regs[2]), "r"(hcall.regs[3]),
			     "r"(hcall.regs[4]), "r"(hcall.regs[5]),
			     "r"(hcall.regs[6]), "r"(hcall.regs[7]),
			     "r"(hcall.regs[8]), "r"(hcall.regs[9])
			     :"r0", "r2", "r3", "r4", "r5", "r6", "r7",
			     "r8", "r9", "r10", "r11", "r12", "cc",
			     "xer", "ctr", "lr", "cr0", "cr1", "cr5",
			     "cr6", "cr7");

#ifdef DEBUG
	ehea_info("HCALL99_OUT r3=%lx r4=%lx r5=%lx r6=%lx r7=%lx r8=%lx "
	     "r9=%lx r10=%lx r11=%lx r12=%lx", hcall.regs[0],
	     hcall.regs[1], hcall.regs[2], hcall.regs[3], hcall.regs[4],
	     hcall.regs[5], hcall.regs[6], hcall.regs[7], hcall.regs[8],
	     hcall.regs[9]);
#endif
	ret = hcall.regs[0];
	*out1 = hcall.regs[1];
	*out2 = hcall.regs[2];
	*out3 = hcall.regs[3];
	*out4 = hcall.regs[4];
	*out5 = hcall.regs[5];
	*out6 = hcall.regs[6];
	*out7 = hcall.regs[7];
	*out8 = hcall.regs[8];
	*out9 = hcall.regs[9];

	return ret;
}

#endif	/* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17) */

#ifndef PLPAR_HCALL9_BUFSIZE
#define PLPAR_HCALL9_BUFSIZE 10

static inline long plpar_hcall9(u64 opcode, u64 *outs, u64 arg1, u64 arg2, u64 arg3, u64 arg4,
	     u64 arg5, u64 arg6, u64 arg7, u64 arg8, u64 arg9)
{
	return plpar_hcall_9arg_9ret(opcode,arg1, arg2, arg3, arg4,
				       arg5, arg6, arg7, arg8, arg9, &outs[0],
				       &outs[1], &outs[2], &outs[3], &outs[4],
				       &outs[5], &outs[6], &outs[7], &outs[7]);
};
#endif

#endif	/* __BACKLEVEL_KERNEL_H__ */
