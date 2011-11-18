#ifndef _NET_SECURE_SEQ
#define _NET_SECURE_SEQ

#include <linux/types.h>

extern __u32 secure_ip_id(__u32 daddr);
extern u32 secure_ipv4_port_ephemeral(__u32 saddr, __u32 daddr, __u16 dport);
extern u32 secure_ipv6_port_ephemeral(const __u32 *saddr, const __u32 *daddr,
				      __u16 dport);
extern __u32 secure_tcp_sequence_number(__u32 saddr, __u32 daddr,
					__u16 sport, __u16 dport);
extern __u32 secure_tcpv6_sequence_number(__u32 *saddr, __u32 *daddr,
					  __u16 sport, __u16 dport);
extern u64 secure_dccp_sequence_number(__u32 saddr, __u32 daddr,
				       __u16 sport, __u16 dport);
extern u64 secure_dccpv6_sequence_number(__u32 *saddr, __u32 *daddr,
					 __u16 sport, __u16 dport);

#endif /* _NET_SECURE_SEQ */
