#ifndef __IXGBE_COMPAT_H__
#define __IXGBE_COMPAT_H__

#include <linux/if_vlan.h>

#define ETH_FCS_LEN               4

static inline struct net_device *vlan_group_get_device(struct vlan_group *vg,
						       int vlan_id)
{
	return vg->vlan_devices[vlan_id];
}

static inline void vlan_group_set_device(struct vlan_group *vg, int vlan_id,
					 struct net_device *dev)
{
	vg->vlan_devices[vlan_id] = NULL;
}

/*
 * * FCoE CRC & EOF - 8 bytes.
 **/
struct fcoe_crc_eof {
	__le32          fcoe_crc32;     /* CRC for FC packet */
	__u8            fcoe_eof;       /* EOF from RFC 3643 */
	__u8            fcoe_resvd[3];  /* reserved - send zero and ignore */
} __attribute__((packed));

#define IXGBE_RTTDCS_ARBDIS     0x00000040 /* DCB arbiter disable */

#endif 
