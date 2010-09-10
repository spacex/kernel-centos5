#ifndef __SKY_COMPAT_H__
#define __SKY_COMPAT_H__

#define CHECKSUM_PARTIAL	CHECKSUM_HW
#define CHECKSUM_COMPLETE	CHECKSUM_HW

static inline void vlan_group_set_device(struct vlan_group *vg, int vlan_id,
                                         struct net_device *dev)
{
	if (vg)
		vg->vlan_devices[vlan_id] = NULL;
}

#endif /* __SKY_COMPAT_H__ */
