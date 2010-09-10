#ifndef __BNX2X_COMPAT_H__
#define __BNX2X_COMPAT_H__

/* Taken from drivers/net/mdio.c */
#include <linux/mii.h>

/* MDIO Manageable Devices (MMDs). */
#define MDIO_MMD_AN		7	/* Auto-Negotiation */

/* Generic MDIO registers. */
#define MDIO_AN_ADVERTISE	16	/* AN advertising (base page) */
#define MDIO_AN_LPA		19	/* AN LP abilities (base page) */

/* Device present registers. */
#define MDIO_DEVS_PRESENT(devad)	(1 << (devad))
#define MDIO_DEVS_AN			MDIO_DEVS_PRESENT(MDIO_MMD_AN)

/**
 * struct mdio_if_info - Ethernet controller MDIO interface
 * @prtad: PRTAD of the PHY (%MDIO_PRTAD_NONE if not present/unknown)
 * @mmds: Mask of MMDs expected to be present in the PHY.  This must be
 *	non-zero unless @prtad = %MDIO_PRTAD_NONE.
 * @mode_support: MDIO modes supported.  If %MDIO_SUPPORTS_C22 is set then
 *	MII register access will be passed through with @devad =
 *	%MDIO_DEVAD_NONE.  If %MDIO_EMULATE_C22 is set then access to
 *	commonly used clause 22 registers will be translated into
 *	clause 45 registers.
 * @dev: Net device structure
 * @mdio_read: Register read function; returns value or negative error code
 * @mdio_write: Register write function; returns 0 or negative error code
 */
struct mdio_if_info {
	int prtad;
	u32 __bitwise mmds;
	unsigned mode_support;

	struct net_device *dev;
	int (*mdio_read)(struct net_device *dev, int prtad, int devad,
			 u16 addr);
	int (*mdio_write)(struct net_device *dev, int prtad, int devad,
			  u16 addr, u16 val);
};

#define MDIO_PRTAD_NONE			(-1)
#define MDIO_DEVAD_NONE			(-1)
#define MDIO_EMULATE_C22		4

/* Mapping between MDIO PRTAD/DEVAD and mii_ioctl_data::phy_id */

#define MDIO_PHY_ID_C45			0x8000
#define MDIO_PHY_ID_PRTAD		0x03e0
#define MDIO_PHY_ID_DEVAD		0x001f
#define MDIO_PHY_ID_C45_MASK						\
	(MDIO_PHY_ID_C45 | MDIO_PHY_ID_PRTAD | MDIO_PHY_ID_DEVAD)

static inline int mdio_phy_id_is_c45(int phy_id)
{
	return (phy_id & MDIO_PHY_ID_C45) && !(phy_id & ~MDIO_PHY_ID_C45_MASK);
}

static inline __u16 mdio_phy_id_prtad(int phy_id)
{
	return (phy_id & MDIO_PHY_ID_PRTAD) >> 5;
}

static inline __u16 mdio_phy_id_devad(int phy_id)
{
	return phy_id & MDIO_PHY_ID_DEVAD;
}

#define MDIO_SUPPORTS_C22		1
#define MDIO_SUPPORTS_C45		2

/**
 * mdio_mii_ioctl - MII ioctl interface for MDIO (clause 22 or 45) PHYs
 * @mdio: MDIO interface
 * @mii_data: MII ioctl data structure
 * @cmd: MII ioctl command
 *
 * Returns 0 on success, negative on error.
 */
static inline int mdio_mii_ioctl(const struct mdio_if_info *mdio,
				 struct mii_ioctl_data *mii_data, int cmd)
{
	int prtad, devad;
	u16 addr = mii_data->reg_num;

	/* Validate/convert cmd to one of SIOC{G,S}MIIREG */
	switch (cmd) {
	case SIOCGMIIPHY:
		if (mdio->prtad == MDIO_PRTAD_NONE)
			return -EOPNOTSUPP;
		mii_data->phy_id = mdio->prtad;
		cmd = SIOCGMIIREG;
		break;
	case SIOCGMIIREG:
		break;
	case SIOCSMIIREG:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		break;
	default:
		return -EOPNOTSUPP;
	}

	/* Validate/convert phy_id */
	if ((mdio->mode_support & MDIO_SUPPORTS_C45) &&
	    mdio_phy_id_is_c45(mii_data->phy_id)) {
		prtad = mdio_phy_id_prtad(mii_data->phy_id);
		devad = mdio_phy_id_devad(mii_data->phy_id);
	} else if ((mdio->mode_support & MDIO_SUPPORTS_C22) &&
		   mii_data->phy_id < 0x20) {
		prtad = mii_data->phy_id;
		devad = MDIO_DEVAD_NONE;
		addr &= 0x1f;
	} else if ((mdio->mode_support & MDIO_EMULATE_C22) &&
		   mdio->prtad != MDIO_PRTAD_NONE &&
		   mii_data->phy_id == mdio->prtad) {
		/* Remap commonly-used MII registers. */
		prtad = mdio->prtad;
		switch (addr) {
		case MII_BMCR:
		case MII_BMSR:
		case MII_PHYSID1:
		case MII_PHYSID2:
			devad = __ffs(mdio->mmds);
			break;
		case MII_ADVERTISE:
		case MII_LPA:
			if (!(mdio->mmds & MDIO_DEVS_AN))
				return -EINVAL;
			devad = MDIO_MMD_AN;
			if (addr == MII_ADVERTISE)
				addr = MDIO_AN_ADVERTISE;
			else
				addr = MDIO_AN_LPA;
			break;
		default:
			return -EINVAL;
		}
	} else {
		return -EINVAL;
	}

	if (cmd == SIOCGMIIREG) {
		int rc = mdio->mdio_read(mdio->dev, prtad, devad, addr);
		if (rc < 0)
			return rc;
		mii_data->val_out = rc;
		return 0;
	} else {
		return mdio->mdio_write(mdio->dev, prtad, devad, addr,
					mii_data->val_in);
	}
}

#endif /* __BNX2X_COMPAT_H__ */

