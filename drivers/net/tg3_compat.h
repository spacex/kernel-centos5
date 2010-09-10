#ifndef __TG3_COMPAT_H__
#define __TG3_COMPAT_H__

#define PCI_X_CMD_READ_2K	0x0008  /* 2Kbyte maximum read byte count */

#define TG3_DIST_FLAG_IN_RESET_TASK	0x00000001

#define ETH_FCS_LEN		4

#define PCI_DEVICE(vend,dev) \
        .vendor = (vend), .device = (dev), \
        .subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID

#endif
