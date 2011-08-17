/*
 * QLogic iSCSI HBA Driver
 * Copyright (c)  2003-2010 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 */

#define QLA4XXX_DRIVER_VERSION	"5.02.04.02.05.06-d0"

/*
 * Driver Versioning Scheme:
 * Major.Minor.Patch.Subminor.Distro.DistroLevel-SuffixBeta
 *
 * - Major#: Denotes driver family
 *           (i.e. 5=iSCSI 2.6, 3=iSCSI 2.4, etc.)
 * - Minor#: Denotes which iSCSI chip is supported
 *           (i.e. 5.01=Add 4032, 5.02=Add P3P, etc.)
 * - Patch#: Major Feature or structure (common w/ IOCTL) change.
 *           Must match patch# in corresponding qisioctl.
 *           **************************************************
 *           ***   Also used to distinguish inbox vs OOT    ***
 *           ***   (Inbox = even number, OOT = odd number)  ***
 *           **************************************************
 * - Subminor#: Updated per external release if the above numbers remain
 *           unchanged. Set to 0 if above numbers are changed.
 * - Beta#:  To be used for internal/test/EVT builds.
 *           Set to 0 for release to DVT or external users.
 * - Suffix [-k/-c/-d]:
 *           -k: upstream or sysfs based drivers,
 *           -d: ioctl based,
 *           -c: Citrix XenServer based
 */
