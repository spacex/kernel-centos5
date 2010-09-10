/*
 *  include/asm-s390/setup.h
 *
 *  S390 version
 *    Copyright (C) 1999 IBM Deutschland Entwicklung GmbH, IBM Corporation
 */

#ifndef _ASM_S390_SETUP_H
#define _ASM_S390_SETUP_H

#ifdef __KERNEL__

#include <asm/types.h>

#define PARMAREA		0x10400
#define COMMAND_LINE_SIZE 	896
#define RAMDISK_ORIGIN		0x800000
#define RAMDISK_SIZE		0x800000
#define MEMORY_CHUNKS		16	/* max 0x7fff */

#ifndef __ASSEMBLY__

#ifndef __s390x__
#define IPL_DEVICE        (*(unsigned long *)  (0x10404))
#define INITRD_START      (*(unsigned long *)  (0x1040C))
#define INITRD_SIZE       (*(unsigned long *)  (0x10414))
#else /* __s390x__ */
#define IPL_DEVICE        (*(unsigned long *)  (0x10400))
#define INITRD_START      (*(unsigned long *)  (0x10408))
#define INITRD_SIZE       (*(unsigned long *)  (0x10410))
#endif /* __s390x__ */
#define COMMAND_LINE      ((char *)            (0x10480))

extern unsigned long real_memory_size;

/*
 * Machine features detected in head.S
 */
extern unsigned long machine_flags;

#define MACHINE_IS_VM		(machine_flags & 1)
#define MACHINE_IS_P390		(machine_flags & 4)
#define MACHINE_HAS_MVPG	(machine_flags & 16)
#define MACHINE_HAS_IDTE	(machine_flags & 128)
#define MACHINE_HAS_DIAG9C	(machine_flags & 256)

#ifndef __s390x__
#define MACHINE_HAS_IEEE	(machine_flags & 2)
#define MACHINE_HAS_CSP		(machine_flags & 8)
#define MACHINE_HAS_DIAG44	(1)
#define MACHINE_HAS_HPAGE	(0)
#define MACHINE_HAS_CPAGE	(0)
#else /* __s390x__ */
#define MACHINE_HAS_IEEE	(1)
#define MACHINE_HAS_CSP		(1)
#define MACHINE_HAS_DIAG44	(machine_flags & 32)
#define MACHINE_HAS_HPAGE	(machine_flags & 1024)
#define MACHINE_HAS_CPAGE	(machine_flags & 2048)
#endif /* __s390x__ */


#define MACHINE_HAS_SCLP	(!MACHINE_IS_P390)
#define ZFCPDUMP_HSA_SIZE	(32UL<<20)

/*
 * Console mode. Override with conmode=
 */
extern unsigned int console_mode;
extern unsigned int console_devno;
extern unsigned int console_irq;

#define CONSOLE_IS_UNDEFINED	(console_mode == 0)
#define CONSOLE_IS_SCLP		(console_mode == 1)
#define CONSOLE_IS_3215		(console_mode == 2)
#define CONSOLE_IS_3270		(console_mode == 3)
#define SET_CONSOLE_SCLP	do { console_mode = 1; } while (0)
#define SET_CONSOLE_3215	do { console_mode = 2; } while (0)
#define SET_CONSOLE_3270	do { console_mode = 3; } while (0)

/*
 * IPL validity flags and parameters as detected in head.S
 */
extern u32 ipl_parameter_flags;
extern u16 ipl_devno;

void do_reipl(void);

#else /* __ASSEMBLY__ */

#ifndef __s390x__
#define IPL_DEVICE        0x10404
#define INITRD_START      0x1040C
#define INITRD_SIZE       0x10414
#else /* __s390x__ */
#define IPL_DEVICE        0x10400
#define INITRD_START      0x10408
#define INITRD_SIZE       0x10410
#endif /* __s390x__ */
#define COMMAND_LINE      0x10480

#endif /* __ASSEMBLY__ */
#endif /* __KERNEL__ */
#endif /* _ASM_S390_SETUP_H */
