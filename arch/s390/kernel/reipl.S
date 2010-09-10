/*
 *  arch/s390/kernel/reipl.S
 *
 *  S390 version
 *    Copyright (C) 2000 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *    Author(s): Holger Smolinski (Holger.Smolinski@de.ibm.com)
 */

#include <asm/lowcore.h>

		.globl	do_reipl_asm
do_reipl_asm:	basr	%r13,0
.Lpg0:		lpsw	.Lnewpsw-.Lpg0(%r13)

		# switch off lowcore protection

.Lpg1:		stctl   %c0,%c0,.Lctlsave1-.Lpg0(%r13)
		stctl   %c0,%c0,.Lctlsave2-.Lpg0(%r13)
		ni      .Lctlsave1-.Lpg0(%r13),0xef
		lctl    %c0,%c0,.Lctlsave1-.Lpg0(%r13)

		# do store status of all registers

		stpx    .Lprefix-.Lpg0(%r13)
		l       %r1,.Lprefix-.Lpg0(%r13)
		stm     %r0,%r15,__LC_GPREGS_SAVE_AREA(%r1)
		stctl   %c0,%c15,__LC_CREGS_SAVE_AREA(%r1)
		mvc     __LC_CREGS_SAVE_AREA(4, %r1),.Lctlsave2-.Lpg0(%r13)
		stam    %a0,%a15,__LC_AREGS_SAVE_AREA(%r1)
		stpx    __LC_PREFIX_SAVE_AREA(%r1)
		stckc   .Lclkcmp-.Lpg0(%r13)
		mvc     __LC_CLOCK_COMP_SAVE_AREA(8, %r1),.Lclkcmp-.Lpg0(%r13)
		stpt    __LC_CPU_TIMER_SAVE_AREA(%r1)
		st      %r13, __LC_PSW_SAVE_AREA+4(%r1)

		lctl    %c6,%c6,.Lall-.Lpg0(%r13)
                lr      %r1,%r2
        	mvc     __LC_PGM_NEW_PSW(8),.Lpcnew-.Lpg0(%r13)
                stsch   .Lschib-.Lpg0(%r13)                                    
	        oi      .Lschib+5-.Lpg0(%r13),0x84 
.Lecs:  	xi      .Lschib+27-.Lpg0(%r13),0x01 
        	msch    .Lschib-.Lpg0(%r13) 
                lhi     %r0,5
.Lssch:		ssch	.Liplorb-.Lpg0(%r13)           
		jz	.L001
                brct    %r0,.Lssch  
		bas	%r14,.Ldisab-.Lpg0(%r13)
.L001:		mvc	__LC_IO_NEW_PSW(8),.Lionew-.Lpg0(%r13)	
.Ltpi:		lpsw	.Lwaitpsw-.Lpg0(%r13)          
.Lcont:		c	%r1,__LC_SUBCHANNEL_ID
		jnz	.Ltpi
		clc	__LC_IO_INT_PARM(4),.Liplorb-.Lpg0(%r13)
		jnz	.Ltpi
		tsch	.Liplirb-.Lpg0(%r13)           
		tm	.Liplirb+9-.Lpg0(%r13),0xbf
                jz      .L002
                bas     %r14,.Ldisab-.Lpg0(%r13)    
.L002:		tm	.Liplirb+8-.Lpg0(%r13),0xf3    
                jz      .L003
                bas     %r14,.Ldisab-.Lpg0(%r13)	

		# restore lowcore for dump case
.L003:		lhi    %r5,4096
		lhi    %r7,4096
		la     %r6,lowcore_save-.Lpg0(%r13)
		lhi    %r4,0x0
0:		mvcle  %r4,%r6,0x0
		jo      0b

		spx	.Lnull-.Lpg0(%r13)
		st 	%r1,__LC_SUBCHANNEL_ID
                lpsw 	0
		sigp    0,0,0(6)               
.Ldisab:	st      %r14,.Ldispsw+4-.Lpg0(%r13)
		lpsw	.Ldispsw-.Lpg0(%r13)
                .align 	8
.Lclkcmp:       .quad   0x0000000000000000
.Lall:		.long	0xff000000
.Lnull:		.long   0x00000000
.Lprefix:	.long   0x00000000
.Lctlsave1:     .long   0x00000000
.Lctlsave2:     .long   0x00000000
                .align 	8
.Lnewpsw:	.long   0x00080000,0x80000000+.Lpg1
.Lpcnew:  	.long   0x00080000,0x80000000+.Lecs
.Lionew:	.long   0x00080000,0x80000000+.Lcont
.Lwaitpsw:	.long	0x020a0000,0x00000000+.Ltpi
.Ldispsw:	.long   0x000a0000,0x00000000
.Liplccws:	.long   0x02000000,0x60000018
		.long   0x08000008,0x20000001
.Liplorb:	.long	0x0049504c,0x0040ff80
		.long	0x00000000+.Liplccws
.Lschib:        .long   0x00000000,0x00000000
		.long   0x00000000,0x00000000
		.long   0x00000000,0x00000000
		.long   0x00000000,0x00000000
		.long   0x00000000,0x00000000
		.long   0x00000000,0x00000000
.Liplirb:	.long	0x00000000,0x00000000
		.long	0x00000000,0x00000000
		.long	0x00000000,0x00000000
		.long	0x00000000,0x00000000
		.long	0x00000000,0x00000000
		.long	0x00000000,0x00000000
		.long	0x00000000,0x00000000
		.long	0x00000000,0x00000000
	.globl lowcore_save
lowcore_save:
	.fill 4096,1,0
