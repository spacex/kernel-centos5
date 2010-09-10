/*
 * This file contains miscellaneous low-level functions.
 *    Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *
 * Largely rewritten by Cort Dougan (cort@cs.nmt.edu)
 * and Paul Mackerras.
 *
 * setjmp/longjmp code by Paul Mackerras.
 *
 * Adapted for iSeries by Mike Corrigan (mikejc@us.ibm.com)
 * PPC64 updates by Dave Engebretsen (engebret@us.ibm.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <asm/ppc_asm.h>
#include <asm/asm-compat.h>
#include <asm/asm-offsets.h>

	.text

/*
 * Returns (address we are running at) - (address we were linked at)
 * for use before the text and data are mapped to KERNELBASE.
 */

_GLOBAL(reloc_offset)
	mflr	r0
	bl	1f
1:	mflr	r3
	LOAD_REG_IMMEDIATE(r4,1b)
	subf	r3,r4,r3
	mtlr	r0
	blr

/*
 * add_reloc_offset(x) returns x + reloc_offset().
 */
_GLOBAL(add_reloc_offset)
	mflr	r0
	bl	1f
1:	mflr	r5
	LOAD_REG_IMMEDIATE(r4,1b)
	subf	r5,r4,r5
	add	r3,r3,r5
	mtlr	r0
	blr

/*
 * I/O string operations
 *
 * insb(port, buf, len)
 * outsb(port, buf, len)
 * insw(port, buf, len)
 * outsw(port, buf, len)
 * insl(port, buf, len)
 * outsl(port, buf, len)
 * insw_ns(port, buf, len)
 * outsw_ns(port, buf, len)
 * insl_ns(port, buf, len)
 * outsl_ns(port, buf, len)
 *
 * The *_ns versions don't do byte-swapping.
 */
_GLOBAL(_insb)
	sync
	cmpwi	0,r5,0
	mtctr	r5
	subi	r4,r4,1
	blelr-
00:	lbz	r5,0(r3)
	eieio
	stbu	r5,1(r4)
	bdnz	00b
	twi	0,r5,0
	isync
	blr

_GLOBAL(_outsb)
	cmpwi	0,r5,0
	mtctr	r5
	subi	r4,r4,1
	blelr-
	sync
00:	lbzu	r5,1(r4)
	stb	r5,0(r3)
	bdnz	00b
	sync
	blr

_GLOBAL(_insw)
	sync
	cmpwi	0,r5,0
	mtctr	r5
	subi	r4,r4,2
	blelr-
00:	lhbrx	r5,0,r3
	eieio
	sthu	r5,2(r4)
	bdnz	00b
	twi	0,r5,0
	isync
	blr

_GLOBAL(_outsw)
	cmpwi	0,r5,0
	mtctr	r5
	subi	r4,r4,2
	blelr-
	sync
00:	lhzu	r5,2(r4)
	sthbrx	r5,0,r3
	bdnz	00b
	sync
	blr

_GLOBAL(_insl)
	sync
	cmpwi	0,r5,0
	mtctr	r5
	subi	r4,r4,4
	blelr-
00:	lwbrx	r5,0,r3
	eieio
	stwu	r5,4(r4)
	bdnz	00b
	twi	0,r5,0
	isync
	blr

_GLOBAL(_outsl)
	cmpwi	0,r5,0
	mtctr	r5
	subi	r4,r4,4
	blelr-
	sync
00:	lwzu	r5,4(r4)
	stwbrx	r5,0,r3
	bdnz	00b
	sync
	blr

#ifdef CONFIG_PPC32
_GLOBAL(__ide_mm_insw)
#endif
_GLOBAL(_insw_ns)
	sync
	cmpwi	0,r5,0
	mtctr	r5
	subi	r4,r4,2
	blelr-
00:	lhz	r5,0(r3)
	eieio
	sthu	r5,2(r4)
	bdnz	00b
	twi	0,r5,0
	isync
	blr

#ifdef CONFIG_PPC32
_GLOBAL(__ide_mm_outsw)
#endif
_GLOBAL(_outsw_ns)
	cmpwi	0,r5,0
	mtctr	r5
	subi	r4,r4,2
	blelr-
	sync
00:	lhzu	r5,2(r4)
	sth	r5,0(r3)
	bdnz	00b
	sync
	blr

#ifdef CONFIG_PPC32
_GLOBAL(__ide_mm_insl)
#endif
_GLOBAL(_insl_ns)
	sync
	cmpwi	0,r5,0
	mtctr	r5
	subi	r4,r4,4
	blelr-
00:	lwz	r5,0(r3)
	eieio
	stwu	r5,4(r4)
	bdnz	00b
	twi	0,r5,0
	isync
	blr

#ifdef CONFIG_PPC32
_GLOBAL(__ide_mm_outsl)
#endif
_GLOBAL(_outsl_ns)
	cmpwi	0,r5,0
	mtctr	r5
	subi	r4,r4,4
	blelr-
	sync
00:	lwzu	r5,4(r4)
	stw	r5,0(r3)
	bdnz	00b
	sync
	blr

_GLOBAL(setjmp)
	mflr    r0
	PPC_STL r0,0(r3)
	PPC_STL r1,SZL(r3)
	PPC_STL r2,2*SZL(r3)
	mfcr    r0
	PPC_STL r0,3*SZL(r3)
	PPC_STL r13,4*SZL(r3)
	PPC_STL r14,5*SZL(r3)
	PPC_STL r15,6*SZL(r3)
	PPC_STL r16,7*SZL(r3)
	PPC_STL r17,8*SZL(r3)
	PPC_STL r18,9*SZL(r3)
	PPC_STL r19,10*SZL(r3)
	PPC_STL r20,11*SZL(r3)
	PPC_STL r21,12*SZL(r3)
	PPC_STL r22,13*SZL(r3)
	PPC_STL r23,14*SZL(r3)
	PPC_STL r24,15*SZL(r3)
	PPC_STL r25,16*SZL(r3)
	PPC_STL r26,17*SZL(r3)
	PPC_STL r26,17*SZL(r3)
	PPC_STL r27,18*SZL(r3)
	PPC_STL r28,19*SZL(r3)
	PPC_STL r29,20*SZL(r3)
	PPC_STL r30,21*SZL(r3)
	PPC_STL r31,22*SZL(r3)
	li      r3,0
	blr

_GLOBAL(longjmp)
	PPC_LCMPI r4,0
	bne     1f
	li      r4,1
1:      PPC_LL  r13,4*SZL(r3)
	PPC_LL  r14,5*SZL(r3)
	PPC_LL  r15,6*SZL(r3)
	PPC_LL  r16,7*SZL(r3)
	PPC_LL  r17,8*SZL(r3)
	PPC_LL  r18,9*SZL(r3)
	PPC_LL  r19,10*SZL(r3)
	PPC_LL  r20,11*SZL(r3)
	PPC_LL  r21,12*SZL(r3)
	PPC_LL  r22,13*SZL(r3)
	PPC_LL  r23,14*SZL(r3)
	PPC_LL  r24,15*SZL(r3)
	PPC_LL  r25,16*SZL(r3)
	PPC_LL  r26,17*SZL(r3)
	PPC_LL  r27,18*SZL(r3)
	PPC_LL  r28,19*SZL(r3)
	PPC_LL  r29,20*SZL(r3)
	PPC_LL  r30,21*SZL(r3)
	PPC_LL  r31,22*SZL(r3)
	PPC_LL  r0,3*SZL(r3)
	mtcrf   0x38,r0
	PPC_LL  r0,0(r3)
	PPC_LL  r1,SZL(r3)
	PPC_LL  r2,2*SZL(r3)
	mtlr    r0
	mr      r3,r4
	blr

