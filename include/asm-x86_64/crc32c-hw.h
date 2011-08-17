/*
 * Using hardware provided CRC32 instruction to accelerate the CRC32 disposal.
 * CRC32C polynomial:0x1EDC6F41(BE)/0x82F63B78(LE)
 * CRC32 is a new instruction in Intel SSE4.2, the reference can be found at:
 * http://www.intel.com/products/processor/manuals/
 * Intel(R) 64 and IA-32 Architectures Software Developer's Manual
 * Volume 2A: Instruction Set Reference, A-M
 *
 * Copyright (C) 2008 Intel Corporation
 * Authors: Austin Zhang <austin_zhang@linux.intel.com>
 *          Kent Liu <kent.liu@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#ifndef __ASM_X86_CRC32C_HW_H
#define __ASM_X86_CRC32C_HW_H

#include <asm/cpufeature.h>
#include <asm/processor.h>

#define SCALE_F	sizeof(unsigned long)

#ifdef CONFIG_X86_64
#define REX_PRE "0x48, "
#else
#define REX_PRE
#endif

static u32 crc32c_intel_le_hw_byte(u32 crc, unsigned char const *data, size_t length)
{
	while (length--) {
		__asm__ __volatile__(
			".byte 0xf2, 0xf, 0x38, 0xf0, 0xf1"
			:"=S"(crc)
			:"0"(crc), "c"(*data)
		);
		data++;
	}

	return crc;
}

static u32 __attribute_pure__ crc32c_intel_le_hw(u32 crc, unsigned char const *p, size_t len)
{
	unsigned int iquotient = len / SCALE_F;
	unsigned int iremainder = len % SCALE_F;
	unsigned long *ptmp = (unsigned long *)p;

	while (iquotient--) {
		__asm__ __volatile__(
			".byte 0xf2, " REX_PRE "0xf, 0x38, 0xf1, 0xf1;"
			:"=S"(crc)
			:"0"(crc), "c"(*ptmp)
		);
		ptmp++;
	}

	if (iremainder)
		crc = crc32c_intel_le_hw_byte(crc, (unsigned char *)ptmp,
				 iremainder);

	return crc;
}

#endif /* __ASM_X86_CRC32C_HW_H */

