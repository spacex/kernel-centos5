/*
 *  Copyright (C) 2006 Giridhar Pemmasani
 *  Copyright (C) 2007-2010 Intel Corp
 *  	Contributed by Chandramouli Narayanan<mouli@linux.intel.com>
 *	Adapted NDIS wrapper macros from http://ndiswrapper.sourceforge.net
 *	for EFI x86_64 linux support
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/spinlock.h>
#include <linux/bootmem.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/efi.h>

#define alloc_win_stack_frame(argc)		\
	"subq $" #argc "*8, %%rsp\n\t"
#define free_win_stack_frame(argc)		\
	"addq $" #argc "*8, %%rsp\n\t"

/* m is index of Windows arg required, n is total number of args to
 * function Windows arg 1 should be at 0(%rsp), arg 2 at 8(%rsp) and
 * so on, after stack frame is allocated, which starts at -n*8(%rsp)
 * when stack frame is allocated. 4 > m >= n.
*/

#define lin2win_win_arg(m,n) "(" #m "-1-" #n ")*8(%%rsp)"

/* volatile args for Windows function must be in clobber / output list */

efi_status_t LIN2WIN0(void *func)
{									
	u64 ret, dummy;
	register u64 r8 __asm__("r8");
	register u64 r9 __asm__("r9");
	register u64 r10 __asm__("r10");
	register u64 r11 __asm__("r11");
	__asm__ __volatile__(					
		alloc_win_stack_frame(4)				
		"call *%[fptr]\n\t"					
		free_win_stack_frame(4)					
		: "=a" (ret), "=c" (dummy), "=d" (dummy),		
		  "=r" (r8), "=r" (r9), "=r" (r10), "=r" (r11)		
		: [fptr] "r" (func));					
	return ret;								
}

efi_status_t LIN2WIN1(void *func, u64 arg1)
{
	u64 ret, dummy;
	register u64 r8 __asm__("r8");
	register u64 r9 __asm__("r9");
	register u64 r10 __asm__("r10");
	register u64 r11 __asm__("r11");
	__asm__ __volatile__(
		alloc_win_stack_frame(4)
		"call *%[fptr]\n\t"
		free_win_stack_frame(4)	
		: "=a" (ret), "=c" (dummy), "=d" (dummy),
		  "=r" (r8), "=r" (r9), "=r" (r10), "=r" (r11)
		: "c" (arg1),
		  [fptr] "r" (func));
	return ret;
}

efi_status_t LIN2WIN2(void *func, u64 arg1, u64 arg2)
{
	u64 ret, dummy;
	register u64 r8 __asm__("r8");
	register u64 r9 __asm__("r9");
	register u64 r10 __asm__("r10");
	register u64 r11 __asm__("r11");
	__asm__ __volatile__(
		alloc_win_stack_frame(4)
		"call *%[fptr]\n\t"
		free_win_stack_frame(4)
		: "=a" (ret), "=c" (dummy), "=d" (dummy),
		  "=r" (r8), "=r" (r9), "=r" (r10), "=r" (r11)
		: "c" (arg1), "d" (arg2),
		  [fptr] "r" (func));
	return ret;
}

efi_status_t LIN2WIN3(
	void *func,
	u64 arg1,
	u64 arg2,
	u64 arg3)
{
	u64 ret, dummy;
	register u64 r8 __asm__("r8") = (u64)arg3;
	register u64 r9 __asm__("r9");
	register u64 r10 __asm__("r10");
	register u64 r11 __asm__("r11");
	__asm__ __volatile__(
		alloc_win_stack_frame(4)
		"call *%[fptr]\n\t"
		free_win_stack_frame(4)
		: "=a" (ret), "=c" (dummy), "=d" (dummy),
		  "=r" (r8), "=r" (r9), "=r" (r10), "=r" (r11)
		: "c" (arg1), "d" (arg2), "r" (r8),
		  [fptr] "r" (func));
	return ret;
}

efi_status_t LIN2WIN4(
	void *func,
	u64 arg1,
	u64 arg2,
	u64 arg3,
	u64 arg4)
{
	u64 ret, dummy;
	register u64 r8 __asm__("r8") = (u64)arg3;
	register u64 r9 __asm__("r9") = (u64)arg4;
	register u64 r10 __asm__("r10");
	register u64 r11 __asm__("r11");
	__asm__ __volatile__(
		alloc_win_stack_frame(4)
		"call *%[fptr]\n\t"
		free_win_stack_frame(4)
		: "=a" (ret), "=c" (dummy), "=d" (dummy),
		  "=r" (r8), "=r" (r9), "=r" (r10), "=r" (r11)
		: "c" (arg1), "d" (arg2), "r" (r8), "r" (r9),
		  [fptr] "r" (func));
	return ret;
}

efi_status_t LIN2WIN5(
	void *func,
	u64 arg1,
	u64 arg2,
	u64 arg3,
	u64 arg4,
	u64 arg5)
{
	u64 ret, dummy;
	register u64 r8 __asm__("r8") = (u64)arg3;
	register u64 r9 __asm__("r9") = (u64)arg4;
	register u64 r10 __asm__("r10");
	register u64 r11 __asm__("r11");
	__asm__ __volatile__(
		"mov %[rarg5], " lin2win_win_arg(5,6) "\n\t"
		alloc_win_stack_frame(6)
		"call *%[fptr]\n\t"
		free_win_stack_frame(6)
		: "=a" (ret), "=c" (dummy), "=d" (dummy),
		  "=r" (r8), "=r" (r9), "=r" (r10), "=r" (r11)
		: "c" (arg1), "d" (arg2), "r" (r8), "r" (r9),
		  [rarg5] "r" ((unsigned long long)arg5),
		  [fptr] "r" (func));
	return ret;
}

efi_status_t LIN2WIN6(
	void *func,
	u64 arg1,
	u64 arg2,
	u64 arg3,
	u64 arg4,
	u64 arg5,
	u64 arg6)
{
	u64 ret, dummy;
	register u64 r8 __asm__("r8") = (u64)arg3;
	register u64 r9 __asm__("r9") = (u64)arg4;
	register u64 r10 __asm__("r10");
	register u64 r11 __asm__("r11");
	__asm__ __volatile__(
		"movq %[rarg5], " lin2win_win_arg(5,6) "\n\t"
		"movq %[rarg6], " lin2win_win_arg(6,6) "\n\t"
		alloc_win_stack_frame(6)
		"call *%[fptr]\n\t"
		free_win_stack_frame(6)
		: "=a" (ret), "=c" (dummy), "=d" (dummy),
		  "=r" (r8), "=r" (r9), "=r" (r10), "=r" (r11)
		: "c" (arg1), "d" (arg2), "r" (r8), "r" (r9),
		  [rarg5] "r" ((u64)arg5), [rarg6] "r" ((u64)arg6),
		  [fptr] "r" (func));
	return ret;
}
EXPORT_SYMBOL_GPL(LIN2WIN0);
EXPORT_SYMBOL_GPL(LIN2WIN1);
EXPORT_SYMBOL_GPL(LIN2WIN2);
EXPORT_SYMBOL_GPL(LIN2WIN3);
EXPORT_SYMBOL_GPL(LIN2WIN4);
EXPORT_SYMBOL_GPL(LIN2WIN5);
EXPORT_SYMBOL_GPL(LIN2WIN6);
