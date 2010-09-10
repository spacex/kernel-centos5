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
extern efi_status_t LIN2WIN0(void *fp);
extern efi_status_t LIN2WIN1(void *fp, u64 arg1);
extern efi_status_t LIN2WIN2(void *fp, u64 arg1, u64 arg2);
extern efi_status_t LIN2WIN3(void *fp, u64 arg1, u64 arg2, u64 arg3);
extern efi_status_t LIN2WIN4(void *fp, u64 arg1, u64 arg2, u64 arg3, u64 arg4);
extern efi_status_t LIN2WIN5(
	void *fp, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5);
extern efi_status_t LIN2WIN6(
	void *fp, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 arg6);
