/*
 * Copyright (c) 2006, 2007 QLogic Corporation. All rights reserved.
 * Copyright (c) 2003, 2004, 2005, 2006 PathScale, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * __iowrite32_copy - copy a memory block using dword multiple writes
 *
 * This is primarily for writing to the InfiniPath PIO buffers, which
 * only support dword multiple writes, and thus can not use memcpy().
 * For this reason, we use nothing smaller than dword writes.
 * It is also used as a fast copy routine in some places that have been
 * measured to win over memcpy, and the performance delta matters.
 *
 * Count is number of dwords; might not be a qword multiple.
 */

 	.globl __iowrite32_copy
	.p2align 4
/* rdi	destination, rsi source, rdx count */
__iowrite32_copy:
	movl %edx,%ecx
	shrl $1,%ecx
	andl $1,%edx
	rep
	movsq
	movl %edx,%ecx
	rep
	movsd
	ret
