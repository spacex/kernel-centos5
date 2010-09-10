	.text
	.p2align 4,,15
	/* rdi  destination, rsi source, rdx count */
	.globl	memcpy_cachebypass
	.type	memcpy_cachebypass, @function
memcpy_cachebypass:
	movq	%rdi, %rax
.L5:
	cmpq	$15, %rdx
	ja	.L34
.L3:
	cmpl	$8, %edx	/* rdx is 0..15 */
	jbe	.L9
.L6:
	testb	$8, %dxl	/* rdx is 3,5,6,7,9..15 */
	je	.L13
	movq	(%rsi), %rcx
	addq	$8, %rsi
	movq	%rcx, (%rdi)
	addq	$8, %rdi
.L13:
	testb	$4, %dxl
	je	.L15
	movl	(%rsi), %ecx
	addq	$4, %rsi
	movl	%ecx, (%rdi)
	addq	$4, %rdi
.L15:
	testb	$2, %dxl
	je	.L17
	movzwl	(%rsi), %ecx
	addq	$2, %rsi
	movw	%cx, (%rdi)
	addq	$2, %rdi
.L17:
	testb	$1, %dxl
	je	.L33
.L1:
	movzbl	(%rsi), %ecx
	movb	%cl, (%rdi)
.L33:
	ret
.L34:
	cmpq	$63, %rdx	/* rdx is > 15 */
	ja	.L64
	movl	$16, %ecx	/* rdx is 16..63 */
.L25:
	movq	8(%rsi), %r8
	movq	(%rsi), %r9
	addq	%rcx, %rsi
	movq	%r8, 8(%rdi)
	movq	%r9, (%rdi)
	addq	%rcx, %rdi
	subq	%rcx, %rdx
	cmpl	%edx, %ecx	/* is rdx >= 16? */
	jbe	.L25
	jmp	.L3		/* rdx is 0..15 */
	.p2align 4,,7
.L64:
	movl	$64, %ecx
.L42:
	prefetchnta	128(%rsi)
	movq	(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	subq	%rcx, %rdx
	movq	%r8, (%rdi)
	movq	32(%rsi), %r8
	movq	%r9, 8(%rdi)
	movq	40(%rsi), %r9
	movq	%r10, 16(%rdi)
	movq	48(%rsi), %r10
	movq	%r11, 24(%rdi)
	movq	56(%rsi), %r11
	addq	%rcx, %rsi
	movq	%r8, 32(%rdi)
	movq	%r9, 40(%rdi)
	movq	%r10, 48(%rdi)
	movq	%r11, 56(%rdi)
	addq	%rcx, %rdi
	cmpq	%rdx, %rcx	/* is rdx >= 64? */
	jbe	.L42
	sfence
	orl	%edx, %edx
	je	.L33
	jmp	.L5
.L9:
	jmp	*.L12(,%rdx,8)	/* rdx is 0..8 */
	.section	.rodata
	.align 8
	.align 4
.L12:
	.quad	.L33
	.quad	.L1
	.quad	.L2
	.quad	.L6
	.quad	.L4
	.quad	.L6
	.quad	.L6
	.quad	.L6
	.quad	.L8
	.text
.L2:
	movzwl	(%rsi), %ecx
	movw	%cx, (%rdi)
	ret
.L4:
	movl	(%rsi), %ecx
	movl	%ecx, (%rdi)
	ret
.L8:
	movq	(%rsi), %rcx
	movq	%rcx, (%rdi)
	ret
