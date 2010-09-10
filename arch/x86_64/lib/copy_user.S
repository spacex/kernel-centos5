/* Copyright 2002 Andi Kleen, SuSE Labs.
 * Subject to the GNU Public License v2.
 * 
 * Functions to copy from and to user space.		
 */		 

#include <linux/linkage.h>
#include <asm/dwarf2.h>

#define FIX_ALIGNMENT 1

	#include <asm/current.h>
	#include <asm/asm-offsets.h>
	#include <asm/thread_info.h>
	#include <asm/cpufeature.h>

/* Standard copy_to_user with segment limit checking */		
ENTRY(copy_to_user)
	CFI_STARTPROC
	GET_THREAD_INFO(%rax)
	movq %rdi,%rcx
	addq %rdx,%rcx
	jc  bad_to_user
	cmpq threadinfo_addr_limit(%rax),%rcx
	jae bad_to_user
2:
	.byte 0xe9	/* 32bit jump */
	.long .Lcug-1f
1:
	CFI_ENDPROC
ENDPROC(copy_to_user)

	.section .altinstr_replacement,"ax"
3:	.byte 0xe9			/* replacement jmp with 32 bit immediate */
	.long copy_user_generic_c-1b	/* offset */
	.previous
	.section .altinstructions,"a"
	.align 8
	.quad  2b
	.quad  3b
	.byte  X86_FEATURE_REP_GOOD
	.byte  5
	.byte  5
	.previous

/* Standard copy_from_user with segment limit checking */	
ENTRY(copy_from_user)
	CFI_STARTPROC
	GET_THREAD_INFO(%rax)
	movq %rsi,%rcx
	addq %rdx,%rcx
	jc  bad_from_user
	cmpq threadinfo_addr_limit(%rax),%rcx
	jae  bad_from_user
	/* FALL THROUGH to copy_user_generic */
	CFI_ENDPROC
ENDPROC(copy_from_user)
	
	.section .fixup,"ax"
	/* must zero dest */
bad_from_user:
	CFI_STARTPROC
	movl %edx,%ecx
	xorl %eax,%eax
	rep
	stosb
bad_to_user:
	movl	%edx,%eax
	ret
	CFI_ENDPROC
END(bad_from_user)
	.previous
	
		
/*
 * copy_user_generic - memory copy with exception handling.
 * 	
 * Input:	
 * rdi destination
 * rsi source
 * rdx count
 *
 * Output:		
 * eax uncopied bytes or 0 if successful.
 */
ENTRY(copy_user_generic)
	CFI_STARTPROC
	.byte 0x66,0x66,0x90	/* 5 byte nop for replacement jump */
	.byte 0x66,0x90
1:
	.section .altinstr_replacement,"ax"
2:	.byte 0xe9	             /* near jump with 32bit immediate */
	.long copy_user_generic_c-1b /* offset */
	.previous
	.section .altinstructions,"a"
	.align 8
	.quad  copy_user_generic
	.quad  2b
	.byte  X86_FEATURE_REP_GOOD
	.byte  5
	.byte  5
	.previous
.Lcug:
	pushq %rbx
	CFI_ADJUST_CFA_OFFSET 8
	CFI_REL_OFFSET rbx, 0
	xorl %eax,%eax		/*zero for the exception handler */

#ifdef FIX_ALIGNMENT
	/* check for bad alignment of destination */
	movl %edi,%ecx
	andl $7,%ecx
	jnz  .Lbad_alignment
.Lafter_bad_alignment:
#endif

	movq %rdx,%rcx

	movl $64,%ebx
	shrq $6,%rdx
	decq %rdx
	js   .Lhandle_tail

	.p2align 4
.Lloop:
.Ls1:	movq (%rsi),%r11
.Ls2:	movq 1*8(%rsi),%r8
.Ls3:	movq 2*8(%rsi),%r9
.Ls4:	movq 3*8(%rsi),%r10
.Ld1:	movq %r11,(%rdi)
.Ld2:	movq %r8,1*8(%rdi)
.Ld3:	movq %r9,2*8(%rdi)
.Ld4:	movq %r10,3*8(%rdi)

.Ls5:	movq 4*8(%rsi),%r11
.Ls6:	movq 5*8(%rsi),%r8
.Ls7:	movq 6*8(%rsi),%r9
.Ls8:	movq 7*8(%rsi),%r10
.Ld5:	movq %r11,4*8(%rdi)
.Ld6:	movq %r8,5*8(%rdi)
.Ld7:	movq %r9,6*8(%rdi)
.Ld8:	movq %r10,7*8(%rdi)

	decq %rdx

	leaq 64(%rsi),%rsi
	leaq 64(%rdi),%rdi

	jns  .Lloop

	.p2align 4
.Lhandle_tail:
	movl %ecx,%edx
	andl $63,%ecx
	shrl $3,%ecx
	jz   .Lhandle_7
	movl $8,%ebx
	.p2align 4
.Lloop_8:
.Ls9:	movq (%rsi),%r8
.Ld9:	movq %r8,(%rdi)
	decl %ecx
	leaq 8(%rdi),%rdi
	leaq 8(%rsi),%rsi
	jnz .Lloop_8

.Lhandle_7:
	movl %edx,%ecx
	andl $7,%ecx
	jz   .Lende
	.p2align 4
.Lloop_1:
.Ls10:	movb (%rsi),%bl
.Ld10:	movb %bl,(%rdi)
	incq %rdi
	incq %rsi
	decl %ecx
	jnz .Lloop_1

	CFI_REMEMBER_STATE
.Lende:
	popq %rbx
	CFI_ADJUST_CFA_OFFSET -8
	CFI_RESTORE rbx
	ret
	CFI_RESTORE_STATE

#ifdef FIX_ALIGNMENT
	/* align destination */
	.p2align 4
.Lbad_alignment:
	movl $8,%r9d
	subl %ecx,%r9d
	movl %r9d,%ecx
	cmpq %r9,%rdx
	jz   .Lhandle_7
	js   .Lhandle_7
.Lalign_1:
.Ls11:	movb (%rsi),%bl
.Ld11:	movb %bl,(%rdi)
	incq %rsi
	incq %rdi
	decl %ecx
	jnz .Lalign_1
	subq %r9,%rdx
	jmp .Lafter_bad_alignment
#endif

	/* table sorted by exception address */
	.section __ex_table,"a"
	.align 8
	.quad .Ls1,.Ls1e
	.quad .Ls2,.Ls2e
	.quad .Ls3,.Ls3e
	.quad .Ls4,.Ls4e
	.quad .Ld1,.Ld1e
	.quad .Ld2,.Ld2e
	.quad .Ld3,.Ld3e
	.quad .Ld4,.Ld4e
	.quad .Ls5,.Ls5e
	.quad .Ls6,.Ls6e
	.quad .Ls7,.Ls7e
	.quad .Ls8,.Ls8e
	.quad .Ld5,.Ld5e
	.quad .Ld6,.Ld6e
	.quad .Ld7,.Ld7e
	.quad .Ld8,.Ld8e
	.quad .Ls9,.Le_quad
	.quad .Ld9,.Le_quad
	.quad .Ls10,.Le_byte
	.quad .Ld10,.Le_byte
#ifdef FIX_ALIGNMENT
	.quad .Ls11,.Lzero_rest
	.quad .Ld11,.Lzero_rest
#endif
	.quad .Le5,.Le_zero
	.previous

	/* Don't forget to store registers, which were loaded before fault.
	   Otherwise we will have up to 24 bytes of garbage and possible
	   security leak */
.Ls8e:	addl $8,%eax
	movq %r9,6*8(%rdi)
.Ls7e:	addl $8,%eax
	movq %r8,5*8(%rdi)
.Ls6e:	addl $8,%eax
	movq %r11,4*8(%rdi)
.Ls5e:	addl $32,%eax
	jmp .Ls1e

.Ls4e:	addl $8,%eax
	movq %r9,2*8(%rdi)
.Ls3e:	addl $8,%eax
	movq %r8,1*8(%rdi)
.Ls2e:	addl $8,%eax
	movq %r11,(%rdi)
.Ls1e:	addq %rax,%rdi
	shlq $6,%rdx
	addq %rbx,%rdx
	subq %rax,%rdx
	andl $63,%ecx
	addq %rcx,%rdx
	jmp .Lzero_rest

	/* compute 64-offset for main loop. 8 bytes accuracy with error on the
	   pessimistic side. this is gross. it would be better to fix the
	   interface. */
	/* eax: zero, ebx: 64 */
.Ld1e: 	addl $8,%eax
.Ld2e: 	addl $8,%eax
.Ld3e: 	addl $8,%eax
.Ld4e: 	addl $8,%eax
.Ld5e: 	addl $8,%eax
.Ld6e: 	addl $8,%eax
.Ld7e: 	addl $8,%eax
.Ld8e: 	addl $8,%eax
	addq %rbx,%rdi	/* +64 */
	subq %rax,%rdi  /* correct destination with computed offset */

	shlq $6,%rdx	/* loop counter * 64 (stride length) */
	addq %rax,%rdx	/* add offset to loopcnt */
	andl $63,%ecx	/* remaining bytes */
	addq %rcx,%rdx	/* add them */
	jmp .Lzero_rest

	/* exception on quad word loop in tail handling */
	/* ecx:	loopcnt/8, %edx: length, rdi: correct */
.Le_quad:
	shll $3,%ecx
	andl $7,%edx
	addl %ecx,%edx
	/* edx: bytes to zero, rdi: dest, eax:zero */
.Lzero_rest:
	movq %rdx,%rcx
.Le_byte:
	xorl %eax,%eax
.Le5:	rep
	stosb
	/* when there is another exception while zeroing the rest just return */
.Le_zero:
	movq %rdx,%rax
	jmp .Lende
	CFI_ENDPROC
ENDPROC(copy_user_generic)


	/* Some CPUs run faster using the string copy instructions.
	   This is also a lot simpler. Use them when possible.
	   Patch in jmps to this code instead of copying it fully
	   to avoid unwanted aliasing in the exception tables. */

 /* rdi	destination
  * rsi source
  * rdx count
  *
  * Output:
  * eax uncopied bytes or 0 if successfull.
  *
  * Only 4GB of copy is supported. This shouldn't be a problem
  * because the kernel normally only writes from/to page sized chunks
  * even if user space passed a longer buffer.
  * And more would be dangerous because both Intel and AMD have
  * errata with rep movsq > 4GB. If someone feels the need to fix
  * this please consider this.
   */
copy_user_generic_c:
	CFI_STARTPROC
	xorq %rax,%rax
	movl %edx,%ecx
	shrl $3,%ecx
	andl $7,%edx
.Lc1:	rep 
	movsq 
	movl %edx,%ecx
.Lc2:	rep
	movsb
	ret

.Lc1e:	movq %rcx,%rsi
.Lc3:	rep
	stosq
.Lc2ec:	movl %edx,%ecx
.Lc4:	rep
	stosb
.Lc3e:	leaq (%rdx,%rsi,8),%rax
	ret
	/* %rsi contains source address - clear it */
.Lc2e:  xorq %rsi,%rsi
	jmp .Lc2ec
	CFI_ENDPROC
END(copy_user_generic_c)

	.section __ex_table,"a"
	.align 8
	.quad .Lc1,.Lc1e
	.quad .Lc2,.Lc2e
	.quad .Lc3,.Lc3e
	.quad .Lc4,.Lc3e
	.previous
