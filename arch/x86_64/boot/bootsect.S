/*
 *	bootsect.S		Copyright (C) 1991, 1992 Linus Torvalds
 *
 *	modified by Drew Eckhardt
 *	modified by Bruce Evans (bde)
 *	modified by Chris Noe (May 1999) (as86 -> gas)
 *	gutted by H. Peter Anvin (Jan 2003)
 *
 * BIG FAT NOTE: We're in real mode using 64k segments.  Therefore segment
 * addresses must be multiplied by 16 to obtain their respective linear
 * addresses. To avoid confusion, linear addresses are written using leading
 * hex while segment addresses are written as segment:offset.
 *
 */

#include <linux/version.h>
#include <linux/utsrelease.h>
#include <linux/compile.h>
#include <linux/elf.h>
#include <linux/elf-em.h>
#include <linux/elf_boot.h>
#include <asm/page.h>
#include <asm/boot.h>

SETUPSECTS	= 4			/* default nr of setup-sectors */
BOOTSEG		= 0x07C0		/* original address of boot-sector */
INITSEG		= DEF_INITSEG		/* we move boot here - out of the way */
SETUPSEG	= DEF_SETUPSEG		/* setup starts here */
SYSSEG		= DEF_SYSSEG		/* system loaded at 0x10000 (65536) */
SYSSIZE		= DEF_SYSSIZE		/* system size: # of 16-byte clicks */
					/* to be loaded */
ROOT_DEV	= 0 			/* ROOT_DEV is now written by "build" */
SWAP_DEV	= 0			/* SWAP_DEV is now written by "build" */

#ifndef SVGA_MODE
#define SVGA_MODE ASK_VGA
#endif

#ifndef RAMDISK
#define RAMDISK 0
#endif

#ifndef ROOT_RDONLY
#define ROOT_RDONLY 1
#endif

.code16
.text

.global _start
_start:
ehdr:
	# e_ident is carefully crafted so if this is treated
	# as an x86 bootsector you will execute through
	# e_ident and then print the bugger off message.
	# The 1 store to bx+di is unfortunate it is
	# unlikely to affect the ability to print
	# a message and you aren't supposed to be booting a
	# bzImage directly from a floppy anyway.

	# e_ident
	.byte ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3
	.byte ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_STANDALONE
	.byte 0xeb, 0x3d, 0, 0, 0, 0, 0, 0
	.word ET_DYN				# e_type
	.word EM_X86_64				# e_machine
	.int  1					# e_version
	.quad 0x0000000000000100		# e_entry (startup_64)
	.quad phdr - _start			# e_phoff
	.quad 0					# e_shoff
	.int  0					# e_flags
	.word e_ehdr - ehdr			# e_ehsize
	.word e_phdr1 - phdr			# e_phentsize
	.word (e_phdr - phdr)/(e_phdr1 - phdr)	# e_phnum
	.word 64				# e_shentsize
	.word 0					# e_shnum
	.word 0					# e_shstrndx
e_ehdr:

.org 71
normalize:
	# Normalize the start address
	jmpl	$BOOTSEG, $start2

.org 80
phdr:
	.int PT_LOAD					# p_type
	.int PF_R | PF_W | PF_X				# p_flags
	.quad (SETUPSECTS+1)*512			# p_offset
	.quad __START_KERNEL_map			# p_vaddr
	.quad 0x0000000000000000			# p_paddr
	.quad SYSSIZE*16				# p_filesz
	.quad 0						# p_memsz
	.quad 2*1024*1024				# p_align
e_phdr1:

	.int PT_NOTE					# p_type
	.int 0						# p_flags
	.quad b_note - _start				# p_offset
	.quad 0						# p_vaddr
	.quad 0						# p_paddr
	.quad e_note - b_note				# p_filesz
	.quad 0						# p_memsz
	.quad 0						# p_align
e_phdr:

.macro note name, type
	.balign 4
	.int	2f - 1f			# n_namesz
	.int	4f - 3f			# n_descsz
	.int	\type			# n_type
	.balign 4
1:	.asciz "\name"
2:	.balign 4
3:
.endm
.macro enote
4:	.balign 4
.endm

	.balign 4
b_note:
	note ELF_NOTE_BOOT, EIN_PROGRAM_NAME
		.asciz	"Linux"
	enote
	note ELF_NOTE_BOOT, EIN_PROGRAM_VERSION
		.asciz	UTS_RELEASE
	enote
	note ELF_NOTE_BOOT, EIN_ARGUMENT_STYLE
		.asciz	"Linux"
	enote
e_note:

start2:
	movw	%cs, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss
	movw	$0x7c00, %sp
	sti
	cld

	movw	$bugger_off_msg, %si

msg_loop:
	lodsb
	andb	%al, %al
	jz	die
	movb	$0xe, %ah
	movw	$7, %bx
	int	$0x10
	jmp	msg_loop

die:
	# Allow the user to press a key, then reboot
	xorw	%ax, %ax
	int	$0x16
	int	$0x19

	# int 0x19 should never return.  In case it does anyway,
	# invoke the BIOS reset code...
	ljmp	$0xf000,$0xfff0


bugger_off_msg:
	.ascii	"Booting linux without a boot loader is no longer supported.\r\n"
	.ascii	"\n"
	.ascii	"Press any key to reboot . . .\r\n"
	.byte	0
ebugger_off_msg:


	# Kernel attributes; used by setup

	.org 497
setup_sects:	.byte SETUPSECTS
root_flags:	.word ROOT_RDONLY
syssize:	.word SYSSIZE
swap_dev:	.word SWAP_DEV
ram_size:	.word RAMDISK
vid_mode:	.word SVGA_MODE
root_dev:	.word ROOT_DEV
boot_flag:	.word 0xAA55
