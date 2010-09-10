#ifndef ELF_BOOT_H
#define ELF_BOOT_H

/* Elf notes to help bootloaders identify what program they are booting.
 */

/* Standardized Elf image notes for booting... The name for all of these is ELFBoot */
#define ELF_NOTE_BOOT		"ELFBoot"

#define EIN_PROGRAM_NAME	0x00000001
/* The program in this ELF file */
#define EIN_PROGRAM_VERSION	0x00000002
/* The version of the program in this ELF file */
#define EIN_PROGRAM_CHECKSUM	0x00000003
/* ip style checksum of the memory image. */
#define EIN_ARGUMENT_STYLE	0x00000004
/* String identifying argument passing style */

#endif /* ELF_BOOT_H */
