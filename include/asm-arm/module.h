#ifndef _ASM_ARM_MODULE_H
#define _ASM_ARM_MODULE_H

struct mod_arch_specific
{
	int foo;
};

#define MODULES_ARE_ELF32
#define Elf_Shdr	Elf32_Shdr
#define Elf_Sym		Elf32_Sym
#define Elf_Ehdr	Elf32_Ehdr
#define Elf_Rel		Elf32_Rel
#define Elf_Rela	Elf32_Rela
#define ELF_R_TYPE(X)	ELF32_R_TYPE(X)
#define ELF_R_SYM(X)	ELF32_R_SYM(X)

/*
 * Include the ARM architecture version.
 */
#define MODULE_ARCH_VERMAGIC	"ARMv" __stringify(__LINUX_ARM_ARCH__) " "

#endif /* _ASM_ARM_MODULE_H */
