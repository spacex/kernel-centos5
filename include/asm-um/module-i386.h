#ifndef __UM_MODULE_I386_H
#define __UM_MODULE_I386_H

/* UML is simple */
struct mod_arch_specific
{
};

#define Elf_Shdr Elf32_Shdr
#define Elf_Sym Elf32_Sym
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Rel Elf32_Rel
#define Elf_Rela Elf32_Rela
#define ELF_R_TYPE(X)	ELF32_R_TYPE(X)
#define ELF_R_SYM(X)	ELF32_R_SYM(X)

#endif
