/* module-verify.c: module verifier
 *
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/elf.h>
#include <linux/crypto.h>
#include <linux/crypto/ksign.h>
#include "module-verify.h"

#if 0
#define _debug(FMT, ...) printk(FMT, ##__VA_ARGS__)
#else
#define _debug(FMT, ...) do {} while (0)
#endif

static int module_verify_elf(struct module_verify_data *mvdata);

/*****************************************************************************/
/*
 * verify a module's integrity
 * - check the ELF is viable
 * - check the module's signature if it has one
 */
int module_verify(const Elf_Ehdr *hdr, size_t size)
{
	struct module_verify_data mvdata;
	int ret;

	memset(&mvdata, 0, sizeof(mvdata));
	mvdata.buffer	= hdr;
	mvdata.hdr	= hdr;
	mvdata.size	= size;

	ret = module_verify_elf(&mvdata);
	if (ret < 0) {
		if (ret == -ELIBBAD)
			printk("Module failed ELF checks\n");
		goto error;
	}

#ifdef CONFIG_MODULE_SIG
	ret = module_verify_signature(&mvdata);
#ifdef CONFIG_CRYPTO_FIPS
	if (fips_enabled && (ret < 0))
		panic("Module verification failed with error %d in FIPS mode\n",
			ret);
#endif
#endif

 error:
	kfree(mvdata.secsizes);
	kfree(mvdata.canonlist);
	return ret;

} /* end module_verify() */

/*****************************************************************************/
/*
 * verify the ELF structure of a module
 */
static int module_verify_elf(struct module_verify_data *mvdata)
{
	const Elf_Ehdr *hdr = mvdata->hdr;
	const Elf_Shdr *section, *section2, *secstop;
	const Elf_Rela *relas, *rela, *relastop;
	const Elf_Rel *rels, *rel, *relstop;
	const Elf_Sym *symbol, *symstop;
	size_t size, sssize, *secsize, tmp, tmp2;
	long last;
	int line;

	size = mvdata->size;
	mvdata->nsects = hdr->e_shnum;

#define elfcheck(X) \
do { if (unlikely(!(X))) { line = __LINE__; goto elfcheck_error; } } while(0)

#define seccheck(X) \
do { if (unlikely(!(X))) { line = __LINE__; goto seccheck_error; } } while(0)

#define symcheck(X) \
do { if (unlikely(!(X))) { line = __LINE__; goto symcheck_error; } } while(0)

#define relcheck(X) \
do { if (unlikely(!(X))) { line = __LINE__; goto relcheck_error; } } while(0)

#define relacheck(X) \
do { if (unlikely(!(X))) { line = __LINE__; goto relacheck_error; } } while(0)

	/* validate the ELF header */
	elfcheck(hdr->e_ehsize < size);
	elfcheck(hdr->e_entry == 0);
	elfcheck(hdr->e_phoff == 0);
	elfcheck(hdr->e_phnum == 0);

	elfcheck(hdr->e_shnum < SHN_LORESERVE);
	elfcheck(hdr->e_shoff < size);
	elfcheck(hdr->e_shoff >= hdr->e_ehsize);
	elfcheck((hdr->e_shoff & (sizeof(long) - 1)) == 0);
	elfcheck(hdr->e_shstrndx > 0);
	elfcheck(hdr->e_shstrndx < hdr->e_shnum);
	elfcheck(hdr->e_shentsize == sizeof(Elf_Shdr));

	tmp = (size_t) hdr->e_shentsize * (size_t) hdr->e_shnum;
	elfcheck(tmp <= size - hdr->e_shoff);

	/* allocate a table to hold in-file section sizes */
	mvdata->secsizes = kmalloc(hdr->e_shnum * sizeof(size_t), GFP_KERNEL);
	if (!mvdata->secsizes)
		return -ENOMEM;

	memset(mvdata->secsizes, 0, hdr->e_shnum * sizeof(size_t));

	/* validate the ELF section headers */
	mvdata->sections = mvdata->buffer + hdr->e_shoff;
	secstop = mvdata->sections + mvdata->nsects;

	sssize = mvdata->sections[hdr->e_shstrndx].sh_size;
	elfcheck(sssize > 0);

	section = mvdata->sections;
	seccheck(section->sh_type == SHT_NULL);
	seccheck(section->sh_size == 0);
	seccheck(section->sh_offset == 0);

	secsize = mvdata->secsizes + 1;
	for (section++; section < secstop; secsize++, section++) {
		seccheck(section->sh_name < sssize);
		seccheck(section->sh_link < hdr->e_shnum);

		if (section->sh_entsize > 0)
			seccheck(section->sh_size % section->sh_entsize == 0);

		seccheck(section->sh_offset >= hdr->e_ehsize);
		seccheck(section->sh_offset < size);

		/* determine the section's in-file size */
		tmp = size - section->sh_offset;
		if (section->sh_offset < hdr->e_shoff)
			tmp = hdr->e_shoff - section->sh_offset;

		for (section2 = mvdata->sections + 1; section2 < secstop; section2++) {
			if (section->sh_offset < section2->sh_offset) {
				tmp2 = section2->sh_offset - section->sh_offset;
				if (tmp2 < tmp)
					tmp = tmp2;
			}
		}
		*secsize = tmp;

		_debug("Section %ld: %zx bytes at %lx\n",
		       section - mvdata->sections,
		       *secsize,
		       section->sh_offset);

		/* perform section type specific checks */
		switch (section->sh_type) {
		case SHT_NOBITS:
			break;

		case SHT_REL:
			seccheck(section->sh_entsize == sizeof(Elf_Rel));
			goto more_rel_checks;

		case SHT_RELA:
			seccheck(section->sh_entsize == sizeof(Elf_Rela));
		more_rel_checks:
			seccheck(section->sh_info > 0);
			seccheck(section->sh_info < hdr->e_shnum);
			goto more_sec_checks;

		case SHT_SYMTAB:
			seccheck(section->sh_entsize == sizeof(Elf_Sym));
			goto more_sec_checks;

		default:
		more_sec_checks:
			/* most types of section must be contained entirely
			 * within the file */
			seccheck(section->sh_size <= *secsize);
			break;
		}
	}

	/* validate the ELF section names */
	section = &mvdata->sections[hdr->e_shstrndx];

	seccheck(section->sh_offset != hdr->e_shoff);

	mvdata->secstrings = mvdata->buffer + section->sh_offset;

	last = -1;
	for (section = mvdata->sections + 1; section < secstop; section++) {
		const char *secname;
		tmp = sssize - section->sh_name;
		secname = mvdata->secstrings + section->sh_name;
		seccheck(secname[0] != 0);
		if (section->sh_name > last)
			last = section->sh_name;
	}

	if (last > -1) {
		tmp = sssize - last;
		elfcheck(memchr(mvdata->secstrings + last, 0, tmp) != NULL);
	}

	/* look for various sections in the module */
	for (section = mvdata->sections + 1; section < secstop; section++) {
		switch (section->sh_type) {
		case SHT_SYMTAB:
			if (strcmp(mvdata->secstrings + section->sh_name,
				   ".symtab") == 0
			    ) {
				seccheck(mvdata->symbols == NULL);
				mvdata->symbols =
					mvdata->buffer + section->sh_offset;
				mvdata->nsyms =
					section->sh_size / sizeof(Elf_Sym);
				seccheck(section->sh_size > 0);
			}
			break;

		case SHT_STRTAB:
			if (strcmp(mvdata->secstrings + section->sh_name,
				   ".strtab") == 0
			    ) {
				seccheck(mvdata->strings == NULL);
				mvdata->strings =
					mvdata->buffer + section->sh_offset;
				sssize = mvdata->nstrings = section->sh_size;
				seccheck(section->sh_size > 0);
			}
			break;
		}
	}

	if (!mvdata->symbols) {
		printk("Couldn't locate module symbol table\n");
		goto format_error;
	}

	if (!mvdata->strings) {
		printk("Couldn't locate module strings table\n");
		goto format_error;
	}

	/* validate the symbol table */
	symstop = mvdata->symbols + mvdata->nsyms;

	symbol = mvdata->symbols;
	symcheck(ELF_ST_TYPE(symbol[0].st_info) == STT_NOTYPE);
	symcheck(symbol[0].st_shndx == SHN_UNDEF);
	symcheck(symbol[0].st_value == 0);
	symcheck(symbol[0].st_size == 0);

	last = -1;
	for (symbol++; symbol < symstop; symbol++) {
		symcheck(symbol->st_name < sssize);
		if (symbol->st_name > last)
			last = symbol->st_name;
		symcheck(symbol->st_shndx < mvdata->nsects ||
			 symbol->st_shndx >= SHN_LORESERVE);
	}

	if (last > -1) {
		tmp = sssize - last;
		elfcheck(memchr(mvdata->strings + last, 0, tmp) != NULL);
	}

	/* validate each relocation table as best we can */
	for (section = mvdata->sections + 1; section < secstop; section++) {
		section2 = mvdata->sections + section->sh_info;

		switch (section->sh_type) {
		case SHT_REL:
			rels = mvdata->buffer + section->sh_offset;
			relstop = mvdata->buffer + section->sh_offset + section->sh_size;

			for (rel = rels; rel < relstop; rel++) {
				relcheck(rel->r_offset < section2->sh_size);
				relcheck(ELF_R_SYM(rel->r_info) < mvdata->nsyms);
			}

			break;

		case SHT_RELA:
			relas = mvdata->buffer + section->sh_offset;
			relastop = mvdata->buffer + section->sh_offset + section->sh_size;

			for (rela = relas; rela < relastop; rela++) {
				relacheck(rela->r_offset < section2->sh_size);
				relacheck(ELF_R_SYM(rela->r_info) < mvdata->nsyms);
			}

			break;

		default:
			break;
		}
	}


	_debug("ELF okay\n");
	return 0;

 elfcheck_error:
	printk("Verify ELF error (assertion %d)\n", line);
	goto format_error;

 seccheck_error:
	printk("Verify ELF error [sec %ld] (assertion %d)\n",
	       (long)(section - mvdata->sections), line);
	goto format_error;

 symcheck_error:
	printk("Verify ELF error [sym %ld] (assertion %d)\n",
	       (long)(symbol - mvdata->symbols), line);
	goto format_error;

 relcheck_error:
	printk("Verify ELF error [sec %ld rel %ld] (assertion %d)\n",
	       (long)(section - mvdata->sections),
	       (long)(rel - rels), line);
	goto format_error;

 relacheck_error:
	printk("Verify ELF error [sec %ld rela %ld] (assertion %d)\n",
	       (long)(section - mvdata->sections),
	       (long)(rela - relas), line);
	goto format_error;

 format_error:
	return -ELIBBAD;

} /* end module_verify_elf() */
