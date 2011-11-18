#ifndef _I386_BUG_H
#define _I386_BUG_H


/*
 * Tell the user there is some problem.
 * The offending file and line are encoded after the "officially
 * undefined" opcode for parsing in the trap handler.
 */

#ifdef CONFIG_BUG
#define HAVE_ARCH_BUG
#ifdef CONFIG_DEBUG_BUGVERBOSE
#define BUG()								\
do {									\
	__asm__ __volatile__("ud2\n"					\
			     "\t.word %c0\n"				\
			     "\t.long %c1\n"				\
			      : : "i" (__LINE__), "i" (__FILE__));	\
	unreachable();							\
} while (0)
#else
#define BUG()								\
do {									\
	__asm__ __volatile__("ud2\n");					\
	unreachable();							\
} while (0)
#endif
#endif

#include <asm-generic/bug.h>
#endif
