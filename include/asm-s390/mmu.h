#ifndef __MMU_H
#define __MMU_H

/* Default "unsigned long" context */
typedef unsigned long mm_context_t;

/* KABI workaround mmu_context_t */
typedef struct {
	atomic_t attach_count;
	unsigned int flush_mm;
} __mm_context_t;

#endif
