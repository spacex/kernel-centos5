/*
 *  include/asm-s390/mmu_context.h
 *
 *  S390 version
 *
 *  Derived from "include/asm-i386/mmu_context.h"
 */

#ifndef __S390_MMU_CONTEXT_H
#define __S390_MMU_CONTEXT_H

#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

static inline int init_new_context(struct task_struct *tsk,
				   struct mm_struct *mm)
{
	__mm_context_t *mmc = (__mm_context_t *) &mm->context;

	atomic_set(&mmc->attach_count, 0);
	mmc->flush_mm = 0;
	return 0;
}

#define destroy_context(mm)             do { } while (0)

static inline void enter_lazy_tlb(struct mm_struct *mm,
                                  struct task_struct *tsk)
{
}

static inline void switch_mm(struct mm_struct *prev, struct mm_struct *next,
                             struct task_struct *tsk)
{
	__mm_context_t *mmc;

        if (prev != next) {
#ifndef __s390x__
	        S390_lowcore.user_asce = (__pa(next->pgd)&PAGE_MASK) |
                      (_SEGMENT_TABLE|USER_STD_MASK);
                /* Load home space page table origin. */
                asm volatile("lctl  13,13,%0"
			     : : "m" (S390_lowcore.user_asce) );
#else /* __s390x__ */
                S390_lowcore.user_asce = (__pa(next->pgd) & PAGE_MASK) |
			(_REGION_TABLE|USER_STD_MASK);
		/* Load home space page table origin. */
		asm volatile("lctlg  13,13,%0"
			     : : "m" (S390_lowcore.user_asce) );
#endif /* __s390x__ */
        }
	cpu_set(smp_processor_id(), next->cpu_vm_mask);
	mmc = (__mm_context_t *) &prev->context;
	atomic_dec(&mmc->attach_count);
	WARN_ON(atomic_read(&mmc->attach_count) < 0);
	mmc = (__mm_context_t *) &next->context;
	atomic_inc(&mmc->attach_count);
	/* Check for TLBs not flushed yet */
	if (mmc->flush_mm)
		__tlb_flush_mm(next);
}

#define deactivate_mm(tsk,mm)	do { } while (0)

static inline void activate_mm(struct mm_struct *prev,
                               struct mm_struct *next)
{
        switch_mm(prev, next, current);
	set_fs(current->thread.mm_segment);
}

#endif
