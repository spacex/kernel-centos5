#ifndef _S390_TLBFLUSH_H
#define _S390_TLBFLUSH_H

#include <linux/mm.h>
#include <asm/processor.h>

/*
 * Flush all tlb entries on the local cpu.
 */
static inline void local_flush_tlb(void)
{
	asm volatile("ptlb" : : : "memory");
}

#ifdef CONFIG_SMP
/*
 * Flush all tlb entries on all cpus.
 */
void smp_ptlb_all(void);

static inline void global_flush_tlb(void)
{
	register unsigned long reg2 asm("2");
	register unsigned long reg3 asm("3");
	register unsigned long reg4 asm("4");
	long dummy;

#ifndef __s390x__
	if (!MACHINE_HAS_CSP) {
		smp_ptlb_all();
		return;
	}
#endif /* __s390x__ */

	dummy = 0;
	reg2 = reg3 = 0;
	reg4 = ((unsigned long) &dummy) + 1;
	asm volatile(
		"	csp	%0,%2"
		: : "d" (reg2), "d" (reg3), "d" (reg4), "m" (dummy) : "cc" );
}

static inline void __tlb_flush_full(struct mm_struct *mm)
{
	cpumask_t local_cpumask;

	preempt_disable();
	/*
	 * If the process only ran on the local cpu, do a local flush.
	 */
	local_cpumask = cpumask_of_cpu(smp_processor_id());
	if (cpus_equal(mm->cpu_vm_mask, local_cpumask))
		local_flush_tlb();
	else
		global_flush_tlb();
	preempt_enable();
}
#else
#define __tlb_flush_full(mm)	__tlb_flush_local()
#endif

/*
 * Flush all tlb entries of a page table on all cpus.
 */
static inline void __tlb_flush_idte(pgd_t *pgd)
{
	asm volatile(
		"	.insn	rrf,0xb98e0000,0,%0,%1,0"
		: : "a" (2048), "a" (__pa(pgd) & PAGE_MASK) : "cc" );
}

static inline void __tlb_flush_mm(struct mm_struct * mm)
{
	if (unlikely(cpus_empty(mm->cpu_vm_mask)))
		return;
	/*
	 * If the machine has IDTE we prefer to do a per mm flush
	 * on all cpus instead of doing a local flush if the mm
	 * only ran on the local cpu.
	 */
	if (MACHINE_HAS_IDTE) {
		__tlb_flush_idte(mm->pgd);
		return;
	}
	__tlb_flush_full(mm);
}

static inline void __tlb_flush_mm_cond(struct mm_struct * mm)
{
	__mm_context_t *mmc = (__mm_context_t *) &mm->context;

	spin_lock(&mm->page_table_lock);
	if (mmc->flush_mm) {
		__tlb_flush_mm(mm);
		mmc->flush_mm = 0;
	}
	spin_unlock(&mm->page_table_lock);
}

static inline void flush_tlb_pgtables(struct mm_struct *mm,
                                      unsigned long start, unsigned long end)
{
        /* S/390 does not keep any page table caches in TLB */
}

/*
 * TLB flushing:
 *  flush_tlb() - flushes the current mm struct TLBs
 *  flush_tlb_all() - flushes all processes TLBs
 *  flush_tlb_mm(mm) - flushes the specified mm context TLB's
 *  flush_tlb_page(vma, vmaddr) - flushes one page
 *  flush_tlb_range(vma, start, end) - flushes a range of pages
 *  flush_tlb_kernel_range(start, end) - flushes a range of kernel pages
 *  flush_tlb_pgtables(mm, start, end) flushes a range of page tables
 */

/*
 * flush_tlb_mm goes together with ptep_set_wrprotect for the
 * copy_page_range operation and flush_tlb_range is related to
 * ptep_get_and_clear for change_protection. ptep_set_wrprotect and
 * ptep_get_and_clear do not flush the TLBs directly if the mm has
 * only one user. At the end of the update the flush_tlb_mm and
 * flush_tlb_range functions need to do the flush.
 */
#define flush_tlb()				do { } while (0)
#define flush_tlb_all()				do { } while (0)
#define flush_tlb_page(vma, addr)		do { } while (0)

static inline void flush_tlb_mm(struct mm_struct *mm)
{
	__tlb_flush_mm_cond(mm);
}

static inline void flush_tlb_range(struct vm_area_struct *vma,
				   unsigned long start, unsigned long end)
{
	__tlb_flush_mm_cond(vma->vm_mm);
}

static inline void flush_tlb_kernel_range(unsigned long start,
					  unsigned long end)
{
	__tlb_flush_mm(&init_mm);
}

#endif /* _S390_TLBFLUSH_H */
