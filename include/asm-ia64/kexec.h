#ifndef _ASM_IA64_KEXEC_H
#define _ASM_IA64_KEXEC_H


/* Maximum physical address we can use pages from */
#define KEXEC_SOURCE_MEMORY_LIMIT (-1UL)
/* Maximum address we can reach in physical address mode */
#define KEXEC_DESTINATION_MEMORY_LIMIT (-1UL)
/* Maximum address we can use for the control code buffer */
#define KEXEC_CONTROL_MEMORY_LIMIT TASK_SIZE

#define KEXEC_CONTROL_CODE_SIZE (8192 + 8192 + 4096)

/* The native architecture */
#define KEXEC_ARCH KEXEC_ARCH_IA_64

#define MAX_NOTE_BYTES 1024

#define pte_bits	3
#define vmlpt_bits	(impl_va_bits - PAGE_SHIFT + pte_bits)
#define POW2(n)		(1ULL << (n))

#define kexec_flush_icache_page(page) do { \
		unsigned long page_addr = (unsigned long)page_address(page); \
		flush_icache_range(page_addr, page_addr + PAGE_SIZE); \
	} while(0)

extern struct kimage *ia64_kimage;
DECLARE_PER_CPU(u64, ia64_mca_pal_base);
const extern unsigned int relocate_new_kernel_size;
volatile extern long kexec_rendez;
extern void relocate_new_kernel(unsigned long, unsigned long,
		struct ia64_boot_param *, unsigned long);
extern void kexec_fake_sal_rendez(void *start, unsigned long wake_up,
		unsigned long pal_base);
static inline void
crash_setup_regs(struct pt_regs *newregs, struct pt_regs *oldregs)
{
}
extern struct resource efi_memmap_res;
extern struct resource boot_param_res;
extern void kdump_smp_send_stop(void);
extern void kdump_smp_send_init(void);
extern void kexec_disable_iosapic(void);
extern void crash_save_this_cpu(void);
struct rsvd_region;
extern unsigned long kdump_find_rsvd_region(unsigned long size,
		struct rsvd_region *rsvd_regions, int n);
extern void kdump_cpu_freeze(struct unw_frame_info *info, void *arg);
extern int kdump_status[];
extern atomic_t kdump_cpu_freezed;
extern int kdump_kernel;

#endif /* _ASM_IA64_KEXEC_H */
