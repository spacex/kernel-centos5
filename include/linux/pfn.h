#ifndef _LINUX_PFN_H_
#define _LINUX_PFN_H_

#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
#if defined(CONFIG_X86_XEN) && defined(CONFIG_X86_PAE)
#define PFN_PHYS(x)	((unsigned long long)(x) << PAGE_SHIFT)
#else
#define PFN_PHYS(x)	((x) << PAGE_SHIFT)
#endif

#endif
