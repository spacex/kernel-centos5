#ifndef __PPC_XMON_H
#define __PPC_XMON_H
#ifdef __KERNEL__

struct pt_regs;

extern int xmon(struct pt_regs *excp);
extern void xmon_printf(const char *fmt, ...);
#ifdef CONFIG_XMON
extern void xmon_setup(void);
#else
static inline void xmon_setup(void) { };
#endif

#endif
#endif
