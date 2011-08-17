#ifndef _ASM_GENERIC_BUG_H
#define _ASM_GENERIC_BUG_H

#include <linux/compiler.h>

#ifndef __ASSEMBLY__
extern const char *print_tainted(void);
#endif

#ifdef CONFIG_BUG
#ifndef HAVE_ARCH_BUG
#define BUG() do { \
	printk("BUG: failure at %s:%d/%s()! (%s)\n", __FILE__, __LINE__, __FUNCTION__, print_tainted()); \
	panic("BUG!"); \
} while (0)
#endif

#ifndef HAVE_ARCH_BUG_ON
#define BUG_ON(condition) do { if (unlikely((condition)!=0)) BUG(); } while(0)
#endif

#ifndef __WARN
#define __WARN() do {							\
	printk("WARNING: at %s:%d %s()\n", __FILE__,			\
		__LINE__, __FUNCTION__);				\
	dump_stack();							\
} while (0)
#endif
#define __WARN_printf(arg...) do { printk(arg); __WARN(); } while (0)

#ifndef WARN_ON
#define WARN_ON(condition) ({ \
	int __ret_warn_on = !!(condition); \
	if (unlikely(__ret_warn_on))                                    \
		__WARN();                                               \
	unlikely(__ret_warn_on); \
})
#endif

#ifndef WARN
#define WARN(condition, format...) ({					\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		__WARN_printf(format);					\
	unlikely(__ret_warn_on);					\
})
#endif

#else /* !CONFIG_BUG */
#ifndef HAVE_ARCH_BUG
#define BUG()
#endif

#ifndef HAVE_ARCH_BUG_ON
#define BUG_ON(condition) do { if (condition) ; } while(0)
#endif

#ifndef HAVE_ARCH_WARN_ON
#define WARN_ON(condition) ({ \
	int __ret_warn_on = !!(condition); \
	unlikely(__ret_warn_on); \
})
#endif

#ifndef WARN
#define WARN(condition, format...) ({                                  \
	int __ret_warn_on = !!(condition);                              \
	unlikely(__ret_warn_on);                                        \
})
#endif

#endif

#define WARN_ON_ONCE(condition)				\
({							\
	static int __warn_once = 1;			\
	int __ret = 0;					\
							\
	if (unlikely((condition) && __warn_once)) {	\
		__warn_once = 0;			\
		WARN_ON(1);				\
		__ret = 1;				\
	}						\
	__ret;						\
})

#define WARN_ONCE(condition, format...)        ({\
	static int __warned;				\
	int __ret_warn_once = !!(condition);		\
							\
	if (unlikely(__ret_warn_once))			\
		if (WARN(!__warned, format))		\
			__warned = 1;			\
	unlikely(__ret_warn_once);			\
})

#ifdef CONFIG_SMP
# define WARN_ON_SMP(x)			WARN_ON(x)
#else
# define WARN_ON_SMP(x)			do { } while (0)
#endif

#endif
