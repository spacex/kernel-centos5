/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef	__XFS_SUPPORT_DEBUG_H__
#define	__XFS_SUPPORT_DEBUG_H__

#include <stdarg.h>

#define CE_DEBUG        KERN_DEBUG
#define CE_CONT         KERN_INFO
#define CE_NOTE         KERN_NOTICE
#define CE_WARN         KERN_WARNING
#define CE_ALERT        KERN_ALERT
#define CE_PANIC        KERN_EMERG

#define cmn_err(lvl, fmt, args...)	\
	do { \
		printk(lvl fmt "\n", ## args); \
		BUG_ON(strncmp(lvl, KERN_EMERG, strlen(KERN_EMERG)) == 0); \
	} while (0)

#define xfs_fs_cmn_err(lvl, mp, fmt, args...)	\
	do { \
		printk(lvl "Filesystem %s: " fmt "\n", (mp)->m_fsname, ## args); \
		BUG_ON(strncmp(lvl, KERN_EMERG, strlen(KERN_EMERG)) == 0); \
	} while (0)

/* All callers to xfs_cmn_err use CE_ALERT, so don't bother testing lvl */
#define xfs_cmn_err(panic_tag, lvl, mp, fmt, args...)	\
	do { \
		printk(KERN_ALERT "Filesystem %s: " fmt "\n", (mp)->m_fsname, ## args); \
		if (xfs_panic_mask & panic_tag) { \
			printk(KERN_ALERT "XFS: Transforming an alert into a BUG."); \
			BUG(); \
		} \
	} while (0)

extern void assfail(char *expr, char *f, int l);

#define ASSERT_ALWAYS(expr)	\
	(unlikely(expr) ? (void)0 : assfail(#expr, __FILE__, __LINE__))

#ifndef DEBUG
#define ASSERT(expr)	((void)0)

#ifndef STATIC
# define STATIC static noinline
#endif

#ifndef STATIC_INLINE
# define STATIC_INLINE static inline
#endif

#else /* DEBUG */

#define ASSERT(expr)	\
	(unlikely(expr) ? (void)0 : assfail(#expr, __FILE__, __LINE__))

#ifndef STATIC
# define STATIC noinline
#endif

/*
 * We stop inlining of inline functions in debug mode.
 * Unfortunately, this means static inline in header files
 * get multiple definitions, so they need to remain static.
 * This then gives tonnes of warnings about unused but defined
 * functions, so we need to add the unused attribute to prevent
 * these spurious warnings.
 */
#ifndef STATIC_INLINE
# define STATIC_INLINE static __attribute__ ((unused)) noinline
#endif

#endif /* DEBUG */


#endif  /* __XFS_SUPPORT_DEBUG_H__ */
