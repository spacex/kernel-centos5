#ifndef __MYRI10GE_COMPAT_H__
#define __MYRI10GE_COMPAT_H__

/* RHEL5 compat */
typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;

static inline __wsum csum_unfold(__sum16 n)
{
	return (__force __wsum)n;
}

#endif /*  __MYRI10GE_COMPAT_H__ */

