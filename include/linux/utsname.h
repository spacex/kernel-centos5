#ifndef _LINUX_UTSNAME_H
#define _LINUX_UTSNAME_H

#define __OLD_UTS_LEN 8

struct oldold_utsname {
	char sysname[9];
	char nodename[9];
	char release[9];
	char version[9];
	char machine[9];
};

#define __NEW_UTS_LEN 64

struct old_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
};

struct new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

#ifdef __KERNEL__

#include <linux/kref.h>

struct uts_namespace {
	struct kref kref;
	struct new_utsname name;
};

extern struct new_utsname system_utsname;
extern struct uts_namespace init_uts_ns;

extern struct rw_semaphore uts_sem;

static inline struct new_utsname *init_utsname(void)
{
	return &system_utsname;
}

#endif /* __KERNEL__ */

#endif
