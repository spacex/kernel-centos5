#ifndef _XT_CONNLIMIT_H
#define _XT_CONNLIMIT_H

struct xt_connlimit_data;

struct xt_connlimit_info {
	unsigned int limit, inverse;
	u_int32_t mask;

	/* Used internally by the kernel */
	struct xt_connlimit_data *data __attribute__((aligned(8)));
};

#endif /* _XT_CONNLIMIT_H */
