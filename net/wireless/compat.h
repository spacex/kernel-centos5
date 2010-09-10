#ifndef __WIRELESS_COMPAT_H_
#define __WIRELESS_COMPAT_H_

static inline const char *dev_name(const struct device *dev)
{
	return kobject_name(&dev->kobj);
}

#endif /* _WIRELESS_COMPAT_H_ *?
