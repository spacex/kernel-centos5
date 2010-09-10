#include <linux/module.h>
#include <linux/device.h>

int dev_set_name(struct device *dev, const char *fmt, ...)
{
	va_list vargs;
	int err, buflen;
	char buf[32];

	va_start(vargs, fmt);
	buflen = vsprintf(buf, fmt, vargs);
	BUG_ON(buflen > sizeof(buf) - 1);
	va_end(vargs);
	err = kobject_set_name(&dev->kobj, buf);
	return err;
}
EXPORT_SYMBOL_GPL(dev_set_name);

MODULE_AUTHOR("John W. Linville <linville@redhat.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("compatibility code for wireless components");
