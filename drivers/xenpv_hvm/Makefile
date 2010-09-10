# include $(src)/overrides.mk

obj-y += platform-pci/

ifneq ($(ARCH),ia64)
obj-y += balloon/
endif

obj-$(CONFIG_XEN_BLKDEV_FRONTEND) += blkfront/
obj-$(CONFIG_XEN_NETDEV_FRONTEND) += netfront/
