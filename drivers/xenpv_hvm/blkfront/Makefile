include $(src)/../overrides.mk

obj-$(CONFIG_XEN_BLKDEV_FRONTEND) := xen-vbd.o

EXTRA_CFLAGS += -I$(src)/../platform-pci

xen-vbd-objs := ../../xen/blkfront/blkfront.o
xen-vbd-objs += ../../xen/blkfront/vbd.o

