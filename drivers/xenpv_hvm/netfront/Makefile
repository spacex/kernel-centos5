include $(src)/../overrides.mk

obj-$(CONFIG_XEN_NETDEV_FRONTEND) := xen-vnif.o

EXTRA_CFLAGS += -I$(src)/../platform-pci

xen-vnif-objs := ../../xen/netfront/netfront.o
