include $(src)/../overrides.mk

EXTRA_CFLAGS += -I$(src)/../platform-pci

obj-y += xenpvhvm-parse-ide.o

obj-m += xen-platform-pci.o

xen-platform-pci-objs := evtchn.o platform-compat.o platform-pci.o xen_support.o
xen-platform-pci-objs += ../../xen/core/gnttab.o
xen-platform-pci-objs += ../../xen/core/features.o 
xen-platform-pci-objs += ../../xen/core/reboot.o 
xen-platform-pci-objs += machine_reboot.o
xen-platform-pci-objs += panic-handler.o

xen-platform-pci-objs += ../../xen/xenbus/xenbus_comms.o
xen-platform-pci-objs += ../../xen/xenbus/xenbus_xs.o
xen-platform-pci-objs += ../../xen/xenbus/xenbus_probe.o 
xen-platform-pci-objs += ../../xen/xenbus/xenbus_client.o 

# Can we do better ?
ifeq ($(ARCH),ia64)
  xen-platform-pci-objs += ../../../arch/ia64/xen/xcom_mini.o 
  xen-platform-pci-objs += ../../../arch/ia64/xen/xencomm.o
endif
