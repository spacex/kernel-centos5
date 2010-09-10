# Hack: we need to use the config which was used to build the kernel,
# except that that won't have the right headers etc., so duplicate
# some of the mach-xen infrastructure in here.
#
# (i.e. we need the native config for things like -mregparm, but
# a Xen kernel to find the right headers)
# EXTRA_CFLAGS += -D__XEN_INTERFACE_VERSION__=0x00030205
EXTRA_CFLAGS += -D__XEN_INTERFACE_VERSION__=0x00030203
EXTRA_CFLAGS += -DCONFIG_XEN_COMPAT=0xffffff -Iinclude$(if $(KBUILD_SRC),2)/asm/mach-xen 
# EXTRA_CFLAGS += -I$(M)/include -I$(M)/compat-include -DHAVE_XEN_PLATFORM_COMPAT_H
#
# ddd: removed next line & moved compat-include in front of kernel includes
#
# EXTRA_CFLAGS += -I$(src)/compat-include -DHAVE_XEN_PLATFORM_COMPAT_H
ifeq ($(ARCH),ia64)
  EXTRA_CFLAGS += -DCONFIG_VMX_GUEST
endif

#CPPFLAGS := -Iinclude$(if $(KBUILD_SRC),2)/asm/mach-xen $(CPPFLAGS)
CPPFLAGS := -I$(srctree)/drivers/xenpv_hvm/compat-include $(CPPFLAGS)
EXTRA_CFLAGS += -DHAVE_XEN_PLATFORM_COMPAT_H

# EXTRA_CFLAGS += -include $(srctree)/include/linux/autoconf.h
