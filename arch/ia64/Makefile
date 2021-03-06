#
# ia64/Makefile
#
# This file is included by the global makefile so that you can add your own
# architecture-specific flags and dependencies.
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 1998-2004 by David Mosberger-Tang <davidm@hpl.hp.com>
#

NM := $(CROSS_COMPILE)nm -B
READELF := $(CROSS_COMPILE)readelf

export AWK

CHECKFLAGS	+= -m64 -D__ia64=1 -D__ia64__=1 -D_LP64 -D__LP64__

OBJCOPYFLAGS	:= --strip-all
LDFLAGS_vmlinux	:= -static
LDFLAGS_MODULE	+= -T $(srctree)/arch/ia64/module.lds
AFLAGS_KERNEL	:= -mconstant-gp
EXTRA		:=

cflags-y	:= -pipe $(EXTRA) -ffixed-r13 -mfixed-range=f12-f15,f32-f127 \
		   -falign-functions=32 -frename-registers -fno-optimize-sibling-calls
CFLAGS_KERNEL	:= -mconstant-gp

CPPFLAGS += -DHAVE_WORKING_TEXT_ALIGN -DHAVE_MODEL_SMALL_ATTRIBUTE -DHAVE_SERIALIZE_DIRECTIVE

ifeq ($(call cc-version),0304)
	cflags-$(CONFIG_ITANIUM)	+= -mtune=merced
	cflags-$(CONFIG_MCKINLEY)	+= -mtune=mckinley
endif

CFLAGS += $(cflags-y)

cppflags-$(CONFIG_XEN) += \
	-D__XEN_INTERFACE_VERSION__=$(CONFIG_XEN_INTERFACE_VERSION)

CPPFLAGS += $(cppflags-y)

head-y := arch/ia64/kernel/head.o arch/ia64/kernel/init_task.o

libs-y				+= arch/ia64/lib/
core-y				+= arch/ia64/kernel/ arch/ia64/mm/
core-$(CONFIG_IA32_SUPPORT)	+= arch/ia64/ia32/
core-$(CONFIG_IA64_DIG) 	+= arch/ia64/dig/
core-$(CONFIG_IA64_GENERIC) 	+= arch/ia64/dig/
core-$(CONFIG_IA64_HP_ZX1)	+= arch/ia64/dig/
core-$(CONFIG_IA64_HP_ZX1_SWIOTLB) += arch/ia64/dig/
core-$(CONFIG_IA64_XEN)		+= arch/ia64/dig/
core-$(CONFIG_IA64_SGI_SN2)	+= arch/ia64/sn/
core-$(CONFIG_XEN)		+= arch/ia64/xen/

drivers-$(CONFIG_PCI)		+= arch/ia64/pci/
ifneq ($(CONFIG_XEN),y)
drivers-$(CONFIG_IA64_HP_SIM)	+= arch/ia64/hp/sim/
endif
ifneq ($(CONFIG_IA64_GENERIC),y)
drivers-$(CONFIG_XEN)		+= arch/ia64/hp/sim/
endif
drivers-$(CONFIG_IA64_HP_ZX1)	+= arch/ia64/hp/common/ arch/ia64/hp/zx1/
drivers-$(CONFIG_IA64_HP_ZX1_SWIOTLB) += arch/ia64/hp/common/ arch/ia64/hp/zx1/
drivers-$(CONFIG_IA64_GENERIC)	+= arch/ia64/hp/common/ arch/ia64/hp/zx1/ arch/ia64/hp/sim/ arch/ia64/sn/
drivers-$(CONFIG_OPROFILE)	+= arch/ia64/oprofile/

boot := arch/ia64/hp/sim/boot

PHONY += boot compressed check

all: compressed unwcheck

compressed: vmlinux.gz

vmlinuz: vmlinux.gz

vmlinux.gz: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $@

unwcheck: vmlinux
	-$(Q)READELF=$(READELF) $(srctree)/arch/ia64/scripts/unwcheck.py $<

archclean:
	$(Q)$(MAKE) $(clean)=$(boot)

CLEAN_FILES += vmlinux.gz bootloader

boot:	lib/lib.a vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $@

install:
	-yes | sh $(srctree)/arch/ia64/install.sh $(KERNELRELEASE) vmlinux.gz System.map "$(INSTALL_PATH)"

define archhelp
  echo '* compressed	- Build compressed kernel image'
  echo '  install	- Install compressed kernel image'
  echo '  boot		- Build vmlinux and bootloader for Ski simulator'
  echo '* unwcheck	- Check vmlinux for invalid unwind info'
endef
