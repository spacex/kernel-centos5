#
# Makefile for x86-compatible CPU details and quirks
#

obj-y	:=	common.o proc.o

obj-y	+=	amd.o
obj-y	+=	cyrix.o
obj-y	+=	centaur.o
obj-y	+=	transmeta.o
obj-y	+=	intel.o intel_cacheinfo.o addon_cpuid_features.o
obj-y	+=	rise.o
obj-y	+=	nexgen.o
obj-y	+=	umc.o

ifndef CONFIG_XEN
obj-y   +=      vmware.o hypervisor.o
endif

obj-$(CONFIG_X86_MCE)	+=	mcheck/

obj-$(CONFIG_MTRR)	+= 	mtrr/
obj-$(CONFIG_CPU_FREQ)	+=	cpufreq/

ifdef CONFIG_XEN
include $(srctree)/scripts/Makefile.xen
obj-y := $(call cherrypickxen, $(obj-y), $(src))
endif
