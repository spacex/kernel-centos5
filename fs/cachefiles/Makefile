#
# Makefile for caching in a mounted filesystem
#

cachefiles-objs := \
	cf-bind.o \
	cf-interface.o \
	cf-key.o \
	cf-main.o \
	cf-namei.o \
	cf-proc.o \
	cf-xattr.o

ifeq ($(CONFIG_SYSCTL),y)
cachefiles-objs += cf-sysctl.o
endif

obj-$(CONFIG_CACHEFILES) := cachefiles.o
