#
# Makefile for the Linux kernel EDAC drivers.
#
# Copyright 02 Jul 2003, Linux Networx (http://lnxi.com)
# This file may be distributed under the terms of the
# GNU General Public License.
#
# $Id: Makefile,v 1.4.2.3 2005/07/08 22:05:38 dsp_llnl Exp $

obj-$(CONFIG_EDAC_MM_EDAC)		+= edac_mc.o
obj-$(CONFIG_EDAC_MCE)			+= edac_mce.o
obj-$(CONFIG_EDAC_AMD76X)		+= amd76x_edac.o
obj-$(CONFIG_EDAC_E7XXX)		+= e7xxx_edac.o
obj-$(CONFIG_EDAC_E752X)		+= e752x_edac.o
obj-$(CONFIG_EDAC_I82875P)		+= i82875p_edac.o
obj-$(CONFIG_EDAC_I3000)		+= i3000_edac.o
obj-$(CONFIG_EDAC_I3200)                += i3200_edac.o
obj-$(CONFIG_EDAC_I5000)		+= i5000_edac.o
obj-$(CONFIG_EDAC_I5400)		+= i5400_edac.o
obj-$(CONFIG_EDAC_I7300)		+= i7300_edac.o
obj-$(CONFIG_EDAC_I7CORE)		+= i7core_edac.o
obj-$(CONFIG_EDAC_I82860)		+= i82860_edac.o
obj-$(CONFIG_EDAC_K8)			+= k8_edac.o

edac_mce_amd-objs			:= mce_amd.o
obj-$(CONFIG_EDAC_DECODE_MCE)		+= edac_mce_amd.o

amd64_edac_mod-y			:= amd64_edac.o
obj-$(CONFIG_EDAC_AMD64)                += amd64_edac_mod.o

obj-$(CONFIG_EDAC_R82600)		+= r82600_edac.o
obj-$(CONFIG_EDAC_CELL)			+= cell_edac.o

