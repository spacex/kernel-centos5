obj-$(CONFIG_CFG80211) += cfg80211.o

cfg80211-y += core.o sysfs.o radiotap.o util.o reg.o scan.o nl80211.o
cfg80211-y += mlme.o ibss.o sme.o chan.o
cfg80211-$(CONFIG_CFG80211_DEBUGFS) += debugfs.o
cfg80211-$(CONFIG_WIRELESS_EXT) += wext-compat.o wext-sme.o
cfg80211-$(CONFIG_CFG80211_INTERNAL_REGDB) += regdb.o

ccflags-y += -D__CHECK_ENDIAN__

wireless_compat-y += compat.o
obj-$(CONFIG_WIRELESS_COMPAT) += wireless_compat.o

$(obj)/regdb.c: $(src)/db.txt $(src)/genregdb.awk
	@$(AWK) -f $(srctree)/$(src)/genregdb.awk < $< > $@

clean-files := regdb.c
