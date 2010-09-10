# NOTE:  We use common code from base.c to build driver
# specific binaries based on the #define IWL -- the target
# setup below creates a specific driver target from base.c
#
# NOTE2: base-XXXX.o has -D"KBUILD_MODNAME=KBUILD_STR(...)" in order to 
# prevent the following kbuild error:
# 	include/linux/pci.h:603: error: `KBUILD_MODNAME' undeclared (first \
#		use in this function)
#
# -jpk

obj-$(CONFIG_IWL3945)	+= iwl3945.o
iwl3945-objs		= base-3945.o iwl-3945.o iwl-3945-rs.o
CFLAGS_iwl-3945.o	= -DIWL=3945
CFLAGS_iwl-3945-rs.o	= -DIWL=3945
CFLAGS_base-3945.o	= -DIWL=3945 -D"KBUILD_MODNAME=KBUILD_STR(iwl3945)"
$(obj)/base-3945.o: $(src)/base.c FORCE
	$(call cmd,force_checksrc)
	$(call if_changed_rule,cc_o_c)

obj-$(CONFIG_IWL4965)	+= iwl4965.o
iwl4965-objs		= base-4965.o iwl-4965.o iwl-4965-rs.o
CFLAGS_iwl-4965.o	= -DIWL=4965
CFLAGS_iwl-4965-rs.o	= -DIWL=4965
CFLAGS_base-4965.o	= -DIWL=4965 -D"KBUILD_MODNAME=KBUILD_STR(iwl4965)"
$(obj)/base-4965.o: $(src)/base.c FORCE
	$(call cmd,force_checksrc)
	$(call if_changed_rule,cc_o_c)

