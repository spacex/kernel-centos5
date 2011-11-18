INFINIBANDINCLUDE := -Idrivers/infiniband/include \
        $(if $(KBUILD_SRC),-I$(srctree)/drivers/infiniband/include)

export CPPFLAGS := $(INFINIBANDINCLUDE) $(CPPFLAGS)

obj-$(CONFIG_SCSI_CXGB3_ISCSI)	+= libcxgbi.o cxgb3i/
obj-$(CONFIG_SCSI_CXGB4_ISCSI)	+= libcxgbi.o cxgb4i/
