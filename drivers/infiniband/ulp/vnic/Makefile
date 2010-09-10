obj-$(CONFIG_INFINIBAND_VNIC)			+= ib_vnic.o

ib_vnic-y					:= vnic_main.o \
						   vnic_ib.o \
						   vnic_viport.o \
						   vnic_control.o \
						   vnic_data.o \
						   vnic_netpath.o \
						   vnic_config.o \
						   vnic_sys.o

ib_vnic-$(CONFIG_INFINIBAND_VNIC_STATS)		+= vnic_stats.o
