INFINIBANDINCLUDE := -Idrivers/infiniband/include \
	$(if $(KBUILD_SRC),-I$(srctree)/drivers/infiniband/include)

export CPPFLAGS := $(INFINIBANDINCLUDE) $(CPPFLAGS)

obj-$(CONFIG_MLX4_CORE)		+= mlx4_core.o

mlx4_core-y :=	alloc.o catas.o cmd.o cq.o eq.o fw.o icm.o intf.o main.o mcg.o \
		mr.o pd.o profile.o qp.o reset.o srq.o port.o sense.o

obj-$(CONFIG_MLX4_EN)			+= mlx4_en.o

mlx4_en-y := en_main.o en_tx.o en_rx.o en_ethtool.o en_port.o en_cq.o \
	     en_resources.o en_netdev.o en_frag.o en_lro.o en_selftest.o
