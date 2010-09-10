INFINIBANDINCLUDE := -Idrivers/infiniband/include \
	$(if $(KBUILD_SRC),-I$(srctree)/drivers/infiniband/include)

export CPPFLAGS := $(INFINIBANDINCLUDE) $(CPPFLAGS)

obj-$(CONFIG_MLX4_CORE)		+= mlx4_core.o

mlx4_core-y :=	alloc.o catas.o cmd.o cq.o eq.o fw.o icm.o intf.o main.o mcg.o \
		mr.o pd.o profile.o qp.o reset.o srq.o
