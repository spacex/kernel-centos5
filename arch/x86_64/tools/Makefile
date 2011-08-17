PHONY += posttest

ifeq ($(KBUILD_VERBOSE),1)
  posttest_verbose = -v
else
  posttest_verbose =
endif

ifeq ($(CONFIG_64BIT),y)
  posttest_64bit = -y
else
  posttest_64bit = -n
endif

distill_awk = $(srctree)/arch/x86_64/tools/distill.awk
chkobjdump = $(srctree)/arch/x86_64/tools/chkobjdump.awk

quiet_cmd_posttest = TEST    $@
      cmd_posttest = ($(OBJDUMP) -v | $(AWK) -f $(chkobjdump)) || $(OBJDUMP) -d -j .text $(objtree)/vmlinux | $(AWK) -f $(distill_awk) | $(obj)/test_get_len $(posttest_64bit) $(posttest_verbose)

posttest: $(obj)/test_get_len vmlinux
	$(call cmd,posttest)

hostprogs-y	:= test_get_len

# -I needed for generated C source and C source which in the kernel tree.
HOSTCFLAGS_test_get_len.o := -Wall -I$(objtree)/arch/x86_64/lib/ -I$(srctree)/arch/x86_64/include/ -I$(srctree)/arch/x86_64/lib/ -I$(srctree)/include/ -I$(objtree)/include2/

# Dependencies are also needed.
$(obj)/test_get_len.o: $(srctree)/arch/x86_64/lib/insn.c $(srctree)/arch/x86_64/lib/inat.c $(srctree)/include/asm-x86_64/inat_types.h $(srctree)/include/asm-x86_64/inat.h $(srctree)/include/asm-x86_64/insn.h $(objtree)/arch/x86_64/lib/inat-tables.c

