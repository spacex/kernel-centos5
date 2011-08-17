#
# Makefile for x86_64-specific library files.
#

inat_tables_script = $(srctree)/arch/x86_64/tools/gen-insn-attr-x86.awk
inat_tables_maps = $(srctree)/arch/x86_64/lib/x86-opcode-map.txt
quiet_cmd_inat_tables = GEN     $@
      cmd_inat_tables = $(AWK) -f $(inat_tables_script) $(inat_tables_maps) > $@

$(obj)/inat-tables.c: $(inat_tables_script) $(inat_tables_maps)
	$(call cmd,inat_tables)

$(obj)/inat.o: $(obj)/inat-tables.c

clean-files := inat-tables.c

CFLAGS_csum-partial.o := -funroll-loops

obj-y := io.o iomap_copy.o

ifndef CONFIG_XEN
obj-$(CONFIG_SMP)	+= msr-on-cpu.o
endif

lib-y := csum-partial.o csum-copy.o csum-wrappers.o delay.o \
	usercopy.o getuser.o putuser.o  \
	thunk.o clear_page.o copy_page.o bitstr.o bitops.o
lib-y += memcpy.o memmove.o memset.o copy_user.o rwlock.o
lib-y += insn.o inat.o
