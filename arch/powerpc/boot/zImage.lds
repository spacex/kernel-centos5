OUTPUT_ARCH(powerpc:common)
ENTRY(_zimage_start)
SECTIONS
{
  . = (56*1024*1024);
  _start = .;
  .text      :
  {
    *(.text)
    *(.fixup)
  }
  _etext = .;
  . = ALIGN(4096);
  .data    :
  {
    *(.rodata*)
    *(.data*)
    *(.sdata*)
    __got2_start = .;
    *(.got2)
    __got2_end = .;
  }

  . = ALIGN(4096);
  _vmlinux_start =  .;
  .kernel:vmlinux.strip : { *(.kernel:vmlinux.strip) }
  _vmlinux_end =  .;

  . = ALIGN(4096);
  _initrd_start =  .;
  .kernel:initrd : { *(.kernel:initrd) }
  _initrd_end =  .;

  . = ALIGN(4096);
  _edata  =  .;

  . = ALIGN(4096);
  __bss_start = .;
  .bss       :
  {
   *(.sbss)
   *(.bss)
  }
  . = ALIGN(4096);
  _end = . ;
}
