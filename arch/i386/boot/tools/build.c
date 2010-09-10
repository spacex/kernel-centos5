/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 1997 Martin Mares
 */

/*
 * This file builds a disk-image from three different files:
 *
 * - bootsect: compatibility mbr which prints an error message if
 *             someone tries to boot the kernel directly.
 * - setup: 8086 machine code, sets up system parm
 * - system: 80386 code for actual system
 *
 * It does some checking that all files are of the correct type, and
 * just writes the result to stdout, removing headers and padding to
 * the right amount. It also writes some system data to stderr.
 */

/*
 * Changes by tytso to allow root device specification
 * High loaded stuff by Hans Lermen & Werner Almesberger, Feb. 1996
 * Cross compiling fixes by Gertjan van Wingerde, July 1996
 * Rewritten by Martin Mares, April 1997
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <elf.h>
#include <byteswap.h>
#define USE_BSD
#include <endian.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <fcntl.h>
#include <asm/boot.h>

typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned long u32;

#define DEFAULT_MAJOR_ROOT 0
#define DEFAULT_MINOR_ROOT 0

/* Minimal number of setup sectors (see also bootsect.S) */
#define SETUP_SECTS 4

byte buf[1024];
int fd;
int is_big_kernel;

#define MAX_PHDRS 100
static Elf32_Ehdr ehdr;
static Elf32_Phdr phdr[MAX_PHDRS];

void die(const char * str, ...)
{
	va_list args;
	va_start(args, str);
	vfprintf(stderr, str, args);
	fputc('\n', stderr);
	exit(1);
}

#if BYTE_ORDER == LITTLE_ENDIAN
#define le16_to_cpu(val) (val)
#define le32_to_cpu(val) (val)
#endif
#if BYTE_ORDER == BIG_ENDIAN
#define le16_to_cpu(val) bswap_16(val)
#define le32_to_cpu(val) bswap_32(val)
#endif

static uint16_t elf16_to_cpu(uint16_t val)
{
	return le16_to_cpu(val);
}

static uint32_t elf32_to_cpu(uint32_t val)
{
	return le32_to_cpu(val);
}

void file_open(const char *name)
{
	if ((fd = open(name, O_RDONLY, 0)) < 0)
		die("Unable to open `%s': %m", name);
}

static void read_ehdr(void)
{
	if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
		die("Cannot read ELF header: %s\n",
			strerror(errno));
	}
	if (memcmp(ehdr.e_ident, ELFMAG, 4) != 0) {
		die("No ELF magic\n");
	}
	if (ehdr.e_ident[EI_CLASS] != ELFCLASS32) {
		die("Not a 32 bit executable\n");
	}
	if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
		die("Not a LSB ELF executable\n");
	}
	if (ehdr.e_ident[EI_VERSION] != EV_CURRENT) {
		die("Unknown ELF version\n");
	}
	/* Convert the fields to native endian */
	ehdr.e_type      = elf16_to_cpu(ehdr.e_type);
	ehdr.e_machine   = elf16_to_cpu(ehdr.e_machine);
	ehdr.e_version   = elf32_to_cpu(ehdr.e_version);
	ehdr.e_entry     = elf32_to_cpu(ehdr.e_entry);
	ehdr.e_phoff     = elf32_to_cpu(ehdr.e_phoff);
	ehdr.e_shoff     = elf32_to_cpu(ehdr.e_shoff);
	ehdr.e_flags     = elf32_to_cpu(ehdr.e_flags);
	ehdr.e_ehsize    = elf16_to_cpu(ehdr.e_ehsize);
	ehdr.e_phentsize = elf16_to_cpu(ehdr.e_phentsize);
	ehdr.e_phnum     = elf16_to_cpu(ehdr.e_phnum);
	ehdr.e_shentsize = elf16_to_cpu(ehdr.e_shentsize);
	ehdr.e_shnum     = elf16_to_cpu(ehdr.e_shnum);
	ehdr.e_shstrndx  = elf16_to_cpu(ehdr.e_shstrndx);

	if ((ehdr.e_type != ET_EXEC) && (ehdr.e_type != ET_DYN)) {
		die("Unsupported ELF header type\n");
	}
	if (ehdr.e_machine != EM_386) {
		die("Not for x86\n");
	}
	if (ehdr.e_version != EV_CURRENT) {
		die("Unknown ELF version\n");
	}
	if (ehdr.e_ehsize != sizeof(Elf32_Ehdr)) {
		die("Bad Elf header size\n");
	}
	if (ehdr.e_phentsize != sizeof(Elf32_Phdr)) {
		die("Bad program header entry\n");
	}
	if (ehdr.e_shentsize != sizeof(Elf32_Shdr)) {
		die("Bad section header entry\n");
	}
	if (ehdr.e_shstrndx >= ehdr.e_shnum) {
		die("String table index out of bounds\n");
	}
}

static void read_phds(void)
{
	int i;
	size_t size;
	if (ehdr.e_phnum > MAX_PHDRS) {
		die("%d program headers supported: %d\n",
			ehdr.e_phnum, MAX_PHDRS);
	}
	if (lseek(fd, ehdr.e_phoff, SEEK_SET) < 0) {
		die("Seek to %d failed: %s\n",
			ehdr.e_phoff, strerror(errno));
	}
	size = sizeof(phdr[0])*ehdr.e_phnum;
	if (read(fd, &phdr, size) != size) {
		die("Cannot read ELF section headers: %s\n",
			strerror(errno));
	}
	for(i = 0; i < ehdr.e_phnum; i++) {
		phdr[i].p_type      = elf32_to_cpu(phdr[i].p_type);
		phdr[i].p_offset    = elf32_to_cpu(phdr[i].p_offset);
		phdr[i].p_vaddr     = elf32_to_cpu(phdr[i].p_vaddr);
		phdr[i].p_paddr     = elf32_to_cpu(phdr[i].p_paddr);
		phdr[i].p_filesz    = elf32_to_cpu(phdr[i].p_filesz);
		phdr[i].p_memsz     = elf32_to_cpu(phdr[i].p_memsz);
		phdr[i].p_flags     = elf32_to_cpu(phdr[i].p_flags);
		phdr[i].p_align     = elf32_to_cpu(phdr[i].p_align);
	}
}

unsigned long vmlinux_memsz(void)
{
	unsigned long min, max, size;
	int i;
	min = 0xffffffff;
	max = 0;
	for(i = 0; i < ehdr.e_phnum; i++) {
		unsigned long start, end;
		if (phdr[i].p_type != PT_LOAD)
			continue;
		start = phdr[i].p_paddr;
		end   = phdr[i].p_paddr + phdr[i].p_memsz;
		if (start < min)
			min = start;
		if (end > max)
			max = end;
	}
	/* Get the reported size by vmlinux */
	size = max - min;
	/* Add 128K for the bootmem bitmap */
	size += 128*1024;
	/* Add in space for the initial page tables */
	size = ((size + (((size + 4095) >> 12)*4)) + 4095) & ~4095;
	return size;
}

void usage(void)
{
	die("Usage: build [-b] bootsect setup system rootdev vmlinux [> image]");
}

int main(int argc, char ** argv)
{
	unsigned int i, sz, setup_sectors;
	unsigned kernel_offset, kernel_filesz, kernel_memsz;
	int c;
	u32 sys_size;
	byte major_root, minor_root;
	struct stat sb;

	if (argc > 2 && !strcmp(argv[1], "-b"))
	  {
	    is_big_kernel = 1;
	    argc--, argv++;
	  }
	if (argc != 6)
		usage();
	if (!strcmp(argv[4], "CURRENT")) {
		if (stat("/", &sb)) {
			perror("/");
			die("Couldn't stat /");
		}
		major_root = major(sb.st_dev);
		minor_root = minor(sb.st_dev);
	} else if (strcmp(argv[4], "FLOPPY")) {
		if (stat(argv[4], &sb)) {
			perror(argv[4]);
			die("Couldn't stat root device.");
		}
		major_root = major(sb.st_rdev);
		minor_root = minor(sb.st_rdev);
	} else {
		major_root = 0;
		minor_root = 0;
	}
	fprintf(stderr, "Root device is (%d, %d)\n", major_root, minor_root);

	file_open(argv[1]);
	i = read(fd, buf, sizeof(buf));
	fprintf(stderr,"Boot sector %d bytes.\n",i);
	if (i != 512)
		die("Boot block must be exactly 512 bytes");
	if (buf[510] != 0x55 || buf[511] != 0xaa)
		die("Boot block hasn't got boot flag (0xAA55)");
	buf[508] = minor_root;
	buf[509] = major_root;
	if (write(1, buf, 512) != 512)
		die("Write call failed");
	close (fd);

	file_open(argv[2]);				    /* Copy the setup code */
	for (i=0 ; (c=read(fd, buf, sizeof(buf)))>0 ; i+=c )
		if (write(1, buf, c) != c)
			die("Write call failed");
	if (c != 0)
		die("read-error on `setup'");
	close (fd);

	setup_sectors = (i + 511) / 512;	/* Pad unused space with zeros */
	/* for compatibility with ancient versions of LILO. */
	if (setup_sectors < SETUP_SECTS)
		setup_sectors = SETUP_SECTS;
	fprintf(stderr, "Setup is %d bytes.\n", i);
	memset(buf, 0, sizeof(buf));
	while (i < setup_sectors * 512) {
		c = setup_sectors * 512 - i;
		if (c > sizeof(buf))
			c = sizeof(buf);
		if (write(1, buf, c) != c)
			die("Write call failed");
		i += c;
	}

	kernel_offset = (setup_sectors + 1)*512;
	file_open(argv[3]);
	if (fstat (fd, &sb))
		die("Unable to stat `%s': %m", argv[3]);
	kernel_filesz = sz = sb.st_size;
	fprintf (stderr, "System is %d kB\n", sz/1024);
	sys_size = (sz + 15) / 16;
	if (!is_big_kernel && sys_size > DEF_SYSSIZE)
		die("System is too big. Try using bzImage or modules.");
	while (sz > 0) {
		int l, n;

		l = (sz > sizeof(buf)) ? sizeof(buf) : sz;
		if ((n=read(fd, buf, l)) != l) {
			if (n < 0)
				die("Error reading %s: %m", argv[3]);
			else
				die("%s: Unexpected EOF", argv[3]);
		}
		if (write(1, buf, l) != l)
			die("Write failed");
		sz -= l;
	}
	close(fd);

	file_open(argv[5]);
	read_ehdr();
	read_phds();
	close(fd);
	kernel_memsz = vmlinux_memsz();

	if (lseek(1,  84, SEEK_SET) != 84)		    /* Write sizes to the bootsector */
		die("Output: seek failed");
	buf[0] = (kernel_offset >>  0) & 0xff;
	buf[1] = (kernel_offset >>  8) & 0xff;
	buf[2] = (kernel_offset >> 16) & 0xff;
	buf[3] = (kernel_offset >> 24) & 0xff;
	if (write(1, buf, 4) != 4)
		die("Write of kernel file offset failed");
	if (lseek(1, 96, SEEK_SET) != 96)
		die("Output: seek failed");
	buf[0] = (kernel_filesz >>  0) & 0xff;
	buf[1] = (kernel_filesz >>  8) & 0xff;
	buf[2] = (kernel_filesz >> 16) & 0xff;
	buf[3] = (kernel_filesz >> 24) & 0xff;
	if (write(1, buf, 4) != 4)
		die("Write of kernel file size failed");
	if (lseek(1, 100, SEEK_SET) != 100)
		die("Output: seek failed");
	buf[0] = (kernel_memsz >>  0) & 0xff;
	buf[1] = (kernel_memsz >>  8) & 0xff;
	buf[2] = (kernel_memsz >> 16) & 0xff;
	buf[3] = (kernel_memsz >> 24) & 0xff;
	if (write(1, buf, 4) != 4)
		die("Write of kernel memory size failed");
	if (lseek(1, 497, SEEK_SET) != 497)
		die("Output: seek failed");
	buf[0] = setup_sectors;
	if (write(1, buf, 1) != 1)
		die("Write of setup sector count failed");
	if (lseek(1, 500, SEEK_SET) != 500)
		die("Output: seek failed");
	buf[0] = (sys_size & 0xff);
	buf[1] = ((sys_size >> 8) & 0xff);
	buf[2] = ((sys_size >> 16) & 0xff);
	buf[3] = ((sys_size >> 24) & 0xff);
	if (write(1, buf, 4) != 4)
		die("Write of image length failed");

	return 0;					    /* Everything is OK */
}
