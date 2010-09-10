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
/* Uncompressed kernel vmlinux. */
static Elf64_Ehdr vmlinux_ehdr;
static Elf64_Phdr vmlinux_phdr[MAX_PHDRS];

/* Compressed kernel vmlinux (With decompressor code attached)*/
static Elf64_Ehdr cvmlinux_ehdr;
static Elf64_Phdr cvmlinux_phdr[MAX_PHDRS];

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
#define le64_to_cpu(val) (val)
#endif
#if BYTE_ORDER == BIG_ENDIAN
#define le16_to_cpu(val) bswap_16(val)
#define le32_to_cpu(val) bswap_32(val)
#define le64_to_cpu(val) bswap_64(val)
#endif

static uint16_t elf16_to_cpu(uint16_t val)
{
	return le16_to_cpu(val);
}

static uint32_t elf32_to_cpu(uint32_t val)
{
	return le32_to_cpu(val);
}

static uint64_t elf64_to_cpu(uint64_t val)
{
	return le64_to_cpu(val);
}

void file_open(const char *name)
{
	if ((fd = open(name, O_RDONLY, 0)) < 0)
		die("Unable to open `%s': %m", name);
}

static void read_ehdr(Elf64_Ehdr *ehdr)
{
	if (read(fd, ehdr, sizeof(*ehdr)) != sizeof(*ehdr)) {
		die("Cannot read ELF header: %s\n",
			strerror(errno));
	}
	if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0) {
		die("No ELF magic\n");
	}
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		die("Not a 64 bit executable\n");
	}
	if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
		die("Not a LSB ELF executable\n");
	}
	if (ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
		die("Unknown ELF version\n");
	}
	/* Convert the fields to native endian */
	ehdr->e_type      = elf16_to_cpu(ehdr->e_type);
	ehdr->e_machine   = elf16_to_cpu(ehdr->e_machine);
	ehdr->e_version   = elf32_to_cpu(ehdr->e_version);
	ehdr->e_entry     = elf64_to_cpu(ehdr->e_entry);
	ehdr->e_phoff     = elf64_to_cpu(ehdr->e_phoff);
	ehdr->e_shoff     = elf64_to_cpu(ehdr->e_shoff);
	ehdr->e_flags     = elf32_to_cpu(ehdr->e_flags);
	ehdr->e_ehsize    = elf16_to_cpu(ehdr->e_ehsize);
	ehdr->e_phentsize = elf16_to_cpu(ehdr->e_phentsize);
	ehdr->e_phnum     = elf16_to_cpu(ehdr->e_phnum);
	ehdr->e_shentsize = elf16_to_cpu(ehdr->e_shentsize);
	ehdr->e_shnum     = elf16_to_cpu(ehdr->e_shnum);
	ehdr->e_shstrndx  = elf16_to_cpu(ehdr->e_shstrndx);

	if ((ehdr->e_type != ET_EXEC) && (ehdr->e_type != ET_DYN)) {
		die("Unsupported ELF header type\n");
	}
	if (ehdr->e_machine != EM_X86_64) {
		die("Not for x86_64\n");
	}
	if (ehdr->e_version != EV_CURRENT) {
		die("Unknown ELF version\n");
	}
	if (ehdr->e_ehsize != sizeof(Elf64_Ehdr)) {
		die("Bad Elf header size\n");
	}
	if (ehdr->e_phentsize != sizeof(Elf64_Phdr)) {
		die("Bad program header entry\n");
	}
	if (ehdr->e_shentsize != sizeof(Elf64_Shdr)) {
		die("Bad section header entry\n");
	}
	if (ehdr->e_shstrndx >= ehdr->e_shnum) {
		die("String table index out of bounds\n");
	}
}

static void read_phdrs(Elf64_Ehdr *ehdr, Elf64_Phdr *phdr)
{
	int i;
	size_t size;
	if (ehdr->e_phnum > MAX_PHDRS) {
		die("%d program headers supported: %d\n",
			ehdr->e_phnum, MAX_PHDRS);
	}
	if (lseek(fd, ehdr->e_phoff, SEEK_SET) < 0) {
		die("Seek to %d failed: %s\n",
			ehdr->e_phoff, strerror(errno));
	}
	size = (sizeof(*phdr))*(ehdr->e_phnum);
	if (read(fd, phdr, size) != size) {
		die("Cannot read ELF program headers: %s\n",
			strerror(errno));
	}
	for(i = 0; i < ehdr->e_phnum; i++) {
		phdr[i].p_type      = elf32_to_cpu(phdr[i].p_type);
		phdr[i].p_flags     = elf32_to_cpu(phdr[i].p_flags);
		phdr[i].p_offset    = elf64_to_cpu(phdr[i].p_offset);
		phdr[i].p_vaddr     = elf64_to_cpu(phdr[i].p_vaddr);
		phdr[i].p_paddr     = elf64_to_cpu(phdr[i].p_paddr);
		phdr[i].p_filesz    = elf64_to_cpu(phdr[i].p_filesz);
		phdr[i].p_memsz     = elf64_to_cpu(phdr[i].p_memsz);
		phdr[i].p_align     = elf64_to_cpu(phdr[i].p_align);
	}
}

uint64_t elf_exec_memsz(Elf64_Ehdr *ehdr, Elf64_Phdr *phdr)
{
	uint64_t min, max, size;
	int i;
	max = 0;
	min = ~max;
	for(i = 0; i < ehdr->e_phnum; i++) {
		uint64_t start, end;
		if (phdr[i].p_type != PT_LOAD)
			continue;
		start = phdr[i].p_paddr;
		end   = phdr[i].p_paddr + phdr[i].p_memsz;
		if (start < min)
			min = start;
		if (end > max)
			max = end;
	}
	/* Get the reported size by elf exec */
	size = max - min;
	return size;
}

void usage(void)
{
	die("Usage: build [-b] bootsect setup system rootdev vmlinux vmlinux.bin.gz <vmlinux with decompressor code>[> image]");
}

int main(int argc, char ** argv)
{
	unsigned int i, sz, setup_sectors;
	uint64_t kernel_offset, kernel_filesz, kernel_memsz;
	uint64_t vmlinux_memsz, cvmlinux_memsz, vmlinux_gz_size;
	int c;
	u32 sys_size;
	byte major_root, minor_root;
	struct stat sb, vmlinux_gz_sb;

	if (argc > 2 && !strcmp(argv[1], "-b"))
	  {
	    is_big_kernel = 1;
	    argc--, argv++;
	  }
	if (argc != 8)
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

	/* Open uncompressed vmlinux. */
	file_open(argv[5]);
	read_ehdr(&vmlinux_ehdr);
	read_phdrs(&vmlinux_ehdr, vmlinux_phdr);
	close(fd);
	vmlinux_memsz = elf_exec_memsz(&vmlinux_ehdr, vmlinux_phdr);

	/* Process vmlinux.bin.gz */
	file_open(argv[6]);
	if (fstat (fd, &vmlinux_gz_sb))
		die("Unable to stat `%s': %m", argv[6]);
	close(fd);
	vmlinux_gz_size = vmlinux_gz_sb.st_size;

	/* Process compressed vmlinux (compressed vmlinux + decompressor) */
	file_open(argv[7]);
	read_ehdr(&cvmlinux_ehdr);
	read_phdrs(&cvmlinux_ehdr, cvmlinux_phdr);
	close(fd);
	cvmlinux_memsz = elf_exec_memsz(&cvmlinux_ehdr, cvmlinux_phdr);

	kernel_memsz = vmlinux_memsz;

	/* Add decompressor code size */
	kernel_memsz += cvmlinux_memsz - vmlinux_gz_size;

	/* Refer arch/x86_64/boot/compressed/misc.c for following adj.
	 * Add 8 bytes for every 32K input block
	 */
	kernel_memsz += vmlinux_memsz >> 12;

	/* Add 32K + 18 bytes of extra slack */
	kernel_memsz = kernel_memsz + (32768 + 18);

	/* Align on a 4K boundary. */
	kernel_memsz = (kernel_memsz + 4095) & (~4095);

	if (lseek(1,  88, SEEK_SET) != 88)		    /* Write sizes to the bootsector */
		die("Output: seek failed");
	buf[0] = (kernel_offset >>  0) & 0xff;
	buf[1] = (kernel_offset >>  8) & 0xff;
	buf[2] = (kernel_offset >> 16) & 0xff;
	buf[3] = (kernel_offset >> 24) & 0xff;
	buf[4] = (kernel_offset >> 32) & 0xff;
	buf[5] = (kernel_offset >> 40) & 0xff;
	buf[6] = (kernel_offset >> 48) & 0xff;
	buf[7] = (kernel_offset >> 56) & 0xff;
	if (write(1, buf, 8) != 8)
		die("Write of kernel file offset failed");
	if (lseek(1, 112, SEEK_SET) != 112)
		die("Output: seek failed");
	buf[0] = (kernel_filesz >>  0) & 0xff;
	buf[1] = (kernel_filesz >>  8) & 0xff;
	buf[2] = (kernel_filesz >> 16) & 0xff;
	buf[3] = (kernel_filesz >> 24) & 0xff;
	buf[4] = (kernel_filesz >> 32) & 0xff;
	buf[5] = (kernel_filesz >> 40) & 0xff;
	buf[6] = (kernel_filesz >> 48) & 0xff;
	buf[7] = (kernel_filesz >> 56) & 0xff;
	if (write(1, buf, 8) != 8)
		die("Write of kernel file size failed");
	if (lseek(1, 120, SEEK_SET) != 120)
		die("Output: seek failed");
	buf[0] = (kernel_memsz >>  0) & 0xff;
	buf[1] = (kernel_memsz >>  8) & 0xff;
	buf[2] = (kernel_memsz >> 16) & 0xff;
	buf[3] = (kernel_memsz >> 24) & 0xff;
	buf[4] = (kernel_memsz >> 32) & 0xff;
	buf[5] = (kernel_memsz >> 40) & 0xff;
	buf[6] = (kernel_memsz >> 48) & 0xff;
	buf[7] = (kernel_memsz >> 56) & 0xff;
	if (write(1, buf, 8) != 8)
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
