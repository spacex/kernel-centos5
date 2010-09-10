/*
 * misc.c
 * 
 * This is a collection of several routines from gzip-1.0.3 
 * adapted for Linux.
 *
 * malloc by Hannu Savolainen 1993 and Matthias Urlichs 1994
 * puts by Nick Holloway 1993, better puts by Martin Mares 1995
 * High loaded stuff by Hans Lermen & Werner Almesberger, Feb. 1996
 */

#define __init
#include <linux/linkage.h>
#include <linux/vmalloc.h>
#include <linux/serial_reg.h>
#include <linux/screen_info.h>
#include <asm/io.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <asm/boot.h>

/* WARNING!!
 * This code is compiled with -fPIC and it is relocated dynamically
 * at run time, but no relocation processing is performed.
 * This means that it is not safe to place pointers in static structures.
 */

/*
 * Getting to provable safe in place decompression is hard.
 * Worst case behaviours need to be analized.
 * Background information:
 *
 * The file layout is:
 *    magic[2]
 *    method[1]
 *    flags[1]
 *    timestamp[4]
 *    extraflags[1]
 *    os[1]
 *    compressed data blocks[N]
 *    crc[4] orig_len[4]
 *
 * resulting in 18 bytes of non compressed data overhead.
 *
 * Files divided into blocks
 * 1 bit (last block flag)
 * 2 bits (block type)
 *
 * 1 block occurs every 32K -1 bytes or when there 50% compression has been achieved.
 * The smallest block type encoding is always used.
 *
 * stored:
 *    32 bits length in bytes.
 *
 * fixed:
 *    magic fixed tree.
 *    symbols.
 *
 * dynamic:
 *    dynamic tree encoding.
 *    symbols.
 *
 *
 * The buffer for decompression in place is the length of the
 * uncompressed data, plus a small amount extra to keep the algorithm safe.
 * The compressed data is placed at the end of the buffer.  The output
 * pointer is placed at the start of the buffer and the input pointer
 * is placed where the compressed data starts.  Problems will occur
 * when the output pointer overruns the input pointer.
 *
 * The output pointer can only overrun the input pointer if the input
 * pointer is moving faster than the output pointer.  A condition only
 * triggered by data whose compressed form is larger than the uncompressed
 * form.
 *
 * The worst case at the block level is a growth of the compressed data
 * of 5 bytes per 32767 bytes.
 *
 * The worst case internal to a compressed block is very hard to figure.
 * The worst case can at least be boundined by having one bit that represents
 * 32764 bytes and then all of the rest of the bytes representing the very
 * very last byte.
 *
 * All of which is enough to compute an amount of extra data that is required
 * to be safe.  To avoid problems at the block level allocating 5 extra bytes
 * per 32767 bytes of data is sufficient.  To avoind problems internal to a block
 * adding an extra 32767 bytes (the worst case uncompressed block size) is
 * sufficient, to ensure that in the worst case the decompressed data for
 * block will stop the byte before the compressed data for a block begins.
 * To avoid problems with the compressed data's meta information an extra 18
 * bytes are needed.  Leading to the formula:
 *
 * extra_bytes = (uncompressed_size >> 12) + 32768 + 18 + decompressor_size.
 *
 * Adding 8 bytes per 32K is a bit excessive but much easier to calculate.
 * Adding 32768 instead of 32767 just makes for round numbers.
 * Adding the decompressor_size is necessary as it musht live after all
 * of the data as well.  Last I measured the decompressor is about 14K.
 * 10K of actuall data and 4K of bss.
 *
 */

/*
 * gzip declarations
 */

#define OF(args)  args
#define STATIC static

#undef memset
#undef memcpy
#undef memcmp
#define memzero(s, n)     memset ((s), 0, (n))
char *strstr(const char *haystack, const char *needle);

typedef unsigned char  uch;
typedef unsigned short ush;
typedef unsigned long  ulg;

#define WSIZE 0x80000000	/* Window size must be at least 32k,
				 * and a power of two
				 * We don't actually have a window just
				 * a huge output buffer so I report
				 * a 2G windows size, as that should
				 * always be larger than our output buffer.
				 */

static uch *inbuf;	/* input buffer */
static uch *window;	/* Sliding window buffer, (and final output buffer) */

static unsigned insize;  /* valid bytes in inbuf */
static unsigned inptr;   /* index of next byte to be processed in inbuf */
static unsigned outcnt;  /* bytes in output buffer */

/* gzip flag byte */
#define ASCII_FLAG   0x01 /* bit 0 set: file probably ASCII text */
#define CONTINUATION 0x02 /* bit 1 set: continuation of multi-part gzip file */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
#define ENCRYPTED    0x20 /* bit 5 set: file is encrypted */
#define RESERVED     0xC0 /* bit 6,7:   reserved */

#define get_byte()  (inptr < insize ? inbuf[inptr++] : fill_inbuf())
		
/* Diagnostic functions */
#ifdef DEBUG
#  define Assert(cond,msg) {if(!(cond)) error(msg);}
#  define Trace(x) fprintf x
#  define Tracev(x) {if (verbose) fprintf x ;}
#  define Tracevv(x) {if (verbose>1) fprintf x ;}
#  define Tracec(c,x) {if (verbose && (c)) fprintf x ;}
#  define Tracecv(c,x) {if (verbose>1 && (c)) fprintf x ;}
#else
#  define Assert(cond,msg)
#  define Trace(x)
#  define Tracev(x)
#  define Tracevv(x)
#  define Tracec(c,x)
#  define Tracecv(c,x)
#endif

static int  fill_inbuf(void);
static void flush_window(void);
static void error(char *m);
static void gzip_mark(void **);
static void gzip_release(void **);
  
/*
 * This is set up by the setup-routine at boot-time
 */
static unsigned char *real_mode; /* Pointer to real-mode data */
static char saved_command_line[COMMAND_LINE_SIZE];

#define RM_EXT_MEM_K   (*(unsigned short *)(real_mode + 0x2))
#ifndef STANDARD_MEMORY_BIOS_CALL
#define RM_ALT_MEM_K   (*(unsigned long *)(real_mode + 0x1e0))
#endif
#define RM_SCREEN_INFO (*(struct screen_info *)(real_mode+0))
#define RM_NEW_CL_POINTER ((char *)(unsigned long)(*(unsigned *)(real_mode+0x228)))
#define RM_OLD_CL_MAGIC (*(unsigned short *)(real_mode + 0x20))
#define RM_OLD_CL_OFFSET (*(unsigned short *)(real_mode + 0x22))
#define OLD_CL_MAGIC 0xA33F

extern unsigned char input_data[];
extern int input_len;

static long bytes_out = 0;

static void *malloc(int size);
static void free(void *where);

static void *memset(void *s, int c, unsigned n);
static void *memcpy(void *dest, const void *src, unsigned n);
static int memcmp(const void *s1, const void *s2, unsigned n);

static void putstr(const char *);
static unsigned simple_strtou(const char *cp,char **endp,unsigned base);

static unsigned long free_mem_ptr;
static unsigned long free_mem_end_ptr;

#define HEAP_SIZE             0x3000

static char *vidmem;
static int vidport;
static int lines, cols;

#ifdef CONFIG_X86_NUMAQ
static void * xquad_portio;
#endif

/* The early serial console */

#define DEFAULT_BAUD 9600
#define DEFAULT_BASE 0x3f8 /* ttyS0 */
static unsigned serial_base = DEFAULT_BASE;

#define CONSOLE_NOOP   0
#define CONSOLE_VID    1
#define CONSOLE_SERIAL 2
static int console = CONSOLE_NOOP;

#include "../../../../lib/inflate.c"

static void *malloc(int size)
{
	void *p;

	if (size <0) error("Malloc error");
	if (free_mem_ptr <= 0) error("Memory error");

	free_mem_ptr = (free_mem_ptr + 3) & ~3;	/* Align */

	p = (void *)free_mem_ptr;
	free_mem_ptr += size;

	if (free_mem_ptr >= free_mem_end_ptr)
		error("Out of memory");

	return p;
}

static void free(void *where)
{	/* Don't care */
}

static void gzip_mark(void **ptr)
{
	*ptr = (void *) free_mem_ptr;
}

static void gzip_release(void **ptr)
{
	free_mem_ptr = (unsigned long) *ptr;
}

/* The early video console */
static void vid_scroll(void)
{
	int i;

	memcpy ( vidmem, vidmem + cols * 2, ( lines - 1 ) * cols * 2 );
	for ( i = ( lines - 1 ) * cols * 2; i < lines * cols * 2; i += 2 )
		vidmem[i] = ' ';
}

static void vid_putstr(const char *s)
{
	int x,y,pos;
	char c;

	x = RM_SCREEN_INFO.orig_x;
	y = RM_SCREEN_INFO.orig_y;

	while ( ( c = *s++ ) != '\0' ) {
		if ( c == '\n' ) {
			x = 0;
			if ( ++y >= lines ) {
				vid_scroll();
				y--;
			}
		} else {
			vidmem [ ( x + cols * y ) * 2 ] = c;
			if ( ++x >= cols ) {
				x = 0;
				if ( ++y >= lines ) {
					vid_scroll();
					y--;
				}
			}
		}
	}

	RM_SCREEN_INFO.orig_x = x;
	RM_SCREEN_INFO.orig_y = y;

	pos = (x + cols * y) * 2;	/* Update cursor position */
	outb_p(14, vidport);
	outb_p(0xff & (pos >> 9), vidport+1);
	outb_p(15, vidport);
	outb_p(0xff & (pos >> 1), vidport+1);
}

static void vid_console_init(void)
{
	if (RM_SCREEN_INFO.orig_video_mode == 7) {
		vidmem = (char *) 0xb0000;
		vidport = 0x3b4;
	} else {
		vidmem = (char *) 0xb8000;
		vidport = 0x3d4;
	}

	lines = RM_SCREEN_INFO.orig_video_lines;
	cols = RM_SCREEN_INFO.orig_video_cols;
}

/* The early serial console */
static void serial_putc(int ch)
{
	if (ch == '\n') {
		serial_putc('\r');
	}
	/* Wait until I can send a byte */
	while ((inb(serial_base + UART_LSR) & UART_LSR_THRE) == 0)
		;

	/* Send the byte */
	outb(ch, serial_base + UART_TX);

	/* Wait until the byte is transmitted */
	while (!(inb(serial_base + UART_LSR) & UART_LSR_TEMT))
		;
}

static void serial_putstr(const char *str)
{
	int ch;
	while((ch = *str++) != '\0') {
		if (ch == '\n') {
			serial_putc('\r');
		}
		serial_putc(ch);
	}
}

static void serial_console_init(char *s)
{
	unsigned base = DEFAULT_BASE;
	unsigned baud = DEFAULT_BAUD;
	unsigned divisor;
	char *e;

	if (*s == ',')
		++s;
	if (*s && (*s != ' ')) {
		if (memcmp(s, "0x", 2) == 0) {
			base = simple_strtou(s, &e, 16);
		} else {
			static const unsigned bases[] = { 0x3f8, 0x2f8 };
			unsigned port;

			if (memcmp(s, "ttyS", 4) == 0)
				s += 4;
			port = simple_strtou(s, &e, 10);
			if ((port > 1) || (s == e))
				port = 0;
			base = bases[port];
		}
		s = e;
		if (*s == ',')
			++s;
	}
	if (*s && (*s != ' ')) {
		baud = simple_strtou(s, &e, 0);
		if ((baud == 0) || (s == e))
			baud = DEFAULT_BAUD;
	}
	divisor = 115200 / baud;
	serial_base = base;

	outb(0x00, serial_base + UART_IER); /* no interrupt */
	outb(0x00, serial_base + UART_FCR); /* no fifo */
	outb(0x03, serial_base + UART_MCR); /* DTR + RTS */

	/* Set Baud Rate divisor  */
	outb(0x83, serial_base + UART_LCR);
	outb(divisor & 0xff, serial_base + UART_DLL);
	outb(divisor >> 8, serial_base + UART_DLM);
	outb(0x03, serial_base + UART_LCR); /* 8n1 */

}

static void putstr(const char *str)
{
	if (console == CONSOLE_VID) {
		vid_putstr(str);
	} else if (console == CONSOLE_SERIAL) {
		serial_putstr(str);
	}
}

static void console_init(char *cmdline)
{
	cmdline = strstr(cmdline, "earlyprintk=");
	if (!cmdline)
		return;
	cmdline += 12;
	if (memcmp(cmdline, "vga", 3) == 0) {
		vid_console_init();
		console = CONSOLE_VID;
	} else if (memcmp(cmdline, "serial", 6) == 0) {
		serial_console_init(cmdline + 6);
		console = CONSOLE_SERIAL;
	} else if (memcmp(cmdline, "ttyS", 4) == 0) {
		serial_console_init(cmdline);
		console = CONSOLE_SERIAL;
	}
}

static inline int tolower(int ch)
{
	return ch | 0x20;
}

static inline int isdigit(int ch)
{
	return (ch >= '0') && (ch <= '9');
}

static inline int isxdigit(int ch)
{
	ch = tolower(ch);
	return isdigit(ch) || ((ch >= 'a') && (ch <= 'f'));
}


static inline int digval(int ch)
{
	return isdigit(ch)? (ch - '0') : tolower(ch) - 'a' + 10;
}

/**
 * simple_strtou - convert a string to an unsigned
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
static unsigned simple_strtou(const char *cp, char **endp, unsigned base)
{
	unsigned result = 0,value;

	if (!base) {
		base = 10;
		if (*cp == '0') {
			base = 8;
			cp++;
			if ((tolower(*cp) == 'x') && isxdigit(cp[1])) {
				cp++;
				base = 16;
			}
		}
	} else if (base == 16) {
		if (cp[0] == '0' && tolower(cp[1]) == 'x')
			cp += 2;
	}
	while (isxdigit(*cp) && ((value = digval(*cp)) < base)) {
		result = result*base + value;
		cp++;
	}
	if (endp)
		*endp = (char *)cp;
	return result;
}

static void* memset(void* s, int c, unsigned n)
{
	int i;
	char *ss = (char*)s;

	for (i=0;i<n;i++) ss[i] = c;
	return s;
}

static void* memcpy(void* dest, const void* src, unsigned n)
{
	int i;
	char *d = (char *)dest, *s = (char *)src;

	for (i=0;i<n;i++) d[i] = s[i];
	return dest;
}

static int memcmp(const void *s1, const void *s2, unsigned n)
{
	const unsigned char *str1 = s1, *str2 = s2;
	size_t i;
	int result = 0;
	for(i = 0; (result == 0) && (i < n); i++) {
		result = *str1++ - *str2++;
		}
	return result;
}

char *strstr(const char *haystack, const char *needle)
{
	size_t len;
	len = strlen(needle);
	while(*haystack) {
		if (memcmp(haystack, needle, len) == 0)
			return (char *)haystack;
		haystack++;
	}
	return NULL;
}

/* ===========================================================================
 * Fill the input buffer. This is called only when the buffer is empty
 * and at least one byte is really needed.
 */
static int fill_inbuf(void)
{
	error("ran out of input data");
	return 0;
}

/* ===========================================================================
 * Write the output window window[0..outcnt-1] and update crc and bytes_out.
 * (Used for the decompressed data only.)
 */
static void flush_window(void)
{
	/* With my window equal to my output buffer
	 * I only need to compute the crc here.
	 */
	ulg c = crc;         /* temporary variable */
	unsigned n;
	uch *in, ch;

	in = window;
	for (n = 0; n < outcnt; n++) {
		ch = *in++;
		c = crc_32_tab[((int)c ^ ch) & 0xff] ^ (c >> 8);
	}
	crc = c;
	bytes_out += (ulg)outcnt;
	outcnt = 0;
}

static void error(char *x)
{
	putstr("\n\n");
	putstr(x);
	putstr("\n\n -- System halted");

	while(1);	/* Halt */
}

static void save_command_line(void)
{
	/* Find the command line */
	char *cmdline;
	cmdline = saved_command_line;
	if (RM_NEW_CL_POINTER) {
		cmdline = RM_NEW_CL_POINTER;
	} else if (OLD_CL_MAGIC == RM_OLD_CL_MAGIC) {
		cmdline = real_mode + RM_OLD_CL_OFFSET;
	}
	memcpy(saved_command_line, cmdline, COMMAND_LINE_SIZE);
	saved_command_line[COMMAND_LINE_SIZE - 1] = '\0';
}

asmlinkage void decompress_kernel(void *rmode, unsigned long end,
	uch *input_data, unsigned long input_len, uch *output)
{
	real_mode = rmode;
	save_command_line();
	console_init(saved_command_line);

	window = output;  	/* Output buffer (Normally at 1M) */
	free_mem_ptr     = end;	/* Heap  */
	free_mem_end_ptr = end + HEAP_SIZE;
	inbuf  = input_data;	/* Input buffer */
	insize = input_len;
	inptr  = 0;

	if ((u32)output & (CONFIG_PHYSICAL_ALIGN -1))
		error("Destination address not CONFIG_PHYSICAL_ALIGN aligned");
	if (end > ((-__PAGE_OFFSET-(512 <<20)-1) & 0x7fffffff))
		error("Destination address too large");
#ifndef CONFIG_RELOCATABLE
	if ((u32)output != LOAD_PHYSICAL_ADDR)
		error("Wrong destination address");
#endif

	makecrc();
	putstr("Uncompressing Linux... ");
	gunzip();
	putstr("Ok, booting the kernel.\n");
	return;
}
