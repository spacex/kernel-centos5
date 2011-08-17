/*
 *  arch/s390/kernel/setup.c
 *
 *  S390 version
 *    Copyright (C) 1999,2000 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *    Author(s): Hartmut Penner (hp@de.ibm.com),
 *               Martin Schwidefsky (schwidefsky@de.ibm.com)
 *
 *  Derived from "arch/i386/kernel/setup.c"
 *    Copyright (C) 1995, Linus Torvalds
 */

/*
 * This file handles the architecture-dependent parts of initialization
 */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/user.h>
#include <linux/a.out.h>
#include <linux/tty.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/bootmem.h>
#include <linux/root_dev.h>
#include <linux/console.h>
#include <linux/seq_file.h>
#include <linux/kernel_stat.h>
#include <linux/device.h>
#include <linux/notifier.h>
#include <linux/topology.h>
#include <linux/ctype.h>

#include <asm/ipl.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/smp.h>
#include <asm/mmu_context.h>
#include <asm/cpcmd.h>
#include <asm/lowcore.h>
#include <asm/irq.h>
#include <asm/page.h>
#include <asm/ptrace.h>
#include <asm/sections.h>
#include <asm/cio.h>
#include <asm/ebcdic.h>

/*
 * Machine setup..
 */
unsigned int console_mode = 0;
unsigned int console_devno = -1;
unsigned int console_irq = -1;
unsigned long machine_flags = 0;
unsigned long elf_hwcap = 0;

struct mem_chunk memory_chunk[MEMORY_CHUNKS];
char elf_platform[ELF_PLATFORM_SIZE];
volatile int __cpu_logical_map[NR_CPUS]; /* logical cpu to cpu address */
unsigned long __initdata zholes_size[MAX_NR_ZONES];
static unsigned long __initdata memory_end;

/*
 * This is set up by the setup-routine at boot-time
 * for S390 need to find out, what we have to setup
 * using address 0x10400 ...
 */

#include <asm/setup.h>

static struct resource code_resource = {
	.name  = "Kernel code",
	.flags = IORESOURCE_BUSY | IORESOURCE_MEM,
};

static struct resource data_resource = {
	.name = "Kernel data",
	.flags = IORESOURCE_BUSY | IORESOURCE_MEM,
};

/*
 * cpu_init() initializes state that is per-CPU.
 */
void __devinit cpu_init (void)
{
        int addr = hard_smp_processor_id();

        /*
         * Store processor id in lowcore (used e.g. in timer_interrupt)
         */
        asm volatile ("stidp %0": "=m" (S390_lowcore.cpu_data.cpu_id));
        S390_lowcore.cpu_data.cpu_addr = addr;

        /*
         * Force FPU initialization:
         */
        clear_thread_flag(TIF_USEDFPU);
        clear_used_math();

	atomic_inc(&init_mm.mm_count);
	current->active_mm = &init_mm;
        if (current->mm)
                BUG();
        enter_lazy_tlb(&init_mm, current);
}

/*
 * condev= and conmode= setup parameter.
 */

static int __init condev_setup(char *str)
{
	int vdev;

	vdev = simple_strtoul(str, &str, 0);
	if (vdev >= 0 && vdev < 65536) {
		console_devno = vdev;
		console_irq = -1;
	}
	return 1;
}

__setup("condev=", condev_setup);

static void __init set_preferred_console(void)
{
	if (CONSOLE_IS_3215 || CONSOLE_IS_SCLP)
		add_preferred_console("ttyS", 0, NULL);
	if (CONSOLE_IS_3270)
		add_preferred_console("tty3270", 0, NULL);
}

static int __init conmode_setup(char *str)
{
#if defined(CONFIG_SCLP_CONSOLE)
	if (strncmp(str, "hwc", 4) == 0 || strncmp(str, "sclp", 5) == 0)
                SET_CONSOLE_SCLP;
#endif
#if defined(CONFIG_TN3215_CONSOLE)
	if (strncmp(str, "3215", 5) == 0)
		SET_CONSOLE_3215;
#endif
#if defined(CONFIG_TN3270_CONSOLE)
	if (strncmp(str, "3270", 5) == 0)
		SET_CONSOLE_3270;
#endif
	set_preferred_console();
        return 1;
}

__setup("conmode=", conmode_setup);

static void __init conmode_default(void)
{
	char query_buffer[1024];
	char *ptr;

        if (MACHINE_IS_VM) {
		__cpcmd("QUERY CONSOLE", query_buffer, 1024, NULL);
		console_devno = simple_strtoul(query_buffer + 5, NULL, 16);
		ptr = strstr(query_buffer, "SUBCHANNEL =");
		console_irq = simple_strtoul(ptr + 13, NULL, 16);
		__cpcmd("QUERY TERM", query_buffer, 1024, NULL);
		ptr = strstr(query_buffer, "CONMODE");
		/*
		 * Set the conmode to 3215 so that the device recognition 
		 * will set the cu_type of the console to 3215. If the
		 * conmode is 3270 and we don't set it back then both
		 * 3215 and the 3270 driver will try to access the console
		 * device (3215 as console and 3270 as normal tty).
		 */
		__cpcmd("TERM CONMODE 3215", NULL, 0, NULL);
		if (ptr == NULL) {
#if defined(CONFIG_SCLP_CONSOLE)
			SET_CONSOLE_SCLP;
#endif
			return;
		}
		if (strncmp(ptr + 8, "3270", 4) == 0) {
#if defined(CONFIG_TN3270_CONSOLE)
			SET_CONSOLE_3270;
#elif defined(CONFIG_TN3215_CONSOLE)
			SET_CONSOLE_3215;
#elif defined(CONFIG_SCLP_CONSOLE)
			SET_CONSOLE_SCLP;
#endif
		} else if (strncmp(ptr + 8, "3215", 4) == 0) {
#if defined(CONFIG_TN3215_CONSOLE)
			SET_CONSOLE_3215;
#elif defined(CONFIG_TN3270_CONSOLE)
			SET_CONSOLE_3270;
#elif defined(CONFIG_SCLP_CONSOLE)
			SET_CONSOLE_SCLP;
#endif
		}
        } else if (MACHINE_IS_P390) {
#if defined(CONFIG_TN3215_CONSOLE)
		SET_CONSOLE_3215;
#elif defined(CONFIG_TN3270_CONSOLE)
		SET_CONSOLE_3270;
#endif
	} else {
#if defined(CONFIG_SCLP_CONSOLE)
		SET_CONSOLE_SCLP;
#endif
	}
}

/* Set up boot command line */
static char s390_command_line[COMMAND_LINE_SIZE];

static void __init setup_boot_command_line(void)
{
	char *parm = NULL;

	/* copy arch command line */
	strlcpy(s390_command_line, COMMAND_LINE, ARCH_COMMAND_LINE_SIZE);

	/* append IPL PARM data to the boot command line */
	if (MACHINE_IS_VM) {
		parm = s390_command_line + strlen(s390_command_line);
		*parm++ = ' ';
		get_ipl_vmparm(parm);
		if (parm[0] == '=')
			memmove(s390_command_line, parm + 1, strlen(parm));
	}
}

#if defined(CONFIG_ZFCPDUMP) || defined(CONFIG_ZFCPDUMP_MODULE)
static void __init setup_zfcpdump(unsigned int console_devno)
{
	static char str[41];

	if (ipl_info.type != IPL_TYPE_FCP_DUMP)
		return;
	if (console_devno != -1)
		sprintf(str, " cio_ignore=all,!0.0.%04x,!0.0.%04x",
			ipl_info.data.fcp.dev_id.devno, console_devno);
	else
		sprintf(str, " cio_ignore=all,!0.0.%04x",
			ipl_info.data.fcp.dev_id.devno);
	strcat(s390_command_line, str);
	console_loglevel = 2;
}
#else
static inline void setup_zfcpdump(unsigned int console_devno) {}
#endif /* CONFIG_ZFCPDUMP */

/*
 * Create a Kernel NSS if the SAVESYS= parameter is defined
*/
#define DEFSYS_CMD_SIZE		128
#define SAVESYS_CMD_SIZE	32

char kernel_nss_name[NSS_NAME_SIZE + 1];

#ifdef CONFIG_SHARED_KERNEL
int __init savesys_ipl_nss(char *cmd, const int cmdlen);

asm(
	"	.section .init.text,\"ax\",@progbits\n"
	"	.align	4\n"
	"	.type	savesys_ipl_nss, @function\n"
	"savesys_ipl_nss:\n"
#ifdef CONFIG_64BIT
	"	stmg	6,15,48(15)\n"
	"	lgr	14,3\n"
	"	sam31\n"
	"	diag	2,14,0x8\n"
	"	sam64\n"
	"	lgr	2,14\n"
	"	lmg	6,15,48(15)\n"
#else
	"	stm	6,15,24(15)\n"
	"	lr	14,3\n"
	"	diag	2,14,0x8\n"
	"	lr	2,14\n"
	"	lm	6,15,24(15)\n"
#endif
	"	br	14\n"
	"	.size	savesys_ipl_nss, .-savesys_ipl_nss\n"
	"	.previous\n");

static __init void create_kernel_nss(void)
{
	unsigned int i, stext_pfn, eshared_pfn, end_pfn, min_size;
#ifdef CONFIG_BLK_DEV_INITRD
	unsigned int sinitrd_pfn, einitrd_pfn;
#endif
	int response;
	size_t len;
	char *savesys_ptr;
	char upper_command_line[COMMAND_LINE_SIZE];
	char defsys_cmd[DEFSYS_CMD_SIZE];
	char savesys_cmd[SAVESYS_CMD_SIZE];

	/* Do nothing if we are not running under VM */
	if (!MACHINE_IS_VM)
		return;

	/* Convert s390_command_line to upper case */
	for (i = 0; i < strlen(s390_command_line); i++)
		upper_command_line[i] = toupper(s390_command_line[i]);

	savesys_ptr = strstr(upper_command_line, "SAVESYS=");

	if (!savesys_ptr)
		return;

	savesys_ptr += 8;    /* Point to the beginning of the NSS name */
	for (i = 0; i < NSS_NAME_SIZE; i++) {
		if (savesys_ptr[i] == ' ' || savesys_ptr[i] == '\0')
			break;
		kernel_nss_name[i] = savesys_ptr[i];
	}

	stext_pfn = PFN_DOWN(__pa(&_stext));
	eshared_pfn = PFN_DOWN(__pa(&_eshared));
	end_pfn = PFN_UP(__pa(&_end));
	min_size = end_pfn << 2;

	sprintf(defsys_cmd, "DEFSYS %s 00000-%.5X EW %.5X-%.5X SR %.5X-%.5X",
		kernel_nss_name, stext_pfn - 1, stext_pfn, eshared_pfn - 1,
		eshared_pfn, end_pfn);

#ifdef CONFIG_BLK_DEV_INITRD
	if (INITRD_START && INITRD_SIZE) {
		sinitrd_pfn = PFN_DOWN(__pa(INITRD_START));
		einitrd_pfn = PFN_UP(__pa(INITRD_START + INITRD_SIZE));
		min_size = einitrd_pfn << 2;
		sprintf(defsys_cmd, "%s EW %.5X-%.5X", defsys_cmd,
		sinitrd_pfn, einitrd_pfn);
	}
#endif

	sprintf(defsys_cmd, "%s EW MINSIZE=%.7iK PARMREGS=0-13",
		defsys_cmd, min_size);
	sprintf(savesys_cmd, "SAVESYS %s \n IPL %s",
		kernel_nss_name, kernel_nss_name);

	__cpcmd(defsys_cmd, NULL, 0, &response);

	if (response != 0) {
		kernel_nss_name[0] = '\0';
		return;
	}

	len = strlen(savesys_cmd);
	ASCEBC(savesys_cmd, len);
	response = savesys_ipl_nss(savesys_cmd, len);

	/* On success: response is equal to the command size,
	 *	       max SAVESYS_CMD_SIZE
	 * On error: response contains the numeric portion of cp error message.
	 *	     for SAVESYS it will be >= 263
	 */
	if (response > SAVESYS_CMD_SIZE) {
		kernel_nss_name[0] = '\0';
		return;
	}

	/* re-setup boot command line with new ipl vm parms */
	ipl_update_parameters();
	setup_boot_command_line();

	ipl_flags = IPL_NSS_VALID;
}

#else /* CONFIG_SHARED_KERNEL */

static inline void create_kernel_nss(void) { }

#endif /* CONFIG_SHARED_KERNEL */

/*
 * Clear bss memory
 */
static __init void clear_bss_section(void)
{
	memset(__bss_start, 0, __bss_stop - __bss_start);
}

/*
 * Initialize storage key for kernel pages
 */
static __init void init_kernel_storage_key(void)
{
	unsigned long end_pfn, init_pfn;

	end_pfn = PFN_UP(__pa(&_end));

	for (init_pfn = 0 ; init_pfn < end_pfn; init_pfn++)
		page_set_storage_key(init_pfn << PAGE_SHIFT, PAGE_DEFAULT_KEY);
}

static __init void detect_machine_type(void)
{
	struct cpuinfo_S390 *cpuinfo = &S390_lowcore.cpu_data;

	asm volatile("stidp %0" : "=m" (S390_lowcore.cpu_data.cpu_id));

	/* Running under z/VM ? */
	if (cpuinfo->cpu_id.version == 0xff)
		machine_flags |= 1;

	/* Running on a P/390 ? */
	if (cpuinfo->cpu_id.machine == 0x7490)
		machine_flags |= 4;
}

static __init void rescue_initrd(void)
{
#ifdef CONFIG_BLK_DEV_INITRD
	/*
	 * Move the initrd right behind the bss section in case it starts
	 * within the bss section. So we don't overwrite it when the bss
	 * section gets cleared.
	 */
	if (!INITRD_START || !INITRD_SIZE)
		return;
	if (INITRD_START >= (unsigned long) __bss_stop)
		return;
	memmove(__bss_stop, (void *) INITRD_START, INITRD_SIZE);
	INITRD_START = (unsigned long) __bss_stop;
#endif
}

/*
 * Save ipl parameters, clear bss memory, initialize storage keys
 * and create a kernel NSS at startup if the SAVESYS= parm is defined
 */
void __init startup_init(void)
{
	ipl_save_parameters();
	rescue_initrd();
	clear_bss_section();
	init_kernel_storage_key();
	detect_machine_type();
	ipl_update_parameters();
	setup_boot_command_line();
	create_kernel_nss();
}

 /*
 * Reboot, halt and power_off stubs. They just call _machine_restart,
 * _machine_halt or _machine_power_off. 
 */

void machine_restart(char *command)
{
	if (!in_interrupt() || oops_in_progress)
		/*
		 * Only unblank the console if we are called in enabled
		 * context or a bust_spinlocks cleared the way for us.
		 */
		console_unblank();
	_machine_restart(command);
}

void machine_halt(void)
{
	if (!in_interrupt() || oops_in_progress)
		/*
		 * Only unblank the console if we are called in enabled
		 * context or a bust_spinlocks cleared the way for us.
		 */
		console_unblank();
	_machine_halt();
}

void machine_power_off(void)
{
	if (!in_interrupt() || oops_in_progress)
		/*
		 * Only unblank the console if we are called in enabled
		 * context or a bust_spinlocks cleared the way for us.
		 */
		console_unblank();
	_machine_power_off();
}

/*
 * Dummy power off function.
 */
void (*pm_power_off)(void) = machine_power_off;

static void __init
add_memory_hole(unsigned long start, unsigned long end)
{
	unsigned long dma_pfn = MAX_DMA_ADDRESS >> PAGE_SHIFT;

	if (end <= dma_pfn)
		zholes_size[ZONE_DMA] += end - start + 1;
	else if (start > dma_pfn)
		zholes_size[ZONE_NORMAL] += end - start + 1;
	else {
		zholes_size[ZONE_DMA] += dma_pfn - start + 1;
		zholes_size[ZONE_NORMAL] += end - dma_pfn;
	}
}

static int __init early_parse_mem(char *p)
{
	memory_end = memparse(p, &p);
	return 0;
}
early_param("mem", early_parse_mem);

/*
 * "ipldelay=XXX[sm]" sets ipl delay in seconds or minutes
 */
static int __init early_parse_ipldelay(char *p)
{
	unsigned long delay = 0;

	delay = simple_strtoul(p, &p, 0);

	switch (*p) {
	case 's':
	case 'S':
		delay *= 1000000;
		break;
	case 'm':
	case 'M':
		delay *= 60 * 1000000;
	}

	/* now wait for the requested amount of time */
	udelay(delay);

	return 0;
}
early_param("ipldelay", early_parse_ipldelay);

static void __init
setup_lowcore(void)
{
	struct _lowcore *lc;
	int lc_pages;

	/*
	 * Setup lowcore for boot cpu
	 */
	lc_pages = sizeof(void *) == 8 ? 2 : 1;
	lc = (struct _lowcore *)
		__alloc_bootmem(lc_pages * PAGE_SIZE, lc_pages * PAGE_SIZE, 0);
	memset(lc, 0, lc_pages * PAGE_SIZE);
	lc->restart_psw.mask = PSW_BASE_BITS | PSW_DEFAULT_KEY;
	lc->restart_psw.addr =
		PSW_ADDR_AMODE | (unsigned long) restart_int_handler;
	lc->external_new_psw.mask = PSW_KERNEL_BITS;
	lc->external_new_psw.addr =
		PSW_ADDR_AMODE | (unsigned long) ext_int_handler;
	lc->svc_new_psw.mask = PSW_KERNEL_BITS | PSW_MASK_IO | PSW_MASK_EXT;
	lc->svc_new_psw.addr = PSW_ADDR_AMODE | (unsigned long) system_call;
	lc->program_new_psw.mask = PSW_KERNEL_BITS;
	lc->program_new_psw.addr =
		PSW_ADDR_AMODE | (unsigned long)pgm_check_handler;
	lc->mcck_new_psw.mask =
		PSW_KERNEL_BITS & ~PSW_MASK_MCHECK & ~PSW_MASK_DAT;
	lc->mcck_new_psw.addr =
		PSW_ADDR_AMODE | (unsigned long) mcck_int_handler;
	lc->io_new_psw.mask = PSW_KERNEL_BITS;
	lc->io_new_psw.addr = PSW_ADDR_AMODE | (unsigned long) io_int_handler;
	lc->ipl_device = S390_lowcore.ipl_device;
	lc->jiffy_timer = -1LL;
	lc->kernel_stack = ((unsigned long) &init_thread_union) + THREAD_SIZE;
	lc->async_stack = (unsigned long)
		__alloc_bootmem(ASYNC_SIZE, ASYNC_SIZE, 0) + ASYNC_SIZE;
	lc->panic_stack = (unsigned long)
		__alloc_bootmem(PAGE_SIZE, PAGE_SIZE, 0) + PAGE_SIZE;
	lc->current_task = (unsigned long) init_thread_union.thread_info.task;
	lc->thread_info = (unsigned long) &init_thread_union;
#ifndef CONFIG_64BIT
	if (MACHINE_HAS_IEEE) {
		lc->extended_save_area_addr = (__u32)
			__alloc_bootmem(PAGE_SIZE, PAGE_SIZE, 0);
		/* enable extended save area */
		ctl_set_bit(14, 29);
	}
#endif
	set_prefix((u32)(unsigned long) lc);
	lowcore_ptr[0] = lc;
}

static void __init
setup_resources(void)
{
	struct resource *res, *sub_res;
	int i;

	code_resource.start = (unsigned long) &_text;
	code_resource.end = (unsigned long) &_etext - 1;
	data_resource.start = (unsigned long) &_etext;
	data_resource.end = (unsigned long) &_edata - 1;

	for (i = 0; i < MEMORY_CHUNKS && memory_chunk[i].size > 0; i++) {
		res = alloc_bootmem_low(sizeof(struct resource));
		res->flags = IORESOURCE_BUSY | IORESOURCE_MEM;
		switch (memory_chunk[i].type) {
		case CHUNK_READ_WRITE:
			res->name = "System RAM";
			break;
		case CHUNK_READ_ONLY:
			res->name = "System ROM";
			res->flags |= IORESOURCE_READONLY;
			break;
		default:
			res->name = "reserved";
		}
		res->start = memory_chunk[i].addr;
		res->end = memory_chunk[i].addr +  memory_chunk[i].size - 1;
		request_resource(&iomem_resource, res);

		if (code_resource.start >= res->start  &&
			code_resource.start <= res->end &&
			code_resource.end > res->end) {
			sub_res = alloc_bootmem_low(sizeof(struct resource));
			memcpy(sub_res, &code_resource,
				sizeof(struct resource));
			sub_res->end = res->end;
			code_resource.start = res->end + 1;
			request_resource(res, sub_res);
		}

		if (code_resource.start >= res->start &&
			code_resource.start <= res->end &&
			code_resource.end <= res->end)
			request_resource(res, &code_resource);

		if (data_resource.start >= res->start &&
			data_resource.start <= res->end &&
			data_resource.end > res->end) {
			sub_res = alloc_bootmem_low(sizeof(struct resource));
			memcpy(sub_res, &data_resource,
				sizeof(struct resource));
			sub_res->end = res->end;
			data_resource.start = res->end + 1;
			request_resource(res, sub_res);
		}

		if (data_resource.start >= res->start &&
			data_resource.start <= res->end &&
			data_resource.end <= res->end)
			request_resource(res, &data_resource);
	}
}

static void __init setup_memory_end(void)
{
	unsigned long real_size, memory_size;
	unsigned long max_mem, max_phys;
	int i;

	memory_size = real_size = 0;
	max_phys = VMALLOC_END - VMALLOC_MIN_SIZE;
	memory_end &= PAGE_MASK;

	max_mem = memory_end ? min(max_phys, memory_end) : max_phys;

	for (i = 0; i < MEMORY_CHUNKS; i++) {
		struct mem_chunk *chunk = &memory_chunk[i];

		real_size = max(real_size, chunk->addr + chunk->size);
		if (chunk->addr >= max_mem) {
			memset(chunk, 0, sizeof(*chunk));
			continue;
		}
		if (chunk->addr + chunk->size > max_mem)
			chunk->size = max_mem - chunk->addr;
		memory_size = max(memory_size, chunk->addr + chunk->size);
	}
	if (!memory_end)
		memory_end = memory_size;
	if (real_size > memory_end)
		printk("More memory detected than supported. Unused: %luk\n",
			(real_size - memory_end) >> 10);
}

unsigned long real_memory_size;
EXPORT_SYMBOL_GPL(real_memory_size);

static void __init
setup_memory(void)
{
        unsigned long bootmap_size;
	unsigned long start_pfn, end_pfn, init_pfn;
	unsigned long last_rw_end;
	int i;

	/*
	 * partially used pages are not usable - thus
	 * we are rounding upwards:
	 */
	start_pfn = (__pa(&_end) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	end_pfn = max_pfn = memory_end >> PAGE_SHIFT;

#ifdef CONFIG_BLK_DEV_INITRD
	/*
	 * Move the initrd in case the bitmap of the bootmem allocater
	 * would overwrite it.
	 */

	if (INITRD_START && INITRD_SIZE) {
		unsigned long bmap_size;
		unsigned long start;

		bmap_size = bootmem_bootmap_pages(end_pfn - start_pfn + 1);
		bmap_size = PFN_PHYS(bmap_size);

		if (PFN_PHYS(start_pfn) + bmap_size > INITRD_START) {
			start = PFN_PHYS(start_pfn) + bmap_size + PAGE_SIZE;
			if (start + INITRD_SIZE > memory_end) {
				printk("initrd extends beyond end of memory "
				       "(0x%08lx > 0x%08lx)\n"
				       "disabling initrd\n",
				       start + INITRD_SIZE, memory_end);
				INITRD_START = INITRD_SIZE = 0;
			} else {
				printk("Moving initrd (0x%08lx -> 0x%08lx, "
				       "size: %ld)\n",
				       INITRD_START, start, INITRD_SIZE);
				memmove((void *) start, (void *) INITRD_START,
					INITRD_SIZE);
				INITRD_START = start;
			}
		}
	}
#endif

	/*
	 * Initialize the boot-time allocator (with low memory only):
	 */
	bootmap_size = init_bootmem(start_pfn, end_pfn);

	/*
	 * Register RAM areas with the bootmem allocator.
	 */
	last_rw_end = start_pfn;

	for (i = 0; i < MEMORY_CHUNKS && memory_chunk[i].size > 0; i++) {
		unsigned long start_chunk, end_chunk;

		if (memory_chunk[i].type != CHUNK_READ_WRITE)
			continue;
		start_chunk = (memory_chunk[i].addr + PAGE_SIZE - 1);
		start_chunk >>= PAGE_SHIFT;
		end_chunk = (memory_chunk[i].addr + memory_chunk[i].size);
		real_memory_size = max(real_memory_size, end_chunk);
		end_chunk >>= PAGE_SHIFT;
		if (start_chunk < start_pfn)
			start_chunk = start_pfn;
		if (end_chunk > end_pfn)
			end_chunk = end_pfn;
		if (start_chunk < end_chunk) {
			/* Initialize storage key for RAM pages */
			for (init_pfn = start_chunk ; init_pfn < end_chunk;
			     init_pfn++)
				page_set_storage_key(init_pfn << PAGE_SHIFT,
						     PAGE_DEFAULT_KEY);
			free_bootmem(start_chunk << PAGE_SHIFT,
				     (end_chunk - start_chunk) << PAGE_SHIFT);
			if (last_rw_end < start_chunk)
				add_memory_hole(last_rw_end, start_chunk - 1);
			last_rw_end = end_chunk;
		}
	}

	psw_set_key(PAGE_DEFAULT_KEY);

	if (last_rw_end < end_pfn - 1)
		add_memory_hole(last_rw_end, end_pfn - 1);

	/*
	 * Reserve the bootmem bitmap itself as well. We do this in two
	 * steps (first step was init_bootmem()) because this catches
	 * the (very unlikely) case of us accidentally initializing the
	 * bootmem allocator with an invalid RAM area.
	 */
	reserve_bootmem(start_pfn << PAGE_SHIFT, bootmap_size, BOOTMEM_DEFAULT);

#ifdef CONFIG_BLK_DEV_INITRD
	if (INITRD_START && INITRD_SIZE) {
		if (INITRD_START + INITRD_SIZE <= memory_end) {
			reserve_bootmem(INITRD_START, INITRD_SIZE,
					BOOTMEM_DEFAULT);
			initrd_start = INITRD_START;
			initrd_end = initrd_start + INITRD_SIZE;
		} else {
			printk("initrd extends beyond end of memory "
			       "(0x%08lx > 0x%08lx)\ndisabling initrd\n",
			       initrd_start + INITRD_SIZE, memory_end);
			initrd_start = initrd_end = 0;
		}
	}
#endif
}

/*
 * Setup hardware capabilities.
 */
static void __init setup_hwcaps(void)
{
	static const int stfl_bits[6] = { 0, 2, 7, 17, 19, 21 };
	struct cpuinfo_S390 *cpuinfo = &S390_lowcore.cpu_data;
	unsigned long long facility_list_extended;
	unsigned int facility_list;
	int i;

	facility_list = stfl();
	/*
	 * The store facility list bits numbers as found in the principles
	 * of operation are numbered with bit 1UL<<31 as number 0 to
	 * bit 1UL<<0 as number 31.
	 *   Bit 0: instructions named N3, "backported" to esa-mode
	 *   Bit 2: z/Architecture mode is active
	 *   Bit 7: the store-facility-list-extended facility is installed
	 *   Bit 17: the message-security assist is installed
	 *   Bit 19: the long-displacement facility is installed
	 *   Bit 21: the extended-immediate facility is installed
	 * These get translated to:
	 *   HWCAP_S390_ESAN3 bit 0, HWCAP_S390_ZARCH bit 1,
	 *   HWCAP_S390_STFLE bit 2, HWCAP_S390_MSA bit 3,
	 *   HWCAP_S390_LDISP bit 4, and HWCAP_S390_EIMM bit 5.
	 */
	for (i = 0; i < 6; i++)
		if (facility_list & (1UL << (31 - stfl_bits[i])))
			elf_hwcap |= 1UL << i;

	/*
	 * Check for additional facilities with store-facility-list-extended.
	 * stfle stores doublewords (8 byte) with bit 1ULL<<63 as bit 0
	 * and 1ULL<<0 as bit 63. Bits 0-31 contain the same information
	 * as stored by stfl, bits 32-xxx contain additional facilities.
	 * How many facility words are stored depends on the number of
	 * doublewords passed to the instruction. The additional facilites
	 * are:
	 *   Bit 43: decimal floating point facility is installed
	 * translated to:
	 *   HWCAP_S390_DFP bit 6.
	 */
	if ((elf_hwcap & (1UL << 2)) &&
	    stfle(&facility_list_extended, 1) > 0) {
		if (facility_list_extended & (1ULL << (64 - 43)))
			elf_hwcap |= 1UL << 6;
	}

	if (facility_list & (1UL << 23))
		elf_hwcap |= 1UL << 7;

	switch (cpuinfo->cpu_id.machine) {
	case 0x9672:
#if !defined(CONFIG_64BIT)
	default:	/* Use "g5" as default for 31 bit kernels. */
#endif
		strcpy(elf_platform, "g5");
		break;
	case 0x2064:
	case 0x2066:
#if defined(CONFIG_64BIT)
	default:	/* Use "z900" as default for 64 bit kernels. */
#endif
		strcpy(elf_platform, "z900");
		break;
	case 0x2084:
	case 0x2086:
		strcpy(elf_platform, "z990");
		break;
	case 0x2094:
		strcpy(elf_platform, "z9-109");
		break;
	}
}

/*
 * Setup function called from init/main.c just after the banner
 * was printed.
 */

void __init
setup_arch(char **cmdline_p)
{
        /*
         * print what head.S has found out about the machine
         */
#ifndef CONFIG_64BIT
	printk((MACHINE_IS_VM) ?
	       "We are running under VM (31 bit mode)\n" :
	       "We are running native (31 bit mode)\n");
	printk((MACHINE_HAS_IEEE) ?
	       "This machine has an IEEE fpu\n" :
	       "This machine has no IEEE fpu\n");
#else /* CONFIG_64BIT */
	printk((MACHINE_IS_VM) ?
	       "We are running under VM (64 bit mode)\n" :
	       "We are running native (64 bit mode)\n");
#endif /* CONFIG_64BIT */

	/* save unparsed s390_command_line for /proc/cmdline */
	memcpy(saved_command_line, s390_command_line, COMMAND_LINE_SIZE);
	*cmdline_p = s390_command_line;

        ROOT_DEV = Root_RAM0;

	init_mm.start_code = PAGE_OFFSET;
	init_mm.end_code = (unsigned long) &_etext;
	init_mm.end_data = (unsigned long) &_edata;
	init_mm.brk = (unsigned long) &_end;

	parse_early_param();

	setup_ipl();
	setup_memory_end();
#if defined(CONFIG_ZFCPDUMP) || defined(CONFIG_ZFCPDUMP_MODULE)
	if (ipl_info.type == IPL_TYPE_FCP_DUMP) {
		memory_end = ZFCPDUMP_HSA_SIZE;
	}
#endif
	setup_memory();
	setup_resources();
	setup_lowcore();

        cpu_init();
        __cpu_logical_map[0] = S390_lowcore.cpu_data.cpu_addr;
	smp_setup_cpu_possible_map();
	s390_init_cpu_topology();

	/*
	 * Setup capabilities (ELF_HWCAP & ELF_PLATFORM).
	 */
	setup_hwcaps();

	if (S390_lowcore.stfl_fac_list & (1UL << 23)) {
		__ctl_set_bit(0, 23);
		machine_flags |= 1024;
	}

	/*
	 * Create kernel page tables and switch to virtual addressing.
	 */
        paging_init();

        /* Setup default console */
	conmode_default();
	set_preferred_console();

	/* Setup zfcpdump support */
	setup_zfcpdump(console_devno);
}

void print_cpu_info(struct cpuinfo_S390 *cpuinfo)
{
   printk("cpu %d "
#ifdef CONFIG_SMP
           "phys_idx=%d "
#endif
           "vers=%02X ident=%06X machine=%04X unused=%04X\n",
           cpuinfo->cpu_nr,
#ifdef CONFIG_SMP
           cpuinfo->cpu_addr,
#endif
           cpuinfo->cpu_id.version,
           cpuinfo->cpu_id.ident,
           cpuinfo->cpu_id.machine,
           cpuinfo->cpu_id.unused);
}

/*
 * show_cpuinfo - Get information on one CPU for use by procfs.
 */

static int show_cpuinfo(struct seq_file *m, void *v)
{
	static const char *hwcap_str[8] = {
		"esan3", "zarch", "stfle", "msa", "ldisp", "eimm", "dfp",
		"edat"
	};
        struct cpuinfo_S390 *cpuinfo;
	unsigned long n = (unsigned long) v - 1;
	int i;

	preempt_disable();
	if (!n) {
		seq_printf(m, "vendor_id       : IBM/S390\n"
			       "# processors    : %i\n"
			       "bogomips per cpu: %lu.%02lu\n",
			       num_online_cpus(), loops_per_jiffy/(500000/HZ),
			       (loops_per_jiffy/(5000/HZ))%100);
		seq_puts(m, "features\t: ");
		for (i = 0; i < 8; i++)
			if (hwcap_str[i] && (elf_hwcap & (1UL << i)))
				seq_printf(m, "%s ", hwcap_str[i]);
		seq_puts(m, "\n");
	}

	if (cpu_online(n)) {
#ifdef CONFIG_SMP
		if (smp_processor_id() == n)
			cpuinfo = &S390_lowcore.cpu_data;
		else
			cpuinfo = &lowcore_ptr[n]->cpu_data;
#else
		cpuinfo = &S390_lowcore.cpu_data;
#endif
		seq_printf(m, "processor %li: "
			       "version = %02X,  "
			       "identification = %06X,  "
			       "machine = %04X\n",
			       n, cpuinfo->cpu_id.version,
			       cpuinfo->cpu_id.ident,
			       cpuinfo->cpu_id.machine);
	}
	preempt_enable();
        return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < NR_CPUS ? (void *)((unsigned long) *pos + 1) : NULL;
}
static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return c_start(m, pos);
}
static void c_stop(struct seq_file *m, void *v)
{
}
struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= show_cpuinfo,
};
