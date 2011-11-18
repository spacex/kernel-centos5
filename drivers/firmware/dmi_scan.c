#include <linux/types.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/dmi.h>
#include <linux/efi.h>
#include <linux/bootmem.h>
#include <linux/slab.h>
#include <asm/dmi.h>

static char * __init dmi_string(const struct dmi_header *dm, u8 s)
{
	u8 *bp = ((u8 *) dm) + dm->length;
	char *str = "";

	if (s) {
		s--;
		while (s > 0 && *bp) {
			bp += strlen(bp) + 1;
			s--;
		}

		if (*bp != 0) {
			str = dmi_alloc(strlen(bp) + 1);
			if (str != NULL)
				strcpy(str, bp);
			else
				printk(KERN_ERR "dmi_string: out of memory.\n");
		}
	}

	return str;
}

/*
 *	We have to be cautious here. We have seen BIOSes with DMI pointers
 *	pointing to completely the wrong place for example
 */
static void dmi_table(u8 *buf, int len, int num,
		     void (*decode)(struct dmi_header *))
{
	u8 *data = buf;
	int i = 0;

	/*
	 *	Stop when we see all the items the table claimed to have
	 *	OR we run off the end of the table (also happens)
	 */
	while ((i < num) && (data - buf + sizeof(struct dmi_header)) <= len) {
		struct dmi_header *dm = (struct dmi_header *)data;
		/*
		 *  We want to know the total length (formated area and strings)
		 *  before decoding to make sure we won't run off the table in
		 *  dmi_decode or dmi_string
		 */
		data += dm->length;
		while ((data - buf < len - 1) && (data[0] || data[1]))
			data++;
		if (data - buf < len - 1)
			decode(dm);
		data += 2;
		i++;
	}
}

static u32 dmi_base;
static u16 dmi_len;
static u16 dmi_num;

static int __init dmi_walk_early(void (*decode)(const struct dmi_header *))
{
	u8 *buf;

	buf = dmi_ioremap(dmi_base, dmi_len);
	if (buf == NULL)
		return -1;

	dmi_table(buf, dmi_len, dmi_num, decode);

	dmi_iounmap(buf, dmi_len);
	return 0;
}

static int __init dmi_checksum(u8 *buf)
{
	u8 sum = 0;
	int a;

	for (a = 0; a < 15; a++)
		sum += buf[a];

	return sum == 0;
}

static char *dmi_ident[DMI_STRING_MAX];
static LIST_HEAD(dmi_devices);
int dmi_available;

/*
 *	Save a DMI string
 */
static void __init dmi_save_ident(const struct dmi_header *dm, int slot, int string)
{
	char *p, *d = (char*) dm;

	if (dmi_ident[slot])
		return;

	p = dmi_string(dm, d[string]);
	if (p == NULL)
		return;

	dmi_ident[slot] = p;
}

static void __init dmi_save_devices(const struct dmi_header *dm)
{
	int i, count = (dm->length - sizeof(struct dmi_header)) / 2;
	struct dmi_device *dev;

	for (i = 0; i < count; i++) {
		char *d = (char *)(dm + 1) + (i * 2);

		/* Skip disabled device */
		if ((*d & 0x80) == 0)
			continue;

		dev = dmi_alloc(sizeof(*dev));
		if (!dev) {
			printk(KERN_ERR "dmi_save_devices: out of memory.\n");
			break;
		}

		dev->type = *d++ & 0x7f;
		dev->name = dmi_string(dm, *d);
		dev->device_data = NULL;

		list_add(&dev->list, &dmi_devices);
	}
}

static void __init dmi_save_oem_strings_devices(const struct dmi_header *dm)
{
	int i, count = *(u8 *)(dm + 1);
	struct dmi_device *dev;

	for (i = 1; i <= count; i++) {
		dev = dmi_alloc(sizeof(*dev));
		if (!dev) {
			printk(KERN_ERR
			   "dmi_save_oem_strings_devices: out of memory.\n");
			break;
		}

		dev->type = DMI_DEV_TYPE_OEM_STRING;
		dev->name = dmi_string(dm, i);
		dev->device_data = NULL;

		list_add(&dev->list, &dmi_devices);
	}
}

static void __init dmi_save_ipmi_device(const struct dmi_header *dm)
{
	struct dmi_device *dev;
	void * data;
#ifdef CONFIG_X86
	extern unsigned int ipmi_dev_order;
#endif

	data = dmi_alloc(dm->length);
	if (data == NULL) {
		printk(KERN_ERR "dmi_save_ipmi_device: out of memory.\n");
		return;
	}

	memcpy(data, dm, dm->length);

	dev = dmi_alloc(sizeof(*dev));
	if (!dev) {
		printk(KERN_ERR "dmi_save_ipmi_device: out of memory.\n");
		return;
	}

	dev->type = DMI_DEV_TYPE_IPMI;
	dev->name = "IPMI controller";
	dev->device_data = data;

#ifdef CONFIG_X86
	switch(ipmi_dev_order) {
	case 2:		/* FIFO */
	  list_add_tail(&dev->list, &dmi_devices);
	  break;
	default:	/* LIFO */
#endif
	  list_add(&dev->list, &dmi_devices);
#ifdef CONFIG_X86
	  break;
	}
#endif

}

/*
 *	Process a DMI table entry. Right now all we care about are the BIOS
 *	and machine entries. For 2.5 we should pull the smbus controller info
 *	out of here.
 */
static void __init dmi_decode(const struct dmi_header *dm)
{
	switch(dm->type) {
	case 0:		/* BIOS Information */
		dmi_save_ident(dm, DMI_BIOS_VENDOR, 4);
		dmi_save_ident(dm, DMI_BIOS_VERSION, 5);
		dmi_save_ident(dm, DMI_BIOS_DATE, 8);
		break;
	case 1:		/* System Information */
		dmi_save_ident(dm, DMI_SYS_VENDOR, 4);
		dmi_save_ident(dm, DMI_PRODUCT_NAME, 5);
		dmi_save_ident(dm, DMI_PRODUCT_VERSION, 6);
		dmi_save_ident(dm, DMI_PRODUCT_SERIAL, 7);
		break;
	case 2:		/* Base Board Information */
		dmi_save_ident(dm, DMI_BOARD_VENDOR, 4);
		dmi_save_ident(dm, DMI_BOARD_NAME, 5);
		dmi_save_ident(dm, DMI_BOARD_VERSION, 6);
		break;
	case 10:	/* Onboard Devices Information */
		dmi_save_devices(dm);
		break;
	case 11:	/* OEM Strings */
		dmi_save_oem_strings_devices(dm);
		break;
	case 38:	/* IPMI Device Information */
		dmi_save_ipmi_device(dm);
	}
}

static void __init print_filtered(const char *info)
{
	const char *p;

	if (!info)
		return;

	for (p = info; *p; p++)
		if (isprint(*p))
			printk(KERN_CONT "%c", *p);
		else
			printk(KERN_CONT "\\x%02x", *p & 0xff);
}

static void __init dmi_dump_ids(void)
{
	const char *board;	/* Board Name is optional */

	printk(KERN_DEBUG "DMI: ");
	print_filtered(dmi_get_system_info(DMI_SYS_VENDOR));
	printk(KERN_CONT " ");
	print_filtered(dmi_get_system_info(DMI_PRODUCT_NAME));
	board = dmi_get_system_info(DMI_BOARD_NAME);
	if (board) {
		printk(KERN_CONT "/");
		print_filtered(board);
	}
	printk(KERN_CONT ", BIOS ");
	print_filtered(dmi_get_system_info(DMI_BIOS_VERSION));
	printk(KERN_CONT " ");
	print_filtered(dmi_get_system_info(DMI_BIOS_DATE));
	printk(KERN_CONT "\n");
}

static int __init dmi_present(char __iomem *p)
{
	u8 buf[15];
	memcpy_fromio(buf, p, 15);
	if ((memcmp(buf, "_DMI_", 5) == 0) && dmi_checksum(buf)) {
		dmi_num = (buf[13] << 8) | buf[12];
		dmi_len = (buf[7] << 8) | buf[6];
		dmi_base = (buf[11] << 24) | (buf[10] << 16) |
			(buf[9] << 8) | buf[8];

		/*
		 * DMI version 0.0 means that the real version is taken from
		 * the SMBIOS version, which we don't know at this point.
		 */
		if (buf[14] != 0)
			printk(KERN_INFO "DMI %d.%d present.\n",
			       buf[14] >> 4, buf[14] & 0xF);
		else
			printk(KERN_INFO "DMI present.\n");
		if (dmi_walk_early(dmi_decode) == 0) {
			dmi_dump_ids();
			return 0;
		}
	}
	return 1;
}

void __init dmi_scan_machine(void)
{
	char __iomem *p, *q;
	int rc;

	if (efi_enabled) {
		if (efi.smbios == EFI_INVALID_TABLE_ADDR)
			goto out;

               /* This is called as a core_initcall() because it isn't
                * needed during early boot.  This also means we can
                * iounmap the space when we're done with it.
		*/
		p = dmi_ioremap(efi.smbios, 32);
		if (p == NULL)
			goto out;

		rc = dmi_present(p + 0x10); /* offset of _DMI_ string */
		dmi_iounmap(p, 32);
		if (!rc) {
			dmi_available = 1;
			return;
		}
	}
	else {
		/*
		 * no iounmap() for that ioremap(); it would be a no-op, but
		 * it's so early in setup that sucker gets confused into doing
		 * what it shouldn't if we actually call it.
		 */
		p = dmi_ioremap(0xF0000, 0x10000);
		if (p == NULL)
			goto out;

		for (q = p; q < p + 0x10000; q += 16) {
			rc = dmi_present(q);
			if (!rc) {
				dmi_available = 1;
				return;
			}
		}
	}
 out:	printk(KERN_INFO "DMI not present or invalid.\n");
}

/**
 *	dmi_check_system - check system DMI data
 *	@list: array of dmi_system_id structures to match against
 *		All non-null elements of the list must match
 *		their slot's (field index's) data (i.e., each
 *		list string must be a substring of the specified
 *		DMI slot's string data) to be considered a
 *		successful match.
 *
 *	Walk the blacklist table running matching functions until someone
 *	returns non zero or we hit the end. Callback function is called for
 *	each successful match. Returns the number of matches.
 */
int dmi_check_system(struct dmi_system_id *list)
{
	int i, count = 0;
	struct dmi_system_id *d = list;

	while (d->ident) {
		for (i = 0; i < ARRAY_SIZE(d->matches); i++) {
			int s = d->matches[i].slot;
			if (s == DMI_NONE)
				continue;
			if (dmi_ident[s] && strstr(dmi_ident[s], d->matches[i].substr))
				continue;
			/* No match */
			goto fail;
		}
		count++;
		if (d->callback && d->callback(d))
			break;
fail:		d++;
	}

	return count;
}
EXPORT_SYMBOL(dmi_check_system);

/**
 *	dmi_get_system_info - return DMI data value
 *	@field: data index (see enum dmi_field)
 *
 *	Returns one DMI data value, can be used to perform
 *	complex DMI data checks.
 */
char *dmi_get_system_info(int field)
{
	return dmi_ident[field];
}
EXPORT_SYMBOL(dmi_get_system_info);

/**
 * dmi_name_in_serial - Check if string is in the DMI product serial information
 * @str: string to check for
 */
int dmi_name_in_serial(const char *str)
{
	int f = DMI_PRODUCT_SERIAL;
	if (dmi_ident[f] && strstr(dmi_ident[f], str))
		return 1;
	return 0;
}

/**
 *	dmi_name_in_vendors - Check if string is anywhere in the DMI vendor information.
 *	@str: 	Case sensitive Name
 */
int dmi_name_in_vendors(char *str)
{
	static int fields[] = { DMI_BIOS_VENDOR, DMI_BIOS_VERSION, DMI_SYS_VENDOR,
				DMI_PRODUCT_NAME, DMI_PRODUCT_VERSION, DMI_BOARD_VENDOR,
				DMI_BOARD_NAME, DMI_BOARD_VERSION, DMI_NONE };
	int i;
	for (i = 0; fields[i] != DMI_NONE; i++) {
		int f = fields[i];
		if (dmi_ident[f] && strstr(dmi_ident[f], str))
			return 1;
	}
	return 0;
}
EXPORT_SYMBOL(dmi_name_in_vendors);

/**
 *	dmi_find_device - find onboard device by type/name
 *	@type: device type or %DMI_DEV_TYPE_ANY to match all device types
 *	@name: device name string or %NULL to match all
 *	@from: previous device found in search, or %NULL for new search.
 *
 *	Iterates through the list of known onboard devices. If a device is
 *	found with a matching @vendor and @device, a pointer to its device
 *	structure is returned.  Otherwise, %NULL is returned.
 *	A new search is initiated by passing %NULL as the @from argument.
 *	If @from is not %NULL, searches continue from next device.
 */
struct dmi_device * dmi_find_device(int type, const char *name,
				    struct dmi_device *from)
{
	struct list_head *d, *head = from ? &from->list : &dmi_devices;

	for(d = head->next; d != &dmi_devices; d = d->next) {
		struct dmi_device *dev = list_entry(d, struct dmi_device, list);

		if (((type == DMI_DEV_TYPE_ANY) || (dev->type == type)) &&
		    ((name == NULL) || (strcmp(dev->name, name) == 0)))
			return dev;
	}

	return NULL;
}
EXPORT_SYMBOL(dmi_find_device);

/**
 *	dmi_get_year - Return year of a DMI date
 *	@field:	data index (like dmi_get_system_info)
 *
 *	Returns -1 when the field doesn't exist. 0 when it is broken.
 */
int dmi_get_year(int field)
{
	int year;
	char *s = dmi_get_system_info(field);

	if (!s)
		return -1;
	if (*s == '\0')
		return 0;
	s = strrchr(s, '/');
	if (!s)
		return 0;

	s += 1;
	year = simple_strtoul(s, NULL, 0);
	if (year && year < 100) {	/* 2-digit year */
		year += 1900;
		if (year < 1996)	/* no dates < spec 1.0 */
			year += 100;
	}

	return year;
}

/**
 *	dmi_walk - Walk the DMI table and get called back for every record
 *	@decode: Callback function
 *
 *	Returns -1 when the DMI table can't be reached, 0 on success.
 */
int dmi_walk(void (*decode)(const struct dmi_header *))
{
	u8 *buf;

	if (!dmi_available)
		return -1;

	buf = ioremap(dmi_base, dmi_len);
	if (buf == NULL)
		return -1;

	dmi_table(buf, dmi_len, dmi_num, decode);

	iounmap(buf);
	return 0;
}
EXPORT_SYMBOL_GPL(dmi_walk);
