/*
 *  drivers/s390/sysinfo.c
 *
 *    Copyright (C) 2001 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *    Author(s): Ulrich Weigand (Ulrich.Weigand@de.ibm.com)
 *	         Martin Schwidefsky <schwidefsky@de.ibm.com>
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <asm/ebcdic.h>
#include <asm/sysinfo.h>
#include <asm/cpcmd.h>

static inline int stsi_0(void)
{
	int rc = stsi (NULL, 0, 0, 0);
	return rc == -ENOSYS ? rc : (((unsigned int) rc) >> 28);
}

static int stsi_1_1_1(struct sysinfo_1_1_1 *info, char *page, int len)
{
	if (stsi(info, 1, 1, 1) == -ENOSYS)
		return len;

	EBCASC(info->manufacturer, sizeof(info->manufacturer));
	EBCASC(info->type, sizeof(info->type));
	EBCASC(info->model, sizeof(info->model));
	EBCASC(info->sequence, sizeof(info->sequence));
	EBCASC(info->plant, sizeof(info->plant));
	EBCASC(info->model_capacity, sizeof(info->model_capacity));
	EBCASC(info->model_perm_cap, sizeof(info->model_perm_cap));
	EBCASC(info->model_temp_cap, sizeof(info->model_temp_cap));
	len += sprintf(page + len, "Manufacturer:         %-16.16s\n",
		       info->manufacturer);
	len += sprintf(page + len, "Type:                 %-4.4s\n",
		       info->type);
	if (info->model[0] != '\0')
		/*
		 * Sigh: the model field has been renamed with System z9
		 * to model_capacity and a new model field has been added
		 * after the plant field. To avoid confusing older programs
		 * the "Model:" prints "model_capacity model" or just
		 * "model_capacity" if the model string is empty .
		 */
		len += sprintf(page + len,
			       "Model:                %-16.16s %-16.16s\n",
			       info->model_capacity, info->model);
	else
		len += sprintf(page + len, "Model:                %-16.16s\n",
			       info->model_capacity);
	len += sprintf(page + len, "Sequence Code:        %-16.16s\n",
		       info->sequence);
	len += sprintf(page + len, "Plant:                %-4.4s\n",
		       info->plant);
	len += sprintf(page + len, "Model Capacity:       %-16.16s %08u\n",
		       info->model_capacity, *(u32 *) info->model_cap_rating);
	if (info->model_perm_cap[0] != '\0')
		len += sprintf(page + len,
			       "Model Perm. Capacity: %-16.16s %08u\n",
			       info->model_perm_cap,
			       *(u32 *) info->model_perm_cap_rating);
	if (info->model_temp_cap[0] != '\0')
		len += sprintf(page + len,
			       "Model Temp. Capacity: %-16.16s %08u\n",
			       info->model_temp_cap,
			       *(u32 *) info->model_temp_cap_rating);
	return len;
}

#if 0 /* Currently unused */
static int stsi_1_2_1(struct sysinfo_1_2_1 *info, char *page, int len)
{
	if (stsi(info, 1, 2, 1) == -ENOSYS)
		return len;

	len += sprintf(page + len, "\n");
	EBCASC(info->sequence, sizeof(info->sequence));
	EBCASC(info->plant, sizeof(info->plant));
	len += sprintf(page + len, "Sequence Code of CPU: %-16.16s\n",
		       info->sequence);
	len += sprintf(page + len, "Plant of CPU:         %-16.16s\n",
		       info->plant);
	return len;
}
#endif

static int stsi_1_2_2(struct sysinfo_1_2_2 *info, char *page, int len)
{
	struct sysinfo_1_2_2_extension *ext;
	int i;

	if (stsi(info, 1, 2, 2) == -ENOSYS)
		return len;
	ext = (struct sysinfo_1_2_2_extension *)
		((unsigned long) info + info->acc_offset);

	len += sprintf(page + len, "\n");
	len += sprintf(page + len, "CPUs Total:           %d\n",
		       info->cpus_total);
	len += sprintf(page + len, "CPUs Configured:      %d\n",
		       info->cpus_configured);
	len += sprintf(page + len, "CPUs Standby:         %d\n",
		       info->cpus_standby);
	len += sprintf(page + len, "CPUs Reserved:        %d\n",
		       info->cpus_reserved);

	if (info->format == 1) {
		/*
		 * Sigh 2. According to the specification the alternate
		 * capability field is a 32 bit floating point number
		 * if the higher order 8 bits are not zero. Printing
		 * a floating point number in the kernel is a no-no,
		 * always print the number as 32 bit unsigned integer.
		 * The user-space needs to know about the stange
		 * encoding of the alternate cpu capability.
		 */
		len += sprintf(page + len, "Capability:           %u %u\n",
			       info->capability, ext->alt_capability);
		for (i = 2; i <= info->cpus_total; i++)
			len += sprintf(page + len,
				       "Adjustment %02d-way:    %u %u\n",
				       i, info->adjustment[i-2],
				       ext->alt_adjustment[i-2]);

	} else {
		len += sprintf(page + len, "Capability:           %u\n",
			       info->capability);
		for (i = 2; i <= info->cpus_total; i++)
			len += sprintf(page + len,
				       "Adjustment %02d-way:    %u\n",
				       i, info->adjustment[i-2]);
	}

	if (info->secondary_capability != 0)
		len += sprintf(page + len, "Secondary Capability: %d\n",
			       info->secondary_capability);

	return len;
}

#if 0 /* Currently unused */
static int stsi_2_2_1(struct sysinfo_2_2_1 *info, char *page, int len)
{
	if (stsi(info, 2, 2, 1) == -ENOSYS)
		return len;

	len += sprintf(page + len, "\n");
	EBCASC (info->sequence, sizeof(info->sequence));
	EBCASC (info->plant, sizeof(info->plant));
	len += sprintf(page + len, "Sequence Code of logical CPU: %-16.16s\n",
		       info->sequence);
	len += sprintf(page + len, "Plant of logical CPU: %-16.16s\n",
		       info->plant);
	return len;
}
#endif

static int stsi_2_2_2(struct sysinfo_2_2_2 *info, char *page, int len)
{
	if (stsi(info, 2, 2, 2) == -ENOSYS)
		return len;

	EBCASC (info->name, sizeof(info->name));

	len += sprintf(page + len, "\n");
	len += sprintf(page + len, "LPAR Number:          %d\n",
		       info->lpar_number);

	len += sprintf(page + len, "LPAR Characteristics: ");
	if (info->characteristics & LPAR_CHAR_DEDICATED)
		len += sprintf(page + len, "Dedicated ");
	if (info->characteristics & LPAR_CHAR_SHARED)
		len += sprintf(page + len, "Shared ");
	if (info->characteristics & LPAR_CHAR_LIMITED)
		len += sprintf(page + len, "Limited ");
	len += sprintf(page + len, "\n");

	len += sprintf(page + len, "LPAR Name:            %-8.8s\n",
		       info->name);

	len += sprintf(page + len, "LPAR Adjustment:      %d\n",
		       info->caf);

	len += sprintf(page + len, "LPAR CPUs Total:      %d\n",
		       info->cpus_total);
	len += sprintf(page + len, "LPAR CPUs Configured: %d\n",
		       info->cpus_configured);
	len += sprintf(page + len, "LPAR CPUs Standby:    %d\n",
		       info->cpus_standby);
	len += sprintf(page + len, "LPAR CPUs Reserved:   %d\n",
		       info->cpus_reserved);
	len += sprintf(page + len, "LPAR CPUs Dedicated:  %d\n",
		       info->cpus_dedicated);
	len += sprintf(page + len, "LPAR CPUs Shared:     %d\n",
		       info->cpus_shared);
	return len;
}

static int stsi_3_2_2(struct sysinfo_3_2_2 *info, char *page, int len)
{
	int i;

	if (stsi(info, 3, 2, 2) == -ENOSYS)
		return len;
	for (i = 0; i < info->count; i++) {
		EBCASC (info->vm[i].name, sizeof(info->vm[i].name));
		EBCASC (info->vm[i].cpi, sizeof(info->vm[i].cpi));
		len += sprintf(page + len, "\n");
		len += sprintf(page + len, "VM%02d Name:            %-8.8s\n",
			       i, info->vm[i].name);
		len += sprintf(page + len, "VM%02d Control Program: %-16.16s\n",
			       i, info->vm[i].cpi);

		len += sprintf(page + len, "VM%02d Adjustment:      %d\n",
			       i, info->vm[i].caf);

		len += sprintf(page + len, "VM%02d CPUs Total:      %d\n",
			       i, info->vm[i].cpus_total);
		len += sprintf(page + len, "VM%02d CPUs Configured: %d\n",
			       i, info->vm[i].cpus_configured);
		len += sprintf(page + len, "VM%02d CPUs Standby:    %d\n",
			       i, info->vm[i].cpus_standby);
		len += sprintf(page + len, "VM%02d CPUs Reserved:   %d\n",
			       i, info->vm[i].cpus_reserved);
	}
	return len;
}


static int proc_read_sysinfo(char *page, char **start,
                             off_t off, int count,
                             int *eof, void *data)
{
	unsigned long info = get_zeroed_page (GFP_KERNEL);
	int level, len;
	
	if (!info)
		return 0;

	len = 0;
	level = stsi_0();
	if (level >= 1)
		len = stsi_1_1_1((struct sysinfo_1_1_1 *) info, page, len);

	if (level >= 1)
		len = stsi_1_2_2((struct sysinfo_1_2_2 *) info, page, len);

	if (level >= 2)
		len = stsi_2_2_2((struct sysinfo_2_2_2 *) info, page, len);

	if (level >= 3)
		len = stsi_3_2_2((struct sysinfo_3_2_2 *) info, page, len);

	free_page (info);
        return len;
}

static __init int create_proc_sysinfo(void)
{
	create_proc_read_entry("sysinfo", 0444, NULL,
			       proc_read_sysinfo, NULL);
	return 0;
}

__initcall(create_proc_sysinfo);

int get_cpu_capability(unsigned int *capability)
{
	struct sysinfo_1_2_2 *info;
	int rc;

	info = (void *) get_zeroed_page(GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	rc = stsi(info, 1, 2, 2);
	if (rc == -ENOSYS)
		goto out;
	rc = 0;
	*capability = info->capability;
out:
	free_page((unsigned long) info);
	return rc;
}

/*
 * Service levels interface.
 */

static DECLARE_RWSEM(service_level_sem);
static LIST_HEAD(service_level_list);

int register_service_level(struct service_level *slr)
{
	struct service_level *ptr;

	down_write(&service_level_sem);
	list_for_each_entry(ptr, &service_level_list, list)
		if (ptr == slr) {
			up_write(&service_level_sem);
			return -EEXIST;
		}
	list_add_tail(&slr->list, &service_level_list);
	up_write(&service_level_sem);
	return 0;
}
EXPORT_SYMBOL(register_service_level);

int unregister_service_level(struct service_level *slr)
{
	struct service_level *ptr, *next;
	int rc = -ENOENT;

	down_write(&service_level_sem);
	list_for_each_entry_safe(ptr, next, &service_level_list, list) {
		if (ptr != slr)
			continue;
		list_del(&ptr->list);
		rc = 0;
		break;
	}
	up_write(&service_level_sem);
	return rc;
}
EXPORT_SYMBOL(unregister_service_level);

static void *service_level_start(struct seq_file *m, loff_t *pos)
{
	struct list_head *lh;
	loff_t off = *pos;

	down_read(&service_level_sem);
	list_for_each(lh, &service_level_list)
		if (off-- == 0)
			return lh;
	return NULL;
}

static void *service_level_next(struct seq_file *m, void *p, loff_t *pos)
{
	struct list_head *lh;

	lh = ((struct list_head *) p)->next;
	++*pos;
	return lh == &service_level_list ? NULL : lh;
}

static void service_level_stop(struct seq_file *m, void *p)
{
	up_read(&service_level_sem);
}

static int service_level_show(struct seq_file *m, void *p)
{
	struct service_level *slr;

	slr = list_entry(p, struct service_level, list);
	slr->seq_print(m, slr);
	return 0;
}

static struct seq_operations service_level_seq_ops = {
	.start		= service_level_start,
	.next		= service_level_next,
	.stop		= service_level_stop,
	.show		= service_level_show
};

static int service_level_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &service_level_seq_ops);
}

static struct file_operations service_level_ops = {
	.open           = service_level_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release
};

static void service_level_vm_print(struct seq_file *m,
				   struct service_level *slr)
{
	char *query_buffer, *str;

	query_buffer = kmalloc(1024, GFP_KERNEL | GFP_DMA);
	if (!query_buffer)
		return;
	cpcmd("QUERY CPLEVEL", query_buffer, 1024, NULL);
	str = strchr(query_buffer, '\n');
	if (str)
		*str = 0;
	seq_printf(m, "VM: %s\n", query_buffer);
	kfree(query_buffer);
}

static struct service_level service_level_vm = {
	.seq_print = service_level_vm_print
};

static struct proc_dir_entry *service_levels_entry = NULL;

static __init int create_proc_service_level(void)
{
	service_levels_entry = create_proc_entry("service_levels", 0444,
						 &proc_root);
	if (service_levels_entry) {
		service_levels_entry->proc_fops = &service_level_ops;
		service_levels_entry->owner = THIS_MODULE;
	}
	if (MACHINE_IS_VM)
		register_service_level(&service_level_vm);
	return 0;
}

subsys_initcall(create_proc_service_level);
