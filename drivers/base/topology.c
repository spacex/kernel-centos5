/*
 * driver/base/topology.c - Populate sysfs with cpu topology information
 *
 * Written by: Zhang Yanmin, Intel Corporation
 *
 * Copyright (C) 2006, Intel Corp.
 *
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#include <linux/sysdev.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/topology.h>

#define define_one_ro_named(_name, _func)				\
static SYSDEV_ATTR(_name, 0444, _func, NULL)

#define define_one_ro(_name)				\
static SYSDEV_ATTR(_name, 0444, show_##_name, NULL)

#define define_id_show_func(name)				\
static ssize_t show_##name(struct sys_device *dev, char *buf)	\
{								\
	unsigned int cpu = dev->id;				\
	return sprintf(buf, "%d\n", topology_##name(cpu));	\
}

static ssize_t show_cpumap(int type, const cpumask_t mask, char *buf)
{
	ptrdiff_t len = PTR_ALIGN(buf + PAGE_SIZE - 1, PAGE_SIZE) - buf;
	int n = 0;

	if (len > 1) {
		n = type?
			cpulist_scnprintf(buf, len-2, mask) :
			cpumask_scnprintf(buf, len-2, mask);
		buf[n++] = '\n';
		buf[n] = '\0';
	}
	return n;
}

#ifdef arch_provides_topology_pointers
#define define_siblings_show_map(name)					\
static ssize_t show_##name(struct sys_device *dev, char *buf)		\
{									\
	unsigned int cpu = dev->id;					\
	return show_cpumap(0, topology_##name(cpu), buf);		\
}

#define define_siblings_show_list(name)					\
static ssize_t show_##name##_list(struct sys_device *dev, char *buf)	\
{									\
	unsigned int cpu = dev->id;					\
	return show_cpumap(1, topology_##name(cpu), buf);		\
}

#else
#define define_siblings_show_map(name)					\
static ssize_t show_##name(struct sys_device *dev, char *buf)		\
{									\
	return show_cpumap(0, topology_##name(dev->id), buf);		\
}

#define define_siblings_show_list(name)					\
static ssize_t show_##name##_list(struct sys_device *dev, char *buf)	\
{									\
	return show_cpumap(1, topology_##name(dev->id), buf);		\
}
#endif

#define define_siblings_show_func(name)		\
	define_siblings_show_map(name); define_siblings_show_list(name)

#ifdef topology_physical_package_id
define_id_show_func(physical_package_id);
define_one_ro(physical_package_id);
#define ref_physical_package_id_attr	&attr_physical_package_id.attr,
#else
#define ref_physical_package_id_attr
#endif

#ifdef topology_core_id
define_id_show_func(core_id);
define_one_ro(core_id);
#define ref_core_id_attr		&attr_core_id.attr,
#else
#define ref_core_id_attr
#endif

#ifdef topology_thread_siblings
define_siblings_show_func(thread_siblings);
define_one_ro(thread_siblings);
define_one_ro(thread_siblings_list);
#define ref_thread_siblings_attr	&attr_thread_siblings.attr,
#define ref_thread_siblings_list_attr	&attr_thread_siblings_list.attr,
#else
#define ref_thread_siblings_attr
#define ref_thread_siblings_list_attr
#endif

#ifdef topology_core_siblings
define_siblings_show_func(core_siblings);
define_one_ro(core_siblings);
define_one_ro(core_siblings_list);
#define ref_core_siblings_attr		&attr_core_siblings.attr,
#define ref_core_siblings_list_attr	&attr_core_siblings_list.attr,
#else
#define ref_core_siblings_attr
#define ref_core_siblings_list_attr
#endif

static struct attribute *default_attrs[] = {
	ref_physical_package_id_attr
	ref_core_id_attr
	ref_thread_siblings_attr
	ref_thread_siblings_list_attr
	ref_core_siblings_attr
	ref_core_siblings_list_attr
	NULL
};

static struct attribute_group topology_attr_group = {
	.attrs = default_attrs,
	.name = "topology"
};

/* Add/Remove cpu_topology interface for CPU device */
static int __cpuinit topology_add_dev(struct sys_device * sys_dev)
{
	sysfs_create_group(&sys_dev->kobj, &topology_attr_group);
	return 0;
}

static int __cpuinit topology_remove_dev(struct sys_device * sys_dev)
{
	sysfs_remove_group(&sys_dev->kobj, &topology_attr_group);
	return 0;
}

static int __cpuinit topology_cpu_callback(struct notifier_block *nfb,
		unsigned long action, void *hcpu)
{
	unsigned int cpu = (unsigned long)hcpu;
	struct sys_device *sys_dev;

	sys_dev = get_cpu_sysdev(cpu);
	switch (action) {
	case CPU_ONLINE:
		topology_add_dev(sys_dev);
		break;
	case CPU_DEAD:
		topology_remove_dev(sys_dev);
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata topology_cpu_notifier =
{
	.notifier_call = topology_cpu_callback,
};

static int __cpuinit topology_sysfs_init(void)
{
	int i;

	for_each_online_cpu(i) {
		topology_cpu_callback(&topology_cpu_notifier, CPU_ONLINE,
				(void *)(long)i);
	}

	register_hotcpu_notifier(&topology_cpu_notifier);

	return 0;
}

device_initcall(topology_sysfs_init);

