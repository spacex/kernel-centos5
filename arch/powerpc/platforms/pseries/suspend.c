/*
  * Copyright (C) 2010 Brian King IBM Corporation
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation; either version 2 of the License, or
  * (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
  */

#include <linux/capability.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/pm.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/sysdev.h>
#include <asm/firmware.h>
#include <asm/hvcall.h>
#include <asm/machdep.h>
#include <asm/mmu.h>
#include <asm/rtas.h>
#include <asm/time.h>

#include "offline_states.h"

static u64 stream_id;
static struct sys_device suspend_sysdev;
static DEFINE_MUTEX(suspend_lock);
static struct rtas_suspend_me_data suspend_data;
static struct rtas_args suspend_args;
static int suspending;

/**
 * pseries_suspend_begin - First phase of hibernation
 *
 * Check to ensure we are in a valid state to hibernate
 *
 * Return value:
 * 	0 on success / other on failure
 **/
static int pseries_suspend_begin(void)
{
	long vasi_state, rc;
	unsigned long dummy;

	/* Make sure the state is valid */
	rc = plpar_hcall(H_VASI_STATE, stream_id, 0, 0, 0, &vasi_state, &dummy, &dummy);

	if (rc) {
		printk(KERN_ERR "pseries_suspend_begin: vasi_state returned %ld\n",rc);
		return rc;
	} else if (vasi_state == H_VASI_ENABLED) {
		return -EAGAIN;
	} else if (vasi_state != H_VASI_SUSPENDING) {
		printk(KERN_ERR "pseries_suspend_begin: vasi_state returned state %ld\n",
		       vasi_state);
		return -EIO;
	}

	return 0;
}

/**
 * pseries_suspend_enter - Final phase of hibernation
 *
 * Return value:
 * 	0 on success / other on failure
 **/
static int pseries_suspend_enter(suspend_state_t state)
{
	return rtas_suspend_last_cpu(&suspend_data);
}

/**
 * pseries_suspend_cpu - Join a single hardware thread
 *
 **/
void pseries_suspend_cpu(void)
{
	if (suspending) {
		smp_rmb();
		rtas_suspend_cpu(&suspend_data);
	}
}

/**
 * pseries_suspend_prepare - Prepare for a suspend
 *
 * This function joins all hardware threads to a single thread
 *
 * Return value:
 * 	0 if success / other on failure
 **/
static int pseries_suspend_prepare(suspend_state_t state)
{
	if (!suspending) {
		smp_rmb();
		return -EINVAL;
	}

	return pseries_suspend_begin();
}

/**
 * pseries_suspend_valid - Only suspend to RAM is supported
 *
 * Return value:
 * 	1 if valid / other if invalid
 **/
static int pseries_suspend_valid(suspend_state_t state)
{
	if (state == PM_SUSPEND_MEM)
		return 1;

	return 0;
}

/**
 * store_hibernate - Initiate partition hibernation
 * @classdev:	sysdev class struct
 * @buf:		buffer
 * @count:		buffer size
 *
 * Write the stream ID received from the HMC to this file
 * to trigger hibernating the partition
 *
 * Return value:
 * 	number of bytes printed to buffer / other on failure
 **/
static ssize_t store_hibernate(struct sysdev_class *classdev,
			       const char *buf, size_t count)
{
	int rc;
	unsigned int cpu;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	mutex_lock(&suspend_lock);
	stream_id = simple_strtoul(buf, NULL, 16);

	do {
		rc = pseries_suspend_begin();
		if (rc == -EAGAIN)
			ssleep(1);
	} while (rc == -EAGAIN);

	if (!rc) {
		memset(&suspend_args, 0, sizeof(suspend_args));
		rtas_suspend_me_data_init(&suspend_data, &suspend_args);
		suspending = 1;
		for_each_online_cpu(cpu)
			if (cpu)
				set_preferred_offline_state(cpu, CPU_STATE_INACTIVE);

		smp_wmb();

		rc = pm_suspend(PM_SUSPEND_MEM);
		suspending = 0;
		smp_wmb();
	}

	stream_id = 0;
	mutex_unlock(&suspend_lock);

	if (!rc)
		rc = count;
	return rc;
}

static SYSDEV_CLASS_ATTR(hibernate, S_IWUSR, NULL, store_hibernate);

static struct sysdev_class suspend_sysdev_class = {
	set_kset_name("power"),
};

static struct pm_ops pseries_suspend_ops = {
	.valid		= pseries_suspend_valid,
	.prepare		= pseries_suspend_prepare,
	.enter		= pseries_suspend_enter,
};

/**
 * pseries_suspend_sysfs_register - Register with sysfs
 *
 * Return value:
 * 	0 on success / other on failure
 **/
static int pseries_suspend_sysfs_register(struct sys_device *sysdev)
{
	int rc;

	if ((rc = sysdev_class_register(&suspend_sysdev_class)))
		return rc;

	sysdev->id = 0;
	sysdev->cls = &suspend_sysdev_class;

	if ((rc = sysdev_class_create_file(&suspend_sysdev_class, &attr_hibernate)))
		goto class_unregister;

	return 0;

class_unregister:
	sysdev_class_unregister(&suspend_sysdev_class);
	return rc;
}

/**
 * pseries_suspend_init - initcall for pSeries suspend
 *
 * Return value:
 * 	0 on success / other on failure
 **/
static int __init pseries_suspend_init(void)
{
	int rc;

	if (!machine_is(pseries) || !firmware_has_feature(FW_FEATURE_LPAR))
		return 0;

	if (!rtas_service_present("ibm,suspend-me"))
		return 0;

	if ((rc = pseries_suspend_sysfs_register(&suspend_sysdev)))
		return rc;

	pm_set_ops(&pseries_suspend_ops);
	return 0;
}

__initcall(pseries_suspend_init);
