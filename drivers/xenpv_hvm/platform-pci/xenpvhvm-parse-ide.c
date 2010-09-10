/*
 * boot-time parse of kernel args so
 * hacky xen config of had-boot device
 * attached to xen-vbd can be done
 *
 * Need to do this at kernel boot time,
 * or can't scan ide kernel args
 */
 /*
 * xen_ide_cmdline_check_setup() gets called VERY EARLY during initialization,
 * to scan kernel "command line" strings beginning with "ide0=noprobe" 
 * or "ide=disable".
 *
 * Note: always return 0, so as not to indicate consumption of cmdline,
 *       enabling ide subsystem to receive & parse it.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>

int xenpv_notify_ide_disable = 0;

int __init xen_ide_cmdline_check_setup(char *s)
{

        /*
         * only look at cmdline args starting with 'ide'
         */
        if (strncmp(s, "ide", 3))
                return 0;

/*      printk(KERN_DEBUG "XENBUS: xen_ide_cmdline_check_setup: %s \n", s);  */

        /* assume disable */
        xenpv_notify_ide_disable=1;
        if (strncmp(s, "ide=disable", 11) == 0) {
                printk(KERN_INFO "drivers/ide subsystem to be disabled ");
                printk("-- skipping xvd_dev_shutdown()\n");
                return 0;
        }

        if (strncmp(s, "ide0=noprobe", 12) == 0) {
                printk(KERN_INFO "ide0 not going to be probed ");
                printk("-- skipping xvd_dev_shutdown()\n");
                return 0;
        }
        /* re-enable xvd_dev_shutdown if ide isn't disabled */
        xenpv_notify_ide_disable=0;
/*      printk(KERN_DEBUG " -- xvd_dev_shutdown to be exec'd \n"); */

        return 0;
}

/* scan entire kernel cmdline, as ide subys does */
__setup("", xen_ide_cmdline_check_setup);

EXPORT_SYMBOL_GPL(xenpv_notify_ide_disable);
