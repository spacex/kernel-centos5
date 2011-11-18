/*
 * This can be used throughout hardware code to indicate that the hardware
 * is unsupported in RHEL6.
 */
#include <linux/kernel.h>
#include <linux/module.h>

/* Mark parts of the kernel as 'Tech Preview', to make it clear to our 
 * support organization and customers what we do not fully support yet.
 * NOTE: this will TAINT the kernel to signify the machine is running
 * code that is not fully supported.  Use with caution.
 */
#ifdef CONFIG_MODULES
void mark_tech_preview(const char *msg, struct module *mod)
{
	const char *str = NULL;

	if (msg)
		str = msg;
	else if (mod && mod->name)
		str = mod->name;

	pr_warning("TECH PREVIEW: %s may not be fully supported.\n"
		   "Please review provided documentation for limitations.\n",
		   (str ? str : "kernel"));
	add_taint(TAINT_TECH_PREVIEW);
	if (mod)
        	mod->license_gplok |= TAINT_TECH_PREVIEW;
}
#else
/*
 * kernels that don't configure module support are not interesting enough to
 * be tainted.
 */
void mark_tech_preview(const char *msg, struct module *mod)
{
	return;
}
#endif
EXPORT_SYMBOL(mark_tech_preview);
