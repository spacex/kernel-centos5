#include <linux/kernel.h>
#include <linux/module.h>
#include <net/neighbour.h>

MODULE_AUTHOR("Eli Cohen");
MODULE_DESCRIPTION("container for ipoib neighbour destructor");
MODULE_LICENSE("Dual BSD/GPL");

DEFINE_SPINLOCK(spl);
static int busy;

static void (*cleanup_func)(struct neighbour *n);

static int ipoib_set_cleanup_function(void (*func)(struct neighbour *n))
{
	unsigned long flags;

	spin_lock_irqsave(&spl, flags);
	if (busy) {
		spin_unlock_irqrestore(&spl, flags);
		return -EBUSY;
	}
	cleanup_func = func;
	spin_unlock_irqrestore(&spl, flags);

	return 0;
}

static void ipoib_neigh_cleanup_container(struct neighbour *n)
{
	unsigned long flags;

	spin_lock_irqsave(&spl, flags);
	busy = 1;
	spin_unlock_irqrestore(&spl, flags);
	if (cleanup_func)
		cleanup_func(n);

	spin_lock_irqsave(&spl, flags);
	busy = 0;
	spin_unlock_irqrestore(&spl, flags);
}


EXPORT_SYMBOL(ipoib_set_cleanup_function);
EXPORT_SYMBOL(ipoib_neigh_cleanup_container);


static int __init ipoib_helper_init(void)
{
	if (!try_module_get(THIS_MODULE))
		return -1;

	return 0;
}


static void __exit ipoib_helper_cleanup(void)
{
}

module_init(ipoib_helper_init);
module_exit(ipoib_helper_cleanup);
