#ifndef __WIRELESS_COMPAT_H__
#define __WIRELESS_COMPAT_H__

#define BIT(nr)			(1UL << (nr))

extern int dev_set_name(struct device *dev, const char *fmt, ...);

/*
 *      We tag multicasts with these structures.
 */

#define dev_addr_list	dev_mc_list
#define da_addr        dmi_addr
#define da_addrlen     dmi_addrlen
#define da_users       dmi_users
#define da_gusers      dmi_gusers

extern void	dev_mc_unsync(struct net_device *to, struct net_device *from);
extern int	dev_mc_sync(struct net_device *to, struct net_device *from);

extern void	__dev_set_rx_mode(struct net_device *dev);

#ifndef __maybe_unused
#define __maybe_unused
#endif

#ifndef uninitialized_var
#define uninitialized_var(x)	x = x
#endif

#ifndef netdev_tx_t
#define netdev_tx_t	int
#endif

#define get_unaligned_le16(x)	le16_to_cpu(get_unaligned(x))
#define get_unaligned_le32(x)	le32_to_cpu(get_unaligned(x))

#define netif_tx_start_all_queues(x)	netif_start_queue(x)
#define netif_tx_stop_all_queues(x)	netif_stop_queue(x)

/* New link list changes added as of 2.6.27, needed for ath9k */

static inline void __list_cut_position(struct list_head *list,
		struct list_head *head, struct list_head *entry)
{
	struct list_head *new_first = entry->next;
	list->next = head->next;
	list->next->prev = list;
	list->prev = entry;
	entry->next = list;
	head->next = new_first;
	new_first->prev = head;
}

/**
 * list_cut_position - cut a list into two
 * @list: a new list to add all removed entries
 * @head: a list with entries
 * @entry: an entry within head, could be the head itself
 *	and if so we won't cut the list
 *
 * This helper moves the initial part of @head, up to and
 * including @entry, from @head to @list. You should
 * pass on @entry an element you know is on @head. @list
 * should be an empty list or a list you do not care about
 * losing its data.
 *
 */
static inline void list_cut_position(struct list_head *list,
		struct list_head *head, struct list_head *entry)
{
	if (list_empty(head))
		return;
	if (list_is_singular(head) &&
		(head->next != entry && head != entry))
		return;
	if (entry == head)
		INIT_LIST_HEAD(list);
	else
		__list_cut_position(list, head, entry);
}


/* __list_splice as re-implemented on 2.6.27, we backport it */
static inline void __compat_list_splice_new_27(const struct list_head *list,
				 struct list_head *prev,
				 struct list_head *next)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

/**
 * list_splice_tail - join two lists, each list being a queue
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void list_splice_tail(struct list_head *list,
				struct list_head *head)
{
	if (!list_empty(list))
		__compat_list_splice_new_27(list, head->prev, head);
}

/**
 * list_splice_tail_init - join two lists and reinitialise the emptied list
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * Each of the lists is a queue.
 * The list at @list is reinitialised
 */
static inline void list_splice_tail_init(struct list_head *list,
					 struct list_head *head)
{
	if (!list_empty(list)) {
		__compat_list_splice_new_27(list, head->prev, head);
		INIT_LIST_HEAD(list);
	}
}

#endif /* __WIRELESS_COMPAT_H__ */
