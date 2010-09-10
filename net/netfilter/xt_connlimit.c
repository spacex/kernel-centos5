/*
 * netfilter module to limit the number of parallel tcp
 * connections per IP address.
 *   (c) 2000 Gerd Knorr <kraxel@bytesex.org>
 *   Nov 2002: Martin Bene <martin.bene@icomedias.com>:
 *		only ignore TIME_WAIT or gone connections
 *   (C) CC Computer Consultants GmbH, 2007
 *   Contact: <jengelh@computergmbh.de>
 *
 * based on ...
 *
 * Kernel module to match connection tracking information.
 * GPL (C) 1999  Rusty Russell (rusty@rustcorp.com.au).
 */
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_connlimit.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ip_conntrack_core.h>
#include <linux/netfilter_ipv4/ip_conntrack_tuple.h>

/* we will save the tuples of all connections we care about */
struct xt_connlimit_conn {
	struct list_head list;
	struct ip_conntrack_tuple tuple;
};

struct xt_connlimit_data {
	struct list_head iphash[256];
	spinlock_t lock;
};

static u_int32_t connlimit_rnd;
static bool connlimit_rnd_inited;

static inline unsigned int connlimit_iphash(__be32 addr)
{
	if (unlikely(!connlimit_rnd_inited)) {
		get_random_bytes(&connlimit_rnd, sizeof(connlimit_rnd));
		connlimit_rnd_inited = true;
	}
	return jhash_1word((__force __u32)addr, connlimit_rnd) & 0xFF;
}

static inline bool already_closed(const struct ip_conntrack *conn)
{
	u_int16_t proto = conn->tuplehash[0].tuple.dst.protonum;

	if (proto == IPPROTO_TCP)
		return conn->proto.tcp.state == TCP_CONNTRACK_TIME_WAIT ||
		       conn->proto.tcp.state == TCP_CONNTRACK_CLOSE;
	else
		return 0;
}

static inline unsigned int
same_source_net(const __be32 addr, const __be32 mask, const __be32 addr2,
		unsigned int family)
{
	return (addr & mask) == (addr2 & mask);
}

static int count_them(struct xt_connlimit_data *data,
		      const struct ip_conntrack_tuple *tuple, const __be32 addr,
		      const __be32 mask, const struct xt_match *match)
{
	struct ip_conntrack_tuple_hash *found;
	struct xt_connlimit_conn *conn;
	struct xt_connlimit_conn *tmp;
	struct ip_conntrack *found_ct;
	struct list_head *hash;
	bool addit = true;
	int matches = 0;


	hash = &data->iphash[connlimit_iphash(addr & mask)];

	read_lock_bh(&ip_conntrack_lock);

	/* check the saved connections */
	list_for_each_entry_safe(conn, tmp, hash, list) {
		found    = __ip_conntrack_find(&conn->tuple, NULL);
		found_ct = NULL;

		if (found != NULL)
			found_ct = tuplehash_to_ctrack(found);

		if (found_ct != NULL &&
		    ip_ct_tuple_equal(&conn->tuple, tuple) &&
		    !already_closed(found_ct))
			/*
			 * Just to be sure we have it only once in the list.
			 * We should not see tuples twice unless someone hooks
			 * this into a table without "-p tcp --syn".
			 */
			addit = false;

		if (found == NULL) {
			/* this one is gone */
			list_del(&conn->list);
			kfree(conn);
			continue;
		}

		if (already_closed(found_ct)) {
			/*
			 * we do not care about connections which are
			 * closed already -> ditch it
			 */
			list_del(&conn->list);
			kfree(conn);
			continue;
		}

		if (same_source_net(addr, mask, conn->tuple.src.ip,
		    match->family))
			/* same source network -> be counted! */
			++matches;
	}

	read_unlock_bh(&ip_conntrack_lock);

	if (addit) {
		/* save the new connection in our list */
		conn = kzalloc(sizeof(*conn), GFP_ATOMIC);
		if (conn == NULL)
			return -ENOMEM;
		conn->tuple = *tuple;
		list_add(&conn->list, hash);
		++matches;
	}

	return matches;
}

static int
connlimit_mt(const struct sk_buff *skb, const struct net_device *in,
             const struct net_device *out, const struct xt_match *match,
             const void *matchinfo, int offset, unsigned int protoff,
             int *hotdrop)
{
	const struct xt_connlimit_info *info = matchinfo;
	__be32 addr;
	struct ip_conntrack_tuple tuple;
	const struct ip_conntrack_tuple *tuple_ptr = &tuple;
	enum ip_conntrack_info ctinfo;
	const struct ip_conntrack *ct;
	int connections;
	struct iphdr *iph;

	ct = ip_conntrack_get(skb, &ctinfo);
	if (ct != NULL)
		tuple_ptr = &ct->tuplehash[0].tuple;
	else if (!ip_ct_get_tuplepr(skb, skb_network_offset(skb), &tuple))
		goto hotdrop;

	iph = ip_hdr(skb);
	addr = iph->saddr;

	spin_lock_bh(&info->data->lock);
	connections = count_them(info->data, tuple_ptr, addr,
	                         info->mask, match);
	spin_unlock_bh(&info->data->lock);

	if (connections < 0) {
		/* kmalloc failed, drop it entirely */
		*hotdrop = 1;
		return 0;
	}

	return (connections > info->limit) ^ info->inverse;

 hotdrop:
	*hotdrop = 1;
	return 0;
}

static int
connlimit_mt_check(const char *tablename, const void *ip,
                   const struct xt_match *match, void *matchinfo,
		   unsigned int matchinfosize, unsigned int hook_mask)
{
	struct xt_connlimit_info *info = matchinfo;
	unsigned int i;

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	if (nf_ct_l3proto_try_module_get(match->family) < 0) {
		printk(KERN_WARNING "cannot load conntrack support for "
		       "address family %u\n", match->family);
		return 0;
	}
#endif

	/* init private data */
	info->data = kmalloc(sizeof(struct xt_connlimit_data), GFP_KERNEL);
	if (info->data == NULL) {
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
		nf_ct_l3proto_module_put(match->family);
#endif
		return 0;
	}

	spin_lock_init(&info->data->lock);
	for (i = 0; i < ARRAY_SIZE(info->data->iphash); ++i)
		INIT_LIST_HEAD(&info->data->iphash[i]);

	return 1;
}

static void
connlimit_mt_destroy(const struct xt_match *match, void *matchinfo,
		     unsigned int matchinfosize)
{
	struct xt_connlimit_info *info = matchinfo;
	struct xt_connlimit_conn *conn;
	struct xt_connlimit_conn *tmp;
	struct list_head *hash = info->data->iphash;
	unsigned int i;

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	nf_ct_l3proto_module_put(match->family);
#endif

	for (i = 0; i < ARRAY_SIZE(info->data->iphash); ++i) {
		list_for_each_entry_safe(conn, tmp, &hash[i], list) {
			list_del(&conn->list);
			kfree(conn);
		}
	}

	kfree(info->data);
}

static struct xt_match connlimit_mt_reg __read_mostly =
{
	.name       = "connlimit",
	.family     = AF_INET,
	.checkentry = connlimit_mt_check,
	.match      = connlimit_mt,
	.matchsize  = sizeof(struct xt_connlimit_info),
	.destroy    = connlimit_mt_destroy,
	.me         = THIS_MODULE,
};

static int __init connlimit_mt_init(void)
{
	return xt_register_match(&connlimit_mt_reg);
}

static void __exit connlimit_mt_exit(void)
{
	xt_unregister_match(&connlimit_mt_reg);
}

module_init(connlimit_mt_init);
module_exit(connlimit_mt_exit);
MODULE_AUTHOR("Jan Engelhardt <jengelh@computergmbh.de>");
MODULE_DESCRIPTION("netfilter xt_connlimit match module");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_connlimit");
