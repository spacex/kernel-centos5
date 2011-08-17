#ifndef OPEN_ISCSI_COMPAT
#define OPEN_ISCSI_COMPAT

#include <asm/scatterlist.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/crypto.h>
#include <linux/net.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#define CRYPTO_ALG_ASYNC		0x00000080
struct hash_desc
{
	struct crypto_tfm *tfm;
	u32 flags;
};

static inline int crypto_hash_init(struct hash_desc *desc)
{
	crypto_digest_init(desc->tfm);
	return 0;
}

static inline int crypto_hash_digest(struct hash_desc *desc,
				     struct scatterlist *sg,
				     unsigned int nbytes, u8 *out)
{
	crypto_digest_digest(desc->tfm, sg, 1, out);
	return nbytes;
}

static inline int crypto_hash_update(struct hash_desc *desc,
				     struct scatterlist *sg,
				     unsigned int nbytes)
{
	crypto_digest_update(desc->tfm, sg, 1);
	return nbytes;
}

static inline int crypto_hash_final(struct hash_desc *desc, u8 *out)
{
	crypto_digest_final(desc->tfm, out);
	return 0;
}

static inline struct crypto_tfm *crypto_alloc_hash(const char *alg_name,
						    u32 type, u32 mask)
{
	struct crypto_tfm *ret = crypto_alloc_tfm(alg_name ,type);
	return ret ? ret : ERR_PTR(-ENOMEM);
}

static inline void crypto_free_hash(struct crypto_tfm *tfm)
{
	crypto_free_tfm(tfm);
}

static inline unsigned long rounddown_pow_of_two(unsigned long n)
{
	return 1UL << (fls_long(n) - 1);
}

#define SCSI_MAX_VARLEN_CDB_SIZE 16

static inline struct scatterlist *sg_next(struct scatterlist *sg)
{
	if (!sg) {
		BUG();
		return NULL;
	}
	return sg + 1;
}

#define scsi_for_each_sg(cmd, sg, nseg, __i)	\
	for_each_sg(scsi_sglist(cmd), sg, nseg, __i)

#define for_each_sg(sglist, sg, nr, __i)        \
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))

#define sg_page(_sg) _sg->page

static inline void sg_set_page(struct scatterlist *sg, struct page *page,
				unsigned int len, unsigned int offset)
{
	sg->page = page;
	sg->offset = offset;
	sg->length = len;
}

static inline void sg_init_table(struct scatterlist *sgl, unsigned int nents)
{
	memset(sgl, 0, sizeof(*sgl) * nents);
}

static inline int scsi_bidi_cmnd(struct scsi_cmnd *cmd)
{
	return 0;
}

static inline struct nlmsghdr *nlmsg_hdr(const struct sk_buff *skb)
{
	return (struct nlmsghdr *)skb->data;
}

#define netlink_kernel_release(_nls) \
	sock_release(_nls->sk_socket)

#define netlink_kernel_create(net, uint, groups, input, cb_mutex, mod) \
	netlink_kernel_create(uint, groups, input, mod)

#define BLK_EH_NOT_HANDLED EH_NOT_HANDLED
#define BLK_EH_RESET_TIMER EH_RESET_TIMER
#define blk_eh_timer_return scsi_eh_timer_return

static inline void INIT_WORK_compat(struct work_struct *work, void *func)
{
	INIT_WORK(work, func, work);
}

#undef INIT_WORK
#define INIT_WORK(_work, _func) INIT_WORK_compat(_work, _func)
#undef INIT_DELAYED_WORK
#define INIT_DELAYED_WORK(_work,_func) INIT_WORK_compat(_work, _func)

#endif
