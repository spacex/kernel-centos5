/*
 * xfrm algorithm interface
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <linux/audit.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pfkeyv2.h>
#include <linux/ncrypto.h>
#include <linux/scatterlist.h>
#include <net/xfrm.h>

static int xfrm_old_kernel;

/*
 * Algorithms supported by IPsec.  These entries contain properties which
 * are used in key negotiation and xfrm processing, and are used to verify
 * that instantiated crypto transforms have correct parameters for IPsec
 * purposes.
 */
static struct xfrm_nalgo_desc aead_list[] = {
{
	.name = "rfc4309(ccm(aes))",

	.uinfo = {
		.aead = {
			.icv_truncbits = 64,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_X_EALG_AES_CCM_ICV8,
		.sadb_alg_ivlen = 8,
		.sadb_alg_minbits = 128,
		.sadb_alg_maxbits = 256
	}
},
{
	.name = "rfc4309(ccm(aes))",

	.uinfo = {
		.aead = {
			.icv_truncbits = 96,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_X_EALG_AES_CCM_ICV12,
		.sadb_alg_ivlen = 8,
		.sadb_alg_minbits = 128,
		.sadb_alg_maxbits = 256
	}
},
{
	.name = "rfc4309(ccm(aes))",

	.uinfo = {
		.aead = {
			.icv_truncbits = 128,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_X_EALG_AES_CCM_ICV16,
		.sadb_alg_ivlen = 8,
		.sadb_alg_minbits = 128,
		.sadb_alg_maxbits = 256
	}
},
};

static struct xfrm_nalgo_desc aalg_list[] = {
{
	.name = "hmac(digest_null)",
	.compat = "digest_null",

	.uinfo = {
		.auth = {
			.icv_truncbits = 0,
			.icv_fullbits = 0,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_X_AALG_NULL,
		.sadb_alg_ivlen = 0,
		.sadb_alg_minbits = 0,
		.sadb_alg_maxbits = 0
	}
},
{
	.name = "hmac(md5)",
	.compat = "md5",

	.uinfo = {
		.auth = {
			.icv_truncbits = 96,
			.icv_fullbits = 128,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_AALG_MD5HMAC,
		.sadb_alg_ivlen = 0,
		.sadb_alg_minbits = 128,
		.sadb_alg_maxbits = 128
	}
},
{
	.name = "hmac(sha1)",
	.compat = "sha1",

	.uinfo = {
		.auth = {
			.icv_truncbits = 96,
			.icv_fullbits = 160,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_AALG_SHA1HMAC,
		.sadb_alg_ivlen = 0,
		.sadb_alg_minbits = 160,
		.sadb_alg_maxbits = 160
	}
},
{
	.name = "hmac(sha256)",
	.compat = "sha256",

	.uinfo = {
		.auth = {
			.icv_truncbits = 96,
			.icv_fullbits = 256,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_X_AALG_SHA2_256HMAC,
		.sadb_alg_ivlen = 0,
		.sadb_alg_minbits = 256,
		.sadb_alg_maxbits = 256
	}
},
{
	.name = "hmac(ripemd160)",
	.compat = "ripemd160",

	.uinfo = {
		.auth = {
			.icv_truncbits = 96,
			.icv_fullbits = 160,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_X_AALG_RIPEMD160HMAC,
		.sadb_alg_ivlen = 0,
		.sadb_alg_minbits = 160,
		.sadb_alg_maxbits = 160
	}
},
{
	.name = "xcbc(aes)",

	.uinfo = {
		.auth = {
			.icv_truncbits = 96,
			.icv_fullbits = 128,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_X_AALG_AES_XCBC_MAC,
		.sadb_alg_ivlen = 0,
		.sadb_alg_minbits = 128,
		.sadb_alg_maxbits = 128
	}
},
};

static struct xfrm_nalgo_desc ealg_list[] = {
{
	.name = "ecb(cipher_null)",
	.compat = "cipher_null",

	.uinfo = {
		.encr = {
			.blockbits = 8,
			.defkeybits = 0,
		}
	},

	.desc = {
		.sadb_alg_id =	SADB_EALG_NULL,
		.sadb_alg_ivlen = 0,
		.sadb_alg_minbits = 0,
		.sadb_alg_maxbits = 0
	}
},
{
	.name = "cbc(des)",
	.compat = "des",

	.uinfo = {
		.encr = {
			.blockbits = 64,
			.defkeybits = 64,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_EALG_DESCBC,
		.sadb_alg_ivlen = 8,
		.sadb_alg_minbits = 64,
		.sadb_alg_maxbits = 64
	}
},
{
	.name = "cbc(des3_ede)",
	.compat = "des3_ede",

	.uinfo = {
		.encr = {
			.blockbits = 64,
			.defkeybits = 192,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_EALG_3DESCBC,
		.sadb_alg_ivlen = 8,
		.sadb_alg_minbits = 192,
		.sadb_alg_maxbits = 192
	}
},
{
	.name = "cbc(cast128)",
	.compat = "cast128",

	.uinfo = {
		.encr = {
			.blockbits = 64,
			.defkeybits = 128,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_X_EALG_CASTCBC,
		.sadb_alg_ivlen = 8,
		.sadb_alg_minbits = 40,
		.sadb_alg_maxbits = 128
	}
},
{
	.name = "cbc(blowfish)",
	.compat = "blowfish",

	.uinfo = {
		.encr = {
			.blockbits = 64,
			.defkeybits = 128,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_X_EALG_BLOWFISHCBC,
		.sadb_alg_ivlen = 8,
		.sadb_alg_minbits = 40,
		.sadb_alg_maxbits = 448
	}
},
{
	.name = "cbc(aes)",
	.compat = "aes",

	.uinfo = {
		.encr = {
			.blockbits = 128,
			.defkeybits = 128,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_X_EALG_AESCBC,
		.sadb_alg_ivlen = 8,
		.sadb_alg_minbits = 128,
		.sadb_alg_maxbits = 256
	}
},
{
	.name = "cbc(serpent)",
	.compat = "serpent",

	.uinfo = {
		.encr = {
			.blockbits = 128,
			.defkeybits = 128,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_X_EALG_SERPENTCBC,
		.sadb_alg_ivlen = 8,
		.sadb_alg_minbits = 128,
		.sadb_alg_maxbits = 256,
	}
},
{
	.name = "cbc(twofish)",
	.compat = "twofish",

	.uinfo = {
		.encr = {
			.blockbits = 128,
			.defkeybits = 128,
		}
	},

	.desc = {
		.sadb_alg_id = SADB_X_EALG_TWOFISHCBC,
		.sadb_alg_ivlen = 8,
		.sadb_alg_minbits = 128,
		.sadb_alg_maxbits = 256
	}
},
{
	.name = "rfc3686(ctr(aes))",

	.uinfo = {
		.encr = {
			.blockbits = 128,
			.defkeybits = 160, /* 128-bit key + 32-bit nonce */
		}
	},

	.desc = {
		.sadb_alg_id = SADB_X_EALG_AESCTR,
		.sadb_alg_ivlen = 8,
		.sadb_alg_minbits = 128,
		.sadb_alg_maxbits = 256
	}
},
};

static struct xfrm_nalgo_desc calg_list[] = {
{
	.name = "deflate",
	.uinfo = {
		.comp = {
			.threshold = 90,
		}
	},
	.desc = { .sadb_alg_id = SADB_X_CALG_DEFLATE }
},
{
	.name = "lzs",
	.uinfo = {
		.comp = {
			.threshold = 90,
		}
	},
	.desc = { .sadb_alg_id = SADB_X_CALG_LZS }
},
{
	.name = "lzjh",
	.uinfo = {
		.comp = {
			.threshold = 50,
		}
	},
	.desc = { .sadb_alg_id = SADB_X_CALG_LZJH }
},
};

static inline int aead_entries(void)
{
	return ARRAY_SIZE(aead_list);
}

static inline int aalg_entries(void)
{
	return ARRAY_SIZE(aalg_list);
}

static inline int ealg_entries(void)
{
	return ARRAY_SIZE(ealg_list);
}

static inline int calg_entries(void)
{
	return ARRAY_SIZE(calg_list);
}

struct xfrm_algo_list {
	struct xfrm_nalgo_desc *algs;
	int entries;
	u32 type;
	u32 mask;
};

static const struct xfrm_algo_list xfrm_aead_list = {
	.algs = aead_list,
	.entries = ARRAY_SIZE(aead_list),
	.type = NCRYPTO_ALG_TYPE_AEAD,
	.mask = NCRYPTO_ALG_TYPE_MASK,
};

static const struct xfrm_algo_list xfrm_aalg_list = {
	.algs = aalg_list,
	.entries = ARRAY_SIZE(aalg_list),
	.type = NCRYPTO_ALG_TYPE_HASH,
	.mask = NCRYPTO_ALG_TYPE_HASH_MASK,
};

static const struct xfrm_algo_list xfrm_ealg_list = {
	.algs = ealg_list,
	.entries = ARRAY_SIZE(ealg_list),
	.type = NCRYPTO_ALG_TYPE_BLKCIPHER,
	.mask = NCRYPTO_ALG_TYPE_MASK,
};

static struct xfrm_nalgo_desc *xfrm_find_algo(
	const struct xfrm_algo_list *algo_list,
	int match(const struct xfrm_nalgo_desc *entry, const void *data),
	const void *data, int probe)
{
	struct xfrm_nalgo_desc *list = algo_list->algs;
	int i, status;

	for (i = 0; i < algo_list->entries; i++) {
		if (!match(list + i, data))
			continue;

		if (list[i].available)
			return &list[i];

		if (!probe)
			break;

		status = crypto_has_alg(list[i].name, algo_list->type,
					algo_list->mask);
		if (!status)
			break;

		list[i].available = status;
		return &list[i];
	}
	return NULL;
}

static int xfrm_alg_name_match(const struct xfrm_nalgo_desc *entry,
			       const void *data)
{
	const char *name = data;

	return name && (!strcmp(name, entry->name) ||
			(entry->compat && !strcmp(name, entry->compat)));
}

struct xfrm_nalgo_desc *xfrm_naalg_get_byname(char *name, int probe)
{
	return xfrm_find_algo(&xfrm_aalg_list, xfrm_alg_name_match, name,
			      probe);
}
EXPORT_SYMBOL_GPL(xfrm_naalg_get_byname);

struct xfrm_nalgo_desc *xfrm_nealg_get_byname(char *name, int probe)
{
	return xfrm_find_algo(&xfrm_ealg_list, xfrm_alg_name_match, name,
			      probe);
}
EXPORT_SYMBOL_GPL(xfrm_nealg_get_byname);

struct xfrm_aead_name {
	const char *name;
	int icvbits;
};

static int xfrm_aead_name_match(const struct xfrm_nalgo_desc *entry,
				const void *data)
{
	const struct xfrm_aead_name *aead = data;
	const char *name = aead->name;

	return (!aead->icvbits ||
		aead->icvbits == entry->uinfo.aead.icv_truncbits) && name &&
	       !strcmp(name, entry->name);
}

struct xfrm_nalgo_desc *xfrm_naead_get_byname(char *name, int icv_len,
					      int probe)
{
	struct xfrm_aead_name data = {
		.name = name,
		.icvbits = icv_len,
	};

	return xfrm_find_algo(&xfrm_aead_list, xfrm_aead_name_match, &data,
			      probe);
}
EXPORT_SYMBOL_GPL(xfrm_naead_get_byname);

int skb_nicv_walk(const struct sk_buff *skb, struct hash_desc *desc,
		  int offset, int len, nicv_update_fn_t icv_update)
{
	int start = skb_headlen(skb);
	int i, copy = start - offset;
	int err;
	struct scatterlist sg;

	/* Checksum header. */
	if (copy > 0) {
		if (copy > len)
			copy = len;
		
		sg.page = virt_to_page(skb->data + offset);
		sg.offset = (unsigned long)(skb->data + offset) % PAGE_SIZE;
		sg.length = copy;
		
		err = icv_update(desc, &sg, copy);
		if (unlikely(err))
			return err;
		
		if ((len -= copy) == 0)
			return 0;
		offset += copy;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;

		BUG_TRAP(start <= offset + len);

		end = start + skb_shinfo(skb)->frags[i].size;
		if ((copy = end - offset) > 0) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

			if (copy > len)
				copy = len;
			
			sg.page = frag->page;
			sg.offset = frag->page_offset + offset-start;
			sg.length = copy;
			
			err = icv_update(desc, &sg, copy);
			if (unlikely(err))
				return err;

			if (!(len -= copy))
				return 0;
			offset += copy;
		}
		start = end;
	}

	if (skb_shinfo(skb)->frag_list) {
		struct sk_buff *list = skb_shinfo(skb)->frag_list;

		for (; list; list = list->next) {
			int end;

			BUG_TRAP(start <= offset + len);

			end = start + list->len;
			if ((copy = end - offset) > 0) {
				if (copy > len)
					copy = len;
				err = skb_nicv_walk(list, desc, offset-start,
						    copy, icv_update);
				if (unlikely(err))
					return err;
				if ((len -= copy) == 0)
					return 0;
				offset += copy;
			}
			start = end;
		}
	}
	BUG_ON(len);
	return 0;
}
EXPORT_SYMBOL_GPL(skb_nicv_walk);

int xfrm_nlookup(struct dst_entry **dst_p, struct flowi *fl,
		 struct sock *sk, int flags)
{
	if (xfrm_old_kernel && (flags & ~XFRM_LOOKUP_WAIT))
		return -ENOSYS;

	return xfrm_lookup(dst_p, fl, sk, flags);
}
EXPORT_SYMBOL(xfrm_nlookup);

#ifdef CONFIG_AUDITSYSCALL
static inline void xfrm_audit_helper_pktinfo(struct sk_buff *skb, u16 family,
					     struct audit_buffer *audit_buf)
{
	struct iphdr *iph4;
	struct ipv6hdr *iph6;

	switch (family) {
	case AF_INET:
		iph4 = ip_hdr(skb);
		audit_log_format(audit_buf,
				 " src=" NIPQUAD_FMT " dst=" NIPQUAD_FMT,
				 NIPQUAD(iph4->saddr),
				 NIPQUAD(iph4->daddr));
		break;
	case AF_INET6:
		iph6 = ipv6_hdr(skb);
		audit_log_format(audit_buf,
				 " src=" NIP6_FMT " dst=" NIP6_FMT
				 " flowlbl=0x%x%x%x",
				 NIP6(iph6->saddr),
				 NIP6(iph6->daddr),
				 iph6->flow_lbl[0] & 0x0f,
				 iph6->flow_lbl[1],
				 iph6->flow_lbl[2]);
		break;
	}
}

void xfrm_audit_state_replay_overflow(struct xfrm_state *x,
				      struct sk_buff *skb)
{
	struct audit_buffer *audit_buf;
	u32 spi;

	if (xfrm_old_kernel)
		return;

	audit_buf = xfrm_audit_start("SA-replay-overflow");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, x->props.family, audit_buf);
	/* don't record the sequence number because it's inherent in this kind
	 * of audit message */
	spi = ntohl(x->id.spi);
	audit_log_format(audit_buf, " spi=%u(0x%x)", spi, spi);
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_replay_overflow);

void xfrm_naudit_state_replay(struct xfrm_state *x, struct sk_buff *skb,
			      __be32 net_seq)
{
	struct audit_buffer *audit_buf;
	u32 spi;

	if (xfrm_old_kernel)
		return;

	audit_buf = xfrm_audit_start("SA-replayed-pkt");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, x->props.family, audit_buf);
	spi = ntohl(x->id.spi);
	audit_log_format(audit_buf, " spi=%u(0x%x) seqno=%u",
			 spi, spi, ntohl(net_seq));
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_naudit_state_replay);

void xfrm_naudit_state_notfound(struct sk_buff *skb, u16 family,
				__be32 net_spi, __be32 net_seq)
{
	struct audit_buffer *audit_buf;
	u32 spi;

	if (xfrm_old_kernel)
		return;

	audit_buf = xfrm_audit_start("SA-notfound");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, family, audit_buf);
	spi = ntohl(net_spi);
	audit_log_format(audit_buf, " spi=%u(0x%x) seqno=%u",
			 spi, spi, ntohl(net_seq));
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_naudit_state_notfound);

void xfrm_audit_state_icvfail(struct xfrm_state *x,
			      struct sk_buff *skb, u8 proto)
{
	struct audit_buffer *audit_buf;
	__be32 net_spi;
	__be32 net_seq;

	if (xfrm_old_kernel)
		return;

	audit_buf = xfrm_audit_start("SA-icv-failure");
	if (audit_buf == NULL)
		return;
	xfrm_audit_helper_pktinfo(skb, x->props.family, audit_buf);
	if (xfrm_parse_spi(skb, proto, &net_spi, &net_seq) == 0) {
		u32 spi = ntohl(net_spi);
		audit_log_format(audit_buf, " spi=%u(0x%x) seqno=%u",
				 spi, spi, ntohl(net_seq));
	}
	audit_log_end(audit_buf);
}
EXPORT_SYMBOL_GPL(xfrm_audit_state_icvfail);
#endif

static int __init xfrm_nalgo_init(void)
{
	xfrm_old_kernel = !xfrm_aalg_get_byname("hmac(md5)", 1);
	return 0;
}

static void __exit xfrm_nalgo_exit(void)
{
}

module_init(xfrm_nalgo_init);
module_exit(xfrm_nalgo_exit);
MODULE_LICENSE("GPL");
