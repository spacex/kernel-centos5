#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <linux/err.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/esp.h>
#include <linux/scatterlist.h>
#include <linux/in6.h>
#include <linux/kernel.h>
#include <linux/pfkeyv2.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/udp.h>

struct esp_skb_cb {
	struct xfrm_skb_cb xfrm;
	void *tmp;
};

#define ESP_SKB_CB(__skb) ((struct esp_skb_cb *)&((__skb)->cb[0]))

/*
 * Allocate an AEAD request structure with extra space for SG and IV.
 *
 * For alignment considerations the IV is placed at the front, followed
 * by the request and finally the SG list.
 *
 * TODO: Use spare space in skb for this where possible.
 */
static void *esp_alloc_tmp(struct crypto_aead *aead, int nfrags)
{
	unsigned int len;

	len = crypto_aead_ivsize(aead);
	if (len) {
		len += crypto_aead_alignmask(aead) &
		       ~(ncrypto_tfm_ctx_alignment() - 1);
		len = ALIGN(len, ncrypto_tfm_ctx_alignment());
	}

	len += sizeof(struct aead_givcrypt_request) + crypto_aead_reqsize(aead);
	len = ALIGN(len, __alignof__(struct scatterlist));

	len += sizeof(struct scatterlist) * nfrags;

	return kmalloc(len, GFP_ATOMIC);
}

static inline u8 *esp_tmp_iv(struct crypto_aead *aead, void *tmp)
{
	return crypto_aead_ivsize(aead) ? 
	       PTR_ALIGN((u8 *)tmp, crypto_aead_alignmask(aead) + 1) : tmp;
}

static inline struct aead_givcrypt_request *esp_tmp_givreq(
	struct crypto_aead *aead, u8 *iv)
{
	struct aead_givcrypt_request *req;

	req = (void *)PTR_ALIGN(iv + crypto_aead_ivsize(aead),
				ncrypto_tfm_ctx_alignment());
	aead_givcrypt_set_tfm(req, aead);
	return req;
}

static inline struct aead_request *esp_tmp_req(struct crypto_aead *aead, u8 *iv)
{
	struct aead_request *req;

	req = (void *)PTR_ALIGN(iv + crypto_aead_ivsize(aead),
				ncrypto_tfm_ctx_alignment());
	aead_request_set_tfm(req, aead);
	return req;
}

static inline struct scatterlist *esp_req_sg(struct crypto_aead *aead,
					     struct aead_request *req)
{
	return (void *)ALIGN((unsigned long)(req + 1) +
			     crypto_aead_reqsize(aead),
			     __alignof__(struct scatterlist));
}

static inline struct scatterlist *esp_givreq_sg(
	struct crypto_aead *aead, struct aead_givcrypt_request *req)
{
	return (void *)ALIGN((unsigned long)(req + 1) +
			     crypto_aead_reqsize(aead),
			     __alignof__(struct scatterlist));
}

static void esp_output_done(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;

	kfree(ESP_SKB_CB(skb)->tmp);
	xfrm4_output_resume(skb, err);
}

static int esp_output(struct xfrm_state *x, struct sk_buff *skb)
{
	int err;
	struct iphdr *top_iph;
	struct ip_esp_hdr *esph;
	struct crypto_aead *aead;
	struct aead_givcrypt_request *req;
	struct scatterlist *sg;
	struct scatterlist *asg;
	struct esp_data *esp;
	struct sk_buff *trailer;
	void *tmp;
	u8 *iv;
	int blksize;
	int clen;
	int alen;
	int nfrags;

	/* Strip IP+ESP header. */
	__skb_pull(skb, skb->h.raw - skb->data);
	/* Now skb is pure payload to encrypt */

	err = -ENOMEM;

	/* Round to block size */
	clen = skb->len;

	esp = x->data;
	aead = esp->aead;
	alen = crypto_aead_authsize(aead);

	blksize = ALIGN(crypto_aead_blocksize(aead), 4);
	clen = ALIGN(clen + 2, blksize);
	if (esp->padlen)
		clen = ALIGN(clen, esp->padlen);

	if ((err = skb_cow_data(skb, clen - skb->len + alen, &trailer)) < 0)
		goto error;
	nfrags = err;

	tmp = esp_alloc_tmp(aead, nfrags + 1);
	if (!tmp)
		goto error;

	iv = esp_tmp_iv(aead, tmp);
	req = esp_tmp_givreq(aead, iv);
	asg = esp_givreq_sg(aead, req);
	sg = asg + 1;

	/* Fill padding... */
	do {
		int i;
		for (i=0; i<clen-skb->len - 2; i++)
			*(u8*)(trailer->tail + i) = i+1;
	} while (0);
	*(u8*)(trailer->tail + clen-skb->len - 2) = (clen - skb->len)-2;
	*(u8*)(trailer->tail + clen-skb->len - 1) = skb->nh.iph->protocol;
	pskb_put(skb, trailer, clen - skb->len + alen);

	__skb_push(skb, skb->data - skb->nh.raw);
	top_iph = skb->nh.iph;
	esph = (struct ip_esp_hdr *)(skb->nh.raw + top_iph->ihl*4);
	top_iph->tot_len = htons(skb->len);

	/* this is non-NULL only with UDP Encapsulation */
	if (x->encap) {
		struct xfrm_encap_tmpl *encap = x->encap;
		struct udphdr *uh;
		u32 *udpdata32;

		uh = (struct udphdr *)esph;
		uh->source = encap->encap_sport;
		uh->dest = encap->encap_dport;
		uh->len = htons(skb->len - top_iph->ihl*4);
		uh->check = 0;

		switch (encap->encap_type) {
		default:
		case UDP_ENCAP_ESPINUDP:
			esph = (struct ip_esp_hdr *)(uh + 1);
			break;
		case UDP_ENCAP_ESPINUDP_NON_IKE:
			udpdata32 = (u32 *)(uh + 1);
			udpdata32[0] = udpdata32[1] = 0;
			esph = (struct ip_esp_hdr *)(udpdata32 + 2);
			break;
		}

		top_iph->protocol = IPPROTO_UDP;
	} else
		top_iph->protocol = IPPROTO_ESP;

	esph->spi = x->id.spi;
	esph->seq_no = htonl(++x->replay.oseq);
	if (unlikely(x->replay.oseq) == 0) {
		x->replay.oseq--;
		xfrm_audit_state_replay_overflow(x, skb);
		err = -EOVERFLOW;
		goto free_tmp;
	}
	xfrm_aevent_doreplay(x);

	sg_init_table(sg, nfrags);
	skb_to_sgvec(skb, sg,
		     esph->enc_data + crypto_aead_ivsize(aead) - skb->data,
		     clen + alen);
	sg_init_one(asg, esph, sizeof(*esph));

	aead_givcrypt_set_callback(req, 0, esp_output_done, skb);
	aead_givcrypt_set_crypt(req, sg, sg, clen, iv);
	aead_givcrypt_set_assoc(req, asg, sizeof(*esph));
	aead_givcrypt_set_giv(req, esph->enc_data, x->replay.oseq);

	ESP_SKB_CB(skb)->tmp = tmp;
	err = crypto_aead_givencrypt(req);
	if (err == -EINPROGRESS)
		goto error;

	if (err == -EBUSY)
		err = NET_XMIT_DROP;

free_tmp:
	kfree(tmp);

	ip_send_check(top_iph);

error:
	return err;
}

static int esp_input_done2(struct xfrm_state *x, struct sk_buff *skb, int err)
{
	struct iphdr *iph;
	struct esp_data *esp = x->data;
	struct crypto_aead *aead = esp->aead;
	int alen = crypto_aead_authsize(aead);
	int hlen = sizeof(struct ip_esp_hdr) + crypto_aead_ivsize(aead);
	int elen = skb->len - hlen;
	int ihl;
	u8 nexthdr[2];
	int padlen;

	kfree(ESP_SKB_CB(skb)->tmp);

	if (unlikely(err)) {
		if (err == -EBADMSG) {
			xfrm_audit_state_icvfail(x, skb, IPPROTO_ESP);
			x->stats.integrity_failed++;
		}
		goto out;
	}

	if (skb_copy_bits(skb, skb->len-alen-2, nexthdr, 2))
		BUG();

	err = -EINVAL;
	padlen = nexthdr[0];
	if (padlen + 2 + alen >= elen)
		goto out;

	/* ... check padding bits here. Silly. :-) */ 

	iph = skb->nh.iph;
	ihl = iph->ihl * 4;

	if (x->encap) {
		struct xfrm_encap_tmpl *encap = x->encap;
		struct udphdr *uh = (void *)(skb->nh.raw + ihl);

		/*
		 * 1) if the NAT-T peer's IP or port changed then
		 *    advertize the change to the keying daemon.
		 *    This is an inbound SA, so just compare
		 *    SRC ports.
		 */
		if (iph->saddr != x->props.saddr.a4 ||
		    uh->source != encap->encap_sport) {
			xfrm_address_t ipaddr;

			ipaddr.a4 = iph->saddr;
			km_new_mapping(x, &ipaddr, uh->source);
				
			/* XXX: perhaps add an extra
			 * policy check here, to see
			 * if we should allow or
			 * reject a packet from a
			 * different source
			 * address/port.
			 */
		}
	
		/*
		 * 2) ignore UDP/TCP checksums in case
		 *    of NAT-T in Transport Mode, or
		 *    perform other post-processing fixes
		 *    as per draft-ietf-ipsec-udp-encaps-06,
		 *    section 3.1.2
		 */
		if (!x->props.mode)
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	}

	iph->protocol = nexthdr[1];
	pskb_trim(skb, skb->len - alen - padlen - 2);
	skb->h.raw = __skb_pull(skb, hlen) - ihl;

	/* RFC4303: Drop dummy packets without any error */
	if (iph->protocol == IPPROTO_NONE)
		goto out;

	err = 0;

out:
	return err;
}

static void esp_input_done(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;

	xfrm4_input_resume(skb,
			   esp_input_done2(xfrm_input_state(skb), skb, err));
}

/*
 * Note: detecting truncated vs. non-truncated authentication data is very
 * expensive, so we only support truncated data, which is the recommended
 * and common case.
 */
static int esp_input(struct xfrm_state *x, struct sk_buff *skb)
{
	struct ip_esp_hdr *esph;
	struct esp_data *esp = x->data;
	struct crypto_aead *aead = esp->aead;
	struct aead_request *req;
	struct sk_buff *trailer;
	int elen = skb->len - sizeof(*esph) - crypto_aead_ivsize(aead);
	int nfrags;
	void *tmp;
	u8 *iv;
	struct scatterlist *sg;
	struct scatterlist *asg;
	int err = -EINVAL;

	if (!pskb_may_pull(skb, sizeof(struct ip_esp_hdr) + crypto_aead_ivsize(aead)))
		goto out;

	if (elen <= 0)
		goto out;

	if ((err = skb_cow_data(skb, 0, &trailer)) < 0)
		goto out;
	nfrags = err;

	err = -ENOMEM;
	tmp = esp_alloc_tmp(aead, nfrags + 1);
	if (!tmp)
		goto out;

	ESP_SKB_CB(skb)->tmp = tmp;
	iv = esp_tmp_iv(aead, tmp);
	req = esp_tmp_req(aead, iv);
	asg = esp_req_sg(aead, req);
	sg = asg + 1;

	skb->ip_summed = CHECKSUM_NONE;

	esph = (struct ip_esp_hdr *)skb->data;

	/* Get ivec. This can be wrong, check against another impls. */
	iv = esph->enc_data;

	sg_init_table(sg, nfrags);
	skb_to_sgvec(skb, sg, sizeof(*esph) + crypto_aead_ivsize(aead), elen);
	sg_init_one(asg, esph, sizeof(*esph));

	aead_request_set_callback(req, 0, esp_input_done, skb);
	aead_request_set_crypt(req, sg, sg, elen, iv);
	aead_request_set_assoc(req, asg, sizeof(*esph));

	err = crypto_aead_decrypt(req);
	if (err == -EINPROGRESS)
		goto out;

	err = esp_input_done2(x, skb, err);

out:
	return err;
}

static u32 esp4_get_max_size(struct xfrm_state *x, int mtu)
{
	struct esp_data *esp = x->data;
	u32 blksize = ALIGN(crypto_aead_blocksize(esp->aead), 4);

	if (x->props.mode) {
		mtu = ALIGN(mtu + 2, blksize);
	} else {
		/* The worst case. */
		mtu = ALIGN(mtu + 2, 4) + blksize - 4;
	}
	if (esp->padlen)
		mtu = ALIGN(mtu, esp->padlen);

	return mtu + x->props.header_len + crypto_aead_authsize(esp->aead);
}

static void esp4_err(struct sk_buff *skb, u32 info)
{
	struct iphdr *iph = (struct iphdr*)skb->data;
	struct ip_esp_hdr *esph = (struct ip_esp_hdr*)(skb->data+(iph->ihl<<2));
	struct xfrm_state *x;

	if (skb->h.icmph->type != ICMP_DEST_UNREACH ||
	    skb->h.icmph->code != ICMP_FRAG_NEEDED)
		return;

	x = xfrm_state_lookup((xfrm_address_t *)&iph->daddr, esph->spi, IPPROTO_ESP, AF_INET);
	if (!x)
		return;
	NETDEBUG(KERN_DEBUG "pmtu discovery on SA ESP/%08x/%08x\n",
		 ntohl(esph->spi), ntohl(iph->daddr));
	xfrm_state_put(x);
}

static void esp_destroy(struct xfrm_state *x)
{
	struct esp_data *esp = x->data;

	if (!esp)
		return;

	crypto_free_aead(esp->aead);
	kfree(esp);
}

static int esp_init_authenc(struct xfrm_state *x)
{
	struct esp_data *esp = x->data;
	struct crypto_aead *aead;
	struct crypto_authenc_key_param *param;
	struct xfrm_nalgo_desc *aalg_desc;
	struct xfrm_nalgo_desc *ealg_desc;
	struct rtattr *rta;
	char *key;
	char *p;
	char authenc_name[CRYPTO_MAX_ALG_NAME];
	unsigned int keylen;
	int err;

	err = -EINVAL;
	if (x->ealg == NULL)
		goto error;

	err = -ENOENT;
	aalg_desc = NULL;
	if (x->aalg) {
		aalg_desc = xfrm_naalg_get_byname(x->aalg->alg_name, 1);
		if (!aalg_desc)
			goto error;
	}

	ealg_desc = xfrm_nealg_get_byname(x->ealg->alg_name, 1);
	if (!ealg_desc)
		goto error;

	err = -ENAMETOOLONG;
	if (snprintf(authenc_name, CRYPTO_MAX_ALG_NAME, "authenc(%s,%s)",
		     aalg_desc ? aalg_desc->name : "hmac(digest_null)",
		     ealg_desc->name) >= CRYPTO_MAX_ALG_NAME)
		goto error;

	aead = crypto_alloc_aead(authenc_name, 0,
				 strcmp(ealg_desc->name, x->ealg->alg_name) ?
				 NCRYPTO_ALG_ASYNC : 0);
	err = PTR_ERR(aead);
	if (IS_ERR(aead))
		goto error;

	esp->aead = aead;

	keylen = (x->aalg ? (x->aalg->alg_key_len + 7) / 8 : 0) +
		 (x->ealg->alg_key_len + 7) / 8 + RTA_SPACE(sizeof(*param));
	err = -ENOMEM;
	key = kmalloc(keylen, GFP_KERNEL);
	if (!key)
		goto error;

	p = key;
	rta = (void *)p;
	rta->rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
	rta->rta_len = RTA_LENGTH(sizeof(*param));
	param = RTA_DATA(rta);
	p += RTA_SPACE(sizeof(*param));

	if (aalg_desc) {
		memcpy(p, x->aalg->alg_key, (x->aalg->alg_key_len + 7) / 8);
		p += (x->aalg->alg_key_len + 7) / 8;

		err = -EINVAL;
		if (aalg_desc->uinfo.auth.icv_fullbits/8 !=
		    crypto_aead_authsize(aead)) {
			NETDEBUG(KERN_INFO "ESP: %s digestsize %u != %hu\n",
				 x->aalg->alg_name,
				 crypto_aead_authsize(aead),
				 aalg_desc->uinfo.auth.icv_fullbits/8);
			goto free_key;
		}

		err = crypto_aead_setauthsize(
			aead, aalg_desc->uinfo.auth.icv_truncbits / 8);
		if (err)
			goto free_key;
	}

	param->enckeylen = cpu_to_be32((x->ealg->alg_key_len + 7) / 8);
	memcpy(p, x->ealg->alg_key, (x->ealg->alg_key_len + 7) / 8);

	err = crypto_aead_setkey(aead, key, keylen);

free_key:
	kfree(key);

error:
	return err;
}

static int esp_init_aead(struct xfrm_state *x)
{
	struct xfrm_algo_aead *aead_algo;
	struct esp_data *esp = x->data;
	struct crypto_aead *aead;
	int err;

	if (!xfrm_naead_get_byname(x->ealg->alg_name, 0, 1))
		return esp_init_authenc(x);

	aead_algo = (struct xfrm_algo_aead *)x->ealg;
	aead = crypto_alloc_aead(aead_algo->alg_name, 0, 0);
	err = PTR_ERR(aead);
	if (IS_ERR(aead))
		goto error;

	esp->aead = aead;

	err = crypto_aead_setkey(aead, aead_algo->alg_key,
				 (aead_algo->alg_key_len + 7) / 8);
	if (err)
		goto error;

	err = crypto_aead_setauthsize(aead, aead_algo->alg_icv_len / 8);
	if (err)
		goto error;

error:
	return err;
}

static int esp_init_state(struct xfrm_state *x)
{
	struct esp_data *esp;
	struct crypto_aead *aead;
	int err;

	esp = kzalloc(sizeof(*esp), GFP_KERNEL);
	if (esp == NULL)
		return -ENOMEM;

	x->data = esp;

	err = esp_init_aead(x);
	if (err)
		goto error;

	aead = esp->aead;

	esp->padlen = 0;

	x->props.header_len = sizeof(struct ip_esp_hdr) +
			      crypto_aead_ivsize(aead);
	if (x->props.mode)
		x->props.header_len += sizeof(struct iphdr);
	if (x->encap) {
		struct xfrm_encap_tmpl *encap = x->encap;

		switch (encap->encap_type) {
		default:
			goto error;
		case UDP_ENCAP_ESPINUDP:
			x->props.header_len += sizeof(struct udphdr);
			break;
		case UDP_ENCAP_ESPINUDP_NON_IKE:
			x->props.header_len += sizeof(struct udphdr) + 2 * sizeof(u32);
			break;
		}
	}
	x->props.trailer_len = esp4_get_max_size(x, 0) - x->props.header_len;

error:
	return err;
}

static struct xfrm_type esp_type =
{
	.description	= "ESP4",
	.owner		= THIS_MODULE,
	.proto	     	= IPPROTO_ESP,
	.init_state	= esp_init_state,
	.destructor	= esp_destroy,
	.get_max_size	= esp4_get_max_size,
	.input		= esp_input,
	.output		= esp_output
};

static struct net_protocol esp4_protocol = {
	.handler	=	xfrm4_rcv,
	.err_handler	=	esp4_err,
	.no_policy	=	1,
};

static int __init esp4_init(void)
{
	if (xfrm_register_type(&esp_type, AF_INET) < 0) {
		printk(KERN_INFO "ip esp init: can't add xfrm type\n");
		return -EAGAIN;
	}
	if (inet_add_protocol(&esp4_protocol, IPPROTO_ESP) < 0) {
		printk(KERN_INFO "ip esp init: can't add protocol\n");
		xfrm_unregister_type(&esp_type, AF_INET);
		return -EAGAIN;
	}
	return 0;
}

static void __exit esp4_fini(void)
{
	if (inet_del_protocol(&esp4_protocol, IPPROTO_ESP) < 0)
		printk(KERN_INFO "ip esp close: can't remove protocol\n");
	if (xfrm_unregister_type(&esp_type, AF_INET) < 0)
		printk(KERN_INFO "ip esp close: can't remove xfrm type\n");
}

module_init(esp4_init);
module_exit(esp4_fini);
MODULE_LICENSE("GPL");
