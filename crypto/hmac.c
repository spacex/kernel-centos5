/*
 * Cryptographic API.
 *
 * HMAC: Keyed-Hashing for Message Authentication (RFC2104).
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2006 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * The HMAC implementation is derived from USAGI.
 * Copyright (c) 2002 Kazunori Miyazawa <miyazawa@linux-ipv6.org> / USAGI
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <crypto/algapi.h>
#include <crypto/nscatterwalk.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>

struct hmac_ctx {
	struct crypto_tfm *child;
};

static inline void *align_ptr(void *p, unsigned int align)
{
	return (void *)ALIGN((unsigned long)p, align);
}

static inline struct hmac_ctx *hmac_ctx(struct crypto_hash *tfm)
{
	return align_ptr(crypto_hash_ctx_aligned(tfm) +
			 crypto_hash_blocksize(tfm) * 2 +
			 crypto_hash_digestsize(tfm), sizeof(void *));
}

static int hmac_setkey(struct crypto_hash *parent,
		       const u8 *inkey, unsigned int keylen)
{
	int bs = crypto_hash_blocksize(parent);
	int ds = crypto_hash_digestsize(parent);
	char *ipad = crypto_hash_ctx_aligned(parent);
	char *opad = ipad + bs;
	char *digest = opad + bs;
	struct hmac_ctx *ctx = align_ptr(digest + ds, sizeof(void *));
	struct crypto_tfm *tfm = ctx->child;
	unsigned int i;

	if (keylen > bs) {
		struct scatterlist tmp;
		int tmplen;

		crypto_digest_init(tfm);

		tmplen = bs * 2 + ds;
		sg_init_one(&tmp, ipad, tmplen);

		for (; keylen > tmplen; inkey += tmplen, keylen -= tmplen) {
			memcpy(ipad, inkey, tmplen);
			crypto_digest_update(tfm, &tmp, 1);
		}

		if (keylen) {
			memcpy(ipad, inkey, keylen);
			tmp.length = keylen;
			crypto_digest_update(tfm, &tmp, 1);
		}

		crypto_digest_final(tfm, digest);

		inkey = digest;
		keylen = ds;
	}

	memcpy(ipad, inkey, keylen);
	memset(ipad + keylen, 0, bs - keylen);
	memcpy(opad, ipad, bs);

	for (i = 0; i < bs; i++) {
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	return 0;
}

static int hmac_init(struct hash_desc *pdesc)
{
	struct crypto_hash *parent = pdesc->tfm;
	int bs = crypto_hash_blocksize(parent);
	int ds = crypto_hash_digestsize(parent);
	char *ipad = crypto_hash_ctx_aligned(parent);
	struct hmac_ctx *ctx = align_ptr(ipad + bs * 2 + ds, sizeof(void *));
	struct crypto_tfm *tfm = ctx->child;
	struct scatterlist tmp;

	sg_init_one(&tmp, ipad, bs);
	crypto_digest_init(tfm);

	crypto_digest_update(tfm, &tmp, 1);
	return 0;
}

static int hmac_update(struct hash_desc *desc,
		       struct scatterlist *sg, unsigned int nbytes)
{
	struct hmac_ctx *ctx = hmac_ctx(desc->tfm);
	struct crypto_tfm *tfm = ctx->child;
	unsigned int alignmask = crypto_tfm_alg_alignmask(tfm);

	if (!nbytes)
		return 0;

	for (;;) {
		struct page *pg = sg_page(sg);
		unsigned int offset = sg->offset;
		unsigned int l = sg->length;

		if (unlikely(l > nbytes))
			l = nbytes;
		nbytes -= l;

		do {
			unsigned int bytes_from_page = min(l, ((unsigned int)
							   (PAGE_SIZE)) - 
							   offset);
			char *src = ncrypto_kmap(pg, 0);
			char *p = src + offset;

			if (unlikely(offset & alignmask)) {
				unsigned int bytes =
					alignmask + 1 - (offset & alignmask);
				bytes = min(bytes, bytes_from_page);
				tfm->__crt_alg->cra_digest.dia_update(tfm, p,
								      bytes);
				p += bytes;
				bytes_from_page -= bytes;
				l -= bytes;
			}
			tfm->__crt_alg->cra_digest.dia_update(tfm, p,
							      bytes_from_page);
			ncrypto_kunmap(src, 0);
			ncrypto_yield(desc->flags);
			offset = 0;
			pg++;
			l -= bytes_from_page;
		} while (l > 0);

		if (!nbytes)
			break;
		sg = scatterwalk_sg_next(sg);
	}

	return 0;
}

static int hmac_final(struct hash_desc *pdesc, u8 *out)
{
	struct crypto_hash *parent = pdesc->tfm;
	int bs = crypto_hash_blocksize(parent);
	int ds = crypto_hash_digestsize(parent);
	char *opad = crypto_hash_ctx_aligned(parent) + bs;
	char *digest = opad + bs;
	struct hmac_ctx *ctx = align_ptr(digest + ds, sizeof(void *));
	struct crypto_tfm *tfm = ctx->child;
	struct scatterlist tmp;

	sg_init_one(&tmp, opad, bs + ds);
	crypto_digest_final(tfm, digest);

	crypto_digest_digest(tfm, &tmp, 1, out);
	return 0;
}

static int hmac_digest(struct hash_desc *pdesc, struct scatterlist *sg,
		       unsigned int nbytes, u8 *out)
{
	int err;

	err = hmac_init(pdesc);
	if (err)
		return err;

	err = hmac_update(pdesc, sg, nbytes);
	if (err)
		return err;

	return hmac_final(pdesc, out);
}

static int hmac_init_tfm(struct ncrypto_tfm *tfm)
{
	struct crypto_tfm *hash;
	struct crypto_instance *inst = (void *)tfm->__crt_alg;
	const char *spawn = crypto_instance_ctx(inst);
	struct hmac_ctx *ctx = hmac_ctx(__crypto_hash_cast(tfm));

	hash = crypto_spawn_digest(spawn);
	if (IS_ERR(hash))
		return PTR_ERR(hash);

	ctx->child = hash;
	return 0;
}

static void hmac_exit_tfm(struct ncrypto_tfm *tfm)
{
	struct hmac_ctx *ctx = hmac_ctx(__crypto_hash_cast(tfm));
	crypto_free_tfm(ctx->child);
}

static void hmac_free(struct crypto_instance *inst)
{
	kfree(inst);
}

static struct crypto_instance *hmac_alloc(struct rtattr **tb)
{
	struct crypto_instance *inst;
	const char *name;
	struct crypto_tfm *tfm;
	struct crypto_alg *alg;
	int err;

	err = crypto_check_attr_type(tb, NCRYPTO_ALG_TYPE_HASH);
	if (err)
		return ERR_PTR(err);

	name = crypto_attr_alg_name(tb[1]);
	err = PTR_ERR(name);
	if (IS_ERR(name))
		return ERR_PTR(err);

	tfm = crypto_alloc_tfm(name, 0);
	if (!tfm)
		return ERR_PTR(-ENOENT);

	inst = ERR_PTR(-EINVAL);
	if (crypto_tfm_alg_type(tfm) != CRYPTO_ALG_TYPE_DIGEST)
		goto out_put_alg;

	alg = tfm->__crt_alg;

	inst = ocrypto_alloc_instance("hmac", alg);
	if (IS_ERR(inst))
		goto out_put_alg;

	inst->alg.cra_flags = NCRYPTO_ALG_TYPE_HASH;
	inst->alg.cra_priority = alg->cra_priority;
	inst->alg.cra_blocksize = alg->cra_blocksize;
	inst->alg.cra_alignmask = alg->cra_alignmask;
	inst->alg.cra_type = &crypto_hash_type;

	inst->alg.cra_hash.digestsize = alg->cra_digest.dia_digestsize;

	inst->alg.cra_ctxsize = sizeof(struct hmac_ctx) +
				ALIGN(inst->alg.cra_blocksize * 2 +
				      inst->alg.cra_hash.digestsize,
				      sizeof(void *));

	inst->alg.cra_init = hmac_init_tfm;
	inst->alg.cra_exit = hmac_exit_tfm;

	inst->alg.cra_hash.init = hmac_init;
	inst->alg.cra_hash.update = hmac_update;
	inst->alg.cra_hash.final = hmac_final;
	inst->alg.cra_hash.digest = hmac_digest;
	inst->alg.cra_hash.setkey = hmac_setkey;

out_put_alg:
	crypto_free_tfm(tfm);
	return inst;
}

static struct crypto_template hmac_tmpl = {
	.name = "hmac",
	.alloc = hmac_alloc,
	.free = hmac_free,
	.module = THIS_MODULE,
};

static int __init hmac_module_init(void)
{
	return crypto_register_template(&hmac_tmpl);
}

static void __exit hmac_module_exit(void)
{
	crypto_unregister_template(&hmac_tmpl);
}

module_init(hmac_module_init);
module_exit(hmac_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HMAC hash algorithm");
