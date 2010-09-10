/*
 * Scatterlist Cryptographic API.
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2002 David S. Miller (davem@redhat.com)
 * Copyright (c) 2005 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * Portions derived from Cryptoapi, by Alexander Kjeldaas <astor@fast.no>
 * and Nettle, by Niels Möller.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 */

#include <linux/completion.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "internal.h"

LIST_HEAD(crypto_alg_list);
DECLARE_RWSEM(crypto_alg_sem);

BLOCKING_NOTIFIER_HEAD(ocrypto_chain);
EXPORT_SYMBOL_GPL(ocrypto_chain);

static inline int crypto_alg_get(struct crypto_alg *alg)
{
	return try_module_get(alg->cra_module);
}

static inline void crypto_alg_put(struct crypto_alg *alg)
{
	module_put(alg->cra_module);
}

static struct crypto_alg *crypto_alg_lookup(const char *name)
{
	struct crypto_alg *q, *alg = NULL;
	int best = -1;

	if (!name)
		return NULL;
	
	down_read(&crypto_alg_sem);
	
	list_for_each_entry(q, &crypto_alg_list, cra_list) {
		int exact, fuzzy;

		exact = !strcmp(q->cra_driver_name, name);
		fuzzy = !strcmp(q->cra_name, name);
		if (!exact && !(fuzzy && q->cra_priority > best))
			continue;

		if (unlikely(!crypto_alg_get(q)))
			continue;

		best = q->cra_priority;
		if (alg)
			crypto_alg_put(alg);
		alg = q;

		if (exact)
			break;
	}
	
	up_read(&crypto_alg_sem);
	return alg;
}

/* A far more intelligent version of this is planned.  For now, just
 * try an exact match on the name of the algorithm. */
static inline struct crypto_alg *crypto_alg_mod_lookup(const char *name)
{
	return try_then_request_module(crypto_alg_lookup(name), name);
}

static int crypto_init_flags(struct crypto_tfm *tfm, u32 flags)
{
	tfm->crt_flags = flags & CRYPTO_TFM_REQ_MASK;
	flags &= ~CRYPTO_TFM_REQ_MASK;
	
	switch (crypto_tfm_alg_type(tfm)) {
	case CRYPTO_ALG_TYPE_CIPHER:
		return crypto_init_cipher_flags(tfm, flags);
		
	case CRYPTO_ALG_TYPE_DIGEST:
		return crypto_init_digest_flags(tfm, flags);
		
	case CRYPTO_ALG_TYPE_COMPRESS:
		return crypto_init_compress_flags(tfm, flags);
	
	default:
		break;
	}
	
	BUG();
	return -EINVAL;
}

static int crypto_init_ops(struct crypto_tfm *tfm)
{
	switch (crypto_tfm_alg_type(tfm)) {
	case CRYPTO_ALG_TYPE_CIPHER:
		return crypto_init_cipher_ops(tfm);
		
	case CRYPTO_ALG_TYPE_DIGEST:
		return crypto_init_digest_ops(tfm);
		
	case CRYPTO_ALG_TYPE_COMPRESS:
		return crypto_init_compress_ops(tfm);
	
	default:
		break;
	}
	
	BUG();
	return -EINVAL;
}

static void crypto_exit_ops(struct crypto_tfm *tfm)
{
	switch (crypto_tfm_alg_type(tfm)) {
	case CRYPTO_ALG_TYPE_CIPHER:
		crypto_exit_cipher_ops(tfm);
		break;
		
	case CRYPTO_ALG_TYPE_DIGEST:
		crypto_exit_digest_ops(tfm);
		break;
		
	case CRYPTO_ALG_TYPE_COMPRESS:
		crypto_exit_compress_ops(tfm);
		break;
	
	default:
		BUG();
		
	}
}

static unsigned int crypto_ctxsize(struct crypto_alg *alg, int flags)
{
	unsigned int len;

	switch (alg->cra_flags & CRYPTO_ALG_TYPE_MASK) {
	default:
		BUG();

	case CRYPTO_ALG_TYPE_CIPHER:
		len = crypto_cipher_ctxsize(alg, flags);
		break;
		
	case CRYPTO_ALG_TYPE_DIGEST:
		len = crypto_digest_ctxsize(alg, flags);
		break;
		
	case CRYPTO_ALG_TYPE_COMPRESS:
		len = crypto_compress_ctxsize(alg, flags);
		break;
	}

	return len + (alg->cra_alignmask & ~(crypto_tfm_ctx_alignment() - 1));
}

struct crypto_tfm *crypto_alloc_tfm2(const char *name, u32 flags,
				     int nomodload)
{
	struct crypto_tfm *tfm = NULL;
	struct crypto_alg *alg;
	unsigned int tfm_size;

	if (!nomodload)
		alg = crypto_alg_mod_lookup(name);
	else
		alg = crypto_alg_lookup(name);

	if (alg == NULL)
		goto out;

	tfm_size = sizeof(*tfm) + crypto_ctxsize(alg, flags);
	tfm = kzalloc(tfm_size, GFP_KERNEL);
	if (tfm == NULL)
		goto out_put;

	tfm->__crt_alg = alg;
	
	if (crypto_init_flags(tfm, flags))
		goto out_free_tfm;
		
	if (crypto_init_ops(tfm))
		goto out_free_tfm;

	if (alg->cra_init && alg->cra_init(tfm))
		goto cra_init_failed;

	goto out;

cra_init_failed:
	crypto_exit_ops(tfm);
out_free_tfm:
	kfree(tfm);
	tfm = NULL;
out_put:
	crypto_alg_put(alg);
out:
	return tfm;
}

struct crypto_tfm *crypto_alloc_tfm(const char *name, u32 flags)
{
	return crypto_alloc_tfm2(name, flags, 0);
}

void crypto_free_tfm(struct crypto_tfm *tfm)
{
	struct crypto_alg *alg;
	int size;

	if (unlikely(!tfm))
		return;

	alg = tfm->__crt_alg;
	size = sizeof(*tfm) + alg->cra_ctxsize;

	if (alg->cra_exit)
		alg->cra_exit(tfm);
	crypto_exit_ops(tfm);
	crypto_alg_put(alg);
	memset(tfm, 0, size);
	kfree(tfm);
}

static inline int crypto_set_driver_name(struct crypto_alg *alg)
{
	static const char suffix[] = "-generic";
	char *driver_name = alg->cra_driver_name;
	int len;

	if (*driver_name)
		return 0;

	len = strlcpy(driver_name, alg->cra_name, CRYPTO_MAX_ALG_NAME);
	if (len + sizeof(suffix) > CRYPTO_MAX_ALG_NAME)
		return -ENAMETOOLONG;

	memcpy(driver_name + len, suffix, sizeof(suffix));
	return 0;
}

static int ocrypto_probing_notify(unsigned long val, void *v)
{
	int ok;

	ok = blocking_notifier_call_chain(&ocrypto_chain, val, v);
	if (ok == NOTIFY_DONE) {
		request_module("testmgr_cipher");
		ok = blocking_notifier_call_chain(&ocrypto_chain, val, v);
	}

	return ok;
}

static DECLARE_COMPLETION(test_done);
static int test_err;

void ocrypto_alg_tested(const char *name, int err)
{
	test_err = err;
	complete(&test_done);
}
EXPORT_SYMBOL_GPL(ocrypto_alg_tested);

int crypto_register_alg(struct crypto_alg *alg)
{
	int ret;
	struct crypto_alg *q;
	struct crypto_cipher_test param;
	static DEFINE_MUTEX(test_lock);

	if (alg->cra_alignmask & (alg->cra_alignmask + 1))
		return -EINVAL;

	if (alg->cra_alignmask & alg->cra_blocksize)
		return -EINVAL;

	if (alg->cra_blocksize > PAGE_SIZE / 8)
		return -EINVAL;

	if (alg->cra_priority < 0)
		return -EINVAL;
	
	ret = crypto_set_driver_name(alg);
	if (unlikely(ret))
		return ret;

	param.alg = alg;
	memcpy(param.name, alg->cra_name, CRYPTO_MAX_ALG_NAME);
	memcpy(alg->cra_name, "untested", sizeof("untested"));

	mutex_lock(&test_lock);

	down_write(&crypto_alg_sem);
	
	list_for_each_entry(q, &crypto_alg_list, cra_list) {
		if (q == alg) {
			ret = -EEXIST;
			goto out;
		}
	}
	
	list_add(&alg->cra_list, &crypto_alg_list);
out:	
	up_write(&crypto_alg_sem);

	if (ret)
		goto out2;

	switch (alg->cra_flags & CRYPTO_ALG_TYPE_MASK) {
	case CRYPTO_ALG_TYPE_CIPHER:
		INIT_COMPLETION(test_done);
		ret = ocrypto_probing_notify(CRYPTO_MSG_ALG_REGISTER, &param);
		if (ret != NOTIFY_STOP) {
			if (unlikely(ret != NOTIFY_DONE)) {
				WARN_ON(1);
				ret = -EINVAL;
				break;
			}
			ocrypto_alg_tested(alg->cra_driver_name, 0);
		}

		ret = wait_for_completion_interruptible(&test_done);
		if (unlikely(ret))
			WARN_ON(1);
		else
			ret = test_err;
		break;

	case CRYPTO_ALG_TYPE_DIGEST:
		ret = digest_test(alg->cra_driver_name, param.name);
		break;
	}

	if (ret)
		crypto_unregister_alg(alg);

out2:
	memcpy(alg->cra_name, param.name, CRYPTO_MAX_ALG_NAME);
	mutex_unlock(&test_lock);
	return ret;
}

int crypto_unregister_alg(struct crypto_alg *alg)
{
	int ret = -ENOENT;
	struct crypto_alg *q;
	
	BUG_ON(!alg->cra_module);
	
	down_write(&crypto_alg_sem);
	list_for_each_entry(q, &crypto_alg_list, cra_list) {
		if (alg == q) {
			list_del(&alg->cra_list);
			ret = 0;
			goto out;
		}
	}
out:	
	up_write(&crypto_alg_sem);
	return ret;
}

int crypto_alg_available(const char *name, u32 flags)
{
	int ret = 0;
	struct crypto_alg *alg = crypto_alg_mod_lookup(name);
	
	if (alg) {
		crypto_alg_put(alg);
		ret = 1;
	}
	
	return ret;
}

int ocrypto_register_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&ocrypto_chain, nb);
}
EXPORT_SYMBOL_GPL(ocrypto_register_notifier);

int ocrypto_unregister_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&ocrypto_chain, nb);
}
EXPORT_SYMBOL_GPL(ocrypto_unregister_notifier);

static int __init init_crypto(void)
{
	printk(KERN_INFO "Initializing Cryptographic API\n");
	crypto_init_proc();
	return 0;
}

__initcall(init_crypto);

EXPORT_SYMBOL_GPL(crypto_register_alg);
EXPORT_SYMBOL_GPL(crypto_unregister_alg);
EXPORT_SYMBOL_GPL(crypto_alloc_tfm);
EXPORT_SYMBOL_GPL(crypto_free_tfm);
EXPORT_SYMBOL_GPL(crypto_alg_available);
