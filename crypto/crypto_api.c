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

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/param.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "ninternal.h"

LIST_HEAD(ncrypto_alg_list);
EXPORT_SYMBOL_GPL(ncrypto_alg_list);
DECLARE_RWSEM(ncrypto_alg_sem);
EXPORT_SYMBOL_GPL(ncrypto_alg_sem);

BLOCKING_NOTIFIER_HEAD(crypto_chain);
EXPORT_SYMBOL_GPL(crypto_chain);

static inline struct ncrypto_alg *ncrypto_alg_get(struct ncrypto_alg *alg)
{
	atomic_inc(&alg->cra_refcnt);
	return alg;
}

struct ncrypto_alg *crypto_mod_get(struct ncrypto_alg *alg)
{
	return try_module_get(alg->cra_module) ? ncrypto_alg_get(alg) : NULL;
}
EXPORT_SYMBOL_GPL(crypto_mod_get);

void crypto_mod_put(struct ncrypto_alg *alg)
{
	struct module *module = alg->cra_module;

	ncrypto_alg_put(alg);
	module_put(module);
}
EXPORT_SYMBOL_GPL(crypto_mod_put);

static inline int crypto_is_test_larval(struct crypto_larval *larval)
{
	return larval->alg.cra_driver_name[0];
}

struct ncrypto_alg *__crypto_alg_lookup(const char *name, u32 type, u32 mask)
{
	struct ncrypto_alg *q, *alg = NULL;
	int best = -2;

	list_for_each_entry(q, &ncrypto_alg_list, cra_list) {
		int exact, fuzzy;

		if (crypto_is_moribund(q))
			continue;

		if ((q->cra_flags ^ type) & mask)
			continue;

		if (crypto_is_larval(q) &&
		    !crypto_is_test_larval((struct crypto_larval *)q) &&
		    ((struct crypto_larval *)q)->mask != mask)
			continue;

		exact = !strcmp(q->cra_driver_name, name);
		fuzzy = !strcmp(q->cra_name, name);
		if (!exact && !(fuzzy && q->cra_priority > best))
			continue;

		if (unlikely(!crypto_mod_get(q)))
			continue;

		best = q->cra_priority;
		if (alg)
			crypto_mod_put(alg);
		alg = q;

		if (exact)
			break;
	}

	return alg;
}
EXPORT_SYMBOL_GPL(__crypto_alg_lookup);

static void crypto_larval_destroy(struct ncrypto_alg *alg)
{
	struct crypto_larval *larval = (void *)alg;

	BUG_ON(!crypto_is_larval(alg));
	if (larval->adult)
		crypto_mod_put(larval->adult);
	kfree(larval);
}

struct crypto_larval *crypto_larval_alloc(const char *name, u32 type, u32 mask)
{
	struct crypto_larval *larval;

	larval = kzalloc(sizeof(*larval), GFP_KERNEL);
	if (!larval)
		return ERR_PTR(-ENOMEM);

	larval->mask = mask;
	larval->alg.cra_flags = NCRYPTO_ALG_LARVAL | type;
	larval->alg.cra_priority = -1;
	larval->alg.cra_destroy = crypto_larval_destroy;

	strlcpy(larval->alg.cra_name, name, CRYPTO_MAX_ALG_NAME);
	init_completion(&larval->completion);

	return larval;
}
EXPORT_SYMBOL_GPL(crypto_larval_alloc);

static struct ncrypto_alg *crypto_larval_add(const char *name, u32 type,
					     u32 mask)
{
	struct ncrypto_alg *alg;
	struct crypto_larval *larval;

	larval = crypto_larval_alloc(name, type, mask);
	if (IS_ERR(larval))
		return ERR_PTR(PTR_ERR((larval)));

	atomic_set(&larval->alg.cra_refcnt, 2);

	down_write(&ncrypto_alg_sem);
	alg = __crypto_alg_lookup(name, type, mask);
	if (!alg) {
		alg = &larval->alg;
		list_add(&alg->cra_list, &ncrypto_alg_list);
	}
	up_write(&ncrypto_alg_sem);

	if (alg != &larval->alg)
		kfree(larval);

	return alg;
}

void crypto_larval_kill(struct ncrypto_alg *alg)
{
	struct crypto_larval *larval = (void *)alg;

	down_write(&ncrypto_alg_sem);
	list_del(&alg->cra_list);
	up_write(&ncrypto_alg_sem);
	complete_all(&larval->completion);
	ncrypto_alg_put(alg);
}
EXPORT_SYMBOL_GPL(crypto_larval_kill);

static struct ncrypto_alg *crypto_larval_wait(struct ncrypto_alg *alg)
{
	struct crypto_larval *larval = (void *)alg;
	long timeout;

	timeout = wait_for_completion_interruptible_timeout(
		&larval->completion, 60 * HZ);

	alg = larval->adult;
	if (timeout < 0)
		alg = ERR_PTR(-EINTR);
	else if (!timeout)
		alg = ERR_PTR(-ETIMEDOUT);
	else if (!alg)
		alg = ERR_PTR(-ENOENT);
	else if (crypto_is_test_larval(larval) &&
		 !(alg->cra_flags & NCRYPTO_ALG_TESTED))
		alg = ERR_PTR(-EAGAIN);
	else if (!crypto_mod_get(alg))
		alg = ERR_PTR(-EAGAIN);
	crypto_mod_put(&larval->alg);

	return alg;
}

static struct ncrypto_alg *crypto_alg_lookup(const char *name, u32 type,
					     u32 mask)
{
	struct ncrypto_alg *alg;

	down_read(&ncrypto_alg_sem);
	alg = __crypto_alg_lookup(name, type, mask);
	up_read(&ncrypto_alg_sem);

	return alg;
}

struct ncrypto_alg *crypto_larval_lookup(const char *name, u32 type, u32 mask)
{
	struct ncrypto_alg *alg;

	if (!name)
		return ERR_PTR(-ENOENT);

	mask &= ~(NCRYPTO_ALG_LARVAL | NCRYPTO_ALG_DEAD);
	type &= mask;

	alg = try_then_request_module(crypto_alg_lookup(name, type, mask),
				      name);
	if (alg)
		return crypto_is_larval(alg) ? crypto_larval_wait(alg) : alg;

	return crypto_larval_add(name, type, mask);
}
EXPORT_SYMBOL_GPL(crypto_larval_lookup);

int crypto_probing_notify(unsigned long val, void *v)
{
	int ok;

	ok = blocking_notifier_call_chain(&crypto_chain, val, v);
	if (ok == NOTIFY_DONE) {
		request_module("cryptomgr");
		request_module("testmgr");
		ok = blocking_notifier_call_chain(&crypto_chain, val, v);
	}

	return ok;
}
EXPORT_SYMBOL_GPL(crypto_probing_notify);

struct ncrypto_alg *ncrypto_alg_mod_lookup(const char *name, u32 type, u32 mask)
{
	struct ncrypto_alg *alg;
	struct ncrypto_alg *larval;
	int ok;

	if (!((type | mask) & NCRYPTO_ALG_TESTED)) {
		type |= NCRYPTO_ALG_TESTED;
		mask |= NCRYPTO_ALG_TESTED;
	}

	larval = crypto_larval_lookup(name, type, mask);
	if (IS_ERR(larval) || !crypto_is_larval(larval))
		return larval;

	ok = crypto_probing_notify(CRYPTO_MSG_ALG_REQUEST, larval);

	if (ok == NOTIFY_STOP)
		alg = crypto_larval_wait(larval);
	else {
		crypto_mod_put(larval);
		alg = ERR_PTR(-ENOENT);
	}
	crypto_larval_kill(larval);
	return alg;
}
EXPORT_SYMBOL_GPL(ncrypto_alg_mod_lookup);

static int crypto_init_ops(struct ncrypto_tfm *tfm, u32 type, u32 mask)
{
	return tfm->__crt_alg->cra_type->init(tfm, type, mask);
}

static void crypto_exit_ops(struct ncrypto_tfm *tfm)
{
	const struct crypto_type *type = tfm->__crt_alg->cra_type;

	if (type->exit)
		type->exit(tfm);
	return;
}

static unsigned int crypto_ctxsize(struct ncrypto_alg *alg, u32 type, u32 mask)
{
	unsigned int len;

	len = alg->cra_alignmask & ~(ncrypto_tfm_ctx_alignment() - 1);
	return len + alg->cra_type->ctxsize(alg, type, mask);
}

void crypto_shoot_alg(struct ncrypto_alg *alg)
{
	down_write(&ncrypto_alg_sem);
	alg->cra_flags |= NCRYPTO_ALG_DYING;
	up_write(&ncrypto_alg_sem);
}
EXPORT_SYMBOL_GPL(crypto_shoot_alg);

struct ncrypto_tfm *__crypto_alloc_tfm(struct ncrypto_alg *alg, u32 type,
				       u32 mask)
{
	struct ncrypto_tfm *tfm = NULL;
	unsigned int tfm_size;
	int err = -ENOMEM;

	tfm_size = sizeof(*tfm) + crypto_ctxsize(alg, type, mask);
	tfm = kzalloc(tfm_size, GFP_KERNEL);
	if (tfm == NULL)
		goto out_err;

	tfm->__crt_alg = alg;

	err = crypto_init_ops(tfm, type, mask);
	if (err)
		goto out_free_tfm;

	if (alg->cra_init && (err = alg->cra_init(tfm))) {
		if (err == -EAGAIN)
			crypto_shoot_alg(alg);
		goto cra_init_failed;
	}

	goto out;

cra_init_failed:
	crypto_exit_ops(tfm);
out_free_tfm:
	kfree(tfm);
out_err:
	tfm = ERR_PTR(err);
out:
	return tfm;
}
EXPORT_SYMBOL_GPL(__crypto_alloc_tfm);

/*
 *	crypto_alloc_base - Locate algorithm and allocate transform
 *	@alg_name: Name of algorithm
 *	@type: Type of algorithm
 *	@mask: Mask for type comparison
 *
 *	crypto_alloc_base() will first attempt to locate an already loaded
 *	algorithm.  If that fails and the kernel supports dynamically loadable
 *	modules, it will then attempt to load a module of the same name or
 *	alias.  If that fails it will send a query to any loaded crypto manager
 *	to construct an algorithm on the fly.  A refcount is grabbed on the
 *	algorithm which is then associated with the new transform.
 *
 *	The returned transform is of a non-determinate type.  Most people
 *	should use one of the more specific allocation functions such as
 *	crypto_alloc_blkcipher.
 *
 *	In case of error the return value is an error pointer.
 */
struct ncrypto_tfm *crypto_alloc_base(const char *alg_name, u32 type, u32 mask)
{
	struct ncrypto_tfm *tfm;
	int err;

	for (;;) {
		struct ncrypto_alg *alg;

		alg = ncrypto_alg_mod_lookup(alg_name, type, mask);
		if (IS_ERR(alg)) {
			err = PTR_ERR(alg);
			goto err;
		}

		tfm = __crypto_alloc_tfm(alg, type, mask);
		if (!IS_ERR(tfm))
			return tfm;

		crypto_mod_put(alg);
		err = PTR_ERR(tfm);

err:
		if (err != -EAGAIN)
			break;
		if (signal_pending(current)) {
			err = -EINTR;
			break;
		}
	}

	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(crypto_alloc_base);
 
/*
 *	ncrypto_free_tfm - Free crypto transform
 *	@tfm: Transform to free
 *
 *	ncrypto_free_tfm() frees up the transform and any associated resources,
 *	then drops the refcount on the associated algorithm.
 */
void ncrypto_free_tfm(struct ncrypto_tfm *tfm)
{
	struct ncrypto_alg *alg;
	int size;

	if (unlikely(!tfm))
		return;

	alg = tfm->__crt_alg;
	size = sizeof(*tfm) + alg->cra_ctxsize;

	if (alg->cra_exit)
		alg->cra_exit(tfm);
	crypto_exit_ops(tfm);
	crypto_mod_put(alg);
	memset(tfm, 0, size);
	kfree(tfm);
}

EXPORT_SYMBOL_GPL(ncrypto_free_tfm);

int crypto_has_alg(const char *name, u32 type, u32 mask)
{
	int ret = 0;
	struct ncrypto_alg *alg = ncrypto_alg_mod_lookup(name, type, mask);
	
	if (!IS_ERR(alg)) {
		crypto_mod_put(alg);
		ret = 1;
	}
	
	return ret;
}
EXPORT_SYMBOL_GPL(crypto_has_alg);

static int __init crypto_api_init(void)
{
	return 0;
}

static void __exit crypto_api_exit(void)
{
}

module_init(crypto_api_init);
module_exit(crypto_api_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Cryptographic API (backported)");
