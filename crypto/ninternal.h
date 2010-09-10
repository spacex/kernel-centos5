/*
 * Cryptographic API.
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2005 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 */
#ifndef _CRYPTO_NINTERNAL_H
#define _CRYPTO_NINTERNAL_H

#include <crypto/algapi.h>
#include <linux/notifier.h>

#include "internal.h"

struct crypto_larval {
	struct ncrypto_alg alg;
	struct ncrypto_alg *adult;
	struct completion completion;
	u32 mask;
};

extern struct list_head ncrypto_alg_list;
extern struct rw_semaphore ncrypto_alg_sem;
extern struct blocking_notifier_head crypto_chain;

struct ncrypto_alg *crypto_mod_get(struct ncrypto_alg *alg);
struct ncrypto_alg *__crypto_alg_lookup(const char *name, u32 type, u32 mask);
struct ncrypto_alg *ncrypto_alg_mod_lookup(const char *name, u32 type,
					   u32 mask);

struct crypto_larval *crypto_larval_alloc(const char *name, u32 type, u32 mask);
void crypto_larval_kill(struct ncrypto_alg *alg);
struct ncrypto_alg *crypto_larval_lookup(const char *name, u32 type, u32 mask);
void crypto_larval_error(const char *name, u32 type, u32 mask);
void crypto_alg_tested(const char *name, int err);

void crypto_shoot_alg(struct ncrypto_alg *alg);
struct ncrypto_tfm *__crypto_alloc_tfm(struct ncrypto_alg *alg, u32 type,
				       u32 mask);

int crypto_register_instance(struct crypto_template *tmpl,
			     struct crypto_instance *inst);

int crypto_register_notifier(struct notifier_block *nb);
int crypto_unregister_notifier(struct notifier_block *nb);
int crypto_probing_notify(unsigned long val, void *v);

static inline void ncrypto_alg_put(struct ncrypto_alg *alg)
{
	if (atomic_dec_and_test(&alg->cra_refcnt) && alg->cra_destroy)
		alg->cra_destroy(alg);
}

static inline int crypto_tmpl_get(struct crypto_template *tmpl)
{
	return try_module_get(tmpl->module);
}

static inline void crypto_tmpl_put(struct crypto_template *tmpl)
{
	module_put(tmpl->module);
}

static inline int crypto_is_larval(struct ncrypto_alg *alg)
{
	return alg->cra_flags & NCRYPTO_ALG_LARVAL;
}

static inline int crypto_is_dead(struct ncrypto_alg *alg)
{
	return alg->cra_flags & NCRYPTO_ALG_DEAD;
}

static inline int crypto_is_moribund(struct ncrypto_alg *alg)
{
	return alg->cra_flags & (NCRYPTO_ALG_DEAD | NCRYPTO_ALG_DYING);
}

static inline void crypto_notify(unsigned long val, void *v)
{
	blocking_notifier_call_chain(&crypto_chain, val, v);
}

#endif	/* _CRYPTO_NINTERNAL_H */
