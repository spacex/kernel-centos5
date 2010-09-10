/*
 * RNG: Random Number Generator  algorithms under the crypto API
 *
 * Copyright (c) 2008 Neil Horman <nhorman@tuxdriver.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#ifndef _CRYPTO_RNG_H
#define _CRYPTO_RNG_H

#include <linux/crypto.h>

#define NCRYPTO_ALG_TYPE_RNG		0x0000000c

/*
 * RNG behavioral flags
 * CRYPTO_RNG_TEST_MODE
 *   places the RNG into a test mode for various certification tests.  Some
 *   RNG's (most notably Deterministic RNGs) Can have internal tests which are 
 *   required in normal operation mode, but affect the deterministic output 
 *   of the RNG which throws some test vectors off, as they may not account for
 *   these tests.  This flag allows us to disable the internal tests of an RNG.
 */
#define CRYPTO_RNG_TEST_MODE	0x01

struct crypto_rng;

struct rng_alg {
	int (*rng_make_random)(struct crypto_rng *tfm, u8 *rdata,
			       unsigned int dlen);
	int (*rng_reset)(struct crypto_rng *tfm, u8 *seed, unsigned int slen);

	int (*rng_set_flags)(struct crypto_rng *tfm, u8 flags);

	int (*rng_get_flags)(struct crypto_rng *tfm, u8 *flags);

	unsigned int seedsize;
};

struct rng_tfm {
	int (*rng_gen_random)(struct crypto_rng *tfm, u8 *rdata,
			      unsigned int dlen);
	int (*rng_reset)(struct crypto_rng *tfm, u8 *seed, unsigned int slen);

	int (*rng_set_flags)(struct crypto_rng *tfm, u8 flags);

	int (*rng_get_flags)(struct crypto_rng *tfm, u8 *flags);
};

struct crypto_rng {
	struct ncrypto_tfm base;
};

extern struct crypto_rng *crypto_default_rng;

int crypto_get_default_rng(void);
void crypto_put_default_rng(void);

static inline struct crypto_rng *__crypto_rng_cast(struct ncrypto_tfm *tfm)
{
	return (struct crypto_rng *)tfm;
}

static inline struct crypto_rng *crypto_alloc_rng(const char *alg_name,
						  u32 type, u32 mask)
{
	type &= ~NCRYPTO_ALG_TYPE_MASK;
	type |= NCRYPTO_ALG_TYPE_RNG;
	mask |= NCRYPTO_ALG_TYPE_MASK;

	return __crypto_rng_cast(crypto_alloc_base(alg_name, type, mask));
}

static inline struct ncrypto_tfm *crypto_rng_tfm(struct crypto_rng *tfm)
{
	return &tfm->base;
}

static inline struct rng_alg *crypto_rng_alg(struct crypto_rng *tfm)
{
	return (struct rng_alg *)&crypto_rng_tfm(tfm)->__crt_alg->cra_u;
}

static inline struct rng_tfm *crypto_rng_crt(struct crypto_rng *tfm)
{
	return (struct rng_tfm *)&crypto_rng_tfm(tfm)->crt_u;
}

static inline void crypto_free_rng(struct crypto_rng *tfm)
{
	ncrypto_free_tfm(crypto_rng_tfm(tfm));
}

static inline int crypto_rng_get_bytes(struct crypto_rng *tfm,
				       u8 *rdata, unsigned int dlen)
{
	return crypto_rng_crt(tfm)->rng_gen_random(tfm, rdata, dlen);
}

static inline int crypto_rng_reset(struct crypto_rng *tfm,
				   u8 *seed, unsigned int slen)
{
	return crypto_rng_crt(tfm)->rng_reset(tfm, seed, slen);
}

static inline int crypto_rng_seedsize(struct crypto_rng *tfm)
{
	return crypto_rng_alg(tfm)->seedsize;
}

static inline int crypto_rng_set_flags(struct crypto_rng *tfm, u8 flags)
{
	return crypto_rng_alg(tfm)->rng_set_flags(tfm, flags);
}

static inline int crypto_rng_get_flags(struct crypto_rng *tfm, u8 *flags)
{
	return crypto_rng_alg(tfm)->rng_get_flags(tfm, flags);
}

#endif
