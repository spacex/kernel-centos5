/*
 * Cipher operations.
 * 
 * Copyright (c) 2006 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 */

#include <linux/ncrypto.h>
#include <linux/kernel.h>
#include <linux/module.h>

struct crypto_cipher *crypto_alloc_cipher(const char *alg_name,
					  u32 type, u32 mask)
{
	struct crypto_tfm *tfm = crypto_alloc_tfm(alg_name, 0);

	if (!tfm)
		return ERR_PTR(-ENOENT);

	if (crypto_tfm_alg_type(tfm) != CRYPTO_ALG_TYPE_CIPHER)
		return ERR_PTR(-EINVAL);

	return __crypto_cipher_cast(tfm);
}
EXPORT_SYMBOL_GPL(crypto_alloc_cipher);

static void cipher_crypt_unaligned(void (*fn)(struct crypto_tfm *, u8 *,
					      const u8 *),
				   struct crypto_cipher *tfm,
				   u8 *dst, const u8 *src)
{
	unsigned long alignmask = crypto_cipher_alignmask(tfm);
	unsigned int size = crypto_cipher_blocksize(tfm);
	u8 buffer[size + alignmask];
	u8 *tmp = (u8 *)ALIGN((unsigned long)buffer, alignmask + 1);

	memcpy(tmp, src, size);
	fn(crypto_cipher_tfm(tfm), tmp, tmp);
	memcpy(dst, tmp, size);
}

void crypto_cipher_encrypt_one(struct crypto_cipher *tfm,
			       u8 *dst, const u8 *src)
{
	unsigned long alignmask = crypto_tfm_alg_alignmask(tfm);
	struct cipher_alg *cipher = &tfm->__crt_alg->cra_cipher;

	if (unlikely(((unsigned long)dst | (unsigned long)src) & alignmask)) {
		cipher_crypt_unaligned(cipher->cia_encrypt, tfm, dst, src);
		return;
	}

	cipher->cia_encrypt(tfm, dst, src);
}
EXPORT_SYMBOL_GPL(crypto_cipher_encrypt_one);

void crypto_cipher_decrypt_one(struct crypto_cipher *tfm,
			       u8 *dst, const u8 *src)
{
	unsigned long alignmask = crypto_tfm_alg_alignmask(tfm);
	struct cipher_alg *cipher = &tfm->__crt_alg->cra_cipher;

	if (unlikely(((unsigned long)dst | (unsigned long)src) & alignmask)) {
		cipher_crypt_unaligned(cipher->cia_decrypt, tfm, dst, src);
		return;
	}

	cipher->cia_decrypt(tfm, dst, src);
}
EXPORT_SYMBOL_GPL(crypto_cipher_decrypt_one);
