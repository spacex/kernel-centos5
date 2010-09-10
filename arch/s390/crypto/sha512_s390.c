/*
 * Cryptographic API.
 *
 * s390 implementation of the SHA512 Secure Hash Algorithm.
 *
 * Copyright IBM Corp. 2007
 * Author(s): Jan Glauber (jang@de.ibm.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>

#include "crypt_s390.h"

#define SHA384_DIGEST_SIZE	48
#define SHA384_BLOCK_SIZE	128

#define SHA512_DIGEST_SIZE      64
#define SHA512_BLOCK_SIZE       128

struct s390_sha512_ctx {
        u64 count;
        u64 state[8];
        u8 buf[2 * SHA512_BLOCK_SIZE];
};

static void sha512_init(struct crypto_tfm *tfm)
{
	struct s390_sha512_ctx *sctx = crypto_tfm_ctx(tfm);

	sctx->state[0] = 0x6a09e667f3bcc908ULL;
	sctx->state[1] = 0xbb67ae8584caa73bULL;
	sctx->state[2] = 0x3c6ef372fe94f82bULL;
	sctx->state[3] = 0xa54ff53a5f1d36f1ULL;
	sctx->state[4] = 0x510e527fade682d1ULL;
	sctx->state[5] = 0x9b05688c2b3e6c1fULL;
	sctx->state[6] = 0x1f83d9abfb41bd6bULL;
	sctx->state[7] = 0x5be0cd19137e2179ULL;
	sctx->count = 0;
	memset(sctx->buf, 0, sizeof(sctx->buf));
}

static void sha384_init(struct crypto_tfm *tfm)
{
	struct s390_sha512_ctx *sctx = crypto_tfm_ctx(tfm);

	sctx->state[0] = 0xcbbb9d5dc1059ed8ULL;
	sctx->state[1] = 0x629a292a367cd507ULL;
	sctx->state[2] = 0x9159015a3070dd17ULL;
	sctx->state[3] = 0x152fecd8f70e5939ULL;
	sctx->state[4] = 0x67332667ffc00b31ULL;
	sctx->state[5] = 0x8eb44a8768581511ULL;
	sctx->state[6] = 0xdb0c2e0d64f98fa7ULL;
	sctx->state[7] = 0x47b5481dbefa4fa4ULL;
	sctx->count = 0;
	memset(sctx->buf, 0, sizeof(sctx->buf));
}

static void sha512_update(struct crypto_tfm *tfm, const u8 *data, unsigned int len)
{      
	struct s390_sha512_ctx *sctx = crypto_tfm_ctx(tfm);
	unsigned int bsize = SHA512_BLOCK_SIZE;
	unsigned int index;
	int ret;

	/* how much is already in the buffer? */
	index = sctx->count & (bsize - 1);
	sctx->count += len;

	if ((index + len) < bsize)
		goto store; 

	/* process one stored block */
	if (index) {
		memcpy(sctx->buf + index, data, bsize - index);
		ret = crypt_s390_kimd(KIMD_SHA_512, sctx->state, sctx->buf, bsize);
		BUG_ON(ret != bsize);
		data += bsize - index;
		len -= bsize - index;
	}

	/* process as many blocks as possible */
	if (len >= bsize) {     
		ret = crypt_s390_kimd(KIMD_SHA_512, sctx->state, data, len & ~(bsize - 1));
		BUG_ON(ret != (len & ~(bsize - 1)));
		data += ret;
		len -= ret;
	}
store:
	/* anything left? */
	if (len)
		memcpy(sctx->buf + index , data, len);
}

static void sha512_final(struct crypto_tfm *tfm, u8 *out)
{
	struct s390_sha512_ctx *sctx = crypto_tfm_ctx(tfm);
	unsigned int bsize = SHA512_BLOCK_SIZE;
	u64 bits;
	unsigned int index, end;
	int ret;

	/* must perform manual padding */
	index = sctx->count & (bsize - 1);
	end = (index < bsize - 16) ? bsize : (2 * bsize);

	sctx->buf[index] = 0x80;                 /* start pad with 1 */
	index++;

	/* pad with zeros */
	memset(sctx->buf + index, 0x00, end - index - 8);

	/*
	 * Append message length. Well, SHA-512 wants a 128 bit lenght value,
	 * nevertheless I use u64, 64 bit message length should be enough for now.
	 */
	bits = sctx->count * 8;
	memcpy(sctx->buf + end - 8, &bits, sizeof(bits));

	ret = crypt_s390_kimd(KIMD_SHA_512, sctx->state, sctx->buf, end);
	BUG_ON(ret != end);

	memcpy(out, sctx->state, SHA512_DIGEST_SIZE);		/* copy digest to out */
	memset(sctx, 0, sizeof *sctx);				/* wipe context */
}

static void sha384_final(struct crypto_tfm *tfm, u8 *out)
{
	struct s390_sha512_ctx *sctx = crypto_tfm_ctx(tfm);
	u8 hash[SHA512_DIGEST_SIZE];

	sha512_final(tfm, hash);

	memcpy(out, hash, SHA384_DIGEST_SIZE);		/* copy digest to out */
	memset(sctx, 0, sizeof *sctx);			/* wipe context */
}

static struct crypto_alg sha512_alg = {
	.cra_name	=	"sha512",
	.cra_driver_name =	"sha512-s390",
	.cra_flags	=	CRYPTO_ALG_TYPE_DIGEST,
	.cra_blocksize	=	SHA512_BLOCK_SIZE,
	.cra_ctxsize	=	sizeof(struct s390_sha512_ctx),
	.cra_module	=	THIS_MODULE,
	.cra_list	=	LIST_HEAD_INIT(sha512_alg.cra_list),
	.cra_u		=	{ .digest = {
	.dia_digestsize	=	SHA512_DIGEST_SIZE,
	.dia_init	=	sha512_init,
	.dia_update	=	sha512_update,
	.dia_final	=	sha512_final } }
};

static struct crypto_alg sha384_alg = {
	.cra_name       =       "sha384",
	.cra_driver_name =      "sha384-s390",
	.cra_flags      =       CRYPTO_ALG_TYPE_DIGEST,
	.cra_blocksize  =       SHA384_BLOCK_SIZE,
	.cra_ctxsize    =       sizeof(struct s390_sha512_ctx),
	.cra_module     =       THIS_MODULE,
	.cra_list       =       LIST_HEAD_INIT(sha384_alg.cra_list),
	.cra_u          =       { .digest = {
	.dia_digestsize =       SHA384_DIGEST_SIZE,
	.dia_init       =       sha384_init,
	.dia_update     =       sha512_update,
	.dia_final      =       sha384_final } }
};

static int __init init(void)
{
	int ret;

	if (!crypt_s390_func_available(KIMD_SHA_512))
		return -EOPNOTSUPP;
	ret = crypto_register_alg(&sha512_alg);
	if (ret < 0)
		goto out;
	ret = crypto_register_alg(&sha384_alg);
	if (ret < 0)
		crypto_unregister_alg(&sha512_alg);
out:
	return ret;
}

static void __exit fini(void)
{
	crypto_unregister_alg(&sha512_alg);
	crypto_unregister_alg(&sha384_alg);
}

module_init(init);
module_exit(fini);

MODULE_ALIAS("sha512");
MODULE_ALIAS("sha384");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SHA512 and SHA-384 Secure Hash Algorithm");
