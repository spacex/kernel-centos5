/*
 * Algorithm testing framework and tests.
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2002 Jean-Francois Dive <jef@linuxbe.org>
 * Copyright (c) 2007 Nokia Siemens Networks
 * Copyright (c) 2008 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * 2007-11-13 Added AEAD support
 * 2004-08-09 Added cipher speed tests (Reyk Floeter <reyk@vantronix.net>)
 * 2003-09-14 Rewritten by Kartikey Mahendra Bhatt
 *
 */

#include <linux/err.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "ninternal.h"
#include "testmgr.h"

/*
 * Need slab memory for testing (size in number of pages).
 */
#define XBUFSIZE	8

/*
 * Indexes into the xbuf to simulate cross-page access.
 */
#define IDX1		32
#define IDX2		32400
#define IDX3		1
#define IDX4		8193
#define IDX5		22222
#define IDX6		17101
#define IDX7		27333
#define IDX8		3000

/*
* Used by test_cipher()
*/
#define ENCRYPT 1
#define DECRYPT 0

struct tcrypt_result {
	struct completion completion;
	int err;
};

struct aead_test_suite {
	struct {
		struct aead_testvec *vecs;
		unsigned int count;
	} enc, dec;
};

struct cipher_test_suite {
	struct {
		struct cipher_testvec *vecs;
		unsigned int count;
	} enc, dec;
};

struct comp_test_suite {
	struct {
		struct comp_testvec *vecs;
		unsigned int count;
	} comp, decomp;
};

struct hash_test_suite {
	struct hash_testvec *vecs;
	unsigned int count;
};

struct alg_test_desc {
	const char *alg;
	int (*test)(const struct alg_test_desc *desc, const char *driver,
		    u32 type, u32 mask);

	union {
		struct aead_test_suite aead;
		struct cipher_test_suite cipher;
		struct comp_test_suite comp;
		struct hash_test_suite hash;
	} suite;
};

struct crypto_test_param {
	char driver[CRYPTO_MAX_ALG_NAME];
	char alg[CRYPTO_MAX_ALG_NAME];
	u32 type;
};

static unsigned int IDX[8] = { IDX1, IDX2, IDX3, IDX4, IDX5, IDX6, IDX7, IDX8 };

static char *xbuf[XBUFSIZE];
static char *axbuf[XBUFSIZE];

static void hexdump(unsigned char *buf, unsigned int len)
{
	while (len--)
		printk("%02x", *buf++);

	printk("\n");
}

static void tcrypt_complete(struct crypto_async_request *req, int err)
{
	struct tcrypt_result *res = req->data;

	if (err == -EINPROGRESS)
		return;

	res->err = err;
	complete(&res->completion);
}

static int test_nhash(struct crypto_hash *tfm, struct hash_testvec *template,
		      unsigned int tcount)
{
	const char *algo = ncrypto_tfm_alg_driver_name(crypto_hash_tfm(tfm));
	unsigned int i, j, k, temp;
	struct scatterlist sg[8];
	char result[64];
	struct hash_desc desc;
	int ret;
	void *hash_buff;

	desc.tfm = tfm;
	desc.flags = 0;

	for (i = 0; i < tcount; i++) {
		memset(result, 0, 64);

		hash_buff = xbuf[0];

		memcpy(hash_buff, template[i].plaintext, template[i].psize);
		sg_init_one(&sg[0], hash_buff, template[i].psize);

		if (template[i].ksize) {
			ret = crypto_hash_setkey(tfm, template[i].key,
						 template[i].ksize);
			if (ret) {
				printk(KERN_ERR "alg: hash: setkey failed on "
				       "test %d for %s: ret=%d\n", i + 1, algo,
				       -ret);
				goto out;
			}
		}

		ret = crypto_hash_digest(&desc, sg, template[i].psize, result);
		if (ret) {
			printk(KERN_ERR "alg: hash: digest failed on test %d "
			       "for %s: ret=%d\n", i + 1, algo, -ret);
			goto out;
		}

		if (memcmp(result, template[i].digest,
			   crypto_hash_digestsize(tfm))) {
			printk(KERN_ERR "alg: hash: Test %d failed for %s\n",
			       i + 1, algo);
			hexdump(result, crypto_hash_digestsize(tfm));
			ret = -EINVAL;
			goto out;
		}
	}

	j = 0;
	for (i = 0; i < tcount; i++) {
		if (template[i].np) {
			j++;
			memset(result, 0, 64);

			temp = 0;
			sg_init_table(sg, template[i].np);
			for (k = 0; k < template[i].np; k++) {
				sg_set_buf(&sg[k],
					   memcpy(xbuf[IDX[k] >> PAGE_SHIFT] +
						  offset_in_page(IDX[k]),
						  template[i].plaintext + temp,
						  template[i].tap[k]),
					   template[i].tap[k]);
				temp += template[i].tap[k];
			}

			if (template[i].ksize) {
				ret = crypto_hash_setkey(tfm, template[i].key,
							 template[i].ksize);

				if (ret) {
					printk(KERN_ERR "alg: hash: setkey "
					       "failed on chunking test %d "
					       "for %s: ret=%d\n", j, algo,
					       -ret);
					goto out;
				}
			}

			ret = crypto_hash_digest(&desc, sg, template[i].psize,
						 result);
			if (ret) {
				printk(KERN_ERR "alg: hash: digest failed "
				       "on chunking test %d for %s: "
				       "ret=%d\n", j, algo, -ret);
				goto out;
			}

			if (memcmp(result, template[i].digest,
				   crypto_hash_digestsize(tfm))) {
				printk(KERN_ERR "alg: hash: Chunking test %d "
				       "failed for %s\n", j, algo);
				hexdump(result, crypto_hash_digestsize(tfm));
				ret = -EINVAL;
				goto out;
			}
		}
	}

	ret = 0;

out:
	return ret;
}

static int test_aead(struct crypto_aead *tfm, int enc,
		     struct aead_testvec *template, unsigned int tcount)
{
	const char *algo = ncrypto_tfm_alg_driver_name(crypto_aead_tfm(tfm));
	unsigned int i, j, k, n, temp;
	int ret = 0;
	char *q;
	char *key;
	struct aead_request *req;
	struct scatterlist sg[8];
	struct scatterlist asg[8];
	const char *e;
	struct tcrypt_result result;
	unsigned int authsize;
	void *input;
	void *assoc;
	char iv[MAX_IVLEN];

	if (enc == ENCRYPT)
		e = "encryption";
	else
		e = "decryption";

	init_completion(&result.completion);

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		printk(KERN_ERR "alg: aead: Failed to allocate request for "
		       "%s\n", algo);
		ret = -ENOMEM;
		goto out;
	}

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  tcrypt_complete, &result);

	for (i = 0, j = 0; i < tcount; i++) {
		if (!template[i].np) {
			j++;

			/* some tepmplates have no input data but they will
			 * touch input
			 */
			input = xbuf[0];
			assoc = axbuf[0];

			memcpy(input, template[i].input, template[i].ilen);
			memcpy(assoc, template[i].assoc, template[i].alen);
			if (template[i].iv)
				memcpy(iv, template[i].iv, MAX_IVLEN);
			else
				memset(iv, 0, MAX_IVLEN);

			crypto_aead_clear_flags(tfm, ~0);
			if (template[i].wk)
				crypto_aead_set_flags(
					tfm, CRYPTO_TFM_REQ_WEAK_KEY);

			key = template[i].key;

			ret = crypto_aead_setkey(tfm, key,
						 template[i].klen);
			if (!ret == template[i].fail) {
				printk(KERN_ERR "alg: aead: setkey failed on "
				       "test %d for %s: flags=%x\n", j, algo,
				       crypto_aead_get_flags(tfm));
				goto out;
			} else if (ret)
				continue;

			authsize = abs(template[i].rlen - template[i].ilen);
			ret = crypto_aead_setauthsize(tfm, authsize);
			if (ret) {
				printk(KERN_ERR "alg: aead: Failed to set "
				       "authsize to %u on test %d for %s\n",
				       authsize, j, algo);
				goto out;
			}

			sg_init_one(&sg[0], input,
				    template[i].ilen + (enc ? authsize : 0));

			sg_init_one(&asg[0], assoc, template[i].alen);

			aead_request_set_crypt(req, sg, sg,
					       template[i].ilen, iv);

			aead_request_set_assoc(req, asg, template[i].alen);

			ret = enc ?
				crypto_aead_encrypt(req) :
				crypto_aead_decrypt(req);

			switch (ret) {
			case 0:
				break;
			case -EINPROGRESS:
			case -EBUSY:
				ret = wait_for_completion_interruptible(
					&result.completion);
				if (!ret && !(ret = result.err)) {
					INIT_COMPLETION(result.completion);
					break;
				}
				/* fall through */
			default:
				printk(KERN_ERR "alg: aead: %s failed on test "
				       "%d for %s: ret=%d\n", e, j, algo, -ret);
				goto out;
			}

			q = input;
			if (memcmp(q, template[i].result, template[i].rlen)) {
				printk(KERN_ERR "alg: aead: Test %d failed on "
				       "%s for %s\n", j, e, algo);
				hexdump(q, template[i].rlen);
				ret = -EINVAL;
				goto out;
			}
		}
	}

	for (i = 0, j = 0; i < tcount; i++) {
		if (template[i].np) {
			j++;

			if (template[i].iv)
				memcpy(iv, template[i].iv, MAX_IVLEN);
			else
				memset(iv, 0, MAX_IVLEN);

			crypto_aead_clear_flags(tfm, ~0);
			if (template[i].wk)
				crypto_aead_set_flags(
					tfm, CRYPTO_TFM_REQ_WEAK_KEY);
			key = template[i].key;

			ret = crypto_aead_setkey(tfm, key, template[i].klen);
			if (!ret == template[i].fail) {
				printk(KERN_ERR "alg: aead: setkey failed on "
				       "chunk test %d for %s: flags=%x\n", j,
				       algo, crypto_aead_get_flags(tfm));
				goto out;
			} else if (ret)
				continue;

			authsize = abs(template[i].rlen - template[i].ilen);

			ret = -EINVAL;
			sg_init_table(sg, template[i].np);
			for (k = 0, temp = 0; k < template[i].np; k++) {
				if (unlikely(offset_in_page(IDX[k]) +
					     template[i].tap[k] > PAGE_SIZE)) {
					WARN_ON(1);
					goto out;
				}

				q = xbuf[IDX[k] >> PAGE_SHIFT] +
				    offset_in_page(IDX[k]);

				memcpy(q, template[i].input + temp,
				       template[i].tap[k]);

				n = template[i].tap[k];
				if (k == template[i].np - 1 && enc)
					n += authsize;
				if (offset_in_page(q) + n < PAGE_SIZE)
					q[n] = 0;

				sg_set_buf(&sg[k], q, template[i].tap[k]);
				temp += template[i].tap[k];
			}

			ret = crypto_aead_setauthsize(tfm, authsize);
			if (ret) {
				printk(KERN_ERR "alg: aead: Failed to set "
				       "authsize to %u on chunk test %d for "
				       "%s\n", authsize, j, algo);
				goto out;
			}

			if (enc) {
				if (unlikely(sg[k - 1].offset +
					     sg[k - 1].length + authsize >
					     PAGE_SIZE)) {
					WARN_ON(1);
					ret = -EINVAL;
					goto out;
				}

				sg[k - 1].length += authsize;
			}

			sg_init_table(asg, template[i].anp);
			for (k = 0, temp = 0; k < template[i].anp; k++) {
				sg_set_buf(&asg[k],
					   memcpy(axbuf[IDX[k] >> PAGE_SHIFT] +
						  offset_in_page(IDX[k]),
						  template[i].assoc + temp,
						  template[i].atap[k]),
					   template[i].atap[k]);
				temp += template[i].atap[k];
			}

			aead_request_set_crypt(req, sg, sg,
					       template[i].ilen,
					       iv);

			aead_request_set_assoc(req, asg, template[i].alen);

			ret = enc ?
				crypto_aead_encrypt(req) :
				crypto_aead_decrypt(req);

			switch (ret) {
			case 0:
				break;
			case -EINPROGRESS:
			case -EBUSY:
				ret = wait_for_completion_interruptible(
					&result.completion);
				if (!ret && !(ret = result.err)) {
					INIT_COMPLETION(result.completion);
					break;
				}
				/* fall through */
			default:
				printk(KERN_ERR "alg: aead: %s failed on "
				       "chunk test %d for %s: ret=%d\n", e, j,
				       algo, -ret);
				goto out;
			}

			ret = -EINVAL;
			for (k = 0, temp = 0; k < template[i].np; k++) {
				q = xbuf[IDX[k] >> PAGE_SHIFT] +
				    offset_in_page(IDX[k]);

				n = template[i].tap[k];
				if (k == template[i].np - 1)
					n += enc ? authsize : -authsize;

				if (memcmp(q, template[i].result + temp, n)) {
					printk(KERN_ERR "alg: aead: Chunk "
					       "test %d failed on %s at page "
					       "%u for %s\n", j, e, k, algo);
					hexdump(q, n);
					goto out;
				}

				q += n;
				if (k == template[i].np - 1 && !enc) {
					if (memcmp(q, template[i].input +
						      temp + n, authsize))
						n = authsize;
					else
						n = 0;
				} else {
					for (n = 0; offset_in_page(q + n) &&
						    q[n]; n++)
						;
				}
				if (n) {
					printk(KERN_ERR "alg: aead: Result "
					       "buffer corruption in chunk "
					       "test %d on %s at page %u for "
					       "%s: %u bytes:\n", j, e, k,
					       algo, n);
					hexdump(q, n);
					goto out;
				}

				temp += template[i].tap[k];
			}
		}
	}

	ret = 0;

out:
	aead_request_free(req);
	return ret;
}

static int test_cipher(struct crypto_cipher *tfm, int enc,
		       struct cipher_testvec *template, unsigned int tcount)
{
	const char *algo = crypto_tfm_alg_driver_name(crypto_cipher_tfm(tfm));
	unsigned int i, j, k;
	int ret;
	char *q;
	const char *e;
	void *data;

	if (enc == ENCRYPT)
	        e = "encryption";
	else
		e = "decryption";

	j = 0;
	for (i = 0; i < tcount; i++) {
		if (template[i].np)
			continue;

		j++;

		data = xbuf[0];
		memcpy(data, template[i].input, template[i].ilen);

		crypto_cipher_clear_flags(tfm, ~0);
		if (template[i].wk)
			crypto_cipher_set_flags(tfm, CRYPTO_TFM_REQ_WEAK_KEY);

		ret = crypto_cipher_setkey(tfm, template[i].key,
					   template[i].klen);
		if (!ret == template[i].fail) {
			printk(KERN_ERR "alg: cipher: setkey failed "
			       "on test %d for %s: flags=%x\n", j,
			       algo, crypto_cipher_get_flags(tfm));
			goto out;
		} else if (ret)
			continue;

		for (k = 0; k < template[i].ilen;
		     k += crypto_cipher_blocksize(tfm)) {
			if (enc)
				crypto_cipher_encrypt_one(tfm, data + k,
							  data + k);
			else
				crypto_cipher_decrypt_one(tfm, data + k,
							  data + k);
		}

		q = data;
		if (memcmp(q, template[i].result, template[i].rlen)) {
			printk(KERN_ERR "alg: cipher: Test %d failed "
			       "on %s for %s\n", j, e, algo);
			hexdump(q, template[i].rlen);
			ret = -EINVAL;
			goto out;
		}
	}

	ret = 0;

out:
	return ret;
}

static int test_skcipher(struct crypto_ablkcipher *tfm, int enc,
			 struct cipher_testvec *template, unsigned int tcount)
{
	const char *algo =
		ncrypto_tfm_alg_driver_name(crypto_ablkcipher_tfm(tfm));
	unsigned int i, j, k, n, temp;
	int ret;
	char *q;
	struct ablkcipher_request *req;
	struct scatterlist sg[8];
	const char *e;
	struct tcrypt_result result;
	void *data;
	char iv[MAX_IVLEN];

	if (enc == ENCRYPT)
	        e = "encryption";
	else
		e = "decryption";

	init_completion(&result.completion);

	req = ablkcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		printk(KERN_ERR "alg: skcipher: Failed to allocate request "
		       "for %s\n", algo);
		ret = -ENOMEM;
		goto out;
	}

	ablkcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
					tcrypt_complete, &result);

	j = 0;
	for (i = 0; i < tcount; i++) {
		if (template[i].iv)
			memcpy(iv, template[i].iv, MAX_IVLEN);
		else
			memset(iv, 0, MAX_IVLEN);

		if (!(template[i].np)) {
			j++;

			data = xbuf[0];
			memcpy(data, template[i].input, template[i].ilen);

			crypto_ablkcipher_clear_flags(tfm, ~0);
			if (template[i].wk)
				crypto_ablkcipher_set_flags(
					tfm, CRYPTO_TFM_REQ_WEAK_KEY);

			ret = crypto_ablkcipher_setkey(tfm, template[i].key,
						       template[i].klen);
			if (!ret == template[i].fail) {
				printk(KERN_ERR "alg: skcipher: setkey failed "
				       "on test %d for %s: flags=%x\n", j,
				       algo, crypto_ablkcipher_get_flags(tfm));
				goto out;
			} else if (ret)
				continue;

			sg_init_one(&sg[0], data, template[i].ilen);

			ablkcipher_request_set_crypt(req, sg, sg,
						     template[i].ilen, iv);
			ret = enc ?
				crypto_ablkcipher_encrypt(req) :
				crypto_ablkcipher_decrypt(req);

			switch (ret) {
			case 0:
				break;
			case -EINPROGRESS:
			case -EBUSY:
				ret = wait_for_completion_interruptible(
					&result.completion);
				if (!ret && !((ret = result.err))) {
					INIT_COMPLETION(result.completion);
					break;
				}
				/* fall through */
			default:
				printk(KERN_ERR "alg: skcipher: %s failed on "
				       "test %d for %s: ret=%d\n", e, j, algo,
				       -ret);
				goto out;
			}

			q = data;
			if (memcmp(q, template[i].result, template[i].rlen)) {
				printk(KERN_ERR "alg: skcipher: Test %d "
				       "failed on %s for %s\n", j, e, algo);
				hexdump(q, template[i].rlen);
				ret = -EINVAL;
				goto out;
			}
		}
	}

	j = 0;
	for (i = 0; i < tcount; i++) {

		if (template[i].iv)
			memcpy(iv, template[i].iv, MAX_IVLEN);
		else
			memset(iv, 0, MAX_IVLEN);

		if (template[i].np) {
			j++;

			crypto_ablkcipher_clear_flags(tfm, ~0);
			if (template[i].wk)
				crypto_ablkcipher_set_flags(
					tfm, CRYPTO_TFM_REQ_WEAK_KEY);

			ret = crypto_ablkcipher_setkey(tfm, template[i].key,
						       template[i].klen);
			if (!ret == template[i].fail) {
				printk(KERN_ERR "alg: skcipher: setkey failed "
				       "on chunk test %d for %s: flags=%x\n",
				       j, algo,
				       crypto_ablkcipher_get_flags(tfm));
				goto out;
			} else if (ret)
				continue;

			temp = 0;
			ret = -EINVAL;
			sg_init_table(sg, template[i].np);
			for (k = 0; k < template[i].np; k++) {
				if (unlikely(offset_in_page(IDX[k]) +
					     template[i].tap[k] > PAGE_SIZE)) {
					WARN_ON(1);
					goto out;
				}

				q = xbuf[IDX[k] >> PAGE_SHIFT] +
				    offset_in_page(IDX[k]);

				memcpy(q, template[i].input + temp,
				       template[i].tap[k]);

				if (offset_in_page(q) + template[i].tap[k] <
				    PAGE_SIZE)
					q[template[i].tap[k]] = 0;

				sg_set_buf(&sg[k], q, template[i].tap[k]);

				temp += template[i].tap[k];
			}

			ablkcipher_request_set_crypt(req, sg, sg,
					template[i].ilen, iv);

			ret = enc ?
				crypto_ablkcipher_encrypt(req) :
				crypto_ablkcipher_decrypt(req);

			switch (ret) {
			case 0:
				break;
			case -EINPROGRESS:
			case -EBUSY:
				ret = wait_for_completion_interruptible(
					&result.completion);
				if (!ret && !((ret = result.err))) {
					INIT_COMPLETION(result.completion);
					break;
				}
				/* fall through */
			default:
				printk(KERN_ERR "alg: skcipher: %s failed on "
				       "chunk test %d for %s: ret=%d\n", e, j,
				       algo, -ret);
				goto out;
			}

			temp = 0;
			ret = -EINVAL;
			for (k = 0; k < template[i].np; k++) {
				q = xbuf[IDX[k] >> PAGE_SHIFT] +
				    offset_in_page(IDX[k]);

				if (memcmp(q, template[i].result + temp,
					   template[i].tap[k])) {
					printk(KERN_ERR "alg: skcipher: Chunk "
					       "test %d failed on %s at page "
					       "%u for %s\n", j, e, k, algo);
					hexdump(q, template[i].tap[k]);
					goto out;
				}

				q += template[i].tap[k];
				for (n = 0; offset_in_page(q + n) && q[n]; n++)
					;
				if (n) {
					printk(KERN_ERR "alg: skcipher: "
					       "Result buffer corruption in "
					       "chunk test %d on %s at page "
					       "%u for %s: %u bytes:\n", j, e,
					       k, algo, n);
					hexdump(q, n);
					goto out;
				}
				temp += template[i].tap[k];
			}
		}
	}

	ret = 0;

out:
	ablkcipher_request_free(req);
	return ret;
}

static int alg_test_aead(const struct alg_test_desc *desc, const char *driver,
			 u32 type, u32 mask)
{
	struct crypto_aead *tfm;
	int err = 0;

	tfm = crypto_alloc_aead(driver, type, mask);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "alg: aead: Failed to load transform for %s: "
		       "%ld\n", driver, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	if (desc->suite.aead.enc.vecs) {
		err = test_aead(tfm, ENCRYPT, desc->suite.aead.enc.vecs,
				desc->suite.aead.enc.count);
		if (err)
			goto out;
	}

	if (!err && desc->suite.aead.dec.vecs)
		err = test_aead(tfm, DECRYPT, desc->suite.aead.dec.vecs,
				desc->suite.aead.dec.count);

out:
	crypto_free_aead(tfm);
	return err;
}

static int alg_test_cipher(const struct alg_test_desc *desc,
			   const char *driver, u32 type, u32 mask)
{
	struct crypto_cipher *tfm;
	int err = 0;

	tfm = crypto_alloc_cipher(driver, type, mask);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "alg: cipher: Failed to load transform for "
		       "%s: %ld\n", driver, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	if (desc->suite.cipher.enc.vecs) {
		err = test_cipher(tfm, ENCRYPT, desc->suite.cipher.enc.vecs,
				  desc->suite.cipher.enc.count);
		if (err)
			goto out;
	}

	if (desc->suite.cipher.dec.vecs)
		err = test_cipher(tfm, DECRYPT, desc->suite.cipher.dec.vecs,
				  desc->suite.cipher.dec.count);

out:
	crypto_free_cipher(tfm);
	return err;
}

static int alg_test_skcipher(const struct alg_test_desc *desc,
			     const char *driver, u32 type, u32 mask)
{
	struct crypto_ablkcipher *tfm;
	int err = 0;

	tfm = crypto_alloc_ablkcipher(driver, type, mask);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "alg: skcipher: Failed to load transform for "
		       "%s: %ld\n", driver, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	if (desc->suite.cipher.enc.vecs) {
		err = test_skcipher(tfm, ENCRYPT, desc->suite.cipher.enc.vecs,
				    desc->suite.cipher.enc.count);
		if (err)
			goto out;
	}

	if (desc->suite.cipher.dec.vecs)
		err = test_skcipher(tfm, DECRYPT, desc->suite.cipher.dec.vecs,
				    desc->suite.cipher.dec.count);

out:
	crypto_free_ablkcipher(tfm);
	return err;
}

static int alg_test_hash(const struct alg_test_desc *desc, const char *driver,
			 u32 type, u32 mask)
{
	struct crypto_hash *tfm;
	int err;

	tfm = crypto_alloc_hash(driver, type, mask);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "alg: hash: Failed to load transform for %s: "
		       "%ld\n", driver, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	err = test_nhash(tfm, desc->suite.hash.vecs, desc->suite.hash.count);

	crypto_free_hash(tfm);
	return err;
}

/* Please keep this list sorted by algorithm name. */
static const struct alg_test_desc alg_test_descs[] = {
	{
		.alg = "cbc(aes)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = aes_cbc_enc_tv_template,
					.count = AES_CBC_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = aes_cbc_dec_tv_template,
					.count = AES_CBC_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "cbc(anubis)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = anubis_cbc_enc_tv_template,
					.count = ANUBIS_CBC_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = anubis_cbc_dec_tv_template,
					.count = ANUBIS_CBC_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "cbc(blowfish)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = bf_cbc_enc_tv_template,
					.count = BF_CBC_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = bf_cbc_dec_tv_template,
					.count = BF_CBC_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "cbc(des)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = des_cbc_enc_tv_template,
					.count = DES_CBC_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = des_cbc_dec_tv_template,
					.count = DES_CBC_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "cbc(des3_ede)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = des3_ede_cbc_enc_tv_template,
					.count = DES3_EDE_CBC_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = des3_ede_cbc_dec_tv_template,
					.count = DES3_EDE_CBC_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "cbc(twofish)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = tf_cbc_enc_tv_template,
					.count = TF_CBC_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = tf_cbc_dec_tv_template,
					.count = TF_CBC_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ccm(aes)",
		.test = alg_test_aead,
		.suite = {
			.aead = {
				.enc = {
					.vecs = aes_ccm_enc_tv_template,
					.count = AES_CCM_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = aes_ccm_dec_tv_template,
					.count = AES_CCM_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(aes)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = aes_enc_tv_template,
					.count = AES_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = aes_dec_tv_template,
					.count = AES_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(anubis)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = anubis_enc_tv_template,
					.count = ANUBIS_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = anubis_dec_tv_template,
					.count = ANUBIS_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(arc4)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = arc4_enc_tv_template,
					.count = ARC4_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = arc4_dec_tv_template,
					.count = ARC4_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(blowfish)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = bf_enc_tv_template,
					.count = BF_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = bf_dec_tv_template,
					.count = BF_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(cast5)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = cast5_enc_tv_template,
					.count = CAST5_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = cast5_dec_tv_template,
					.count = CAST5_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(cast6)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = cast6_enc_tv_template,
					.count = CAST6_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = cast6_dec_tv_template,
					.count = CAST6_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(des)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = des_enc_tv_template,
					.count = DES_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = des_dec_tv_template,
					.count = DES_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(des3_ede)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = des3_ede_enc_tv_template,
					.count = DES3_EDE_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = des3_ede_dec_tv_template,
					.count = DES3_EDE_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(khazad)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = khazad_enc_tv_template,
					.count = KHAZAD_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = khazad_dec_tv_template,
					.count = KHAZAD_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(serpent)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = serpent_enc_tv_template,
					.count = SERPENT_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = serpent_dec_tv_template,
					.count = SERPENT_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(tea)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = tea_enc_tv_template,
					.count = TEA_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = tea_dec_tv_template,
					.count = TEA_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(tnepres)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = tnepres_enc_tv_template,
					.count = TNEPRES_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = tnepres_dec_tv_template,
					.count = TNEPRES_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(twofish)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = tf_enc_tv_template,
					.count = TF_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = tf_dec_tv_template,
					.count = TF_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(xeta)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = xeta_enc_tv_template,
					.count = XETA_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = xeta_dec_tv_template,
					.count = XETA_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "ecb(xtea)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = xtea_enc_tv_template,
					.count = XTEA_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = xtea_dec_tv_template,
					.count = XTEA_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "hmac(md5)",
		.test = alg_test_hash,
		.suite = {
			.hash = {
				.vecs = hmac_md5_tv_template,
				.count = HMAC_MD5_TEST_VECTORS
			}
		}
	}, {
		.alg = "hmac(sha1)",
		.test = alg_test_hash,
		.suite = {
			.hash = {
				.vecs = hmac_sha1_tv_template,
				.count = HMAC_SHA1_TEST_VECTORS
			}
		}
	}, {
		.alg = "hmac(sha256)",
		.test = alg_test_hash,
		.suite = {
			.hash = {
				.vecs = hmac_sha256_tv_template,
				.count = HMAC_SHA256_TEST_VECTORS
			}
		}
	}, {
		.alg = "rfc3686(ctr(aes))",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = {
				.enc = {
					.vecs = aes_ctr_enc_tv_template,
					.count = AES_CTR_ENC_TEST_VECTORS
				},
				.dec = {
					.vecs = aes_ctr_dec_tv_template,
					.count = AES_CTR_DEC_TEST_VECTORS
				}
			}
		}
	}, {
		.alg = "xcbc(aes)",
		.test = alg_test_hash,
		.suite = {
			.hash = {
				.vecs = aes_xcbc128_tv_template,
				.count = XCBC_AES_TEST_VECTORS
			}
		}
	}
};

static int alg_find_test(const char *alg)
{
	int start = 0;
	int end = ARRAY_SIZE(alg_test_descs);

	while (start < end) {
		int i = (start + end) / 2;
		int diff = strcmp(alg_test_descs[i].alg, alg);

		if (diff > 0) {
			end = i;
			continue;
		}

		if (diff < 0) {
			start = i + 1;
			continue;
		}

		return i;
	}

	return -1;
}

int alg_test(const char *driver, const char *alg, u32 type, u32 mask)
{
	int i;

	if ((type & CRYPTO_ALG_TYPE_MASK) == CRYPTO_ALG_TYPE_CIPHER) {
		char nalg[CRYPTO_MAX_ALG_NAME];

		if (snprintf(nalg, sizeof(nalg), "ecb(%s)", alg) >=
		    sizeof(nalg))
			return -ENAMETOOLONG;

		i = alg_find_test(nalg);
		if (i < 0)
			goto notest;

		return alg_test_cipher(alg_test_descs + i, driver, type, mask);
	}

	i = alg_find_test(alg);
	if (i < 0)
		goto notest;

	return alg_test_descs[i].test(alg_test_descs + i, driver,
				      type, mask);

notest:
	printk(KERN_INFO "alg: No test for %s (%s)\n", alg, driver);
	return 0;
}
EXPORT_SYMBOL_GPL(alg_test);

static int cryptomgr_test(void *data)
{
	struct crypto_test_param *param = data;
	u32 type = param->type;
	int err = 0;

	if (!((type ^ NCRYPTO_ALG_TYPE_BLKCIPHER) &
	      NCRYPTO_ALG_TYPE_BLKCIPHER_MASK) && !(type & NCRYPTO_ALG_GENIV))
		goto skiptest;

	err = alg_test(param->driver, param->alg, type, NCRYPTO_ALG_TESTED);

skiptest:
	crypto_alg_tested(param->driver, err);

	kfree(param);
	module_put_and_exit(0);
}

static int cryptomgr_schedule_test(struct ncrypto_alg *alg)
{
	struct task_struct *thread;
	struct crypto_test_param *param;

	if (!try_module_get(THIS_MODULE))
		goto err;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param)
		goto err_put_module;

	memcpy(param->driver, alg->cra_driver_name, sizeof(param->driver));
	memcpy(param->alg, alg->cra_name, sizeof(param->alg));
	param->type = alg->cra_flags;

	thread = kthread_run(cryptomgr_test, param, "cryptomgr_test");
	if (IS_ERR(thread))
		goto err_free_param;

	return NOTIFY_STOP;

err_free_param:
	kfree(param);
err_put_module:
	module_put(THIS_MODULE);
err:
	return NOTIFY_OK;
}

static int testmgr_notify(struct notifier_block *this, unsigned long msg,
			  void *data)
{
	switch (msg) {
	case CRYPTO_MSG_ALG_REGISTER:
		return cryptomgr_schedule_test(data);
	}

	return NOTIFY_DONE;
}

static struct notifier_block testmgr_notifier = {
	.notifier_call = testmgr_notify,
};

static int __init testmgr_init(void)
{
	int err = -ENOMEM;
	int i;

	for (i = 0; i < XBUFSIZE; i++) {
		xbuf[i] = (void *)__get_free_page(GFP_KERNEL);
		if (!xbuf[i])
			goto err_free_xbuf;
	}

	for (i = 0; i < XBUFSIZE; i++) {
		axbuf[i] = (void *)__get_free_page(GFP_KERNEL);
		if (!axbuf[i])
			goto err_free_axbuf;
	}

	err = crypto_register_notifier(&testmgr_notifier);
	if (err)
		goto err_free_axbuf;

	return 0;

err_free_axbuf:
	for (i = 0; i < XBUFSIZE && axbuf[i]; i++)
		free_page((unsigned long)axbuf[i]);
err_free_xbuf:
	for (i = 0; i < XBUFSIZE && xbuf[i]; i++)
		free_page((unsigned long)xbuf[i]);

	return err;
}

static void __exit testmgr_exit(void)
{
	int err;
	int i;

	err = crypto_unregister_notifier(&testmgr_notifier);
	BUG_ON(err);

	for (i = 0; i < XBUFSIZE; i++)
		free_page((unsigned long)axbuf[i]);
	for (i = 0; i < XBUFSIZE; i++)
		free_page((unsigned long)xbuf[i]);
}

subsys_initcall(testmgr_init);
module_exit(testmgr_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Algorithm Test Manager");
