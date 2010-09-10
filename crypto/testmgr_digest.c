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
 */

#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "internal.h"
#include "testmgr_digest.h"

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

struct hash_test_suite {
	struct hash_testvec *vecs;
	unsigned int count;
};

struct alg_test_desc {
	const char *alg;
	int (*test)(const struct alg_test_desc *desc, const char *driver,
		    u32 type, u32 mask);

	union {
		struct hash_test_suite hash;
	} suite;
};

static unsigned int IDX[8] = { IDX1, IDX2, IDX3, IDX4, IDX5, IDX6, IDX7, IDX8 };

static char *xbuf[XBUFSIZE];

static void hexdump(unsigned char *buf, unsigned int len)
{
	while (len--)
		printk("%02x", *buf++);

	printk("\n");
}

static int test_hash(const char *algo, struct hash_testvec *template,
		     unsigned int tcount)
{
	unsigned int i, j, k, temp;
	struct scatterlist sg[8];
	char result[64];
	struct crypto_tfm *tfm;
	int ret;
	void *hash_buff;

	tfm = crypto_alloc_tfm(algo, 0);
	if (tfm == NULL) {
		printk(KERN_ERR "alg: digest: Failed to load transform for %s\n",
		       algo);
		return -ENOENT;
	}

	for (i = 0; i < tcount; i++) {
		memset(result, 0, 64);

		hash_buff = xbuf[0];

		memcpy(hash_buff, template[i].plaintext, template[i].psize);
		sg_init_one(&sg[0], hash_buff, template[i].psize);

		crypto_digest_init(tfm);
		if (tfm->crt_u.digest.dit_setkey) {
			crypto_digest_setkey(tfm, template[i].key,
					     template[i].ksize);
		}
		crypto_digest_update(tfm, sg, 1);
		crypto_digest_final(tfm, result);

		if (memcmp(result, template[i].digest,
			   crypto_tfm_alg_digestsize(tfm))) {
			printk(KERN_ERR "alg: digest: Test %d failed for %s\n",
			       i + 1, algo);
			hexdump(result, crypto_tfm_alg_digestsize(tfm));
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
			for (k = 0; k < template[i].np; k++) {
				sg_set_buf(&sg[k], 
					   memcpy(xbuf[IDX[k] >> PAGE_SHIFT] +
						  offset_in_page(IDX[k]),
						  template[i].plaintext + temp,
						  template[i].tap[k]),
					   template[i].tap[k]);
				temp += template[i].tap[k];
			}

			crypto_digest_digest(tfm, sg, template[i].np, result);

			if (memcmp(result, template[i].digest,
				   crypto_tfm_alg_digestsize(tfm))) {
				printk(KERN_ERR "alg: digest: Chunking test %d "
				       "failed for %s\n", j, algo);
				hexdump(result, crypto_tfm_alg_digestsize(tfm));
				ret = -EINVAL;
				goto out;
			}
		}
	}

	ret = 0;

out:
	crypto_free_tfm(tfm);
	return ret;
}

static int alg_test_digest(const struct alg_test_desc *desc,
			   const char *driver, u32 type, u32 mask)
{
	return test_hash(driver, desc->suite.hash.vecs, desc->suite.hash.count);
}

static const struct alg_test_desc digest_test_descs[] = {
	{
		.alg = "md4",
		.test = alg_test_digest,
		.suite = {
			.hash = {
				.vecs = md4_tv_template,
				.count = MD4_TEST_VECTORS
			}
		}
	}, {
		.alg = "md5",
		.test = alg_test_digest,
		.suite = {
			.hash = {
				.vecs = md5_tv_template,
				.count = MD5_TEST_VECTORS
			}
		}
	}, {
		.alg = "michael_mic",
		.test = alg_test_digest,
		.suite = {
			.hash = {
				.vecs = michael_mic_tv_template,
				.count = MICHAEL_MIC_TEST_VECTORS
			}
		}
	}, {
		.alg = "sha1",
		.test = alg_test_digest,
		.suite = {
			.hash = {
				.vecs = sha1_tv_template,
				.count = SHA1_TEST_VECTORS
			}
		}
	}, {
		.alg = "sha256",
		.test = alg_test_digest,
		.suite = {
			.hash = {
				.vecs = sha256_tv_template,
				.count = SHA256_TEST_VECTORS
			}
		}
	}, {
		.alg = "sha384",
		.test = alg_test_digest,
		.suite = {
			.hash = {
				.vecs = sha384_tv_template,
				.count = SHA384_TEST_VECTORS
			}
		}
	}, {
		.alg = "sha512",
		.test = alg_test_digest,
		.suite = {
			.hash = {
				.vecs = sha512_tv_template,
				.count = SHA512_TEST_VECTORS
			}
		}
	}, {
		.alg = "tgr128",
		.test = alg_test_digest,
		.suite = {
			.hash = {
				.vecs = tgr128_tv_template,
				.count = TGR128_TEST_VECTORS
			}
		}
	}, {
		.alg = "tgr160",
		.test = alg_test_digest,
		.suite = {
			.hash = {
				.vecs = tgr160_tv_template,
				.count = TGR160_TEST_VECTORS
			}
		}
	}, {
		.alg = "tgr192",
		.test = alg_test_digest,
		.suite = {
			.hash = {
				.vecs = tgr192_tv_template,
				.count = TGR192_TEST_VECTORS
			}
		}
	}, {
		.alg = "wp256",
		.test = alg_test_digest,
		.suite = {
			.hash = {
				.vecs = wp256_tv_template,
				.count = WP256_TEST_VECTORS
			}
		}
	}, {
		.alg = "wp384",
		.test = alg_test_digest,
		.suite = {
			.hash = {
				.vecs = wp384_tv_template,
				.count = WP384_TEST_VECTORS
			}
		}
	}, {
		.alg = "wp512",
		.test = alg_test_digest,
		.suite = {
			.hash = {
				.vecs = wp512_tv_template,
				.count = WP512_TEST_VECTORS
			}
		}
	}
};

int digest_test(const char *driver, const char *alg)
{
	int start = 0;
	int end = ARRAY_SIZE(digest_test_descs);

	while (start < end) {
		int i = (start + end) / 2;
		int diff = strcmp(digest_test_descs[i].alg, alg);

		if (diff > 0) {
			end = i;
			continue;
		}

		if (diff < 0) {
			start = i + 1;
			continue;
		}

		return digest_test_descs[i].test(digest_test_descs + i, driver,
						 0, 0);
	}

	printk(KERN_INFO "alg: No test for %s (%s)\n", alg, driver);
	return 0;
}
EXPORT_SYMBOL_GPL(digest_test);

static int __init testmgr_digest_init(void)
{
	int i;

	for (i = 0; i < XBUFSIZE; i++) {
		xbuf[i] = (void *)__get_free_page(GFP_KERNEL);
		if (!xbuf[i])
			goto err_free_xbuf;
	}

	return 0;

err_free_xbuf:
	for (i = 0; i < XBUFSIZE && xbuf[i]; i++)
		free_page((unsigned long)xbuf[i]);

	return -ENOMEM;
}

static void __exit testmgr_digest_exit(void)
{
	int i;

	for (i = 0; i < XBUFSIZE; i++)
		free_page((unsigned long)xbuf[i]);
}

subsys_initcall(testmgr_digest_init);
module_exit(testmgr_digest_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Algorithm Test Manager for Digests");
