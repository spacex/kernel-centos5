/*
 * Quick & dirty crypto testing module.
 *
 * This will only exist until we have a better testing mechanism
 * (e.g. a char device).
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2002 Jean-Francois Dive <jef@linuxbe.org>
 * Copyright (c) 2007 Nokia Siemens Networks
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
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/ncrypto.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/timex.h>
#include <linux/interrupt.h>

#include "tcrypt.h"
#include "internal.h"

/*
 * Need slab memory for testing (size in number of pages).
 */
#define TVMEMSIZE	4

/*
* Used by test_cipher_speed()
*/
#define ENCRYPT 1
#define DECRYPT 0

/*
 * Used by test_cipher_speed()
 */
static unsigned int sec;

static int mode;
static char *tvmem[TVMEMSIZE];

static char *check[] = {
	"des", "md5", "des3_ede", "rot13", "sha1", "sha256", "blowfish",
	"twofish", "serpent", "sha384", "sha512", "md4", "aes", "cast6",
	"arc4", "michael_mic", "deflate", "crc32c", "tea", "xtea",
	"khazad", "wp512", "wp384", "wp256", "tnepres", "xeta", NULL
};

static void hexdump(unsigned char *buf, unsigned int len)
{
	while (len--)
		printk("%02x", *buf++);

	printk("\n");
}

static int test_cipher_jiffies(struct blkcipher_desc *desc, int enc,
			       struct scatterlist *sg, int blen, int sec)
{
	unsigned long start, end;
	int bcount;
	int ret;

	for (start = jiffies, end = start + sec * HZ, bcount = 0;
	     time_before(jiffies, end); bcount++) {
		if (enc)
			ret = crypto_blkcipher_encrypt(desc, sg, sg, blen);
		else
			ret = crypto_blkcipher_decrypt(desc, sg, sg, blen);

		if (ret)
			return ret;
	}

	printk("%d operations in %d seconds (%ld bytes)\n",
	       bcount, sec, (long)bcount * blen);
	return 0;
}

static int test_cipher_cycles(struct blkcipher_desc *desc, int enc,
			      struct scatterlist *sg, int blen)
{
	unsigned long cycles = 0;
	int ret = 0;
	int i;

	local_bh_disable();
	local_irq_disable();

	/* Warm-up run. */
	for (i = 0; i < 4; i++) {
		if (enc)
			ret = crypto_blkcipher_encrypt(desc, sg, sg, blen);
		else
			ret = crypto_blkcipher_decrypt(desc, sg, sg, blen);

		if (ret)
			goto out;
	}

	/* The real thing. */
	for (i = 0; i < 8; i++) {
		cycles_t start, end;

		start = get_cycles();
		if (enc)
			ret = crypto_blkcipher_encrypt(desc, sg, sg, blen);
		else
			ret = crypto_blkcipher_decrypt(desc, sg, sg, blen);
		end = get_cycles();

		if (ret)
			goto out;

		cycles += end - start;
	}

out:
	local_irq_enable();
	local_bh_enable();

	if (ret == 0)
		printk("1 operation in %lu cycles (%d bytes)\n",
		       (cycles + 4) / 8, blen);

	return ret;
}

static u32 block_sizes[] = { 16, 64, 256, 1024, 8192, 0 };

static void test_cipher_speed(const char *algo, int enc, unsigned int sec,
			      struct cipher_speed_template *template,
			      unsigned int tcount, u8 *keysize)
{
	unsigned int ret, i, j, iv_len;
	const char *key, iv[128];
	struct crypto_blkcipher *tfm;
	struct blkcipher_desc desc;
	const char *e;
	u32 *b_size;

	if (enc == ENCRYPT)
	        e = "encryption";
	else
		e = "decryption";

	printk("\ntesting speed of %s %s\n", algo, e);

	tfm = crypto_alloc_blkcipher(algo, 0, NCRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		printk("failed to load transform for %s: %ld\n", algo,
		       PTR_ERR(tfm));
		return;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	i = 0;
	do {

		b_size = block_sizes;
		do {
			struct scatterlist sg[TVMEMSIZE];

			if ((*keysize + *b_size) > TVMEMSIZE * PAGE_SIZE) {
				printk("template (%u) too big for "
				       "tvmem (%lu)\n", *keysize + *b_size,
				       TVMEMSIZE * PAGE_SIZE);
				goto out;
			}

			printk("test %u (%d bit key, %d byte blocks): ", i,
					*keysize * 8, *b_size);

			memset(tvmem[0], 0xff, PAGE_SIZE);

			/* set key, plain text and IV */
			key = tvmem[0];
			for (j = 0; j < tcount; j++) {
				if (template[j].klen == *keysize) {
					key = template[j].key;
					break;
				}
			}

			ret = crypto_blkcipher_setkey(tfm, key, *keysize);
			if (ret) {
				printk("setkey() failed flags=%x\n",
						crypto_blkcipher_get_flags(tfm));
				goto out;
			}

			sg_init_table(sg, TVMEMSIZE);
			sg_set_buf(sg, tvmem[0] + *keysize,
				   PAGE_SIZE - *keysize);
			for (j = 1; j < TVMEMSIZE; j++) {
				sg_set_buf(sg + j, tvmem[j], PAGE_SIZE);
				memset (tvmem[j], 0xff, PAGE_SIZE);
			}

			iv_len = crypto_blkcipher_ivsize(tfm);
			if (iv_len) {
				memset(&iv, 0xff, iv_len);
				crypto_blkcipher_set_iv(tfm, iv, iv_len);
			}

			if (sec)
				ret = test_cipher_jiffies(&desc, enc, sg,
							  *b_size, sec);
			else
				ret = test_cipher_cycles(&desc, enc, sg,
							 *b_size);

			if (ret) {
				printk("%s() failed flags=%x\n", e, desc.flags);
				break;
			}
			b_size++;
			i++;
		} while (*b_size);
		keysize++;
	} while (*keysize);

out:
	crypto_free_blkcipher(tfm);
}

static void test_digest_jiffies(struct crypto_tfm *tfm, struct scatterlist *sg,
				int blen, int plen, char *out, int sec)
{
	unsigned long start, end;
	int bcount, pcount;

	for (start = jiffies, end = start + sec * HZ, bcount = 0;
	     time_before(jiffies, end); bcount++) {
		crypto_digest_init(tfm);
		for (pcount = 0; pcount < blen; pcount += plen) {
			crypto_digest_update(tfm, sg, 1);
		}
		/* we assume there is enough space in 'out' for the result */
		crypto_digest_final(tfm, out);
	}

	printk("%6u opers/sec, %9lu bytes/sec\n",
	       bcount / sec, ((long)bcount * blen) / sec);

	return;
}

static void test_digest_cycles(struct crypto_tfm *tfm, struct scatterlist *sg,
			       int blen, int plen, char *out)
{
	unsigned long cycles = 0;
	int i, pcount;

	local_bh_disable();
	local_irq_disable();

	/* Warm-up run. */
	for (i = 0; i < 4; i++) {
		crypto_digest_init(tfm);
		for (pcount = 0; pcount < blen; pcount += plen) {
			crypto_digest_update(tfm, sg, 1);
		}
		crypto_digest_final(tfm, out);
	}

	/* The real thing. */
	for (i = 0; i < 8; i++) {
		cycles_t start, end;

		crypto_digest_init(tfm);

		start = get_cycles();

		for (pcount = 0; pcount < blen; pcount += plen) {
			crypto_digest_update(tfm, sg, 1);
		}
		crypto_digest_final(tfm, out);

		end = get_cycles();

		cycles += end - start;
	}

	local_irq_enable();
	local_bh_enable();

	printk("%6lu cycles/operation, %4lu cycles/byte\n",
	       cycles / 8, cycles / (8 * blen));

	return;
}

static void test_digest_speed(const char *algo, unsigned int sec,
			      struct digest_speed *speed)
{
	struct scatterlist sg[TVMEMSIZE];
	struct crypto_tfm *tfm;
	char output[1024];
	int i;

	printk("\ntesting speed of %s\n", algo);

	tfm = crypto_alloc_tfm(algo, 0);

	if (tfm == NULL) {
		printk("failed to load transform for %s\n", algo);
		return;
	}

	if (crypto_tfm_alg_digestsize(tfm) > sizeof(output)) {
		printk("digestsize(%u) > outputbuffer(%zu)\n",
		       crypto_tfm_alg_digestsize(tfm), sizeof(output));
		goto out;
	}

	sg_init_table(sg, TVMEMSIZE);
	for (i = 0; i < TVMEMSIZE; i++) {
		sg_set_buf(sg + i, tvmem[i], PAGE_SIZE);
		memset(tvmem[i], 0xff, PAGE_SIZE);
	}

	for (i = 0; speed[i].blen != 0; i++) {
		if (speed[i].blen > TVMEMSIZE * PAGE_SIZE) {
			printk("template (%u) too big for tvmem (%lu)\n",
			       speed[i].blen, TVMEMSIZE * PAGE_SIZE);
			goto out;
		}

		printk("test%3u (%5u byte blocks,%5u bytes per update,%4u updates): ",
		       i, speed[i].blen, speed[i].plen, speed[i].blen / speed[i].plen);

		if (sec)
			test_digest_jiffies(tfm, sg, speed[i].blen, speed[i].plen, output, sec);
		else
			test_digest_cycles(tfm, sg, speed[i].blen, speed[i].plen, output);
	}

out:
	crypto_free_tfm(tfm);
}

static int test_deflate(void)
{
	unsigned int i;
	char result[COMP_BUF_SIZE];
	struct crypto_tfm *tfm;
	int ret;

	tfm = crypto_alloc_tfm("deflate", 0);
	if (tfm == NULL) {
		printk(KERN_ERR "alg: deflate: Failed to load transform\n");
		return -ENOENT;
	}

	for (i = 0; i < DEFLATE_COMP_TEST_VECTORS; i++) {
		int ilen, dlen = COMP_BUF_SIZE;

		memset(result, 0, sizeof (result));

		ilen = deflate_comp_tv_template[i].inlen;
		ret = crypto_comp_compress(
			tfm, deflate_comp_tv_template[i].input,
			ilen, result, &dlen);
		if (ret) {
			printk(KERN_ERR "alg: deflate: compression failed "
			       "on test %d: ret=%d\n", i + 1, -ret);
			goto out;
		}

		if (memcmp(result, deflate_comp_tv_template[i].output, dlen)) {
			printk(KERN_ERR "alg: deflate: Compression test %d "
			       "failed\n", i + 1);
			hexdump(result, dlen);
			ret = -EINVAL;
			goto out;
		}
	}

	for (i = 0; i < DEFLATE_DECOMP_TEST_VECTORS; i++) {
		int ilen, dlen = COMP_BUF_SIZE;

		memset(result, 0, sizeof (result));

		ilen = deflate_decomp_tv_template[i].inlen;
		ret = crypto_comp_decompress(
			tfm, deflate_decomp_tv_template[i].input,
			ilen, result, &dlen);
		if (ret) {
			printk(KERN_ERR "alg: deflate: decompression failed "
			       "on test %d: ret=%d\n", i + 1, -ret);
			goto out;
		}

		if (memcmp(result, deflate_decomp_tv_template[i].output,
			   dlen)) {
			printk(KERN_ERR "alg: deflate: Decompression test %d "
			       "failed\n", i + 1);
			hexdump(result, dlen);
			ret = -EINVAL;
			goto out;
		}
	}

out:
	crypto_free_tfm(tfm);
	return ret;
}

static void test_crc32c(void)
{
#define NUMVEC 6
#define VECSIZE 40

	int i, j, pass;
	u32 crc;
	u8 b, test_vec[NUMVEC][VECSIZE];
	static u32 vec_results[NUMVEC] = {
		0x0e2c157f, 0xe980ebf6, 0xde74bded,
		0xd579c862, 0xba979ad0, 0x2b29d913
	};
	static u32 tot_vec_results = 0x24c5d375;

	struct scatterlist sg[NUMVEC];
	struct crypto_tfm *tfm;
	char *fmtdata = "testing crc32c initialized to %08x: %s\n";
#define SEEDTESTVAL 0xedcba987
	u32 seed;

	printk("\ntesting crc32c\n");

	tfm = crypto_alloc_tfm("crc32c", 0);
	if (tfm == NULL) {
		printk("failed to load transform for crc32c\n");
		return;
	}

	crypto_digest_init(tfm);
	crypto_digest_final(tfm, (u8*)&crc);
	printk(fmtdata, crc, (crc == 0) ? "pass" : "ERROR");

	/*
	 * stuff test_vec with known values, simple incrementing
	 * byte values.
	 */
	b = 0;
	for (i = 0; i < NUMVEC; i++) {
		for (j = 0; j < VECSIZE; j++)
			test_vec[i][j] = ++b;
		sg_set_buf(&sg[i], test_vec[i], VECSIZE);
	}

	seed = SEEDTESTVAL;
	(void)crypto_digest_setkey(tfm, (const u8*)&seed, sizeof(u32));
	crypto_digest_final(tfm, (u8*)&crc);
	printk("testing crc32c setkey returns %08x : %s\n", crc, (crc == (SEEDTESTVAL ^ ~(u32)0)) ?
	       "pass" : "ERROR");

	printk("testing crc32c using update/final:\n");

	pass = 1;		    /* assume all is well */

	for (i = 0; i < NUMVEC; i++) {
		seed = ~(u32)0;
		(void)crypto_digest_setkey(tfm, (const u8*)&seed, sizeof(u32));
		crypto_digest_update(tfm, &sg[i], 1);
		crypto_digest_final(tfm, (u8*)&crc);
		if (crc == vec_results[i]) {
			printk(" %08x:OK", crc);
		} else {
			printk(" %08x:BAD, wanted %08x\n", crc, vec_results[i]);
			pass = 0;
		}
	}

	printk("\ntesting crc32c using incremental accumulator:\n");
	crc = 0;
	for (i = 0; i < NUMVEC; i++) {
		seed = (crc ^ ~(u32)0);
		(void)crypto_digest_setkey(tfm, (const u8*)&seed, sizeof(u32));
		crypto_digest_update(tfm, &sg[i], 1);
		crypto_digest_final(tfm, (u8*)&crc);
	}
	if (crc == tot_vec_results) {
		printk(" %08x:OK", crc);
	} else {
		printk(" %08x:BAD, wanted %08x\n", crc, tot_vec_results);
		pass = 0;
	}

	printk("\ntesting crc32c using digest:\n");
	seed = ~(u32)0;
	(void)crypto_digest_setkey(tfm, (const u8*)&seed, sizeof(u32));
	crypto_digest_digest(tfm, sg, NUMVEC, (u8*)&crc);
	if (crc == tot_vec_results) {
		printk(" %08x:OK", crc);
	} else {
		printk(" %08x:BAD, wanted %08x\n", crc, tot_vec_results);
		pass = 0;
	}

	printk("\n%s\n", pass ? "pass" : "ERROR");

	crypto_free_tfm(tfm);
	printk("crc32c test complete\n");
}

static void test_available(void)
{
	char **name = check;

	while (*name) {
		printk("alg %s ", *name);
		printk(crypto_alg_available(*name, 0) ||
		       crypto_has_alg(*name, 0, 0) ?
		       "found\n" : "not found\n");
		name++;
	}
}

static inline int tcrypt_test(const char *alg)
{
	return alg_test(alg, alg, 0, 0);
}

static inline int tcrypt_test_digest(const char *alg)
{
	return digest_test(alg, alg);
}

static void do_test(int m)
{
	int i;

	switch (m) {
	case 0:
		for (i = 1; i < 200; i++)
			do_test(i);

	case 1:
		tcrypt_test_digest("md5");
		break;

	case 2:
		tcrypt_test_digest("sha1");
		break;

	case 3:
		tcrypt_test("ecb(des)");
		tcrypt_test("cbc(des)");
		break;

	case 4:
		tcrypt_test("ecb(des3_ede)");
		tcrypt_test("cbc(des3_ede)");
		break;

	case 5:
		tcrypt_test_digest("md4");
		break;

	case 6:
		tcrypt_test_digest("sha256");
		break;

	case 7:
		tcrypt_test("ecb(blowfish)");
		tcrypt_test("cbc(blowfish)");
		break;

	case 8:
		tcrypt_test("ecb(twofish)");
		tcrypt_test("cbc(twofish)");
		break;

	case 9:
		tcrypt_test("ecb(serpent)");
		break;

	case 10:
		tcrypt_test("ecb(aes)");
		tcrypt_test("cbc(aes)");
		tcrypt_test("rfc3686(ctr(aes))");
		break;

	case 11:
		tcrypt_test_digest("sha384");
		break;

	case 12:
		tcrypt_test_digest("sha512");
		break;

	case 13:
		test_deflate();
		break;

	case 14:
		tcrypt_test("ecb(cast5)");
		break;

	case 15:
		tcrypt_test("ecb(cast6)");
		break;

	case 16:
		tcrypt_test("ecb(arc4)");
		break;

	case 17:
		tcrypt_test_digest("michael_mic");
		break;

	case 18:
		test_crc32c();
		break;

	case 19:
		tcrypt_test("ecb(tea)");
		break;

	case 20:
		tcrypt_test("ecb(xtea)");
		break;

	case 21:
		tcrypt_test("ecb(khazad)");
		break;

	case 22:
		tcrypt_test_digest("wp512");
		break;

	case 23:
		tcrypt_test_digest("wp384");
		break;

	case 24:
		tcrypt_test_digest("wp256");
		break;

	case 25:
		tcrypt_test("ecb(tnepres)");
		break;

	case 26:
		tcrypt_test("ecb(anubis)");
		tcrypt_test("cbc(anubis)");
		break;

	case 27:
		tcrypt_test_digest("tgr192");
		break;

	case 28:

		tcrypt_test_digest("tgr160");
		break;

	case 29:
		tcrypt_test_digest("tgr128");
		break;
		
	case 30:
		tcrypt_test("ecb(xeta)");
		break;

	case 37:
		tcrypt_test("ccm(aes)");
		break;

	case 100:
		tcrypt_test("hmac(md5)");
		break;

	case 101:
		tcrypt_test("hmac(sha1)");
		break;

	case 102:
		tcrypt_test("hmac(sha256)");
		break;

	case 106:
		tcrypt_test("xcbc(aes)");
		break;

	case 200:
		test_cipher_speed("ecb(aes)", ENCRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("ecb(aes)", DECRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("cbc(aes)", ENCRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("cbc(aes)", DECRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		break;

	case 201:
		test_cipher_speed("ecb(des3_ede)", ENCRYPT, sec,
				des3_speed_template, DES3_SPEED_VECTORS,
				speed_template_24);
		test_cipher_speed("ecb(des3_ede)", DECRYPT, sec,
				des3_speed_template, DES3_SPEED_VECTORS,
				speed_template_24);
		test_cipher_speed("cbc(des3_ede)", ENCRYPT, sec,
				des3_speed_template, DES3_SPEED_VECTORS,
				speed_template_24);
		test_cipher_speed("cbc(des3_ede)", DECRYPT, sec,
				des3_speed_template, DES3_SPEED_VECTORS,
				speed_template_24);
		break;

	case 202:
		test_cipher_speed("ecb(twofish)", ENCRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("ecb(twofish)", DECRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("cbc(twofish)", ENCRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("cbc(twofish)", DECRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		break;

	case 203:
		test_cipher_speed("ecb(blowfish)", ENCRYPT, sec, NULL, 0,
				  speed_template_8_32);
		test_cipher_speed("ecb(blowfish)", DECRYPT, sec, NULL, 0,
				  speed_template_8_32);
		test_cipher_speed("cbc(blowfish)", ENCRYPT, sec, NULL, 0,
				  speed_template_8_32);
		test_cipher_speed("cbc(blowfish)", DECRYPT, sec, NULL, 0,
				  speed_template_8_32);
		break;

	case 204:
		test_cipher_speed("ecb(des)", ENCRYPT, sec, NULL, 0,
				  speed_template_8);
		test_cipher_speed("ecb(des)", DECRYPT, sec, NULL, 0,
				  speed_template_8);
		test_cipher_speed("cbc(des)", ENCRYPT, sec, NULL, 0,
				  speed_template_8);
		test_cipher_speed("cbc(des)", DECRYPT, sec, NULL, 0,
				  speed_template_8);
		break;

	case 300:
		/* fall through */

	case 301:
		test_digest_speed("md4", sec, generic_digest_speed_template);
		if (mode > 300 && mode < 400) break;

	case 302:
		test_digest_speed("md5", sec, generic_digest_speed_template);
		if (mode > 300 && mode < 400) break;

	case 303:
		test_digest_speed("sha1", sec, generic_digest_speed_template);
		if (mode > 300 && mode < 400) break;

	case 304:
		test_digest_speed("sha256", sec, generic_digest_speed_template);
		if (mode > 300 && mode < 400) break;

	case 305:
		test_digest_speed("sha384", sec, generic_digest_speed_template);
		if (mode > 300 && mode < 400) break;

	case 306:
		test_digest_speed("sha512", sec, generic_digest_speed_template);
		if (mode > 300 && mode < 400) break;

	case 307:
		test_digest_speed("wp256", sec, generic_digest_speed_template);
		if (mode > 300 && mode < 400) break;

	case 308:
		test_digest_speed("wp384", sec, generic_digest_speed_template);
		if (mode > 300 && mode < 400) break;

	case 309:
		test_digest_speed("wp512", sec, generic_digest_speed_template);
		if (mode > 300 && mode < 400) break;

	case 310:
		test_digest_speed("tgr128", sec, generic_digest_speed_template);
		if (mode > 300 && mode < 400) break;

	case 311:
		test_digest_speed("tgr160", sec, generic_digest_speed_template);
		if (mode > 300 && mode < 400) break;

	case 312:
		test_digest_speed("tgr192", sec, generic_digest_speed_template);
		if (mode > 300 && mode < 400) break;

	case 399:
		break;

	case 1000:
		test_available();
		break;
	}
}

static int __init init(void)
{
	int err = -ENOMEM;
	int i;

	for (i = 0; i < TVMEMSIZE; i++) {
		tvmem[i] = (void *)__get_free_page(GFP_KERNEL);
		if (!tvmem[i])
			goto err_free_tv;
	}

	do_test(mode);

	/* We intentionaly return -EAGAIN to prevent keeping
	 * the module. It does all its work from init()
	 * and doesn't offer any runtime functionality 
	 * => we don't need it in the memory, do we?
	 *                                        -- mludvig
	 */
	err = -EAGAIN;

err_free_tv:
	for (i = 0; i < TVMEMSIZE && tvmem[i]; i++)
		free_page((unsigned long)tvmem[i]);

	return err;
}

/*
 * If an init function is provided, an exit function must also be provided
 * to allow module unload.
 */
static void __exit fini(void) { }

module_init(init);
module_exit(fini);

module_param(mode, int, 0);
module_param(sec, uint, 0);
MODULE_PARM_DESC(sec, "Length in seconds of speed tests "
		      "(defaults to zero which uses CPU cycles instead)");

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Quick & dirty crypto testing module");
MODULE_AUTHOR("James Morris <jmorris@intercode.com.au>");
