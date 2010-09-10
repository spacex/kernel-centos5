/* ksign.c: signature checker
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <asm/errno.h>
#include "local.h"

#if 0
#define _debug(FMT, ...) printk(KERN_DEBUG FMT, ##__VA_ARGS__)
#else
#define _debug(FMT, ...) do { ; } while (0)
#endif

/*****************************************************************************/
/*
 * check the signature which is contained in SIG.
 */
static int ksign_signature_check(const struct ksign_signature *sig,
				 struct crypto_tfm *sha1_tfm)
{
	struct ksign_public_key *pk;
	uint8_t sha1[SHA1_DIGEST_SIZE];
	MPI result = NULL;
	int rc = 0;

	pk = ksign_get_public_key(sig->keyid);
	if (!pk) {
		printk("ksign: module signed with unknown public key\n");
		printk("- signature keyid: %08x%08x ver=%u\n",
		       sig->keyid[0], sig->keyid[1], sig->version);
		return -EPERM;
	}

	if (pk->timestamp > sig->timestamp)
		printk("ksign:"
		       " public key is %lu seconds newer than the signature\n",
		       pk->timestamp - sig->timestamp);

	/* complete the digest */
	if (sig->version >= 4)
		SHA1_putc(sha1_tfm, sig->version);
	SHA1_putc(sha1_tfm, sig->sig_class);

	if (sig->version < 4) {
		u32 a = sig->timestamp;
		SHA1_putc(sha1_tfm, (a >> 24) & 0xff);
		SHA1_putc(sha1_tfm, (a >> 16) & 0xff);
		SHA1_putc(sha1_tfm, (a >>  8) & 0xff);
		SHA1_putc(sha1_tfm, (a >>  0) & 0xff);
	}
	else {
		uint8_t buf[6];
		size_t n;
		SHA1_putc(sha1_tfm, PUBKEY_ALGO_DSA);
		SHA1_putc(sha1_tfm, DIGEST_ALGO_SHA1);
		if (sig->hashed_data) {
			n = (sig->hashed_data[0] << 8) | sig->hashed_data[1];
			SHA1_write(sha1_tfm, sig->hashed_data, n + 2);
			n += 6;
		}
		else {
			n = 6;
		}

		/* add some magic */
		buf[0] = sig->version;
		buf[1] = 0xff;
		buf[2] = n >> 24;
		buf[3] = n >> 16;
		buf[4] = n >>  8;
		buf[5] = n;
		SHA1_write(sha1_tfm, buf, 6);
	}

	crypto_digest_final(sha1_tfm, sha1);
	crypto_free_tfm(sha1_tfm);






	rc = -ENOMEM;
	result = mpi_alloc((SHA1_DIGEST_SIZE + BYTES_PER_MPI_LIMB - 1) / BYTES_PER_MPI_LIMB);
	if (!result)
		goto cleanup;

	rc = mpi_set_buffer(result, sha1, SHA1_DIGEST_SIZE, 0);
	if (rc < 0)
		goto cleanup;

	rc = DSA_verify(result, sig->data, pk->pkey);

 cleanup:
	mpi_free(result);
	ksign_put_public_key(pk);

	return rc;
} /* end ksign_signature_check() */

/*****************************************************************************/
/*
 * examine the signatures that are parsed out of the signature data - we keep
 * the first one that's appropriate and ignore the rest
 * - return 0 if signature of interest (sig not freed by caller)
 * - return 1 if no interest (caller frees)
 */
static int ksign_grab_signature(struct ksign_signature *sig, void *fnxdata)
{
	struct ksign_signature **_sig = fnxdata;

	if (sig->sig_class != 0x00) {
		_debug("ksign: standalone signature of class 0x%02x\n",
		       sig->sig_class);
		return 1;
	}

	if (*_sig)
		return 1;

	*_sig = sig;
	return 0;
} /* end ksign_grab_signature() */

/*****************************************************************************/
/*
 * verify the signature of some data with one of the kernel's known public keys
 * - the SHA1 context should be currently open with the signed data digested
 *   into it so that more data can be appended
 * - the SHA1 context is finalised and freed before returning
 */
int ksign_verify_signature(const char *sigdata, unsigned sig_size,
			   struct crypto_tfm *sha1)
{
	struct ksign_signature *sig = NULL;
	int retval;

	/* parse the signature data to get the actual signature */
	retval = ksign_parse_packets(sigdata, sig_size,
				     &ksign_grab_signature, NULL, NULL,
				     &sig);
	if (retval < 0)
		goto cleanup;

	if (!sig) {
		printk("Couldn't find valid DSA signature in module\n");
		return -ENOENT;
	}

	_debug("signature keyid: %08x%08x ver=%u\n",
	       sig->keyid[0], sig->keyid[1], sig->version);

	/* check the data SHA1 transformation against the public key */
	retval = ksign_signature_check(sig, sha1);
	if (retval == 0) {
		_debug("ksign: Signature check succeeded\n");
	}
	else if (retval != -ENOMEM) {
		_debug("ksign: Signature check failed\n");
		retval = -EPERM;
	}
	else {
		_debug("ksign: Signature check ENOMEM\n");
	}

 cleanup:
	if (sig)
		ksign_free_signature(sig);

	return retval;
} /* end ksign_verify_signature() */
