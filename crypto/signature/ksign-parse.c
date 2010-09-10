/* parse-packet.c  - read packets
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <asm/errno.h>
#include "local.h"

static inline uint32_t buffer_to_u32(const uint8_t *buffer)
{
	uint32_t a;
	a =  *buffer << 24;
	a |= buffer[1] << 16;
	a |= buffer[2] << 8;
	a |= buffer[3];
	return a;
}

static inline uint16_t read_16(const uint8_t **datap)
{
	uint16_t a;
	a = *(*datap)++ << 8;
	a |= *(*datap)++;
	return a;
}

static inline uint32_t read_32(const uint8_t **datap)
{
	uint32_t a;
	a =  *(*datap)++ << 24;
	a |= *(*datap)++ << 16;
	a |= *(*datap)++ << 8;
	a |= *(*datap)++;
	return a;
}

void ksign_free_signature(struct ksign_signature *sig)
{
	int i;

	if (!sig)
		return;

	for (i = 0; i < DSA_NSIG; i++)
		mpi_free(sig->data[i]);
	kfree(sig->hashed_data);
	kfree(sig->unhashed_data);
	kfree(sig);
}

void ksign_free_public_key(struct ksign_public_key *pk)
{
	int i;

	if (pk) {
		for (i = 0; i < DSA_NPKEY; i++)
			mpi_free(pk->pkey[i]);
		kfree(pk);
	}
}

void ksign_free_user_id(struct ksign_user_id *uid)
{
	if (uid)
		kfree(uid);
}

/*****************************************************************************/
/*
 *
 */
static void ksign_calc_pk_keyid(struct crypto_tfm *sha1,
				struct ksign_public_key *pk)
{
	unsigned n;
	unsigned nb[DSA_NPKEY];
	unsigned nn[DSA_NPKEY];
	uint8_t *pp[DSA_NPKEY];
	uint32_t a32;
	int i;
	int npkey = DSA_NPKEY;

	crypto_digest_init(sha1);

	n = pk->version < 4 ? 8 : 6;
	for (i = 0; i < npkey; i++) {
		nb[i] = mpi_get_nbits(pk->pkey[i]);
		pp[i] = mpi_get_buffer( pk->pkey[i], nn + i, NULL);
		n += 2 + nn[i];
	}

	SHA1_putc(sha1, 0x99);     /* ctb */
	SHA1_putc(sha1, n >> 8);   /* 2 uint8_t length header */
	SHA1_putc(sha1, n);

	if( pk->version < 4)
		SHA1_putc(sha1, 3);
	else
		SHA1_putc(sha1, 4);

	a32 = pk->timestamp;
	SHA1_putc(sha1, a32 >> 24 );
	SHA1_putc(sha1, a32 >> 16 );
	SHA1_putc(sha1, a32 >>  8 );
	SHA1_putc(sha1, a32 >>  0 );

	if (pk->version < 4) {
		uint16_t a16;

		if( pk->expiredate )
			a16 = (uint16_t) ((pk->expiredate - pk->timestamp) / 86400L);
		else
			a16 = 0;
		SHA1_putc(sha1, a16 >> 8);
		SHA1_putc(sha1, a16 >> 0);
	}

	SHA1_putc(sha1, PUBKEY_ALGO_DSA);

	for (i = 0; i < npkey; i++) {
		SHA1_putc(sha1, nb[i] >> 8);
		SHA1_putc(sha1, nb[i]);
		SHA1_write(sha1, pp[i], nn[i]);
		kfree(pp[i]);
	}

} /* end ksign_calc_pk_keyid() */

/*****************************************************************************/
/*
 * parse a user ID embedded in a signature
 */
static int ksign_parse_user_id(const uint8_t *datap, const uint8_t *endp,
			       ksign_user_id_actor_t uidfnx, void *fnxdata)
{
	struct ksign_user_id *uid;
	int rc = 0;
	int n;

	if (!uidfnx)
		return 0;

	n = endp - datap;
	uid = kmalloc(sizeof(*uid) + n + 1, GFP_KERNEL);
	if (!uid)
		return -ENOMEM;
	uid->len = n;

	memcpy(uid->name, datap, n);
	uid->name[n] = 0;

	rc = uidfnx(uid, fnxdata);
	if (rc == 0)
		return rc; /* uidfnx keeps the record */
	if (rc == 1)
		rc = 0;

	ksign_free_user_id(uid);
	return rc;
} /* end ksign_parse_user_id() */

/*****************************************************************************/
/*
 * extract a public key embedded in a signature
 */
static int ksign_parse_key(const uint8_t *datap, const uint8_t *endp,
			   uint8_t *hdr, int hdrlen,
			   ksign_public_key_actor_t pkfnx, void *fnxdata)
{
	struct ksign_public_key *pk;
	struct crypto_tfm *sha1_tfm;
	unsigned long timestamp, expiredate;
	uint8_t sha1[SHA1_DIGEST_SIZE];
	int i, version;
	int is_v4 = 0;
	int rc = 0;

	if (endp - datap < 12) {
		printk("ksign: public key packet too short\n");
		return -EBADMSG;
	}

	version = *datap++;
	switch (version) {
	case 4:
		is_v4 = 1;
	case 2:
	case 3:
		break;
	default:
		printk("ksign: public key packet with unknown version %d\n",
		       version);
		return -EBADMSG;
	}

	timestamp = read_32(&datap);
	if (is_v4)
		expiredate = 0; /* have to get it from the selfsignature */
	else {
		unsigned short ndays;
		ndays = read_16(&datap);
		if (ndays)
			expiredate = timestamp + ndays * 86400L;
		else
			expiredate = 0;
	}

	if (*datap++ != PUBKEY_ALGO_DSA) {
		printk("ksign: public key packet with unknown version %d\n",
		       version);
		return 0;
	}

	/* extract the stuff from the DSA public key */
	pk = kmalloc(sizeof(struct ksign_public_key), GFP_KERNEL);
	if (!pk)
		return -ENOMEM;

	memset(pk, 0, sizeof(struct ksign_public_key));
	atomic_set(&pk->count, 1);
	pk->timestamp	= timestamp;
	pk->expiredate	= expiredate;
	pk->hdrbytes	= hdrlen;
	pk->version	= version;

	for (i = 0; i < DSA_NPKEY; i++) {
		unsigned int remaining = endp - datap;
		pk->pkey[i] = mpi_read_from_buffer(datap, &remaining);
		datap += remaining;
	}

	rc = -ENOMEM;

	sha1_tfm = crypto_alloc_tfm2("sha1", 0, 1);
	if (!sha1_tfm)
		goto cleanup;

	ksign_calc_pk_keyid(sha1_tfm, pk);
	crypto_digest_final(sha1_tfm, sha1);
	crypto_free_tfm(sha1_tfm);

	pk->keyid[0] = sha1[12] << 24 | sha1[13] << 16 | sha1[14] << 8 | sha1[15];
	pk->keyid[1] = sha1[16] << 24 | sha1[17] << 16 | sha1[18] << 8 | sha1[19];

	rc = 0;
	if (pkfnx)
		rc = pkfnx(pk, fnxdata);

 cleanup:
	ksign_put_public_key(pk);
	return rc;
} /* end ksign_parse_key() */

/*****************************************************************************/
/*
 *
 */
static const uint8_t *ksign_find_sig_issuer(const uint8_t *buffer)
{
	size_t buflen;
	size_t n;
	int type;
	int seq = 0;

	if (!buffer)
		return NULL;

	buflen = read_16(&buffer);
	while (buflen) {
		n = *buffer++; buflen--;
		if (n == 255) {
			if (buflen < 4)
				goto too_short;
			n = read_32(&buffer);
			buflen -= 4;
		}
		else if (n >= 192) {
			if(buflen < 2)
				goto too_short;
			n = ((n - 192) << 8) + *buffer + 192;
			buffer++;
			buflen--;
		}

		if (buflen < n)
			goto too_short;

		type = *buffer & 0x7f;
		if (!(++seq > 0))
			;
		else if (type == SIGSUBPKT_ISSUER) { /* found */
			buffer++;
			n--;
			if (n > buflen || n < 8)
				goto too_short;
			return buffer;
		}

		buffer += n;
		buflen -= n;
	}

 too_short:
	return NULL; /* end of subpackets; not found */
} /* end ksign_find_sig_issuer() */

/*****************************************************************************/
/*
 * extract signature data embedded in a signature
 */
static int ksign_parse_signature(const uint8_t *datap, const uint8_t *endp,
				 ksign_signature_actor_t sigfnx, void *fnxdata)
{
	struct ksign_signature *sig;
	size_t n;
	int version, is_v4 = 0;
	int rc;
	int i;

	if (endp - datap < 16) {
		printk("ksign: signature packet too short\n");
		return -EBADMSG;
	}

	version = *datap++;
	switch (version) {
	case 4:
		is_v4 = 1;
	case 3:
	case 2:
		break;
	default:
		printk("ksign: signature packet with unknown version %d\n", version);
		return 0;
	}

	/* store information */
	sig = kmalloc(sizeof(*sig), GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	memset(sig, 0, sizeof(*sig));
	sig->version = version;

	if (!is_v4)
		datap++; /* ignore md5 length */

	sig->sig_class = *datap++;
	if (!is_v4) {
		sig->timestamp = read_32(&datap);
		sig->keyid[0] = read_32(&datap);
		sig->keyid[1] = read_32(&datap);
	}

	rc = 0;
	if (*datap++ != PUBKEY_ALGO_DSA) {
		printk("ksign: ignoring non-DSA signature\n");
		goto leave;
	}
	if (*datap++ != DIGEST_ALGO_SHA1) {
		printk("ksign: ignoring non-SHA1 signature\n");
		goto leave;
	}

	rc = -EBADMSG;
	if (is_v4) { /* read subpackets */
		n = read_16(&datap); /* length of hashed data */
		if (n > 10000) {
			printk("ksign: signature packet: hashed data too long\n");
			goto leave;
		}
		if (n) {
			if ((size_t)(endp - datap) < n) {
				printk("ksign: signature packet: available data too short\n");
				goto leave;
			}
			sig->hashed_data = kmalloc(n + 2, GFP_KERNEL);
			if (!sig->hashed_data) {
				rc = -ENOMEM;
				goto leave;
			}
			sig->hashed_data[0] = n >> 8;
			sig->hashed_data[1] = n;
			memcpy(sig->hashed_data + 2, datap, n);
			datap += n;
		}

		n = read_16(&datap); /* length of unhashed data */
		if (n > 10000) {
			printk("ksign: signature packet: unhashed data too long\n");
			goto leave;
		}
		if (n) {
			if ((size_t) (endp - datap) < n) {
				printk("ksign: signature packet: available data too short\n");
				goto leave;
			}
			sig->unhashed_data = kmalloc(n + 2, GFP_KERNEL);
			if (!sig->unhashed_data) {
				rc = -ENOMEM;
				goto leave;
			}
			sig->unhashed_data[0] = n >> 8;
			sig->unhashed_data[1] = n;
			memcpy(sig->unhashed_data + 2, datap, n);
			datap += n;
		}
	}

	if (endp - datap < 5) { /* sanity check */
		printk("ksign: signature packet too short\n");
		goto leave;
	}

	sig->digest_start[0] = *datap++;
	sig->digest_start[1] = *datap++;

	if (is_v4) {
		const uint8_t *p;

		p = ksign_find_sig_issuer(sig->hashed_data);
		if (!p)
			p = ksign_find_sig_issuer(sig->unhashed_data);
		if (!p)
			printk("ksign: signature packet without issuer\n");
		else {
			sig->keyid[0] = buffer_to_u32(p);
			sig->keyid[1] = buffer_to_u32(p + 4);
		}
	}

	for (i = 0; i < DSA_NSIG; i++) {
		unsigned remaining = endp - datap;
		sig->data[i] = mpi_read_from_buffer(datap, &remaining);
		datap += remaining;
	}

	rc = 0;
	if (sigfnx) {
		rc = sigfnx(sig, fnxdata);
		if (rc == 0)
			return rc; /* sigfnx keeps the signature */
		if (rc == 1)
			rc = 0;
	}

 leave:
	ksign_free_signature(sig);
	return rc;
} /* end ksign_parse_signature() */

/*****************************************************************************/
/*
 * parse the next packet and call appropriate handler function for known types
 * - returns:
 *     0 on EOF
 *     1 if there might be more packets
 *     -EBADMSG if the packet is in an invalid format
 *     -ve on other error
 */
static int ksign_parse_one_packet(const uint8_t **datap,
				  const uint8_t *endp,
				  ksign_signature_actor_t sigfnx,
				  ksign_public_key_actor_t pkfnx,
				  ksign_user_id_actor_t uidfnx,
				  void *data)
{
	int rc, c, ctb, pkttype, lenuint8_ts;
	unsigned long pktlen;
	uint8_t hdr[8];
	int hdrlen;

	/* extract the next packet and dispatch it */
	rc = 0;
	if (*datap >= endp)
		goto leave;
	ctb = *(*datap)++;

	rc = -EBADMSG;

	hdrlen = 0;
	hdr[hdrlen++] = ctb;
	if (!(ctb & 0x80)) {
		printk("ksign: invalid packet (ctb=%02x)\n", ctb);
		goto leave;
	}

	pktlen = 0;
	if (ctb & 0x40) {
		pkttype = ctb & 0x3f;
		if (*datap >= endp) {
			printk("ksign: 1st length byte missing\n");
			goto leave;
		}
		c = *(*datap)++;
		hdr[hdrlen++] = c;

		if (c < 192) {
			pktlen = c;
		}
		else if (c < 224) {
			pktlen = (c - 192) * 256;
			if (*datap >= endp) {
				printk("ksign: 2nd length uint8_t missing\n");
				goto leave;
			}
			c = *(*datap)++;
			hdr[hdrlen++] = c;
			pktlen += c + 192;
		}
		else if (c == 255) {
			if (*datap + 3 >= endp) {
				printk("ksign: 4 uint8_t length invalid\n");
				goto leave;
			}
			pktlen  = (hdr[hdrlen++] = *(*datap)++ << 24	);
			pktlen |= (hdr[hdrlen++] = *(*datap)++ << 16	);
			pktlen |= (hdr[hdrlen++] = *(*datap)++ <<  8	);
			pktlen |= (hdr[hdrlen++] = *(*datap)++ <<  0	);
		}
		else {
			pktlen = 0;/* to indicate partial length */
		}
	}
	else {
		pkttype = (ctb >> 2) & 0xf;
		lenuint8_ts = ((ctb & 3) == 3) ? 0 : (1 << (ctb & 3));
		if( !lenuint8_ts ) {
			pktlen = 0; /* don't know the value */
		}
		else {
			if (*datap + lenuint8_ts > endp) {
				printk("ksign: length uint8_ts missing\n");
				goto leave;
			}
			for( ; lenuint8_ts; lenuint8_ts-- ) {
				pktlen <<= 8;
				pktlen |= hdr[hdrlen++] = *(*datap)++;
			}
		}
	}

	if (*datap + pktlen > endp) {
		printk("ksign: packet length longer than available data\n");
		goto leave;
	}

	/* deal with the next packet appropriately */
	switch (pkttype) {
	case PKT_PUBLIC_KEY:
		rc = ksign_parse_key(*datap, *datap + pktlen, hdr, hdrlen, pkfnx, data);
		break;
	case PKT_SIGNATURE:
		rc = ksign_parse_signature(*datap, *datap + pktlen, sigfnx, data);
		break;
	case PKT_USER_ID:
		rc = ksign_parse_user_id(*datap, *datap + pktlen, uidfnx, data);
		break;
	default:
		rc = 0; /* unknown packet */
		break;
	}

	*datap += pktlen;
 leave:
	return rc;
} /* end ksign_parse_one_packet() */

/*****************************************************************************/
/*
 * parse the contents of a packet buffer, passing the signature, public key and
 * user ID to the caller's callback functions
 */
int ksign_parse_packets(const uint8_t *buf,
			size_t size,
			ksign_signature_actor_t sigfnx,
			ksign_public_key_actor_t pkfnx,
			ksign_user_id_actor_t uidfnx,
			void *data)
{
	const uint8_t *datap, *endp;
	int rc;

	datap = buf;
	endp = buf + size;
	do {
		rc = ksign_parse_one_packet(&datap, endp,
					    sigfnx, pkfnx, uidfnx, data);
	} while (rc == 0 && datap < endp);

	return rc;
} /* end ksign_parse_packets() */
