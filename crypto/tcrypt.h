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
 * 2004-08-09 Cipher speed tests by Reyk Floeter <reyk@vantronix.net>
 * 2003-09-14 Changes by Kartikey Mahendra Bhatt
 *
 */
#ifndef _CRYPTO_TCRYPT_H
#define _CRYPTO_TCRYPT_H

struct cipher_speed_template {
	char *key;
	unsigned int klen;
};

struct digest_speed {
	unsigned int blen;	/* buffer length */
	unsigned int plen;	/* per-update length */
};

/*
 * DES test vectors.
 */
#define DES3_SPEED_VECTORS		1

static struct cipher_speed_template des3_speed_template[] = {
	{
		.key	= "\x01\x23\x45\x67\x89\xab\xcd\xef"
			  "\x55\x55\x55\x55\x55\x55\x55\x55"
			  "\xfe\xdc\xba\x98\x76\x54\x32\x10",
		.klen	= 24,
	}
};

/*
 * Compression stuff.
 */
#define COMP_BUF_SIZE           512

struct comp_testvec {
	int inlen, outlen;
	char input[COMP_BUF_SIZE];
	char output[COMP_BUF_SIZE];
};

/*
 * Deflate test vectors (null-terminated strings).
 * Params: winbits=11, Z_DEFAULT_COMPRESSION, MAX_MEM_LEVEL.
 */
#define DEFLATE_COMP_TEST_VECTORS 2
#define DEFLATE_DECOMP_TEST_VECTORS 2

static struct comp_testvec deflate_comp_tv_template[] = {
	{
		.inlen	= 70,
		.outlen	= 38,
		.input	= "Join us now and share the software "
			"Join us now and share the software ",
		.output	= "\xf3\xca\xcf\xcc\x53\x28\x2d\x56"
			  "\xc8\xcb\x2f\x57\x48\xcc\x4b\x51"
			  "\x28\xce\x48\x2c\x4a\x55\x28\xc9"
			  "\x48\x55\x28\xce\x4f\x2b\x29\x07"
			  "\x71\xbc\x08\x2b\x01\x00",
	}, {
		.inlen	= 191,
		.outlen	= 122,
		.input	= "This document describes a compression method based on the DEFLATE"
			"compression algorithm.  This document defines the application of "
			"the DEFLATE algorithm to the IP Payload Compression Protocol.",
		.output	= "\x5d\x8d\x31\x0e\xc2\x30\x10\x04"
			  "\xbf\xb2\x2f\xc8\x1f\x10\x04\x09"
			  "\x89\xc2\x85\x3f\x70\xb1\x2f\xf8"
			  "\x24\xdb\x67\xd9\x47\xc1\xef\x49"
			  "\x68\x12\x51\xae\x76\x67\xd6\x27"
			  "\x19\x88\x1a\xde\x85\xab\x21\xf2"
			  "\x08\x5d\x16\x1e\x20\x04\x2d\xad"
			  "\xf3\x18\xa2\x15\x85\x2d\x69\xc4"
			  "\x42\x83\x23\xb6\x6c\x89\x71\x9b"
			  "\xef\xcf\x8b\x9f\xcf\x33\xca\x2f"
			  "\xed\x62\xa9\x4c\x80\xff\x13\xaf"
			  "\x52\x37\xed\x0e\x52\x6b\x59\x02"
			  "\xd9\x4e\xe8\x7a\x76\x1d\x02\x98"
			  "\xfe\x8a\x87\x83\xa3\x4f\x56\x8a"
			  "\xb8\x9e\x8e\x5c\x57\xd3\xa0\x79"
			  "\xfa\x02",
	},
};

static struct comp_testvec deflate_decomp_tv_template[] = {
	{
		.inlen	= 122,
		.outlen	= 191,
		.input	= "\x5d\x8d\x31\x0e\xc2\x30\x10\x04"
			  "\xbf\xb2\x2f\xc8\x1f\x10\x04\x09"
			  "\x89\xc2\x85\x3f\x70\xb1\x2f\xf8"
			  "\x24\xdb\x67\xd9\x47\xc1\xef\x49"
			  "\x68\x12\x51\xae\x76\x67\xd6\x27"
			  "\x19\x88\x1a\xde\x85\xab\x21\xf2"
			  "\x08\x5d\x16\x1e\x20\x04\x2d\xad"
			  "\xf3\x18\xa2\x15\x85\x2d\x69\xc4"
			  "\x42\x83\x23\xb6\x6c\x89\x71\x9b"
			  "\xef\xcf\x8b\x9f\xcf\x33\xca\x2f"
			  "\xed\x62\xa9\x4c\x80\xff\x13\xaf"
			  "\x52\x37\xed\x0e\x52\x6b\x59\x02"
			  "\xd9\x4e\xe8\x7a\x76\x1d\x02\x98"
			  "\xfe\x8a\x87\x83\xa3\x4f\x56\x8a"
			  "\xb8\x9e\x8e\x5c\x57\xd3\xa0\x79"
			  "\xfa\x02",
		.output	= "This document describes a compression method based on the DEFLATE"
			"compression algorithm.  This document defines the application of "
			"the DEFLATE algorithm to the IP Payload Compression Protocol.",
	}, {
		.inlen	= 38,
		.outlen	= 70,
		.input	= "\xf3\xca\xcf\xcc\x53\x28\x2d\x56"
			  "\xc8\xcb\x2f\x57\x48\xcc\x4b\x51"
			  "\x28\xce\x48\x2c\x4a\x55\x28\xc9"
			  "\x48\x55\x28\xce\x4f\x2b\x29\x07"
			  "\x71\xbc\x08\x2b\x01\x00",
		.output	= "Join us now and share the software "
			"Join us now and share the software ",
	},
};

/*
 * Cipher speed tests
 */
static u8 speed_template_8[] = {8, 0};
static u8 speed_template_24[] = {24, 0};
static u8 speed_template_8_32[] = {8, 32, 0};
static u8 speed_template_16_24_32[] = {16, 24, 32, 0};
static u8 speed_template_32_48_64[] = {32, 48, 64, 0};
/*
 * Digest speed tests
 */
static struct digest_speed generic_digest_speed_template[] = {
	{ .blen = 16, 	.plen = 16, },
	{ .blen = 64,	.plen = 16, },
	{ .blen = 64,	.plen = 64, },
	{ .blen = 256,	.plen = 16, },
	{ .blen = 256,	.plen = 64, },
	{ .blen = 256,	.plen = 256, },
	{ .blen = 1024,	.plen = 16, },
	{ .blen = 1024,	.plen = 256, },
	{ .blen = 1024,	.plen = 1024, },
	{ .blen = 2048,	.plen = 16, },
	{ .blen = 2048,	.plen = 256, },
	{ .blen = 2048,	.plen = 1024, },
	{ .blen = 2048,	.plen = 2048, },
	{ .blen = 4096,	.plen = 16, },
	{ .blen = 4096,	.plen = 256, },
	{ .blen = 4096,	.plen = 1024, },
	{ .blen = 4096,	.plen = 4096, },
	{ .blen = 8192,	.plen = 16, },
	{ .blen = 8192,	.plen = 256, },
	{ .blen = 8192,	.plen = 1024, },
	{ .blen = 8192,	.plen = 4096, },
	{ .blen = 8192,	.plen = 8192, },

	/* End marker */
	{  .blen = 0,	.plen = 0, }
};

#endif	/* _CRYPTO_TCRYPT_H */
