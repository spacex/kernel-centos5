/* ksign.h: in-kernel signature checker
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _LINUX_CRYPTO_KSIGN_H
#define _LINUX_CRYPTO_KSIGN_H

#include <linux/types.h>

#ifdef CONFIG_CRYPTO_SIGNATURE
extern int ksign_verify_signature(const char *sig, unsigned sig_size,
				  struct crypto_tfm *sha1);
#endif

#endif /* _LINUX_CRYPTO_KSIGN_H */
