/* fsdef.c: filesystem index definition
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include "fscache-int.h"

static uint16_t fscache_fsdef_netfs_get_key(const void *cookie_netfs_data,
					    void *buffer, uint16_t bufmax);

static uint16_t fscache_fsdef_netfs_get_aux(const void *cookie_netfs_data,
					    void *buffer, uint16_t bufmax);

static fscache_checkaux_t fscache_fsdef_netfs_check_aux(void *cookie_netfs_data,
							const void *data,
							uint16_t datalen);

struct fscache_cookie_def fscache_fsdef_netfs_def = {
	.name		= "FSDEF.netfs",
	.type		= FSCACHE_COOKIE_TYPE_INDEX,
	.get_key	= fscache_fsdef_netfs_get_key,
	.get_aux	= fscache_fsdef_netfs_get_aux,
	.check_aux	= fscache_fsdef_netfs_check_aux,
};

struct fscache_cookie fscache_fsdef_index = {
	.usage		= ATOMIC_INIT(1),
	.def		= NULL,
	.sem		= __RWSEM_INITIALIZER(fscache_fsdef_index.sem),
	.backing_objects = HLIST_HEAD_INIT,
};

EXPORT_SYMBOL(fscache_fsdef_index);

/*****************************************************************************/
/*
 * get the key data for an FSDEF index record
 */
static uint16_t fscache_fsdef_netfs_get_key(const void *cookie_netfs_data,
					    void *buffer, uint16_t bufmax)
{
	const struct fscache_netfs *netfs = cookie_netfs_data;
	unsigned klen;

	_enter("{%s.%u},", netfs->name, netfs->version);

	klen = strlen(netfs->name);
	if (klen > bufmax)
		return 0;

	memcpy(buffer, netfs->name, klen);
	return klen;
}

/*****************************************************************************/
/*
 * get the auxilliary data for an FSDEF index record
 */
static uint16_t fscache_fsdef_netfs_get_aux(const void *cookie_netfs_data,
					    void *buffer, uint16_t bufmax)
{
	const struct fscache_netfs *netfs = cookie_netfs_data;
	unsigned dlen;

	_enter("{%s.%u},", netfs->name, netfs->version);

	dlen = sizeof(uint32_t);
	if (dlen > bufmax)
		return 0;

	memcpy(buffer, &netfs->version, dlen);
	return dlen;
}

/*****************************************************************************/
/*
 * check that the version stored in the auxilliary data is correct
 */
static fscache_checkaux_t fscache_fsdef_netfs_check_aux(void *cookie_netfs_data,
							const void *data,
							uint16_t datalen)
{
	struct fscache_netfs *netfs = cookie_netfs_data;
	uint32_t version;

	_enter("{%s},,%hu", netfs->name, datalen);

	if (datalen != sizeof(version)) {
		_leave(" = OBSOLETE [dl=%d v=%d]",
		       datalen, sizeof(version));
		return FSCACHE_CHECKAUX_OBSOLETE;
	}

	memcpy(&version, data, sizeof(version));
	if (version != netfs->version) {
		_leave(" = OBSOLETE [ver=%x net=%x]",
		       version, netfs->version);
		return FSCACHE_CHECKAUX_OBSOLETE;
	}

	_leave(" = OKAY");
	return FSCACHE_CHECKAUX_OKAY;
}
