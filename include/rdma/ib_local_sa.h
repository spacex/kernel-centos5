/*
 * Copyright (c) 2006 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef IB_LOCAL_SA_H
#define IB_LOCAL_SA_H

#include <rdma/ib_sa.h>

/**
 * ib_get_path_rec - Query the local SA database for path information.
 * @device: The local device to query.
 * @port_num: The port of the local device being queried.
 * @sgid: The source GID of the path record.
 * @dgid: The destination GID of the path record.
 * @pkey: The protection key of the path record.
 * @rec: A reference to a path record structure that will receive a copy of
 *   the response.
 *
 * Returns a copy of a path record meeting the specified criteria to the
 * location referenced by %rec.  A return value < 0 indicates that an error
 * occurred processing the request, or no path record was found.
 */
int ib_get_path_rec(struct ib_device *device, u8 port_num, union ib_gid *sgid,
		    union ib_gid *dgid, u16 pkey, struct ib_sa_path_rec *rec);

/**
 * ib_create_path_iter - Create an iterator that may be used to walk through
 *   a list of path records.
 * @device: The local device to retrieve path records for.
 * @port_num: The port of the local device.
 * @dgid: The destination GID of the path record.
 *
 * This call allocates an iterator that is used to walk through a list of
 * cached path records.  All path records accessed by the iterator will have the
 * specified DGID.  User should not hold the iterator for an extended period of
 * time, and must free it by calling ib_free_sa_iter.
 */
struct ib_sa_iterator *ib_create_path_iter(struct ib_device *device,
					   u8 port_num, union ib_gid *dgid);

/**
 * ib_free_sa_iter - Release an iterator.
 * @iter: The iterator to free.
 */
void ib_free_sa_iter(struct ib_sa_iterator *iter);

/**
 * ib_get_next_sa_attr - Retrieve the next SA attribute referenced by an
 *   iterator.
 * @iter: A reference to an iterator that points to the next attribute to
 *   retrieve.
 */
void *ib_get_next_sa_attr(struct ib_sa_iterator **iter);

#endif /* IB_LOCAL_SA_H */
