/*
 * Copyright (c) 2006 Intel Corporation.  All rights reserved.
 *
 * This Software is licensed under one of the following licenses:
 *
 * 1) under the terms of the "Common Public License 1.0" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/cpl.php.
 *
 * 2) under the terms of the "The BSD License" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/bsd-license.php.
 *
 * 3) under the terms of the "GNU General Public License (GPL) Version 2" a
 *    copy of which is available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/gpl-license.php.
 *
 * Licensee has the right to choose one of the above licenses.
 *
 * Redistributions of source code must retain the above copyright
 * notice and one of the license notices.
 *
 * Redistributions in binary form must reproduce both the above copyright
 * notice, one of the license notices in the documentation
 * and/or other materials provided with the distribution.
 *
 */

#if !defined(RDMA_CM_IB_H)
#define RDMA_CM_IB_H

#include <rdma/rdma_cm.h>

/**
 * rdma_set_ib_paths - Manually sets the path records used to establish a
 *   connection.
 * @id: Connection identifier associated with the request.
 * @path_rec: Reference to the path record
 *
 * This call permits a user to specify routing information for rdma_cm_id's
 * bound to Infiniband devices.  It is called on the client side of a
 * connection and replaces the call to rdma_resolve_route.
 */
int rdma_set_ib_paths(struct rdma_cm_id *id,
		      struct ib_sa_path_rec *path_rec, int num_paths);

struct ib_cm_req_opt {
	u8	remote_cm_response_timeout;
	u8	local_cm_response_timeout;
	u8	max_cm_retries;
};

/**
 * rdma_get_ib_req_info - Retrieves the current IB CM REQ / SIDR REQ values
 *   that will be used when connection, or performing service ID resolution.
 * @id: Connection identifier associated with the request.
 * @info: Current values for CM REQ messages.
 */
int rdma_get_ib_req_info(struct rdma_cm_id *id, struct ib_cm_req_opt *info);

/**
 * rdma_set_ib_req_info - Sets the current IB CM REQ / SIDR REQ values
 *   that will be used when connection, or performing service ID resolution.
 * @id: Connection identifier associated with the request.
 * @info: New values for CM REQ messages.
 */
int rdma_set_ib_req_info(struct rdma_cm_id *id, struct ib_cm_req_opt *info);

#endif /* RDMA_CM_IB_H */
