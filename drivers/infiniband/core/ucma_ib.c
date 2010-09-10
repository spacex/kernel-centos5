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

#include <rdma/ib_addr.h>
#include <rdma/ib_marshall.h>
#include <rdma/rdma_cm_ib.h>
#include <rdma/rdma_user_cm.h>

#include "ucma_ib.h"

static int ucma_get_req_opt(struct rdma_cm_id *id, void __user *opt,
			    int *optlen)
{
	struct ib_cm_req_opt req_opt;
	int ret = 0;

	if (!opt)
		goto out;

 	if (*optlen < sizeof req_opt) {
		ret = -ENOMEM;
		goto out;
	}

	ret = rdma_get_ib_req_info(id, &req_opt);
	if (!ret)
		if (copy_to_user(opt, &req_opt, sizeof req_opt))
			ret = -EFAULT;
out:
	*optlen = sizeof req_opt;
	return ret;	
}

int ucma_get_ib_option(struct rdma_cm_id *id, int optname,
		       void *optval, int *optlen)
{
	switch (optname) {
	case IB_PATH_OPTIONS:
		return -EINVAL;
	case IB_CM_REQ_OPTIONS:
		return ucma_get_req_opt(id, optval, optlen);
	default:
		return -EINVAL;
	}
}

static int ucma_set_req_opt(struct rdma_cm_id *id, void __user *opt, int optlen)
{
	struct ib_cm_req_opt req_opt;

	if (optlen != sizeof req_opt)
		return -EINVAL;

	if (copy_from_user(&req_opt, opt, sizeof req_opt))
		return -EFAULT;

	return rdma_set_ib_req_info(id, &req_opt);
}

int ucma_set_ib_option(struct rdma_cm_id *id, int optname,
		       void *optval, int optlen)
{
	switch (optname) {
	case IB_PATH_OPTIONS:
		return -EINVAL;
	case IB_CM_REQ_OPTIONS:
		return ucma_set_req_opt(id, optval, optlen);
	default:
		return -EINVAL;
	}
}
