/*
 * Copyright (c) 2005 Intel Corporation.  All rights reserved.
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

#ifndef RDMA_USER_CM_H
#define RDMA_USER_CM_H

#include <linux/types.h>
#include <linux/in6.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_user_sa.h>

#define RDMA_USER_CM_ABI_VERSION	1

#define RDMA_MAX_PRIVATE_DATA		256

enum {
	RDMA_USER_CM_CMD_CREATE_ID,
	RDMA_USER_CM_CMD_DESTROY_ID,
	RDMA_USER_CM_CMD_BIND_ADDR,
	RDMA_USER_CM_CMD_RESOLVE_ADDR,
	RDMA_USER_CM_CMD_RESOLVE_ROUTE,
	RDMA_USER_CM_CMD_QUERY_ROUTE,
	RDMA_USER_CM_CMD_CONNECT,
	RDMA_USER_CM_CMD_LISTEN,
	RDMA_USER_CM_CMD_ACCEPT,
	RDMA_USER_CM_CMD_REJECT,
	RDMA_USER_CM_CMD_DISCONNECT,
	RDMA_USER_CM_CMD_INIT_QP_ATTR,
	RDMA_USER_CM_CMD_GET_EVENT,
	RDMA_USER_CM_CMD_GET_OPTION,
	RDMA_USER_CM_CMD_SET_OPTION,
};

/*
 * command ABI structures.
 */
struct rdma_ucm_cmd_hdr {
	__u32 cmd;
	__u16 in;
	__u16 out;
};

struct rdma_ucm_create_id {
	__u64 uid;
	__u64 response;
};

struct rdma_ucm_create_id_resp {
	__u32 id;
};

struct rdma_ucm_destroy_id {
	__u64 response;
	__u32 id;
	__u32 reserved;
};

struct rdma_ucm_destroy_id_resp {
	__u32 events_reported;
};

struct rdma_ucm_bind_addr {
	__u64 response;
	struct sockaddr_in6 addr;
	__u32 id;
};

struct rdma_ucm_resolve_addr {
	struct sockaddr_in6 src_addr;
	struct sockaddr_in6 dst_addr;
	__u32 id;
	__u32 timeout_ms;
};

struct rdma_ucm_resolve_route {
	__u32 id;
	__u32 timeout_ms;
};

struct rdma_ucm_query_route {
	__u64 response;
	__u32 id;
	__u32 reserved;
};

struct rdma_ucm_query_route_resp {
	__u64 node_guid;
	struct ib_user_path_rec ib_route[2];
	struct sockaddr_in6 src_addr;
	struct sockaddr_in6 dst_addr;
	__u32 num_paths;
	__u8 port_num;
	__u8 reserved[3];
};

struct rdma_ucm_conn_param {
	__u32 qp_num;
	__u32 qp_type;
	__u8  private_data[RDMA_MAX_PRIVATE_DATA];
	__u8  private_data_len;
	__u8  srq;
	__u8  responder_resources;
	__u8  initiator_depth;
	__u8  flow_control;
	__u8  retry_count;
	__u8  rnr_retry_count;
	__u8  valid;
};

struct rdma_ucm_connect {
	struct rdma_ucm_conn_param conn_param;
	__u32 id;
	__u32 reserved;
};

struct rdma_ucm_listen {
	__u32 id;
	__u32 backlog;
};

struct rdma_ucm_accept {
	__u64 uid;
	struct rdma_ucm_conn_param conn_param;
	__u32 id;
	__u32 reserved;
};

struct rdma_ucm_reject {
	__u32 id;
	__u8  private_data_len;
	__u8  reserved[3];
	__u8  private_data[RDMA_MAX_PRIVATE_DATA];
};

struct rdma_ucm_disconnect {
	__u32 id;
};

struct rdma_ucm_init_qp_attr {
	__u64 response;
	__u32 id;
	__u32 qp_state;
};

struct rdma_ucm_get_event {
	__u64 response;
};

struct rdma_ucm_event_resp {
	__u64 uid;
	__u32 id;
	__u32 event;
	__u32 status;
	__u8  private_data_len;
	__u8  reserved[3];
	__u8  private_data[RDMA_MAX_PRIVATE_DATA];
};

struct rdma_ucm_get_option {
	__u64 response;
	__u64 optval;
	__u32 id;
	__u32 level;
	__u32 optname;
	__u32 optlen;
};

/* Protocol levels for get/set options. */
enum {
	RDMA_PROTO_IP = 0,
	RDMA_PROTO_IB = 1,
};

/* IB specific option names for get/set. */
enum {
	IB_PATH_OPTIONS = 1,
	IB_CM_REQ_OPTIONS = 2,
};

struct rdma_ucm_get_option_resp {
	__u32 optlen;
};

struct rdma_ucm_set_option {
	__u64 optval;
	__u32 id;
	__u32 level;
	__u32 optname;
	__u32 optlen;
};

#endif /* RDMA_USER_CM_H */
