/*
 * Copyright (c) 2006 QLogic, Inc.  All rights reserved.
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

#ifndef VNIC_CONTROL_PKT_H_INCLUDED
#define VNIC_CONTROL_PKT_H_INCLUDED

#include <linux/utsname.h>

#define VNIC_MAX_NODENAME_LEN	64

struct vnic_connection_data {
	u64	path_id;
	u8	vnic_instance;
	u8	path_num;
	u8	nodename[VNIC_MAX_NODENAME_LEN + 1];
};

struct vnic_control_header {
	u8	pkt_type;
	u8	pkt_cmd;
	u8	pkt_seq_num;
	u8	pkt_retry_count;
	u32	reserved;	/* for 64-bit alignmnet */
};

/* ptk_type values */
enum {
	TYPE_INFO	= 0,
	TYPE_REQ	= 1,
	TYPE_RSP	= 2,
	TYPE_ERR	= 3
};

/* ptk_cmd values */
enum {
	CMD_INIT_VNIC		= 1,
	CMD_CONFIG_DATA_PATH	= 2,
	CMD_EXCHANGE_POOLS	= 3,
	CMD_CONFIG_ADDRESSES	= 4,
	CMD_CONFIG_LINK		= 5,
	CMD_REPORT_STATISTICS	= 6,
	CMD_CLEAR_STATISTICS	= 7,
	CMD_REPORT_STATUS	= 8,
	CMD_RESET		= 9,
	CMD_HEARTBEAT		= 10
};

/* pkt_cmd CMD_INIT_VNIC, pkt_type TYPE_REQ data format */
struct vnic_cmd_init_vnic_req {
	__be16	vnic_major_version;
	__be16	vnic_minor_version;
	u8	vnic_instance;
	u8	num_data_paths;
	__be16	num_address_entries;
};

/* pkt_cmd CMD_INIT_VNIC, pkt_type TYPE_RSP subdata format */
struct vnic_lan_switch_attribs {
	u8	lan_switch_num;
	u8	num_enet_ports;
	__be16	default_vlan;
	u8	hw_mac_address[ETH_ALEN];
};

/* pkt_cmd CMD_INIT_VNIC, pkt_type TYPE_RSP data format */
struct vnic_cmd_init_vnic_rsp {
	__be16				vnic_major_version;
	__be16				vnic_minor_version;
	u8				num_lan_switches;
	u8				num_data_paths;
	__be16				num_address_entries;
	__be32				features_supported;
	struct vnic_lan_switch_attribs	lan_switch[1];
};

/* features_supported values */
enum {
	VNIC_FEAT_IPV4_HEADERS		= 0x0001,
	VNIC_FEAT_IPV6_HEADERS		= 0x0002,
	VNIC_FEAT_IPV4_CSUM_RX		= 0x0004,
	VNIC_FEAT_IPV4_CSUM_TX		= 0x0008,
	VNIC_FEAT_TCP_CSUM_RX		= 0x0010,
	VNIC_FEAT_TCP_CSUM_TX		= 0x0020,
	VNIC_FEAT_UDP_CSUM_RX		= 0x0040,
	VNIC_FEAT_UDP_CSUM_TX		= 0x0080,
	VNIC_FEAT_TCP_SEGMENT		= 0x0100,
	VNIC_FEAT_IPV4_IPSEC_OFFLOAD	= 0x0200,
	VNIC_FEAT_IPV6_IPSEC_OFFLOAD	= 0x0400,
	VNIC_FEAT_FCS_PROPAGATE		= 0x0800,
	VNIC_FEAT_PF_KICK		= 0x1000,
	VNIC_FEAT_PF_FORCE_ROUTE	= 0x2000,
	VNIC_FEAT_CHASH_OFFLOAD		= 0x4000
};

/* pkt_cmd CMD_CONFIG_DATA_PATH subdata format */
struct vnic_recv_pool_config {
	__be32	size_recv_pool_entry;
	__be32	num_recv_pool_entries;
	__be32	timeout_before_kick;
	__be32	num_recv_pool_entries_before_kick;
	__be32	num_recv_pool_bytes_before_kick;
	__be32	free_recv_pool_entries_per_update;
};

/* pkt_cmd CMD_CONFIG_DATA_PATH data format */
struct vnic_cmd_config_data_path {
	u64				path_identifier;
	u8				data_path;
	u8				reserved[3];
	struct vnic_recv_pool_config	host_recv_pool_config;
	struct vnic_recv_pool_config	eioc_recv_pool_config;
};

/* pkt_cmd CMD_EXCHANGE_POOLS data format */
struct vnic_cmd_exchange_pools {
	u8	data_path;
	u8	reserved[3];
	__be32	pool_rkey;
	__be64	pool_addr;
};

/* pkt_cmd CMD_CONFIG_ADDRESSES subdata format */
struct vnic_address_op {
	__be16	index;
	u8	operation;
	u8	valid;
	u8	address[6];
	__be16	vlan;
};

/* operation values */
enum {
	VNIC_OP_SET_ENTRY = 0x01,
	VNIC_OP_GET_ENTRY = 0x02
};

/* pkt_cmd CMD_CONFIG_ADDRESSES data format */
struct vnic_cmd_config_addresses {
	u8			num_address_ops;
	u8			lan_switch_num;
	struct vnic_address_op	list_address_ops[1];
};

/* CMD_CONFIG_LINK data format */
struct vnic_cmd_config_link {
	u8	cmd_flags;
	u8	lan_switch_num;
	__be16	mtu_size;
	__be16	default_vlan;
	u8	hw_mac_address[6];
};

/* cmd_flags values */
enum {
	VNIC_FLAG_ENABLE_NIC		= 0x01,
	VNIC_FLAG_DISABLE_NIC		= 0x02,
	VNIC_FLAG_ENABLE_MCAST_ALL	= 0x04,
	VNIC_FLAG_DISABLE_MCAST_ALL	= 0x08,
	VNIC_FLAG_ENABLE_PROMISC	= 0x10,
	VNIC_FLAG_DISABLE_PROMISC	= 0x20,
	VNIC_FLAG_SET_MTU		= 0x40
};

/* pkt_cmd CMD_REPORT_STATISTICS, pkt_type TYPE_REQ data format */
struct vnic_cmd_report_stats_req {
	u8	lan_switch_num;
};

/* pkt_cmd CMD_REPORT_STATISTICS, pkt_type TYPE_RSP data format */
struct vnic_cmd_report_stats_rsp {
	u8	lan_switch_num;
	u8	reserved[7];		/* for 64-bit alignment */
	__be64	if_in_broadcast_pkts;
	__be64	if_in_multicast_pkts;
	__be64	if_in_octets;
	__be64	if_in_ucast_pkts;
	__be64	if_in_nucast_pkts;	/* if_in_broadcast_pkts
					 + if_in_multicast_pkts */
	__be64	if_in_underrun;		/* (OID_GEN_RCV_NO_BUFFER) */
	__be64	if_in_errors;		/* (OID_GEN_RCV_ERROR) */
	__be64	if_out_errors;		/* (OID_GEN_XMIT_ERROR) */
	__be64	if_out_octets;
	__be64	if_out_ucast_pkts;
	__be64	if_out_multicast_pkts;
	__be64	if_out_broadcast_pkts;
	__be64	if_out_nucast_pkts;	/* if_out_broadcast_pkts
					 + if_out_multicast_pkts */
	__be64	if_out_ok;		/* if_out_nucast_pkts
					 + if_out_ucast_pkts(OID_GEN_XMIT_OK) */
	__be64	if_in_ok;		/* if_in_nucast_pkts
					 + if_in_ucast_pkts(OID_GEN_RCV_OK) */
	__be64	if_out_ucast_bytes;	/* (OID_GEN_DIRECTED_BYTES_XMT) */
	__be64	if_out_multicast_bytes;	/* (OID_GEN_MULTICAST_BYTES_XMT) */
	__be64	if_out_broadcast_bytes;	/* (OID_GEN_BROADCAST_BYTES_XMT) */
	__be64	if_in_ucast_bytes;	/* (OID_GEN_DIRECTED_BYTES_RCV) */
	__be64	if_in_multicast_bytes;	/* (OID_GEN_MULTICAST_BYTES_RCV) */
	__be64	if_in_broadcast_bytes;	/* (OID_GEN_BROADCAST_BYTES_RCV) */
	__be64	 ethernet_status;	/* OID_GEN_MEDIA_CONNECT_STATUS) */
};

/* pkt_cmd CMD_CLEAR_STATISTICS data format */
struct vnic_cmd_clear_statistics {
	u8	lan_switch_num;
};

/* pkt_cmd CMD_REPORT_STATUS data format */
struct vnic_cmd_report_status {
	u8	lan_switch_num;
	u8	is_fatal;
	u8	reserved[2];		/* for 32-bit alignment */
	__be32	status_number;
	__be32	status_info;
	u8	file_name[32];
	u8	routine[32];
	__be32	line_num;
	__be32	error_parameter;
	u8	desc_text[128];
};

/* pkt_cmd CMD_HEARTBEAT data format */
struct vnic_cmd_heartbeat {
	__be32	hb_interval;
};

enum {
	VNIC_STATUS_LINK_UP			= 1,
	VNIC_STATUS_LINK_DOWN			= 2,
	VNIC_STATUS_ENET_AGGREGATION_CHANGE	= 3,
	VNIC_STATUS_EIOC_SHUTDOWN		= 4,
	VNIC_STATUS_CONTROL_ERROR		= 5,
	VNIC_STATUS_EIOC_ERROR			= 6
};

#define VNIC_MAX_CONTROLPKTSZ		256
#define VNIC_MAX_CONTROLDATASZ						\
	(VNIC_MAX_CONTROLPKTSZ - sizeof(struct vnic_control_header))

struct vnic_control_packet {
	struct vnic_control_header	hdr;
	union {
		struct vnic_cmd_init_vnic_req		init_vnic_req;
		struct vnic_cmd_init_vnic_rsp		init_vnic_rsp;
		struct vnic_cmd_config_data_path	config_data_path_req;
		struct vnic_cmd_config_data_path	config_data_path_rsp;
		struct vnic_cmd_exchange_pools		exchange_pools_req;
		struct vnic_cmd_exchange_pools		exchange_pools_rsp;
		struct vnic_cmd_config_addresses	config_addresses_req;
		struct vnic_cmd_config_addresses	config_addresses_rsp;
		struct vnic_cmd_config_link		config_link_req;
		struct vnic_cmd_config_link		config_link_rsp;
		struct vnic_cmd_report_stats_req	report_statistics_req;
		struct vnic_cmd_report_stats_rsp	report_statistics_rsp;
		struct vnic_cmd_clear_statistics	clear_statistics_req;
		struct vnic_cmd_clear_statistics	clear_statistics_rsp;
		struct vnic_cmd_report_status		report_status;
		struct vnic_cmd_heartbeat		heartbeat_req;
		struct vnic_cmd_heartbeat		heartbeat_rsp;

		char   cmd_data[VNIC_MAX_CONTROLDATASZ];
	} cmd;
};

#endif	/* VNIC_CONTROL_PKT_H_INCLUDED */
