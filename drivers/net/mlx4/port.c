/*
 * Copyright (c) 2007 Mellanox Technologies. All rights reserved.
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
 *
 */

#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

#include <linux/mlx4/cmd.h>

#include "mlx4.h"
#include "en_port.h"

int mlx4_ib_set_4k_mtu = 0;
module_param_named(set_4k_mtu, mlx4_ib_set_4k_mtu, int, 0444);
MODULE_PARM_DESC(set_4k_mtu, "attempt to set 4K MTU to all ConnectX ports");

#define MLX4_MAC_VALID		(1ull << 63)
#define MLX4_MAC_MASK		0x7fffffffffffffffULL

#define MLX4_VLAN_VALID		(1u << 31)
#define MLX4_VLAN_MASK		0xfff

void mlx4_init_mac_table(struct mlx4_dev *dev, struct mlx4_mac_table *table)
{
	int i;

	mutex_init(&table->mutex);
	for (i = 0; i < MLX4_MAX_MAC_NUM; i++)
		table->entries[i] = 0;
	table->max   = 1 << dev->caps.log_num_macs;
	table->total = 0;
}

void mlx4_init_vlan_table(struct mlx4_dev *dev, struct mlx4_vlan_table *table)
{
	int i;

	sema_init(&table->vlan_sem, 1);
	for (i = 0; i < MLX4_MAX_VLAN_NUM; i++) {
		table->entries[i] = 0;
		table->refs[i] = 0;
	}
	table->max = 1 << dev->caps.log_num_vlans;
	table->total = 0;
}

static int mlx4_set_port_mac_table(struct mlx4_dev *dev, u8 port,
				   __be64 *entries)
{
	struct mlx4_cmd_mailbox *mailbox;
	u32 in_mod;
	int err;

	mailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	memcpy(mailbox->buf, entries, MLX4_MAC_TABLE_SIZE);

	in_mod = MLX4_SET_PORT_MAC_TABLE << 8 | port;
	err = mlx4_cmd(dev, mailbox->dma, in_mod, 1, MLX4_CMD_SET_PORT,
		       MLX4_CMD_TIME_CLASS_B);

	mlx4_free_cmd_mailbox(dev, mailbox);
	return err;
}

int mlx4_register_mac(struct mlx4_dev *dev, u8 port, u64 mac, int *qpn)
{
	struct mlx4_port_info *info = &mlx4_priv(dev)->port[port];
	struct mlx4_mac_table *table = &info->mac_table;
	u64 out_param;
	int i, err = 0;
	int free = -1;

	if (mlx4_is_slave(dev)) {
		err = mlx4_cmd_imm(dev, mac, &out_param, RES_MAC, port,
				   MLX4_CMD_ALLOC_RES, MLX4_CMD_TIME_CLASS_A);
		if (!err)
			*qpn = out_param;
		return err;
	} else
		mac |= (u64) (dev->caps.function) << 48;

	mlx4_dbg(dev, "Registering MAC: 0x%llx\n", (unsigned long long) mac);
	mutex_lock(&table->mutex);
	for (i = 0; i < MLX4_MAX_MAC_NUM; i++) {
		if (free < 0 && !table->entries[i]) {
			free = i;
			continue;
		}

		if (mac == (MLX4_MAC_MASK & be64_to_cpu(table->entries[i]))) {
			/* MAC + PF already registered, Must not have duplicates */
			err = -EEXIST;
			goto out;
		}
	}
	mlx4_dbg(dev, "Free MAC index is %d\n", free);

	if (table->total == table->max) {
		/* No free mac entries */
		err = -ENOSPC;
		goto out;
	}

	/* Register new MAC */
	table->entries[free] = cpu_to_be64(mac | MLX4_MAC_VALID);

	err = mlx4_set_port_mac_table(dev, port, table->entries);
	if (unlikely(err)) {
		mlx4_err(dev, "Failed adding MAC: 0x%llx\n", (unsigned long long) mac);
		table->entries[free] = 0;
		goto out;
	}

	*qpn = info->base_qpn + free;
	++table->total;
out:
	mutex_unlock(&table->mutex);
	return err;
}
EXPORT_SYMBOL_GPL(mlx4_register_mac);

static int validate_index(struct mlx4_dev *dev,
			  struct mlx4_mac_table *table, int index)
{
	int err = 0;

	if (index < 0 || index >= table->max || !table->entries[index]) {
		mlx4_warn(dev, "No valid Mac entry for the given index\n");
		err = -EINVAL;
	}
	return err;
}

void mlx4_unregister_mac(struct mlx4_dev *dev, u8 port, int qpn)
{
	struct mlx4_port_info *info = &mlx4_priv(dev)->port[port];
	struct mlx4_mac_table *table = &info->mac_table;
	int index = qpn - info->base_qpn;

	if (mlx4_is_slave(dev)) {
		mlx4_cmd(dev, qpn, RES_MAC, port,
			 MLX4_CMD_FREE_RES, MLX4_CMD_TIME_CLASS_A);
		return;
	}

	mutex_lock(&table->mutex);

	if (validate_index(dev, table, index))
		goto out;

	table->entries[index] = 0;
	mlx4_set_port_mac_table(dev, port, table->entries);
	--table->total;
out:
	mutex_unlock(&table->mutex);
}
EXPORT_SYMBOL_GPL(mlx4_unregister_mac);

int mlx4_replace_mac(struct mlx4_dev *dev, u8 port, int qpn, u64 new_mac)
{
	struct mlx4_port_info *info = &mlx4_priv(dev)->port[port];
	struct mlx4_mac_table *table = &info->mac_table;
	int index = qpn - info->base_qpn;
	int err;

	if (mlx4_is_slave(dev)) {
		err = mlx4_cmd_imm(dev, new_mac, (u64 *) &qpn, RES_MAC, port,
				   MLX4_CMD_REPLACE_RES, MLX4_CMD_TIME_CLASS_A);
		return err;
	}

	mutex_lock(&table->mutex);

	err = validate_index(dev, table, index);
	if (err)
		goto out;

	table->entries[index] = cpu_to_be64(new_mac | MLX4_MAC_VALID);

	err = mlx4_set_port_mac_table(dev, port, table->entries);
	if (unlikely(err)) {
		mlx4_err(dev, "Failed adding MAC: 0x%llx\n", (unsigned long long) new_mac);
		table->entries[index] = 0;
	}
out:
	mutex_unlock(&table->mutex);
	return err;
}
EXPORT_SYMBOL_GPL(mlx4_replace_mac);

static int mlx4_set_port_vlan_table(struct mlx4_dev *dev, u8 port,
				    __be32 *entries)
{
	struct mlx4_cmd_mailbox *mailbox;
	u32 in_mod;
	int err;

	mailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	memcpy(mailbox->buf, entries, MLX4_VLAN_TABLE_SIZE);
	in_mod = MLX4_SET_PORT_VLAN_TABLE << 8 | port;
	err = mlx4_cmd(dev, mailbox->dma, in_mod, 1, MLX4_CMD_SET_PORT,
		       MLX4_CMD_TIME_CLASS_B);

	mlx4_free_cmd_mailbox(dev, mailbox);

	return err;
}

int mlx4_register_vlan(struct mlx4_dev *dev, u8 port, u16 vlan, int *index)
{
	struct mlx4_vlan_table *table = &mlx4_priv(dev)->port[port].vlan_table;
	int i, err = 0;
	int free = -1;

	down(&table->vlan_sem);
	for (i = MLX4_VLAN_REGULAR; i < MLX4_MAX_VLAN_NUM; i++) {
		if (free < 0 && (table->refs[i] == 0)) {
			free = i;
			continue;
		}

		if (table->refs[i] &&
		    (vlan == (MLX4_VLAN_MASK &
			      be32_to_cpu(table->entries[i])))) {
			/* Vlan already registered, increase refernce count */
			*index = i;
			++table->refs[i];
			goto out;
		}
	}

	if (table->total == table->max) {
		/* No free vlan entries */
		err = -ENOSPC;
		goto out;
	}

	/* Register new MAC */
	table->refs[free] = 1;
	table->entries[free] = cpu_to_be32(vlan | MLX4_VLAN_VALID);

	err = mlx4_set_port_vlan_table(dev, port, table->entries);
	if (unlikely(err)) {
		mlx4_warn(dev, "Failed adding vlan: %u\n", vlan);
		table->refs[free] = 0;
		table->entries[free] = 0;
		goto out;
	}

	*index = free;
	++table->total;
out:
	up(&table->vlan_sem);
	return err;
}
EXPORT_SYMBOL_GPL(mlx4_register_vlan);

void mlx4_unregister_vlan(struct mlx4_dev *dev, u8 port, int index)
{
	struct mlx4_vlan_table *table = &mlx4_priv(dev)->port[port].vlan_table;

	if (index < MLX4_VLAN_REGULAR) {
		mlx4_warn(dev, "Trying to free special vlan index %d\n", index);
		return;
	}

	down(&table->vlan_sem);
	if (!table->refs[index]) {
		mlx4_warn(dev, "No vlan entry for index %d\n", index);
		goto out;
	}
	if (--table->refs[index]) {
		mlx4_dbg(dev, "Have more references for index %d,"
			 "no need to modify vlan table\n", index);
		goto out;
	}
	table->entries[index] = 0;
	mlx4_set_port_vlan_table(dev, port, table->entries);
	--table->total;
out:
	up(&table->vlan_sem);
}
EXPORT_SYMBOL_GPL(mlx4_unregister_vlan);

int mlx4_get_port_ib_caps(struct mlx4_dev *dev, u8 port, __be32 *caps)
{
	struct mlx4_cmd_mailbox *inmailbox, *outmailbox;
	u8 *inbuf, *outbuf;
	int err;

	inmailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(inmailbox))
		return PTR_ERR(inmailbox);

	outmailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(outmailbox)) {
		mlx4_free_cmd_mailbox(dev, inmailbox);
		return PTR_ERR(outmailbox);
	}

	inbuf = inmailbox->buf;
	outbuf = outmailbox->buf;
	memset(inbuf, 0, 256);
	memset(outbuf, 0, 256);
	inbuf[0] = 1;
	inbuf[1] = 1;
	inbuf[2] = 1;
	inbuf[3] = 1;
	*(__be16 *) (&inbuf[16]) = cpu_to_be16(0x0015);
	*(__be32 *) (&inbuf[20]) = cpu_to_be32(port);

	err = mlx4_cmd_box(dev, inmailbox->dma, outmailbox->dma, port, 3,
			   MLX4_CMD_MAD_IFC, MLX4_CMD_TIME_CLASS_C);
	if (!err)
		*caps = *(__be32 *) (outbuf + 84);
	mlx4_free_cmd_mailbox(dev, inmailbox);
	mlx4_free_cmd_mailbox(dev, outmailbox);
	return err;
}

static int mlx4_common_set_port(struct mlx4_dev *dev, int slave, u32 in_mod,
				u8 op_mod, struct mlx4_cmd_mailbox *inbox)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_port_info *port_info;
	struct mlx4_mfunc_master_ctx *master = &priv->mfunc.master;
	struct mlx4_slave_state *slave_st = &master->slave_state[slave];
	struct mlx4_set_port_rqp_calc_context *qpn_context;
	struct mlx4_set_port_general_context *gen_context;
	int reset_qkey_viols;
	int port;
	int is_eth;
	u32 in_modifier;
	u32 promisc;
	u16 mtu, prev_mtu;
	int err;
	int i;
	__be32 agg_cap_mask;
	__be32 slave_cap_mask;
	__be32 new_cap_mask;

	port = in_mod & 0xff;
	in_modifier = in_mod >> 8;
	is_eth = op_mod;
	port_info = &priv->port[port];

	/* All slaves can perform SET_PORT operations, just need to verify
	 * we keep the mutual resources unchanged */
	if (is_eth) {
		switch (in_modifier) {
		case MLX4_SET_PORT_RQP_CALC:
			qpn_context = inbox->buf;
			qpn_context->base_qpn = cpu_to_be32(port_info->base_qpn);
			qpn_context->n_mac = 0x7;
			promisc = be32_to_cpu(qpn_context->promisc) >>
				SET_PORT_PROMISC_SHIFT;
			qpn_context->promisc = cpu_to_be32(
				promisc << SET_PORT_PROMISC_SHIFT |
				port_info->base_qpn);
			promisc = be32_to_cpu(qpn_context->mcast) >>
				SET_PORT_MC_PROMISC_SHIFT;
			qpn_context->mcast = cpu_to_be32(
				promisc << SET_PORT_MC_PROMISC_SHIFT |
				port_info->base_qpn);
			break;
		case MLX4_SET_PORT_GENERAL:
			gen_context = inbox->buf;
			/* Mtu is configured as the max MTU among all the
			 * the functions on the port. */
			mtu = be16_to_cpu(gen_context->mtu);
			mtu = min_t(int, mtu, dev->caps.eth_mtu_cap[port]);
			prev_mtu = slave_st->mtu[port];
			slave_st->mtu[port] = mtu;
			if (mtu > master->max_mtu[port])
				master->max_mtu[port] = mtu;
			if (mtu < prev_mtu && prev_mtu == master->max_mtu[port]) {
				slave_st->mtu[port] = mtu;
				master->max_mtu[port] = mtu;
				for (i = 0; i < dev->num_slaves; i++) {
					master->max_mtu[port] =
						max(master->max_mtu[port],
						    master->slave_state[i].mtu[port]);
				}
			}

			gen_context->mtu = cpu_to_be16(master->max_mtu[port]);
			break;
		}
		return mlx4_cmd(dev, inbox->dma, in_mod, op_mod,
				MLX4_CMD_SET_PORT, MLX4_CMD_TIME_CLASS_B);
	}

	/* For IB, we only consider:
	 * - The capability mask, which is set to the aggregate of all slave frunction
	 *   capabilities
	 * - The QKey violatin counter - reset according to each request.
	 */

	if (dev->flags & MLX4_FLAG_OLD_PORT_CMDS) {
		reset_qkey_viols = (*(u8 *) inbox->buf) & 0x40;
		new_cap_mask = ((__be32 *) inbox->buf)[2];
	} else {
		reset_qkey_viols = ((u8 *) inbox->buf)[3] & 0x1;
		new_cap_mask = ((__be32 *) inbox->buf)[1];
	}

	/* only master has access to qp0 */
	if (new_cap_mask & cpu_to_be32(IB_PORT_SM) &&
	    slave != dev->caps.function) {
		mlx4_warn(dev, "denying sm port capability for slave:%d\n", slave);
		return -EINVAL;
	}

	agg_cap_mask = 0;
	slave_cap_mask = priv->mfunc.master.slave_state[slave].ib_cap_mask[port];
	priv->mfunc.master.slave_state[slave].ib_cap_mask[port] = new_cap_mask;
	for (i = 0; i < dev->num_slaves; i++)
		agg_cap_mask |= priv->mfunc.master.slave_state[slave].ib_cap_mask[port];

#if 0
	mlx4_warn(dev, "old_slave_cap:0x%x slave_cap:0x%x cap:0x%x qkey_reset:%d\n",
			slave_cap_mask, priv->mfunc.master.slave_state[slave].ib_cap_mask[port],
			agg_cap_mask, reset_qkey_viols);
#endif

	memset(inbox->buf, 0, 256);
	if (dev->flags & MLX4_FLAG_OLD_PORT_CMDS) {
		*(u8 *) inbox->buf	   = !!reset_qkey_viols << 6;
		((__be32 *) inbox->buf)[2] = agg_cap_mask;
	} else {
		((u8 *) inbox->buf)[3]     = !!reset_qkey_viols;
		((__be32 *) inbox->buf)[1] = agg_cap_mask;
	}

	err = mlx4_cmd(dev, inbox->dma, port, is_eth, MLX4_CMD_SET_PORT,
		       MLX4_CMD_TIME_CLASS_B);
	if (err)
		priv->mfunc.master.slave_state[slave].ib_cap_mask[port] = slave_cap_mask;
	return err;
}

int mlx4_SET_PORT_wrapper(struct mlx4_dev *dev, int slave,
			  struct mlx4_vhcr *vhcr,
			  struct mlx4_cmd_mailbox *inbox,
			  struct mlx4_cmd_mailbox *outbox)
{
	return mlx4_common_set_port(dev, slave, vhcr->in_modifier,
				    vhcr->op_modifier, inbox);
}


int mlx4_SET_PORT(struct mlx4_dev *dev, u8 port)
{
	struct mlx4_cmd_mailbox *mailbox;
	int err;

	if (dev->caps.port_type[port] == MLX4_PORT_TYPE_ETH)
		return 0;

	mailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	memset(mailbox->buf, 0, 256);

	if (mlx4_ib_set_4k_mtu)
		((__be32 *) mailbox->buf)[0] |= cpu_to_be32((1 << 22) | (1 << 21) | (5 << 12) | (2 << 4));

	((__be32 *) mailbox->buf)[1] = dev->caps.ib_port_def_cap[port];

	if (mlx4_is_master(dev))
		err = mlx4_common_set_port(dev, dev->caps.function, port, 0, mailbox);
	else
		err = mlx4_cmd(dev, mailbox->dma, port, 0, MLX4_CMD_SET_PORT,
			       MLX4_CMD_TIME_CLASS_B);

	mlx4_free_cmd_mailbox(dev, mailbox);
	return err;
}


int mlx4_SET_PORT_general(struct mlx4_dev *dev, u8 port, int mtu,
			  u8 pptx, u8 pfctx, u8 pprx, u8 pfcrx)
{
	struct mlx4_cmd_mailbox *mailbox;
	struct mlx4_set_port_general_context *context;
	int err;
	u32 in_mod;

	mailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);
	context = mailbox->buf;
	memset(context, 0, sizeof *context);

	context->flags = SET_PORT_GEN_ALL_VALID;
	context->mtu = cpu_to_be16(mtu);
	context->pptx = (pptx * (!pfctx)) << 7;
	context->pfctx = pfctx;
	context->pprx = (pprx * (!pfcrx)) << 7;
	context->pfcrx = pfcrx;

	in_mod = MLX4_SET_PORT_GENERAL << 8 | port;
	if (mlx4_is_master(dev))
		err = mlx4_common_set_port(dev, dev->caps.function, in_mod, 1, mailbox);
	else
		err = mlx4_cmd(dev, mailbox->dma, in_mod, 1, MLX4_CMD_SET_PORT,
			       MLX4_CMD_TIME_CLASS_B);

	mlx4_free_cmd_mailbox(dev, mailbox);
	return err;
}
EXPORT_SYMBOL(mlx4_SET_PORT_general);

int mlx4_SET_PORT_qpn_calc(struct mlx4_dev *dev, u8 port, u32 base_qpn,
			   u8 promisc)
{
	struct mlx4_cmd_mailbox *mailbox;
	struct mlx4_set_port_rqp_calc_context *context;
	int err;
	u32 in_mod;

	mailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);
	context = mailbox->buf;
	memset(context, 0, sizeof *context);

	context->base_qpn = cpu_to_be32(base_qpn);
	context->n_mac = 0x7;
	context->promisc = cpu_to_be32(promisc << SET_PORT_PROMISC_SHIFT |
				       base_qpn);
	context->mcast = cpu_to_be32(MCAST_DIRECT << SET_PORT_MC_PROMISC_SHIFT |
				     base_qpn);
	context->intra_no_vlan = 0;
	context->no_vlan = MLX4_NO_VLAN_IDX;
	context->intra_vlan_miss = 0;
	context->vlan_miss = MLX4_VLAN_MISS_IDX;

	in_mod = MLX4_SET_PORT_RQP_CALC << 8 | port;
	if (mlx4_is_master(dev))
		err = mlx4_common_set_port(dev, dev->caps.function, in_mod, 1, mailbox);
	else
		err = mlx4_cmd(dev, mailbox->dma, in_mod, 1, MLX4_CMD_SET_PORT,
			       MLX4_CMD_TIME_CLASS_B);

	mlx4_free_cmd_mailbox(dev, mailbox);
	return err;
}
EXPORT_SYMBOL(mlx4_SET_PORT_qpn_calc);

static int mlx4_common_set_mcast_fltr(struct mlx4_dev *dev, int function,
				      int port, u64 addr, u64 clear, u8 mode)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int err = 0;
	struct mlx4_mcast_entry *entry, *tmp;
	struct mlx4_slave_state *s_state = &priv->mfunc.master.slave_state[function];
	int i;

	switch (mode) {
	case MLX4_MCAST_DISABLE:
		/* The multicast filter is disabled only once,
		 * If some other function already done it, operation
		 * is ignored */
		if (!(priv->mfunc.master.disable_mcast_ref[port]++))
			err = mlx4_cmd(dev, 0, port, MLX4_MCAST_DISABLE,
					MLX4_CMD_SET_MCAST_FLTR,
					MLX4_CMD_TIME_CLASS_B);
		break;
	case MLX4_MCAST_ENABLE:
		/* We enable the muticast filter only if all functions
		 * have the filter enabled */
		if (!(--priv->mfunc.master.disable_mcast_ref[port]))
			err = mlx4_cmd(dev, 0, port, MLX4_MCAST_ENABLE,
					MLX4_CMD_SET_MCAST_FLTR,
					MLX4_CMD_TIME_CLASS_B);
		break;
	case MLX4_MCAST_CONFIG:
		if (clear) {
			/* Disable the muticast filter while updating it */
			if (!priv->mfunc.master.disable_mcast_ref[port]) {
				err = mlx4_cmd(dev, 0, port, MLX4_MCAST_DISABLE,
						MLX4_CMD_SET_MCAST_FLTR,
						MLX4_CMD_TIME_CLASS_B);
				if (err) {
					mlx4_warn(dev, "Failed to disable multicast "
						       "filter\n");
					goto out;
				}
			}
			/* Clear the multicast filter */
			err = mlx4_cmd(dev, clear << 63, port,
				       MLX4_MCAST_CONFIG,
				       MLX4_CMD_SET_MCAST_FLTR,
				       MLX4_CMD_TIME_CLASS_B);
			if (err) {
				mlx4_warn(dev, "Failed clearing the multicast filter\n");
				goto out;
			}

			/* Clear the multicast addresses for the given slave */
			list_for_each_entry_safe(entry, tmp,
						 &s_state->mcast_filters[port],
						 list) {
				list_del(&entry->list);
				kfree(entry);
			}

			/* Assign all the multicast addresses that still exist */
			for (i = 0; i < dev->num_slaves; i++) {
				list_for_each_entry(entry,
					&priv->mfunc.master.slave_state[function].mcast_filters[port],
					list) {
					if (mlx4_cmd(dev, entry->addr, port,
						     MLX4_MCAST_CONFIG,
						     MLX4_CMD_SET_MCAST_FLTR,
						     MLX4_CMD_TIME_CLASS_B))
						mlx4_warn(dev, "Failed to reconfigure "
							  "multicast address: 0x%llx\n",
							  entry->addr);
				}
			}
			/* Enable the filter */
			if (!priv->mfunc.master.disable_mcast_ref[port]) {
				err = mlx4_cmd(dev, 0, port, MLX4_MCAST_ENABLE,
						MLX4_CMD_SET_MCAST_FLTR,
						MLX4_CMD_TIME_CLASS_B);
				if (err) {
					mlx4_warn(dev, "Failed to enable multicast "
						       "filter\n");
					goto out;
				}
			}
		}
		/* Add the new address if exists */
		if (addr) {
			entry = kzalloc(sizeof (struct mlx4_mcast_entry),
					GFP_KERNEL);
			if (!entry) {
				mlx4_warn(dev, "Failed to allocate entry for "
					       "muticast address\n");
				err = -ENOMEM;
				goto out;
			}
			INIT_LIST_HEAD(&entry->list);
			entry->addr = addr;
			list_add_tail(&entry->list, &s_state->mcast_filters[port]);
			err = mlx4_cmd(dev, addr, port, MLX4_MCAST_CONFIG,
				       MLX4_CMD_SET_MCAST_FLTR,
				       MLX4_CMD_TIME_CLASS_B);
			if (err)
				mlx4_warn(dev, "Failed to add the new address:"
					       "0x%llx\n", addr);
		}
		break;
	default:
		mlx4_warn(dev, "SET_MCAST_FILTER called with illegal modifier\n");
		err = -EINVAL;
	}
out:
	return err;
}

int mlx4_SET_MCAST_FLTR_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
				struct mlx4_cmd_mailbox *inbox,
				struct mlx4_cmd_mailbox *outbox)
{
	int port = vhcr->in_modifier;
	u64 addr = vhcr->in_param & 0xffffffffffffULL;
	u64 clear = vhcr->in_param >> 63;
	u8 mode = vhcr->op_modifier;

	return mlx4_common_set_mcast_fltr(dev, slave, port, addr, clear, mode);
}

int mlx4_SET_MCAST_FLTR(struct mlx4_dev *dev, u8 port,
			u64 mac, u64 clear, u8 mode)
{
	if (mlx4_is_master(dev))
		return mlx4_common_set_mcast_fltr(dev, dev->caps.function,
						  port, mac, clear, mode);
	else
		return mlx4_cmd(dev, (mac | (clear << 63)), port, mode,
				MLX4_CMD_SET_MCAST_FLTR, MLX4_CMD_TIME_CLASS_B);
}
EXPORT_SYMBOL(mlx4_SET_MCAST_FLTR);


static int mlx4_common_set_vlan_fltr(struct mlx4_dev *dev, int function,
				     int port, void *buf)
{
	struct mlx4_cmd_mailbox *mailbox;
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_vlan_fltr *filter;
	struct mlx4_slave_state *s_state = &priv->mfunc.master.slave_state[function];
	int i, j, err;

	mailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	/* Update slave's Vlan filter */
	memcpy(s_state->vlan_filter[port]->entry, buf,
	       sizeof(struct mlx4_vlan_fltr));

	/* We configure the Vlan filter to allow the vlans of
	 * all slaves */
	filter = mailbox->buf;
	memset(filter, 0, sizeof(*filter));
	for (i = VLAN_FLTR_SIZE - 1; i >= 0; i--) {
		for (j = 0; j < dev->num_slaves; j++) {
			s_state = &priv->mfunc.master.slave_state[j];
			filter->entry[i] |= s_state->vlan_filter[port]->entry[i];
		}
	}
	err = mlx4_cmd(dev, mailbox->dma, port, 0, MLX4_CMD_SET_VLAN_FLTR,
		       MLX4_CMD_TIME_CLASS_B);
	mlx4_free_cmd_mailbox(dev, mailbox);
	return err;
}

int mlx4_SET_VLAN_FLTR_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
			       struct mlx4_cmd_mailbox *inbox,
			       struct mlx4_cmd_mailbox *outbox)
{
	return mlx4_common_set_vlan_fltr(dev, slave, vhcr->in_modifier,
					 inbox->buf);
}


int mlx4_SET_VLAN_FLTR(struct mlx4_dev *dev, u8 port, struct vlan_group *grp)
{
	struct mlx4_cmd_mailbox *mailbox;
	struct mlx4_vlan_fltr *filter;
	int i;
	int j;
	int index = 0;
	u32 entry;
	int err = 0;

	mailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	filter = mailbox->buf;
	if (grp) {
		memset(filter, 0, sizeof *filter);
		for (i = VLAN_FLTR_SIZE - 1; i >= 0; i--) {
			entry = 0;
			for (j = 0; j < 32; j++)
				if (vlan_group_get_device(grp, index++))
					entry |= 1 << j;
			filter->entry[i] = cpu_to_be32(entry);
		}
	} else {
		/* When no vlans are configured we block all vlans */
		memset(filter, 0, sizeof(*filter));
	}
	if (mlx4_is_master(dev))
		err = mlx4_common_set_vlan_fltr(dev, dev->caps.function,
						port, mailbox->buf);
	else
		err = mlx4_cmd(dev, mailbox->dma, port, 0, MLX4_CMD_SET_VLAN_FLTR,
			       MLX4_CMD_TIME_CLASS_B);

	mlx4_free_cmd_mailbox(dev, mailbox);
	return err;
}
EXPORT_SYMBOL(mlx4_SET_VLAN_FLTR);
