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

#include <linux/parser.h>
#include <linux/netdevice.h>
#include <linux/if.h>

#include "vnic_util.h"
#include "vnic_config.h"
#include "vnic_ib.h"
#include "vnic_viport.h"
#include "vnic_main.h"
#include "vnic_stats.h"

extern struct list_head vnic_list;

/*
 * target eiocs are added by writing
 *
 * ioc_guid=<EIOC GUID>,dgid=<dest GID>,pkey=<P_key>,name=<interface_name>
 * to the create_primary  sysfs attribute.
 */
enum {
	VNIC_OPT_ERR = 0,
	VNIC_OPT_IOC_GUID = 1 << 0,
	VNIC_OPT_DGID = 1 << 1,
	VNIC_OPT_PKEY = 1 << 2,
	VNIC_OPT_NAME = 1 << 3,
	VNIC_OPT_INSTANCE = 1 << 4,
	VNIC_OPT_RXCSUM = 1 << 5,
	VNIC_OPT_TXCSUM = 1 << 6,
	VNIC_OPT_HEARTBEAT = 1 << 7,
	VNIC_OPT_ALL = (VNIC_OPT_IOC_GUID |
			VNIC_OPT_DGID | VNIC_OPT_NAME | VNIC_OPT_PKEY),
};

static match_table_t vnic_opt_tokens = {
	{VNIC_OPT_IOC_GUID, "ioc_guid=%s"},
	{VNIC_OPT_DGID, "dgid=%s"},
	{VNIC_OPT_PKEY, "pkey=%x"},
	{VNIC_OPT_NAME, "name=%s"},
	{VNIC_OPT_INSTANCE, "instance=%d"},
	{VNIC_OPT_RXCSUM, "rx_csum=%s"},
	{VNIC_OPT_TXCSUM, "tx_csum=%s"},
	{VNIC_OPT_HEARTBEAT, "heartbeat=%d"},
	{VNIC_OPT_ERR, NULL}
};

static void vnic_release_class_dev(struct class_device *class_dev)
{
	struct class_dev_info *cdev_info =
	    container_of(class_dev, struct class_dev_info, class_dev);

	complete(&cdev_info->released);

}

struct class vnic_class = {
	.name = "infiniband_vnic",
	.release = vnic_release_class_dev
};

struct class_dev_info interface_cdev;

static int vnic_parse_options(const char *buf, struct path_param *param)
{
	char *options, *sep_opt;
	char *p;
	char dgid[3];
	substring_t args[MAX_OPT_ARGS];
	int opt_mask = 0;
	int token;
	int ret = -EINVAL;
	int i;

	options = kstrdup(buf, GFP_KERNEL);
	if (!options)
		return -ENOMEM;

	sep_opt = options;
	while ((p = strsep(&sep_opt, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, vnic_opt_tokens, args);
		opt_mask |= token;

		switch (token) {
		case VNIC_OPT_IOC_GUID:
			p = match_strdup(args);
			param->ioc_guid = cpu_to_be64(simple_strtoull(p, NULL,
								      16));
			kfree(p);
			break;

		case VNIC_OPT_DGID:
			p = match_strdup(args);
			if (strlen(p) != 32) {
				printk(KERN_WARNING PFX
				       "bad dest GID parameter '%s'\n", p);
				kfree(p);
				goto out;
			}

			for (i = 0; i < 16; ++i) {
				strlcpy(dgid, p + i * 2, 3);
				param->dgid[i] = simple_strtoul(dgid, NULL,
								16);

			}
			kfree(p);
			break;

		case VNIC_OPT_PKEY:
			if (match_hex(args, &token)) {
				printk(KERN_WARNING PFX
				       "bad P_key parameter '%s'\n", p);
				goto out;
			}
			param->pkey = cpu_to_be16(token);
			break;

		case VNIC_OPT_NAME:
			p = match_strdup(args);
			if (strlen(p) >= IFNAMSIZ) {
				printk(KERN_WARNING PFX
				       "interface name parameter too long\n");
				kfree(p);
				goto out;
			}
			strcpy(param->name, p);
			kfree(p);
			break;
		case VNIC_OPT_INSTANCE:
			if (match_int(args, &token)) {
				printk(KERN_WARNING PFX
				       "bad instance parameter '%s'\n", p);
				goto out;
			}

			if (token > 255 || token < 0) {
				printk(KERN_WARNING PFX
				       "instance parameter must be"
				       " > 0 and <= 255\n");
				goto out;
			}

			param->instance = token;
			break;
		case VNIC_OPT_RXCSUM:
			p = match_strdup(args);
			if (!strncmp(p, "true", 4))
				param->rx_csum = 1;
			else if (!strncmp(p, "false", 5))
				param->rx_csum = 0;
			else {
				printk(KERN_WARNING PFX
				       "bad rx_csum parameter."
				       " must be 'true' or 'false'\n");
				kfree(p);
				goto out;
			}
			kfree(p);
			break;
		case VNIC_OPT_TXCSUM:
			p = match_strdup(args);
			if (!strncmp(p, "true", 4))
				param->tx_csum = 1;
			else if (!strncmp(p, "false", 5))
				param->tx_csum = 0;
			else {
				printk(KERN_WARNING PFX
				       "bad tx_csum parameter."
				       " must be 'true' or 'false'\n");
				kfree(p);
				goto out;
			}
			kfree(p);
			break;
		case VNIC_OPT_HEARTBEAT:
			if (match_int(args, &token)) {
				printk(KERN_WARNING PFX
				       "bad instance parameter '%s'\n", p);
				goto out;
			}

			if (token > 6000 || token < 0) {
				printk(KERN_WARNING PFX
				       "heartbeat parameter must be"
				       " > 0 and <= 6000\n");
				goto out;
			}
			param->heartbeat = token;
			break;
		default:
			printk(KERN_WARNING PFX
			       "unknown parameter or missing value "
			       "'%s' in target creation request\n", p);
			goto out;
		}

	}

	if ((opt_mask & VNIC_OPT_ALL) == VNIC_OPT_ALL)
		ret = 0;
	else
		for (i = 0; i < ARRAY_SIZE(vnic_opt_tokens); ++i)
			if ((vnic_opt_tokens[i].token & VNIC_OPT_ALL) &&
			    !(vnic_opt_tokens[i].token & opt_mask))
				printk(KERN_WARNING PFX
				       "target creation request is "
				       "missing parameter '%s'\n",
				       vnic_opt_tokens[i].pattern);

out:
	kfree(options);
	return ret;

}

static ssize_t show_vnic_state(struct class_device *class_dev, char *buf)
{
	struct class_dev_info *info =
	    container_of(class_dev, struct class_dev_info, class_dev);
	struct vnic *vnic = container_of(info, struct vnic, class_dev_info);
	switch (vnic->state) {
	case VNIC_UNINITIALIZED:
		return sprintf(buf, "VNIC_UNINITIALIZED\n");
	case VNIC_REGISTERED:
		return sprintf(buf, "VNIC_REGISTERED\n");
	default:
		return sprintf(buf, "INVALID STATE\n");
	}

}

static CLASS_DEVICE_ATTR(vnic_state, S_IRUGO, show_vnic_state, NULL);

static ssize_t show_rx_csum(struct class_device *class_dev, char *buf)
{
	struct class_dev_info *info =
	    container_of(class_dev, struct class_dev_info, class_dev);
	struct vnic *vnic = container_of(info, struct vnic, class_dev_info);

	if (vnic->config->use_rx_csum)
		return sprintf(buf, "true\n");
	else
		return sprintf(buf, "false\n");
}

static CLASS_DEVICE_ATTR(rx_csum, S_IRUGO, show_rx_csum, NULL);

static ssize_t show_tx_csum(struct class_device *class_dev, char *buf)
{
	struct class_dev_info *info =
	    container_of(class_dev, struct class_dev_info, class_dev);
	struct vnic *vnic = container_of(info, struct vnic, class_dev_info);

	if (vnic->config->use_tx_csum)
		return sprintf(buf, "true\n");
	else
		return sprintf(buf, "false\n");
}

static CLASS_DEVICE_ATTR(tx_csum, S_IRUGO, show_tx_csum, NULL);

static ssize_t show_current_path(struct class_device *class_dev, char *buf)
{
	struct class_dev_info *info =
	    container_of(class_dev, struct class_dev_info, class_dev);
	struct vnic *vnic = container_of(info, struct vnic, class_dev_info);

	if (vnic->current_path == &vnic->primary_path)
		return sprintf(buf, "primary path\n");
	else if (vnic->current_path == &vnic->secondary_path)
		return sprintf(buf, "secondary path\n");
	else
		return sprintf(buf, "none\n");

}

static CLASS_DEVICE_ATTR(current_path, S_IRUGO, show_current_path, NULL);

static struct attribute * vnic_dev_attrs[] = {
	&class_device_attr_vnic_state.attr,
	&class_device_attr_rx_csum.attr,
	&class_device_attr_tx_csum.attr,
	&class_device_attr_current_path.attr,
	NULL
};

struct attribute_group vnic_dev_attr_group = {
	.attrs = vnic_dev_attrs,
};

static int create_netpath(struct netpath *npdest,
			  struct path_param *p_params)
{
	struct viport_config	*viport_config;
	struct viport		*viport;
	struct vnic		*vnic;
	struct list_head	*ptr;
	int			ret = 0;

	list_for_each(ptr, &vnic_list) {
		vnic = list_entry(ptr, struct vnic, list_ptrs);
		if (vnic->primary_path.viport) {
			viport_config = vnic->primary_path.viport->config;
			if ((viport_config->ioc_guid == p_params->ioc_guid)
			    && (viport_config->control_config.vnic_instance
				== p_params->instance)) {
				SYS_ERROR("GUID %llx,"
					  " INSTANCE %d already in use\n",
					  be64_to_cpu(p_params->ioc_guid),
					  p_params->instance);
				ret = -EINVAL;
				goto out;
			}
		}

		if (vnic->secondary_path.viport) {
			viport_config = vnic->secondary_path.viport->config;
			if ((viport_config->ioc_guid == p_params->ioc_guid)
			    && (viport_config->control_config.vnic_instance
				== p_params->instance)) {
				SYS_ERROR("GUID %llx,"
					  " INSTANCE %d already in use\n",
					  be64_to_cpu(p_params->ioc_guid),
					  p_params->instance);
				ret = -EINVAL;
				goto out;
			}
		}
	}

	if (npdest->viport) {
		SYS_ERROR("create_netpath: path already exists\n");
		ret = -EINVAL;
		goto out;
	}

	viport_config = config_alloc_viport(p_params);
	if (!viport_config) {
		SYS_ERROR("create_netpath: failed creating viport config\n");
		ret = -1;
		goto out;
	}

	/*User specified heartbeat value is in 1/100s of a sec*/
	if (p_params->heartbeat != -1) {
		viport_config->hb_interval =
			msecs_to_jiffies(p_params->heartbeat * 10);
		viport_config->hb_timeout =
			(p_params->heartbeat << 6) * 10000; /* usec */
	}

	viport_config->path_idx = 0;

	viport = viport_allocate(viport_config);
	if (!viport) {
		SYS_ERROR("create_netpath: failed creating viport\n");
		kfree(viport_config);
		ret = -1;
		goto out;
	}

	npdest->viport = viport;
	viport->parent = npdest;
	viport->vnic = npdest->parent;
	viport_kick(viport);
	vnic_disconnected(npdest->parent, npdest);
out:
	return ret;
}

struct vnic *create_vnic(struct path_param *param)
{
	struct vnic_config *vnic_config;
	struct vnic *vnic;
	struct list_head *ptr;

	SYS_INFO("create_vnic: name = %s\n", param->name);
	list_for_each(ptr, &vnic_list) {
		vnic = list_entry(ptr, struct vnic, list_ptrs);
		if (!strcmp(vnic->config->name, param->name)) {
			SYS_ERROR("vnic %s already exists\n",
				   param->name);
			return NULL;
		}
	}

	vnic_config = config_alloc_vnic();
	if (!vnic_config) {
		SYS_ERROR("create_vnic: failed creating vnic config\n");
		return NULL;
	}

	if (param->rx_csum != -1)
		vnic_config->use_rx_csum = param->rx_csum;

	if (param->tx_csum != -1)
		vnic_config->use_tx_csum = param->tx_csum;

	strcpy(vnic_config->name, param->name);
	vnic = vnic_allocate(vnic_config);
	if (!vnic) {
		SYS_ERROR("create_vnic: failed allocating vnic\n");
		goto free_vnic_config;
	}

	init_completion(&vnic->class_dev_info.released);

	vnic->class_dev_info.class_dev.class = &vnic_class;
	vnic->class_dev_info.class_dev.parent = &interface_cdev.class_dev;
	snprintf(vnic->class_dev_info.class_dev.class_id, BUS_ID_SIZE,
		 vnic_config->name);

	if (class_device_register(&vnic->class_dev_info.class_dev)) {
		SYS_ERROR("create_vnic: error in registering"
			  " vnic class dev\n");
		goto free_vnic;
	}

	if (sysfs_create_group(&vnic->class_dev_info.class_dev.kobj,
			       &vnic_dev_attr_group)) {
		SYS_ERROR("create_vnic: error in creating"
			  "vnic attr group\n");
		goto err_attr;

	}

	if (vnic_setup_stats_files(vnic))
		goto err_stats;

	return vnic;
err_stats:
	sysfs_remove_group(&vnic->class_dev_info.class_dev.kobj,
			   &vnic_dev_attr_group);
err_attr:
	class_device_unregister(&vnic->class_dev_info.class_dev);
	wait_for_completion(&vnic->class_dev_info.released);
free_vnic:
	list_del(&vnic->list_ptrs);
	kfree(vnic);
free_vnic_config:
	kfree(vnic_config);
	return NULL;
}

ssize_t vnic_delete(struct class_device * class_dev,
		    const char *buf, size_t count)
{
	struct vnic *vnic;
	struct list_head *ptr;
	int ret = -EINVAL;

	if (count > IFNAMSIZ) {
		printk(KERN_WARNING PFX "invalid vnic interface name\n");
		return ret;
	}

	SYS_INFO("vnic_delete: name = %s\n", buf);
	list_for_each(ptr, &vnic_list) {
		vnic = list_entry(ptr, struct vnic, list_ptrs);
		if (!strcmp(vnic->config->name, buf)) {
			vnic_free(vnic);
			return count;
		}
	}

	printk(KERN_WARNING PFX "vnic interface '%s' does not exist\n", buf);
	return ret;
}

static ssize_t show_viport_state(struct class_device *class_dev, char *buf)
{
	struct class_dev_info *info =
	    container_of(class_dev, struct class_dev_info, class_dev);
	struct netpath *path =
	    container_of(info, struct netpath, class_dev_info);
	switch (path->viport->state) {
	case VIPORT_DISCONNECTED:
		return sprintf(buf, "VIPORT_DISCONNECTED\n");
	case VIPORT_CONNECTED:
		return sprintf(buf, "VIPORT_CONNECTED\n");
	default:
		return sprintf(buf, "INVALID STATE\n");
	}

}

static CLASS_DEVICE_ATTR(viport_state, S_IRUGO, show_viport_state, NULL);

static ssize_t show_link_state(struct class_device *class_dev, char *buf)
{
	struct class_dev_info *info =
	    container_of(class_dev, struct class_dev_info, class_dev);
	struct netpath *path =
	    container_of(info, struct netpath, class_dev_info);

	switch (path->viport->link_state) {
	case LINK_UNINITIALIZED:
		return sprintf(buf, "LINK_UNINITIALIZED\n");
	case LINK_INITIALIZE:
		return sprintf(buf, "LINK_INITIALIZE\n");
	case LINK_INITIALIZECONTROL:
		return sprintf(buf, "LINK_INITIALIZECONTROL\n");
	case LINK_INITIALIZEDATA:
		return sprintf(buf, "LINK_INITIALIZEDATA\n");
	case LINK_CONTROLCONNECT:
		return sprintf(buf, "LINK_CONTROLCONNECT\n");
	case LINK_CONTROLCONNECTWAIT:
		return sprintf(buf, "LINK_CONTROLCONNECTWAIT\n");
	case LINK_INITVNICREQ:
		return sprintf(buf, "LINK_INITVNICREQ\n");
	case LINK_INITVNICRSP:
		return sprintf(buf, "LINK_INITVNICRSP\n");
	case LINK_BEGINDATAPATH:
		return sprintf(buf, "LINK_BEGINDATAPATH\n");
	case LINK_CONFIGDATAPATHREQ:
		return sprintf(buf, "LINK_CONFIGDATAPATHREQ\n");
	case LINK_CONFIGDATAPATHRSP:
		return sprintf(buf, "LINK_CONFIGDATAPATHRSP\n");
	case LINK_DATACONNECT:
		return sprintf(buf, "LINK_DATACONNECT\n");
	case LINK_DATACONNECTWAIT:
		return sprintf(buf, "LINK_DATACONNECTWAIT\n");
	case LINK_XCHGPOOLREQ:
		return sprintf(buf, "LINK_XCHGPOOLREQ\n");
	case LINK_XCHGPOOLRSP:
		return sprintf(buf, "LINK_XCHGPOOLRSP\n");
	case LINK_INITIALIZED:
		return sprintf(buf, "LINK_INITIALIZED\n");
	case LINK_IDLE:
		return sprintf(buf, "LINK_IDLE\n");
	case LINK_IDLING:
		return sprintf(buf, "LINK_IDLING\n");
	case LINK_CONFIGLINKREQ:
		return sprintf(buf, "LINK_CONFIGLINKREQ\n");
	case LINK_CONFIGLINKRSP:
		return sprintf(buf, "LINK_CONFIGLINKRSP\n");
	case LINK_CONFIGADDRSREQ:
		return sprintf(buf, "LINK_CONFIGADDRSREQ\n");
	case LINK_CONFIGADDRSRSP:
		return sprintf(buf, "LINK_CONFIGADDRSRSP\n");
	case LINK_REPORTSTATREQ:
		return sprintf(buf, "LINK_REPORTSTATREQ\n");
	case LINK_REPORTSTATRSP:
		return sprintf(buf, "LINK_REPORTSTATRSP\n");
	case LINK_HEARTBEATREQ:
		return sprintf(buf, "LINK_HEARTBEATREQ\n");
	case LINK_HEARTBEATRSP:
		return sprintf(buf, "LINK_HEARTBEATRSP\n");
	case LINK_RESET:
		return sprintf(buf, "LINK_RESET\n");
	case LINK_RESETRSP:
		return sprintf(buf, "LINK_RESETRSP\n");
	case LINK_RESETCONTROL:
		return sprintf(buf, "LINK_RESETCONTROL\n");
	case LINK_RESETCONTROLRSP:
		return sprintf(buf, "LINK_RESETCONTROLRSP\n");
	case LINK_DATADISCONNECT:
		return sprintf(buf, "LINK_DATADISCONNECT\n");
	case LINK_CONTROLDISCONNECT:
		return sprintf(buf, "LINK_CONTROLDISCONNECT\n");
	case LINK_CLEANUPDATA:
		return sprintf(buf, "LINK_CLEANUPDATA\n");
	case LINK_CLEANUPCONTROL:
		return sprintf(buf, "LINK_CLEANUPCONTROL\n");
	case LINK_DISCONNECTED:
		return sprintf(buf, "LINK_DISCONNECTED\n");
	case LINK_RETRYWAIT:
		return sprintf(buf, "LINK_RETRYWAIT\n");
	default:
		return sprintf(buf, "INVALID STATE\n");

	}

}
static CLASS_DEVICE_ATTR(link_state, S_IRUGO, show_link_state, NULL);

static ssize_t show_heartbeat(struct class_device *class_dev, char *buf)
{
	struct class_dev_info *info =
	    container_of(class_dev, struct class_dev_info, class_dev);

	struct netpath *path =
	    container_of(info, struct netpath, class_dev_info);

	/* hb_inteval is in jiffies, convert it back to
	 * 1/100ths of a second
	 */
	return sprintf(buf, "%d\n",
		(jiffies_to_msecs(path->viport->config->hb_interval)/10));
}

static CLASS_DEVICE_ATTR(heartbeat, S_IRUGO, show_heartbeat, NULL);

static struct attribute * vnic_path_attrs[] = {
	&class_device_attr_viport_state.attr,
	&class_device_attr_link_state.attr,
	&class_device_attr_heartbeat.attr,
	NULL
};

struct attribute_group vnic_path_attr_group = {
	.attrs = vnic_path_attrs,
};


static int setup_path_class_files(struct netpath *path, char *name)
{
	init_completion(&path->class_dev_info.released);

	path->class_dev_info.class_dev.class = &vnic_class;
	path->class_dev_info.class_dev.parent =
	    &path->parent->class_dev_info.class_dev;
	snprintf(path->class_dev_info.class_dev.class_id,
		 BUS_ID_SIZE, name);

	if (class_device_register(&path->class_dev_info.class_dev)) {
		SYS_ERROR("error in registering path class dev\n");
		goto out;
	}

	if (sysfs_create_group(&path->class_dev_info.class_dev.kobj,
			       &vnic_path_attr_group)) {
		SYS_ERROR("error in creating vnic path group attrs");
		goto err_path;
	}

	return 0;

err_path:
	class_device_unregister(&path->class_dev_info.class_dev);
	wait_for_completion(&path->class_dev_info.released);
out:
	return -1;

}

ssize_t vnic_create_primary(struct class_device * class_dev,
			    const char *buf, size_t count)
{
	struct class_dev_info *cdev =
	    container_of(class_dev, struct class_dev_info, class_dev);
	struct vnic_ib_port *target =
	    container_of(cdev, struct vnic_ib_port, cdev_info);

	struct path_param param;
	int ret = -EINVAL;
	struct vnic *vnic;

	param.instance = 0;
	param.rx_csum = -1;
	param.tx_csum = -1;
	param.heartbeat = -1;

	ret = vnic_parse_options(buf, &param);

	if (ret)
		goto out;

	param.ibdev = target->dev->dev;
	param.ibport = target;
	param.port = target->port_num;

	vnic = create_vnic(&param);
	if (!vnic) {
		printk(KERN_ERR PFX "creating vnic failed\n");
		ret = -EINVAL;
		goto out;
	}

	if (create_netpath(&vnic->primary_path, &param)) {
		printk(KERN_ERR PFX "creating primary netpath failed\n");
		goto free_vnic;
	}

	if (setup_path_class_files(&vnic->primary_path, "primary_path"))
		goto free_vnic;

	if (vnic && !vnic->primary_path.viport) {
		printk(KERN_ERR PFX "no valid netpaths\n");
		goto free_vnic;
	}

	return count;

free_vnic:
	vnic_free(vnic);
	ret = -EINVAL;
out:
	return ret;
}

ssize_t vnic_create_secondary(struct class_device * class_dev,
			      const char *buf, size_t count)
{
	struct class_dev_info *cdev =
	    container_of(class_dev, struct class_dev_info, class_dev);
	struct vnic_ib_port *target =
	    container_of(cdev, struct vnic_ib_port, cdev_info);

	struct path_param param;
	struct vnic *vnic;
	int ret = -EINVAL;
	struct list_head *ptr;
	int found = 0;

	param.instance = 0;
	param.rx_csum = -1;
	param.tx_csum = -1;
	param.heartbeat = -1;

	ret = vnic_parse_options(buf, &param);

	if (ret)
		goto out;

	list_for_each(ptr, &vnic_list) {
		vnic = list_entry(ptr, struct vnic, list_ptrs);
		if (!strncmp(vnic->config->name, param.name, IFNAMSIZ)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		printk(KERN_ERR PFX
		       "primary connection with name '%s' does not exist\n",
		       param.name);
		ret = -EINVAL;
		goto out;
	}

	param.ibdev = target->dev->dev;
	param.ibport = target;
	param.port = target->port_num;

	if (create_netpath(&vnic->secondary_path, &param)) {
		printk(KERN_ERR PFX "creating secondary netpath failed\n");
		ret = -EINVAL;
		goto out;
	}

	if (setup_path_class_files(&vnic->secondary_path, "secondary_path"))
		goto free_vnic;

	return count;

free_vnic:
	vnic_free(vnic);
	ret = -EINVAL;
out:
	return ret;
}
