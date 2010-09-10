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

#ifndef VNIC_SYS_H_INCLUDED
#define VNIC_SYS_H_INCLUDED

struct class_dev_info {
	struct class_device	class_dev;
	struct completion	released;
};

extern struct class vnic_class;
extern struct class_dev_info interface_cdev;
extern struct attribute_group vnic_dev_attr_group;
extern struct attribute_group vnic_path_attr_group;
extern struct class_device_attribute class_device_attr_create_primary;
extern struct class_device_attribute class_device_attr_create_secondary;
extern struct class_device_attribute class_device_attr_delete_vnic;
extern struct class_device_attribute class_device_attr_force_failover;
extern struct class_device_attribute class_device_attr_unfailover;

#endif	/*VNIC_SYS_H_INCLUDED*/
