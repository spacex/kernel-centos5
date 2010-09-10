/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * mod.c: loading/registering of dynamic TUX modules
 */

#include <net/tux.h>
#include <linux/kmod.h>

/****************************************************************
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2, or (at your option)
 *      any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ****************************************************************/

DEFINE_SPINLOCK(tuxmodules_lock);
static LIST_HEAD(tuxmodules_list);

tcapi_template_t * get_first_usermodule (void)
{
	tcapi_template_t *tcapi;
	struct list_head *head, *curr, *next;

	spin_lock(&tuxmodules_lock);
	head = &tuxmodules_list;
	next = head->next;

	while ((curr = next) != head) {
		tcapi = list_entry(curr, tcapi_template_t, modules);
		next = curr->next;
		if (tcapi->userspace_id) {
			spin_unlock(&tuxmodules_lock);
			return tcapi;
		}
	}
	spin_unlock(&tuxmodules_lock);
	return NULL;
}

static tcapi_template_t * lookup_module (const char *vfs_name)
{
	tcapi_template_t *tcapi;
	struct list_head *head, *curr, *next;

	while (*vfs_name == '/')
		vfs_name++;
	Dprintk("looking up TUX module {%s}.\n", vfs_name);
	head = &tuxmodules_list;
	next = head->next;

	while ((curr = next) != head) {
		tcapi = list_entry(curr, tcapi_template_t, modules);
		next = curr->next;
		Dprintk("checking module {%s} == {%s}?\n", vfs_name, tcapi->vfs_name);
		if (!strcmp(tcapi->vfs_name, vfs_name))
			return tcapi;
	}
	return NULL;
}

/*
 * Attempt to load a TUX application module.
 * This is the slow path, we cache ('link') the module's
 * API vector to the inode.
 * The module loading path is serialized, and we handshake
 * with the loaded module and fetch its API vector.
 */
tcapi_template_t * lookup_tuxmodule (const char *filename)
{
	tcapi_template_t *tcapi;

	spin_lock(&tuxmodules_lock);
	tcapi = lookup_module(filename);
	if (!tcapi)
		Dprintk("did not find module vfs:{%s}\n", filename);
	spin_unlock(&tuxmodules_lock);
	return tcapi;
}


int register_tuxmodule (tcapi_template_t *tcapi)
{
	int ret = -EEXIST;

	spin_lock(&tuxmodules_lock);

	if (lookup_module(tcapi->vfs_name)) {
		Dprintk("module with VFS binding '%s' already registered!\n",
						 tcapi->vfs_name);
		goto out;
	}

	list_add(&tcapi->modules, &tuxmodules_list);
	ret = 0;
	Dprintk("TUX module %s registered.\n", tcapi->vfs_name);
out:
	spin_unlock(&tuxmodules_lock);

	return ret;
}

void unregister_all_tuxmodules (void)
{
	tcapi_template_t *tcapi;
	struct list_head *curr;

	spin_lock(&tuxmodules_lock);
	while (((curr = tuxmodules_list.next)) != &tuxmodules_list) {
		tcapi = list_entry(curr, tcapi_template_t, modules);
		list_del(curr);
		kfree(tcapi->vfs_name);
		kfree(tcapi);
	}
	spin_unlock(&tuxmodules_lock);
}

tcapi_template_t * unregister_tuxmodule (char *vfs_name)
{
	tcapi_template_t *tcapi;
	int err = 0;

	spin_lock(&tuxmodules_lock);
	tcapi = lookup_module(vfs_name);
	if (!tcapi) {
		Dprintk("huh, module %s not registered??\n", vfs_name);
		err = -1;
	} else {
		list_del(&tcapi->modules);
		Dprintk("TUX module %s unregistered.\n", vfs_name);
	}
	spin_unlock(&tuxmodules_lock);

	return tcapi;
}

static int check_module_version (user_req_t *u_info)
{
	int major, minor, patch, ret;

	ret = copy_from_user(&major, &u_info->version_major, sizeof(int));
	ret += copy_from_user(&minor, &u_info->version_minor, sizeof(int));
	ret += copy_from_user(&patch, &u_info->version_patch, sizeof(int));
	if (ret)
		return -EFAULT;

	if ((major != TUX_MAJOR_VERSION) || (minor > TUX_MINOR_VERSION)) {

		printk(KERN_ERR "TUX: module version %d:%d incompatible with kernel version %d:%d!\n", major, minor, TUX_MAJOR_VERSION, TUX_MINOR_VERSION);
		return -EINVAL;
	}
	return 0;
}

int user_register_module (user_req_t *u_info)
{
	int idx, len, ret;
	tcapi_template_t *tcapi;
	char modulename [MAX_URI_LEN+1];

	ret = check_module_version(u_info);
	if (ret)
		return ret;

	/*
	 * Check module name length.
	 */
	ret = strnlen_user(u_info->objectname, MAX_URI_LEN+2);
	if (ret < 0)
		goto out;
	ret = -EINVAL;
	if (ret >= MAX_URI_LEN)
		goto out;

	Dprintk("register user-module, %p.\n", u_info);
	ret = strncpy_from_user(modulename, u_info->objectname, MAX_URI_LEN);
	if (ret < 0)
		goto out;
	modulename[ret] = 0;
	Dprintk("... user-module is: {%s}.\n", modulename);
	len = strlen(modulename);
	if (!len)
		printk(KERN_ERR "no module name provided: please upgrade your TUX user-space utilities!\n");
	if (!len || (len > MAX_URI_LEN))
		return -EINVAL;
	Dprintk("... user-module len is: %d.\n", len);

	ret = copy_from_user(&idx, &u_info->module_index, sizeof(int));
	if (ret || !idx)
		goto out;
	Dprintk("... user-module index is: %d.\n", idx);

	ret = -ENOMEM;
	tcapi = (tcapi_template_t *) kmalloc(sizeof(*tcapi), GFP_KERNEL);
	if (!tcapi)
		goto out;
	memset(tcapi, 0, sizeof(*tcapi));

	tcapi->vfs_name = (char *) kmalloc(len+1, GFP_KERNEL);
	if (!tcapi->vfs_name) {
		kfree(tcapi);
		goto out;
	}
	strcpy(tcapi->vfs_name, modulename);
	tcapi->userspace_id = idx;

	Dprintk("... registering module {%s}.\n", tcapi->vfs_name);
	ret = register_tuxmodule(tcapi);
out:
	return ret;
}

int user_unregister_module (user_req_t *u_info)
{
	int len, ret;
	tcapi_template_t *tcapi;
	char modulename [MAX_URI_LEN+1];

	/*
	 * Check module name length.
	 */
	ret = strnlen_user(u_info->objectname, MAX_URI_LEN+2);
	if (ret < 0)
		goto out;
	ret = -EINVAL;
	if (ret >= MAX_URI_LEN)
		goto out;
	Dprintk("unregister user-module, %p.\n", u_info);
	ret = strncpy_from_user(modulename, u_info->objectname, MAX_URI_LEN);
	if (ret <= 0)
		goto out;
	modulename[ret] = 0;
	Dprintk("... user-module is: {%s}.\n", modulename);
	len = strlen(modulename);
	if (!len || (len > MAX_URI_LEN))
		return -EINVAL;
	Dprintk("... user-module len is: %d.\n", len);

	Dprintk("... unregistering module {%s}.\n", modulename);
	tcapi = unregister_tuxmodule(modulename);
	ret = -EINVAL;
	if (tcapi) {
		ret = 0;
		kfree(tcapi->vfs_name);
		kfree(tcapi);
	}
out:
	return ret;
}

