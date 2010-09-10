/*
 * Algorithm testing framework and tests.
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2002 Jean-Francois Dive <jef@linuxbe.org>
 * Copyright (c) 2007 Nokia Siemens Networks
 * Copyright (c) 2008 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <linux/err.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "ninternal.h"

struct crypto_test_param {
	char driver[CRYPTO_MAX_ALG_NAME];
	char alg[CRYPTO_MAX_ALG_NAME];
	u32 type;
};

static int cryptomgr_test_cipher(void *data)
{
	struct crypto_test_param *param = data;
	u32 type = param->type;

	ocrypto_alg_tested(param->driver,
			   alg_test(param->driver, param->alg, type,
				    NCRYPTO_ALG_TESTED));

	kfree(param);
	module_put_and_exit(0);
}

static int cryptomgr_schedule_test_cipher(struct crypto_cipher_test *test)
{
	struct crypto_alg *alg = test->alg;
	struct task_struct *thread;
	struct crypto_test_param *param;

	if (!try_module_get(THIS_MODULE))
		goto err;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param)
		goto err_put_module;

	memcpy(param->driver, alg->cra_driver_name, sizeof(param->driver));
	memcpy(param->alg, test->name, sizeof(param->alg));
	param->type = alg->cra_flags;

	thread = kthread_run(cryptomgr_test_cipher, param,
			     "cryptomgr_test_cipher");
	if (IS_ERR(thread))
		goto err_free_param;

	return NOTIFY_STOP;

err_free_param:
	kfree(param);
err_put_module:
	module_put(THIS_MODULE);
err:
	return NOTIFY_OK;
}

static int otestmgr_notify(struct notifier_block *this, unsigned long msg,
			   void *data)
{
	switch (msg) {
	case CRYPTO_MSG_ALG_REGISTER:
		return cryptomgr_schedule_test_cipher(data);
	}

	return NOTIFY_DONE;
}

static struct notifier_block otestmgr_notifier = {
	.notifier_call = otestmgr_notify,
};

static int __init testmgr_cipher_init(void)
{
	return ocrypto_register_notifier(&otestmgr_notifier);
}

static void __exit testmgr_cipher_exit(void)
{
	int err;

	err = ocrypto_unregister_notifier(&otestmgr_notifier);
	BUG_ON(err);
}

subsys_initcall(testmgr_cipher_init);
module_exit(testmgr_cipher_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Algorithm Test Manager for Ciphers");
