#ifndef _SFC_I2C_COMPAT_H_
#define _SFC_I2C_COMPAT_H_

struct i2c_board_info {
	char		type[I2C_NAME_SIZE];
	unsigned short	addr;
	void		*platform_data;
	int		irq;
};

#define I2C_BOARD_INFO(dev_type, dev_addr) \
        .type = dev_type, .addr = (dev_addr)

/*
 * These functions do not really (/un)register the i2c device.
 * Only create a minimal i2c_client, so i2c_smbus_read_byte_data and
 * i2c_smbus_write_byte_data can work.
 */
static inline struct i2c_client *
i2c_new_dummy(struct i2c_adapter *adap, u16 address)
{
	struct i2c_client *client;

	client = kzalloc(sizeof(struct i2c_client), GFP_KERNEL);
	if (client) {
		client->addr = address;
		client->adapter = adap;
	}
	return client;
}

static inline void i2c_unregister_device(struct i2c_client *c)
{
	kfree(c);
}

#endif /* _SFC_I2C_COMPAT_H_ */
