/*
 * Copyright (C) 2005-2007  Kristian Hoegsberg <krh@bitplanet.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include "fw-transaction.h"
#include "fw-topology.h"
#include "fw-device.h"

/* Looted from lib/crc-itu-t.c in later kernels */
/* made static to avoid namespace pollution */
/** CRC table for the CRC ITU-T V.41 0x0x1021 (x^16 + x^12 + x^15 + 1) */
static const u16 crc_itu_t_table[256] = {
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
        0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
        0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
        0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
        0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
        0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
        0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
        0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
        0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
        0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
        0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
        0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
        0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
        0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
        0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
        0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
        0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
        0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
        0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
        0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
        0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
        0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
        0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
        0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
        0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
        0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

static inline u16 crc_itu_t_byte(u16 crc, const u8 data)
{
	return (crc << 8) ^ crc_itu_t_table[((crc >> 8) ^ data) & 0xff];
}
/**
 * crc_itu_t - Compute the CRC-ITU-T for the data buffer
 *
 * @crc:     previous CRC value
 * @buffer:  data pointer
 * @len:     number of bytes in the buffer
 *
 * Returns the updated CRC value
 */
static u16 crc_itu_t(u16 crc, const u8 *buffer, size_t len)
{
        while (len--)
                crc = crc_itu_t_byte(crc, *buffer++);
        return crc;
}

int fw_compute_block_crc(u32 *block)
{
        __be32 be32_block[256];
        int i, length;

        length = (*block >> 16) & 0xff;
        for (i = 0; i < length; i++)
                be32_block[i] = cpu_to_be32(block[i + 1]);
        *block |= crc_itu_t(0, (u8 *) be32_block, length * 4);

        return length;
}


static DEFINE_MUTEX(card_mutex);
static LIST_HEAD(card_list);

static LIST_HEAD(descriptor_list);
static int descriptor_count;

#define BIB_CRC(v)		((v) <<  0)
#define BIB_CRC_LENGTH(v)	((v) << 16)
#define BIB_INFO_LENGTH(v)	((v) << 24)

#define BIB_LINK_SPEED(v)	((v) <<  0)
#define BIB_GENERATION(v)	((v) <<  4)
#define BIB_MAX_ROM(v)		((v) <<  8)
#define BIB_MAX_RECEIVE(v)	((v) << 12)
#define BIB_CYC_CLK_ACC(v)	((v) << 16)
#define BIB_PMC			((1) << 27)
#define BIB_BMC			((1) << 28)
#define BIB_ISC			((1) << 29)
#define BIB_CMC			((1) << 30)
#define BIB_IMC			((1) << 31)

static u32 *
generate_config_rom(struct fw_card *card, size_t *config_rom_length)
{
	struct fw_descriptor *desc;
	static u32 config_rom[256];
	int i, j, length;

	/*
	 * Initialize contents of config rom buffer.  On the OHCI
	 * controller, block reads to the config rom accesses the host
	 * memory, but quadlet read access the hardware bus info block
	 * registers.  That's just crack, but it means we should make
	 * sure the contents of bus info block in host memory mathces
	 * the version stored in the OHCI registers.
	 */

	memset(config_rom, 0, sizeof(config_rom));
	config_rom[0] = BIB_CRC_LENGTH(4) | BIB_INFO_LENGTH(4) | BIB_CRC(0);
	config_rom[1] = 0x31333934;

	config_rom[2] =
		BIB_LINK_SPEED(card->link_speed) |
		BIB_GENERATION(card->config_rom_generation++ % 14 + 2) |
		BIB_MAX_ROM(2) |
		BIB_MAX_RECEIVE(card->max_receive) |
		BIB_BMC | BIB_ISC | BIB_CMC | BIB_IMC;
	config_rom[3] = card->guid >> 32;
	config_rom[4] = card->guid;

	/* Generate root directory. */
	i = 5;
	config_rom[i++] = 0;
	config_rom[i++] = 0x0c0083c0; /* node capabilities */
	j = i + descriptor_count;

	/* Generate root directory entries for descriptors. */
	list_for_each_entry (desc, &descriptor_list, link) {
		if (desc->immediate > 0)
			config_rom[i++] = desc->immediate;
		config_rom[i] = desc->key | (j - i);
		i++;
		j += desc->length;
	}

	/* Update root directory length. */
	config_rom[5] = (i - 5 - 1) << 16;

	/* End of root directory, now copy in descriptors. */
	list_for_each_entry (desc, &descriptor_list, link) {
		memcpy(&config_rom[i], desc->data, desc->length * 4);
		i += desc->length;
	}

	/*
	 * Calculate CRCs for all blocks in the config rom.  This
	 * assumes that CRC length and info length are identical for
	 * the bus info block, which is always the case for this
	 * implementation.
	 */
	for (i = 0; i < j; i += length + 1) {
		length = fw_compute_block_crc(config_rom + i);
	}

	*config_rom_length = j;

	return config_rom;
}

static void
update_config_roms(void)
{
	struct fw_card *card;
	u32 *config_rom;
	size_t length;

	list_for_each_entry (card, &card_list, link) {
		config_rom = generate_config_rom(card, &length);
		card->driver->set_config_rom(card, config_rom, length);
	}
}

int
fw_core_add_descriptor (struct fw_descriptor *desc)
{
	size_t i;

	/*
	 * Check descriptor is valid; the length of all blocks in the
	 * descriptor has to add up to exactly the length of the
	 * block.
	 */
	i = 0;
	while (i < desc->length)
		i += (desc->data[i] >> 16) + 1;

	if (i != desc->length)
		return -EINVAL;

	mutex_lock(&card_mutex);

	list_add_tail(&desc->link, &descriptor_list);
	descriptor_count++;
	if (desc->immediate > 0)
		descriptor_count++;
	update_config_roms();

	mutex_unlock(&card_mutex);

	return 0;
}
EXPORT_SYMBOL(fw_core_add_descriptor);

void
fw_core_remove_descriptor(struct fw_descriptor *desc)
{
	mutex_lock(&card_mutex);

	list_del(&desc->link);
	descriptor_count--;
	if (desc->immediate > 0)
		descriptor_count--;
	update_config_roms();

	mutex_unlock(&card_mutex);
}
EXPORT_SYMBOL(fw_core_remove_descriptor);

static const char gap_count_table[] = {
	63, 5, 7, 8, 10, 13, 16, 18, 21, 24, 26, 29, 32, 35, 37, 40
};

struct bm_data {
	struct fw_transaction t;
	struct {
		__be32 arg;
		__be32 data;
	} lock;
	u32 old;
	int rcode;
	struct completion done;
};

static void
complete_bm_lock(struct fw_card *card, int rcode,
		 void *payload, size_t length, void *data)
{
	struct bm_data *bmd = data;

	if (rcode == RCODE_COMPLETE)
		bmd->old = be32_to_cpu(*(__be32 *) payload);
	bmd->rcode = rcode;
	complete(&bmd->done);
}

static void
fw_card_bm_work(void *w)
{
	struct work_struct *work = w;
	struct fw_card *card = container_of(work, struct fw_card, work);
	struct fw_device *root;
	struct bm_data bmd;
	unsigned long flags;
	int root_id, new_root_id, irm_id, gap_count, generation, grace;
	int do_reset = 0;

	spin_lock_irqsave(&card->lock, flags);

	generation = card->generation;
	root = card->root_node->data;
	root_id = card->root_node->node_id;
	grace = time_after(jiffies, card->reset_jiffies + DIV_ROUND_UP(HZ, 10));

	if (card->bm_generation + 1 == generation ||
	    (card->bm_generation != generation && grace)) {
		/*
		 * This first step is to figure out who is IRM and
		 * then try to become bus manager.  If the IRM is not
		 * well defined (e.g. does not have an active link
		 * layer or does not responds to our lock request, we
		 * will have to do a little vigilante bus management.
		 * In that case, we do a goto into the gap count logic
		 * so that when we do the reset, we still optimize the
		 * gap count.  That could well save a reset in the
		 * next generation.
		 */

		irm_id = card->irm_node->node_id;
		if (!card->irm_node->link_on) {
			new_root_id = card->local_node->node_id;
			fw_notify("IRM has link off, making local node (%02x) root.\n",
				  new_root_id);
			goto pick_me;
		}

		bmd.lock.arg = cpu_to_be32(0x3f);
		bmd.lock.data = cpu_to_be32(card->local_node->node_id);

		spin_unlock_irqrestore(&card->lock, flags);

		init_completion(&bmd.done);
		fw_send_request(card, &bmd.t, TCODE_LOCK_COMPARE_SWAP,
				irm_id, generation,
				SCODE_100, CSR_REGISTER_BASE + CSR_BUS_MANAGER_ID,
				&bmd.lock, sizeof(bmd.lock),
				complete_bm_lock, &bmd);
		wait_for_completion(&bmd.done);

		if (bmd.rcode == RCODE_GENERATION) {
			/*
			 * Another bus reset happened. Just return,
			 * the BM work has been rescheduled.
			 */
			return;
		}

		if (bmd.rcode == RCODE_COMPLETE && bmd.old != 0x3f)
			/* Somebody else is BM, let them do the work. */
			return;

		spin_lock_irqsave(&card->lock, flags);
		if (bmd.rcode != RCODE_COMPLETE) {
			/*
			 * The lock request failed, maybe the IRM
			 * isn't really IRM capable after all. Let's
			 * do a bus reset and pick the local node as
			 * root, and thus, IRM.
			 */
			new_root_id = card->local_node->node_id;
			fw_notify("BM lock failed, making local node (%02x) root.\n",
				  new_root_id);
			goto pick_me;
		}
	} else if (card->bm_generation != generation) {
		/* OK, we weren't BM in the last generation, and it's
		 * less than 100ms since last bus reset. Reschedule
		 * this task 100ms from now. */
		spin_unlock_irqrestore(&card->lock, flags);
		schedule_delayed_work(&card->work, DIV_ROUND_UP(HZ, 10));
		return;
	}

	/* We're bus manager for this generation, so next step is to
	 * make sure we have an active cycle master and do gap count
	 * optimization. */
	card->bm_generation = generation;

	if (root == NULL) {
		/*
		 * Either link_on is false, or we failed to read the
		 * config rom.  In either case, pick another root.
		 */
		new_root_id = card->local_node->node_id;
	} else if (atomic_read(&root->state) != FW_DEVICE_RUNNING) {
		/*
		 * If we haven't probed this device yet, bail out now
		 * and let's try again once that's done.
		 */
		spin_unlock_irqrestore(&card->lock, flags);
		return;
	} else if (root->config_rom[2] & BIB_CMC) {
		/*
		 * FIXME: I suppose we should set the cmstr bit in the
		 * STATE_CLEAR register of this node, as described in
		 * 1394-1995, 8.4.2.6.  Also, send out a force root
		 * packet for this node.
		 */
		new_root_id = root_id;
	} else {
		/*
		 * Current root has an active link layer and we
		 * successfully read the config rom, but it's not
		 * cycle master capable.
		 */
		new_root_id = card->local_node->node_id;
	}

 pick_me:
	/*
	 * Pick a gap count from 1394a table E-1.  The table doesn't cover
	 * the typically much larger 1394b beta repeater delays though.
	*/
	if (!card->beta_repeaters_present &&
	    card->root_node->max_hops < ARRAY_SIZE(gap_count_table)) {
		gap_count = gap_count_table[card->root_node->max_hops];
	} else {
		gap_count = 63;
	}
		

	/*
	 * Finally, figure out if we should do a reset or not.  If we've
	 * done less that 5 resets with the same physical topology and we
	 * have either a new root or a new gap count setting, let's do it.
	 */

	if (card->bm_retries++ < 5 &&
	    (card->gap_count != gap_count || new_root_id != root_id)) {
		do_reset = 1;
	}

	spin_unlock_irqrestore(&card->lock, flags);

	if (do_reset) {
		fw_send_phy_config(card, new_root_id, generation, gap_count);
		fw_core_initiate_bus_reset(card, 1);
	}
}

static void
flush_timer_callback(unsigned long data)
{
	struct fw_card *card = (struct fw_card *)data;

	fw_flush_transactions(card);
}

void
fw_card_initialize(struct fw_card *card, const struct fw_card_driver *driver,
		   struct device *device)
{
	static atomic_t index = ATOMIC_INIT(-1);

	kref_init(&card->kref);
	card->index = atomic_inc_return(&index);
	card->driver = driver;
	card->device = device;
	card->current_tlabel = 0;
	card->tlabel_mask = 0;
	card->color = 0;

	INIT_LIST_HEAD(&card->transaction_list);
	spin_lock_init(&card->lock);
	setup_timer(&card->flush_timer,
		    flush_timer_callback, (unsigned long)card);

	card->local_node = NULL;

	INIT_WORK(&card->work, fw_card_bm_work, &(card->work));
}
EXPORT_SYMBOL(fw_card_initialize);

int
fw_card_add(struct fw_card *card,
	    u32 max_receive, u32 link_speed, u64 guid)
{
	u32 *config_rom;
	size_t length;

	card->max_receive = max_receive;
	card->link_speed = link_speed;
	card->guid = guid;

	/*
	 * The subsystem grabs a reference when the card is added and
	 * drops it when the driver calls fw_core_remove_card.
	 */
	fw_card_get(card);

	mutex_lock(&card_mutex);
	config_rom = generate_config_rom(card, &length);
	list_add_tail(&card->link, &card_list);
	mutex_unlock(&card_mutex);

	return card->driver->enable(card, config_rom, length);
}
EXPORT_SYMBOL(fw_card_add);


/*
 * The next few functions implements a dummy driver that use once a
 * card driver shuts down an fw_card.  This allows the driver to
 * cleanly unload, as all IO to the card will be handled by the dummy
 * driver instead of calling into the (possibly) unloaded module.  The
 * dummy driver just fails all IO.
 */

static int
dummy_enable(struct fw_card *card, u32 *config_rom, size_t length)
{
	BUG();
	return -1;
}

static int
dummy_update_phy_reg(struct fw_card *card, int address,
		     int clear_bits, int set_bits)
{
	return -ENODEV;
}

static int
dummy_set_config_rom(struct fw_card *card,
		     u32 *config_rom, size_t length)
{
	/*
	 * We take the card out of card_list before setting the dummy
	 * driver, so this should never get called.
	 */
	BUG();
	return -1;
}

static void
dummy_send_request(struct fw_card *card, struct fw_packet *packet)
{
	packet->callback(packet, card, -ENODEV);
}

static void
dummy_send_response(struct fw_card *card, struct fw_packet *packet)
{
	packet->callback(packet, card, -ENODEV);
}

static int
dummy_cancel_packet(struct fw_card *card, struct fw_packet *packet)
{
	return -ENOENT;
}

static int
dummy_enable_phys_dma(struct fw_card *card,
		      int node_id, int generation)
{
	return -ENODEV;
}

static struct fw_card_driver dummy_driver = {
	.name            = "dummy",
	.enable          = dummy_enable,
	.update_phy_reg  = dummy_update_phy_reg,
	.set_config_rom  = dummy_set_config_rom,
	.send_request    = dummy_send_request,
	.cancel_packet   = dummy_cancel_packet,
	.send_response   = dummy_send_response,
	.enable_phys_dma = dummy_enable_phys_dma,
};

void
fw_core_remove_card(struct fw_card *card)
{
	card->driver->update_phy_reg(card, 4,
				     PHY_LINK_ACTIVE | PHY_CONTENDER, 0);
	fw_core_initiate_bus_reset(card, 1);

	mutex_lock(&card_mutex);
	list_del(&card->link);
	mutex_unlock(&card_mutex);

	/* Set up the dummy driver. */
	card->driver = &dummy_driver;

	fw_destroy_nodes(card);
	flush_scheduled_work();

	fw_flush_transactions(card);
	del_timer_sync(&card->flush_timer);

	fw_card_put(card);
}
EXPORT_SYMBOL(fw_core_remove_card);

struct fw_card *
fw_card_get(struct fw_card *card)
{
	kref_get(&card->kref);

	return card;
}
EXPORT_SYMBOL(fw_card_get);

static void
release_card(struct kref *kref)
{
	struct fw_card *card = container_of(kref, struct fw_card, kref);

	kfree(card);
}

/*
 * An assumption for fw_card_put() is that the card driver allocates
 * the fw_card struct with kalloc and that it has been shut down
 * before the last ref is dropped.
 */
void
fw_card_put(struct fw_card *card)
{
	kref_put(&card->kref, release_card);
}
EXPORT_SYMBOL(fw_card_put);

int
fw_core_initiate_bus_reset(struct fw_card *card, int short_reset)
{
	int reg = short_reset ? 5 : 1;
	int bit = short_reset ? PHY_BUS_SHORT_RESET : PHY_BUS_RESET;

	return card->driver->update_phy_reg(card, reg, 0, bit);
}
EXPORT_SYMBOL(fw_core_initiate_bus_reset);
