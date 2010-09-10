/*******************************************************************************

  Intel(R) Gigabit Ethernet Linux driver
  Copyright(c) 2007 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#include <linux/delay.h>
#include <linux/io.h>

#include "e1000_api.h"
#include "e1000_manage.h"

static u8 e1000_calculate_checksum(u8 *buffer, u32 length);

/**
 *  e1000_calculate_checksum - Calculate checksum for buffer
 *  @buffer: pointer to EEPROM
 *  @length: size of EEPROM to calculate a checksum for
 *
 *  Calculates the checksum for some buffer on a specified length.  The
 *  checksum calculated is returned.
 **/
static u8 e1000_calculate_checksum(u8 *buffer, u32 length)
{
	u32 i;
	u8  sum = 0;


	if (!buffer)
		return 0;

	for (i = 0; i < length; i++)
		sum += buffer[i];

	return (u8) (0 - sum);
}

/**
 *  e1000_mng_enable_host_if_generic - Checks host interface is enabled
 *  @hw: pointer to the HW structure
 *
 *  Returns E1000_success upon success, else E1000_ERR_HOST_INTERFACE_COMMAND
 *
 *  This function checks whether the HOST IF is enabled for command operaton
 *  and also checks whether the previous command is completed.  It busy waits
 *  in case of previous command is not completed.
 **/
s32 e1000_mng_enable_host_if_generic(struct e1000_hw *hw)
{
	u32 hicr;
	s32 ret_val = E1000_SUCCESS;
	u8  i;


	/* Check that the host interface is enabled. */
	hicr = E1000_READ_REG(hw, E1000_HICR);
	if ((hicr & E1000_HICR_EN) == 0) {
		ret_val = -E1000_ERR_HOST_INTERFACE_COMMAND;
		goto out;
	}
	/* check the previous command is completed */
	for (i = 0; i < E1000_MNG_DHCP_COMMAND_TIMEOUT; i++) {
		hicr = E1000_READ_REG(hw, E1000_HICR);
		if (!(hicr & E1000_HICR_C))
			break;
		mdelay(1);
	}

	if (i == E1000_MNG_DHCP_COMMAND_TIMEOUT) {
		ret_val = -E1000_ERR_HOST_INTERFACE_COMMAND;
		goto out;
	}

out:
	return ret_val;
}

/**
 *  e1000_mng_write_cmd_header_generic - Writes manageability command header
 *  @hw: pointer to the HW structure
 *  @hdr: pointer to the host interface command header
 *
 *  Writes the command header after does the checksum calculation.
 **/
s32 e1000_mng_write_cmd_header_generic(struct e1000_hw *hw,
                                     struct e1000_host_mng_command_header *hdr)
{
	u16 i, length = sizeof(struct e1000_host_mng_command_header);


	/* Write the whole command header structure with new checksum. */

	hdr->checksum = e1000_calculate_checksum((u8 *)hdr, length);

	length >>= 2;
	/* Write the relevant command block into the ram area. */
	for (i = 0; i < length; i++) {
		E1000_WRITE_REG_ARRAY_DWORD(hw, E1000_HOST_IF, i,
		                            *((u32 *) hdr + i));
		E1000_WRITE_FLUSH(hw);
	}

	return E1000_SUCCESS;
}

/**
 *  e1000_mng_host_if_write_generic - Writes to the manageability host interface
 *  @hw: pointer to the HW structure
 *  @buffer: pointer to the host interface buffer
 *  @length: size of the buffer
 *  @offset: location in the buffer to write to
 *  @sum: sum of the data (not checksum)
 *
 *  This function writes the buffer content at the offset given on the host if.
 *  It also does alignment considerations to do the writes in most efficient
 *  way.  Also fills up the sum of the buffer in *buffer parameter.
 **/
s32 e1000_mng_host_if_write_generic(struct e1000_hw *hw, u8 *buffer,
                                    u16 length, u16 offset, u8 *sum)
{
	u8 *tmp;
	u8 *bufptr = buffer;
	u32 data = 0;
	s32 ret_val = E1000_SUCCESS;
	u16 remaining, i, j, prev_bytes;


	/* sum = only sum of the data and it is not checksum */

	if (length == 0 || offset + length > E1000_HI_MAX_MNG_DATA_LENGTH) {
		ret_val = -E1000_ERR_PARAM;
		goto out;
	}

	tmp = (u8 *)&data;
	prev_bytes = offset & 0x3;
	offset >>= 2;

	if (prev_bytes) {
		data = E1000_READ_REG_ARRAY_DWORD(hw, E1000_HOST_IF, offset);
		for (j = prev_bytes; j < sizeof(u32); j++) {
			*(tmp + j) = *bufptr++;
			*sum += *(tmp + j);
		}
		E1000_WRITE_REG_ARRAY_DWORD(hw, E1000_HOST_IF, offset, data);
		length -= j - prev_bytes;
		offset++;
	}

	remaining = length & 0x3;
	length -= remaining;

	/* Calculate length in DWORDs */
	length >>= 2;

	/* The device driver writes the relevant command block into the
	 * ram area. */
	for (i = 0; i < length; i++) {
		for (j = 0; j < sizeof(u32); j++) {
			*(tmp + j) = *bufptr++;
			*sum += *(tmp + j);
		}

		E1000_WRITE_REG_ARRAY_DWORD(hw, E1000_HOST_IF, offset + i, data);
	}
	if (remaining) {
		for (j = 0; j < sizeof(u32); j++) {
			if (j < remaining)
				*(tmp + j) = *bufptr++;
			else
				*(tmp + j) = 0;

			*sum += *(tmp + j);
		}
		E1000_WRITE_REG_ARRAY_DWORD(hw, E1000_HOST_IF, offset + i, data);
	}

out:
	return ret_val;
}

/**
 *  e1000_enable_mng_pass_thru - Enable processing of ARP's
 *  @hw: pointer to the HW structure
 *
 *  Verifies the hardware needs to allow ARPs to be processed by the host.
 **/
bool e1000_enable_mng_pass_thru(struct e1000_hw *hw)
{
	u32 manc;
	u32 fwsm, factps;
	bool ret_val = 0;


	if (!hw->mac.asf_firmware_present)
		goto out;

	manc = E1000_READ_REG(hw, E1000_MANC);

	if (!(manc & E1000_MANC_RCV_TCO_EN) ||
	    !(manc & E1000_MANC_EN_MAC_ADDR_FILTER))
		goto out;

	if (hw->mac.arc_subsystem_valid == 1) {
		fwsm = E1000_READ_REG(hw, E1000_FWSM);
		factps = E1000_READ_REG(hw, E1000_FACTPS);

		if (!(factps & E1000_FACTPS_MNGCG) &&
		    ((fwsm & E1000_FWSM_MODE_MASK) ==
		     (e1000_mng_mode_pt << E1000_FWSM_MODE_SHIFT))) {
			ret_val = 1;
			goto out;
		}
	} else {
		if ((manc & E1000_MANC_SMBUS_EN) &&
		    !(manc & E1000_MANC_ASF_EN)) {
			ret_val = 1;
			goto out;
		}
	}

out:
	return ret_val;
}

