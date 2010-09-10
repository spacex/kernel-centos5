/*
 * SCSI device handler infrastruture - export symbols used by scsi generic
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright IBM Corporation, 2008
 *      Authors:
 *               Chandra Seetharaman <sekharan@us.ibm.com>
 */

#include <scsi/scsi_dh.h>

void store_scsi_dh_data(struct scsi_device *sdev, struct scsi_dh_data *data)
{
	struct scsi_device_dh_data *s = container_of(sdev,
					struct scsi_device_dh_data, sdev);
	s->scsi_dh_data = data;
}
EXPORT_SYMBOL_GPL(store_scsi_dh_data);

struct scsi_dh_data *retrieve_scsi_dh_data(struct scsi_device *sdev)
{
	struct scsi_device_dh_data *s = container_of(sdev,
					struct scsi_device_dh_data, sdev);
	return s->scsi_dh_data;
}
EXPORT_SYMBOL_GPL(retrieve_scsi_dh_data);

