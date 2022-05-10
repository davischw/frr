/*
 * PIM address list integration.
 *
 * Copyright (C) 2022-2023 Network Device Education Foundation, Inc. ("NetDEF")
 *                         Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef PIM_ADDRESS_LIST_H
#define PIM_ADDRESS_LIST_H

#include "lib/address_list.h"

/** MSDP peer tracking data structure. */
struct msdp_named_peer {
	/** MSDP peer name. */
	char list_name[ADDRESS_LIST_NAME_LONGEST];
	/** PIM instance pointer. */
	struct pim_instance *pim;
	/** Local address. */
	struct in_addr local_address;
	/** MSDP peer data structure pointer. */
	struct pim_msdp_peer peer_data;

	SLIST_ENTRY(msdp_named_peer) entry;
};
SLIST_HEAD(msdp_named_peer_list, msdp_named_peer);

/** Create new MSDP peer. */
struct pim_msdp_peer *
pim_msdp_named_peer_new(struct pim_instance *pim,
			const struct in_addr *local_address,
			const char *peer_name, const char *mesh_group_name);

/* Delete and free MSDP peer. */
void pim_msdp_named_peer_free(struct pim_msdp_peer *msdp_peer);

/** Initialize address list integration. */
void pim_address_list_init(void);

#endif /* PIM_ADDRESS_LIST_H */
