/*
 * Static route address list usage implementation.
 *
 * Copyright (C) 2021 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael F. Zalamena
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

#ifndef STATIC_ADDRESS_LIST
#define STATIC_ADDRESS_LIST

#include "lib/address_list.h"
#include "lib/nexthop.h"

/* Forward declaration */
struct static_nexthop;

/** Address list private data structure. */
struct static_named_route {
	/** Address list name. */
	char name[ADDRESS_LIST_NAME_LONGEST];
	/** Selected address entry. */
	const struct address_entry *address_entry;
	/** Static route pointer. */
	struct static_nexthop *sn;
	/** Back pointer to VRF. */
	struct static_vrf *svrf;

	LIST_ENTRY(static_named_route) entry;
};
LIST_HEAD(static_named_route_list, static_named_route);

static inline bool
static_named_route_active(const struct static_named_route *snr)
{
	return snr->address_entry != NULL;
}

struct static_named_route *static_address_list_new(struct static_vrf *svrf,
						   const char *name,
						   struct static_nexthop *sn);
void static_address_list_free(struct static_named_route **snr);

void static_address_list_init(void);

#endif /* STATIC_ADDRESS_LIST */
