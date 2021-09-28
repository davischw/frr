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

#include <zebra.h>

#include "lib/bfd.h"
#include "lib/memory.h"
#include "lib/command.h"
#include "lib/address_list.h"
#include "lib/openbsd-queue.h"

#include "staticd/static_address_list.h"
#include "staticd/static_routes.h"
#include "staticd/static_zebra.h"

DEFINE_MTYPE_STATIC(STATIC, STATIC_NAMED_ROUTE, "Static address list context");

/*
 * Functions
 */
static void address_entry_to_g_addr(const struct address_entry *source,
				    union g_addr *destination)
{
	if (source == NULL) {
		memset(&destination->ipv6, 0, sizeof(destination->ipv6));
		return;
	}

	switch (source->ae_ip.ipa_type) {
	case IPADDR_V4:
		destination->ipv4 = source->ae_ip.ipaddr_v4;
		break;
	case IPADDR_V6:
		destination->ipv6 = source->ae_ip.ipaddr_v6;
		break;
	case IPADDR_NONE:
		memset(&destination->ipv6, 0, sizeof(destination->ipv6));
		break;
	}
}

struct static_named_route *static_address_list_new(struct static_vrf *svrf,
						   const char *name,
						   struct static_nexthop *sn)
{
	struct static_named_route *snr;
	struct address_entry *ae;
	struct address_list *al;

	al = address_list_lookup(name);
	if (al)
		ae = al->al_selected;
	else
		ae = NULL;

	/* Already exists, just return the old pointer. */
	snr = sn->snr;
	if (snr) {
		strlcpy(snr->name, name, sizeof(snr->name));
		snr->address_entry = ae;
		address_entry_to_g_addr(ae, &sn->addr);
		return sn->snr;
	}

	/* Allocate new named route context. */
	snr = XCALLOC(MTYPE_STATIC_NAMED_ROUTE, sizeof(*snr));
	snr->sn = sn;
	snr->address_entry = ae;
	address_entry_to_g_addr(ae, &sn->addr);
	strlcpy(snr->name, name, sizeof(snr->name));
	LIST_INSERT_HEAD(&svrf->named_route_list, snr, entry);

	return snr;
}

void static_address_list_free(struct static_named_route **snr)
{
	if (*snr == NULL)
		return;

	LIST_REMOVE((*snr), entry);
	XFREE(MTYPE_STATIC_NAMED_ROUTE, (*snr));
}

static void static_named_route_toggle_address(struct static_named_route *snr,
					      struct static_vrf *svrf)
{
	struct static_nexthop *sn = snr->sn;

	/* Uninstall, update address and install again. */
	static_zebra_route_add(sn->rn, sn->sp, sn->safi, false);
	address_entry_to_g_addr(snr->address_entry, &sn->addr);
	if (snr->address_entry) {
		/* Update BFD address. */
		if (sn->bsp) {
			switch (sn->type) {
			case STATIC_IPV4_GATEWAY:
			case STATIC_IPV4_GATEWAY_IFNAME:
				bfd_sess_set_ipv4_addrs(sn->bsp, NULL,
							&sn->addr.ipv4);
				break;

			case STATIC_IPV6_GATEWAY:
			case STATIC_IPV6_GATEWAY_IFNAME:
				bfd_sess_set_ipv6_addrs(sn->bsp, NULL,
							&sn->addr.ipv6);
				break;

			case STATIC_IFNAME:
			case STATIC_BLACKHOLE:
			default:
				zlog_err("%s: invalid next hop type", __func__);
				return;
			}

			/* Update session. */
			bfd_sess_install(sn->bsp);
		}

		static_install_path(sn->rn, sn->sp, sn->safi, svrf);
	} else {
		/* No address, uninstall session. */
		if (sn->bsp)
			bfd_sess_uninstall(sn->bsp);
	}
}

static int static_next_address_entry(const struct address_list *al,
				      const struct address_entry *ae)
{
	struct static_named_route *snr;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct static_vrf *svrf = vrf->info;
		if (svrf == NULL)
			continue;

		LIST_FOREACH (snr, &svrf->named_route_list, entry) {
			/* Skip unmatched address lists. */
			if (strcmp(snr->name, al->al_name))
				continue;

			snr->address_entry = ae;
			static_named_route_toggle_address(snr, svrf);
		}
	}

	return 0;
}

void static_address_list_init(void)
{
	hook_register(address_entry_next, static_next_address_entry);
}
