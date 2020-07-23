/*
 * BGP address list usage implementation.
 *
 * Copyright (C) 2020 Network Device Education Foundation, Inc. ("NetDEF")
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

#include "lib/memory.h"
#include "lib/command.h"
#include "lib/address_list.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_vty.h"

#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_address_list_clippy.c"
#endif /* VTYSH_EXTRACT_PL */

/*
 * Prototypes.
 */
DEFINE_MTYPE_STATIC(BGPD, ADDRESS_LIST_NAME, "Address list name");

static void peer_group_toggle_address(struct peer_group *pg,
				      const struct address_list *al,
				      const struct address_entry *ae);

/*
 * Commands
 */
DEFPY(neighbor_named, neighbor_named_cmd,
      "[no] neighbor named WORD$al_name peer-group PGNAME$pg_name",
      NO_STR
      NEIGHBOR_STR
      "Use address list named\n"
      "Address list name\n"
      "Member of the peer-group\n"
      "Peer-group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct peer_group *pg;
	struct address_list *al;

	/* Look up for existing peer group. */
	pg = peer_group_lookup(bgp, pg_name);
	if (pg == NULL) {
		vty_out(vty, "%% Configure the peer-group first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* No group specified. */
	if (pg->conf->as_type == AS_UNSPECIFIED
	    || (pg->conf->as_type == AS_SPECIFIED && !pg->conf->as))
		return bgp_vty_return(vty, BGP_ERR_PEER_GROUP_NO_REMOTE_AS);

	/* Remove entry if any. */
	if (no) {
		XFREE(MTYPE_ADDRESS_LIST_NAME, pg->pg_al_name);
		return CMD_SUCCESS;
	}

	/* Remove previously configured name (if any). */
	if (pg->pg_al_name) {
		XFREE(MTYPE_ADDRESS_LIST_NAME, pg->pg_al_name);
		peer_delete(pg->pg_peer);
		pg->pg_peer = NULL;
	}

	/* Keep the new address list name even if not using it yet. */
	pg->pg_al_name = XSTRDUP(MTYPE_ADDRESS_LIST_NAME, al_name);

	/* Find the address list entry (if it exists). */
	al = address_list_lookup(pg->pg_al_name);
	if (al == NULL)
		return CMD_SUCCESS;

	/* Add the selected entry. */
	peer_group_toggle_address(pg, al, al->al_selected);

	return CMD_SUCCESS;
}

/*
 * Functions.
 */
static void peer_group_toggle_address(struct peer_group *pg,
				      const struct address_list *al,
				      const struct address_entry *ae)
{
	struct peer *p;
	safi_t safi;
	afi_t afi;
	union sockunion su;

	/* Remove previously created peer. */
	if (pg->pg_peer) {
		if (BGP_DEBUG(neighbor_events, NEIGHBOR_EVENTS))
			zlog_debug("%s: removing previously configured peer",
				   __func__);

		peer_delete(pg->pg_peer);
		pg->pg_peer = NULL;
	}

	/* No more entries in the list. */
	if (ae == NULL) {
		if (BGP_DEBUG(neighbor_events, NEIGHBOR_EVENTS))
			zlog_debug("%s: no new addresses", __func__);
		return;
	}

	/* Create new dynamic session. */
	memset(&su, 0, sizeof(su));
	switch (ae->ae_ip.ipa_type) {
	case IPADDR_V4:
		su.sin.sin_family = AF_INET;
		su.sin.sin_addr.s_addr = ae->ae_ip.ip._v4_addr.s_addr;
		zlog_debug("%s: new address %pI4", __func__, &su.sin.sin_addr);
		break;
	case IPADDR_V6:
		su.sin6.sin6_family = AF_INET6;
		memcpy(&su.sin6.sin6_addr, &ae->ae_ip.ip._v6_addr,
		       sizeof(su.sin6.sin6_addr));
		zlog_debug("%s: new address %pI6", __func__,
			   &su.sin6.sin6_addr);
		break;

	default:
		assert(0);
		break;
	}

	/* Don't attempt to connect to ourselves. */
	if (peer_address_self_check(pg->bgp, &su)) {
		zlog_err("%s: connecting to self is not allowed", __func__);
		return;
	}

	/* Check for duplicated addresses. */
	p = peer_lookup(pg->bgp, &su);
	if (p != NULL) {
		if (ae->ae_ip.ipa_type == IPADDR_V4)
			zlog_info("%s: peer with address '%pI4' already exists",
				  __func__, &su.sin.sin_addr);
		else
			zlog_info("%s: peer with address '%pI6' already exists",
				  __func__, &su.sin6.sin6_addr);
		return;
	}

	/* Create dynamic peer. */
	p = peer_create(&su, NULL, pg->bgp, pg->bgp->as, pg->conf->as,
			pg->conf->as_type, pg);
	p = peer_lock(p);
	listnode_add(pg->peer, p);
	peer_group2peer_config_copy(pg, p);

	/*
	 * If the peer-group is active for this afi/safi then activate
	 * for this peer
	 */
	FOREACH_AFI_SAFI (afi, safi) {
		if (pg->conf->afc[afi][safi]) {
			p->afc[afi][safi] = 1;
			peer_af_create(p, afi, safi);
			peer_group2peer_config_copy_af(pg, p, afi, safi);
		} else if (p->afc[afi][safi])
			peer_deactivate(p, afi, safi);
	}

	/*
	 * Mark as dynamic, but also as a "config node" for other things to
	 * work.
	 */
	SET_FLAG(p->flags, PEER_FLAG_ADDRESS_LIST_USER);
	SET_FLAG(p->flags, PEER_FLAG_CONFIG_NODE);

	/* Set up peer's events and timers. */
	if (peer_active(p))
		bgp_timer_set(p);

	pg->pg_peer = p;
}

/**
 * Address list new address selection callback.
 */
static int peer_group_next_address(const struct address_list *al,
				   const struct address_entry *ae)
{
	struct bgp *bgp = bgp_get_default();
	struct peer_group *pg;
	struct listnode *ln;

	/* No bgp instances yet. */
	if (bgp == NULL)
		return 0;

	if (BGP_DEBUG(neighbor_events, NEIGHBOR_EVENTS)) {
		if (ae != NULL) {
			switch (ae->ae_ip.ipa_type) {
			case IPADDR_V4:
				zlog_debug("%s: address list %s update: %pI4",
					   __func__, al->al_name,
					   &ae->ae_ip.ip._v4_addr);
				break;
			case IPADDR_V6:
				zlog_debug("%s: address list %s update: %pI6",
					   __func__, al->al_name,
					   &ae->ae_ip.ip._v6_addr);
				break;

			default:
				zlog_err("%s: invalid address type", __func__);
				return 0;
			}
		} else {
			zlog_debug("%s: address list %s is now empty", __func__,
				   al->al_name);
		}
	}

	for (ALL_LIST_ELEMENTS_RO(bgp->group, ln, pg)) {
		/* Skip peer groups without address list. */
		if (pg->pg_al_name == NULL)
			continue;
		/* Match address list names. */
		if (strcmp(al->al_name, pg->pg_al_name))
			continue;

		if (BGP_DEBUG(neighbor_events, NEIGHBOR_EVENTS))
			zlog_debug("  peer group %s matched", pg->name);

		peer_group_toggle_address(pg, al, ae);
	}

	return 0;
}

void bgp_address_list_init(void)
{
	hook_register(address_entry_next, peer_group_next_address);

	install_element(BGP_NODE, &neighbor_named_cmd);
}
