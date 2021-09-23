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
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_zebra.h"

#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_address_list_clippy.c"
#endif /* VTYSH_EXTRACT_PL */

/*
 * Prototypes.
 */
DEFINE_MTYPE_STATIC(BGPD, BGP_NAMED_PEER, "BGP peer address list name");

/*
 * Functions.
 */
/** Clone of `bgp_peer_conf_if_to_su_update` with modifications */
static void bgp_peer_su_update(struct peer *peer, const union sockunion *su)
{
	int prev_family;

	/*
	 * Our peer structure is stored in the bgp->peerhash
	 * release it before we modify anything.
	 */
	hash_release(peer->bgp->peerhash, peer);

	prev_family = peer->su.sa.sa_family;
	peer->su = *su;

	if (CHECK_FLAG(peer->flags, PEER_FLAG_PASSWORD)
	    && prev_family == AF_UNSPEC)
		bgp_md5_set(peer);

	/*
	 * Since our su changed we need to del/add peer to the peerhash
	 */
	hash_get(peer->bgp->peerhash, peer, hash_alloc_intern);
}

static void address_list_peer_toggle(struct bgp_named_peer *np,
				     const struct address_entry *ae)
{
	union sockunion su;

	if (BGP_DEBUG(neighbor_events, NEIGHBOR_EVENTS))
		zlog_debug("%s: removing previously configured peer", __func__);

	/* Only disable peer if address was configured. */
	if (np->peer->su.sa.sa_family != AF_UNSPEC) {
		peer_notify_unconfig(np->peer);
		BGP_EVENT_ADD(np->peer, BGP_Stop);

		/* Reset address. */
		np->peer->su.sa.sa_family = AF_UNSPEC;
		memset(&np->peer->su.sin6.sin6_addr, 0,
		       sizeof(struct in6_addr));

		/*
		 * Scrub some information that might be left over from a
		 * previous, session
		 */
		if (np->peer->su_local) {
			sockunion_free(np->peer->su_local);
			np->peer->su_local = NULL;
		}
		if (np->peer->su_remote) {
			sockunion_free(np->peer->su_remote);
			np->peer->su_remote = NULL;
		}
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
	if (peer_address_self_check(np->bgp, &su)) {
		zlog_err("%s: connecting to self is not allowed", __func__);
		return;
	}

	/* Check for duplicated addresses. */
	if (peer_lookup(np->bgp, &su) != NULL) {
		if (ae->ae_ip.ipa_type == IPADDR_V4)
			zlog_info("%s: peer with address '%pI4' already exists",
				  __func__, &su.sin.sin_addr);
		else
			zlog_info("%s: peer with address '%pI6' already exists",
				  __func__, &su.sin6.sin6_addr);
		return;
	}

	/* Update peer address. */
	bgp_peer_su_update(np->peer, &su);
	if (peer_active(np->peer))
		bgp_timer_set(np->peer);
}

struct bgp_named_peer *address_list_lookup_by_name(struct bgp *bgp,
						   const char *name)
{
	struct bgp_named_peer *np;

	LIST_FOREACH (np, &bgp->named_peer_list, entry) {
		if (strcmp(np->name, name))
			continue;

		return np;
	}

	return NULL;
}

struct peer *peer_lookup_by_address_list(struct bgp *bgp, const char *name)
{
	struct bgp_named_peer *np = address_list_lookup_by_name(bgp, name);
	return np ? np->peer : NULL;
}

/** Modified copy of function `peer_create`. */
static struct peer *_address_list_peer_new(struct bgp *bgp, const char *name)
{
	struct peer *peer = peer_new(bgp);
	safi_t safi;
	int active;
	afi_t afi;

	XFREE(MTYPE_BGP_PEER_HOST, peer->host);
	peer->host = XSTRDUP(MTYPE_BGP_PEER_HOST, name);

	peer->local_id = bgp->router_id;
	peer->v_holdtime = bgp->default_holdtime;
	peer->v_keepalive = bgp->default_keepalive;
	peer->v_routeadv = (peer_sort(peer) == BGP_PEER_IBGP)
				   ? BGP_DEFAULT_IBGP_ROUTEADV
				   : BGP_DEFAULT_EBGP_ROUTEADV;

	peer = peer_lock(peer); /* bgp peer list reference */
	peer->group = NULL;
	listnode_add_sort(bgp->peer, peer);
	hash_get(bgp->peerhash, peer, hash_alloc_intern);

	/* Adjust update-group coalesce timer heuristics for # peers. */
	if (bgp->heuristic_coalesce) {
		long ct = BGP_DEFAULT_SUBGROUP_COALESCE_TIME
			  + (bgp->peer->count
			     * BGP_PEER_ADJUST_SUBGROUP_COALESCE_TIME);
		bgp->coalesce_time = MIN(BGP_MAX_SUBGROUP_COALESCE_TIME, ct);
	}

	active = peer_active(peer);
	if (!active) {
		if (peer->su.sa.sa_family == AF_UNSPEC)
			peer->last_reset = PEER_DOWN_NBR_ADDR;
		else
			peer->last_reset = PEER_DOWN_NOAFI_ACTIVATED;
	}

	/* Last read and reset time set */
	peer->readtime = peer->resettime = bgp_clock();

	/* Default TTL set. */
	peer->ttl = (peer->sort == BGP_PEER_IBGP) ? MAXTTL : BGP_DEFAULT_TTL;

	/* Default configured keepalives count for shutdown rtt command */
	peer->rtt_keepalive_conf = 1;

	SET_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE);

	/* If address family is IPv4 and `bgp default ipv4-unicast` (default),
	 * then activate the neighbor for this AF.
	 * If address family is IPv6 and `bgp default ipv6-unicast`
	 * (non-default), then activate the neighbor for this AF.
	 */
	FOREACH_AFI_SAFI (afi, safi) {
		if ((afi == AFI_IP || afi == AFI_IP6) && safi == SAFI_UNICAST) {
			if ((afi == AFI_IP
			     && !CHECK_FLAG(bgp->flags,
					    BGP_FLAG_NO_DEFAULT_IPV4))
			    || (afi == AFI_IP6
				&& CHECK_FLAG(bgp->flags,
					      BGP_FLAG_DEFAULT_IPV6))) {
				peer->afc[afi][safi] = 1;
				peer_af_create(peer, afi, safi);
			}
		}
	}

	bgp_peer_gr_flags_update(peer);
	BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(bgp, bgp->peer);

	bgp_stop(peer);

	return peer;
}

static struct bgp_named_peer *address_list_peer_new(struct bgp *bgp,
						    const char *name)
{
	struct bgp_named_peer *np;

	np = XCALLOC(MTYPE_BGP_NAMED_PEER, sizeof(*np));
	np->bgp = bgp;

	/* Create peer and point back. */
	np->peer = _address_list_peer_new(bgp, name);
	np->peer->np = np;

	strlcpy(np->name, name, sizeof(np->name));
	LIST_INSERT_HEAD(&bgp->named_peer_list, np, entry);
	return np;
}

void address_list_peer_free(struct bgp_named_peer **npp)
{
	struct peer *peer;
	struct bgp_named_peer *np = *npp;

	if (np == NULL)
		return;

	peer = np->peer;
	if (peer) {
		*npp = NULL;
		peer->np = NULL;
		if (CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE))
			bgp_zebra_terminate_radv(peer->bgp, peer);

		peer_notify_unconfig(peer);
		peer_delete(peer);
	}

	LIST_REMOVE(np, entry);
	XFREE(MTYPE_BGP_NAMED_PEER, np);
}

void bgp_address_list_peers_free(struct bgp *bgp)
{
	struct bgp_named_peer *np;

	while ((np = LIST_FIRST(&bgp->named_peer_list)) != NULL)
		address_list_peer_free(&np);
}

void peer_address_list_remote_as(struct bgp *bgp, const char *name, as_t as,
				 int as_type)
{
	struct bgp_named_peer *np;
	struct address_list *al;

	/* Find or create new named peer. */
	np = address_list_lookup_by_name(bgp, name);
	if (np == NULL)
		np = address_list_peer_new(bgp, name);

	/* Save configuration. */
	peer_remote_as(bgp, NULL, name, &as, as_type);

	/* Attempt to create dynamic peer if address exists. */
	al = address_list_lookup(np->name);
	if (al)
		address_list_peer_toggle(np, al->al_selected);
}

/**
 * Address list new address selection callback.
 */
static int peer_group_next_address(const struct address_list *al,
				   const struct address_entry *ae)
{
	struct bgp_named_peer *np;
	struct listnode *node;
	struct bgp *bgp;

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

	/* Update all BGP instances. */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		LIST_FOREACH (np, &bgp->named_peer_list, entry) {
			/* Skip unmatched names. */
			if (strcmp(np->name, al->al_name))
				continue;

			if (BGP_DEBUG(neighbor_events, NEIGHBOR_EVENTS))
				zlog_debug("  peer %s matched", np->name);

			address_list_peer_toggle(np, ae);
		}
	}

	return 0;
}

void bgp_address_list_init(void)
{
	hook_register(address_entry_next, peer_group_next_address);
}
