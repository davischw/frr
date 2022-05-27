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

#include <zebra.h>

#include "lib/queue.h"
#include "lib/address_list.h"
#include "lib/memory.h"
#include "lib/prefix.h"
#include "lib/vrf.h"

#include "pimd/pimd.h"
#include "pimd/pim_msdp.h"
#include "pimd/pim_address_list.h"
#include "pimd/pim_msdp_packet.h"
#include "pimd/pim_instance.h"
#include "pimd/pim_str.h"
#include "pimd/pim_msdp.h"

DEFINE_MTYPE_STATIC(PIMD, PIM_MSDP_NAMED_PEER, "MSDP named peer context");

struct pim_msdp_peer *pim_msdp_named_peer_lookup(const struct pim_instance *pim,
						 const char *name)
{
	struct msdp_named_peer *peer;

	SLIST_FOREACH (peer, &pim->msdp_named_peer_list, entry) {
		if (strcmp(peer->list_name, name))
			continue;

		return &peer->peer_data;
	}

	return NULL;
}

static void msdp_named_peer_disable(struct pim_msdp_peer *msdp_peer)
{
	/* Destination not configured, skip this. */
	if (msdp_peer->peer.s_addr == INADDR_ANY)
		return;

	if (PIM_DEBUG_MSDP_EVENTS)
		zlog_debug("Removing MSDP peer %s previous address: %pI4",
			   msdp_peer->named_peer->list_name, &msdp_peer->peer);

	/* Stop connection. */
	pim_msdp_peer_stop_tcp_conn(msdp_peer, true);
	THREAD_OFF(msdp_peer->auth_listen_ev);
	if (msdp_peer->auth_listen_sock != -1) {
		close(msdp_peer->auth_listen_sock);
		msdp_peer->auth_listen_sock = -1;
	}

	/* Remove the session from various tables. */
	listnode_delete(msdp_peer->pim->msdp.peer_list, msdp_peer);
	hash_release(msdp_peer->pim->msdp.peer_hash, msdp_peer);

	/* Reset peer address. */
	msdp_peer->peer.s_addr = INADDR_ANY;
}

static void msdp_named_peer_toggle(struct msdp_named_peer *peer,
				   const struct address_entry *ae)
{
	/* Remove previously configured peer. */
	msdp_named_peer_disable(&peer->peer_data);

	/* No more entries in the list. */
	if (ae == NULL) {
		if (PIM_DEBUG_MSDP_EVENTS)
			zlog_debug("MSDP peer %s: no new addresses",
				   peer->list_name);
		return;
	}

	/* Create new peer according to IP protocol. */
	switch (ae->ae_ip.ipa_type) {
	case IPADDR_V4:
		if (pim_msdp_peer_find(peer->pim, ae->ae_ip.ip._v4_addr)) {
			zlog_info(
				"MSDP peer %s address %pI4 not created because another configured peer is already using it",
				peer->list_name, &ae->ae_ip.ip._v4_addr);
			return;
		}

		if (PIM_DEBUG_MSDP_EVENTS)
			zlog_debug("MSDP peer %s new address: %pI4",
				   peer->list_name, &ae->ae_ip.ip._v4_addr);

		/* Higher IP address is listener */
		peer->peer_data.peer = ae->ae_ip.ip._v4_addr;
		pim_inet4_dump("<peer?>", peer->peer_data.peer,
			       peer->peer_data.key_str,
			       sizeof(peer->peer_data.key_str));
		if (ntohl(peer->peer_data.local.s_addr) >
		    ntohl(peer->peer_data.peer.s_addr))
			peer->peer_data.flags = PIM_MSDP_PEERF_LISTENER;
		else
			peer->peer_data.flags = 0;
		break;

	case IPADDR_NONE:
		/* Peer disabled, no address. */
		if (PIM_DEBUG_MSDP_EVENTS)
			zlog_debug("MSDP peer %s no address", peer->list_name);
		return;

	case IPADDR_V6:
	default:
		if (PIM_DEBUG_MSDP_EVENTS)
			zlog_debug(
				"MSDP peer %s new address: unsupported family %d",
				peer->list_name, ae->ae_ip.ipa_type);
		return;
	}

	strlcpy(peer->peer_data.last_reset, "-",
		sizeof(peer->peer_data.last_reset));

	/* insert into misc tables for easy access */
	hash_get(peer->pim->msdp.peer_hash, &peer->peer_data,
		 hash_alloc_intern);
	listnode_add_sort(peer->pim->msdp.peer_list, &peer->peer_data);

	if (PIM_DEBUG_MSDP_EVENTS) {
		zlog_debug("MSDP peer %s started", peer->list_name);
		pim_msdp_peer_state_chg_log(&peer->peer_data);
	}

	/* fireup the connect state machine */
	if (PIM_MSDP_PEER_IS_LISTENER(&peer->peer_data))
		pim_msdp_peer_listen(&peer->peer_data);
	else
		pim_msdp_peer_connect(&peer->peer_data);
}

struct pim_msdp_peer *
pim_msdp_named_peer_new(struct pim_instance *pim,
			const struct in_addr *local_address,
			const char *list_name, const char *mesh_group_name)
{
	struct msdp_named_peer *peer;
	struct address_list *address_list;

	/* Required to start MSDP peers. */
	pim_msdp_enable(pim);

	peer = XCALLOC(MTYPE_PIM_MSDP_NAMED_PEER, sizeof(*peer));
	peer->pim = pim;
	peer->local_address = *local_address;
	strlcpy(peer->list_name, list_name, sizeof(peer->list_name));
	peer->peer_data.fd = -1;
	peer->peer_data.auth_listen_sock = -1;
	peer->peer_data.pim = pim;
	peer->peer_data.ibuf = stream_new(PIM_MSDP_MAX_PACKET_SIZE);
	peer->peer_data.obuf = stream_fifo_new();
	peer->peer_data.named_peer = peer;
	SLIST_INSERT_HEAD(&pim->msdp_named_peer_list, peer, entry);

	address_list = address_list_lookup(list_name);
	if (address_list && address_list->al_selected)
		msdp_named_peer_toggle(peer, address_list->al_selected);

	return &peer->peer_data;
}

void pim_msdp_named_peer_free(struct pim_msdp_peer *msdp_peer)
{
	struct msdp_named_peer *peer = msdp_peer->named_peer;

	assert(peer != NULL);

	SLIST_REMOVE(&msdp_peer->pim->msdp_named_peer_list, peer,
		     msdp_named_peer, entry);

	msdp_named_peer_disable(msdp_peer);

	if (msdp_peer->ibuf)
		stream_free(msdp_peer->ibuf);
	if (msdp_peer->obuf)
		stream_fifo_free(msdp_peer->obuf);

	XFREE(MTYPE_PIM_MSDP_AUTH_KEY, msdp_peer->auth_key);
	XFREE(MTYPE_PIM_MSDP_MG_NAME, msdp_peer->mesh_group_name);
	XFREE(MTYPE_PIM_MSDP_NAMED_PEER, peer);
}

static int pim_next_address(const struct address_list *al,
			    const struct address_entry *ae)
{
	struct vrf *vrf;

	if (PIM_DEBUG_MSDP_EVENTS) {
		if (ae != NULL) {
			switch (ae->ae_ip.ipa_type) {
			case IPADDR_V4:
				zlog_debug("address list %s update: %pI4",
					   al->al_name, &ae->ae_ip.ip._v4_addr);
				break;
			case IPADDR_V6:
				zlog_debug("address list %s update: %pI6",
					   al->al_name, &ae->ae_ip.ip._v6_addr);
				break;

			case IPADDR_NONE:
			default:
				zlog_err("invalid address type %d",
					 ae->ae_ip.ipa_type);
				return 0;
			}
		} else {
			zlog_debug("address list %s is now empty", al->al_name);
		}
	}

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		struct pim_instance *pim = vrf->info;
		struct msdp_named_peer *peer;

		SLIST_FOREACH (peer, &pim->msdp_named_peer_list, entry) {
			if (strcmp(peer->list_name, al->al_name))
				continue;

			msdp_named_peer_toggle(peer, ae);
		}
	}

	return 0;
}

void pim_address_list_init(void)
{
	hook_register(address_entry_next, pim_next_address);
}
