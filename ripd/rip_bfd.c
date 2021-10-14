/*
 * RIP BFD integration.
 *
 * Copyright (C) 2021 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
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

#include "lib/zclient.h"
#include "lib/bfd.h"

#include "ripd/ripd.h"
#include "ripd/rip_bfd.h"
#include "ripd/rip_debug.h"

extern struct zclient *zclient;

static const char *rip_bfd_interface_profile(struct rip_interface *ri)
{
	struct rip *rip = ri->rip;

	if (ri->bfd.profile)
		return ri->bfd.profile;

	if (rip->default_bfd_profile)
		return rip->default_bfd_profile;

	return NULL;
}

static void rip_bfd_session_change(struct bfd_session_params *bsp,
				   const struct bfd_session_status *bss,
				   void *arg)
{
	struct rip_peer *rp = arg;

	/* BFD peer went down. */
	if (bss->state == BFD_STATUS_DOWN
	    && bss->previous_state == BFD_STATUS_UP) {
		if (IS_RIP_DEBUG_EVENT)
			zlog_debug("%s: peer %pI4: BFD Down", __func__,
				   &rp->addr);

		listnode_delete(rp->rip->peer_list, rp);
		rip_peer_free(rp);
		return;
	}

	/* BFD peer went up. */
	if (bss->state == BSS_UP && bss->previous_state == BSS_DOWN)
		if (IS_RIP_DEBUG_EVENT)
			zlog_debug("%s: peer %pI4: BFD Up", __func__,
				   &rp->addr);
}

void rip_bfd_session_update(struct rip_peer *rp)
{
	struct rip_interface *ri = rp->ri;

	/* BFD configuration was removed. */
	if (!ri->bfd.enabled) {
		bfd_sess_free(&rp->bfd_session);
		return;
	}

	/* New BFD session. */
	if (rp->bfd_session == NULL) {
		rp->bfd_session = bfd_sess_new(rip_bfd_session_change, rp);
		bfd_sess_set_ipv4_addrs(rp->bfd_session, NULL, &rp->addr);
		bfd_sess_set_interface(rp->bfd_session, ri->ifp->name);
		bfd_sess_set_vrf(rp->bfd_session, rp->rip->vrf->vrf_id);
	}

	/* Set new configuration. */
	bfd_sess_set_timers(rp->bfd_session, BFD_DEF_DETECT_MULT,
			    BFD_DEF_MIN_RX, BFD_DEF_MIN_TX);
	bfd_sess_set_profile(rp->bfd_session, rip_bfd_interface_profile(ri));

	bfd_sess_install(rp->bfd_session);
}

void rip_bfd_interface_update(struct rip_interface *ri)
{
	struct rip *rip;
	struct rip_peer *rp;
	struct listnode *node;

	rip = ri->rip;
	if (!rip)
		return;

	for (ALL_LIST_ELEMENTS_RO(rip->peer_list, node, rp)) {
		if (rp->ri != ri)
			continue;

		rip_bfd_session_update(rp);
	}
}

void rip_bfd_instance_update(struct rip *rip)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (rip->vrf, ifp) {
		struct rip_interface *ri;

		ri = ifp->info;
		if (!ri)
			continue;

		rip_bfd_interface_update(ri);
	}
}

void rip_bfd_init(struct thread_master *tm)
{
	bfd_protocol_integration_init(zclient, tm);
}
