/*
 * PIM southbound implementation.
 * Copyright (C) 2021-2023 Network Education Foundation
 *                         Rafael Zalamena
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "lib/zebra.h"

#include <linux/mroute.h>
#include <sys/un.h>

#include <err.h>
#include <stdbool.h>

#include "lib/checksum.h"
#include "lib/lib_errors.h"
#include "lib/printfrr.h"
#include "lib/network.h"
#include "lib/sockopt.h"
#include "lib/stream.h"
#include "lib/zclient.h"
#include "lib/zlog.h"
#include "pimd/pimd.h"
#include "pimd/pim_errors.h"
#include "pimd/pim_iface.h"
#include "pimd/pim_igmp.h"
#include "pimd/pim_igmp_packet.h"
#include "pimd/pim_igmpv3.h"
#include "pimd/pim_instance.h"
#include "pimd/pim_neighbor.h"
#include "pimd/pim_join.h"
#include "pimd/pim_pim.h"
#include "pimd/pim_register.h"
#include "pimd/pim_sock.h"
#include "pimd/pim_southbound.h"
#include "pimd/pim_ssm.h"
#include "pimd/pim_static.h"
#include "pimd/pim_time.h"
#include "pimd/pim_nht.h"

/** Global variable to keep state of user implemented southbound. */
bool pim_southbound_enabled;

static struct zclient *zclient;
static const struct in_addr ia_zero;

/* IGMP global data. */
static int igmp_fd = -1;
static struct thread *igmp_read_ev;

/* PIM global data. */
static int pim_fd = -1;
static struct thread *pim_read_ev;

/** PIM southbound client for server mode. */
struct pimsb_client {
	/** Peer socket. */
	int sock;
	/** Input events. */
	struct thread *in_ev;
	/** Output events. */
	struct thread *out_ev;
	/** Connection start event. */
	struct thread *connstart_ev;

	/** Peer message buffer. */
	char msgbuf[256];
	/** Bytes available. */
	size_t msgbuf_available;
};

/** PIM southbound server information for client mode */
struct pimsb_server {
	/** Listening socket for server mode. */
	int listening_socket;
	/** Listening event. */
	struct thread *listening_ev;
	/** Reuse PIM client context for server. */
	struct pimsb_client client;
};

/** PIM southbound context information. */
struct pimsb_ctx {
	/*
	 * PIM southbound can operate in two ways:
	 *  - Server mode (accepts only one connection a time)
	 *  - Client mode (connects to a server)
	 */
	union {
		struct pimsb_server server;
		struct pimsb_client client;
	};
	/** Client/server indicator. */
	bool is_server;
	/** Listening/connect address. */
	struct sockaddr_storage ss;
	/** Address length. */
	socklen_t sslen;
};

static struct pimsb_ctx pimsb_ctx;

/*
 * FPM handling.
 */

/** Get interface of the best path to source. */
void pimsb_set_input_interface(struct channel_oil *oil)
{
	struct pim_upstream *upstream = oil->up;
	struct interface *ifp;
	struct rp_info *rp;
	int32_t rp_if = 0;
	bool i_am_rp = false;
	bool has_rp_if = false;
	bool star_source = false;
	bool use_notifif = false;
	struct prefix p = {};
	struct pim_nexthop pn = {};

	/* Figure out what part of the topology we are. */
	star_source = oil->oil.mfcc_origin.s_addr == INADDR_ANY;
	i_am_rp = pim_rp_i_am_rp(oil->pim, oil->oil.mfcc_mcastgrp);

	/* Figure out RP information. */
	p.family = AF_INET;
	p.prefixlen = 32;
	p.u.prefix4.s_addr = oil->oil.mfcc_mcastgrp.s_addr;
	rp = pim_rp_find_match_group(oil->pim, &p);
	if (rp && rp->rp.source_nexthop.interface) {
		has_rp_if = true;
		rp_if = rp->rp.source_nexthop.interface->ifindex;
	}

	/*
	 * Set input interface:
	 * 1. If RP and star source, then don't set input interface.
	 * 2. Use special index when `pimreg`.
	 * 3. `MAXVIFS` means no interface.
	 * 4. If PIM decided to use its own RP interface and we are RP, then
	 *    use `pimreg` (also see item (2)).
	 * 5. Otherwise use what PIM decided.
	 */
	if ((i_am_rp && star_source) || oil->oil.mfcc_parent == 0)
		oil->iif.ifindex = PIM_REG_IF_IDX;
	else if (oil->oil.mfcc_parent == system_maxvifs())
		oil->iif.ifindex = 0;
	else {
		ifp = pim_if_find_by_vif_index(oil->pim, oil->oil.mfcc_parent);
		oil->iif.ifindex = ifp ? ifp->ifindex : PIM_REG_IF_IDX;
		if (i_am_rp && has_rp_if && rp_if == oil->iif.ifindex)
			oil->iif.ifindex = PIM_REG_IF_IDX;
	}

	/*
	 * Notification interface must be used when we want to know
	 * that we are receiving multicast data on the specified
	 * interface.
	 *
	 * SG(*,G) does not need to watch for multicast data.
	 */
	if (!star_source && has_rp_if &&
	    (i_am_rp || oil->iif.ifindex == 0 || rp_if == oil->iif.ifindex))
		use_notifif = true;

	/* We need more information to process further. */
	if (upstream == NULL)
		return;

	/* Handle RP special cases. */
	if (i_am_rp) {
		/*
		 * If no traffic has been seen yet, then set notification
		 * interface instead of input interface.
		 */
		if (!(upstream->flags & PIM_UPSTREAM_FLAG_MASK_DATA_START) &&
		    oil->iif.ifindex != PIM_REG_IF_IDX) {
			oil->notifif.ifindex = oil->iif.ifindex;
			oil->iif.ifindex = 0;
		}
	}

	/* Don't use notification interface. */
	if (!use_notifif) {
		oil->notifif.ifindex = 0;
		return;
	}

	/* Figure out the SPT path. */
	if (pim_nexthop_lookup(oil->pim, &pn, oil->oil.mfcc_origin, 0) &&
	    oil->iif.ifindex != pn.interface->ifindex)
		oil->notifif.ifindex = pn.interface->ifindex;
	else
		oil->notifif.ifindex = 0;
}

static void pimsb_debug_oil(const struct channel_oil *oil)
{
	struct interface *ifp;
	int index;
	char line[128];
	char buf[512];

	zlog_debug("OIL[installed:%d rescan:%d size:%d refcount:%d]",
		   oil->installed, oil->oil_inherited_rescan, oil->oil_size,
		   oil->oil_ref_count);
	for (index = 0; index < system_maxvifs(); index++) {
		if (oil->oif_flags[index] == 0)
			continue;

		ifp = pim_if_find_by_vif_index(oil->pim, index);
		if (ifp == NULL)
			snprintf(buf, sizeof(buf),
				 "  IF[index:%d flags:", index);
		else
			snprintf(buf, sizeof(buf),
				 "  IF[index:%d name:%s flags:", index,
				 ifp->name);

		if (oil->oif_flags[index] & PIM_OIF_FLAG_PROTO_GM)
			strlcat(buf, " GM", sizeof(buf));
		if (oil->oif_flags[index] & PIM_OIF_FLAG_PROTO_PIM)
			strlcat(buf, " PIM", sizeof(buf));
		if (oil->oif_flags[index] & PIM_OIF_FLAG_PROTO_STAR)
			strlcat(buf, " STAR", sizeof(buf));
		if (oil->oif_flags[index] & PIM_OIF_FLAG_PROTO_VXLAN)
			strlcat(buf, " VXLAN", sizeof(buf));
		strlcat(buf, "]", sizeof(buf));
		zlog_debug("%s", buf);
	}

	snprintfrr(buf, sizeof(buf), "  MFC(%pI4,%pI4)[iif:%d,",
		   &oil->oil.mfcc_origin, &oil->oil.mfcc_mcastgrp,
		   oil->oil.mfcc_parent);
	for (index = 0; index < system_maxvifs(); index++) {
		if (oil->oil.mfcc_ttls[index] == 0)
			continue;

		ifp = pim_if_find_by_vif_index(oil->pim, index);
		if (ifp == NULL)
			snprintf(line, sizeof(line), "X(%d:X:ttl=%d),", index,
				 oil->oil.mfcc_ttls[index]);
		else
			snprintf(line, sizeof(line), "%s(%d,%d,ttl=%d),",
				 ifp->name, index, ifp->ifindex,
				 oil->oil.mfcc_ttls[index]);
		strlcat(buf, line, sizeof(buf));
	}
	zlog_debug("%s]", buf);
}

static void pimsb_debug_upstream(const struct pim_upstream *up)
{
	struct pim_ifchannel *ch;
	struct listnode *node;
	char buf[1024];

	snprintfrr(
		buf, sizeof(buf),
		"UP[up:%pI4 register:%pI4 sg:%s join:%d reg:%d spt:%d flags:",
		&up->upstream_addr, &up->upstream_register, up->sg_str,
		up->join_state, up->reg_state, up->sptbit);

#define PRINT_FLAG(flag, str)                                                  \
	do {                                                                   \
		if (up->flags & (flag))                                        \
			strlcat(buf, str ",", sizeof(buf));                    \
	} while (0)
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED, "DR_JOIN_DESIRED");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED,
		   "DR_JOIN_DESIRED_UPDATED");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_FHR, "FHR");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_IGMP, "SRC_IGMP");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_PIM, "SRC_PIM");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_STREAM, "SRC_STREAM");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_MSDP, "SRC_MSDP");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SEND_SG_RPT_PRUNE,
		   "SEND_SG_RPT_PRUNE");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_LHR, "SRC_LHR");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_STATIC_IIF, "STATIC_IIF");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_ALLOW_IIF_IN_OIL, "ALLOW_IIF_IN_OIL");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_NO_PIMREG_DATA, "NO_PIMREG_DATA");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_FORCE_PIMREG, "FORCE_PIMREG");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_ORIG, "SRC_VXLAN_ORIG");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_TERM, "SRC_VXLAN_TERM");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_MLAG_VXLAN, "MLAG_VXLAN");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_MLAG_NON_DF, "MLAG_NON_DF");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_MLAG_PEER, "MLAG_PEER");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE, "SRC_NOCACHE");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_USE_RPT, "USE_RPT");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE, "MLAG_INTERFACE");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED, "SPT_DESIRED");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_DATA_START, "DATA_START");
	zlog_debug("%s]", buf);
	zlog_debug("  RPF[if:%s nh:%pFX rpf_addr:%pFX]",
		   up->rpf.source_nexthop.interface != NULL
			   ? up->rpf.source_nexthop.interface->name
			   : "unknown",
		   &up->rpf.source_nexthop.mrib_nexthop_addr,
		   &up->rpf.rpf_addr);

	for (ALL_LIST_ELEMENTS_RO(up->ifchannels, node, ch)) {
		buf[0] = 0;
		PRINT_FLAG(PIM_IF_FLAG_MASK_COULD_ASSERT, "COULD_ASSERT");
		PRINT_FLAG(PIM_IF_FLAG_MASK_ASSERT_TRACKING_DESIRED,
			   "ASSERT_TRACKING_DESIRED");
		PRINT_FLAG(PIM_IF_FLAG_MASK_S_G_RPT, "S_G_RPT");
		PRINT_FLAG(PIM_IF_FLAG_MASK_PROTO_PIM, "PROTO_PIM");
		PRINT_FLAG(PIM_IF_FLAG_MASK_PROTO_IGMP, "PROTO_IGMP");
		zlog_debug(
			"  SOURCE[sg:%s if:%s join:%d assert:%d winner:%pI4 flags:%s]",
			ch->sg_str,
			ch->interface ? ch->interface->name : "unknown",
			ch->ifjoin_state, ch->ifassert_state,
			&ch->ifassert_winner, buf);
	}
#undef PRINT_FLAG

	if (PIM_UPSTREAM_FLAG_TEST_USE_RPT(up->flags)) {
		if (up->parent)
			pimsb_debug_upstream(up->parent);
		else
			zlog_debug("%s:  no upstream parent, but USE_RPT set",
				   __func__);
	}
}

void pimsb_mroute_do(struct channel_oil *oil, bool install)
{
	struct pim_upstream *upstream = oil->up;
	struct pim_interface *pim_ifp;
	struct channel_if *oif;
	struct interface *ifp;
	struct rp_info *rp;
	struct stream *s;
	size_t oif_count_pos;
	size_t oif_count;
	bool i_am_rp = false;
	bool i_am_fhr = false;
	bool i_am_lhr = false;
	bool i_am_mhr = false;
	bool has_rp_if = false;
	bool is_static = false;
	bool has_pimreg = false;
	bool star_source = false;
	uint32_t route_flags = 0;
	uint32_t spt_threshold = 0;
	struct prefix p = {};
	char intf[128];
	char oifs[2048];

	if (PIM_DEBUG_MROUTE) {
		zlog_backtrace(LOG_DEBUG);
		pimsb_debug_oil(oil);
		if (upstream)
			pimsb_debug_upstream(upstream);
	}

	/* Treat IGMP joined routes as static. */
	if (upstream != NULL &&
	    (upstream->flags & PIM_UPSTREAM_FLAG_MASK_SRC_IGMP))
		is_static = true;

	/* Figure out what part of the topology we are. */
	star_source = oil->oil.mfcc_origin.s_addr == INADDR_ANY;
	i_am_rp = pim_rp_i_am_rp(oil->pim, oil->oil.mfcc_mcastgrp);
	if (upstream) {
		i_am_lhr = !!(upstream->flags &
			      (PIM_UPSTREAM_FLAG_MASK_SRC_LHR |
			       PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED));
		i_am_fhr = PIM_UPSTREAM_FLAG_TEST_FHR(upstream->flags);
	}

	i_am_mhr = !i_am_lhr && !i_am_rp && !i_am_fhr;

	/* Figure out RP information. */
	p.family = AF_INET;
	p.prefixlen = 32;
	p.u.prefix4.s_addr = oil->oil.mfcc_mcastgrp.s_addr;
	rp = pim_rp_find_match_group(oil->pim, &p);
	if (rp != NULL && rp->rp.source_nexthop.interface != NULL &&
	    rp->rp.source_nexthop.interface->info != NULL)
		has_rp_if = true;

	/* Generate flags based on detected information. */
	if (!is_static && !star_source && !i_am_mhr)
		route_flags |= MRT_FLAG_RESTART_DL_TIMER;

	/*
	 * SPT only matters for LHR (the router which receives the IGMP join),
	 * however since we don't know about LHR status in star route until
	 * it is too late we'll check for not FHR and not RP.
	 *
	 * Intermediary routers do not create star route so it shouldn't be
	 * a problem.
	 */
	if (!i_am_fhr && !i_am_rp && star_source &&
	    oil->spt_threshold < PIM_SPT_THRESH_NEVER) {
		route_flags |= MRT_FLAG_JOIN_SPT_ALLOWED;
		spt_threshold = oil->spt_threshold;
	}
	if (!is_static && (oil->oif_list_count == 0 || oil->filtered))
		route_flags |= MRT_FLAG_DUMMY | MRT_FLAG_DL_TIMER;

	/*
	 * Handle special case: RP and FHR.
	 *
	 * If there is a upstream to send traffic but it has not yet joined
	 * the stream then don't attempt to send any traffic.
	 */
	if (i_am_rp && upstream &&
	    upstream->join_state == PIM_UPSTREAM_NOTJOINED)
		route_flags |= MRT_FLAG_DUMMY | MRT_FLAG_DL_TIMER;

	/*
	 * Disable data plane notification to remove dummy route if no
	 * input interface is configured.
	 */
	if (oil->iif.ifindex == 0)
		route_flags &= ~MRT_FLAG_DL_TIMER;

	/*
	 * Multicast route internal communication format:
	 *  - 2 bytes: Action (0: install, 1: delete).
	 *  - 2 bytes: address family.
	 *  - X bytes: IP(v4|v6) source address.
	 *  - X bytes: IP(v4|v6) group address.
	 *  - 4 bytes: input interface.
	 *  - 4 bytes: RPF interface.
	 *  - 2 byte: flags.
	 *  - 2 bytes: output interface amount.
	 *  - 4 * X bytes: output interface array.
	 *  - 4 bytes: SPT threshould.
	 *  - X bytes: IP(v4|v6) local address.
	 *  - X bytes: IP(v4|v6) remote address.
	 */
	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_MROUTE_EVENT, oil->pim->vrf->vrf_id);
	stream_putw(s, install ? 0 : 1);
	stream_putw(s, AF_INET);
	stream_putl(s, oil->oil.mfcc_origin.s_addr);
	stream_putl(s, oil->oil.mfcc_mcastgrp.s_addr);

	/* Input interface. */
	stream_putl(s, oil->iif.ifindex);
	/* Notification interface. */
	stream_putl(s, oil->notifif.ifindex);

	/* Multicast route flags. */
	stream_putw(s, route_flags);

	/* Output interface amount. */
	oif_count_pos = stream_get_endp(s);
	stream_putw(s, 0);

	/* Output interfaces. */
	oif_count = 0;
	if (!oil->filtered) {
		SLIST_FOREACH (oif, &oil->oif_list, entry) {
			if (oif->ifindex == PIM_REG_IF_IDX)
				has_pimreg = true;

			stream_putl(s, oif->ifindex);
			oif_count++;
		}
	}

	stream_putw_at(s, oif_count_pos, oif_count);

	/* SPT threshold. */
	stream_putl(s, spt_threshold);

	/* Interface address in the way to the RP. */
	if (has_pimreg && has_rp_if) {
		pim_ifp = rp->rp.source_nexthop.interface->info;
		/* Interface address in the way to the RP. */
		stream_putl(s, pim_ifp->primary_address.s_addr);
	} else
		stream_putl(s, ia_zero.s_addr);

	/* Remote RP address. */
	if (has_pimreg && has_rp_if) {
		stream_putl(s, rp->rp.rpf_addr.s_addr);
		upstream->sb_register_to = rp->rp.rpf_addr;
	} else {
		stream_putl(s, ia_zero.s_addr);
		upstream->sb_register_to = ia_zero;
	}

	stream_putw_at(s, 0, (uint16_t)stream_get_endp(s));
	zclient_send_message(zclient);

	if (PIM_DEBUG_MROUTE) {
		oifs[0] = 0;
		SLIST_FOREACH (oif, &oil->oif_list, entry) {
			if (oif->ifindex == PIM_REG_IF_IDX) {
				snprintf(intf, sizeof(intf), "pimreg(%d),",
					 oif->ifindex);
				strlcat(oifs, intf, sizeof(oifs));
				continue;
			}

			ifp = if_lookup_by_index(oif->ifindex,
						 oil->pim->vrf->vrf_id);
			snprintf(intf, sizeof(intf), "%s(%d),",
				 ifp ? ifp->name : "?", oif->ifindex);
			strlcat(oifs, intf, sizeof(oifs));
		}
		if (oifs[0])
			oifs[strlen(oifs) - 1] = 0;

		zlog_debug(
			"%s: %s SG(%pI4, %pI4) iif:%d notifif:%d flags:0x%04x OIFS_AMOUNT:%zu OIF:[%s] encap:(local:%pI4, rp:%pI4) rp:%s fhr:%s lhr:%s",
			__func__, install ? "INSTALL" : "DELETE",
			&oil->oil.mfcc_origin, &oil->oil.mfcc_mcastgrp,
			oil->iif.ifindex, 0, route_flags, oif_count, oifs,
			has_pimreg && has_rp_if ? &pim_ifp->primary_address
						: &ia_zero,
			has_pimreg && has_rp_if ? &rp->rp.rpf_addr : &ia_zero,
			i_am_rp ? "yes" : "no", i_am_fhr ? "yes" : "no",
			i_am_lhr ? "yes" : "no");
	}

	/* Update route installation status.  */
	if (install) {
		if (!oil->installed)
			oil->mroute_creation = pim_time_monotonic_sec();

		oil->installed = 1;
	} else
		oil->installed = 0;
}

static void pim_mroute_copy(struct mfcctl_vendor *oil,
			    struct channel_oil *c_oil)
{
	int i;

	oil->mfcc_origin = c_oil->oil.mfcc_origin;
	oil->mfcc_mcastgrp = c_oil->oil.mfcc_mcastgrp;
	oil->mfcc_parent = c_oil->oil.mfcc_parent;

	for (i = 0; i < system_maxvifs(); ++i) {
		if ((oil->mfcc_parent == i) &&
		    !pim_mroute_allow_iif_in_oil(c_oil, i)) {
			oil->mfcc_ttls[i] = 0;
			continue;
		}

		if (c_oil->oif_flags[i] & PIM_OIF_FLAG_MUTE)
			oil->mfcc_ttls[i] = 0;
		else
			oil->mfcc_ttls[i] = c_oil->oil.mfcc_ttls[i];
	}
}

int pimsb_mroute_add(struct channel_oil *c_oil, const char *name)
{
	struct pim_instance *pim = c_oil->pim;
	struct mfcctl_vendor tmp_oil = {};
	int err = 0;

	pim->mroute_add_last = pim_time_monotonic_sec();
	++pim->mroute_add_events;

	/* Copy the oil to a temporary structure to fixup (without need to
	 * later restore) before sending the mroute add to the dataplane
	 */
	pim_mroute_copy(&tmp_oil, c_oil);

	pimsb_mroute_do(c_oil, true);

	if (err) {
		zlog_warn(
			"%s %s: failure: setsockopt(fd=%d,IPPROTO_IP,MRT_ADD_MFC): errno=%d: %s",
			__FILE__, __func__, pim->mroute_socket, errno,
			safe_strerror(errno));
		return -2;
	}

	if (PIM_DEBUG_MROUTE) {
		char buf[2048];
		zlog_debug("%s(%s), vrf %s Added Route: %s", __func__, name,
			   pim->vrf->name,
			   pim_channel_oil_dump(c_oil, buf, sizeof(buf)));
	}

	return 0;
}

int pimsb_mroute_del(struct channel_oil *c_oil, const char *name)
{
	struct pim_instance *pim = c_oil->pim;

	pim->mroute_del_last = pim_time_monotonic_sec();
	++pim->mroute_del_events;

	if (!c_oil->installed) {
		if (PIM_DEBUG_MROUTE) {
			char buffer[2048];
			zlog_debug(
				"%s %s: vifi %d for route is %s not installed, do not need to send del req. ",
				__FILE__, __func__, c_oil->oil.mfcc_parent,
				pim_channel_oil_dump(c_oil, buffer,
						     sizeof(buffer)));
		}
		return -2;
	}

	pimsb_mroute_do(c_oil, false);

	if (PIM_DEBUG_MROUTE) {
		char buffer[2048];

		zlog_debug("%s(%s), vrf %s Deleted Route: %s", __func__, name,
			   pim->vrf->name,
			   pim_channel_oil_dump(c_oil, buffer, sizeof(buffer)));
	}

	return 0;
}

/*
 * IGMP socket.
 */
static void pimsb_igmp_read_cb(struct thread *t);

static void pimsb_igmp_add_read(void)
{
	thread_add_read(router->master, pimsb_igmp_read_cb, NULL, igmp_fd,
			&igmp_read_ev);
}

static bool ipv4_has_router_alert(const uint8_t *packet, size_t packet_length)
{
	const struct ipv4_header *ipv4 = (const struct ipv4_header *)packet;
	size_t header_length = ipv4_header_length(ipv4);

	/* No additional options or packet too short. */
	if ((header_length < 24) || (packet_length < header_length))
		return false;

	/* Check for router alert signature in option. */
	if (packet[20] == 0x94)
		return true;

	return false;
}

void pimsb_packet_read(int sock)
{
	enum ip_encap_packet_assemble_result erv;
	enum ip_packet_assemble_result rv;
	struct pim_interface *pim_ifp;
	struct interface *ifp = NULL;
	const uint8_t *packet;
	struct vrf *vrf;
	size_t packet_length;
	ssize_t bytes_read;
	struct ipv4_encap_result encap_result;
	uint8_t buf[2048];

	/* Attempt to read a whole packet. */
	bytes_read = read(sock, buf, sizeof(buf));
	if (bytes_read == -1) {
		zlog_warn("%s: read: %s", __func__, strerror(errno));
		return;
	}
	if (bytes_read == 0) {
		zlog_warn("%s: read: EOF", __func__);
		return;
	}

	/* Parse the encapsulation. */
	erv = ipv4_encap_parse(buf, bytes_read, &encap_result);
	if (erv != IEPA_OK)
		return;

	/* Skip packets to data plane. */
	if (encap_result.destination == htonl(IPV4_ENCAP_DST))
		return;

	/* Find interface to figure out which VRF it belongs. */
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(encap_result.ifindex, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: could not find interface %d", __func__,
				   encap_result.ifindex);
		return;
	}

	/* Reassemble the packet (if fragmented) and pass it along. */
	rv = ipv4_packet_assemble(&buf[encap_result.encap_length],
				  bytes_read - encap_result.encap_length,
				  &packet, &packet_length);
	switch (rv) {
	case IPA_NOT_FRAGMENTED:
	case IPA_OK:
		break;

	default:
		/* Assembly failed, just quit. */
		return;
	}

	/* Packet assembled, get VRF information and call PIM code. */
	pim_ifp = ifp->info;
	if (pim_ifp)
		(void)pim_mroute_msg(
			pim_ifp->pim, (char *)packet, packet_length,
			encap_result.ifindex,
			ipv4_has_router_alert(packet, packet_length));
	else if (PIM_DEBUG_GM_PACKETS)
		zlog_debug("%s: received packet on disabled interface (%d) %s",
			   __func__, ifp->ifindex, ifp->name);
}

static void pimsb_igmp_read_cb(struct thread *t)
{
	pimsb_packet_read(THREAD_FD(t));
	pimsb_igmp_add_read();
}

static void pimsb_init_igmp(void)
{
	int sock;
	int on = 1;

	frr_with_privs (&pimd_privs) {
		sock = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK,
			      PIM_IP_ENCAP_IGMP);
		if (sock == -1) {
			zlog_err("%s: socket: %s", __func__, strerror(errno));
			return;
		}

		/* Include IP header. */
		if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) ==
		    -1) {
			flog_err(EC_LIB_SOCKET,
				 "Can't set IP_HDRINCL option for fd %d: %s",
				 sock, safe_strerror(errno));
			close(sock);
			return;
		}
	}

	setsockopt_so_sendbuf(sock, 1024 * 1024);
	setsockopt_so_recvbuf(sock, 1024 * 1024);

	igmp_fd = sock;
	pimsb_igmp_add_read();
}

static void pimsb_client_read_cb(struct thread *t);
static void pimsb_client_connect_cb(struct thread *t);
static void pimsb_client_restart(struct pimsb_client *client);

static void pimsb_client_start_connection_cb(struct thread *t)
{
	struct pimsb_client *client = THREAD_ARG(t);
	int rv;

	client->sock =
		socket(pimsb_ctx.ss.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (client->sock == -1) {
		zlog_err("%s: socket: %s", __func__, strerror(errno));
		thread_add_timer(router->master,
				 pimsb_client_start_connection_cb, client, 3,
				 &client->connstart_ev);
		return;
	}

	/* Set 'no delay' (disables nagle algorithm) for IPv4/IPv6. */
	rv = 1;
	if (pimsb_ctx.ss.ss_family != AF_UNIX &&
	    setsockopt(client->sock, IPPROTO_TCP, TCP_NODELAY, &rv,
		       sizeof(rv)) == -1)
		zlog_warn("%s: setsockopt(TCP_NODELAY): %s", __func__,
			  strerror(errno));

	rv = connect(client->sock, (struct sockaddr *)&pimsb_ctx.ss,
		     pimsb_ctx.sslen);
	/* Connection successful, just schedule read. */
	if (rv == 0) {
		thread_add_read(router->master, pimsb_client_read_cb, client,
				client->sock, &client->in_ev);
		return;
	}

	/* Connect failed, handle it according to the failure. */
	if (errno == EAGAIN || errno == EALREADY || errno == EINPROGRESS) {
		thread_add_write(router->master, pimsb_client_connect_cb,
				 client, client->sock, &client->out_ev);
		return;
	}

	close(client->sock);
	client->sock = -1;

	/* Try again later, maybe the server will be available. */
	thread_add_timer(router->master, pimsb_client_start_connection_cb,
			 client, 3, &client->connstart_ev);
}

static void pimsb_client_stop(struct pimsb_client *client)
{
	if (client->sock != -1) {
		close(client->sock);
		client->sock = -1;
	}

	client->msgbuf_available = 0;
	THREAD_OFF(client->in_ev);
	THREAD_OFF(client->out_ev);
	THREAD_OFF(client->connstart_ev);
}

static void pimsb_client_restart(struct pimsb_client *client)
{
	pimsb_client_stop(client);

	/* If server then wait for the next accepted connection. */
	if (pimsb_ctx.is_server)
		return;

	/* If client then try to connect again. */
	thread_add_timer(router->master, pimsb_client_start_connection_cb,
			 client, 3, &client->connstart_ev);
}

static void pimsb_client_connect_cb(struct thread *t)
{
	struct pimsb_client *client = THREAD_ARG(t);
	int rv = 0;
	socklen_t rvlen = sizeof(rv);

	/* Make sure `errno` is reset, then test `getsockopt` success. */
	errno = 0;
	if (getsockopt(client->sock, SOL_SOCKET, SO_ERROR, &rv, &rvlen) == -1)
		rv = -1;

	/* Connection successful. */
	if (rv == 0) {
		thread_add_read(router->master, pimsb_client_read_cb, client,
				client->sock, &client->in_ev);
		return;
	}

	switch (rv) {
	case EINTR:
	case EAGAIN:
	case EALREADY:
	case EINPROGRESS:
		/* non error, wait more. */
		thread_add_write(router->master, pimsb_client_connect_cb,
				 client, client->sock, &client->out_ev);
		return;

	default:
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: connection failed: %s", __func__,
				   strerror(rv));

		pimsb_client_restart(client);
		return;
	}
}

static void pimsb_client_data_start(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct pim_upstream *up;
	struct interface *ifp = NULL;
	struct vrf *vrf;
	int32_t input_index = ntohl(me->iif_idx);
	pim_sgaddr sg_p = {};

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(input_index, vrf->vrf_id);
		if (ifp)
			break;
	}
	pim_ifp = ifp ? ifp->info : NULL;
	if (PIM_DEBUG_MROUTE)
		zlog_debug(
			"%s: DATA_START iif:%d(%s:%s) source:%pI4 group:%pI4",
			__func__, input_index, ifp ? ifp->name : "unknown",
			ifp ? (pim_ifp ? "enabled" : "disabled") : "disabled",
			&me->source.v4, &me->group.v4);
	if (pim_ifp == NULL)
		return;

	sg_p.src = me->source.v4;
	sg_p.grp = me->group.v4;

	/* Handle simplest case first. */
	if (pim_if_connected_to_source(ifp, sg_p.src)) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: source connected (%s, %pI4)", __func__,
				   ifp->name, &sg_p.src);

		if (!(PIM_I_am_DR(pim_ifp))) {
			if (PIM_DEBUG_MROUTE_DETAIL)
				zlog_debug("%s: '%s' is not the DR for %pSG",
					   __func__, ifp->name, &sg_p);

			up = pim_upstream_find_or_add(
				&sg_p, ifp, PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE,
				__func__);
			pim_upstream_mroute_add(up->channel_oil, __func__);
			return;
		}

		up = pim_upstream_find(pim_ifp->pim, &sg_p);
		if (up == NULL)
			up = pim_upstream_add(pim_ifp->pim, &sg_p, ifp,
					      PIM_UPSTREAM_FLAG_MASK_FHR,
					      __func__, NULL);

		PIM_UPSTREAM_FLAG_SET_SRC_STREAM(up->flags);
		up->flags |= PIM_UPSTREAM_FLAG_MASK_DATA_START;
		pim_upstream_keep_alive_timer_start(
			up, pim_ifp->pim->keep_alive_time);

		up->channel_oil->cc.pktcnt++;
		if (up->rpf.source_nexthop.interface != NULL &&
		    up->channel_oil->oil.mfcc_parent >= system_maxvifs())
			pim_upstream_mroute_iif_update(up->channel_oil,
						       __func__);

		pim_register_join(up);
		pim_upstream_inherited_olist_decide(pim_ifp->pim, up);
		pimsb_mroute_do(up->channel_oil, true);
		return;
	}

	/* Figure out what case this is by looking at upstream. */
	up = pim_upstream_find(pim_ifp->pim, &sg_p);
	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: unconnected source (%s, %pI4) %s", __func__,
			   ifp->name, &sg_p.src,
			   up ? (up->flags & PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED)
					   ? "upstream switch"
					   : "upstream no switch"
			      : "no upstream");

	if (up && (up->flags & PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED)) {
		struct pim_neighbor *nbr = NULL;

		/* SPT_DESIRED is holding 1 ref, "transfer" that to SRC_LHR */
		up->flags &= ~PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED;
		up->flags |= PIM_UPSTREAM_FLAG_MASK_SRC_LHR;
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%pSG4: -SPT_DESIRED +SRC_LHR rc=%d",
				   &up->sg, up->ref_count);

		pim_upstream_set_sptbit(up, ifp);
		pim_upstream_update_use_rpt(up, true);
		pim_upstream_inherited_olist_decide(pim_ifp->pim, up);
		pim_upstream_keep_alive_timer_start(
			up, pim_ifp->pim->keep_alive_time);

		/*
		 * Generate the prune message immediately for SG(*,G)
		 * so we only receive traffic from SG(S,G).
		 */
		if (up->parent && up->parent->rpf.source_nexthop.interface) {
			nbr = pim_neighbor_find(
				up->parent->rpf.source_nexthop.interface,
				up->parent->rpf.rpf_addr);
			if (nbr) {
				struct pim_rpf rpf = {};

				rpf.source_nexthop.interface = nbr->interface;
				rpf.rpf_addr = nbr->source_addr;
				pim_joinprune_send(&rpf, nbr->upstream_jp_agg);
			}
		}
		return;
	}

	if (up && (up->flags & PIM_UPSTREAM_FLAG_MASK_SRC_LHR)) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%pSG4: extra DATA_START after SPT switch",
				   &up->sg);
		if (up->sptbit != PIM_UPSTREAM_SPTBIT_TRUE)
			zlog_warn(
				"%pSG4: LHR DATA_START without SPT_DESIRED, and we're not on SPT?",
				&up->sg);
		return;
	}

	if (!up)
		up = pim_upstream_add(pim_ifp->pim, &sg_p, ifp,
				      PIM_UPSTREAM_FLAG_MASK_SRC_PIM, __func__,
				      NULL);
	if (!up)
		return;

	up->flags |= PIM_UPSTREAM_FLAG_MASK_DATA_START;
	up->flags |= PIM_UPSTREAM_FLAG_MASK_USE_RPT;
	pimsb_set_input_interface(up->channel_oil);
	pimsb_mroute_do(up->channel_oil, true);
}

static void pimsb_client_data_stop(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct pim_upstream *up;
	struct interface *ifp = NULL;
	struct vrf *vrf;
	pim_sgaddr sg = {};

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(ntohl(me->iif_idx), vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug(
				"%s: DATA_STOP SG(%pI4, %pI4) interface %d not found",
				__func__, &me->source.v4, &me->group.v4,
				ntohl(me->iif_idx));
		return;
	}

	pim_ifp = ifp->info;
	if (pim_ifp == NULL) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug(
				"%s: DATA_STOP interface %s(%d) not configured",
				__func__, ifp->name, ifp->ifindex);
		return;
	}

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: DATA_STOP interface %d source %pI4 group %pI4",
			   __func__, ntohl(me->iif_idx), &me->source.v4,
			   &me->group.v4);

	sg.src = me->source.v4;
	sg.grp = me->group.v4;
	up = pim_upstream_find(pim_ifp->pim, &sg);
	if (up == NULL) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s:   upstream %pSG not found", __func__,
				   &sg);
		return;
	}

	/* Don't remove routes created by IGMP joins. */
	if (up->flags & PIM_UPSTREAM_FLAG_MASK_SRC_IGMP) {
		zlog_debug("%s:  route not removed due to IGMP join", __func__);
		return;
	}

	/* HACK: make sure reference count is low so it gets deleted. */
	up->ref_count = 1;

	pim_upstream_del(pim_ifp->pim, up, __func__);
}

static void pimsb_client_wrong_if(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct interface *ifp = NULL;
	struct vrf *vrf;
	int32_t input_index = ntohl(me->iif_idx);
	struct igmpmsg im = {};

	im.im_msgtype = IGMPMSG_WRONGVIF;
	im.im_src = me->source.v4;
	im.im_dst = me->group.v4;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(input_index, vrf->vrf_id);
		if (ifp)
			break;
	}
	pim_ifp = ifp ? ifp->info : NULL;
	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: WRONG_IF iif:%d(%s:%s) source:%pI4 group:%pI4",
			   __func__, input_index, ifp ? ifp->name : "unknown",
			   ifp ? (pim_ifp ? "enabled" : "disabled")
			       : "disabled",
			   &me->source.v4, &me->group.v4);

	if (pim_ifp)
		pim_mroute_msg_wrongvif(pim_ifp->pim->mroute_socket, ifp, &im);
}

static void pimsb_client_spt_join(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct pim_upstream *up;
	struct interface *ifp = NULL;
	struct vrf *vrf;
	pim_sgaddr sg_p;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(ntohl(me->iif_idx), vrf->vrf_id);
		if (ifp)
			break;
	}
	pim_ifp = ifp ? ifp->info : NULL;
	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: SPT_JOIN iif:%d(%s:%s) source:%pI4 group:%pI4",
			   __func__, ntohl(me->iif_idx),
			   ifp ? ifp->name : "unknown",
			   ifp ? (pim_ifp ? "enabled" : "disabled")
			       : "disabled",
			   &me->source.v4, &me->group.v4);

	/* Interface not found, quit. */
	if (ifp == NULL || pim_ifp == NULL)
		return;

	sg_p.src = me->source.v4;
	sg_p.grp = me->group.v4;
	up = pim_upstream_add(pim_ifp->pim, &sg_p, NULL,
			      PIM_UPSTREAM_FLAG_MASK_SRC_PIM, __func__, NULL);
	if (!up)
		return;

	/*
	 * pim_upstream_add unconditionally added a ref above.  but the ref
	 * we track here is bound to the SPT_DESIRED flag (otherwise we leak
	 * later)
	 */
	if (up->flags & PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED) {
		assert(up->ref_count >= 2);
		pim_upstream_del(pim_ifp->pim, up, __func__);
	} else
		up->flags |= PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED;

	pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);
	pim_upstream_inherited_olist(pim_ifp->pim, up);
}

/** Parses message buffer and returns whether it can be called again. */
static bool pimsb_client_msg_parse(struct pimsb_client *client)
{
	const struct mroute_event_header *meheader;
	size_t msglen;

	/* Check for minimum amount of data. */
	if (client->msgbuf_available < sizeof(*meheader)) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: header incomplete (%zu of %zu bytes)",
				   __func__, sizeof(*meheader),
				   client->msgbuf_available);
		return false;
	}

	/* Basic header length check. */
	meheader = (const struct mroute_event_header *)client->msgbuf;
	msglen = ntohs(meheader->length);
	if (msglen < sizeof(*meheader)) {
		zlog_err("%s: invalid length %zu", __func__, msglen);
		/*
		 * We've got an invalid message length so all other messages
		 * in this stream will be unaligned or wrong.
		 */
		pimsb_client_restart(client);
		return false;
	}

	/* Check if we've downloaded the whole message. */
	if (msglen > client->msgbuf_available) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: message incomplete (%zu of %zu bytes)",
				   __func__, msglen, client->msgbuf_available);
		return false;
	}

	/* Basic version check. */
	if (meheader->version != MRE_VERSION_V1) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: invalid version %d (skipping message)",
				   __func__, meheader->version);
		goto prepare_next_message;
	}

	switch (meheader->type) {
	case MRT_EVENT_DATA_START:
		pimsb_client_data_start((const struct mroute_event *)meheader);
		break;
	case MRT_EVENT_DATA_STOP:
		pimsb_client_data_stop((const struct mroute_event *)meheader);
		break;
	case MRT_EVENT_WRONG_IF:
		pimsb_client_wrong_if((const struct mroute_event *)meheader);
		break;
	case MRT_EVENT_JOIN_SPT:
		pimsb_client_spt_join((const struct mroute_event *)meheader);
		break;
	case MRT_EVENT_DATA_PACKET:
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: DATA_PACKET: not implemented",
				   __func__);
		break;

	default:
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: unhandled type %d", __func__,
				   meheader->type);
		break;
	}

prepare_next_message:
	/* Move data to the beginning of the buffer and account it. */
	if ((client->msgbuf_available - msglen) > 0)
		memmove(client->msgbuf, client->msgbuf + msglen,
			client->msgbuf_available - msglen);

	client->msgbuf_available -= msglen;
	return client->msgbuf_available > 0;
}

static void pimsb_client_read_cb(struct thread *t)
{
	struct pimsb_client *client = THREAD_ARG(t);
	ssize_t bytes_read;

	bytes_read =
		read(client->sock, client->msgbuf + client->msgbuf_available,
		     sizeof(client->msgbuf) - client->msgbuf_available);
	if (bytes_read == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			goto schedule_and_return;

		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: read: %s", __func__, strerror(errno));

		/* Fatal connection error, don't schedule anymore. */
		pimsb_client_restart(client);
		return;
	}
	if (bytes_read == 0) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: read: connection closed", __func__);

		/* Connection closed, don't schedule anymore. */
		pimsb_client_restart(client);
		return;
	}

	client->msgbuf_available += bytes_read;

	/* Handle data. */
	while (pimsb_client_msg_parse(client))
		/* NOTHING */;

schedule_and_return:
	thread_add_read(router->master, pimsb_client_read_cb, client,
			client->sock, &client->in_ev);
}

static void pimsb_server_wait_cb(struct thread *t)
{
	int sock = THREAD_FD(t);
	int fd;

	/* Accept new connection. */
	fd = accept(sock, NULL, NULL);
	if (fd == -1) {
		zlog_err("%s: accept: %s", __func__, strerror(errno));
		goto schedule_and_return;
	}

	/* Only one client supported at the moment. */
	if (pimsb_ctx.server.client.sock != -1) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: client already connected", __func__);

		close(fd);
		goto schedule_and_return;
	}

	/* Schedule new client read events. */
	pimsb_ctx.server.client.sock = fd;
	thread_add_read(router->master, pimsb_client_read_cb,
			&pimsb_ctx.server.client, fd,
			&pimsb_ctx.server.client.in_ev);

schedule_and_return:
	/* Re-schedule accept connection. */
	thread_add_read(router->master, pimsb_server_wait_cb, NULL, sock,
			&pimsb_ctx.server.listening_ev);
}

static void pimsb_socket_init(const struct sockaddr_storage *ss,
			      socklen_t sslen, bool client)
{
	int sock;

	pim_southbound_enabled = true;

	pimsb_ctx.ss = *ss;
	pimsb_ctx.sslen = sslen;

	if (client) {
		/* Start client socket. */
		zlog_info("initializing PIM southbound (client mode)");
		thread_add_timer(
			router->master, pimsb_client_start_connection_cb,
			&pimsb_ctx.client, 0, &pimsb_ctx.client.connstart_ev);
		return;
	}

	zlog_info("initializing PIM southbound (server mode)");

	/* Start server socket. */
	sock = socket(ss->ss_family, SOCK_STREAM, 0);
	if (sock == -1) {
		zlog_err("%s: socket: %s", __func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (bind(sock, (struct sockaddr *)ss, sslen) == -1) {
		zlog_err("%s: bind: %s", __func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (listen(sock, 1) == -1) {
		zlog_err("%s: listen: %s", __func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Reset server's client data socket value. */
	pimsb_ctx.server.client.sock = -1;

	/* Schedule listening events. */
	thread_add_read(router->master, pimsb_server_wait_cb, NULL, sock,
			&pimsb_ctx.server.listening_ev);

	pimsb_ctx.is_server = true;
}

/*
 * PIM socket.
 */
static void pimsb_pim_packet_read(int sock)
{
	enum ip_encap_packet_assemble_result erv;
	enum ip_packet_assemble_result rv;
	const struct ipv4_header *ipv4;
	struct pim_interface *pim_ifp;
	struct interface *ifp = NULL;
	struct vrf *vrf;
	const uint8_t *packet;
	size_t packet_length;
	ssize_t bytes_read;
	struct ipv4_encap_result encap_result;
	pim_sgaddr addr = {};
	uint8_t buf[2048];

	/* Attempt to read a whole packet. */
	bytes_read = read(sock, buf, sizeof(buf));
	if (bytes_read == -1) {
		zlog_warn("%s: read: %s", __func__, strerror(errno));
		return;
	}
	if (bytes_read == 0) {
		zlog_warn("%s: read: EOF", __func__);
		return;
	}

	/* Parse the encapsulation. */
	erv = ipv4_encap_parse(buf, bytes_read, &encap_result);
	if (erv != IEPA_OK)
		return;

	/* Skip packets to data plane. */
	if (encap_result.destination == htonl(IPV4_ENCAP_DST))
		return;

	/* Reassemble the packet (if fragmented) and pass it along. */
	rv = ipv4_packet_assemble(&buf[encap_result.encap_length],
				  bytes_read - encap_result.encap_length,
				  &packet, &packet_length);
	switch (rv) {
	case IPA_NOT_FRAGMENTED:
	case IPA_OK:
		break;

	default:
		/* Assembly failed, just quit. */
		return;
	}

	/* Find interface to figure out which VRF it belongs. */
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(encap_result.ifindex, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"%s: incoming packet on unknown interface %d",
				__func__, encap_result.ifindex);
		return;
	}

	/* Packet assembled, get VRF information and call PIM code. */
	pim_ifp = ifp->info;

	if (PIM_DEBUG_PIM_PACKETS)
		zlog_debug("%s: incoming pim packet on %s(%d)", __func__,
			   ifp ? ifp->name : "unknown", encap_result.ifindex);

	ipv4 = (const struct ipv4_header *)packet;
	if (if_address_is_local(&ipv4->source, AF_INET, ifp->vrf->vrf_id)) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: incoming packet from myself", __func__);
		return;
	}

	addr.src.s_addr = ipv4->source;
	addr.grp.s_addr = ipv4->destination;
	if (pim_ifp)
		pim_pim_packet(ifp, (uint8_t *)(size_t)packet, packet_length,
			       addr);
}

static void pimsb_pim_add_read(void);

static void pimsb_pim_read_cb(struct thread *t)
{
	pimsb_pim_packet_read(THREAD_FD(t));
	pimsb_pim_add_read();
}

static void pimsb_pim_add_read(void)
{
	thread_add_read(router->master, pimsb_pim_read_cb, NULL, pim_fd,
			&pim_read_ev);
}

static void pimsb_init_pim(void)
{
	int sock;
	int on = 1;

	frr_with_privs (&pimd_privs) {
		sock = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK,
			      PIM_IP_ENCAP_PIM);
		if (sock == -1) {
			zlog_err("%s: socket: %s", __func__, strerror(errno));
			return;
		}

		/* Include IP header. */
		if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) ==
		    -1) {
			flog_err(EC_LIB_SOCKET,
				 "Can't set IP_HDRINCL option for fd %d: %s",
				 sock, safe_strerror(errno));
			close(sock);
			return;
		}
	}

	setsockopt_so_sendbuf(sock, 1024 * 1024);
	setsockopt_so_recvbuf(sock, 1024 * 1024);

	pim_fd = sock;
	pimsb_pim_add_read();
}

/*
 * Exported functions.
 */
void pimsb_init(struct zclient *zc)
{
	/* Keep pointer to zebra client context. */
	zclient = zc;

	pimsb_init_igmp();
	pimsb_init_pim();
}

void pimsb_shutdown(void)
{
	if (pimsb_ctx.is_server) {
		THREAD_OFF(pimsb_ctx.server.listening_ev);
		close(pimsb_ctx.server.listening_socket);
		pimsb_ctx.server.listening_socket = -1;
		pimsb_client_stop(&pimsb_ctx.server.client);
	} else
		pimsb_client_stop(&pimsb_ctx.client);

	THREAD_OFF(igmp_read_ev);
	close(igmp_fd);
	igmp_fd = -1;

	THREAD_OFF(pim_read_ev);
	close(pim_fd);
	pim_fd = -1;
}

ssize_t pimsb_igmp_sendto(const char *ifname, const void *data, size_t datalen,
			  struct sockaddr *sa, socklen_t salen)
{
	struct sockaddr_in *dsin = (struct sockaddr_in *)sa;
	struct pim_interface *pim_ifp;
	struct interface *ifp = NULL;
	struct vrf *vrf;
	ssize_t bytes_sent;
	struct ipv4_encap_params encap_params;
	struct sockaddr_in sin = {};
	struct msghdr msg = {};
	struct iovec iov[3] = {};
	uint8_t ipv4_encap[IPV4_ENCAP_DATA_SIZE] = {};
	struct {
		struct ipv4_header ipv4;
		uint8_t ipv4_options[4];
	} ipv4_data = {};

	/* Get output interface. */
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_name(ifname, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: no interface %s found", __func__,
				   ifname);

		errno = ENOENT;
		return -1;
	}

	/* Generate the IPv4 encapsulation header. */
	pim_ifp = ifp->info;
	encap_params.source = pim_ifp->primary_address.s_addr;
	encap_params.ifindex = ifp->ifindex;
	ipv4_encap_output(&encap_params, &ipv4_encap, datalen);

	/* Generate the IPv4 header. */
	ipv4_set_version(&ipv4_data.ipv4);
	ipv4_set_header_length(&ipv4_data.ipv4, sizeof(ipv4_data));
	ipv4_data.ipv4.tos = 0xC0;
	ipv4_data.ipv4.total_length = htons(sizeof(ipv4_data) + datalen);
	ipv4_data.ipv4.ttl = 1;
	ipv4_data.ipv4.protocol = 2;
	ipv4_data.ipv4.source = pim_ifp->primary_address.s_addr;
	ipv4_data.ipv4.destination = dsin->sin_addr.s_addr;
	ipv4_data.ipv4_options[0] = 148;
	ipv4_data.ipv4_options[1] = 4;
	ipv4_data.ipv4_options[2] = 0;
	ipv4_data.ipv4_options[3] = 0;
	ipv4_data.ipv4.checksum = in_cksum(&ipv4_data, sizeof(ipv4_data));

	/* Send to data plane in loopback. */
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(IPV4_ENCAP_DST);

	msg.msg_name = &sin;
	msg.msg_namelen = sizeof(sin);
	msg.msg_iov = iov;
	msg.msg_iovlen = 3;
	iov[0].iov_base = &ipv4_encap;
	iov[0].iov_len = sizeof(ipv4_encap);
	iov[1].iov_base = &ipv4_data;
	iov[1].iov_len = sizeof(ipv4_data);
	iov[2].iov_base = (void *)(size_t)data;
	iov[2].iov_len = datalen;

	bytes_sent = sendmsg(igmp_fd, &msg, 0);
	if (bytes_sent == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return -1;

		zlog_err("%s: sendmsg: (%d) %s", __func__, errno,
			 strerror(errno));
		return -1;
	} else if (bytes_sent == 0) {
		zlog_err("%s: sendmsg: connection closed", __func__);
		return 0;
	}

	if (PIM_DEBUG_GM_PACKETS)
		zlog_debug("%s: [sent %zd bytes (of %ld) via interface %d]",
			   __func__, bytes_sent,
			   sizeof(ipv4_encap) + sizeof(ipv4_data) + datalen,
			   ifp->ifindex);

	return datalen;
}

/**
 * IGMP join callback: when timer expires it injects an IGMP join packet
 * into the IGMP input path to simulate a local membership to source/group.
 *
 * This callback is called on `pimsb_igmp_join` or when a IGMP general query
 * is sent.
 */
static void pimsb_igmp_join_cb(struct thread *thread)
{
	struct gm_sock *igmp_socket = THREAD_ARG(thread);
	const struct igmp_packet *packet;
	struct igmp_packet_list *packets;
	struct igmp_packet_params *params;

	params = pim_interface_generate_igmp_static_params(
		igmp_socket->interface, true, NULL, NULL);
	packets = igmp_generate_packets(params);
	igmp_join_params_free(params);

	/* IGMP static join was called, but no groups configured. */
	if (packets == NULL)
		return;

	SLIST_FOREACH (packet, packets, entry)
		pim_igmp_packet(igmp_socket, (char *)packet->data, packet->size,
				true);

	igmp_packet_list_free(packets);
}

void pimsb_igmp_join(const struct pim_interface *pim_interface)
{
	struct gm_sock *igmp_socket = pim_igmp_sock_lookup_ifaddr(
		pim_interface->gm_socket_list, pim_interface->primary_address);

	/* This is possible if interface is not multicast enabled. */
	if (igmp_socket == NULL)
		return;

	thread_cancel(&igmp_socket->join_event);
	thread_add_timer(router->master, pimsb_igmp_join_cb, igmp_socket, 0,
			 &igmp_socket->join_event);
}

void pimsb_igmp_leave(const struct pim_interface *pim_interface,
		      const struct in_addr *source, const struct in_addr *group)
{
	struct gm_sock *igmp_socket = pim_igmp_sock_lookup_ifaddr(
		pim_interface->gm_socket_list, pim_interface->primary_address);
	const struct igmp_packet *packet;
	struct igmp_packet_list *packets;
	struct igmp_packet_params *params;

	/* This is possible if interface is not multicast enabled. */
	if (igmp_socket == NULL)
		return;

	params = pim_interface_generate_igmp_static_params(
		igmp_socket->interface, false, source, group);
	packets = igmp_generate_packets(params);
	igmp_join_params_free(params);

	/* IGMP static join was called, but no groups configured. */
	if (packets == NULL)
		return;

	SLIST_FOREACH (packet, packets, entry)
		pim_igmp_packet(igmp_socket, (char *)packet->data, packet->size,
				true);

	igmp_packet_list_free(packets);
}

int pimsb_socket_mcast(int protocol, struct in_addr ifaddr,
		       struct interface *ifp, uint8_t loop)
{
	int blen = 1024 * 1024 * 8;
	int opt = 1;
	int fd;
	long flags = 0;
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr = ifaddr,
	};

	fd = pim_socket_raw(protocol);
	if (fd < 0) {
		zlog_warn("%s: Could not create multicast socket: errno=%d: %s",
			  __func__, errno, safe_strerror(errno));
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		zlog_warn("%s: bind(%pI4): %s", __func__, &ifaddr,
			  safe_strerror(errno));

#if defined(HAVE_IP_PKTINFO)
	/* Linux and Solaris IP_PKTINFO */
	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) == -1)
		zlog_warn("%s: setsockopt(%d, IP_PKTINFO): %s", __func__, fd,
			  safe_strerror(errno));
#elif defined(HAVE_IP_RECVDSTADDR)
	/* BSD IP_RECVDSTADDR */
	if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &opt, sizeof(opt)) == -1)
		zlog_warn("%s: setsockopt(%d, IP_RECVDSTADDR): %s", __func__,
			  fd, safe_strerror(errno));
#endif
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
		zlog_warn("%s: setsockopt(%d, SO_REUSEADDR): %s", __func__, fd,
			  safe_strerror(errno));

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &blen, sizeof(blen)) == -1)
		zlog_warn("%s: setsockopt(%d, SO_RCVBUF, %d): %s", __func__, fd,
			  blen, safe_strerror(errno));

	flags = fcntl(fd, F_GETFL, 0);
	if (flags != -1) {
		if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
			zlog_warn("%s: fcntl(%d, F_SETFL,O_NONBLOCK): %s",
				  __func__, fd, safe_strerror(errno));
	} else
		zlog_warn("%s: fcntl(%d, F_GETFL,O_NONBLOCK): %s", __func__, fd,
			  safe_strerror(errno));

	if (setsockopt_ipv4_tos(fd, IPTOS_PREC_INTERNETCONTROL))
		zlog_warn("%s: setsockopt(%d, IPTOS_PREC_INTERNETCONTROL): %s",
			  __func__, fd, safe_strerror(errno));

	return fd;
}

int pim_socket_get(void)
{
	return pim_fd;
}

int pimsb_mroute_socket_enable(struct pim_instance *pim)
{
	pim->mroute_socket = igmp_fd;
	pim->mroute_socket_creation = pim_time_monotonic_sec();
	return 0;
}

void pimsb_socket_parse(const char *arg)
{
	struct network_address address;

	if (!network_address_parse(arg, &address, PIMSB_DEFAULT_PORT)) {
		zlog_err("PIM southbound initialization: %s", address.error);
		return;
	}

	/* Initialize IP handler. */
	ip_fragmentation_handler_init(router->master);

	/* Initialize BFD data plane listening socket. */
	pimsb_socket_init(&address.address, (socklen_t)address.address_size,
			  !address.listen);
}

void pimsb_msg_send_frame(const struct interface *ifp, const struct ip *ip,
			  const void *msg, const size_t msglen)
{
	struct ipv4_output_params params = {
		.destination = ip->ip_dst.s_addr,
		.source = ip->ip_src.s_addr,
		.protocol = ip->ip_p,
		.tos = ip->ip_tos,
		.socket = pim_socket_get(),
		.ttl = ip->ip_ttl,
		.mtu = ifp ? ifp->mtu : 1500,
		.encap.ifindex = ifp ? ifp->ifindex : 0,
		.encap.source = ip->ip_src.s_addr,
	};

	ipv4_output(&params, msg, msglen);
}

static void pimsb_mrt_iif(struct pim_instance *pim, const struct in_addr group,
			  vifi_t input, char *ifname_out, size_t ifname_len)
{
	struct rp_info *rp = NULL;
	struct interface *ifp;
	struct prefix p = {};

	strlcpy(ifname_out, "<iif?>", ifname_len);

	/* Figure out current input interface. */
	ifp = pim_if_find_by_vif_index(pim, input);
	if (ifp == NULL)
		return;

	/* I'm not RP so it doesn't matter. */
	if (!pim_rp_i_am_rp(pim, group)) {
		strlcpy(ifname_out, ifp->name, ifname_len);
		return;
	}

	/* Look up our RP and see if it matches our interface. */
	p.family = AF_INET;
	p.prefixlen = 32;
	p.u.prefix4 = group;
	rp = pim_rp_find_match_group(pim, &p);

	/* Return PIMREG if it matches our RP interface. */
	if (rp && rp->rp.source_nexthop.interface &&
	    rp->rp.source_nexthop.interface->ifindex == ifp->ifindex)
		strlcpy(ifname_out, "pimreg", ifname_len);
	else
		strlcpy(ifname_out, ifp->name, ifname_len);
}

void pimsb_show_state_json(struct vty *vty, struct pim_instance *pim,
			   const char *src_grp, const char *grp,
			   struct json_object *json)
{
	json_object *json_group = NULL;
	json_object *json_ifp_in = NULL;
	json_object *json_source = NULL;
	json_object *json_ifp_out = NULL;
	struct interface *ifp_out;
	struct channel_oil *oil;
	int oif_idx;
	time_t now;
	bool isRpt;
	bool i_am_rp = false;
	bool i_am_lhr = false;
	char in_ifname[INTERFACE_NAMSIZ + 1];
	char out_ifname[INTERFACE_NAMSIZ + 1];
	char grp_str[INET_ADDRSTRLEN];
	char src_str[INET_ADDRSTRLEN];
	char oif_uptime[16];

	now = pim_time_monotonic_sec();

	frr_each (rb_pim_oil, &pim->channel_oil_head, oil) {
		i_am_rp = pim_rp_i_am_rp(pim, oil->oil.mfcc_mcastgrp);
		if (oil->up)
			i_am_lhr =
				!PIM_UPSTREAM_FLAG_TEST_FHR(oil->up->flags) &&
				!i_am_rp;
		else
			i_am_lhr = false;
		if ((oil->up &&
		     PIM_UPSTREAM_FLAG_TEST_USE_RPT(oil->up->flags)) ||
		    oil->oil.mfcc_origin.s_addr == INADDR_ANY)
			isRpt = true;
		else
			isRpt = false;

		pim_inet4_dump("<group?>", oil->oil.mfcc_mcastgrp, grp_str,
			       sizeof(grp_str));
		pim_inet4_dump("<source?>", oil->oil.mfcc_origin, src_str,
			       sizeof(src_str));
		pimsb_mrt_iif(pim, oil->oil.mfcc_mcastgrp, oil->oil.mfcc_parent,
			      in_ifname, sizeof(in_ifname));

		if (src_grp) {
			if (strcmp(src_grp, src_str) &&
			    strcmp(src_grp, grp_str))
				continue;
			if (grp && strcmp(grp, grp_str))
				continue;
		}

		/* Find the group, create it if it doesn't exist */
		json_object_object_get_ex(json, grp_str, &json_group);

		if (!json_group) {
			json_group = json_object_new_object();
			json_object_object_add(json, grp_str, json_group);
		}

		/* Find the source nested under the group, create it if
		 * it doesn't exist */
		json_object_object_get_ex(json_group, src_str, &json_source);

		if (!json_source) {
			json_source = json_object_new_object();
			json_object_object_add(json_group, src_str,
					       json_source);
		}

		/* Find the inbound interface nested under the source,
		 * create it if it doesn't exist */
		json_object_object_get_ex(json_source, in_ifname, &json_ifp_in);

		if (!json_ifp_in) {
			json_ifp_in = json_object_new_object();
			json_object_object_add(json_source, in_ifname,
					       json_ifp_in);
			json_object_int_add(json_source, "Installed",
					    oil->installed);
			if (isRpt)
				json_object_boolean_true_add(json_source,
							     "isRpt");
			else
				json_object_boolean_false_add(json_source,
							      "isRpt");
			json_object_int_add(json_source, "RefCount",
					    oil->oil_ref_count);
			json_object_int_add(json_source, "OilListSize",
					    oil->oil_size);
			json_object_int_add(json_source, "OilRescan",
					    oil->oil_inherited_rescan);
			json_object_int_add(json_source, "LastUsed",
					    oil->cc.lastused);
			json_object_int_add(json_source, "PacketCount",
					    oil->cc.pktcnt);
			json_object_int_add(json_source, "ByteCount",
					    oil->cc.bytecnt);
			json_object_int_add(json_source, "WrongInterface",
					    oil->cc.wrong_if);
		}

		for (oif_idx = 0; oif_idx < system_maxvifs(); ++oif_idx) {
			if (oil->oil.mfcc_ttls[oif_idx] < 1)
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_idx);
			if (i_am_lhr &&
			    (ifp_out == NULL || ifp_out->ifindex == 0))
				continue;

			pim_time_uptime(oif_uptime, sizeof(oif_uptime),
					now - oil->oif_creation[oif_idx]);

			if (ifp_out)
				strlcpy(out_ifname, ifp_out->name,
					sizeof(out_ifname));
			else
				strlcpy(out_ifname, "<oif?>",
					sizeof(out_ifname));

			json_ifp_out = json_object_new_object();
			json_object_string_add(json_ifp_out, "source", src_str);
			json_object_string_add(json_ifp_out, "group", grp_str);
			json_object_string_add(json_ifp_out, "inboundInterface",
					       in_ifname);
			json_object_string_add(json_ifp_out,
					       "outboundInterface", out_ifname);
			json_object_int_add(json_ifp_out, "installed",
					    oil->installed);
			json_object_string_add(json_ifp_out, "uptime",
					       oif_uptime);

			json_object_object_add(json_ifp_in, out_ifname,
					       json_ifp_out);
		}
	}
}

void pimsb_show_state(struct vty *vty, struct pim_instance *pim,
		      const char *src_grp, const char *grp, bool json_output)
{
	struct interface *ifp_out;
	struct channel_oil *oil;
	bool first_oif;
	int oif_idx;
	time_t now;
	bool isRpt;
	bool i_am_rp = false;
	bool i_am_lhr = false;
	char in_ifname[INTERFACE_NAMSIZ + 1];
	char out_ifname[INTERFACE_NAMSIZ + 1];
	char grp_str[INET_ADDRSTRLEN];
	char src_str[INET_ADDRSTRLEN];
	char oif_uptime[16];

	/* Process JSON output here. */
	if (json_output) {
		struct json_object *json = json_object_new_object();
		pimsb_show_state_json(vty, pim, src_grp, grp, json);
		vty_json(vty, json);
		return;
	}

	now = pim_time_monotonic_sec();

	vty_out(vty,
		"Codes: J -> Pim Join, I -> IGMP Report, S -> Source, * -> Inherited from (*,G), V -> VxLAN, M -> Muted");
	vty_out(vty,
		"\nActive Source           Group            RPT  IIF               OIL\n");

	frr_each (rb_pim_oil, &pim->channel_oil_head, oil) {
		first_oif = true;
		i_am_rp = pim_rp_i_am_rp(pim, oil->oil.mfcc_mcastgrp);
		if (oil->up)
			i_am_lhr =
				!PIM_UPSTREAM_FLAG_TEST_FHR(oil->up->flags) &&
				!i_am_rp;
		else
			i_am_lhr = false;
		if ((oil->up &&
		     PIM_UPSTREAM_FLAG_TEST_USE_RPT(oil->up->flags)) ||
		    oil->oil.mfcc_origin.s_addr == INADDR_ANY)
			isRpt = true;
		else
			isRpt = false;

		pim_inet4_dump("<group?>", oil->oil.mfcc_mcastgrp, grp_str,
			       sizeof(grp_str));
		pim_inet4_dump("<source?>", oil->oil.mfcc_origin, src_str,
			       sizeof(src_str));
		pimsb_mrt_iif(pim, oil->oil.mfcc_mcastgrp, oil->oil.mfcc_parent,
			      in_ifname, sizeof(in_ifname));

		if (src_grp) {
			if (strcmp(src_grp, src_str) &&
			    strcmp(src_grp, grp_str))
				continue;
			if (grp && strcmp(grp, grp_str))
				continue;
		}

		vty_out(vty, "%-6d %-15s  %-15s  %-3s  %-16s  ", oil->installed,
			src_str, grp_str, isRpt ? "y" : "n", in_ifname);

		for (oif_idx = 0; oif_idx < system_maxvifs(); ++oif_idx) {
			if (oil->oil.mfcc_ttls[oif_idx] < 1)
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_idx);
			if (i_am_lhr &&
			    (ifp_out == NULL || ifp_out->ifindex == 0))
				continue;

			pim_time_uptime(oif_uptime, sizeof(oif_uptime),
					now - oil->oif_creation[oif_idx]);

			if (ifp_out)
				strlcpy(out_ifname, ifp_out->name,
					sizeof(out_ifname));
			else
				strlcpy(out_ifname, "<oif?>",
					sizeof(out_ifname));

			if (!first_oif)
				vty_out(vty, ", ");
			else
				first_oif = false;

			vty_out(vty, "%s(%c%c%c%c%c)", out_ifname,
				(oil->oif_flags[oif_idx] &
				 PIM_OIF_FLAG_PROTO_GM)
					? 'I'
					: ' ',
				(oil->oif_flags[oif_idx] &
				 PIM_OIF_FLAG_PROTO_PIM)
					? 'J'
					: ' ',
				(oil->oif_flags[oif_idx] &
				 PIM_OIF_FLAG_PROTO_VXLAN)
					? 'V'
					: ' ',
				(oil->oif_flags[oif_idx] &
				 PIM_OIF_FLAG_PROTO_STAR)
					? '*'
					: ' ',
				(oil->oif_flags[oif_idx] & PIM_OIF_FLAG_MUTE)
					? 'M'
					: ' ');
		}
		vty_out(vty, "\n");
	}
	vty_out(vty, "\n");
}

void pimsb_show_mroute_json(struct vty *vty, struct pim_instance *pim,
			    const pim_sgaddr *sg, struct json_object *json)
{
	json_object *json_ifp_out = NULL;
	json_object *json_source = NULL;
	json_object *json_group = NULL;
	json_object *json_oil = NULL;
	struct static_route *s_route;
	struct interface *ifp_out;
	struct channel_oil *oil, *i_oil;
	struct listnode *node;
	int oif_idx;
	time_t now;
	char oif_uptime[16];
	bool i_am_rp = false;
	bool i_am_lhr = false;
	char mroute_uptime[16];
	char grp_str[INET_ADDRSTRLEN];
	char src_str[INET_ADDRSTRLEN];
	char in_ifname[INTERFACE_NAMSIZ + 1];
	char out_ifname[INTERFACE_NAMSIZ + 1];
	char state_str[PIM_REG_STATE_STR_LEN];
	pim_sgaddr sg_star = {0};

	now = pim_time_monotonic_sec();

	/* print list of PIM and IGMP routes */
	frr_each (rb_pim_oil, &pim->channel_oil_head, oil) {
		pim_sgaddr source_group = {
			.src = oil->oil.mfcc_origin,
			.grp = oil->oil.mfcc_mcastgrp,
		};

		i_am_rp = pim_rp_i_am_rp(pim, oil->oil.mfcc_mcastgrp);
		if (oil->up)
			i_am_lhr =
				!PIM_UPSTREAM_FLAG_TEST_FHR(oil->up->flags) &&
				!i_am_rp;
		else
			i_am_lhr = false;
		if (!oil->installed)
			continue;

		if (sg->grp.s_addr != INADDR_ANY &&
		    sg->grp.s_addr != oil->oil.mfcc_mcastgrp.s_addr)
			continue;
		if (sg->src.s_addr != INADDR_ANY &&
		    sg->src.s_addr != oil->oil.mfcc_origin.s_addr)
			continue;

		pim_inet4_dump("<group?>", oil->oil.mfcc_mcastgrp, grp_str,
			       sizeof(grp_str));
		pim_inet4_dump("<source?>", oil->oil.mfcc_origin, src_str,
			       sizeof(src_str));

		strlcpy(state_str, "S", sizeof(state_str));
		/* When a non DR receives a igmp join, it creates a (*,G)
		 * channel_oil without any upstream creation */
		if (oil->up) {
			if (PIM_UPSTREAM_FLAG_TEST_SRC_IGMP(oil->up->flags))
				strlcat(state_str, "C", sizeof(state_str));
			if (pim_upstream_is_sg_rpt(oil->up))
				strlcat(state_str, "R", sizeof(state_str));
			if (PIM_UPSTREAM_FLAG_TEST_FHR(oil->up->flags))
				strlcat(state_str, "F", sizeof(state_str));
			if (oil->up->sptbit == PIM_UPSTREAM_SPTBIT_TRUE)
				strlcat(state_str, "T", sizeof(state_str));
			if (pim_is_sg_ssm(pim, &source_group))
				strlcat(state_str, "M", sizeof(state_str));
		}
		if (pim_channel_oil_empty(oil))
			strlcat(state_str, "P", sizeof(state_str));

		pimsb_mrt_iif(pim, oil->oil.mfcc_mcastgrp, oil->oil.mfcc_parent,
			      in_ifname, sizeof(in_ifname));
		pim_time_uptime(mroute_uptime, sizeof(mroute_uptime),
				now - oil->mroute_creation);

		/* If we have an inherited OIL for (S,G), we should check
		 * (*,G) for an accurate protocol.
		 */
		sg_star.grp = oil->oil.mfcc_mcastgrp;
		i_oil = pim_find_channel_oil(pim, &sg_star);

		/* Find the group, create it if it doesn't exist */
		json_object_object_get_ex(json, grp_str, &json_group);

		if (!json_group) {
			json_group = json_object_new_object();
			json_object_object_add(json, grp_str, json_group);
		}

		/* Find the source nested under the group, create it if
		 * it doesn't exist
		 */
		json_object_object_get_ex(json_group, src_str, &json_source);

		if (!json_source) {
			json_source = json_object_new_object();
			json_object_object_add(json_group, src_str,
					       json_source);
		}

		/* Find the inbound interface nested under the source,
		 * create it if it doesn't exist */
		json_object_int_add(json_source, "installed", oil->installed);
		json_object_int_add(json_source, "refCount",
				    oil->oil_ref_count);
		json_object_int_add(json_source, "oilSize", oil->oil_size);
		json_object_int_add(json_source, "OilInheritedRescan",
				    oil->oil_inherited_rescan);
		json_object_string_add(json_source, "iif", in_ifname);
		json_object_string_add(json_source, "upTime", mroute_uptime);
		json_object_string_add(json_source, "flags", state_str);
		json_oil = NULL;

		for (oif_idx = 0; oif_idx < system_maxvifs(); ++oif_idx) {
			/* Don't show any output interface if filtered. */
			if (oil->filtered)
				break;

			if (oil->oil.mfcc_ttls[oif_idx] < 1)
				continue;

			/* do not display muted OIFs */
			if (oil->oif_flags[oif_idx] & PIM_OIF_FLAG_MUTE)
				continue;

			if (oil->oil.mfcc_parent == oif_idx &&
			    !pim_mroute_allow_iif_in_oil(oil, oif_idx))
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_idx);
			if (i_am_lhr &&
			    (ifp_out == NULL || ifp_out->ifindex == 0))
				continue;

			if (ifp_out)
				strlcpy(out_ifname, ifp_out->name,
					sizeof(out_ifname));
			else
				strlcpy(out_ifname, "<oif?>",
					sizeof(out_ifname));

			json_ifp_out = json_object_new_object();
			json_object_string_add(json_ifp_out, "source", src_str);
			json_object_string_add(json_ifp_out, "group", grp_str);

			json_object_boolean_add(
				json_ifp_out, "protocolPim",
				oil->oif_flags[oif_idx] &
						PIM_OIF_FLAG_PROTO_PIM ||
					(i_oil &&
					 i_oil->oif_flags[oif_idx] &
						 PIM_OIF_FLAG_PROTO_PIM));

			json_object_boolean_add(
				json_ifp_out, "protocolIgmp",
				oil->oif_flags[oif_idx] &
						PIM_OIF_FLAG_PROTO_GM ||
					(i_oil &&
					 i_oil->oif_flags[oif_idx] &
						 PIM_OIF_FLAG_PROTO_GM));

			json_object_boolean_add(
				json_ifp_out, "protocolVxlan",
				oil->oif_flags[oif_idx] &
						PIM_OIF_FLAG_PROTO_VXLAN ||
					(i_oil &&
					 i_oil->oif_flags[oif_idx] &
						 PIM_OIF_FLAG_PROTO_VXLAN));

			json_object_boolean_add(
				json_ifp_out, "protocolInherited",
				oil->oif_flags[oif_idx] &
					PIM_OIF_FLAG_PROTO_STAR);

			json_object_string_add(json_ifp_out, "inboundInterface",
					       in_ifname);
			json_object_int_add(json_ifp_out, "iVifI",
					    oil->oil.mfcc_parent);
			json_object_string_add(json_ifp_out,
					       "outboundInterface", out_ifname);
			json_object_int_add(json_ifp_out, "oVifI", oif_idx);
			json_object_int_add(json_ifp_out, "ttl",
					    oil->oil.mfcc_ttls[oif_idx]);
			pim_time_uptime(mroute_uptime, sizeof(mroute_uptime),
					now - oil->oif_creation[oif_idx]);
			json_object_string_add(json_ifp_out, "upTime",
					       mroute_uptime);
			if (!json_oil) {
				json_oil = json_object_new_object();
				json_object_object_add(json_source, "oil",
						       json_oil);
			}
			json_object_object_add(json_oil, out_ifname,
					       json_ifp_out);
		}
	}

	for (ALL_LIST_ELEMENTS_RO(pim->static_routes, node, s_route)) {
		i_am_rp = pim_rp_i_am_rp(pim, s_route->group);
		if (s_route->c_oil.up)
			i_am_lhr = !PIM_UPSTREAM_FLAG_TEST_FHR(
					   s_route->c_oil.up->flags) &&
				   !i_am_rp;
		else
			i_am_lhr = false;
		if (!s_route->c_oil.installed)
			continue;

		pim_inet4_dump("<group?>", s_route->group, grp_str,
			       sizeof(grp_str));
		pim_inet4_dump("<source?>", s_route->source, src_str,
			       sizeof(src_str));
		pimsb_mrt_iif(pim, s_route->group, s_route->iif, in_ifname,
			      sizeof(in_ifname));

		/* Find the group, create it if it doesn't exist */
		json_object_object_get_ex(json, grp_str, &json_group);

		if (!json_group) {
			json_group = json_object_new_object();
			json_object_object_add(json, grp_str, json_group);
		}

		/* Find the source nested under the group, create it if
		 * it doesn't exist */
		json_object_object_get_ex(json_group, src_str, &json_source);

		if (!json_source) {
			json_source = json_object_new_object();
			json_object_object_add(json_group, src_str,
					       json_source);
		}

		json_object_string_add(json_source, "iif", in_ifname);
		json_oil = NULL;

		for (oif_idx = 0; oif_idx < system_maxvifs(); ++oif_idx) {
			if (s_route->oif_ttls[oif_idx] < 1)
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_idx);
			if (i_am_lhr &&
			    (ifp_out == NULL || ifp_out->ifindex == 0))
				continue;

			pim_time_uptime(
				oif_uptime, sizeof(oif_uptime),
				now - s_route->c_oil.oif_creation[oif_idx]);

			if (ifp_out)
				strlcpy(out_ifname, ifp_out->name,
					sizeof(out_ifname));
			else
				strlcpy(out_ifname, "<oif?>",
					sizeof(out_ifname));

			json_ifp_out = json_object_new_object();
			json_object_string_add(json_ifp_out, "source", src_str);
			json_object_string_add(json_ifp_out, "group", grp_str);
			json_object_boolean_true_add(json_ifp_out,
						     "protocolStatic");
			json_object_string_add(json_ifp_out, "inboundInterface",
					       in_ifname);
			json_object_int_add(json_ifp_out, "iVifI",
					    s_route->c_oil.oil.mfcc_parent);
			json_object_string_add(json_ifp_out,
					       "outboundInterface", out_ifname);
			json_object_int_add(json_ifp_out, "oVifI", oif_idx);
			json_object_int_add(json_ifp_out, "ttl",
					    s_route->oif_ttls[oif_idx]);
			json_object_string_add(json_ifp_out, "upTime",
					       oif_uptime);
			if (!json_oil) {
				json_oil = json_object_new_object();
				json_object_object_add(json_source, "oil",
						       json_oil);
			}
			json_object_object_add(json_oil, out_ifname,
					       json_ifp_out);
		}
	}
}

void pimsb_show_mroute(struct vty *vty, struct pim_instance *pim,
		       const pim_sgaddr *sg, bool fill, bool json)
{
	struct static_route *s_route;
	struct interface *ifp_out;
	struct channel_oil *oil;
	struct listnode *node;
	int oif_idx;
	bool found_oif;
	bool first;
	time_t now;
	char proto[100];
	char oif_uptime[16];
	bool i_am_rp = false;
	bool i_am_lhr = false;
	char mroute_uptime[16];
	char grp_str[INET_ADDRSTRLEN];
	char src_str[INET_ADDRSTRLEN];
	char in_ifname[INTERFACE_NAMSIZ + 1];
	char out_ifname[INTERFACE_NAMSIZ + 1];
	char state_str[PIM_REG_STATE_STR_LEN];

	if (json) {
		struct json_object *json_parent = json_object_new_object();
		pimsb_show_mroute_json(vty, pim, sg, json_parent);
		vty_json(vty, json_parent);
		return;
	}

	vty_out(vty, "IP Multicast Routing Table\n");
	vty_out(vty, "Flags: S - Sparse, C - Connected, P - Pruned, M - SSM\n");
	vty_out(vty,
		"       R - SGRpt Pruned, F - Register flag, T - SPT-bit set\n");
	vty_out(vty,
		"\nSource          Group           Flags    Proto  Input            Output           TTL  Uptime\n");

	now = pim_time_monotonic_sec();

	/* print list of PIM and IGMP routes */
	frr_each (rb_pim_oil, &pim->channel_oil_head, oil) {
		pim_sgaddr source_group = {
			.src = oil->oil.mfcc_origin,
			.grp = oil->oil.mfcc_mcastgrp,
		};

		first = true;
		found_oif = false;
		i_am_rp = pim_rp_i_am_rp(pim, oil->oil.mfcc_mcastgrp);
		if (oil->up)
			i_am_lhr =
				!PIM_UPSTREAM_FLAG_TEST_FHR(oil->up->flags) &&
				!i_am_rp;
		else
			i_am_lhr = false;
		if (!oil->installed)
			continue;

		if (sg->grp.s_addr != INADDR_ANY &&
		    sg->grp.s_addr != oil->oil.mfcc_mcastgrp.s_addr)
			continue;
		if (sg->src.s_addr != INADDR_ANY &&
		    sg->src.s_addr != oil->oil.mfcc_origin.s_addr)
			continue;

		pim_inet4_dump("<group?>", oil->oil.mfcc_mcastgrp, grp_str,
			       sizeof(grp_str));
		pim_inet4_dump("<source?>", oil->oil.mfcc_origin, src_str,
			       sizeof(src_str));

		strlcpy(state_str, "S", sizeof(state_str));
		/* When a non DR receives a igmp join, it creates a (*,G)
		 * channel_oil without any upstream creation */
		if (oil->up) {
			if (PIM_UPSTREAM_FLAG_TEST_SRC_IGMP(oil->up->flags))
				strlcat(state_str, "C", sizeof(state_str));
			if (pim_upstream_is_sg_rpt(oil->up))
				strlcat(state_str, "R", sizeof(state_str));
			if (PIM_UPSTREAM_FLAG_TEST_FHR(oil->up->flags))
				strlcat(state_str, "F", sizeof(state_str));
			if (oil->up->sptbit == PIM_UPSTREAM_SPTBIT_TRUE)
				strlcat(state_str, "T", sizeof(state_str));
			if (pim_is_sg_ssm(pim, &source_group))
				strlcat(state_str, "M", sizeof(state_str));
		}
		if (pim_channel_oil_empty(oil))
			strlcat(state_str, "P", sizeof(state_str));

		pimsb_mrt_iif(pim, oil->oil.mfcc_mcastgrp, oil->oil.mfcc_parent,
			      in_ifname, sizeof(in_ifname));
		pim_time_uptime(mroute_uptime, sizeof(mroute_uptime),
				now - oil->mroute_creation);

		for (oif_idx = 0; oif_idx < system_maxvifs(); ++oif_idx) {
			/* Don't show any output interface if filtered. */
			if (oil->filtered)
				break;

			if (oil->oil.mfcc_ttls[oif_idx] < 1)
				continue;

			/* do not display muted OIFs */
			if (oil->oif_flags[oif_idx] & PIM_OIF_FLAG_MUTE)
				continue;

			if (oil->oil.mfcc_parent == oif_idx &&
			    !pim_mroute_allow_iif_in_oil(oil, oif_idx))
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_idx);
			if (i_am_lhr &&
			    (ifp_out == NULL || ifp_out->ifindex == 0))
				continue;

			found_oif = true;

			if (ifp_out)
				strlcpy(out_ifname, ifp_out->name,
					sizeof(out_ifname));
			else
				strlcpy(out_ifname, "<oif?>",
					sizeof(out_ifname));

			proto[0] = '\0';
			if (oil->oif_flags[oif_idx] & PIM_OIF_FLAG_PROTO_PIM) {
				strlcpy(proto, "PIM", sizeof(proto));
			}

			if (oil->oif_flags[oif_idx] & PIM_OIF_FLAG_PROTO_GM) {
				strlcpy(proto, "IGMP", sizeof(proto));
			}

			if (oil->oif_flags[oif_idx] &
			    PIM_OIF_FLAG_PROTO_VXLAN) {
				strlcpy(proto, "VxLAN", sizeof(proto));
			}

			if (oil->oif_flags[oif_idx] & PIM_OIF_FLAG_PROTO_STAR) {
				strlcpy(proto, "STAR", sizeof(proto));
			}

			vty_out(vty,
				"%-15s %-15s %-8s %-6s %-16s %-16s %-3d  %8s\n",
				src_str, grp_str, state_str, proto, in_ifname,
				out_ifname, oil->oil.mfcc_ttls[oif_idx],
				mroute_uptime);

			if (first) {
				src_str[0] = '\0';
				grp_str[0] = '\0';
				in_ifname[0] = '\0';
				state_str[0] = '\0';
				mroute_uptime[0] = '\0';
				first = false;
			}
		}

		if (!found_oif) {
			vty_out(vty,
				"%-15s %-15s %-15s %-6s %-16s %-16s %-3d  %8s\n",
				src_str, grp_str, state_str, "none", in_ifname,
				"none", 0, "--:--:--");
		}
	}

	/* Print list of static routes */
	for (ALL_LIST_ELEMENTS_RO(pim->static_routes, node, s_route)) {
		first = true;
		i_am_rp = pim_rp_i_am_rp(pim, s_route->group);
		if (s_route->c_oil.up)
			i_am_lhr = !PIM_UPSTREAM_FLAG_TEST_FHR(
					   s_route->c_oil.up->flags) &&
				   !i_am_rp;
		else
			i_am_lhr = false;
		if (!s_route->c_oil.installed)
			continue;

		pim_inet4_dump("<group?>", s_route->group, grp_str,
			       sizeof(grp_str));
		pim_inet4_dump("<source?>", s_route->source, src_str,
			       sizeof(src_str));
		pimsb_mrt_iif(pim, s_route->group, s_route->iif, in_ifname,
			      sizeof(in_ifname));
		found_oif = false;

		strlcpy(proto, "STATIC", sizeof(proto));

		for (oif_idx = 0; oif_idx < system_maxvifs(); ++oif_idx) {
			if (s_route->oif_ttls[oif_idx] < 1)
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_idx);
			if (i_am_lhr &&
			    (ifp_out == NULL || ifp_out->ifindex == 0))
				continue;

			pim_time_uptime(
				oif_uptime, sizeof(oif_uptime),
				now - s_route->c_oil.oif_creation[oif_idx]);
			found_oif = true;

			if (ifp_out)
				strlcpy(out_ifname, ifp_out->name,
					sizeof(out_ifname));
			else
				strlcpy(out_ifname, "<oif?>",
					sizeof(out_ifname));

			vty_out(vty,
				"%-15s %-15s %-6s %-16s %-16s %-3d  %8s %s\n",
				src_str, grp_str, proto, in_ifname, out_ifname,
				s_route->oif_ttls[oif_idx], oif_uptime,
				pim->vrf->name);
			if (first && !fill) {
				src_str[0] = '\0';
				grp_str[0] = '\0';
				in_ifname[0] = '\0';
				first = false;
			}
		}

		if (!found_oif) {
			vty_out(vty,
				"%-15s %-15s %-6s %-16s %-16s %-3d  %8s %s\n",
				src_str, grp_str, proto, in_ifname, "none", 0,
				"--:--:--", pim->vrf->name);
		}
	}
}
