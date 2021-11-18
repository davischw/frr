/*
 * PIM southbound implementation.
 *
 * Copyright (C) 2021 Network Education Foundation
 *                    Rafael Zalamena
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
#include "pimd/pim_igmpv3.h"
#include "pimd/pim_neighbor.h"
#include "pimd/pim_pim.h"
#include "pimd/pim_register.h"
#include "pimd/pim_sock.h"
#include "pimd/pim_southbound.h"
#include "pimd/pim_static.h"
#include "pimd/pim_time.h"
#include "pimd/pim_nht.h"

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
	else if (oil->oil.mfcc_parent == MAXVIFS)
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
	if (!star_source && has_rp_if
	    && (i_am_rp || oil->iif.ifindex == 0 || rp_if == oil->iif.ifindex))
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
		if (!(upstream->flags & PIM_UPSTREAM_FLAG_MASK_DATA_START)
		    && oil->iif.ifindex != PIM_REG_IF_IDX) {
			oil->notifif.ifindex = oil->iif.ifindex;
			oil->iif.ifindex = 0;
		}

		/*
		 * If upstream has not joined yet, then don't set input
		 * interface.
		 */
		if (upstream->join_state == PIM_UPSTREAM_NOTJOINED)
			oil->iif.ifindex = 0;
	}

	/* Don't use notification interface. */
	if (!use_notifif) {
		oil->notifif.ifindex = 0;
		return;
	}

	/* Figure out the SPT path. */
	if (pim_nexthop_lookup(oil->pim, &pn, oil->oil.mfcc_origin, 0)
	    && oil->iif.ifindex != pn.interface->ifindex)
		oil->notifif.ifindex = pn.interface->ifindex;
	else
		oil->notifif.ifindex = 0;
}

static bool pimsb_mroute_is_static(const struct interface *interface,
				   const struct in_addr *source,
				   const struct in_addr *group)
{
	struct pim_interface *pim_if;
	struct listnode *node;
	struct igmp_join *ij;

	if (interface == NULL)
		return false;

	pim_if = interface->info;
	if (pim_if == NULL || pim_if->igmp_join_list == NULL)
		return false;

	/* Look up for statically configured join. */
	for (ALL_LIST_ELEMENTS_RO(pim_if->igmp_join_list, node, ij)) {
		if (group->s_addr != ij->group_addr.s_addr)
			continue;
		if (source->s_addr != ij->source_addr.s_addr)
			continue;

		return true;
	}

	return false;
}


static bool pimsb_oil_static(const struct channel_oil *oil)
{
	struct channel_if *oif;

	/* Quick case: `ip mroute` was configured. */
	if (oil->is_static)
		return true;

	/* Check for `ip igmp join` configurations. */
	SLIST_FOREACH (oif, &oil->oif_list, entry) {
		struct interface *interface =
			if_lookup_by_index_all_vrf(oif->ifindex);
		if (pimsb_mroute_is_static(interface,
					   &oil->oil.mfcc_origin,
					   &oil->oil.mfcc_mcastgrp))
		    return true;
	}

	return false;
}

static void pimsb_debug_oil(const struct channel_oil *oil)
{
	struct interface *ifp;
	int index;
	char line[128];
	char buf[512];

	zlog_debug("OIL[installed:%d rescan:%d size:%d refcount:%d static:%s]",
		   oil->installed, oil->oil_inherited_rescan, oil->oil_size,
		   oil->oil_ref_count, pimsb_oil_static(oil) ? "Y" : "N");
	for (index = 0; index < MAXVIFS; index++) {
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

		if (oil->oif_flags[index] & PIM_OIF_FLAG_PROTO_IGMP)
			strlcat(buf, " IGMP", sizeof(buf));
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
	for (index = 0; index < MAXVIFS; index++) {
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
	bool is_static = pimsb_oil_static(oil);
	bool has_pimreg = false;
	bool star_source = false;
	uint32_t route_flags = 0;
	uint32_t spt_threshold = 0;
	struct prefix p = {};
	char intf[32];
	char oifs[512];

	if (PIM_DEBUG_MROUTE) {
		zlog_backtrace(LOG_DEBUG);
		pimsb_debug_oil(oil);
		if (upstream)
			pimsb_debug_upstream(upstream);
	}

	/* Treat IGMP joined routes as static. */
	if (is_static == false && upstream != NULL
	    && (upstream->flags & PIM_UPSTREAM_FLAG_MASK_SRC_IGMP))
		is_static = true;

	/* Figure out what part of the topology we are. */
	star_source = oil->oil.mfcc_origin.s_addr == INADDR_ANY;
	i_am_rp = pim_rp_i_am_rp(oil->pim, oil->oil.mfcc_mcastgrp);
	if (upstream) {
		i_am_lhr = !PIM_UPSTREAM_FLAG_TEST_FHR(upstream->flags)
			   && !i_am_rp;
		i_am_fhr = PIM_UPSTREAM_FLAG_TEST_FHR(upstream->flags);
	} else
		i_am_lhr = true;

	i_am_mhr = !i_am_lhr && !i_am_rp && !i_am_fhr;

	/*
	 * Don't install FHR routes if DATA_START has not been set.
	 *
	 * How can this happen? When a PIM router is restarted during a
	 * multicast transmission and the source goes away before it is
	 * started, the other routers in the topology still remember the
	 * source/group and they will send PIM join to this FHR router
	 * causing it to install a multicast route even though multicast
	 * data has never been seen.
	 */
	if (i_am_fhr && install) {
		if (upstream == NULL
		    || !(upstream->flags & PIM_UPSTREAM_FLAG_MASK_DATA_START)) {
			if (PIM_DEBUG_MROUTE)
				zlog_debug(
					"%s: data hasn't started, don't install FHR mroute",
					__func__);
			return;
		}
	}

	/* Figure out RP information. */
	p.family = AF_INET;
	p.prefixlen = 32;
	p.u.prefix4.s_addr = oil->oil.mfcc_mcastgrp.s_addr;
	rp = pim_rp_find_match_group(oil->pim, &p);
	if (rp && rp->rp.source_nexthop.interface)
		has_rp_if = true;

	/* Generate flags based on detected information. */
	if (!is_static && !star_source && !i_am_mhr)
		route_flags |= MRT_FLAG_RESTART_DL_TIMER;
	if (i_am_lhr && star_source
	    && oil->spt_threshold < PIM_SPT_THRESH_NEVER) {
		route_flags |= MRT_FLAG_JOIN_SPT_ALLOWED;
		spt_threshold = oil->spt_threshold;
	}
	if (!is_static && (oil->oif_list_count == 0 || oil->filtered))
		route_flags |= MRT_FLAG_DUMMY | MRT_FLAG_DL_TIMER;

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
	if (has_pimreg && has_rp_if)
		stream_putl(s, rp->rp.rpf_addr.u.prefix4.s_addr);
	else
		stream_putl(s, ia_zero.s_addr);

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

			ifp = if_lookup_by_index_all_vrf(oif->ifindex);
			snprintf(intf, sizeof(intf), "%s(%d),",
				 ifp ? ifp->name : "?", oif->ifindex);
			strlcat(oifs, intf, sizeof(oifs));
		}
		if (oifs[0])
			oifs[strlen(oifs) - 1] = 0;

		zlog_debug(
			"%s: %s SG(%pI4, %pI4) iif:%d notifif:%d flags:0x%04x OIF:[%s] encap:(local:%pI4, rp:%pI4) rp:%s fhr:%s lhr:%s",
			__func__, install ? "INSTALL" : "DELETE",
			&oil->oil.mfcc_origin, &oil->oil.mfcc_mcastgrp,
			oil->iif.ifindex, 0, route_flags, oifs,
			has_pimreg && has_rp_if ? &pim_ifp->primary_address
						: &ia_zero,
			has_pimreg && has_rp_if ? &rp->rp.rpf_addr.u.prefix4
						: &ia_zero,
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

/*
 * IGMP socket.
 */
static int pimsb_igmp_read_cb(struct thread *t);

static void pimsb_igmp_add_read(void)
{
	thread_add_read(router->master, pimsb_igmp_read_cb, NULL, igmp_fd,
			&igmp_read_ev);
}

void pimsb_packet_read(int sock)
{
	enum ip_encap_packet_assemble_result erv;
	enum ip_packet_assemble_result rv;
	struct pim_interface *pim_ifp;
	struct interface *ifp;
	const uint8_t *packet;
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
	ifp = if_lookup_by_index_all_vrf(encap_result.ifindex);
	if (ifp == NULL) {
		if (PIM_DEBUG_IGMP_PACKETS)
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
		(void)pim_mroute_msg(pim_ifp->pim, (char *)packet,
				     packet_length, encap_result.ifindex,
				     false);
	else if (PIM_DEBUG_IGMP_PACKETS)
		zlog_debug("%s: received packet on disabled interface (%d) %s",
			   __func__, ifp->ifindex, ifp->name);
}

static int pimsb_igmp_read_cb(struct thread *t)
{
	pimsb_packet_read(THREAD_FD(t));
	pimsb_igmp_add_read();
	return 0;
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
		if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))
		    == -1) {
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

static int pimsb_client_read_cb(struct thread *t);
static int pimsb_client_connect_cb(struct thread *t);
static void pimsb_client_restart(struct pimsb_client *client);

static int pimsb_client_start_connection_cb(struct thread *t)
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
		return 0;
	}

	/* Set 'no delay' (disables nagle algorithm) for IPv4/IPv6. */
	rv = 1;
	if (pimsb_ctx.ss.ss_family != AF_UNIX
	    && setsockopt(client->sock, IPPROTO_TCP, TCP_NODELAY, &rv,
			  sizeof(rv))
		       == -1)
		zlog_warn("%s: setsockopt(TCP_NODELAY): %s", __func__,
			  strerror(errno));

	rv = connect(client->sock, (struct sockaddr *)&pimsb_ctx.ss,
		     pimsb_ctx.sslen);
	/* Connection successful, just schedule read. */
	if (rv == 0) {
		thread_add_read(router->master, pimsb_client_read_cb, client,
				client->sock, &client->in_ev);
		return 0;
	}

	/* Connect failed, handle it according to the failure. */
	if (errno == EAGAIN || errno == EALREADY || errno == EINPROGRESS) {
		thread_add_write(router->master, pimsb_client_connect_cb,
				 client, client->sock, &client->out_ev);
		return 0;
	}

	close(client->sock);
	client->sock = -1;

	/* Try again later, maybe the server will be available. */
	thread_add_timer(router->master, pimsb_client_start_connection_cb,
			 client, 3, &client->connstart_ev);
	return 0;
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

static int pimsb_client_connect_cb(struct thread *t)
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
		return 0;
	}

	switch (rv) {
	case EINTR:
	case EAGAIN:
	case EALREADY:
	case EINPROGRESS:
		/* non error, wait more. */
		thread_add_write(router->master, pimsb_client_connect_cb,
				 client, client->sock, &client->out_ev);
		return 0;

	default:
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: connection failed: %s", __func__,
				   strerror(rv));

		pimsb_client_restart(client);
		return 0;
	}

	return 0;
}

static void pimsb_client_data_start(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct pim_upstream *up;
	struct interface *ifp;
	struct igmpmsg im = {};
	struct prefix_sg sg_p = {};

	im.im_msgtype = IGMPMSG_NOCACHE;
	im.im_vif = ntohl(me->iif_idx);
	im.im_src = me->source.v4;
	im.im_dst = me->group.v4;

	ifp = if_lookup_by_index_all_vrf(im.im_vif);
	pim_ifp = ifp ? ifp->info : NULL;
	if (PIM_DEBUG_MROUTE)
		zlog_debug(
			"%s: DATA_START iif:%d(%s:%s) source:%pI4 group:%pI4",
			__func__, im.im_vif, ifp ? ifp->name : "unknown",
			ifp ? (pim_ifp ? "enabled" : "disabled") : "disabled",
			&me->source.v4, &me->group.v4);
	if (pim_ifp == NULL)
		return;

	sg_p.family = AF_INET;
	sg_p.prefixlen = 32;
	sg_p.src.s_addr = me->source.v4.s_addr;
	sg_p.grp.s_addr = me->group.v4.s_addr;

	/* Handle simplest case first. */
	if (pim_if_connected_to_source(ifp, sg_p.src)) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: source connected (%s, %pI4)", __func__,
				   ifp->name, &sg_p.src);

		if (!(PIM_I_am_DR(pim_ifp))) {
			if (PIM_DEBUG_MROUTE_DETAIL)
				zlog_debug("%s: '%s' is not the DR for %pSG4",
					   __func__, ifp->name, &sg_p);

			up = pim_upstream_find_or_add(
				&sg_p, ifp, PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE,
				__func__);
			pim_upstream_mroute_add(up->channel_oil, __func__);
			return;
		}

		up = pim_upstream_find_or_add(
			&sg_p, ifp, PIM_UPSTREAM_FLAG_MASK_FHR, __func__);
		PIM_UPSTREAM_FLAG_SET_SRC_STREAM(up->flags);
		up->flags |= PIM_UPSTREAM_FLAG_MASK_DATA_START;
		pim_upstream_keep_alive_timer_start(
			up, pim_ifp->pim->keep_alive_time);

		up->channel_oil->cc.pktcnt++;
		if (up->rpf.source_nexthop.interface != NULL
		    && up->channel_oil->oil.mfcc_parent >= MAXVIFS)
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
	} else if (up) {
		up->flags |= PIM_UPSTREAM_FLAG_MASK_DATA_START;
		pimsb_set_input_interface(up->channel_oil);
		pimsb_mroute_do(up->channel_oil, true);
		pim_upstream_switch(pim_ifp->pim, up, PIM_UPSTREAM_NOTJOINED);
	} else
		pim_upstream_add(pim_ifp->pim, &sg_p, ifp,
				 PIM_UPSTREAM_FLAG_MASK_SRC_PIM, __func__,
				 NULL);
}

static void pimsb_client_data_stop(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct pim_upstream *up;
	struct interface *ifp;
	struct prefix_sg sg = {};

	ifp = if_lookup_by_index_all_vrf(ntohl(me->iif_idx));
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

	sg.family = AF_INET;
	sg.prefixlen = 32;
	sg.src = me->source.v4;
	sg.grp = me->group.v4;
	up = pim_upstream_find(pim_ifp->pim, &sg);
	if (up == NULL) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s:   upstream %pSG4 not found", __func__,
				   &sg);
		return;
	}

	/* Don't remove routes created by IGMP joins. */
	if (up->flags & PIM_UPSTREAM_FLAG_MASK_SRC_IGMP) {
		zlog_debug("%s:  route not removed due to IGMP join",
			   __func__);
		return;
	}

	/* Handle exception of configured routes. */
	if (pimsb_oil_static(up->channel_oil)) {
		zlog_debug("%s:   no routes removed due configuration",
			   __func__);
		return;
	}

	/* HACK: make sure reference count is low so it gets deleted. */
	up->ref_count = 1;

	pim_upstream_del(pim_ifp->pim, up, __func__);
}

static void pimsb_client_wrong_if(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct interface *ifp;
	struct igmpmsg im = {};

	im.im_msgtype = IGMPMSG_WRONGVIF;
	im.im_vif = ntohl(me->iif_idx);
	im.im_src = me->source.v4;
	im.im_dst = me->group.v4;

	ifp = if_lookup_by_index_all_vrf(im.im_vif);
	pim_ifp = ifp ? ifp->info : NULL;
	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: WRONG_IF iif:%d(%s:%s) source:%pI4 group:%pI4",
			   __func__, im.im_vif, ifp ? ifp->name : "unknown",
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
	struct interface *ifp;
	struct prefix_sg sg_p = {};

	ifp = if_lookup_by_index_all_vrf(ntohl(me->iif_idx));
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

	sg_p.family = AF_INET;
	sg_p.prefixlen = 32;
	sg_p.src.s_addr = me->source.v4.s_addr;
	sg_p.grp.s_addr = me->group.v4.s_addr;
	up = pim_upstream_add(pim_ifp->pim, &sg_p, NULL,
			      PIM_UPSTREAM_FLAG_MASK_SRC_PIM
				      | PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED,
			      __func__, NULL);
	if (!up)
		return;

	pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);
	pim_upstream_inherited_olist(pim_ifp->pim, up);
}

static void pimsb_client_msg_parse(struct pimsb_client *client)
{
	const struct mroute_event_header *meheader;
	size_t msglen;

	/* Check for minimum amount of data. */
	if (client->msgbuf_available < sizeof(*meheader))
		return;

	meheader = (const struct mroute_event_header *)client->msgbuf;
	/* Basic version check. */
	if (meheader->version != MRE_VERSION_V1) {
		zlog_err("%s: invalid version %d", __func__, meheader->version);
		return;
	}

	/* Basic header length check. */
	msglen = ntohs(meheader->length);
	if (msglen < sizeof(*meheader)) {
		zlog_err("%s: invalid length %zu", __func__, msglen);
		return;
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

	/* Move data to the beginning of the buffer and account it. */
	memmove(client->msgbuf, client->msgbuf + msglen,
		client->msgbuf_available - msglen);
	client->msgbuf_available -= msglen;
}

static int pimsb_client_read_cb(struct thread *t)
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
		return 0;
	}
	if (bytes_read == 0) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: read: connection closed", __func__);

		/* Connection closed, don't schedule anymore. */
		pimsb_client_restart(client);
		return 0;
	}

	client->msgbuf_available += bytes_read;

	/* Handle data. */
	pimsb_client_msg_parse(client);

schedule_and_return:
	thread_add_read(router->master, pimsb_client_read_cb, client,
			client->sock, &client->in_ev);
	return 0;
}

static int pimsb_server_wait_cb(struct thread *t)
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
	return 0;
}

static void pimsb_socket_init(const struct sockaddr_storage *ss,
			      socklen_t sslen, bool client)
{
	int sock;

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

static uint16_t parse_port(const char *str)
{
	char *nulbyte;
	long rv;

	errno = 0;
	rv = strtol(str, &nulbyte, 10);
	/* No conversion performed. */
	if (rv == 0 && errno == EINVAL) {
		fprintf(stderr, "invalid PIM data plane address port: %s\n",
			str);
		exit(0);
	}
	/* Invalid number range. */
	if ((rv <= 0 || rv >= 65535) || errno == ERANGE) {
		fprintf(stderr, "invalid PIM data plane port range: %s\n", str);
		exit(0);
	}
	/* There was garbage at the end of the string. */
	if (*nulbyte != 0) {
		fprintf(stderr, "invalid PIM data plane port: %s\n", str);
		exit(0);
	}

	return (uint16_t)rv;
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
	struct interface *ifp;
	const uint8_t *packet;
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
	ifp = if_lookup_by_index_all_vrf(encap_result.ifindex);
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
	if (if_address_is_local(&ipv4->source, AF_INET, ifp->vrf_id)) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: incoming packet from myself", __func__);
		return;
	}

	if (pim_ifp)
		pim_pim_packet(ifp, (uint8_t *)(size_t)packet, packet_length);
}

static void pimsb_pim_add_read(void);

static int pimsb_pim_read_cb(struct thread *t)
{
	pimsb_pim_packet_read(THREAD_FD(t));
	pimsb_pim_add_read();
	return 0;
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
		if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))
		    == -1) {
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

static void pimsb_igmp_action(struct interface *ifp, struct in_addr *source,
			      struct in_addr *group, bool join)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct igmp_sock *igmp;
	struct listnode *node;
	char src_str[INET_ADDRSTRLEN];

	/* Find IGMP socket associated with the interface. */
	for (ALL_LIST_ELEMENTS_RO(pim_ifp->igmp_socket_list, node, igmp))
		if (igmp->ifaddr.s_addr == pim_ifp->primary_address.s_addr)
			break;

	if (igmp == NULL) {
		if (PIM_DEBUG_IGMP_EVENTS)
			zlog_debug(
				"%s: IGMP %s SG(%s, %pI4) interface %s: failed (not configured)",
				__func__, join ? "join" : "leave", src_str,
				group, ifp->name);
		return;
	}

	/* Use interface as source if not specified. */
	if (source->s_addr == INADDR_NONE)
		source = &pim_ifp->primary_address;

	if (PIM_DEBUG_IGMP_EVENTS) {
		pim_inet4_dump("<src?>", *source, src_str, sizeof(src_str));
		zlog_debug("%s: IGMP %s SG(%s,%pI4) interface %s", __func__,
			   join ? "join" : "leave", src_str, group, ifp->name);
	}

	/* Join/leave source/group from multicast route. */
	if (join)
		igmpv3_report_allow(igmp, pim_ifp->primary_address, *group, 1,
				    source);
	else
		igmpv3_report_block(igmp, pim_ifp->primary_address, *group, 1,
				    source);
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
	struct interface *ifp;
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
	ifp = if_lookup_by_name_all_vrf(ifname);
	if (ifp == NULL) {
		if (PIM_DEBUG_IGMP_PACKETS)
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

	if (PIM_DEBUG_IGMP_PACKETS)
		zlog_debug("%s: [sent %zd bytes (of %ld) via interface %d]",
			   __func__, bytes_sent,
			   sizeof(ipv4_encap) + sizeof(ipv4_data) + datalen,
			   ifp->ifindex);

	return datalen;
}

void pimsb_igmp_join(struct interface *ifp, struct in_addr *source,
		     struct in_addr *group)
{
	pimsb_igmp_action(ifp, source, group, true);
}

void pimsb_igmp_leave(struct interface *ifp, struct in_addr *source,
		      struct in_addr *group)
{
	pimsb_igmp_action(ifp, source, group, false);
}

bool pimsb_igmp_sg_is_static(const struct igmp_source *source,
			     const struct igmp_group *group)
{
	return pimsb_mroute_is_static(group->interface, &source->source_addr,
				      &group->group_addr);
}

int pimsb_msg_send_frame(const struct pimsb_pim_args *args)
{
	size_t data_size;
	size_t remaining;
	size_t payload_size;
	size_t fragment_offset;
	ssize_t bytes_sent;
	struct ipv4_header *ipv4;
	struct ipv4_encap_header *ipv4e;
	const struct ipv4_header *ipv4_old;
	const uint8_t *data_start;
	uint16_t more_fragments;
	struct ipv4_encap_params encap_params;
	struct msghdr msg = {};
	struct iovec iov[2] = {};
	struct sockaddr_in sin = {};
	uint8_t packet_headers[128];

	/* Point to data locations. */
	ipv4_old = (const struct ipv4_header *)args->data;
	data_start = args->data + ipv4_header_length(ipv4_old);
	ipv4e = (struct ipv4_encap_header *)packet_headers;
	ipv4 = (struct ipv4_header *)(&packet_headers[sizeof(*ipv4e)]);

	/* Copy the previous IPv4 header for reutilization. */
	memcpy(ipv4, args->data, ipv4_header_length(ipv4_old));

	/* MTU is assumed to be 1500. */
	payload_size = 1500 - sizeof(*ipv4);
	payload_size = payload_size - (payload_size % 8);

	/* Fill IPv4 encapsulation parameters. */
	encap_params.source = args->source;
	encap_params.ifindex = args->ifindex;

	/* Fill destination parameter. */
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(IPV4_ENCAP_DST);
	msg.msg_name = &sin;
	msg.msg_namelen = sizeof(sin);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	fragment_offset = 0;
	remaining = args->datalen - ipv4_header_length(ipv4);

	if (PIM_DEBUG_PIM_PACKETS)
		zlog_debug("%s: [send %zu bytes to %pI4 interface %d (MTU %d)]",
			   __func__, args->datalen, &sin.sin_addr,
			   args->ifindex, 1500);

	while (remaining) {
		if (remaining > payload_size) {
			data_size = payload_size;
			more_fragments = IPV4_MORE_FRAGMENTS;
		} else {
			data_size = remaining;
			more_fragments = 0;
		}

		ipv4_encap_output(&encap_params, ipv4e,
				  ipv4_header_length(ipv4) + data_size);
		ipv4->fragmentation = htons(more_fragments
					    | (uint16_t)(fragment_offset >> 3));
		ipv4->total_length =
			htons((uint16_t)(sizeof(*ipv4) + data_size));
		ipv4->checksum = 0;
		ipv4->checksum =
			(uint16_t)in_cksum(ipv4, ipv4_header_length(ipv4));

		iov[0].iov_base = packet_headers;
		iov[0].iov_len = sizeof(*ipv4e) + ipv4_header_length(ipv4);
		/* XXX: double cast hack to workaround `const` warning. */
		iov[1].iov_base =
			(void *)(size_t)(data_start + fragment_offset);
		iov[1].iov_len = data_size;

		bytes_sent = sendmsg(pim_fd, &msg, 0);
		if (bytes_sent == -1) {
			if (errno == EINTR || errno == EAGAIN
			    || errno == EWOULDBLOCK)
				continue;

			zlog_warn("%s: sendmsg: %s", __func__, strerror(errno));
			return -1;
		}
		if (bytes_sent == 0) {
			zlog_warn("%s: sendmsg: connection closed", __func__);
			return -1;
		}

		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"%s:   [id %d fragment 0x%04zx%s] written %zd (of %zu) bytes",
				__func__, ntohs(ipv4->id), fragment_offset,
				more_fragments ? "" : " final", bytes_sent,
				iov[0].iov_len + iov[1].iov_len);

		remaining -= data_size;
	}

	return 0;
}

int pim_socket_mcastloop_get(int fd __attribute__((unused)))
{
	return 0;
}

int pim_socket_mcast(int protocol, struct in_addr ifaddr, struct interface *ifp,
		     uint8_t loop)
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

void pim_sock_delete(struct interface *ifp, const char *delete_message)
{
	struct pim_interface *pim_ifp = ifp->info;

	zlog_info("PIM INTERFACE DOWN: on interface %s: %s", ifp->name,
		  delete_message);

	if (!ifp->info) {
		flog_err(EC_PIM_CONFIG,
			 "%s: %s: but PIM not enabled on interface %s (!)",
			 __func__, delete_message, ifp->name);
		return;
	}

	/*
	  RFC 4601: 4.3.1.  Sending Hello Messages

	  Before an interface goes down or changes primary IP address, a Hello
	  message with a zero HoldTime should be sent immediately (with the
	  old IP address if the IP address changed).
	*/
	pim_hello_send(ifp, 0 /* zero-sec holdtime */);

	pim_neighbor_delete_all(ifp, delete_message);

	if (PIM_DEBUG_PIM_TRACE) {
		if (pim_ifp->t_pim_hello_timer) {
			zlog_debug(
				"Cancelling PIM hello timer for interface %s",
				ifp->name);
		}
	}
	THREAD_OFF(pim_ifp->t_pim_hello_timer);

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug("Deleting PIM socket fd=%d on interface %s",
			   pim_ifp->pim_sock_fd, ifp->name);
	}

	pim_ifp->pim_sock_fd = -1;
	pim_ifp->pim_sock_creation = 0;
}

int pim_mroute_socket_enable(struct pim_instance *pim)
{
	pim->mroute_socket = igmp_fd;
	pim->mroute_socket_creation = pim_time_monotonic_sec();
	return 0;
}

int pim_mroute_add_vif(struct interface *ifp, struct in_addr ifaddr,
		       unsigned char flags)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: Add Vif %d (%s[%s])", __func__,
			   pim_ifp->mroute_vif_index, ifp->name,
			   pim_ifp->pim->vrf->name);

	return 0;
}

int pim_mroute_del_vif(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: Del Vif %d (%s[%s])", __func__,
			   pim_ifp->mroute_vif_index, ifp->name,
			   pim_ifp->pim->vrf->name);

	return 0;
}

struct igmp_sock *pim_igmp_sock_add(struct list *igmp_sock_list,
				    struct in_addr ifaddr,
				    struct interface *ifp, bool mtrace_only)
{
	struct igmp_sock *igmp;

	igmp = igmp_sock_new(-1, ifaddr, ifp, mtrace_only);
	listnode_add(igmp_sock_list, igmp);

	return igmp;
}

void pimsb_socket_parse(const char *arg)
{
	char *sptr, *saux;
	bool is_client = false;
	size_t slen;
	socklen_t salen;
	char addr[64];
	char type[64];
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr_storage ss;
		struct sockaddr_un sun;
	} sa;

	/* Basic parsing: find ':' to figure out type part and address part. */
	sptr = strchr(arg, ':');
	if (sptr == NULL) {
		fprintf(stderr, "invalid PIM data plane socket: %s\n", arg);
		exit(1);
	}

	/* Calculate type string length. */
	slen = (size_t)(sptr - arg);

	/* Copy the address part. */
	sptr++;
	strlcpy(addr, sptr, sizeof(addr));

	/* Copy type part. */
	strlcpy(type, arg, slen + 1);

	/* Reset address data. */
	memset(&sa, 0, sizeof(sa));

	/* Fill the address information. */
	if (strcmp(type, "unix") == 0 || strcmp(type, "unixc") == 0) {
		if (strcmp(type, "unixc") == 0)
			is_client = true;

		salen = sizeof(sa.sun);
		sa.sun.sun_family = AF_UNIX;
		strlcpy(sa.sun.sun_path, addr, sizeof(sa.sun.sun_path));
	} else if (strcmp(type, "ipv4") == 0 || strcmp(type, "ipv4c") == 0) {
		if (strcmp(type, "ipv4c") == 0)
			is_client = true;

		salen = sizeof(sa.sin);
		sa.sin.sin_family = AF_INET;

		/* Parse port if any. */
		sptr = strchr(addr, ':');
		if (sptr == NULL) {
			sa.sin.sin_port = htons(PIMSB_DEFAULT_PORT);
		} else {
			*sptr = 0;
			sa.sin.sin_port = htons(parse_port(sptr + 1));
		}

		if (inet_pton(AF_INET, addr, &sa.sin.sin_addr) != 1)
			errx(1, "%s: inet_pton: invalid address %s", __func__,
			     addr);
	} else if (strcmp(type, "ipv6") == 0 || strcmp(type, "ipv6c") == 0) {
		if (strcmp(type, "ipv6c") == 0)
			is_client = true;

		salen = sizeof(sa.sin6);
		sa.sin6.sin6_family = AF_INET6;

		/* Check for IPv6 enclosures '[]' */
		sptr = &addr[0];
		if (*sptr != '[')
			errx(1, "%s: invalid IPv6 address format: %s", __func__,
			     addr);

		saux = strrchr(addr, ']');
		if (saux == NULL)
			errx(1, "%s: invalid IPv6 address format: %s", __func__,
			     addr);

		/* Consume the '[]:' part. */
		slen = saux - sptr;
		memmove(addr, addr + 1, slen);
		addr[slen - 1] = 0;

		/* Parse port if any. */
		saux++;
		sptr = strrchr(saux, ':');
		if (sptr == NULL) {
			sa.sin6.sin6_port = htons(PIMSB_DEFAULT_PORT);
		} else {
			*sptr = 0;
			sa.sin6.sin6_port = htons(parse_port(sptr + 1));
		}

		if (inet_pton(AF_INET6, addr, &sa.sin6.sin6_addr) != 1)
			errx(1, "%s: inet_pton: invalid address %s", __func__,
			     addr);
	} else {
		fprintf(stderr, "invalid PIM data plane socket type: %s\n",
			type);
		exit(1);
	}

	/* Initialize BFD data plane listening socket. */
	pimsb_socket_init(&sa.ss, salen, is_client);
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

static void pimsb_show_state_json(struct vty *vty, struct pim_instance *pim,
				  const char *src_grp, const char *grp)
{
	json_object *json = NULL;
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
	json = json_object_new_object();

	frr_each (rb_pim_oil, &pim->channel_oil_head, oil) {
		i_am_rp = pim_rp_i_am_rp(pim, oil->oil.mfcc_mcastgrp);
		i_am_lhr =
			!PIM_UPSTREAM_FLAG_TEST_FHR(oil->up->flags) && !i_am_rp;
		if ((oil->up && PIM_UPSTREAM_FLAG_TEST_USE_RPT(oil->up->flags))
		    || oil->oil.mfcc_origin.s_addr == INADDR_ANY)
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
			if (strcmp(src_grp, src_str)
			    && strcmp(src_grp, grp_str))
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

		for (oif_idx = 0; oif_idx < MAXVIFS; ++oif_idx) {
			if (oil->oil.mfcc_ttls[oif_idx] < 1)
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_idx);
			if (i_am_lhr
			    && (ifp_out == NULL || ifp_out->ifindex == 0))
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

			json_object_object_add(json_ifp_in, out_ifname,
					       json_ifp_out);
		}
	}

	vty_out(vty, "%s\n",
		json_object_to_json_string_ext(json, JSON_C_TO_STRING_PRETTY));
	json_object_free(json);
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
		pimsb_show_state_json(vty, pim, src_grp, grp);
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
		i_am_lhr =
			!PIM_UPSTREAM_FLAG_TEST_FHR(oil->up->flags) && !i_am_rp;
		if ((oil->up && PIM_UPSTREAM_FLAG_TEST_USE_RPT(oil->up->flags))
		    || oil->oil.mfcc_origin.s_addr == INADDR_ANY)
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
			if (strcmp(src_grp, src_str)
			    && strcmp(src_grp, grp_str))
				continue;
			if (grp && strcmp(grp, grp_str))
				continue;
		}

		vty_out(vty, "%-6d %-15s  %-15s  %-3s  %-16s  ", oil->installed,
			src_str, grp_str, isRpt ? "y" : "n", in_ifname);

		for (oif_idx = 0; oif_idx < MAXVIFS; ++oif_idx) {
			if (oil->oil.mfcc_ttls[oif_idx] < 1)
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_idx);
			if (i_am_lhr
			    && (ifp_out == NULL || ifp_out->ifindex == 0))
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
				(oil->oif_flags[oif_idx]
				 & PIM_OIF_FLAG_PROTO_IGMP)
					? 'I'
					: ' ',
				(oil->oif_flags[oif_idx]
				 & PIM_OIF_FLAG_PROTO_PIM)
					? 'J'
					: ' ',
				(oil->oif_flags[oif_idx]
				 & PIM_OIF_FLAG_PROTO_VXLAN)
					? 'V'
					: ' ',
				(oil->oif_flags[oif_idx]
				 & PIM_OIF_FLAG_PROTO_STAR)
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

static void pimsb_show_mroute_json(struct vty *vty, struct pim_instance *pim,
				   struct prefix_sg *sg)
{
	json_object *json_ifp_out = NULL;
	json_object *json_source = NULL;
	json_object *json_group = NULL;
	json_object *json_oil = NULL;
	json_object *json = NULL;
	struct static_route *s_route;
	struct interface *ifp_out;
	struct channel_oil *oil;
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

	now = pim_time_monotonic_sec();
	json = json_object_new_object();

	/* print list of PIM and IGMP routes */
	frr_each (rb_pim_oil, &pim->channel_oil_head, oil) {
		i_am_rp = pim_rp_i_am_rp(pim, oil->oil.mfcc_mcastgrp);
		i_am_lhr =
			!PIM_UPSTREAM_FLAG_TEST_FHR(oil->up->flags) && !i_am_rp;
		if (!oil->installed)
			continue;

		if (sg->grp.s_addr != INADDR_ANY
		    && sg->grp.s_addr != oil->oil.mfcc_mcastgrp.s_addr)
			continue;
		if (sg->src.s_addr != INADDR_ANY
		    && sg->src.s_addr != oil->oil.mfcc_origin.s_addr)
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
		}
		if (pim_channel_oil_empty(oil))
			strlcat(state_str, "P", sizeof(state_str));

		pimsb_mrt_iif(pim, oil->oil.mfcc_mcastgrp, oil->oil.mfcc_parent,
			      in_ifname, sizeof(in_ifname));
		pim_time_uptime(mroute_uptime, sizeof(mroute_uptime),
				now - oil->mroute_creation);

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

		for (oif_idx = 0; oif_idx < MAXVIFS; ++oif_idx) {
			/* Don't show any output interface if filtered. */
			if (oil->filtered)
				break;

			if (oil->oil.mfcc_ttls[oif_idx] < 1)
				continue;

			/* do not display muted OIFs */
			if (oil->oif_flags[oif_idx] & PIM_OIF_FLAG_MUTE)
				continue;

			if (oil->oil.mfcc_parent == oif_idx
			    && !pim_mroute_allow_iif_in_oil(oil, oif_idx))
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_idx);
			if (i_am_lhr
			    && (ifp_out == NULL || ifp_out->ifindex == 0))
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

			if (oil->oif_flags[oif_idx] & PIM_OIF_FLAG_PROTO_PIM)
				json_object_boolean_true_add(json_ifp_out,
							     "protocolPim");

			if (oil->oif_flags[oif_idx] & PIM_OIF_FLAG_PROTO_IGMP)
				json_object_boolean_true_add(json_ifp_out,
							     "protocolIgmp");

			if (oil->oif_flags[oif_idx] & PIM_OIF_FLAG_PROTO_VXLAN)
				json_object_boolean_true_add(json_ifp_out,
							     "protocolVxlan");

			if (oil->oif_flags[oif_idx] & PIM_OIF_FLAG_PROTO_STAR)
				json_object_boolean_true_add(
					json_ifp_out, "protocolInherited");

			json_object_string_add(json_ifp_out, "inboundInterface",
					       in_ifname);
			json_object_int_add(json_ifp_out, "iVifI",
					    oil->oil.mfcc_parent);
			json_object_string_add(json_ifp_out,
					       "outboundInterface", out_ifname);
			json_object_int_add(json_ifp_out, "oVifI", oif_idx);
			json_object_int_add(json_ifp_out, "ttl",
					    oil->oil.mfcc_ttls[oif_idx]);
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
		i_am_lhr =
			!PIM_UPSTREAM_FLAG_TEST_FHR(oil->up->flags) && !i_am_rp;
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

		for (oif_idx = 0; oif_idx < MAXVIFS; ++oif_idx) {
			if (s_route->oif_ttls[oif_idx] < 1)
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_idx);
			if (i_am_lhr
			    && (ifp_out == NULL || ifp_out->ifindex == 0))
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

	vty_out(vty, "%s\n",
		json_object_to_json_string_ext(json, JSON_C_TO_STRING_PRETTY));
	json_object_free(json);
}

void pimsb_show_mroute(struct vty *vty, struct pim_instance *pim,
		       struct prefix_sg *sg, bool fill, bool json)
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
		pimsb_show_mroute_json(vty, pim, sg);
		return;
	}

	vty_out(vty, "IP Multicast Routing Table\n");
	vty_out(vty, "Flags: S - Sparse, C - Connected, P - Pruned\n");
	vty_out(vty,
		"       R - SGRpt Pruned, F - Register flag, T - SPT-bit set\n");
	vty_out(vty,
		"\nSource          Group           Flags    Proto  Input            Output           TTL  Uptime\n");

	now = pim_time_monotonic_sec();

	/* print list of PIM and IGMP routes */
	frr_each (rb_pim_oil, &pim->channel_oil_head, oil) {
		first = true;
		found_oif = false;
		i_am_rp = pim_rp_i_am_rp(pim, oil->oil.mfcc_mcastgrp);
		i_am_lhr =
			!PIM_UPSTREAM_FLAG_TEST_FHR(oil->up->flags) && !i_am_rp;
		if (!oil->installed)
			continue;

		if (sg->grp.s_addr != INADDR_ANY
		    && sg->grp.s_addr != oil->oil.mfcc_mcastgrp.s_addr)
			continue;
		if (sg->src.s_addr != INADDR_ANY
		    && sg->src.s_addr != oil->oil.mfcc_origin.s_addr)
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
		}
		if (pim_channel_oil_empty(oil))
			strlcat(state_str, "P", sizeof(state_str));

		pimsb_mrt_iif(pim, oil->oil.mfcc_mcastgrp, oil->oil.mfcc_parent,
			      in_ifname, sizeof(in_ifname));
		pim_time_uptime(mroute_uptime, sizeof(mroute_uptime),
				now - oil->mroute_creation);

		for (oif_idx = 0; oif_idx < MAXVIFS; ++oif_idx) {
			/* Don't show any output interface if filtered. */
			if (oil->filtered)
				break;

			if (oil->oil.mfcc_ttls[oif_idx] < 1)
				continue;

			/* do not display muted OIFs */
			if (oil->oif_flags[oif_idx] & PIM_OIF_FLAG_MUTE)
				continue;

			if (oil->oil.mfcc_parent == oif_idx
			    && !pim_mroute_allow_iif_in_oil(oil, oif_idx))
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_idx);
			if (i_am_lhr
			    && (ifp_out == NULL || ifp_out->ifindex == 0))
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

			if (oil->oif_flags[oif_idx] & PIM_OIF_FLAG_PROTO_IGMP) {
				strlcpy(proto, "IGMP", sizeof(proto));
			}

			if (oil->oif_flags[oif_idx]
			    & PIM_OIF_FLAG_PROTO_VXLAN) {
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
		i_am_lhr =
			!PIM_UPSTREAM_FLAG_TEST_FHR(oil->up->flags) && !i_am_rp;
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

		for (oif_idx = 0; oif_idx < MAXVIFS; ++oif_idx) {
			if (s_route->oif_ttls[oif_idx] < 1)
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_idx);
			if (i_am_lhr
			    && (ifp_out == NULL || ifp_out->ifindex == 0))
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
