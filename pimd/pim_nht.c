/*
 * PIM for Quagga
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Chirag Shah
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
#include "network.h"
#include "zclient.h"
#include "stream.h"
#include "nexthop.h"
#include "if.h"
#include "hash.h"
#include "jhash.h"

#include "lib/printfrr.h"

#include "pimd.h"
#include "pimd/pim_nht.h"
#include "log.h"
#include "pim_time.h"
#include "pim_oil.h"
#include "pim_ifchannel.h"
#include "pim_mroute.h"
#include "pim_zebra.h"
#include "pim_upstream.h"
#include "pim_join.h"
#include "pim_jp_agg.h"
#include "pim_zebra.h"
#include "pim_zlookup.h"
#include "pim_rp.h"

DECLARE_DLIST(pending_pncs, struct pim_nexthop_cache, pending_itm);

static struct zclient *nht_zclient;
static bool nht_wait_cancelled = true;
static struct pending_pncs_head nht_pending_pncs[1] = {
	INIT_DLIST(nht_pending_pncs[0])
};
static struct thread *t_nht_pending_drain;

static inline bool pnc_answered(struct pim_nexthop_cache *pnc)
{
	if (pnc->rib[0].flags & pnc->rib[1].flags & PIM_NEXTHOP_ANSWER_RECEIVED)
		return true;
	return false;
}

/**
 * pim_sendmsg_zebra_rnh -- Format and send a nexthop register/Unregister
 *   command to Zebra.
 */
void pim_sendmsg_zebra_rnh(struct pim_instance *pim,
			   struct pim_nexthop_cache *pnc, int command)
{
	struct prefix *p;
	int uret, mret;

	p = &(pnc->rpf.rpf_addr);
	uret = zclient_send_rnh(nht_zclient, command, p, SAFI_UNICAST, false,
				false, pim->vrf->vrf_id);
	if (uret == ZCLIENT_SEND_FAILURE)
		zlog_warn("sendmsg_nexthop: zclient_send_message() failed");

	mret = zclient_send_rnh(nht_zclient, command, p, SAFI_MULTICAST, false,
				false, pim->vrf->vrf_id);
	if (mret == ZCLIENT_SEND_FAILURE)
		zlog_warn("sendmsg_nexthop: zclient_send_message() failed");

	if (PIM_DEBUG_PIM_NHT)
		zlog_debug(
			"%s: NHT %sregistered addr %pFX(%s) with Zebra ret:%d(U) %d(M)",
			__func__,
			(command == ZEBRA_NEXTHOP_REGISTER) ? " " : "de", p,
			pim->vrf->name, uret, mret);

	return;
}

struct pim_nexthop_cache *pim_nexthop_cache_find(struct pim_instance *pim,
						 struct pim_rpf *rpf)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;

	lookup.rpf.rpf_addr.family = rpf->rpf_addr.family;
	lookup.rpf.rpf_addr.prefixlen = rpf->rpf_addr.prefixlen;
	lookup.rpf.rpf_addr.u.prefix4.s_addr = rpf->rpf_addr.u.prefix4.s_addr;

	pnc = hash_lookup(pim->rpf_hash, &lookup);

	return pnc;
}

static struct pim_nexthop_cache *pim_nexthop_cache_add(struct pim_instance *pim,
						       struct pim_rpf *rpf_addr)
{
	struct pim_nexthop_cache *pnc;
	char hash_name[64];

	pnc = XCALLOC(MTYPE_PIM_NEXTHOP_CACHE,
		      sizeof(struct pim_nexthop_cache));
	pnc->rpf.rpf_addr.family = rpf_addr->rpf_addr.family;
	pnc->rpf.rpf_addr.prefixlen = rpf_addr->rpf_addr.prefixlen;
	pnc->rpf.rpf_addr.u.prefix4.s_addr =
		rpf_addr->rpf_addr.u.prefix4.s_addr;

	pnc = hash_get(pim->rpf_hash, pnc, hash_alloc_intern);

	pnc->rp_list = list_new();
	pnc->rp_list->cmp = pim_rp_list_cmp;

	snprintfrr(hash_name, sizeof(hash_name), "PNC %pFX(%s) Upstream Hash",
		   &pnc->rpf.rpf_addr, pim->vrf->name);
	pnc->upstream_hash = hash_create_size(8192, pim_upstream_hash_key,
					      pim_upstream_equal, hash_name);

	return pnc;
}

static struct pim_nexthop_cache *pim_nht_get(struct pim_instance *pim,
					     struct prefix *addr)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_rpf rpf;

	memset(&rpf, 0, sizeof(struct pim_rpf));
	rpf.rpf_addr.family = addr->family;
	rpf.rpf_addr.prefixlen = addr->prefixlen;
	rpf.rpf_addr.u.prefix4 = addr->u.prefix4;

	pnc = pim_nexthop_cache_find(pim, &rpf);
	if (!pnc) {
		pnc = pim_nexthop_cache_add(pim, &rpf);
		pim_sendmsg_zebra_rnh(pim, pnc, ZEBRA_NEXTHOP_REGISTER);
		if (PIM_DEBUG_PIM_NHT)
			zlog_debug(
				"%s: NHT cache and zebra notification added for %pFX(%s)",
				__func__, addr, pim->vrf->name);
	}

	return pnc;
}

/* TBD: this does several distinct things and should probably be split up.
 * (checking state vs. returning pnc vs. adding upstream vs. adding rp)
 */
int pim_find_or_track_nexthop(struct pim_instance *pim, struct prefix *addr,
			      struct pim_upstream *up, struct rp_info *rp,
			      struct pim_nexthop_data *out_nhd)
{
	struct pim_nexthop_cache *pnc;
	struct listnode *ch_node = NULL;

	pnc = pim_nht_get(pim, addr);

	assertf(up || rp, "addr=%pFX", addr);

	if (rp != NULL) {
		ch_node = listnode_lookup(pnc->rp_list, rp);
		if (ch_node == NULL)
			listnode_add_sort(pnc->rp_list, rp);
	}

	if (up != NULL)
		hash_get(pnc->upstream_hash, up, hash_alloc_intern);

	if (pnc->rib_sel != SAFI_UNSPEC) {
		if (out_nhd)
			memcpy(out_nhd, pnc_nhdata(pnc), sizeof(*out_nhd));
		return 1;
	}

	return 0;
}

void pim_nht_bsr_add(struct pim_instance *pim, struct in_addr addr)
{
	struct pim_nexthop_cache *pnc;
	struct prefix pfx;

	pfx.family = AF_INET;
	pfx.prefixlen = IPV4_MAX_BITLEN;
	pfx.u.prefix4 = addr;

	pnc = pim_nht_get(pim, &pfx);

	pnc->bsr_count++;
}

static void pim_nht_drop_maybe(struct pim_instance *pim,
			       struct pim_nexthop_cache *pnc)
{
	if (PIM_DEBUG_PIM_NHT)
		zlog_debug(
			"%s: NHT %pFX(%s) rp_list count:%d upstream count:%ld BSR count:%u",
			__func__, &pnc->rpf.rpf_addr, pim->vrf->name,
			pnc->rp_list->count, pnc->upstream_hash->count,
			pnc->bsr_count);

	if (pnc->rp_list->count == 0 && pnc->upstream_hash->count == 0
	    && pnc->bsr_count == 0) {
		pim_sendmsg_zebra_rnh(pim, pnc, ZEBRA_NEXTHOP_UNREGISTER);

		if (pending_pncs_anywhere(pnc))
			pending_pncs_del(nht_pending_pncs, pnc);

		list_delete(&pnc->rp_list);
		hash_free(pnc->upstream_hash);

		hash_release(pim->rpf_hash, pnc);
		if (pnc->rib[0].nexthop)
			nexthops_free(pnc->rib[0].nexthop);
		if (pnc->rib[1].nexthop)
			nexthops_free(pnc->rib[1].nexthop);

		XFREE(MTYPE_PIM_NEXTHOP_CACHE, pnc);
	}
}

void pim_delete_tracked_nexthop(struct pim_instance *pim, struct prefix *addr,
				struct pim_upstream *up, struct rp_info *rp)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;
	struct pim_upstream *upstream = NULL;

	/* Remove from RPF hash if it is the last entry */
	lookup.rpf.rpf_addr = *addr;
	pnc = hash_lookup(pim->rpf_hash, &lookup);
	if (!pnc) {
		zlog_warn("attempting to delete nonexistent NHT entry %pFX",
			  addr);
		return;
	}

	if (rp) {
		/* Release the (*, G)upstream from pnc->upstream_hash,
		 * whose Group belongs to the RP getting deleted
		 */
		frr_each (rb_pim_upstream, &pim->upstream_head, upstream) {
			struct prefix grp;
			struct rp_info *trp_info;

			if (upstream->sg.src.s_addr != INADDR_ANY)
				continue;

			grp.family = AF_INET;
			grp.prefixlen = IPV4_MAX_BITLEN;
			grp.u.prefix4 = upstream->sg.grp;

			trp_info = pim_rp_find_match_group(pim, &grp);
			if (trp_info == rp)
				hash_release(pnc->upstream_hash, upstream);
		}
		listnode_delete(pnc->rp_list, rp);
	}

	if (up)
		hash_release(pnc->upstream_hash, up);

	pim_nht_drop_maybe(pim, pnc);
}

void pim_nht_bsr_del(struct pim_instance *pim, struct in_addr addr)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;

	lookup.rpf.rpf_addr.family = AF_INET;
	lookup.rpf.rpf_addr.prefixlen = IPV4_MAX_BITLEN;
	lookup.rpf.rpf_addr.u.prefix4 = addr;

	pnc = hash_lookup(pim->rpf_hash, &lookup);

	if (!pnc) {
		zlog_warn("attempting to delete nonexistent NHT BSR entry %pI4",
			  &addr);
		return;
	}

	assertf(pnc->bsr_count > 0, "addr=%pI4", &addr);
	pnc->bsr_count--;

	pim_nht_drop_maybe(pim, pnc);
}

bool pim_nht_bsr_rpf_check(struct pim_instance *pim, struct in_addr bsr_addr,
			   struct interface *src_ifp, struct in_addr src_ip)
{
	struct pim_nexthop_cache *pnc = NULL, *pnc_alloc = NULL;
	struct pim_nexthop_cache lookup;
	struct pim_nexthop_data *nhd;
	struct pim_neighbor *nbr = NULL;
	struct nexthop *nh;
	struct interface *ifp;
	bool ret = false;

	lookup.rpf.rpf_addr.family = AF_INET;
	lookup.rpf.rpf_addr.prefixlen = IPV4_MAX_BITLEN;
	lookup.rpf.rpf_addr.u.prefix4 = bsr_addr;

	pnc = hash_lookup(pim->rpf_hash, &lookup);
	if (!pnc) {
		zlog_warn("BSR check has no NHT entry (%pFX)",
			  &lookup.rpf.rpf_addr);
		pnc = pnc_alloc = pim_nht_get(pim, &lookup.rpf.rpf_addr);
	}

	if (!pim_nexthop_cache_wait(pim, pnc, 1000))
		goto out_drop_maybe;

	if (pnc->rib_sel == SAFI_UNSPEC)
		goto out_drop_maybe;

	/* if we accept BSMs from more than one ECMP nexthop, this will cause
	 * BSM message "multiplication" for each ECMP hop.  i.e. if you have
	 * 4-way ECMP and 4 hops you end up with 256 copies of each BSM
	 * message.
	 *
	 * so...  only accept the first (IPv4) valid nexthop as source.
	 */

	nhd = pnc_nhdata(pnc);

	for (nh = nhd->nexthop; nh; nh = nh->next) {
		struct in_addr nhaddr;

		switch (nh->type) {
		case NEXTHOP_TYPE_IPV4:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;

			/* fallthru */
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			nhaddr = nh->gate.ipv4;
			break;

		case NEXTHOP_TYPE_IFINDEX:
			nhaddr = bsr_addr;
			break;

		default:
			continue;
		}

		ifp = if_lookup_by_index(nh->ifindex, pim->vrf->vrf_id);
		if (!ifp || !ifp->info)
			continue;

		if (if_is_loopback(ifp) && if_is_loopback(src_ifp)) {
			ret = true;
			break;
		}

		/* MRIB (IGP) may be pointing at a router where PIM is down */
		nbr = pim_neighbor_find(ifp, nhaddr);
		if (!nbr)
			continue;

		ret = (nh->ifindex == src_ifp->ifindex
		       && nhaddr.s_addr == src_ip.s_addr);
		break;
	}

out_drop_maybe:
	if (pnc_alloc)
		pim_nht_drop_maybe(pim, pnc_alloc);
	return ret;
}

void pim_rp_nexthop_del(struct rp_info *rp_info)
{
	rp_info->rp.source_nexthop.interface = NULL;
	rp_info->rp.source_nexthop.mrib_nexthop_addr.u.prefix4.s_addr =
		PIM_NET_INADDR_ANY;
	rp_info->rp.source_nexthop.mrib_metric_preference =
		router->infinite_assert_metric.metric_preference;
	rp_info->rp.source_nexthop.mrib_route_metric =
		router->infinite_assert_metric.route_metric;
}

/* Update RP nexthop info based on Nexthop update received from Zebra.*/
static void pim_update_rp_nh(struct pim_instance *pim,
			     struct pim_nexthop_cache *pnc)
{
	struct listnode *node = NULL;
	struct rp_info *rp_info = NULL;

	/*Traverse RP list and update each RP Nexthop info */
	for (ALL_LIST_ELEMENTS_RO(pnc->rp_list, node, rp_info)) {
		if (rp_info->rp.rpf_addr.u.prefix4.s_addr == INADDR_NONE)
			continue;

		// Compute PIM RPF using cached nexthop
		if (!pim_ecmp_nexthop_lookup(pim, &rp_info->rp.source_nexthop,
					     &rp_info->rp.rpf_addr,
					     &rp_info->group, 1))
			pim_rp_nexthop_del(rp_info);
	}
}

/* Update Upstream nexthop info based on Nexthop update received from Zebra.*/
static int pim_update_upstream_nh_helper(struct hash_bucket *bucket, void *arg)
{
	struct pim_instance *pim = (struct pim_instance *)arg;
	struct pim_upstream *up = (struct pim_upstream *)bucket->data;

	enum pim_rpf_result rpf_result;
	struct pim_rpf old;

	old.source_nexthop.interface = up->rpf.source_nexthop.interface;
	rpf_result = pim_rpf_update(pim, up, &old, __func__);

	/* update kernel multicast forwarding cache (MFC); if the
	 * RPF nbr is now unreachable the MFC has already been updated
	 * by pim_rpf_clear
	 */
	if (rpf_result != PIM_RPF_FAILURE)
		pim_upstream_mroute_iif_update(up->channel_oil, __func__);

	if (rpf_result == PIM_RPF_CHANGED ||
		(rpf_result == PIM_RPF_FAILURE && old.source_nexthop.interface))
		pim_zebra_upstream_rpf_changed(pim, up, &old);


	if (PIM_DEBUG_PIM_NHT) {
		zlog_debug(
			"%s: NHT upstream %s(%s) old ifp %s new ifp %s",
			__func__, up->sg_str, pim->vrf->name,
			old.source_nexthop.interface ? old.source_nexthop
							       .interface->name
						     : "Unknown",
			up->rpf.source_nexthop.interface ? up->rpf.source_nexthop
								   .interface->name
							 : "Unknown");
	}

	return HASHWALK_CONTINUE;
}

static int pim_update_upstream_nh(struct pim_instance *pim,
				  struct pim_nexthop_cache *pnc)
{
	hash_walk(pnc->upstream_hash, pim_update_upstream_nh_helper, pim);

	pim_zebra_update_all_interfaces(pim);

	return 0;
}

uint32_t pim_compute_ecmp_hash(struct prefix *src, struct prefix *grp)
{
	uint32_t hash_val;
	uint32_t s = 0, g = 0;

	if ((!src))
		return 0;

	switch (src->family) {
	case AF_INET: {
		s = src->u.prefix4.s_addr;
		s = s == 0 ? 1 : s;
		if (grp)
			g = grp->u.prefix4.s_addr;
	} break;
	default:
		break;
	}

	hash_val = jhash_2words(g, s, 101);
	return hash_val;
}

static int pim_ecmp_nexthop_search(struct pim_instance *pim,
				   struct pim_nexthop_cache *pnc,
				   struct pim_nexthop *nexthop,
				   struct prefix *src, struct prefix *grp,
				   int neighbor_needed)
{
	struct pim_neighbor *nbrs[MULTIPATH_NUM], *nbr = NULL;
	struct interface *ifps[MULTIPATH_NUM];
	struct nexthop *nh_node = NULL;
	ifindex_t first_ifindex;
	struct interface *ifp = NULL;
	uint32_t hash_val = 0, mod_val = 0;
	uint8_t nh_iter = 0, found = 0;
	uint32_t i, num_nbrs = 0;
	struct pim_nexthop_data *nhd;

	if (!pnc || pnc->rib_sel == SAFI_UNSPEC)
		return 0;
	nhd = pnc_nhdata(pnc);

	memset(&nbrs, 0, sizeof(nbrs));
	memset(&ifps, 0, sizeof(ifps));

	// Current Nexthop is VALID, check to stay on the current path.
	if (nexthop->interface && nexthop->interface->info
	    && nexthop->mrib_nexthop_addr.u.prefix4.s_addr
		       != PIM_NET_INADDR_ANY) {
		/* User configured knob to explicitly switch
		   to new path is disabled or current path
		   metric is less than nexthop update.
		 */

		if (pim->ecmp_rebalance_enable == 0) {
			uint8_t curr_route_valid = 0;
			// Check if current nexthop is present in new updated
			// Nexthop list.
			// If the current nexthop is not valid, candidate to
			// choose new Nexthop.
			for (nh_node = nhd->nexthop; nh_node;
			     nh_node = nh_node->next) {
				curr_route_valid = (nexthop->interface->ifindex
						    == nh_node->ifindex);
				if (curr_route_valid)
					break;
			}

			if (curr_route_valid
			    && !pim_if_connected_to_source(nexthop->interface,
							   src->u.prefix4)) {
				nbr = pim_neighbor_find(
					nexthop->interface,
					nexthop->mrib_nexthop_addr.u.prefix4);
				if (!nbr
				    && !if_is_loopback(nexthop->interface)) {
					if (PIM_DEBUG_PIM_NHT)
						zlog_debug(
							"%s: current nexthop does not have nbr ",
							__func__);
				} else {
					/* update metric even if the upstream
					 * neighbor stays unchanged
					 */
					nexthop->mrib_metric_preference =
						nhd->distance;
					nexthop->mrib_route_metric =
						nhd->metric;
					if (PIM_DEBUG_PIM_NHT) {
						char src_str[INET_ADDRSTRLEN];
						pim_inet4_dump("<addr?>",
							       src->u.prefix4,
							       src_str,
							       sizeof(src_str));
						char grp_str[INET_ADDRSTRLEN];
						pim_inet4_dump("<addr?>",
							       grp->u.prefix4,
							       grp_str,
							       sizeof(grp_str));
						zlog_debug(
							"%s: (%s,%s)(%s) current nexthop %s is valid, skipping new path selection",
							__func__, src_str,
							grp_str, pim->vrf->name,
							nexthop->interface->name);
					}
					return 1;
				}
			}
		}
	}

	/*
	 * Look up all interfaces and neighbors,
	 * store for later usage
	 */
	for (nh_node = nhd->nexthop, i = 0; nh_node;
	     nh_node = nh_node->next, i++) {
		ifps[i] =
			if_lookup_by_index(nh_node->ifindex, pim->vrf->vrf_id);
		if (ifps[i]) {
			nbrs[i] = pim_neighbor_find(ifps[i],
						    nh_node->gate.ipv4);
			if (nbrs[i] || pim_if_connected_to_source(ifps[i],

								  src->u.prefix4))
				num_nbrs++;
		}
	}
	if (pim->ecmp_enable) {
		uint32_t consider = nhd->nexthop_num;

		if (neighbor_needed && num_nbrs < consider)
			consider = num_nbrs;

		if (consider == 0)
			return 0;

		// PIM ECMP flag is enable then choose ECMP path.
		hash_val = pim_compute_ecmp_hash(src, grp);
		mod_val = hash_val % consider;
	}

	for (nh_node = nhd->nexthop; nh_node && (found == 0);
	     nh_node = nh_node->next) {
		first_ifindex = nh_node->ifindex;
		ifp = ifps[nh_iter];
		if (!ifp) {
			if (PIM_DEBUG_PIM_NHT) {
				char addr_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<addr?>", src->u.prefix4,
					       addr_str, sizeof(addr_str));
				zlog_debug(
					"%s %s: could not find interface for ifindex %d (address %s(%s))",
					__FILE__, __func__, first_ifindex,
					addr_str, pim->vrf->name);
			}
			if (nh_iter == mod_val)
				mod_val++; // Select nexthpath
			nh_iter++;
			continue;
		}
		if (!ifp->info) {
			if (PIM_DEBUG_PIM_NHT) {
				char addr_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<addr?>", src->u.prefix4,
					       addr_str, sizeof(addr_str));
				zlog_debug(
					"%s: multicast not enabled on input interface %s(%s) (ifindex=%d, RPF for source %s)",
					__func__, ifp->name, pim->vrf->name,
					first_ifindex, addr_str);
			}
			if (nh_iter == mod_val)
				mod_val++; // Select nexthpath
			nh_iter++;
			continue;
		}

		if (neighbor_needed
		    && !pim_if_connected_to_source(ifp, src->u.prefix4)) {
			nbr = nbrs[nh_iter];
			if (!nbr && !if_is_loopback(ifp)) {
				if (PIM_DEBUG_PIM_NHT)
					zlog_debug(
						"%s: pim nbr not found on input interface %s(%s)",
						__func__, ifp->name,
						pim->vrf->name);
				if (nh_iter == mod_val)
					mod_val++; // Select nexthpath
				nh_iter++;
				continue;
			}
		}

		if (nh_iter == mod_val) {
			nexthop->interface = ifp;
			nexthop->mrib_nexthop_addr.family = AF_INET;
			nexthop->mrib_nexthop_addr.prefixlen = IPV4_MAX_BITLEN;
			nexthop->mrib_nexthop_addr.u.prefix4 =
				nh_node->gate.ipv4;
			nexthop->mrib_metric_preference = nhd->distance;
			nexthop->mrib_route_metric = nhd->metric;
			nexthop->last_lookup = src->u.prefix4;
			nexthop->last_lookup_time = pim_time_monotonic_usec();
			nexthop->nbr = nbr;
			found = 1;
			if (PIM_DEBUG_PIM_NHT) {
				char buf[INET_ADDRSTRLEN];
				char buf2[INET_ADDRSTRLEN];
				char buf3[INET_ADDRSTRLEN];
				pim_inet4_dump("<src?>", src->u.prefix4, buf2,
					       sizeof(buf2));
				pim_inet4_dump("<grp?>", grp->u.prefix4, buf3,
					       sizeof(buf3));
				pim_inet4_dump(
					"<rpf?>",
					nexthop->mrib_nexthop_addr.u.prefix4,
					buf, sizeof(buf));
				zlog_debug(
					"%s: (%s,%s)(%s) selected nhop interface %s addr %s mod_val %u iter %d ecmp %d",
					__func__, buf2, buf3, pim->vrf->name,
					ifp->name, buf, mod_val, nh_iter,
					pim->ecmp_enable);
			}
		}
		nh_iter++;
	}

	if (found)
		return 1;
	else
		return 0;
}

static int nht_pending_drain(struct thread *t)
{
	struct pim_nexthop_cache *pnc;
	struct pim_instance *pim = pim_get_pim_instance(VRF_DEFAULT);

	while ((pnc = pending_pncs_pop(nht_pending_pncs))) {
		pim_rpf_set_refresh_time(pim);

		if (listcount(pnc->rp_list))
			pim_update_rp_nh(pim, pnc);
		if (pnc->upstream_hash->count)
			pim_update_upstream_nh(pim, pnc);
	}

	return 0;
}

static void pim_nht_reselect(struct pim_instance *pim,
			     struct pim_nexthop_cache *pnc, bool changed)
{
	safi_t safi_prev = pnc->rib_sel;
	safi_t safi_now = SAFI_UNSPEC;
	uint8_t distance = 255;

	switch (pim->rpf_mode) {
	case RPF_MRIB_ONLY:
		if (pnc->rib[SAFI_MULTICAST - 1].flags & PIM_NEXTHOP_VALID)
			safi_now = SAFI_MULTICAST;
		break;

	case RPF_URIB_ONLY:
		if (pnc->rib[SAFI_UNICAST - 1].flags & PIM_NEXTHOP_VALID)
			safi_now = SAFI_UNICAST;
		break;

	case RPF_NO_CONFIG:
	case RPF_MIX_MRIB_FIRST:
		if (pnc->rib[SAFI_MULTICAST - 1].flags & PIM_NEXTHOP_VALID)
			safi_now = SAFI_MULTICAST;
		else if (pnc->rib[SAFI_UNICAST - 1].flags & PIM_NEXTHOP_VALID)
			safi_now = SAFI_UNICAST;
		break;

	case RPF_MIX_DISTANCE:
		if (pnc->rib[SAFI_UNICAST - 1].flags & PIM_NEXTHOP_VALID) {
			distance = pnc->rib[SAFI_UNICAST - 1].distance;
			safi_now = SAFI_UNICAST;
		}
		if ((pnc->rib[SAFI_MULTICAST - 1].flags & PIM_NEXTHOP_VALID)
		    && pnc->rib[SAFI_MULTICAST - 1].distance <= distance) {
			distance = pnc->rib[SAFI_MULTICAST - 1].distance;
			safi_now = SAFI_MULTICAST;
		}
		break;

	case RPF_MIX_PFXLEN:
#ifdef DEV_BUILD
		CPP_NOTICE("RPF_MIX_PFXLEN is not currently implemented");
#endif
		break;
	}

	if (safi_now != safi_prev) {
		pnc->rib_sel = safi_now;
		changed = true;
	}

	if (!changed)
		return;


	if (PIM_DEBUG_PIM_NHT)
		zlog_debug("NHT(%pI4): %s", &pnc->rpf.rpf_addr.u.prefix4,
			   safi_now == SAFI_UNICAST ? "resolved on URIB" :
			   safi_now == SAFI_MULTICAST ? "resolved on MRIB" :
			   "unresolveable");

	if (!nht_wait_cancelled) {
		if (pending_pncs_anywhere(pnc))
			return;

		pending_pncs_add_tail(nht_pending_pncs, pnc);

		if (!t_nht_pending_drain)
			thread_add_event(nht_zclient->master, nht_pending_drain,
					 0, 0, &t_nht_pending_drain);
	} else {
		pim_rpf_set_refresh_time(pim);

		if (listcount(pnc->rp_list))
			pim_update_rp_nh(pim, pnc);
		if (pnc->upstream_hash->count)
			pim_update_upstream_nh(pim, pnc);
	}
}

/* This API is used to parse Registered address nexthop update coming from Zebra
 */
static int pim_nht_update(ZAPI_CALLBACK_ARGS)
{
	struct nexthop *nexthop;
	struct nexthop *nhlist_head = NULL;
	struct nexthop *nhlist_tail = NULL;
	int i;
	struct pim_rpf rpf;
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_neighbor *nbr = NULL;
	struct interface *ifp = NULL;
	struct interface *ifp1 = NULL;
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct pim_instance *pim;
	struct zapi_route nhr;
	struct pim_nexthop_data *nhd;

	if (!vrf)
		return 0;
	pim = vrf->info;

	if (!zapi_nexthop_update_decode(zclient->ibuf, &nhr)) {
		zlog_err("%s: Decode of nexthop update from zebra failed",
			 __func__);
		return 0;
	}

	if (cmd == ZEBRA_NEXTHOP_UPDATE) {
		prefix_copy(&rpf.rpf_addr, &nhr.prefix);
		pnc = pim_nexthop_cache_find(pim, &rpf);
		if (!pnc) {
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug(
					"%s: Skipping NHT update, addr %pFX is not in local cached DB.",
					__func__, &rpf.rpf_addr);
			return 0;
		}
	} else {
		/*
		 * We do not currently handle ZEBRA_IMPORT_CHECK_UPDATE
		 */
		return 0;
	}

	nhd = &pnc->rib[nhr.safi - 1];
	nhd->last_update = pim_time_monotonic_usec();

	if (nhr.nexthop_num) {
		nhd->nexthop_num = 0; // Only increment for pim enabled rpf.

		for (i = 0; i < nhr.nexthop_num; i++) {
			nexthop = nexthop_from_zapi_nexthop(&nhr.nexthops[i]);
			switch (nexthop->type) {
			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_BLACKHOLE:
				break;
			case NEXTHOP_TYPE_IFINDEX:
				/*
				 * Connected route (i.e. no nexthop), use
				 * RPF address from nexthop cache (i.e.
				 * destination) as PIM nexthop.
				 */
				nexthop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
				nexthop->gate.ipv4 =
					pnc->rpf.rpf_addr.u.prefix4;
				break;
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				ifp1 = if_lookup_by_index(nexthop->ifindex,
							  pim->vrf->vrf_id);

				if (!ifp1)
					nbr = NULL;
				else
					nbr = pim_neighbor_find_if(ifp1);
				/* Overwrite with Nbr address as NH addr */
				if (nbr)
					nexthop->gate.ipv4 = nbr->source_addr;
				else {
					// Mark nexthop address to 0 until PIM
					// Nbr is resolved.
					nexthop->gate.ipv4.s_addr =
						PIM_NET_INADDR_ANY;
				}

				break;
			}

			ifp = if_lookup_by_index(nexthop->ifindex,
						 pim->vrf->vrf_id);
			if (!ifp) {
				if (PIM_DEBUG_PIM_NHT) {
					char buf[NEXTHOP_STRLEN];
					zlog_debug(
						"%s: could not find interface for ifindex %d(%s) (addr %s)",
						__func__, nexthop->ifindex,
						pim->vrf->name,
						nexthop2str(nexthop, buf,
							    sizeof(buf)));
				}
				nexthop_free(nexthop);
				continue;
			}

			if (PIM_DEBUG_PIM_NHT)
				zlog_debug(
					"%s: NHT addr %pFX(%s) safi=%d %d-nhop via %pI4(%s) type %d distance:%u metric:%u ",
					__func__, &nhr.prefix, pim->vrf->name,
					nhr.safi, i + 1, &nexthop->gate.ipv4,
					ifp->name, nexthop->type, nhr.distance,
					nhr.metric);

			if (!ifp->info) {
				/*
				 * Though Multicast is not enabled on this
				 * Interface store it in database otheriwse we
				 * may miss this update and this will not cause
				 * any issue, because while choosing the path we
				 * are ommitting the Interfaces which are not
				 * multicast enabled
				 */
				if (PIM_DEBUG_PIM_NHT) {
					char buf[NEXTHOP_STRLEN];

					zlog_debug(
						"%s: multicast not enabled on input interface %s(%s) (ifindex=%d, addr %s)",
						__func__, ifp->name,
						pim->vrf->name,
						nexthop->ifindex,
						nexthop2str(nexthop, buf,
							    sizeof(buf)));
				}
			}

			if (nhlist_tail) {
				nhlist_tail->next = nexthop;
				nhlist_tail = nexthop;
			} else {
				nhlist_tail = nexthop;
				nhlist_head = nexthop;
			}
			// Only keep track of nexthops which are PIM enabled.
			nhd->nexthop_num++;
		}
		/* Reset existing pnc->nexthop before assigning new list */
		nexthops_free(nhd->nexthop);
		nhd->nexthop = nhlist_head;
		if (nhd->nexthop_num) {
			nhd->flags |= PIM_NEXTHOP_VALID;
			nhd->distance = nhr.distance;
			nhd->metric = nhr.metric;
		}
	} else {
		nhd->flags &= ~PIM_NEXTHOP_VALID;
		nhd->nexthop_num = nhr.nexthop_num;
		nexthops_free(nhd->nexthop);
		nhd->nexthop = NULL;
	}
	SET_FLAG(nhd->flags, PIM_NEXTHOP_ANSWER_RECEIVED);

	if (PIM_DEBUG_PIM_NHT)
		zlog_debug(
			"%s: NHT Update for %pFX(%s) num_nh %d num_pim_nh %d vrf:%u up %ld rp %d",
			__func__, &nhr.prefix, pim->vrf->name, nhr.nexthop_num,
			nhd->nexthop_num, vrf_id, pnc->upstream_hash->count,
			listcount(pnc->rp_list));

	pim_nht_reselect(pim, pnc, true);
	return 0;
}

/* When we get any system state change (VRFs/interfaces/addresses), a blocking
 * wait for NHT data is considered "cancelled" because the state change may
 * have side effects on the thing that the NHT data is waited for
 *
 * This is intended to avoid hard to debug state desynchronization problems,
 * e.g. we wait on the result of a RPF lookup, but meanwhile the interface
 * went down and we'd end up installing an invalid MFIB entry with the result
 * of this RPF lookup.
 */
static int pim_nht_wait_cancel(ZAPI_CALLBACK_ARGS)
{
	if (nht_wait_cancelled)
		return 0;

	if (PIM_DEBUG_PIM_NHT)
		zlog_debug("NHT wait cancelled by system state change");
	nht_wait_cancelled = true;
	return 0;
}

/* Need data for this NHT entry immediately to continue processing something
 *
 * This replaces the previous synchronous zlookup handling
 */
bool pim_nexthop_cache_wait(struct pim_instance *pim,
			    struct pim_nexthop_cache *pnc, unsigned timeout_ms)
{
	struct timeval deadline;
	unsigned timeout_sec;

	if (pnc_answered(pnc))
		return true;

	if (PIM_DEBUG_PIM_NHT)
		zlog_debug("NHT %pFX(%s) state needed immediately, waiting %ums",
			   &pnc->rpf.rpf_addr, pim->vrf->name, timeout_ms);

	monotime(&deadline);
	timeout_sec = timeout_ms / 1000;
	timeout_ms = timeout_ms - timeout_sec * 1000;

	deadline.tv_sec += timeout_sec;
	deadline.tv_usec += timeout_ms * 1000;
	if (deadline.tv_usec > 1000000) {
		deadline.tv_usec -= 1000000;
		deadline.tv_sec++;
	}

	nht_wait_cancelled = false;

	while (zclient_wait(nht_zclient, &deadline)) {
		if (pnc_answered(pnc)) {
			nht_wait_cancelled = true;
			return true;
		}

		if (nht_wait_cancelled)
			return false;
	}

	nht_wait_cancelled = true;
	if (PIM_DEBUG_PIM_NHT)
		zlog_debug("NHT %pFX(%s) wait timed out", &pnc->rpf.rpf_addr,
			   pim->vrf->name);
	return false;
}

int pim_ecmp_nexthop_lookup(struct pim_instance *pim,
			    struct pim_nexthop *nexthop, struct prefix *src,
			    struct prefix *grp, int neighbor_needed)
{
	struct pim_nexthop_cache *pnc, *pnc_alloc = NULL;
	struct pim_rpf rpf;
	int ret;
	char addr_str[PREFIX_STRLEN];

	if (PIM_DEBUG_PIM_NHT) {
		pim_inet4_dump("<addr?>", src->u.prefix4, addr_str,
			       sizeof(addr_str));
		zlog_debug("%s: Looking up: %s(%s), last lookup time: %lld",
			   __func__, addr_str, pim->vrf->name,
			   nexthop->last_lookup_time);
	}

	memset(&rpf, 0, sizeof(struct pim_rpf));
	rpf.rpf_addr.family = AF_INET;
	rpf.rpf_addr.prefixlen = IPV4_MAX_BITLEN;
	rpf.rpf_addr.u.prefix4 = src->u.prefix4;

	pnc = pim_nexthop_cache_find(pim, &rpf);
	if (!pnc) {
		zlog_debug("no NHT entry, creating temp");
		pnc = pnc_alloc = pim_nht_get(pim, src);
	}

	if (pim_nexthop_cache_wait(pim, pnc, 1000))
		ret = pim_ecmp_nexthop_search(pim, pnc, nexthop, src, grp,
					      neighbor_needed);
	else {
		zlog_debug("wait timed out without NH data");
		ret = 0;
	}

	if (pnc_alloc)
		pim_nht_drop_maybe(pim, pnc_alloc);
	return ret;
}

int pim_ecmp_fib_lookup_if_vif_index(struct pim_instance *pim,
				     struct prefix *src, struct prefix *grp)
{
	struct pim_nexthop nhop;
	int vif_index;
	ifindex_t ifindex;
	char addr_str[PREFIX_STRLEN];

	if (PIM_DEBUG_PIM_NHT)
		pim_inet4_dump("<addr?>", src->u.prefix4, addr_str,
			       sizeof(addr_str));

	memset(&nhop, 0, sizeof(nhop));
	if (!pim_ecmp_nexthop_lookup(pim, &nhop, src, grp, 1)) {
		if (PIM_DEBUG_PIM_NHT)
			zlog_debug(
				"%s: could not find nexthop ifindex for address %s(%s)",
				__func__, addr_str, pim->vrf->name);
		return -1;
	}

	ifindex = nhop.interface->ifindex;
	if (PIM_DEBUG_PIM_NHT)
		zlog_debug(
			"%s: found nexthop ifindex=%d (interface %s(%s)) for address %s",
			__func__, ifindex,
			ifindex2ifname(ifindex, pim->vrf->vrf_id),
			pim->vrf->name, addr_str);

	vif_index = pim_if_find_vifindex_by_ifindex(pim, ifindex);

	if (vif_index < 0) {
		if (PIM_DEBUG_PIM_NHT) {
			zlog_debug(
				"%s: low vif_index=%d(%s) < 1 nexthop for address %s",
				__func__, vif_index, pim->vrf->name, addr_str);
		}
		return -2;
	}

	return vif_index;
}

/* Connect to zebra for nexthop lookup. */
static int nht_zclient_connect(struct thread *t)
{
	assert(nht_zclient->sock == -1);

	if (zclient_start(nht_zclient) < 0) {
		zlog_warn("failure connecting NHT socket: failures=%d",
			  nht_zclient->fail);

		thread_add_timer(router->master, nht_zclient_connect, NULL, 1,
				 &nht_zclient->t_connect);
		return 0;
	}

	return 0;
}

static struct zclient_options nht_zcopts = {
	.supplemental = true,
	.can_wait = true,
};

static zclient_handler *const pim_nht_handlers[] = {
	[ZEBRA_VRF_ADD] = pim_nht_wait_cancel,
	[ZEBRA_VRF_DELETE] = pim_nht_wait_cancel,
	[ZEBRA_INTERFACE_ADD] = pim_nht_wait_cancel,
	[ZEBRA_INTERFACE_DELETE] = pim_nht_wait_cancel,
	[ZEBRA_INTERFACE_UP] = pim_nht_wait_cancel,
	[ZEBRA_INTERFACE_DOWN] = pim_nht_wait_cancel,

	[ZEBRA_INTERFACE_ADDRESS_ADD] = pim_nht_wait_cancel,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = pim_nht_wait_cancel,
	[ZEBRA_INTERFACE_VRF_UPDATE] = pim_nht_wait_cancel,

	[ZEBRA_NEXTHOP_UPDATE] = pim_nht_update,
};

void pim_nht_init(void)
{
	/* Socket for receiving updates from Zebra daemon */
	nht_zclient = zclient_new(router->master, &nht_zcopts, pim_nht_handlers,
				  array_size(pim_nht_handlers));
	nht_zclient->sock = -1;
	nht_zclient->privs = &pimd_privs;

	thread_execute(router->master, nht_zclient_connect, NULL, 0);
}
