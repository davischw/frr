/*
 * BGP Conditional advertisement
 * Copyright (C) 2020  Samsung R&D Institute India - Bangalore.
 *			Madhurilatha Kuruganti
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "bgpd/bgp_conditional_adv.h"
#include "bgpd/bgp_vty.h"

static route_map_result_t
bgp_check_rmap_prefixes_in_bgp_table(struct bgp_table *table,
				     struct route_map *rmap)
{
	struct attr dummy_attr = {0};
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_path_info path = {0};
	struct bgp_path_info_extra path_extra = {0};
	const struct prefix *dest_p;
	route_map_result_t ret = RMAP_DENYMATCH;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		dest_p = bgp_dest_get_prefix(dest);
		assert(dest_p);

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			dummy_attr = *pi->attr;

			/* Fill temp path_info */
			prep_for_rmap_apply(&path, &path_extra, dest, pi,
					    pi->peer, &dummy_attr);

			RESET_FLAG(dummy_attr.rmap_change_flags);

			ret = route_map_apply(rmap, dest_p, &path);
			if (ret != RMAP_PERMITMATCH)
				bgp_attr_flush(&dummy_attr);
			else {
				bgp_dest_unlock_node(dest);
				if (BGP_DEBUG(update, UPDATE_OUT))
					zlog_debug(
						"%s: Condition map routes present in BGP table",
						__func__);

				return ret;
			}
		}
	}

	if (BGP_DEBUG(update, UPDATE_OUT))
		zlog_debug("%s: Condition map routes not present in BGP table",
			   __func__);

	return ret;
}

static void bgp_advmaps_evaluate(struct bgp_table *table, struct peer *peer,
				 afi_t afi, safi_t safi)
{
	struct bgp_filter *filter = &peer->filter[afi][safi];
	struct bgp_filter *pg_filter = peer->group
		? &peer->group->conf->filter[afi][safi] : NULL;
	struct bgp_advmap *advmap;
	struct peer_af *paf = NULL;
	struct update_subgroup *subgrp = NULL;
	int addpath_capable;
	struct bgp_dest *dest;

	frr_each (bgp_advmaps, filter->advmaps, advmap) {
		route_map_result_t ret;

		if (!advmap->cmap) {
			advmap->status = false;
			continue;
		}

		/* cmap (route-map attached to exist-map or non-exist-map) map
		 * validation
		 */
		ret = bgp_check_rmap_prefixes_in_bgp_table(table, advmap->cmap);
		advmap->status = (ret == RMAP_PERMITMATCH);
	}

	if (pg_filter) {
		frr_each (bgp_advmaps, pg_filter->advmaps, advmap) {
			route_map_result_t ret;

			if (!advmap->cmap) {
				advmap->status = false;
				continue;
			}

			ret = bgp_check_rmap_prefixes_in_bgp_table(table,
								advmap->cmap);
			advmap->status = (ret == RMAP_PERMITMATCH);
		}
	}

	if (BGP_DEBUG(update, UPDATE_OUT)) {
		if (filter->advmap_cfg_changed)
			zlog_debug("%s: %s for %s - advertise-map config update",
				   __func__, peer->host,
				   get_afi_safi_str(afi, safi, false));
		if (filter->advmap_rib_changed)
			zlog_debug("%s: %s for %s - advertise-map routes update",
				   __func__, peer->host,
				   get_afi_safi_str(afi, safi, false));
	}

	paf = peer_af_find(peer, afi, safi);
	if (!paf)
		return;

	/* Send regular update as per the existing policy.
	 * There is a change in route-map, match-rule, ACLs,
	 * or route-map filter configuration on the same peer.
	 */
	if (filter->advmap_cfg_changed) {
		if (BGP_DEBUG(update, UPDATE_OUT))
			zlog_debug(
				"%s: Configuration is changed on peer %s for %s, send the normal update first.",
				__func__, peer->host,
				get_afi_safi_str(afi, safi, false));


		update_subgroup_split_peer(paf, NULL);
		subgrp = paf->subgroup;
		if (subgrp && subgrp->update_group)
			subgroup_announce_table(paf->subgroup, NULL);
	}

	subgrp = PAF_SUBGRP(paf);
	/* Ignore if subgroup doesn't exist (implies AF is not negotiated) */
	if (!subgrp)
		return;

	addpath_capable = bgp_addpath_encode_tx(peer, afi, safi);

	if (BGP_DEBUG(update, UPDATE_OUT))
		zlog_debug("%s: refresh advertise-map to/from %s for %s",
			   __func__, peer->host,
			   get_afi_safi_str(afi, safi, false));

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		struct bgp_path_info *pi;
		struct bgp_path_info path;
		const struct prefix *dest_p;
		struct attr dummy_attr = {0}, attr = {0};
		struct bgp_path_info_extra path_extra = {0};
		route_map_result_t ret;

		dest_p = bgp_dest_get_prefix(dest);
		assert(dest_p);

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			struct bgp_advmap *now = NULL;
			struct bgp_advmap *p_advmap;
			struct bgp_advmap *pg_advmap = NULL;
			int update_type;

			p_advmap = bgp_advmaps_first(filter->advmaps);
			if (peer->group)
				pg_advmap = bgp_advmaps_first(
							pg_filter->advmaps);

			dummy_attr = *pi->attr;

			/* Fill temp path_info */
			prep_for_rmap_apply(&path, &path_extra, dest, pi,
					    pi->peer, &dummy_attr);

			RESET_FLAG(dummy_attr.rmap_change_flags);

			while (p_advmap || pg_advmap) {
				if ((p_advmap && pg_advmap &&
				     p_advmap->seqno > pg_advmap->seqno)
				    || !p_advmap) {
					now = pg_advmap;
					pg_advmap = bgp_advmaps_next(
							pg_filter->advmaps,
							pg_advmap);
				} else {
					now = p_advmap;
					p_advmap = bgp_advmaps_next(
							filter->advmaps,
							p_advmap);
				}

				assert(now);

				ret = route_map_apply(now->amap, dest_p, &path);
				bgp_attr_flush(&dummy_attr);

				if (ret == RMAP_PERMITMATCH)
					break;

				now = NULL;
			}

			if (!now)
				continue;

			if (now->cond == CONDITION_EXIST)
				update_type = now->status ? ADVERTISE
					: WITHDRAW;
			else
				update_type = now->status ? WITHDRAW
					: ADVERTISE;

			if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)
			    || (addpath_capable
				&& bgp_addpath_tx_path(
					   peer->addpath_type[afi][safi],
					   pi))) {

				/* Skip route-map checks in
				 * subgroup_announce_check while executing from
				 * the conditional advertise scanner process.
				 * otherwise when route-map is also configured
				 * on same peer, routes in advertise-map may not
				 * be advertised as expected.
				 */
				if ((update_type == ADVERTISE)
				    && subgroup_announce_check(dest, pi, subgrp,
							       dest_p, &attr,
							       true))
					bgp_adj_out_set_subgroup(dest, subgrp,
								 &attr, pi);
				else {
					/* If default originate is enabled for
					 * the peer, do not send explicit
					 * withdraw. This will prevent deletion
					 * of default route advertised through
					 * default originate.
					 */
					if (CHECK_FLAG(
						    peer->af_flags[afi][safi],
						    PEER_FLAG_DEFAULT_ORIGINATE)
					    && is_default_prefix(dest_p))
						break;

					bgp_adj_out_unset_subgroup(
						dest, subgrp, 1,
						bgp_addpath_id_for_peer(
							peer, afi, safi,
							&pi->tx_addpath));
				}
			}
		}
	}
}

/* Handler of conditional advertisement timer event.
 * Each route in the condition-map is evaluated.
 */
static int bgp_conditional_adv_timer(struct thread *t)
{
	afi_t afi;
	safi_t safi;
	int pfx_rcd_safi;
	struct bgp *bgp = NULL;
	struct peer *peer = NULL;
	struct bgp_table *table = NULL;
	struct listnode *node, *nnode = NULL;

	bgp = THREAD_ARG(t);
	assert(bgp);

	thread_add_timer(bm->master, bgp_conditional_adv_timer, bgp,
			 bgp->condition_check_period, &bgp->t_condition_check);

	/* loop through each peer and advertise or withdraw routes if
	 * advertise-map is configured and prefix(es) in condition-map
	 * does exist(exist-map)/not exist(non-exist-map) in BGP table
	 * based on condition(exist-map or non-exist map)
	 */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;

		if (peer->status != Established)
			continue;

		FOREACH_AFI_SAFI (afi, safi) {
			if (!peer->afc_nego[afi][safi])
				continue;

			if (!peer->filter[afi][safi].advmap_cfg_changed &&
			    !peer->filter[afi][safi].advmap_rib_changed)
				continue;

			/* labeled-unicast routes are installed in the unicast
			 * table so in order to display the correct PfxRcd value
			 * we must look at SAFI_UNICAST
			 */
			pfx_rcd_safi = (safi == SAFI_LABELED_UNICAST)
					       ? SAFI_UNICAST
					       : safi;

			table = bgp->rib[afi][pfx_rcd_safi];
			if (!table)
				continue;

			bgp_advmaps_evaluate(table, peer, afi, safi);

			peer->filter[afi][safi].advmap_cfg_changed = false;
			peer->filter[afi][safi].advmap_rib_changed = false;
		}
	}
	return 0;
}

void bgp_conditional_adv_enable(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp *bgp = peer->bgp;

	assert(bgp);

	if (peer->af_flags[afi][safi] & PEER_FLAG_ADVERTISE_MAPS)
		return;
	peer->af_flags[afi][safi] |= PEER_FLAG_ADVERTISE_MAPS;

	/* advertise-map is already configured on atleast one of its
	 * neighbors (AFI/SAFI). So just increment the counter.
	 */
	if (++bgp->condition_filter_count > 1) {
		if (BGP_DEBUG(update, UPDATE_OUT))
			zlog_debug("%s: condition_filter_count %d", __func__,
				   bgp->condition_filter_count);

		return;
	}

	/* Register for conditional routes polling timer */
	thread_add_timer(bm->master, bgp_conditional_adv_timer, bgp,
			 bgp->condition_check_period, &bgp->t_condition_check);
}

void bgp_conditional_adv_disable(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp *bgp = peer->bgp;

	assert(bgp);

	if (!(peer->af_flags[afi][safi] & PEER_FLAG_ADVERTISE_MAPS))
		return;
	peer->af_flags[afi][safi] &= ~PEER_FLAG_ADVERTISE_MAPS;

	/* advertise-map is not configured on any of its neighbors or
	 * it is configured on more than one neighbor(AFI/SAFI).
	 * So there's nothing to do except decrementing the counter.
	 */
	if (--bgp->condition_filter_count != 0) {
		if (BGP_DEBUG(update, UPDATE_OUT))
			zlog_debug("%s: condition_filter_count %d", __func__,
				   bgp->condition_filter_count);

		return;
	}

	/* Last filter removed. So cancel conditional routes polling thread. */
	THREAD_OFF(bgp->t_condition_check);
}
