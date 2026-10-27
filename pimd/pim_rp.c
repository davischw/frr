/*
 * PIM for Quagga
 * Copyright (C) 2015 Cumulus Networks, Inc.
 * Donald Sharp
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

#include "filter.h"
#include "lib/json.h"
#include "log.h"
#include "network.h"
#include "if.h"
#include "linklist.h"
#include "prefix.h"
#include "memory.h"
#include "vty.h"
#include "vrf.h"
#include "plist.h"
#include "nexthop.h"
#include "table.h"
#include "lib_errors.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_vty.h"
#include "pim_str.h"
#include "pim_iface.h"
#include "pim_rp.h"
#include "pim_rpf.h"
#include "pim_sock.h"
#include "pim_memory.h"
#include "pim_neighbor.h"
#include "pim_msdp.h"
#include "pim_nht.h"
#include "pim_mroute.h"
#include "pim_oil.h"
#include "pim_zebra.h"
#include "pim_bsm.h"
#include "pim_util.h"
#include "pim_ssm.h"
#include "termtable.h"

static void pim_upstream_update(struct pim_instance *pim,
				struct pim_upstream *up);

/* Cleanup pim->rpf_hash each node data */
void pim_rp_list_hash_clean(void *data)
{
	struct pim_nexthop_cache *pnc = (struct pim_nexthop_cache *)data;

#ifdef DEV_BUILD
	/* PNC should not be deleted in pim_rp.c */
	CPP_NOTICE("cleanup required in aisle 4");
#endif
	list_delete(&pnc->rp_list);

	hash_clean(pnc->upstream_hash, NULL);
	hash_free(pnc->upstream_hash);
	pnc->upstream_hash = NULL;
	if (pnc->rib[0].nexthop)
		nexthops_free(pnc->rib[0].nexthop);
	if (pnc->rib[1].nexthop)
		nexthops_free(pnc->rib[1].nexthop);

	XFREE(MTYPE_PIM_NEXTHOP_CACHE, pnc);
}

static void pim_rp_info_free(struct rp_info *rp_info)
{
	XFREE(MTYPE_PIM_FILTER_NAME, rp_info->plist);
	XFREE(MTYPE_PIM_FILTER_NAME, rp_info->alist);
	XFREE(MTYPE_PIM_RP, rp_info);
}

int pim_rp_list_cmp(void *v1, void *v2)
{
	struct rp_info *rp1 = (struct rp_info *)v1;
	struct rp_info *rp2 = (struct rp_info *)v2;
	int ret;

	/*
	 * Sort by RP IP address
	 */
	ret = pim_addr_cmp(rp1->rp.rpf_addr, rp2->rp.rpf_addr);
	if (ret)
		return ret;

	/*
	 * Sort by group IP address
	 */
	ret = prefix_cmp(&rp1->group, &rp2->group);
	if (ret)
		return ret;

	return 0;
}

void pim_rp_init(struct pim_instance *pim)
{
	struct rp_info *rp_info;
	struct route_node *rn;

	pim->rp_list = list_new();
	pim->rp_list->del = (void (*)(void *))pim_rp_info_free;
	pim->rp_list->cmp = pim_rp_list_cmp;

	pim->rp_table = route_table_init();

	pim->fb_rp_list = list_new();
	pim->fb_rp_list->del = (void (*)(void *))pim_rp_info_free;
	pim->fb_rp_list->cmp = pim_rp_list_cmp;
	pim->fb_rp_table = route_table_init();

	rp_info = XCALLOC(MTYPE_PIM_RP, sizeof(*rp_info));

	if (!pim_get_all_mcast_group(&rp_info->group)) {
		flog_err(EC_LIB_DEVELOPMENT,
			 "Unable to convert all-multicast prefix");
		list_delete(&pim->fb_rp_list);
		route_table_finish(pim->fb_rp_table);
		list_delete(&pim->rp_list);
		route_table_finish(pim->rp_table);
		XFREE(MTYPE_PIM_RP, rp_info);
		return;
	}
	rp_info->rp.rpf_addr = PIMADDR_ANY;

	listnode_add(pim->rp_list, rp_info);

	rn = route_node_get(pim->rp_table, &rp_info->group);
	rn->info = rp_info;
	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("Allocated: %p for rp_info: %p(%pFX) Lock: %d", rn,
			   rp_info, &rp_info->group,
			   route_node_get_lock_count(rn));

#if PIM_IPV == 6
	/*
	 * Embedded RP defaults
	 */
	pim->embedded_rp.enable = false;
	pim->embedded_rp.group_list = NULL;
	pim->embedded_rp.maximum_rps = PIM_EMBEDDED_RP_MAXIMUM;

	pim->embedded_rp.table = route_table_init();
#endif /* PIM_IPV == 6 */
}

void pim_rp_free(struct pim_instance *pim)
{
#if PIM_IPV == 6
	struct route_node *rn;

	pim_embedded_rp_set_group_list(pim, NULL);

	for (rn = route_top(pim->embedded_rp.table); rn; rn = route_next(rn)) {
		pim_embedded_rp_free(pim, rn->info);
		rn->info = NULL;
	}

	route_table_finish(pim->embedded_rp.table);
	pim->embedded_rp.table = NULL;
#endif /* PIM_IPV == 6 */

	if (pim->fb_rp_list)
		list_delete(&pim->fb_rp_list);
	if (pim->fb_rp_table)
		route_table_finish(pim->fb_rp_table);
	pim->fb_rp_table = NULL;

	if (pim->rp_table)
		route_table_finish(pim->rp_table);
	pim->rp_table = NULL;

	if (pim->rp_list)
		list_delete(&pim->rp_list);
}

/*
 * Given an RP's prefix-list, return the RP's rp_info for that prefix-list
 */
static struct rp_info *pim_rp_find_rpaddr(struct pim_instance *pim,
					  enum rp_source rp_src, pim_addr rp)
{
	struct list *list;
	struct listnode *node;
	struct rp_info *rp_info;

	list = (rp_src != RP_SRC_FALLBACK) ? pim->rp_list : pim->fb_rp_list;

	for (ALL_LIST_ELEMENTS_RO(list, node, rp_info))
		if (pim_addr_cmp(rp, rp_info->rp.rpf_addr) == 0 &&
		    rp_info->rp_src == rp_src)
			return rp_info;
	return NULL;
}

/*
 * Given an RP's prefix-list, return the RP's rp_info for that prefix-list
 */
static struct rp_info *pim_rp_find_prefix_list(struct pim_instance *pim,
					       enum rp_source rp_src,
					       pim_addr rp, const char *plist)
{
	struct list *list;
	struct listnode *node;
	struct rp_info *rp_info;

	list = (rp_src != RP_SRC_FALLBACK) ? pim->rp_list : pim->fb_rp_list;

	for (ALL_LIST_ELEMENTS_RO(list, node, rp_info)) {
		if ((!pim_addr_cmp(rp, rp_info->rp.rpf_addr)) &&
		    rp_info->rp_src == rp_src && rp_info->plist &&
		    strcmp(rp_info->plist, plist) == 0) {
			return rp_info;
		}
	}

	return NULL;
}

/*
 * Given an RP's prefix-list, return the RP's rp_info for that prefix-list
 */
static struct rp_info *pim_rp_find_access_list(struct pim_instance *pim,
					       enum rp_source rp_src,
					       pim_addr rp, const char *alist)
{
	struct list *list;
	struct listnode *node;
	struct rp_info *rp_info;

	list = (rp_src != RP_SRC_FALLBACK) ? pim->rp_list : pim->fb_rp_list;

	for (ALL_LIST_ELEMENTS_RO(list, node, rp_info)) {
		if (pim_addr_cmp(rp, rp_info->rp.rpf_addr) == 0 &&
		    rp_info->rp_src == rp_src && rp_info->alist &&
		    strcmp(rp_info->alist, alist) == 0) {
			return rp_info;
		}
	}

	return NULL;
}

/*
 * Return true if plist is used by any rp_info
 */
static int pim_rp_prefix_list_used(struct pim_instance *pim, const char *plist)
{
	struct listnode *node;
	struct rp_info *rp_info;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (rp_info->plist && strcmp(rp_info->plist, plist) == 0) {
			return 1;
		}
	}

	for (ALL_LIST_ELEMENTS_RO(pim->fb_rp_list, node, rp_info)) {
		if (rp_info->plist && strcmp(rp_info->plist, plist) == 0) {
			return 1;
		}
	}

	return 0;
}

/*
 * Return true if plist is used by any rp_info
 */
static int pim_rp_access_list_used(struct pim_instance *pim, const char *alist)
{
	struct listnode *node;
	struct rp_info *rp_info;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (rp_info->alist && strcmp(rp_info->alist, alist) == 0) {
			return 1;
		}
	}
	for (ALL_LIST_ELEMENTS_RO(pim->fb_rp_list, node, rp_info)) {
		if (rp_info->alist && strcmp(rp_info->alist, alist) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * Given an RP's address, return the RP's rp_info that is an exact match for
 * 'group'
 */
static struct rp_info *pim_rp_find_exact(struct pim_instance *pim,
					 enum rp_source rp_src, pim_addr rp,
					 const struct prefix *group)
{
	struct list *list;
	struct listnode *node;
	struct rp_info *rp_info;

	list = (rp_src != RP_SRC_FALLBACK) ? pim->rp_list : pim->fb_rp_list;

	for (ALL_LIST_ELEMENTS_RO(list, node, rp_info)) {
		if ((!pim_addr_cmp(rp, rp_info->rp.rpf_addr)) &&
		    rp_info->rp_src == rp_src &&
		    prefix_same(&rp_info->group, group))
			return rp_info;
	}

	return NULL;
}

/*
 * XXX: long-term issue:  we don't actually have a good "ip address-list"
 * implementation.  ("access-list XYZ" is the closest but honestly it's
 * kinda garbage.)
 *
 * So it's using a prefix-list to match an address here, which causes very
 * unexpected results for the user since prefix-lists by default only match
 * when the prefix length is an exact match too.  i.e. you'd have to add the
 * "le 32" and do "ip prefix-list foo permit 10.0.0.0/24 le 32"
 *
 * To avoid this pitfall, this code uses "address_mode = true" for the prefix
 * list match (this is the only user for that.)
 *
 * In the long run, we need to add a "ip address-list", but that's a wholly
 * separate bag of worms, and existing configs using ip prefix-list would
 * drop into the UX pitfall.
 */

#include "lib/plist_int.h"

static inline bool pim_rp_try_alist(struct rp_info *rp_info,
				    const struct prefix *group,
				    struct prefix *ent)
{
	struct prefix nullpfx = {.family = PIM_AFI, .prefixlen = 0};
	struct prefix tmp;
#if PIM_IPV == 4
	struct in_addr tmpmask;
#else
	size_t i;
	struct in6_addr tmpmask;
#endif
	struct filter *hit = NULL;
	struct access_list *acl;

	if (!rp_info->alist)
		return false;

	acl = access_list_lookup(PIM_AFI, rp_info->alist);
	if (!acl)
		return false;

	if (access_list_apply_sadr(acl, &nullpfx, group, &hit) == FILTER_DENY)
		return false;

	assert(hit);

	if (!hit->cisco || !hit->u.cfilter.extended) {
		zlog_err(
			"BROKEN CONFIG: non-extended entry in access list %s for RP config",
			rp_info->alist);
		return false;
	}

	/* mask is inverted in ext ACL... */
#if PIM_IPV == 4
	tmpmask.s_addr = ~hit->u.cfilter.sadr.dst_mask.s_addr;
#else
	for (i = 0; i < sizeof(tmpmask) / 4; i++)
		tmpmask.s6_addr32[i] =
			~hit->u.cfilter.sadr6.dst_mask.s6_addr32[i];
#endif

	tmp.family = PIM_AF;
#if PIM_IPV == 4
	tmp.prefixlen = ip_masklen(tmpmask);
	tmp.u.prefix4 = hit->u.cfilter.sadr.dst;
#else
	tmp.prefixlen = (uint16_t)ip6_masklen(tmpmask);
	tmp.u.prefix6 = hit->u.cfilter.sadr6.dst;
#endif

#if PIM_IPV == 4
	if (tmp.prefixlen < 4) {
		tmp.prefixlen = 4;
		tmp.u.prefix4.s_addr = inet_addr("224.0.0.0");
	}
#else
	if (tmp.prefixlen < 8) {
		tmp.prefixlen = 8;
		tmp.u.prefix6 = (struct in6_addr){.s6_addr32 = {0xFF0000}};
	}
#endif

	if (ent->prefixlen >= tmp.prefixlen)
		return false;

	*ent = tmp;
	return true;
}

/*
 * Given a group, return the rp_info for that group
 */
struct rp_info *pim_rp_find_match_group(struct pim_instance *pim,
					const struct prefix *group)
{
	struct listnode *node;
	struct rp_info *best = NULL;
	struct rp_info *rp_info;
	struct prefix_list *plist;
	struct prefix alist_pfx = {.prefixlen = 0};
	const struct prefix *bp = NULL;
	struct route_node *rn;

#if PIM_IPV == 6
	/*
	 * Embedded RP search. Always try to match against embedded RP first.
	 */
	rn = route_node_match(pim->embedded_rp.table, group);
	if (rn != NULL) {
		rp_info = rn->info ? rn->info : NULL;

		if (rp_info && PIM_DEBUG_PIM_TRACE_DETAIL) {
			zlog_debug("Lookedup(%pFX): rn %p found:%pFX", group,
				   rn, &rp_info->group);
		}

		route_unlock_node(rn);
		if (rp_info)
			return rp_info;
	}
#endif /* PIM_IPV == 6 */

	bp = NULL;
	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (!rp_info->rp.source_nexthop.interface)
			continue;

		if (rp_info->plist) {
			const struct prefix_list_entry *entry;
			plist = prefix_list_lookup(PIM_AFI, rp_info->plist);

			if (prefix_list_apply_ext(plist, &entry, group, true) ==
				    PREFIX_DENY ||
			    !entry)
				continue;

			if (!bp) {
				best = rp_info;
				bp = &entry->prefix;
				continue;
			}

			if (bp && bp->prefixlen < entry->prefix.prefixlen) {
				best = rp_info;
				bp = &entry->prefix;
				continue;
			}
		}

		if (pim_rp_try_alist(rp_info, group, &alist_pfx)) {
			if (!bp) {
				best = rp_info;
				bp = &alist_pfx;
				continue;
			}

			if (bp && bp->prefixlen < alist_pfx.prefixlen) {
				best = rp_info;
				bp = &alist_pfx;
				continue;
			}
		}
	}

	if (pim->rp_table == NULL)
		return best;

	rn = route_node_match(pim->rp_table, group);
	if (!rn) {
		flog_err(
			EC_LIB_DEVELOPMENT,
			"%s: BUG We should have found default group information",
			__func__);
		return best;
	}

	rp_info = rn->info;
	if (PIM_DEBUG_PIM_TRACE_DETAIL) {
		if (best)
			zlog_debug(
				"Lookedup(%pFX): prefix_list match %s, rn %p found: %pFX",
				group, best->plist, rn, &rp_info->group);
		else
			zlog_debug("Lookedup(%pFX): rn %p found:%pFX", group,
				   rn, &rp_info->group);
	}

	route_unlock_node(rn);

	for (rp_info = NULL; rn; rn = rn->parent, rp_info = NULL) {
		rp_info = rn->info;

		if (rp_info && rp_info->rp.source_nexthop.interface)
			break;
	}

	if (rp_info && !rp_info->alist && !rp_info->plist) {
		if (!best)
			best = rp_info;
		else if (rp_info->group.prefixlen < best->group.prefixlen)
			best = rp_info;
	}

	if (best && !pim_addr_is_any(best->rp.rpf_addr)) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"Lookedup: group %pFX, rp_info %p group %pFX, RP %pPA",
				group, best, &best->group, &best->rp.rpf_addr);
		return best;
	}

	for (ALL_LIST_ELEMENTS_RO(pim->fb_rp_list, node, rp_info)) {
		if (!rp_info->rp.source_nexthop.interface)
			continue;

		if (rp_info->plist) {
			const struct prefix_list_entry *entry;
			plist = prefix_list_lookup(PIM_AFI, rp_info->plist);

			if (prefix_list_apply_ext(plist, &entry, group, true) ==
				    PREFIX_DENY ||
			    !entry)
				continue;

			if (!bp) {
				best = rp_info;
				bp = &entry->prefix;
				continue;
			}

			if (bp && bp->prefixlen < entry->prefix.prefixlen) {
				best = rp_info;
				bp = &entry->prefix;
			}
		}

		if (pim_rp_try_alist(rp_info, group, &alist_pfx)) {
			if (!bp) {
				best = rp_info;
				bp = &alist_pfx;
				continue;
			}

			if (bp && bp->prefixlen < alist_pfx.prefixlen) {
				best = rp_info;
				bp = &alist_pfx;
				continue;
			}
		}
	}

	rp_info = NULL;

	rn = route_node_match(pim->fb_rp_table, group);
	if (rn) {
		route_unlock_node(rn);

		for (; rn; rn = rn->parent, rp_info = NULL) {
			rp_info = rn->info;

			if (rp_info && rp_info->rp.source_nexthop.interface)
				break;
		}
	}

	if (rp_info) {
		/*
		 * Fix clang NULL deference warning:
		 * if `best` was never chosen then pick the first one as best.
		 */
		if (best == NULL)
			best = rp_info;

		if (pim_addr_is_any(best->rp.rpf_addr))
			best = rp_info;
		else if (rp_info->group.prefixlen < best->group.prefixlen)
			best = rp_info;
	}

	if (PIM_DEBUG_PIM_TRACE) {
		if (best)
			zlog_debug("Lookedup: group %pFX, fallback rp_info %p group %pFX, RP %pPA",
				   group, best, &best->group, &best->rp.rpf_addr);
		else
			zlog_debug("Lookedup: group %pFX, no RP found", group);
	}

	return best;
}

/*
 * Return the 224.0.0.0/4 pseudo-RP: it always exists in the RP table, even
 * when unconfigured (RP address is any) or unreachable, and it must not be
 * confused with a fallback RP covering the same range.
 */
struct rp_info *pim_rp_find_match_root(struct pim_instance *pim)
{
	struct route_node *rn;
	struct rp_info *rpi;
	struct prefix g;

	pim_get_all_mcast_group(&g);
	rn = route_node_lookup(pim->rp_table, &g);
	assertf(rn && rn->info, "cannot find dummy RP for all multicast");
	rpi = rn->info;
	route_unlock_node(rn);
	return rpi;
}

/*
 * When the user makes "ip pim rp" configuration changes or if they change the
 * prefix-list(s) used by these statements we must tickle the upstream state
 * for each group to make them re-lookup who their RP should be.
 *
 * This is a placeholder function for now.
 */
static void pim_rp_refresh_group_to_rp_mapping_thread(struct thread *t)
{
	struct pim_instance *pim = THREAD_ARG(t);
	struct pim_upstream *up;

	THREAD_OFF(pim->t_refresh_group_to_rp);

	pim_msdp_i_am_rp_changed(pim);
	/* pim_upstream_reeval_use_rpt(pim);
	 * inlined below, don't loop over all S,G twice
	 */

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		struct prefix grp;
		struct rp_info *trp_info;

#if PIM_IPV == 4
		grp.family = AF_INET;
		grp.prefixlen = IPV4_MAX_BITLEN;
		grp.u.prefix4 = up->sg.grp;
#else
		grp.family = AF_INET6;
		grp.prefixlen = IPV6_MAX_BITLEN;
		grp.u.prefix6 = up->sg.grp;
#endif

		trp_info = pim_rp_find_match_group(pim, &grp);

		if (!trp_info && PIM_DEBUG_PIM_TRACE)
			zlog_debug("Group to RP refresh: no RP info for %pFX",
				   &grp);

		if (pim_addr_is_any(up->sg.src)) {
			/* RP not found for the group grp */
			if (!trp_info ||
			    pim_addr_is_any(trp_info->rp.rpf_addr)) {
				/*
				 * The (*,G) upstream is tracked in the RP's
				 * nexthop cache keyed by up->upstream_addr.
				 * Remove it from that bucket before clearing the
				 * RPF and resetting upstream_addr; otherwise the
				 * stale entry survives (pim_upstream_del() later
				 * releases NHT tracking keyed by the by-then ANY
				 * upstream_addr and misses the old bucket),
				 * leaving a dangling upstream pointer that a
				 * later Zebra nexthop update would walk.
				 */
				if (!pim_addr_is_any(up->upstream_addr))
					pim_delete_tracked_upstream(up);
				pim_upstream_rpf_clear(pim, up);
				pim_upstream_remove_address(up);
				pim_rp_set_upstream_addr(pim, &up->upstream_addr,
							 up->sg.src, up->sg.grp);
			} else {
				/* RP found for the group grp */
				pim_upstream_update(pim, up);
			}
		} else {
			/* pim_upstream_reeval_use_rpt(pim); */
			pim_upstream_update_use_rpt(up, true /*update_mroute*/);

#ifdef VENDOR_SOUTHBOUND
			if (trp_info && IPV4_ADDR_CMP(&trp_info->rp.rpf_addr,
						      &up->sb_register_to))
				pim_upstream_mroute_add(up->channel_oil,
							__func__);
#endif
		}
	}

	pim_zebra_update_all_interfaces(pim);
}

/* since this walks through all groups, give it a 0.1s delay to accumulate
 * in case we have multiple things triggering a Group-to-RP reeval
 */
void pim_rp_refresh_group_to_rp_mapping(struct pim_instance *pim)
{
	/* this is not allowed to delay further, even if re-triggered */
	if (pim->t_refresh_group_to_rp)
		return;

	thread_add_timer_msec(router->master,
			      pim_rp_refresh_group_to_rp_mapping_thread, pim,
			      100, &pim->t_refresh_group_to_rp);
}

void pim_rp_prefix_list_update(struct pim_instance *pim,
			       struct prefix_list *plist)
{
	struct listnode *node;
	struct rp_info *rp_info;
	int refresh_needed = 0;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (rp_info->plist &&
		    strcmp(rp_info->plist, prefix_list_name(plist)) == 0) {
			refresh_needed = 1;
			break;
		}
	}

	for (ALL_LIST_ELEMENTS_RO(pim->fb_rp_list, node, rp_info)) {
		if (rp_info->plist &&
		    strcmp(rp_info->plist, prefix_list_name(plist)) == 0) {
			refresh_needed = 1;
			break;
		}
	}

	if (refresh_needed)
		pim_rp_refresh_group_to_rp_mapping(pim);
}

static int pim_rp_check_interface_addrs(struct rp_info *rp_info,
					struct pim_interface *pim_ifp)
{
	struct listnode *node;
	struct pim_secondary_addr *sec_addr;
	pim_addr sec_paddr;

	if (!pim_addr_cmp(pim_ifp->primary_address, rp_info->rp.rpf_addr))
		return 1;

	if (!pim_ifp->sec_addr_list) {
		return 0;
	}

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->sec_addr_list, node, sec_addr)) {
		sec_paddr = pim_addr_from_prefix(&sec_addr->addr);
		/* If an RP-address is self, It should be enough to say
		 * I am RP the prefix-length should not matter here */
		if (!pim_addr_cmp(sec_paddr, rp_info->rp.rpf_addr))
			return 1;
	}

	return 0;
}

static void pim_rp_check_interfaces(struct pim_instance *pim,
				    struct rp_info *rp_info)
{
	struct interface *ifp;

	rp_info->i_am_rp = 0;
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		if (pim_rp_check_interface_addrs(rp_info, pim_ifp)) {
			rp_info->i_am_rp = 1;
		}
	}
}

static void pim_upstream_update(struct pim_instance *pim,
				struct pim_upstream *up)
{
	struct pim_rpf old_rpf;
	enum pim_rpf_result rpf_result;
	pim_addr old_upstream_addr;
	pim_addr new_upstream_addr;

	old_upstream_addr = up->upstream_addr;
	pim_rp_set_upstream_addr(pim, &new_upstream_addr, up->sg.src,
				 up->sg.grp);

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("%s: %pSG upstream update, US %pPA -> %pPA",
			   __func__, &up->sg, &old_upstream_addr,
			   &new_upstream_addr);

	if (!pim_addr_cmp(old_upstream_addr, new_upstream_addr))
		return;

	/* Update the upstream address */
	pim_upstream_remove_address(up);
	up->upstream_addr = new_upstream_addr;

	old_rpf.source_nexthop.interface = up->rpf.source_nexthop.interface;

	rpf_result = pim_rpf_update(pim, up, &old_rpf, __func__);
	if (rpf_result == PIM_RPF_FAILURE)
		pim_mroute_del(up->channel_oil, __func__);

	/* update kernel multicast forwarding cache (MFC) */
	if (up->rpf.source_nexthop.interface && up->channel_oil)
		pim_upstream_mroute_iif_update(up->channel_oil, __func__);

	if (rpf_result == PIM_RPF_CHANGED ||
	    (rpf_result == PIM_RPF_FAILURE && old_rpf.source_nexthop.interface))
		pim_zebra_upstream_rpf_changed(pim, up, &old_rpf);
}

int pim_rp_valid(struct pim_instance *pim, pim_addr rp_addr,
		 struct prefix group, const char *plist, const char *alist,
		 enum rp_source rp_src_flag)
{
	struct rp_info *rp_all;
	struct rp_info *tmp_rp_info;

	if (pim_addr_is_any(rp_addr))
		return PIM_RP_BAD_ADDRESS;

	/* These are mutually exclusive and can't be set at the same time. */
	assert(!(plist && alist));

	if (plist) {
		/*
		 * Return if the prefix-list is already configured for this RP
		 */
		if (pim_rp_find_prefix_list(pim, rp_src_flag, rp_addr, plist))
			return PIM_SUCCESS;

		/*
		 * Barf if the prefix-list is already configured for an RP
		 */
		if (pim_rp_prefix_list_used(pim, plist))
			return PIM_RP_PFXLIST_IN_USE;

	} else if (alist) {
		/*
		 * Return if the prefix-list is already configured for this RP
		 */
		if (pim_rp_find_access_list(pim, rp_src_flag, rp_addr, alist))
			return PIM_SUCCESS;

		/*
		 * Barf if the prefix-list is already configured for an RP
		 */
		if (pim_rp_access_list_used(pim, alist))
			return PIM_RP_ACLIST_IN_USE;

	} else {
		rp_all = pim_rp_find_match_root(pim);

		/*
		 * Barf if group is a non-multicast subnet
		 */
		if (!prefix_match(&rp_all->group, &group))
			return PIM_GROUP_BAD_ADDRESS;

		/*
		 * Barf if this group is already covered by some other RP
		 */
		tmp_rp_info = pim_rp_find_match_group(pim, &group);

		bool new_is_fb = (rp_src_flag == RP_SRC_FALLBACK);
		bool tmp_is_fb =
			tmp_rp_info && (tmp_rp_info->rp_src == RP_SRC_FALLBACK);

		if (tmp_rp_info && (tmp_is_fb == new_is_fb)) {
			if (tmp_rp_info->plist)
				return PIM_GROUP_PFXLIST_OVERLAP;
			else if (tmp_rp_info->alist)
				return PIM_GROUP_ACLIST_OVERLAP;
			else {
				/*
				 * If the only RP that covers this group is an
				 * RP configured for
				 * 224.0.0.0/4 that is fine, ignore that one.
				 * For all others
				 * though we must return PIM_GROUP_OVERLAP
				 */
				if (prefix_same(&group, &tmp_rp_info->group)) {
					if ((rp_src_flag != RP_SRC_BSR) &&
					    (tmp_rp_info->rp_src ==
					     rp_src_flag))
						return PIM_GROUP_OVERLAP;
				}
			}
		}
	}

	return PIM_SUCCESS;
}

int pim_rp_new(struct pim_instance *pim, pim_addr rp_addr, struct prefix group,
	       const char *plist, const char *alist, enum rp_source rp_src_flag)
{
	int result = 0;
	struct list *list;
	struct route_table *table;
	struct rp_info *rp_info;
	struct rp_info *rp_all;
	struct listnode *node, *nnode;
	struct rp_info *tmp_rp_info;
	char buffer[BUFSIZ];
	pim_addr nht_p;
	struct route_node *rn = NULL;
	struct pim_upstream *up;
	bool upstream_updated = false;

	if (pim_addr_is_any(rp_addr))
		return PIM_RP_BAD_ADDRESS;

	if (rp_src_flag == RP_SRC_FALLBACK) {
		list = pim->fb_rp_list;
		table = pim->fb_rp_table;
	} else {
		list = pim->rp_list;
		table = pim->rp_table;
	}

	rp_info = XCALLOC(MTYPE_PIM_RP, sizeof(*rp_info));

	rp_info->rp.rpf_addr = rp_addr;
	prefix_copy(&rp_info->group, &group);
	rp_info->rp_src = rp_src_flag;

	/* These are mutually exclusive and can't be set at the same time. */
	assert(!(plist && alist));
	if (plist) {
		/*
		 * Return if the prefix-list is already configured for this RP
		 */
		if (pim_rp_find_prefix_list(pim, rp_src_flag, rp_addr, plist)) {
			XFREE(MTYPE_PIM_RP, rp_info);
			return PIM_SUCCESS;
		}

		/*
		 * Barf if the prefix-list is already configured for an RP
		 */
		if (pim_rp_prefix_list_used(pim, plist)) {
			XFREE(MTYPE_PIM_RP, rp_info);
			return PIM_RP_PFXLIST_IN_USE;
		}

		/*
		 * Free any existing rp_info entries for this RP
		 */
		for (ALL_LIST_ELEMENTS(list, node, nnode, tmp_rp_info)) {
			if (!pim_addr_cmp(rp_info->rp.rpf_addr,
					  tmp_rp_info->rp.rpf_addr)) {
				if (tmp_rp_info->plist)
					pim_rp_del_config(pim, rp_addr, NULL,
							  tmp_rp_info->plist,
							  NULL, rp_src_flag);
				else if (tmp_rp_info->alist)
					pim_rp_del_config(
						pim, rp_info->rp.rpf_addr, NULL,
						NULL, tmp_rp_info->alist,
						rp_src_flag);
				else
					pim_rp_del_config(
						pim, rp_addr,
						prefix2str(&tmp_rp_info->group,
							   buffer, BUFSIZ),
						NULL, NULL, rp_src_flag);
			}
		}

		rp_info->plist = XSTRDUP(MTYPE_PIM_FILTER_NAME, plist);
	} else if (alist) {
		/*
		 * Return if the prefix-list is already configured for this RP
		 */
		if (pim_rp_find_access_list(pim, rp_src_flag,
					    rp_info->rp.rpf_addr, alist)) {
			XFREE(MTYPE_PIM_RP, rp_info);
			return PIM_SUCCESS;
		}

		/*
		 * Barf if the prefix-list is already configured for an RP
		 */
		if (pim_rp_access_list_used(pim, alist)) {
			XFREE(MTYPE_PIM_RP, rp_info);
			return PIM_RP_ACLIST_IN_USE;
		}

		/*
		 * Free any existing rp_info entries for this RP
		 */
		for (ALL_LIST_ELEMENTS(list, node, nnode, tmp_rp_info)) {
			if (pim_addr_cmp(rp_info->rp.rpf_addr,
					 tmp_rp_info->rp.rpf_addr) == 0) {
				if (tmp_rp_info->plist)
					pim_rp_del_config(
						pim, rp_info->rp.rpf_addr, NULL,
						tmp_rp_info->plist, NULL,
						rp_src_flag);
				else if (tmp_rp_info->alist)
					pim_rp_del_config(
						pim, rp_info->rp.rpf_addr, NULL,
						NULL, tmp_rp_info->alist,
						rp_src_flag);
				else
					pim_rp_del_config(
						pim, rp_info->rp.rpf_addr,
						prefix2str(&tmp_rp_info->group,
							   buffer, BUFSIZ),
						NULL, NULL, rp_src_flag);
			}
		}

		rp_info->alist = XSTRDUP(MTYPE_PIM_FILTER_NAME, alist);
	} else {
		struct route_node *rn;

		rp_all = pim_rp_find_match_root(pim);

		/*
		 * Barf if group is a non-multicast subnet
		 */
		if (!prefix_match(&rp_all->group, &rp_info->group)) {
			XFREE(MTYPE_PIM_RP, rp_info);
			return PIM_GROUP_BAD_ADDRESS;
		}

		/*
		 * Remove any prefix-list rp_info entries for this RP
		 */
		for (ALL_LIST_ELEMENTS(list, node, nnode, tmp_rp_info)) {
			if (tmp_rp_info->plist &&
			    (!pim_addr_cmp(rp_info->rp.rpf_addr,
					   tmp_rp_info->rp.rpf_addr))) {
				pim_rp_del_config(pim, rp_addr, NULL,
						  tmp_rp_info->plist, NULL,
						  rp_src_flag);
				continue;
			}
			if (tmp_rp_info->alist &&
			    pim_addr_cmp(rp_info->rp.rpf_addr,
					 tmp_rp_info->rp.rpf_addr) == 0) {
				pim_rp_del_config(
					pim, rp_info->rp.rpf_addr, NULL, NULL,
					tmp_rp_info->alist, rp_src_flag);
				continue;
			}
		}

		/*
		 * Take over the 224.0.0.0/4 group if the rp is INADDR_ANY
		 */
		if (rp_src_flag != RP_SRC_FALLBACK &&
		    prefix_same(&rp_all->group, &rp_info->group) &&
		    pim_rpf_addr_is_inaddr_any(&rp_all->rp)) {
			rp_all->rp.rpf_addr = rp_info->rp.rpf_addr;
			rp_all->rp_src = rp_src_flag;
			XFREE(MTYPE_PIM_RP, rp_info);

			/* Register addr with Zebra NHT */
			nht_p = rp_all->rp.rpf_addr;
			if (PIM_DEBUG_PIM_NHT_RP)
				zlog_debug(
					"%s: NHT Register rp_all addr %pPA grp %pFX ",
					__func__, &nht_p, &rp_all->group);

			frr_each (rb_pim_upstream, &pim->upstream_head, up) {
				/* Find (*, G) upstream whose RP is not
				 * configured yet
				 */
				if (pim_addr_is_any(up->upstream_addr) &&
				    pim_addr_is_any(up->sg.src)) {
					struct prefix grp;
					struct rp_info *trp_info;

					pim_addr_to_prefix(&grp, up->sg.grp);
					trp_info = pim_rp_find_match_group(
						pim, &grp);
					if (trp_info == rp_all) {
						pim_upstream_update(pim, up);
						upstream_updated = true;
					}
				}
			}
			if (upstream_updated)
				pim_zebra_update_all_interfaces(pim);

			pim_rp_check_interfaces(pim, rp_all);
			pim_rp_refresh_group_to_rp_mapping(pim);
			pim_find_or_track_nexthop(pim, nht_p, NULL, rp_all,
						  NULL);

			if (!pim_ecmp_nexthop_lookup(pim,
						     &rp_all->rp.source_nexthop,
						     nht_p, &rp_all->group, 1))
				return PIM_RP_NO_PATH;
			return PIM_SUCCESS;
		}

		/*
		 * Return if the group is already configured for this RP
		 */
		tmp_rp_info = pim_rp_find_exact(pim, rp_src_flag, rp_addr,
						&rp_info->group);
		if (tmp_rp_info) {
			if ((tmp_rp_info->rp_src != rp_src_flag) &&
			    (rp_src_flag == RP_SRC_STATIC))
				/* replace RP_SRC_BSR entry */
				tmp_rp_info->rp_src = rp_src_flag;
			XFREE(MTYPE_PIM_RP, rp_info);
			return result;
		}

		/*
		 * Barf if this group is already covered by some other RP
		 */
		tmp_rp_info = pim_rp_find_match_group(pim, &rp_info->group);

		bool new_is_fb = (rp_src_flag == RP_SRC_FALLBACK);
		bool tmp_is_fb =
			tmp_rp_info && (tmp_rp_info->rp_src == RP_SRC_FALLBACK);
		if (tmp_rp_info && (tmp_is_fb == new_is_fb)) {
			if (tmp_rp_info->plist) {
				XFREE(MTYPE_PIM_RP, rp_info);
				return PIM_GROUP_PFXLIST_OVERLAP;
			} else if (tmp_rp_info->alist) {
				XFREE(MTYPE_PIM_RP, rp_info);
				return PIM_GROUP_ACLIST_OVERLAP;
			} else {
				/*
				 * If the only RP that covers this group is an
				 * RP configured for
				 * 224.0.0.0/4 that is fine, ignore that one.
				 * For all others
				 * though we must return PIM_GROUP_OVERLAP
				 */
				if (prefix_same(&rp_info->group,
						&tmp_rp_info->group)) {
					if ((rp_src_flag == RP_SRC_BSR) &&
					    (tmp_rp_info->rp_src ==
					     rp_src_flag)) {
						XFREE(MTYPE_PIM_RP, rp_info);
						return PIM_GROUP_OVERLAP;
					}

					result = pim_rp_change(
						pim, rp_addr,
						tmp_rp_info->group,
						rp_src_flag);
					XFREE(MTYPE_PIM_RP, rp_info);
					return result;
				}
			}
		}

		/*
		 * The lookup above skips unreachable RPs, but the range may
		 * still have one: change it like a reachable one instead of
		 * replacing its RP table node (which, for 224.0.0.0/4, is
		 * the pseudo-RP).
		 */
		rn = route_node_lookup(table, &rp_info->group);
		if (rn) {
			tmp_rp_info = rn->info;
			route_unlock_node(rn);
			if (!pim_addr_is_any(tmp_rp_info->rp.rpf_addr)) {
				XFREE(MTYPE_PIM_RP, rp_info);
				if ((rp_src_flag == RP_SRC_BSR) &&
				    (tmp_rp_info->rp_src == rp_src_flag))
					return PIM_GROUP_OVERLAP;

				return pim_rp_change(pim, rp_addr,
						     tmp_rp_info->group,
						     rp_src_flag);
			}
		}

		rn = route_node_get(table, &rp_info->group);
		rn->info = rp_info;
	}

	listnode_add_sort(list, rp_info);

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("Allocated: %p for rp_info: %p(%pFX) Lock: %d", rn,
			   rp_info, &rp_info->group,
			   rn ? route_node_get_lock_count(rn) : 0);

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (pim_addr_is_any(up->sg.src)) {
			struct prefix grp;
			struct rp_info *trp_info;

			pim_addr_to_prefix(&grp, up->sg.grp);
			trp_info = pim_rp_find_match_group(pim, &grp);

			if (trp_info == rp_info) {
				pim_upstream_update(pim, up);
				upstream_updated = true;
			}
		}
	}

	if (upstream_updated)
		pim_zebra_update_all_interfaces(pim);

	pim_rp_check_interfaces(pim, rp_info);
	pim_rp_refresh_group_to_rp_mapping(pim);

	/* Register addr with Zebra NHT */
	nht_p = rp_info->rp.rpf_addr;
	if (PIM_DEBUG_PIM_NHT_RP)
		zlog_debug("%s: NHT Register RP addr %pPA grp %pFX with Zebra ",
			   __func__, &nht_p, &rp_info->group);
	pim_find_or_track_nexthop(pim, nht_p, NULL, rp_info, NULL);
	if (!pim_ecmp_nexthop_lookup(pim, &rp_info->rp.source_nexthop, nht_p,
				     &rp_info->group, 1))
		return PIM_RP_NO_PATH;

	return PIM_SUCCESS;
}

void pim_rp_del_config(struct pim_instance *pim, pim_addr rp_addr,
		       const char *group_range, const char *plist,
		       const char *alist, enum rp_source rp_src_flag)
{
	struct prefix group;
	int result;

	if (group_range == NULL)
		result = pim_get_all_mcast_group(&group);
	else
		result = str2prefix(group_range, &group);

	if (!result) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"%s: String to prefix failed for %pPAs group",
				__func__, &rp_addr);
		return;
	}

	pim_rp_del(pim, rp_addr, group, plist, alist, rp_src_flag);
}

int pim_rp_del(struct pim_instance *pim, pim_addr rp_addr, struct prefix group,
	       const char *plist, const char *alist, enum rp_source rp_src_flag)
{
	struct list *list;
	struct route_table *table;
	struct rp_info *rp_info;
	struct rp_info *rp_all;
	pim_addr nht_p;
	struct route_node *rn;
	bool was_plist = false;
	bool was_alist = false;
	struct rp_info *trp_info;
	struct pim_upstream *up;
	struct bsgrp_node *bsgrp = NULL;
	struct bsm_rpinfo *bsrp = NULL;

	if (rp_src_flag == RP_SRC_FALLBACK) {
		list = pim->fb_rp_list;
		table = pim->fb_rp_table;
	} else {
		list = pim->rp_list;
		table = pim->rp_table;
	}

	if (plist)
		rp_info = pim_rp_find_prefix_list(pim, rp_src_flag, rp_addr,
						  plist);
	else if (alist)
		rp_info = pim_rp_find_access_list(pim, rp_src_flag, rp_addr,
						  alist);
	else if (group.prefixlen == 0)
		rp_info = pim_rp_find_rpaddr(pim, rp_src_flag, rp_addr);
	else
		rp_info = pim_rp_find_exact(pim, rp_src_flag, rp_addr, &group);

	if (!rp_info)
		return PIM_RP_NOT_FOUND;

	if (rp_info->plist) {
		XFREE(MTYPE_PIM_FILTER_NAME, rp_info->plist);
		was_plist = true;
	}

	if (rp_info->alist) {
		XFREE(MTYPE_PIM_FILTER_NAME, rp_info->alist);
		was_alist = true;
	}

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("%s: Delete RP %pPA for the group %pFX", __func__,
			   &rp_addr, &group);

	/* While static RP is getting deleted, we need to check if dynamic RP
	 * present for the same group in BSM RP table, then install the dynamic
	 * RP for the group node into the main rp table
	 *
	 * (not necessary for RP_SRC_FALLBACK)
	 */
	if (rp_src_flag == RP_SRC_STATIC) {
		bsgrp = pim_bsm_get_bsgrp_node(&pim->global_scope, &group);

		if (bsgrp) {
			bsrp = bsm_rpinfos_first(bsgrp->bsrp_list);
			if (bsrp) {
				if (PIM_DEBUG_PIM_TRACE)
					zlog_debug(
						"%s: BSM RP %pPA found for the group %pFX",
						__func__, &bsrp->rp_address,
						&group);
				return pim_rp_change(pim, bsrp->rp_address,
						     group, RP_SRC_BSR);
			}
		} else {
			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug(
					"%s: BSM RP not found for the group %pFX",
					__func__, &group);
		}
	}

	/* Deregister addr with Zebra NHT */
	nht_p = rp_info->rp.rpf_addr;
	if (PIM_DEBUG_PIM_NHT_RP)
		zlog_debug("%s: Deregister RP addr %pPA with Zebra ", __func__,
			   &nht_p);
	pim_delete_tracked_nexthop(pim, nht_p, NULL, rp_info);

	rp_all = pim_rp_find_match_root(pim);

	if (rp_all == rp_info && rp_src_flag != RP_SRC_FALLBACK) {
		frr_each (rb_pim_upstream, &pim->upstream_head, up) {
			/* Find the upstream (*, G) whose upstream address is
			 * same as the deleted RP
			 */
			pim_addr rpf_addr;

			rpf_addr = rp_info->rp.rpf_addr;
			if (!pim_addr_cmp(up->upstream_addr, rpf_addr) &&
			    pim_addr_is_any(up->sg.src)) {
				struct prefix grp;

				pim_addr_to_prefix(&grp, up->sg.grp);
				trp_info = pim_rp_find_match_group(pim, &grp);
				if (trp_info == rp_all) {
					pim_delete_tracked_upstream(up);
					pim_upstream_rpf_clear(pim, up);
					pim_upstream_remove_address(up);
				}
			}
		}
		rp_all->rp.rpf_addr = PIMADDR_ANY;
		rp_all->i_am_rp = 0;
		pim_rp_nexthop_del(rp_all);
		/*
		 * The cleared (*,G)s may be covered by another RP (e.g. a
		 * fallback RP for the same range): let them look it up.
		 */
		pim_rp_refresh_group_to_rp_mapping(pim);
		return PIM_SUCCESS;
	}

	listnode_delete(list, rp_info);

	if (!was_plist && !was_alist) {
		rn = route_node_get(table, &rp_info->group);
		if (rn) {
			if (rn->info != rp_info)
				flog_err(
					EC_LIB_DEVELOPMENT,
					"Expected rn->info to be equal to rp_info");

			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug(
					"%s:Found for Freeing: %p for rp_info: %p(%pFX) Lock: %d",
					__func__, rn, rp_info, &rp_info->group,
					route_node_get_lock_count(rn));

			rn->info = NULL;
			route_unlock_node(rn);
			route_unlock_node(rn);
		}
	}

	pim_rp_refresh_group_to_rp_mapping(pim);

	XFREE(MTYPE_PIM_RP, rp_info);
	return PIM_SUCCESS;
}

int pim_rp_change(struct pim_instance *pim, pim_addr new_rp_addr,
		  struct prefix group, enum rp_source rp_src_flag)
{
	struct list *list;
	struct route_table *table;
	pim_addr nht_p;
	struct route_node *rn;
	int result = 0;
	struct rp_info *rp_info = NULL;
	struct pim_upstream *up;
	bool upstream_updated = false;
	pim_addr old_rp_addr;

	if (rp_src_flag == RP_SRC_FALLBACK) {
		list = pim->fb_rp_list;
		table = pim->fb_rp_table;
	} else {
		list = pim->rp_list;
		table = pim->rp_table;
	}

	rn = route_node_lookup(table, &group);
	if (!rn) {
		result = pim_rp_new(pim, new_rp_addr, group, NULL, NULL,
				    rp_src_flag);
		return result;
	}

	rp_info = rn->info;

	if (!rp_info) {
		route_unlock_node(rn);
		result = pim_rp_new(pim, new_rp_addr, group, NULL, NULL,
				    rp_src_flag);
		return result;
	}

	old_rp_addr = rp_info->rp.rpf_addr;
	if (!pim_addr_cmp(new_rp_addr, old_rp_addr)) {
		if (rp_info->rp_src != rp_src_flag) {
			rp_info->rp_src = rp_src_flag;
			route_unlock_node(rn);
			return PIM_SUCCESS;
		}
	}

	/* Deregister old RP addr with Zebra NHT */

	if (!pim_addr_is_any(old_rp_addr)) {
		nht_p = rp_info->rp.rpf_addr;
		if (PIM_DEBUG_PIM_NHT_RP)
			zlog_debug("%s: Deregister RP addr %pPA with Zebra ",
				   __func__, &nht_p);
		pim_delete_tracked_nexthop(pim, nht_p, NULL, rp_info);
	}

	pim_rp_nexthop_del(rp_info);
	listnode_delete(list, rp_info);
	/* Update the new RP address*/

	rp_info->rp.rpf_addr = new_rp_addr;
	rp_info->rp_src = rp_src_flag;
	rp_info->i_am_rp = 0;

	listnode_add_sort(list, rp_info);

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (pim_addr_is_any(up->sg.src)) {
			struct prefix grp;
			struct rp_info *trp_info;

			pim_addr_to_prefix(&grp, up->sg.grp);
			trp_info = pim_rp_find_match_group(pim, &grp);

			if (trp_info == rp_info) {
				pim_upstream_update(pim, up);
				upstream_updated = true;
			}
		}
	}

	if (upstream_updated)
		pim_zebra_update_all_interfaces(pim);

	/* Register new RP addr with Zebra NHT */
	nht_p = rp_info->rp.rpf_addr;
	if (PIM_DEBUG_PIM_NHT_RP)
		zlog_debug("%s: NHT Register RP addr %pPA grp %pFX with Zebra ",
			   __func__, &nht_p, &rp_info->group);

	pim_find_or_track_nexthop(pim, nht_p, NULL, rp_info, NULL);
	if (!pim_ecmp_nexthop_lookup(pim, &rp_info->rp.source_nexthop, nht_p,
				     &rp_info->group, 1)) {
		route_unlock_node(rn);
		return PIM_RP_NO_PATH;
	}

	pim_rp_check_interfaces(pim, rp_info);

	route_unlock_node(rn);

	pim_rp_refresh_group_to_rp_mapping(pim);

	return result;
}

void pim_rp_setup(struct pim_instance *pim)
{
	struct listnode *node;
	struct rp_info *rp_info;
	pim_addr nht_p;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
			continue;

		nht_p = rp_info->rp.rpf_addr;

		pim_find_or_track_nexthop(pim, nht_p, NULL, rp_info, NULL);
		if (!pim_ecmp_nexthop_lookup(pim, &rp_info->rp.source_nexthop,
					     nht_p, &rp_info->group, 1)) {
			if (PIM_DEBUG_PIM_NHT_RP)
				zlog_debug(
					"Unable to lookup nexthop for rp specified");
			pim_rp_nexthop_del(rp_info);
		}
	}

	for (ALL_LIST_ELEMENTS_RO(pim->fb_rp_list, node, rp_info)) {
		if (pim_addr_is_any(rp_info->rp.rpf_addr))
			continue;

		nht_p = rp_info->rp.rpf_addr;

		pim_find_or_track_nexthop(pim, nht_p, NULL, rp_info, NULL);
		if (!pim_ecmp_nexthop_lookup(pim, &rp_info->rp.source_nexthop,
					     nht_p, &rp_info->group, 1))
			if (PIM_DEBUG_PIM_NHT_RP)
				zlog_debug(
					"Unable to lookup nexthop for rp specified");
	}
}

/*
 * Checks to see if we should elect ourself the actual RP when new if
 * addresses are added against an interface.
 */
void pim_rp_check_on_if_add(struct pim_interface *pim_ifp)
{
	struct listnode *node;
	struct rp_info *rp_info;
	bool i_am_rp_changed = false;
	struct pim_instance *pim = pim_ifp->pim;

	if (pim->rp_list == NULL)
		return;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
			continue;

		/* if i_am_rp is already set nothing to be done (adding new
		 * addresses
		 * is not going to make a difference). */
		if (rp_info->i_am_rp) {
			continue;
		}

		if (pim_rp_check_interface_addrs(rp_info, pim_ifp)) {
			i_am_rp_changed = true;
			rp_info->i_am_rp = 1;
			if (PIM_DEBUG_PIM_NHT_RP)
				zlog_debug("%s: %pPA: i am rp", __func__,
					   &rp_info->rp.rpf_addr);
		}
	}

	for (ALL_LIST_ELEMENTS_RO(pim->fb_rp_list, node, rp_info)) {
		if (pim_addr_is_any(rp_info->rp.rpf_addr))
			continue;

		/* if i_am_rp is already set nothing to be done (adding new
		 * addresses
		 * is not going to make a difference). */
		if (rp_info->i_am_rp) {
			continue;
		}

		if (pim_rp_check_interface_addrs(rp_info, pim_ifp)) {
			i_am_rp_changed = true;
			rp_info->i_am_rp = 1;
			if (PIM_DEBUG_PIM_NHT_RP) {
				zlog_debug("%s: %pPA: i am rp", __func__,
					   &rp_info->rp.rpf_addr);
			}
		}
	}

	if (i_am_rp_changed) {
		pim_msdp_i_am_rp_changed(pim);
		pim_upstream_reeval_use_rpt(pim);
	}
}

/* up-optimized re-evaluation of "i_am_rp". this is used when ifaddresses
 * are removed. Removing numbers is an uncommon event in an active network
 * so I have made no attempt to optimize it. */
void pim_i_am_rp_re_evaluate(struct pim_instance *pim)
{
	struct listnode *node;
	struct rp_info *rp_info;
	bool i_am_rp_changed = false;
	int old_i_am_rp;

	if (pim->rp_list == NULL)
		return;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
			continue;

		old_i_am_rp = rp_info->i_am_rp;
		pim_rp_check_interfaces(pim, rp_info);

		if (old_i_am_rp != rp_info->i_am_rp) {
			i_am_rp_changed = true;
			if (PIM_DEBUG_PIM_NHT_RP) {
				if (rp_info->i_am_rp)
					zlog_debug("%s: %pPA: i am rp",
						   __func__,
						   &rp_info->rp.rpf_addr);
				else
					zlog_debug(
						"%s: %pPA: i am no longer rp",
						__func__,
						&rp_info->rp.rpf_addr);
			}
		}
	}

	for (ALL_LIST_ELEMENTS_RO(pim->fb_rp_list, node, rp_info)) {
		if (pim_addr_is_any(rp_info->rp.rpf_addr))
			continue;

		old_i_am_rp = rp_info->i_am_rp;
		pim_rp_check_interfaces(pim, rp_info);

		if (old_i_am_rp != rp_info->i_am_rp) {
			i_am_rp_changed = true;
			if (PIM_DEBUG_PIM_NHT_RP) {
				if (rp_info->i_am_rp) {
					zlog_debug("%s: %pPA: i am rp",
						   __func__,
						   &rp_info->rp.rpf_addr);
				} else {
					zlog_debug(
						"%s: %pPA: i am no longer rp",
						__func__,
						&rp_info->rp.rpf_addr);
				}
			}
		}
	}

	if (i_am_rp_changed) {
		pim_msdp_i_am_rp_changed(pim);
		pim_upstream_reeval_use_rpt(pim);
	}
}

/*
 * I_am_RP(G) is true if the group-to-RP mapping indicates that
 * this router is the RP for the group.
 *
 * Since we only have static RP, all groups are part of this RP
 */
int pim_rp_i_am_rp(struct pim_instance *pim, pim_addr group)
{
	struct prefix g;
	struct rp_info *rp_info;

	memset(&g, 0, sizeof(g));
	pim_addr_to_prefix(&g, group);
	rp_info = pim_rp_find_match_group(pim, &g);

	if (rp_info)
		return rp_info->i_am_rp;
	return 0;
}

/*
 * RP(G)
 *
 * Return the RP that the Group belongs too.
 */
struct pim_rpf *pim_rp_g(struct pim_instance *pim, pim_addr group)
{
	struct prefix g;
	struct rp_info *rp_info;

	memset(&g, 0, sizeof(g));
	pim_addr_to_prefix(&g, group);

	rp_info = pim_rp_find_match_group(pim, &g);

	if (rp_info) {
		pim_addr nht_p;

		if (pim_addr_is_any(rp_info->rp.rpf_addr)) {
			if (PIM_DEBUG_PIM_NHT_RP)
				zlog_debug(
					"%s: Skipping NHT Register since RP is not configured for the group %pPA",
					__func__, &group);
			return &rp_info->rp;
		}

		/* Register addr with Zebra NHT */
		nht_p = rp_info->rp.rpf_addr;
		if (PIM_DEBUG_PIM_NHT_RP)
			zlog_debug(
				"%s: NHT Register RP addr %pPA grp %pFX with Zebra",
				__func__, &nht_p, &rp_info->group);
		pim_find_or_track_nexthop(pim, nht_p, NULL, rp_info, NULL);
		pim_rpf_set_refresh_time(pim);
		(void)pim_ecmp_nexthop_lookup(pim, &rp_info->rp.source_nexthop,
					      nht_p, &rp_info->group, 1);
		return (&rp_info->rp);
	}

	// About to Go Down
	return NULL;
}

/*
 * Set the upstream IP address we want to talk to based upon
 * the rp configured and the source address
 *
 * If we have don't have a RP configured and the source address is *
 * then set the upstream addr as INADDR_ANY and return failure.
 *
 */
int pim_rp_set_upstream_addr(struct pim_instance *pim, pim_addr *up,
			     pim_addr source, pim_addr group)
{
	struct rp_info *rp_info;
	struct prefix g;

	memset(&g, 0, sizeof(g));

	pim_addr_to_prefix(&g, group);

	rp_info = pim_rp_find_match_group(pim, &g);

	if ((!rp_info || (pim_rpf_addr_is_inaddr_any(&rp_info->rp))) &&
			 (pim_addr_is_any(source))) {
		if (PIM_DEBUG_PIM_NHT_RP)
			zlog_debug("%s: Received a (*,G) with no RP configured",
				   __func__);
		*up = PIMADDR_ANY;
		return 0;
	}

	if (pim_addr_is_any(source))
		*up = rp_info->rp.rpf_addr;
	else
		*up = source;

	return 1;
}

int pim_rp_config_write(struct pim_instance *pim, struct vty *vty,
			const char *spaces)
{
	struct listnode *node;
	struct rp_info *rp_info;
	int count = 0;
	pim_addr rp_addr;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
			continue;

		if (rp_info->rp_src == RP_SRC_BSR)
			continue;
#if PIM_IPV == 6
		if (rp_info->rp_src == RP_SRC_EMBEDDED_RP)
			continue;
#endif /* PIM_IPV == 6 */

		rp_addr = rp_info->rp.rpf_addr;
		if (rp_info->alist)
			vty_out(vty,
				"%s" PIM_AF_NAME
				" pim rp %pPA access-list %s\n",
				spaces, &rp_addr, rp_info->alist);
		else if (rp_info->plist)
			vty_out(vty,
				"%s" PIM_AF_NAME
				" pim rp %pPA prefix-list %s\n",
				spaces, &rp_addr, rp_info->plist);
		else
			vty_out(vty, "%s" PIM_AF_NAME " pim rp %pPA %pFX\n",
				spaces, &rp_addr, &rp_info->group);
		count++;
	}

	for (ALL_LIST_ELEMENTS_RO(pim->fb_rp_list, node, rp_info)) {
		if (pim_addr_is_any(rp_info->rp.rpf_addr))
			continue;

		if (rp_info->alist)
			vty_out(vty,
				"%s" PIM_AF_NAME
				" pim rp %pPA fallback access-list %s\n",
				spaces, &rp_info->rp.rpf_addr, rp_info->alist);
		else if (rp_info->plist)
			vty_out(vty,
				"%s" PIM_AF_NAME
				" pim rp %pPA fallback prefix-list %s\n",
				spaces, &rp_info->rp.rpf_addr, rp_info->plist);
		else
			vty_out(vty,
				"%s" PIM_AF_NAME " pim rp %pPA fallback %pFX\n",
				spaces, &rp_info->rp.rpf_addr, &rp_info->group);
		count++;
	}

	return count;
}

static void pim_rp_show_info_list(struct pim_instance *pim,
				  const struct prefix *range, struct list *list,
				  struct vty *vty, struct ttable *tt,
				  json_object *json);
static void pim_rp_show_info_ssm_plist(struct vty *vty, struct ttable *tt,
				       struct pim_ssm *ssm, json_object *json,
				       struct prefix *range);

void pim_rp_show_information(struct pim_instance *pim, struct prefix *range,
			     struct vty *vty, json_object *json)
{
	struct ttable *tt = NULL;

	if (!json) {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(
			tt,
			"RP address|group/prefix-list|OIF|I am RP|Source|Group-Type");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
	}

	pim_rp_show_info_list(pim, range, pim->rp_list, vty, tt, json);
	pim_rp_show_info_list(pim, range, pim->fb_rp_list, vty, tt, json);
	pim_rp_show_info_ssm_plist(vty, tt, (struct pim_ssm *)pim->ssm_info,
				   json, range);

	/* Dump the generated table. */
	if (!json) {
		char *table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
		ttable_del(tt);
	}
}

static void pim_rpinfo_show_alist(struct ttable *tt, struct rp_info *rp_info,
				  json_object *json, const struct prefix *range)
{
	struct filter *item;
	struct filter_cisco *cfilter;
	struct access_list *acl;

	acl = access_list_lookup(PIM_AFI, rp_info->alist);
	if (!acl)
		return;

	for (item = acl->head; item; item = item->next) {
		struct prefix p;
#if PIM_IPV == 4
		struct in_addr mask;
#else
		struct in6_addr mask;
#endif

		if (!item->cisco || !item->u.cfilter.extended) {
			if (json)
				continue;

			ttable_add_row(
				tt, "%pPA|(invalid entry seq %" PRIu64 ")||||",
				&rp_info->rp.rpf_addr, item->seq);
			continue;
		}

		cfilter = &item->u.cfilter;

		p.family = PIM_AF;
#if PIM_IPV == 4
		mask.s_addr = ~cfilter->sadr.dst_mask.s_addr;
		p.prefixlen = ip_masklen(mask);
		p.u.prefix4 = cfilter->sadr.dst;
#else
		for (unsigned long i = 0; i < sizeof(mask) / 4; i++)
			mask.s6_addr32[i] =
				~cfilter->sadr6.dst_mask.s6_addr32[i];

		p.prefixlen = (uint16_t)ip6_masklen(mask);
		p.u.prefix6 = cfilter->sadr6.dst;
#endif /* PIM_IPV == 6 */
		if (json) {
			char buf[PREFIX_STRLEN];
			prefix2str(&p, buf, sizeof(buf));
			json_object_array_add(json,
					      json_object_new_string(buf));
		} else
			ttable_add_row(tt, "%pPA|%pFX||||",
				       &rp_info->rp.rpf_addr, &p);
	}
}

static void pim_rp_show_info_ssm_plist(struct vty *vty, struct ttable *tt,
				       struct pim_ssm *ssm, json_object *json,
				       struct prefix *range)
{
	struct prefix_list_entry *pentry;
	struct prefix_list *plist;
	struct prefix *p = NULL;
	json_object *json_rp_rows = NULL;
	json_object *json_row = NULL;
#if PIM_IPV == 4
	const char *no_rp = "0.0.0.0";
#else
	const char *no_rp = "::";
#endif
	const char *source = "Static";
	const char *type = "SSM";
	char buf[PREFIX_STRLEN];

	if (ssm->plist_name) {
		plist = prefix_list_lookup(PIM_AFI, ssm->plist_name);
		if (!plist) {
			if (!json)
				vty_out(vty,
					"\t-- prefix-list does not exist\n");
			return;
		}

		for (pentry = plist->head; pentry; pentry = pentry->next) {
			if (pentry->any)
				continue;

			p = &pentry->prefix;
			prefix2str(p, buf, sizeof(buf));

			if (range && !prefix_match(p, range))
				continue;

			if (!json)
				ttable_add_row(tt, "%s|%s|%s|%s|%s|%s", no_rp,
					       buf, "Unknown", "no", source,
					       type);
			else {
				json_row = json_object_new_object();
				if (!json_object_object_get_ex(json, no_rp, &json_rp_rows)) {
					json_rp_rows = json_object_new_array();
					json_object_object_add(json, no_rp,
							       json_rp_rows);
				}

				json_object_string_add(json_row, "rpAddress",
						       no_rp);
				json_object_string_add(json_row,
						       "outboundInterface",
						       "Unknown");
				json_object_boolean_false_add(json_row,
							      "iAmRP");
				json_object_string_add(json_row, "group", buf);
				json_object_string_add(json_row, "source",
						       source);
				json_object_string_add(json_row, "groupType",
						       type);
				json_object_array_add(json_rp_rows, json_row);
			}
		}
	} else {
		struct prefix p_match;
		(void)str2prefix(PIM_SSM_STANDARD_RANGE, &p_match);
		apply_mask(&p_match);

		if (range && !prefix_match(&p_match, range))
			return;

		if (!json)
			ttable_add_row(tt, "%s|%s|%s|%s|%s|%s", no_rp,
				       PIM_SSM_STANDARD_RANGE, "Unknown", "no",
				       source, type);
		else {
			json_row = json_object_new_object();
			if (!json_object_object_get_ex(json, no_rp, &json_rp_rows)) {
				json_rp_rows = json_object_new_array();
				json_object_object_add(json, no_rp,
						       json_rp_rows);
			}

			json_object_string_add(json_row, "rpAddress", no_rp);
			json_object_string_add(json_row, "outboundInterface",
					       "Unknown");
			json_object_boolean_false_add(json_row, "iAmRP");
			json_object_string_add(json_row, "group",
					       PIM_SSM_STANDARD_RANGE);
			json_object_string_add(json_row, "source", source);
			json_object_string_add(json_row, "groupType", type);
			json_object_array_add(json_rp_rows, json_row);
		}
	}
}

static void pim_rp_show_info_list(struct pim_instance *pim,
				  const struct prefix *range, struct list *list,
				  struct vty *vty, struct ttable *tt,
				  json_object *json)
{
	struct rp_info *rp_info;
	struct listnode *node;
	char source[9];
	char grp[PREFIX2STR_BUFFER];
	char rp_address[INET6_ADDRSTRLEN];

	json_object *json_rp_rows = NULL;
	json_object *json_row = NULL;

	for (ALL_LIST_ELEMENTS_RO(list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
			continue;

#if PIM_IPV == 4
		pim_addr group = rp_info->group.u.prefix4;
#else
		pim_addr group = rp_info->group.u.prefix6;
#endif
		const char *group_type =
			pim_is_grp_ssm(pim, group) ? "SSM" : "ASM";

		if (range && !prefix_match(&rp_info->group, range))
			continue;

		if (rp_info->rp_src == RP_SRC_STATIC)
			strlcpy(source, "Static", sizeof(source));
		else if (rp_info->rp_src == RP_SRC_BSR)
			strlcpy(source, "BSR", sizeof(source));
		else if (rp_info->rp_src == RP_SRC_FALLBACK)
			strlcpy(source, "Fallback", sizeof(source));
#if PIM_IPV == 6
		else if (rp_info->rp_src == RP_SRC_EMBEDDED_RP)
			strlcpy(source, "Embedded-RP", sizeof(source));
#endif /* PIM_IPV == 6 */
		else
			strlcpy(source, "None", sizeof(source));

		prefix2str(&rp_info->group, grp, sizeof(grp));

		if (json) {
			inet_ntop(PIM_AF, &rp_info->rp.rpf_addr, rp_address,
				  sizeof(rp_address));

			if (!json_object_object_get_ex(json, rp_address,
						       &json_rp_rows)) {
				json_rp_rows = json_object_new_array();
				json_object_object_add(json, rp_address, json_rp_rows);
			}

			json_row = json_object_new_object();
			json_object_string_add(json_row, "rpAddress", rp_address);
			if (rp_info->rp.source_nexthop.interface)
				json_object_string_add(
					json_row, "outboundInterface",
					rp_info->rp.source_nexthop
						.interface->name);
			else
				json_object_string_add(json_row,
						       "outboundInterface",
						       "Unknown");
			json_object_boolean_add(json_row, "iAmRP",
						rp_info->i_am_rp);

			if (rp_info->plist)
				json_object_string_add(json_row, "prefixList",
						       rp_info->plist);
			else if (rp_info->alist) {
				json_object *json_aclrules;

				json_object_string_add(json_row, "accessList",
						       rp_info->alist);
				json_aclrules = json_object_new_array();
				json_object_object_add(json_row,
						       "accessListContents",
						       json_aclrules);
				pim_rpinfo_show_alist(tt, rp_info,
						      json_aclrules, range);
			} else
				json_object_string_add(json_row, "group", grp);

			json_object_string_add(json_row, "source", source);
			json_object_string_add(json_row, "groupType",
					       group_type);
			json_object_array_add(json_rp_rows, json_row);
		} else {
			ttable_add_row(tt, "%pPA|%s|%s|%s|%s|%s",
					  &rp_info->rp.rpf_addr,
					  rp_info->plist
					  ? rp_info->plist
					  : rp_info->alist ? rp_info->alist : grp,
					  rp_info->rp.source_nexthop.interface
					  ? rp_info->rp.source_nexthop
						.interface->name
						: "Unknown",
					  rp_info->i_am_rp
					  ? "yes"
					  : "no",
					  source, group_type);

			if (rp_info->alist)
				pim_rpinfo_show_alist(tt, rp_info, json, range);
		}
	}
}

void pim_resolve_rp_nh(struct pim_instance *pim, struct pim_neighbor *nbr)
{
	struct listnode *node = NULL;
	struct rp_info *rp_info = NULL;
	struct nexthop *nh_node = NULL;
	pim_addr nht_p;
	struct pim_nexthop_data nhd;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
			continue;

		nht_p = rp_info->rp.rpf_addr;
		memset(&nhd, 0, sizeof(nhd));
		if (!pim_find_or_track_nexthop(pim, nht_p, NULL, rp_info, &nhd))
			continue;

		for (nh_node = nhd.nexthop; nh_node; nh_node = nh_node->next) {
#if PIM_IPV == 4
			if (!pim_addr_is_any(nh_node->gate.ipv4))
				continue;
#else
			if (!pim_addr_is_any(nh_node->gate.ipv6))
				continue;
#endif

			struct interface *ifp1 = if_lookup_by_index(
				nh_node->ifindex, pim->vrf->vrf_id);

			if (nbr->interface != ifp1)
				continue;

#if PIM_IPV == 4
			nh_node->gate.ipv4 = nbr->source_addr;
#else
			nh_node->gate.ipv6 = nbr->source_addr;
#endif
			if (PIM_DEBUG_PIM_NHT_RP)
				zlog_debug(
					"%s: addr %pPA new nexthop addr %pPAs interface %s",
					__func__, &nht_p, &nbr->source_addr,
					ifp1->name);
		}
	}

	for (ALL_LIST_ELEMENTS_RO(pim->fb_rp_list, node, rp_info)) {
		if (pim_addr_is_any(rp_info->rp.rpf_addr))
			continue;

		nht_p = rp_info->rp.rpf_addr;
		memset(&nhd, 0, sizeof(nhd));
		if (!pim_find_or_track_nexthop(pim, nht_p, NULL, rp_info, &nhd))
			continue;

		for (nh_node = nhd.nexthop; nh_node; nh_node = nh_node->next) {
			if (nh_node->gate.ipv4.s_addr != INADDR_ANY)
				continue;

			struct interface *ifp1 = if_lookup_by_index(
				nh_node->ifindex, pim->vrf->vrf_id);

			if (nbr->interface != ifp1)
				continue;

#if PIM_IPV == 4
			nh_node->gate.ipv4 = nbr->source_addr;
#else
			nh_node->gate.ipv6 = nbr->source_addr;
#endif
			if (PIM_DEBUG_PIM_NHT_RP)
				zlog_debug(
					"%s: addr %pPA new nexthop addr %pPA interface %s",
					__func__, &nht_p, &nbr->source_addr,
					ifp1->name);
		}
	}
}

#if PIM_IPV == 6
DEFINE_MTYPE_STATIC(PIMD, PIM_EMBEDDED_RP_GROUP_LIST,
		    "PIM embedded RP group list");
DEFINE_MTYPE_STATIC(PIMD, PIM_EMBEDDED_RP_ENTRY,
		    "PIM embedded RP configuration");

void pim_embedded_rp_enable(struct pim_instance *pim, bool enable)
{
	struct route_node *rn;

	pim->embedded_rp.enable = enable;
	if (enable)
		return;

	/* Remove all learned embedded RPs and reallocate data structure. */
	for (rn = route_top(pim->embedded_rp.table); rn; rn = route_next(rn)) {
		pim_embedded_rp_free(pim, rn->info);
		rn->info = NULL;
	}
	route_table_finish(pim->embedded_rp.table);

	pim->embedded_rp.table = route_table_init();
}

void pim_embedded_rp_set_group_list(struct pim_instance *pim,
				    const char *group_list)
{
	if (pim->embedded_rp.group_list)
		XFREE(MTYPE_PIM_EMBEDDED_RP_GROUP_LIST,
		      pim->embedded_rp.group_list);

	if (group_list == NULL)
		return;

	pim->embedded_rp.group_list =
		XSTRDUP(MTYPE_PIM_EMBEDDED_RP_GROUP_LIST, group_list);
}

void pim_embedded_rp_set_maximum_rps(struct pim_instance *pim, uint32_t maximum)
{
	pim->embedded_rp.maximum_rps = maximum;
}

bool pim_embedded_rp_filter_match(const struct pim_instance *pim,
				  const pim_addr *group)
{
	struct prefix_list *list;
	struct prefix group_prefix = {
		.family = PIM_AF,
		.prefixlen = PIM_MAX_BITLEN,
		.u.prefix6 = *group,
	};

	list = prefix_list_lookup(PIM_AFI, pim->embedded_rp.group_list);
	if (list == NULL)
		return false;

	if (prefix_list_apply_ext(list, NULL, &group_prefix, true) ==
	    PREFIX_DENY) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("filtering embedded-rp group %pPA", group);
		return true;
	}

	return false;
}

bool pim_embedded_rp_is_embedded(const pim_addr *group)
{
	/*
	 * Embedded RP basic format:
	 * - First byte:         0xFF
	 * - Third nibble:       0x7 (binary 0111)
	 * - Fourth nibble:      Scope
	 * - Fifth nibble:       Reserved (zero)
	 * - Sixth nibble:       RIID (RP interface ID)
	 * - Fourth byte:        Prefix length (1..64)
	 * - Fifth byte and on:  RP address prefix
	 * - Last four bytes:    Multicast group ID
	 */
	if (group->s6_addr[0] != 0xFF)
		return false;
	/* Embedded RP flags must all be set. */
	if ((group->s6_addr[1] & 0xF0) != 0x70)
		return false;
	/* Reserved nibble */
	if ((group->s6_addr[2] & 0xF0) != 0x00)
		return false;
	/* RP Interface ID must not be zero */
	if ((group->s6_addr[2] & 0x0F) == 0x00)
		return false;
	/* Prefix length must be between 1 and 64. */
	if (group->s6_addr[3] == 0 || group->s6_addr[3] > 64)
		return false;

	return true;
}

bool pim_embedded_rp_extract(const pim_addr *group, pim_addr *rp)
{
	struct prefix prefix;

	if (!pim_embedded_rp_is_embedded(group))
		return false;

	/* Copy at most the prefix bytes length to RP prefix. */
	prefix = (struct prefix){
		.family = PIM_AF,
		.prefixlen = group->s6_addr[3],
	};
	memcpy(&prefix.u.prefix6, &group->s6_addr[4],
	       (prefix.prefixlen % 8) == 0 ? (prefix.prefixlen / 8)
					   : (prefix.prefixlen / 8) + 1);
	/* Zero unused address bits. */
	apply_mask(&prefix);

	/* Return assembled RP address. */
	*rp = prefix.u.prefix6;
	rp->s6_addr[15] = group->s6_addr[2] & 0x0F;
	return true;
}

void pim_embedded_rp_new(struct pim_instance *pim, const pim_addr *group,
			 const pim_addr *rp)
{
	struct route_node *rnode;
	struct rp_info *rp_info;
	struct prefix group_prefix = {
		.family = PIM_AF,
		.prefixlen = PIM_MAX_BITLEN,
		.u.prefix6 = *group,
	};

	rnode = route_node_get(pim->embedded_rp.table, &group_prefix);
	if (rnode->info != NULL) {
		route_unlock_node(rnode);
		return;
	}

	if (pim->embedded_rp.rp_count >= pim->embedded_rp.maximum_rps) {
		zlog_info(
			"Embedded RP maximum (%u) has been reached. Disregarding new RP %pPA",
			pim->embedded_rp.maximum_rps, rp);
		route_unlock_node(rnode);
		return;
	}

	pim->embedded_rp.rp_count++;

	rnode->info = rp_info =
		XCALLOC(MTYPE_PIM_EMBEDDED_RP_ENTRY, sizeof(struct rp_info));
	rp_info->rp.rpf_addr = *rp;
	prefix_copy(&rp_info->group, &group_prefix);
	rp_info->rp_src = RP_SRC_EMBEDDED_RP;
	listnode_add_sort(pim->rp_list, rp_info);
	if (PIM_DEBUG_TRACE)
		zlog_debug("add embedded RP %pPA for group %pPA", rp, group);

	/*
	 * PIM RP regular maintenance
	 */
	pim_zebra_update_all_interfaces(pim);
	pim_rp_check_interfaces(pim, rp_info);
	if (rp_info->i_am_rp && PIM_DEBUG_PIM_NHT_RP)
		zlog_debug("new RP %pPA for %pFX is ourselves", &rp_info->rp.rpf_addr,
			   &rp_info->group);

	pim_rp_refresh_group_to_rp_mapping(pim);
	if (PIM_DEBUG_PIM_NHT_RP)
		zlog_debug("%s: NHT Register RP addr %pPA grp %pFX with Zebra",
			   __func__, &rp_info->rp.rpf_addr, &rp_info->group);

	pim_find_or_track_nexthop(pim, rp_info->rp.rpf_addr, NULL, rp_info,
				  NULL);
	pim_ecmp_nexthop_lookup(pim, &rp_info->rp.source_nexthop,
				rp_info->rp.rpf_addr, &rp_info->group, 1);
}

void pim_embedded_rp_delete(struct pim_instance *pim, const pim_addr *group)
{
	struct route_node *rnode;
	struct prefix group_prefix = {
		.family = PIM_AF,
		.prefixlen = PIM_MAX_BITLEN,
		.u.prefix6 = *group,
	};

	/* Avoid NULL accesses during shutdown */
	if (pim->embedded_rp.table == NULL)
		return;

	rnode = route_node_lookup(pim->embedded_rp.table, &group_prefix);
	if (rnode == NULL)
		return;

	pim_embedded_rp_free(pim, rnode->info);
	rnode->info = NULL;

	/* Unlock twice to remove the node */
	route_unlock_node(rnode);
	route_unlock_node(rnode);
}

void pim_embedded_rp_free(struct pim_instance *pim, struct rp_info *rp_info)
{
	if (pim->embedded_rp.rp_count > 0)
		pim->embedded_rp.rp_count--;

	if (PIM_DEBUG_TRACE)
		zlog_debug("delete embedded RP %pPA", &rp_info->rp.rpf_addr);

	pim_delete_tracked_nexthop(pim, rp_info->rp.rpf_addr, NULL, rp_info);
	listnode_delete(pim->rp_list, rp_info);
	XFREE(MTYPE_PIM_EMBEDDED_RP_ENTRY, rp_info);
}
#endif /* PIM_IPV == 6 */
