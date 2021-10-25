/*
 * OSPFv3 virtual link implementation.
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

#include "lib/zebra.h"
#include "lib/command.h"
#include "lib/memory.h"
#include "lib/printfrr.h"

#include "ospf6d/ospf6d.h"
#include "ospf6d/ospf6_area.h"
#include "ospf6d/ospf6_interface.h"
#include "ospf6d/ospf6_lsa.h"
#include "ospf6d/ospf6_message.h"
#include "ospf6d/ospf6_neighbor.h"
#include "ospf6d/ospf6_top.h"
#include "ospf6d/ospf6_vlink.h"
#include "ospf6d/ospf6_proto.h"
#include "ospf6d/ospf6_lsdb.h"
#include "ospf6d/ospf6_intra.h"

#ifndef VTYSH_EXTRACT_PL
#include "ospf6d/ospf6_vlink_clippy.c"
#endif /* VTYSH_EXTRACT_PL */

static uint8_t debug_vlink;
static int sb_socket = -1;

struct sb_vldata {
	uint16_t vr_id;
	struct in_addr router_id;
	struct in_addr area_id;
	struct in6_addr src;
	struct in6_addr dst;
} __attribute__((packed));

static void sb_vlink_send_info(struct ospf6_virtual_link *vlink)
{
	struct sb_vldata vldata;
	struct sockaddr_in dst = {
		.sin_family = AF_INET,
		.sin_port = htons(2621),
		.sin_addr.s_addr = inet_addr("127.200.0.254"),
	};
	ssize_t ret;

	vldata.vr_id = htons(vlink->ospf6->vrf_id);
	vldata.router_id = vlink->remote;
	vldata.area_id.s_addr = vlink->area->area_id;
	vldata.src = vlink->area->vlink_local_addr;
	vldata.dst = vlink->transport;

	ret = sendto(sb_socket, &vldata, sizeof(vldata), 0,
		     (struct sockaddr *)&dst, sizeof(dst));

	if (ret <= 0)
		zlog_warn("auth data send failed for virtual link to %pI4 area %pI4: %m",
			  &vlink->remote, &vlink->area->area_id);
}

/* implementation note/rosetta stone:
 *
 * The most non-obvious aspect of this virtual link implementation is that it
 * uses ONE dummy interface for ALL virtual links, and that dummy interface is
 * a member of the backbone area.  Virtual links are neighbors on this dummy
 * interface, so everything works as usual for any neighbor in the backbone
 * area.  This dummy interface also ensures that the backbone area isn't
 * "empty" if the router only has virtual links.
 *
 * As a downside, this means the timers that are normally an interface
 * property are now duplicated as a virtual link property, but that's not a
 * huge impact.
 */

/* remaining TODOs:
 *
 * - verify router LSA updates from other routers that change their LA
 *   correctly propagate into the address being used for virtual links.  It
 *   works for most cases but there may be some corner cases left that don't
 *   update the address correctly.
 *
 * - authentication options for virtual links are completely missing
 *
 * - check if multiple parallel virtual links through different areas to the
 *   same router make sense.  (no clue if it does.  not currently supported.)
 *
 * - show commands.  There are none.
 */

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_VIRTUAL_LINK, "OSPF6 virtual link data");
DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_VLINK_ADDR,   "OSPF6 virtual link address base");

static int ospf6_vlink_cmp(const struct ospf6_virtual_link *a,
			   const struct ospf6_virtual_link *b)
{
	return IPV4_ADDR_CMP(&a->remote, &b->remote);
}

DECLARE_RBTREE_UNIQ(ospf6_virtual_links, struct ospf6_virtual_link, item,
		    ospf6_vlink_cmp);

DECLARE_RBTREE_UNIQ(ospf6_area_vlinks, struct ospf6_virtual_link, areaitem,
		    ospf6_vlink_cmp);

static int ospf6_vlink_addr_cmp(const struct ospf6_vlink_addr *a,
				const struct ospf6_vlink_addr *b)
{
	return IPV6_ADDR_CMP(&a->remote_addr, &b->remote_addr);
}

DECLARE_RBTREE_UNIQ(ospf6_vlink_addrs, struct ospf6_vlink_addr, item,
		    ospf6_vlink_addr_cmp);

size_t ospf6_vlink_area_vlcount(struct ospf6_area *oa)
{
	return ospf6_area_vlinks_count(oa->vlinks);
}

static void ospf6_vlink_prep(struct ospf6 *o)
{
	struct interface *ifp;

	if (o->vlink_oi)
		return;

	if (debug_vlink)
		zlog_debug("creating OSPFv3 virtual link interface for VRF %u",
			   o->vrf_id);

	/* it is very intentional that the dummy interface has an empty
	 * interface name;  otherwise the user could try to "configure" things
	 * on this interface (which would just wreak havoc.)  With an empty
	 * interface name, the CLI can't invoke "interface XYZ" commands.
	 */
	ifp = if_create_name("", o->vrf_id);
	UNSET_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION);
	SET_FLAG(ifp->flags, IFF_LOOPBACK | IFF_VIRTUAL);

	ifp->desc = asprintfrr(MTYPE_TMP, "OSPFv3 virtual link (VRF %u)",
			       o->vrf_id);

	o->vlink_oi = ospf6_interface_basic_create(ifp);
	o->vlink_oi->type = OSPF_IFTYPE_VIRTUALLINK;
	o->vlink_oi->state = OSPF6_INTERFACE_VIRTUALLINK;
	o->vlink_oi->ifmtu = 65520;
	o->vlink_oi->mtu_ignore = true;

	o->vlink_oi->area_id = 0;
	o->vlink_oi->area_id_format = OSPF6_AREA_FMT_DOTTEDQUAD;

	o->last_vlink_ifindex = 0x80000000;

	ospf6_interface_start(o->vlink_oi);
}

static void ospf6_vlink_unprep(struct ospf6 *o)
{
	struct interface *ifp;

	if (ospf6_virtual_links_count(o->vlinks))
		return;

	if (debug_vlink)
		zlog_debug("removing OSPFv3 virtual link interface for VRF %u",
			   o->vrf_id);

	ospf6_interface_stop(o->vlink_oi);

	ifp = o->vlink_oi->interface;
	ospf6_interface_basic_delete(o->vlink_oi);
	o->vlink_oi = NULL;

	if_delete(&ifp);
}

/**
 * Find OSPF virtual link by attributes.
 */
struct ospf6_virtual_link *ospf6_virtual_link_find(struct ospf6 *o,
						   struct in_addr remote)
{
	struct ospf6_virtual_link ref;

	ref.remote = remote;
	return ospf6_virtual_links_find(o->vlinks, &ref);
}

static struct ospf6_vlink_addr *ospf6_vlink_addr_new(
		struct ospf6_virtual_link *vlink, struct in6_addr *addr)
{
	struct ospf6_vlink_addr *vaddr;

	vaddr = XCALLOC(MTYPE_OSPF6_VLINK_ADDR, sizeof(*vaddr));
	vaddr->remote_addr = *addr;
	return vaddr;
}

static void ospf6_vlink_addr_delall(struct ospf6_vlink_addrs_head *head)
{
	struct ospf6_vlink_addr *vaddr;

	while ((vaddr = ospf6_vlink_addrs_pop(head))) {
		XFREE(MTYPE_OSPF6_VLINK_ADDR, vaddr);
	}
}

static int ospf6_vlink_hello(struct thread *t)
{
	struct ospf6_virtual_link *vlink = THREAD_ARG(t);

	ospf6_hello_send_addr(vlink->ospf6->vlink_oi, vlink, &vlink->transport);

	thread_add_timer(master, ospf6_vlink_hello, vlink,
			 vlink->hello_interval, &vlink->t_hello);
	return 0;
}

static void ospf6_vlink_refresh(struct ospf6_virtual_link *vlink, bool changed)
{
	struct ospf6_vlink_addrs_head oldaddrs[1];
	struct ospf6_vlink_addr *vaddr, ref, *bestaddr = NULL;
	struct ospf6_route *ort;
	struct ospf6_lsa *lsa;
	struct prefix pfx;

	ospf6_vlink_addrs_init(oldaddrs);
	ospf6_vlink_addrs_swap_all(oldaddrs, vlink->addrs);

	for (ALL_LSDB_TYPED_ADVRTR(vlink->area->lsdb,
				   htons(OSPF6_LSTYPE_INTRA_PREFIX),
				   vlink->remote.s_addr, lsa)) {
		struct ospf6_intra_prefix_lsa *lsa_intra;
		struct ospf6_prefix *op;
		size_t i, count;

		lsa_intra = (struct ospf6_intra_prefix_lsa *)(lsa->header + 1);
		op = (struct ospf6_prefix *)(lsa_intra + 1);
		count = ntohs(lsa_intra->prefix_num);

		for (i = 0; i < count; i++, op = OSPF6_PREFIX_NEXT(op)) {
			struct in6_addr *addr = op->addr;

			if (!(op->prefix_options & OSPF6_PREFIX_OPTION_LA))
				continue;

			ref.remote_addr = *addr;
			vaddr = ospf6_vlink_addrs_find(oldaddrs, &ref);
			if (vaddr)
				ospf6_vlink_addrs_del(oldaddrs, vaddr);
			else
				vaddr = ospf6_vlink_addr_new(vlink, addr);
			ospf6_vlink_addrs_add(vlink->addrs, vaddr);

			/* RFC5340 4.4.3.9 requires using neighbor's first LA
			 * (other addrs would work, except with IPsec...)
			 */
			if (!bestaddr)
				bestaddr = vaddr;
		}
	}

	ospf6_linkstate_prefix(vlink->remote.s_addr, INADDR_ANY, &pfx);
	ort = ospf6_route_lookup(&pfx, vlink->area->spf_table);

	if (!ort || !bestaddr) {
		const char *reason = ort ? "no routable address" : "no route";

		if (vlink->spf_cost == ~0U)
			goto out;

		changed = true;
		if (debug_vlink)
			zlog_debug(
				"Virtual link to %pI4 through area %pI4 down (%s)",
				&vlink->remote, &vlink->area->area_id, reason);

		vlink->spf_cost = ~0U;
		memset(&vlink->transport, 0, sizeof(vlink->transport));
		ospf6_neighbor_vlink_change(vlink->nbr, false);

		THREAD_OFF(vlink->t_hello);
		goto out;
	}

	if (debug_vlink)
		zlog_debug(
			"Virtual link to %pI4 (area %pI4): using %pI6, cost %u",
			&vlink->remote, &vlink->area->area_id,
			&bestaddr->remote_addr, ort->path.cost);

	if (!IPV6_ADDR_SAME(&vlink->transport, &bestaddr->remote_addr)) {
		if (debug_vlink)
			zlog_debug(
				"Virtual link to %pI4 (area %pI4) address changed",
				&vlink->remote, &vlink->area->area_id);

		vlink->transport = bestaddr->remote_addr;
		changed = true;
	}
	if (ort->path.cost != vlink->spf_cost) {
		if (debug_vlink)
			zlog_debug(
				"Virtual link to %pI4 (area %pI4) cost changed",
				&vlink->remote, &vlink->area->area_id);

		vlink->spf_cost = ort->path.cost;
		changed = true;
	}

	if (vlink->nbr->state < OSPF6_NEIGHBOR_ATTEMPT) {
		ospf6_neighbor_vlink_change(vlink->nbr, true);
		thread_add_timer(master, ospf6_vlink_hello, vlink,
				 vlink->hello_interval, &vlink->t_hello);
	}
out:
	if (changed) {
		sb_vlink_send_info(vlink);
		OSPF6_ROUTER_LSA_SCHEDULE(vlink->ospf6->backbone);
	}

	ospf6_vlink_addr_delall(oldaddrs);
}

void ospf6_vlink_area_calculation(struct ospf6_area *oa)
{
	struct ospf6_virtual_link *vlink;

	assert(oa->area_id != 0);

	if (debug_vlink)
		zlog_debug("recalculating %zu virtual links on area %pI4",
			   ospf6_area_vlinks_count(oa->vlinks), &oa->area_id);

	frr_each (ospf6_area_vlinks, oa->vlinks, vlink)
		ospf6_vlink_refresh(vlink, false);
}

void ospf6_vlink_prefix_update(struct ospf6_area *oa, in_addr_t rtr)
{
	struct ospf6_virtual_link *vlink, ref;

	if (oa->area_id == 0)
		return;

	ref.remote.s_addr = rtr;
	vlink = ospf6_area_vlinks_find(oa->vlinks, &ref);
	if (!vlink)
		return;

	if (debug_vlink)
		zlog_debug("recalculating virtual link addrs in %pI4 for %pI4",
			   &oa->area_id, &rtr);

	ospf6_vlink_refresh(vlink, false);
}

void ospf6_vlink_area_la_change(struct ospf6_area *oa, struct in6_addr *addr)
{
	struct ospf6_virtual_link *vlink;

	if (debug_vlink)
		zlog_debug("LA for virtual links in area %pI4 changed from %pI6 to %pI6",
			   &oa->area_id, &oa->vlink_local_addr, addr);

	oa->vlink_local_addr = *addr;

	frr_each (ospf6_area_vlinks, oa->vlinks, vlink)
		sb_vlink_send_info(vlink);
}

/**
 * OSPF virtual link registration function.
 *
 * Allocates memory and registers virtual link in OSPF instance / area.
 */
static struct ospf6_virtual_link *ospf6_virtual_link_new(struct ospf6_area *oa,
							 struct in_addr remote)
{
	struct ospf6_virtual_link *vlink;

	ospf6_vlink_prep(oa->ospf6);

	vlink = XCALLOC(MTYPE_OSPF6_VIRTUAL_LINK, sizeof(*vlink));
	vlink->ospf6 = oa->ospf6;
	vlink->area = oa;
	vlink->remote = remote;
	vlink->spf_cost = ~0U;
	ospf6_vlink_addrs_init(vlink->addrs);

	oa->ospf6->last_vlink_ifindex++;
	if (oa->ospf6->last_vlink_ifindex == 0)
		oa->ospf6->last_vlink_ifindex = 0x80000000;
	vlink->v_ifindex = htonl(oa->ospf6->last_vlink_ifindex);

	vlink->dead_interval = VLINK_DEFAULT_DEAD_INTERVAL;
	vlink->hello_interval = VLINK_DEFAULT_HELLO_INTERVAL;
	vlink->transmit_delay = VLINK_DEFAULT_TRANSMIT_DELAY;
	vlink->retransmit_interval = VLINK_DEFAULT_RETRANSMIT_INTERVAL;

	ospf6_virtual_links_add(oa->ospf6->vlinks, vlink);
	ospf6_area_vlinks_add(oa->vlinks, vlink);

	vlink->nbr = ospf6_neighbor_create(remote.s_addr, oa->ospf6->vlink_oi);
	vlink->nbr->vlink = vlink;

	if (ospf6_area_vlinks_count(oa->vlinks) == 1)
		/* make sure we have an intra-prefix with LA advertised */
		OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB(oa);

	return vlink;
}

/**
 * OSPF virtual link removal function.
 *
 * Tears down the virtual link, remove area registration and free resources.
 */
static void ospf6_virtual_link_free(struct ospf6_virtual_link **vlink)
{
	struct ospf6_area *oa;

	if ((*vlink) == NULL)
		return;

	memset(&(*vlink)->transport, 0, sizeof((*vlink)->transport));
	sb_vlink_send_info(*vlink);

	oa = (*vlink)->area;
	THREAD_OFF((*vlink)->t_hello);

	if (ospf6_area_vlinks_count(oa->vlinks) == 0)
		/* drop LA, maybe */
		OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB(oa);

	(*vlink)->nbr->vlink = NULL;
	ospf6_neighbor_delete((*vlink)->nbr);

	ospf6_area_vlinks_del(oa->vlinks, (*vlink));
	ospf6_virtual_links_del(oa->ospf6->vlinks, (*vlink));
	ospf6_vlink_addr_delall((*vlink)->addrs);
	ospf6_vlink_addrs_fini((*vlink)->addrs);
	XFREE(MTYPE_OSPF6_VIRTUAL_LINK, (*vlink));

	ospf6_vlink_unprep(oa->ospf6);
}

void ospf6_vlink_init(struct ospf6 *o)
{
	ospf6_virtual_links_init(o->vlinks);
}

void ospf6_vlink_fini(struct ospf6 *o)
{
	struct ospf6_virtual_link *vlink;

	while ((vlink = ospf6_virtual_links_first(o->vlinks)))
		ospf6_virtual_link_free(&vlink);

	ospf6_virtual_links_fini(o->vlinks);
}

void ospf6_vlink_area_init(struct ospf6_area *oa)
{
	ospf6_area_vlinks_init(oa->vlinks);
}

void ospf6_vlink_area_fini(struct ospf6_area *oa)
{
	struct ospf6_virtual_link *vlink;

	while ((vlink = ospf6_area_vlinks_first(oa->vlinks)))
		ospf6_virtual_link_free(&vlink);

	ospf6_area_vlinks_fini(oa->vlinks);
}

/*
 * Commands
 */
DEFPY (debug_ospf6_vlink,
       debug_ospf6_vlink_cmd,
       "[no] debug ospf6 virtual-link",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Virtual link management\n"
      )
{
	uint8_t flag = (vty->node == CONFIG_NODE) ? (1 << 1) : (1 << 0);

	if (no)
		debug_vlink &= ~flag;
	else
		debug_vlink |= flag;
	return CMD_SUCCESS;
}

void config_write_ospf6_debug_vlink(struct vty *vty)
{
	if (debug_vlink & (1 << 1))
		vty_out(vty, "debug ospf6 virtual-link\n");
}

static void ospf6_show_vlinks(struct vty *vty, struct ospf6 *ospf6,
			      json_object *json, bool uj)
{
	struct ospf6_area *oa;
	struct listnode *node;
	struct ospf6_virtual_link *vlink;

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {
		frr_each (ospf6_area_vlinks, oa->vlinks, vlink) {
			const char *state;

			state = (vlink->nbr->state == OSPF6_NEIGHBOR_FULL)
					? "up"
					: "down";
			if (uj) {
				json_object *json_vl;
				char buf[INET_ADDRSTRLEN];

				inet_ntop(AF_INET, &vlink->remote, buf,
					  sizeof(buf));
				json_vl = json_object_new_object();
				json_object_object_add(json, buf, json_vl);
				json_object_string_add(json_vl, "state", state);
				json_object_int_add(json_vl, "interfaceId",
						    vlink->v_ifindex);
				inet_ntop(AF_INET6, &vlink->transport, buf,
					  sizeof(buf));
				json_object_string_add(json_vl, "ipv6Address",
						       buf);
				json_object_int_add(json_vl, "cost",
						    vlink->spf_cost);
				inet_ntop(AF_INET, &vlink->area->area_id, buf,
					  sizeof(buf));
				json_object_string_add(json_vl, "transitArea",
						       buf);
				json_object_int_add(json_vl, "transmitDelay",
						    vlink->transmit_delay);
				json_object_int_add(json_vl,
						    "timerIntervalsConfigHello",
						    vlink->hello_interval);
				json_object_int_add(json_vl,
						    "timerIntervalsConfigDead",
						    vlink->dead_interval);
				json_object_int_add(
					json_vl,
					"timerIntervalsConfigRetransmit",
					vlink->retransmit_interval);
				/* TODO: do vlinks have I/F scoped LSAs? */
				json_object_int_add(
					json_vl, "numberOfInterfaceScopedLsa",
					0);
			} else {
				vty_out(vty,
					"Virtual Link to router %pI4 is %s\n",
					&vlink->remote, state);
				vty_out(vty, "  Interface ID: %u\n",
					vlink->v_ifindex);
				vty_out(vty, "  IPv6 address: %pI6\n",
					&vlink->transport);
				vty_out(vty, "  Cost: %u\n", vlink->spf_cost);
				vty_out(vty, "  Transit area: %pI4\n",
					&vlink->area->area_id);
				vty_out(vty, "  Transmit delay: %u\n",
					vlink->transmit_delay);
				vty_out(vty, "  Timer intervals configured:\n");
				vty_out(vty,
					"   Hello %u, Dead %u, Retransmit %u\n",
					vlink->hello_interval,
					vlink->dead_interval,
					vlink->retransmit_interval);
				/* TODO: do vlinks have I/F scoped LSAs? */
				vty_out(vty,
					"  Number of I/F scoped LSAs: %u\n", 0);
				vty_out(vty, "\n");
			}
		}
	}
}

DEFPY (ospf6_vlink_show,
       ospf6_vlink_show_cmd,
       "show ipv6 ospf6 [vrf <NAME|all>] virtual-links [json]",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Virtual link information\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct ospf6 *ospf6;
	json_object *json = NULL;
	const char *vrf_name = NULL;
	struct listnode *node;
	bool all_vrf = false;
	int idx_vrf = 0;

	if (uj)
		json = json_object_new_object();

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {

			ospf6_show_vlinks(vty, ospf6, json, uj);
			if (!all_vrf)
				break;
		}
	}

	if (uj) {
		vty_out(vty, "%s\n",
			json_object_to_json_string_ext(
				json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_WARNING;
}

DEFPY(ospf6_vlink_config, ospf6_vlink_config_cmd,
      "[no] area <A.B.C.D$area_dot|(0-4294967295)$area_num> virtual-link A.B.C.D$peer "
      "[{hello-interval (1-65535)$hello|retransmit-interval (1-65535)$retx"
      "|transmit-delay (1-65535)$tx|dead-interval (1-65535)$dead}]",
      NO_STR
      "OSPF area parameters\n"
      "OSPF area ID in IP address format\n"
      "OSPF area ID as a decimal value\n"
      "Configure a virtual link\n"
      "Router ID of the remote ABR\n"
      "Hello packets interval\n"
      "Hello packets interval in seconds\n"
      "Retransmission interval between lost link state advertisements\n"
      "Retransmission interval between lost link state advertisements in seconds\n"
      "Link state transmission interval\n"
      "Link state transmission interval in seconds\n"
      "Interval before declaring a peer dead\n"
      "Interval before declaring a peer dead in seconds\n")
{
	struct ospf6_virtual_link *vlink;
	struct ospf6_area *oa;
	uint32_t area;
	VTY_DECLVAR_CONTEXT(ospf6, o);

	if (area_dot_str)
		area = area_dot.s_addr;
	else
		area = htonl(area_num);

	/* Validations. */
	if (area == 0) {
		vty_out(vty,
			"Virtual links cannot be configured on backbone\n");
		return CMD_WARNING;
	}

	oa = ospf6_area_lookup(area, o);
	if (oa == NULL) {
		vty_out(vty, "OSPFv3 area %u does not exist\n", area);
		return CMD_WARNING;
	}

	if (IS_AREA_STUB(oa) || IS_AREA_NSSA(oa)) {
		vty_out(vty,
			"Virtual link can only be configured on regular areas");
		return CMD_WARNING;
	}

	vlink = ospf6_virtual_link_find(o, peer);
	if (vlink && vlink->area->area_id != area) {
		vty_out(vty,
			"Virtual link to %pI4 exists in different area %pI4",
			&peer, &vlink->area->area_id);
		return CMD_WARNING;
	}

	/* Handle configuration removal. */
	if (no) {
		if (vlink == NULL)
			return CMD_SUCCESS;

		ospf6_virtual_link_free(&vlink);
		return CMD_SUCCESS;
	}

	/* Create and apply. */
	if (vlink == NULL)
		vlink = ospf6_virtual_link_new(oa, peer);

	if (retx_str)
		vlink->retransmit_interval = retx;
	if (tx_str)
		vlink->transmit_delay = tx;
	if (hello_str)
		vlink->hello_interval = hello;
	if (dead_str)
		vlink->dead_interval = dead;

	ospf6_vlink_refresh(vlink, true);

	return CMD_SUCCESS;
}

void ospf6_vlink_area_config(struct ospf6_area *oa, struct vty *vty)
{
	struct ospf6_virtual_link *vlink;

	frr_each (ospf6_area_vlinks, oa->vlinks, vlink) {
		vty_out(vty, " area %s virtual-link %pI4", oa->name,
			&vlink->remote);
		if (vlink->hello_interval != VLINK_DEFAULT_HELLO_INTERVAL)
			vty_out(vty, " hello-interval %u", vlink->hello_interval);
		if (vlink->dead_interval != VLINK_DEFAULT_DEAD_INTERVAL)
			vty_out(vty, " dead-interval %u", vlink->dead_interval);
		if (vlink->retransmit_interval != VLINK_DEFAULT_RETRANSMIT_INTERVAL)
			vty_out(vty, " retransmit-interval %u", vlink->retransmit_interval);
		if (vlink->transmit_delay != VLINK_DEFAULT_TRANSMIT_DELAY)
			vty_out(vty, " transmit-delay %u", vlink->transmit_delay);

		vty_out(vty, "\n");
	}
}

void ospf6_virtual_link_init(void)
{
	struct sockaddr_in sin = { .sin_family = AF_INET };
	int ret;

	sb_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	assertf(sb_socket >= 0, "failed to open SB socket for vlink auth: %m");
	ret = bind(sb_socket, (struct sockaddr *)&sin, sizeof(sin));
	assertf(ret == 0, "failed to bind SB socket for vlink auth: %m");

	install_element(ENABLE_NODE, &debug_ospf6_vlink_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_vlink_cmd);

	install_element(VIEW_NODE, &ospf6_vlink_show_cmd);

	install_element(OSPF6_NODE, &ospf6_vlink_config_cmd);
}
