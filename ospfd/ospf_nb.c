/*
 * OSPFv2 northbound implementation.
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

#include "lib/command.h"
#include "lib/northbound.h"
#include "lib/northbound_cli.h"
#include "lib/printfrr.h"
#include "lib/table.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_nb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_vty.h"
#include "yang_wrappers.h"

static struct vty *ospf_nb_vty;

void ospf_nb_init(void)
{
	ospf_nb_vty = vty_new();
	ospf_nb_vty->wfd = STDERR_FILENO;
	ospf_nb_vty->node = CONFIG_NODE;
	ospf_nb_vty->type = VTY_FILE;
	ospf_nb_vty->config = true;
	ospf_nb_vty->candidate_config = vty_shared_candidate_config;
}

static void vty_clear_enqueued_changes(struct vty *vty)
{
	/* Clear array of enqueued configuration changes. */
	vty->num_cfg_changes = 0;
	memset(&vty->cfg_changes, 0, sizeof(vty->cfg_changes));
}

void ospf_nb_add_instance(struct ospf *o)
{
	char xpath[XPATH_MAXLEN];
	const char *vrf_name = o->name ? o->name : VRF_DEFAULT_NAME;

	snprintf(xpath, sizeof(xpath), OSPF_NB_INSTANCE_XPATH, vrf_name,
		 o->instance);
	nb_cli_enqueue_change(ospf_nb_vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_apply_changes(ospf_nb_vty, NULL);
	vty_clear_enqueued_changes(ospf_nb_vty);
}

void ospf_nb_del_instance(struct ospf *o)
{
	char xpath[XPATH_MAXLEN];
	const char *vrf_name = o->name ? o->name : VRF_DEFAULT_NAME;

	snprintf(xpath, sizeof(xpath), OSPF_NB_INSTANCE_XPATH, vrf_name,
		 o->instance);
	nb_cli_enqueue_change(ospf_nb_vty, xpath, NB_OP_DESTROY, NULL);
	nb_cli_apply_changes(ospf_nb_vty, NULL);
	vty_clear_enqueued_changes(ospf_nb_vty);
}

void ospf_nb_add_area(struct ospf_area *area)
{
	char xpath[XPATH_MAXLEN];
	const char *vrf_name =
		area->ospf->name ? area->ospf->name : VRF_DEFAULT_NAME;

	snprintfrr(xpath, sizeof(xpath), OSPF_NB_AREA_XPATH, vrf_name,
		   area->ospf->instance, &area->area_id);
	nb_cli_enqueue_change(ospf_nb_vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_apply_changes(ospf_nb_vty, NULL);
	vty_clear_enqueued_changes(ospf_nb_vty);
}

void ospf_nb_del_area(struct ospf_area *area)
{
	char xpath[XPATH_MAXLEN];
	const char *vrf_name =
		area->ospf->name ? area->ospf->name : VRF_DEFAULT_NAME;

	snprintfrr(xpath, sizeof(xpath), OSPF_NB_AREA_XPATH, vrf_name,
		   area->ospf->instance, &area->area_id);
	nb_cli_enqueue_change(ospf_nb_vty, xpath, NB_OP_DESTROY, NULL);
	nb_cli_apply_changes(ospf_nb_vty, NULL);
	vty_clear_enqueued_changes(ospf_nb_vty);
}

void ospf_nb_add_interface(struct ospf_interface *oif)
{
	char xpath[XPATH_MAXLEN];
	const char *vrf_name =
		oif->ospf->name ? oif->ospf->name : VRF_DEFAULT_NAME;

	snprintfrr(xpath, sizeof(xpath), OSPF_NB_INTERFACE_XPATH, vrf_name,
		   oif->ospf->instance, &oif->area->area_id, oif->ifp->name);
	nb_cli_enqueue_change(ospf_nb_vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_apply_changes(ospf_nb_vty, NULL);
	vty_clear_enqueued_changes(ospf_nb_vty);
}

void ospf_nb_del_interface(struct ospf_interface *oif)
{
	char xpath[XPATH_MAXLEN];
	const char *vrf_name =
		oif->ospf->name ? oif->ospf->name : VRF_DEFAULT_NAME;

	snprintfrr(xpath, sizeof(xpath), OSPF_NB_INTERFACE_XPATH, vrf_name,
		   oif->ospf->instance, &oif->area->area_id, oif->ifp->name);
	nb_cli_enqueue_change(ospf_nb_vty, xpath, NB_OP_DESTROY, NULL);
	nb_cli_apply_changes(ospf_nb_vty, NULL);
	vty_clear_enqueued_changes(ospf_nb_vty);
}

void ospf_nb_add_neighbor(struct ospf_neighbor *on)
{
	const char *vrf_name =
		on->oi->ospf->name ? on->oi->ospf->name : VRF_DEFAULT_NAME;
	char xpath[XPATH_MAXLEN];
	char source_str[INET6_ADDRSTRLEN];

	snprintfrr(xpath, sizeof(xpath), OSPF_NB_NEIGHBOR_XPATH, vrf_name,
		   on->oi->ospf->instance, &on->oi->area->area_id,
		   on->oi->ifp->name, &on->router_id);
	nb_cli_enqueue_change(ospf_nb_vty, xpath, NB_OP_CREATE, NULL);
	snprintfrr(source_str, sizeof(source_str), "%pI4", &on->src);
	nb_cli_enqueue_change(ospf_nb_vty, "./source", NB_OP_CREATE,
			      source_str);
	nb_cli_apply_changes(ospf_nb_vty, xpath);
	vty_clear_enqueued_changes(ospf_nb_vty);
}

void ospf_nb_del_neighbor(struct ospf_neighbor *on)
{
	char xpath[XPATH_MAXLEN];
	const char *vrf_name =
		on->oi->ospf->name ? on->oi->ospf->name : VRF_DEFAULT_NAME;

	snprintfrr(xpath, sizeof(xpath), OSPF_NB_NEIGHBOR_XPATH, vrf_name,
		   on->oi->ospf->instance, &on->oi->area->area_id,
		   on->oi->ifp->name, &on->router_id);
	nb_cli_enqueue_change(ospf_nb_vty, xpath, NB_OP_DESTROY, NULL);
	nb_cli_apply_changes(ospf_nb_vty, NULL);
	vty_clear_enqueued_changes(ospf_nb_vty);
}

static struct route_node *
ospf_neighbor_lookup(const struct ospf_interface *oi,
		     const struct in_addr *source,
		     const struct in_addr *router_id)
{
	struct route_node *rn;
	struct ospf_neighbor *nbr;

	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		if (rn->info == NULL)
			continue;

		nbr = rn->info;

		/* Virtual link and P2P uses router-id as index. */
		if (oi->type == OSPF_IFTYPE_VIRTUALLINK
		    || oi->type == OSPF_IFTYPE_POINTOPOINT) {
			if (!IPV4_ADDR_SAME(&nbr->router_id, router_id))
				continue;

			route_unlock_node(rn);
			return rn;
		}

		/* Regular peer. */
		if (!IPV4_ADDR_SAME(&nbr->src, source)) {
			route_unlock_node(rn);
			return rn;
		}
	}

	return NULL;
}

/*
 * XPath: /frr-ospf:ospf/instance
 */
static int ospf_instance_create(struct nb_cb_create_args *args)
{
	struct ospf *o;
	const char *vrf_name;
	struct listnode *node;
	unsigned int instance;

	switch (args->event) {
	case NB_EV_VALIDATE:
		o = ospf_lookup(yang_dnode_get_uint16(args->dnode, "./id"),
				yang_dnode_get_string(args->dnode, "./vrf"));
		if (o == NULL) {
			snprintf(args->errmsg, args->errmsg_len,
				 "OSPF instance %d VRF %s doesn't exist",
				 yang_dnode_get_uint16(args->dnode, "./id"),
				 yang_dnode_get_string(args->dnode, "./vrf"));
			return NB_ERR_VALIDATION;
		}
		break;

	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;

	case NB_EV_APPLY:
		instance = yang_dnode_get_uint16(args->dnode, "./id");
		vrf_name = yang_dnode_get_string(args->dnode, "./vrf");
		for (ALL_LIST_ELEMENTS_RO(om->ospf, node, o)) {
			if (o->instance != instance)
				continue;
			if (o->name == NULL
			    && strcmp(vrf_name, VRF_DEFAULT_NAME))
				continue;
			if (o->name && strcmp(o->name, vrf_name))
				continue;

			/* Set sequence number default value. */
			o->auth_seq_num_offset = 0;

			nb_running_set_entry(args->dnode, o);
			return NB_OK;
		}

		zlog_err("%s: ospf instance %u vrf %s does not exist", __func__,
			 instance, vrf_name);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int ospf_instance_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nb_running_unset_entry(args->dnode);
		break;
	}

	return NB_OK;
}

static const void *ospf_instance_get_next(struct nb_cb_get_next_args *args)
{
	struct listnode *node;

	if (args->list_entry == NULL)
		node = listhead(om->ospf);
	else
		node = listnextnode((struct listnode *)args->list_entry);

	return node;
}

static int ospf_instance_get_keys(struct nb_cb_get_keys_args *args)
{
	struct ospf *o = listgetdata((struct listnode *)args->list_entry);

	args->keys->num = 2;
	if (o->name)
		strlcpy(args->keys->key[0], o->name,
			sizeof(args->keys->key[0]));
	else
		strlcpy(args->keys->key[0], VRF_DEFAULT_NAME,
			sizeof(args->keys->key[0]));

	snprintf(args->keys->key[1], sizeof(args->keys->key[1]), "%u",
		 o->instance);

	return NB_OK;
}

static const void *
ospf_instance_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct listnode *node;
	struct ospf *o;
	long instance;

	for (ALL_LIST_ELEMENTS_RO(om->ospf, node, o)) {
		if (strcmp(o->name, args->keys->key[0]))
			continue;
		instance = strtol(args->keys->key[1], NULL, 10);
		if (o->instance != instance)
			continue;

		return node;
	}

	return NULL;
}

/*
 * XPath: /frr-ospf:ospf/instance/auth-sequence-number
 */
static int ospf_instance_auth_sequence_number(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	struct ospf_interface *oif;
	struct listnode *node;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = nb_running_get_entry(args->dnode, NULL, true);
	ospf->auth_seq_num_offset =
		yang_dnode_get_uint32(args->dnode, NULL) -
		(time(NULL) & 0xFFFFFFFF);
	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oif))
		oif->crypt_seqnum = ospf->auth_seq_num_offset +
			 (time(NULL) & 0xFFFFFFFF);

	return NB_OK;
}

/*
 * XPath: /frr-ospf:ospf/instance/auth-sequence-number-current
 */
static struct yang_data *ospf_instance_auth_sequence_number_current_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct ospf *ospf = listgetdata(node);

	return yang_data_new_uint32(args->xpath, ospf->auth_seq_num_offset +
			 (time(NULL) & 0xFFFFFFFF));
}

/*
 * XPath: /frr-ospf:ospf/instance/shutdown
 */
static int ospf_instance_shutdown(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	struct ospf_area *area;
	struct ospf_interface *oi;
	struct listnode *anode, *inode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = nb_running_get_entry(args->dnode, NULL, true);

	/* On `no shutdown` perform graceful restart. */
	if (!yang_dnode_get_bool(args->dnode, NULL)) {
		/*
		 * RFC 3623 - Section 5 ("Unplanned Outages"):
		 * "The grace-LSAs are encapsulated in Link State Update Packets
		 * and sent out to all interfaces, even though the restarted
		 * router has no adjacencies and no knowledge of previous
		 * adjacencies".
		 */
		for (ALL_LIST_ELEMENTS_RO(ospf->areas, anode, area)) {
			for (ALL_LIST_ELEMENTS_RO(area->oiflist, inode, oi)) {
				/*
				 * Can't check OSPF interface state as the OSPF
				 * instance wasn't enabled yet.
				 */
				if (!if_is_operative(oi->ifp)
				    || if_is_loopback(oi->ifp))
					continue;

				/* Send Grace-LSA. */
				ospf_gr_lsa_originate(
					oi, OSPF_GR_SWITCH_CONTROL_PROCESSOR,
					false);

				/* Start GR hello-delay interval. */
				if (OSPF_IF_PARAM_CONFIGURED(
					    IF_DEF_PARAMS(oi->ifp),
					    v_gr_hello_delay)) {
					oi->gr.hello_delay.elapsed_seconds = 0;
					thread_add_timer(
						master,
						ospf_gr_iface_send_grace_lsa,
						oi, 1,
						&oi->gr.hello_delay
							 .t_grace_send);
				}
			}
		}

		/* Reenable routing instance in the GR mode. */
		ospf_gr_restart_enter(ospf,
				      time(NULL) + OSPF_DFLT_GRACE_INTERVAL);
		ospf_shutdown(ospf, false, false);
	} else
		ospf_shutdown(ospf, true, true);

	return NB_OK;
}

/*
 * XPath: /frr-ospf:ospf/instance/area
 */
static int ospf_instance_area_create(struct nb_cb_create_args *args)
{
	struct ospf_area *area;
	struct listnode *node;
	struct ospf *o;
	struct in_addr area_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
		o = ospf_lookup(yang_dnode_get_uint16(args->dnode, "../id"),
				yang_dnode_get_string(args->dnode, "../vrf"));
		if (o == NULL) {
			snprintf(args->errmsg, args->errmsg_len,
				 "OSPF instance %d VRF %s doesn't exist",
				 yang_dnode_get_uint16(args->dnode, "../id"),
				 yang_dnode_get_string(args->dnode, "../vrf"));
			return NB_ERR_VALIDATION;
		}
		yang_dnode_get_ipv4(&area_id, args->dnode, "./id");
		area = ospf_area_lookup_by_area_id(o, area_id);
		if (area == NULL) {
			snprintf(args->errmsg, args->errmsg_len,
				 "OSPF area %pI4 doesn't exist", &area_id);
			return NB_ERR_VALIDATION;
		}
		break;

	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;

	case NB_EV_APPLY:
		o = nb_running_get_entry(args->dnode, NULL, true);
		yang_dnode_get_ipv4(&area_id, args->dnode, "./id");
		for (ALL_LIST_ELEMENTS_RO(o->areas, node, area)) {
			if (!IPV4_ADDR_SAME(&area->area_id, &area_id))
				continue;

			nb_running_set_entry(args->dnode, area);
			return NB_OK;
		}

		zlog_err("%s: ospf area %pI4 does not exist", __func__,
			 &area_id);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int ospf_instance_area_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	(void)nb_running_unset_entry(args->dnode);

	return NB_OK;
}

static const void *ospf_instance_area_get_next(struct nb_cb_get_next_args *args)
{
	const struct listnode *node = args->parent_list_entry;
	struct ospf *o = listgetdata(node);

	if (args->list_entry == NULL)
		node = listhead(o->areas);
	else
		node = listnextnode((struct listnode *)args->list_entry);

	return node;
}

static int ospf_instance_area_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct listnode *node = args->list_entry;
	struct ospf_area *area = listgetdata(node);

	args->keys->num = 1;
	snprintfrr(args->keys->key[0], sizeof(args->keys->key[0]), "%pI4",
		   &area->area_id);
	return NB_OK;
}

static const void *
ospf_instance_area_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const struct listnode *node = args->parent_list_entry;
	struct ospf *o = listgetdata(node);
	struct ospf_area *area;
	struct in_addr area_id;

	inet_pton(AF_INET, args->keys->key[0], &area_id);
	for (ALL_LIST_ELEMENTS_RO(o->areas, node, area)) {
		if (!IPV4_ADDR_SAME(&area->area_id, &area_id))
			continue;
		return node;
	}
	return NULL;
}

/*
 * XPath: /frr-ospf:ospf/instance/area/interface
 */
static int ospf_instance_area_interface_create(struct nb_cb_create_args *args)
{
	struct listnode *node;
	struct ospf_area *area;
	struct ospf_interface *oif;
	const char *ifname;
	struct ospf *o;
	struct in_addr area_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
		o = ospf_lookup(
			yang_dnode_get_uint16(args->dnode, "../../id"),
			yang_dnode_get_string(args->dnode, "../../vrf"));
		if (o == NULL) {
			snprintf(args->errmsg, args->errmsg_len,
				 "OSPF instance %d VRF %s doesn't exist",
				 yang_dnode_get_uint16(args->dnode, "../../id"),
				 yang_dnode_get_string(args->dnode,
						       "../../vrf"));
			return NB_ERR_VALIDATION;
		}
		yang_dnode_get_ipv4(&area_id, args->dnode, "../id");
		ifname = yang_dnode_get_string(args->dnode, "./name");
		for (ALL_LIST_ELEMENTS_RO(o->oiflist, node, oif))
			if (strcmp(oif->ifp->name, ifname) == 0)
				return NB_OK;

		snprintf(args->errmsg, args->errmsg_len,
			 "OSPF interface %s doesn't exist", ifname);
		return NB_ERR_VALIDATION;

	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;

	case NB_EV_APPLY:
		area = nb_running_get_entry(args->dnode, NULL, true);
		ifname = yang_dnode_get_string(args->dnode, "./name");
		for (ALL_LIST_ELEMENTS_RO(area->oiflist, node, oif)) {
			if (strcmp(oif->ifp->name, ifname))
				continue;

			nb_running_set_entry(args->dnode, oif);
			return NB_OK;
		}

		zlog_err("%s: OSPF interface %s does not exist", __func__,
			 ifname);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int ospf_instance_area_interface_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	(void)nb_running_unset_entry(args->dnode);

	return NB_OK;
}

static const void *
ospf_instance_area_interface_get_next(struct nb_cb_get_next_args *args)
{
	const struct listnode *node = args->parent_list_entry;
	struct ospf_area *area = listgetdata(node);

	if (args->list_entry == NULL)
		node = listhead(area->oiflist);
	else
		node = listnextnode((struct listnode *)args->list_entry);

	return node;
}

static int
ospf_instance_area_interface_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct listnode *node = args->list_entry;
	struct ospf_interface *oif = listgetdata(node);

	args->keys->num = 1;
	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%s",
		 oif->ifp->name);
	return NB_OK;
}

static const void *
ospf_instance_area_interface_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const struct listnode *node = args->parent_list_entry;
	struct ospf_area *area = listgetdata(node);
	const char *ifname = args->keys->key[0];
	struct ospf_interface *oif;

	for (ALL_LIST_ELEMENTS_RO(area->oiflist, node, oif)) {
		if (strcmp(oif->ifp->name, ifname))
			continue;
		return node;
	}
	return NULL;
}

/*
 * XPath: /frr-ospf:ospf/instance/area/interface/neighbor
 */
static int
ospf_instance_area_interface_neighbor_create(struct nb_cb_create_args *args)
{
	struct ospf_interface *oi;
	struct route_node *rn;
	const char *ifname;
	struct ospf *o;
	struct in_addr source;
	struct in_addr router_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
		o = ospf_lookup(
			yang_dnode_get_uint16(args->dnode, "../../../id"),
			yang_dnode_get_string(args->dnode, "../../../vrf"));
		if (o == NULL) {
			snprintf(args->errmsg, args->errmsg_len,
				 "OSPF instance %d VRF %s doesn't exist",
				 yang_dnode_get_uint16(args->dnode,
						       "../../../id"),
				 yang_dnode_get_string(args->dnode,
						       "../../../vrf"));
			return NB_ERR_VALIDATION;
		}

		{
			struct listnode *node;

			ifname = yang_dnode_get_string(args->dnode, "../name");
			for (ALL_LIST_ELEMENTS_RO(o->oiflist, node, oi))
				if (strcmp(oi->ifp->name, ifname) == 0)
					break;
		}

		if (oi == NULL) {
			snprintf(args->errmsg, args->errmsg_len,
				 "OSPF interface %s doesn't exist", ifname);
			return NB_ERR_VALIDATION;
		}

		yang_dnode_get_ipv4(&source, args->dnode, "./router-id");
		yang_dnode_get_ipv4(&source, args->dnode, "./source");

		rn = ospf_neighbor_lookup(oi, &source, &router_id);
		if (rn == NULL) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "OSPF neighbor %pI4 doesn't exist",
				   &router_id);
			return NB_ERR_VALIDATION;
		}
		break;

	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;

	case NB_EV_APPLY:
		oi = nb_running_get_entry(args->dnode, NULL, true);
		yang_dnode_get_ipv4(&router_id, args->dnode, "./router-id");
		yang_dnode_get_ipv4(&source, args->dnode, "./source");
		rn = ospf_neighbor_lookup(oi, &source, &router_id);
		nb_running_set_entry(args->dnode, rn);
		break;
	}

	return NB_OK;
}

static int
ospf_instance_area_interface_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	(void)nb_running_unset_entry(args->dnode);

	return NB_OK;
}

static const void *
ospf_instance_area_interface_neighbor_get_next(struct nb_cb_get_next_args *args)
{
	const struct listnode *node = args->parent_list_entry;
	const struct ospf_interface *oi = listgetdata(node);
	const struct ospf_neighbor *nbr;
	struct route_node *rn;

	if (args->list_entry == NULL)
		rn = route_top(oi->nbrs);
	else {
		route_lock_node((struct route_node *)args->list_entry);
		rn = route_next((struct route_node *)args->list_entry);
	}

	for (; rn; rn = route_next(rn)) {
		nbr = rn->info;
		/* Skip empty entries. */
		if (nbr == NULL)
			continue;
		/* Skip self neighbor. */
		if (IPV4_ADDR_SAME(&oi->nbr_self->router_id, &nbr->router_id))
			continue;

		route_unlock_node(rn);
		break;
	}

	return rn;
}

static int
ospf_instance_area_interface_neighbor_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct route_node *rn = args->list_entry;
	const struct ospf_neighbor *on = rn->info;

	args->keys->num = 1;
	snprintfrr(args->keys->key[0], sizeof(args->keys->key[0]), "%pI4",
		   &on->router_id);
	return NB_OK;
}

static const void *ospf_instance_area_interface_neighbor_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	const struct listnode *node = args->parent_list_entry;
	const struct ospf_interface *oi = listgetdata(node);
	struct route_node *rn;
	struct in_addr router_id;

	inet_pton(AF_INET, args->keys->key[0], &router_id);
	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		struct ospf_neighbor *on = rn->info;
		if (on == NULL)
			continue;
		if (!IPV4_ADDR_CMP(&on->router_id, &router_id))
			continue;
		route_unlock_node(rn);
		return rn;
	}
	return NULL;
}

/*
 * XPath: /frr-ospf:ospf/instance/area/interface/neighbor/source
 */
static int ospf_instance_area_interface_neighbor_source_modify(
	struct nb_cb_modify_args *args)
{
	/* NOTHING */
	return NB_OK;
}

static int ospf_instance_area_interface_neighbor_source_destroy(
	struct nb_cb_destroy_args *args)
{
	/* NOTHING */
	return NB_OK;
}

/*
 * XPath:
 * /frr-ospf:ospf/instance/area/interface/neighbor/auth-sequence-number-current
 */
static struct yang_data *
ospf_instance_area_interface_neighbor_auth_sequence_number_current_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct route_node *rn = args->list_entry;
	struct ospf_neighbor *on = rn->info;

	return yang_data_new_uint32(args->xpath, ntohl(on->crypt_seqnum));
}

/* clang-format off */
const struct frr_yang_module_info frr_ospf_info = {
	.name = "frr-ospf",
	.nodes = {
		{
			.xpath = "/frr-ospf:ospf/instance",
			.cbs = {
				.create = ospf_instance_create,
				.destroy = ospf_instance_destroy,
				.get_next = ospf_instance_get_next,
				.get_keys = ospf_instance_get_keys,
				.lookup_entry = ospf_instance_lookup_entry,
			}
		},
		{
			.xpath = "/frr-ospf:ospf/instance/auth-sequence-number",
			.cbs = {
				.modify = ospf_instance_auth_sequence_number,
			}
		},
		{
			.xpath = "/frr-ospf:ospf/instance/auth-sequence-number-current",
			.cbs = {
				.get_elem = ospf_instance_auth_sequence_number_current_get_elem,
			}
		},
		{
			.xpath = "/frr-ospf:ospf/instance/shutdown",
			.cbs = {
				.modify = ospf_instance_shutdown,
			}
		},
		{
			.xpath = "/frr-ospf:ospf/instance/area",
			.cbs = {
				.create = ospf_instance_area_create,
				.destroy = ospf_instance_area_destroy,
				.get_next = ospf_instance_area_get_next,
				.get_keys = ospf_instance_area_get_keys,
				.lookup_entry = ospf_instance_area_lookup_entry,
			}
		},
		{
			.xpath = "/frr-ospf:ospf/instance/area/interface",
			.cbs = {
				.create = ospf_instance_area_interface_create,
				.destroy = ospf_instance_area_interface_destroy,
				.get_next = ospf_instance_area_interface_get_next,
				.get_keys = ospf_instance_area_interface_get_keys,
				.lookup_entry = ospf_instance_area_interface_lookup_entry,
			}
		},
		{
			.xpath = "/frr-ospf:ospf/instance/area/interface/neighbor",
			.cbs = {
				.create = ospf_instance_area_interface_neighbor_create,
				.destroy = ospf_instance_area_interface_neighbor_destroy,
				.get_next = ospf_instance_area_interface_neighbor_get_next,
				.get_keys = ospf_instance_area_interface_neighbor_get_keys,
				.lookup_entry = ospf_instance_area_interface_neighbor_lookup_entry,
			}
		},
		{
			.xpath = "/frr-ospf:ospf/instance/area/interface/neighbor/source",
			.cbs = {
				.modify = ospf_instance_area_interface_neighbor_source_modify,
				.destroy = ospf_instance_area_interface_neighbor_source_destroy,
			}
		},
		{
			.xpath = "/frr-ospf:ospf/instance/area/interface/neighbor/auth-sequence-number-current",
			.cbs = {
				.get_elem = ospf_instance_area_interface_neighbor_auth_sequence_number_current_get_elem,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
