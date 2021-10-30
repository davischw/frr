/*
 * OSPFv3 northbound implementation.
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
#include "lib/vrf.h"

#include "ospf6d/ospf6d.h"
#include "ospf6d/ospf6_top.h"
#include "ospf6d/ospf6_lsa.h"
#include "ospf6d/ospf6_area.h"
#include "ospf6d/ospf6_interface.h"
#include "ospf6d/ospf6_gr.h"
#include "ospf6d/ospf6_nb.h"

static struct vty *ospf6_nb_vty;

void ospf6_nb_init(void)
{
	ospf6_nb_vty = vty_new();
	ospf6_nb_vty->wfd = STDERR_FILENO;
	ospf6_nb_vty->node = CONFIG_NODE;
	ospf6_nb_vty->type = VTY_FILE;
	ospf6_nb_vty->config = true;
	ospf6_nb_vty->candidate_config = vty_shared_candidate_config;
}

static void vty_clear_enqueued_changes(struct vty *vty)
{
	/* Clear array of enqueued configuration changes. */
	vty->num_cfg_changes = 0;
	memset(&vty->cfg_changes, 0, sizeof(vty->cfg_changes));
}

void ospf6_nb_add_instance(struct ospf6 *o)
{
	char xpath[XPATH_MAXLEN];
	const char *vrf_name = o->name ? o->name : VRF_DEFAULT_NAME;

	snprintf(xpath, sizeof(xpath), OSPFV3_NB_INSTANCE_XPATH, vrf_name);
	nb_cli_enqueue_change(ospf6_nb_vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_apply_changes(ospf6_nb_vty, NULL);
	vty_clear_enqueued_changes(ospf6_nb_vty);
}

void ospf6_nb_del_instance(struct ospf6 *o)
{
	char xpath[XPATH_MAXLEN];
	const char *vrf_name = o->name ? o->name : VRF_DEFAULT_NAME;

	snprintf(xpath, sizeof(xpath), OSPFV3_NB_INSTANCE_XPATH, vrf_name);
	nb_cli_enqueue_change(ospf6_nb_vty, xpath, NB_OP_DESTROY, NULL);
	nb_cli_apply_changes(ospf6_nb_vty, NULL);
	vty_clear_enqueued_changes(ospf6_nb_vty);
}

/*
 * XPath: /frr-ospfv3:ospfv3/instance
 */
static int ospfv3_instance_create(struct nb_cb_create_args *args)
{
	struct ospf6 *o;
	struct listnode *node;
	const char *vrf_name;

	vrf_name = yang_dnode_get_string(args->dnode, "./vrf");

	switch (args->event) {
	case NB_EV_VALIDATE:
		o = ospf6_lookup_by_vrf_name(vrf_name);
		if (o == NULL) {
			snprintf(args->errmsg, args->errmsg_len,
				 "OSPF instance on VRF %s doesn't exist",
				 vrf_name);
			return NB_ERR_VALIDATION;
		}
		break;

	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;

	case NB_EV_APPLY:
		for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, o)) {
			if (o->name == NULL
			    && strcmp(vrf_name, VRF_DEFAULT_NAME))
				continue;
			if (o->name && strcmp(o->name, vrf_name))
				continue;

			nb_running_set_entry(args->dnode, o);
			return NB_OK;
		}

		zlog_err("%s: ospf instance on vrf %s does not exist", __func__,
			 vrf_name);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int ospfv3_instance_destroy(struct nb_cb_destroy_args *args)
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

/*
 * XPath: /frr-ospfv3:ospfv3/instance/shutdown
 */
static int ospfv3_instance_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	struct ospf6_area *area;
	struct ospf6_interface *oi;
	struct listnode *anode, *inode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf6 = nb_running_get_entry(args->dnode, NULL, true);

	/* On `no shutdown` perform graceful restart. */
	if (!yang_dnode_get_bool(args->dnode, NULL)) {
		/*
		 * RFC 3623 - Section 5 ("Unplanned Outages"):
		 * "The grace-LSAs are encapsulated in Link State Update Packets
		 * and sent out to all interfaces, even though the restarted
		 * router has no adjacencies and no knowledge of previous
		 * adjacencies".
		 */
		for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, anode, area)) {
			for (ALL_LIST_ELEMENTS_RO(area->if_list, inode, oi)) {
				/*
				 * Can't check OSPF interface state as the OSPF
				 * instance wasn't enabled yet.
				 */
				if (!if_is_operative(oi->interface)
				    || if_is_loopback(oi->interface))
					continue;

				/* Send Grace-LSA. */
				ospf6_gr_lsa_originate(
					oi, OSPF6_GR_SWITCH_CONTROL_PROCESSOR);

				/* Start GR hello-delay interval. */
				if (oi->gr.hello_delay.interval) {
					oi->gr.hello_delay.elapsed_seconds = 0;
					thread_add_timer(
						master,
						ospf6_gr_iface_send_grace_lsa,
						oi, 1,
						&oi->gr.hello_delay
							 .t_grace_send);
				}
			}
		}

		/* Reenable routing instance in the GR mode. */
		ospf6_gr_restart_enter(ospf6, OSPF6_GR_SWITCH_CONTROL_PROCESSOR,
				       time(NULL)
					       + ospf6->gr_info.grace_period);
		ospf6_shutdown(ospf6, false, false);
	} else
		ospf6_shutdown(ospf6, true, true);

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_ospfv3_info = {
	.name = "frr-ospfv3",
	.nodes = {
		{
			.xpath = "/frr-ospfv3:ospfv3/instance",
			.cbs = {
				.create = ospfv3_instance_create,
				.destroy = ospfv3_instance_destroy,
			}
		},
		{
			.xpath = "/frr-ospfv3:ospfv3/instance/shutdown",
			.cbs = {
				.modify = ospfv3_instance_shutdown_modify,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
