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

#include "bgpd/bgpd.h"
#include "bgpd/bgp_nb.h"

static struct vty *bgp_nb_vty;

void bgp_nb_init(void)
{
	bgp_nb_vty = vty_new();
	bgp_nb_vty->wfd = STDERR_FILENO;
	bgp_nb_vty->node = CONFIG_NODE;
	bgp_nb_vty->type = VTY_FILE;
	bgp_nb_vty->config = true;
	bgp_nb_vty->candidate_config = vty_shared_candidate_config;
}

void bgp_nb_add_instance(struct bgp *bgp)
{
	char xpath[XPATH_MAXLEN];
	const char *vrf_name = bgp->name ? bgp->name : VRF_DEFAULT_NAME;

	snprintf(xpath, sizeof(xpath), BGP_NB_INSTANCE_XPATH, vrf_name);
	nb_cli_enqueue_change(bgp_nb_vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_apply_changes(bgp_nb_vty, NULL);
}

void bgp_nb_del_instance(struct bgp *bgp)
{
	char xpath[XPATH_MAXLEN];
	const char *vrf_name = bgp->name ? bgp->name : VRF_DEFAULT_NAME;

	snprintf(xpath, sizeof(xpath), BGP_NB_INSTANCE_XPATH, vrf_name);
	nb_cli_enqueue_change(bgp_nb_vty, xpath, NB_OP_DESTROY, NULL);
	nb_cli_apply_changes(bgp_nb_vty, NULL);
}

/*
 * XPath: /frr-bgpd:bgpd/instance
 */
static int bgpd_instance_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	struct listnode *node;
	const char *vrf_name;

	vrf_name = yang_dnode_get_string(args->dnode, "./vrf");

	switch (args->event) {
	case NB_EV_VALIDATE:
#if 0
		bgp = bgp_lookup_by_name(vrf_name);
		if (bgp == NULL) {
			snprintf(args->errmsg, args->errmsg_len,
				 "BGP instance on VRF %s doesn't exist",
				 vrf_name);
			return NB_ERR_VALIDATION;
		}
#endif
		break;

	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;

	case NB_EV_APPLY:
		for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
			if (bgp->name == NULL
			    && strcmp(vrf_name, VRF_DEFAULT_NAME))
				continue;
			if (bgp->name && strcmp(bgp->name, vrf_name))
				continue;

			nb_running_set_entry(args->dnode, bgp);
			return NB_OK;
		}

		zlog_err("%s: ospf instance on vrf %s does not exist", __func__,
			 vrf_name);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int bgpd_instance_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-bgpd:bgpd/instance/shutdown
 */
static int bgpd_instance_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		bgp_shutdown_enable(bgp, NULL);
	else
		bgp_shutdown_disable(bgp);

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_bgpd_info = {
	.name = "frr-bgpd",
	.nodes = {
		{
			.xpath = "/frr-bgpd:bgpd/instance",
			.cbs = {
				.create = bgpd_instance_create,
				.destroy = bgpd_instance_destroy,
			}
		},
		{
			.xpath = "/frr-bgpd:bgpd/instance/shutdown",
			.cbs = {
				.modify = bgpd_instance_shutdown_modify,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
