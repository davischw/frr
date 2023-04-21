/*
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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

#include "if.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "northbound_cli.h"
#include "libfrr.h"
#include "lib/table.h"

#include "ripd/ripd.h"
#include "ripd/rip_nb.h"
#ifndef VTYSH_EXTRACT_PL
#include "ripd/rip_cli_clippy.c"
#endif

/*
 * XPath: /frr-ripd:ripd/instance
 */
DEFPY_YANG_NOSH (router_rip,
       router_rip_cmd,
       "router rip [vrf NAME]",
       "Enable a routing process\n"
       "Routing Information Protocol (RIP)\n"
       VRF_CMD_HELP_STR)
{
	char xpath[XPATH_MAXLEN];
	int ret;

	/* Build RIP instance XPath. */
	if (!vrf)
		vrf = VRF_DEFAULT_NAME;
	snprintf(xpath, sizeof(xpath), "/frr-ripd:ripd/instance[vrf='%s']",
		 vrf);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(RIP_NODE, xpath);

	return ret;
}

DEFPY_YANG (no_router_rip,
       no_router_rip_cmd,
       "no router rip [vrf NAME]",
       NO_STR
       "Enable a routing process\n"
       "Routing Information Protocol (RIP)\n"
       VRF_CMD_HELP_STR)
{
	char xpath[XPATH_MAXLEN];

	/* Build RIP instance XPath. */
	if (!vrf)
		vrf = VRF_DEFAULT_NAME;
	snprintf(xpath, sizeof(xpath), "/frr-ripd:ripd/instance[vrf='%s']",
		 vrf);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes_clear_pending(vty, NULL);
}

void cli_show_router_rip(struct vty *vty, const struct lyd_node *dnode,
			 bool show_defaults)
{
	const char *vrf_name;

	vrf_name = yang_dnode_get_string(dnode, "./vrf");

	vty_out(vty, "!\n");
	vty_out(vty, "router rip");
	if (!strmatch(vrf_name, VRF_DEFAULT_NAME))
		vty_out(vty, " vrf %s", vrf_name);
	vty_out(vty, "\n");
}

DEFPY_YANG (rip_shutdown,
	    rip_shutdown_cmd,
	    "[no] shutdown",
	    NO_STR
	    "Disable RIP operation\n")
{
	nb_cli_enqueue_change(vty, "./shutdown", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_shutdown(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " shutdown\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/allow-ecmp
 */
DEFPY_YANG (rip_allow_ecmp,
       rip_allow_ecmp_cmd,
       "[no] allow-ecmp",
       NO_STR
       "Allow Equal Cost MultiPath\n")
{
	nb_cli_enqueue_change(vty, "./allow-ecmp", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_allow_ecmp(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " allow-ecmp\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/default-information-originate
 */
DEFPY_YANG (rip_default_information_originate,
       rip_default_information_originate_cmd,
       "[no] default-information originate",
       NO_STR
       "Control distribution of default route\n"
       "Distribute a default route\n")
{
	nb_cli_enqueue_change(vty, "./default-information-originate",
			      NB_OP_MODIFY, no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_default_information_originate(struct vty *vty,
						const struct lyd_node *dnode,
						bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " default-information originate\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/default-metric
 */
DEFPY_YANG (rip_default_metric,
       rip_default_metric_cmd,
       "default-metric (1-16)",
       "Set a metric of redistribute routes\n"
       "Default metric\n")
{
	nb_cli_enqueue_change(vty, "./default-metric", NB_OP_MODIFY,
			      default_metric_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_rip_default_metric,
       no_rip_default_metric_cmd,
       "no default-metric [(1-16)]",
       NO_STR
       "Set a metric of redistribute routes\n"
       "Default metric\n")
{
	nb_cli_enqueue_change(vty, "./default-metric", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_default_metric(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	vty_out(vty, " default-metric %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/default
 */
DEFPY_YANG (rip_distance,
       rip_distance_cmd,
       "distance (1-255)",
       "Administrative distance\n"
       "Distance value\n")
{
	nb_cli_enqueue_change(vty, "./distance/default", NB_OP_MODIFY,
			      distance_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_rip_distance,
       no_rip_distance_cmd,
       "no distance [(1-255)]",
       NO_STR
       "Administrative distance\n"
       "Distance value\n")
{
	nb_cli_enqueue_change(vty, "./distance/default", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_distance(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	if (yang_dnode_is_default(dnode, NULL))
		vty_out(vty, " no distance\n");
	else
		vty_out(vty, " distance %s\n",
			yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/source
 */
DEFPY_YANG (rip_distance_source,
       rip_distance_source_cmd,
       "[no] distance (1-255) A.B.C.D/M$prefix [WORD$acl]",
       NO_STR
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n"
       "Access list name\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./distance", NB_OP_MODIFY,
				      distance_str);
		nb_cli_enqueue_change(vty, "./access-list",
				      acl ? NB_OP_MODIFY : NB_OP_DESTROY, acl);
	} else
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "./distance/source[prefix='%s']",
				    prefix_str);
}

void cli_show_rip_distance_source(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	vty_out(vty, " distance %s %s",
		yang_dnode_get_string(dnode, "./distance"),
		yang_dnode_get_string(dnode, "./prefix"));
	if (yang_dnode_exists(dnode, "./access-list"))
		vty_out(vty, " %s",
			yang_dnode_get_string(dnode, "./access-list"));
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/log-neighbor-changes
 */
DEFPY_YANG(rip_log_neighbor_changes, rip_log_neighbor_changes_cmd, "[no] log-neighbor-changes",
      NO_STR "Log neighbor discovery and disapperances\n")
{
        nb_cli_enqueue_change(vty, "./log-neighbor-changes", NB_OP_MODIFY,
                              no ? "false" : "true");

        return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_log_neighbor_changes(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
                vty_out(vty, " no");
        vty_out(vty, " log-neighbor-changes\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/explicit-neighbor
 */
DEFPY_YANG (rip_neighbor,
       rip_neighbor_cmd,
       "[no] neighbor A.B.C.D",
       NO_STR
       "Specify a neighbor router\n"
       "Neighbor address\n")
{
	nb_cli_enqueue_change(vty, "./explicit-neighbor",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, neighbor_str);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_neighbor(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, " neighbor %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/offset-list
 */
DEFPY_YANG (rip_offset_list,
       rip_offset_list_cmd,
       "[no] offset-list ACCESSLIST4_NAME$acl <in|out>$direction (0-16)$metric [IFNAME]",
       NO_STR
       "Modify RIP metric\n"
       "Access-list name\n"
       "For incoming updates\n"
       "For outgoing updates\n"
       "Metric value\n"
       "Interface to match\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./access-list", NB_OP_MODIFY, acl);
		nb_cli_enqueue_change(vty, "./metric", NB_OP_MODIFY,
				      metric_str);
	} else
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(
		vty, "./offset-list[interface='%s'][direction='%s']",
		ifname ? ifname : "*", direction);
}

void cli_show_rip_offset_list(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults)
{
	const char *interface;

	interface = yang_dnode_get_string(dnode, "./interface");

	vty_out(vty, " offset-list %s %s %s",
		yang_dnode_get_string(dnode, "./access-list"),
		yang_dnode_get_string(dnode, "./direction"),
		yang_dnode_get_string(dnode, "./metric"));
	if (!strmatch(interface, "*"))
		vty_out(vty, " %s", interface);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/passive-default
 */
DEFPY_YANG (rip_passive_default,
       rip_passive_default_cmd,
       "[no] passive-interface default",
       NO_STR
       "Suppress routing updates on an interface\n"
       "default for all interfaces\n")
{
	nb_cli_enqueue_change(vty, "./passive-default", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_passive_default(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " passive-interface default\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/passive-interface
 *        /frr-ripd:ripd/instance/non-passive-interface
 */
DEFPY_YANG (rip_passive_interface,
       rip_passive_interface_cmd,
       "[no] passive-interface IFNAME",
       NO_STR
       "Suppress routing updates on an interface\n"
       "Interface name\n")
{
	bool passive_default =
		yang_dnode_get_bool(vty->candidate_config->dnode, "%s%s",
				    VTY_CURR_XPATH, "/passive-default");

	if (passive_default) {
		nb_cli_enqueue_change(vty, "./non-passive-interface",
				      no ? NB_OP_CREATE : NB_OP_DESTROY,
				      ifname);
	} else {
		nb_cli_enqueue_change(vty, "./passive-interface",
				      no ? NB_OP_DESTROY : NB_OP_CREATE,
				      ifname);
	}

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_passive_interface(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, " passive-interface %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void cli_show_rip_non_passive_interface(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, " no passive-interface %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/redistribute
 */
DEFPY_YANG (rip_redistribute,
       rip_redistribute_cmd,
       "[no] redistribute " FRR_REDIST_STR_RIPD "$protocol [{metric (0-16)|route-map RMAP_NAME$route_map}]",
       NO_STR
       REDIST_STR
       FRR_REDIST_HELP_STR_RIPD
       "Metric\n"
       "Metric value\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./route-map",
				      route_map ? NB_OP_MODIFY : NB_OP_DESTROY,
				      route_map);
		nb_cli_enqueue_change(vty, "./metric",
				      metric_str ? NB_OP_MODIFY : NB_OP_DESTROY,
				      metric_str);
	} else
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "./redistribute[protocol='%s']",
				    protocol);
}

void cli_show_rip_redistribute(struct vty *vty, const struct lyd_node *dnode,
			       bool show_defaults)
{
	vty_out(vty, " redistribute %s",
		yang_dnode_get_string(dnode, "./protocol"));
	if (yang_dnode_exists(dnode, "./metric"))
		vty_out(vty, " metric %s",
			yang_dnode_get_string(dnode, "./metric"));
	if (yang_dnode_exists(dnode, "./route-map"))
		vty_out(vty, " route-map %s",
			yang_dnode_get_string(dnode, "./route-map"));
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/static-route
 */
DEFPY_YANG (rip_route,
       rip_route_cmd,
       "[no] route A.B.C.D/M",
       NO_STR
       "RIP static route configuration\n"
       "IP prefix <network>/<length>\n")
{
	nb_cli_enqueue_change(vty, "./static-route",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, route_str);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_route(struct vty *vty, const struct lyd_node *dnode,
			bool show_defaults)
{
	vty_out(vty, " route %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/timers
 */
DEFPY_YANG (rip_timers,
       rip_timers_cmd,
       "timers basic (5-2147483647)$update (5-2147483647)$timeout (5-2147483647)$garbage",
       "Adjust routing timers\n"
       "Basic routing protocol update timers\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")
{
	nb_cli_enqueue_change(vty, "./update-interval", NB_OP_MODIFY,
			      update_str);
	nb_cli_enqueue_change(vty, "./holddown-interval", NB_OP_MODIFY,
			      timeout_str);
	nb_cli_enqueue_change(vty, "./flush-interval", NB_OP_MODIFY,
			      garbage_str);

	return nb_cli_apply_changes(vty, "./timers");
}

DEFPY_YANG (no_rip_timers,
       no_rip_timers_cmd,
       "no timers basic [(5-2147483647) (5-2147483647) (5-2147483647)]",
       NO_STR
       "Adjust routing timers\n"
       "Basic routing protocol update timers\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")
{
	nb_cli_enqueue_change(vty, "./update-interval", NB_OP_MODIFY, NULL);
	nb_cli_enqueue_change(vty, "./holddown-interval", NB_OP_MODIFY, NULL);
	nb_cli_enqueue_change(vty, "./flush-interval", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, "./timers");
}

void cli_show_rip_timers(struct vty *vty, const struct lyd_node *dnode,
			 bool show_defaults)
{
	vty_out(vty, " timers basic %s %s %s\n",
		yang_dnode_get_string(dnode, "./update-interval"),
		yang_dnode_get_string(dnode, "./holddown-interval"),
		yang_dnode_get_string(dnode, "./flush-interval"));
}

/*
 * XPath: /frr-ripd:ripd/instance/version
 */
DEFPY_YANG (rip_version,
       rip_version_cmd,
       "version (1-2)",
       "Set routing protocol version\n"
       "version\n")
{
	nb_cli_enqueue_change(vty, "./version/receive", NB_OP_MODIFY,
			      version_str);
	nb_cli_enqueue_change(vty, "./version/send", NB_OP_MODIFY, version_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_rip_version,
       no_rip_version_cmd,
       "no version [(1-2)]",
       NO_STR
       "Set routing protocol version\n"
       "version\n")
{
	nb_cli_enqueue_change(vty, "./version/receive", NB_OP_MODIFY, NULL);
	nb_cli_enqueue_change(vty, "./version/send", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_version(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults)
{
	/*
	 * We have only one "version" command and three possible combinations of
	 * send/receive values.
	 */
	switch (yang_dnode_get_enum(dnode, "./receive")) {
	case RI_RIP_VERSION_1:
		vty_out(vty, " version 1\n");
		break;
	case RI_RIP_VERSION_2:
		vty_out(vty, " version 2\n");
		break;
	case RI_RIP_VERSION_1_AND_2:
		vty_out(vty, " no version\n");
		break;
	}
}

/*
 * XPath: /frr-ripd:ripd/instance/default-bfd-profile
 */
DEFPY_YANG(rip_bfd_default_profile, rip_bfd_default_profile_cmd,
	   "bfd default-profile BFDPROF$profile",
	   "Bidirection Forwarding Detection\n"
	   "BFD default profile\n"
	   "Profile name\n")
{
	nb_cli_enqueue_change(vty, "./default-bfd-profile", NB_OP_MODIFY,
			      profile);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_rip_bfd_default_profile, no_rip_bfd_default_profile_cmd,
	   "no bfd default-profile [BFDPROF]",
	   NO_STR
	   "Bidirection Forwarding Detection\n"
	   "BFD default profile\n"
	   "Profile name\n")
{
	nb_cli_enqueue_change(vty, "./default-bfd-profile", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripd_instance_default_bfd_profile(struct vty *vty,
						const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, " bfd default-profile %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip
 */
DEFPY_YANG(ip_rip_interface_enable, ip_rip_interface_enable_cmd,
	   "[no] ip rip",
	   NO_STR
	   IP_STR
	   RIP_STR)
{
	const struct lyd_node *interface_dnode =
		yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);

	if (interface_dnode == NULL) {
		vty_out(vty, "%% Failed to find interface\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, "./frr-ripd:rip",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_lib_interface_rip(struct vty *vty, const struct lyd_node *dnode,
				bool show_default)
{
	vty_out(vty, " ip rip\n");
}

/*
 * Backwards compatibility for the previous XPaths:
 * - /frr-ripd:ripd/instance/network
 * - /frr-ripd:ripd/instance/interface
 */
static struct vty *rip_nb_vty;

static void rip_nb_init(void)
{
	rip_nb_vty = vty_new();
	rip_nb_vty->wfd = STDERR_FILENO;
	rip_nb_vty->node = CONFIG_NODE;
	rip_nb_vty->type = VTY_FILE;
	rip_nb_vty->config = true;
	rip_nb_vty->candidate_config = vty_shared_candidate_config;
}

static void vty_clear_enqueued_changes(void)
{
	/* Clear array of enqueued configuration changes. */
	rip_nb_vty->num_cfg_changes = 0;
	memset(&rip_nb_vty->cfg_changes, 0, sizeof(rip_nb_vty->cfg_changes));
}

int ip_rip_interface_network_toggle(struct vty *vty,
				    const struct prefix_ipv4 *network)
{
	struct vty *vty_selected = vty ? vty : rip_nb_vty;
	struct vrf *vrf;
	int return_value = CMD_SUCCESS;
	char xpath[XPATH_MAXLEN];

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct interface *interface;

		FOR_ALL_INTERFACES (vrf, interface) {
			const struct listnode *node;
			const struct connected *connected;

			FOR_ALL_INTERFACES_ADDRESSES (interface, connected,
						      node) {
				if (prefix_cmp(network, connected->address) !=
				    0)
					continue;

				snprintf(
					xpath, sizeof(xpath),
					"/frr-interface:lib/interface[name='%s']/frr-ripd:rip",
					interface->name);
				nb_cli_enqueue_change(vty_selected, xpath,
						      NB_OP_CREATE, NULL);
				if (nb_cli_apply_changes(vty_selected, NULL) !=
				    CMD_SUCCESS)
					return_value = CMD_WARNING;
				if (vty_selected == rip_nb_vty)
					vty_clear_enqueued_changes();
			}
		}
	}

	return return_value;
}

DEFPY_HIDDEN(rip_network_prefix,
	     rip_network_prefix_cmd,
	     "[no] network A.B.C.D/M$network",
	     NO_STR
	     "Enable routing on an IP network\n"
	     "IP prefix\n")
{
	char xpath[XPATH_MAXLEN];
	struct vrf *vrf;

	if (snprintf(xpath, sizeof(xpath), "%s/vrf", VTY_CURR_XPATH) >=
	    XPATH_MAXLEN)
		zlog_err("XPath %s is truncated (expected %s/vrf)", xpath,
			 xpath);

	vrf = vrf_lookup_by_name(
		yang_dnode_get_string(vty->candidate_config->dnode, xpath));
	if (no) {
		rip_network_legacy_free_prefix(vrf->info,
					       (struct prefix *)network);
		return CMD_SUCCESS;
	}

	rip_network_legacy_new_prefix(vrf->info, (struct prefix *)network);
	return ip_rip_interface_network_toggle(vty, network);
}

int ip_rip_interface_name_toggle(struct vty *vty, const char *name)
{
	struct vty *vty_selected = vty ? vty : rip_nb_vty;
	struct vrf *vrf;
	int return_value = CMD_SUCCESS;
	char xpath[XPATH_MAXLEN];

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct interface *interface;

		FOR_ALL_INTERFACES (vrf, interface) {
			if (strcmp(name, interface->name) != 0)
				continue;

			snprintf(
				xpath, sizeof(xpath),
				"/frr-interface:lib/interface[name='%s']/frr-ripd:rip",
				interface->name);
			nb_cli_enqueue_change(vty_selected, xpath, NB_OP_CREATE,
					      NULL);
			if (nb_cli_apply_changes(vty_selected, NULL) !=
			    CMD_SUCCESS)
				return_value = CMD_WARNING;
			if (vty_selected == rip_nb_vty)
				vty_clear_enqueued_changes();
		}
	}

	return return_value;
}

DEFPY_HIDDEN(rip_network_if,
	     rip_network_if_cmd,
	     "[no] network WORD$interface_name",
	     NO_STR
	     "Enable routing on an IP network\n"
	     "Interface name\n")
{
	char xpath[XPATH_MAXLEN];
	struct vrf *vrf;

	if (snprintf(xpath, sizeof(xpath), "%s/vrf", VTY_CURR_XPATH) >=
	    XPATH_MAXLEN)
		zlog_err("XPath %s is truncated (expected %s/vrf)", xpath,
			 xpath);

	vrf = vrf_lookup_by_name(
		yang_dnode_get_string(vty->candidate_config->dnode, xpath));
	if (no) {
		rip_network_legacy_free_interface(vrf->info, interface_name);
		return CMD_SUCCESS;
	}

	rip_network_legacy_new_interface(vrf->info, interface_name);
	return ip_rip_interface_name_toggle(vty, interface_name);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/split-horizon
 */
DEFPY_YANG (ip_rip_split_horizon,
       ip_rip_split_horizon_cmd,
       "[no] ip rip split-horizon [poisoned-reverse$poisoned_reverse]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Perform split horizon\n"
       "With poisoned-reverse\n")
{
	const char *value;

	if (no)
		value = "disabled";
	else if (poisoned_reverse)
		value = "poison-reverse";
	else
		value = "simple";

	nb_cli_enqueue_change(vty, "./split-horizon", NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_split_horizon(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	int value;

	value = yang_dnode_get_enum(dnode, NULL);
	switch (value) {
	case RIP_NO_SPLIT_HORIZON:
		vty_out(vty, " no ip rip split-horizon\n");
		break;
	case RIP_SPLIT_HORIZON:
		vty_out(vty, " ip rip split-horizon\n");
		break;
	case RIP_SPLIT_HORIZON_POISONED_REVERSE:
		vty_out(vty, " ip rip split-horizon poisoned-reverse\n");
		break;
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/v2-broadcast
 */
DEFPY_YANG (ip_rip_v2_broadcast,
       ip_rip_v2_broadcast_cmd,
       "[no] ip rip v2-broadcast",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Send ip broadcast v2 update\n")
{
	nb_cli_enqueue_change(vty, "./v2-broadcast", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_v2_broadcast(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " ip rip v2-broadcast\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/version-receive
 */
DEFPY_YANG (ip_rip_receive_version,
       ip_rip_receive_version_cmd,
       "ip rip receive version <{1$v1|2$v2}|none>",
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement reception\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n"
       "None\n")
{
	const char *value;

	if (v1 && v2)
		value = "both";
	else if (v1)
		value = "1";
	else if (v2)
		value = "2";
	else
		value = "none";

	nb_cli_enqueue_change(vty, "./version-receive", NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

DEFPY_YANG (no_ip_rip_receive_version,
       no_ip_rip_receive_version_cmd,
       "no ip rip receive version [<{1|2}|none>]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement reception\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n"
       "None\n")
{
	nb_cli_enqueue_change(vty, "./version-receive", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_receive_version(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults)
{
	switch (yang_dnode_get_enum(dnode, NULL)) {
	case RI_RIP_UNSPEC:
		vty_out(vty, " no ip rip receive version\n");
		break;
	case RI_RIP_VERSION_1:
		vty_out(vty, " ip rip receive version 1\n");
		break;
	case RI_RIP_VERSION_2:
		vty_out(vty, " ip rip receive version 2\n");
		break;
	case RI_RIP_VERSION_1_AND_2:
		vty_out(vty, " ip rip receive version 1 2\n");
		break;
	case RI_RIP_VERSION_NONE:
		vty_out(vty, " ip rip receive version none\n");
		break;
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/version-send
 */
DEFPY_YANG (ip_rip_send_version,
       ip_rip_send_version_cmd,
       "ip rip send version <{1$v1|2$v2}|none>",
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement transmission\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n"
       "None\n")
{
	const char *value;

	if (v1 && v2)
		value = "both";
	else if (v1)
		value = "1";
	else if (v2)
		value = "2";
	else
		value = "none";

	nb_cli_enqueue_change(vty, "./version-send", NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

DEFPY_YANG (no_ip_rip_send_version,
       no_ip_rip_send_version_cmd,
       "no ip rip send version [<{1|2}|none>]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement transmission\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n"
       "None\n")
{
	nb_cli_enqueue_change(vty, "./version-send", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_send_version(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	switch (yang_dnode_get_enum(dnode, NULL)) {
	case RI_RIP_UNSPEC:
		vty_out(vty, " no ip rip send version\n");
		break;
	case RI_RIP_VERSION_1:
		vty_out(vty, " ip rip send version 1\n");
		break;
	case RI_RIP_VERSION_2:
		vty_out(vty, " ip rip send version 2\n");
		break;
	case RI_RIP_VERSION_1_AND_2:
		vty_out(vty, " ip rip send version 1 2\n");
		break;
	case RI_RIP_VERSION_NONE:
		vty_out(vty, " ip rip send version none\n");
		break;
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-scheme
 */
DEFPY_YANG (ip_rip_authentication_mode,
       ip_rip_authentication_mode_cmd,
       "ip rip authentication mode <md5$mode [auth-length <rfc|old-ripd>$auth_length]|text$mode>",
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication mode\n"
       "Keyed message digest\n"
       "MD5 authentication data length\n"
       "RFC compatible\n"
       "Old ripd compatible\n"
       "Clear text authentication\n")
{
	const char *value = NULL;

	if (auth_length) {
		if (strmatch(auth_length, "rfc"))
			value = "16";
		else
			value = "20";
	}

	nb_cli_enqueue_change(vty, "./authentication-scheme/mode", NB_OP_MODIFY,
			      strmatch(mode, "md5") ? "md5" : "plain-text");
	if (strmatch(mode, "md5"))
		nb_cli_enqueue_change(vty,
				      "./authentication-scheme/md5-auth-length",
				      NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

DEFPY_YANG (no_ip_rip_authentication_mode,
       no_ip_rip_authentication_mode_cmd,
       "no ip rip authentication mode [<md5 [auth-length <rfc|old-ripd>]|text>]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication mode\n"
       "Keyed message digest\n"
       "MD5 authentication data length\n"
       "RFC compatible\n"
       "Old ripd compatible\n"
       "Clear text authentication\n")
{
	nb_cli_enqueue_change(vty, "./authentication-scheme/mode", NB_OP_MODIFY,
			      NULL);
	nb_cli_enqueue_change(vty, "./authentication-scheme/md5-auth-length",
			      NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_authentication_scheme(struct vty *vty,
					   const struct lyd_node *dnode,
					   bool show_defaults)
{
	switch (yang_dnode_get_enum(dnode, "./mode")) {
	case RIP_NO_AUTH:
		vty_out(vty, " no ip rip authentication mode\n");
		break;
	case RIP_AUTH_SIMPLE_PASSWORD:
		vty_out(vty, " ip rip authentication mode text\n");
		break;
	case RIP_AUTH_MD5:
		vty_out(vty, " ip rip authentication mode md5");
		if (show_defaults
		    || !yang_dnode_is_default(dnode, "./md5-auth-length")) {
			if (yang_dnode_get_enum(dnode, "./md5-auth-length")
			    == RIP_AUTH_MD5_SIZE)
				vty_out(vty, " auth-length rfc");
			else
				vty_out(vty, " auth-length old-ripd");
		}
		vty_out(vty, "\n");
		break;
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-password
 */
DEFPY_YANG (ip_rip_authentication_string,
       ip_rip_authentication_string_cmd,
       "ip rip authentication string LINE$password",
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication string\n"
       "Authentication string\n")
{
	if (strlen(password) > 16) {
		vty_out(vty,
			"%% RIPv2 authentication string must be shorter than 16\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (yang_dnode_existsf(vty->candidate_config->dnode, "%s%s",
			       VTY_CURR_XPATH,
			       "/frr-ripd:rip/authentication-key-chain")) {
		vty_out(vty, "%% key-chain configuration exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, "./authentication-password", NB_OP_MODIFY,
			      password);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

DEFPY_YANG (no_ip_rip_authentication_string,
       no_ip_rip_authentication_string_cmd,
       "no ip rip authentication string [LINE]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication string\n"
       "Authentication string\n")
{
	nb_cli_enqueue_change(vty, "./authentication-password", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_authentication_string(struct vty *vty,
					   const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, " ip rip authentication string %s\n",
		vty->is_show_running ? "****"
				     : yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-key-chain
 */
DEFPY_YANG (ip_rip_authentication_key_chain,
       ip_rip_authentication_key_chain_cmd,
       "ip rip authentication key-chain LINE$keychain",
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication key-chain\n"
       "name of key-chain\n")
{
	if (yang_dnode_existsf(vty->candidate_config->dnode, "%s%s",
			       VTY_CURR_XPATH,
			       "/frr-ripd:rip/authentication-password")) {
		vty_out(vty, "%% authentication string configuration exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, "./authentication-key-chain", NB_OP_MODIFY,
			      keychain);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

DEFPY_YANG (no_ip_rip_authentication_key_chain,
       no_ip_rip_authentication_key_chain_cmd,
       "no ip rip authentication key-chain [LINE]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication key-chain\n"
       "name of key-chain\n")
{
	nb_cli_enqueue_change(vty, "./authentication-key-chain", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_authentication_key_chain(struct vty *vty,
					      const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, " ip rip authentication key-chain %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/bfd-monitoring/enable
 */
DEFPY_YANG(ip_rip_bfd, ip_rip_bfd_cmd, "[no] ip rip bfd",
	   NO_STR IP_STR
	   "Routing Information Protocol\n"
	   "Enable BFD support\n")
{
	nb_cli_enqueue_change(vty, "./bfd-monitoring/enable", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_bfd_enable(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, " ip rip bfd\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/bfd/profile
 */
DEFPY_YANG(ip_rip_bfd_profile, ip_rip_bfd_profile_cmd,
	   "[no] ip rip bfd profile BFDPROF$profile",
	   NO_STR IP_STR
	   "Routing Information Protocol\n"
	   "Enable BFD support\n"
	   "Use a pre-configured profile\n"
	   "Profile name\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./bfd-monitoring/profile",
				      NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./bfd-monitoring/profile",
				      NB_OP_MODIFY, profile);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

DEFPY_YANG(no_ip_rip_bfd_profile, no_ip_rip_bfd_profile_cmd,
	   "no ip rip bfd profile",
	   NO_STR IP_STR
	   "Routing Information Protocol\n"
	   "Enable BFD support\n"
	   "Use a pre-configured profile\n")
{
	nb_cli_enqueue_change(vty, "./bfd-monitoring/profile", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_bfd_profile(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	vty_out(vty, " ip rip bfd profile %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:clear-rip-route
 */
DEFPY_YANG (clear_ip_rip,
       clear_ip_rip_cmd,
       "clear ip rip [vrf WORD]",
       CLEAR_STR
       IP_STR
       "Clear IP RIP database\n"
       VRF_CMD_HELP_STR)
{
	struct list *input;
	int ret;

	input = list_new();
	if (vrf) {
		struct yang_data *yang_vrf;

		yang_vrf = yang_data_new("/frr-ripd:clear-rip-route/input/vrf",
					 vrf);
		listnode_add(input, yang_vrf);
	}

	ret = nb_cli_rpc(vty, "/frr-ripd:clear-rip-route", input, NULL);

	list_delete(&input);

	return ret;
}

DEFUN (rip_distribute_list,
       rip_distribute_list_cmd,
       "distribute-list [prefix] ACCESSLIST4_NAME <in|out> [WORD]",
       "Filter networks in routing updates\n"
       "Specify a prefix\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	const char *ifname = NULL;
	int prefix = (argv[1]->type == WORD_TKN) ? 1 : 0;

	if (argv[argc - 1]->type == VARIABLE_TKN)
		ifname = argv[argc - 1]->arg;

	return distribute_list_parser(prefix, true, argv[2 + prefix]->text,
				      argv[1 + prefix]->arg, ifname);
}

DEFUN (rip_no_distribute_list,
       rip_no_distribute_list_cmd,
       "no distribute-list [prefix] ACCESSLIST4_NAME <in|out> [WORD]",
       NO_STR
       "Filter networks in routing updates\n"
       "Specify a prefix\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	const char *ifname = NULL;
	int prefix = (argv[2]->type == WORD_TKN) ? 1 : 0;

	if (argv[argc - 1]->type == VARIABLE_TKN)
		ifname = argv[argc - 1]->arg;

	return distribute_list_no_parser(vty, prefix, true,
					 argv[3 + prefix]->text,
					 argv[2 + prefix]->arg, ifname);
}

static inline void show_rip_redist_route(struct vty *vty, const struct rip *rip,
					 const struct rip_info *info)
{
	const struct interface *interface =
		if_lookup_by_index(info->nh.ifindex, rip->vrf->vrf_id);

	vty_out(vty, "{\"prefix\":\"%pFX\",", &info->rp->p);
	vty_out(vty, "\"nextHop\":\"%pI4\",", &info->nh.gate.ipv4);
	vty_out(vty, "\"interface\":\"%s\",",
		interface ? interface->name : "unknown");
	vty_out(vty, "\"metric\":%u,", info->metric);
	vty_out(vty, "\"vrf\":\"%s\",", rip->vrf_name);
	vty_out(vty, "\"from\":\"%s\",", zebra_route_string(info->type));
	vty_out(vty, "\"to\":\"rip\"}");
}

static void show_rip_redist_routes(struct vty *vty)
{
	struct rip *rip;
	bool first = true;

	RB_FOREACH (rip, rip_instance_head, &rip_instances) {
		struct route_node *route_node;

		for (route_node = route_top(rip->table); route_node;
		     route_node = route_next(route_node)) {
			const struct list *route_list = route_node->info;
			const struct listnode *route_list_node;
			const struct rip_info *info = route_node->info;

			if (route_list == NULL || listcount(route_list) == 0)
				continue;

			route_list_node = listhead(route_list);
			info = route_list_node->data;

			if (first)
				first = false;
			else
				vty_out(vty, ",");

			show_rip_redist_route(vty, rip, info);
		}
	}
}

DEFUN(show_rip_redist, show_rip_redist_cmd,
      "show routing redistribution ripd json",
      SHOW_STR
      ROUTING_CMD_STR
      REDISTRIBUTION_CMD_STR
      RIP_STR
      JSON_STR)
{
	vty_out(vty, "[");
	show_rip_redist_routes(vty);
	vty_out(vty, "]\n");
	return CMD_SUCCESS;
}

DEFUN_NOSH(show_rip_redist_no_list, show_rip_redist_no_list_cmd,
	   "show routing redistribution ripd json no-list [comma]",
	   SHOW_STR
	   ROUTING_CMD_STR
	   REDISTRIBUTION_CMD_STR
	   RIP_STR
	   JSON_STR
	   REDIST_NO_LIST_STR
	   REDIST_COMMA_STR)
{
	if (argc == 7)
		vty_out(vty, ",");

	vty_out(vty, "{\"ripd\":[");
	show_rip_redist_routes(vty);
	vty_out(vty, "]}\n");
	return CMD_SUCCESS;
}

void rip_cli_init(void)
{
	rip_nb_init();

	install_element(CONFIG_NODE, &router_rip_cmd);
	install_element(CONFIG_NODE, &no_router_rip_cmd);

	install_element(RIP_NODE, &rip_distribute_list_cmd);
	install_element(RIP_NODE, &rip_no_distribute_list_cmd);

	install_element(RIP_NODE, &rip_shutdown_cmd);
	install_element(RIP_NODE, &rip_allow_ecmp_cmd);
	install_element(RIP_NODE, &rip_default_information_originate_cmd);
	install_element(RIP_NODE, &rip_default_metric_cmd);
	install_element(RIP_NODE, &no_rip_default_metric_cmd);
	install_element(RIP_NODE, &rip_distance_cmd);
	install_element(RIP_NODE, &no_rip_distance_cmd);
	install_element(RIP_NODE, &rip_distance_source_cmd);
	install_element(RIP_NODE, &rip_log_neighbor_changes_cmd);
	install_element(RIP_NODE, &rip_neighbor_cmd);
	install_element(RIP_NODE, &rip_offset_list_cmd);
	install_element(RIP_NODE, &rip_passive_default_cmd);
	install_element(RIP_NODE, &rip_passive_interface_cmd);
	install_element(RIP_NODE, &rip_redistribute_cmd);
	install_element(RIP_NODE, &rip_route_cmd);
	install_element(RIP_NODE, &rip_timers_cmd);
	install_element(RIP_NODE, &no_rip_timers_cmd);
	install_element(RIP_NODE, &rip_version_cmd);
	install_element(RIP_NODE, &no_rip_version_cmd);
	install_element(RIP_NODE, &rip_bfd_default_profile_cmd);
	install_element(RIP_NODE, &no_rip_bfd_default_profile_cmd);

	install_element(INTERFACE_NODE, &ip_rip_interface_enable_cmd);
	install_element(RIP_NODE, &rip_network_prefix_cmd);
	install_element(RIP_NODE, &rip_network_if_cmd);
	install_element(INTERFACE_NODE, &ip_rip_split_horizon_cmd);
	install_element(INTERFACE_NODE, &ip_rip_v2_broadcast_cmd);
	install_element(INTERFACE_NODE, &ip_rip_receive_version_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_receive_version_cmd);
	install_element(INTERFACE_NODE, &ip_rip_send_version_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_send_version_cmd);
	install_element(INTERFACE_NODE, &ip_rip_authentication_mode_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_authentication_mode_cmd);
	install_element(INTERFACE_NODE, &ip_rip_authentication_string_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_authentication_string_cmd);
	install_element(INTERFACE_NODE, &ip_rip_authentication_key_chain_cmd);
	install_element(INTERFACE_NODE,
			&no_ip_rip_authentication_key_chain_cmd);
	install_element(INTERFACE_NODE, &ip_rip_bfd_cmd);
	install_element(INTERFACE_NODE, &ip_rip_bfd_profile_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_bfd_profile_cmd);

	install_element(ENABLE_NODE, &clear_ip_rip_cmd);

	install_element(ENABLE_NODE, &show_rip_redist_cmd);
	install_element(ENABLE_NODE, &show_rip_redist_no_list_cmd);
}
