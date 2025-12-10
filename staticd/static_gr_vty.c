// SPDX-License-Identifier: GPL-2.0-or-later


/*
 * staticd - graceful restart vty code
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 *               David Schweizer
 */


#include <zebra.h>

#include "command.h"
#include "vty.h"

/*
#include "vrf.h"
#include "prefix.h"
#include "nexthop.h"
#include "table.h"
#include "srcdest_table.h"
#include "mgmt_be_client.h"
#include "mpls.h"
#include "northbound.h"
#include "libfrr.h"
#include "routing_nb.h"
#include "northbound_cli.h"
#include "frrdistance.h"
*/

/*
#include "static_vrf.h"
#include "static_vty.h"
#include "static_routes.h"
#include "static_debug.h"
#include "staticd/static_vty_clippy.c"
#include "static_nb.h"
#include "static_srv6.h"
#include "static_zebra.h"
*/


/* TODO: string definitions */


/* clang-format off */


DEFPY( staticd_show_graceful_restart,
       staticd_show_graceful_restart_cmd,
       "show static graceful-restart [vrf$vrf_name] [json]",
       SHOW_STR
       STATICD_STR
       "GRACEFUL_RESTART_STR"
       VRF_STR
       JSON_STR)
{
	vrf_id_t vrf_id;

	if (vrf_name) {
		vrf_id_t = vrf_id_lookup_by_name(vrf_name);

		if (!!json)
			show_static_gr_vrf_json(vty, vrf_id);
		else
			show_static_gr_vrf(vty, vrf_id);
	} else {
		if (!!json)
        		show_static_gr_vrf_all_json(vty);
		else
        		show_static_gr_vrf_all(vty);
	}

        return CMD_SUCCESS;

}


/* clang-format on */


/* EOF */
