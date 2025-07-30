/* SPDX-License-Identifier: GPL-2.0-or-later */

/* 
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 *                    David Schweizer
 */


#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"
#include "static_gr_nb.h"
#include "static_gr_vty.h"


/* clang-format off */


const struct frr_yang_module_info frr_staticd_gr_info = {
	.name = "frr-staticd-gr",
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plan   ...",
			.cbs  = {
				.create = NULL,
				.modify = NULL,
				.destroy = NULL,
				.apply_finish = NULL,
			}
		},
		{
			.xpath = NULL,
		}
	}
};


/* EOF */
