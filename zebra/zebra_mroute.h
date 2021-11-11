/* zebra_mroute.h
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __ZEBRA_MROUTE_H__
#define __ZEBRA_MROUTE_H__

#include <linux/mroute.h>

#include "zebra/zserv.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mcast_route_data {
	struct prefix_sg sg;
	unsigned int ifindex;
	unsigned long long lastused;
};

void zebra_ipmr_route_stats(ZAPI_HANDLER_ARGS);

/** Custom netlink attribute value definition. */
#define RTA_MRT_EXTRA 64

/** Custom netlink attribute for passing extra multicast route information. */
struct mrt_extra_attr {
	/** Bandwidth threshold in kbps. */
	int32_t spt_threshold;
	/** RPF interface index. */
	int32_t notif_idx;
	/** Multicast flags. */
	uint32_t flags;
	/** RP encapsulated data: source. */
	struct in6_addr local;
	/** RP encapsulated data: destination. */
	struct in6_addr remote;
};

/** Multicast route argument represantation. */
struct mroute_args {
	/** Source address. */
	struct ipaddr source;
	/** Multicast group address. */
	struct ipaddr group;
	/** Flags to signalize different options. */
	uint32_t flags;
	/** Input interface index. */
	ifindex_t input;
	/** Amount of output interfaces. */
	size_t output_amount;
	/** Output interface indexes. */
	ifindex_t output[MAXVIFS];
	/** RPF interface information. */
	ifindex_t notif_idx;

	/** Bandwidth threshold information (in kbps). */
	int32_t spt_threshold;

	/** RP encap local information. */
	struct ipaddr local;
	/** RP encap remote information. */
	struct ipaddr remote;

	/** Multicast route operation. */
	/* enum dplane_op_e */ int mroute_op;

	/** VRF identification. */
	vrf_id_t vrf_id;
};

void zmroute_event(ZAPI_HANDLER_ARGS);
void zmroute_sync(vrf_id_t vrf_id);

#ifdef __cplusplus
}
#endif

#endif
