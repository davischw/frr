/*
 * OSPF IP magic encapsulation.
 *
 * Copyright (C) 2021 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "lib/checksum.h"
#include "lib/network.h"
#include "lib/prefix.h"
#include "lib/thread.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_packet.h"

#include <stdint.h>

void
ospf_ip_encap_set(struct ip_encap *ie, const struct ospf_interface *oi,
		  const struct ip *ip)
{
	/*
	 * Direction |  Source  | Destination   | Proto | TTL
	 * ----------+----------+---------------+-------+----
	 * MP -> DP  | original | 127.130.1.254 |   249 |   1
	 */
	ie->ver_hl = IP_ENCAP_VER << 4 | IP_ENCAP_WORD_SIZE;
	ie->dsf_ecn = IP_ENCAP_DSF;
	ie->frag = 0;
	ie->id = htons(((uint16_t)frr_weak_random()));
	ie->len = htons(sizeof(*ie) + ntohs(ip->ip_len));
	ie->ttl = 1;
	ie->proto = OSPF_IP_ENCAP_OTHER;
	ie->src = oi->address->u.prefix4.s_addr;
	ie->dst = htonl(IP_ENCAP_DST);
	ie->checksum = 0;
	ie->checksum = (uint16_t)in_cksum(ie, IP_ENCAP_WORD_SIZE << 2);

	ie->ver = 0;
	ie->ifindex = htons((uint16_t)oi->ifp->ifindex);
	ie->magic = htonl(IP_ENCAP_MAGIC_VALUE);
}
