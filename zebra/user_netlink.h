/*
 * Userland netlink code.
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef USERLAND_NETLINK_H
#define USERLAND_NETLINK_H

#include <sys/types.h>

#include <stdint.h>

#include "lib/frr_pthread.h"
#include "zebra/zebra_nhg.h"

/** Default netlink proxy port. */
#define NETLINK_PROXY_PORT 2630

struct nlbuf {
	/* Netlink metadata. */
	uint32_t nb_seq;

	/* Request data buffer. */
	size_t nb_datasiz;
	size_t nb_dataoff;
	uint8_t nb_data[];
};

extern void dpd_parse_address(const char *address);

extern pthread_mutex_t user_netlink_mtx;
#define USER_NETLINK_LOCK_AUTOUNLOCK() \
	frr_mutex_lock_autounlock(&user_netlink_mtx)

void user_netlink_lock(void);
void user_netlink_unlock(void);

extern int netlink_talk_info(int (*filter)(struct nlmsghdr *, ns_id_t,
					   int startup),
			     struct nlmsghdr *nlmsg,
			     struct zebra_dplane_info *dp_info, int startup);
extern int rib_append_nexthop(afi_t afi, struct prefix *p,
			      struct prefix_ipv6 *src_p, struct route_entry *re,
			      struct nhg_hash_entry *rt_nhe,
			      struct route_node *rn);
extern int rib_delete_nexthop(afi_t afi, struct route_node *rn,
			      struct route_entry *re, struct nexthop *nh);

#endif /* USERLAND_NETLINK_H */
