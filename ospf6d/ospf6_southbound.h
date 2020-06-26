/*
 * OSPFv3 user space southbound.
 * Copyright (C) 2022-2023 Network Device Education Foundation, Inc. ("NetDEF")
 *                         Rafael Zalamena
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

#ifndef OSPF6_SOUTHBOUND_H
#define OSPF6_SOUTHBOUND_H

#include <netinet/in.h>

#include <stdbool.h>
#include <stdint.h>

#include "lib/if.h"
#include "lib/openbsd-queue.h"

#define IP6_OSPF6_SPF_PROTO 248
#define IP6_OSPF6_DR_PROTO 250

struct ospf6_vif_ctx {
	ifindex_t vif;
	uint32_t refcount;
	struct in6_addr group;
	SLIST_ENTRY(ospf6_vif_ctx) entry;
};
SLIST_HEAD(ospf6_vif_ctx_list, ospf6_vif_ctx);

/* Forward declaration */
struct ospf6;
struct ospf6_interface;

/** Initialize southbound sockets and events. */
void ospf6_sb_init(void);

/** Releases southbound resources. */
void ospf6_sb_finish(void);

/** Create OSPFv3 VRF socket. */
int ospf6_sb_serv_sock(struct ospf6 *ospf6);

/** Set OSPFv3 socket options. */
int ospf6_sb_sso(struct ospf6_interface *ospf6_interface,
		 const struct in6_addr *group, int option);

/** Send OSPFv3 message southbound semantics. */
ssize_t ospf6_sb_sendmsg(struct ospf6 *ospf6, const struct in6_addr *src,
			 const struct in6_addr *dst, ifindex_t ifindex,
			 struct iovec *message, int ospf6_sock);

/** Receive OSPFv3 message southbound semantics. */
ssize_t ospf6_sb_recvmsg(struct in6_addr *src, struct in6_addr *dst,
			 ifindex_t *ifindex, struct iovec *message,
			 int ospf6_sock);

/** Schedule socket read based on descriptor. */
void ospf6_sb_schedule(int fd);

/** Get southbound file descriptor based on destination. */
int ospf6_sb_get_fd(const struct ospf6 *ospf6,
		    const struct in6_addr *destination);


/*
 * Vendor southbound bundles multiple data plane interface into a single
 * OS interface, so in order to enable/disable multicast we must keep
 * track of virtual interface information (e.g. avoid interface getting
 * into inconsistent state).
 *
 * Example of possible problem:
 *  Interface 'A' shares the same virtual index as 'B'.
 *  Interface 'A' joins multicast group 224.0.0.1.
 *  Interface 'B' joins multicast group 224.0.0.1.
 *  Interface 'A' leaves multicast group 224.0.0.1. <== interface 'B' no longer
 *                                                      gets multicast
 */
/** Find virtual interface context. */
struct ospf6_vif_ctx *ospf6_vif_find(struct ospf6 *o, ifindex_t vif,
				     const struct in6_addr *group);

/** Increments a virtual interface context information. */
uint32_t ospf6_vif_ref(struct ospf6 *o, ifindex_t vif,
		       const struct in6_addr *group);

/** Decretment a virtual interface context information. */
uint32_t ospf6_vif_unref(struct ospf6 *o, ifindex_t vif,
			 const struct in6_addr *group);

/** Free virtual interface context information. */
void ospf6_vif_free(struct ospf6 *o, struct ospf6_vif_ctx **vifc);

/** Release all allocated resources for virtual interface information. */
void ospf6_vif_free_all(struct ospf6 *o);

extern bool ospf6_southbound_enabled;

#endif /* OSPF_SOUTHBOUND_H */
