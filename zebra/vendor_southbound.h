/*
 * Vendor southbound implementation.
 * Copyright (C) 2018-2023 Network Device Education Foundation, Inc. ("NetDEF")
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

#ifndef VENDOR_SOUTHBOUND_H
#define VENDOR_SOUTHBOUND_H

#include <sys/types.h>

#include <stdint.h>

#include "lib/frr_pthread.h"
#include "zebra/zebra_nhg.h"

/* Forward declarations. */
struct zebra_dplane_info;

/** Netlink filter function callback type. */
typedef int (*filter_cb)(struct nlmsghdr *, ns_id_t, int);

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

extern void vendor_southbound_parse_address(const char *address);

extern pthread_mutex_t vendor_southbound_mtx;
#define VENDOR_SOUTHBOUND_LOCK_AUTOUNLOCK()                                    \
	frr_mutex_lock_autounlock(&vendor_southbound_mtx)

extern void vendor_southbound_lock(void);
extern void vendor_southbound_unlock(void);

extern int rib_append_nexthop(afi_t afi, struct prefix *p,
			      struct prefix_ipv6 *src_p, struct route_entry *re,
			      struct nhg_hash_entry *rt_nhe,
			      struct route_node *rn);
extern int rib_delete_nexthop(afi_t afi, struct route_node *rn,
			      struct route_entry *re, struct nexthop *nh);

extern void vendor_southbound_init(struct zebra_ns *zns);
extern void vendor_southbound_terminate(struct zebra_ns *zns, bool complete);
extern void vendor_southbound_read(struct thread *thread);
extern void vendor_southbound_write(struct thread *thread);


extern ssize_t vendor_southbound_recv(const struct nlsock *ns, filter_cb filter,
				      bool *found, bool startup, int *ret,
				      int *attempts);

extern int vendor_southbound_parse_info(filter_cb filter,
					const struct nlsock *ns, bool startup);
extern int vendor_southbound_talk_info(int (*filter)(struct nlmsghdr *, ns_id_t,
						     int startup),
				       struct nlmsghdr *nlmsg,
				       struct zebra_dplane_info *dp_info,
				       bool startup);
extern ssize_t vendor_southbound_send_msg(struct nlsock *ns, const void *buf,
					  size_t buflen);
extern int vendor_southbound_request(struct nlsock *ns, void *msg);

extern int vendor_southbound_information_fetch(struct nlmsghdr *h,
					       ns_id_t ns_id, int startup);

extern bool vendor_southbound_enabled;

#endif /* VENDOR_SOUTHBOUND_H */
