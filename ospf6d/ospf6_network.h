/*
 * Copyright (C) 2003 Yasuhiro Ohara
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

#ifndef OSPF6_NETWORK_H
#define OSPF6_NETWORK_H

extern struct in6_addr allspfrouters6;
extern struct in6_addr alldrouters6;

/* forward declaration. */
struct ospf6;

/* global variable(s). */
extern bool use_flowinfo;

void ospf6_sb_init(void);
void ospf6_sb_finish(void);
void ospf6_sb_schedule(int fd);

extern int ospf6_serv_sock(struct ospf6 *ospf6);
extern void ospf6_serv_close(int *ospf6_sock);
extern int ospf6_sso(struct ospf6 *o, ifindex_t ifindex, struct in6_addr *group,
		     int option);

extern ssize_t ospf6_sendmsg(struct ospf6 *, struct in6_addr *,
			     struct in6_addr *, struct interface *,
			     struct iovec *, int);
extern ssize_t ospf6_recvmsg(struct in6_addr *, struct in6_addr *, ifindex_t *,
			     struct iovec *, int);

#endif /* OSPF6_NETWORK_H */
