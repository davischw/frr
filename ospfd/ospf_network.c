/*
 * OSPF network related functions
 *   Copyright (C) 1999 Toshiaki Takada
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

#include "thread.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "sockunion.h"
#include "log.h"
#include "sockopt.h"
#include "privs.h"
#include "lib_errors.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_dump.h"

/* Join to the OSPF ALL SPF ROUTERS multicast group. */
int ospf_if_add_allspfrouters(struct ospf *top, struct prefix *p,
			      ifindex_t ifindex)
{
	int ret;

	ret = setsockopt_ipv4_multicast(top->fd, IP_ADD_MEMBERSHIP,
					p->u.prefix4, htonl(OSPF_ALLSPFROUTERS),
					ifindex);
	if (ret < 0)
		flog_err(
			EC_LIB_SOCKET,
			"can't setsockopt IP_ADD_MEMBERSHIP (fd %d, addr %pI4, ifindex %u, AllSPFRouters): %s; perhaps a kernel limit on # of multicast group memberships has been exceeded?",
			top->fd, &p->u.prefix4, ifindex,
			safe_strerror(errno));
	else {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"interface %pI4 [%u] join AllSPFRouters Multicast group.",
				&p->u.prefix4, ifindex);
	}

	return ret;
}

int ospf_if_drop_allspfrouters(struct ospf *top, struct prefix *p,
			       ifindex_t ifindex)
{
	int ret;

	ret = setsockopt_ipv4_multicast(top->fd, IP_DROP_MEMBERSHIP,
					p->u.prefix4, htonl(OSPF_ALLSPFROUTERS),
					ifindex);
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IP_DROP_MEMBERSHIP (fd %d, addr %pI4, ifindex %u, AllSPFRouters): %s",
			 top->fd, &p->u.prefix4, ifindex,
			 safe_strerror(errno));
	else {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"interface %pI4 [%u] leave AllSPFRouters Multicast group.",
				&p->u.prefix4, ifindex);
	}

	return ret;
}

/* Join to the OSPF ALL Designated ROUTERS multicast group. */
int ospf_if_add_alldrouters(struct ospf *top, struct prefix *p,
			    ifindex_t ifindex)
{
	int ret;

	ret = setsockopt_ipv4_multicast(top->fd, IP_ADD_MEMBERSHIP,
					p->u.prefix4, htonl(OSPF_ALLDROUTERS),
					ifindex);
	if (ret < 0)
		flog_err(
			EC_LIB_SOCKET,
			"can't setsockopt IP_ADD_MEMBERSHIP (fd %d, addr %pI4, ifindex %u, AllDRouters): %s; perhaps a kernel limit on # of multicast group memberships has been exceeded?",
			top->fd, &p->u.prefix4, ifindex,
			safe_strerror(errno));
	else
		zlog_debug(
			"interface %pI4 [%u] join AllDRouters Multicast group.",
			&p->u.prefix4, ifindex);

	return ret;
}

int ospf_if_drop_alldrouters(struct ospf *top, struct prefix *p,
			     ifindex_t ifindex)
{
	int ret;

	ret = setsockopt_ipv4_multicast(top->fd, IP_DROP_MEMBERSHIP,
					p->u.prefix4, htonl(OSPF_ALLDROUTERS),
					ifindex);
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IP_DROP_MEMBERSHIP (fd %d, addr %pI4, ifindex %u, AllDRouters): %s",
			 top->fd, &p->u.prefix4, ifindex,
			 safe_strerror(errno));
	else
		zlog_debug(
			"interface %pI4 [%u] leave AllDRouters Multicast group.",
			&p->u.prefix4, ifindex);

	return ret;
}

int ospf_if_ipmulticast(struct ospf *top, struct prefix *p, ifindex_t ifindex)
{
	uint8_t val;
	int ret, len;

	/* Prevent receiving self-origined multicast packets. */
	ret = setsockopt_ipv4_multicast_loop(top->fd, 0);
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IP_MULTICAST_LOOP(0) for fd %d: %s",
			 top->fd, safe_strerror(errno));

	/* Explicitly set multicast ttl to 1 -- endo. */
	val = 1;
	len = sizeof(val);
	ret = setsockopt(top->fd, IPPROTO_IP, IP_MULTICAST_TTL, (void *)&val,
			 len);
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IP_MULTICAST_TTL(1) for fd %d: %s",
			 top->fd, safe_strerror(errno));
#ifndef GNU_LINUX
	/* For GNU LINUX ospf_write uses IP_PKTINFO, in_pktinfo to send
	 * packet out of ifindex. Below would be used Non Linux system.
	 */
	ret = setsockopt_ipv4_multicast_if(top->fd, p->u.prefix4, ifindex);
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IP_MULTICAST_IF(fd %d, addr %pI4, ifindex %u): %s",
			 top->fd, &p->u.prefix4, ifindex,
			 safe_strerror(errno));
#endif

	return ret;
}

static int
ospf_create_socket(struct ospf *ospf, int protocol)
{
	int sock;
	int ret, hincl = 1;
	int bufsize = (8 * 1024 * 1024);

	frr_with_privs(&ospfd_privs) {
		sock = vrf_socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, protocol,
				  ospf->vrf_id, ospf->name);
		if (sock == -1) {
			flog_err(EC_LIB_SOCKET,
				 "ospf_read_sock_init: socket: %s",
				 safe_strerror(errno));
			exit(1);
		}

		/* we will include IP header with packet */
		ret = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &hincl,
				 sizeof(hincl));
		if (ret == -1) {
			flog_err(EC_LIB_SOCKET,
				 "Can't set IP_HDRINCL option for fd %d: %s",
				 sock, safe_strerror(errno));
			close(sock);
			break;
		}

		ret = setsockopt_ipv4_tos(sock, IPTOS_PREC_INTERNETCONTROL);
		if (ret == -1) {
			flog_err(EC_LIB_SOCKET,
				 "can't set sockopt IP_TOS to socket %d: %s",
				 sock, safe_strerror(errno));
			close(sock);
			break;
		}
	}

	setsockopt_so_sendbuf(sock, bufsize);
	setsockopt_so_recvbuf(sock, bufsize);

	return sock;
}

int ospf_sock_init(struct ospf *ospf)
{
	/* silently ignore. already done */
	if (ospf->fd > 0)
		return -1;

	if (ospf->vrf_id == VRF_UNKNOWN) {
		/* silently return since VRF is not ready */
		return -1;
	}

	ospf->fd = ospf_create_socket(ospf, IPPROTO_OSPFIGP);
	ospf->ie_dr_sock = ospf_create_socket(ospf, OSPF_IP_ENCAP_DR);
	ospf->ie_spf_sock = ospf_create_socket(ospf, OSPF_IP_ENCAP_SPF);
	ospf->ie_other_sock = ospf_create_socket(ospf, OSPF_IP_ENCAP_OTHER);

	return 0;
}
