/*
 * RIP southbound.
 *
 * Copyright (C) 2021 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael F. Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "lib/lib_errors.h"
#include "lib/network.h"
#include "lib/sockopt.h"
#include "lib/vector.h"
#include "lib/vrf.h"

#include "ripd/rip_debug.h"
#include "ripd/rip_southbound.h"
#include "ripd/ripd.h"

static int encap_sock = -1;

int ripsb_create_socket(struct vrf *vrf)
{
	const char *vrf_dev = vrf->vrf_id != VRF_DEFAULT ? vrf->name : NULL;
	int sock;
	int rv;
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK & 0xFF000000),
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
		.sin_len = sizeof(struct sockaddr_in),
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
		.sin_port = htons(RIPSB_PORT_DEFAULT),
	};

	frr_with_privs (&ripd_privs) {
		sock = vrf_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, vrf->vrf_id,
				  vrf_dev);
		if (sock < 0) {
			flog_err_sys(EC_LIB_SOCKET,
				     "Cannot create UDP socket: %s",
				     safe_strerror(errno));
			return -1;
		}
	}

	sockopt_reuseaddr(sock);
	sockopt_reuseport(sock);
#ifdef IPTOS_PREC_INTERNETCONTROL
	setsockopt_ipv4_tos(sock, IPTOS_PREC_INTERNETCONTROL);
#endif /* IPTOS_PREC_INTERNETCONTROL */
	setsockopt_so_recvbuf(sock, 40 * 1024);

	frr_with_privs (&ripd_privs) {
		rv = bind(sock, (struct sockaddr *)&sin, sizeof(sin));
		if (rv == -1) {
			zlog_err("%s: bind %d to %pI4 port %d: %s", __func__,
				 sock, &sin.sin_addr, ntohs(sin.sin_port),
				 safe_strerror(errno));
			close(sock);
			return rv;
		}
	}

	return sock;
}

int ripsb_send_packet(uint8_t *buf, int size, struct sockaddr_in *to,
		      struct connected *ifc)
{
	int rv;
	struct ipv4_output_params params = {};

	assert(ifc != NULL);

	if (IS_RIP_DEBUG_PACKET) {
		if (to)
			zlog_debug("%s: %pI4 > %pI4 (%s)", __func__,
				   &ifc->address->u.prefix4, &to->sin_addr,
				   ifc->ifp->name);
		else
			zlog_debug("%s: %pI4 > 224.0.0.9 (%s)", __func__,
				   &ifc->address->u.prefix4, ifc->ifp->name);
	}

	if (CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY)) {
		/*
		 * ZEBRA_IFA_SECONDARY is set on linux when an interface is
		 * configured
		 * with multiple addresses on the same subnet: the first address
		 * on the subnet is configured "primary", and all subsequent
		 * addresses
		 * on that subnet are treated as "secondary" addresses.
		 * In order to avoid routing-table bloat on other rip listeners,
		 * we do not send out RIP packets with ZEBRA_IFA_SECONDARY
		 * source addrs.
		 * XXX Since Linux is the only system for which the
		 * ZEBRA_IFA_SECONDARY
		 * flag is set, we would end up sending a packet for a
		 * "secondary"
		 * source address on non-linux systems.
		 */
		return 0;
	}

	/* Fill encapsulation header and send. */
	params.socket = encap_sock;
	params.mtu = ifc->ifp->mtu;
	params.protocol = IPPROTO_UDP;
	params.tos = 0xC0;
	params.source = ifc->address->u.prefix4.s_addr;
	params.udp_source = htons(RIP_PORT_DEFAULT);
	params.encapsulation = true;
	params.encap.source = params.source;
	params.encap.ifindex = ifc->ifp->ifindex;
	if (to) {
		params.ttl = 64;
		params.destination = to->sin_addr.s_addr;
		params.udp_destination = to->sin_port;
	} else {
		params.ttl = 1;
		params.destination = htonl(INADDR_RIP_GROUP);
		params.udp_destination = htons(RIP_PORT_DEFAULT);
	}

	rv = ipv4_output(&params, buf, size);
	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("%s: SEND to %pI4%d", __func__,
			   (struct in_addr *)&params.destination,
			   ntohs(params.udp_destination));
	if (rv == -1)
		zlog_warn("%s: sendmsg: %s", __func__, safe_strerror(errno));

	return rv;
}

int ripsb_read(struct thread *t)
{
	struct rip *rip = THREAD_ARG(t);
	enum ip_packet_assemble_result ipar;
	struct ipv4_header *ipv4;
	struct interface *ifp = NULL;
	struct connected *ifc;
	const uint8_t *packet_p;
	size_t packet_len;
	int sock;
	int len;
	struct prefix p;
	struct sockaddr_in from = {
		.sin_family = AF_INET,
		.sin_port = htons(RIP_PORT_DEFAULT),
	};
	uint8_t packet_buf[2048];

	/* Fetch socket then register myself. */
	sock = THREAD_FD(t);
	rip_event(rip, RIP_READ, sock);

	len = read(sock, packet_buf, sizeof(packet_buf));
	if (len == -1) {
		zlog_info("recvfrom failed (VRF %s): %s", rip->vrf_name,
			  safe_strerror(errno));
		return -1;
	}
	if (len == 0)
		return -1;

	/* Reassemble packet if needed. */
	ipar = ipv4_packet_assemble(&packet_buf[sizeof(struct encap_header)],
				    len, &packet_p, &packet_len);
	switch (ipar) {
	case IPA_OK:
		len = packet_len;
		break;
	case IPA_NOT_FRAGMENTED:
		packet_p = packet_buf;
		break;

	default:
		return -1;
	}

	/* Get source address. */
	packet_p = &packet_buf[0];
	packet_p += sizeof(struct encap_header);

	ipv4 = (struct ipv4_header *)packet_p;
	from.sin_addr.s_addr = ipv4->source;

	/* Now point to payload. */
	packet_p += ipv4_header_length(ipv4) + sizeof(struct udp_header);
	len -= sizeof(struct encap_header) + ipv4_header_length(ipv4)
	       + sizeof(struct udp_header);

	/* Check is this packet coming from myself? */
	if (if_check_address(rip, from.sin_addr)) {
		if (IS_RIP_DEBUG_PACKET)
			zlog_debug("ignore packet comes from myself (VRF %s)",
				   rip->vrf_name);
		return -1;
	}

	/* Which interface is this packet comes from. */
	ifc = if_lookup_address(&from.sin_addr, AF_INET, rip->vrf->vrf_id);
	if (ifc)
		ifp = ifc->ifp;

	/* RIP packet received */
	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("%s: RECV packet from %pI4 port %d on %s (VRF %s)",
			   __func__, &from.sin_addr, RIP_PORT_DEFAULT,
			   ifp ? ifp->name : "unknown", rip->vrf_name);

	/* If this packet come from unknown interface, ignore it. */
	if (ifp == NULL) {
		zlog_info(
			"%s: cannot find interface for packet from %pI4 port %d (VRF %s)",
			__func__, &from.sin_addr, RIP_PORT_DEFAULT,
			rip->vrf_name);
		return -1;
	}

	p.family = AF_INET;
	p.u.prefix4 = from.sin_addr;
	p.prefixlen = IPV4_MAX_BITLEN;

	ifc = connected_lookup_prefix(ifp, &p);
	if (ifc == NULL) {
		zlog_info(
			"%s: cannot find connected address for packet from %pI4 port %d on interface %s (VRF %s)",
			__func__, &from.sin_addr, RIP_PORT_DEFAULT, ifp->name,
			rip->vrf_name);
		return -1;
	}

	return rip_read_process(rip, ifp, ifc, (struct rip_packet *)packet_p,
				len, from);
}

void ripsb_init(void)
{
	int sock;
	int on = 1;

	frr_with_privs (&ripd_privs) {
		sock = vrf_socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK,
				  IP_ENCAP_ROUTING, VRF_DEFAULT, NULL);
		if (sock == -1) {
			flog_err(EC_LIB_SOCKET, "%s: socket: %s", __func__,
				 safe_strerror(errno));
			exit(1);
		}

		/* we will include IP header with packet */
		if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))
		    == -1)
			flog_err(EC_LIB_SOCKET,
				 "Can't set IP_HDRINCL option for fd %d: %s",
				 sock, safe_strerror(errno));
	}
	setsockopt_so_sendbuf(sock, 40 * 1024);
	encap_sock = sock;

	ip_fragmentation_handler_init(master);
}
