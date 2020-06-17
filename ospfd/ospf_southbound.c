/*
 * OSPF user space southbound.
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

#include <zebra.h>

#include "lib/lib_errors.h"
#include "lib/privs.h"
#include "lib/network.h"
#include "lib/sockopt.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_packet.h"

/** Global state that keeps user southbound state. */
bool ospf_southbound_enabled;

static int ospfsb_create_socket(struct ospf *ospf, int protocol)
{
	int sock;
	int result;
	const int header_include = 1;
	const int bufsize = (8 * 1024 * 1024);

	frr_with_privs (&ospfd_privs) {
		sock = vrf_socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, protocol,
				  ospf->vrf_id, ospf->name);
		if (sock == -1) {
			flog_err(EC_LIB_SOCKET,
				 "ospf_read_sock_init: socket: %s",
				 safe_strerror(errno));
			exit(1);
		}

		/* we will include IP header with packet */
		result = setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
				    &header_include, sizeof(header_include));
		if (result == -1) {
			flog_err(EC_LIB_SOCKET,
				 "Can't set IP_HDRINCL option for fd %d: %s",
				 sock, safe_strerror(errno));
			close(sock);
			break;
		}

		result = setsockopt_ipv4_tos(sock, IPTOS_PREC_INTERNETCONTROL);
		if (result == -1) {
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

/* Exported functions */
int ospf_southbound_sock_init(struct ospf *ospf)
{
	ospf->fd = ospfsb_create_socket(ospf, OSPF_IP_ENCAP_OTHER);
	ospf->southbound.ie_dr_sock =
		ospfsb_create_socket(ospf, OSPF_IP_ENCAP_DR);
	ospf->southbound.ie_spf_sock =
		ospfsb_create_socket(ospf, OSPF_IP_ENCAP_SPF);

	return 0;
}

void ospf_southbound_new(struct ospf *ospf)
{
	thread_add_read(master, ospf_read, ospf, ospf->southbound.ie_dr_sock,
			&ospf->southbound.ie_dr_ev);
	thread_add_read(master, ospf_read, ospf, ospf->southbound.ie_spf_sock,
			&ospf->southbound.ie_spf_ev);
}

void ospf_southbound_free(struct ospf *ospf)
{
	thread_cancel(&ospf->southbound.ie_spf_ev);
	thread_cancel(&ospf->southbound.ie_dr_ev);

	close(ospf->southbound.ie_spf_sock);
	ospf->southbound.ie_spf_sock = -1;
	close(ospf->southbound.ie_dr_sock);
	ospf->southbound.ie_dr_sock = -1;
}

void ospf_southbound_read_prepare(struct ospf *ospf, int fd)
{
	if (fd == ospf->southbound.ie_spf_sock)
		thread_add_read(master, ospf_read, ospf, fd,
				&ospf->southbound.ie_spf_ev);
	else if (fd == ospf->southbound.ie_dr_sock)
		thread_add_read(master, ospf_read, ospf, fd,
				&ospf->southbound.ie_dr_ev);
	else
		thread_add_read(master, ospf_read, ospf, fd, &ospf->t_read);
}

void ospf_southbound_write(const struct ospf *ospf,
			   const struct ospf_interface *interface,
			   const struct ospf_packet *packet)
{
	struct ipv4_output_params params = {
		.encap.ifindex = interface->ifp->ifindex,
		.encap.source = interface->address->u.prefix4.s_addr,
		.source = interface->address->u.prefix4.s_addr,
		.destination = packet->dst.s_addr,
		.mtu = (uint16_t)interface->ifp->mtu,
		.protocol = IPPROTO_OSPFIGP,
		.tos = IPTOS_PREC_INTERNETCONTROL,
		.ttl = interface->type == OSPF_IFTYPE_VIRTUALLINK
			       ? OSPF_VL_IP_TTL
			       : OSPF_IP_TTL,
		.socket = ospf->fd,
	};

	ipv4_output(&params, stream_pnt(packet->s), packet->length);
}

struct stream *ospf_southbound_read(struct ospf *ospf, int sock,
				    struct interface **interface,
				    struct stream *stream)
{
	const struct ip *ip;
	const uint8_t *packet;
	ssize_t rv;
	size_t packetlen;
	enum ip_packet_assemble_result ipar_result;
	enum ip_encap_packet_assemble_result iepa_result;
	struct ipv4_encap_result result;

	rv = stream_read_try(stream, sock, STREAM_WRITEABLE(stream));
	/* Interruption: try again later. */
	if (rv == -2)
		return NULL;

	/*
	 * Socket failure: don't bother logging `stream_read_try` already
	 * does that.
	 */
	if (rv == -1) {
		zlog_info("%s: read: %s", __func__, strerror(errno));
		return NULL;
	}

	iepa_result = ipv4_encap_parse(stream_pnt(stream),
				       STREAM_READABLE(stream), &result);
	if (iepa_result != IEPA_OK)
		return NULL;

	/* Move pointer to encapsulation payload. */
	stream_forward_getp(stream, result.encap_length);

	/*
	 * All good, decode the information to pass down.
	 *
	 * Direction            |        Source | Destination   | Proto | TTL
	 * ---------------------+---------------+---------------+-------+----
	 * DP -> MP (224.0.0.5) | 127.130.1.240 | DP IP         |   248 |  64
	 * DP -> MP (224.0.0.6) | 127.130.1.240 | DP IP         |   250 |  64
	 * DP -> MP (other)     | 127.130.1.240 | DP IP         |   249 |  64
	 */
	ipar_result = ipv4_packet_assemble(stream_pnt(stream),
					   STREAM_READABLE(stream), &packet,
					   &packetlen);
	switch (ipar_result) {
	case IPA_NOT_FRAGMENTED:
		packet = stream_pnt(stream);
		packetlen = STREAM_READABLE(stream);
		if (IS_DEBUG_OSPF_PACKET(0, RECV)) {
			ip = (const struct ip *)packet;
			zlog_debug(
				"%s: ip encap [ifindex=%d proto=%d] ip [id=%d src=%pI4 dst=%pI4 proto=%d]",
				__func__, result.ifindex, result.protocol,
				ip->ip_id, &ip->ip_src, &ip->ip_dst, ip->ip_p);
		}
		break;
	case IPA_OK:
		if (IS_DEBUG_OSPF_PACKET(0, RECV)) {
			ip = (const struct ip *)packet;
			zlog_debug(
				"%s: ip encap [ifindex=%d proto=%d] ip [id=%d src=%pI4 dst=%pI4 proto=%d] REASSEMBLED",
				__func__, result.ifindex, result.protocol,
				ip->ip_id, &ip->ip_src, &ip->ip_dst, ip->ip_p);
		}
		break;

	case IPA_FRAGMENT_OVERLAP:
	case IPA_IGNORED:
	case IPA_INVALID_CHECKSUM:
	case IPA_INVALID_HEADER_LENGTH:
	case IPA_INVALID_LENGTH:
	case IPA_INVALID_VERSION:
	case IPA_NO_MEMORY:
	case IPA_OK_INCOMPLETE:
	case IPA_PACKET_TOO_BIG:
	case IPA_REPEATED_PACKET:
	case IPA_TOO_MANY_FRAGMENTS:
		/* Fall through */
	default:
		/* Debugging only. */
		if (IS_DEBUG_OSPF_PACKET(0, RECV)) {
			ip = (const struct ip *)stream_pnt(stream);
			zlog_debug(
				"%s: ip encap [ifindex=%d proto=%d] ip [id=%d src=%pI4 dst=%pI4 proto=%d frag=0x%04x] INVALID: (%d) %s",
				__func__, result.ifindex, result.protocol,
				ip->ip_id, &ip->ip_src, &ip->ip_dst, ip->ip_p,
				ip->ip_off, ipar_result,
				ip_packet_assemble_result_str(ipar_result));
		}
		return NULL;
	}

	*interface = if_lookup_by_index(result.ifindex, ospf->vrf_id);

	/* Rearrange the packet in stream. */
	memmove(STREAM_DATA(stream), packet, packetlen);
	stream->endp = packetlen;
	stream->getp = 0;

	return stream;
}


void ospf_southbound_init(void)
{
	/* Wire the IP assembly API with main thread. */
	ip_fragmentation_handler_init(master);

	ospf_southbound_enabled = true;

	zlog_info("OSPF user southbound enabled");
}
