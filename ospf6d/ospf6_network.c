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

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "sockunion.h"
#include "sockopt.h"
#include "privs.h"
#include "lib_errors.h"
#include "vrf.h"

#include "libospf.h"
#include "ospf6_proto.h"
#include "ospf6_top.h"
#include "ospf6_message.h"
#include "ospf6_network.h"
#include "ospf6d.h"

#define IP6_OSPF6_SPF_PROTO 248
#define IP6_OSPF6_DR_PROTO 250

struct in6_addr allspfrouters6;
struct in6_addr alldrouters6;

static struct ospf6_sb_ctx {
	int routing_sock;
	int spf_sock;
	struct thread *spf_ev;
	int dr_sock;
	struct thread *dr_ev;
} sb_ctx;

/* setsockopt MulticastLoop to off */
static void ospf6_reset_mcastloop(int ospf6_sock)
{
	unsigned int off = 0;
	if (setsockopt(ospf6_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &off,
		       sizeof(unsigned int))
	    < 0)
		zlog_warn("Network: reset IPV6_MULTICAST_LOOP failed: %s",
			  safe_strerror(errno));
}

static void ospf6_set_pktinfo(int ospf6_sock)
{
	setsockopt_ipv6_pktinfo(ospf6_sock, 1);
}

static void ospf6_set_flowid(int sd)
{
	int optval = 1;
	socklen_t optlen = sizeof(optval);

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_FLOWINFO, &optval, optlen) == -1)
		zlog_warn("%s: failed to request IPV6_FLOWINFO", __func__);
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &optval, optlen) == -1)
		zlog_warn("%s: failed to request IPV6_FLOWINFO_SENDINFO",
			  __func__);
}

static void ospf6_set_transport_class(int ospf6_sock)
{
#ifdef IPTOS_PREC_INTERNETCONTROL
	setsockopt_ipv6_tclass(ospf6_sock, IPTOS_PREC_INTERNETCONTROL);
#endif
}

static void ospf6_set_checksum(int ospf6_sock)
{
	int offset = 12;
#ifndef DISABLE_IPV6_CHECKSUM
	if (setsockopt(ospf6_sock, IPPROTO_IPV6, IPV6_CHECKSUM, &offset,
		       sizeof(offset))
	    < 0)
		zlog_warn("Network: set IPV6_CHECKSUM failed: %s",
			  safe_strerror(errno));
#else
	zlog_warn("Network: Don't set IPV6_CHECKSUM");
#endif /* DISABLE_IPV6_CHECKSUM */
}

void ospf6_serv_close(int *ospf6_sock)
{
	if (*ospf6_sock != -1) {
		close(*ospf6_sock);
		*ospf6_sock = -1;
		return;
	}
}

/* Make ospf6d's server socket. */
int ospf6_serv_sock(struct ospf6 *ospf6)
{
	if (ospf6->fd != -1)
		return -1;

	if (ospf6->vrf_id == VRF_UNKNOWN)
		return -1;

	frr_with_privs (&ospf6d_privs) {
		ospf6->fd =
			vrf_socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK,
				   IPPROTO_OSPFIGP, ospf6->vrf_id, ospf6->name);
		if (ospf6->fd < 0) {
			zlog_warn("Network: can't create OSPF6 socket.");
			return -1;
		}
	}
	sockopt_reuseaddr(ospf6->fd);
	ospf6_reset_mcastloop(ospf6->fd);
	setsockopt_so_sendbuf(ospf6->fd, 8 * 1024 * 1024);
	setsockopt_so_recvbuf(ospf6->fd, 8 * 1024 * 1024);
	ospf6_set_pktinfo(ospf6->fd);
	ospf6_set_transport_class(ospf6->fd);
	ospf6_set_checksum(ospf6->fd);
	ospf6_set_flowid(ospf6->fd);

	return 0;
}

void ospf6_sb_init(void)
{
	/* setup global in6_addr, allspf6 and alldr6 for later use */
	inet_pton(AF_INET6, ALLSPFROUTERS6, &allspfrouters6);
	inet_pton(AF_INET6, ALLDROUTERS6, &alldrouters6);

	frr_with_privs(&ospf6d_privs) {
		/* Sockets to receive OSPFv3 packets. */
		sb_ctx.dr_sock = socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK,
					IP6_OSPF6_DR_PROTO);
		sb_ctx.spf_sock = socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK,
					 IP6_OSPF6_SPF_PROTO);
	}

	setsockopt_so_sendbuf(sb_ctx.dr_sock, (8 * 1024 * 1024));
	setsockopt_so_recvbuf(sb_ctx.dr_sock, (8 * 1024 * 1024));
	ospf6_set_pktinfo(sb_ctx.dr_sock);
	ospf6_set_flowid(sb_ctx.dr_sock);
	ospf6_set_checksum(sb_ctx.dr_sock);
	thread_add_read(master, ospf6_receive, NULL, sb_ctx.dr_sock,
			&sb_ctx.dr_ev);

	setsockopt_so_sendbuf(sb_ctx.spf_sock, (8 * 1024 * 1024));
	setsockopt_so_recvbuf(sb_ctx.spf_sock, (8 * 1024 * 1024));
	ospf6_set_pktinfo(sb_ctx.spf_sock);
	ospf6_set_flowid(sb_ctx.spf_sock);
	ospf6_set_checksum(sb_ctx.spf_sock);
	thread_add_read(master, ospf6_receive, NULL, sb_ctx.spf_sock,
			&sb_ctx.spf_ev);
}

void ospf6_sb_finish(void)
{
	THREAD_OFF(sb_ctx.dr_ev);
	close(sb_ctx.dr_sock);
	sb_ctx.dr_sock = -1;

	THREAD_OFF(sb_ctx.spf_ev);
	close(sb_ctx.spf_sock);
	sb_ctx.spf_sock = -1;
}

void ospf6_sb_schedule(int fd)
{
	if (fd == sb_ctx.dr_sock)
		thread_add_read(master, ospf6_receive, NULL, sb_ctx.dr_sock,
				&sb_ctx.dr_ev);
	else if (fd == sb_ctx.spf_sock)
		thread_add_read(master, ospf6_receive, NULL, sb_ctx.spf_sock,
				&sb_ctx.spf_ev);
}

/* ospf6 set socket option */
int ospf6_sso(struct ospf6 *o, ifindex_t ifindex, struct in6_addr *group,
	      int option)
{
	struct ipv6_mreq mreq6;
	uint32_t refcount;
	int ret;

	if (o->fd == -1)
		return -1;

	mreq6.ipv6mr_interface = ifindex;
	memcpy(&mreq6.ipv6mr_multiaddr, group, sizeof(struct in6_addr));

	if (option == IPV6_JOIN_GROUP)
		refcount = ospf6_vif_ref(o, ifindex, group);
	else if (option == IPV6_LEAVE_GROUP)
		refcount = ospf6_vif_unref(o, ifindex, group);
	else
		refcount = 0;

	if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_SB, SEND))
		zlog_debug("%s: socket %d if %d (refcount %u) %s %pI6",
			   __func__, o->fd, ifindex, refcount,
			   option == IPV6_JOIN_GROUP	? "JOIN"
			   : option == IPV6_LEAVE_GROUP ? "LEAVE"
							: "unknown",
			   &mreq6.ipv6mr_multiaddr);

	/* There are still other data plane interfaces using this. */
	if (refcount >= 1)
		return 0;

	ret = setsockopt(o->fd, IPPROTO_IPV6, option, &mreq6, sizeof(mreq6));
	if (ret < 0) {
		flog_err_sys(
			EC_LIB_SOCKET,
			"Network: setsockopt (%d) on ifindex %d failed: %s",
			option, ifindex, safe_strerror(errno));
		return ret;
	}

	return 0;
}

static int iov_count(struct iovec *iov)
{
	int i;
	for (i = 0; iov[i].iov_base; i++)
		;
	return i;
}

static int iov_totallen(struct iovec *iov)
{
	int i;
	int totallen = 0;
	for (i = 0; iov[i].iov_base; i++)
		totallen += iov[i].iov_len;
	return totallen;
}

ssize_t ospf6_sendmsg(struct ospf6 *ospf6, struct in6_addr *src,
		      struct in6_addr *dst, struct interface *ifp,
		      struct iovec *message, int ospf6_sock)
{
	struct in6_pktinfo *ipi6;
	struct cmsghdr *cmsg;
	int sock;
	ssize_t rv;
	size_t cmsglen = 0;
	struct msghdr msg = {};
	struct iovec iovec[3] = {};
	uint8_t cmsgbuf[128] = {};
	struct sockaddr_in6 dst_sin6 = {
		.sin6_family = AF_INET6,
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		.sin6_len = sizeof(dst_sin6),
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
	};

	assert(dst);
	assert(ifp);

	/* Use the proper ouput socket. */
	if (dst == &alldrouters6)
		sock = sb_ctx.dr_sock;
	else if (dst == &allspfrouters6)
		sock = sb_ctx.spf_sock;
	else
		sock = ospf6->fd;

	/* Prepare message data pointers. */
	iovec[0].iov_base = message[0].iov_base;
	iovec[0].iov_len = message[0].iov_len;

	/* Prepare message header. */
	msg.msg_iov = iovec;
	msg.msg_iovlen = 1;
	msg.msg_name = &dst_sin6;
	msg.msg_namelen = sizeof(dst_sin6);
	msg.msg_control = &cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	/* Destination. */
	memcpy(&dst_sin6.sin6_addr, dst, sizeof(dst_sin6.sin6_addr));
	dst_sin6.sin6_flowinfo = htonl(ifp->ifindex);
	if (IN6_IS_ADDR_LINKLOCAL(dst))
		dst_sin6.sin6_scope_id = ifp->vif_index;

	/*
	 * First control data:
	 * IPv6 destination address / interface.
	 */
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*ipi6));
	cmsglen += CMSG_LEN(sizeof(*ipi6));

	ipi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	ipi6->ipi6_ifindex = ifp->vif_index;
	if (src)
		memcpy(&ipi6->ipi6_addr, src, sizeof(ipi6->ipi6_addr));

	msg.msg_controllen = cmsglen;
	rv = sendmsg(sock, &msg, 0);
	if (rv != iov_totallen(iovec))
		zlog_warn(
			"%s: sendmsg failed (ifindex: %d, vif_index: %d): %s (%d)",
			__func__, ifp->ifindex, ifp->vif_index,
			safe_strerror(errno), errno);

	if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_SB, SEND))
		zlog_debug("%s: sent=%zd src=%pI6 dst=%pI6 flow-info=%d",
			   __func__, rv, &ipi6->ipi6_addr, dst, ifp->vif_index);

	return message[0].iov_len;
}

ssize_t ospf6_recvmsg(struct in6_addr *src, struct in6_addr *dst,
		      ifindex_t *ifindex, struct iovec *message, int ospf6_sock)
{
	struct in6_pktinfo *ipi6;
	struct cmsghdr *cmsg;
	int flowinfo = -1;
	ssize_t rv;
	struct sockaddr_in6 src_sin6 = {};
	uint8_t cmsgbuf[128] = {};
	struct msghdr msg = {};

	/* Message header for receiving. */
	msg.msg_iov = message;
	msg.msg_iovlen = iov_count(message);
	msg.msg_name = &src_sin6;
	msg.msg_namelen = sizeof(src_sin6);
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	rv = recvmsg(ospf6_sock, &msg, 0);
	if (rv == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return -1;

		zlog_warn("recvmsg failed: %s", safe_strerror(errno));
		return -1;
	} else if (rv == iov_totallen(message))
		zlog_warn("recvmsg read full buffer size: %zd", rv);

	/* Parse cmsg and extract required info. */
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6)
			continue;

		switch (cmsg->cmsg_type) {
		case IPV6_PKTINFO:
			ipi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			*ifindex = (ifindex_t)ipi6->ipi6_ifindex;
			memcpy(dst, &ipi6->ipi6_addr, sizeof(*dst));
			break;
		case IPV6_FLOWINFO:
			memcpy(&flowinfo, CMSG_DATA(cmsg), sizeof(flowinfo));
			flowinfo = ntohl(flowinfo) & 0x0FFFFF;
			break;
		}
	}

	/* source address */
	memcpy(src, &src_sin6.sin6_addr, sizeof(*src));

	if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_SB, RECV))
		zlog_debug("%s: src=%pI6 dst=%pI6 ifindex=%d flowinfo=0x%08x",
			   __func__, src, dst, *ifindex, flowinfo);

	*ifindex = flowinfo;

	return rv;
}
