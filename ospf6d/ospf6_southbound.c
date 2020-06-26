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

#include <zebra.h>

#include "lib/lib_errors.h"
#include "lib/privs.h"
#include "lib/network.h"
#include "lib/sockopt.h"
#include "lib/openbsd-queue.h"
#include "lib/vrf.h"

#include "ospf6d/ospf6d.h"
#include "ospf6d/ospf6_message.h"
#include "ospf6d/ospf6_network.h"
#include "ospf6d/ospf6_southbound.h"
#include "ospf6d/ospf6_top.h"

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_VIF_CTX, "OSPF6 vif context");

/** Southbound context data. */
struct ospf6_sb_ctx {
	/** Routing socket to send packets. */
	int routing_sock;
	/** Socket for receiving SPF messages. */
	int spf_sock;
	/** Event handler for receiving SPF messages. */
	struct thread *spf_ev;
	/** Socket for receiving DR messages. */
	int dr_sock;
	/** Event handler for receiving DR messages. */
	struct thread *dr_ev;
};

/** Global state that keeps user southbound state. */
bool ospf6_southbound_enabled;

/** Global southbound state. */
struct ospf6_sb_ctx sb_ctx;

/** Call setsockopt to enable flow id required by southbound. */
static void ospf6_set_flow_id(int sd)
{
	int optval = 1;
	socklen_t optlen = sizeof(optval);

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_FLOWINFO, &optval, optlen) == -1)
		zlog_warn("%s: failed to request IPV6_FLOWINFO", __func__);
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &optval, optlen) ==
	    -1)
		zlog_warn("%s: failed to request IPV6_FLOWINFO_SENDINFO",
			  __func__);
}

static void ospf6_set_checksum(int ospf6_sock)
{
	int offset = 12;
#ifndef DISABLE_IPV6_CHECKSUM
	if (setsockopt(ospf6_sock, IPPROTO_IPV6, IPV6_CHECKSUM, &offset,
		       sizeof(offset)) < 0)
		zlog_warn("Network: set IPV6_CHECKSUM failed: %s",
			  safe_strerror(errno));
#else
	zlog_warn("Network: Don't set IPV6_CHECKSUM");
#endif /* DISABLE_IPV6_CHECKSUM */
}

void ospf6_sb_init(void)
{
	frr_with_privs (&ospf6d_privs) {
		/* Sockets to receive OSPFv3 packets. */
		sb_ctx.dr_sock = socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK,
					IP6_OSPF6_DR_PROTO);
		sb_ctx.spf_sock = socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK,
					 IP6_OSPF6_SPF_PROTO);
	}

	setsockopt_so_sendbuf(sb_ctx.dr_sock, (8 * 1024 * 1024));
	setsockopt_so_recvbuf(sb_ctx.dr_sock, (8 * 1024 * 1024));
	setsockopt_ipv6_pktinfo(sb_ctx.dr_sock, 1);
	ospf6_set_flow_id(sb_ctx.dr_sock);
	ospf6_set_checksum(sb_ctx.dr_sock);
	thread_add_read(master, ospf6_receive, NULL, sb_ctx.dr_sock,
			&sb_ctx.dr_ev);

	setsockopt_so_sendbuf(sb_ctx.spf_sock, (8 * 1024 * 1024));
	setsockopt_so_recvbuf(sb_ctx.spf_sock, (8 * 1024 * 1024));
	setsockopt_ipv6_pktinfo(sb_ctx.spf_sock, 1);
	ospf6_set_flow_id(sb_ctx.spf_sock);
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

int ospf6_sb_serv_sock(struct ospf6 *ospf6)
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
	setsockopt_ipv6_pktinfo(ospf6->fd, 1);
#ifdef IPTOS_PREC_INTERNETCONTROL
	setsockopt_ipv6_tclass(ospf6->fd, IPTOS_PREC_INTERNETCONTROL);
#endif /* IPTOS_PREC_INTERNETCONTROL */
	ospf6_set_checksum(ospf6->fd);
	ospf6_set_flow_id(ospf6->fd);

	return 0;
}

int ospf6_sb_sso(struct ospf6_interface *ospf6_interface,
		 const struct in6_addr *group, int option)
{
	const struct interface *interface = ospf6_interface->interface;
	struct ospf6 *ospf6 = ospf6_interface->area->ospf6;
	int ospf6_fd = ospf6->fd;
	int bufsize = (8 * 1024 * 1024);
	uint32_t refcount;
	int ret;
	unsigned int ifindex;
	struct ipv6_mreq mreq6;

	if (ospf6_fd == -1)
		return -1;

	ifindex = (interface->vif_index) ? (unsigned int)interface->vif_index
					 : (unsigned int)interface->ifindex;

	mreq6.ipv6mr_interface = ifindex;
	memcpy(&mreq6.ipv6mr_multiaddr, group, sizeof(struct in6_addr));

	if (option == IPV6_JOIN_GROUP)
		refcount = ospf6_vif_ref(ospf6, (int)ifindex, group);
	else if (option == IPV6_LEAVE_GROUP)
		refcount = ospf6_vif_unref(ospf6, (int)ifindex, group);
	else
		refcount = 0;

	if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_SB, SEND))
		zlog_debug("%s: socket %d if %d (refcount %u) %s %pI6",
			   __func__, ospf6_fd, ifindex, refcount,
			   option == IPV6_JOIN_GROUP	? "JOIN"
			   : option == IPV6_LEAVE_GROUP ? "LEAVE"
							: "unknown",
			   &mreq6.ipv6mr_multiaddr);

	/* There are still other data plane interfaces using this. */
	if (refcount >= 1)
		return 0;

	ret = setsockopt(ospf6_fd, IPPROTO_IPV6, option, &mreq6, sizeof(mreq6));
	if (ret < 0) {
		flog_err_sys(
			EC_LIB_SOCKET,
			"Network: setsockopt (%d) on ifindex %d failed: %s",
			option, ifindex, safe_strerror(errno));
		return ret;
	}

	setsockopt_so_sendbuf(ospf6_fd, bufsize);
	setsockopt_so_recvbuf(ospf6_fd, bufsize);

	return 0;
}

ssize_t ospf6_sb_sendmsg(struct ospf6 *ospf6, const struct in6_addr *src,
			 const struct in6_addr *dst, ifindex_t ifindex,
			 struct iovec *message, int ospf6_sock)
{
	struct interface *interface;
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

	interface = if_lookup_by_index(ifindex, ospf6->vrf_id);

	/* Use the proper ouput socket. */
	sock = ospf6_sb_get_fd(ospf6, dst);

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
	dst_sin6.sin6_flowinfo = htonl(interface->ifindex);
	if (IN6_IS_ADDR_LINKLOCAL(dst)) {
		if (interface->vif_index)
			dst_sin6.sin6_scope_id =
				(unsigned int)interface->vif_index;
		else
			dst_sin6.sin6_scope_id =
				(unsigned int)interface->ifindex;
	}

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
	if (interface->vif_index)
		ipi6->ipi6_ifindex = (unsigned int)interface->vif_index;
	else
		ipi6->ipi6_ifindex = (unsigned int)interface->ifindex;
	if (src)
		memcpy(&ipi6->ipi6_addr, src, sizeof(ipi6->ipi6_addr));

	msg.msg_controllen = cmsglen;
	rv = sendmsg(sock, &msg, 0);
	if (rv != iov_totallen(iovec))
		zlog_warn(
			"%s: sendmsg failed (ifindex: %d, vif_index: %d): %s (%d)",
			__func__, interface->ifindex, interface->vif_index,
			safe_strerror(errno), errno);

	if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_SB, SEND))
		zlog_debug("%s: sent=%zd src=%pI6 dst=%pI6 flow-info=%d",
			   __func__, rv, &ipi6->ipi6_addr, dst,
			   interface->ifindex);

	return message[0].iov_len;
}

ssize_t ospf6_sb_recvmsg(struct in6_addr *src, struct in6_addr *dst,
			 ifindex_t *ifindex, struct iovec *message,
			 int ospf6_sock)
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


void ospf6_sb_schedule(int fd)
{
	if (fd == sb_ctx.dr_sock)
		thread_add_read(master, ospf6_receive, NULL, sb_ctx.dr_sock,
				&sb_ctx.dr_ev);
	else if (fd == sb_ctx.spf_sock)
		thread_add_read(master, ospf6_receive, NULL, sb_ctx.spf_sock,
				&sb_ctx.spf_ev);
}

int ospf6_sb_get_fd(const struct ospf6 *ospf6,
		    const struct in6_addr *destination)
{
	if (destination == &alldrouters6)
		return sb_ctx.dr_sock;
	else if (destination == &allspfrouters6)
		return sb_ctx.spf_sock;
	else
		return ospf6->fd;
}

struct ospf6_vif_ctx *ospf6_vif_find(struct ospf6 *o, ifindex_t vif,
				     const struct in6_addr *group)
{
	struct ospf6_vif_ctx *vifc;

	SLIST_FOREACH (vifc, &o->vif_ctx_list, entry) {
		if (vifc->vif != vif)
			continue;
		if (memcmp(&vifc->group, group, sizeof(vifc->group)))
			continue;
		return vifc;
	}
	return NULL;
}

uint32_t ospf6_vif_ref(struct ospf6 *o, ifindex_t vif,
		       const struct in6_addr *group)
{
	struct ospf6_vif_ctx *vifc;

	vifc = ospf6_vif_find(o, vif, group);
	if (vifc != NULL) {
		vifc->refcount++;
		return vifc->refcount;
	}

	vifc = XCALLOC(MTYPE_OSPF6_VIF_CTX, sizeof(*vifc));
	vifc->vif = vif;
	vifc->refcount = 1;
	memcpy(&vifc->group, group, sizeof(vifc->group));
	SLIST_INSERT_HEAD(&o->vif_ctx_list, vifc, entry);
	return vifc->refcount;
}

void ospf6_vif_free(struct ospf6 *o, struct ospf6_vif_ctx **vifc)
{
	if (*vifc == NULL)
		return;

	SLIST_REMOVE(&o->vif_ctx_list, (*vifc), ospf6_vif_ctx, entry);
	XFREE(MTYPE_OSPF6_VIF_CTX, (*vifc));
}

void ospf6_vif_free_all(struct ospf6 *o)
{
	struct ospf6_vif_ctx *vifc;

	while (!SLIST_EMPTY(&o->vif_ctx_list)) {
		vifc = SLIST_FIRST(&o->vif_ctx_list);
		ospf6_vif_free(o, &vifc);
	}
}

uint32_t ospf6_vif_unref(struct ospf6 *o, ifindex_t vif,
			 const struct in6_addr *group)
{
	struct ospf6_vif_ctx *vifc;

	vifc = ospf6_vif_find(o, vif, group);
	if (vifc == NULL)
		return 0;

	vifc->refcount--;
	if (vifc->refcount > 0)
		return vifc->refcount;

	ospf6_vif_free(o, &vifc);
	return 0;
}
