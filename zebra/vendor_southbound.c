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

#include <zebra.h>

#include <sys/types.h>
#include <sys/un.h>

#include "lib/debug.h"
#include "lib/lib_errors.h"
#include "lib/linklist.h"
#include "lib/network.h"
#include "lib/ns.h"
#include "lib/privs.h"
#include "lib/stream.h"
#include "lib/thread.h"

#include "zebra/debug.h"
#include "zebra/zebra_errors.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_router.h"

#include "zebra/kernel_netlink.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/vendor_southbound.h"
#include "zebra/netconf_netlink.h"
#include "zebra/rt_netlink.h"
#include "zebra/rule_netlink.h"
#include "zebra/if_netlink.h"
#include "zebra/interface.h"

struct vendor_southbound_settings {
	/** Server address. */
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_un sun;
		struct sockaddr_in6 sin6;
		struct sockaddr_storage ss;
	} addr;
	socklen_t addrlen;
} uns;

enum vendor_southbound_event {
	VENDOR_SYNC_ROUTES,
	VENDOR_SYNC_INTERFACES,
};

pthread_mutex_t vendor_southbound_mtx;

bool vendor_southbound_enabled = false;

/* Monitor memory usage. */
DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_NETLINK, "Netlink buffers");
DEFINE_MTYPE_STATIC(ZEBRA, NL_BATCH_BUF, "Vendor batch buffers");

/* zebra/main.c zserv_priv struct. */
extern struct zebra_privs_t zserv_privs;

/* Prototypes. */
static int vendor_southbound_socket(void);
static ssize_t vendor_southbound_send(struct nlsock *ns, bool restart);
static int vendor_southbound_wait(const struct nlsock *ns, int event,
				  int timeout);
static void vendor_southbound_poll_read(struct zebra_ns *zns, int enabled);
static void vendor_southbound_poll_write(struct zebra_ns *zns, int enabled);
static void vendor_southbound_event_cb(struct thread *t);

static struct nlmsghdr *netlink_nextmsg(void *nlmsgp, size_t mtotal,
					size_t *mlen, uint32_t *seq,
					uint32_t *id);
static int nlmsg_parse_err(const struct nlsock *ns, struct nlmsghdr *nlmsg,
			   size_t nlmsglen);
static void netlink_buf_enqueue(struct list *l, uint32_t seq, const void *data,
				size_t dlen);
static int netlink_buf_cmp(struct nlbuf *nr1, struct nlbuf *nr2);
static void netlink_buf_del(struct nlbuf *nr);

static void if_select_all(void);
static void if_delete_selected(void);
static void rib_select_all_routes(struct route_node *);
static void rib_select_all(void);
static void rib_delete_selected_routes(afi_t, safi_t, struct route_node *);
static void rib_delete_selected(void);


/*
 * Netlink proxy implementation.
 */
void vendor_southbound_parse_address(const char *address_string)
{
	struct network_address address;

	if (!network_address_parse(address_string, &address,
				   NETLINK_PROXY_PORT)) {
		zlog_err("Southbound initialization: %s", address.error);
		return;
	}

	/*
	 * Server mode is not supported, but to keep backwards compatibility
	 * assume the user meant client mode and warn.
	 */
	if (address.listen) {
		zlog_warn(
			"Southbound initialization: server mode not supported, falling back to user mode.");
		zlog_warn(
			"Southbound initialization: please change your configuration to `ipv4c` or `ipv6c` to be forward compatible.");
		address.listen = false;
	}

	uns.addr.ss = address.address;
	uns.addrlen = (socklen_t)address.address_size;
	vendor_southbound_enabled = true;
}

static void vendor_southbound_socket_data(struct zebra_ns *zns,
					  struct nlsock *ns)
{
	/* Back-point to zebra_ns. */
	ns->zns = zns;

	/* Allocate buffers. */
	ns->nsbuf = stream_new(16 * NL_PKT_BUF_SIZE);

	/* Input buffers. */
	ns->inbufs = list_new();
	ns->inbufs->cmp = (void *)netlink_buf_cmp;
	ns->inbufs->del = (void *)netlink_buf_del;

	/* Output buffers. */
	ns->outbufs = list_new();
	ns->outbufs->del = (void *)netlink_buf_del;

	/* Message batch buffer. */
	ns->buflen = NL_RCV_PKT_BUF_SIZE;
	ns->buf = XMALLOC(MTYPE_NL_BATCH_BUF, ns->buflen);
}

static void vendor_southbound_socket_data_reset(const struct nlsock *nsc)
{
	static const char dplane_name[] = "netlink-dp";
	static const size_t dplane_name_len = sizeof(dplane_name) - 1;
	struct nlsock *ns = (struct nlsock *)nsc;
	struct nlbuf *nb;

	/* Create new socket. */
	close(ns->sock);
	kernel_netlink_nlsock_remove(ns);

	ns->sock = vendor_southbound_socket();

	/* Reset input buffer, otherwise we'll parse mixed messages. */
	stream_reset(ns->nsbuf);

	/* Reset outgoing buffer back to zero. */
	nb = listnode_head(ns->outbufs);
	if (nb != NULL)
		nb->nb_dataoff = 0;

	/*
	 * On zebra reconnect process route synchronization. Data plane
	 * should not trigger any event.
	 */
	if (memcmp(nsc->name, dplane_name, dplane_name_len) != 0)
		thread_execute(zrouter.master, vendor_southbound_event_cb, ns,
			       VENDOR_SYNC_INTERFACES);
}

static int vendor_southbound_socket(void)
{
	int sd;
	int on = 1;
	int errno_copy;

	/* Create and connect to the proxy. */
	if (uns.addr.sa.sa_family == 0) {
		uns.addr.sin.sin_family = AF_INET;
		uns.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		uns.addr.sin.sin_port = htons(NETLINK_PROXY_PORT);
		uns.addrlen = sizeof(struct sockaddr_in);
	}

	frr_with_privs (&zserv_privs) {
		sd = socket(uns.addr.sa.sa_family, SOCK_STREAM, 0);
		if (sd == -1) {
			zlog_err("%s: failure to create netlink socket: %s",
				 __func__, strerror(errno));
			exit(-1);
		}

		do {
			switch (uns.addr.sa.sa_family) {
			case AF_INET:
				zlog_debug("%s: connecting to %pI4:%d",
					   __func__, &uns.addr.sin.sin_addr,
					   ntohs(uns.addr.sin.sin_port));
				break;
			case AF_INET6:
				zlog_debug("%s: connecting to %pI6:%d",
					   __func__, &uns.addr.sin6.sin6_addr,
					   ntohs(uns.addr.sin6.sin6_port));
				break;
			case AF_UNIX:
				zlog_debug("%s: connecting to %s", __func__,
					   uns.addr.sun.sun_path);
				break;
			}

			if (connect(sd, &uns.addr.sa, uns.addrlen) == -1) {
				errno_copy = errno;
				zlog_err(
					"%s: failure to connect to dataplane: (%d) %s",
					__func__, errno_copy,
					strerror(errno_copy));
				if (errno_copy != ECONNREFUSED &&
				    errno_copy != ECONNRESET)
					exit(-1);

				/* Sleep a bit to avoid log message flooding. */
				sleep(1);
				continue;
			}
			break;
		} while (true);

		if (fcntl(sd, F_SETFL, O_NONBLOCK) == -1)
			flog_err_sys(EC_LIB_SOCKET, "%s: fcntl(O_NONBLOCK): %s",
				     __func__, safe_strerror(errno));

		/*
		 * Don't use Nagle algorithm to delay TCP messages, we
		 * always write the whole thing in a single write.
		 */
		if (uns.addr.sa.sa_family != AF_UNIX &&
		    setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) ==
			    -1)
			flog_err_sys(EC_LIB_SOCKET,
				     "%s: setsockopt(TCP_NODELAY): %s",
				     __func__, safe_strerror(errno));
	}

	return sd;
}

/*
 * Private
 */
static struct nlsock *vendor_southbound_namespace(const struct nlsock *ns)
{
	return &ns->zns->netlink;
}

/*
 * Exported
 */
int vendor_southbound_information_fetch(struct nlmsghdr *h, ns_id_t ns_id,
					int startup)
{
	/*
	 * When we handle new message types here
	 * because we are starting to install them
	 * then lets check the netlink_install_filter
	 * and see if we should add the corresponding
	 * allow through entry there.
	 * Probably not needed to do but please
	 * think about it.
	 */
	switch (h->nlmsg_type) {
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		return netlink_route_change(h, ns_id, startup);
	case RTM_NEWLINK:
	case RTM_DELLINK:
		return netlink_link_change(h, ns_id, startup);
	case RTM_NEWADDR:
	case RTM_DELADDR:
		return netlink_interface_addr_dplane(h, ns_id, startup);
	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
		return netlink_neigh_change(h, ns_id);
	case RTM_GETNEIGH:
		/*
		 * Kernel in some situations when it expects
		 * user space to resolve arp entries, we will
		 * receive this notification.  As we don't
		 * need this notification and as that
		 * we don't want to spam the log file with
		 * below messages, just ignore.
		 */
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("Received RTM_GETNEIGH, ignoring");
		break;
	case RTM_NEWRULE:
	case RTM_DELRULE:
		return netlink_rule_change(h, ns_id, startup);
	case RTM_NEWNEXTHOP:
	case RTM_DELNEXTHOP:
		return netlink_nexthop_change(h, ns_id, startup);
	case RTM_NEWNETCONF:
	case RTM_DELNETCONF:
		return netlink_netconf_change(h, ns_id, startup);
	default:
		/*
		 * If we have received this message then
		 * we have made a mistake during development
		 * and we need to write some code to handle
		 * this message type or not ask for
		 * it to be sent up to us
		 */
		flog_err(EC_ZEBRA_UNKNOWN_NLMSG,
			 "Unknown netlink nlmsg_type %s(%d) vrf %u",
			 nl_msg_type_to_str(h->nlmsg_type), h->nlmsg_type,
			 ns_id);
		break;
	}
	return 0;
}

void vendor_southbound_init(struct zebra_ns *zns)
{
	/* Initialize data structure. */
	pthread_mutex_init(&vendor_southbound_mtx, NULL);

	/* Start listening/using it. */
	vendor_southbound_socket_data(zns, &zns->netlink);
	zns->netlink.sock = vendor_southbound_socket();
	kernel_netlink_nlsock_insert(&zns->netlink);
	zns->netlink_cmd.sock = zns->netlink.sock;
	zns->netlink_cmd.zns = zns;
	zns->netlink_dplane_in.sock = zns->netlink.sock;
	zns->netlink_dplane_in.zns = zns;
	zns->netlink_dplane_out.sock = zns->netlink.sock;
	zns->netlink_dplane_out.zns = zns;
	vendor_southbound_poll_read(zns, 1);

	/* Data plane netlink-connection. */
	snprintf(zns->netlink.name, sizeof(zns->netlink.name),
		 "netlink-dp (NS %u)", zns->ns_id);

	rt_netlink_init();
}

void vendor_southbound_terminate(struct zebra_ns *zns, bool complete)
{
	THREAD_OFF(zns->t_netlink);
	THREAD_OFF(zns->t_netlinkout);

	/*
	 * During zebra shutdown, we need to leave the dataplane socket
	 * around until all work is done.
	 */
	if (complete)
		kernel_nlsock_fini(&zns->netlink);
}

void vendor_southbound_lock(void)
{
	pthread_mutex_lock(&vendor_southbound_mtx);
}

void vendor_southbound_unlock(void)
{
	pthread_mutex_unlock(&vendor_southbound_mtx);
}

void vendor_southbound_read(struct thread *thread)
{
	struct zebra_ns *zns = (struct zebra_ns *)THREAD_ARG(thread);
	struct zebra_dplane_info dp_info;

	VENDOR_SOUTHBOUND_LOCK_AUTOUNLOCK();

	/* Capture key info from ns struct */
	zebra_dplane_info_from_zns(&dp_info, zns, false);

	vendor_southbound_parse_info(vendor_southbound_information_fetch,
				     &zns->netlink, false);
	vendor_southbound_poll_read(zns, 1);
}

void vendor_southbound_write(struct thread *thread)
{
	struct zebra_ns *zns = (struct zebra_ns *)THREAD_ARG(thread);
	struct zebra_dplane_info dp_info;

	VENDOR_SOUTHBOUND_LOCK_AUTOUNLOCK();

	/* Capture key info from ns struct */
	zebra_dplane_info_from_zns(&dp_info, zns, false);

	/* Send all remaining data. */
	vendor_southbound_send(&zns->netlink, false);
}

ssize_t vendor_southbound_send_msg(struct nlsock *ns, const void *buf,
				   size_t buflen)
{
	const struct nlmsghdr *nlmsg = buf;
	ssize_t wlen = 0;

	ns = vendor_southbound_namespace(ns);

	/* Enqueue buffer to send. */
	netlink_buf_enqueue(ns->outbufs, nlmsg->nlmsg_seq, buf, buflen);
	ns->lastseq = ns->seq;
	ns->zns->netlink.lastseq = ns->seq;

	/* Flush the netlink buffer. */
	while ((wlen = vendor_southbound_send(ns, true)) != 0) {
		/* Connection failed/closed. */
		if (wlen == -1)
			return -1;
	}

	return wlen;
}

int vendor_southbound_request(struct nlsock *ns, void *msg)
{
	ssize_t wlen = 0;
	struct nlmsghdr *nlmsg = msg;

	ns = vendor_southbound_namespace(ns);

	/* Check netlink socket. */
	if (ns->sock < 0) {
		flog_err_sys(EC_LIB_SOCKET, "%s socket isn't active.",
			     ns->name);
		return -1;
	}

	/* Fill common fields for all requests. */
	nlmsg->nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	nlmsg->nlmsg_pid = ns->snl.nl_pid;
	nlmsg->nlmsg_seq = ++ns->seq;

	/* Save the sequence number we expect back. */
	ns->lastseq = nlmsg->nlmsg_seq;

	/* Enqueue buffer to send. */
	netlink_buf_enqueue(ns->outbufs, nlmsg->nlmsg_seq, nlmsg,
			    nlmsg->nlmsg_len);

	/* Flush the netlink buffer. */
	while ((wlen = vendor_southbound_send(ns, true)) != 0) {
		/* Connection failed/closed. */
		if (wlen == -1)
			return -1;
	}

	return 0;
}

int vendor_southbound_parse_info(filter_cb filter, const struct nlsock *ns,
				 bool startup)
{
	struct listnode *ln, *lnn;
	struct nlmsghdr *nlmsg;
	struct nlbuf *nb;
	size_t nlmsglen;
	ssize_t rlen;
	int ret = 0, attempts = 10;
	bool found = false;

	ns = vendor_southbound_namespace(ns);

read_again:
	/*
	 * We make the assumption that when this function is called, the
	 * previous one is a request. Here we have to wait for the full
	 * request response and it might be big.
	 *
	 * Exception note:
	 * Don't wait for responses when this function is called
	 * asynchronously.
	 */
	if (filter != vendor_southbound_information_fetch)
		vendor_southbound_wait(ns, POLLIN, 1000);

	/* Receive all pending messages. */
	while ((rlen = vendor_southbound_recv(ns, filter, &found, startup, &ret,
					      &attempts)) != 0) {
		/* Connection failed/closed. */
		if (rlen == -1)
			return -1;
	}

	/* Go over the received buffer list. */
	for (ALL_LIST_ELEMENTS(ns->inbufs, ln, lnn, nb)) {
		/*
		 * Skip sequences that are notifications or not the
		 * number we expected.
		 */
		if (nb->nb_seq != ns->lastseq) {
			/*
			 * If the sequence number is old or newer than
			 * expected it was probably requested by us.
			 *
			 * This will also help us to avoid memory leaks
			 * since we'll not hold response buffers not
			 * belonging to us.
			 */
			if (nb->nb_seq < ns->lastseq) {
				listnode_delete(ns->inbufs, nb);
				netlink_buf_del(nb);
			}
			continue;
		}

		/*
		 * We might be receiving a very big response (for an
		 * example in case of hundreds of thousand of route
		 * install response or pre-installed), so increment the
		 * attempt count unless the sequence number doesn't
		 * match.
		 */
		attempts++;

		nlmsglen = nb->nb_datasiz;
		for (nlmsg = (struct nlmsghdr *)nb->nb_data;
		     NLMSG_OK(nlmsg, nlmsglen);
		     nlmsg = NLMSG_NEXT(nlmsg, nlmsglen)) {
			/* Handle single messages. */
			if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0 &&
			    nlmsg->nlmsg_seq == ns->lastseq)
				found = true;
			/* Handle error messages. */
			if (nlmsg->nlmsg_type == NLMSG_ERROR) {
				if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0 &&
				    nlmsg->nlmsg_seq == ns->lastseq)
					found = true;

				nlmsg_parse_err(ns, nlmsg, nlmsg->nlmsg_len);
				continue;
			}
			/* Skip done messages to avoid errors. */
			if (nlmsg->nlmsg_type == NLMSG_DONE) {
				if (nlmsg->nlmsg_seq == ns->lastseq)
					found = true;

				continue;
			}

			ret = filter(nlmsg, ns->zns->ns_id, startup);
		}

		listnode_delete(ns->inbufs, nb);
		netlink_buf_del(nb);
	}

	/*
	 * If we are expecting an answer back, then attempt to get an
	 * answer or notify message loss.
	 */
	if (found == false && filter != vendor_southbound_information_fetch) {
		/*
		 * The dataplane sent a notification or is taking too
		 * long to send an answer back, lets wait a bit more to
		 * avoid losing the message.
		 */
		attempts--;
		if (attempts > 0)
			goto read_again;

		zlog_err("%s: could not find netlink answer for %u", __func__,
			 ns->lastseq);
	}

	return ret;
}

int vendor_southbound_talk_info(int (*filter)(struct nlmsghdr *, ns_id_t,
					      int startup),
				struct nlmsghdr *nlmsg,
				struct zebra_dplane_info *dp_info, bool startup)
{
	ssize_t wlen = 0;
	struct nlsock *ns;

	ns = kernel_netlink_nlsock_lookup(dp_info->sock);

	/* Prepare netlink message. */
	nlmsg->nlmsg_pid = ns->snl.nl_pid;

	/*
	 * Messages that don't expect answer back should use
	 * notification request number.
	 *
	 * This should imitate the old behavior of having a second
	 * socket listening for this events.
	 */
	if (filter != netlink_talk_filter) {
		nlmsg->nlmsg_seq = ++dp_info->seq;
		/* Save the sequence number we expect back. */
		ns->lastseq = nlmsg->nlmsg_seq;
	} else
		nlmsg->nlmsg_seq = 0;

	/* Enqueue buffer to send. */
	netlink_buf_enqueue(ns->outbufs, nlmsg->nlmsg_seq, nlmsg,
			    nlmsg->nlmsg_len);

	/* Flush the netlink buffer. */
	while ((wlen = vendor_southbound_send(
			ns, filter != netlink_talk_filter)) != 0) {
		/* Connection failed/closed. */
		if (wlen == -1)
			return -1;
	}

	if (filter == netlink_talk_filter) {
		/* In userspace netlink operation, we must process the answer as
		 * an update, instead of ignoring it. */
		filter = vendor_southbound_information_fetch;
	}

	/* Expect answer back. */
	return vendor_southbound_parse_info(filter, ns, startup);
}


/*
 * Local helper functions.
 */
ssize_t vendor_southbound_recv(const struct nlsock *ns, filter_cb filter,
			       bool *found, bool startup, int *ret,
			       int *attempts)
{
	struct nlmsghdr *nlmsg;
	size_t rtotal = 0;
	size_t mlen;
	ssize_t rlen;
	uint32_t seq, id;

	/* Make space for more reads. */
	stream_pulldown(ns->nsbuf);

	/* Try to receive message. */
	rlen = stream_read_try(ns->nsbuf, ns->sock,
			       STREAM_WRITEABLE(ns->nsbuf));
	if (rlen <= -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return 0;

		flog_err(EC_ZEBRA_RECVMSG_OVERRUN, "%s recv overrun: %s",
			 ns->name, safe_strerror(errno));
		vendor_southbound_socket_data_reset(ns);
		return 0;
	}
	if (rlen == 0) {
		flog_err_sys(EC_LIB_SOCKET, "%s recv: EOF", ns->name);
		vendor_southbound_socket_data_reset(ns);
		return 0;
	}

nl_next:
	/* Get next message. */
	nlmsg = netlink_nextmsg(&ns->nsbuf->data[ns->nsbuf->getp],
				STREAM_READABLE(ns->nsbuf), &mlen, &seq, &id);
	if (nlmsg == NULL || mlen == 0)
		return rtotal;

	/* Advance buffer pointer. */
	stream_forward_getp(ns->nsbuf, mlen);
	rtotal += mlen;

	/* Validate incoming data. */
	if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV) {
		zlog_debug("%s: << netlink message dump [recv]", __func__);
#ifdef NETLINK_DEBUG
		nl_dump(nlmsg, mlen);
#else
		zlog_hexdump(nlmsg, mlen);
#endif /* NETLINK_DEBUG */
	}

	/* OK we got netlink message. */
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: %s type %s(%u), len=%d, seq=%u, pid=%u",
			   __func__, ns->name,
			   nl_msg_type_to_str(nlmsg->nlmsg_type),
			   nlmsg->nlmsg_type, nlmsg->nlmsg_len,
			   nlmsg->nlmsg_seq, nlmsg->nlmsg_pid);

	/* Handle notifications. */
	if (nlmsg->nlmsg_seq == 0 ||
	    (nlmsg->nlmsg_seq > ns->lastseq &&
	     filter == vendor_southbound_information_fetch)) {
		for (; NLMSG_OK(nlmsg, mlen); nlmsg = NLMSG_NEXT(nlmsg, mlen)) {
			/* Skip done messages to avoid errors. */
			if (nlmsg->nlmsg_type == NLMSG_DONE)
				continue;

			vendor_southbound_information_fetch(
				nlmsg, ns->zns->ns_id, false);
		}

		/* Drain more the read buffer. */
		goto nl_next;
	} else if (nlmsg->nlmsg_seq <= ns->lastseq) {
		*attempts = *attempts + 1;
		for (; NLMSG_OK(nlmsg, mlen); nlmsg = NLMSG_NEXT(nlmsg, mlen)) {
			/* Handle single messages. */
			if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0 &&
			    nlmsg->nlmsg_seq == ns->lastseq)
				*found = true;
			/* Handle error messages. */
			if (nlmsg->nlmsg_type == NLMSG_ERROR) {
				if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0 &&
				    nlmsg->nlmsg_seq == ns->lastseq)
					*found = true;

				nlmsg_parse_err(ns, nlmsg, nlmsg->nlmsg_len);
				continue;
			}
			/* Skip done messages to avoid errors. */
			if (nlmsg->nlmsg_type == NLMSG_DONE) {
				if (nlmsg->nlmsg_seq == ns->lastseq)
					*found = true;

				continue;
			}

			*ret = filter(nlmsg, ns->zns->ns_id, startup);
		}
		goto nl_next;
	}

	/* Don't keep old messages. */
	if (listcount(ns->inbufs) >= 100) {
		struct nlbuf *nb = listnode_head(ns->inbufs);
		listnode_delete(ns->inbufs, nb);
		netlink_buf_del(nb);
	}

	/* Enqueue it so the answer can be found. */
	netlink_buf_enqueue(ns->inbufs, seq, nlmsg, mlen);

	goto nl_next;
}

/**
 * Netlink message queue send function.
 * \param ns netlink socket.
 * \param restart whether or not to restart syscall on interruptions.
 * \return amount of bytes written or zero.
 */
static ssize_t vendor_southbound_send(struct nlsock *ns, bool restart)
{
	struct nlbuf *nb;
	size_t wtotal = 0;
	ssize_t wlen;

dequeue_buf:
	nb = listnode_head(ns->outbufs);
	/* No data to send. */
	if (nb == NULL) {
		vendor_southbound_poll_write(ns->zns, 0);
		return wtotal;
	}

	/* Wait to be ready to write. */
	vendor_southbound_wait(ns, POLLOUT, 1000);

	/* Send data and empty buffer. */
	wlen = send(ns->sock, nb->nb_data + nb->nb_dataoff,
		    nb->nb_datasiz - nb->nb_dataoff, MSG_DONTWAIT);
	if (wlen == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			if (restart)
				goto dequeue_buf;

			vendor_southbound_poll_write(ns->zns, 1);
			return wtotal;
		}

		flog_err(EC_ZEBRA_RECVMSG_OVERRUN, "%s send overrun: %s",
			 ns->name, safe_strerror(errno));
		return -1;
	}
	if (wlen == 0) {
		flog_err_sys(EC_LIB_SOCKET, "%s send: EOF", ns->name);
		vendor_southbound_socket_data_reset(ns);
		return 0;
	}

	wtotal += wlen;
	nb->nb_dataoff += wlen;
	/* If we emptied the buffer, then get rid of it. */
	if (nb->nb_dataoff == nb->nb_datasiz) {
		if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND) {
			zlog_debug("%s: >> netlink message dump [sent]",
				   __func__);
#ifdef NETLINK_DEBUG
			nl_dump(nb->nb_data, nb->nb_datasiz);
#else
			zlog_hexdump(nb->nb_data, nb->nb_datasiz);
#endif /* NETLINK_DEBUG */
		}
		listnode_delete(ns->outbufs, nb);
		netlink_buf_del(nb);
	}

	goto dequeue_buf;
}

static int vendor_southbound_wait(const struct nlsock *ns, int event,
				  int timeout)
{
	struct pollfd pf;
	int rv;

	memset(&pf, 0, sizeof(pf));
	pf.fd = ns->sock;
	pf.events = event;

poll_again:
	rv = poll(&pf, 1, timeout);
	if (rv == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			goto poll_again;

		flog_err_sys(EC_LIB_SOCKET, "%s: poll: %s", __func__,
			     strerror(errno));
		return -1;
	}

	return 0;
}

static struct nlmsghdr *netlink_nextmsg(void *nlmsgp, size_t mtotal,
					size_t *mlen, uint32_t *seq,
					uint32_t *id)
{
	struct nlmsghdr *nlmsg = nlmsgp;

	/* Initialize return values. */
	*mlen = 0;
	*seq = 0;
	*id = 0;

	/* Validate message size. */
	if (mtotal < sizeof(struct nlmsghdr) ||
	    NLMSG_ALIGN(nlmsg->nlmsg_len) > mtotal)
		return NULL;

	/* Check for multipart whole message. */
	if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0) {
		*seq = nlmsg->nlmsg_seq;
		*id = nlmsg->nlmsg_pid;
		*mlen = NLMSG_ALIGN(nlmsg->nlmsg_len);
		return nlmsgp;
	}

#ifdef NETLINK_FULL_MSG
	/* If this is a multipart, then we must wait for all the parts. */
	for (; NLMSG_OK(nlmsg, mtotal); nlmsg = NLMSG_NEXT(nlmsg, mtotal)) {
		/* Add up this message to the pile. */
		*mlen += NLMSG_ALIGN(nlmsg->nlmsg_len);

		/* Continue until the end of buffer or final message. */
		if (nlmsg->nlmsg_type != NLMSG_DONE)
			continue;

		/* We found the last part, so return all values found. */
		*seq = nlmsg->nlmsg_seq;
		*id = nlmsg->nlmsg_pid;
		return nlmsgp;
	}

	return NULL;
#else  /* !NETLINK_FULL_MSG */
	/*
	 * Full message is not needed, so just return the current
	 * message part. We'll download the rest later.
	 */
	*seq = nlmsg->nlmsg_seq;
	*id = nlmsg->nlmsg_pid;

	/*
	 * If this is a multipart, then we'll gather whatever we have
	 * available.
	 */
	for (; NLMSG_OK(nlmsg, mtotal); nlmsg = NLMSG_NEXT(nlmsg, mtotal)) {
		/* Add up this message to the pile. */
		*mlen += NLMSG_ALIGN(nlmsg->nlmsg_len);

		/* Continue until the end of buffer or final message. */
		if (nlmsg->nlmsg_type == NLMSG_DONE)
			break;
	}

	return nlmsgp;
#endif /* !NETLINK_FULL_MSG */
}

static int nlmsg_parse_err(const struct nlsock *ns, struct nlmsghdr *nlmsg,
			   size_t nlmsglen)
{
	struct nlmsgerr *err = NLMSG_DATA(nlmsg);

	if (nlmsg->nlmsg_len < NLMSG_LENGTH(sizeof(*err))) {
		flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
			 "%s error: message truncated", ns->name);
		return -1;
	}

	/*
	 * Parse the extended information before we actually handle it.
	 * At this point in time we do not do anything other than report
	 * the issue.
	 */
	if (nlmsg->nlmsg_flags & NLM_F_ACK_TLVS)
		netlink_parse_extended_ack(nlmsg);

	/* If the error field is zero, then this is an ACK. */
	if (err->error == 0) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: %s ACK: type=%s(%u), seq=%u, pid=%u",
				   __func__, ns->name,
				   nl_msg_type_to_str(err->msg.nlmsg_type),
				   err->msg.nlmsg_type, err->msg.nlmsg_seq,
				   err->msg.nlmsg_pid);

		return -1;
	}

	/* Deal with errors that occur because of races
	 * in link handling */
	if ((nlmsg->nlmsg_type == RTM_DELROUTE &&
	     (-err->error == ENODEV || -err->error == ESRCH)) ||
	    (nlmsg->nlmsg_type == RTM_NEWROUTE &&
	     (-err->error == ENETDOWN || -err->error == EEXIST))) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: error: %s type=%s(%u), seq=%u, pid=%u",
				   ns->name, safe_strerror(-err->error),
				   nl_msg_type_to_str(nlmsg->nlmsg_type),
				   nlmsg->nlmsg_type, err->msg.nlmsg_seq,
				   err->msg.nlmsg_pid);
		return 0;
	}

	/*
	 * We see RTM_DELNEIGH when shutting down an interface with an
	 * IPv4 link-local.  The kernel should have already deleted the
	 * neighbor so do not log these as an error.
	 */
	if (nlmsg->nlmsg_type == RTM_DELNEIGH ||
	    (nlmsg->nlmsg_type == RTM_NEWROUTE &&
	     (-err->error == ESRCH || -err->error == ENETUNREACH))) {
		/*
		 * This is known to happen in some situations, don't log
		 * as error.
		 */
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s error: %s, type=%s(%u), seq=%u, pid=%u",
				   ns->name, safe_strerror(-err->error),
				   nl_msg_type_to_str(nlmsg->nlmsg_type),
				   nlmsg->nlmsg_type, err->msg.nlmsg_seq,
				   err->msg.nlmsg_pid);
		return -1;
	} else {
		flog_err(EC_ZEBRA_UNEXPECTED_MESSAGE,
			 "%s error: %s, type=%s(%u), seq=%u, pid=%u", ns->name,
			 safe_strerror(-err->error),
			 nl_msg_type_to_str(nlmsg->nlmsg_type),
			 nlmsg->nlmsg_type, err->msg.nlmsg_seq,
			 err->msg.nlmsg_pid);
		return -1;
	}

	return 0;
}

void vendor_southbound_poll_read(struct zebra_ns *zns, int enabled)
{
	THREAD_OFF(zns->t_netlink);
	if (!enabled)
		return;

	thread_add_read(zrouter.master, vendor_southbound_read, zns,
			zns->netlink.sock, &zns->t_netlink);
}

void vendor_southbound_poll_write(struct zebra_ns *zns, int enabled)
{
	THREAD_OFF(zns->t_netlinkout);
	if (!enabled)
		return;

	thread_add_read(zrouter.master, vendor_southbound_write, zns,
			zns->netlink.sock, &zns->t_netlinkout);
}

void netlink_buf_enqueue(struct list *l, uint32_t seq, const void *data,
			 size_t dlen)
{
	struct nlbuf *nb;
	size_t dtotal = sizeof(*nb) + dlen;

	nb = XMALLOC(MTYPE_ZEBRA_NETLINK, dtotal);

	/* Copy the buffer data. */
	memcpy(nb->nb_data, data, dlen);
	nb->nb_datasiz = dlen;
	nb->nb_dataoff = 0;
	nb->nb_seq = seq;

	/* Add to output list. */
	listnode_add_sort(l, nb);
}

int netlink_buf_cmp(struct nlbuf *nb1, struct nlbuf *nb2)
{
	if (nb1->nb_seq > nb2->nb_seq)
		return 1;
	if (nb1->nb_seq < nb2->nb_seq)
		return -1;
	return 0;
}

void netlink_buf_del(struct nlbuf *nb)
{
	XFREE(MTYPE_ZEBRA_NETLINK, nb);
}

/*
 * Mark all RIB routes as unselected so we can remove after data plane
 * refresh.
 */
void rib_select_all_routes(struct route_node *rn)
{
	struct route_entry *re, *next;

	RNODE_FOREACH_RE_SAFE (rn, re, next) {
		/*
		 * Skip interface addresses, those are already properly
		 * manipulated on add/removal with the interface add/del.
		 */
		if (re->type == ZEBRA_ROUTE_CONNECT)
			continue;

		/*
		 * Skip all routing protocol routes as southbound doesn't
		 * expect to update them.
		 */
		if (re->type != ZEBRA_ROUTE_KERNEL &&
		    re->type != ZEBRA_ROUTE_STATIC &&
		    re->type != ZEBRA_ROUTE_SYSTEM)
			continue;

		SET_FLAG(re->flags, ZEBRA_FLAG_SYNC_ROUTE);
	}
}

void rib_select_all(void)
{
	struct route_table *rt;
	struct route_node *rn;
	rib_tables_iter_t rt_iter;

	rt_iter.state = RIB_TABLES_ITER_S_INIT;
	while ((rt = rib_tables_iter_next(&rt_iter))) {
		for (rn = route_top(rt); rn; rn = srcdest_route_next(rn)) {
			rib_select_all_routes(rn);
		}
	}
}

/*
 * Delete all routes marked with SYNC for deletion.
 */
void rib_delete_selected_routes(afi_t afi, safi_t safi, struct route_node *rn)
{
	struct route_entry *re, *next;

	RNODE_FOREACH_RE_SAFE (rn, re, next) {
		/* Skip routes already marked for removal. */
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		/*
		 * Remove routes that existed in zebra, but doesn't exist
		 * anymore and are marked for sync removal.
		 */
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SYNC_ROUTE) == 0)
			continue;

		rib_delnode(rn, re);
	}
}

void rib_delete_selected(void)
{
	struct route_table *rt;
	struct route_node *rn;
	unsigned int it, itn;
	vrf_id_t vrf_id;
	afi_t afis[] = {
		AFI_IP,
		AFI_IP6,
	};
	safi_t safis[] = {
		SAFI_UNICAST,
		SAFI_MULTICAST,
		SAFI_LABELED_UNICAST,
	};

	for (it = 0; it < array_size(afis); it++) {
		for (itn = 0; itn < array_size(safis); itn++) {
			vrf_id = VRF_DEFAULT;
			do {
				rt = zebra_vrf_table(afis[it], safis[itn],
						     vrf_id);
				if (rt == NULL)
					continue;

				for (rn = route_top(rt); rn;
				     rn = srcdest_route_next(rn)) {
					rib_delete_selected_routes(
						afis[it], safis[itn], rn);
				}
			} while (vrf_id_get_next(vrf_id, &vrf_id));
		}
	}
}

void if_select_all(void)
{
	struct interface *ifp;
	struct vrf *vrf;
	vrf_id_t vrf_id;

	vrf_id = VRF_DEFAULT;
	do {
		vrf = vrf_lookup_by_id(vrf_id);
		FOR_ALL_INTERFACES (vrf, ifp) {
			SET_FLAG(ifp->status, ZEBRA_INTERFACE_SYNC);
		}
	} while (vrf_id_get_next(vrf_id, &vrf_id));
}

void if_delete_selected(void)
{
	struct interface *ifp;
	struct vrf *vrf;
	vrf_id_t vrf_id;

	vrf_id = VRF_DEFAULT;
	do {
		vrf = vrf_lookup_by_id(vrf_id);
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_SYNC) == 0)
				continue;

			UNSET_FLAG(ifp->status, ZEBRA_INTERFACE_VRF_LOOPBACK);

			/* Special handling for bridge or VxLAN interfaces. */
			if (IS_ZEBRA_IF_BRIDGE(ifp))
				zebra_l2_bridge_del(ifp);
			else if (IS_ZEBRA_IF_VXLAN(ifp))
				zebra_l2_vxlanif_del(ifp);
			if (!IS_ZEBRA_IF_VRF(ifp))
				if_delete_update(&ifp);
		}
	} while (vrf_id_get_next(vrf_id, &vrf_id));
}

static void vendor_southbound_event_cb(struct thread *t)
{
	enum vendor_southbound_event une = THREAD_VAL(t);
	struct nlsock *ns = THREAD_ARG(t);

	switch (une) {
	case VENDOR_SYNC_INTERFACES:
		/* Select all routes and mark them for deletion. */
		rib_select_all();

		/* Select all interfaces to figure out removed ones. */
		if_select_all();

		/*
		 * Synchronize interfaces in order to create / delete
		 * next hops. Routes pointing to non existent next hops
		 * will get purged by rib properly. We'll also need new
		 * interfaces' addresses to create future incoming
		 * routes.
		 */
		if (interface_lookup_netlink(ns->zns) == 0)
			thread_execute(zrouter.master,
				       vendor_southbound_event_cb, ns,
				       VENDOR_SYNC_ROUTES);

		/*
		 * Interfaces will get deselected with the sync flag
		 * when the netlink interface handling procedure
		 * update the interface flags.
		 */
		if_delete_selected();
		break;

	case VENDOR_SYNC_ROUTES:
		/* Routes will be unselected when incoming from data plane. */
		netlink_route_read(ns->zns);

		/* Delete still marked routes. */
		rib_delete_selected();
		break;

	default:
		break;
	}
}

/**
 * Look up for old route and create a new group with the previous and new
 * next hops.
 *
 * \returns '-1' on failure otherwise '0'.
 */
int rib_append_nexthop(afi_t afi, struct prefix *p, struct prefix_ipv6 *src_p,
		       struct route_entry *re, struct nhg_hash_entry *rt_nhe,
		       struct route_node *rn)
{
	struct nhg_hash_entry *nhe = NULL;
	struct nexthop_group *nhg = NULL;
	struct route_entry *same = NULL;
	struct nexthop *nha, *nhb, *nhc;
	bool found = false;
	int copy_count;

	/* Look up the route that matches the entry we want to append. */
	RNODE_FOREACH_RE (rn, same) {
		if (CHECK_FLAG(same->status, ROUTE_ENTRY_REMOVED))
			continue;

		if (same->type != re->type)
			continue;
		if (same->instance != re->instance)
			continue;
		if (re->type == ZEBRA_ROUTE_STATIC) {
			if (same->distance != re->distance)
				continue;
			if (same->metric != re->metric)
				continue;
		}
		if (same->type == ZEBRA_ROUTE_KERNEL &&
		    same->metric != re->metric)
			continue;

		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_RR_USE_DISTANCE) &&
		    same->distance != re->distance)
			continue;

		found = true;
		break;
	}

	/*
	 * Always allocate a next hop group, because this function might have
	 * been called from `rib_add_multipath_nhe` using a stack pointer
	 * instead of heap (or worse heap that is deallocated by
	 * `rib_add_multipath`).
	 */
	nhg = nexthop_group_new();
	if (rt_nhe != NULL)
		nexthop_group_copy(nhg, &rt_nhe->nhg);

	/* This is a new route, don't attempt to append it anywhere. */
	if (found == false) {
		if (rt_nhe == NULL)
			goto error_and_return;

		UNSET_FLAG(re->flags, ZEBRA_FLAG_APPEND_ROUTE);
		goto skip_nh_copy;
	}

	/*
	 * To append a nexthop to a new group, we actually do a copy of
	 * all non duplicated next hops from previous group to a new one.
	 */
	copy_count = 0;
	for (ALL_NEXTHOPS(same->nhe->nhg, nha)) {
		found = false;
		for (ALL_NEXTHOPS_PTR(nhg, nhb)) {
			if (nexthop_same(nha, nhb) == false)
				continue;

			found = true;
			break;
		}
		if (found)
			continue;

		nhc = nexthop_dup(nha, nha->rparent);
		nexthop_group_add_sorted(nhg, nhc);
		copy_count++;
	}
	for (ALL_NEXTHOPS_PTR(nhg, nha))
		SET_FLAG(nha->flags, NEXTHOP_FLAG_FIB);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: copied %d routes from previous group", __func__,
			   copy_count);

skip_nh_copy:
	/* Find or create next hop group for this entry. */
	nhe = zebra_nhg_rib_find(0, nhg, afi, ZEBRA_ROUTE_NHG);

	/* The next hops got copied over into an entry, so free them now. */
	nexthop_group_delete(&nhg);

	if (nhe == NULL) {
	error_and_return:
		nexthop_group_delete(&nhg);
		if (src_p && src_p->family)
			flog_err(EC_ZEBRA_TABLE_LOOKUP_FAILED,
				 "%s: failed to find/create next hop group for "
				 "%pFX from %pFX",
				 __func__, p, src_p);
		else
			flog_err(EC_ZEBRA_TABLE_LOOKUP_FAILED,
				 "%s: failed to find/create next hop group for "
				 "%pFX",
				 __func__, p);

		return -1;
	}

	/* Attach next hop group to route entry. */
	route_entry_update_nhe(re, nhe);
	return 0;
}

/**
 * Creates a new next hop group and removes selected next hop.
 *
 * \returns '-1' on failure otherwise '0'.
 */
int rib_delete_nexthop(afi_t afi, struct route_node *rn, struct route_entry *re,
		       struct nexthop *nh)
{
	struct nhg_hash_entry *nhe;
	struct nexthop *nha, *nhc;
	struct nexthop_group *nhg;
	int copy_count;

	/* Easiest case: if there is only one next hop then delete it. */
	if (nexthop_group_active_nexthop_num_no_recurse(&re->nhe->nhg) <= 1) {
		rib_delnode(rn, re);
		route_unlock_node(rn);
		return 0;
	}

	/*
	 * To remove a next hop from a group we need to create a new one with
	 * all next hops except the ones we want to remove.
	 */
	copy_count = 0;
	nhg = nexthop_group_new();
	for (ALL_NEXTHOPS(re->nhe->nhg, nha)) {
		if (nexthop_same(nha, nh) == true)
			continue;

		nhc = nexthop_dup(nha, nha->rparent);
		nexthop_group_add_sorted(nhg, nhc);
		copy_count++;
	}
	for (ALL_NEXTHOPS_PTR(nhg, nha))
		SET_FLAG(nha->flags, NEXTHOP_FLAG_FIB);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: copied %d routes from previous group", __func__,
			   copy_count);

	/* Find or create next hop group for this entry. */
	nhe = zebra_nhg_rib_find(0, nhg, afi, ZEBRA_ROUTE_NHG);

	/* The next hops got copied over into an entry, so free them now. */
	nexthop_group_delete(&nhg);

	/* Attach next hop group to route entry. */
	route_entry_update_nhe(re, nhe);

	/* Enqueue update and release reference. */
	rib_queue_add(rn);
	route_unlock_node(rn);

	return 0;
}
