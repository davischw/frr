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

#include <zebra.h>

#ifdef NETLINK_PROXY

#include <sys/types.h>
#include <sys/un.h>

#include "lib/debug.h"
#include "lib/lib_errors.h"
#include "lib/linklist.h"
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
#include "zebra/user_netlink.h"
#include "zebra/if_netlink.h"
#include "zebra/interface.h"

struct user_netlink_settings {
	/** Server address. */
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_un sun;
		struct sockaddr_in6 sin6;
	} addr;
	socklen_t addrlen;
} uns;

enum user_netlink_event {
	UNE_SYNC_ROUTES,
	UNE_SYNC_INTERFACES,
};

/* Monitor memory usage. */
DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_NETLINK, "Netlink buffers");

/* zebra/main.c zserv_priv struct. */
extern struct zebra_privs_t zserv_privs;

/* Netlink private functions. */
void dpd_socket_data(struct zebra_ns *zns, struct nlsock *ns);
void dpd_socket_data_reset(const struct nlsock *nsc);
int dpd_socket(void);
int kernel_read(struct thread *thread);
int kernel_write(struct thread *thread);
ssize_t netlink_send_msg(struct nlsock *ns, const void *buf, size_t buflen);
int netlink_request(struct nlsock *ns, void *msg);
void netlink_parse_notify(const struct nlsock *ns);

/* Helper functions. */
ssize_t netlink_recv(const struct nlsock *ns);
ssize_t netlink_send(struct nlsock *ns);
int netlink_wait(const struct nlsock *ns, int event, int timeout);
struct nlmsghdr *netlink_nextmsg(void *nlmsgp, size_t mtotal, size_t *mlen,
				 uint32_t *seq, uint32_t *id);
int nlmsg_parse_err(const struct nlsock *ns, struct nlmsghdr *nlmsg,
		    size_t nlmsglen);
void netlink_poll_read(struct zebra_ns *zns, int enabled);
void netlink_poll_write(struct zebra_ns *zns, int enabled);
void netlink_buf_enqueue(struct list *l, uint32_t seq, const void *data,
			 size_t dlen);

int netlink_buf_cmp(struct nlbuf *nr1, struct nlbuf *nr2);
void netlink_buf_del(struct nlbuf *nr);

void stream_pulldown(struct stream *s);

void if_select_all(void);
void if_delete_selected(void);
void rib_select_all_routes(struct route_node *);
void rib_select_all(void);
void rib_delete_selected_routes(afi_t, safi_t, struct route_node *);
void rib_delete_selected(void);
int user_netlink_event_cb(struct thread *t);

/*
 * Netlink proxy implementation.
 */
static uint16_t dpd_parse_port(const char *str)
{
	char *nulbyte;
	long rv;

	errno = 0;
	rv = strtol(str, &nulbyte, 10);
	/* No conversion performed. */
	if (rv == 0 && errno == EINVAL) {
		zlog_err("invalid IFM port: %s", str);
		return NETLINK_PROXY_PORT;
	}
	/* Invalid number range. */
	if ((rv <= 0 || rv >= 65535) || errno == ERANGE) {
		zlog_err("invalid IFM port range: %s", str);
		return NETLINK_PROXY_PORT;
	}
	/* There was garbage at the end of the string. */
	if (*nulbyte != 0) {
		zlog_err("invalid IFM port: %s", str);
		return NETLINK_PROXY_PORT;
	}

	return (uint16_t)rv;
}

void dpd_parse_address(const char *address)
{
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	struct sockaddr_un *sun;
	char *sptr, *saux;
	size_t slen;
	char addr[64];
	char type[64];

	/* Basic parsing: find ':' to figure out type part and address part. */
	sptr = strchr(address, ':');
	if (sptr == NULL) {
		zlog_err("invalid IFM address: %s", address);
		return;
	}

	/* Calculate type string length. */
	slen = (size_t)(sptr - address);

	/* Copy the address part. */
	sptr++;
	strlcpy(addr, sptr, sizeof(addr));

	/* Copy type part. */
	strlcpy(type, address, slen + 1);

	/* Fill the address information. */
	if (strcmp(type, "unix") == 0) {
		uns.addrlen = sizeof(*sun);
		sun = &uns.addr.sun;
		sun->sun_family = AF_UNIX;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sun->sun_len = sizeof(*sun);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		strlcpy(sun->sun_path, addr, sizeof(sun->sun_path));
	} else if (strcmp(type, "ipv4") == 0) {
		uns.addrlen = sizeof(*sin);
		sin = &uns.addr.sin;
		sin->sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sin->sin_len = sizeof(*sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */

		/* Parse port if any. */
		sptr = strchr(addr, ':');
		if (sptr == NULL) {
			sin->sin_port = htons(NETLINK_PROXY_PORT);
		} else {
			*sptr = 0;
			sin->sin_port = htons(dpd_parse_port(sptr + 1));
		}

		if (inet_pton(AF_INET, addr, &sin->sin_addr) == 1) {
			zlog_info("%s: IFM server address %pI4", __func__,
				  &sin->sin_addr);
		} else
			zlog_err("%s: inet_pton: invalid address %s", __func__,
				 addr);
	} else if (strcmp(type, "ipv6") == 0) {
		uns.addrlen = sizeof(*sin6);
		sin6 = &uns.addr.sin6;
		sin6->sin6_family = AF_INET6;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sin6->sin6_len = sizeof(*sin6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */

		/* Check for IPv6 enclosures '[]' */
		sptr = &addr[0];
		if (*sptr != '[') {
			zlog_err("%s: invalid IPv6 address format: %s",
				 __func__, addr);
			return;
		}

		saux = strrchr(addr, ']');
		if (saux == NULL) {
			zlog_err("%s: invalid IPv6 address format: %s",
				 __func__, addr);
			return;
		}

		/* Consume the '[]:' part. */
		slen = saux - sptr;
		memmove(addr, addr + 1, slen);
		addr[slen - 1] = 0;

		/* Parse port if any. */
		saux++;
		sptr = strrchr(saux, ':');
		if (sptr == NULL) {
			sin6->sin6_port = htons(NETLINK_PROXY_PORT);
		} else {
			*sptr = 0;
			sin6->sin6_port = htons(dpd_parse_port(sptr + 1));
		}

		if (inet_pton(AF_INET6, addr, &sin6->sin6_addr) == 1) {
			zlog_info("%s: IFM server address %pI6", __func__,
				  &sin6->sin6_addr);
		} else
			zlog_err("%s: inet_pton: invalid address %s", __func__,
				 addr);
	} else
		zlog_err("invalid IFM socket type: %s", type);
}

void dpd_socket_data(struct zebra_ns *zns, struct nlsock *ns)
{
	/* Back-point to zebra_ns. */
	ns->zns = zns;

	/* Allocate buffers. */
	ns->nsbuf = stream_new(32 * 1024);

	/* Input buffers. */
	ns->inbufs = list_new();
	ns->inbufs->cmp = (void *)netlink_buf_cmp;
	ns->inbufs->del = (void *)netlink_buf_del;

	/* Output buffers. */
	ns->outbufs = list_new();
	ns->outbufs->cmp = (void *)netlink_buf_cmp;
	ns->outbufs->del = (void *)netlink_buf_del;
}

void dpd_socket_data_reset(const struct nlsock *nsc)
{
	static const char dplane_name[] = "netlink-dp";
	static const size_t dplane_name_len = sizeof(dplane_name) - 1;
	struct nlsock *ns = (struct nlsock *)nsc;
	struct nlbuf *nb;

	/* Create new socket. */
	close(ns->sock);
	ns->sock = dpd_socket();

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
		thread_execute(zrouter.master, user_netlink_event_cb, ns,
			       UNE_SYNC_INTERFACES);
}

int dpd_socket(void)
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
			zlog_err("Failure to create netlink socket");
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
				if (errno_copy != ECONNREFUSED
				    && errno_copy != ECONNRESET)
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
		if (uns.addr.sa.sa_family != AF_UNIX
		    && setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on))
			       == -1)
			flog_err_sys(EC_LIB_SOCKET,
				     "%s: setsockopt(TCP_NODELAY): %s",
				     __func__, safe_strerror(errno));
	}

	return sd;
}

void kernel_init(struct zebra_ns *zns)
{
	/* Initialize data structure. */
	snprintf(zns->netlink_cmd.name, sizeof(zns->netlink_cmd.name),
		 "netlink-user (NS %u)", zns->ns_id);

	/* Start listening/using it. */
	dpd_socket_data(zns, &zns->netlink);
	zns->netlink.sock = dpd_socket();
	zns->t_netlink = NULL;
	zns->t_netlinkout = NULL;
	netlink_poll_read(zns, 1);

	/* Data plane netlink-connection. */
	snprintf(zns->netlink.name, sizeof(zns->netlink.name),
		 "netlink-dp (NS %u)", zns->ns_id);
	dpd_socket_data(zns, &zns->netlink);

	rt_netlink_init();
}

void kernel_terminate(struct zebra_ns *zns, bool complete)
{
	THREAD_OFF(zns->t_netlink);
	THREAD_OFF(zns->t_netlinkout);

	if (zns->netlink.sock >= 0) {
		close(zns->netlink.sock);
		zns->netlink.sock = -1;
	}

	/* During zebra shutdown, we need to leave the dataplane socket
	 * around until all work is done.
	 */
	if (complete) {
		if (zns->netlink_dplane.sock >= 0) {
			close(zns->netlink_dplane.sock);
			zns->netlink_dplane.sock = -1;
		}
	}
}

int kernel_read(struct thread *thread)
{
	struct zebra_ns *zns = (struct zebra_ns *)THREAD_ARG(thread);
	struct zebra_dplane_info dp_info;

	/* Capture key info from ns struct */
	zebra_dplane_info_from_zns(&dp_info, zns, false);

	netlink_parse_info(netlink_information_fetch, &zns->netlink, &dp_info,
			   5, 0);
	netlink_poll_read(zns, 1);

	return 0;
}

int kernel_write(struct thread *thread)
{
	struct zebra_ns *zns = (struct zebra_ns *)THREAD_ARG(thread);
	struct zebra_dplane_info dp_info;

	/* Capture key info from ns struct */
	zebra_dplane_info_from_zns(&dp_info, zns, false);

	/* Send all remaining data. */
	netlink_send(&zns->netlink);

	return 0;
}

ssize_t netlink_send_msg(struct nlsock *ns, const void *buf, size_t buflen)
{
	ssize_t wlen = 0;

	/* Enqueue buffer to send. */
	netlink_buf_enqueue(ns->outbufs, ++ns->seq, buf, buflen);

	/* Flush the netlink buffer. */
	while ((wlen = netlink_send(ns)) != 0) {
		/* Connection failed/closed. */
		if (wlen == -1)
			return -1;
	}

	return wlen;
}

int netlink_request(struct nlsock *ns, void *msg)
{
	ssize_t wlen = 0;
	struct nlmsghdr *nlmsg = msg;

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
	while ((wlen = netlink_send(ns)) != 0) {
		/* Connection failed/closed. */
		if (wlen == -1)
			return -1;
	}

	return 0;
}

int netlink_parse_info(int (*filter)(struct nlmsghdr *, ns_id_t, int),
		       const struct nlsock *ns,
		       const struct zebra_dplane_info *zns
		       __attribute__((__unused__)),
		       int count __attribute__((__unused__)), int stup)
{
	struct listnode *ln, *lnn;
	struct nlmsghdr *nlmsg;
	struct nlbuf *nb;
	size_t nlmsglen;
	ssize_t rlen;
	int ret = 0, attempts = 10;
	bool found = false;

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
	if (filter != netlink_information_fetch)
		netlink_wait(ns, POLLIN, 1000);

	/* Receive all pending messages. */
	while ((rlen = netlink_recv(ns)) != 0) {
		/* Connection failed/closed. */
		if (rlen == -1)
			return -1;
	}

	/* Handle notifications. */
	netlink_parse_notify(ns);

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

		found = true;
		nlmsglen = nb->nb_datasiz;
		for (nlmsg = (struct nlmsghdr *)nb->nb_data;
		     NLMSG_OK(nlmsg, nlmsglen);
		     nlmsg = NLMSG_NEXT(nlmsg, nlmsglen)) {
			/* Skip done messages to avoid errors. */
			if (nlmsg->nlmsg_type == NLMSG_DONE)
				continue;

			ret = filter(nlmsg, ns->zns->ns_id, stup);
		}

		listnode_delete(ns->inbufs, nb);
		netlink_buf_del(nb);
	}

	/*
	 * If we are expecting an answer back, then attempt to get an
	 * answer or notify message loss.
	 */
	if (found == false && filter != netlink_information_fetch) {
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

void netlink_parse_notify(const struct nlsock *ns)
{
	struct listnode *ln, *lnn;
	struct nlmsghdr *nlmsg;
	struct nlbuf *nb;
	size_t nlmsglen;

	/* Iterate over all received messages and process notifications. */
	for (ALL_LIST_ELEMENTS(ns->inbufs, ln, lnn, nb)) {
		/* Skip responses. */
		if (nb->nb_seq != 0)
			continue;

		/* Handle notifications. */
		nlmsglen = nb->nb_datasiz;
		for (nlmsg = (struct nlmsghdr *)nb->nb_data;
		     NLMSG_OK(nlmsg, nlmsglen);
		     nlmsg = NLMSG_NEXT(nlmsg, nlmsglen)) {
			/* Skip done messages to avoid errors. */
			if (nlmsg->nlmsg_type == NLMSG_DONE)
				continue;

			netlink_information_fetch(nlmsg, ns->zns->ns_id, 0);
		}

		/* Remove the notification from the queue. */
		listnode_delete(ns->inbufs, nb);
		netlink_buf_del(nb);
	}
}

int netlink_talk_info(int (*filter)(struct nlmsghdr *, ns_id_t, int startup),
		      struct nlmsghdr *nlmsg, struct zebra_dplane_info *dp_info,
		      int startup)
{
	struct nlsock *ns = &dp_info->nls;
	ssize_t wlen = 0;

	/* Prepare netlink message. */
	nlmsg->nlmsg_pid = ns->snl.nl_pid;

	/*
	 * Messages that don't expect answer back should use
	 * notification request number.
	 *
	 * This should imitate the old behavior of having a second
	 * socket listening for this events.
	 */
	if (filter != netlink_talk_filter)
		nlmsg->nlmsg_seq = ++ns->seq;
	else
		nlmsg->nlmsg_seq = 0;

	/* Save the sequence number we expect back. */
	ns->lastseq = nlmsg->nlmsg_seq;

	/* Enqueue buffer to send. */
	netlink_buf_enqueue(ns->outbufs, nlmsg->nlmsg_seq, nlmsg,
			    nlmsg->nlmsg_len);

	/* Flush the netlink buffer. */
	while ((wlen = netlink_send(ns)) != 0) {
		/* Connection failed/closed. */
		if (wlen == -1)
			return -1;
	}

	if (filter == netlink_talk_filter) {
		/* In userspace netlink operation, we must process the answer as
		 * an update, instead of ignoring it. */
		filter = netlink_information_fetch;
	}

	/* Expect answer back. */
	return netlink_parse_info(filter, ns, NULL, 1, startup);
}

int netlink_talk(int (*filter)(struct nlmsghdr *, ns_id_t, int startup),
		 struct nlmsghdr *n, struct nlsock *nl, struct zebra_ns *zns,
		 int startup)
{
	struct zebra_dplane_info dp_info;

	/* Capture info in intermediate info struct. */
	zebra_dplane_info_from_zns(&dp_info, zns, (nl == &(zns->netlink_cmd)));

	return netlink_talk_info(filter, n, &dp_info, startup);
}


/*
 * Local helper functions.
 */
ssize_t netlink_recv(const struct nlsock *ns)
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
		dpd_socket_data_reset(ns);
		return 0;
	}
	if (rlen == 0) {
		flog_err_sys(EC_LIB_SOCKET, "%s recv: EOF", ns->name);
		dpd_socket_data_reset(ns);
		return 0;
	}

nl_next:
	/* Get next message. */
	nlmsg = netlink_nextmsg(&ns->nsbuf->data[ns->nsbuf->getp],
				STREAM_READABLE(ns->nsbuf), &mlen, &seq, &id);
	if (nlmsg == NULL)
		return rtotal;

	/* Advance buffer pointer. */
	stream_forward_getp(ns->nsbuf, mlen);
	rtotal += mlen;

	/* Validate incoming data. */
	if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV) {
		zlog_debug("%s: << netlink message dump [recv]", __func__);
		zlog_hexdump(nlmsg, mlen);
	}

	/* Check for errors. */
	if (nlmsg->nlmsg_type == NLMSG_ERROR
	    && nlmsg_parse_err(ns, nlmsg, mlen) == 0) {
		flog_err_sys(EC_LIB_SOCKET, "%s: found error", __func__);
		goto nl_next;
	}

	/* OK we got netlink message. */
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: %s type %s(%u), len=%d, seq=%u, pid=%u",
			   __func__, ns->name,
			   nl_msg_type_to_str(nlmsg->nlmsg_type),
			   nlmsg->nlmsg_type, nlmsg->nlmsg_len,
			   nlmsg->nlmsg_seq, nlmsg->nlmsg_pid);

	/* Enqueue it so the answer can be found. */
	netlink_buf_enqueue(ns->inbufs, seq, nlmsg, mlen);

	goto nl_next;
}

ssize_t netlink_send(struct nlsock *ns)
{
	struct nlbuf *nb;
	size_t wtotal = 0;
	ssize_t wlen;

dequeue_buf:
	nb = listnode_head(ns->outbufs);
	/* No data to send. */
	if (nb == NULL) {
		netlink_poll_write(ns->zns, 0);
		return wtotal;
	}

	/* Wait to be ready to write. */
	netlink_wait(ns, POLLOUT, 1000);

	/* Send data and empty buffer. */
	wlen = send(ns->sock, nb->nb_data + nb->nb_dataoff,
		    nb->nb_datasiz - nb->nb_dataoff, MSG_DONTWAIT);
	if (wlen == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			netlink_poll_write(ns->zns, 1);
			return wtotal;
		}

		flog_err(EC_ZEBRA_RECVMSG_OVERRUN, "%s send overrun: %s",
			 ns->name, safe_strerror(errno));
		return -1;
	}
	if (wlen == 0) {
		flog_err_sys(EC_LIB_SOCKET, "%s send: EOF", ns->name);
		dpd_socket_data_reset(ns);
		return 0;
	}

	wtotal += wlen;
	nb->nb_dataoff += wlen;
	/* If we emptied the buffer, then get rid of it. */
	if (nb->nb_dataoff == nb->nb_datasiz) {
		listnode_delete(ns->outbufs, nb);
		netlink_buf_del(nb);
	}

	goto dequeue_buf;
}

int netlink_wait(const struct nlsock *ns, int event, int timeout)
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

struct nlmsghdr *netlink_nextmsg(void *nlmsgp, size_t mtotal, size_t *mlen,
				 uint32_t *seq, uint32_t *id)
{
	struct nlmsghdr *nlmsg = nlmsgp;

	/* Initialize return values. */
	*mlen = 0;
	*seq = 0;
	*id = 0;

	/* Validate message size. */
	if (mtotal < sizeof(struct nlmsghdr)
	    || NLMSG_ALIGN(nlmsg->nlmsg_len) > mtotal)
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

int nlmsg_parse_err(const struct nlsock *ns, struct nlmsghdr *nlmsg,
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
	if ((nlmsg->nlmsg_type == RTM_DELROUTE
	     && (-err->error == ENODEV || -err->error == ESRCH))
	    || (nlmsg->nlmsg_type == RTM_NEWROUTE
		&& (-err->error == ENETDOWN || -err->error == EEXIST))) {
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
	if (nlmsg->nlmsg_type == RTM_DELNEIGH
	    || (nlmsg->nlmsg_type == RTM_NEWROUTE
		&& (-err->error == ESRCH || -err->error == ENETUNREACH))) {
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

void netlink_poll_read(struct zebra_ns *zns, int enabled)
{
	THREAD_OFF(zns->t_netlink);
	if (!enabled)
		return;

	thread_add_read(zrouter.master, kernel_read, zns, zns->netlink.sock,
			&zns->t_netlink);
}

void netlink_poll_write(struct zebra_ns *zns, int enabled)
{
	THREAD_OFF(zns->t_netlinkout);
	if (!enabled)
		return;

	thread_add_read(zrouter.master, kernel_write, zns, zns->netlink.sock,
			&zns->t_netlinkout);
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

void stream_pulldown(struct stream *s)
{
	size_t rlen = STREAM_READABLE(s);

	/* No more data, so just move the pointers. */
	if (rlen == 0) {
		s->endp = s->getp = 0;
		return;
	}

	/* Move the available data to the beginning. */
	memmove(s->data, &s->data[s->getp], rlen);
	s->getp = 0;
	s->endp -= rlen;
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
		if (re->type != ZEBRA_ROUTE_KERNEL
		    && re->type != ZEBRA_ROUTE_STATIC
		    && re->type != ZEBRA_ROUTE_SYSTEM)
			continue;

		SET_FLAG(re->flags, ZEBRA_FLAG_SYNC);
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
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SYNC) == 0)
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
				if_delete_update(ifp);
		}
	} while (vrf_id_get_next(vrf_id, &vrf_id));
}

int user_netlink_event_cb(struct thread *t)
{
	enum user_netlink_event une = THREAD_VAL(t);
	struct nlsock *ns = THREAD_ARG(t);

	switch (une) {
	case UNE_SYNC_INTERFACES:
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
			thread_execute(zrouter.master, user_netlink_event_cb,
				       ns, UNE_SYNC_ROUTES);

		/*
		 * Interfaces will get deselected with the sync flag
		 * when the netlink interface handling procedure
		 * update the interface flags.
		 */
		if_delete_selected();
		break;

	case UNE_SYNC_ROUTES:
		/* Routes will be unselected when incoming from data plane. */
		netlink_route_read(ns->zns);

		/* Delete still marked routes. */
		rib_delete_selected();
		break;

	default:
		break;
	}

	return 0;
}

#endif /* NETLINK_PROXY */
