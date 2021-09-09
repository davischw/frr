/*
 * PIM southbound implementation.
 *
 * Copyright (C) 2021 Network Education Foundation
 *                    Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _PIM_SOUTHBOUND_
#define _PIM_SOUTHBOUND_

#include <netinet/in.h>

#include <stdint.h>

#define PIM_SOUTHBOUND

/** Default TCP listening port. */
#define PIMSB_DEFAULT_PORT 2650

/** pimreg interface index value for southbound. */
#define PIM_REG_IF_IDX 0x7FFF0000

/*
 * PIM southbound.
 */
enum multicast_event_type {
	MRT_EVENT_DATA_START,
	MRT_EVENT_DATA_STOP,
	MRT_EVENT_WRONG_IF,
	MRT_EVENT_JOIN_SPT,
	MRT_EVENT_DATA_PACKET,
};

/** PIM southbound message version. */
#define MRE_VERSION_V1 0x01

struct mroute_event_header {
	/** Protocol message version. */
	uint8_t version;
	/** Multicast route event. \see enum multicast_event_type. */
	uint8_t type;
	/** Message length. */
	uint16_t length;
};

struct mroute_event {
	/** Event header. */
	struct mroute_event_header header;
	/** Event flags. \see MRE_FLAG_* definitions. */
	uint32_t flags;
	/** Input interface index. */
	int32_t iif_idx;
	/** Source address. */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} source;
	/** Group address. */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} group;
};


/*
 * FPM southbound.
 */
/** Tell data plane that SPT switch over is allowed. */
#define MRT_FLAG_JOIN_SPT_ALLOWED 0x0001
/** Ask data plane to tell us when the data flow stops. */
#define MRT_FLAG_RESTART_DL_TIMER 0x0002
/** Blackhole multicast packets. */
#define MRT_FLAG_DUMMY 0x0020
/** Used with dummy to remove blackhole after a time. */
#define MRT_FLAG_DL_TIMER 0x0040

struct pimsb_mroute_args {
	struct channel_oil *oil;
	struct mfcctl *mfcc;
	union {
		struct in_addr v4;
		struct in_addr v6;
	} local;
	union {
		struct in_addr v4;
		struct in_addr v6;
	} remote;
};

/*
 * PIM southbound.
 */

/** Send PIM packet parameters. */
struct pimsb_pim_args {
	/** Source address. */
	uint32_t source;
	/** Destination address. */
	uint32_t destination;
	/** Selected interface. */
	int32_t ifindex;

	/** Data pointer. */
	uint8_t *data;
	/** Data amount. */
	size_t datalen;
};

void pimsb_packet_read(int sock);
ssize_t pimsb_igmp_sendto(const char *ifname, const void *data, size_t datalen,
			  struct sockaddr *sa, socklen_t salen);
void pimsb_igmp_join(struct interface *ifp, struct in_addr *source,
		     struct in_addr *group);
void pimsb_igmp_leave(struct interface *ifp, struct in_addr *source,
		      struct in_addr *group);
bool pimsb_igmp_sg_is_static(const struct igmp_source *source,
			     const struct igmp_group *group);

int pim_socket_mcast(int protocol, struct in_addr ifaddr, struct interface *ifp,
		     uint8_t loop);
int pimsb_msg_send_frame(const struct pimsb_pim_args *args);

void pimsb_init(struct zclient *zc);
void pimsb_shutdown(void);

void pimsb_socket_parse(const char *arg);

void pimsb_show_state(struct vty *vty, struct pim_instance *pim,
		      const char *src_grp, const char *grp, bool json_output);
void pimsb_show_mroute(struct vty *vty, struct pim_instance *pim,
		       struct prefix_sg *sg, bool fill, bool json);

void pimsb_set_input_interface(struct channel_oil *oil);
void pimsb_mroute_do(const struct channel_oil *oil, bool install);

#endif /* _PIM_SOUTHBOUND_ */
