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

#ifndef OSPF_SOUTHBOUND_H
#define OSPF_SOUTHBOUND_H

/** User southbound related variables for OSPF instance. */
struct ospf_southbound {
	/** OSPF SPF socket. */
	int ie_spf_sock;
	/** OSPF SPF socket event. */
	struct thread *ie_spf_ev;

	/** OSPF DR socket. */
	int ie_dr_sock;
	/** OSPF DR socket events. */
	struct thread *ie_dr_ev;

	/* Authentication sequence number offset from time */
	uint32_t auth_seq_num_offset;
};

/* Forward declaration. */
struct interface;
struct ospf;
struct ospf_interface;
struct ospf_packet;

/** Enable and initialize user space southbound. */
void ospf_southbound_init(void);

/** Initialize per VRF southbound instance. */
void ospf_southbound_new(struct ospf *ospf);

/** Release per VRF southbound instance resources. */
void ospf_southbound_free(struct ospf *ospf);

/** Initialize per VRF southbound sockets. */
int ospf_southbound_sock_init(struct ospf *ospf);

/** Prepare OSPF southbound sockets for next read. */
void ospf_southbound_read_prepare(struct ospf *ospf, int fd);

/** Send packets in packet queue. */
void ospf_southbound_write(const struct ospf *ospf,
			   const struct ospf_interface *interface,
			   const struct ospf_packet *packet);

/** Read packet into buffer. */
struct stream *ospf_southbound_read(struct ospf *ospf, int sock,
				    struct interface **interface,
				    struct stream *stream);

extern bool ospf_southbound_enabled;

#endif /* OSPF_SOUTHBOUND_H */
