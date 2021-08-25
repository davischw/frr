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

#ifndef _RIP_SOUTHBOUND_
#define _RIP_SOUTHBOUND_

#define RIP_SOUTHBOUND

#define RIPSB_PORT_DEFAULT 5200

int ripsb_create_socket(struct vrf *vrf);
int ripsb_read(struct thread *t);
int ripsb_send_packet(uint8_t *buf, int size, struct sockaddr_in *to,
		      struct connected *ifc);

void ripsb_init(void);

#endif /* _RIP_SOUTHBOUND_ */
