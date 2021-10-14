/*
 * RIP BFD integration.
 *
 * Copyright (C) 2021 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
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

#ifndef _RIP_BFD_
#define _RIP_BFD_

#include "thread.h"

struct rip;
struct rip_interface;
struct rip_peer;

void rip_bfd_session_update(struct rip_peer *rp);
void rip_bfd_interface_update(struct rip_interface *ri);
void rip_bfd_instance_update(struct rip *rip);
void rip_bfd_init(struct thread_master *tm);

#endif /* _RIP_BFD_ */
