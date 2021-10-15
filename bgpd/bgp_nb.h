/*
 * BGP northbound implementation.
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

#ifndef BGPD_NB
#define BGPD_NB

struct bgp;

/* Definitions. */
#define BGP_NB_INSTANCE_XPATH "/frr-bgpd:bgpd/instance[vrf='%s']"

/* Functions. */
void bgp_nb_add_instance(struct bgp *bgp);
void bgp_nb_del_instance(struct bgp *bgp);

void bgp_nb_init(void);

/* Northbound callbacks. */
extern const struct frr_yang_module_info frr_bgpd_info;

#endif /* BGPD_NB */
