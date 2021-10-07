/*
 * OSPFv2 northbound implementation.
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

#ifndef OSPFD_NB
#define OSPFD_NB

/* Definitions. */
#define OSPF_NB_INSTANCE_XPATH "/frr-ospf:ospf/instance[vrf='%s'][id='%d']"
#define OSPF_NB_AREA_XPATH OSPF_NB_INSTANCE_XPATH "/area[id='%pI4']"
#define OSPF_NB_INTERFACE_XPATH OSPF_NB_AREA_XPATH "/interface[name='%s']"
#define OSPF_NB_NEIGHBOR_XPATH                                                 \
	OSPF_NB_INTERFACE_XPATH "/neighbor[router-id='%pI4']"

/* Functions. */
void ospf_nb_add_instance(struct ospf *o);
void ospf_nb_del_instance(struct ospf *o);
void ospf_nb_add_area(struct ospf_area *area);
void ospf_nb_del_area(struct ospf_area *area);
void ospf_nb_add_interface(struct ospf_interface *oif);
void ospf_nb_del_interface(struct ospf_interface *oif);
void ospf_nb_add_neighbor(struct ospf_neighbor *on);
void ospf_nb_del_neighbor(struct ospf_neighbor *on);

void ospf_nb_init(void);

/* Northbound callbacks. */
extern const struct frr_yang_module_info frr_ospf_info;

#endif /* OSPFD_NB */
