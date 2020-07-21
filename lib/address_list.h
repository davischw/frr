/*
 * Address list implementation.
 *
 * Copyright (C) 2020 Network Device Education Foundation, Inc. ("NetDEF")
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

#ifndef _ADDRESS_LIST_
#define _ADDRESS_LIST_

#include <netinet/in.h>

#include "lib/hook.h"
#include "lib/ipaddr.h"
#include "lib/openbsd-queue.h"

struct address_entry {
	/** The address. */
	struct ipaddr ae_ip;

	/** Sequence number. */
	uint32_t ae_sequence;

	/** Back pointer to list head. */
	struct address_list *ae_al;

	/** List entry. */
	TAILQ_ENTRY(address_entry) ae_entry;
};

/** Define the longest address list name length. */
#define ADDRESS_LIST_NAME_LONGEST 64

struct address_list {
	/** Address list name. */
	char al_name[ADDRESS_LIST_NAME_LONGEST];

	/** Currently selected entry (lower sequence number). */
	struct address_entry *al_selected;

	/** List head. */
	TAILQ_HEAD(, address_entry) al_list;

	/** List entry. */
	TAILQ_ENTRY(address_list) al_entry;
};

/*
 * New address entry with lower sequence was added or the previous one was
 * removed and is being replaced.
 *
 * If no new address entries, then `ae` will be `NULL`.
 */
DECLARE_HOOK(address_entry_next,
	     (const struct address_list *al, const struct address_entry *ae),
	     (al, ae));

/* New address entry added to address list.  */
DECLARE_HOOK(address_entry_added,
	     (const struct address_list *al, const struct address_entry *ae),
	     (al, ae));

/* Address entry removed from address list.  */
DECLARE_HOOK(address_entry_deleted,
	     (const struct address_list *al, const struct address_entry *ae),
	     (al, ae));


/* address_list_nb.c */
struct address_list *address_list_lookup(const char *name);
struct address_entry *address_list_get_next(struct address_list *al);

extern const struct frr_yang_module_info frr_address_list_info;

/* address_list_cli.c */
struct vty;
struct lyd_node;
void address_list_show(struct vty *vty, struct lyd_node *dnode,
		       bool show_defaults);

void address_list_cli_init(void);

#endif /* _ADDRESS_LIST_ */
