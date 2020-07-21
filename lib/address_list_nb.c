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

#include <zebra.h>

#include "lib/northbound.h"
#include "lib/address_list.h"

DEFINE_MTYPE_STATIC(LIB, ADDRESS_LIST, "Address list head");
DEFINE_MTYPE_STATIC(LIB, ADDRESS_LIST_ENTRY, "Address list entry");

/*
 * Definitions and prototypes.
 */
DEFINE_HOOK(address_entry_next,
	    (const struct address_list *al, const struct address_entry *ae),
	    (al, ae));
DEFINE_HOOK(address_entry_added,
	    (const struct address_list *al, const struct address_entry *ae),
	    (al, ae));
DEFINE_HOOK(address_entry_deleted,
	    (const struct address_list *al, const struct address_entry *ae),
	    (al, ae));

TAILQ_HEAD(, address_list) al_list = TAILQ_HEAD_INITIALIZER(al_list);

static void address_list_update_selection(struct address_list *al);


/*
 * Address list implementation.
 */
static struct address_entry *address_entry_new(struct address_list *al)
{
	struct address_entry *ae;

	ae = XCALLOC(MTYPE_ADDRESS_LIST_ENTRY, sizeof(*ae));
	ae->ae_al = al;
	TAILQ_INSERT_TAIL(&al->al_list, ae, ae_entry);

	return ae;
}

static void address_entry_free(struct address_entry **ae)
{
	if ((*ae) == NULL)
		return;

	/* Unlink so next update doesn't select us. */
	TAILQ_REMOVE(&(*ae)->ae_al->al_list, (*ae), ae_entry);

	/* Notify listeners about deleted address. */
	hook_call(address_entry_deleted, (*ae)->ae_al, (*ae));

	/* Update current address entry selection. */
	address_list_update_selection((*ae)->ae_al);

	/* Free memory. */
	XFREE(MTYPE_ADDRESS_LIST_ENTRY, (*ae));
}

static struct address_list *address_list_new(const char *name)
{
	struct address_list *al;

	al = XCALLOC(MTYPE_ADDRESS_LIST, sizeof(*al));

	/* Copy the name. */
	strlcpy(al->al_name, name, sizeof(al->al_name));

	/* Initialize address entries list. */
	TAILQ_INIT(&al->al_list);

	/* Insert into global address-list list. */
	TAILQ_INSERT_TAIL(&al_list, al, al_entry);

	return al;
}

static void address_list_free(struct address_list **al)
{
	struct address_entry *ae;

	if ((*al) == NULL)
		return;

	/* Remove this list from global list. */
	TAILQ_REMOVE(&al_list, (*al), al_entry);

	/* Free all other entries before the list itself (if any). */
	while ((ae = TAILQ_FIRST(&(*al)->al_list)) != NULL)
		address_entry_free(&ae);

	/* Free resources. */
	XFREE(MTYPE_ADDRESS_LIST, (*al));
}

struct address_list *address_list_lookup(const char *name)
{
	struct address_list *al;

	TAILQ_FOREACH (al, &al_list, al_entry) {
		if (strcmp(al->al_name, name))
			continue;

		return al;
	}

	return NULL;
}

struct address_entry *address_list_get_next(struct address_list *al)
{
	struct address_entry *ae, *ae_lowest;

	/* Boot strap sequence. */
	ae_lowest = TAILQ_FIRST(&al->al_list);

	/* Find the lowest sequence number. */
	TAILQ_FOREACH (ae, &al->al_list, ae_entry) {
		if (ae_lowest->ae_sequence <= ae->ae_sequence)
			continue;

		ae_lowest = ae;
	}

	return ae_lowest;
}

static void address_list_update_selection(struct address_list *al)
{
	struct address_entry *ae_cur;

	ae_cur = al->al_selected;
	al->al_selected = address_list_get_next(al);

	/* Selected entry changed, notify listeners. */
	if (ae_cur != al->al_selected)
		hook_call(address_entry_next, al, al->al_selected);
}


/*
 * XPath: /frr-address-list:lib/address-list
 */
static int lib_address_list_create(struct nb_cb_create_args *args)
{
	struct address_list *al;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	al = address_list_new(yang_dnode_get_string(args->dnode, "./name"));
	nb_running_set_entry(args->dnode, al);

	return NB_OK;
}

static int lib_address_list_destroy(struct nb_cb_destroy_args *args)
{
	struct address_list *al;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	al = nb_running_unset_entry(args->dnode);
	address_list_free(&al);

	return NB_OK;
}

/*
 * XPath: /frr-address-list:lib/address-list/addresses
 */
static int lib_address_list_addresses_create(struct nb_cb_create_args *args)
{
	struct address_entry *ae;
	struct address_list *al;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	al = nb_running_get_entry(args->dnode, NULL, true);
	ae = address_entry_new(al);
	yang_dnode_get_ip(&ae->ae_ip, args->dnode, "./address");
	ae->ae_sequence = yang_dnode_get_uint32(args->dnode, "./sequence");
	nb_running_set_entry(args->dnode, ae);

	/* Update current address entry selection. */
	address_list_update_selection(al);

	/* Notify listeners about new address. */
	hook_call(address_entry_added, al, ae);

	return NB_OK;
}

static int lib_address_list_addresses_destroy(struct nb_cb_destroy_args *args)
{
	struct address_entry *ae;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ae = nb_running_unset_entry(args->dnode);
	address_entry_free(&ae);

	return NB_OK;
}

/*
 * XPath: /frr-address-list:lib/address-list/addresses/sequence
 */
static int
lib_address_list_addresses_sequence_modify(struct nb_cb_modify_args *args)
{
	struct address_entry *ae;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Update this entry sequence number. */
	ae = nb_running_get_entry(args->dnode, NULL, true);
	ae->ae_sequence = yang_dnode_get_uint32(args->dnode, NULL);

	/* Update current address entry selection. */
	address_list_update_selection(ae->ae_al);

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_address_list_info = {
	.name = "frr-address-list",
	.nodes = {
		{
			.xpath = "/frr-address-list:lib/address-list",
			.cbs = {
				.create = lib_address_list_create,
				.destroy = lib_address_list_destroy,
				.cli_show = address_list_show,
			}
		},
		{
			.xpath = "/frr-address-list:lib/address-list/addresses",
			.cbs = {
				.create = lib_address_list_addresses_create,
				.destroy = lib_address_list_addresses_destroy,
			}
		},
		{
			.xpath = "/frr-address-list:lib/address-list/addresses/sequence",
			.cbs = {
				.modify = lib_address_list_addresses_sequence_modify,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
