/*
 * Address list CLI implementation.
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

#include "lib/command.h"
#include "lib/address_list.h"
#include "lib/northbound_cli.h"

#define ADDR_LIST_STR "Address-list related command\n"
#define ADDR_LIST_NAME_STR "Address-list name\n"
#define ADDR_STR "Address\n"
#define ADDR_VALUE_STR "Address value\n"
#define SEQUENCE_STR "Address entry usage sequence number\n"
#define SEQUENCE_VALUE_STR                                                     \
	"Sequence number (lower the number higher the priority)\n"

#ifndef VTYSH_EXTRACT_PL
#include "lib/address_list_cli_clippy.c"
#endif /* VTYSH_EXTRACT_PL */

/*
 * Helper functions.
 */
static int address_entry_next_cb(const struct lyd_node *dnode, void *arg)
{
	uint32_t *seqp = arg;
	uint32_t cur_seq = yang_dnode_get_uint32(dnode, "./sequence");

	if (cur_seq > *seqp)
		*seqp = cur_seq;

	return YANG_ITER_CONTINUE;
}

static uint32_t address_entry_get_next_sequence(struct vty *vty,
						const char *xpath)
{
	uint32_t seq = 0;

	yang_dnode_iterate(address_entry_next_cb, &seq,
			   vty->candidate_config->dnode, "%s/addresses", xpath);

	return seq + 10;
}

/*
 * Commands.
 */
DEFPY(address_list_new, address_list_new_cmd,
      "[no] address-list WORD$name",
      NO_STR
      ADDR_LIST_STR
      ADDR_LIST_NAME_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-address-list:lib/address-list[name='%s']", name);
	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void address_list_show(struct vty *vty, struct lyd_node *dnode,
		       bool show_defaults)
{
	vty_out(vty, "address-list %s\n",
		yang_dnode_get_string(dnode, "./name"));
}

DEFPY(address_list_append, address_list_append_cmd,
      "address-list WORD$name address <A.B.C.D|X:X::X:X>$addr [sequence (1-4294967295)$sequence]",
      ADDR_LIST_STR
      ADDR_LIST_NAME_STR
      ADDR_STR
      IP_STR
      IPV6_STR
      SEQUENCE_STR
      SEQUENCE_VALUE_STR)
{
	char xpath[XPATH_MAXLEN], xpath_full[XPATH_MAXLEN];
	char nsequence_str[32];
	uint32_t seq;

	/* Address list might not exist yet. */
	snprintf(xpath_full, sizeof(xpath_full),
		 "/frr-address-list:lib/address-list[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath_full, NB_OP_CREATE, NULL);

	/* Create the address entry. */
	strlcpy(xpath, xpath_full, sizeof(xpath));
	strlcat(xpath, "/addresses[address='", sizeof(xpath));
	strlcat(xpath, addr_str, sizeof(xpath));
	strlcat(xpath, "']", sizeof(xpath));
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	/* Set the sequence (if specified). */
	strlcat(xpath, "/sequence", sizeof(xpath));
	if (sequence_str == NULL) {
		seq = address_entry_get_next_sequence(vty, xpath_full);
		snprintf(nsequence_str, sizeof(nsequence_str), "%u", seq);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, nsequence_str);
	} else
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, sequence_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(address_list_remove_entry, address_list_remove_entry_cmd,
      "no address-list WORD$name address <A.B.C.D|X:X::X:X>$addr",
      NO_STR
      ADDR_LIST_STR
      ADDR_LIST_NAME_STR
      ADDR_STR
      IP_STR
      IPV6_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(
		xpath, sizeof(xpath),
		"/frr-address-list:lib/address-list[name='%s']/addresses[address='%s']",
		name, addr_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(address_list_show_state, address_list_show_state_cmd,
      "show address-list WORD$name",
      SHOW_STR
      ADDR_LIST_STR
      ADDR_LIST_NAME_STR)
{
	struct address_list *al;
	struct address_entry *ae, *ae_active;

	al = address_list_lookup(name);
	if (al == NULL) {
		vty_out(vty, "No address list name '%s'.\n", name);
		return CMD_SUCCESS;
	}

	/* Find the active entry. */
	ae_active = address_list_get_next(al);

	vty_out(vty, "%s:\n", name);
	TAILQ_FOREACH (ae, &al->al_list, ae_entry) {
		switch (ae->ae_ip.ipa_type) {
		case IPADDR_V4:
			vty_out(vty, "  %pI4", &ae->ae_ip.ip._v4_addr);
			break;
		case IPADDR_V6:
			vty_out(vty, "  %pI6", &ae->ae_ip.ip._v6_addr);
			break;
		default:
			vty_out(vty, "  Unknown address (type %d)",
				ae->ae_ip.ipa_type);
			break;
		}

		vty_out(vty, " (sequence %u)", ae->ae_sequence);
		if (ae == ae_active)
			vty_out(vty, " <ACTIVE>");

		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

void address_list_cli_init(void)
{
	install_element(ENABLE_NODE, &address_list_show_state_cmd);

	install_element(CONFIG_NODE, &address_list_new_cmd);
	install_element(CONFIG_NODE, &address_list_append_cmd);
	install_element(CONFIG_NODE, &address_list_remove_entry_cmd);
}
