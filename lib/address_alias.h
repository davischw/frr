/*
 * Address alias implementation.
 *
 * Copyright (C) 2020 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael F. Zalamena
 *                    David U. Schweizer
 */

#ifndef _ADDRESS_ALIAS_
#define _ADDRESS_ALIAS_

#include "netinet/in.h"

#include "lib/hook.h"
#include "lib/ipaddr.h"
#include "lib/ipaddr.h"

#define ADDRESS_ALIAS_NAME_LONGEST 64

struct address_alias {
	char aa_name[ADDRESS_ALIAS_NAME_LONGEST];
	struct ipaddr aa_ip;
	TAILQ_ENTRY(address_alias) aa_entry;
};

struct address_alias *address_alias_lookup(const char *name);

extern const struct frr_yang_module_info frr_address_alias_info;

struct vty;
struct lyd_node;

void address_alias_show(struct vty *vty, const struct lyd_node *dnode,
			bool show_defaults);
void address_alias_address_show(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);

void address_alias_cli_init(void);

#endif /* _ADDRESS_ALIAS_ */

