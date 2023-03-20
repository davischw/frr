#include <zebra.h>

#include "lib/command.h"
#include "lib/address_alias.h"
#include "lib/northbound_cli.h"

#define ADDR_ALIAS_STR "Address-alias related command\n"
#define ADDR_ALIAS_NAME_STR "Address-alias name\n"
#define ADDR_STR "Address\n"
#define ADDR_VALUE_STR "Address value\n"

#include "lib/address_alias_cli_clippy.c"

DEFPY(address_alias_new, address_alias_new_cmd,
      "[no] address-alias WORD$name",
      NO_STR
      ADDR_ALIAS_STR
      ADDR_ALIAS_NAME_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-address-alias:lib/address-alias[name='%s']", name);

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void address_alias_show(struct vty *vty, const struct lyd_node *dnode,
		       bool show_defaults)
{
	vty_out(vty, "address-alias %s\n",
		yang_dnode_get_string(dnode, "./name"));
}


void address_alias_address_show(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	/* TODO: implement proper address leaf display */
	vty_out(vty, "address-alias %s address [A.B.C.D|X:X::X:X]\n",
		yang_dnode_get_string(dnode, "./address"));
}


DEFPY(address_alias_show_state, address_alias_show_state_cmd,
      "show address-alias WORD$name",
      SHOW_STR
      ADDR_ALIAS_STR
      ADDR_ALIAS_NAME_STR)
{
	struct address_alias *aa = NULL;

	aa = address_alias_lookup(name);
	if (aa == NULL) {
		vty_out(vty, "No address-alias with name '%s' found.\n", name);
		return CMD_SUCCESS;
	}

	/* TODO: implement address init */
	/*
	if (aa->aa_ip)
		switch(aa->aa_ip.ipa_type) {
		case IPADDR_V4 :
			vty_out(vty, "%s: %pI4\n", aa->aa_name,
				&aa->aa_ip.ip._v4_addr);
			break;
		case IPADDR_V6 :
			vty_out(vty, "%s: %pI6\n", aa->aa_name,
				&aa->aa_ip.ip._v6_addr);
			break;
		default :
			vty_out(vty, "%s: Unknown address (type %d)\n",
				aa->aa_name, aa->aa_ip.ipa_type);
		}
	else
		vty_out(vty, "%s: Uninitialized address\n", aa->aa_name);
	*/
	vty_out(vty, "%s: Uninitialized address\n", aa->aa_name);

	return CMD_SUCCESS;
}

void address_alias_cli_init(void)
{
	install_element(ENABLE_NODE, &address_alias_show_state_cmd);
	install_element(CONFIG_NODE, &address_alias_new_cmd);
}
