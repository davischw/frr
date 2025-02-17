/* TODO: license */
/*
 * LLDPd - vty code.
 * Copyright (c) 2016 zhurish
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 */


#include <zebra.h>

#include "command.h"
#include "vty.h"

#include "lldpd/lldp_interface.h"
#include "lldpd/lldp_vty.h"
#include "lldpd/lldp_vty_clippy.c"


/* TODO: remove dummy command after forward-port */
DEFPY (show_lldp_dummy, show_lldp_dummy_cmd,
      "show lldp dummy",
      SHOW_STR
      LLDP_STR
      "Dummy\n")
{
	vty_out(vty, "dummy\n");

	return CMD_SUCCESS;
}


DEFPY (show_lldp_interface, show_lldp_interface_cmd,
       "show lldp interface",
       SHOW_STR
       LLDP_STR
       "LLDP interface information\n")
{
	show_lldp_interface_all(vty);

	return CMD_SUCCESS;
}


void lldp_vty_init(void)
{
	install_element(ENABLE_NODE, &show_lldp_dummy_cmd);

	install_element(VIEW_NODE, &show_lldp_interface_cmd);
	install_element(ENABLE_NODE, &show_lldp_interface_cmd);
}


/* EOF */
