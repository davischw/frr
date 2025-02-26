/*
 * RSVPd - vty example code.
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 *                    David Schweizer <dschweizer@netdef.org>
 */


#include <zebra.h>

#include "command.h"
#include "vty.h"

#include "rsvpd/rsvp_vty_example.h"
#include "rsvpd/rsvp_vty_example_clippy.c" /* Generated during build */


DEFPY (show_rsvp_dummy, show_rsvp_dummy_cmd,
       "show rsvp dummy",
       SHOW_STR
       RSVP_STR
       "Dummy\n")
{
	vty_out(vty, "dummy\n");

	return CMD_SUCCESS;
}


void rsvp_vty_example_init(void)
{
	install_element(ENABLE_NODE, &show_rsvp_dummy_cmd);
}


/* EOF */
