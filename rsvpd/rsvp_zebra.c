
// SPDX-License-Identifier: GPL-2.0-or-later


#include <zebra.h>

#include "frrevent.h"
#include "zclient.h"

#include "rsvpd/rsvpd.h"
#include "rsvpd/rsvp_zebra.h"


/* Zebra client information. */
static struct zclient *zclient = NULL;


/* Thread master. */
extern struct event_loop *master;


/* Privileges information. */
extern struct zebra_privs_t rsvp_privs;


/* Zebra client handlers. */
static zclient_handler *const rsvpd_handlers[] = {};


/* Initialize RSVP zebra client. */
void rsvp_zebra_init(void)
{
	zclient = zclient_new(master, &zclient_options_default, rsvpd_handlers,
			      array_size(rsvpd_handlers));

	zclient_init(zclient, ZEBRA_ROUTE_RSVP, 0, &rsvp_privs);
}


/* Terminate RSVP zebra client. */
void rsvp_zebra_terminate(void)
{
	zclient_stop(zclient);
	zclient_free(zclient);
}

