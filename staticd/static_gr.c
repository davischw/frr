// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Static graceful restart code.
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 *               David Schweizer
 */


#include "lib/vrf.h"
#include "lib/zclient.h"

#include "static_gr.h"


void static_send_zebra_gr_cap(struct zclient *zclient, vrf_id_t vrf_id)
{
	struct zapi_cap api;

	api.cap = ZEBRA_CLIENT_GR_CAPABILITIES;
	api.stale_removal_time = STATIC_DEFAULT_GR_STALE_TIME;
	api.vrf_id = vrf_id;
	
	if (zclient_capabilities_send(ZEBRA_CLIENT_CAPABILITIES, zclient, &api)
	    == ZCLIENT_SEND_FAILURE) {
		zlog_err("Failure to send GR capability to zebra for vrf_id %d", vrf_id);
	} else {
		zlog_info("Send GR capability to zebra was successful for vrf_id %d", vrf_id);
	}
}


/* EOF */
