// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Static graceful restart code.
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 *               David Schweizer
 */


#include <zebra.h>

#include <stddef.h>

#include "lib/freebsd-queue.h"
#include "lib/vrf.h"
#include "lib/zclient.h"

#include "static_gr.h"


struct static_gr_info_queue gr_info_queue;


/* Function prototypes */
static struct static_gr_vrf_info *static_gr_vrf_info_new(void);
static void static_gr_vrf_info_delete(struct static_gr_vrf_info *gr_info);
static struct static_gr_vrf_info *static_gr_vrf_info_lookup(vrf_id_t vrf_id);
static int static_announce_zebra_gr_cap(struct static_gr_vrf_info *gr_info);

/* TODO: unused atm
static int static_update_zebra_gr_cap(struct static_gr_vrf_info *gr_info);
*/

static int static_revoke_zebra_gr_cap(struct static_gr_vrf_info *gr_info);

struct json_object *show_static_gr_vrf_info_json(struct static_gr_vrf_info *gr_info);
int show_static_gr_vrf_json(struct vty *vty, char* vrf_name);


int static_gr_init(void) {
	/* Initialize per VRF info queue */
	TAILQ_INIT(&gr_info_queue);

	return 0;
}


int static_gr_exit(void) {
	/* TODO: Iterate trough gr_info list, clean up elements
	while (!TAILQ_EMPTY(&q)) {
		gr_info = TAILQ_FIRST(&gr_info_queue);
		if (gr_info) {
			if (gr_info->)



		}

		TAILQ_REMOVE(&q, p, tailq);
	}
	*/

	return -1;
}


static struct static_gr_vrf_info *static_gr_vrf_info_new(void)
{
	struct static_gr_vrf_info *gr_info = NULL;

	/* TODO: memtype */
	gr_info = malloc(sizeof(struct static_gr_vrf_info));
	if (gr_info) {
		gr_info->enabled = false;
		gr_info->zclient = NULL;
		gr_info->vrf_id = 0; /* TODO: check for non-init value */
		gr_info->stale_removal_time_sec = STATIC_DEFAULT_GR_STALE_TIME;
		gr_info->grace_period_sec = STATIC_DEFAULT_GR_GRACE_PERIOD;
	}

	return gr_info;
}


void static_gr_vrf_info_delete(struct static_gr_vrf_info *gr_info)
{
	if (gr_info) {
		/* TODO: mtype/free */
		free(gr_info);
	}
}


static struct static_gr_vrf_info *static_gr_vrf_info_lookup(vrf_id_t vrf_id)
{
	struct static_gr_vrf_info *gr_info = NULL;
	struct static_gr_vrf_info *gr_info_cur = NULL;

	/* TODO: check VRF id validity */
	if (!vrf_id)
		return NULL;

	TAILQ_FOREACH(gr_info, &gr_info_queue, entries) {
		if (gr_info_cur->vrf_id == vrf_id) {
			gr_info = gr_info_cur;
			break;
		}
	}

	return gr_info;
}


static int static_announce_zebra_gr_cap(struct static_gr_vrf_info *gr_info)
{
	struct zapi_cap api;

	if (gr_info) {
		if (gr_info->init) {
			api.cap = ZEBRA_CLIENT_GR_CAPABILITIES;
			api.stale_removal_time = gr_info->stale_removal_time_sec;

			/* TODO: grace period
			api.grace_period = gr_info->grace_period_sec;
			*/

			api.vrf_id = gr_info->vrf_id;
	
			if (!(zclient_capabilities_send(ZEBRA_CLIENT_CAPABILITIES, gr_info->zclient, &api)
			    == ZCLIENT_SEND_FAILURE)) {
				zlog_info("Send GR capability to zebra was successful for vrf_id %d", gr_info->vrf_id);

				return 0;
			}

			zlog_err("Failure to send GR capability to zebra for vrf_id %d", gr_info->vrf_id);
		}
	}

	return -1;
}


/* TODO: needed to update stale time and grace period
 * unused atm
static int static_update_zebra_gr_cap(struct static_gr_vrf_info *gr_info)
{
	return -1;
}
*/


/* TODO: needed to disable static graceful-restart in zebra */
static int static_revoke_zebra_gr_cap(struct static_gr_vrf_info *gr_info)
{
	return -1;
}


int static_gr_vrf_enable(struct zclient *zclient, vrf_id_t vrf_id)
{
	struct static_gr_vrf_info *gr_info = NULL;
	
	/* TODO: check vrf_id validity */

	if (zclient) {
		gr_info = static_gr_vrf_info_lookup(vrf_id);
		if (!gr_info) {
			gr_info = static_gr_vrf_info_new();
			gr_info->zclient = zclient;
			gr_info->vrf_id = vrf_id;
			TAILQ_INSERT_HEAD(&gr_info_queue, gr_info, entries);
		}

		/* TODO: Updating zclient pointer for existing entries? */

		if (gr_info) {
			if (gr_info->enabled) {
				/* Already enabled */
				return 0;
			} else if (!static_announce_zebra_gr_cap(gr_info)) {
				gr_info->enabled = true;

				return 0;
			}
		}
	}

	return -1;
}


int static_gr_vrf_disable(vrf_id_t vrf_id)
{
	struct static_gr_vrf_info *gr_info = NULL;

	/* TODO: check vrf_id validity */

	gr_info = static_gr_vrf_info_lookup(vrf_id);
	if (gr_info) {
		if (gr_info->enabled) {
			if (!static_revoke_zebra_gr_cap(gr_info)) {
				gr_info->enabled = false;

				return 0;
			}
		}
	}

	return -1;
}


int show_static_gr_vrf(struct vty *vty, char* vrf_name);


struct json_object *show_static_gr_vrf_info_json(struct static_gr_vrf_info *gr_info)
{
	struct json_object *json = NULL;

	if (gr_info) {
		if (gr_info->init) {
			json = json_object_new_object(void);
			if (json) {
				json_object_int_add(json, "vrfId", gr_info->vrf_id);
				json_object_boolean_add(json, "enabled", gr_info->enabled);
				json_object_int_add(json, "staleRemovalTimeSeconds", gr_info->stale_removal_time_sec);
				json_object_int_add(json, "gracePeriodSeconds", gr_info->grace_period_sec);
			}
		}
	}

	return json;
}


int show_static_gr_vrf_json(struct vty *vty, char* vrf_name)
{
	/* TODO: Implement */

	return -1;
}


/* TODO:
int show_static_gr_vrf_all_json(struct vty *vty)
{
	if (vty) {
		if (vrf
*/



void static_gr_set_vrf_stale_removal_time(vrf_id_t vrf_id, uint32_t stale_removal_time);

void static_gr_set_vrf_grace_period(vrf_id_t vrf_id, uint32_t stale_removal_time);


/* EOF */
