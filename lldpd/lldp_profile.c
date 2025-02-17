/*
 * LLDP profile
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 */


#include "lldp_interface.h"
#include "lldp_profile.h"


struct lldp_profile *lldp_profiles;

/* TODO:
void lldp_profile_config_write(struct vty vty);
*/


/* Allocate LLDP profile */
struct lldp_profile *lldp_profile_new(void)
{
	struct lldp_profile *lprof = NULL;

	lprof = XCALLOC(MTYPE_LLDP_PROFILE, sizeof(struct lldp_profile));
	if (lprof) {
		/* TODO: default values */
		/* TODO: initialize empty hooks? */
		lprof->name = NULL;

		lprof->rx_enable = true;
		lprof->tx_enable = true;

		lprof->send_interval_ms = 100;

		lprof->prev = NULL;
		lprof->next = NULL;
	}

	return lprof;
}


/* Delete LLDP profile */
void lldp_profile_delete(struct lldp_profile *lprof)
{
	if (lprof) {
		/* TODO: delete hooks?*/
		XFREE(lprof);
	}
}


struct lldp_profile *lldp_profile_lookup_by_name(const char *name)
{
	struct lldp_profile *lprof = NULL;
	struct lldp_profile *lprof_iter = NULL;

	if (name) {
		/* TODO: list iteration */
		FOREACH_ELEMENT(lldp_profiles, lprof_iter) {
			/* TODO: strncmp */
			if (strncmp(lprof->name, name, LLDP_PROFILE_NAME_MAXLEN)) {
				lprof = lprof_iter;
				break;
			}
		}
	}

	return lprof;
}


void lldp_profile_apply(struct lldp_profile *lprof, lldp_interface *lifp)
{
	/* TODO: implement, make sure threads are reset, etc. */
	return;
}


/* TODO: move to lldp_profile_vty.c or similar */
DEFPY (lldp_profile, lldp_profile_cmd,
       "lldp profile WORD$profile"
       LLDP_STR
       LLDP_PROFILE_STR
       LLDP_PROFILE_NAME_STR)
{
	struct lldp_profile *lprof = NULL;

	if (profile) {
		lprof = lldp_profile_lookup_by_name(profile);
		if (lprof) {
			/* TODO: move to config node? */
			return CMD_SUCCESS;
		} else {
			/* Create new profile if it does not exist yet */
			lprof = lldp_profile_new();
			if (lprof) {
				strncpy(profile, lprof->name, strlen(profile),
					LLDP_PROFILE_NAME_MAXLEN);

				/* TODO: push to list */
				ADD_TAILQ(lldp_profiles, lprof);
			
				/* TODO: check if interfaces configured to
				 * profile exist */

				return CMD_SUCCESS;
			}
		}
	}

	return CMD_WARNING_FAILED;
}


/* TODO: move to lldp_profile_vty.c or similar */
DEFPY (no_lldp_profile, lldp_profile_cmd,
       "no lldp profile WORD$profile"
       NO_STR
       LLDP_STR
       LLDP_PROFILE_STR
       LLDP_PROFILE_NAME_STR)
{
	struct lldp_profile *lprof = NULL;

	if (profile) {
		lprof = lldp_profile_lookup_by_name(profile);
		if (lprof) {
			/* TODO: use return value of deletion */
			lldp_profile_delete(lprof);

			return CMD_SUCCESS;
		}
	}

	return CMD_WARNING_FAILED;
}


/* TODO: move to lldp_profile_vty.c or similar */
DEFPY (lldp_profile_send_interval, lldp_profile_cmd,
       "lldp profile WORD$profile send-interval INTEGER(0-UINT16_MAXVAL)$send_interval"
       LLDP_STR
       LLDP_PROFILE_STR
       LLDP_PROFILE_NAME_STR
       LLDP_SEND_INTERVAL_STR
       )
{
	/* TODO: implement some demo function */
#include <assert.h>
	assert(false);

	return CMD_WARNING_FAILED;
}


/* EOF */

