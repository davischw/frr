/*
 * LLDP profile
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 */


#ifndef __LLDPD_LLDP_PROFILE_H__
#define __LLDPD_LLDP_PROFILE_H__


#include <stdbool.h>
#include <inttypes.h>

#include "lldp_interface.h"


#define LLDP_PROFILE_NAME_MAXLEN 128


/* LLDP profile */
struct lldp_profile {	
	char *name[LLDP_PROFILE_NAME_MAXLEN];

	/* Port enable */
	bool tx_enable;
	bool rx_enable;

	/* Timers */
	uint32_t send_interval_ms;

	/* Protocols */
	struct lldp_profile *prev;
	struct lldp_profile *next;
};

/* TODO: memtype, memsubtype */


extern struct lldp_profile *lldp_profiles;


/* TODO: show/write config
void lldp_profile_config_write(struct vty vty);
*/


/* Allocate LLDP profile */
struct lldp_profile *lldp_profile_new(void);

/* Delete LLDP profile */
void lldp_profile_delete(struct lldp_profile *lprof);

/* Lookup a LLDP profile by name */
struct lldp_profile *lldp_profile_lookup_by_name(const char *name);

/* Apply LLDP profile to LLDP interface */
void lldp_profile_apply(struct lldp_profile *lprof, struct lldp_interface *lifp);


#endif /* __LLDPD_LLDP_PROFILE_H__ */


/* EOF */

