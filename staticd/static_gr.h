// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Static graceful restart header.
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 *               David Schweizer
 */


#ifndef __STATIC_GR_H__
#define __STATIC_GR_H__

#include <zebra.h>

#include <inttypes.h>
#include <stdbool.h>

#include "lib/freebsd-queue.h"
#include "lib/vrf.h"
#include "lib/zclient.h"


/* TODO: check if handled as the same timer */
#define STATIC_DEFAULT_GR_STALE_TIME 120
#define STATIC_DEFAULT_GR_GRACE_PERIOD 120


TAILQ_HEAD(static_gr_info_queue, static_gr_vrf_info);


/* Per VRF graceful-restart info */
struct static_gr_vrf_info {
	bool init;
	bool enabled;
	struct zclient *zclient;
	vrf_id_t vrf_id;
	uint32_t stale_removal_time_sec;
	uint32_t grace_period_sec;

	/* Queue entries */
	TAILQ_ENTRY(static_gr_vrf_info) entries;
};


int static_gr_init(void);

int static_gr_exit(void);

int static_gr_vrf_enable(struct zclient *zclient, vrf_id_t vrf_id);

int static_gr_vrf_disable(vrf_id_t vrf_id);


#endif /* __STATIC_GR_H__ */


/* EOF */
