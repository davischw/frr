// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Static graceful restart header.
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 *               David Schweizer
 */


#ifndef __STATIC_GR_H__
#define __STATIC_GR_H__


#include "lib/vrf.h"
#include "lib/zclient.h"


/* TODO: check if handled as the same timer */
#define STATIC_DEFAULT_GR_STALE_TIME 120
#define STATIC_DEFAULT_GR_GRACE_PERIOD 120


void static_send_zebra_gr_cap(struct zclient *zclient, vrf_id_t vrf_id);


#endif /* __STATIC_GR_H__ */


/* EOF */
