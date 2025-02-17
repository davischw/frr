// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LLDPd -  memory type definitions
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 */


#include <zebra.h>

#include "memory.h"

#include "lldp_memory.h"


DEFINE_MGROUP(LLDPD, "lldpd");
DEFINE_MTYPE(LLDPD, LLDP, "LLDP instance");
DEFINE_MTYPE(LLDPD, LLDP_IF_INFO, "LLDP interface information");


/* EOF */
