/* TODO: license */
/*
 * Copyright (c) 2016 zhurish
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 */


#ifndef __LLDPD_LLDP_SOCKET_H__
#define __LLDPD_LLDP_SOCKET_H__


#include "if.h"
#include "stream.h"


#ifndef ETH_P_LLDP
#define ETH_P_LLDP 0x88cc
#endif

#ifndef ETH_P_SLLDP
#define ETH_P_SLLDP 0xaaaa
#endif


int lldp_write_packet(int fd, struct interface *ifp, struct stream *obuf);

struct stream *lldp_recv_packet(int fd, struct interface **ifp, struct stream *ibuf);

int lldp_interface_socket_init(struct interface *ifp);


#endif /* __LLDPD_LLDP_SOCKET_H__ */


/* EOF */
