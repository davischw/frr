#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# igmpv3_send.py
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
Inject hand crafted IGMPv3 packets on an interface.

Used by test_pim_igmpv3_query_numsrc.py to build both well formed and
malformed IGMPv3 messages.  Scapy is driven directly (instead of joining the
group with the host stack) so that the "Number of Sources" field of a query
can be set independently from the number of source addresses that are
actually appended to the packet.
"""

import argparse
import sys

from scapy.all import IP, Ether, sendp
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3gr, IGMPv3mq, IGMPv3mr

# IGMPv3 group record types (RFC 3376 section 4.2.12)
IGMPV3_MODE_IS_INCLUDE = 1

# Well known destinations (RFC 3376 sections 4.1.1 and 4.2.14)
IGMPV3_ALL_ROUTERS = "224.0.0.22"

# All IGMP messages are sent with TTL 1, pimd drops anything else.
IGMP_TTL = 1

# IP Router Alert option (RFC 2113), required by RFC 3376 for all IGMP
# messages.  Four bytes, so it does not need any padding.
IP_ROUTER_ALERT = b"\x94\x04\x00\x00"


def multicast_mac(group):
    "Map a multicast group address onto its 01:00:5e ethernet address."
    octets = [int(octet) for octet in group.split(".")]
    return "01:00:5e:%02x:%02x:%02x" % (octets[1] & 0x7F, octets[2], octets[3])


def send_report(iface, src, group, sources):
    """
    Send an IGMPv3 membership report putting `group` in INCLUDE mode with
    `sources`.  This is what establishes the group state on the router that
    the group-and-source-specific query later looks up.
    """
    pkt = (
        Ether(dst=multicast_mac(IGMPV3_ALL_ROUTERS))
        / IP(
            src=src,
            dst=IGMPV3_ALL_ROUTERS,
            ttl=IGMP_TTL,
            options=IP_ROUTER_ALERT,
        )
        / IGMPv3(type=0x22)
        / IGMPv3mr(
            records=[
                IGMPv3gr(rtype=IGMPV3_MODE_IS_INCLUDE, maddr=group, srcaddrs=sources)
            ]
        )
    )
    sendp(pkt, iface=iface, verbose=False)


def send_query(iface, src, group, sources, numsrc):
    """
    Send a group-and-source-specific IGMPv3 query for `group`.

    `numsrc` overrides the "Number of Sources" field.  Scapy normally derives
    it from `sources`; passing a larger value produces the malformed query
    that used to walk pimd off the end of its receive buffer.  The Suppress
    Router-Side Processing flag is left clear (s=0) because that is what makes
    the receiver walk the source list to lower the source timers.
    """
    query = IGMPv3mq(gaddr=group, srcaddrs=sources, qrv=2, s=0)
    if numsrc is not None:
        query.numsrc = numsrc

    pkt = (
        Ether(dst=multicast_mac(group))
        / IP(src=src, dst=group, ttl=IGMP_TTL, options=IP_ROUTER_ALERT)
        / IGMPv3(type=0x11, mrcode=100)
        / query
    )
    sendp(pkt, iface=iface, verbose=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iface", required=True, help="interface to send on")
    parser.add_argument("--src", required=True, help="IP source address to use")
    parser.add_argument("--group", required=True, help="multicast group address")
    parser.add_argument(
        "--source",
        dest="sources",
        action="append",
        default=[],
        help="source address to include (repeatable)",
    )
    parser.add_argument(
        "--numsrc",
        type=int,
        help="override the query 'Number of Sources' field (query only)",
    )
    parser.add_argument("kind", choices=["report", "query"])
    args = parser.parse_args()

    if args.kind == "report":
        send_report(args.iface, args.src, args.group, args.sources)
    else:
        send_query(args.iface, args.src, args.group, args.sources, args.numsrc)

    return 0


if __name__ == "__main__":
    sys.exit(main())
