#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_nssa_lsa.py
# Part of NetDEF Topology Tests
#

"""
Send an OSPFv2 Link State Update carrying a single NSSA-LSA (Type-7).

The packet is sent as if it came from an existing neighbor (the OSPF header
carries the neighbor's Router ID and the packet is sourced from its interface
address), so the receiving router installs the LSA as long as it's more recent
than its database copy. This allows planting arbitrary NSSA-LSAs, e.g. a stale
copy of an LSA originated by someone else, in a router's LSDB.
"""

import argparse
import socket
import struct

IPPROTO_OSPF = 89
OSPF_LS_UPDATE = 4
OSPF_AS_NSSA_LSA = 7
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)


def fletcher_checksum(data, offset):
    "LSA checksum (RFC 2328 section 12.1.7), same as lib/checksum.c."
    data = bytearray(data)
    data[offset : offset + 2] = b"\x00\x00"
    c0 = c1 = 0
    for byte in data:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    x = ((len(data) - offset - 1) * c0 - c1) % 255
    if x <= 0:
        x += 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    data[offset] = x
    data[offset + 1] = y

    # Validate: both running sums must be zero over the checksummed data.
    c0 = c1 = 0
    for byte in data:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    assert c0 == 0 and c1 == 0, "bad LSA checksum"

    return bytes(data)


def ip_checksum(data):
    "Internet checksum, used by the OSPF packet header."
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!{}H".format(len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_nssa_lsa(args):
    body = socket.inet_aton(args.mask)
    body += struct.pack(
        "!I", (0x80000000 if args.metric_type == 2 else 0) | args.metric
    )
    body += socket.inet_aton(args.fwd_addr)
    body += struct.pack("!I", args.tag)

    header = struct.pack(
        "!HBB4s4sIHH",
        args.age,
        args.options,
        OSPF_AS_NSSA_LSA,
        socket.inet_aton(args.lsa_id),
        socket.inet_aton(args.adv_router),
        args.seqnum,
        0,
        20 + len(body),
    )
    lsa = header + body

    # The checksum doesn't cover the LS age field, and its offset (16) is
    # relative to the start of the LSA.
    return lsa[:2] + fletcher_checksum(lsa[2:], 14)


def build_ls_update(args, lsa):
    body = struct.pack("!I", 1) + lsa
    header = struct.pack(
        "!BBH4s4sHH8s",
        2,
        OSPF_LS_UPDATE,
        24 + len(body),
        socket.inet_aton(args.router_id),
        socket.inet_aton(args.area),
        0,
        0,
        b"\x00" * 8,
    )
    packet = bytearray(header + body)
    packet[12:14] = struct.pack("!H", ip_checksum(bytes(packet)))
    return bytes(packet)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ifname", required=True, help="outgoing interface")
    parser.add_argument("--src", required=True, help="source IP address")
    parser.add_argument("--dst", required=True, help="destination IP address")
    parser.add_argument("--router-id", required=True, help="sender's Router ID")
    parser.add_argument("--area", required=True, help="area ID")
    parser.add_argument("--lsa-id", required=True, help="Link State ID")
    parser.add_argument("--adv-router", required=True, help="advertising router")
    parser.add_argument("--seqnum", required=True, type=lambda x: int(x, 0))
    parser.add_argument("--options", default=0x02, type=lambda x: int(x, 0))
    parser.add_argument("--age", default=1, type=int)
    parser.add_argument("--mask", default="255.255.255.0")
    parser.add_argument("--metric-type", default=2, type=int, choices=[1, 2])
    parser.add_argument("--metric", default=20, type=int)
    parser.add_argument("--fwd-addr", default="0.0.0.0")
    parser.add_argument("--tag", default=0, type=int)
    args = parser.parse_args()

    packet = build_ls_update(args, build_nssa_lsa(args))

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_OSPF)
    sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, args.ifname.encode())
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
    sock.bind((args.src, 0))
    sock.sendto(packet, (args.dst, 0))
    sock.close()

    print(
        "sent LS Update to {} via {}: NSSA-LSA {} adv-router {} seq 0x{:08x} options 0x{:02x} fwd-addr {}".format(
            args.dst,
            args.ifname,
            args.lsa_id,
            args.adv_router,
            args.seqnum,
            args.options,
            args.fwd_addr,
        )
    )


if __name__ == "__main__":
    main()
