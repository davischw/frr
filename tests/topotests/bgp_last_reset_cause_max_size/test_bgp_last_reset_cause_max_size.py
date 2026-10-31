#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_last_reset_cause_max_size.py
# Part of NetDEF Topology Tests
#

"""
test_bgp_last_reset_cause_max_size.py: `show bgp neighbors` must print the
packet that made bgpd send a NOTIFICATION when that packet has the maximum
BGP message size (65535 bytes, RFC 8654).

    r1 (AS 65001) ------ s1 ------ r2 (AS 65002)
    192.168.1.1/24                 192.168.1.2/24

r1 and r2 negotiate the Extended Message capability, so r2 packs up to 65535
bytes in each UPDATE: 23 bytes of header and length fields, 28 bytes of path
attributes (ORIGIN, AS_PATH, NEXT_HOP and MED) and 16371 /24 prefixes of 4
bytes each. r1 accepts at most 100 prefixes from r2, so the first UPDATE
makes r1 send a NOTIFICATION and keep the UPDATE as the reset cause.

bgpd printed the stored packet with a 16 bit counter that can't get past
65535, so it kept reading past the end of the packet until it crashed.
"""

import os
import re
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]

R2_ADDRESS = "192.168.1.2"
MAX_PACKET_SIZE = 65535
# More than the (65535 - 23 - 28) / 4 = 16371 prefixes that fill an UPDATE.
PREFIXES = 16384


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def r2_bgp_config():
    "Returns the r2 BGP configuration announcing PREFIXES prefixes."
    config = [
        "router bgp 65002",
        " no bgp ebgp-requires-policy",
        " no bgp network import-check",
        " neighbor 192.168.1.1 remote-as 65001",
        " neighbor 192.168.1.1 timers 3 10",
        " neighbor 192.168.1.1 timers connect 1",
        " address-family ipv4 unicast",
    ]
    config += [
        "  network 10.{}.{}.0/24".format(i // 256, i % 256) for i in range(PREFIXES)
    ]
    config += [" exit-address-family", "!"]
    return "\n".join(config) + "\n"


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Generated so r2 has all its prefixes before the session comes up and
    # fills its first UPDATE.
    r2_bgp_config_path = os.path.join(tgen.logdir, "r2-bgpd.conf")
    with open(r2_bgp_config_path, "w") as config_file:
        config_file.write(r2_bgp_config())

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
    tgen.gears["r1"].load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r1/bgpd.conf"))
    tgen.gears["r2"].load_config(TopoRouter.RD_BGP, r2_bgp_config_path)

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_maximum_prefix_overflow():
    "r1 must reset the session when the first UPDATE exceeds maximum-prefix."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r1"],
        "show bgp neighbors {} json".format(R2_ADDRESS),
        {R2_ADDRESS: {"prefixesConfigExceedMax": True}},
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 didn't reset the session with r2: {}".format(result)


def test_bgp_show_neighbors_last_reset_cause():
    "r1 must show the whole maximum size UPDATE that made it reset the session."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = tgen.gears["r1"].vtysh_cmd("show bgp neighbors {}".format(R2_ADDRESS))
    assert not tgen.routers_have_failure(), tgen.errors

    match = re.search(
        r"Message received that caused BGP to send a NOTIFICATION:\n"
        r"((?: +[0-9A-F ]+\n)+)",
        output,
    )
    assert match is not None, "r1 doesn't show the reset cause packet"

    packet = bytes.fromhex(re.sub(r"\s", "", match.group(1)))
    assert len(packet) == MAX_PACKET_SIZE, "r1 shows {} bytes, expected {}".format(
        len(packet), MAX_PACKET_SIZE
    )
    # BGP header: marker, length and type (UPDATE).
    assert packet[:16] == b"\xff" * 16, "bad marker"
    assert int.from_bytes(packet[16:18], "big") == MAX_PACKET_SIZE, "bad length"
    assert packet[18] == 2, "not an UPDATE"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
