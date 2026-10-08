#!/usr/bin/env python

#
# test_bgp_default_originate_route_map_leak.py
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
Test that `neighbor X default-originate route-map RMAP` does not leak
AS-path memory when RMAP has `set as-path prepend` and no match clause.

    r2 (AS 65002) ---- r1 (AS 65001) ---- r3 (AS 65003)
    100 prefixes       default-originate  receives 0.0.0.0/0
                       route-map with
                       as-path prepend

Without a match clause the default-originate route-map is applied to every
path in r1's BGP RIB. For every permitted path except the first one, the
AS-path duplicated by `set as-path prepend` was never freed. The route-map
is re-evaluated after each best-path change (RMAP_DEFAULT_ORIGINATE_EVAL_TIMER),
so each refresh of the r1-r2 session leaked about one AS-path per prefix
received from r2.
"""

import os
import re
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]

# Number of prefixes r2 announces to r1 (see r2/bgpd.conf)
R2_PREFIXES = 100
REFRESHES = 3
ASPATH_MTYPES = [
    "BGP aspath",
    "BGP aspath seg",
    "BGP aspath segment data",
    "BGP aspath str",
]


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _neighbor(router, neighbor):
    output = json.loads(router.vtysh_cmd("show bgp neighbors {} json".format(neighbor)))
    return output.get(neighbor, {})


def _aspath_memory(router):
    """
    Return the number of allocated objects for each AS-path memory type
    from `show memory bgpd`.
    """
    output = router.vtysh_cmd("show memory bgpd")
    counts = {}
    for mtype in ASPATH_MTYPES:
        match = re.search(
            r"^{}\s*:\s*(\d+)".format(re.escape(mtype)), output, re.MULTILINE
        )
        assert match, 'Memory type "{}" not found in "show memory bgpd"'.format(mtype)
        counts[mtype] = int(match.group(1))
    return counts


def _bgp_default_route_received(router):
    output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))
    routes = list(output.get("routes", {}).keys())
    if routes != ["0.0.0.0/0"]:
        return "Expected only 0.0.0.0/0, got {}".format(routes)
    expected = {
        "routes": {
            "0.0.0.0/0": [
                {
                    "valid": True,
                    "path": "65001 65001 65001 65001 65001 65001",
                }
            ]
        }
    }
    return topotest.json_cmp(output, expected)


def _refresh_r2_session(tgen):
    """
    Hard reset the r1-r2 session (as done in the customer's lab) and wait
    until r2's prefixes are back and r1 re-evaluated the default-originate
    route-map toward r3 after the reset.
    """
    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    established = _neighbor(r1, "192.168.1.2")["connectionsEstablished"]
    updates = _neighbor(r3, "192.168.2.1")["messageStats"]["updatesRecv"]

    r1.vtysh_cmd("clear bgp ipv4 unicast 192.168.1.2")

    def _refreshed():
        r2_peer = _neighbor(r1, "192.168.1.2")
        if r2_peer.get("connectionsEstablished", 0) <= established:
            return "r1-r2 session not yet re-established"
        if r2_peer.get("bgpState") != "Established":
            return "r1-r2 session not Established"
        received = r2_peer["addressFamilyInfo"]["ipv4Unicast"]["acceptedPrefixCounter"]
        if received != R2_PREFIXES:
            return "r1 received {} of {} prefixes from r2".format(received, R2_PREFIXES)
        # r1 does not send anything but default-originate to r3, so a new
        # UPDATE on r3 means the route-map was re-evaluated after the reset.
        r1_peer = _neighbor(r3, "192.168.2.1")
        if r1_peer["messageStats"]["updatesRecv"] <= updates:
            return "default-originate route-map not yet re-evaluated"
        return _bgp_default_route_received(r3)

    _, result = topotest.run_and_expect(_refreshed, None, count=60, wait=1)
    assert result is None, "r1-r2 refresh did not complete: {}".format(result)


def test_bgp_converge():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
        expected = {
            "peers": {
                "192.168.1.2": {"state": "Established", "pfxRcd": R2_PREFIXES},
                "192.168.2.3": {"state": "Established", "pfxSnt": 1},
            }
        }
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_bgp_converge, None, count=60, wait=1)
    assert result is None, "Failed to see BGP convergence on r1"

    test_func = functools.partial(_bgp_default_route_received, r3)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r3 did not receive the prepended default route only"


def test_bgp_default_originate_route_map_aspath_leak():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Warm up: get past the initial convergence before taking the baseline
    _refresh_r2_session(tgen)
    baseline = _aspath_memory(r1)

    for _ in range(REFRESHES):
        _refresh_r2_session(tgen)

    after = _aspath_memory(r1)

    # Without the fix every route-map evaluation leaks R2_PREFIXES - 1
    # AS-paths, so after REFRESHES refreshes the counters grew by at least
    # REFRESHES * (R2_PREFIXES - 1). With the fix they stay (nearly) the
    # same; allow a small slack for AS-paths in flight.
    for mtype in ASPATH_MTYPES:
        growth = after[mtype] - baseline[mtype]
        assert growth < R2_PREFIXES, (
            '"{}" grew by {} objects after {} refreshes of the r1-r2 session '
            "(before: {}, after: {}): AS-path memory leaked by default-originate "
            "route-map".format(mtype, growth, REFRESHES, baseline[mtype], after[mtype])
        )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
