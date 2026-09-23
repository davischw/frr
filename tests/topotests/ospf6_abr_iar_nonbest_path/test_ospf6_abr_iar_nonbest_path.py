#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf6_abr_iar_nonbest_path.py
# Part of NetDEF Topology Tests
#

r"""
test_ospf6_abr_iar_nonbest_path.py: an ABR must not flush the
Inter-Area-Router-LSA of an ASBR when it learns a non-best path to it.

      area 0          area 2          area 2
  r2 -------- r1 ------------- r3 ------------- r4
                               |                |
                               +----------------+
                                area 0 (cost 5)

r3 and r4 are ASBRs in area 2. r1 is the only ABR between area 2 and r2's
backbone, so r2 reaches r3's and r4's AS-External routes only through the
Inter-Area-Router-LSAs that r1 originates into area 0.

The test then enables the area 0 link between r3 and r4, which is a backbone
partition of its own. r3 and r4 become ABRs, and each one prefers the other
through area 0, so each originates an IAR for the other into area 2. r1 now
has two border-router entries for each of r3 and r4: the best, intra-area one
and a non-best, inter-area one learned from those IARs.

When the non-best entry is processed, the "secondary path to the ASBR" branch
must ignore it instead of flushing the IAR originated for the best entry.
Otherwise r2 loses the external routes while every adjacency stays up.
"""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospf6d]

ASBRS = {
    "3.3.3.3": "2001:db8:e3::/56",
    "4.4.4.4": "2001:db8:e4::/56",
}


def build_topo(tgen):
    "Build function"

    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth0")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth0")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth1")
    switch.add_link(tgen.gears["r3"], nodeif="r3-eth0")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r3"], nodeif="r3-eth1")
    switch.add_link(tgen.gears["r4"], nodeif="r4-eth0")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"], nodeif="r3-eth2")
    switch.add_link(tgen.gears["r4"], nodeif="r4-eth1")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(router.name)),
            [TopoRouter.RD_ZEBRA, TopoRouter.RD_OSPF6, TopoRouter.RD_STATIC],
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def border_router_entries(asbr):
    "Number of border-router entries r1 has for the given router."
    tgen = get_topogen()
    output = tgen.gears["r1"].vtysh_cmd("show ipv6 ospf6 border-routers")
    return sum(1 for line in output.splitlines() if line.startswith(asbr))


def r1_iars():
    "ASBRs for which r1 has a live (non-MaxAge) IAR in area 0."
    tgen = get_topogen()
    output = tgen.gears["r1"].vtysh_cmd(
        "show ipv6 ospf6 database inter-router self-originated json", isjson=True
    )
    iars = set()
    for area in output.get("areaScopedLinkStateDb", []):
        if area["areaId"] != "0.0.0.0":
            continue
        for lsa in area["lsa"]:
            if lsa["payload"] in ASBRS and lsa["age"] < 3600:
                iars.add(lsa["payload"])
    return sorted(iars)


def r2_externals():
    "External prefixes of r3 and r4 that r2 has from OSPFv3 in its RIB."
    tgen = get_topogen()
    output = tgen.gears["r2"].vtysh_cmd("show ipv6 route ospf6 json", isjson=True)
    return sorted(
        prefix
        for prefix in ASBRS.values()
        if any(r.get("protocol") == "ospf6" for r in output.get(prefix, []))
    )


def log_state(title):
    tgen = get_topogen()
    for router, cmd in [
        ("r1", "show ipv6 ospf6 border-routers"),
        ("r1", "show ipv6 ospf6 database inter-router"),
        ("r2", "show ipv6 route ospf6"),
    ]:
        logger.info(
            "%s: %s %s:\n%s", title, router, cmd, tgen.gears[router].vtysh_cmd(cmd)
        )


def test_convergence():
    "r2 learns r3's and r4's external routes through r1's IARs."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = sorted(ASBRS.values())
    _, result = topotest.run_and_expect(r2_externals, expected, count=90, wait=1)
    assert result == expected, "r2 has external routes {}, expected {}".format(
        result, expected
    )
    assert r1_iars() == sorted(ASBRS), "r1 IARs in area 0: {}".format(r1_iars())


def test_iar_survives_nonbest_path():
    "Non-best border-router paths to r3 and r4 must not cost r1 its IARs."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("enabling the area 0 link between r3 and r4")
    for router, ifname in [("r3", "r3-eth2"), ("r4", "r4-eth1")]:
        tgen.gears[router].vtysh_cmd(
            """
            configure terminal
            interface {}
             ipv6 ospf6 area 0.0.0.0
            """.format(ifname)
        )

    # r1 learns the non-best inter-area paths from r3's and r4's IARs.
    for asbr in ASBRS:
        _, result = topotest.run_and_expect(
            lambda: border_router_entries(asbr), 2, count=90, wait=1
        )
        assert result == 2, "r1 has {} border-router entries for {}".format(
            result, asbr
        )

    # Several SPF runs' worth of time, then make sure the result is stable.
    topotest.sleep(20, "waiting for SPF and ABR processing on r1")
    log_state("after enabling the r3-r4 backbone link")

    assert r1_iars() == sorted(ASBRS), "r1 flushed IARs, left with {}".format(
        r1_iars()
    )
    expected = sorted(ASBRS.values())
    _, result = topotest.run_and_expect(r2_externals, expected, count=30, wait=1)
    assert result == expected, "r2 has external routes {}, expected {}".format(
        result, expected
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
