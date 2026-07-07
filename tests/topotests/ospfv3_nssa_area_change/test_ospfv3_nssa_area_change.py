#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospfv3_nssa_area_change.py
# Part of NetDEF Topology Tests
#
# Regression test for PAN-839: ospf6d aborts with
#   assert(route_area) at ospf6d/ospf6_abr.c
# when the area-id of an OSPFv3 NSSA interface is changed at runtime.
#
# Root cause: border-router routes live in the instance-wide brouter table
# tagged with path.area_id and are only purged by
# ospf6_intra_brouter_calculation() during that area's SPF run.  When the
# area is deleted (interface moved to a different area) it never runs SPF
# again, so a stale ROUTER entry survives.  The periodic ABR task then walks
# the brouter table, calls ospf6_area_lookup(path.area_id) for the now-gone
# area, gets NULL and trips assert(route_area), aborting the daemon.

r"""
                    area 0.0.0.0 (backbone)
      +----+  r3-eth0            r1-eth0  +----+
      | r3 |----------------------------- | r1 |  ABR + NSSA translator
      +----+                              +----+
                                           | r1-eth1
                                           |  area 0.0.0.1 (NSSA)
                                           |  ->changed at runtime to 0.0.0.100
                                  r2-eth0  |
                                        +----+
                                        | r2 | NSSA ASBR (redistribute
                                        +----+  connected -> E-bit)
                                           | r2-eth1  connected stub

  r2 is an ASBR inside NSSA area 0.0.0.1, so r1 installs 10.0.0.2 as a
  border router with the E-bit set and path.area_id = 0.0.0.1 in its
  instance-wide brouter table.  That E-bit entry is the one that reaches
  assert(route_area) after area 0.0.0.1 is deleted on r1.
"""

import os
import sys
import time
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospf6d]


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # backbone area 0.0.0.0 : r1 <-> r3
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth0")
    switch.add_link(tgen.gears["r3"], nodeif="r3-eth0")

    # NSSA area 0.0.0.1 : r1 <-> r2
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth1")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth0")

    # connected stub on r2 (redistributed -> r2 becomes an NSSA ASBR)
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/ospf6d.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_converge():
    "Wait for OSPFv3 adjacencies to reach Full."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def expect_full(router, neighbor):
        test_func = lambda: topotest.router_json_cmp(
            tgen.gears[router],
            "show ipv6 ospf6 neighbor json",
            {"neighbors": [{"neighborId": neighbor, "state": "Full"}]},
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, '"{}" <-> "{}" did not reach Full'.format(
            router, neighbor
        )

    expect_full("r1", "10.0.0.3")  # backbone
    expect_full("r1", "10.0.0.2")  # NSSA area 0.0.0.1


def test_precondition_r2_is_border_router():
    "r1 must have r2 installed as a border router in area 0.0.0.1."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _has_brouter():
        out = r1.vtysh_cmd("show ipv6 ospf6 border-routers")
        logger.info("r1 border-routers:\n%s", out)
        # r2 (10.0.0.2) installed as a border router in NSSA area 0.0.0.1
        for line in out.splitlines():
            if "10.0.0.2" in line and "0.0.0.1" in line:
                return True
        return None

    _, result = topotest.run_and_expect(_has_brouter, True, count=30, wait=1)
    assert result is True, (
        "r1 never installed r2 as a border router in area 0.0.0.1 - "
        "the crash precondition is not set up"
    )


def test_nssa_area_change_no_crash():
    "Change the NSSA area-id on r1 and confirm ospf6d does not abort."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info(
        "before change, r1 border-routers:\n%s",
        r1.vtysh_cmd("show ipv6 ospf6 border-routers"),
    )

    logger.info("changing NSSA area-id 0.0.0.1 -> 0.0.0.100 on r1")
    # Full area-id change, as an operator would do it: move the interface AND
    # drop the per-area "area 0.0.0.1 nssa" config.  Removing both the last
    # interface and the area config lets ospf6_area_no_config_delete() delete
    # area 0.0.0.1 while the stale ASBR brouter entry (path.area_id = 0.0.0.1)
    # still lingers -> the ABR task then trips assert(route_area).
    r1.vtysh_cmd(
        """
        configure terminal
          router ospf6
            area 0.0.0.100 nssa default-information-originate metric 10
            no area 0.0.0.1 nssa default-information-originate metric 10
          exit
          interface r1-eth1
            no ipv6 ospf6 area 0.0.0.1
            ipv6 ospf6 area 0.0.0.100
          exit
        """
    )

    # On the buggy code the ABR task fires within the SPF window after the
    # reconfig and aborts ospf6d.  Poll aliveness for a while; fail as soon
    # as the daemon is detected dead.
    crashed = None
    for _ in range(20):
        err = r1.check_router_running()
        if err != "":
            crashed = err
            break
        time.sleep(1)

    assert crashed is None, (
        "ospf6d on r1 crashed after the NSSA area-id change (PAN-839):\n{}".format(
            crashed
        )
    )

    # Daemon must still answer, the stale area-0.0.0.1 brouter entry must be
    # gone, and the interface must have moved to the new area.
    brouters = r1.vtysh_cmd("show ipv6 ospf6 border-routers")
    logger.info("after change, r1 border-routers:\n%s", brouters)
    for line in brouters.splitlines():
        # data rows: <router-id> <rtr-bits> <options> <path-type> <area>
        parts = line.split()
        if not parts or not parts[0].startswith("10.0.0."):
            continue
        assert parts[-1] != "0.0.0.1", (
            "stale brouter entry for the deleted area 0.0.0.1 remains:\n" + line
        )

    out = r1.vtysh_cmd("show ipv6 ospf6 interface r1-eth1")
    logger.info("r1-eth1 after change:\n%s", out)
    assert "0.0.0.100" in out, "r1-eth1 was not moved to area 0.0.0.100"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
