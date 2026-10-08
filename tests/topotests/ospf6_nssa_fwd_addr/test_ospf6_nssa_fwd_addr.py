#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf6_nssa_fwd_addr.py
# Part of NetDEF Topology Tests
#

r"""
test_ospf6_nssa_fwd_addr.py: a Type-7 route whose forwarding address is on
a directly attached network must be installed via that forwarding address.

       NSSA 0.0.3.230
  r1 ------------------- r2 ------------------- r3
     2001:db8:16::/64       2001:db8:200::/64   ("Internet")
                        (ASBR)                  lo 2001:db8:100::3

r2 originates two Type-7 LSAs into the NSSA, both with the forwarding address
set to its global address on the shared link (2001:db8:16::2):
- ::/0, from "nssa default-information-originate" (E2, metric 1);
- 2001:db8:100::/64, a redistributed static route.

r1 resolves the forwarding address through its own connected route
2001:db8:16::/64, whose only nexthop is the interface. ospf6_asbr_lsa_add()
copies that nexthop to the external route and never fills in the forwarding
address, so r1 installs both routes as "directly connected" on r1-eth0. The
kernel then tries to resolve every destination with NDP on r1-eth0 and the
traffic is blackholed. ospfd handles the same case with
ospf_ase_complete_direct_routes().

The link must be a broadcast one: on a point-to-point link r2 also advertises
2001:db8:16::2/128 (LA-bit), the forwarding address resolves through that
route instead (nexthop r2's link-local) and the problem doesn't show.
"""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospf6d]

AREA = "0.0.3.230"
R2_ID = "10.151.192.167"
FWD_ADDR = "2001:db8:16::2"

# Route learned through a Type-7 LSA -> destination only reachable through it.
ROUTES = {
    "::/0": "2001:db8:200::3",
    "2001:db8:100::/64": "2001:db8:100::3",
}


def build_topo(tgen):
    "Build function"

    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth0")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth0")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth1")
    switch.add_link(tgen.gears["r3"], nodeif="r3-eth0")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    daemons = {
        "r1": [TopoRouter.RD_ZEBRA, TopoRouter.RD_OSPF6],
        "r2": [TopoRouter.RD_ZEBRA, TopoRouter.RD_OSPF6, TopoRouter.RD_STATIC],
        "r3": [TopoRouter.RD_ZEBRA, TopoRouter.RD_STATIC],
    }
    for router in tgen.routers().values():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(router.name)),
            daemons[router.name],
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def r1_ospf6_nexthops(prefix):
    "(gateway, interface) of each nexthop of r1's OSPFv3 RIB entry for prefix."
    tgen = get_topogen()
    output = tgen.gears["r1"].vtysh_cmd(
        "show ipv6 route {} json".format(prefix), isjson=True
    )
    for entry in output.get(prefix, []):
        if entry.get("protocol") == "ospf6":
            return sorted(
                (nh.get("ip"), nh.get("interfaceName")) for nh in entry["nexthops"]
            )
    return None


def r1_has_ospf6_route(prefix):
    "Whether r1 has an OSPFv3 RIB entry for prefix."
    return r1_ospf6_nexthops(prefix) is not None


def r1_reaches(address):
    "Whether r1 can ping address."
    tgen = get_topogen()
    output = tgen.gears["r1"].run("ping -c 1 -W 1 {}".format(address))
    return " 0% packet loss" in output


def test_convergence():
    "r1 learns both Type-7 LSAs, with the forwarding address set, and installs them."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {"neighbors": [{"neighborId": R2_ID, "state": "Full"}]}
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r1"],
        "show ipv6 ospf6 neighbor json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1-r2 adjacency didn't come up"

    # r2 picks the forwarding address when it originates the Type-7 LSA and
    # doesn't refresh it once r2-eth0 comes up. The redistributed route may
    # have been originated before that, so originate it again.
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
         no ipv6 route 2001:db8:100::/64 2001:db8:200::3
         ipv6 route 2001:db8:100::/64 2001:db8:200::3
        """
    )

    expected = {
        "areaScopedLinkStateDb": [
            {
                "areaId": AREA,
                "lsa": [
                    {
                        "advertisingRouter": R2_ID,
                        "prefix": "::",
                        "forwardingAddress": FWD_ADDR,
                    },
                    {
                        "advertisingRouter": R2_ID,
                        "prefix": "2001:db8:100::/64",
                        "forwardingAddress": FWD_ADDR,
                    },
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r1"],
        "show ipv6 ospf6 database type-7 detail json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 didn't learn r2's Type-7 LSAs with FA {}".format(
        FWD_ADDR
    )

    for prefix in ROUTES:
        _, result = topotest.run_and_expect(
            partial(r1_has_ospf6_route, prefix), True, count=30, wait=1
        )
        assert result, "r1 didn't install the OSPFv3 route {}".format(prefix)


def test_nexthop_is_forwarding_address():
    "r1 must install the Type-7 routes via the forwarding address."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "r1 OSPFv3 routes:\n%s",
        tgen.gears["r1"].vtysh_cmd("show ipv6 ospf6 route detail"),
    )
    logger.info("r1 kernel routes:\n%s", tgen.gears["r1"].run("ip -6 route show"))

    expected = [(FWD_ADDR, "r1-eth0")]
    failures = []
    for prefix in ROUTES:
        _, result = topotest.run_and_expect(
            partial(r1_ospf6_nexthops, prefix), expected, count=10, wait=1
        )
        if result != expected:
            failures.append("{} nexthops {}".format(prefix, result))

    assert not failures, "r1 didn't install via {}: {}".format(
        FWD_ADDR, "; ".join(failures)
    )


def test_traffic():
    "r1 must reach the destinations behind r2."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    failures = []
    for prefix, address in ROUTES.items():
        _, result = topotest.run_and_expect(
            partial(r1_reaches, address), True, count=5, wait=1
        )
        if not result:
            failures.append("{} (via {})".format(address, prefix))

    logger.info("r1 neighbors:\n%s", tgen.gears["r1"].run("ip -6 neigh show"))
    assert not failures, "r1 can't reach {}".format(", ".join(failures))


def test_spf_recalculation():
    "The forwarding address must survive an SPF run that recomputes the routes."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Changing r1-eth0's cost changes the cost of the route to the forwarding
    # address, so the Type-7 routes are recomputed with the new cost.
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
         interface r1-eth0
          ipv6 ospf6 cost 20
        """
    )
    expected = {"routes": {prefix: {"metricCost": 20} for prefix in ROUTES}}
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r1"],
        "show ipv6 ospf6 route detail json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 didn't recompute the Type-7 routes"

    logger.info(
        "r1 OSPFv3 routes:\n%s",
        tgen.gears["r1"].vtysh_cmd("show ipv6 ospf6 route detail"),
    )

    expected = [(FWD_ADDR, "r1-eth0")]
    failures = []
    for prefix in ROUTES:
        _, result = topotest.run_and_expect(
            partial(r1_ospf6_nexthops, prefix), expected, count=10, wait=1
        )
        if result != expected:
            failures.append("{} nexthops {}".format(prefix, result))

    assert not failures, "r1 didn't install via {} after SPF: {}".format(
        FWD_ADDR, "; ".join(failures)
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
