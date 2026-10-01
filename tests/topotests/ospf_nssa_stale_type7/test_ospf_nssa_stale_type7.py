#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_nssa_stale_type7.py
# Part of NetDEF Topology Tests
#

r"""
test_ospf_nssa_stale_type7.py: an NSSA ABR must not inherit the P-bit and
forwarding address of a stale copy of its own NSSA-LSA.

             area 1 (NSSA)            area 0
  rt2 ------------------------ rt1 ------------ rt3
                          (ABR, ASBR)

rt1 redistributes 10.0.115.0/24 (nexthop 10.0.13.30, on an OSPF interface)
into area 1 as an NSSA-LSA with the P-bit set and the nexthop as forwarding
address, then translates it into an AS-external-LSA for the backbone.

When a router receives a more recent instance of one of its own NSSA-LSAs, it
must reoriginate the LSA with its current contents. ospfd used to copy the
P-bit and the forwarding address from the received instance instead, so a
stale copy without the P-bit was readopted and refreshed forever, and the
NSSA-LSA was never translated again. The stale copy is planted here with a
forged LS Update, either directly in rt1 or in rt2 before restarting rt1,
emulating an HA switchover where the neighbors still hold the stale copy.
"""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd]

RT1 = "1.1.1.1"
PREFIX = "10.0.115.0"
FWD_ADDR = "10.0.13.30"
# rt1's own address in area 1, as in the forwarding address of the stale copy
# reported in the field.
STALE_FWD_ADDR = "10.0.12.1"
STALE_SEQNUM_INCREMENT = 0x100

# Sender side of rt1 <-> rt2, used to forge the LS Updates.
LINKS = {
    "rt1": {"ifname": "eth-rt2", "src": "10.0.12.1", "router_id": "1.1.1.1"},
    "rt2": {"ifname": "eth-rt1", "src": "10.0.12.2", "router_id": "2.2.2.2"},
}


def build_topo(tgen):
    "Build function"

    for router in ["rt1", "rt2", "rt3"]:
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt3")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt1")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Per-daemon configuration files, so that a restarted ospfd reloads its
    # configuration.
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def get_lsa(rname, lsa_type):
    "rt1's LSA for PREFIX of the given type in rname's LSDB, or None."
    tgen = get_topogen()
    output = tgen.gears[rname].vtysh_cmd(
        "show ip ospf database {} {} adv-router {} json".format(lsa_type, PREFIX, RT1),
        isjson=True,
    )
    if lsa_type == "nssa-external":
        lsas = output.get("nssaExternalLinkStates", {}).get("areas", {}).get("0.0.0.1")
    else:
        lsas = output.get("asExternalLinkStates")
    if not lsas or lsas[0]["lsaAge"] >= 3600:
        return None
    return lsas[0]


def get_type7_seqnum(rname):
    lsa = get_lsa(rname, "nssa-external")
    assert lsa is not None, "{} has no NSSA-LSA for {}".format(rname, PREFIX)
    return int(lsa["lsaSeqNumber"], 16)


def check_type7(rname, newer_than):
    "rt1's NSSA-LSA in rname's LSDB has its current contents."
    lsa = get_lsa(rname, "nssa-external")
    if lsa is None:
        return "no NSSA-LSA"
    seqnum = int(lsa["lsaSeqNumber"], 16)
    if seqnum <= newer_than:
        return "sequence number 0x{:x} isn't newer than 0x{:x}".format(
            seqnum, newer_than
        )
    if "N/P" not in lsa["options"]:
        return "P-bit is clear (options {})".format(lsa["options"])
    if lsa["nssaForwardAddress"] != FWD_ADDR:
        return "forwarding address is {}, expected {}".format(
            lsa["nssaForwardAddress"], FWD_ADDR
        )
    return None


def check_translation(translated):
    "rt1 advertises PREFIX into the backbone and rt3 receives it."
    lsa = get_lsa("rt1", "external")
    if lsa is None:
        return "rt1 has no AS-external-LSA"
    if translated and not lsa.get("translatedFromType7"):
        return "rt1's AS-external-LSA isn't translated from its NSSA-LSA"
    if get_lsa("rt3", "external") is None:
        return "rt3 has no AS-external-LSA"
    return None


def expect(func, description, count=60):
    _, result = topotest.run_and_expect(func, None, count=count, wait=1)
    assert result is None, "{}: {}".format(description, result)


def expect_current_lsas(newer_than=0, translated=True):
    for rname in ["rt1", "rt2"]:
        expect(
            partial(check_type7, rname, newer_than),
            "{}: wrong copy of rt1's NSSA-LSA".format(rname),
        )
    expect(
        partial(check_translation, translated),
        "rt1 doesn't advertise its NSSA-LSA into the backbone",
    )


def send_stale_type7(sender, dst, seqnum):
    "Forge an LS Update from sender to dst with a stale copy of rt1's NSSA-LSA."
    tgen = get_topogen()
    link = LINKS[sender]
    cmd = [
        "python3",
        os.path.join(CWD, "send_nssa_lsa.py"),
        "--ifname {}".format(link["ifname"]),
        "--src {}".format(link["src"]),
        "--dst {}".format(dst),
        "--router-id {}".format(link["router_id"]),
        "--area 0.0.0.1",
        "--lsa-id {}".format(PREFIX),
        "--adv-router {}".format(RT1),
        "--seqnum 0x{:08x}".format(seqnum),
        # E-bit only, no P-bit, as seen in the field.
        "--options 0x02",
        "--fwd-addr {}".format(STALE_FWD_ADDR),
    ]
    output = tgen.gears[sender].cmd_raises(" ".join(cmd))
    logger.info("%s: %s", sender, output.strip())


def plant_stale_type7(sender, dst, receiver, installed):
    """
    Send the stale copy of rt1's NSSA-LSA until receiver accepts it, as
    checked by installed(seqnum). The receiver discards it when its current
    copy arrived less than MinLSArrival ago, so a single packet isn't enough.
    """
    state = {}

    def attempt():
        if "seqnum" in state and installed(state["seqnum"]):
            return None
        state["seqnum"] = get_type7_seqnum(receiver) + STALE_SEQNUM_INCREMENT
        send_stale_type7(sender, dst, state["seqnum"])
        return "stale NSSA-LSA (0x{:x}) not accepted".format(state["seqnum"])

    expect(attempt, "{} didn't accept the stale NSSA-LSA".format(receiver), count=10)
    return state["seqnum"]


def plant_stale_type7_in_rt2():
    "Make rt2 hold a stale copy of rt1's NSSA-LSA, unbeknownst to rt1."

    def rt2_has_stale_copy(seqnum):
        lsa = get_lsa("rt2", "nssa-external")
        return (
            lsa is not None
            and int(lsa["lsaSeqNumber"], 16) == seqnum
            and "N/P" not in lsa["options"]
        )

    # rt2 doesn't flood the LSA back to rt1 over the point-to-point link it
    # was received on.
    return plant_stale_type7("rt1", "10.0.12.2", "rt2", rt2_has_stale_copy)


def test_convergence():
    "rt1 originates its NSSA-LSA with the P-bit set and translates it."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_current_lsas()


def test_stale_type7_received():
    "rt1 receives a stale copy of its NSSA-LSA from rt2."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Once rt1 accepts the stale copy, it reoriginates the NSSA-LSA past it.
    seqnum = plant_stale_type7(
        "rt2", "10.0.12.1", "rt1", lambda s: get_type7_seqnum("rt1") > s
    )

    # rt1 must reoriginate its NSSA-LSA with the P-bit and forwarding address
    # it originated it with.
    expect_current_lsas(newer_than=seqnum)


def test_stale_type7_after_restart():
    "rt1 restarts while rt2 holds a stale copy of rt1's NSSA-LSA."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    seqnum = plant_stale_type7_in_rt2()

    kill_router_daemons(tgen, "rt1", ["ospfd"], save_config=False)
    start_router_daemons(tgen, "rt1", ["ospfd"])

    # rt1 learns the stale copy from rt2 during the database exchange.
    #
    # It also gets its previous translation back from rt3. Received copies
    # don't carry the local translation flag, so rt1 reoriginates it as a
    # regular AS-external-LSA, which then takes precedence over a new
    # translation. That's unrelated to the P-bit, so only check that rt1 keeps
    # advertising the prefix into the backbone.
    expect_current_lsas(newer_than=seqnum, translated=False)


def test_stale_type7_after_graceful_restart():
    "rt1 restarts gracefully while rt2 holds a stale copy of rt1's NSSA-LSA."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    helpers = [("rt2", "2.2.2.2", "0.0.0.1"), ("rt3", "3.3.3.3", "0.0.0.0")]

    # After the previous restart, the Router-LSAs of rt1 and of the helpers
    # need to list each other again, or rt1 aborts the graceful restart on a
    # topology change.
    def router_lsa_has_link(rname, router_id, neighbor_id, area):
        output = tgen.gears[rname].vtysh_cmd(
            "show ip ospf database router {} json".format(router_id), isjson=True
        )
        lsas = output.get("routerLinkStates", {}).get("areas", {}).get(area, [])
        for lsa in lsas:
            for link in lsa.get("routerLinks", {}).values():
                if link.get("neighborRouterId") == neighbor_id:
                    return None
        return "no link to {} in {}'s Router-LSA".format(neighbor_id, router_id)

    for helper, router_id, area in helpers:
        for lsa_router, neighbor in [(router_id, RT1), (RT1, router_id)]:
            expect(
                partial(router_lsa_has_link, helper, lsa_router, neighbor, area),
                "{} and rt1 aren't fully adjacent".format(helper),
            )

    seqnum = plant_stale_type7_in_rt2()

    tgen.gears["rt1"].vtysh_cmd("graceful-restart prepare ip ospf")
    for helper, _, area in helpers:
        expect(
            partial(
                topotest.router_json_cmp,
                tgen.gears[helper],
                "show ip ospf database opaque-link json",
                {
                    "linkLocalOpaqueLsa": {
                        "areas": {
                            area: [
                                {"advertisingRouter": RT1, "opaqueType": "Grace-LSA"}
                            ]
                        }
                    }
                },
            ),
            "{} didn't receive a Grace-LSA from rt1".format(helper),
        )
    kill_router_daemons(tgen, "rt1", ["ospfd"], save_config=False)
    start_router_daemons(tgen, "rt1", ["ospfd"])

    def gr_finished():
        output = tgen.gears["rt1"].vtysh_cmd("show ip ospf json", isjson=True)
        if output.get("grStatus") != "not started" or "grExitReason" not in output:
            return "graceful restart not finished: {}".format(
                {k: v for k, v in output.items() if k.startswith("gr")}
            )
        if output["grExitReason"] != "all adjacencies were reestablished":
            return "graceful restart failed: {}".format(output["grExitReason"])
        return None

    expect(gr_finished, "rt1's graceful restart didn't succeed", count=120)

    # At the end of the graceful restart, rt1 reoriginates its NSSA-LSA from
    # scratch, which rt2 overrides with the stale copy's successor. See
    # test_stale_type7_after_restart() about the AS-external-LSA.
    expect_current_lsas(newer_than=seqnum, translated=False)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
