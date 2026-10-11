#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Issue #867: Type-5 LSAs sent in LS Updates on an NSSA area.
#
#   r1 ----- NSSA 0.0.0.3 ----- r2 (ABR+ASBR) ----- area 0 ----- r3
#
# r2 redistributes connected and static routes. A PAN config commit
# reapplies the area configuration ("no area 0.0.0.3 nssa", "area 0.0.0.3
# nssa ...").
#
# "area X nssa" used to set r2's self-originated Type-5 LSAs to MaxAge and
# flood them into that area. Routers in an NSSA area discard Type-5 LSAs
# without acknowledging them, so r2 retransmitted them every RxmtInterval,
# and r2's own copies stayed at MaxAge while the backbone kept using them.
# Also, "no area X nssa" used to flush direct Type-5 LSAs through the whole
# AS along with r2's Type-7 LSAs for the same prefixes, although the routes
# were still redistributed.
#
# Only direct Type-5 LSAs were affected, not translations of Type-7 LSAs. In
# the issue's capture, r2's Type-5 LSAs are direct ones (a Type-5 forwarding
# address of 0.0.0.0, while the Type-7 one is set). Here, r2 translates its
# own Type-7 LSAs, except right after a commit: "no area 0.0.0.3 nssa"
# flushes the Type-7 LSAs along with their translations, and r2 reoriginates
# the routes as direct Type-5 LSAs until its new Type-7 LSAs are translated.
# So the commit is applied twice, the second time while r2's Type-5 LSAs are
# direct ones.
#
# A tcpdump capture on the NSSA link checks that no Type-5 LSAs are sent
# there.

import os
import re
import sys
import shutil
import time
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd]

TCPDUMP = {}


def build_topo(tgen):
    for router in ["r1", "r2", "r3"]:
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="eth-r2")
    switch.add_link(tgen.gears["r2"], nodeif="eth-r1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"], nodeif="eth-r3")
    switch.add_link(tgen.gears["r3"], nodeif="eth-r2")


def pcap_path(rname):
    return os.path.join(get_topogen().logdir, rname, "r2-link.pcap")


def start_capture(tgen, rname):
    "Capture all OSPF packets on the router's link to r2 into a pcap file."
    pcap = pcap_path(rname)
    errlog = open(os.path.join(tgen.logdir, rname, "tcpdump.log"), "w")
    # -U: flush every packet so the file can be read while capturing.
    # -Z root: don't drop privileges, the log dir isn't writable by tcpdump.
    proc = tgen.gears[rname].popen(
        ["tcpdump", "-n", "-U", "-Z", "root", "-i", "eth-r2", "-w", pcap]
        + ["ip proto 89"],
        stdout=errlog,
        stderr=errlog,
    )
    TCPDUMP[rname] = proc

    # The file is created once the capture is active.
    _, result = topotest.run_and_expect(
        lambda: proc.poll() is None and os.path.exists(pcap),
        True,
        count=20,
        wait=0.5,
    )
    assert result, "tcpdump failed to start on {} (see {}/tcpdump.log)".format(
        rname, rname
    )


def setup_module(mod):
    if not shutil.which("tcpdump"):
        pytest.skip("tcpdump not available")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Start capturing on the NSSA link before the daemons so the initial
    # database exchange is captured too.
    start_capture(tgen, "r1")

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        staticd_conf = os.path.join(CWD, "{}/staticd.conf".format(rname))
        if os.path.exists(staticd_conf):
            router.load_config(TopoRouter.RD_STATIC, staticd_conf)
    tgen.start_router()


def teardown_module(_mod):
    for proc in TCPDUMP.values():
        if proc.poll() is None:
            proc.terminate()
            proc.wait()
    get_topogen().stop_topology()


#
# Helpers
#
LSU_RE = re.compile(r"(?P<src>[\d.]+) > (?P<dst>[\d.]+): OSPFv2, LS-Update")
TYPE5_RE = re.compile(
    r"Advertising Router (?P<adv>[\d.]+), seq (?P<seq>\w+), age (?P<age>\d+)s.*\n"
    r"\s*External LSA \(5\), LSA-ID: (?P<id>[\d.]+)"
)


def type5_on_link(rname, since=0.0):
    """
    Type-5 LSAs carried in LS Updates on the link between `rname` and r2, as
    decoded by tcpdump, sent at or after `since` (epoch seconds).
    """
    output = get_topogen().gears[rname].cmd(
        "tcpdump -n -tt -vvv -r {} 2>/dev/null".format(pcap_path(rname))
    )
    found = []
    for pkt in re.split(r"\n(?=\d+\.\d+ IP )", output):
        lsu = LSU_RE.search(pkt)
        if not lsu:
            continue
        stamp = float(pkt.split(" ", 1)[0])
        if stamp < since:
            continue
        for lsa in TYPE5_RE.finditer(pkt):
            found.append(
                "{:.3f} {} > {}: Type-5 {} adv {} seq {} age {}".format(
                    stamp,
                    lsu.group("src"),
                    lsu.group("dst"),
                    lsa.group("id"),
                    lsa.group("adv"),
                    lsa.group("seq"),
                    lsa.group("age"),
                )
            )
    return found


def assert_no_type5(when, since=0.0):
    "No Type-5 LSAs may be sent on the NSSA link."
    found = type5_on_link("r1", since)
    for line in found:
        logger.info("Type-5 on NSSA link: %s", line)
    assert not found, (
        "{}: {} Type-5 LSA(s) sent in LS Updates on NSSA area 0.0.0.3 "
        "(see r1/r2-link.pcap):\n{}".format(when, len(found), "\n".join(found[:20]))
    )


def maxage_type5(router, adv_router):
    "Type-5 LSAs from `adv_router` on the router's MaxAge list."
    output = router.vtysh_cmd("show ip ospf database max-age")
    return re.findall(
        r"Link type: 5\nLink State ID: ([\d.]+)\nAdvertising Router: "
        + re.escape(adv_router)
        + r"\n",
        output,
    )


#
# Tests
#
def test_ospf_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # r1 learns the static route through r2's Type-7, r3 through r2's Type-5.
    for rname in ["r1", "r3"]:
        logger.info("Waiting for %s to learn 192.168.100.0/24", rname)
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rname],
            "show ip ospf route json",
            {"192.168.100.0/24": {}},
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "{} did not learn 192.168.100.0/24".format(rname)

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r3"],
        "show ip ospf database external 192.168.100.0 adv-router 2.2.2.2 json",
        {"asExternalLinkStates": [{"linkStateId": "192.168.100.0"}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r3 did not get r2's Type-5 for 192.168.100.0"


def test_no_type5_after_convergence():
    "Adjacency bring-up and the initial database exchange must not leak."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    assert_no_type5("after convergence")


def r2conf(lines):
    get_topogen().gears["r2"].vtysh_cmd(
        "configure terminal\n" + "\n".join(["router ospf"] + lines) + "\n"
    )


def r2_direct_type5():
    "Whether r2's Type-5 LSA for 192.168.100.0 is a valid direct one."
    output = get_topogen().gears["r2"].vtysh_cmd(
        "show ip ospf database external 192.168.100.0 adv-router 2.2.2.2 json",
        isjson=True,
    )
    lsas = output.get("asExternalLinkStates", [])
    return (
        len(lsas) == 1
        and not lsas[0].get("translatedFromType7", False)
        and lsas[0].get("lsaAge", 3600) < 3600
    )


# What a PAN config commit sends to ospfd.
PAN_COMMIT = [
    "no area 0.0.0.3 nssa",
    "area 0.0.0.3 nssa translate-always no-summary",
]
COMMIT_START = None
AREA_START = None
MAXAGE_TYPE5 = None


def test_pan_commit_1():
    "First commit, r2's Type-5 LSAs are translations of its Type-7 LSAs."
    global COMMIT_START

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    COMMIT_START = time.time()
    r2conf(PAN_COMMIT)


def test_pan_commit_2():
    "Second commit, while r2's Type-5 LSAs are direct ones."
    global AREA_START, MAXAGE_TYPE5

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    if COMMIT_START is None:
        pytest.skip("PAN commit #1 not applied")

    # Test precondition: r2's Type-5 LSAs must be direct ones, or the bug
    # isn't exercised. They are until r2 reoriginates its Type-7 LSAs
    # (OSPF_ASBR_NSSA_REDIST_UPDATE_DELAY, 9s) and translates them.
    _, result = topotest.run_and_expect(r2_direct_type5, True, count=10, wait=0.5)
    assert result, "r2 didn't originate a direct Type-5 LSA for 192.168.100.0"

    r2conf(PAN_COMMIT)
    AREA_START = time.time()

    # Checked later, the LSAs are reoriginated once r2 translates them again.
    MAXAGE_TYPE5 = maxage_type5(tgen.gears["r2"], "2.2.2.2")
    logger.info("r2's MaxAge Type-5 LSAs after the PAN commit: %s", MAXAGE_TYPE5)


def test_no_type5_after_pan_commits():
    "r2 must not flood Type-5 LSAs into the NSSA area."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    if AREA_START is None:
        pytest.skip("PAN commits not applied")

    # Give r2 a couple of RxmtIntervals (5s) to also show retransmissions.
    remaining = AREA_START + 12 - time.time()
    if remaining > 0:
        topotest.sleep(remaining, "capturing on the NSSA link")

    r2 = tgen.gears["r2"]
    logger.info("r2 neighbors:\n%s", r2.vtysh_cmd("show ip ospf neighbor detail"))
    logger.info("r2 Type-5 LSAs:\n%s", r2.vtysh_cmd("show ip ospf database external"))

    assert_no_type5("after the PAN commits", since=COMMIT_START)


def test_type5_not_maxage_after_pan_commits():
    "r2 must keep its own Type-5 LSAs valid, they are still redistributed."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    if MAXAGE_TYPE5 is None:
        pytest.skip("PAN commits not applied")

    assert not MAXAGE_TYPE5, (
        "r2 set its own Type-5 LSA(s) {} to MaxAge after the PAN commit, "
        "although they are still redistributed".format(MAXAGE_TYPE5)
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
