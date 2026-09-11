#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_pim_igmpv3_query_numsrc.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_pim_igmpv3_query_numsrc.py: Test IGMPv3 query source list bounds checking.

A group-and-source-specific IGMPv3 query carries a "Number of Sources" field
followed by that many source addresses.  pimd used to trust the field instead
of comparing it against the number of bytes it actually received, so a query
that claimed more sources than it carried made pimd walk off the end of its
receive buffer while lowering the source timers, crashing the daemon.

Reaching the vulnerable loop requires existing group state, so the test first
establishes it with an IGMPv3 membership report and only then injects the
malformed query.

Topology:

                  192.168.100.0/24          192.168.101.0/24
    +----+                          +----+                     +----+
    | h1 |-------------- s1 --------| r1 |-------- s2 ---------| h2 |
    +----+ .10                   .1 +----+ .1               .10+----+
   receiver                       ip igmp                     source
                                   ip pim
"""

import os
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.pimd]

#
# The group and sources h1 pretends to be interested in.  An SSM group is used
# so that no RP configuration is needed for the group state to come up.
#
GROUP = "232.1.1.1"
SOURCE_A = "192.168.101.10"
SOURCE_B = "192.168.101.11"

# h1's address, deliberately higher than r1's so that r1 stays the elected
# querier and the query is processed rather than triggering querier election.
RECEIVER = "192.168.100.10"

SENDER = os.path.join(CWD, "igmpv3_send.py")


def setup_module(module):
    topodef = {
        "s1": ("r1", "h1"),
        "s2": ("r1", "h2"),
    }
    tgen = Topogen(topodef, module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(f"{CWD}/{router.name}/frr.conf")

    tgen.start_router()


def teardown_module(module):
    tgen = get_topogen()
    tgen.stop_topology()


#
# Helpers
#


def send_igmpv3(kind, sources, numsrc=None):
    """
    Run the scapy based injector inside h1's namespace.

    `kind` is either "report" or "query", `sources` the source addresses to
    actually put in the packet and `numsrc` an optional override of the
    query's "Number of Sources" field.
    """
    tgen = get_topogen()

    cmd = f"python3 {SENDER} --iface h1-eth0 --src {RECEIVER} --group {GROUP}"
    for source in sources:
        cmd += f" --source {source}"
    if numsrc is not None:
        cmd += f" --numsrc {numsrc}"
    cmd += f" {kind}"

    tgen.gears["h1"].cmd_raises(cmd)


def igmp_sources(router, group=GROUP, interface="r1-eth0"):
    """
    Return the sorted list of source addresses `router` currently tracks for
    `group` on `interface`, or None when the group is not known at all.
    """
    output = router.vtysh_cmd("show ip igmp sources json", isjson=True)

    # "show ip igmp sources json" keys the groups by address underneath the
    # interface they were learned on: {"r1-eth0": {"232.1.1.1": {"sources": []}}}
    entry = output.get(interface, {}).get(group)
    if entry is None:
        return None

    return sorted(source["source"] for source in entry.get("sources", []))


def expect_igmp_sources(expected, count=30, wait=1):
    "Wait until r1 tracks exactly `expected` as the sources of GROUP."
    tgen = get_topogen()
    router = tgen.gears["r1"]

    def _get_sources():
        return igmp_sources(router)

    _, result = topotest.run_and_expect(_get_sources, expected, count=count, wait=wait)
    return result


#
# Tests
#


def test_igmp_group_state():
    "Establish the group state the malformed query needs to reach the bug"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    send_igmpv3("report", [SOURCE_A, SOURCE_B])

    expected = sorted([SOURCE_A, SOURCE_B])
    result = expect_igmp_sources(expected)
    assert result == expected, f"r1 did not learn {expected} for {GROUP}, got {result}"


def test_igmpv3_query_inflated_numsrc():
    "A query claiming more sources than it carries must not crash pimd"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # 65535 is the largest value the 16 bit field can hold: an unpatched pimd
    # reads 65535 * 4 bytes of source addresses out of a query that carries
    # one, running ~256KB past the end of the 10000 byte receive buffer.  The
    # smaller values stay inside that buffer but still read past the bytes
    # that were actually received, so they are acted on as stale source
    # addresses rather than crashing.
    for numsrc in [65535, 4096, 64, 2]:
        logger.info(f"Sending IGMPv3 query for {GROUP} with numsrc={numsrc}")
        send_igmpv3("query", [SOURCE_A], numsrc=numsrc)

    # A query with the source list truncated away entirely is the degenerate
    # case of the same bug.
    send_igmpv3("query", [], numsrc=1)

    # pimd must still be alive and answering.
    assert (
        r1.check_router_running() == ""
    ), "r1 daemons stopped running after the malformed IGMPv3 queries"

    def _discarded():
        # grep exits 1 and prints "0" when there is no match yet.
        out = r1.run('grep -c "truncated source list" pimd.log 2>/dev/null')
        return int(out.strip() or 0)

    _, discarded = topotest.run_and_expect(_discarded, 5, count=20, wait=1)
    assert discarded == 5, (
        "r1 did not log all 5 malformed IGMPv3 queries as discarded, "
        "counted {}".format(discarded)
    )

    # Discarded queries must not have touched the group state either.
    expected = sorted([SOURCE_A, SOURCE_B])
    result = igmp_sources(r1)
    assert result == expected, (
        "malformed IGMPv3 queries changed the group state, "
        "expected {} got {}".format(expected, result)
    )


def test_igmpv3_query_valid_numsrc():
    "A well formed group-and-source-specific query must still be processed"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Query only SOURCE_A.  That lowers its source timer to the Last Member
    # Query Time (2s with the default robustness of 2 and a 1s last member
    # query interval), and since nothing answers, the source is dropped while
    # SOURCE_B keeps its much longer group membership interval.
    send_igmpv3("query", [SOURCE_A])

    result = expect_igmp_sources([SOURCE_B])
    assert result == [SOURCE_B], (
        f"r1 did not expire {SOURCE_A} after a valid group-and-source-specific query, "
        f"sources are {result}"
    )

    assert (
        r1.check_router_running() == ""
    ), "r1 daemons stopped running after the valid IGMPv3 query"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
