#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_template.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_template.py: template test.
"""

import os
import re
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.staticd]


def setup_module(mod):
    topodef = {
        "s1": ("r1")
    }

    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(f"{CWD}/{router.name}/frr.conf")

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def parse_uptime(uptime):
    "Parse the format 00:00:00 into seconds"
    match = re.match(r"(\d+):(\d+):(\d+)", uptime)
    assert match is not None
    return (int(match[1]) * 60 * 60) + (int(match[2]) * 60) + int(match[3])


def test_static_route_no_flap():
    "Test that static route doesn't flap when interface update is received"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(5, "introduce some route uptime")

    # Get initial uptime
    route_output = tgen.gears["r1"].vtysh_cmd("show ip route json", isjson=True)
    uptime_before = parse_uptime(route_output["192.168.1.0/24"][0]["uptime"])

    topotest.sleep(5, "add more uptime before sending interface update")

    # Change the interface MTU
    tgen.gears["r1"].run("ip link set r1-eth0 mtu 1490")

    # Verify uptime again
    route_output = tgen.gears["r1"].vtysh_cmd("show ip route json", isjson=True)
    uptime_after = parse_uptime(route_output["192.168.1.0/24"][0]["uptime"])

    assert uptime_before < uptime_after, f"static route flapped: uptime in seconds before {uptime_before} after {uptime_after}"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
