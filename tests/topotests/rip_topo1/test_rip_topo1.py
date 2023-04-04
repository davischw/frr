#!/usr/bin/env python

#
# test_rip_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
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
test_rip_topo1.py: Testing RIPv2

"""

import os
import re
import sys
import pytest
from time import sleep


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib import topotest
from lib.topogen import Topogen, get_topogen

fatal_error = ""

pytestmark = [pytest.mark.ripd]

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    # Setup RIP Routers
    for i in range(1, 4):
        tgen.add_router("r%s" % i)

    #
    # On main router
    # First switch is for a dummy interface (for local network)
    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])
    #
    # Switches for RIP

    # switch 2 switch is for connection to RIP router
    switch = tgen.add_switch("sw2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # switch 3 is between RIP routers
    switch = tgen.add_switch("sw3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"], nodeif="r3-eth1")

    # switch 4 is stub on remote RIP router
    switch = tgen.add_switch("sw4")
    switch.add_link(tgen.gears["r3"], nodeif="r3-eth0")

    switch = tgen.add_switch("sw5")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("sw6")
    switch.add_link(tgen.gears["r1"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    print("\n\n** %s: Setup Topology" % module.__name__)
    print("******************************************\n")

    thisDir = os.path.dirname(os.path.realpath(__file__))
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    net = tgen.net

    # Starting Routers
    #
    for i in range(1, 4):
        net["r%s" % i].loadConf("zebra", "%s/r%s/zebra.conf" % (thisDir, i))
        net["r%s" % i].loadConf("ripd", "%s/r%s/ripd.conf" % (thisDir, i))
        tgen.gears["r%s" % i].start()

    # For debugging after starting FRR daemons, uncomment the next line
    # tgen.mininet_cli()


def teardown_module(module):
    print("\n\n** %s: Shutdown Topology" % module.__name__)
    print("******************************************\n")
    tgen = get_topogen()
    tgen.stop_topology()


def test_router_running():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** Check if FRR is running on each Router node")
    print("******************************************\n")

    # Make sure that all daemons are running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def show_rip_status_json(router):
    """Parse router 'show ip rip status' and generate JSON output """
    output = router.vtysh_cmd("show ip rip status")
    json = {
            "routingNetworks": [],
            "passiveInterfaces": [],
            "routingInformation": {},
    }

    STEP_HEADER = 1
    STEP_VERSION = 2
    STEP_ROUTING_NETWORKS = 3
    STEP_PASSIVE_INTERFACES = 4
    STEP_ROUTING_INFORMATION = 5
    step = STEP_HEADER

    for line in output.splitlines():
        if step == STEP_HEADER:
            match = re.match(r"\s+Interface\s+Send\s+Recv\s+Key\-chain", line)
            if match is not None:
                step = STEP_VERSION
                continue

        elif step == STEP_VERSION:
            match = re.match(r"\s+Routing for Networks:", line)
            if match is not None:
                step = STEP_ROUTING_NETWORKS
                continue

        elif step == STEP_ROUTING_NETWORKS:
            match = re.match(r"\s+Passive Interface\(s\):", line)
            if match is not None:
                step = STEP_PASSIVE_INTERFACES
                continue

            match = re.match(r"\s+Routing Information Sources:", line)
            if match is not None:
                step = STEP_ROUTING_INFORMATION
                continue

            match = re.match(r"    (.+)", line)
            if match is not None:
                json["routingNetworks"].append(match[1])

        elif step == STEP_PASSIVE_INTERFACES:
            match = re.match(r"\s+Routing Information Sources:", line)
            if match is not None:
                step = STEP_ROUTING_INFORMATION
                continue

            match = re.match(r"    (.+)", line)
            if match is not None:
                json["passiveInterfaces"].append(match[1])

        elif step == STEP_ROUTING_INFORMATION:
            match = re.match(
                r"\s+Gateway\s+BadPackets BadRoutes  Distance Last Update",
                line)
            if match is not None:
                continue

            match = re.match(
                r"\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)",
                line)
            if match is not None:
                json["routingInformation"][match[1]] = {
                    "badPackets": int(match[2]),
                    "badRoutes": int(match[3]),
                    "distance": int(match[4]),
                    "lastUpdate": match[5],
                }

    return json


def expect_rip_status(router, status):
    "Expect 'status' in router 'router'."
    def test_function():
        return topotest.json_cmp(show_rip_status_json(router), status)

    _, result = topotest.run_and_expect(test_function, None, count=15, wait=1)
    assert result is None, "Unexpected RIP status in {}".format(router.name)


def test_converge_protocols():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Waiting for protocols convergence")
    print("******************************************\n")

    # Not really implemented yet - just sleep 11 secs for now
    sleep(21)

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_rip_status():
    global fatal_error
    tgen = get_topogen()
    net = tgen.net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    # Verify RIP Status
    print("\n\n** Verifing RIP status")
    print("******************************************\n")

    expect_rip_status(tgen.gears["r1"], {
        "routingNetworks": ["193.1.1.0/26", "r1-eth2", "r1-eth3"],
        "passiveInterfaces": ["r1-eth3"],
        "routingInformation": {
            "193.1.1.2": {
                "distance": 120,
            }
        }
    })

    expect_rip_status(tgen.gears["r2"], {
        "routingNetworks": ["193.1.1.0/26", "193.1.2.0/24"],
        "routingInformation": {
            "193.1.1.1": {
                "distance": 120,
            },
            "193.1.2.2": {
                "distance": 120,
            }
        }
    })

    expect_rip_status(tgen.gears["r3"], {
        "routingNetworks": ["193.1.2.0/24"],
        "routingInformation": {
            "193.1.2.1": {
                "distance": 120,
            }
        }
    })

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_rip_routes():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify RIP Status
    print("\n\n** Verifing RIP routes")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = "%s/r%s/show_ip_rip.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = net["r%s" % i].cmd('vtysh -c "show ip rip" 2> /dev/null').rstrip()
            # Drop Time
            actual = re.sub(r"[0-9][0-9]:[0-5][0-9]", "XX:XX", actual)
            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual SHOW IP RIP",
                title2="expected SHOW IP RIP",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write("r%s failed SHOW IP RIP check:\n%s\n" % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "SHOW IP RIP failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_zebra_ipv4_routingTable():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifing Zebra IPv4 Routing Table")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = "%s/r%s/show_ip_route.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r%s" % i]
                .cmd('vtysh -c "show ip route" 2> /dev/null | grep "^R"')
                .rstrip()
            )
            # Drop timers on end of line
            actual = re.sub(r", [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", "", actual)
            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual Zebra IPv4 routing table",
                title2="expected Zebra IPv4 routing table",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r%s failed Zebra IPv4 Routing Table Check:\n%s\n" % (i, diff)
                )
                failures += 1
            else:
                print("r%s ok" % i)

            assert (
                failures == 0
            ), "Zebra IPv4 Routing Table verification failed for router r%s:\n%s" % (
                i,
                diff,
            )

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_shutdown_check_stderr():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifing unexpected STDERR output from daemons")
    print("******************************************\n")

    net["r1"].stopRouter()

    log = net["r1"].getStdErr("ripd")
    if log:
        print("\nRIPd StdErr Log:\n" + log)
    log = net["r1"].getStdErr("zebra")
    if log:
        print("\nZebra StdErr Log:\n" + log)


if __name__ == "__main__":

    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
