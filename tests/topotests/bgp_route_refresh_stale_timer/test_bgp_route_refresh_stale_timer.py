#!/usr/bin/env python

# Copyright (c) 2026 by NetDEF, Inc.
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
Regression test for route-refresh (RFC 7313, Enhanced Route
Refresh) stale-timer must not delete valid routes.

Scenario:
  r1 (DUT) --- r2 (route source), iBGP within AS 65001 over a single link.

When r1 issues a REFRESH_REQ (Enhanced Route Refresh), r2 replies with a
Begin-of-RIB (BoRR) marker, re-advertises the AFI/SAFI, and finally an
End-of-RIB (EoRR) marker. On receiving the BoRR, r1 marks the peer's routes
stale and arms the graceful-restart "stalepath-time" safety timer. The
intent of RFC 7313 is that, even if the EoRR never arrives, the stale routes
are kept -- the route-refresh exchange must not be able to withdraw valid
routes. The bug caused r1 to *delete* the still-valid routes when the
safety timer expired without an EoRR. The fix keeps them.

Making the reproduction deterministic
--------------------------------------
The hard part of this test is creating the BoRR->(no EoRR) window reliably.
Naively SIGSTOP-ing r2 right after "clear bgp * soft in" races the refresh:
if r2 is stopped before it sends the BoRR, r1 never arms the timer; if it is
stopped after the EoRR, r1 clears the stale state normally. Either way the
probe survives for the wrong reason and the test passes even against the
buggy code (a false negative).

We remove the race with three measures:

  1. A *large* bulk table on r2 (10.0.0.0/8 /24s, generated at runtime).
     TCP flow-control then keeps r2 from finishing its re-advertisement walk
     for seconds, so the BoRR->EoRR window is wide instead of a few ms.

  2. The probe prefix (198.51.100.0/24) sorts *after* every bulk route, so
     r2 re-advertises it LAST. It therefore stays marked stale on r1 for
     almost the entire refresh walk.

  3. We do not guess the timing: we poll r1 until the probe is observed
     `stale` (which proves the BoRR was processed, the safety timer is armed,
     and the EoRR has not yet arrived) and only THEN SIGSTOP r2. Immediately
     after stopping we assert the probe is *still* stale -- so a missed
     window is a loud failure, never a silent pass.

Then we sleep past stalepath-time and assert the probe is STILL installed in
r1's RIB:
  Pre-fix:  r1 deleted it when the timer expired      -> assertion fails.
  Post-fix: r1 keeps the still-valid route             -> assertion passes.
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

# Probe prefix (TEST-NET-2). Chosen so it sorts AFTER every bulk route and is
# therefore re-advertised last; it must survive the stale timer.
PROBE_PREFIX = "198.51.100.0/24"

# Must match "bgp graceful-restart stalepath-time" in r1/bgpd.conf.
STALEPATH_TIME = 5

# Number of bulk filler routes r2 sources (10.0.0.0/8, /32s) via sharpd. A large
# table makes r2's BoRR re-advertisement walk slow (TCP flow-control), widening
# the BoRR->EoRR window the test depends on. sharpd injects them after start-up
# (asynchronously), so unlike a huge static config it does not slow the daemons
# at boot. If the window is too narrow ("probe never observed stale"), raise
# this; if convergence is too slow, lower it.
NUM_BULK_ROUTES = 5000

# Peer TCP socket buffer (bytes) for both bgpd's, passed as -s/--socket_size and
# pinned into the per-netns tcp_rmem/tcp_wmem. Deliberately tiny so r2 hits TCP
# flow-control during the BoRR re-advertisement and cannot finish the walk (and
# reach the EoRR) before the test samples the probe as stale. See setup_module().
BGP_SOCKET_BUFFER = 4096

# Per-port one-way latency added to the r1<->r2 link (via netem). Combined with
# the tiny socket buffer above, this caps r2's re-advertisement throughput
# (~= buffer / RTT) so the BoRR->EoRR window stretches to seconds. See
# setup_module().
LINK_DELAY_MS = 50


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # Force real TCP flow-control on the r1<->r2 BGP session.
    #
    # The test must observe the probe in its transient BoRR->EoRR "stale"
    # window. On a fast host, r2 re-advertises the whole table in ~150ms and
    # the window closes before the poller (a fresh vtysh per sample, ~230ms
    # apart) ever sees it -- the test then fails with "never observed stale".
    #
    # Shrinking the BGP peer socket buffers keeps r2 from blasting the entire
    # re-advertised table into r1 in one burst: r1's small receive window fills,
    # r2 blocks on write() and drains in lock-step with r1's per-prefix
    # processing, stretching the BoRR->EoRR window to seconds regardless of host
    # speed. Because the probe sorts last it stays stale for that whole span.
    #
    # bgp_socket_set_buffer_size() only ever *raises* the socket buffer to
    # bm->socket_buffer (default 65536), so shrinking requires BOTH: lower the
    # per-netns tcp_rmem/tcp_wmem AND pass a matching small -s/--socket_size so
    # bgpd does not bump it back up.
    for rname, router in router_list.items():
        # tcp_rmem/tcp_wmem are per-netns, so this only touches this router's
        # namespace (unlike net.core.*mem_max/_default, which are not namespaced
        # on older kernels and would leak into parallel CI runs). Pinning all
        # three fields caps TCP window autotuning at BGP_SOCKET_BUFFER.
        for knob in (
            "net.ipv4.tcp_rmem=4096 {0} {0}".format(BGP_SOCKET_BUFFER),
            "net.ipv4.tcp_wmem=4096 {0} {0}".format(BGP_SOCKET_BUFFER),
        ):
            router.run('sysctl -qw "{}"'.format(knob))
        # A small socket buffer only throttles when the bandwidth-delay product
        # is small. Over veth the RTT is ~0, so a tiny window still sustains huge
        # throughput. Add link latency so throughput ~= window/RTT actually
        # bounds r2's send rate and TCP flow-control engages. Applied on both
        # ports of the r1<->r2 link (keepalives are tiny and only see the added
        # delay, never head-of-line blocking, so the session is unaffected).
        router.run(
            "tc qdisc add dev {}-eth0 root netem delay {}ms".format(
                rname, LINK_DELAY_MS
            )
        )

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, "{}/bgpd.conf".format(rname)),
            "-s {}".format(BGP_SOCKET_BUFFER),
        )

    # Only r2 sources routes redistributed into BGP:
    #   - staticd: the single probe prefix (the regression target).
    #   - sharpd:  the bulk filler table, injected at test time (see below).
    r2 = tgen.gears["r2"]
    r2.load_config(TopoRouter.RD_STATIC, os.path.join(CWD, "r2/staticd.conf"))
    r2.load_config(TopoRouter.RD_SHARP, os.path.join(CWD, "r2/sharpd.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _probe_installed(router):
    """Return None when PROBE_PREFIX is installed in the zebra RIB."""
    output = json.loads(
        router.vtysh_cmd("show ip route {} json".format(PROBE_PREFIX))
    )
    expected = {PROBE_PREFIX: [{"installed": True, "protocol": "bgp"}]}
    return topotest.json_cmp(output, expected)


def _probe_stale(router):
    """True when r1 has the probe path marked stale (BoRR processed, no EoRR)."""
    output = json.loads(
        router.vtysh_cmd("show bgp ipv4 unicast {} json".format(PROBE_PREFIX))
    )
    return any(path.get("stale") for path in output.get("paths", []))


def test_bgp_route_refresh_stale_timer():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # 1. Wait for the adjacency to come up on r1.
    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show ip bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {"192.168.1.2": {"state": "Established"}}
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "BGP session to r2 did not establish"

    # 1b. Inject the bulk filler table on r2 via sharpd (fast, asynchronous) and
    #     have bgpd redistribute it. The /32s start at 10.0.0.0 so every one
    #     sorts before the probe (198.51.100.0/24); the probe is therefore
    #     re-advertised LAST during the later BoRR walk.
    r2.vtysh_cmd(
        "sharp install routes 10.0.0.0 nexthop-group bulk {}".format(NUM_BULK_ROUTES)
    )

    # 1c. Wait until r1 has received the full table (bulk + probe) from r2 over
    #     BGP. This is the convergence gate before triggering the refresh.
    expected_prefixes = NUM_BULK_ROUTES + 1  # bulk routes + the probe

    def _bulk_received():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
        # "show bgp ipv4 unicast summary json" returns peers at the top level;
        # the per-afi "ipv4Unicast" wrapper only appears for the unqualified
        # "show bgp summary json". Accept either shape.
        peers = output.get("peers") or output.get("ipv4Unicast", {}).get("peers", {})
        rcvd = peers.get("192.168.1.2", {}).get("pfxRcd", 0)
        return None if rcvd >= expected_prefixes else rcvd

    test_func = functools.partial(_bulk_received)
    _, result = topotest.run_and_expect(test_func, None, count=240, wait=0.5)
    assert result is None, "r1 received {} of {} expected prefixes from r2".format(
        result, expected_prefixes
    )

    # 1d. Confirm the probe itself is installed in r1's RIB before the refresh.
    test_func = functools.partial(_probe_installed, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "r1 never installed probe prefix {}".format(PROBE_PREFIX)

    # 2. Trigger an Enhanced Route Refresh from r1 towards r2 (REFRESH_REQ).
    #    r2 answers with BoRR, re-advertises the (large) table, then EoRR.
    r1.vtysh_cmd("clear bgp * soft in")

    # 3. Synchronize on the BoRR instead of racing it: poll r1 until the probe
    #    is marked stale. That state only exists between r1 receiving the BoRR
    #    (timer armed) and r2 re-advertising the probe / sending the EoRR.
    #    Because the probe is advertised last and the bulk table is large, this
    #    window is seconds wide. SIGSTOP r2 the moment we see it so the EoRR
    #    can never arrive.
    #
    #    r2's pid file lives in /var/run/<routertype>/ (routertype defaults to
    #    "frr"), the same path the lib uses in Router.stopRouter().
    stale_seen = False
    for _ in range(200):
        if _probe_stale(r1):
            r2.run("kill -STOP $(cat /var/run/frr/bgpd.pid)")
            stale_seen = True
            break
        time.sleep(0.05)

    assert stale_seen, (
        "probe {} was never observed stale after the route-refresh: the "
        "BoRR->EoRR window was missed. Increase NUM_BULK_ROUTES to widen "
        "it.".format(PROBE_PREFIX)
    )

    try:
        # 3b. Confirm we really caught the window: the probe must still be
        #     stale right after stopping r2 (i.e. no EoRR slipped through).
        #     This turns a missed window into a loud failure, not a silent
        #     pass that would also "succeed" against the buggy code.
        assert _probe_stale(r1), (
            "probe {} no longer stale immediately after stopping r2 -- the "
            "EoRR arrived before the SIGSTOP; widen the window "
            "(NUM_BULK_ROUTES).".format(PROBE_PREFIX)
        )

        # 4. Sleep past stalepath-time so r1's BoRR safety timer expires while
        #    no EoRR has arrived.
        time.sleep(STALEPATH_TIME + 3)

        # 5. The probe prefix MUST still be installed in r1's RIB, and the
        #    stale marking must have been cleared (route restored, not deleted).
        #    Pre-fix: r1 deleted it when the timer expired -> assertion fails.
        #    Post-fix: r1 keeps the still-valid route       -> assertion passes.
        result = _probe_installed(r1)
        assert result is None, (
            "r1 dropped {} after the route-refresh stale timer expired "
            "without an EoRR (result: {})".format(PROBE_PREFIX, result)
        )
        assert not _probe_stale(r1), (
            "r1 left {} marked stale after the safety timer expired; the "
            "timer should have restored (un-staled) it".format(PROBE_PREFIX)
        )
    finally:
        # 6. Resume r2's bgpd so teardown is clean and the EoRR can flow.
        r2.run("kill -CONT $(cat /var/run/frr/bgpd.pid)")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
