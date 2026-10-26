#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Network Education Foundation, Inc. ("NetDEF")
#                    Rafael Zalamena

"""
test_pim_bsr_rp_install.py: Test PIM BSR learned RPs installation.

Reproduces the Nexus 9K (BSR + C-RPs) <-> Palo Alto (FRR) topology where
the BSR information is accepted (`show ip pim bsrp-info` shows the RPs as
ACTIVE) but the BSR RP is never installed in `show ip pim rp-info`, with
and without a fallback RP configured for the same group range.

    +----------------------------------------------+
    | nexus (NX-OS stand-in)                        |
    |   lo: 10.192.99.1    -> BSR, priority 210,    |
    |                         hash-mask-len 30      |
    |   lo: 172.31.99.100  -> C-RP, priority 100    |
    |   lo: 172.31.99.99   -> C-RP, priority 10     |
    |   lo: 172.31.99.98   -> fallback RP           |
    +----------------------------------------------+
       | nexus-eth0                 | nexus-eth1
       | 10.192.91.178/29           | 10.192.92.178/29
       |                            |
       | pa-eth0                    | pa-eth2
       | 10.192.91.177/29           | 10.192.92.177/29
    +----------------------------------------------+
    | pa (FRR)                                      |
    |   static routes to BSR and C-RPs via pa-eth0, |
    |   to the fallback RP via pa-eth2              |
    +----------------------------------------------+
                  | pa-eth1 10.0.1.1/24 (IGMP)
                  |
                  | h1-eth0 10.0.1.2/24
    +----------------------------------------------+
    | h1: receiver for 239.1.1.1                    |
    +----------------------------------------------+
"""

import os
import subprocess
import sys
import pytest
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.pimd]

BSR_ADDRESS = "10.192.99.1"
BSR_PRIORITY = 210
BSR_HASH_MASK_LENGTH = 30
CRP_HIGH = "172.31.99.100"
CRP_LOW = "172.31.99.99"
FALLBACK_RP = "172.31.99.98"
# No route to these addresses: never reachable.
UNREACHABLE_RP = "192.0.2.1"
OTHER_RP = "192.0.2.2"
GROUP_RANGE = "224.0.0.0/4"
GROUP = "239.1.1.1"
# Short C-RP hold time so the BSR loss can be observed through expiration.
RP_HOLD_TIME = 20

bsm_sender = None
bsm_sender_starts = 0
receiver = None


def build_topo(tgen):
    tgen.add_router("nexus")
    tgen.add_router("pa")
    tgen.add_host("h1", "10.0.1.2/24", "via 10.0.1.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["nexus"])
    switch.add_link(tgen.gears["pa"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["pa"])
    switch.add_link(tgen.gears["h1"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["nexus"])
    switch.add_link(tgen.gears["pa"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for name in ["nexus", "pa"]:
        router = tgen.gears[name]
        router.load_frr_config(os.path.join(CWD, f"{name}/frr.conf"))
    # For the IPv6 RP configuration tests.
    tgen.gears["pa"].load_config(TopoRouter.RD_PIM6)

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()

    stop_bsm_sender()
    if receiver is not None and receiver.poll() is None:
        receiver.terminate()
        receiver.wait()

    tgen.stop_topology()


def start_bsm_sender(crps=((CRP_HIGH, 100), (CRP_LOW, 10))):
    "Start the Nexus BSR imitation with the (C-RP, priority) `crps`."
    global bsm_sender, bsm_sender_starts

    tgen = get_topogen()
    bsm_sender_starts += 1
    log_path = os.path.join(tgen.logdir, f"nexus-send_bsm-{bsm_sender_starts}.log")
    with open(log_path, "w") as bsm_log:
        bsm_sender = tgen.gears["nexus"].popen(
            [
                sys.executable,
                os.path.join(CWD, "send_bsm.py"),
                "10.192.91.178",
                BSR_ADDRESS,
                f"--bsr-priority={BSR_PRIORITY}",
                f"--hash-mask-length={BSR_HASH_MASK_LENGTH}",
                f"--group={GROUP_RANGE}",
                *[f"--rp={crp},{priority},{RP_HOLD_TIME}" for crp, priority in crps],
                "--interval=5",
            ],
            stdout=bsm_log,
            stderr=subprocess.STDOUT,
        )

    def sent_first_bsm():
        if bsm_sender.poll() is not None:
            return f"send_bsm.py exited with {bsm_sender.returncode}"
        with open(log_path) as bsm_log:
            if "sent BSM #1" in bsm_log.read():
                return None
        return "no BSM sent yet"

    _, result = topotest.run_and_expect(sent_first_bsm, None, count=10, wait=1)
    assert result is None, f"{result}, see {log_path}"


def stop_bsm_sender():
    "Stop the Nexus BSR imitation, if running."
    if bsm_sender is not None and bsm_sender.poll() is None:
        bsm_sender.terminate()
        bsm_sender.wait()


def expect_json(router, command, expected, count=30, wait=1):
    tgen = get_topogen()
    test_func = partial(topotest.router_json_cmp, tgen.gears[router], command, expected)
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assert result is None, f'"{router}" unexpected "{command}" output: {result}'


def expect_upstream_joined(rp, interface, count=30):
    """
    The receiver's (*,G) must be joined towards `rp` reached via `interface`.

    `rpfAddress` is looked up from the RP table when displayed: the
    (*,G) incoming interface is what tells which RP it was joined towards.
    """
    expect_json(
        "pa",
        "show ip pim upstream json",
        {
            GROUP: {
                "*": {
                    "rpfAddress": rp,
                    "inboundInterface": interface,
                    "joinState": "Joined",
                }
            }
        },
        count=count,
    )


def test_pim_neighbor():
    "PA must see the Nexus as PIM neighbor on both links."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_json(
        "pa",
        "show ip pim neighbor json",
        {
            "pa-eth0": {"10.192.91.178": {"interface": "pa-eth0"}},
            "pa-eth2": {"10.192.92.178": {"interface": "pa-eth2"}},
        },
        count=60,
    )


def test_pim_rpf_to_bsr():
    "PA must resolve the BSR, C-RP and fallback RP addresses via static routes."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for address, nexthop, interface in [
        (BSR_ADDRESS, "10.192.91.178", "pa-eth0"),
        (CRP_HIGH, "10.192.91.178", "pa-eth0"),
        (CRP_LOW, "10.192.91.178", "pa-eth0"),
        (FALLBACK_RP, "10.192.92.178", "pa-eth2"),
    ]:
        expect_json(
            "pa",
            "show ip route json",
            {
                f"{address}/32": [
                    {
                        "protocol": "static",
                        "selected": True,
                        "nexthops": [{"ip": nexthop, "interfaceName": interface}],
                    }
                ]
            },
        )


def test_receiver_join():
    "Start the receiver: PA must learn its group membership."
    global receiver

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    receiver = tgen.gears["h1"].popen(
        [
            sys.executable,
            os.path.join(CWD, "../lib/mcast-tester.py"),
            GROUP,
            "h1-eth0",
        ]
    )
    expect_json(
        "pa",
        "show ip pim upstream json",
        {GROUP: {"*": {"sourceIgmp": True}}},
    )


def test_pim_bsm_send():
    "Start the Nexus BSR imitation."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    start_bsm_sender()


def test_pim_bsr_elected():
    "PA must accept the Nexus as the elected BSR."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_json(
        "pa",
        "show ip pim bsr json",
        {"bsr": BSR_ADDRESS, "priority": BSR_PRIORITY, "state": "ACCEPT_PREFERRED"},
    )


def test_pim_bsrp_info():
    "PA must have learned both C-RPs from the BSR."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_json(
        "pa",
        "show ip pim bsrp-info json",
        {
            "BSR Address": BSR_ADDRESS,
            GROUP_RANGE: {
                CRP_LOW: {"Rp Address": CRP_LOW, "Rp Priority": 10},
                CRP_HIGH: {"Rp Address": CRP_HIGH, "Rp Priority": 100},
                "Pending RP count": 0,
            },
        },
    )


def test_pim_rp_info_bsr():
    """
    The BSR elected RP (lowest priority value: 172.31.99.99) must be
    installed in the RP table and used to join the receiver's group.

    Regression: `pim_instate_pend_list` used to move the RPs to the
    active BSR list without calling `pim_rp_new`, so `rp-info` only
    showed the 232.0.0.0/8 SSM entry.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_rp_info_bsr()
    expect_upstream_joined(CRP_LOW, "pa-eth0")


def expect_rp_info_bsr():
    expect_json(
        "pa",
        "show ip pim rp-info json",
        {
            CRP_LOW: [
                {
                    "rpAddress": CRP_LOW,
                    "group": GROUP_RANGE,
                    "source": "BSR",
                    "outboundInterface": "pa-eth0",
                }
            ]
        },
    )


def expect_rp_info_fallback():
    expect_json(
        "pa",
        "show ip pim rp-info json",
        {
            FALLBACK_RP: [
                {
                    "rpAddress": FALLBACK_RP,
                    "group": GROUP_RANGE,
                    "source": "Fallback",
                    "outboundInterface": "pa-eth2",
                }
            ]
        },
    )


def test_pim_rp_info_bsr_with_fallback():
    """
    Configure a fallback RP for the same range (PAN-OS external RP without
    override) and learn the BSR RPs again: the BSR RP must be installed
    and preferred over the fallback RP.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pa = tgen.gears["pa"]
    pa.vtysh_cmd(f"configure terminal\nip pim rp {FALLBACK_RP} fallback {GROUP_RANGE}")
    expect_rp_info_fallback()
    expect_rp_info_bsr()
    expect_upstream_joined(CRP_LOW, "pa-eth0")

    # Forget the BSR learned RPs (with the BSR stopped so no BSM installs
    # them again meanwhile): the fallback RP takes over.
    stop_bsm_sender()
    pa.vtysh_cmd("clear ip pim bsr-data")
    expect_range_rp_sources(["Fallback"])
    expect_upstream_joined(FALLBACK_RP, "pa-eth2")

    # Learn the BSR RPs again, now with the fallback RP present.
    start_bsm_sender()
    expect_rp_info_bsr()
    expect_rp_info_fallback()
    expect_upstream_joined(CRP_LOW, "pa-eth0")


def test_pim_prefix_list_rp_removal():
    """
    Removing a prefix-list static RP while BSR RPs exist for 224.0.0.0/4
    must delete it, whether its address has other (fallback) ranges or not.

    Regression: with other ranges, the removal installed the 224.0.0.0/4
    BSR RP instead and returned, leaving the RP behind without its
    prefix-list.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pa = tgen.gears["pa"]
    pa.vtysh_cmd(
        "configure terminal\nip prefix-list RP-PLIST seq 5 permit 238.0.0.0/8 le 32"
    )
    for fallback in [True, False]:
        if fallback:
            pa.vtysh_cmd(
                f"configure terminal\nip pim rp {CRP_HIGH} fallback 236.0.0.0/8"
            )
        pa.vtysh_cmd(f"configure terminal\nip pim rp {CRP_HIGH} prefix-list RP-PLIST")
        expect_json(
            "pa",
            "show ip pim rp-info json",
            {CRP_HIGH: [{"prefixList": "RP-PLIST", "source": "Static"}]},
        )

        pa.vtysh_cmd(
            f"configure terminal\nno ip pim rp {CRP_HIGH} prefix-list RP-PLIST"
        )
        if fallback:
            expect_rp_address_ranges(CRP_HIGH, [("236.0.0.0/8", "Fallback")])
            pa.vtysh_cmd(
                f"configure terminal\nno ip pim rp {CRP_HIGH} fallback 236.0.0.0/8"
            )
        expect_rp_address_ranges(CRP_HIGH, [])

    pa.vtysh_cmd("configure terminal\nno ip prefix-list RP-PLIST")
    expect_rp_info_bsr()


def test_pim_static_rp_removal_restores_bsr_rp():
    """
    Override the BSR RP with a static RP for the range, stop the BSR and
    remove the static RP: the BSR RP (still within its hold time) must be
    installed again right away.

    Regression: removing the static RP looked up the BSR RPs of a /0 range
    (deleting by RP address), so nothing was installed until the next BSM.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pa = tgen.gears["pa"]
    pa.vtysh_cmd(f"configure terminal\nip pim rp {CRP_HIGH} {GROUP_RANGE}")
    expect_json(
        "pa",
        "show ip pim rp-info json",
        {CRP_HIGH: [{"group": GROUP_RANGE, "source": "Static"}]},
    )
    # The static RP replaced the BSR RP.
    expect_rp_address_ranges(CRP_LOW, [])

    stop_bsm_sender()
    pa.vtysh_cmd(f"configure terminal\nno ip pim rp {CRP_HIGH} {GROUP_RANGE}")
    # Well within the C-RPs hold time.
    expect_json(
        "pa",
        "show ip pim rp-info json",
        {CRP_LOW: [{"group": GROUP_RANGE, "source": "BSR"}]},
        count=5,
    )


def test_pim_rp_info_fallback_after_bsr_loss():
    """
    Stop the BSR: once the C-RPs hold time expires only the fallback RP
    must remain for the range and the receiver's group must be joined
    towards it.

    Regression: the (*,G) using the expired BSR RP was left not joined
    instead of moving to the fallback RP.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    stop_bsm_sender()

    expect_range_rp_sources(["Fallback"], count=RP_HOLD_TIME + 30)
    expect_upstream_joined(FALLBACK_RP, "pa-eth2")


def test_pim_rp_overlap_unreachable():
    """
    A second RP for the group range of an RP of the same kind must be
    rejected, but one transaction can still move the range of an
    unreachable RP to another RP.

    Regression: the second RP was accepted in the configuration but only
    replaced the first one in pimd, so the running configuration lost the
    first one. When the first RP was unreachable, the second one replaced
    the 224.0.0.0/4 pseudo-RP in the RP table instead, leaving the first RP
    behind, and removing the first RP then left the table without the
    pseudo-RP: pimd aborted on the next RP lookup.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pa = tgen.gears["pa"]
    pa.vtysh_cmd(f"configure terminal\nip pim rp {OTHER_RP} {GROUP_RANGE}")
    expect_rp_address_ranges(OTHER_RP, [(GROUP_RANGE, "Static")])

    output = pa.vtysh_cmd(
        f"configure terminal\nip pim rp {UNREACHABLE_RP} {GROUP_RANGE}"
    )
    assert "already has RP" in output, f"second RP not rejected: {output}"
    expect_rp_address_ranges(OTHER_RP, [(GROUP_RANGE, "Static")])
    expect_rp_address_ranges(UNREACHABLE_RP, [])
    output = pa.vtysh_cmd("show running-config")
    assert UNREACHABLE_RP not in output, f"rejected RP configured: {output}"

    pa.vtysh_cmd(
        "configure terminal\nipv6 pim rp 2001:db8::1 ff0f::/16\n"
        "ipv6 pim rp 2001:db8::1 fallback ff0f::/16"
    )
    output = pa.vtysh_cmd("configure terminal\nipv6 pim rp 2001:db8::2 FF0F::0/16")
    assert "already has RP" in output, f"second IPv6 RP not rejected: {output}"
    expect_rp_address_ranges(
        "2001:db8::1", [("ff0f::/16", "Static"), ("ff0f::/16", "Fallback")], af="ipv6"
    )
    pa.vtysh_cmd(
        "configure terminal\nno ipv6 pim rp 2001:db8::1 ff0f::/16\n"
        "no ipv6 pim rp 2001:db8::1 fallback ff0f::/16"
    )
    expect_rp_address_ranges("2001:db8::1", [], af="ipv6")

    # The rejection checks the candidate configuration: in one transaction
    # the range is already removed from OTHER_RP.
    pa.vtysh_cmd(
        f"configure terminal\nip pim rp {UNREACHABLE_RP} 238.0.0.0/8\n"
        f"ip pim rp {OTHER_RP} 237.0.0.0/8"
    )
    swap = os.path.join(tgen.logdir, "pa", "rp-swap.conf")
    with open(swap, "w") as f:
        f.write(
            f"no ip pim rp {OTHER_RP} {GROUP_RANGE}\n"
            f"ip pim rp {UNREACHABLE_RP} {GROUP_RANGE}\n"
        )
    pa.cmd(f"vtysh -f {swap}")
    expect_rp_address_ranges(
        UNREACHABLE_RP, [(GROUP_RANGE, "Static"), ("238.0.0.0/8", "Static")]
    )
    expect_rp_address_ranges(OTHER_RP, [("237.0.0.0/8", "Static")])

    pa.vtysh_cmd(
        f"configure terminal\nno ip pim rp {OTHER_RP} 237.0.0.0/8\n"
        f"no ip pim rp {UNREACHABLE_RP} 238.0.0.0/8\n"
        f"no ip pim rp {UNREACHABLE_RP} {GROUP_RANGE}"
    )
    expect_range_rp_sources(["Fallback"])
    expect_rp_address_ranges(UNREACHABLE_RP, [])
    assert pa.check_router_running() == "", "pa daemons stopped running"


def test_pim_rp_delete_one_group_range():
    """
    Removing one group range of a static RP address must keep its other
    ranges and its fallback range.

    Regression: the static RP was deleted by address only, so the first
    range of that address was removed (238.0.0.0/8 here) together with
    the fallback RP using the same address.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pa = tgen.gears["pa"]
    pa.vtysh_cmd(
        f"configure terminal\nip pim rp {FALLBACK_RP} 238.0.0.0/8\n"
        f"ip pim rp {FALLBACK_RP} 239.0.0.0/8"
    )
    expect_rp_address_ranges(
        FALLBACK_RP,
        [
            ("238.0.0.0/8", "Static"),
            ("239.0.0.0/8", "Static"),
            (GROUP_RANGE, "Fallback"),
        ],
    )

    pa.vtysh_cmd(f"configure terminal\nno ip pim rp {FALLBACK_RP} 239.0.0.0/8")
    expect_rp_address_ranges(
        FALLBACK_RP, [("238.0.0.0/8", "Static"), (GROUP_RANGE, "Fallback")]
    )

    pa.vtysh_cmd(f"configure terminal\nno ip pim rp {FALLBACK_RP} 238.0.0.0/8")
    expect_rp_address_ranges(FALLBACK_RP, [(GROUP_RANGE, "Fallback")])


def test_pim_static_rp_removal_unreachable_bsr_rp():
    """
    Override an unreachable BSR RP (already tracked as the static RP of
    another range) with a static RP and remove the static RP: the BSR RP
    is installed again and the receiver's group must move to the fallback
    RP, without configuration error.

    Regression: the removal reported an error because the restored BSR RP
    is unreachable, and the group stayed joined towards the removed RP.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pa = tgen.gears["pa"]
    pa.vtysh_cmd(f"configure terminal\nip pim rp {UNREACHABLE_RP} 238.0.0.0/8")
    start_bsm_sender(crps=[(UNREACHABLE_RP, 10)])
    expect_json(
        "pa",
        "show ip pim rp-info json",
        {UNREACHABLE_RP: [{"group": GROUP_RANGE, "source": "BSR"}]},
    )
    expect_upstream_joined(FALLBACK_RP, "pa-eth2")

    pa.vtysh_cmd(f"configure terminal\nip pim rp {CRP_LOW} {GROUP_RANGE}")
    expect_upstream_joined(CRP_LOW, "pa-eth0")

    def config_errors():
        output = pa.cmd(
            "grep -c 'error processing configuration change' pimd.log || true"
        ).strip()
        assert output.isdigit(), f"cannot read pimd.log: {output!r}"
        return int(output)

    errors = config_errors()
    pa.vtysh_cmd(f"configure terminal\nno ip pim rp {CRP_LOW} {GROUP_RANGE}")
    expect_json(
        "pa",
        "show ip pim rp-info json",
        {UNREACHABLE_RP: [{"group": GROUP_RANGE, "source": "BSR"}]},
    )
    expect_upstream_joined(FALLBACK_RP, "pa-eth2")
    assert config_errors() == errors, "static RP removal reported an error"

    stop_bsm_sender()
    pa.vtysh_cmd(
        f"configure terminal\nno ip pim rp {UNREACHABLE_RP} 238.0.0.0/8\n"
        "do clear ip pim bsr-data"
    )
    expect_range_rp_sources(["Fallback"])


def test_pim_rp_removal_keeps_other_kind():
    """
    Removing the last static group range or prefix-list of an RP address
    must keep its fallback configuration, for IPv4 and IPv6.

    Regression: IPv4 ignored the fallback access-list and IPv6 always
    removed the whole RP address configuration.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pa = tgen.gears["pa"]
    rp = "192.0.2.3"
    pa.vtysh_cmd(
        "configure terminal\n"
        "access-list RP-ACL seq 5 permit ip any 236.0.0.0 0.255.255.255\n"
        f"ip pim rp {rp} fallback access-list RP-ACL\n"
        f"ip pim rp {rp} 237.0.0.0/8"
    )
    expect_rp_address_ranges(rp, [("237.0.0.0/8", "Static"), ("RP-ACL", "Fallback")])
    pa.vtysh_cmd(f"configure terminal\nno ip pim rp {rp} 237.0.0.0/8")
    expect_rp_address_ranges(rp, [("RP-ACL", "Fallback")])
    pa.vtysh_cmd(
        f"configure terminal\nno ip pim rp {rp} fallback access-list RP-ACL\n"
        "no access-list RP-ACL"
    )
    expect_rp_address_ranges(rp, [])

    rp = "2001:db8::1"
    pa.vtysh_cmd(
        "configure terminal\n"
        "ipv6 prefix-list RP6-PLIST seq 5 permit ff0d::/16 le 128\n"
        f"ipv6 pim rp {rp} fallback ff0e::/16\n"
        f"ipv6 pim rp {rp} ff0f::/16"
    )
    expect_rp_address_ranges(
        rp, [("ff0f::/16", "Static"), ("ff0e::/16", "Fallback")], af="ipv6"
    )
    pa.vtysh_cmd(f"configure terminal\nno ipv6 pim rp {rp} ff0f::/16")
    expect_rp_address_ranges(rp, [("ff0e::/16", "Fallback")], af="ipv6")

    pa.vtysh_cmd(f"configure terminal\nipv6 pim rp {rp} prefix-list RP6-PLIST")
    expect_rp_address_ranges(
        rp, [("RP6-PLIST", "Static"), ("ff0e::/16", "Fallback")], af="ipv6"
    )
    pa.vtysh_cmd(f"configure terminal\nno ipv6 pim rp {rp} prefix-list RP6-PLIST")
    expect_rp_address_ranges(rp, [("ff0e::/16", "Fallback")], af="ipv6")

    pa.vtysh_cmd(
        f"configure terminal\nno ipv6 pim rp {rp} fallback ff0e::/16\n"
        "no ipv6 prefix-list RP6-PLIST"
    )
    expect_rp_address_ranges(rp, [], af="ipv6")


def expect_rp_address_ranges(rp, expected, af="ip"):
    """
    `rp` must be the RP for exactly the `expected` (range, source) list,
    the range being a group range, prefix-list or access-list.
    """
    tgen = get_topogen()

    def check_rp_info():
        output = tgen.gears["pa"].vtysh_cmd(f"show {af} pim rp-info json", isjson=True)
        ranges = sorted(
            (
                entry.get("group", entry.get("prefixList", entry.get("accessList"))),
                entry["source"],
            )
            for entry in output.get(rp, [])
        )
        if ranges != sorted(expected):
            return f"unexpected {rp} RP ranges: {ranges}"
        return None

    _, result = topotest.run_and_expect(check_rp_info, None, count=30, wait=1)
    assert result is None, f'"pa" {result}'


def expect_range_rp_sources(expected, count=30):
    "The `GROUP_RANGE` RP table entries must come from `expected` sources."
    tgen = get_topogen()

    def check_rp_info():
        output = tgen.gears["pa"].vtysh_cmd("show ip pim rp-info json", isjson=True)
        sources = [
            entry["source"]
            for entries in output.values()
            for entry in entries
            if entry.get("group") == GROUP_RANGE
        ]
        if sources != expected:
            return f"unexpected {GROUP_RANGE} RP sources: {sources}"
        return None

    _, result = topotest.run_and_expect(check_rp_info, None, count=count, wait=1)
    assert result is None, f'"pa" {result}'


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
