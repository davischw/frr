#!/usr/bin/env python3


import json
import os
import re
import string
import sys


def main(argv):
    fd = None
    buffer = None

    with open("show-ipv6-route-example.json", "r") as fd:
        buffer = fd.read()
        fd.close()

        if isinstance(buffer, str):
            json_dict = json.loads(buffer)

            for _, route_entries in json_dict.items():
                if isinstance(route_entries, list):
                    for route_entry in route_entries:
                        if isinstance(route_entry, dict):
                            # Mask out timestamp
                            if "uptime" in route_entry:
                                if isinstance(route_entry["uptime"], str):
                                    route_entry["uptime"] = re.sub(
                                        r"[0-2][0-9]:[0-5][0-9]:[0-5][0-9]",
                                        "XX:XX:XX",
                                        route_entry["uptime"]
                                    )

                            # Mask out the link-local addresses
                            if "nexthops" in route_entry:
                                nexthops = route_entry["nexthops"]
                                if isinstance(nexthops, list):
                                    for nexthop in nexthops:
                                        if isinstance(nexthop, dict):
                                            if "afi" in nexthop:
                                                if nexthop["afi"] == "ipv6":
                                                    if "ip" in nexthop:
                                                        nexthop["ip"] = re.sub(
                                                            r"fe80::[^ ]+",
                                                            "fe80::XXXX:XXXX:XXXX:XXXX",
                                                            nexthop["ip"]
                                                        )

            print(json.dumps(json_dict, indent=4))

    sys.exit(0)


if __name__ == "__main__":
    main(sys.argv)


sys.exit(1)


# EOF
