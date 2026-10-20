#!/usr/bin/env python3
"""
Report which of C's unit-test programs have Rust ports.

The programs of tests/unit and tests/tunit test C internals and never run
on the Rust build; Rust tests beside the code stand in for them (DESIGN.md,
"Ported unit tests"). A port is a Rust test named after its original:
`unit1309_due_order` ports unit1309.c, `tool1394_...` ports tool1394.c.

Lists the workspace's tests with `cargo test -- --list`, maps each port to
its program in inventory/tests.json, and prints every program as ported
(with its Rust tests) or missing. Fails on a port naming a program that
does not exist, and on a listing with no ports at all, which would mean the
listing was not read.
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import common
from common import ROOT, check

FEATURES = "curl-sys-abi/debug-hooks,curl-tool/debug-hooks,curl-core/test-util"
PORT = re.compile(r"(?:^|::)((?:unit|tool)\d+)_\w+: test$")


def programs():
    """The unit-test programs, by name, with the runtests.pl tests that run
    them."""
    data = json.loads((common.INVENTORY / "tests.json").read_text())["data"]
    return {name: p["tests"] for name, p in data["programs"].items()
            if p["kind"] in ("unit", "tunit")}


def rust_tests():
    out = subprocess.run(
        ["cargo", "test", "--workspace", "--features", FEATURES, "--", "--list"],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout
    listed = [line for line in out.splitlines() if line.endswith(": test")]
    check(listed, "cargo test --list listed no tests")
    return listed


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--missing", action="store_true",
                    help="also list the programs with no port")
    args = ap.parse_args()

    known = programs()
    ports = {}
    for line in rust_tests():
        if m := PORT.search(line):
            ports.setdefault(m[1], []).append(line[:-len(": test")])
    unknown = sorted(set(ports) - set(known))
    check(not unknown, f"ports of programs that do not exist: {unknown}")
    check(ports, "no ports found in the test listing")

    for name in sorted(ports):
        print(f"ported   {name} (test {', '.join(map(str, known[name]))}): "
              f"{', '.join(sorted(ports[name]))}")
    missing = sorted(set(known) - set(ports))
    if args.missing:
        for name in missing:
            print(f"missing  {name}")
    print(f"{len(ports)} of {len(known)} unit-test programs ported, "
          f"{len(missing)} missing")


if __name__ == "__main__":
    main()
