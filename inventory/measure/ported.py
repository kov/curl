#!/usr/bin/env python3
"""
Report which of C's unit-test programs have Rust ports.

The programs of tests/unit and tests/tunit test C internals and never run
on the Rust build; Rust tests beside the code stand in for them (DESIGN.md,
"Ported unit tests"). A port is a Rust test named after its original:
`unit1309_due_order` ports unit1309.c, `tool1394_...` ports tool1394.c.

A program that tests a C internal the rewrite has no counterpart of, or
that the reference build compiles to nothing, is listed in NO_COUNTERPART
with the reason, and counted apart: it has nothing to port to.

Lists the workspace's tests with `cargo test -- --list`, maps each port to
its program in inventory/tests.json, and prints every program as ported
(with its Rust tests), without a counterpart (with the reason) or missing.
Fails on a port naming a program that does not exist, on a listing with no
ports at all, which would mean the listing was not read, and on an entry of
NO_COUNTERPART that names no program or a program that has a port.
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

# The programs with nothing in the rewrite to port to, and why.
NO_COUNTERPART = {
    "unit1300": "Curl_llist, C's linked list; the rewrite's lists are "
                "Vec, VecDeque and id::Arena",
    "unit1305": "Curl_hash freeing a DNS entry put in by hand; the DNS "
                "cache is a std HashMap",
    "unit1330": "curlx_malloc and curlx_free; Rust allocates through "
                "curl-alloc's fallible containers",
    "unit1600": "NTLM's NT hash; the reference build has no NTLM "
                "(SCOPE.md), and the C test compiles to nothing in it",
    "unit1602": "Curl_hash's clean and destroy; the rewrite's maps are std's",
    "unit1603": "Curl_hash's slots, its string hash and its element "
                "destructors; the rewrite's maps are std's",
    "unit1611": "MD4, used by NTLM alone; the reference build has no NTLM "
                "(SCOPE.md), and the C test compiles to nothing in it",
    "unit1661": "Curl_bufref, a pointer, length and destructor; the "
                "rewrite holds bytes as Vec, Cow and slices",
    "unit2602": "dynhds, C's growable header list with its own limits; the "
                "rewrite's header lists are Vecs of fields",
    "unit3205": "the cipher suite table of mbedTLS and rustls; the "
                "reference build uses OpenSSL, and the C test compiles to "
                "nothing in it",
    "unit3213": "uint32_spbset, the sparse set of a host's connections; "
                "the pool finds them by filtering its arena",
    "unit3300": "Curl_thrdpool, C's generic thread pool with take, process "
                "and return callbacks; the rewrite's only threads are the "
                "threaded resolver's (conn::threaded's tests)",
    "unit3301": "Curl_thrdq, C's generic queue to a thread pool; the "
                "threaded resolver's queue is typed to its queries "
                "(conn::threaded's tests)",
}


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
    unknown = sorted(set(NO_COUNTERPART) - set(known))
    check(not unknown, f"NO_COUNTERPART names programs that do not exist: {unknown}")
    both = sorted(set(NO_COUNTERPART) & set(ports))
    check(not both, f"NO_COUNTERPART names programs that have ports: {both}")

    for name in sorted(ports):
        print(f"ported   {name} (test {', '.join(map(str, known[name]))}): "
              f"{', '.join(sorted(ports[name]))}")
    for name in sorted(NO_COUNTERPART):
        print(f"no-port  {name} (test {', '.join(map(str, known[name]))}): "
              f"{NO_COUNTERPART[name]}")
    missing = sorted(set(known) - set(ports) - set(NO_COUNTERPART))
    if args.missing:
        for name in missing:
            print(f"missing  {name}")
    print(f"{len(ports)} of {len(known)} unit-test programs ported, "
          f"{len(NO_COUNTERPART)} without a counterpart, {len(missing)} missing")


if __name__ == "__main__":
    main()
