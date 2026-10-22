#!/usr/bin/env python3
"""
Run the tests behind runtests.pl's `crypto` gate with the gate forced open.

runtests.pl claims `crypto` only for a build with NTLM, Kerberos or
SPNEGO, and the Rust build has none of them yet, so every test requiring
`crypto` skips on the Rust leg, the Digest tests among them, and scores as
absent. This runs them anyway, through a copy of runtests.pl that claims
`crypto` unconditionally, so a regression in them is still seen. Tests
that need another feature the build lacks (NTLM, SPNEGO, a protocol) skip
on that feature as before.

It is a regression net, not a score: its results are never merged into
score.py's. Delete it once the Rust build claims NTLM, Kerberos or SPNEGO
and runtests.pl opens the gate by itself.

Usage: gated.py [--no-build] [TEST...]   (default: every test requiring
`crypto`, from inventory/tests.json)
"""

import json
import pathlib
import subprocess
import sys

import score
from common import ROOT, check

GATE = '$feature{"crypto"} = $feature{"NTLM"} || $feature{"Kerberos"} || $feature{"SPNEGO"};'
FORCED = '$feature{"crypto"} = 1;  # gated.py: forced open'
SUMMARY = ("FAILED", "SKIPPED", "TESTDONE", "TESTFAIL", "TESTINFO", "IGNORED")


def gated_tests():
    tests = json.loads((ROOT / "inventory/tests.json").read_text())["data"]["tests"]
    return [str(t["number"]) for t in tests if "crypto" in t["features"]]


def forced_runtests():
    text = (ROOT / "tests/runtests.pl").read_text()
    check(text.count(GATE) == 1,
          "runtests.pl no longer sets `crypto` as gated.py expects: "
          "update GATE, or delete gated.py if the gate opens by itself")
    out = score.BUILD / "gated" / "runtests.pl"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text.replace(GATE, FORCED))
    return out


def main():
    args = sys.argv[1:]
    build = "--no-build" not in args
    tests = [a for a in args if a != "--no-build"] or gated_tests()
    if build:
        score.assemble("rust", "rust")
    runtests = forced_runtests()
    env = {**score.environment(), "srcdir": str(ROOT / "tests")}
    r = subprocess.run(["perl", str(runtests), "-a", "-n", *tests],
                       cwd=score.BUILD / "tests", env=env,
                       capture_output=True, text=True)
    log = score.BUILD / "gated" / "runtests.log"
    log.write_text(r.stdout + r.stderr)
    for line in (r.stdout + r.stderr).splitlines():
        if line.startswith(SUMMARY):
            print(line)
    print(f"full log: {log}")


if __name__ == "__main__":
    main()
