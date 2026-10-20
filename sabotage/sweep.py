#!/usr/bin/env python3
"""
Break each recorded invariant on purpose and check its test notices.

Each entry in sabotage/entries/*.txt names an invariant, the file and exact
text to change, the replacement that breaks it, and the test that must
fail (its witness). The sweep applies one entry at a time, runs only its
witness, and puts the file back, whatever happens. Verdicts:

  RED       the witness failed (named), the suite hung, or the build
            refused the change outside the replaced text: caught
  BROKEN    the replacement itself does not compile, or the witness ran
            no test: the entry checks nothing
  SURVIVED  the witness passed with the invariant broken: a hole

Entry format, one or more per file:

  === <the invariant, broken, as a sentence>
  file: <path from the repository root>
  witness: <package> <exact test name>
  --- old
  <text, exactly as in the file, found exactly once>
  --- new
  <the replacement>

`cargo test` checks every entry's old text is still in the tree
(curl-sys-abi's `sabotage_entries_are_current`), so a refactor cannot leave
the sweep testing nothing.

Usage: sabotage/sweep.py [entry file stem or substring of entry names...]

Witnesses run under a memory cap (systemd-run), as a planted fault can
allocate without bound faster than the timeout fires.
"""

import os
import pathlib
import re
import signal
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENTRIES = ROOT / "sabotage" / "entries"
CAP = ["systemd-run", "--user", "--scope", "--quiet", "-p", "MemoryMax=6G",
       "-p", "MemorySwapMax=0", "-p", "OOMPolicy=continue"]


class Entry:
    def __init__(self, source, name, fields, old, new):
        self.source, self.name, self.old, self.new = source, name, old, new
        self.file = fields.get("file")
        witness = fields.get("witness", "").split()
        if not self.file or len(witness) != 2:
            sys.exit(f"{source}: entry '{name}' needs file: and witness: <package> <test>")
        self.package, self.test = witness


def parse(path):
    entries, block = [], None
    for line in path.read_text().split("\n"):
        if line.startswith("=== "):
            block = {"name": line[4:], "fields": {}, "old": None, "new": None, "into": None}
            entries.append(block)
        elif block is None:
            continue
        elif line == "--- old":
            block["into"], block["old"] = "old", []
        elif line == "--- new":
            block["into"], block["new"] = "new", []
        elif block["into"]:
            block[block["into"]].append(line)
        elif m := re.fullmatch(r"(\w+): (.*)", line):
            block["fields"][m[1]] = m[2]
        elif line.strip():
            sys.exit(f"{path}: unexpected line in '{block['name']}': {line}")
    out = []
    for b in entries:
        if b["old"] is None or b["new"] is None:
            sys.exit(f"{path}: entry '{b['name']}' needs --- old and --- new")
        # A block ends at the next entry; the blank lines before it are not
        # part of the text.
        old = "\n".join(b["old"]).rstrip("\n")
        new = "\n".join(b["new"]).rstrip("\n")
        out.append(Entry(path, b["name"], b["fields"], old, new))
    return out


def stale(entries):
    bad = []
    for e in entries:
        path = ROOT / e.file
        count = path.read_text().count(e.old) if path.exists() else 0
        if count != 1:
            bad.append(f"  {e.name}: old text found {count} times in {e.file}")
    return bad


def run(e, timeout):
    """Run the witness; (verdict, detail)."""
    cmd = CAP + ["cargo", "test", "-p", e.package, "--", "--exact", e.test]
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        return "hung", ""
    return ("passed" if proc.returncode == 0 else "failed"), out


def ran_witness(out, test):
    return re.search(rf"^test {re.escape(test)}( - should panic)? \.\.\. ", out, re.MULTILINE)


def build_error_inside(out, e, start, end):
    """Whether a compile error points inside the replaced lines."""
    for m in re.finditer(r"--> ([^:\n]+):(\d+):\d+", out):
        if pathlib.Path(m[1]).resolve() == (ROOT / e.file).resolve() and start <= int(m[2]) <= end:
            return True
    return False


def main():
    names = sys.argv[1:]
    entries = [e for p in sorted(ENTRIES.glob("*.txt")) for e in parse(p)]
    if bad := stale(entries):
        sys.exit("stale entries:\n" + "\n".join(bad))
    chosen = [e for e in entries
              if not names or any(n == e.source.stem or n in e.name for n in names)]
    if not chosen:
        sys.exit("no entry matches")
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                           cwd=ROOT, capture_output=True, text=True, check=True).stdout
    if dirty.strip():
        sys.exit("the tree has uncommitted changes; commit them first")

    # A clean run of each witness: it must pass, and its time sets the
    # budget for a sabotaged one.
    budget = {}
    for e in chosen:
        if (e.package, e.test) in budget:
            continue
        run(e, None)  # build
        t = time.monotonic()
        verdict, out = run(e, None)
        if verdict != "passed" or not ran_witness(out, e.test):
            sys.exit(f"witness {e.package} {e.test} does not pass on a clean tree:\n{out[-2000:]}")
        budget[(e.package, e.test)] = max(180.0, 8 * (time.monotonic() - t))

    holes = 0
    for e in chosen:
        path = ROOT / e.file
        original = path.read_text()
        at = original.index(e.old)
        start = original.count("\n", 0, at) + 1
        end = start + e.new.count("\n")
        try:
            path.write_text(original.replace(e.old, e.new, 1))
            verdict, out = run(e, budget[(e.package, e.test)])
        finally:
            path.write_text(original)
        if verdict == "hung":
            result = "RED       the suite hung"
        elif verdict == "failed" and "could not compile" in out:
            if build_error_inside(out, e, start, end):
                result, holes = "BROKEN    the replacement does not compile", holes + 1
            else:
                result = "RED       the build refused it"
        elif not ran_witness(out, e.test):
            result, holes = f"BROKEN    the witness ran no test ({e.test})", holes + 1
        elif verdict == "failed":
            result = f"RED       {e.test}"
        else:
            result, holes = "SURVIVED", holes + 1
        print(f"{result}  -- {e.name}", flush=True)
    print(f"{len(chosen)} entries, {holes} holes")
    sys.exit(1 if holes else 0)


if __name__ == "__main__":
    main()
