#!/usr/bin/env python3
"""
Regenerate every inventory section.

With --check, fail if regeneration changed any committed output: the
inventory is then stale against the C tree.
"""

import pathlib
import subprocess
import sys

GEN = pathlib.Path(__file__).resolve().parent
ROOT = GEN.parents[1]


def main():
    scripts = sorted(p for p in GEN.glob("*.py")
                     if p.name not in ("all.py", "common.py"))
    for script in scripts:
        r = subprocess.run([sys.executable, str(script)], check=False)
        if r.returncode:
            sys.exit(f"all.py: {script.name} failed")
    if "--check" in sys.argv[1:]:
        # Only what regeneration touched counts: worktree changes against
        # the index, and outputs git does not know about yet.
        def git(*args):
            return subprocess.run(["git", "-C", str(ROOT), *args],
                                  check=True, capture_output=True,
                                  text=True).stdout
        stale = git("diff", "--name-only", "--", "inventory")
        stale += git("ls-files", "--others", "--exclude-standard", "--",
                     "inventory/*.json", "inventory/*.md")
        if stale:
            sys.exit(f"all.py: inventory is stale:\n{stale}")


if __name__ == "__main__":
    main()
