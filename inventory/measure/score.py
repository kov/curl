#!/usr/bin/env python3
"""
Score the Rust build against the C test suite.

Assembles build/rust as a build tree runtests.pl and pytest accept: the
test servers and test programs of the C build in build/c, with the Rust
library installed as lib/libcurl-d.so.4 and the Rust curl and curlinfo in
src/. Runs both suites through suite.py and compares every result with the
C baseline in inventory/baseline.json. Results go to build/rust/score/.

runtests.pl always enables the `unittest` gate, but the tests behind it
run the C unit-test programs, which test C internals whatever library is
installed. They are linked in only with the C library, and are scored on
their own, never as passes: their Rust ports are checked separately.

Other components can be swapped in to arm the harness:

  --lib c     the C library itself, so the score must equal the baseline
  --lib stub  a library whose every export aborts, so nothing may pass
  --tool c    the C tool, loading whichever library is chosen

`--threaded` scores the build that stands in for a distribution's
library, with the threaded resolver, against the second C oracle
(baseline.py --threaded): build/c-threaded's programs, compared with
inventory/baseline-threaded.json, laid out in build/rust-threaded.

`--report` re-reads the stored results without running anything.
"""

import argparse
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import baseline
import common
import suite
from common import ROOT, check

SONAME = "libcurl-d.so.4"
# Overlay entries of build/c that are not linked into build/rust: replaced
# by the Rust build, written by a run, or belonging to the C leg only.
NOT_LINKED = {"baseline", "pytest-venv", "src/curl", "src/curlinfo",
              "tests/libtest/libtests",
              "tests/log", "tests/.cache", "tests/second-hsts.txt"}
UNIT_PROGRAMS = {"tests/unit", "tests/tunit"}
UNIT_RUNNERS = {"unit", "tunit"}
# Directories rebuilt entry by entry rather than linked whole.
DESCEND = {"src", "lib", "tests", "tests/libtest"}


@dataclass(frozen=True)
class Leg:
    """A Rust build, the C oracle it is scored against, and where it runs."""
    oracle: baseline.Oracle
    build: pathlib.Path
    # Its own target directory, so neither build undoes the other's.
    target: pathlib.Path
    features: tuple

    @property
    def results(self):
        return self.build / "score"

    @property
    def cargo_out(self):
        return self.target / "debug"


DEBUG_HOOKS = ("curl-sys-abi/debug-hooks", "curl-tool/debug-hooks")
RUST = Leg(baseline.REFERENCE, ROOT / "build" / "rust",
           ROOT / "build" / "target", DEBUG_HOOKS)
THREADED = Leg(baseline.THREADED, ROOT / "build" / "rust-threaded",
               ROOT / "build" / "target-threaded",
               DEBUG_HOOKS + ("curl-sys-abi/threaded-resolver",
                              "curl-tool/threaded-resolver"))


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def overlay(root, src, dst, skip):
    """Link every entry of `src`, under `root`, into `dst`, but `skip`."""
    dst.mkdir(parents=True)
    for entry in sorted(src.iterdir()):
        rel = str(entry.relative_to(root))
        if rel in skip or re.match(r"^lib/libcurl.*\.so", rel):
            continue
        if rel in DESCEND:
            overlay(root, entry, dst / entry.name, skip)
        else:
            (dst / entry.name).symlink_to(entry)


def build_stub(leg):
    """Build a library exporting the C build's symbols, each aborting."""
    lib = json.loads((common.INVENTORY / f"{leg.oracle.inventory}.json")
                     .read_text())
    symbols = lib["data"]["library"]["symbols"]
    check("curl_easy_init" in symbols, "baseline has no curl_easy_init")
    stub = leg.build / "stub"
    stub.mkdir()
    (stub / "stub.c").write_text(
        "#include <stdlib.h>\n" + "".join(
            f"void {s}(void);\nvoid {s}(void) {{ abort(); }}\n"
            for s in symbols))
    out = stub / SONAME
    subprocess.run(["cc", "-shared", "-fPIC", f"-Wl,-soname,{SONAME}",
                    "-o", str(out), str(stub / "stub.c")], check=True)
    return out


def assemble(leg, lib, tool):
    """Build the Rust crates and lay out the leg's build tree."""
    cargo = subprocess.run(
        ["cargo", "build", "-p", "curl-sys-abi", "-p", "curl-tool",
         "--target-dir", str(leg.target), "--features",
         ",".join(leg.features)], cwd=ROOT, check=False)
    check(cargo.returncode == 0, "cargo build failed")
    c_build = leg.oracle.build
    if leg.build.exists():
        shutil.rmtree(leg.build)
    overlay(c_build, c_build, leg.build,
            NOT_LINKED if lib == "c" else NOT_LINKED | UNIT_PROGRAMS)
    library = {"rust": leg.cargo_out / "libcurl.so",
               "c": next(c_build.glob("lib/libcurl-d.so.*.*.*")),
               "stub": None}[lib] or build_stub(leg)
    shutil.copy2(library, leg.build / "lib" / SONAME)
    # The C programs find the leg's library whatever their environment:
    # pytest runs a client with only the variables a test names, so the
    # C build's lib in their RUNPATH would load the C library.
    libtests = leg.build / "tests/libtest/libtests"
    shutil.copy2(c_build / "tests/libtest/libtests", libtests)
    own_runpath(libtests, c_build / "lib", "$ORIGIN/../../lib")
    tools = {"rust": leg.cargo_out, "c": c_build / "src"}[tool]
    for name in ("curl", "curlinfo"):
        shutil.copy2(tools / name, leg.build / "src" / name)
        if tool == "c":
            own_runpath(leg.build / "src" / name, c_build / "lib",
                        "$ORIGIN/../lib")


def own_runpath(binary, c_lib, ours):
    """
    Point `binary`'s RUNPATH entry `c_lib` at `ours` instead, in place.

    The new string is no longer than the old, so it is written over it in
    the dynamic string table and padded with NULs.
    """
    data = bytearray(binary.read_bytes())
    check(data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1,
          f"{binary} is not a little-endian ELF64 file")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)

    def section(i):
        # sh_type, sh_offset, sh_size, sh_link
        base = shoff + i * shentsize
        kind, = struct.unpack_from("<I", data, base + 4)
        offset, size = struct.unpack_from("<QQ", data, base + 24)
        link, = struct.unpack_from("<I", data, base + 40)
        return kind, offset, size, link

    dynamic = [section(i) for i in range(shnum) if section(i)[0] == 6]
    check(len(dynamic) == 1, f"{binary} has no dynamic section")
    _, offset, size, link = dynamic[0]
    strtab = section(link)[1]
    found = 0
    for at in range(offset, offset + size, 16):
        tag, value = struct.unpack_from("<qQ", data, at)
        if tag not in (15, 29):  # DT_RPATH, DT_RUNPATH
            continue
        start = strtab + value
        end = data.index(0, start)
        old = data[start:end].decode()
        new = ":".join(ours if part == str(c_lib) else part
                       for part in old.split(":"))
        check(new != old, f"{binary}'s RUNPATH {old} names no {c_lib}")
        check(len(new) <= len(old), f"{new} is longer than {old}")
        data[start:end] = new.encode().ljust(end - start, b"\0")
        found += 1
    check(found == 1, f"{binary} has {found} RUNPATH entries, not 1")
    binary.write_bytes(data)


def environment(leg):
    """Return the environment the suites run with in the leg's tree."""
    return {**os.environ, "LD_LIBRARY_PATH": str(leg.build / "lib")}


def resolved_libcurl(binary, env):
    """Return the file `binary` loads for SONAME under `env`, or None."""
    needed = subprocess.run(["readelf", "-d", str(binary)], check=True,
                            capture_output=True, text=True).stdout
    if f"[{SONAME}]" not in needed:
        return None
    ldd = subprocess.run(["ldd", str(binary)], env=env, check=True,
                         capture_output=True, text=True).stdout
    m = re.search(rf"^\s*{re.escape(SONAME)} => (\S+)", ldd, re.MULTILINE)
    check(m is not None, f"ldd does not resolve {SONAME} for {binary}")
    return pathlib.Path(m.group(1)).resolve()


def check_loading(leg, tool):
    """
    Fail unless the test programs and tool load the library in the leg.

    The C test programs carry a RUNPATH to the C build's lib, which the
    leg's copies have pointed at the leg's own: pytest runs a client with
    only the variables a test names, so they must load the leg's library
    without the environment too. As a positive control, the C build's own
    libtests without it must find the C library.
    """
    ours = (leg.build / "lib" / SONAME).resolve()
    libtests = leg.build / "tests/libtest/libtests"
    bare = {k: v for k, v in os.environ.items() if k != "LD_LIBRARY_PATH"}
    for env in (environment(leg), bare):
        check(resolved_libcurl(libtests, env) == ours,
              f"{libtests} does not load {ours}")
    c_lib = resolved_libcurl(leg.oracle.build / "tests/libtest/libtests",
                             bare)
    check(c_lib is not None and c_lib.is_relative_to(leg.oracle.build),
          f"the C build's libtests loads {c_lib}, not "
          f"{leg.oracle.build}'s")
    curl = resolved_libcurl(leg.build / "src/curl", environment(leg))
    if tool == "c":
        check(curl == ours, f"src/curl loads {curl}, not {ours}")
        curl = resolved_libcurl(leg.build / "src/curl", bare)
        check(curl == ours, f"src/curl without the environment loads "
              f"{curl}, not {ours}")
    else:
        check(curl is None, f"the Rust tool loads {curl}")


def tree_check(test):
    """
    Whether a test checks the C tree rather than the build.

    Such perl-script tests read sources and built docs; they pass or fail
    whatever library and tool are installed.
    """
    return (test["runner"] == "perl-script"
            and "%CURL" not in (test.get("command") or ""))


def check_replacements():
    """Each test replaced by a Rust test names one that exists."""
    for n, (path, func) in suite.REPLACED.items():
        source = ROOT / path
        check(source.exists() and f"fn {func}(" in source.read_text(),
              f"test {n} is replaced by {path}::{func}, which does not exist")


def compare(now, base, tests):
    """Classify each result against the baseline's."""
    check_replacements()
    classes = {}
    for n, b in base.items():
        r = now[n]["result"]
        if n in suite.REPLACED:
            cls = f"replaced by a Rust test, {r}"
        elif tests[n]["runner"] in UNIT_RUNNERS:
            cls = f"C unit program, {r}"
        elif tree_check(tests[n]):
            cls = f"C tree check, {r}"
        elif b["result"] == "ok":
            cls = {"ok": "passes", "failed": "fails"}.get(r, "absent")
        elif r == "ok":
            cls = "newly passes"
        else:
            cls = f"{b['result']} on both"
        classes.setdefault(cls, []).append(n)
    return classes


def compare_pytest(now, base):
    classes = {}
    for case, b in base.items():
        r = now.get(case, {"outcome": "not collected"})["outcome"]
        if b["outcome"] == "passed":
            cls = {"passed": "passes", "skipped": "absent",
                   "not collected": "absent"}.get(r, "fails")
        elif r == "passed":
            cls = "newly passes"
        else:
            cls = f"{b['outcome']} on both"
        classes.setdefault(cls, []).append(case)
    for case in sorted(set(now) - set(base)):
        classes.setdefault("not in baseline", []).append(case)
    return classes


def report(leg):
    meta = json.loads((leg.results / "run.json").read_text())
    check(meta["c-commit"] == common.c_commit(),
          f"results are for C commit {meta['c-commit'][:12]}, the tree is at "
          f"{common.c_commit()[:12]}")
    tests = json.loads((common.INVENTORY / "tests.json").read_text())["data"]
    base = json.loads((common.INVENTORY / f"{leg.oracle.inventory}.json")
                      .read_text())["data"]
    now, cases, _ = suite.results(leg.build, leg.results, tests)
    classes = compare(now, {int(n): r for n, r in base["results"].items()},
                      {t["number"]: t for t in tests["tests"]})
    pyclasses = compare_pytest(cases, base["pytest"]["cases"])
    score = {**meta, "runtests": {k: sorted(v) for k, v in classes.items()},
             "pytest": {k: sorted(v) for k, v in pyclasses.items()}}
    (leg.results / "score.json").write_text(json.dumps(score, indent=1) + "\n")

    print(f"lib={meta['lib']} tool={meta['tool']} at {meta['rust-commit']}")
    for name, cls in (("runtests.pl", classes), ("pytest", pyclasses)):
        base_ok = sum(len(cls.get(k, [])) for k in ("passes", "fails",
                                                    "absent"))
        print(f"{name}: {len(cls.get('passes', []))} of {base_ok} passing "
              "on the C build pass")
        for k in sorted(cls):
            items = sorted(cls[k])
            shown = " ".join(map(str, items[:20]))
            more = f" ... (+{len(items) - 20})" if len(items) > 20 else ""
            print(f"  {k}: {len(items)}: {shown}{more}")
    return classes, pyclasses


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--lib", choices=["rust", "c", "stub"], default="rust")
    ap.add_argument("--tool", choices=["rust", "c"], default="rust")
    ap.add_argument("--threaded", action="store_true")
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args()
    leg = THREADED if args.threaded else RUST
    if not args.report:
        commit = common.c_commit()
        c_build = leg.oracle.build
        run = json.loads((leg.oracle.results / "run.json").read_text())
        check(run["c-commit"] == commit,
              f"{c_build} was measured at {run['c-commit'][:12]}, the C "
              f"tree is at {commit[:12]}: rerun baseline.py "
              f"{leg.oracle.flag} --run first")
        assemble(leg, args.lib, args.tool)
        check_loading(leg, args.tool)
        dirty = git("status", "--porcelain", "--untracked-files=no", "--",
                    *(p for p in common.NOT_C_TREE if p != "inventory"))
        meta = suite.run(leg.build, leg.results, environment(leg))
        (leg.results / "run.json").write_text(json.dumps({
            "c-commit": commit,
            "rust-commit": git("rev-parse", "HEAD")[:12]
            + ("-dirty" if dirty else ""),
            "lib": args.lib, "tool": args.tool, **meta}, indent=1) + "\n")
    report(leg)


if __name__ == "__main__":
    main()
