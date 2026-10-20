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

`--report` re-reads the stored results without running anything.
"""

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import baseline
import common
import suite
from common import ROOT, check

C_BUILD = baseline.BUILD
BUILD = ROOT / "build" / "rust"
RESULTS = BUILD / "score"
CARGO_OUT = ROOT / "build" / "target" / "debug"
SONAME = "libcurl-d.so.4"
# Overlay entries of build/c that are not linked into build/rust: replaced
# by the Rust build, written by a run, or belonging to the C leg only.
NOT_LINKED = {"baseline", "pytest-venv", "src/curl", "src/curlinfo",
              "tests/log", "tests/.cache", "tests/second-hsts.txt"}
UNIT_PROGRAMS = {"tests/unit", "tests/tunit"}
UNIT_RUNNERS = {"unit", "tunit"}
# Directories rebuilt entry by entry rather than linked whole.
DESCEND = {"src", "lib", "tests"}


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def overlay(src, dst, skip):
    """Link every entry of `src` into `dst`, except those in `skip`."""
    dst.mkdir(parents=True)
    for entry in sorted(src.iterdir()):
        rel = str(entry.relative_to(C_BUILD))
        if rel in skip or re.match(r"^lib/libcurl.*\.so", rel):
            continue
        if rel in DESCEND:
            overlay(entry, dst / entry.name, skip)
        else:
            (dst / entry.name).symlink_to(entry)


def build_stub():
    """Build a library exporting the C build's symbols, each aborting."""
    lib = json.loads((common.INVENTORY / "baseline.json").read_text())
    symbols = lib["data"]["library"]["symbols"]
    check("curl_easy_init" in symbols, "baseline has no curl_easy_init")
    stub = BUILD / "stub"
    stub.mkdir()
    (stub / "stub.c").write_text(
        "#include <stdlib.h>\n" + "".join(
            f"void {s}(void);\nvoid {s}(void) {{ abort(); }}\n"
            for s in symbols))
    out = stub / SONAME
    subprocess.run(["cc", "-shared", "-fPIC", f"-Wl,-soname,{SONAME}",
                    "-o", str(out), str(stub / "stub.c")], check=True)
    return out


def assemble(lib, tool):
    """Build the Rust crates and lay out build/rust."""
    cargo = subprocess.run(
        ["cargo", "build", "-p", "curl-sys-abi", "-p", "curl-tool",
         "--features", "curl-sys-abi/debug-hooks,curl-tool/debug-hooks"], cwd=ROOT, check=False)
    check(cargo.returncode == 0, "cargo build failed")
    if BUILD.exists():
        shutil.rmtree(BUILD)
    overlay(C_BUILD, BUILD,
            NOT_LINKED if lib == "c" else NOT_LINKED | UNIT_PROGRAMS)
    library = {"rust": CARGO_OUT / "libcurl.so",
               "c": next(C_BUILD.glob("lib/libcurl-d.so.*.*.*")),
               "stub": None}[lib] or build_stub()
    shutil.copy2(library, BUILD / "lib" / SONAME)
    tools = {"rust": CARGO_OUT, "c": C_BUILD / "src"}[tool]
    for name in ("curl", "curlinfo"):
        shutil.copy2(tools / name, BUILD / "src" / name)


def environment():
    """Return the environment the suites run with in build/rust."""
    return {**os.environ, "LD_LIBRARY_PATH": str(BUILD / "lib")}


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


def check_loading(tool):
    """
    Fail unless the test programs and tool load the library in build/rust.

    The C test programs carry a RUNPATH to build/c/lib, so a mistake in the
    environment would silently test the C library. As a positive control,
    the same check without the environment must find the C library.
    """
    ours = (BUILD / "lib" / SONAME).resolve()
    libtests = BUILD / "tests/libtest/libtests"
    check(resolved_libcurl(libtests, environment()) == ours,
          f"{libtests} does not load {ours}")
    c_lib = resolved_libcurl(libtests, {k: v for k, v in os.environ.items()
                                        if k != "LD_LIBRARY_PATH"})
    check(c_lib is not None and c_lib.is_relative_to(C_BUILD),
          f"without LD_LIBRARY_PATH libtests loads {c_lib}, not build/c's")
    curl = resolved_libcurl(BUILD / "src/curl", environment())
    if tool == "c":
        check(curl == ours, f"src/curl loads {curl}, not {ours}")
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


def compare(now, base, tests):
    """Classify each result against the baseline's."""
    classes = {}
    for n, b in base.items():
        r = now[n]["result"]
        if tests[n]["runner"] in UNIT_RUNNERS:
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


def report():
    meta = json.loads((RESULTS / "run.json").read_text())
    check(meta["c-commit"] == common.c_commit(),
          f"results are for C commit {meta['c-commit'][:12]}, the tree is at "
          f"{common.c_commit()[:12]}")
    tests = json.loads((common.INVENTORY / "tests.json").read_text())["data"]
    base = json.loads((common.INVENTORY / "baseline.json").read_text())["data"]
    now, cases, _ = suite.results(BUILD, RESULTS, tests)
    classes = compare(now, {int(n): r for n, r in base["results"].items()},
                      {t["number"]: t for t in tests["tests"]})
    pyclasses = compare_pytest(cases, base["pytest"]["cases"])
    score = {**meta, "runtests": {k: sorted(v) for k, v in classes.items()},
             "pytest": {k: sorted(v) for k, v in pyclasses.items()}}
    (RESULTS / "score.json").write_text(json.dumps(score, indent=1) + "\n")

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
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args()
    if not args.report:
        commit = common.c_commit()
        run = json.loads((C_BUILD / "baseline/run.json").read_text())
        check(run["c-commit"] == commit,
              f"build/c was measured at {run['c-commit'][:12]}, the C tree "
              f"is at {commit[:12]}: rerun baseline.py --run first")
        assemble(args.lib, args.tool)
        check_loading(args.tool)
        dirty = git("status", "--porcelain", "--untracked-files=no", "--",
                    *(p for p in common.NOT_C_TREE if p != "inventory"))
        meta = suite.run(BUILD, RESULTS, environment())
        (RESULTS / "run.json").write_text(json.dumps({
            "c-commit": commit,
            "rust-commit": git("rev-parse", "HEAD")[:12]
            + ("-dirty" if dirty else ""),
            "lib": args.lib, "tool": args.tool, **meta}, indent=1) + "\n")
    report()


if __name__ == "__main__":
    main()
