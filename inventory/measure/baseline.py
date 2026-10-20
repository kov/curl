#!/usr/bin/env python3
"""
Measure the C reference build against the C test suite.

`--run` configures and builds the C tree in build/c with CMAKE_ARGS, runs
tests/runtests.pl over every test, and keeps the raw results in
build/c/baseline/. Without `--run`, the stored results are parsed into
inventory/baseline.{json,md}.

This is a measurement, not a derivation from source, so inventory/gen/all.py
does not run it: rerun it with `--run` when the C tree or the build
configuration changes.
"""

import json
import pathlib
import re
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import common
from common import ROOT, check

BUILD = ROOT / "build" / "c"
RESULTS = BUILD / "baseline"
# Every backend and feature this machine can provide; see SCOPE.md.
CMAKE_ARGS = {
    "CMAKE_BUILD_TYPE": "Debug",
    "ENABLE_DEBUG": "ON",
    "BUILD_TESTING": "ON",
    "CURL_USE_OPENSSL": "ON",
    "USE_NGHTTP2": "ON",
    "USE_NGTCP2": "ON",
    "CURL_USE_LIBSSH2": "ON",
    "ENABLE_ARES": "ON",
    "CURL_BROTLI": "ON",
    "CURL_ZSTD": "ON",
    "USE_LIBIDN2": "ON",
    "CURL_USE_LIBPSL": "ON",
    "CURL_USE_GSSAPI": "ON",
    "CURL_ENABLE_NTLM": "ON",
    "USE_HTTPSRR": "ON",
    "USE_SSLS_EXPORT": "ON",
    "CURL_DISABLE_HTTPSIG": "OFF",
    "USE_PROXY_HTTP3": "ON",
    "USE_ECH": "OFF",
}
RUNTESTS_ARGS = ["-a", "-n", "-j8"]


def run():
    commit = common.c_commit()
    check(not commit.endswith("-dirty"),
          "C tree has local changes; a baseline must name a commit")
    subprocess.run(["cmake", "-S", str(ROOT), "-B", str(BUILD), "-G",
                    "Ninja", *(f"-D{k}={v}" for k, v in CMAKE_ARGS.items())],
                   check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["ninja", "-C", str(BUILD)], check=True,
                   stdout=subprocess.DEVNULL)
    RESULTS.mkdir(exist_ok=True)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with (RESULTS / "runtests.log").open("w") as log:
        r = subprocess.run(["perl", str(ROOT / "tests/runtests.pl"),
                            *RUNTESTS_ARGS], cwd=BUILD / "tests",
                           stdout=log, stderr=subprocess.STDOUT, check=False)
    finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (RESULTS / "run.json").write_text(json.dumps({
        "c-commit": commit, "started": started, "finished": finished,
        "exit-status": r.returncode, "runtests-args": RUNTESTS_ARGS},
        indent=1) + "\n")


def build_config():
    cache = {}
    for line in (BUILD / "CMakeCache.txt").read_text().splitlines():
        m = re.match(r"^(\w+):\w+=(.*)$", line)
        if m:
            cache[m.group(1)] = m.group(2)
    for k, v in CMAKE_ARGS.items():
        check(cache.get(k) == v,
              f"build/c has {k}={cache.get(k)!r}, CMAKE_ARGS says {v!r}")
    return cache


def parse_log(log, all_tests, disabled):
    ran = [int(n) for n in re.findall(r"^test (\d+) \[", log, re.MULTILINE)]
    check(len(ran) == len(set(ran)), "a test ran twice")
    ran = set(ran)
    m = re.search(r"^TESTDONE: (\d+) tests were considered", log, re.MULTILINE)
    check(m and int(m.group(1)) == len(all_tests),
          "considered count differs from the tests inventory")
    m = re.search(r"^TESTFAIL: These test cases failed: (.*)$", log, re.MULTILINE)
    failed = {int(n) for n in m.group(1).split()} if m else set()
    check(failed <= ran, "a failed test never started")
    m = re.search(r"^TESTDONE: (\d+) tests out of (\d+) reported OK", log,
                  re.MULTILINE)
    check(m is not None, "no TESTDONE result line")
    ok, total = int(m.group(1)), int(m.group(2))
    check(total == len(ran) and ok == len(ran) - len(failed),
          f"runtests says {ok}/{total} OK; log has {len(ran)} started, "
          f"{len(failed)} failed")
    check(len(re.findall(r"^\S+ OK \(", log, re.MULTILINE)) == ok,
          "OK lines differ from the OK count")

    # Skip reasons: SKIPPED lines, then TESTINFO lists (cut off after ten
    # numbers, hence the other two sources), then DISABLED.
    reason = {}
    for n, why in re.findall(r"^test (\d+) SKIPPED: (.*?)\s*$", log, re.MULTILINE):
        reason.setdefault(int(n), why)
    info = {}
    for why, count, nums in re.findall(
            r'^TESTINFO: "(.*?)" (\d+) times? \(([^)]*)\)', log, re.MULTILINE):
        info[why.strip()] = int(count)
        for n in re.findall(r"\d+", nums.split(" and ")[0]):
            reason.setdefault(int(n), why.strip())
    for n in disabled:
        reason.setdefault(n, "configured as DISABLED")
    skipped = set(all_tests) - ran
    check(skipped == set(reason) - ran,
          f"skipped tests without a reason: {sorted(skipped - set(reason))}")
    counts = {}
    for n in skipped:
        counts[reason[n]] = counts.get(reason[n], 0) + 1
    check(counts == info, f"skip reasons {counts} differ from TESTINFO {info}")

    failures = {}
    for n in failed:
        failures[n] = sorted(set(re.findall(
            rf"^ {n}: (.*?) FAILED", log, re.MULTILINE)))
    return ran, failed, {n: reason[n] for n in skipped}, failures


def classify(why):
    if why == "configured as DISABLED":
        return "disabled"
    if re.match(r"^curl lacks ", why):
        return "feature missing from build"
    if re.match(r"^curl has ", why):
        return "test requires a feature to be absent"
    return "environment"


def main():
    if "--run" in sys.argv[1:]:
        run()
    meta = json.loads((RESULTS / "run.json").read_text())
    check(meta["c-commit"] == common.c_commit(),
          f"baseline was run at {meta['c-commit'][:12]}, the C tree is at "
          f"{common.c_commit()[:12]}: rerun with --run")
    cache = build_config()
    tests = json.loads((common.INVENTORY / "tests.json").read_text())["data"]
    check(json.loads((common.INVENTORY / "tests.json").read_text())
          ["c-commit"] == meta["c-commit"], "tests inventory is stale")
    by_num = {t["number"]: t for t in tests["tests"]}
    disabled = tests["disabled"]["unconditional"]
    log = (RESULTS / "runtests.log").read_text(errors="replace")
    ran, failed, skipped, failures = parse_log(log, list(by_num), disabled)

    version = subprocess.run([str(BUILD / "src/curl"), "-V"],
                             capture_output=True, text=True,
                             check=True).stdout
    features = re.search(r"^Features: (.*)$", version, re.MULTILINE).group(1).split()
    protocols = re.search(r"^Protocols: (.*)$", version, re.MULTILINE).group(1)
    system = re.search(r"^\*+ System characteristics \*+ *\n(.*?)^\*+ *$",
                       log, re.MULTILINE | re.DOTALL)
    check(system is not None, "no System characteristics block")

    results = {}
    for n in sorted(by_num):
        if n in failed:
            results[n] = {"result": "failed", "failed-parts": failures[n]}
        elif n in ran:
            results[n] = {"result": "ok"}
        else:
            results[n] = {"result": "skipped", "reason": skipped[n],
                          "class": classify(skipped[n])}
    data = {
        "measured": {"started": meta["started"],
                     "finished": meta["finished"]},
        "runtests-args": meta["runtests-args"],
        "runtests-exit-status": meta["exit-status"],
        "cmake-args": CMAKE_ARGS,
        "compiler": cache.get("CMAKE_C_COMPILER"),
        "curl-version": version.strip().splitlines(),
        "features": features,
        "protocols": protocols.split(),
        "system": system.group(1).strip().splitlines(),
        "counts": {"considered": len(by_num), "ran": len(ran),
                   "ok": len(ran) - len(failed), "failed": len(failed),
                   "skipped": len(skipped)},
        "results": {str(n): r for n, r in results.items()},
    }

    reasons = {}
    for n, why in skipped.items():
        reasons.setdefault(why, []).append(n)
    md = [
        "# C reference baseline\n",
        ("What the C build in `build/c` does on the C test suite: the floor "
         "the rewrite is scored against. Measured "
         f"{meta['started']} to {meta['finished']} with `runtests.pl "
         f"{' '.join(meta['runtests-args'])}`; build flags are in "
         "`inventory/measure/baseline.py` and SCOPE.md.\n"),
        "```",
        *version.strip().splitlines(),
        "```\n",
        common.md_table(["", "tests"], list(data["counts"].items())),
        "## Failed\n",
        common.md_table(
            ["test", "name", "failed parts", "keywords"],
            [(n, by_num[n]["name"], failures[n], by_num[n]["keywords"])
             for n in sorted(failed)]) if failed else "None.\n",
        "## Skipped\n",
        common.md_table(
            ["reason", "class", "count", "tests"],
            [(why, classify(why), len(nums), sorted(nums))
             for why, nums in sorted(reasons.items(),
                                     key=lambda x: (classify(x[0]), x[0]))]),
    ]
    common.write("baseline", data, "\n".join(md), [
        "build/c/baseline/", "build/c/CMakeCache.txt", "tests/runtests.pl"],
        generated_by="inventory/measure/baseline.py")


if __name__ == "__main__":
    main()
