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
import os
import pathlib
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import common
import deps
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
    # Out of scope (SCOPE.md); explicit so an older cache cannot keep it on.
    "CURL_ENABLE_NTLM": "OFF",
    "USE_HTTPSRR": "ON",
    "USE_SSLS_EXPORT": "ON",
    "CURL_DISABLE_HTTPSIG": "OFF",
    "USE_PROXY_HTTP3": "ON",
    "USE_ECH": "OFF",
    # ngtcp2 from inventory/measure/deps.py, found through PKG_CONFIG_PATH.
    "CMAKE_BUILD_RPATH": str(deps.NGTCP2 / "lib"),
    # Test servers for the tests/http pytest suite, where CMake does not
    # look on Fedora: dante's daemon is sockd, sftp-server is under openssh.
    "DANTED": "/usr/bin/sockd",
    "SFTPD": "/usr/libexec/openssh/sftp-server",
}
# Features SCOPE.md leaves out: tests needing them skip by design.
OUT_OF_SCOPE = {"NTLM"}
# Test programs that link libcurl and ngtcp2 themselves.
TEST_PROGRAMS = [BUILD / "tests/libtest/libtests",
                 BUILD / "tests/unit/units", BUILD / "tests/tunit/tunits"]
RUNTESTS_ARGS = ["-a", "-n", "-j8"]
# As the curl-pytest CMake target, plus a machine-readable report.
PYTEST_ARGS = ["-n", "auto", "-p", "no:cacheprovider"]
VENV = BUILD / "pytest-venv"


def run():
    commit = common.c_commit()
    check(not commit.endswith("-dirty"),
          "C tree has local changes; a baseline must name a commit")
    dep_env = deps.build()
    # A fresh cache: nothing configured by hand earlier, such as another
    # library location, may carry into the measurement.
    (BUILD / "CMakeCache.txt").unlink(missing_ok=True)
    subprocess.run(["cmake", "-S", str(ROOT), "-B", str(BUILD), "-G",
                    "Ninja", *(f"-D{k}={v}" for k, v in CMAKE_ARGS.items())],
                   check=True, stdout=subprocess.DEVNULL,
                   env={**os.environ, **dep_env})
    # The test programs are not in the default target.
    subprocess.run(["ninja", "-C", str(BUILD), "all", "testdeps"],
                   check=True, stdout=subprocess.DEVNULL)
    for binary in [next(BUILD.glob("lib/libcurl*.so.*.*.*")),
                   BUILD / "src/curl", *TEST_PROGRAMS]:
        deps.check_linked(binary)
    RESULTS.mkdir(exist_ok=True)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with (RESULTS / "runtests.log").open("w") as log:
        r = subprocess.run(["perl", str(ROOT / "tests/runtests.pl"),
                            *RUNTESTS_ARGS], cwd=BUILD / "tests",
                           stdout=log, stderr=subprocess.STDOUT, check=False)
    probe_skips()
    if not (VENV / "bin/pytest").exists():
        subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
        subprocess.run([str(VENV / "bin/pip"), "install", "-q", "-r",
                        str(ROOT / "tests/http/requirements.txt")],
                       check=True)
    # The test servers run as `#!/usr/bin/env python3` and need the venv's
    # modules, so the venv goes first on PATH, as if activated.
    env = {**os.environ,
           "PATH": f"{VENV / 'bin'}:{os.environ.get('PATH', '')}"}
    with (RESULTS / "pytest.log").open("w") as log:
        p = subprocess.run([str(VENV / "bin/pytest"), *PYTEST_ARGS,
                            f"--junitxml={RESULTS / 'pytest.xml'}",
                            str(ROOT / "tests/http")], cwd=BUILD / "tests",
                           env=env, stdout=log, stderr=subprocess.STDOUT,
                           check=False)
    # The pytest harness leaves the vsftpd daemons it starts running; stop
    # them so repeated runs do not pile them up.
    leftover = subprocess.run(["pkill", "-c", "-f",
                               f"^\\S*vsftpd {ROOT}/tests/http/gen/"],
                              check=False, capture_output=True,
                              text=True).stdout.strip()
    finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (RESULTS / "run.json").write_text(json.dumps({
        "c-commit": commit, "started": started, "finished": finished,
        "exit-status": r.returncode, "runtests-args": RUNTESTS_ARGS,
        "pytest-exit-status": p.returncode, "pytest-args": PYTEST_ARGS,
        "pytest-leftover-vsftpd": int(leftover or 0)},
        indent=1) + "\n")


SKIPPED_LINE = r"^test (\d+) SKIPPED: (.*?)\s*$"


def probe_skips():
    """
    Recover the skip reason of every test runtests.pl skipped.

    runtests.pl prints only the first three SKIPPED lines per reason and
    nine numbers per reason in its summary. Rerunning just the unexplained
    tests prints the next three, without starting any server; repeat until
    each has its line in skip-probes.log.
    """
    log = (RESULTS / "runtests.log").read_text(errors="replace")
    tests = json.loads((common.INVENTORY / "tests.json").read_text())["data"]
    explained = {int(n) for n in
                 re.findall(r"^test (\d+) [\[S]", log, re.MULTILINE)}
    explained |= set(tests["disabled"]["unconditional"])
    pending = sorted({t["number"] for t in tests["tests"]} - explained)
    with (RESULTS / "skip-probes.log").open("w") as out:
        while pending:
            r = subprocess.run(["perl", str(ROOT / "tests/runtests.pl"),
                                "-n", *map(str, pending)],
                               cwd=BUILD / "tests", capture_output=True,
                               text=True, check=False)
            out.write(r.stdout)
            check(not re.search(r"^test \d+ \[", r.stdout, re.MULTILINE),
                  "a probed test ran instead of skipping")
            got = {int(n) for n, _ in
                   re.findall(SKIPPED_LINE, r.stdout, re.MULTILINE)}
            check(got, f"probe explained none of {pending}")
            pending = [n for n in pending if n not in got]


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

    # Skip reasons: SKIPPED lines (the run's, then probe_skips'), then
    # TESTINFO lists (cut off after nine numbers), then DISABLED.
    reason = {}
    probes = (RESULTS / "skip-probes.log").read_text(errors="replace")
    for n, why in re.findall(SKIPPED_LINE, log + probes, re.MULTILINE):
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


def parse_pytest(report, log, files):
    """
    Return per-case outcomes from pytest's JUnit report.

    Checked against the summary line pytest printed, and against the test
    functions the tests inventory found in tests/http.
    """
    cases = {}
    for tc in ET.parse(report).getroot().iter("testcase"):
        module = next((p for p in tc.get("classname").split(".")
                       if re.match(r"^test_\d+", p)), None)
        check(module is not None, f"no module in {tc.get('classname')}")
        case = f"{module}::{tc.get('name')}"
        check(case not in cases, f"duplicate pytest case {case}")
        outcome, message = "passed", None
        for kind in ("failure", "error", "skipped"):
            el = tc.find(kind)
            if el is not None:
                outcome = {"failure": "failed", "error": "error",
                           "skipped": "skipped"}[kind]
                message = (el.get("message") or "").strip()[:300]
                break
        cases[case] = {"outcome": outcome, "message": message}
    m = re.search(r"^=+ (.*) in [\d.]+s.* =+$", log, re.MULTILINE)
    check(m is not None, "no pytest summary line")
    summary = {}
    for n, what in re.findall(r"(\d+) (\w+)", m.group(1)):
        summary[{"errors": "error", "error": "error"}.get(what, what)] = \
            int(n)
    counts = {}
    for c in cases.values():
        counts[c["outcome"]] = counts.get(c["outcome"], 0) + 1
    check(counts == summary,
          f"JUnit outcomes {counts} differ from pytest's summary {summary}")
    known = set()
    for f in files:
        module = pathlib.Path(f["file"]).stem
        names = [t["name"] for c in f["classes"] for t in c["tests"]]
        names += [t["name"] for t in f.get("functions", [])]
        known |= {f"{module}::{n}" for n in names}
    ran = {c.split("[")[0] for c in cases}
    check(ran <= known, f"cases for unknown functions: {sorted(ran - known)}")
    return cases, sorted(known - ran)


def exports():
    """Return the built library's soname and defined dynamic symbols."""
    libs = sorted(BUILD.glob("lib/libcurl*.so.*.*.*"))
    check(len(libs) == 1, f"expected one built libcurl, found {libs}")
    dyn = subprocess.run(["readelf", "-d", str(libs[0])], check=True,
                         capture_output=True, text=True).stdout
    soname = re.search(r"Library soname: \[(.*?)\]", dyn).group(1)
    nm = subprocess.run(["nm", "-D", "--defined-only", str(libs[0])],
                        check=True, capture_output=True, text=True).stdout
    symbols = sorted(line.split()[-1] for line in nm.splitlines())
    check("curl_easy_init" in symbols, "nm output has no curl_easy_init")
    return {"file": libs[0].name, "soname": soname, "symbols": symbols}


def classify(why):
    if why == "configured as DISABLED":
        return "disabled"
    m = re.match(r"^curl lacks (\S+) support$", why)
    if m and m.group(1) in OUT_OF_SCOPE:
        return "out of scope"
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

    pytest_cases, pytest_uncollected = parse_pytest(
        RESULTS / "pytest.xml",
        (RESULTS / "pytest.log").read_text(errors="replace"),
        tests["pytest"]["files"])
    pytest_counts = {}
    for c in pytest_cases.values():
        pytest_counts[c["outcome"]] = pytest_counts.get(c["outcome"], 0) + 1
    skip_reasons = {}
    for c in pytest_cases.values():
        if c["outcome"] == "skipped":
            skip_reasons[c["message"]] = skip_reasons.get(c["message"], 0) + 1

    lib = exports()
    abi = json.loads((common.INVENTORY / "abi.json").read_text())["data"]
    public = {f["name"] for f in abi["functions"]}
    lib["not-public"] = sorted(set(lib["symbols"]) - public)
    lib["public-missing"] = sorted(public - set(lib["symbols"]))

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
        "library": lib,
        "counts": {"considered": len(by_num), "ran": len(ran),
                   "ok": len(ran) - len(failed), "failed": len(failed),
                   "skipped": len(skipped)},
        "results": {str(n): r for n, r in results.items()},
        "pytest": {"args": meta["pytest-args"],
                   "exit-status": meta["pytest-exit-status"],
                   "counts": pytest_counts,
                   "functions-without-cases": pytest_uncollected,
                   "cases": pytest_cases},
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
        "## Built library\n",
        (f"`{lib['file']}`, soname `{lib['soname']}`, "
         f"{len(lib['symbols'])} defined dynamic symbols. Public functions "
         f"missing: {lib['public-missing'] or 'none'}. Exported but not "
         "public (`inventory/abi.md` lists the source definitions): "
         + (", ".join(f"`{n}`" for n in lib["not-public"]) or "none")
         + ".\n"),
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
    md += [
        "## pytest suite (tests/http)\n",
        common.md_table(["outcome", "cases"], sorted(pytest_counts.items())),
        "### Not passed\n",
        common.md_table(
            ["case", "outcome", "message"],
            [(k, c["outcome"], c["message"])
             for k, c in sorted(pytest_cases.items())
             if c["outcome"] in ("failed", "error")]),
        "### Skip reasons\n",
        common.md_table(["reason", "cases"],
                        sorted(skip_reasons.items(), key=lambda x: -x[1])),
        ("Test functions with no case in the report (collected away): "
         + (", ".join(f"`{n}`" for n in pytest_uncollected) or "none")
         + ".\n"),
    ]
    common.write("baseline", data, "\n".join(md), [
        "build/c/baseline/", "build/c/CMakeCache.txt", "tests/runtests.pl"],
        generated_by="inventory/measure/baseline.py")


if __name__ == "__main__":
    main()
