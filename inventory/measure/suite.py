"""
Run the C test suite against a build tree and parse what it reports.

A build tree is laid out as CMake lays out build/c: `src/curl`,
`src/curlinfo`, `tests/` with the test servers and programs. runtests.pl
and the tests/http pytest suite run from its `tests/` directory. Both the C
baseline (baseline.py) and the Rust build (score.py) go through here, so
they are run and judged the same way.
"""

import json
import pathlib
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import common
from common import ROOT, check

RUNTESTS_ARGS = ["-a", "-n", "-j8"]
# As the curl-pytest CMake target, plus a machine-readable report.
PYTEST_ARGS = ["-n", "auto", "-p", "no:cacheprovider"]
# Shared by every build tree: it holds only the suite's Python modules.
VENV = ROOT / "build" / "c" / "pytest-venv"
# Features SCOPE.md leaves out: tests needing them skip by design.
OUT_OF_SCOPE = {"NTLM"}
SKIPPED_LINE = r"^test (\d+) SKIPPED: (.*?)\s*$"


def run(build, results, env):
    """
    Run runtests.pl and pytest from `build`/tests into `results`.

    `env` is the whole environment the suites run with. Returns the run's
    metadata.
    """
    results.mkdir(parents=True, exist_ok=True)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with (results / "runtests.log").open("w") as log:
        r = subprocess.run(["perl", str(ROOT / "tests/runtests.pl"),
                            *RUNTESTS_ARGS], cwd=build / "tests", env=env,
                           stdout=log, stderr=subprocess.STDOUT, check=False)
    log = (results / "runtests.log").read_text(errors="replace")
    check(re.search(r"^TESTDONE: \d+ tests were considered", log,
                    re.MULTILINE),
          "runtests.pl did not run the suite; it ended with:\n"
          + "\n".join(log.splitlines()[-5:]))
    probe_skips(build, results, env)
    if not (VENV / "bin/pytest").exists():
        subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
        subprocess.run([str(VENV / "bin/pip"), "install", "-q", "-r",
                        str(ROOT / "tests/http/requirements.txt")],
                       check=True)
    # The test servers run as `#!/usr/bin/env python3` and need the venv's
    # modules, so the venv goes first on PATH, as if activated.
    pyenv = {**env, "PATH": f"{VENV / 'bin'}:{env.get('PATH', '')}"}
    with (results / "pytest.log").open("w") as log:
        p = subprocess.run([str(VENV / "bin/pytest"), *PYTEST_ARGS,
                            f"--junitxml={results / 'pytest.xml'}",
                            str(ROOT / "tests/http")], cwd=build / "tests",
                           env=pyenv, stdout=log, stderr=subprocess.STDOUT,
                           check=False)
    # The pytest harness leaves the vsftpd daemons it starts running; stop
    # them so repeated runs do not pile them up.
    leftover = subprocess.run(["pkill", "-c", "-f",
                               f"^\\S*vsftpd {ROOT}/tests/http/gen/"],
                              check=False, capture_output=True,
                              text=True).stdout.strip()
    finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {"started": started, "finished": finished,
            "exit-status": r.returncode, "runtests-args": RUNTESTS_ARGS,
            "pytest-exit-status": p.returncode, "pytest-args": PYTEST_ARGS,
            "pytest-leftover-vsftpd": int(leftover or 0)}


def probe_skips(build, results, env):
    """
    Recover the skip reason of every test runtests.pl skipped.

    runtests.pl prints only the first three SKIPPED lines per reason and
    nine numbers per reason in its summary. Rerunning just the unexplained
    tests prints the next three, without starting any server; repeat until
    each has its line in skip-probes.log.
    """
    log = (results / "runtests.log").read_text(errors="replace")
    tests = json.loads((common.INVENTORY / "tests.json").read_text())["data"]
    explained = {int(n) for n in
                 re.findall(r"^test (\d+) [\[S]", log, re.MULTILINE)}
    explained |= set(tests["disabled"]["unconditional"])
    pending = sorted({t["number"] for t in tests["tests"]} - explained)
    with (results / "skip-probes.log").open("w") as out:
        while pending:
            r = subprocess.run(["perl", str(ROOT / "tests/runtests.pl"),
                                "-n", *map(str, pending)],
                               cwd=build / "tests", env=env,
                               capture_output=True, text=True, check=False)
            out.write(r.stdout)
            check(not re.search(r"^test \d+ \[", r.stdout, re.MULTILINE),
                  "a probed test ran instead of skipping")
            got = {int(n) for n, _ in
                   re.findall(SKIPPED_LINE, r.stdout, re.MULTILINE)}
            check(got, f"probe explained none of {pending}")
            pending = [n for n in pending if n not in got]


def parse_log(log, probes, all_tests, disabled):
    """
    Return (ran, failed, {skipped: reason}, {failed: parts}, {ignored: why}).

    `log` is runtests.pl's output and `probes` probe_skips()'s. Every count
    is checked against the totals runtests.pl printed itself. A test whose
    tool does not exist starts, is reported IGNORED, and is neither run nor
    skipped as far as runtests.pl's totals go.
    """
    started = [int(n) for n in re.findall(r"^test (\d+) \[", log,
                                          re.MULTILINE)]
    check(len(started) == len(set(started)), "a test ran twice")
    ignored = {int(n): why for n, why in re.findall(
        r"^ (\d+): IGNORED: (.*?)\s*$", log, re.MULTILINE)}
    check(set(ignored) <= set(started), "an ignored test never started")
    ran = set(started) - set(ignored)
    m = re.search(r"^TESTDONE: (\d+) tests were considered", log, re.MULTILINE)
    check(m and int(m.group(1)) == len(all_tests) - len(ignored),
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
    skipped = set(all_tests) - ran - set(ignored)
    check(skipped == set(reason) - ran - set(ignored),
          f"skipped tests without a reason: {sorted(skipped - set(reason))}")
    counts = {}
    for n in skipped:
        counts[reason[n]] = counts.get(reason[n], 0) + 1
    check(counts == info, f"skip reasons {counts} differ from TESTINFO {info}")

    failures = {}
    for n in failed:
        failures[n] = sorted(set(re.findall(
            rf"^ {n}: (.*?) FAILED", log, re.MULTILINE)))
    return ran, failed, {n: reason[n] for n in skipped}, failures, ignored


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


def results(build, results_dir, tests):
    """
    Parse a finished run into per-test results.

    Returns ({test: result}, {pytest case: outcome}, pytest functions with
    no case).
    """
    by_num = {t["number"]: t for t in tests["tests"]}
    log = (results_dir / "runtests.log").read_text(errors="replace")
    probes = (results_dir / "skip-probes.log").read_text(errors="replace")
    ran, failed, skipped, failures, ignored = parse_log(
        log, probes, list(by_num), tests["disabled"]["unconditional"])
    out = {}
    for n in sorted(by_num):
        if n in ignored:
            out[n] = {"result": "ignored", "reason": ignored[n]}
        elif n in failed:
            out[n] = {"result": "failed", "failed-parts": failures[n]}
        elif n in ran:
            out[n] = {"result": "ok"}
        else:
            out[n] = {"result": "skipped", "reason": skipped[n],
                      "class": classify(skipped[n])}
    cases, uncollected = parse_pytest(
        results_dir / "pytest.xml",
        (results_dir / "pytest.log").read_text(errors="replace"),
        tests["pytest"]["files"])
    return out, cases, uncollected


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
