#!/usr/bin/env python3
"""
Measure the C reference build against the C test suite.

`--run` configures and builds the C tree in build/c with CMAKE_ARGS, runs
tests/runtests.pl over every test, and keeps the raw results in
build/c/baseline/. Without `--run`, the stored results are parsed into
inventory/baseline.{json,md}.

`--threaded` does the same for the second oracle, the reference build with
the threaded resolver in place of c-ares (SCOPE.md): build/c-threaded,
inventory/baseline-threaded.{json,md}.

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
from dataclasses import dataclass

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import common
import deps
import suite
from common import ROOT, check

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


@dataclass(frozen=True)
class Oracle:
    """A C build the rewrite is checked against, and where its results go."""
    build: pathlib.Path
    # The stem of its inventory/<stem>.{json,md}.
    inventory: str
    # What its inventory page is titled, and the flag that selects it.
    title: str
    flag: str
    cmake_args: dict

    @property
    def results(self):
        return self.build / "baseline"

    @property
    def test_programs(self):
        """Test programs that link libcurl and ngtcp2 themselves."""
        return [self.build / "tests/libtest/libtests",
                self.build / "tests/unit/units",
                self.build / "tests/tunit/tunits"]


REFERENCE = Oracle(ROOT / "build" / "c", "baseline", "C reference baseline",
                   "", CMAKE_ARGS)
# The resolver distributions build libcurl with, in place of c-ares.
THREADED = Oracle(ROOT / "build" / "c-threaded", "baseline-threaded",
                  "C threaded-resolver baseline", "--threaded",
                  {**CMAKE_ARGS, "ENABLE_ARES": "OFF",
                   "ENABLE_THREADED_RESOLVER": "ON"})


def run(oracle):
    commit = common.c_commit()
    check(not commit.endswith("-dirty"),
          "C tree has local changes; a baseline must name a commit")
    dep_env = deps.build()
    # A fresh cache: nothing configured by hand earlier, such as another
    # library location, may carry into the measurement.
    (oracle.build / "CMakeCache.txt").unlink(missing_ok=True)
    subprocess.run(["cmake", "-S", str(ROOT), "-B", str(oracle.build), "-G",
                    "Ninja", *(f"-D{k}={v}" for k, v in oracle.cmake_args.items())],
                   check=True, stdout=subprocess.DEVNULL,
                   env={**os.environ, **dep_env})
    # The test programs are not in the default target.
    subprocess.run(["ninja", "-C", str(oracle.build), "all", "testdeps"],
                   check=True, stdout=subprocess.DEVNULL)
    for binary in [next(oracle.build.glob("lib/libcurl*.so.*.*.*")),
                   oracle.build / "src/curl", *oracle.test_programs]:
        deps.check_linked(binary)
    meta = suite.run(oracle.build, oracle.results, dict(os.environ))
    (oracle.results / "run.json").write_text(
        json.dumps({"c-commit": commit, **meta}, indent=1) + "\n")


def build_config(oracle):
    cache = {}
    for line in (oracle.build / "CMakeCache.txt").read_text().splitlines():
        m = re.match(r"^(\w+):\w+=(.*)$", line)
        if m:
            cache[m.group(1)] = m.group(2)
    for k, v in oracle.cmake_args.items():
        check(cache.get(k) == v,
              f"{oracle.build} has {k}={cache.get(k)!r}, it should be {v!r}")
    return cache


def exports(oracle):
    """Return the built library's soname and defined dynamic symbols."""
    libs = sorted(oracle.build.glob("lib/libcurl*.so.*.*.*"))
    check(len(libs) == 1, f"expected one built libcurl, found {libs}")
    dyn = subprocess.run(["readelf", "-d", str(libs[0])], check=True,
                         capture_output=True, text=True).stdout
    soname = re.search(r"Library soname: \[(.*?)\]", dyn).group(1)
    nm = subprocess.run(["nm", "-D", "--defined-only", str(libs[0])],
                        check=True, capture_output=True, text=True).stdout
    symbols = sorted(line.split()[-1] for line in nm.splitlines())
    check("curl_easy_init" in symbols, "nm output has no curl_easy_init")
    return {"file": libs[0].name, "soname": soname, "symbols": symbols}


def main():
    oracle = THREADED if "--threaded" in sys.argv[1:] else REFERENCE
    if "--run" in sys.argv[1:]:
        run(oracle)
    meta = json.loads((oracle.results / "run.json").read_text())
    check(meta["c-commit"] == common.c_commit(),
          f"baseline was run at {meta['c-commit'][:12]}, the C tree is at "
          f"{common.c_commit()[:12]}: rerun with --run")
    cache = build_config(oracle)
    tests = json.loads((common.INVENTORY / "tests.json").read_text())["data"]
    check(json.loads((common.INVENTORY / "tests.json").read_text())
          ["c-commit"] == meta["c-commit"], "tests inventory is stale")
    by_num = {t["number"]: t for t in tests["tests"]}
    results, pytest_cases, pytest_uncollected = suite.results(
        oracle.build, oracle.results, tests)
    failures = {n: r["failed-parts"] for n, r in results.items()
                if r["result"] == "failed"}
    failed = set(failures)
    skipped = {n: r["reason"] for n, r in results.items()
               if r["result"] == "skipped"}
    ran = set(by_num) - set(skipped)
    log = (oracle.results / "runtests.log").read_text(errors="replace")

    version = subprocess.run([str(oracle.build / "src/curl"), "-V"],
                             capture_output=True, text=True,
                             check=True).stdout
    features = re.search(r"^Features: (.*)$", version, re.MULTILINE).group(1).split()
    protocols = re.search(r"^Protocols: (.*)$", version, re.MULTILINE).group(1)
    system = re.search(r"^\*+ System characteristics \*+ *\n(.*?)^\*+ *$",
                       log, re.MULTILINE | re.DOTALL)
    check(system is not None, "no System characteristics block")

    pytest_counts = {}
    for c in pytest_cases.values():
        pytest_counts[c["outcome"]] = pytest_counts.get(c["outcome"], 0) + 1
    skip_reasons = {}
    for c in pytest_cases.values():
        if c["outcome"] == "skipped":
            skip_reasons[c["message"]] = skip_reasons.get(c["message"], 0) + 1

    lib = exports(oracle)
    abi = json.loads((common.INVENTORY / "abi.json").read_text())["data"]
    public = {f["name"] for f in abi["functions"]}
    lib["not-public"] = sorted(set(lib["symbols"]) - public)
    lib["public-missing"] = sorted(public - set(lib["symbols"]))

    data = {
        "measured": {"started": meta["started"],
                     "finished": meta["finished"]},
        "runtests-args": meta["runtests-args"],
        "runtests-exit-status": meta["exit-status"],
        "cmake-args": oracle.cmake_args,
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
    rel = oracle.build.relative_to(ROOT)
    md = [
        f"# {oracle.title}\n",
        (f"What the C build in `{rel}` does on the C test suite: the floor "
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
            [(why, suite.classify(why), len(nums), sorted(nums))
             for why, nums in sorted(reasons.items(),
                                     key=lambda x: (suite.classify(x[0]), x[0]))]),
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
    common.write(oracle.inventory, data, "\n".join(md), [
        f"{rel}/baseline/", f"{rel}/CMakeCache.txt", "tests/runtests.pl"],
        generated_by=" ".join(filter(None, ["inventory/measure/baseline.py",
                                            oracle.flag])))


if __name__ == "__main__":
    main()
