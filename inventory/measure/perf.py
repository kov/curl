#!/usr/bin/env python3
"""
Measure the performance of the rewrite's release build against C's.

`--run` builds both sides in release form, measures them, and keeps the raw
samples under each build directory's perf/; `--build` only builds them.
Without either, the stored samples are summarised into
inventory/perf.{json,md}.

Two configurations, each a C leg and a Rust leg:

- reference: the reference configuration (baseline.py's CMAKE_ARGS without
  the debug features, which distort timings; the Rust crates' default
  features). The C leg is build/c-release; the Rust leg is
  build/rust-release, the C release tree with the Rust library and tool in
  place of C's (build/target-release).
- threaded: the same with the threaded resolver, and the scorecard's
  transfers verbose (`--curl-verbose`): the way WebKit runs libcurl
  (MILESTONES.md, milestone 8). build/c-release-threaded and
  build/rust-release-threaded.

Two kinds of measurement:

- tests/perf: each program runs SAMPLES times with its default loop count;
  the headline figure is its first `Time/...` line (ns per operation). A
  program on the public API runs the C binary against each leg's library.
  One that times a C internal helper (inventory/tests.json's `rust_leg`
  `port`) has a Rust counterpart, an ignored test named in PORTS, run from
  a release build of its crate's tests. Measured in the reference
  configuration only: the resolver changes none of them.
- tests/http/scorecard.py: downloads, uploads and request rates against the
  local httpd for each protocol, SCORECARD_RUNS times. Its handshake part is
  left out: it connects to public internet hosts.

The legs' samples are interleaved, sample by sample, so that drift in the
host spreads over all of them. The figures hold for this machine only,
which is a virtual machine whose host schedules the cores: compare builds
measured here, in one run, by medians, never against numbers from
elsewhere.
"""

import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import baseline
import common
import deps
import score
from common import ROOT, check

RELEASE = {"CMAKE_BUILD_TYPE": "Release", "ENABLE_DEBUG": "OFF"}
C_CMAKE_ARGS = {**baseline.CMAKE_ARGS, **RELEASE}
SAMPLES = 9
SCORECARD_RUNS = 5
SCORECARD_PROTOCOLS = ["h1", "h2", "h3"]
SCORECARD_ARGS = ["-j", "--samples", "1", "-d", "-u", "-r", "--httpd"]
# The release library's name, as the C release build installs it.
SONAME = "libcurl.so.4"
# The Rust counterparts of the programs that time C internals: the crate,
# the cargo target that holds the test and the test's path.
PORTS = {
    "base64dec": ("curl-core", ["--lib"], "base64::perf::base64dec"),
    "base64enc": ("curl-core", ["--lib"], "base64::perf::base64enc"),
    "numparser": ("curl-tool", ["--bin", "curl"],
                  "options::number::perf::numparser"),
}
# tests/perf/README.md points urlparser at this dataset; pinned by commit
# and checksum so every measurement parses the same URLs.
URL_DATASET = {
    "url": "https://raw.githubusercontent.com/ada-url/url-various-datasets/"
           "96a6fdd1e36a98904025ed5d1efd5ac9375bc18c/top100/top100.txt",
    "sha256": "b11a9be08fc3065413e60b1bcddcb2b50ee0eb4923158d1a1a9e251cf89970d3",
    "path": deps.DEPS / "datasets" / "top100.txt",
}


@dataclass(frozen=True)
class Config:
    name: str
    cmake: dict
    features: tuple
    scorecard_args: tuple
    perf: bool


REFERENCE = Config("reference", C_CMAKE_ARGS, (), (), True)
THREADED = Config("threaded", {**baseline.THREADED.cmake_args, **RELEASE},
                  ("curl-sys-abi/threaded-resolver",
                   "curl-tool/threaded-resolver"),
                  ("--curl-verbose",), False)
CONFIGS = [REFERENCE, THREADED]


@dataclass(frozen=True)
class Leg:
    config: Config
    side: str  # "c" or "rust"

    @property
    def name(self):
        suffix = "" if self.config is REFERENCE else f"-{self.config.name}"
        return f"{self.side}{suffix}"

    @property
    def c_build(self):
        suffix = "" if self.config is REFERENCE else f"-{self.config.name}"
        return ROOT / "build" / f"c-release{suffix}"

    @property
    def build(self):
        if self.side == "c":
            return self.c_build
        suffix = "" if self.config is REFERENCE else f"-{self.config.name}"
        return ROOT / "build" / f"rust-release{suffix}"

    @property
    def target(self):
        suffix = "" if self.config is REFERENCE else f"-{self.config.name}"
        return ROOT / "build" / f"target-release{suffix}"

    @property
    def results(self):
        return self.build / "perf"

    def env(self):
        """The environment the leg's programs run with."""
        if self.side == "c":
            return dict(os.environ)
        return {**os.environ, "LD_LIBRARY_PATH": str(self.build / "lib")}


LEGS = [Leg(c, s) for c in CONFIGS for s in ("c", "rust")]


def url_dataset():
    path = URL_DATASET["path"]
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(URL_DATASET["url"]) as r:
            path.write_bytes(r.read())
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    check(digest == URL_DATASET["sha256"], f"{path} has sha256 {digest}")
    return path


def nice(cmd):
    """`cmd` run at a low priority: builds must not crowd a measurement."""
    return ["nice", "-n", "10", *cmd]


def build_c(leg):
    dep_env = deps.build()
    build = leg.c_build
    (build / "CMakeCache.txt").unlink(missing_ok=True)
    subprocess.run(nice(["cmake", "-S", str(ROOT), "-B", str(build), "-G",
                         "Ninja",
                         *(f"-D{k}={v}" for k, v in leg.config.cmake.items())]),
                   check=True, stdout=subprocess.DEVNULL,
                   env={**os.environ, **dep_env})
    subprocess.run(nice(["ninja", "-C", str(build), "all", "testdeps",
                         "perf"]), check=True, stdout=subprocess.DEVNULL)
    for binary in [next(build.glob("lib/libcurl*.so.*.*.*")),
                   build / "src/curl", build / "tests/perf/perf"]:
        deps.check_linked(binary)


def cargo(leg, *args):
    features = ["--features", ",".join(leg.config.features)] \
        if leg.config.features else []
    return nice(["cargo", *args, "--release", "--target-dir",
                 str(leg.target), *features])


def port_binaries(leg):
    """Build each PORTS test binary; return their paths by program."""
    out = {}
    for name, (crate, target, _test) in PORTS.items():
        r = subprocess.run(
            cargo(leg, "test", "--no-run", "-p", crate, *target,
                  "--message-format=json"),
            cwd=ROOT, check=True, capture_output=True, text=True)
        exes = [m["executable"] for m in map(json.loads, r.stdout.splitlines())
                if m.get("reason") == "compiler-artifact"
                and m.get("executable") and m["target"]["name"] ==
                ("curl" if crate == "curl-tool" else crate.replace("-", "_"))
                and m["profile"]["test"]]
        check(len(exes) == 1, f"{crate} {target}: test binaries {exes}")
        out[name] = exes[0]
    return out


def build_rust(leg):
    """Build the Rust crates and lay out the leg's tree over C's."""
    subprocess.run(cargo(leg, "build", "-p", "curl-sys-abi", "-p",
                         "curl-tool"), cwd=ROOT, check=True)
    out = leg.target / "release"
    c_build = leg.c_build
    if leg.build.exists():
        shutil.rmtree(leg.build)
    # tests/perf is left out whole and rebuilt with a copy of its program:
    # a link to C's directory would put the copy in C's tree.
    skip = {"perf", "src/curl", "src/curlinfo", "tests/perf", "tests/log",
            "tests/.cache"}
    score.overlay(c_build, c_build, leg.build, skip)
    shutil.copy2(out / "libcurl.so", leg.build / "lib" / SONAME)
    for name in ("curl", "curlinfo"):
        shutil.copy2(out / name, leg.build / "src" / name)
    perf = leg.build / "tests/perf/perf"
    perf.parent.mkdir()
    shutil.copy2(c_build / "tests/perf/perf", perf)
    # Without the environment too, it loads the leg's library.
    score.own_runpath(perf, c_build / "lib", "$ORIGIN/../../lib")
    if leg.config.perf:
        ports = port_binaries(leg)
        (leg.build / "ports.json").write_text(json.dumps(ports, indent=1))


def check_loading(leg):
    """Fail unless the leg's programs load the leg's own library."""
    want = (leg.build / "lib" / SONAME).resolve()
    if leg.side == "c":
        want = next(leg.build.glob("lib/libcurl.so.*.*.*")).resolve()
    bare = {k: v for k, v in os.environ.items() if k != "LD_LIBRARY_PATH"}
    for env in (leg.env(), bare):
        ldd = subprocess.run(["ldd", str(leg.build / "tests/perf/perf")],
                             env=env, check=True, capture_output=True,
                             text=True).stdout
        m = re.search(rf"^\s*{re.escape(SONAME)} => (\S+)", ldd, re.MULTILINE)
        check(m and pathlib.Path(m.group(1)).resolve() == want,
              f"{leg.name}: tests/perf/perf loads {m and m.group(1)}, "
              f"not {want}")
    version = subprocess.run([str(leg.build / "src/curl"), "-V"],
                             capture_output=True, text=True, check=True,
                             env=leg.env()).stdout
    resolver = "c-ares/" in version.splitlines()[0]
    check(resolver == (leg.config is REFERENCE),
          f"{leg.name}: curl -V says {version.splitlines()[0]!r}")


def machine():
    def read(path):
        try:
            return pathlib.Path(path).read_text().strip()
        except OSError:
            return None
    virt = subprocess.run(["systemd-detect-virt"], capture_output=True,
                          text=True, check=False).stdout.strip()
    return {"kernel": platform.release(), "machine": platform.machine(),
            "cpus": os.cpu_count(), "virtualization": virt or None,
            "memory": read("/proc/meminfo").splitlines()[0],
            "loadavg-before": read("/proc/loadavg")}


def parse_perf_output(text):
    values = {}
    for key, num, unit in re.findall(
            r"^([A-Za-z/ ]+):\s+([0-9.]+)\s*(\S*)\s*$", text, re.MULTILINE):
        values[key.strip()] = {"value": float(num), "unit": unit or None}
    return values


def perf_command(leg, name, dataset):
    """The command that runs program `name` for `leg`."""
    if leg.side == "rust" and name in PORTS:
        ports = json.loads((leg.build / "ports.json").read_text())
        return [ports[name], "--ignored", "--exact", PORTS[name][2],
                "--nocapture", "--test-threads", "1"]
    args = [str(leg.build / "tests/perf/perf"), name]
    if name == "urlparser":
        args.append(str(dataset))
    return args


def measure_perf(legs, programs):
    """Run every tests/perf program SAMPLES times on each leg, interleaved."""
    dataset = url_dataset()
    for name in programs:
        runs = {leg.name: [] for leg in legs}
        for _ in range(SAMPLES):
            for leg in legs:
                r = subprocess.run(perf_command(leg, name, dataset),
                                   capture_output=True, text=True,
                                   check=True, env=leg.env())
                values = parse_perf_output(r.stdout + r.stderr)
                check(any(k.startswith("Time/") for k in values),
                      f"{leg.name} perf {name} printed no Time/ line: "
                      f"{r.stdout!r}")
                runs[leg.name].append(values)
        for leg in legs:
            (leg.results / f"perf-{name}.json").write_text(
                json.dumps(runs[leg.name], indent=1))


def measure_scorecard(legs):
    """Run the scorecard SCORECARD_RUNS times per protocol, interleaved."""
    path = f"{baseline.VENV / 'bin'}:{os.environ.get('PATH', '')}"
    for proto in SCORECARD_PROTOCOLS:
        runs = {leg.name: [] for leg in legs}
        for i in range(SCORECARD_RUNS):
            for leg in legs:
                r = subprocess.run(
                    [str(baseline.VENV / "bin/python3"),
                     str(ROOT / "tests/http/scorecard.py"), *SCORECARD_ARGS,
                     *leg.config.scorecard_args, proto],
                    cwd=leg.build / "tests", env={**leg.env(), "PATH": path},
                    capture_output=True, text=True, check=False)
                (leg.results / f"scorecard-{proto}-{i}.err").write_text(
                    r.stderr)
                check(r.returncode == 0, f"{leg.name} scorecard {proto} run "
                      f"{i} failed: {r.stderr[-500:]}")
                runs[leg.name].append(json.loads(r.stdout))
        for leg in legs:
            (leg.results / f"scorecard-{proto}.json").write_text(
                json.dumps(runs[leg.name]))


def rust_commit():
    sha = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                         check=True, capture_output=True,
                         text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain",
                            "--untracked-files=no"], check=True,
                           capture_output=True, text=True).stdout.strip()
    return sha + ("-dirty" if dirty else "")


def build():
    for leg in LEGS:
        if leg.side == "c":
            build_c(leg)
    for leg in LEGS:
        if leg.side == "rust":
            build_rust(leg)
    for leg in LEGS:
        check_loading(leg)


def run():
    commit = common.c_commit()
    check(not commit.endswith("-dirty"),
          "C tree has local changes; a measurement must name a commit")
    rust = rust_commit()
    check(not rust.endswith("-dirty"),
          "the tree has local changes; a measurement must name a commit")
    build()
    for leg in LEGS:
        if leg.results.exists():
            shutil.rmtree(leg.results)
        leg.results.mkdir(parents=True)
    tests = json.loads((common.INVENTORY / "tests.json").read_text())["data"]
    meta = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "machine": machine(), "samples": SAMPLES,
            "scorecard-runs": SCORECARD_RUNS,
            "scorecard-args": SCORECARD_ARGS,
            "url-dataset": {k: str(v) for k, v in URL_DATASET.items()},
            "c-commit": commit, "commit": rust}
    measure_perf([leg for leg in LEGS if leg.config.perf],
                 sorted(tests["perf"]))
    measure_scorecard(LEGS)
    meta["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    meta["loadavg-after"] = machine()["loadavg-before"]
    for leg in LEGS:
        (leg.results / "run.json").write_text(json.dumps(meta, indent=1) + "\n")


def spread(values):
    """
    Summarise samples by their median and interquartile range.

    The host occasionally takes a core for a whole run, giving one sample
    twice as slow; the IQR, unlike max - min, ignores such a sample.
    """
    med = statistics.median(values)
    q1, _, q3 = statistics.quantiles(values, n=4, method="inclusive")
    return {"median": med, "min": min(values), "max": max(values),
            "iqr-pct": round(100 * (q3 - q1) / med, 1) if med else None,
            "samples": values}


def summarize_perf(out, programs):
    result = {}
    for name in programs:
        runs = json.loads((out / f"perf-{name}.json").read_text())
        keys = list(runs[0])
        check(all(list(r) == keys for r in runs),
              f"perf {name}: runs printed different keys")
        headline = next(k for k in keys if k.startswith("Time/"))
        result[name] = {
            "headline": headline,
            "unit": runs[0][headline]["unit"],
            "values": {k: spread([r[k]["value"] for r in runs])
                       for k in keys}}
    return result


def summarize_scorecard(out):
    result = {}
    for proto in SCORECARD_PROTOCOLS:
        runs = json.loads((out / f"scorecard-{proto}.json").read_text())
        tables = {}
        for section in ("downloads", "uploads", "requests"):
            cols = runs[0][section]["cols"]
            check(all(r[section]["cols"] == cols for r in runs),
                  f"scorecard {proto} {section}: runs differ in columns")
            rows = []
            for i, row in enumerate(runs[0][section]["rows"]):
                cells = {}
                for j, col in enumerate(cols[1:], start=1):
                    if col == "total":
                        continue  # the request count, not a measurement
                    vals = [r[section]["rows"][i][j]["val"] for r in runs]
                    if all(isinstance(v, (int, float)) for v in vals):
                        cells[col] = spread(vals)
                rows.append({"size": row[0]["sval"], "cells": cells})
            check(rows and all(r["cells"] for r in rows),
                  f"scorecard {proto} {section}: no numeric results")
            tables[section] = {"title": runs[0][section]["meta"]["title"],
                               "rows": rows}
        result[proto] = {"server": runs[0]["meta"]["server"],
                         "implementation": runs[0]["meta"].get(
                             "implementation"),
                         "tables": tables}
    return result


def fmt(v, unit):
    if unit == "r/s":
        return f"{v:,.0f} r/s"
    if unit == "B/s":
        return f"{v / 1e6:,.1f} MB/s"
    return f"{v:,.2f} {unit}"


def ratio(rust, c):
    return f"{rust / c:.2f}" if c else "-"


def scorecard_md(config, c, rust, runs):
    md = []
    for proto, sc in c.items():
        md.append(f"### {proto} ({runs} runs each, {sc['server']})\n")
        for section, table in sc["tables"].items():
            unit = "r/s" if section == "requests" else "B/s"
            rtable = rust[proto]["tables"][section]
            cols = list(table["rows"][0]["cells"])
            rows = []
            for crow, rrow in zip(table["rows"], rtable["rows"]):
                check(crow["size"] == rrow["size"],
                      f"{config} {proto} {section}: rows differ")
                for col in cols:
                    cc, rc = crow["cells"][col], rrow["cells"][col]
                    rows.append((crow["size"], col,
                                 f"{fmt(cc['median'], unit)} "
                                 f"(IQR {cc['iqr-pct']:.0f}%)",
                                 f"{fmt(rc['median'], unit)} "
                                 f"(IQR {rc['iqr-pct']:.0f}%)",
                                 ratio(rc["median"], cc["median"])))
            md.extend([f"**{table['title']}** (Rust/C above 1 is faster)\n",
                       common.md_table(["size", "kind", "C", "Rust",
                                        "Rust/C"], rows)])
    return md


def main():
    if "--build" in sys.argv[1:]:
        build()
        return
    if "--run" in sys.argv[1:]:
        run()
    metas = {leg.name: json.loads((leg.results / "run.json").read_text())
             for leg in LEGS}
    meta = metas["c"]
    check(all(m == meta for m in metas.values()),
          "the legs' results come from different runs: rerun with --run")
    check(meta["c-commit"] == common.c_commit(),
          f"measured at {meta['c-commit'][:12]}, the C tree is at "
          f"{common.c_commit()[:12]}: rerun with --run")
    tests = json.loads((common.INVENTORY / "tests.json").read_text())["data"]
    programs = sorted(tests["perf"])
    legs = {}
    for leg in LEGS:
        version = subprocess.run([str(leg.build / "src/curl"), "-V"],
                                 capture_output=True, text=True, check=True,
                                 env=leg.env()).stdout.strip().splitlines()
        legs[leg.name] = {
            "build": str(leg.build.relative_to(ROOT)),
            "curl-version": version,
            "perf": summarize_perf(leg.results, programs)
            if leg.config.perf else None,
            "scorecard": summarize_scorecard(leg.results)}
    data = {"measured": {"started": meta["started"],
                         "finished": meta["finished"]},
            "commit": meta["commit"],
            "machine": meta["machine"],
            "loadavg-after": meta["loadavg-after"],
            "configs": {c.name: {"cmake-args": c.cmake,
                                 "cargo-features": list(c.features),
                                 "scorecard-extra-args":
                                     list(c.scorecard_args)}
                        for c in CONFIGS},
            "samples": meta["samples"],
            "scorecard-runs": meta["scorecard-runs"],
            "scorecard-args": meta["scorecard-args"],
            "url-dataset": meta["url-dataset"],
            "ports": {k: {"crate": v[0], "test": v[2]}
                      for k, v in PORTS.items()},
            "legs": legs}

    m = data["machine"]
    md = ["# Performance: the rewrite against C\n",
          ("Release builds, measured "
           f"{meta['started']} to {meta['finished']} on a "
           f"{m['cpus']}-CPU {m['machine']} "
           f"{m['virtualization'] or 'bare-metal'} machine (kernel "
           f"{m['kernel']}), the legs' samples interleaved; load average "
           f"{m['loadavg-before'].split()[0]} before and "
           f"{meta['loadavg-after'].split()[0]} after. The rewrite at "
           f"`{meta['commit'][:12]}`. Figures are medians; compare only "
           "builds measured on this machine, in one run of this script.\n"),
          "```", *(f"{name}: {legs[name]['curl-version'][0]}"
                   for name in legs), "```\n",
          f"## tests/perf ({meta['samples']} runs each, reference "
          "configuration)\n",
          ("A program marked *port* times a C internal on the C leg and its "
           "Rust counterpart (`ports` in perf.json) on the Rust leg; the "
           "others run the same C program against each library. Rust/C "
           "below 1 is faster.\n"),
          common.md_table(
              ["program", "measure", "C", "C IQR", "Rust", "Rust IQR",
               "Rust/C"],
              [(f"{n} (port)" if n in PORTS else n, p["headline"],
                fmt(p["values"][p["headline"]]["median"], p["unit"]),
                f"{p['values'][p['headline']]['iqr-pct']}%",
                fmt(r["values"][r["headline"]]["median"], r["unit"]),
                f"{r['values'][r['headline']]['iqr-pct']}%",
                ratio(r["values"][r["headline"]]["median"],
                      p["values"][p["headline"]]["median"]))
               for (n, p), r in zip(legs["c"]["perf"].items(),
                                    legs["rust"]["perf"].values())])]
    for config in CONFIGS:
        suffix = "" if config is REFERENCE else f"-{config.name}"
        extra = (f", scorecard with `{' '.join(config.scorecard_args)}`"
                 if config.scorecard_args else "")
        md.append(f"## scorecard, {config.name} configuration{extra}\n")
        md.extend(scorecard_md(config.name, legs[f"c{suffix}"]["scorecard"],
                               legs[f"rust{suffix}"]["scorecard"],
                               meta["scorecard-runs"]))
    common.write("perf", data, "\n".join(md), [
        "tests/perf/", "tests/http/scorecard.py"],
        generated_by="inventory/measure/perf.py")


if __name__ == "__main__":
    main()
