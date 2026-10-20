#!/usr/bin/env python3
"""
Measure the performance of a release build of the C reference.

`--run` configures a release build of the reference configuration in
build/c-release (baseline.py's CMAKE_ARGS without the debug features, which
distort timings), then measures it and keeps the raw samples in
build/c-release/perf/. Without `--run`, the stored samples are summarised
into inventory/perf.{json,md}.

Two kinds of measurement:

- tests/perf: each program runs SAMPLES times with its default loop count;
  the headline figure is its first `Time/...` line (ns per operation).
- tests/http/scorecard.py: downloads, uploads and request rates against the
  local httpd for each protocol, SCORECARD_RUNS times. Its handshake part is
  left out: it connects to public internet hosts.

The figures hold for this machine only, which is a virtual machine whose
host schedules the cores: compare builds measured here, by medians, never
against numbers from elsewhere. `measure()` takes the build directory, so
another libcurl is measured the same way.
"""

import hashlib
import json
import os
import pathlib
import platform
import re
import statistics
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import baseline
import common
import deps
from common import ROOT, check

BUILD = ROOT / "build" / "c-release"
RESULTS = BUILD / "perf"
CMAKE_ARGS = {**baseline.CMAKE_ARGS, "CMAKE_BUILD_TYPE": "Release",
              "ENABLE_DEBUG": "OFF"}
SAMPLES = 9
SCORECARD_RUNS = 5
SCORECARD_PROTOCOLS = ["h1", "h2", "h3"]
SCORECARD_ARGS = ["-j", "--samples", "1", "-d", "-u", "-r", "--httpd"]
# tests/perf/README.md points urlparser at this dataset; pinned by commit
# and checksum so every measurement parses the same URLs.
URL_DATASET = {
    "url": "https://raw.githubusercontent.com/ada-url/url-various-datasets/"
           "96a6fdd1e36a98904025ed5d1efd5ac9375bc18c/top100/top100.txt",
    "sha256": "b11a9be08fc3065413e60b1bcddcb2b50ee0eb4923158d1a1a9e251cf89970d3",
    "path": deps.DEPS / "datasets" / "top100.txt",
}


def url_dataset():
    path = URL_DATASET["path"]
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(URL_DATASET["url"]) as r:
            path.write_bytes(r.read())
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    check(digest == URL_DATASET["sha256"], f"{path} has sha256 {digest}")
    return path


def build():
    dep_env = deps.build()
    (BUILD / "CMakeCache.txt").unlink(missing_ok=True)
    subprocess.run(["cmake", "-S", str(ROOT), "-B", str(BUILD), "-G",
                    "Ninja", *(f"-D{k}={v}" for k, v in CMAKE_ARGS.items())],
                   check=True, stdout=subprocess.DEVNULL,
                   env={**os.environ, **dep_env})
    subprocess.run(["ninja", "-C", str(BUILD), "all", "testdeps", "perf"],
                   check=True, stdout=subprocess.DEVNULL)
    for binary in [next(BUILD.glob("lib/libcurl*.so.*.*.*")),
                   BUILD / "src/curl", BUILD / "tests/perf/perf"]:
        deps.check_linked(binary)


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


def measure_perf(build_dir, programs, out):
    """Run every tests/perf program SAMPLES times; return raw samples."""
    perf = build_dir / "tests/perf/perf"
    dataset = url_dataset()
    raw = {}
    for name in programs:
        args = [str(perf), name]
        if name == "urlparser":
            args.append(str(dataset))
        runs = []
        for _ in range(SAMPLES):
            r = subprocess.run(args, capture_output=True, text=True,
                               check=True)
            values = parse_perf_output(r.stdout + r.stderr)
            check(any(k.startswith("Time/") for k in values),
                  f"perf {name} printed no Time/ line: {r.stdout!r}")
            runs.append(values)
        raw[name] = runs
        (out / f"perf-{name}.json").write_text(json.dumps(runs, indent=1))
    return raw


def measure_scorecard(build_dir, out):
    """Run the scorecard SCORECARD_RUNS times per protocol."""
    env = {**os.environ,
           "PATH": f"{baseline.VENV / 'bin'}:{os.environ.get('PATH', '')}"}
    raw = {}
    for proto in SCORECARD_PROTOCOLS:
        runs = []
        for i in range(SCORECARD_RUNS):
            r = subprocess.run(
                [str(baseline.VENV / "bin/python3"),
                 str(ROOT / "tests/http/scorecard.py"), *SCORECARD_ARGS,
                 proto], cwd=build_dir / "tests", env=env,
                capture_output=True, text=True, check=False)
            (out / f"scorecard-{proto}-{i}.err").write_text(r.stderr)
            check(r.returncode == 0,
                  f"scorecard {proto} run {i} failed: {r.stderr[-500:]}")
            runs.append(json.loads(r.stdout))
        raw[proto] = runs
        (out / f"scorecard-{proto}.json").write_text(json.dumps(runs))
    return raw


def measure(build_dir, out):
    """Measure the libcurl in `build_dir`; keep raw results in `out`."""
    out.mkdir(parents=True, exist_ok=True)
    tests = json.loads((common.INVENTORY / "tests.json").read_text())["data"]
    meta = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "machine": machine(), "samples": SAMPLES,
            "scorecard-runs": SCORECARD_RUNS,
            "scorecard-args": SCORECARD_ARGS,
            "url-dataset": {k: str(v) for k, v in URL_DATASET.items()}}
    measure_perf(build_dir, sorted(tests["perf"]), out)
    measure_scorecard(build_dir, out)
    meta["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (out / "run.json").write_text(json.dumps(meta, indent=1) + "\n")


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


def main():
    if "--run" in sys.argv[1:]:
        commit = common.c_commit()
        check(not commit.endswith("-dirty"),
              "C tree has local changes; a baseline must name a commit")
        build()
        measure(BUILD, RESULTS)
        meta = json.loads((RESULTS / "run.json").read_text())
        meta["c-commit"] = commit
        (RESULTS / "run.json").write_text(json.dumps(meta, indent=1) + "\n")
    meta = json.loads((RESULTS / "run.json").read_text())
    check(meta["c-commit"] == common.c_commit(),
          f"measured at {meta['c-commit'][:12]}, the C tree is at "
          f"{common.c_commit()[:12]}: rerun with --run")
    tests = json.loads((common.INVENTORY / "tests.json").read_text())["data"]
    version = subprocess.run([str(BUILD / "src/curl"), "-V"],
                             capture_output=True, text=True,
                             check=True).stdout.strip().splitlines()
    data = {"measured": {"started": meta["started"],
                         "finished": meta["finished"]},
            "machine": meta["machine"], "cmake-args": CMAKE_ARGS,
            "curl-version": version, "samples": meta["samples"],
            "scorecard-runs": meta["scorecard-runs"],
            "scorecard-args": meta["scorecard-args"],
            "url-dataset": meta["url-dataset"],
            "perf": summarize_perf(RESULTS, sorted(tests["perf"])),
            "scorecard": summarize_scorecard(RESULTS)}

    m = data["machine"]
    md = ["# C reference performance\n",
          ("Release build of the reference configuration in "
           "`build/c-release`, measured "
           f"{meta['started']} to {meta['finished']} on a "
           f"{m['cpus']}-CPU {m['machine']} "
           f"{m['virtualization'] or 'bare-metal'} machine (kernel "
           f"{m['kernel']}). Figures are medians; compare only builds "
           "measured on this machine, by the same script.\n"),
          "```", *version[:1], "```\n",
          (f"## tests/perf ({meta['samples']} runs each)\n"),
          common.md_table(
              ["program", "measure", "median", "min", "IQR"],
              [(n, p["headline"],
                fmt(p["values"][p["headline"]]["median"], p["unit"]),
                fmt(p["values"][p["headline"]]["min"], p["unit"]),
                f"{p['values'][p['headline']]['iqr-pct']}%")
               for n, p in data["perf"].items()])]
    for proto, sc in data["scorecard"].items():
        md.append(f"## scorecard {proto} ({meta['scorecard-runs']} runs, "
                  f"{sc['server']})\n")
        for section, table in sc["tables"].items():
            unit = "r/s" if section == "requests" else "B/s"
            cols = list(table["rows"][0]["cells"])
            md.extend([f"**{table['title']}**\n", common.md_table(
                ["size", *cols],
                [(r["size"], *(f"{fmt(r['cells'][c]['median'], unit)} "
                               f"(IQR {r['cells'][c]['iqr-pct']:.0f}%)"
                               for c in cols))
                 for r in table["rows"]])])
    common.write("perf", data, "\n".join(md), [
        "build/c-release/perf/", "tests/perf/", "tests/http/scorecard.py"],
        generated_by="inventory/measure/perf.py")


if __name__ == "__main__":
    main()
