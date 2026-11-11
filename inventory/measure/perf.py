#!/usr/bin/env python3
"""
Measure the performance of the rewrite's release build against C's.

`--run` builds both sides in release form, measures them, and keeps the raw
samples under each build directory's perf/; `--build` only builds them.
Without either, the stored samples are summarised into
inventory/<name>.{json,md}: perf on aarch64 Linux, perf-x86_64 on x86_64
Linux and perf-macos on macOS.

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
host spreads over all of them, and the load average is kept with each
scorecard run. The figures hold for the machine they were taken on only:
compare builds measured there, in one run, by medians, never against
numbers from elsewhere.

On macOS the dependencies come from Homebrew, OpenSSL from `OPENSSL_DIR`
(as the Rust build's openssl-sys takes it) and ngtcp2 from
`CURL_NGTCP2_DIR` (as curl-ngtcp2's build takes it). Homebrew's nghttpx
has no HTTP/3, so the first nghttpx on PATH is the one the C build's
tests/http configuration names: put one built with HTTP/3 there first.
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
import suite
from common import ROOT, check

sys.path.insert(0, str(ROOT / ".cargo" / "link"))
import hot_order  # noqa: E402

MACOS = sys.platform == "darwin"
# The release library's name, as the C release build installs it, and the
# glob that finds the file it names.
SONAME = "libcurl.4.dylib" if MACOS else "libcurl.so.4"
C_LIBRARY = "lib/libcurl.*.*.*.dylib" if MACOS else "lib/libcurl*.so.*.*.*"
# The variable that puts a directory first on the library search path.
LIBRARY_PATH = "DYLD_LIBRARY_PATH" if MACOS else "LD_LIBRARY_PATH"
# Where the summary goes: inventory/<OUTPUT>.{json,md}.
OUTPUT = ("perf-macos" if MACOS
          else "perf-x86_64" if platform.machine() == "x86_64" else "perf")
RELEASE = {"CMAKE_BUILD_TYPE": "Release", "ENABLE_DEBUG": "OFF"}


def platform_cmake_args():
    """What the C build needs on this platform beyond baseline's."""
    if not MACOS:
        return {}
    openssl = os.environ.get("OPENSSL_DIR")
    check(openssl, "OPENSSL_DIR must name the OpenSSL to build against")
    brew = subprocess.run(["brew", "--prefix"], check=True,
                          capture_output=True, text=True).stdout.strip()
    nghttpx = shutil.which("nghttpx")
    check(nghttpx, "no nghttpx on PATH")
    return {"OPENSSL_ROOT_DIR": openssl,
            "CMAKE_PREFIX_PATH": f"{deps.NGTCP2};{openssl};{brew}",
            "CMAKE_BUILD_RPATH": f"{deps.NGTCP2 / 'lib'};{openssl}/lib",
            # baseline's are Fedora's paths, and deps.py's h2o is built
            # on Linux alone: CMake finds macOS's.
            "DANTED": "", "SFTPD": "", "H2O": "",
            "HTTPD_NGHTTPX": nghttpx}


PLATFORM = platform_cmake_args()
C_CMAKE_ARGS = {**baseline.CMAKE_ARGS, **RELEASE, **PLATFORM}
SAMPLES = 9
SCORECARD_RUNS = 5
SCORECARD_PROTOCOLS = ["h1", "h2", "h3"]
SCORECARD_ARGS = ["-j", "--samples", "1", "-d", "-u", "-r", "--httpd"]
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
THREADED = Config("threaded", {**baseline.THREADED.cmake_args, **RELEASE,
                               **PLATFORM},
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
        """
        The environment the leg's programs run with.

        Not on macOS, where perf's rpath alone finds the leg's library: with
        DYLD_LIBRARY_PATH set, the loader takes some 40 ms more to start
        each program (measured 2026-11-05 on an M1 Max: `curl
        file:///etc/hosts` 16 ms without, 54 ms with), which the
        scorecard's single transfers would count as the leg's.
        """
        if self.side == "c" or MACOS:
            return dict(os.environ)
        return {**os.environ, LIBRARY_PATH: str(self.build / "lib")}


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
                   env={**os.environ, **dep_env, "PKG_CONFIG_PATH": ":".join(
                       p for p in (dep_env["PKG_CONFIG_PATH"],
                                   os.environ.get("PKG_CONFIG_PATH")) if p)})
    # CMake's own variable for the build's parallelism (cargo's is
    # CARGO_BUILD_JOBS), for a shared machine.
    jobs = os.environ.get("CMAKE_BUILD_PARALLEL_LEVEL")
    subprocess.run(nice(["ninja", "-C", str(build),
                         *([f"-j{jobs}"] if jobs else []), "all", "testdeps",
                         "perf"]), check=True, stdout=subprocess.DEVNULL)
    for binary in [next(build.glob(C_LIBRARY)),
                   build / "src/curl", build / "tests/perf/perf"]:
        deps.check_linked(binary)


def cargo(leg, *args):
    features = ["--features", ",".join(leg.config.features)] \
        if leg.config.features else []
    return nice(["cargo", *args, "--release", "--target-dir",
                 str(leg.target), *features])


def cargo_env():
    """
    The environment cargo builds a Rust leg in: curl-ngtcp2 links the
    ngtcp2 the C leg links, the one deps.py names, whatever a caller's
    CURL_NGTCP2_DIR or the build script's default would pick.
    """
    return {**os.environ, "CURL_NGTCP2_DIR": str(deps.NGTCP2)}


def check_ngtcp2_link(messages):
    """
    Fail unless cargo's JSON `messages` show curl-ngtcp2's build script
    linking ngtcp2 from deps.NGTCP2, as the C leg does.
    """
    want = f"native={deps.NGTCP2 / 'lib'}"
    paths = [m.get("linked_paths", []) for m in map(json.loads, messages)
             if m.get("reason") == "build-script-executed"
             and "curl-ngtcp2" in m.get("package_id", "")]
    check(paths and all(want in p for p in paths),
          f"curl-ngtcp2 links from {paths}, not {want}")


def check_one_engine(library):
    """
    Fail unless `library` carries the engine once, for the shim's host
    alone: an engine for `NoHost` too doubles the code a release ships.
    The shim's own instantiation is the positive control.
    """
    names = subprocess.run(["nm", "-C", str(library)], check=True,
                           capture_output=True, text=True).stdout
    check("CHost" in names, f"{library}: no engine for the shim's CHost")
    check("curl_core::multi::NoHost" not in names,
          f"{library} carries an engine for NoHost beside CHost's")


def check_hot_order(binary, order):
    """
    Fail unless `binary` starts its `.text` with the hot functions `order`
    lists, in its order (hot_order.check, whose positive control is that
    most of the list is in the binary at all). Linux only: on macOS the
    link lays out none.
    """
    if MACOS:
        return
    try:
        hot_order.check(order, binary)
    except AssertionError as e:
        check(False, f"hot-function order: {e}")


def port_binaries(leg):
    """Build each PORTS test binary; return their paths by program."""
    out = {}
    for name, (crate, target, _test) in PORTS.items():
        r = subprocess.run(
            cargo(leg, "test", "--no-run", "-p", crate, *target,
                  "--message-format=json"),
            cwd=ROOT, check=True, capture_output=True, text=True,
            env=cargo_env())
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
    r = subprocess.run(cargo(leg, "build", "-p", "curl-sys-abi", "-p",
                             "curl-tool",
                             "--message-format=json-render-diagnostics"),
                       cwd=ROOT, check=True, stdout=subprocess.PIPE,
                       text=True, env=cargo_env())
    check_ngtcp2_link(r.stdout.splitlines())
    out = leg.target / "release"
    c_build = leg.c_build
    if leg.build.exists():
        shutil.rmtree(leg.build)
    # tests/perf is left out whole and rebuilt with a copy of its program:
    # a link to C's directory would put the copy in C's tree.
    skip = {"perf", "src/curl", "src/curlinfo", "tests/perf", "tests/log",
            "tests/.cache"}
    score.overlay(c_build, c_build, leg.build, skip)
    library = leg.build / "lib" / SONAME
    if MACOS:
        shutil.copy2(out / "libcurl.dylib", library)
        # Named as C's is, so that what links C's finds it.
        subprocess.run(["install_name_tool", "-id", f"@rpath/{SONAME}",
                        str(library)], check=True)
        codesign(library)
    else:
        shutil.copy2(out / "libcurl.so", library)
    check_one_engine(library)
    check_hot_order(library, ROOT / "crates/curl-sys-abi/hot.order")
    check_hot_order(out / "curl", ROOT / "crates/curl-tool/hot.order")
    for name in ("curl", "curlinfo"):
        shutil.copy2(out / name, leg.build / "src" / name)
    perf = leg.build / "tests/perf/perf"
    perf.parent.mkdir()
    shutil.copy2(c_build / "tests/perf/perf", perf)
    # Without the environment too, it loads the leg's library.
    if MACOS:
        subprocess.run(["install_name_tool", "-rpath", str(c_build / "lib"),
                        "@loader_path/../../lib", str(perf)], check=True)
        codesign(perf)
    else:
        score.own_runpath(perf, c_build / "lib", "$ORIGIN/../../lib")
    if leg.config.perf:
        ports = port_binaries(leg)
        (leg.build / "ports.json").write_text(json.dumps(ports, indent=1))


def codesign(binary):
    """Sign `binary` ad hoc again: macOS kills one whose code was edited."""
    subprocess.run(["codesign", "-f", "-s", "-", str(binary)], check=True,
                   capture_output=True)


def loaded_libcurl(binary, env):
    """The libcurl `binary` loads under `env`, as the loader reports it."""
    if MACOS:
        # The loader itself lists what it loads; perf without arguments
        # loads everything and exits.
        r = subprocess.run([str(binary)], env={**env,
                                               "DYLD_PRINT_LIBRARIES": "1"},
                           check=False, capture_output=True, text=True)
        found = re.findall(r"^dyld\[\d+\]: (?:<[-0-9A-F]+> )?"
                           r"(\S*/libcurl[^/]*\.dylib)$",
                           r.stderr, re.MULTILINE)
        # The system's own, which a system framework loads beside
        # ours: two-level namespaces keep the two apart.
        found = [f for f in found if not f.startswith("/usr/lib/")]
        check(len(found) == 1, f"{binary} loads libcurl {found}")
        return pathlib.Path(found[0]).resolve()
    ldd = subprocess.run(["ldd", str(binary)], env=env, check=True,
                         capture_output=True, text=True).stdout
    m = re.search(rf"^\s*{re.escape(SONAME)} => (\S+)", ldd, re.MULTILINE)
    return m and pathlib.Path(m.group(1)).resolve()


def loaded(binary, env, name):
    """The library `name` (its file name's start) `binary` loads."""
    if MACOS:
        return None
    ldd = subprocess.run(["ldd", str(binary)], env=env, check=True,
                         capture_output=True, text=True).stdout
    m = re.search(rf"^\s*{re.escape(name)}\S* => (\S+)", ldd, re.MULTILINE)
    return m and str(pathlib.Path(m.group(1)).resolve())


def check_quic(legs):
    """
    Fail unless every leg's library loads the same nghttp3, and the C
    legs' the ngtcp2 deps.py names: the Rust legs link that build's
    static archives (check_ngtcp2_link).
    """
    if MACOS:
        return
    found = set()
    for leg in legs:
        library = (next(leg.build.glob(C_LIBRARY)) if leg.side == "c"
                   else leg.build / "lib" / SONAME)
        found.add(loaded(library, leg.env(), "libnghttp3.so"))
        if leg.side == "c":
            deps.check_linked(library)
    check(len(found) == 1 and None not in found,
          f"the legs load nghttp3 from {found}")


def check_loading(leg):
    """Fail unless the leg's programs load the leg's own library."""
    want = (leg.build / "lib" / SONAME).resolve()
    if leg.side == "c":
        want = next(leg.build.glob(C_LIBRARY)).resolve()
    bare = {k: v for k, v in os.environ.items() if k != LIBRARY_PATH}
    for env in (leg.env(), bare):
        got = loaded_libcurl(leg.build / "tests/perf/perf", env)
        check(got == want,
              f"{leg.name}: tests/perf/perf loads {got}, not {want}")
    version = subprocess.run([str(leg.build / "src/curl"), "-V"],
                             capture_output=True, text=True, check=True,
                             env=leg.env()).stdout
    resolver = "c-ares/" in version.splitlines()[0]
    check(resolver == (leg.config is REFERENCE),
          f"{leg.name}: curl -V says {version.splitlines()[0]!r}")


def loadavg():
    return " ".join(f"{v:.2f}" for v in os.getloadavg())


def machine():
    if MACOS:
        def sysctl(name):
            return subprocess.run(["sysctl", "-n", name], check=True,
                                  capture_output=True,
                                  text=True).stdout.strip()
        return {"system": f"macOS {platform.mac_ver()[0]}",
                "kernel": f"Darwin {platform.release()}",
                "machine": platform.machine(), "cpus": os.cpu_count(),
                "model": sysctl("hw.model"),
                "cpu": sysctl("machdep.cpu.brand_string"),
                "virtualization": None,
                "memory": f"{int(sysctl('hw.memsize')) // 2**30} GiB",
                "loadavg-before": loadavg()}
    virt = subprocess.run(["systemd-detect-virt"], capture_output=True,
                          text=True, check=False).stdout.strip()
    return {"kernel": platform.release(), "machine": platform.machine(),
            "cpus": os.cpu_count(),
            "virtualization": None if virt in ("", "none") else virt,
            "memory": pathlib.Path("/proc/meminfo").read_text()
            .splitlines()[0],
            "loadavg-before": loadavg()}


def fastest_cpus():
    """On a processor whose cores differ in speed (a hybrid one, as
    banana's Zen 5 and Zen 5c), the CPUs of the fastest kind, or None
    when all are alike. A run left to the scheduler times each sample on
    whichever kind it lands on, and its spread swamps the legs'
    difference."""
    if MACOS:
        return None
    speeds = {}
    for cpu in os.sched_getaffinity(0):
        f = pathlib.Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/"
                         "cpuinfo_max_freq")
        if f.exists():
            speeds[cpu] = int(f.read_text())
    if len(set(speeds.values())) < 2:
        return None
    top = max(speeds.values())
    return sorted(cpu for cpu, speed in speeds.items() if speed == top)


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
    suite.venv()
    path = f"{suite.VENV / 'bin'}:{os.environ.get('PATH', '')}"
    for proto in SCORECARD_PROTOCOLS:
        runs = {leg.name: [] for leg in legs}
        for i in range(SCORECARD_RUNS):
            for leg in legs:
                load = loadavg()
                r = subprocess.run(
                    [str(suite.VENV / "bin/python3"),
                     str(ROOT / "tests/http/scorecard.py"), *SCORECARD_ARGS,
                     *leg.config.scorecard_args, proto],
                    cwd=leg.build / "tests", env={**leg.env(), "PATH": path},
                    capture_output=True, text=True, check=False)
                (leg.results / f"scorecard-{proto}-{i}.err").write_text(
                    r.stderr)
                check(r.returncode == 0, f"{leg.name} scorecard {proto} run "
                      f"{i} failed: {r.stderr[-500:]}")
                runs[leg.name].append({**json.loads(r.stdout),
                                       "loadavg-before": load})
        for leg in legs:
            (leg.results / f"scorecard-{proto}.json").write_text(
                json.dumps(runs[leg.name]))


def quic():
    """The HTTP/3 libraries both legs link, as deps.py describes them,
    with the nghttp3 the C leg loads."""
    described = deps.describe()
    leg = LEGS[0]
    described["nghttp3-loaded"] = loaded(next(leg.build.glob(C_LIBRARY)),
                                         leg.env(), "libnghttp3.so")
    return described


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
    check_quic(LEGS)


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
    # The clients, the servers and the benchmarks all inherit this.
    fast = fastest_cpus()
    if fast:
        os.sched_setaffinity(0, fast)
    meta = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "machine": machine(), "samples": SAMPLES,
            "scorecard-runs": SCORECARD_RUNS,
            "scorecard-args": SCORECARD_ARGS,
            "url-dataset": {k: str(v) for k, v in URL_DATASET.items()},
            "quic": quic(), "c-commit": commit, "commit": rust,
            "cpus-used": fast}
    measure_perf([leg for leg in LEGS if leg.config.perf],
                 sorted(tests["perf"]))
    measure_scorecard(LEGS)
    meta["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    meta["loadavg-after"] = loadavg()
    for leg in LEGS:
        (leg.results / "run.json").write_text(json.dumps(meta, indent=1) + "\n")


def spread(values):
    """
    Summarise samples by their median and interquartile range.

    The host occasionally takes a core for a whole run, giving one sample
    twice as slow; the IQR, unlike max - min, ignores such a sample.
    """
    med = statistics.median(values)
    q1, _, q3 = statistics.quantiles(values, n=4, method="inclusive") \
        if len(values) > 1 else (med, med, med)
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


def cell(got):
    """
    Summarise one scorecard cell's runs, leaving out the failed ones.

    A failed run is one the scorecard gave errors for: it reports -1, or
    a rate from the transfers that did not fail, neither of them a
    measurement.
    """
    errors = [g["errors"] for g in got if g.get("errors")]
    ok = [g["val"] for g in got if not g.get("errors")]
    return {**(spread(ok) if ok else {}), "failed": len(errors),
            "errors": errors}


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
                    got = [r[section]["rows"][i][j] for r in runs]
                    if all(isinstance(g["val"], (int, float)) for g in got):
                        cells[col] = cell(got)
                rows.append({"size": row[0]["sval"], "cells": cells})
            check(rows and all(r["cells"] for r in rows),
                  f"scorecard {proto} {section}: no numeric results")
            tables[section] = {"title": runs[0][section]["meta"]["title"],
                               "rows": rows}
        result[proto] = {"server": runs[0]["meta"]["server"],
                         "implementation": runs[0]["meta"].get(
                             "implementation"),
                         # One-minute load average before each run.
                         "loadavg": [float(r["loadavg-before"].split()[0])
                                     for r in runs if "loadavg-before" in r],
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


def cell_md(c, unit, runs):
    if "median" not in c:
        return f"failed in all {runs} runs"
    failed = c.get("failed", 0)
    return (f"{fmt(c['median'], unit)} (IQR {c['iqr-pct']:.0f}%"
            + (f", failed in {failed} of {runs} runs" if failed else "")
            + ")")


def scorecard_md(config, c, rust, runs):
    md = []
    for proto, sc in c.items():
        md.append(f"### {proto} ({runs} runs each, {sc['server']})\n")
        load = sc["loadavg"] + rust[proto]["loadavg"]
        if load:
            md.append(f"Load average before each run: {min(load):.2f} to "
                      f"{max(load):.2f}.\n")
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
                    rows.append((crow["size"], col, cell_md(cc, unit, runs),
                                 cell_md(rc, unit, runs),
                                 ratio(rc["median"], cc["median"])
                                 if "median" in cc and "median" in rc
                                 else "-"))
            md.extend([f"**{table['title']}** (Rust/C above 1 is faster)\n",
                       common.md_table(["size", "kind", "C", "Rust",
                                        "Rust/C"], rows)])
    return md


def quic_md(quic):
    """What the summary says of the HTTP/3 libraries the legs link."""
    if not quic:
        return ["The HTTP/3 libraries the legs linked were not recorded.\n"]
    ngtcp2 = quic["ngtcp2"]
    where = pathlib.Path(ngtcp2["dir"])
    if where.is_relative_to(ROOT):
        where = where.relative_to(ROOT)
    built = (f"ngtcp2 {ngtcp2['built']} (inventory/measure/deps.py: "
             f"`configure {' '.join(ngtcp2['configure'])}`)"
             if ngtcp2["built"] else "ngtcp2 of no recorded build")
    return [f"Both legs link one HTTP/3 build: {built} from `{where}`, the "
            "C legs its shared libraries and the Rust legs its static "
            f"archives; nghttp3 {quic['nghttp3']} "
            f"(`{quic.get('nghttp3-loaded')}`).\n"]


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
            "cpus-used": meta.get("cpus-used"),
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
            "quic": meta.get("quic"),
            "ports": {k: {"crate": v[0], "test": v[2]}
                      for k, v in PORTS.items()},
            "legs": legs}

    m = data["machine"]
    host = (f"{m['cpus']}-CPU {m['machine']} {m['model']} ({m['cpu']}, "
            f"{m['system']}, {m['kernel']})" if "system" in m else
            f"{m['cpus']}-CPU {m['machine']} "
            f"{m['virtualization'] or 'bare-metal'} machine (kernel "
            f"{m['kernel']})")
    if meta.get("cpus-used"):
        host += (", on its fastest CPUs alone ("
                 + ", ".join(map(str, meta["cpus-used"])) + ")")
    md = ["# Performance: the rewrite against C\n",
          ("Release builds, measured "
           f"{meta['started']} to {meta['finished']} on a {host}, "
           "the legs' samples interleaved; load average "
           f"{m['loadavg-before'].split()[0]} before and "
           f"{meta['loadavg-after'].split()[0]} after. The rewrite at "
           f"`{meta['commit'][:12]}`. Figures are medians; compare only "
           "builds measured on this machine, in one run of this script.\n"),
          "```", *(f"{name}: {legs[name]['curl-version'][0]}"
                   for name in legs), "```\n",
          *quic_md(meta.get("quic")),
          f"## tests/perf ({meta['samples']} runs each, reference "
          "configuration)\n",
          ("A program marked *port* times a C internal on the C leg and its "
           f"Rust counterpart (`ports` in {OUTPUT}.json) on the Rust leg; the "
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
                                    legs["rust"]["perf"].values())]),
          "## scorecard\n",
          ("A run the scorecard reports errors for is left out of its "
           "cell's median and counted as failed in it. A requests run fails "
           "when a response is not a 200 or the tool exits with an error; "
           "with `--parallel`, Rust's tool exits with a transfer's failure "
           "where C's can forget it (DIVERGENCE.md), so a run in which "
           "both legs lost transfers can fail on the Rust leg alone.\n")]
    for config in CONFIGS:
        suffix = "" if config is REFERENCE else f"-{config.name}"
        extra = (f", scorecard with `{' '.join(config.scorecard_args)}`"
                 if config.scorecard_args else "")
        md.append(f"## scorecard, {config.name} configuration{extra}\n")
        md.extend(scorecard_md(config.name, legs[f"c{suffix}"]["scorecard"],
                               legs[f"rust{suffix}"]["scorecard"],
                               meta["scorecard-runs"]))
    common.write(OUTPUT, data, "\n".join(md), [
        "tests/perf/", "tests/http/scorecard.py"],
        generated_by="inventory/measure/perf.py")


if __name__ == "__main__":
    main()
