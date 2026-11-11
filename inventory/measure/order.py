#!/usr/bin/env python3
"""
Write the hot-function lists the release link lays out first.

crates/curl-tool/hot.order names the tool's hot functions and
crates/curl-sys-abi/hot.order libcurl's, in the order the link lays them
out; `.cargo/link/cc` resolves them at the release link of each
(`.cargo/link/hot_order.py`). They are found by running the release build of this tree under callgrind on
the scorecard's kinds of traffic against the local httpd, and nghttpx in
front of it for HTTP/3, as tests/http/scorecard.py runs them:

- requests for a 10 KB file, 25 at a time, and downloads of a 1 MB file,
  10 at a time, each over HTTP/1.1, HTTP/2 and HTTP/3;
- the tool through Rust's own `curl`, and the library through C's `curl`
  (build/c-release) loading Rust's libcurl, which drives it through the C
  ABI as an application does.

Each kind runs twice, with few and with many transfers, and what grows
between the two is counted per unit of the kind: a request, or 16 KB of a
download. A function is hot on a protocol when one of its instructions runs
at least HOT times per unit of one of the protocol's kinds. The list holds
every hot function, grouped by the protocols it is hot on: those hot on all
three first, then those of two, then those of one, so that each protocol's
hot code is the shared group and its own, packed together. Within a group
the functions come by the share of their bytes that is hot (128-byte lines
holding a hot instruction), densest first, so that the hottest lines sit
together whatever the functions' cold remainder.

Run it on a release build of the tree as it is (`cargo build --release -p
curl-sys-abi -p curl-tool`, the lists in place, so that the link writes
what can be ordered beside each artefact: `<artefact>.hot-keys`), with the
C release tree built (`perf.py --build`), then rebuild and measure.
"""

import argparse
import collections
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
from common import ROOT, check  # noqa: E402

sys.path.insert(0, str(ROOT / ".cargo" / "link"))
import hot_order  # noqa: E402

LISTS = {"curl": ROOT / "crates/curl-tool/hot.order",
         "libcurl.so": ROOT / "crates/curl-sys-abi/hot.order"}
HOT = 0.9
PROTOCOLS = {"h1": "--http1.1", "h2": "--http2", "h3": "--http3-only"}
# (file served, its size, transfers at once, few, many, bytes per unit)
KINDS = {"requests": ("order10k.data", 10 * 1024, 25, 25, 525, None),
         "downloads": ("order1m.data", 1024 * 1024, 10, 2, 12, 16 * 1024)}
LINE = 128
CALLGRIND = ["valgrind", "--tool=callgrind", "--dump-instr=yes",
             "--dump-line=no", "--compress-strings=no", "--compress-pos=no",
             "--demangle=no"]


def serve(docs_sizes):
    """
    Run from a release tree's tests/ under tests/http's venv: start httpd
    and nghttpx, print where they listen, and keep them up until SIGTERM.
    """
    sys.path.insert(0, str(ROOT / "tests" / "http"))
    from testenv import Env, Httpd, NghttpxQuic
    env = Env()
    env.setup()
    httpd = Httpd(env=env)
    httpd.clear_logs()
    check(httpd.initial_start(), "httpd did not start")
    for name, size in docs_sizes.items():
        pathlib.Path(httpd.docs_dir, name).write_bytes(b"x" * size)
    nghttpx = NghttpxQuic(env=env)
    nghttpx.clear_logs()
    check(nghttpx.initial_start(), "nghttpx did not start")
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    print("READY", json.dumps({"host": env.domain1, "ca": env.ca.cert_file,
                      "h1": env.https_port, "h2": env.https_port,
                      "h3": env.h3_port, "docs": httpd.docs_dir}),
          flush=True)
    while not stop:
        time.sleep(0.5)
    nghttpx.stop(wait_dead=False)
    httpd.stop()


def command(client, servers, proto, kind, count):
    name, _size, parallel, *_ = KINDS[kind]
    host, port = servers["host"], servers[proto]
    return [*client, "--disable", "-s", "--path-as-is", "-w",
            "%{response_code},\\n", "--parallel", "--parallel-max",
            str(parallel), "--out-null", PROTOCOLS[proto], "--cacert",
            servers["ca"], "--resolve", f"{host}:{port}:127.0.0.1",
            f"https://{host}:{port}/{name}?[0-{count - 1}]"]


def parse(path, obj):
    """{(function, address): instructions} of `obj` in a callgrind file."""
    cost = collections.Counter()
    real = {}
    ob = fn = None
    skip = False
    with open(path, errors="replace") as f:
        for line in f:
            if skip:
                skip = False
            elif line.startswith("0x"):
                if ob == obj:
                    parts = line.split()
                    cost[(fn, int(parts[0], 16))] += int(parts[1])
            elif line.startswith("ob="):
                name = line[3:].rstrip("\n")
                ob = real.setdefault(name, os.path.realpath(name))
            elif line.startswith("fn="):
                fn = re.sub(r"'[0-9]+$", "", line[3:].rstrip("\n"))
            elif line.startswith("calls="):
                skip = True
    return cost


def profile(client, env, servers, proto, kind, obj, out):
    """{function: (share of the kind's instructions, hot lines)} of `obj`
    per unit of one kind of traffic."""
    _name, size, _parallel, few, many, unit = KINDS[kind]
    runs = []
    for count in (few, many):
        path = out / f"{obj.name}-{proto}-{kind}-{count}.callgrind"
        r = subprocess.run([*CALLGRIND, f"--callgrind-out-file={path}",
                            *command(client, servers, proto, kind, count)],
                           env=env, capture_output=True, text=True,
                           check=False)
        ok = r.stdout.count("200,")
        check(r.returncode == 0 and ok == count,
              f"{proto} {kind} x{count}: exit {r.returncode}, {ok} ok: "
              f"{r.stderr[-500:]}")
        runs.append(parse(path, str(obj)))
    units = (many - few) * (size // unit if unit else 1)
    grown = {key: (value - runs[0].get(key, 0)) / units
             for key, value in runs[1].items()}
    total = sum(grown.values())
    instructions = collections.Counter()
    lines = collections.defaultdict(set)
    for (fn, addr), g in grown.items():
        instructions[fn] += g
        if g >= HOT:
            lines[fn].add(addr // LINE)
    return {fn: (instructions[fn] / total, len(lines[fn])) for fn in lines}


def keys_file(artefact):
    """What the link of `artefact` could order (hot_order.py writes it
    beside the artefact cargo links into deps/)."""
    deps = artefact.parent / "deps"
    for f in deps.iterdir():
        if f.is_file() and not f.name.endswith((".d", ".hot-order",
                                                ".hot-keys")) \
                and f.samefile(artefact):
            path = pathlib.Path(f"{f}.hot-keys")
            check(path.exists(), f"no {path}: build with the lists in place")
            return set(path.read_text().splitlines())
    check(False, f"no link of {artefact} in {deps}")


def sizes(binary):
    """{mangled name: size} of `binary`'s functions."""
    out = {}
    table = subprocess.run(["nm", "-S", "--defined-only", str(binary)],
                           check=True, capture_output=True, text=True).stdout
    for line in table.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[2] in "tT":
            out[parts[3]] = int(parts[1], 16)
    return out


def rank(profiles, orderable, size):
    """The keys of the functions hot in any profile, in the list's order."""
    protocols = collections.defaultdict(set)
    share = collections.Counter()
    hot_lines = collections.Counter()
    for (proto, _kind), per_fn in profiles.items():
        for fn, (part, lines) in per_fn.items():
            protocols[fn].add(proto)
            share[fn] += part
            hot_lines[fn] = max(hot_lines[fn], lines)
    names = list(protocols)
    order = list(PROTOCOLS)
    rows = []
    for name, key in zip(names, hot_order.keys(names)):
        if key not in orderable:
            continue
        group = sorted(order.index(p) for p in protocols[name])
        bytes_ = max(size.get(name, LINE), 1)
        density = min(hot_lines[name] * LINE, bytes_) / bytes_
        rows.append(((-len(group), group, -density, -share[name]), key))
    keys = []
    for _, key in sorted(rows):
        if key not in keys:
            keys.append(key)
    return keys


def commit():
    return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short=10",
                           "HEAD"], check=True, capture_output=True,
                          text=True).stdout.strip()


def write(path, artefact, keys, profiles):
    kinds = ", ".join(sorted(f"{p} {k}" for p, k in profiles))
    header = [
        f"# The hot functions of the release {artefact}, in the order the link",
        "# lays them out (hot on more protocols first, densest first), by",
        "# demangled path without crate hashes: written by",
        "# inventory/measure/order.py, resolved at the link by",
        "# .cargo/link/hot_order.py.",
        f"# Trained at {commit()} on {os.uname().machine}: {kinds}.",
    ]
    path.write_text("\n".join(header + keys) + "\n")


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--target", type=pathlib.Path,
                   default=ROOT / "build/target-release/release",
                   help="the cargo release output holding curl and "
                   "libcurl.so")
    p.add_argument("--c-build", type=pathlib.Path,
                   default=ROOT / "build/c-release",
                   help="C's release build tree: its test servers' "
                   "configuration and its curl")
    p.add_argument("--venv", type=pathlib.Path,
                   default=ROOT / "build/c/pytest-venv",
                   help="the venv with tests/http's modules")
    p.add_argument("--keep", type=pathlib.Path,
                   help="keep the callgrind files here")
    p.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args()
    if args.serve:
        serve({name: size for name, size, *_ in KINDS.values()})
        return
    tool = (args.target / "curl").resolve()
    library = (args.target / "libcurl.so").resolve()
    orderable = {"curl": keys_file(args.target / "curl"),
                 "libcurl.so": keys_file(args.target / "libcurl.so")}
    out = args.keep or pathlib.Path(tempfile.mkdtemp(prefix="order-"))
    out.mkdir(parents=True, exist_ok=True)
    libdir = out / "lib"
    libdir.mkdir(exist_ok=True)
    (libdir / "libcurl.so.4").unlink(missing_ok=True)
    (libdir / "libcurl.so.4").symlink_to(library)
    clients = {
        "curl": ([str(tool)], dict(os.environ), tool),
        "libcurl.so": ([str(args.c_build / "src/curl")],
                       {**os.environ, "LD_LIBRARY_PATH": str(libdir)},
                       library),
    }
    ldd = subprocess.run(["ldd", clients["libcurl.so"][0][0]],
                         env=clients["libcurl.so"][1], check=True,
                         capture_output=True, text=True).stdout
    check(f"=> {libdir / 'libcurl.so.4'}" in ldd,
          f"C's curl does not load Rust's libcurl: {ldd}")
    server = subprocess.Popen(
        [str(args.venv / "bin/python3"), __file__, "--serve"],
        cwd=args.c_build / "tests", stdout=subprocess.PIPE, text=True)
    try:
        line = ""
        while not line.startswith("READY "):
            line = server.stdout.readline()
            check(line, "the servers did not start")
        servers = json.loads(line[len("READY "):])
        for artefact, (client, env, obj) in clients.items():
            profiles = {}
            for proto in PROTOCOLS:
                for kind in KINDS:
                    profiles[(proto, kind)] = profile(client, env, servers,
                                                      proto, kind, obj, out)
                    hot = len(profiles[(proto, kind)])
                    print(f"{artefact} {proto} {kind}: {hot} hot functions",
                          flush=True)
            keys = rank(profiles, orderable[artefact], sizes(obj))
            write(LISTS[artefact], artefact, keys, profiles)
            print(f"{LISTS[artefact].relative_to(ROOT)}: {len(keys)} functions")
    finally:
        server.send_signal(signal.SIGTERM)
        server.wait()
        if not args.keep:
            shutil.rmtree(out)


if __name__ == "__main__":
    main()
