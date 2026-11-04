#!/usr/bin/env python3
"""
Measure the libcurl C ABI for aarch64 macOS with Apple clang.

As `abi_foreign.py` says, for aarch64-apple-darwin: the declarations as
clang's preprocessor leaves them on macOS (`__APPLE__` defined by the
compiler itself), the probe's numbers as clang computes them, into
`inventory/abi-aarch64-apple-darwin.json`.

It runs on an arm64 Mac, in a checkout at the C commit `abi.json` was made
from, with the Xcode command line tools' clang:

    python3 inventory/measure/abi_darwin.py
"""

import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import abi_foreign
from common import ROOT, check

TARGET = "aarch64-apple-darwin"
MEASURED_BY = "inventory/measure/abi_darwin.py on an arm64 Mac"
CFLAGS = ["-std=gnu17", "-I", str(ROOT / "include"),
          "-DCURL_DISABLE_TYPECHECK"]


def clang(args, cwd):
    return subprocess.run(["clang", *CFLAGS, *args], check=False, cwd=cwd,
                          capture_output=True, text=True)


class Clang:
    """Apple clang, as abi.run_probe drives a compiler."""

    diagnostic = re.compile(r"probe\.c:(\d+):\d+: (?:error|note)")

    def build(self, src, scratch):
        # As the host's gcc: a pointer handed to the probe's integer printer
        # is an error, a deprecation is not.
        r = clang(["-Werror=int-conversion", "-Wno-deprecated-declarations",
                   "-o", "probe", src.name], scratch)
        return r.returncode, r.stderr, scratch / "probe"


def compiler_version():
    r = subprocess.run(["clang", "--version"], check=True,
                       capture_output=True, text=True)
    m = re.search(r"^Apple clang version (\S+)", r.stdout, re.M)
    check(m is not None, f"not Apple clang: {r.stdout!r}")
    t = re.search(r"^Target: (\S+)", r.stdout, re.M)
    check(t is not None and t.group(1).startswith("arm64-apple-darwin"),
          f"clang targets {t and t.group(1)}, not arm64 macOS")
    return f"Apple clang {m.group(1)}"


def preprocess(scratch):
    """Return the public headers' preprocessed code, by header."""
    src = scratch / "pp.c"
    src.write_text("#include <curl/curl.h>\n")
    r = clang(["-E", src.name], scratch)
    check(r.returncode == 0, f"preprocessing failed: {r.stderr}")
    include = str(ROOT / "include/curl") + "/"
    code, cur = {}, None
    for line in r.stdout.splitlines():
        m = re.match(r'^# \d+ "([^"]*)"', line)
        if m:
            p = m.group(1)
            cur = p[len(include):] if p.startswith(include) else None
            continue
        if cur is None or line.startswith("#pragma"):
            continue
        code.setdefault(cur, []).append(line)
    return {h: "\n".join(v) for h, v in code.items()}


def controls(v, sizes, structs):
    """What makes this LP64 with an `int` socket, as the host is."""
    check(structs["struct curl_slist"]["size"] == 16, "curl_slist on arm64")
    check(sizes["curl_off_t"]["size"] == 8 and
          sizes["curl_socket_t"]["size"] == 4, "curl_off_t, socket")
    check(next(f for f in structs["struct curl_fileinfo"]["fields"]
               if f["name"] == "hardlinks")["size"] == 8, "LP64 long")


def main():
    abi_foreign.measure(TARGET, "aarch64 macOS (Apple clang)", Clang(),
                        compiler_version(), preprocess, MEASURED_BY,
                        "inventory/measure/abi_darwin.py", controls)


if __name__ == "__main__":
    main()
