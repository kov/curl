#!/usr/bin/env python3
"""
Measure the libcurl C ABI for x86_64 Windows with MSVC.

As `abi_foreign.py` says, for x86_64-pc-windows-msvc: the declarations as
MSVC's preprocessor leaves them (`_WIN32` and `_MSC_VER` defined by the
compiler itself), the probe's numbers as `cl` computes them, into
`inventory/abi-x86_64-pc-windows-msvc.json`.

It runs on Windows, in a checkout at the C commit `abi.json` was made
from, under MSYS2's python3 inside a Visual Studio developer environment:

    cmd //c 'inventory\\measure\\abi_msvc.bat'
"""

import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import abi_foreign
from common import ROOT, check

TARGET = "x86_64-pc-windows-msvc"
MEASURED_BY = "inventory/measure/abi_msvc.bat on Windows"


def winpath(path):
    """`path` as cl reads it: MSYS2 passes POSIX paths unconverted here."""
    return subprocess.run(["cygpath", "-m", str(path)], check=True,
                          capture_output=True, text=True).stdout.strip()


# Options are spelled with `-`: MSYS2 rewrites arguments starting with `/`
# into paths before cl sees them.
CFLAGS = ["-nologo", "-std:c11", "-I", winpath(ROOT / "include"),
          "-DCURL_DISABLE_TYPECHECK"]


def cl(args, cwd):
    return subprocess.run(["cl", *CFLAGS, *args], check=False, cwd=cwd,
                          capture_output=True, text=True)


class Msvc:
    """cl, as abi.run_probe drives a compiler."""

    diagnostic = re.compile(r"probe\.c\((\d+)\): (?:fatal )?error\b")

    def build(self, src, scratch):
        # A pointer handed to the probe's integer printer is an error, as
        # gcc's -Werror=int-conversion makes it: C4047 (levels of
        # indirection) and C4024 (argument type). C4996 is a deprecation.
        r = cl(["-we4047", "-we4024", "-wd4996", "-Feprobe.exe", src.name],
               scratch)
        # cl prints its diagnostics on stdout.
        return r.returncode, r.stdout + r.stderr, scratch / "probe.exe"


def compiler_version():
    r = subprocess.run(["cl"], check=False, capture_output=True, text=True)
    m = re.search(r"Compiler Version (\S+) for (\S+)", r.stderr)
    check(m is not None, f"no cl version in {r.stderr!r}")
    check(m.group(2) == "x64", f"cl targets {m.group(2)}, not x64")
    return m.group(1)


def preprocess(scratch):
    """Return the public headers' preprocessed code, by header."""
    src = scratch / "pp.c"
    src.write_text("#include <curl/curl.h>\n")
    r = cl(["-E", src.name], scratch)
    check(r.returncode == 0, f"preprocessing failed: {r.stdout}{r.stderr}")
    include = winpath(ROOT / "include/curl").lower() + "/"
    code, cur = {}, None
    for line in r.stdout.splitlines():
        m = re.match(r'^#line \d+ "(.*)"', line)
        if m:
            p = m.group(1).replace("\\\\", "/").replace("\\", "/")
            cur = p[len(include):] if p.lower().startswith(include) else None
            continue
        if cur is None or line.startswith("#pragma"):
            continue
        # CURL_EXTERN: the linkage of a declaration, not its type.
        code.setdefault(cur, []).append(
            line.replace("__declspec(dllimport)", ""))
    return {h: "\n".join(v) for h, v in code.items()}


def controls(v, sizes, structs):
    """What makes this LLP64 x64 rather than the host's LP64."""
    check(structs["struct curl_slist"]["size"] == 16, "curl_slist on x64")
    check(sizes["curl_off_t"]["size"] == 8 and
          sizes["curl_socket_t"]["size"] == 8, "curl_off_t, SOCKET")
    check(next(f for f in structs["struct curl_fileinfo"]["fields"]
               if f["name"] == "hardlinks")["size"] == 4, "LLP64 long")


def main():
    abi_foreign.measure(TARGET, "x86_64 Windows (MSVC)", Msvc(),
                        f"cl {compiler_version()}", preprocess, MEASURED_BY,
                        "inventory/measure/abi_msvc.py", controls)


if __name__ == "__main__":
    main()
