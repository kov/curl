#!/usr/bin/env python3
"""
Build the libraries the reference build needs newer than the distribution's.

ngtcp2: HTTP/3 0-RTT early data is rejected with the distribution's ngtcp2
1.22.1 and accepted with 1.25.0, both on the system OpenSSL 3.5, so the
HTTP/3 early-data tests in tests/http only exercise early data with the
newer one. ngtcp2 is built against the system OpenSSL at the version
curl's CI pins in .github/workflows/http3-linux.yml.

Everything goes under build/deps and is rebuilt only when a pinned version
changes. Run directly, or through `baseline.py --run`.
"""

import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import common
from common import ROOT, check

DEPS = ROOT / "build" / "deps"
WORKFLOW = ".github/workflows/http3-linux.yml"
NGTCP2 = DEPS / "ngtcp2"


def pinned(name):
    """Return the version curl's HTTP/3 CI pins for `name`."""
    m = re.search(rf"^  {name}: (\S+)$", common.read(WORKFLOW), re.MULTILINE)
    check(m is not None, f"{WORKFLOW} does not pin {name}")
    return m.group(1)


def sh(args, cwd):
    subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.DEVNULL)


def build():
    """Build what is missing; return the environment CMake needs."""
    version = pinned("NGTCP2_VERSION")
    stamp = NGTCP2 / ".version"
    if not (stamp.exists() and stamp.read_text().strip() == version):
        src = DEPS / "src" / f"ngtcp2-{version}"
        if not src.exists():
            src.parent.mkdir(parents=True, exist_ok=True)
            sh(["git", "clone", "--quiet", "--depth", "1", "--branch",
                f"v{version}", "https://github.com/ngtcp2/ngtcp2", str(src)],
               cwd=src.parent)
        sh(["autoreconf", "-fi"], cwd=src)
        sh(["./configure", "--disable-dependency-tracking",
            f"--prefix={NGTCP2}", "--enable-lib-only", "--with-openssl"],
           cwd=src)
        sh(["make", f"-j{os.cpu_count()}", "install"], cwd=src)
        stamp.write_text(version + "\n")
    pc = subprocess.run(["pkg-config", "--modversion", "libngtcp2"],
                        env={**os.environ,
                             "PKG_CONFIG_PATH": f"{NGTCP2}/lib/pkgconfig"},
                        check=True, capture_output=True, text=True)
    check(pc.stdout.strip() == version,
          f"pkg-config finds ngtcp2 {pc.stdout.strip()}, want {version}")
    return {"PKG_CONFIG_PATH": f"{NGTCP2}/lib/pkgconfig"}


def check_linked(binary):
    """Fail unless `binary` loads the ngtcp2 built here."""
    libs = subprocess.run(["ldd", str(binary)], check=True,
                          capture_output=True, text=True).stdout
    check(f"{NGTCP2}/lib/libngtcp2.so" in libs,
          f"{binary} does not load {NGTCP2}/lib/libngtcp2.so")


if __name__ == "__main__":
    print(build())
