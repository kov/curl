#!/usr/bin/env python3
"""
Build the libraries the reference build needs newer than the distribution's.

ngtcp2: HTTP/3 0-RTT early data is rejected with the distribution's ngtcp2
1.22.1 and accepted with 1.25.0, both on the system OpenSSL 3.5, so the
HTTP/3 early-data tests in tests/http only exercise early data with the
newer one. ngtcp2 is built against the system OpenSSL at the version
curl's CI pins in .github/workflows/http3-linux.yml.

Its static archives are built position-independent, as the rewrite's
curl-ngtcp2 links them into its executables, which are.

wolfSSL: not packaged on Fedora. Built at the version curl's CI pins, as
its `wolfssl-all` job in .github/workflows/linux.yml configures it, for
the C build with wolfSSL (`baseline.py --wolfssl`), which loads its
shared library, and the rewrite's curl-wolfssl, which links its static
archive, built position-independent for the same reason as ngtcp2's.

Everything goes under build/deps and is rebuilt only when a pinned version
or the way it is built changes. Run directly, or through `baseline.py --run`.
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
# CURL_NGTCP2_DIR names an ngtcp2 built elsewhere, as for curl-ngtcp2's
# build: it is checked, not built.
OWN_NGTCP2 = "CURL_NGTCP2_DIR" not in os.environ
NGTCP2 = DEPS / "ngtcp2" if OWN_NGTCP2 else pathlib.Path(
    os.environ["CURL_NGTCP2_DIR"])
# CURL_WOLFSSL_DIR likewise, for wolfSSL and curl-wolfssl's build.
OWN_WOLFSSL = "CURL_WOLFSSL_DIR" not in os.environ
WOLFSSL = DEPS / "wolfssl" if OWN_WOLFSSL else pathlib.Path(
    os.environ["CURL_WOLFSSL_DIR"])


# How ngtcp2 is configured here, besides its prefix; a build's stamp names
# its version and this recipe (`pic`).
CONFIGURE = ["--disable-dependency-tracking", "--enable-lib-only",
             "--with-openssl", "--with-pic"]


# How wolfSSL is configured here: the CI job's flags, and both libraries,
# the static one position-independent (`pic`).
WOLFSSL_CONFIGURE = ["--disable-dependency-tracking", "--enable-tls13",
                     "--enable-harden", "--enable-all",
                     "--disable-benchmark", "--disable-crypttests",
                     "--disable-examples", "--enable-static",
                     "--with-pic"]


def pinned(name, workflow=WORKFLOW):
    """Return the version curl's CI pins for `name` in `workflow`."""
    m = re.search(rf"^  {name}: (\S+)$", common.read(workflow), re.MULTILINE)
    check(m is not None, f"{workflow} does not pin {name}")
    return m.group(1)


def sh(args, cwd):
    subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.DEVNULL)


def build_wolfssl():
    """
    Build wolfSSL if it is missing; return the environment CMake needs to
    find it.
    """
    version = pinned("WOLFSSL_VERSION", ".github/workflows/linux.yml")
    built = f"{version} pic"
    stamp = WOLFSSL / ".version"
    if OWN_WOLFSSL and not (stamp.exists()
                            and stamp.read_text().strip() == built):
        src = DEPS / "src" / f"wolfssl-{version}-stable"
        if not src.exists():
            src.parent.mkdir(parents=True, exist_ok=True)
            tarball = src.parent / f"wolfssl-{version}.tar.gz"
            sh(["curl", "--fail", "--silent", "--show-error", "--location",
                "--output", str(tarball),
                f"https://github.com/wolfSSL/wolfssl/archive/v{version}-stable.tar.gz"],
               cwd=src.parent)
            sh(["tar", "-xzf", str(tarball)], cwd=src.parent)
            tarball.unlink()
        sh(["./autogen.sh"], cwd=src)
        sh(["./configure", f"--prefix={WOLFSSL}", *WOLFSSL_CONFIGURE],
           cwd=src)
        sh(["make", "clean"], cwd=src)
        sh(["make", f"-j{os.cpu_count()}", "install"], cwd=src)
        stamp.write_text(built + "\n")
    pc = subprocess.run(["pkg-config", "--modversion", "wolfssl"],
                        env={**os.environ,
                             "PKG_CONFIG_PATH": f"{WOLFSSL}/lib/pkgconfig"},
                        check=True, capture_output=True, text=True)
    check(pc.stdout.strip() == version,
          f"pkg-config finds wolfSSL {pc.stdout.strip()}, want {version}")
    return {"PKG_CONFIG_PATH": f"{WOLFSSL}/lib/pkgconfig"}


def build():
    """Build what is missing; return the environment CMake needs."""
    version = pinned("NGTCP2_VERSION")
    built = f"{version} pic"
    stamp = NGTCP2 / ".version"
    if OWN_NGTCP2 and not (stamp.exists()
                           and stamp.read_text().strip() == built):
        src = DEPS / "src" / f"ngtcp2-{version}"
        if not src.exists():
            src.parent.mkdir(parents=True, exist_ok=True)
            sh(["git", "clone", "--quiet", "--depth", "1", "--branch",
                f"v{version}", "https://github.com/ngtcp2/ngtcp2", str(src)],
               cwd=src.parent)
        sh(["autoreconf", "-fi"], cwd=src)
        sh(["./configure", f"--prefix={NGTCP2}", *CONFIGURE], cwd=src)
        # Without dependency tracking, objects an earlier configure built
        # would be kept.
        sh(["make", "clean"], cwd=src)
        sh(["make", f"-j{os.cpu_count()}", "install"], cwd=src)
        stamp.write_text(built + "\n")
    pc = subprocess.run(["pkg-config", "--modversion", "libngtcp2"],
                        env={**os.environ,
                             "PKG_CONFIG_PATH": f"{NGTCP2}/lib/pkgconfig"},
                        check=True, capture_output=True, text=True)
    check(pc.stdout.strip() == version,
          f"pkg-config finds ngtcp2 {pc.stdout.strip()}, want {version}")
    return {"PKG_CONFIG_PATH": f"{NGTCP2}/lib/pkgconfig"}


def describe():
    """
    Which ngtcp2 and nghttp3 a build here links, for a measurement to
    name: ngtcp2's directory and the stamp its build left (version and
    recipe), and the nghttp3 pkg-config finds, the system's.
    """
    stamp = NGTCP2 / ".version"
    nghttp3 = subprocess.run(["pkg-config", "--modversion", "libnghttp3"],
                             check=True, capture_output=True, text=True)
    return {"ngtcp2": {"dir": str(NGTCP2),
                       "built": stamp.read_text().strip()
                       if stamp.exists() else None,
                       "configure": CONFIGURE},
            "nghttp3": nghttp3.stdout.strip()}


def check_linked(binary):
    """Fail unless `binary` loads the ngtcp2 built here."""
    macos = sys.platform == "darwin"
    libs = subprocess.run([*(["otool", "-L"] if macos else ["ldd"]),
                           str(binary)], check=True, capture_output=True,
                          text=True).stdout
    # libngtcp2.16.dylib on macOS, libngtcp2.so.16 on Linux.
    lib = f"{NGTCP2}/lib/libngtcp2.{'' if macos else 'so'}"
    check(lib in libs, f"{binary} does not load {lib}")


if __name__ == "__main__":
    print(build())
    print(build_wolfssl())
