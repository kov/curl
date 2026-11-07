#!/usr/bin/env python3
"""
Build the libraries the reference build needs newer than the distribution's.

ngtcp2: HTTP/3 0-RTT early data is rejected with the distribution's ngtcp2
1.22.1 and accepted with 1.25.0, both on the system OpenSSL 3.5, so the
HTTP/3 early-data tests in tests/http only exercise early data with the
newer one. ngtcp2 is built at the version curl's CI pins in
.github/workflows/http3-linux.yml, with the crypto libraries for each TLS
library a build here does HTTP/3 over, as that CI builds it: the system
OpenSSL's (LibreSSL's on macOS), and on Linux the system GnuTLS's and the
wolfSSL's built here.

Its static archives are built position-independent, as the rewrite's
curl-ngtcp2 links them into its executables, which are.

wolfSSL: not packaged on Fedora. Built at the version curl's CI pins, as
its `wolfssl-all` job in .github/workflows/linux.yml configures it, for
the C build with wolfSSL (`baseline.py --wolfssl`), which loads its
shared library, and the rewrite's curl-wolfssl, which links its static
archive, built position-independent for the same reason as ngtcp2's.

GNU GSS: not packaged on Fedora, nor Shishi, which gives it Kerberos.
Built at their latest releases, as curl's CI builds neither, for the C
build with GNU GSS (`baseline.py --gnugss`), which loads its shared
library, and the rewrite's curl-gssapi with `gnu-gss`, which links the
static archives, built position-independent. Only with `--gnugss` or
through that baseline.

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
# CURL_GNUGSS_DIR likewise, for GNU GSS and curl-gssapi's `gnu-gss` build.
OWN_GNUGSS = "CURL_GNUGSS_DIR" not in os.environ
GNUGSS = DEPS / "gnugss" if OWN_GNUGSS else pathlib.Path(
    os.environ["CURL_GNUGSS_DIR"])


# The TLS libraries besides OpenSSL (or LibreSSL, on macOS) ngtcp2's
# crypto is built for here, each a library `libngtcp2_crypto_<name>`: on
# Linux, where the GnuTLS and wolfSSL legs are measured, the system's
# GnuTLS and the wolfSSL built here.
CRYPTO = ["gnutls", "wolfssl"] if sys.platform.startswith("linux") else []
# How ngtcp2 is configured here, besides its prefix; a build's stamp names
# its version and this recipe (`pic`, and the other crypto libraries).
CONFIGURE = ["--disable-dependency-tracking", "--enable-lib-only",
             "--with-openssl", *(f"--with-{crypto}" for crypto in CRYPTO),
             "--with-pic"]


# How wolfSSL is configured here: the CI job's flags, and both libraries,
# the static one position-independent (`pic`).
WOLFSSL_CONFIGURE = ["--disable-dependency-tracking", "--enable-tls13",
                     "--enable-harden", "--enable-all",
                     "--disable-benchmark", "--disable-crypttests",
                     "--disable-examples", "--enable-static",
                     "--with-pic"]


# GNU GSS and Shishi, which gives it Kerberos: curl's CI builds neither,
# so their latest releases.
GNUGSS_VERSION = "1.0.4"
SHISHI_VERSION = "1.0.3"
GNUGSS_CONFIGURE = ["--disable-dependency-tracking", "--enable-static",
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


def build_gnugss():
    """
    Build GNU GSS over Shishi, its Kerberos, if missing; return the
    environment CMake needs to find it.
    """
    built = f"gss-{GNUGSS_VERSION} shishi-{SHISHI_VERSION} pic"
    stamp = GNUGSS / ".version"
    if OWN_GNUGSS and not (stamp.exists()
                           and stamp.read_text().strip() == built):
        # Shishi first, then GNU GSS finding it in the same prefix. Each
        # from a fresh tarball: a distclean drops the shipped manuals,
        # which would then need makeinfo.
        flags = [f"CPPFLAGS=-I{GNUGSS}/include",
                 f"LDFLAGS=-L{GNUGSS}/lib -Wl,-rpath,{GNUGSS}/lib"]
        for name, version, extra in (
                ("shishi", SHISHI_VERSION, ["--disable-pam",
                                            "--without-libidn"]),
                ("gss", GNUGSS_VERSION, [])):
            src = DEPS / "src" / f"{name}-{version}"
            src.parent.mkdir(parents=True, exist_ok=True)
            tarball = src.parent / f"{name}-{version}.tar.gz"
            if not tarball.exists():
                sh(["curl", "--fail", "--silent", "--show-error",
                    "--location", "--output", str(tarball),
                    f"https://ftp.gnu.org/gnu/{name}/{name}-{version}.tar.gz"],
                   cwd=src.parent)
            if src.exists():
                sh(["rm", "-rf", str(src)], cwd=src.parent)
            sh(["tar", "-xzf", str(tarball)], cwd=src.parent)
            sh(["./configure", f"--prefix={GNUGSS}", *GNUGSS_CONFIGURE,
                *extra, *flags], cwd=src)
            sh(["make", f"-j{os.cpu_count()}", "install"], cwd=src)
        stamp.write_text(built + "\n")
    # Without Shishi found, GNU GSS builds with no mechanism at all.
    check("shishi" in (GNUGSS / "lib" / "libgss.la").read_text(),
          f"{GNUGSS}/lib/libgss.a was built without Shishi")
    pc = subprocess.run(["pkg-config", "--modversion", "gss"],
                        env={**os.environ,
                             "PKG_CONFIG_PATH": f"{GNUGSS}/lib/pkgconfig"},
                        check=True, capture_output=True, text=True)
    check(pc.stdout.strip() == GNUGSS_VERSION,
          f"pkg-config finds GNU GSS {pc.stdout.strip()}, "
          f"want {GNUGSS_VERSION}")
    return {"PKG_CONFIG_PATH": f"{GNUGSS}/lib/pkgconfig"}


def build():
    """
    Build what is missing, wolfSSL first where ngtcp2's crypto for it is
    built against it; return the environment CMake needs to find ngtcp2.
    """
    wolfssl_env = build_wolfssl() if "wolfssl" in CRYPTO else {}
    version = pinned("NGTCP2_VERSION")
    built = f"{version} pic"
    if CRYPTO:
        wolfssl = pinned("WOLFSSL_VERSION", ".github/workflows/linux.yml")
        built += f" {'+'.join(CRYPTO)} wolfssl-{wolfssl}"
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
        subprocess.run(["./configure", f"--prefix={NGTCP2}", *CONFIGURE],
                       cwd=src, check=True, stdout=subprocess.DEVNULL,
                       env={**os.environ, **wolfssl_env})
        # Without dependency tracking, objects an earlier configure built
        # would be kept.
        sh(["make", "clean"], cwd=src)
        sh(["make", f"-j{os.cpu_count()}", "install"], cwd=src)
        stamp.write_text(built + "\n")
    # A crypto library configure found no TLS library for is skipped, not
    # failed: each must be there.
    for crypto in CRYPTO if OWN_NGTCP2 else []:
        lib = NGTCP2 / "lib" / f"libngtcp2_crypto_{crypto}.a"
        check(lib.exists(), f"{lib} was not built")
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


def check_linked(binary, crypto=None):
    """
    Fail unless `binary` loads the ngtcp2 built here, and if `crypto`
    names one, its crypto library for that TLS library (`ossl`, `gnutls`,
    `wolfssl`).
    """
    macos = sys.platform == "darwin"
    libs = subprocess.run([*(["otool", "-L"] if macos else ["ldd"]),
                           str(binary)], check=True, capture_output=True,
                          text=True).stdout
    # libngtcp2.16.dylib on macOS, libngtcp2.so.16 on Linux.
    for name in ["ngtcp2", *([f"ngtcp2_crypto_{crypto}"] if crypto else [])]:
        lib = f"{NGTCP2}/lib/lib{name}.{'' if macos else 'so'}"
        check(lib in libs, f"{binary} does not load {lib}")


if __name__ == "__main__":
    print(build())
    print(build_wolfssl())
    if "--gnugss" in sys.argv[1:]:
        print(build_gnugss())
