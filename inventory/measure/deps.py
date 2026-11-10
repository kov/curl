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

AWS-LC and BoringSSL: the OpenSSL forks the rewrite's curl-openssl builds
over besides OpenSSL and LibreSSL, built only when asked for (`--awslc`,
`--boringssl`, or the oracle `baseline.py` builds with them). Each is built
at the version http3-linux.yml pins, as that CI builds it (CMake, shared
libraries, no tests), for the C build over it, which loads the shared
library; and again static and position-independent into the same prefix
for the rewrite's, which links it statically (`OPENSSL_STATIC`) so that its
programs need no search path to find it. ngtcp2's crypto for both is
`ngtcp2_crypto_boringssl`, of one name, so each fork has an ngtcp2 of its
own, `build/deps/ngtcp2-<fork>`, built with that crypto alone, as CI's
`ngtcp2-boringssl` is. AWS-LC's build needs Go.

quiche: built only when asked for (`--quiche`, or the oracle `baseline.py`
builds with it), at the version http3-linux.yml pins, as that CI builds it:
its git tree with `cargo build --package quiche --release --features
ffi,pkg-config-meta,qlog`, which builds the BoringSSL of the `boring-sys`
crate besides; then that BoringSSL's static libraries and headers staged
in `boringssl/` beside it, as CI stages them, for the OpenSSL backend of
both builds over quiche (C's CMake `OPENSSL_ROOT_DIR`, the rewrite's
`OPENSSL_DIR`). The C build loads quiche's shared library; the rewrite
builds the quiche crate itself, at the same version, over that BoringSSL.

rustls-ffi: not packaged on Fedora. The release curl's CI pins, as its
`rustls` jobs in .github/workflows/linux.yml install it: the project's
prebuilt library for the machine, its pkg-config file pointed at where it
is unpacked, for the C build with Rustls (`baseline.py --rustls`). The
rewrite's curl-rustls uses the rustls crate itself, at the version this
release is built with.

The ECH test servers: tests/http's Encrypted Client Hello cases need an
`openssl` command that makes ECH configurations (OpenSSL 4) and an nghttpx
that serves them (nghttp2 1.70 over that OpenSSL), which Fedora's are not.
Both are built at the versions http3-linux.yml pins, into build/deps/ech,
OpenSSL's libraries found through its run path, for the oracles built with
ECH and the rewrite's legs against them (`--ech`, or the oracle
`baseline.py` builds with it). They are servers and tools only: no curl
links them.

h2o: not packaged on Fedora. The HTTP/3 proxy the tests/http cases of
test_60_h3_proxy.py tunnel through, built at the commit http3-linux.yml
pins, from the archive whose checksum it pins, as that CI builds it
(`WITHOUT_LIBS`, the server alone), over the system OpenSSL: CI builds it
over the OpenSSL 3.5 release it calls `OPENSSL_PREV`, which is the
system's here. For every oracle's pytest run (`H2O` in baseline.py's
CMAKE_ARGS) and the rewrite's legs over them.

Everything goes under build/deps and is rebuilt only when a pinned version
or the way it is built changes. Run directly, or through `baseline.py --run`.
Builds run `DEPS_JOBS` jobs at once, the machine's processors by default.
"""

import hashlib
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
JOBS = os.environ.get("DEPS_JOBS", str(os.cpu_count()))
# CURL_WOLFSSL_DIR likewise, for wolfSSL and curl-wolfssl's build.
OWN_WOLFSSL = "CURL_WOLFSSL_DIR" not in os.environ
WOLFSSL = DEPS / "wolfssl" if OWN_WOLFSSL else pathlib.Path(
    os.environ["CURL_WOLFSSL_DIR"])
# CURL_GNUGSS_DIR likewise, for GNU GSS and curl-gssapi's `gnu-gss` build.
OWN_GNUGSS = "CURL_GNUGSS_DIR" not in os.environ
GNUGSS = DEPS / "gnugss" if OWN_GNUGSS else pathlib.Path(
    os.environ["CURL_GNUGSS_DIR"])
RUSTLS = DEPS / "rustls-ffi"


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
    m = re.search(rf"^  {name}: (\S+)(?:\s+#.*)?$", common.read(workflow),
                  re.MULTILINE)
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
        sh(["make", f"-j{JOBS}", "install"], cwd=src)
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


def build_rustls():
    """
    Unpack rustls-ffi if it is missing; return the environment CMake needs
    to find it.
    """
    version = pinned("RUSTLS_VERSION", ".github/workflows/linux.yml")
    arch = {"x86_64": "x86_64", "aarch64": "arm64"}[os.uname().machine]
    built = f"{version} {arch}-linux-gnu"
    stamp = RUSTLS / ".version"
    if not (stamp.exists() and stamp.read_text().strip() == built):
        RUSTLS.mkdir(parents=True, exist_ok=True)
        archive = RUSTLS / "rustls-ffi.zip"
        sh(["curl", "--fail", "--silent", "--show-error", "--location",
            "--output", str(archive),
            f"https://github.com/rustls/rustls-ffi/releases/download/"
            f"v{version}/rustls-ffi-{arch}-linux-gnu.zip"], cwd=RUSTLS)
        sh(["unzip", "-o", "-q", str(archive)], cwd=RUSTLS)
        archive.unlink()
        pc = RUSTLS / "lib" / "pkgconfig" / "rustls.pc"
        pc.write_text(pc.read_text().replace("prefix=dist",
                                             f"prefix={RUSTLS}"))
        stamp.write_text(built + "\n")
    pc = subprocess.run(["pkg-config", "--modversion", "rustls"],
                        env={**os.environ,
                             "PKG_CONFIG_PATH": f"{RUSTLS}/lib/pkgconfig"},
                        check=True, capture_output=True, text=True)
    check(pc.stdout.strip() == version,
          f"pkg-config finds rustls-ffi {pc.stdout.strip()}, want {version}")
    return {"PKG_CONFIG_PATH": f"{RUSTLS}/lib/pkgconfig"}


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
        sh(["make", f"-j{JOBS}", "install"], cwd=src)
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


# The OpenSSL forks built on request: the variable http3-linux.yml pins
# each one's version in, the tarball's URL and directory, and the CMake
# flags of CI's build of it.
FORKS = {
    "awslc": ("AWSLC_VERSION",
              "https://github.com/awslabs/aws-lc/archive/refs/tags/v{v}.tar.gz",
              "aws-lc-{v}", ["-DBUILD_TESTING=OFF", "-DBUILD_TOOL=OFF"]),
    "boringssl": ("BORINGSSL_VERSION",
                  "https://github.com/google/boringssl/releases/download/{v}/boringssl-{v}.tar.gz",
                  "boringssl-{v}", ["-DBUILD_TESTING=OFF"]),
}


def fork_dir(fork):
    """Where the OpenSSL fork `fork` is installed."""
    return DEPS / fork


def fork_ngtcp2_dir(fork):
    """Where the ngtcp2 with crypto for `fork` is installed."""
    return DEPS / f"ngtcp2-{fork}"


def build_fork(fork):
    """
    Build the OpenSSL fork `fork` and an ngtcp2 with crypto for it if
    missing; return the environment CMake needs to find that ngtcp2.
    """
    var, url, tree, flags = FORKS[fork]
    version = pinned(var)
    prefix = fork_dir(fork)
    built = f"{version} shared+static-pic"
    stamp = prefix / ".version"
    if not (stamp.exists() and stamp.read_text().strip() == built):
        src = DEPS / "src" / tree.format(v=version)
        if not src.exists():
            src.parent.mkdir(parents=True, exist_ok=True)
            tarball = src.parent / f"{fork}-{version}.tar.gz"
            sh(["curl", "--fail", "--silent", "--show-error", "--location",
                "--output", str(tarball), url.format(v=version)],
               cwd=src.parent)
            sh(["tar", "-xzf", str(tarball)], cwd=src.parent)
            tarball.unlink()
        # CI's shared build, then the static one beside it.
        for kind, extra in [("shared", ["-DBUILD_SHARED_LIBS=ON"]),
                            ("static", ["-DBUILD_SHARED_LIBS=OFF",
                                        "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"])]:
            out = src / f"build-{kind}"
            sh(["cmake", "-S", str(src), "-B", str(out), "-G", "Ninja",
                "-DCMAKE_BUILD_TYPE=Release",
                f"-DCMAKE_INSTALL_PREFIX={prefix}",
                "-DCMAKE_INSTALL_LIBDIR=lib", *flags, *extra], cwd=src)
            sh(["cmake", "--build", str(out), "-j", JOBS], cwd=src)
            sh(["cmake", "--install", str(out)], cwd=src)
        stamp.write_text(built + "\n")
    for lib in ["libssl.so", "libcrypto.so", "libssl.a", "libcrypto.a"]:
        check((prefix / "lib" / lib).exists(),
              f"{prefix / 'lib' / lib} was not built")
    ngtcp2 = fork_ngtcp2_dir(fork)
    ngtcp2_version = pinned("NGTCP2_VERSION")
    ngtcp2_built = f"{ngtcp2_version} fpic {fork}-{version}"
    stamp = ngtcp2 / ".version"
    if not (stamp.exists() and stamp.read_text().strip() == ngtcp2_built):
        src = DEPS / "src" / f"ngtcp2-{ngtcp2_version}"
        if not src.exists():
            src.parent.mkdir(parents=True, exist_ok=True)
            sh(["git", "clone", "--quiet", "--depth", "1", "--branch",
                f"v{ngtcp2_version}", "https://github.com/ngtcp2/ngtcp2",
                str(src)], cwd=src.parent)
        sh(["autoreconf", "-fi"], cwd=src)
        # As CI's `ngtcp2-boringssl`: that crypto, and no other.
        sh(["./configure", f"--prefix={ngtcp2}",
            "--disable-dependency-tracking", "--enable-lib-only",
            "--with-openssl=no", "--with-boringssl", "--with-pic",
            # The crypto library is an archive libtool does not build, which
            # `--with-pic` leaves as it is: the shared libcurl links it in.
            "CFLAGS=-g -O2 -fPIC", "CXXFLAGS=-g -O2 -fPIC",
            f"BORINGSSL_LIBS=-L{prefix / 'lib'} -lssl -lcrypto",
            f"BORINGSSL_CFLAGS=-I{prefix / 'include'}"], cwd=src)
        sh(["make", "clean"], cwd=src)
        sh(["make", f"-j{JOBS}", "install"], cwd=src)
        stamp.write_text(ngtcp2_built + "\n")
    lib = ngtcp2 / "lib" / "libngtcp2_crypto_boringssl.a"
    check(lib.exists(), f"{lib} was not built")
    return {"PKG_CONFIG_PATH": f"{ngtcp2}/lib/pkgconfig"}


H2O = DEPS / "h2o"


def h2o():
    """The h2o server the HTTP/3 proxy cases run."""
    return H2O / "bin" / "h2o"


def build_h2o():
    """Build h2o if it is missing; return the server."""
    version = pinned("H2O_VERSION")
    sha256 = pinned("H2O_SHA256")
    built = f"{version} without-libs"
    stamp = H2O / ".version"
    if not (stamp.exists() and stamp.read_text().strip() == built):
        src = DEPS / "src" / f"h2o-{version}"
        if src.exists():
            sh(["rm", "-rf", str(src)], cwd=DEPS)
        src.parent.mkdir(parents=True, exist_ok=True)
        tarball = src.parent / f"h2o-{version}.tar.gz"
        sh(["curl", "--fail", "--silent", "--show-error", "--location",
            "--output", str(tarball),
            f"https://github.com/h2o/h2o/archive/{version}.tar.gz"],
           cwd=src.parent)
        got = hashlib.sha256(tarball.read_bytes()).hexdigest()
        check(got == sha256, f"h2o's archive has sha256 {got}, want {sha256}")
        sh(["tar", "-xzf", str(tarball)], cwd=src.parent)
        tarball.unlink()
        # Its build names the git commit it finds itself in, which for an
        # archive unpacked here would be the curl tree's: git stops above
        # it.
        env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(src.parent)}
        for step in (["-S", str(src), "-B", str(src / "build"), "-G", "Ninja",
                      "-DWITHOUT_LIBS=ON", f"-DCMAKE_INSTALL_PREFIX={H2O}"],
                     ["--build", str(src / "build"), "-j", JOBS],
                     ["--install", str(src / "build")]):
            subprocess.run(["cmake", *step], cwd=src, env=env, check=True,
                           stdout=subprocess.DEVNULL)
        stamp.write_text(built + "\n")
    # The positive control: the server runs and says its version, as the
    # pytest harness asks of it before it uses one.
    said = subprocess.run([str(h2o()), "--version"], check=True,
                          capture_output=True, text=True).stdout
    check(re.search(r"^h2o version \S+", said, re.MULTILINE) is not None,
          f"{h2o()} says {said.strip()}")
    return h2o()


ECH = DEPS / "ech"


def ech_openssl():
    """The `openssl` command that makes the ECH test servers' keys."""
    return ECH / "bin" / "openssl"


def ech_nghttpx():
    """The nghttpx that serves ECH."""
    return ECH / "bin" / "nghttpx"


def build_ech_servers():
    """
    Build what C's ECH pytest cases (`test_23_ech.py`) need and the system
    lacks, if missing: an `openssl` command that makes ECH configurations
    (`openssl ech`, OpenSSL 4), and an nghttpx that serves them
    (`--ech-config-file`, nghttp2 over OpenSSL 4), with HTTP/3 over an
    ngtcp2 built for that OpenSSL, as http3-linux.yml builds its nghttpx,
    so the legs that run their pytest over it keep its h3 cases. OpenSSL
    is built with its command-line tool, which CI's build leaves out; the
    nghttp3 is the system's. All of it goes into one prefix, found by
    nghttpx's RUNPATH. Return the `openssl` command and nghttpx.
    """
    openssl = pinned("OPENSSL_VERSION")
    ngtcp2 = pinned("NGTCP2_VERSION")
    nghttp2 = pinned("NGHTTP2_VERSION")
    built = f"openssl-{openssl} ngtcp2-{ngtcp2} nghttp2-{nghttp2}"
    stamp = ECH / ".version"
    if not (stamp.exists() and stamp.read_text().strip() == built):
        src = DEPS / "src" / "ech"
        if src.exists():
            sh(["rm", "-rf", str(src)], cwd=DEPS)
        src.mkdir(parents=True)
        for repo, tag in (("openssl/openssl", f"openssl-{openssl}"),
                          ("ngtcp2/ngtcp2", f"v{ngtcp2}"),
                          ("nghttp2/nghttp2", f"v{nghttp2}")):
            sh(["git", "clone", "--quiet", "--depth", "1", "--branch", tag,
                f"https://github.com/{repo}", repo.split("/")[1]], cwd=src)
        sh(["./config", f"--prefix={ECH}", "--libdir=lib", "no-docs",
            "no-tests", f"-Wl,-rpath,{ECH}/lib"], cwd=src / "openssl")
        sh(["make", f"-j{JOBS}"], cwd=src / "openssl")
        sh(["make", "install_sw"], cwd=src / "openssl")
        env = {**os.environ, "PKG_CONFIG_PATH": f"{ECH}/lib/pkgconfig",
               "LDFLAGS": f"-Wl,-rpath,{ECH}/lib"}
        for name, flags in (
                ("ngtcp2", ["--enable-lib-only", "--with-openssl"]),
                ("nghttp2", ["--enable-app", "--enable-http3",
                             "--with-libbrotlienc", "--with-libbrotlidec"])):
            tree = src / name
            if name == "nghttp2":
                sh(["git", "submodule", "update", "--init", "--depth", "1"],
                   cwd=tree)
            sh(["autoreconf", "-fi"], cwd=tree)
            subprocess.run(["./configure", "--disable-dependency-tracking",
                            f"--prefix={ECH}", *flags], cwd=tree, check=True,
                           stdout=subprocess.DEVNULL, env=env)
            sh(["make", f"-j{JOBS}", "install"], cwd=tree)
        stamp.write_text(built + "\n")
    # The positive controls: the command is OpenSSL 4's, and the server
    # takes ECH configurations and speaks HTTP/3, as the pytest harness
    # asks of them.
    version = subprocess.run([str(ech_openssl()), "version"], check=True,
                             capture_output=True, text=True).stdout
    check(version.startswith(f"OpenSSL {openssl} "),
          f"{ech_openssl()} is {version.strip()}")
    usage = subprocess.run([str(ech_nghttpx()), "--help"], check=True,
                           capture_output=True, text=True).stdout
    check("--ech-config-file" in usage, f"{ech_nghttpx()} serves no ECH")
    said = subprocess.run([str(ech_nghttpx()), "--version"], check=True,
                          capture_output=True, text=True).stdout
    check(f"nghttp2/{nghttp2}" in said and "ngtcp2/" in said,
          f"{ech_nghttpx()} says {said.strip()}")
    return ech_openssl(), ech_nghttpx()


QUICHE = DEPS / "quiche"
# The `boring` crates quiche's build takes its BoringSSL from. The tag
# locks none, so CI's build takes the latest release; this is the latest
# at the C tree's commit (2026-10-20). The next, 5.4.0, has a BoringSSL
# that declares `ASN1_STRING_get_length`, which the C tree's
# lib/vtls/openssl.c defines for itself below OpenSSL 4.1, and so does not
# build.
BORING_SYS_VERSION = "5.3.0"


def build_quiche():
    """
    Build quiche and the BoringSSL its build makes if missing, staged as
    curl's CI stages them; return the environment CMake needs to find
    quiche.
    """
    version = pinned("QUICHE_VERSION")
    built = f"{version} ffi,pkg-config-meta,qlog boring-{BORING_SYS_VERSION}"
    release = QUICHE / "target" / "release"
    stamp = QUICHE / ".version"
    if not (stamp.exists() and stamp.read_text().strip() == built):
        if QUICHE.exists():
            sh(["rm", "-rf", str(QUICHE)], cwd=DEPS)
        DEPS.mkdir(parents=True, exist_ok=True)
        sh(["git", "clone", "--quiet", "--depth", "1", "--branch", version,
            "--recursive", "https://github.com/cloudflare/quiche",
            str(QUICHE)], cwd=DEPS)
        for crate in ["boring", "boring-sys"]:
            sh(["cargo", "update", "--quiet", "--package", crate,
                "--precise", BORING_SYS_VERSION], cwd=QUICHE)
        # Its own target directory, whatever the environment or the
        # tree's .cargo/config.toml, which cargo finds above it, says.
        sh(["cargo", "build", "--package", "quiche", "--release",
            "--features", "ffi,pkg-config-meta,qlog",
            "--target-dir", str(QUICHE / "target"), "-j", JOBS], cwd=QUICHE)
        (release / "libquiche.so.0").symlink_to("libquiche.so")
        # As CI: the static libraries in boringssl/lib, the headers
        # boring-sys built against in boringssl/include.
        staged = QUICHE / "boringssl"
        (staged / "lib").mkdir(parents=True)
        for name in ["libcrypto.a", "libssl.a"]:
            found = sorted(release.rglob(name))
            check(len(found) == 1, f"quiche's build made {found} for {name}")
            os.link(found[0], staged / "lib" / name)
        include = sorted(release.glob(
            "build/boring-sys-*/out/boringssl/include"))
        check(len(include) == 1, f"quiche's build made {include} for include")
        (staged / "include").symlink_to(include[0])
        stamp.write_text(built + "\n")
    for path in [release / "libquiche.so", release / "quiche.pc",
                 QUICHE / "boringssl" / "lib" / "libssl.a",
                 QUICHE / "boringssl" / "lib" / "libcrypto.a",
                 QUICHE / "boringssl" / "include" / "openssl" / "ssl.h"]:
        check(path.exists(), f"{path} was not built")
    for crate in ["boring", "boring-sys"]:
        check(re.search(rf'^name = "{crate}"\nversion = "{BORING_SYS_VERSION}"$',
                        (QUICHE / "Cargo.lock").read_text(), re.MULTILINE)
              is not None, f"quiche's build took another {crate}")
    return {"PKG_CONFIG_PATH": str(release)}


def quiche_boringssl():
    """Where the BoringSSL quiche's build made is staged."""
    return QUICHE / "boringssl"


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


def check_linked(binary, crypto=None, ngtcp2=NGTCP2):
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
        lib = f"{ngtcp2}/lib/lib{name}.{'' if macos else 'so'}"
        check(lib in libs, f"{binary} does not load {lib}")


if __name__ == "__main__":
    print(build())
    print(build_wolfssl())
    if "--gnugss" in sys.argv[1:]:
        print(build_gnugss())
    for fork in FORKS:
        if f"--{fork}" in sys.argv[1:]:
            print(build_fork(fork))
    if "--h2o" in sys.argv[1:]:
        print(build_h2o())
    if "--ech" in sys.argv[1:]:
        print(build_ech_servers())
    if "--quiche" in sys.argv[1:]:
        print(build_quiche())
