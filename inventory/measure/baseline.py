#!/usr/bin/env python3
"""
Measure the C reference build against the C test suite.

`--run` configures and builds the C tree in build/c with CMAKE_ARGS, runs
tests/runtests.pl over every test, and keeps the raw results in
build/c/baseline/. Without `--run`, the stored results are parsed into
inventory/baseline.{json,md}.

`--threaded` does the same for the second oracle, the reference build with
the threaded resolver in place of c-ares (SCOPE.md): build/c-threaded,
inventory/baseline-threaded.{json,md}.

`--libssh` does the same for the third, the reference build with libssh in
place of libssh2, the SSH library the rewrite binds (SCOPE.md):
build/c-libssh, inventory/baseline-libssh.{json,md}.

`--gnutls` does the same for the reference build with GnuTLS in place of
OpenSSL, the TLS library the rewrite's `gnutls` feature binds, with
HTTP/3 over ngtcp2's GnuTLS crypto and without the HTTP/3 proxy, which C
builds over OpenSSL only: build/c-gnutls,
inventory/baseline-gnutls.{json,md}.

`--mbedtls` does the same with mbedTLS in place of OpenSSL, the library the
rewrite's `mbedtls` feature binds: without HTTP/3, which C has no mbedTLS
crypto for, and without HTTP message signatures, which C signs only with
OpenSSL, GnuTLS or wolfSSL: build/c-mbedtls,
inventory/baseline-mbedtls.{json,md}.

`--wolfssl` does the same with wolfSSL in place of OpenSSL, the library the
rewrite's `wolfssl` feature binds, built by inventory/measure/deps.py as
curl's CI builds it: with HTTP/3 over ngtcp2's wolfSSL crypto, without
the HTTP/3 proxy, and without Encrypted Client Hello, off in every oracle
here: build/c-wolfssl,
inventory/baseline-wolfssl.{json,md}.

`--gnugss` does the same with GNU GSS in place of MIT krb5, the library
the rewrite's `gnu-gss` feature binds, built by inventory/measure/deps.py
over Shishi: CMake's FindGSS takes MIT's pkg-config module first, so the
configure runs with a pkg-config that has every module of the system's
but MIT's, and the built curl must name `libgss/` and load no MIT
library: build/c-gnugss, inventory/baseline-gnugss.{json,md}.

`--awslc` and `--boringssl` do the same with AWS-LC and BoringSSL in place
of OpenSSL, the forks the rewrite's curl-openssl builds over as C's
OpenSSL backend does, each built by inventory/measure/deps.py as curl's
CI builds it, its shared library loaded: with HTTP/3 over ngtcp2's
BoringSSL crypto from the ngtcp2 built for that fork: build/c-awslc,
build/c-boringssl, inventory/baseline-{awslc,boringssl}.{json,md}.

`--rustls` does the same with Rustls in place of OpenSSL, the library the
rewrite's `rustls` feature binds, the release of rustls-ffi curl's CI
installs, unpacked by inventory/measure/deps.py: without HTTP/3, which C
does over Rustls with quiche alone, without HTTP message signatures,
which C does not sign with Rustls, and without Encrypted Client Hello:
build/c-rustls, inventory/baseline-rustls.{json,md}.

This is a measurement, not a derivation from source, so inventory/gen/all.py
does not run it: rerun it with `--run` when the C tree or the build
configuration changes.
"""

import json
import os
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import common
import deps
import suite
from common import ROOT, check

# Every backend and feature this machine can provide; see SCOPE.md.
CMAKE_ARGS = {
    "CMAKE_BUILD_TYPE": "Debug",
    "ENABLE_DEBUG": "ON",
    "BUILD_TESTING": "ON",
    "CURL_USE_OPENSSL": "ON",
    "USE_NGHTTP2": "ON",
    "USE_NGTCP2": "ON",
    "CURL_USE_LIBSSH2": "ON",
    "ENABLE_ARES": "ON",
    "CURL_BROTLI": "ON",
    "CURL_ZSTD": "ON",
    "USE_LIBIDN2": "ON",
    "CURL_USE_LIBPSL": "ON",
    "CURL_USE_GSSAPI": "ON",
    # Out of scope (SCOPE.md); explicit so an older cache cannot keep it on.
    "CURL_ENABLE_NTLM": "OFF",
    "USE_HTTPSRR": "ON",
    "USE_SSLS_EXPORT": "ON",
    "CURL_DISABLE_HTTPSIG": "OFF",
    "USE_PROXY_HTTP3": "ON",
    "USE_ECH": "OFF",
    # ngtcp2 from inventory/measure/deps.py, found through PKG_CONFIG_PATH.
    "CMAKE_BUILD_RPATH": str(deps.NGTCP2 / "lib"),
    # Test servers for the tests/http pytest suite, where CMake does not
    # look on Fedora: dante's daemon is sockd, sftp-server is under openssh.
    "DANTED": "/usr/bin/sockd",
    "SFTPD": "/usr/libexec/openssh/sftp-server",
}


@dataclass(frozen=True)
class Oracle:
    """A C build the rewrite is checked against, and where its results go."""
    build: pathlib.Path
    # The stem of its inventory/<stem>.{json,md}.
    inventory: str
    # What its inventory page is titled, and the flag that selects it.
    title: str
    flag: str
    cmake_args: dict
    # Its programs load the ngtcp2 built here (`deps.check_linked`), and
    # its crypto for the TLS library named.
    links_ngtcp2: bool = True
    crypto: str | None = None
    # It is built with the wolfSSL built here (`deps.build_wolfssl`).
    wolfssl: bool = False
    # It is built with the GNU GSS built here (`deps.build_gnugss`), MIT
    # krb5 hidden from its configure.
    gnu_gss: bool = False
    # It is built with this OpenSSL fork and the ngtcp2 for it, built here
    # (`deps.build_fork`).
    fork: str | None = None

    @property
    def ngtcp2(self):
        """The ngtcp2 its programs load."""
        return deps.fork_ngtcp2_dir(self.fork) if self.fork else deps.NGTCP2
    # It is built with the rustls-ffi unpacked here (`deps.build_rustls`).
    rustls: bool = False

    @property
    def results(self):
        return self.build / "baseline"

    @property
    def test_programs(self):
        """Test programs that link libcurl and ngtcp2 themselves."""
        return [self.build / "tests/libtest/libtests",
                self.build / "tests/unit/units",
                self.build / "tests/tunit/tunits"]


REFERENCE = Oracle(ROOT / "build" / "c", "baseline", "C reference baseline",
                   "", CMAKE_ARGS)
# The resolver distributions build libcurl with, in place of c-ares.
THREADED = Oracle(ROOT / "build" / "c-threaded", "baseline-threaded",
                  "C threaded-resolver baseline", "--threaded",
                  {**CMAKE_ARGS, "ENABLE_ARES": "OFF",
                   "ENABLE_THREADED_RESOLVER": "ON"})
# The SSH library distributions build libcurl with, in place of libssh2.
LIBSSH = Oracle(ROOT / "build" / "c-libssh", "baseline-libssh",
                "C libssh baseline", "--libssh",
                {**CMAKE_ARGS, "CURL_USE_LIBSSH2": "OFF",
                 "CURL_USE_LIBSSH": "ON"})
# GnuTLS in place of OpenSSL, as the rewrite's `gnutls` feature has it:
# HTTP/3 over ngtcp2's GnuTLS crypto, and no HTTP/3 proxy, which CMake
# builds over OpenSSL only.
GNUTLS = Oracle(ROOT / "build" / "c-gnutls", "baseline-gnutls",
                "C GnuTLS baseline", "--gnutls",
                {**CMAKE_ARGS, "CURL_USE_OPENSSL": "OFF",
                 "CURL_USE_GNUTLS": "ON", "USE_PROXY_HTTP3": "OFF"},
                crypto="gnutls")
# mbedTLS in place of OpenSSL, as the rewrite's `mbedtls` feature has it:
# no QUIC (ngtcp2 has no mbedTLS crypto), and no Ed25519 to sign HTTP
# messages with (CMake turns HTTPSIG off without it).
MBEDTLS = Oracle(ROOT / "build" / "c-mbedtls", "baseline-mbedtls",
                 "C mbedTLS baseline", "--mbedtls",
                 {**CMAKE_ARGS, "CURL_USE_OPENSSL": "OFF",
                  "CURL_USE_MBEDTLS": "ON", "USE_NGTCP2": "OFF",
                  "USE_PROXY_HTTP3": "OFF", "CURL_DISABLE_HTTPSIG": "ON"},
                 links_ngtcp2=False)
# wolfSSL in place of OpenSSL, as the rewrite's `wolfssl` feature has it:
# HTTP/3 over ngtcp2's wolfSSL crypto, no HTTP/3 proxy (OpenSSL's only),
# and Ed25519 for HTTP message signatures from wolfCrypt. Its programs
# find the library by their RUNPATH, beside ngtcp2's.
WOLFSSL = Oracle(ROOT / "build" / "c-wolfssl", "baseline-wolfssl",
                 "C wolfSSL baseline", "--wolfssl",
                 {**CMAKE_ARGS, "CURL_USE_OPENSSL": "OFF",
                  "CURL_USE_WOLFSSL": "ON", "USE_PROXY_HTTP3": "OFF",
                  "CMAKE_BUILD_RPATH":
                  f"{deps.NGTCP2 / 'lib'};{deps.WOLFSSL / 'lib'}"},
                 wolfssl=True, crypto="wolfssl")
# GNU GSS in place of MIT krb5, as the rewrite's `gnu-gss` feature has it,
# otherwise the reference build. Its programs find the library by their
# RUNPATH, beside ngtcp2's.
GNUGSS = Oracle(ROOT / "build" / "c-gnugss", "baseline-gnugss",
                "C GNU GSS baseline", "--gnugss",
                {**CMAKE_ARGS, "CMAKE_BUILD_RPATH":
                 f"{deps.NGTCP2 / 'lib'};{deps.GNUGSS / 'lib'}"},
                gnu_gss=True)


def without_mit(build):
    """
    Return a pkg-config directory holding every module the system's
    pkg-config knows but MIT krb5's, for PKG_CONFIG_LIBDIR: FindGSS asks
    for `mit-krb5-gssapi` before `gss`.
    """
    farm = build / "pkgconfig-without-mit"
    if farm.exists():
        subprocess.run(["rm", "-rf", str(farm)], check=True)
    farm.mkdir(parents=True)
    pc_path = subprocess.run(["pkg-config", "--variable", "pc_path",
                              "pkg-config"], check=True, capture_output=True,
                             text=True).stdout.strip()
    for d in pc_path.split(":"):
        for pc in sorted(pathlib.Path(d).glob("*.pc")):
            if not pc.name.startswith("mit-krb5") and not (
                    farm / pc.name).exists():
                (farm / pc.name).symlink_to(pc)
    check((farm / "openssl.pc").exists(), f"{farm} has no openssl.pc")
    return str(farm)


def fork_oracle(fork, name):
    """
    Return the reference build over the OpenSSL fork `fork`, as CMake finds it
    (`OPENSSL_ROOT_DIR`): HTTP/3 over ngtcp2's BoringSSL crypto from the
    ngtcp2 built for the fork, both found by their RUNPATH; that crypto is
    a static library of ngtcp2's, linked in, not loaded.
    """
    return Oracle(ROOT / "build" / f"c-{fork}", f"baseline-{fork}",
                  f"C {name} baseline", f"--{fork}",
                  {**CMAKE_ARGS, "OPENSSL_ROOT_DIR": str(deps.fork_dir(fork)),
                   "CMAKE_BUILD_RPATH":
                   f"{deps.fork_ngtcp2_dir(fork) / 'lib'};"
                   f"{deps.fork_dir(fork) / 'lib'}"},
                  fork=fork)


AWSLC = fork_oracle("awslc", "AWS-LC")
BORINGSSL = fork_oracle("boringssl", "BoringSSL")


# Rustls in place of OpenSSL, as the rewrite's `rustls` feature has it: no
# QUIC (C's HTTP/3 over Rustls is quiche's, not built here), and no
# Ed25519 to sign HTTP messages with (CMake turns HTTPSIG off without it).
# Its programs find rustls-ffi's library by their RUNPATH.
RUSTLS = Oracle(ROOT / "build" / "c-rustls", "baseline-rustls",
                "C Rustls baseline", "--rustls",
                {**CMAKE_ARGS, "CURL_USE_OPENSSL": "OFF",
                 "CURL_USE_RUSTLS": "ON", "USE_NGTCP2": "OFF",
                 "USE_PROXY_HTTP3": "OFF", "CURL_DISABLE_HTTPSIG": "ON",
                 "CMAKE_BUILD_RPATH": str(deps.RUSTLS / "lib")},
                links_ngtcp2=False, rustls=True)


def run(oracle):
    commit = common.c_commit()
    check(not commit.endswith("-dirty"),
          "C tree has local changes; a baseline must name a commit")
    dep_env = deps.build_fork(oracle.fork) if oracle.fork else deps.build()
    if oracle.wolfssl:
        dep_env = {"PKG_CONFIG_PATH": ":".join(
            e["PKG_CONFIG_PATH"] for e in (deps.build_wolfssl(), dep_env))}
    if oracle.gnu_gss:
        dep_env = {"PKG_CONFIG_PATH": ":".join(
            e["PKG_CONFIG_PATH"] for e in (deps.build_gnugss(), dep_env)),
                   "PKG_CONFIG_LIBDIR": without_mit(oracle.build)}
    if oracle.rustls:
        dep_env = {"PKG_CONFIG_PATH": ":".join(
            e["PKG_CONFIG_PATH"] for e in (deps.build_rustls(), dep_env))}
    # A fresh cache: nothing configured by hand earlier, such as another
    # library location, may carry into the measurement.
    (oracle.build / "CMakeCache.txt").unlink(missing_ok=True)
    subprocess.run(["cmake", "-S", str(ROOT), "-B", str(oracle.build), "-G",
                    "Ninja", *(f"-D{k}={v}" for k, v in oracle.cmake_args.items())],
                   check=True, stdout=subprocess.DEVNULL,
                   env={**os.environ, **dep_env})
    # The test programs are not in the default target.
    subprocess.run(["ninja", "-C", str(oracle.build), "all", "testdeps"],
                   check=True, stdout=subprocess.DEVNULL)
    for binary in [next(oracle.build.glob("lib/libcurl*.so.*.*.*")),
                   oracle.build / "src/curl", *oracle.test_programs]:
        if oracle.links_ngtcp2:
            deps.check_linked(binary, oracle.crypto, oracle.ngtcp2)
    if oracle.gnu_gss:
        # The positive control: GNU GSS is the one named and loaded, and
        # no MIT library is there for its symbols to resolve to.
        version = subprocess.run([str(oracle.build / "src/curl"), "-V"],
                                 check=True, capture_output=True,
                                 text=True).stdout
        check(" libgss/" in version and "mit-krb5" not in version,
              f"the GNU GSS build says {version.splitlines()[0]}")
        libcurl = next(oracle.build.glob("lib/libcurl*.so.*.*.*"))
        ldd = subprocess.run(["ldd", str(libcurl)], check=True,
                             capture_output=True, text=True).stdout
        check(f"{deps.GNUGSS}/lib/libgss.so" in ldd
              and "libgssapi_krb5" not in ldd,
              f"{libcurl} loads {ldd}")
    meta = suite.run(oracle.build, oracle.results, dict(os.environ))
    (oracle.results / "run.json").write_text(
        json.dumps({"c-commit": commit, **meta}, indent=1) + "\n")


def build_config(oracle):
    cache = {}
    for line in (oracle.build / "CMakeCache.txt").read_text().splitlines():
        m = re.match(r"^(\w+):\w+=(.*)$", line)
        if m:
            cache[m.group(1)] = m.group(2)
    for k, v in oracle.cmake_args.items():
        check(cache.get(k) == v,
              f"{oracle.build} has {k}={cache.get(k)!r}, it should be {v!r}")
    return cache


def exports(oracle):
    """Return the built library's soname and defined dynamic symbols."""
    libs = sorted(oracle.build.glob("lib/libcurl*.so.*.*.*"))
    check(len(libs) == 1, f"expected one built libcurl, found {libs}")
    dyn = subprocess.run(["readelf", "-d", str(libs[0])], check=True,
                         capture_output=True, text=True).stdout
    soname = re.search(r"Library soname: \[(.*?)\]", dyn).group(1)
    nm = subprocess.run(["nm", "-D", "--defined-only", str(libs[0])],
                        check=True, capture_output=True, text=True).stdout
    symbols = sorted(line.split()[-1] for line in nm.splitlines())
    check("curl_easy_init" in symbols, "nm output has no curl_easy_init")
    return {"file": libs[0].name, "soname": soname, "symbols": symbols}


def main():
    oracle = next((o for o in (THREADED, LIBSSH, GNUTLS, MBEDTLS, WOLFSSL,
                               GNUGSS, AWSLC, BORINGSSL, RUSTLS)
                   if o.flag in sys.argv[1:]), REFERENCE)
    if "--run" in sys.argv[1:]:
        run(oracle)
    meta = json.loads((oracle.results / "run.json").read_text())
    check(meta["c-commit"] == common.c_commit(),
          f"baseline was run at {meta['c-commit'][:12]}, the C tree is at "
          f"{common.c_commit()[:12]}: rerun with --run")
    cache = build_config(oracle)
    tests = json.loads((common.INVENTORY / "tests.json").read_text())["data"]
    check(json.loads((common.INVENTORY / "tests.json").read_text())
          ["c-commit"] == meta["c-commit"], "tests inventory is stale")
    by_num = {t["number"]: t for t in tests["tests"]}
    results, pytest_cases, pytest_uncollected = suite.results(
        oracle.build, oracle.results, tests)
    failures = {n: r["failed-parts"] for n, r in results.items()
                if r["result"] == "failed"}
    failed = set(failures)
    skipped = {n: r["reason"] for n, r in results.items()
               if r["result"] == "skipped"}
    ran = set(by_num) - set(skipped)
    log = (oracle.results / "runtests.log").read_text(errors="replace")

    version = subprocess.run([str(oracle.build / "src/curl"), "-V"],
                             capture_output=True, text=True,
                             check=True).stdout
    features = re.search(r"^Features: (.*)$", version, re.MULTILINE).group(1).split()
    protocols = re.search(r"^Protocols: (.*)$", version, re.MULTILINE).group(1)
    system = re.search(r"^\*+ System characteristics \*+ *\n(.*?)^\*+ *$",
                       log, re.MULTILINE | re.DOTALL)
    check(system is not None, "no System characteristics block")

    pytest_counts = {}
    for c in pytest_cases.values():
        pytest_counts[c["outcome"]] = pytest_counts.get(c["outcome"], 0) + 1
    skip_reasons = {}
    for c in pytest_cases.values():
        if c["outcome"] == "skipped":
            skip_reasons[c["message"]] = skip_reasons.get(c["message"], 0) + 1

    lib = exports(oracle)
    abi = json.loads((common.INVENTORY / "abi.json").read_text())["data"]
    public = {f["name"] for f in abi["functions"]}
    lib["not-public"] = sorted(set(lib["symbols"]) - public)
    lib["public-missing"] = sorted(public - set(lib["symbols"]))

    data = {
        "measured": {"started": meta["started"],
                     "finished": meta["finished"]},
        "runtests-args": meta["runtests-args"],
        "runtests-exit-status": meta["exit-status"],
        "cmake-args": oracle.cmake_args,
        "compiler": cache.get("CMAKE_C_COMPILER"),
        "curl-version": version.strip().splitlines(),
        "features": features,
        "protocols": protocols.split(),
        "system": system.group(1).strip().splitlines(),
        "library": lib,
        "counts": {"considered": len(by_num), "ran": len(ran),
                   "ok": len(ran) - len(failed), "failed": len(failed),
                   "skipped": len(skipped)},
        "results": {str(n): r for n, r in results.items()},
        "pytest": {"args": meta["pytest-args"],
                   "exit-status": meta["pytest-exit-status"],
                   "counts": pytest_counts,
                   "functions-without-cases": pytest_uncollected,
                   "cases": pytest_cases},
    }

    reasons = {}
    for n, why in skipped.items():
        reasons.setdefault(why, []).append(n)
    rel = oracle.build.relative_to(ROOT)
    md = [
        f"# {oracle.title}\n",
        (f"What the C build in `{rel}` does on the C test suite: the floor "
         "the rewrite is scored against. Measured "
         f"{meta['started']} to {meta['finished']} with `runtests.pl "
         f"{' '.join(meta['runtests-args'])}`; build flags are in "
         "`inventory/measure/baseline.py` and SCOPE.md.\n"),
        "```",
        *version.strip().splitlines(),
        "```\n",
        common.md_table(["", "tests"], list(data["counts"].items())),
        "## Built library\n",
        (f"`{lib['file']}`, soname `{lib['soname']}`, "
         f"{len(lib['symbols'])} defined dynamic symbols. Public functions "
         f"missing: {lib['public-missing'] or 'none'}. Exported but not "
         "public (`inventory/abi.md` lists the source definitions): "
         + (", ".join(f"`{n}`" for n in lib["not-public"]) or "none")
         + ".\n"),
        "## Failed\n",
        common.md_table(
            ["test", "name", "failed parts", "keywords"],
            [(n, by_num[n]["name"], failures[n], by_num[n]["keywords"])
             for n in sorted(failed)]) if failed else "None.\n",
        "## Skipped\n",
        common.md_table(
            ["reason", "class", "count", "tests"],
            [(why, suite.classify(why), len(nums), sorted(nums))
             for why, nums in sorted(reasons.items(),
                                     key=lambda x: (suite.classify(x[0]), x[0]))]),
    ]
    md += [
        "## pytest suite (tests/http)\n",
        common.md_table(["outcome", "cases"], sorted(pytest_counts.items())),
        "### Not passed\n",
        common.md_table(
            ["case", "outcome", "message"],
            [(k, c["outcome"], c["message"])
             for k, c in sorted(pytest_cases.items())
             if c["outcome"] in ("failed", "error")]),
        "### Skip reasons\n",
        common.md_table(["reason", "cases"],
                        sorted(skip_reasons.items(), key=lambda x: -x[1])),
        ("Test functions with no case in the report (collected away): "
         + (", ".join(f"`{n}`" for n in pytest_uncollected) or "none")
         + ".\n"),
    ]
    common.write(oracle.inventory, data, "\n".join(md), [
        f"{rel}/baseline/", f"{rel}/CMakeCache.txt", "tests/runtests.pl"],
        generated_by=" ".join(filter(None, ["inventory/measure/baseline.py",
                                            oracle.flag])))


if __name__ == "__main__":
    main()
