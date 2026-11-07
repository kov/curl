# Scope of the rewrite

What "drop-in replacement, all features, all tests" means for this project. `CLAUDE.md` holds
the principles; this file holds the decisions. What the C tree contains is enumerated in
[`inventory/`](inventory/README.md).

## Deliverables

- **`libcurl.so.4`**, ABI-compatible with the C library built from this tree: the same exported
  functions, constant values, struct layouts and behaviour, so existing binaries and builds work
  unchanged. The public headers in `include/curl/` are the contract and ship unchanged.
- **`curl`**, the command-line tool, with the same options, output and exit codes.
- **A Rust API** that is the product. The C ABI is a translation layer over it (see `CLAUDE.md`).

## Out of scope

- **NTLM.** It has been opt-in in both C build systems since 8.20.0 (`CURL_ENABLE_NTLM`,
  `--enable-ntlm`), and `docs/DEPRECATE.md` schedules its removal. The rewrite behaves like a
  default C build: `CURLAUTH_NTLM` and the related constants keep their values, and the
  `NTLM` feature is not reported. Tests that need NTLM skip, as they do on a default C build.

A few tests check how the C code is written rather than what it does. Each is replaced by a
Rust test that checks the same property of the rewrite, named after the original and listed in
`REPLACED` in `inventory/measure/suite.py`; the scorer counts the original apart. Tests 96
and 558 expect C's source file names in the memdump, of the tool and of the library; their
replacements check that the memdump records the tool's allocations, and lib558's own block and
escape each allocated and freed, and that `tests/memanalyze.pl` finds nothing wrong in it.

## Where it differs from C

The rewrite does what the C does, but for C behaviour that is a clear bug (see `CLAUDE.md`).
Each such difference is listed, with the test that pins it, in [`DIVERGENCE.md`](DIVERGENCE.md).

## Platforms

Linux is the first target. Windows (SSPI, Schannel, WinIDN) and macOS (Apple SecTrust,
AppleIDN) come later. Design so they slot in without restructuring: platform-specific code
sits behind the same seams as backends, never as conditionals spread through shared code.

## Backends

Bind the same C libraries the C build uses, so that options handing the application a
backend-native object behave identically. An example is `CURLOPT_SSL_CTX_FUNCTION`, which
receives an OpenSSL `SSL_CTX *`. Each backend category (TLS, QUIC, SSH, resolver, compression,
IDN, PSL, GSS-API) is a pluggable interface. Rust crates may be offered as alternative backends
behind the same interface.

## Tests

The suite is the floor. It counts as passed only when each part runs on both the C and the Rust
build:

- `tests/data` through `runtests.pl`;
- `tests/libtest`, which uses only the public ABI and is the ABI oracle;
- the `tests/http` pytest suite;
- torture runs (`runtests.pl -t`), which fail each allocation of a test in turn: a failed
  allocation is an error, never an abort (see `DESIGN.md`). They are scored against a torture
  run of the C build on the same tests.

`tests/unit` and `tests/tunit` link internal `Curl_*` symbols and cannot run against the
rewrite. Each is ported to a Rust test beside the code it exercises. The inventory maps every
unit test to its target, so none is dropped silently.

The rewrite's test build must expose the same test hooks as a C debug build: the `Debug` and
`TrackMemory` feature gates and the `libcurl-env-dbg` variables. Without them, the tests gated
on those features skip instead of running. The `unittest` gate is always open in `runtests.pl`,
but the tests behind it run C unit-test programs, which test C internals whatever library is
installed: on the Rust build they are counted apart from the suite and replaced by the Rust ports.

## Reference build

The C oracle is built in `build/c` by `inventory/measure/baseline.py --run`. Its `CMAKE_ARGS`
holds the exact configuration, and its results are the inventory's `baseline` section. The build
uses every backend and feature this machine can provide:

- a debug build (`ENABLE_DEBUG`), so the `Debug` and `TrackMemory` test gates are open;
- OpenSSL for TLS;
- nghttp2 for HTTP/2, and ngtcp2 + nghttp3 for HTTP/3. ngtcp2 is built by
  `inventory/measure/deps.py` at the version curl's CI pins, because HTTP/3 0-RTT is rejected
  with the distribution's older ngtcp2;
- libssh2 for SSH and c-ares for name resolution;
- zlib, brotli, zstd, libidn2, libpsl, GSS-API (MIT krb5) and OpenLDAP;
- the experimental HTTPS RR, SSL session export, HTTP message signatures and HTTP/3 proxy.

These cannot be built here:

- ECH, because the system OpenSSL lacks it;
- quiche and Apple fast UDP.

These are not covered by this build:

- the other TLS backends (GnuTLS, mbedTLS, wolfSSL and Rustls, which have their own below);
- libssh;
- the threaded resolver, which c-ares replaces.

Each of these needs its own build configuration to be measured.

The rewrite binds libssh for SCP and SFTP by default, as distributions build libcurl, and
libssh2, the reference build's, with the `libssh2` feature in its place, as C's configure
chooses one. libssh's SSH behaviour is checked against a C oracle of its own,
`build/c-libssh`: the reference configuration with `CURL_USE_LIBSSH` in place of
`CURL_USE_LIBSSH2`, built and measured by `baseline.py --libssh` and scored against by
`score.py --libssh`. libssh2's is checked against the reference build, by `score.py
--libssh2`.

GnuTLS has one too: `build/c-gnutls`, the reference configuration with `CURL_USE_GNUTLS` in
place of `CURL_USE_OPENSSL`, with HTTP/3 over ngtcp2's GnuTLS crypto (which `deps.py` builds
beside its OpenSSL crypto) and without the HTTP/3 proxy (C's CMake has it with OpenSSL alone),
built and measured by `baseline.py --gnutls`. The rewrite's TLS library is a build
choice, the shim's and the tool's `gnutls` feature in place of `openssl`, and its leg (with
libssh2, as the oracle has it) is scored against that oracle by `score.py --gnutls`.

mbedTLS has one too: `build/c-mbedtls`, the reference configuration with `CURL_USE_MBEDTLS` in
place of `CURL_USE_OPENSSL`, without HTTP/3 (ngtcp2 has no mbedTLS crypto) and without HTTP
message signatures (C's CMake turns them off with mbedTLS, which has no Ed25519), built and
measured by `baseline.py --mbedtls`. The rewrite's leg, the `mbedtls` feature with libssh2, is
scored against it by `score.py --mbedtls`.

wolfSSL has one too: `build/c-wolfssl`, the reference configuration with `CURL_USE_WOLFSSL` in
place of `CURL_USE_OPENSSL`, with HTTP/3 over ngtcp2's wolfSSL crypto and without the HTTP/3
proxy, over the wolfSSL `inventory/measure/deps.py`
builds at the version and with the flags curl's CI uses (it is not packaged here), built and
measured by `baseline.py --wolfssl`. Encrypted Client Hello is off there as in the reference
build, so C's wolfSSL build has none of its code. The rewrite's leg, the `wolfssl` feature with
libssh2, is scored against it by `score.py --wolfssl`.

AWS-LC and BoringSSL, the OpenSSL forks C builds its OpenSSL backend over, have one each:
`build/c-awslc` and `build/c-boringssl`, the reference configuration with `OPENSSL_ROOT_DIR`
naming the fork, with HTTP/3 and its proxy over ngtcp2's BoringSSL crypto, over the fork and the
ngtcp2 `deps.py` builds at the versions curl's CI uses (`http3-linux.yml`), built and
measured by `baseline.py --awslc` and `--boringssl`. The rewrite's fork is a build choice as
C's is: curl-openssl over the fork openssl-sys finds (`OPENSSL_DIR`, linked statically), its
leg with libssh2 scored against the oracle by `score.py --awslc` and `--boringssl`. In those C
builds libssh2 and krb5, linked against the system's OpenSSL, bind to the fork's unversioned
`libcrypto.so` as well, and their SCP and SFTP tests fail; the rewrite links the fork into
itself and exports none of it, so its SSH runs over the system's OpenSSL. LibreSSL is a variant
of the same backend (102); quictls, which C still names apart, has no oracle.

Rustls has one too: `build/c-rustls`, the reference configuration with `CURL_USE_RUSTLS` in
place of `CURL_USE_OPENSSL`, over the rustls-ffi release curl's CI pins (0.15.5, its released
library, which `inventory/measure/deps.py` downloads), without HTTP/3 (C has no QUIC over
Rustls) and without HTTP message signatures, built and measured by `baseline.py --rustls`.
Encrypted Client Hello is off there as in the reference build. The rewrite's leg, the
`rustls` feature with libssh2, calls the rustls crate itself at the version that release pins,
not rustls-ffi, and is scored against it by `score.py --rustls`.

The threaded resolver has one: a second C oracle in `build/c-threaded`, the reference build's
configuration with `ENABLE_ARES` off and `ENABLE_THREADED_RESOLVER` on, as distributions build
libcurl. The rewrite's resolver is a build choice, a cargo feature, as C's configure makes it:
the suite's measurement build keeps the resolver checked against the c-ares reference above,
and the library that stands in for a distribution's (milestone 4's last step) uses the threaded
resolver, checked against `build/c-threaded`. c-ares is bound by `crates/curl-ares`; the tool and
the shim have it by their default `c-ares` feature, and neither uses nor links it when built with
`threaded-resolver`. With neither feature the build stops.

The machine also needs the following for the test servers, which the build does not check:

- httpd with mod_ssl and httpd-devel (for `apxs`);
- nghttpx, caddy, vsftpd, dante-server, sshd and stunnel;
- tcpdump;
- `::1 ip6-localhost` in `/etc/hosts`, which tests 241 and 1083 resolve.

A missing server makes its tests skip or error. It does not make them fail.

## Performance

The rewrite is compared with the C reference on this machine, release build against release
build. `inventory/measure/perf.py` measures both the same way: the `tests/perf` benchmarks and the
local download, upload and request scorecard of `tests/http/scorecard.py`. Its `perf` section is the C
side. The benchmarks that call internal helpers rather than the public API (base64, number parsing)
need Rust counterparts; the inventory marks them `port`.

## Stages

Each stage ends with its tests running on the Rust build and matching the C reference, with no
test newly skipped:

0. **Harness.** The Cargo workspace, a `build/rust` test tree in which the Rust library and tool
   replace the C ones under the C-built test servers and programs, and a comparison against the
   C baseline. The harness is armed by showing that a stub library passes nothing.
1. **APIs without a network.** Formatted printing, error strings, string lists, escaping, date
   parsing, the URL API, option metadata, version information and global init, with the debug
   hooks those tests depend on. The tool answers `-V`.
2. **The tool's command line.** Option parsing, help, configuration files and variables, and the
   tool tests that need no server.
3. **The transfer engine.** Easy and multi handles, the connection pool, `file://`, then HTTP/1.1
   with cookies, authentication, redirects and proxies.
4. **TLS** through OpenSSL.
5. **HTTP/2 and HTTP/3.**
6. **The other protocols:** FTP, SMTP, IMAP, POP3, SSH, LDAP, MQTT, WebSocket and the rest.
7. **Shared state:** the share interface, HSTS, alt-svc, DoH and SSL session export.
8. **Performance** against the C reference.

## Repository layout

- The C tree stays where it is; it is the reference, not upstream.
- The Cargo workspace lives at the top level, with its crates in `crates/` and build output in
  `build/target`. `DESIGN.md` describes its architecture.
- `inventory/` is generated and committed.

Paths that belong to the rewrite are listed in `NOT_C_TREE` in `inventory/gen/common.py`.
