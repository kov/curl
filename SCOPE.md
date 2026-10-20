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
- the `tests/http` pytest suite.

`tests/unit` and `tests/tunit` link internal `Curl_*` symbols and cannot run against the
rewrite. Each is ported to a Rust test beside the code it exercises. The inventory maps every
unit test to its target, so none is dropped silently.

The rewrite's test build must expose the same test hooks as a C debug build: the `Debug` and
`TrackMemory` feature gates and the `libcurl-env-dbg` variables. Without them, the tests gated
on those features skip instead of running. It does not report `unittest`: the tests behind that
gate run C unit-test programs, which test the C internals whatever library is installed.

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
- quiche, Rustls and Apple fast UDP.

These are not covered by this build:

- the other TLS backends (GnuTLS, mbedTLS, wolfSSL, Rustls);
- libssh;
- the threaded resolver, which c-ares replaces.

Each of these needs its own build configuration to be measured.

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
