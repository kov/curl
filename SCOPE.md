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

The rewrite's build must expose the same test hooks as a C debug build: the `Debug`,
`TrackMemory` and `unittest` feature gates and the `libcurl-env-dbg` variables. Without them,
the tests gated on those features skip instead of running.

## Reference build

The C oracle is built in `build/c`, with every backend and feature this machine can provide.
Its test results are recorded by the inventory's `baseline` section.

| setting | value |
|---|---|
| build | CMake + Ninja, `CMAKE_BUILD_TYPE=Debug`, `ENABLE_DEBUG=ON` |
| TLS | OpenSSL |
| HTTP/2, HTTP/3 | nghttp2; ngtcp2 + nghttp3 (OpenSSL QUIC API) |
| SSH | libssh2 |
| resolver | c-ares |
| compression | zlib, brotli, zstd |
| other | libidn2, libpsl, GSS-API (MIT krb5), OpenLDAP |
| opt-in | `CURL_ENABLE_NTLM`, and the experimental `USE_HTTPSRR`, `USE_SSLS_EXPORT`, `CURL_DISABLE_HTTPSIG=OFF`, `USE_PROXY_HTTP3` |
| test run | `runtests.pl -a -n -j8` from `build/c/tests` (valgrind off) |
| not buildable here | ECH (the system OpenSSL has no ECH support), quiche, Rustls, Apple fast UDP |

Not covered by this build:

- the other TLS backends (GnuTLS, mbedTLS, wolfSSL, Rustls);
- libssh;
- the threaded resolver, which c-ares replaces.

Each of these needs its own build configuration to be measured.

## Repository layout

- The C tree stays where it is; it is the reference, not upstream.
- The Cargo workspace lives at the top level.
- `inventory/` is generated and committed.

Paths that belong to the rewrite are listed in `NOT_C_TREE` in `inventory/gen/common.py`.
