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

The C oracle is built in `build/c` by `inventory/measure/baseline.py --run`. Its `CMAKE_ARGS`
holds the exact configuration, and its results are the inventory's `baseline` section. The build
uses every backend and feature this machine can provide:

- a debug build (`ENABLE_DEBUG`), so the `Debug` and `TrackMemory` test gates are open;
- OpenSSL for TLS;
- nghttp2 for HTTP/2, and ngtcp2 + nghttp3 for HTTP/3;
- libssh2 for SSH and c-ares for name resolution;
- zlib, brotli, zstd, libidn2, libpsl, GSS-API (MIT krb5) and OpenLDAP;
- the opt-in NTLM, and the experimental HTTPS RR, SSL session export, HTTP message signatures
  and HTTP/3 proxy.

These cannot be built here:

- ECH, because the system OpenSSL lacks it;
- quiche, Rustls and Apple fast UDP.

These are not covered by this build:

- the other TLS backends (GnuTLS, mbedTLS, wolfSSL, Rustls);
- libssh;
- the threaded resolver, which c-ares replaces.

Each of these needs its own build configuration to be measured.

## Repository layout

- The C tree stays where it is; it is the reference, not upstream.
- The Cargo workspace lives at the top level.
- `inventory/` is generated and committed.

Paths that belong to the rewrite are listed in `NOT_C_TREE` in `inventory/gen/common.py`.
