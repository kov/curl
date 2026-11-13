# curl, rewritten in Rust

This repository holds a rewrite of curl and libcurl in Rust, alongside the C source it was
written against. The rewrite produces three things:

- **`libcurl.so.4`**: a drop-in replacement for the C library. It has the same exported
  functions, constant values, struct layouts and behaviour, and the unchanged public headers
  in `include/curl/`. Existing programs use it without being rebuilt.
- **`curl`**: the command-line tool, with the same options, output and exit codes.
- **A Rust API** (`curl-core`), which is the product. The C ABI is a translation layer over it.

The reason for the rewrite is the language. curl's security history is mostly memory-safety
bugs, bare integers taken for one another, and state that outlived what it described. In the
rewrite:

- `unsafe` code is confined to a listed set of modules: the bindings to C libraries, the OS
  interfaces and the C ABI shim.
- Libcurl's interchangeable integers each get a type of their own.
- A connection or transfer in a different state is a different type.

The original curl README is kept as [`README.upstream.md`](README.upstream.md) (and
[`README.upstream`](README.upstream)).

## How it was built

The rewrite was written by Claude, Anthropic's model, working in Claude Code under the
direction and review of this repository's maintainer. It took about 2,300 commits, starting on
20 October 2026. It is about 430,000 lines of Rust, tests included, against the 200,000 lines
of C in `lib/` and `src/`.

The C tree is the reference, and it was not translated line by line:

- **The C tree defines what has to be built.** [`inventory/`](inventory/README.md) is
  generated from the C tree: every option, constant, struct layout, test, feature and command
  line the rewrite must match.
- **The rules are written down.** [`CLAUDE.md`](CLAUDE.md) holds the principles,
  [`SCOPE.md`](SCOPE.md) what counts as done, [`DESIGN.md`](DESIGN.md) and
  [`ENGINE.md`](ENGINE.md) the architecture, and [`MILESTONES.md`](MILESTONES.md) the order of
  the work and each step's status.
- **C's test suite is the oracle.** A step was done when its tests passed on the Rust build as
  they do on a C build from the same tree. Where the two disagreed, the C build was run on the
  same case first.
- **Deliberate differences are recorded.** Each place where the rewrite does not do what C
  does is listed in [`DIVERGENCE.md`](DIVERGENCE.md), with the test that pins it. These are
  C bugs, or cases where the rewrite cannot behave as C does.

### What it covers

- **Protocols:** all of curl's: HTTP/1.1, HTTP/2 and HTTP/3, FTP and FTPS, SMTP, IMAP, POP3,
  SCP and SFTP, LDAP, MQTT, WebSocket, DICT, Gopher, RTSP, TELNET, TFTP and FILE.
- **APIs:** the share, multi and URL interfaces, and HSTS, alt-svc, DoH and SSL session
  export.
- **TLS backends:**
  - OpenSSL, plus the LibreSSL, AWS-LC and BoringSSL forks;
  - GnuTLS, wolfSSL, mbedTLS and Rustls;
  - Schannel on Windows;
  - Apple SecTrust verification on macOS.
- **Other backends:**
  - QUIC: ngtcp2 over each TLS library it has crypto for, and quiche;
  - SSH: libssh or libssh2;
  - resolvers: c-ares or the threaded resolver;
  - GSS-API: MIT krb5 or GNU GSS, and SSPI on Windows;
  - IDN: libidn2, WinIDN or AppleIDN.
- **Platforms:** Linux (x86_64 and aarch64), macOS (arm64) and Windows (x86_64, MSVC).

The following are not built:

- NTLM, which is opt-in in C and scheduled for removal there;
- quictls;
- Apple's experimental fast UDP.

### Compatibility claim

On every build configuration we measured, the rewrite passes every test in curl's own suite
that the C build passes. Exactly two exceptions apply everywhere: tests 96 and 558. They
check C's source file names in the debug memory log, so [`SCOPE.md`](SCOPE.md) replaces them
with Rust tests of the same property. "Validated" below gives the figures and how they were
measured.

### Performance claim

Built in release mode, the rewrite transfers data at about C's rate:

| Platform | Rust's rate / C's | Notes |
|---|---|---|
| Linux x86_64 | 0.86–1.11 | most cases 0.97–1.04 |
| Linux aarch64 | 0.81–1.17 | lowest case: 50 parallel HTTP/3 downloads (0.81–0.87) |
| macOS | 0.84–1.08 | |

- With verbose tracing on, as WebKit runs it, the rewrite makes 1.2 to 2.4 times C's request
  rate.
- Lowest x86_64 cases: single 1 MB HTTP/1.1 uploads (0.86) and parallel 1 MB HTTP/2
  downloads (0.89).
- Micro-benchmarks run 0.57 to 1.09 of C's time.

The scorecards are [`inventory/perf.md`](inventory/perf.md) (Linux aarch64),
[`inventory/perf-x86_64.md`](inventory/perf-x86_64.md) and
[`inventory/perf-macos.md`](inventory/perf-macos.md).

## Building

You need:

- a stable Rust toolchain (`rust-toolchain.toml` selects it);
- a C compiler;
- Python 3;
- the development packages of the C libraries the build binds.

For the default build on Fedora:

```sh
sudo dnf install openssl-devel libnghttp2-devel libnghttp3-devel c-ares-devel libssh-devel \
    libidn2-devel libpsl-devel zlib-ng-compat-devel brotli-devel libzstd-devel krb5-devel \
    openldap-devel cmake autoconf automake libtool
```

HTTP/3 needs a newer ngtcp2 than distributions ship, at the version curl's CI pins. Build it
once into `build/deps/ngtcp2`:

```sh
python3 inventory/measure/deps.py
```

Then build the library and the tool:

```sh
cargo build --release -p curl-sys-abi -p curl-tool
```

The build writes `build/target/release/libcurl.so` (soname `libcurl.so.4`) and
`build/target/release/curl`.

The backends are chosen with cargo features on `curl-sys-abi` and `curl-tool`, as C's
configure chooses them:

- **TLS** (pick one): `openssl` (the default), `gnutls`, `wolfssl`, `mbedtls`, `rustls`,
  `quiche` or `schannel`.
- **SSH:** `libssh` (the default) or `libssh2`.
- **Resolver:** `c-ares` (the default) or `threaded-resolver`.

Each crate's `Cargo.toml` describes the rest of its features.

To match how distributions build libcurl, use the threaded resolver:

```sh
cargo build --release -p curl-sys-abi -p curl-tool --no-default-features \
    --features curl-sys-abi/openssl,curl-sys-abi/libssh,curl-sys-abi/threaded-resolver \
    --features curl-tool/openssl,curl-tool/libssh,curl-tool/threaded-resolver
```

## Replacing a system's libcurl

Any program linked against `libcurl.so.4` can load the rewrite instead. Installing it in a
directory of its own leaves the system's library in place and makes it easy to undo.

1. Install the library under its soname:

   ```sh
   sudo install -D -m 755 build/target/release/libcurl.so /opt/curl-rs/lib/libcurl.so.4
   ```

2. Point programs at it. Pick one:
   - **One program at a time:**

     ```sh
     LD_LIBRARY_PATH=/opt/curl-rs/lib some-program
     ```

   - **System-wide:** list the directory for the dynamic loader:

     ```sh
     echo /opt/curl-rs/lib | sudo tee /etc/ld.so.conf.d/00-curl-rs.conf
     sudo ldconfig
     ```

3. Check what a program loads:

   ```sh
   ldd /usr/bin/curl | grep libcurl
   ```

   It should show `libcurl.so.4 => /opt/curl-rs/lib/libcurl.so.4`.

To undo, remove the file under `/etc/ld.so.conf.d` and run `sudo ldconfig` again.

The rewrite's own `curl` is `build/target/release/curl` and needs no installation.

- **macOS:** the library is `libcurl.dylib`, with install name `@rpath/libcurl.4.dylib`.
- **Windows:** the DLL is named as C's CMake build names it.

## Validation

### Compatibility

curl's own test suite is the floor. A test counts only when it runs on both legs:

- the C build of this tree;
- the Rust build, laid over the C build's test servers and test programs.

The suite has three parts:

- `tests/data` through `runtests.pl`;
- the `tests/libtest` programs, which use only the public ABI and so test the ABI itself;
- the `tests/http` pytest suite.

The C test oracles are built from this tree by `inventory/measure/baseline.py`, one for each
backend, and `inventory/measure/score.py` compares the two legs. Results from the last full
run:

| Build | Test-suite result | Notes |
|---|---|---|
| Linux reference (OpenSSL, c-ares, libssh2, HTTP/2 and HTTP/3) | runtests 1992 of 1996, pytest 949 of 949 | One of the four failures is a C source check that C's own build fails too. |
| Linux, the other backends | Every test C passes | GnuTLS, wolfSSL, mbedTLS, AWS-LC, BoringSSL, GNU GSS, quiche and Rustls, each against a C build with the same backend |
| macOS arm64 | Matches C | Also checked against C's build with Apple SecTrust and AppleIDN |
| Windows, OpenSSL | 1966 of 1981, as C | |
| Windows, Schannel | 1933 of 1948 | C passes 1934; C alone fails one test |

The Rustls build is scored against C over rustls-ffi; the 56 pytest cases whose clients call
rustls-ffi directly are left out. Each of the following was also checked:

- **Every symbol the system's libcurl exports is exported.** All 507 installed programs on a
  Linux system that link libcurl resolve every libcurl symbol against the rewrite. The
  system's `curl` and CMake's downloads run on it.
- **The C unit tests are ported.** They link C internals, so they cannot run against the
  rewrite. 74 of the 87 are ported to Rust tests that read their cases from the C sources.
  The other 13 test C internals that have nothing in Rust to port to, each listed with its
  reason.
- **The tool matches real command lines.** A corpus of real command lines, taken from
  distribution packages, is checked against the tool's option parsing.
- **A real application runs on it.** A WebKit port on WebKit's curl network backend serves
  as an application-level check.

### Security

- **Unsafe code is confined.** It is allowed only in the modules [`CLAUDE.md`](CLAUDE.md)
  lists, and every block states the invariant it relies on. A change to one of those modules
  also runs its crate's tests under Miri, wherever Miri can run them.
- **Every curl CVE was reviewed.** Each CVE published in curl's `vuln.json` was compared with
  the rewrite's design. Each gap found was closed, most by making the mistake impossible to
  compile:
  - A request's credentials (Authorization, cookies, a login, a client certificate) reach the
    wire only through a value proving that its gate opened for that peer. That value is
    decided in one place.
  - TLS data flows only once the backend's peer check has produced a value for this
    connection's own identity. Backend crates cannot construct that value; compile-fail tests
    check this.
  - Connection reuse and TLS session keys compare every field.
  - Recursive structures are bounded without recursion.

  Where the rewrite keeps a weakness because C has it, the weakness is listed at the end of
  `DIVERGENCE.md`.
- **Invariants are tested against planted faults.** Every test guarding an invariant has a
  sabotage entry (`sabotage/entries/`): the fault that breaks the invariant, and the test that
  must catch it. `sabotage/sweep.py` plants each fault and checks that its test fails.
- **Mutation testing covers the rest.** cargo-mutants runs over each large change. A surviving
  mutant gets a test, or an exclusion in `.cargo/mutants.toml` with the reason it changes
  nothing observable.
- **Malformed input is an error, never a crash.** Hostile or malformed input from a server, a
  URL or the application is rejected with an error. Assertions guard only the rewrite's own
  internal invariants. A panic aborts; it never unwinds into C.
- **A failed allocation is an error, not an abort.** Torture tests refuse each of a
  scenario's allocations in turn. Every run must end cleanly with nothing left allocated.

### Performance

`inventory/measure/perf.py` builds both legs in release mode and measures them the same way,
with the samples of the two legs interleaved. It runs:

- the `tests/perf` micro-benchmarks;
- the download, upload and request scorecard from `tests/http/scorecard.py`, over HTTP/1.1,
  HTTP/2 and HTTP/3.

Ratios are medians of five runs, with their spread recorded. Each optimisation was measured
against the build before it, in interleaved runs. Where instruction counts tell more than wall
time, they were counted under callgrind.

## Licence

curl's licence: see [`COPYING`](COPYING).
