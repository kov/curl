# Design of the rewrite

The architectural decisions that every stage builds on. `CLAUDE.md` holds the principles and
`SCOPE.md` what is covered; this file says how the code is shaped to honour them. It records
decisions, not implementation details: those live beside the code.

## Crates

| Crate | Role | Unsafe |
|---|---|---|
| `curl-core` | The Rust API: handles, protocols, caches, the transfer engine. | forbidden |
| `curl-sys-abi` | The C ABI over `curl-core`, built as `libcurl.so.4`. | yes: it is the shim |
| `curl-tool` | The `curl` binary, written against the Rust API, not the C ABI. | forbidden |
| `curl-alloc` | Fallible allocation; the debug build's memory tracker. | in named modules |

Code that must talk to C or to the OS gets its own crate, never a module of `curl-core`:
- one crate per bound C library (OpenSSL, nghttp2, ngtcp2, libssh2, c-ares and the rest);
- one crate for sockets, polling and other OS interfaces, with Linux first and other
  platforms behind the same API;
- one crate for allocation: the fallible constructors std lacks on stable (see
  [Allocation failure](#allocation-failure)) and the debug build's memory tracker (see
  [Debug hooks](#debug-hooks)).

That keeps `#![forbid(unsafe_code)]` on `curl-core` true for the whole project. The workspace
denies `unsafe_code`, and each module allowed to use it opts in by name and is listed in
`CLAUDE.md`.

Each backend category is a trait in `curl-core`. The crate binding the C library implements
it, and a Rust crate may implement the same trait. Selection happens at build time through
Cargo features, and at run time where the C ABI allows it (`curl_global_sslset`).

## Execution model

- **The application drives the I/O.** `curl_multi_socket_action` and the socket and timer
  callbacks hand the event loop to the application, so the core cannot own one.
- **No async runtime and no threads of our own** beyond those the C library uses for the same
  job.
- **Protocols are sans-IO state machines.** Each one consumes received bytes and the current
  time, and produces bytes to send, events for the transfer, and what it waits for next
  (readable, writable, a deadline). Only the multi loop touches sockets.
- **`curl_easy_perform` runs a private multi loop**, as in C.
- **Protocols are testable without a network.** Unit tests feed bytes and a clock, with no
  sockets and no sleeps.
- **A connection is a stack of filters.** TCP, then a proxy tunnel, then TLS, then HTTP/2, each
  with the same sans-IO interface. This is the C tree's `cfilters` model, and it keeps the
  combinations orthogonal.
- **Time is an injected clock**, never read ad hoc, so timeouts are deterministic under test.

## Variadic C functions

The `...` and `va_list` functions (`curl_easy_setopt`, the `curl_m*printf` family) read their
arguments in the shim with `core::ffi::VaList`, after a safe parse has typed every argument.
Stable Rust cannot read a `long double`. A format with `%L` conversions therefore has its
arguments read by a small C helper (`csrc/va_fetch.c`), unless the shim is built with its
`nightly` feature, which reads them as `f128` on aarch64.

## Ownership and lifetimes

- **The multi handle owns the live state.** It holds the transfers, connections, the
  connection pool, the timers and, unless shared, the DNS cache.
- **Cross-references are generational keys, never pointers or references.** A `TransferId`
  or `ConnId` names an arena slot. Looking up a slot that has been freed and reused fails by
  itself, so a stale id is an error at the lookup instead of a use-after-free.
- **An easy handle is configuration plus at most one running transfer.** The C `CURL *` mixes
  the options, the in-flight state and the results of the last transfer. In Rust:
  - `Easy` owns the options;
  - starting a transfer creates its state, and finishing it drops that state;
  - what `curl_easy_getinfo` reports is a `TransferReport` value, replaced whole by the next
    transfer, never patched field by field.
- **Typestate is used where C keeps flags.** Examples are a connection before and after its
  handshake, and a response before and after its headers. An operation that is valid in only
  one state exists only on that state's type.
- **Shared caches live in one owner.** The share handle holds them, and transfers reach them
  through the share. Locking is a trait: the Rust default is a mutex, and the shim implements
  it with the application's lock callbacks, which tests observe.

## Types

- **Every integer that means something has a newtype.** Ports, socket handles, transfer and
  connection ids, byte counts and offsets are each their own type. Durations are `Duration`,
  never milliseconds in a `long`.
- **Wire data is bytes.** Headers, paths, cookies and bodies are `&[u8]` or `Vec<u8>`. They
  become `str` only after validation.
- **URLs use a parser of our own** that matches `lib/urlapi.c`'s semantics. Test 1560 alone
  checks hundreds of cases. WHATWG-based crates parse differently.
- **The Rust API has typed setters.** An option takes its real type (`Duration`, an enum, a
  `Url`), and related options form a config struct. No setter takes an option id.
  - The C ABI's `CURLoption` → setter dispatch is **generated** from `inventory/options.json`,
    as is the `curl_easy_option_*` metadata table. Ids, types, aliases and deprecation flags
    therefore have one source.
- **Errors:** one `Error` type per API (easy, multi, share, URL), each carrying an error kind
  and an optional detail message.
  - The shim maps each kind to its `CURLcode` with a `match` that has no wildcard, so a new
    kind fails the build until it is mapped.
  - The detail message is what `CURLOPT_ERRORBUFFER` shows.
- **Callbacks are traits.** Example: a write handler receives `&[u8]` and returns an enum.
  Pausing is a variant of that enum, not a magic return value. The shim implements these
  traits over the application's function pointers and user data.
- **Strings handed to C belong to the shim.** It keeps NUL-terminated copies with the lifetime
  the C API promises (`CURLINFO_EFFECTIVE_URL` lives until the next transfer or cleanup), so
  the core never stores C-shaped strings.

## Allocation

The debug test build counts Rust allocations, so the C suite's memory limits apply to us.
- Every test is capped at 1000 allocations and 1 MB peak unless its `<limits>` section says
  otherwise.
- 32 tests set limits of their own. Test 1, a plain HTTP GET with the tool, allows 140
  allocations and 136000 bytes.

Rules that keep us inside those limits from the start:

- **No allocation per chunk on the data path.** Each connection has a receive buffer and a send
  buffer, sized once and reused. Parsers return slices borrowed from the receive buffer, and
  write callbacks get those slices directly.
- **Response headers live in one buffer per response**, as byte ranges into it, not one string
  per header. The buffer exists only while something can still ask for the headers
  (`curl_easy_header`, the header callback).
- **Requests are formatted straight into the send buffer.** No intermediate strings.
- **Configuration strings are stored once.** A copy shared between handles (`duphandle`, the
  share) is reference-counted, not duplicated.
- **Small, bounded collections are inline arrays**, not `Vec`s.
- **A test measures allocations per transfer** on the steady-state data path, so a regression
  fails a build rather than a benchmark.

Memory the application frees with `curl_free` comes from the application's allocator: the
`curl_global_init_mem` callbacks when set, `malloc` otherwise. Everything internal uses the
Rust allocator. The two never mix.

## Allocation failure

We ship a shared library, and a library must not take down the process that loaded it. A failed
allocation is an error: `CURLE_OUT_OF_MEMORY` at the C ABI, an `OutOfMemory` error kind in the
Rust API, and a NULL return from the C functions that return pointers. The C library behaves
this way, and its torture tests (`runtests.pl -t`) check it by failing each allocation of a test
in turn. The rule covers `curl-core`, the shim and the tool, which those tests also run.

Rust's standard library aborts when an allocation fails, and stable Rust offers no hook to change
that. Allocation is therefore always explicit and always fallible:

- **Collections grow only through `try_reserve`.** `Vec`, `String`, `VecDeque` and `HashMap`
  have it on stable; a push is valid only within capacity already reserved.
- **Heap objects are created through the allocation crate.** It provides the constructors std
  has only on nightly: a fallible `Box`, and a reference-counted pointer of its own, since std's
  `Arc` cannot be built fallibly on stable.
- **The infallible APIs are banned at build time.** Clippy's `disallowed_methods` and
  `disallowed_macros` reject `Box::new`, `Arc::new`, `format!`, `vec!`, `to_string`,
  `to_owned`, `collect` and the growing methods of the collections in these crates.
- **Third-party Rust crates are vetted for this before use.** A crate that allocates
  infallibly on a path we call cannot be used there. The C libraries we bind report allocation
  failure as an error themselves.
- **Peer-chosen sizes are bounded first.** Lengths, chunk sizes and header counts are checked
  against limits at the trust boundary before anything is reserved for them, so a hostile peer
  gets a protocol error, not an out-of-memory one.
- **The torture tests enforce the rule.** The debug tracker honours `CURL_MEMLIMIT` by failing
  the Nth allocation. Any allocation site that is still infallible then aborts, and the test
  fails. Rust unit tests use the same mechanism to fail every allocation of a code path in turn.

## Debug hooks

The test build is the counterpart of the C debug build (`SCOPE.md`). A `debug-hooks` feature
on `curl-sys-abi` provides:
- the `libcurl-d.so.4` soname;
- the `curl_dbg_*` exports the C test programs and tool import;
- `curl_easy_perform_ev`;
- memory tracking: a global allocator that writes the `memdump` log `tests/memanalyze.pl`
  reads when `CURL_MEMDEBUG` names a file. It writes `MEM` lines for allocations and `FD`
  lines for sockets.
  - Only allocations made while logging are tracked; a header tag marks them, so freeing an
    earlier allocation is not reported as a bad free.
  - `CURL_MEMLIMIT` makes the Nth allocation fail, which the torture tests rely on.
  - The tool honours `CURL_MEMDEBUG` and `CURL_MEMLIMIT` the same way.
- the same log and limit for the memory C code sees: the application's `curl_dbg_*` calls and
  every block the shim hands out, logged with its Rust caller. These blocks carry no header, so
  the two are one pool, as in C: `curl_free` and `curl_dbg_free` each free either.

Release builds contain none of this.

The C unit-test programs link C internals, so they never run on the Rust leg; the tests that
use them are scored apart, and their Rust ports stand in for them (see below).

## Ported unit tests

`tests/unit` and `tests/tunit` become Rust tests beside the code they exercise. Each port must
provably test the same thing as its C original:
- **Tables are generated, not copied.** Where a C unit test is driven by a table of inputs and
  expected outputs, a generator extracts the table into data the Rust test reads.
- **Ports are named after their originals.** Each Rust test carries the number of the C test
  it replaces.
- **A checker compares the two lists.** The inventory records each C unit test and its number
  of cases. The checker maps that to the Rust tests (`cargo test -- --list`), and reports each
  C test as ported or missing, failing when the number of cases differs.
