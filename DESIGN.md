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
| `curl-os` | Operating-system interfaces: the command line, the terminal, the user database, sockets and polling. | in named modules |
| `curl-psl` | libpsl's public suffix list, behind `curl_core::cookie::PublicSuffixes`. | yes: it is a binding |
| `curl-zlib` | zlib's inflate, behind `curl_core::coding::Decoder`. | yes: it is a binding |

Code that must talk to C or to the OS gets its own crate, never a module of `curl-core`:
- one crate per bound C library (OpenSSL, nghttp2, ngtcp2, libssh2, c-ares and the rest);
- one crate for sockets, polling and other OS interfaces (`curl-os`, over `libc`), with Linux
  first and other platforms behind the same API. It exposes safe functions; `curl-core` adapts
  them to its own traits;
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
- **Parsers are sans-IO; drivers do I/O only through a connection.** A protocol's parsers and
  renderers (`proto/http1/`) consume bytes and the current time and produce bytes and events,
  with no I/O. Its driver (`proto/http.rs`) sends and receives through the leased `Conn` only,
  never a socket, and reports what it waits for next; only the multi loop and the pool touch
  sockets.
- **`curl_easy_perform` runs a private multi loop**, as in C.
- **Protocols are testable without a network.** Unit tests feed bytes and a clock, with no
  sockets and no sleeps.
- **A connection is a stack of filters.** TCP, then a proxy tunnel, then TLS, then HTTP/2, each
  with the same sans-IO interface. This is the C tree's `cfilters` model, and it keeps the
  combinations orthogonal.
- **A TLS backend is driven as C drives it.** The OpenSSL layer gets a custom BIO method over the
  layer below, as `lib/vtls/openssl.c` does, so the `SSL *` and `SSL_CTX *` an application is
  handed look the same as C's. A more efficient arrangement can come later as an opt-in.
- **Time is an injected clock**, owned by the multi and read once per pass; everything below
  receives that `now` as an argument, so timeouts are deterministic under test.
- **Callbacks fire when C fires them.** The timer callback runs inside `add`, `remove` and
  `pause`; the socket callback inside `remove` and `pause`, including a pause made from a write
  callback; each transfer's pollset is assessed right after it runs. Ordering the application
  can observe is part of the ABI.

## The transfer engine

- **A transfer's state is one enum.** The lease on its connection lives only inside the variants
  that hold a connection, and only the step that finishes a request releases it, after the
  protocol is done and the output flushed. `Completed` has one way in, which `remove` uses too.
  C's `data->conn`, `conn->attached_xfers`, the multi's set memberships and `state.done` are all
  read off the variant instead of being kept in step.
- **A request's two directions are states, not flags.** Sending is head, waiting for
  `100-continue`, body, done or aborted; receiving is head, body or done. How the body is framed
  (length, chunked, until close) is decided once when the headers end.
- **Time limits have one owner.** `Deadlines` holds the limits and the armed timers, and the
  report's `Timings` the start instants (`Starts`) the limits are judged from; both the wake-up
  and the "is it late" check are computed from them, and the timer queue is an
  index over it with one entry per transfer, reserved when the transfer is added. C's two anchors
  for the total timeout (the wake-up from the current request, lateness from the whole
  operation) are kept until a test on the C build shows the difference is a bug.
- **A connection's identity is a `Route`, fixed when it is created.** Reuse means the routes are
  equal, plus the deliberate allowances C makes (a TLS connection serving the plain scheme,
  multiplexing limits). A setting added to the route joins the comparison by construction, and
  nothing is written onto a pooled connection when it is reused.
- **The pool owns every connection and issues leases.** A connection is connecting, open or
  closing under one id that survives its handshake; setup is a pipeline of stages (resolve, race
  the addresses, proxy, TLS), each owning what the one before produced. Operations that need a
  handshaken connection exist only on an open one. The share lock is taken at the same four
  points as in C.
- **Pause is one value per direction.** Receiving is running, stopped by `curl_easy_pause` (the
  current buffer still finishes) or held by a callback's pause (output is held at once); sending
  is running or paused. A multiplexed connection buffers per stream, so a paused stream never
  holds the connection's shared receive buffer.
- **No engine borrow is live across a call-out** except values moved out of their homes for its
  duration (the stepping transfer's state, the connection's receive buffer), so a callback's
  context can reach every other transfer without aliasing.
- **Reads are capped at the response's remaining size** on connections that are not
  multiplexed, as C caps them, keeping traces and reuse decisions identical; the cap goes only
  if both legs agree without it.
- **A protocol is reported in `curl -V` as soon as its basic transfer works.** Tests that need
  it then fail instead of skipping, which is the honest state.

## Variadic C functions

The `...` and `va_list` functions (`curl_easy_setopt`, the `curl_m*printf` family) read their
arguments in the shim with `core::ffi::VaList`, after a safe parse has typed every argument.
Stable Rust cannot read a `long double`. A format with `%L` conversions therefore has its
arguments read by a small C helper (`csrc/va_fetch.c`), unless the shim is built with its
`nightly` feature, which reads them as `f128` on aarch64.

## Ownership and lifetimes

- **The multi handle owns the live state.** It holds the transfers, connections, the
  connection pool, the timers and, unless shared, the DNS cache. Ids are handed out as C hands
  out its transfer ids (the next free row after the last one used, with C's growth policy), so
  message and processing order match C's under add and remove churn.
- **Cross-references are generational keys, never pointers or references.** A `TransferId`
  or `ConnId` names an arena slot. Looking up a slot that has been freed and reused fails by
  itself, so a stale id is an error at the lookup instead of a use-after-free.
- **An easy handle is configuration plus at most one running transfer.** The C `CURL *` mixes
  the options, the in-flight state and the results of the last transfer. In Rust:
  - `Easy` owns the options;
  - `Multi::add` takes the `Easy` by value and `remove` hands it back; `Easy::perform` moves
    itself into its private multi and back. The private multi, with its connections and DNS
    cache, persists across performs;
  - starting a transfer creates its state, and finishing it drops that state;
  - what `curl_easy_getinfo` reports is a `TransferReport`, created whole when a transfer
    starts, written only by the engine while it runs (getinfo inside a callback reads it live),
    and left unchanged in the `Easy` until the next transfer replaces it. Its header store spans
    every request of the transfer, since `curl_easy_header` is callable after `perform`.
- **There is no hidden internal easy handle.** Connection-level work (pruning, health checks,
  shutdown) takes a connection context whose limits are captured per connection when it is
  created, not copied from whichever transfer ran last. The shim passes one internal `CURL *`
  per multi where the C ABI shows connection-owned sockets.
- **The Rust multi carries the application's values.** `Multi<H: Host>` stores one value per
  transfer and one per socket, so the shim keeps no second map from ids to its handles.
- **Typestate is used where C keeps flags.** Examples are a connection before and after its
  handshake, and a response before and after its headers. An operation that is valid in only
  one state exists only on that state's type.
- **Shared caches live in one owner.** The share handle holds them, and lends them whole to the
  multi a transfer runs in for the length of its perform. Once transfers on one share run at
  once, only idle connections and names stay in the share, and a busy connection belongs to its
  multi; locking is then a trait, taken at C's lock points, which the shim implements with the
  application's lock callbacks, which tests observe.

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
  - The C ABI's `CURLoption` → setter dispatch is matched by hand in the shim, each option
    checked as setopt.c checks it. The ids libcurl knows are generated from
    `inventory/options.json` (`gen/setopt.py`), so an id the shim lacks answers
    `CURLE_NOT_BUILT_IN` and an unknown one `CURLE_UNKNOWN_OPTION`.
- **Errors:** one `Error` type per API (easy, multi, share, URL), each carrying an error kind
  and an optional detail message.
  - The shim maps each kind to its `CURLcode` with a `match` that has no wildcard, so a new
    kind fails the build until it is mapped.
  - The detail message is what `CURLOPT_ERRORBUFFER` shows.
- **Callbacks are traits.** Example: a write handler receives `&[u8]` and returns an enum.
  Pausing is a variant of that enum, not a magic return value. The shim implements these
  traits over the application's function pointers and user data.
- **What a callback may call is a type.** Each call-out receives a context whose methods are
  exactly the calls C allows from that callback (`lib/api.c`): transfer callbacks may pause,
  read info or headers and change options of any transfer in the multi; socket and timer
  callbacks may not pause; notification callbacks may also add and remove. The shim routes a
  re-entrant C call through the live context, by a table generated from `lib/api.c`.
- **Options are read when C reads them.** C reads options live, so a setopt during a transfer
  takes effect per piece, per request or per transfer depending on the option. The core reads
  each option where C does (handlers at each call, limits at the transfer's start); an option
  whose C storage the application may change after setopt is copied at setopt instead
  (`CURLOPT_HTTPHEADER`'s list).
- **Strings handed to C belong to the shim.** It keeps NUL-terminated copies with the lifetime
  the C API promises (`CURLINFO_EFFECTIVE_URL` lives until the next transfer or cleanup), so
  the core never stores C-shaped strings.

## Allocation

Most of C's allocations exist because of C: a copy of every string option, a node per list
item, a temporary string per formatted message. They have no counterpart here. What remains is
state that outlives a call, since the application drives I/O and every call returns. The rule:
**heap at setup, borrow on the hot path, small temporaries on the stack, buffers reused.**

- **State that lives across calls lives in its handle**, allocated when the handle, the
  connection or the transfer is set up, and borrowed after that. Large state stays where it is
  and is passed by reference, not moved: a move is a copy.
- **Temporaries within a call go on the stack, and stay small.** We run on the application's
  threads, whose stacks may be small: a log line or a formatted number belongs on the stack, a
  receive buffer does not.
- **No allocation per chunk on the data path.** Each connection has a receive buffer and a send
  buffer, sized once and reused. Parsers return slices borrowed from the receive buffer, and
  write callbacks get those slices directly.
- **Response headers live in one store per transfer**, as byte ranges into a buffer, not one
  string per header. It belongs to the `TransferReport` and lives as long as it does.
- **Requests are formatted straight into the send buffer.** No intermediate strings.
- **Configuration strings are stored once.** A copy shared between handles (`duphandle`, the
  share) is reference-counted, not duplicated.
- **Small, bounded collections are inline arrays**, not `Vec`s.

Two sets of budgets check this:

- **The C suite's limits are ceilings.** The debug test build counts our allocations (see
  [Debug hooks](#debug-hooks)), and every test is capped at 1000 allocations and 1 MB peak
  unless its `<limits>` says otherwise; test 1, a plain HTTP GET, allows 140 and 136000 bytes.
  They were set for C's design, and ours should sit well below them.
- **Our own budgets are tighter, as Rust tests.** Each scenario (a plain GET, a reused
  connection, a redirect, the steady-state data path) has a test that counts the allocations
  its thread makes and fails above the budget, so a regression fails the build rather than a
  benchmark. Budgets are set as each scenario lands, at what the design calls for, not at what
  the code happens to do.

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

The test build is the counterpart of the C debug build (`SCOPE.md`), and `runtests.pl` ties memory
checking to the `Debug` feature, which 148 tests require: once we claim it, every test must leave
a memdump that `tests/memanalyze.pl` finds leak-free and within the test's limits. The tracking
behind it exists for what it checks in our model, not to mirror `lib/memdebug.c`:
- **Allocation failure is an error** (see [Allocation failure](#allocation-failure)). Torture
  runs fail each tracked allocation in turn; any infallible site left aborts the test. This is
  the main purpose: the clippy ban cannot see `clone`, `collect` or allocations made in other
  crates on our behalf.
- **The allocation budgets** above.
- **Leaks across the C boundary**, in memory the application and the shim share. Inside Rust,
  ownership frees memory; a leak report there means a forgotten exclusion or a reference cycle.

What is tracked: our allocations, not the process's, as C's tracker sees libcurl's and not
libc's. Tracking starts when `CURL_MEMDEBUG` or `CURL_MEMLIMIT` turns it on and covers every
Rust allocation from then on, except those made inside a named exclusion: the standard
library's lazily created globals, such as the standard output buffer, which are created once
and never freed. Excluding by name, rather than including by entry point, makes a mistake loud:
a missing exclusion reports a leak, where a missing inclusion would silently under-count.

A `debug-hooks` feature provides it, on `curl-alloc`, `curl-sys-abi` and `curl-tool`:
- **`curl-alloc`** owns the tracker: the memdump, written line by line with nothing allocated
  while logging, and the allocation limit. Its global allocator tags each block when it is
  made, so a block made before tracking started is never reported as a bad free. Being
  Rust's global allocator, it is process-wide by definition. It and the command line
  `curl-os` captures for the tool, written once before `main`, are the only globals outside
  the shim's root. It also counts allocations per thread, for the budget tests.
- **`curl-sys-abi`** installs that allocator and adds:
  - the `libcurl-d.so.4` soname;
  - the `curl_dbg_*` exports the C test programs import, logging to the same memdump and
    counting against the same limit. The application's blocks and those the shim hands out
    carry no header and come from the installed C allocator, so `curl_free` and
    `curl_dbg_free` each free either, as in C;
  - `curl_easy_perform_ev`.
- **`curl-tool`** installs the allocator and turns tracking on from `CURL_MEMDEBUG` and
  `CURL_MEMLIMIT`, as `src/tool_main.c` does.

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
- **A checker compares the two lists.** `inventory/measure/ported.py` maps the unit-test
  programs the inventory records to the Rust tests named after them (`cargo test -- --list`),
  reports each program as ported or missing, and fails on a port of a program that does not
  exist. It does not count cases: the C tests share no notion of one. A port tests the same
  cases as its original because its tables are generated from it.
