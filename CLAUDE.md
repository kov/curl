# curl, in Rust

A rewrite of curl and libcurl in Rust. The C tree here is what it is written against: it is the
reference implementation, and its test suite (`tests/`, driven by `runtests.pl`; see
`docs/tests/TEST-SUITE.md` and `docs/tests/FILEFORMAT.md`) is the floor the rewrite is scored
on. The C is not upstream to us: there is no obligation to feed anything back, and upstream's
contribution etiquette does not apply here. This file does.

What the rewrite covers (platforms, backends, which tests count, the reference build) is decided
in [`SCOPE.md`](SCOPE.md); what the C tree contains is enumerated in [`inventory/`](inventory/README.md).
How the code is shaped (crates, ownership, types, allocation) is in [`DESIGN.md`](DESIGN.md); the
transfer engine in detail is in [`ENGINE.md`](ENGINE.md), and the order it is built in, with each
step's status, in [`MILESTONES.md`](MILESTONES.md).

## Why Rust, and what follows from it

We are not porting for fashion. The language is the point: it is meant to remove whole classes
of the bugs this code has cost its users. Every rule below is that reason, applied.

**Keep `unsafe` minimal and wrapped.** Unsafe lives in named modules and nowhere else: the
bindings to C libraries (TLS backends, compression, resolvers and the like), the socket and OS
interfaces, and the C shim that exposes the libcurl ABI. Every unsafe block carries a `SAFETY:`
comment naming the invariant and who upholds it. The rest of the code is safe Rust, and an
unsafe block outside these modules is a design failure, not a shortcut. Name each such module in
this list when it is created, and keep the list exhaustive on purpose: a module that starts
needing unsafe is a module whose types are wrong.

Allowed to use unsafe, each opting in with `#![allow(unsafe_code)]`:

- `crates/curl-sys-abi`: the C ABI shim.
- `crates/curl-alloc/src/boxed.rs`: the fallible `Box` constructor std lacks on stable.
- `crates/curl-alloc/src/rc.rs`: the fallible reference-counted pointers std lacks on stable.
- `crates/curl-alloc/src/track.rs`: the debug test build's global allocator and memory tracker.
- `crates/curl-psl/src/lib.rs`: libpsl, the public suffix list cookies are checked against.
- `crates/curl-zlib/src/lib.rs`: zlib's inflate, undoing the `deflate` and `gzip` codings.
- `crates/curl-brotli/src/lib.rs`: brotli's decoder, undoing the `br` coding.
- `crates/curl-zstd/src/lib.rs`: zstd's decoder, undoing the `zstd` coding.
- `crates/curl-openssl/src/sys.rs`: OpenSSL's initialisation, and the version of the library
  loaded.
- `crates/curl-openssl/src/sign.rs`: OpenSSL's Ed25519, signing HTTP message signatures.
- `crates/curl-os/src/args.rs`: the process's command line, captured before `main` and wiped in
  place.
- `crates/curl-os/src/env.rs`: reading the environment, its values copied fallibly.
- `crates/curl-os/src/error.rs`: the text of an operating-system error, `strerror_r` into a
  buffer on the stack.
- `crates/curl-os/src/fs.rs`: opening and closing files, a file's status, removing, renaming
  and setting the times of files by name, making and listing directories, reading standard
  input unbuffered, making a file's reads nonblocking, and pointing standard error at a file.
- `crates/curl-os/src/net.rs`: opening, setting and connecting sockets, and adopting one the
  application opened.
- `crates/curl-os/src/poll.rs`: `poll(2)`.
- `crates/curl-os/src/wake.rs`: the multi's waker, an eventfd.
- `crates/curl-os/src/random.rs`: random bytes from the kernel, `getrandom`.
- `crates/curl-os/src/resolve.rs`: the system's resolver, `getaddrinfo`.
- `crates/curl-os/src/terminal.rs`: the terminal's width, and reading a password from it with
  echo off.
- `crates/curl-os/src/time.rs`: the local time of day, and formatting it in the process's
  locale (`strftime`).
- `crates/curl-os/src/locale.rs`: the process's locale, from the environment (`setlocale`).
- `crates/curl-os/src/users.rs`: the user database.
- `crates/curl-os/src/xattr.rs`: setting an open file's extended attributes (`fsetxattr`).
- `crates/curl-sys-abi/csrc/va_fetch.c`: C, not Rust; reads the printf arguments stable Rust
  cannot (`long double`). The `nightly` feature reads them in Rust instead.

**Make bad state unrepresentable; fail the build, not the run.** Use the type system in our
favour. libcurl is a soup of bare integers, `long` options and `void *` — option values, socket
descriptors, connection ids, transfer ids, lengths and offsets, all mutually interchangeable and
none of them checked. Each gets its own newtype. Where an operation is only valid in one state
(a connection before and after the handshake, a transfer before and after its headers), that
state is a distinct type, not a flag someone must remember to test.

**When the language can't enforce it, crash loudly.** `assert!` and `.expect()` are runtime
safety nets that surface a problem at the moment it is introduced, not three frames later.
Never silently ignore, never paper over, never `let _ =` a real error.

**Except at the trust boundary, where input is never allowed to crash us.** An assert fires on
a violated *internal* invariant — something we got wrong. Malformed, hostile or nonsensical input
is not that: a server, a proxy, a URL, a header, a cookie jar, a redirect or an option value from
the application that is out of range must be rejected with an error, never allowed to abort the
process. One bad peer must not be able to take down the application that embeds us. Validate and
reject at the boundary; assert behind it.

**Panics abort; they never unwind into C.** Unwinding across `extern "C"` is undefined
behaviour, so the C shim never lets one through. A loud abort is the behaviour we want anyway.

**No global mutable state.** The C carries process-wide state behind `curl_global_init` and
file-scope statics, which is where data races live. State hangs off an explicitly owned root (the
easy, multi and share handles) and is reached through it. Where the C ABI demands a global, it is
a single owned root at the shim — one place, not a habit.

**The Rust API is the product; the C ABI is a translation of it.** Wherever the two are in
tension, the ABI takes the hit — in performance, in efficiency, in ergonomics. Never the other
way round.

Concretely: C's idiosyncrasies stop at the shim and never leak inward. No `CURLcode` in a Rust
signature, no bare-integer id where a newtype belongs, no `bool` or `int` standing in for a
`Result`, no `repr(C)` argument struct in a Rust API, no length travelling beside the buffer it
measures, no varargs-shaped option setter, and no concept that exists only because a C header
says so. Review every signature against one question: **would this still make sense if the C
shim were deleted?** If the answer needs a C header to explain it, the translation belongs in the
shim.

**Do what the C does.** Observable behaviour — the bytes on the wire and their order, what is
traced, returned, reported and called back — follows the C unless the C's is a clear bug. Where
compatibility and performance or efficiency pull apart, compatibility wins, and the faster way
comes later as an addition or an opt-in. That choice is not a question for the user: take C's.
A deliberate difference from C is recorded, with the test that pins it, in `DIVERGENCE.md`.

**Two values that must agree are one value.** A count and its pointer, an offset and its base, a
capacity and its buffer. Passed onward as a pair, every layer in between has to be trusted to keep
them in step — and the layer that quietly repairs a mismatch is worse than the one that crashes,
because it reports success for work it did not do. Reconcile the pair once, at the boundary that
knows the truth (the parser for a wire field, the shim for a C one), and pass a slice or a newtype
from there on. Where the wire genuinely lets the two disagree, that same boundary is where the
peer's version is rejected — never averaged, never clamped. The pair may reappear only as the
arguments of the foreign call that needs it, rebuilt from the single value.

The rule is about state as much as about wire pairs. Two containers holding one fact, two maps
each holding a copy of a handle, two writers deciding one thing — each is a bug waiting. The same
reconciliation applies: one owner, and everything else holds a key to it rather than a copy of it.

**A lifetime mismatch is a design bug, and wants a structural fix.** When something outlives what
it describes — an id still naming a closed connection, a record surviving the transfer it
recorded, a cached answer outliving what it was true of — the fix is never another cleanup to
remember at another teardown site. Adding one leaves the next teardown path to be found by
whoever hits it in production. Restructure so the stale thing cannot be reached: make one place
the owner, have everything else name it indirectly, and let a reference to something gone fail on
its own. The test of a proposed fix is whether a future call site can still get it wrong. If it
can, it is a patch, not a fix.

**Generated code is generated.** Fixing a bug by editing generated output puts it somewhere no
one will find it and the next regeneration eats it. Fix the generator or its input.

## Testing discipline

- **Every behaviour fix carries a test that would have caught it**, in the suite that reaches it
  most directly: a `tests/data/testNNNN` case, a unit test, or a Rust test beside the code.
- **The C leg is the oracle.** When the rewrite and the C disagree on a test, run the C build on
  the same case before deciding which side is wrong.
- **A documented C limitation is a hypothesis until a test reproduces it.** The C tree carries
  workarounds whose comments assert things that are no longer true; porting one faithfully
  carries the folklore forward and hides that the real bug was fixed elsewhere. Reproduce it
  first, then port it or delete it.
- **Arm a new test by breaking the fix.** A test you have not watched fail is not a test, and
  agreement is worth only what would have made it differ.
- **A test that guards an invariant gets a sabotage entry** (`sabotage/entries/`, format in
  `sabotage/sweep.py`) in the same commit: the fault that breaks the invariant, planted by hand,
  and the test that must catch it. `cargo test` fails when an entry's text has left the tree.
- **At the end of a large piece of work, run the sweep and cargo-mutants on what it changed**:
  `sabotage/sweep.py <area>` for the faults about meaning (the wrong anchor, the wrong order),
  cargo-mutants for the mechanical ones, from a clean worktree and under a memory cap (the recipe
  heads `.cargo/mutants.toml`; a runaway mutant otherwise takes the session down). Not on every
  commit: their builds are slow. A survivor is code no test checks: add the test, or exclude the
  mutant in that config with a comment saying why it changes nothing observable.
- **An unrun test is absent, not passing.** A skipped test, a feature missing from the build or a
  test number not in the run all read as success. Read `runtests.pl`'s skipped line, and check
  the test ran on both legs.
- **Before believing a null, check the needle.** "No failures" and "no difference" are evidence
  only if you can name the result that would have shown the effect. A grep for error lines needs
  a positive control: also assert a line that is always written, or a dead needle reads green.
- **Proxies lie, and they lie towards success.** An exit code of 0, a clean log, a status that
  reads healthy: each is true about something, and none of them is the bytes on the wire or in the
  output. For a load-bearing claim, look at the artifact the claim is about.
- **Check a long run every 10 minutes while it runs** (the suite, a sweep, cargo-mutants): its log
  still grows, and no test process has sat at 0% CPU for longer than its test can take. A quiet
  background job reads the same whether it is working or hung. A tool hung under `runtests.pl`
  inherits its ignored SIGINT and SIGTERM: end it with `kill -9`.
- **Poke the live failure before bisecting.** One run against it beats a day of reasoning, and a
  bisect is only as good as its oracle.

## Working here

- Keep `ENGINE.md` and `MILESTONES.md` true as the engine is built. A commit that makes the code
  depart from the design, or changes the design, updates `ENGINE.md` (and `DESIGN.md` for the
  decisions it holds); a commit that finishes, splits or reorders a step updates its status in
  `MILESTONES.md`. They describe what is, not how it got there.
- Commit as work finishes. Never `git add -A` — this tree has untracked local files that must
  not be committed. Never push without asking.
- Before committing, run the project's formatter, `cargo clippy -- -D warnings` and the tests the
  change touches.
- A change to an unsafe module also runs that crate's unit tests under Miri with the Tree
  Borrows model (`MIRIFLAGS=-Zmiri-tree-borrows cargo +nightly miri test -p <crate> --lib`,
  with the crate's features), where Miri can run them; say so when it cannot (FFI,
  `.init_array`).

## Commit messages

Linux-style: `git log --oneline` should tell a reader who has not seen the code what each diff
does. The aphoristic voice of the rules above is for principles; it does not belong in a commit.

- **Subject:** `area: <imperative verb> <concrete object>`, aim for 60 characters, never over 72.
  It names what the code does differently, not the principle the change serves. A subject that
  needs "and" is usually two commits.
- **Body**, wrapped at 72, in this order: the problem as observable behaviour; its cause, if not
  obvious; what this commit changes; how it was verified. History — false starts, what was
  measured and rejected — goes last, in its own paragraph, and only if it would stop someone
  repeating it.
- **Plain words.** Code identifiers in backticks. Project shorthand is glossed once or not used.
  No first person, no rhetorical closers, no session names.
- **Trailers:** `Fixes: <sha12> ("<subject>")` when correcting an earlier commit.
