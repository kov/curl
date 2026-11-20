# Designing out vulnerabilities

The rewrite exists to have fewer vulnerabilities than the C, not the same ones in another
language. Memory safety comes free with Rust and removes one class. The rest of curl's
advisories are logic: a credential sent to the wrong host, a connection reused when its set-up
differs, a length that disagrees with the bytes it describes, a state a peer can steer into an
abort. Rust only prevents those where the code is shaped so the wrong program does not compile.
This file says how to shape it, and how to review the code for the places that are not.

`CLAUDE.md` holds the rules; this file holds the patterns behind them, each with the type that
closes it and where the tree already uses it. Read it before designing a change that touches a
trust boundary (a peer, a URL, an option from the application, a callback), and use it as the
checklist of a review.

## The patterns

Each pattern is a C idiom, the way it turns into a vulnerability, and the shape that makes the
wrong code fail to compile or fail closed. The idiom is internal shape in nearly every case, so
removing it changes no byte on the wire.

### One fact, one owner; decisions derived where they are used

A flag set at one site and read at another (`mark_close()`, `late`, `yielded`, `wired`) makes
the decision the sum of every site that remembers to set it. The next path that forgets is the
bug. Store the fact once and derive the decision from it at the point of use:

- whether a connection may be pooled is asked of the connection (`LineConn`'s rest), not of the
  29 sites that may close it;
- whether an HTTP/1 response closes its connection follows from its framing being abandoned
  (`Response::closes`), not from a flag set beside it;
- how an HTTP/2 stream ended is one `StreamEnd`, not three fields that five writers set in
  different combinations.

Two values that must agree are one value: a count and its buffer, a state and a flag about the
state, two containers holding one handle.

### No permissive sentinel

An absent or zero value that means "allowed" (`None` for "any origin", `0` for "all", `-1` for
"unknown") lets every caller that forgot to fill a field grant the widest permission.
`Option` means present or absent, nothing else. When absence carries a policy, the policy is a
variant of its own, and the type has no state for "not decided yet":

- the first origin is recorded before a request is built, so a request's gate has no open arm
  (`FirstOrigin`, `Origins`);
- a port range starts at a `NonZeroU16` (`LocalPorts`), so "no port" is the absence of the
  range, not a range from zero;
- an SSH host-key requirement that asks nothing is compared as such (`HostAsk::serves`), not
  read from four `Option`s at each use.

### Origin-bound values only through the gate

What the application said for the first origin (credentials, an FTP account) must not reach
another, and what a server gave goes back to that server alone (an RTSP session id it set). An
RTSP session id the application sets is not of the first origin: it goes with every request, as
in C. C reads `data->set` at the point of use, so each use is a place to forget the check. Here the value is wrapped (`ForOrigin<T>`), and its only reader inside the
engine takes the gate's token (`get(&self, _: OriginTrusted)`), so a read without the decision
does not compile. A secret is never compared with `==`: equality on `ForOrigin` exists in test
builds only, and library code compares secrets with `same_secret`.

### A connection describes itself completely

A connection is reused when its description matches the transfer's. Anything that shaped the
connection but is not in that description is something no reusing transfer is asked about: the
shape of the reuse advisories (CVE-2022-27782, CVE-2023-27535, CVE-2023-27536, CVE-2023-27538).
So:

- set-up reads what it is set up with from the connection's route (`RouteCold`, `SshSetup`,
  `FtpSetup`), never from the transfer's options;
- every comparison destructures its type by name, so a new field does not compile until it is
  compared or named with the reason it is not (`Route::reaches`, `RouteCold::suits`,
  `SshSetup::serves`);
- a requirement the connection did not meet (a host key check, a login method) gets a new
  connection, even where C reuses.

The same holds for every cache shared between transfers: whatever shaped a cached CA store,
TLS session or pooled connection is part of what the cache is keyed and compared by, or the
entry is that transfer's alone.

### What the application gave is taken where C reads it

The application may set an option from any of its callbacks, and the engine runs callbacks in
the middle of a protocol's exchange. A step that finds a value by its place in the live options
after a callback ran (the next recipient, the next quote command, the cookie string) reads a
list the callback may have emptied or replaced: an `expect` that aborts, or a command applied to
another command's arguments. Take the value where C reads it, shared rather than copied, and
have every later step read what was taken: SMTP's recipients at DO, FTP's postquote list as DONE
starts, an SFTP quote run's list as it starts (`QuoteRun`), the cookie string before the jar is
traced. Where C reads live at each step, read live, and let a missing entry end the list.

### A callback reaches only what it was lent

Every call into application code either lends the callback a frame through which its calls
reach the transfer, or lends nothing, and then the gate refuses what would reach a borrowed
handle or a held multi (`CURLE_RECURSIVE_API_CALL`), never panics on the borrow. An easy call
reaches a multi's core only counted as a call on it (`MultiStack::hold`), so a callback inside
it cannot take the core a second time; the uncounted reach is private to the gate.

### A call that blocks says what it took

A send that would block after the library took some bytes leaves the caller an unstated duty:
give the same bytes again. A shorter retry made rustls count bytes the caller no longer held,
and Schannel abort. A call that blocks either takes nothing or reports what it took; where a
library keeps the duty, it refuses a retry that breaks it, and the core refuses a count larger
than the bytes it handed down (`TlsLayer::send`).

### Foreign errors are typed, not defaulted

`unwrap_or_default()`, `.ok()` and `Err(_) => {}` on a foreign library's result turn a refusal
into a value that means something else: quiche's "stream stopped" became "nothing taken", and an
upload was offered again for ever. A binding returns the library's answer as an enum the caller
must match (`BodyRefused`).

### An unsafe module's safe surface is sound in any order

A safe function in an unsafe module must stay sound whatever the caller does before and after.
No reference into an object lives across a foreign call whose callback writes that object
through its own pointer; such an object lives behind that one pointer and is borrowed only
between calls (c-ares's `Answers`). A precondition on call order or on a library's lifetime is
an `unsafe fn` or a type, not a sentence in a `SAFETY:` comment no test checks.

### Lengths come from the thing they measure

A size kept beside the bytes it measures drifts from them: a converted upload announced with its
source's size, a control message's length tested in one place and its data read in another.
The length that goes on the wire is read from the built body only (`WireSize`), and a check and
the read it guards are one function.

### Assert only what this module established

`assert!` and `expect` are for violated internal invariants. A state that peer input can reach
through another module's dispatch is not internal: there the function returns an error, or
takes a value only the right state can produce. A failed operation leaves its state failed, not
at a value that can be entered again (a TLS layer whose handshake failed stays failed). The same
holds for states an application can reach from its own callbacks: a handle added from inside its
own cleanup is refused with an error, not an `unreachable!`.

### Proofs, not booleans

Where a later step must only run after a check, the check returns a value only its module can
make, and the step takes it: `OriginTrusted` and `SameOrigin` from the gate, `HostVerified` from
the SSH host-key check, `Checked` from TLS verification. A `bool` at a decision point is a
question someone answered elsewhere; an enum with a variant per case names the answer, and two
positional `bool`s are a call site waiting to swap them.

### One door to the application's handlers

The write and header handlers are reached through `deliver` alone, which applies the pause and
the size limit in one place. A second caller is a second place to forget them.

### A record is checked, not trusted

Comments in an exhaustive destructure, and records such as a backend's `Residual`s, are prose:
the compiler checks the destructure, not the sentence beside a `_`. Where a record stands for a
decision, a test reads the record (two identities differing in any input give different keys; a
residual is asserted by the test that shows the weakness).

## Diverging from C for security

Observable behaviour follows C, except where C's behaviour is the weakness. Then the rewrite
does the safe thing: a new connection where C reuses one, an error where C proceeds, a refusal
where C aborts or corrupts. Each such divergence is the owner's decision, is recorded in
`DIVERGENCE.md` with the test that pins it, and is described there neutrally as what each side
does. An unfixed weakness in C is described only in the private `build/UPSTREAM-REGISTER.md`,
never in a tracked file or a commit message. Run the C build on the case before writing the
divergence, so the entry rests on an observation.

## Reviews

Two kinds, run as a pair after each batch of upstream security reports and at the end of a
large piece of work.

### What would have prevented it

For each upstream vulnerability report and security fix (GitHub issues labelled `vuln:*`,
disclosed HackerOne reports, upstream's fix commits):

1. Is the rewrite affected? Reproduce it on both legs; a claim read from the code is labelled as
   such.
2. The root cause in one line.
3. What language feature or design would have made it impossible here.
4. Whether the C idiom behind it is needed for C's observable behaviour, or internal shape only.
5. The class: search the tree for other instances of the same idiom, reachable or not.

Rank the structural changes by the classes they close against their cost. A patch is right only
where no type can hold the invariant (a foreign library's default, a policy); then the control
is a test against the real library.

### The idiom audit

Sweep the tree for the patterns above, without waiting for a report:

- `Option` fields and parameters whose `None` is a policy, sentinels compared with `0` or `-1`;
- `bool` parameters and fields at decision points;
- options read from `Options` during connection set-up or in a protocol's connection state;
- options read by index, or read again, after a step that runs a callback;
- `assert!`, `expect`, `unreachable!` and indexing in modules that peer input reaches;
- flags set by `mark_*` at one site and read at another;
- two fields or containers that hold one fact;
- `as` casts on lengths and offsets; `let _ =`, `.ok()`, `unwrap_or_default()` and
  `Err(_) => {}` on a `Result`, a foreign library's above all;
- a `RefCell` borrow, or a `&mut` into the core, held across a call into application code;
- a reference held across a foreign call that may call back;
- a call that may block after taking input, and what it asks of the caller's retry;
- comments that claim a property a test does not check.

Include a critique of what the last round landed: each fix is a new design, and its gaps are the
next round's findings.

### Every finding

- is re-read at the cited lines before it is acted on; a reviewer's claim is a hypothesis;
- is fixed with a test armed by breaking the fix, and a sabotage entry where it guards an
  invariant;
- is labelled "C weakness" where C behaves the same and the behaviour is a weakness, which
  routes it to the private register.
