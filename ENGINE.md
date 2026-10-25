# The transfer engine

The shape of the transfer engine in `curl-core`: the multi loop, transfers, connections, the
data path, HTTP/1.x, and how the C ABI maps onto them, at the level of types and steps.
`DESIGN.md` holds the decisions every crate builds on and `MILESTONES.md` the order the engine
is built in; this file is where the engine's design lives in detail. It describes the engine as
designed: when the code departs from it, or the design changes, this file changes in the same
commit.

C facts are cited by file and line from the C tree this rewrite is written against. Stage
numbers are those of `SCOPE.md`.

---

## 1. Summary of decisions

**State model**

1. **A transfer's state is one closed enum, and the connection lease lives inside the variants
   that hold a connection.** `ConnLease` is linear (no `Clone`, created only by the pool,
   consumed by `Pool::release`). C's `data->conn`, `conn->attached_xfers`, `attached_multi` and
   `state.done` collapse into "which variant holds the lease". The lease is released only by
   the `Done` step, after protocol `done`, `DataDone` and writer flush, never by a transition
   helper.
2. **`Completed` is reachable through one exit function.** `remove` uses it too, so the bypass
   at multi.c:815 cannot be written.
3. **Set membership is derived from the state.** process, pending and msgsent are functions of
   the variant (msgsent is `Completed`'s `Message`); the trace's `MState` agrees with it,
   PENDING exactly while the variant is `Pending`, which the debug build's check holds. The
   only stored set is `dirty`, which is a genuine separate fact (a work queue). Counters are an
   index with one writer (the transition function) and a full recount in the debug build after
   every pass.
4. **`Deadlines` is the only owner of time limits.** The wake-up and the "is it late" check are
   both derived from the same stored instants, the report's `Starts`, which the getinfo times
   are taken from too. The timer queue is an index over it.
5. **Connection identity is an immutable `Route`; reuse matching names every field.** The
   comparison destructures each struct it compares without `..`, so a new field does not
   compile until it is compared or excused with a reason. Nothing on a pooled connection is rewritten on
   reuse.
6. **A connection is `ConnSlot::{Connecting, Open, Failed}` under a stable `ConnId`.**
   `Connecting` holds a typed `ConnectMachine` (resolve, eyeballs, then the proxy's tunnel or
   SOCKS handshake over the `Dialed` connection), each stage owning the output of the one
   before. Operations that need a handshaken connection exist only on `Open`. Bytes move
   through one `Stream` (the socket, its layers and its receive buffer), owned first by
   `Dialed` and then by the `Conn`. The layers are a pull chain, as C's filters are (§4.3).
   Where a connection is, is its place in its pool: `Leased` by one transfer, `Idle`, or
   `Reserved` for the handle whose transfer only connected, and later `Attached`; one shutting down is in no pool but in its multi's
   `ShutdownSet` (§4.6). A lease names its home pool and is given
   back only to it; every socket carries the closer it was opened with.
7. **Generational ids everywhere**: `TransferId`, `ConnId` (whose generation is the
   "Connection #N" number), `ResolveId`, `HeaderCursor`. A stale id fails its own lookup.

**Call-outs and re-entrancy**

8. **Every call-out receives a context, and the context is the api.c table as types.**
   `TransferCx` (write, header, read, debug, progress, prereq, seek), `EventCx` (socket and
   timer callbacks: no `pause`) and `NotifyCx` (adds `add`, `remove`). A method exists on a
   context only if C allows that call from that callback. Contexts reach every other transfer
   and the multi's tables through `EngineRest`.
9. **No engine borrow is live across a call-out except owned values moved out of their
   homes**: the stepping transfer's `Run`, its connection's receive buffer, and a multiplexed
   connection the step has out of its pool place (§4.4). Everything else stays in
   `EngineRest`, which the context borrows.
10. **Side effects are synchronous where C's are.** The timer callback fires inside `add`,
    `remove` and `pause`; the socket callback fires inside `remove` and `pause`; the pollset of
    each transfer is re-assessed right after it runs in `run_dirty`. Pause from a write
    callback runs the timer and socket callbacks before `curl_easy_pause` returns, as
    easy.c:1229 and :1236 do.
11. **The shim routes re-entrant C calls through the live context** behind one gate
    (`with_multi`/`with_easy`). The routing table is generated from `lib/api.c` and tested
    against it.

**Data path**

12. **Pause is one value per direction**: `RecvPause::{Running, Stopped, Held}` and
    `SendPause::{Running, Paused, Asked}`. `Stopped` is an API pause (the current buffer still
    finishes); `Held` is a callback pause (output is held at once). `Paused` is an API pause of
    sending; `Asked` a read handler's, which an API pause leaves as it is and whose lift the
    `Pause` counts (`Lifts`, §5.4.1). Rate limiting is a separate fact.
13. **The response pipeline is a fixed struct**, ordered by its fields, not a phase-sorted list.
    Paused output is ranges into one buffer, O(1) per append, EOS a separate event.
14. **A multiplexed connection delivers each stream's data at once, as C does**: what the
    session reads for a sibling stream goes to that sibling's pipeline in the step that read
    it, the sibling's `Run` moved out in turn; a paused sibling's bytes wait in its pipeline's
    paused output (§4.4).
15. **`TransferReport` is created whole at transfer start, written live by the engine during
    the transfer, and stays in the `Easy` afterwards.** getinfo inside a callback reads it live
    (lib1541, lib1485). The header store is part of it and spans every request of the transfer.

**Ownership and API**

16. **`Multi::add` takes the `Easy` by value and `remove` gives it back.** `Easy::perform`
    moves itself into its private multi with `mem::take` and back, so `Easy` has no
    "None during perform" field.
17. **No admin easy.** Connection-level work, a connect drive included, takes a connection
    context (`ConnCx`, §4.7) with settings captured per connection.
18. **The clock is owned** (`Box<dyn Clock>`), read by the drive before each step and passed
    down as `now`.
19. **Sockets and polling live in `curl-os`** (`net.rs`, `poll.rs`, behind a `net` feature);
    `curl-core` depends on it and adapts it in safe code. Only `conn::*` and `multi::wait`
    touch sockets.
20. **C's read cap at `size - bytecount` is kept**, deliberately, for byte-identical `DATA_IN`
    traces and reuse decisions, until a C-leg comparison on 1701 and 3223 shows it can go.
21. **C's two-anchor total timeout is ported as is** (wake-up from the leg start, lateness from
    the operation start), both judged from the report's `Starts`. A single anchor needs a test on the C
    build reproducing the late wake-up first.

**Delivery**

22. **Compatibility wins over efficiency.** Where the two pull apart, the engine does what C
    does, and a more efficient variant can come later as an opt-in. Section 9 lists the choices
    this settles.

---

## 2. Module and type layout

### 2.1 Crates

```
curl-alloc    fallible Box, Vec and String growth, TryRc and TryArc; the debug build's tracker
curl-os       the OS interfaces as safe functions: the command line, the environment, the
              terminal, local time, users, random bytes; sockets, poll(2), the system's
              resolver and the waker (feature "net"); files (feature "fs")
curl-core     #![forbid(unsafe_code)]; depends on curl-alloc and curl-os ("net", "fs")
curl-psl      libpsl, the public suffixes cookies are checked against
curl-zlib     zlib's inflate, curl-brotli brotli's decoder, curl-zstd zstd's decoder: the
              content codings, behind `curl_core::coding::Decoder`
curl-openssl  OpenSSL 3.0 or later through openssl-sys's declarations: Ed25519 for HTTP
              signatures, behind `curl_core::libraries::Ed25519`; the TLS backend behind
              `curl_core::tls` (§4.9)
curl-sys-abi  the shim: handles, frames, callback adapters, generated setopt and api table
curl-tool     drives transfers through the Rust API
```

`curl-os` exposes safe functions; it does not implement `curl-core` traits (that would be a
dependency cycle). `curl-core::conn::io::SystemNet` adapts `curl-os` to the `Net` trait in safe
code. The libraries the core does not depend on (libpsl, the decoders, the Ed25519 signer, the
TLS library and the GSS-API library) are handed to a handle by whoever builds it: the shim and
the tool. The decoders, the signer, the TLS library and the GSS-API library come as one
`Libraries` (`curl_core::libraries`), which a handle holds as `SharedLibraries`, as it holds its
`Components`: the shim's are statics (`SharedLibraries::of_static`), the C ABI's one owned root;
the tool's are made by `main` and shared with its handles (`SharedLibraries::new`, the TLS
library owned by them, `Library::Owned`), so it keeps no static. A handle given none has
`Libraries::NONE`. The TLS library is OpenSSL's (`curl_openssl::OpenSsl`); the GSS-API library
is MIT krb5's (`curl_gssapi::GSSAPI`, behind `curl_core::gss::Gss`), with C's debug stub under
`debug-hooks`, chosen per context by `CURL_STUB_GSS_CREDS` as C's wrappers choose per call. The
shim and the tool each have a second static without it and hand a handle the one the build's
GSS-API claim picks (`HAVE_GSSAPI` is C's library being linked): unclaimed, SOCKS5 offers no
GSS-API, as a C build without it. Each initialises OpenSSL as C's
global init does (`OPENSSL_init_ssl` with the configuration and the built-in engines): the shim
at `curl_global_init`, the tool as it starts; the signer does it again before it signs, so a
program that never called `curl_global_init` signs the same.

### 2.2 `curl-core` modules

```
curl-core/src/
  error.rs, error/kinds.rs   Error, ErrorKind (kinds generated by gen/errors.py)
  date.rs                    the date parser (parsedate.c), pure
  version.rs                 the features and protocols this build reports
  time.rs                    Instant, TimeLimit, Clock, SystemClock, ManualClock (test-util)
  id/                        Arena<T>, ArenaPolicy, Key<T>, TransferId; C's mid order (generated)
  url/                       Url and its parts; urlapi.c-compatible parser (host, path, encode,
                             schemes)
  options/                   typed config groups: Network, Http, Output, Limits, Callbacks…,
                             the seldom-set ones in `Cold<T>`; script.rs: what the test
                             protocol `script:` plays (test-util)
  easy.rs                    Easy, Easy::perform
  report.rs, report/         TransferReport, Timings, Starts, Sizes; HeaderStore, HeaderCursor
  handler.rs                 handler traits, their verdict enums, Handler
  trace.rs, text.rs          failf/infof: a failure's reason and text lines, on a stack buffer
  components.rs              Components, Component, Level: which components trace
  share.rs                   Share, Kind, ShareLock: what transfers of several handles keep
  cookie.rs                  Jar, Cookie, Suffixes: the cookie jar (cookie.c)
  hsts.rs                    Hsts, HstsEntry, HstsReader, HstsWriter: the HSTS cache (hsts.c)
  altsvc.rs                  AltSvc, AltSvcCtrl, Alpn: the alt-svc cache (altsvc.c)
  idn.rs                     Idn, IdnFailure: host names in Unicode, converted by a library
  http2.rs, http2/           Http2, Session, Event: the seam an HTTP/2 library implements;
                             fake.rs: FakeH2, frames as lines (test-util)
  netrc.rs                   .netrc files: the file's path, its entries for a host
  coding.rs                  Coding, Decoder, Decoders, AcceptEncoding: the content codings
  libraries.rs               Libraries, SharedLibraries, Library, Ed25519: what the bound C
                             libraries do for a handle
  gss.rs                     Gss, GssContext: the seam a GSS-API library implements
  tls.rs, tls/               TlsIdentity, the seam a TLS library implements (TlsBackend,
                             TlsSession, TlsIo, TlsPeer, TlsWait); cache.rs: SessionCache,
                             SessionPeer, TlsTicket (vtls_scache.c); keylog.rs: KeyLog,
                             SharedKeyLog;
                             fake.rs: FakeTls (test-util)
  hash.rs                    MD5, SHA-256 and SHA-512/256, for Digest
  save.rs                    a file written whole under a name of its own, then renamed
  multi/
    mod.rs                   Multi<H>, Host, Slot, ConnLimits, the public API
    state.rs                 Run, TransferState and its variant structs, StepCx, the steps;
                             state/tunnel.rs, state/socks.rs, state/haproxy.rs,
                             state/tls.rs: the CONNECT and SOCKS handshakes, the PROXY
                             line and the origin's TLS handshake a transfer makes;
                             state/https.rs: the HTTPS connect filter heading an
                             https setup, its HTTPS-RR lookup and its timer
    mstate.rs                MState: where a transfer is in C's states, for the trace
    sched.rs                 RowSet (the dirty set), Counts, Tally
    timers.rs                Deadlines, TimerQueue, TimerAnnounce
    sockets.rs               SocketTable, pollset diff, announce
    notify.rs                NotifyQueue, Notification, NotifyKind
    check.rs                 the debug build's invariant check
    cx.rs                    EngineRest, TransferCx, EventCx, NotifyCx, CloseLater
    wait.rs                  wait, the waker, drive_to_completion over Net
    props.rs                 random call sequences checked against a model (tests)
  conn/
    mod.rs                   Caches, ConnSlot, Conn, Route, ProxyRoute, Tcp, Scheme, Peer,
                             Transport, ConnNumber
    pool.rs                  Pool, ConnLease, ReuseRules, Released
    connect.rs               ConnectMachine, Eyeballs, Racing, Dialed
    proxy.rs                 the proxy a transfer goes through: the options' or the
                             environment's, the no-proxy list, a proxy URL parsed
    socks.rs                 the SOCKS4, 4a and 5 handshakes, sans-IO
    socks/gss.rs             SOCKS5's GSS-API method (RFC 1961), states of the same
                             handshake
    connect_to.rs            the CURLOPT_CONNECT_TO entry matcher and parser
    dns.rs                   DnsCache, Answer, the CURLOPT_RESOLVE entry parser
    buf.rs                   RecvBuf
    io.rs                    Net, Socket, SystemNet, FakeNet (test-util)
    stream.rs                Stream: a socket, its layers and its receive buffer
    layer.rs                 Layer, Below, LayerStack, LayerCx; the tests' layers
    tls.rs                   TlsLayer: the layer over a TLS library's session
    shutdown.rs, shutdown/   ShutdownSet, ConnSettings: connections saying goodbye
    chain.rs                 Chain: C's filter chain rendered for the trace from how
                             far the setup got, the handshake under way and the route
  deliver/                   BodyAccountant, ClientOut; held.rs: HeldOutput;
                             decode.rs: Gate, the decoders' chain;
                             pause.rs: Pause, PauseRequest, Directions
  progress/                  Speedometer, the low-speed check; meter.rs, the meter's text
  upload/                    Upload, Readout (C's client readers); chain.rs: Body, Chain
  mime/                      Mime, Part, Content, Encoder, MimeSource; read.rs: MimeReader
  proto/
    mod.rs                   ProtoState (File, Http; test-util: Null, Stall, Script, Tcp),
                             Before, Ended
    file.rs
    http.rs, http/           the HTTP driver: the request sent, the response read;
                             h2.rs, the request's HTTP/2 stream; cookies.rs (the jar as
                             HTTP uses it), sigv4.rs, httpsig.rs; suite.rs, C's test
                             cases over the fake network
    http2.rs                 H2Conn: a connection's HTTP/2 session and its output; the
                             request's head read back into fields
    script.rs                the test protocol `script:` (test-util)
    http1/                   the parsers and the renderer, sans-IO, which import nothing of
                             the driver: request.rs, response.rs, framing.rs, chunked.rs
                             (decoder and encoder), fields.rs, follow.rs (where a
                             `Location:` leads, HTTP's `Inherited`); auth.rs (Basic, Bearer, the challenges a
                             head reads), digest.rs; tunnel.rs, CONNECT and the proxy's
                             answer; fixture.rs, the test cases' sections (tests)
  untrusted.rs, test_cell.rs input for the never-panics properties; a Cell for handlers (tests)
```

Planned, not built: `conn/mux.rs`; a `Resolver` for names the cache and the shortcuts do not
answer; and `DebugNet`.

### 2.3 Ids and the arena

```rust
pub struct Key<T> { row: u32, generation: NonZeroU32, _of: PhantomData<fn() -> T> }  // Copy, Eq
pub struct ArenaPolicy { initial: u32, reserved: u32 }
impl ArenaPolicy {
    pub fn new(initial: u32, reserved: u32) -> Option<Self>;  // None unless a row is left to hand out
}
impl<T, K = T> Arena<T, K> {                     // values T, keys Key<K>
    pub fn new(p: ArenaPolicy) -> Result<Self, OutOfMemory>;
    pub fn reserve(&mut self) -> Result<Vacancy<'_, T, K>, OutOfMemory>; // grows by the policy
    pub fn get(&self, k: Key<K>) -> Option<&T>;                // stale key: None
    pub fn get_mut(&mut self, k: Key<K>) -> Option<&mut T>;
    pub fn remove(&mut self, k: Key<K>) -> Option<T>;          // bumps the generation
    pub fn next_after(&self, k: Option<Key<K>>) -> Option<Key<K>>; // ascending row cursor
    pub fn key_at(&self, row: u32) -> Option<Key<K>>;
}
impl<T, K> Vacancy<'_, T, K> {
    pub fn rows(&self) -> u32;                                 // to reserve the other tables
    pub fn fill(self, v: T) -> Key<K>;                         // cannot fail: the row is free
}
pub enum Transfer {}                              // TransferId's marker: Slot stays private
pub type TransferId = Key<Transfer>;
pub struct ConnNumber(u64);                       // monotonic per pool: "Connection #N"
pub(crate) type ConnId = Key<ConnSlot>;            // the Conn carries its ConnNumber
```

Slot selection copies `Curl_uint32_tbl_add`: scan for a free row from `last_added + 1`, wrap
from the first unreserved row; grow when fewer than `max(capacity/8, 4)` rows are free, by
`clamp(capacity/2, 128, 2048)` (multi.c:419-440). Because `curl_multi_info_read` and
`multi_perform` walk ascending mids, matching the policy keeps message order identical to C
under add/remove churn (751). `reserve` then `fill` is the add: `add` reserves rows in every
table it needs before it fills any, and filling cannot fail. The test replays a seeded churn
whose ids `gen/arena.py` records from C's real multi, built against the C build's `libcurlu`.

The policy is a value, not constants in the core:
- the shim passes `ArenaPolicy::new(128, 1)` for `curl_multi_init` and `new(16, 1)` for the
  private multi of `curl_easy_perform` (multi.c:53, easy.c:805). Row 0 stays unused only so
  that indices equal C's mids, where the admin easy holds mid 0; the core has no admin easy.
- the Rust API's default is `new(16, 0)`.

`ConnId` folds C's `(last_cpid, last_conn_id)` pair into one value. CONNECT_ONLY's "last
connection" (`ACTIVESOCKET`, `curl_easy_send`/`recv`) is an ordinary lookup that fails on its
own when the connection is gone. What `CURLINFO_CONN_ID` reports is only the connection's
number, kept in the transfer's report as it attaches and dropped when the pool closes the
connection as it comes back; `CURLINFO_XFER_ID` is a number the pool (the share's if it keeps
connections) hands each transfer that joins it, kept in the report across its restarts.

### 2.4 Time

```rust
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);                         // µs since the clock's epoch; saturating ops
pub struct TimeLimit(NonZeroU64);                // ms; C's 0 ("no limit") is None
pub trait Clock: Send { fn now(&self) -> Instant; fn unix_time(&self) -> i64; }
pub struct SystemClock { base: std::time::Instant }
#[cfg(any(test, feature = "test-util"))]
pub struct ManualClock(TryArc<ManualTime>);       // tests hold a second handle and advance it
```

`Multi` owns `Box<dyn Clock>`. A pass reads `now` at entry, and the drive reads it again before
each step of a transfer, as C's `multi_runsingle` does at the top of its loop: a step that took
time (a `file:` transfer's, a slow handler's) is timed, and checked against its time limit, as
the next step starts. Steps, decoders, limiters and filters receive `now` as an argument and
never read the clock. `socket_action` keeps C's second read after it ran something (§3.5).
Timing records (`Timings::mark`) take the step's `now`; under
`ManualClock` everything is deterministic. The calendar time (`unix_time`, C's `time(NULL)`)
comes from the same clock, read where a date is compared with the present (a Retry-After
date) and never for a limit; `ManualClock::set_unix_time` sets it for a test.

### 2.5 Errors and outcomes

```rust
pub struct Error { kind: ErrorKind, detail: Option<Vec<u8>> }  // detail dropped on OOM, kind kept
pub enum Recv { Data(NonZeroUsize), Eof, WouldBlock }
pub enum Sent { Bytes(NonZeroUsize), WouldBlock }
pub enum Acquired { New(ConnLease), Reused(ConnLease), Wait(WaitReason) }
pub enum WaitReason { HostLimit, TotalLimit(NonZeroU32) }  // Multiplexable(ConnId) with HTTP/2
pub enum ConnectStep<S> { Pending(Interest, Option<Instant>), Next(S), Restart(RestartReason) }
pub enum Wake { Again, Idle }          // Again: run this transfer again in the same pass
```

A failure's reason is given where it happens: `trace::fail(cx, kind, args)` (`failf`) formats it
on the stack, at most 255 bytes as `CURL_ERROR_SIZE` allows, keeps the first one a transfer gives
in its report (`TransferReport::failure`, cleared when the report restarts) and traces every
one as a text line for a verbose transfer. `Easy::perform`'s `Error` carries a copy; the shim
copies it into ERRORBUFFER. `trace::info` (`infof`) traces a line only for a verbose transfer,
cut at 2048 bytes and marked `...` as `trc_end_buf` does, so a quiet transfer formats nothing.
Text goes to the debug handler, or without one to the STDERR sink after `* `. The debug build's
"!!! WARNING !!!" lines go to the first transfer added to a multi, at its first step rather than
inside `add`, which has no transfer context. `trace::debug_info` is C's `DEBUGF(infof(...))`: a
line only the debug-hooks build traces, under plain verbose, at the point C's debug build does
(HTTP's sends and their end, the 100-continue reader's states, the end of the connection, a
failed read pass and a failed pass, `file:`'s range).

Which components trace is a `Components` handle (`components.rs`): a `Level` per `Component`,
C's trace features and filter types (its DNS feature and DNS filter share a name, so they are one
component), parsed from C's configuration syntax (`all`, `protocol`, `network`, `proxy`, a name,
each after an optional `+` or `-`). Copies share one setting, read at each line, so a change
shows in transfers already running. `Easy` holds it outside its options, kept through `reset` and
by a copy of the handle; without one, only lines of no component are traced. The shim gives every
handle the process's, a static `Levels` beside its root that `curl_global_trace` sets (and the
debug build's `CURL_DEBUG` after it); the tool owns one, set by `--trace-config` and each `v`
past the first of `-vv`. A component's line is traced when the transfer is verbose and the
component is on, after `[NAME] `. With `LIB-IDS` on, every line but a failure's reason starts with `[T-C] ` (`x` for
a number the transfer has none of), and so does what `trace::bytes` (`Curl_debug`) gives the
debug handler, when it fits a trace line. Not traced: what C traces on the multi's internal handle,
verbose only under `CURL_DEBUG`, and the source line number C's debug build adds to a state change.

`WRITE` follows a response through C's writer chain, which the pipeline (`deliver/`) stands
for: each write at the chain's start (`client_write`, `xfer_write_resp`), the transfer and
content decoders stacked as their header is read, the chunked decoder's chunks and trailers, the
header store (`header_collect`), the download writer (`download_write`), the gate in front of
the content decoders (`[PAUSE]`) and the handlers (`[OUT]`), with C's numeric write types and
results. A `Transfer-Encoding` list is read by the head parser, which has no context to trace
in; the line it hands out carries a `CodingTale` the protocol retells, before the line, as C
traces while it reads.

`MULTI` follows C's state machine (`multi/mstate.rs`): each slot keeps the `MState` C would be
in, which every multi line names, and a change is traced in the state left. The engine's states
fold several of C's (INIT runs C's INIT and SETUP and starts its CONNECT), so the step enters C's
at the points C passes them, and after each step the state is brought to the one the engine's
names; a request that failed stays where it failed, as C's is done with there. Traced: the
changes, the times taken (`[PGRS-*]`), the transfer's coming and going, `[CPOOL]`'s new
connection, `Curl_conn_setup`, `multi_done`'s lines, and the chain C's filters make
(`Curl_conn_trc_filters`), rendered by `conn/chain.rs` from how far the setup got, the
handshake under way and the route, as no filter object exists to name itself: `cf_setup_connect
[0][…]` as SETUP's connect is entered (once a call of `Curl_conn_connect` finds the name resolved,
again as it adds a filter and as it starts over), `connected [0][…]` and `reduced to [0][…]` as
the connection is up, and `failed to connect [0][…]` before `connect failed -> N`, for a failed
race and a failed handshake alike; `Curl_multi_will_close fd=N` as a drive closes a socket
(`DriveCx`), which a socket a connection keeps is not, as C closes it on its internal handle.
A transfer's pollset is traced wherever C makes one (`Curl_multi_pollset`): `pollset[…],
timeouts=N` (`paused S/R (r/w)` for an empty one), for each transfer the multi works on (neither
completed nor PENDING) as `wait` and `sockets` (`curl_multi_fdset`, `curl_multi_waitfds`)
collect them, and for the transfer event handling assesses, after each run and as it is taken
out; then `wait`'s `multi_wait(fds=N, timeout=T) tinternal=I` on the last of them, after the
multi's own timeout is read, the waker counted in `fds` as it is watched (§3.6). A socket
action traces `multi_run_dirty` as it comes to each dirty transfer. Not traced: the credentials
line (`Curl_creds_trace`), `xfer_setup` and `[TIMEOUT]`; event mode's socket-hash
lines (`ev new entry`, `ev entry … added transfer`, `ev update`, `ev update call`, `ev last user
gone`), which count the readers, writers and owners of C's socket hash entries, a bookkeeping the
engine's `SocketTable` does not keep in that form. A transfer let out of PENDING enters CONNECT
as it is let, traced on it then (`move_pending_to_connect`), so a wait before it runs collects its
empty pollset.

`TCP` traces each send and receive on a transfer's connection, and the PROXY protocol's line,
with what it asked for and what it came to. Through the drive's context (§3.6), it traces an
attempt's socket as `cf-socket.c` does: its opening (`cf_socket_open() -> 0, fd=N`) and local
address after `Trying`; at each check of its connect, `not connected yet on fd=N`, `connected
on fd=N`, or `poll/select error on fd=N` for one that polls in error or hung up; and `destroy` as
its filter goes: after the failure's `connect to … failed` for a failed attempt, and before
`cf_socket_close, fd=N` and the multi's `Curl_multi_will_close` for a socket still open (the
race's losers and its oldest attempt pruned, and a 407's redial). A connection that leaves the
pool traces no `destroy`, as C closes it on its internal handle. With a pollset made while the
connection is set up, the socket's part in it: `adjust_pollset, !connected, POLLOUT fd=N` for
each attempt, and `adjust_pollset, !active, POLLIN fd=N` for the socket a handshake runs over,
which waits to read throughout as C's filter, connected but not in use, adds. A socket whose
connect fails at once traces its opening, `Immediate connect fail`, its close and the failure,
as C does. Not traced: the health check's `is_alive`
lines, which the pool's check makes with a silent context where C traces them on the transfer
looking for a connection. Not traced: the receive
C tries before its first poll in PERFORMING, which the engine does not make; a tunnel's and
SOCKS handshake's reads and writes, as C reads a proxy's answer to `CONNECT` a byte at a time
from the socket, where the engine reads what is there.

`SETUP` traces cf-setup.c's lines as the transfer's step meets the points C passes: `added` as
a new connection's setup starts, `happy eyeballing to origin|proxy H:P` as the race starts,
`added SOCKS filter to H:P`, `added HTTP proxy tunnel filter` and `added HAPROXY filter` as each
handshake starts, `retrying connect, N. time` as a 407 redials, and `removing connected setup
filter` and `destroy` as the connection is up. `HTTP-PROXY` and `HAPROXY`, setup filters too,
trace their removal and `destroy` with it, and the tunnel's two filters (`HTTP-PROXY`,
`H1-PROXY`) their `destroy` as a redial discards them.
Not traced: the `HAPPY-EYEBALLS` and `DNS` filters' removal and destruction (below), and the
`SOCKS`, `HTTP-PROXY` and `H1-PROXY` components' own lines: SOCKS's state changes, which name
C's machine's states and source lines where the engine's sans-IO handshake has states of its
own, and its `adjust pollset in (N)`; the tunnel's `CONNECT`, `installing subfilter`, `connect`,
`CONNECT send`/`receive`/`response`, `new tunnel state` and its header lines, which follow C's
two filters (HTTP-PROXY installing H1-PROXY) and its byte-at-a-time read of the answer.

`TIMER` names each of a transfer's timers by C's `expire_id` (`TimerKind::name`; the protocol's
own wait is HTTP's for a 100, the only one there is) where C arms or clears it: the leg's limits
as it starts, the low-speed check, the rate limits, the next connect attempt and the wait for a
100, each with what is left of its wait read from the clock as it is traced; the race's timer as
its attempt connects and the 100's as it comes, runs out or the body ends. The first timer due
is named as a socket action fires it; a perform fires it silently, as C's does. With the
multi's lines on, each armed timer's `[X] expires in Nus` follows its transfer's pollset line,
the first to fire first (`Deadlines::in_order`). `[X] gives multi timeout in Nms` names the timer
the multi waits for, on its transfer, when nothing is ready (`multi_timeout`, which `wait`, the
timer update and `Multi::timeout_traced`, the shim's `curl_multi_timeout`, call);
`Multi::timeout(&self)` stays untraced for Rust callers.

`HAPPY-EYEBALLS` traces the connect machine's race (C's `cf_ip_ballers_run`), the drive its
steps and the transfer what a drive reports: each attempt as it starts, the first or the next
and its family, the start of the next as the delay runs out, the oldest attempt discarded to keep
the limit, the winner by its place among the attempts running before the losers close, the delay
armed while an address is left, the peer it connected to, and the end of a race with no attempt
left. As C goes back over the running attempts after starting one (`goto evaluate`), the drive
checks them again before the new attempt's socket opens: one connecting then wins without it,
and one failing then goes as it opens. Not
traced: the filter's own life (`init ip ballers`, `adjust_pollset`, its removal and
destruction) and the walk over the addresses (`want to do more`, `check for next`, `checked
connect attempts`), which describe C's structures rather than a step the machine takes.

`DNS` traces the lookup of the name a connection goes to first, from what the connect machine
reports (`Found`, `Unresolved`): the cache looked in, found, missing, stale or holding the
resolver's no; what answered a name it did not have, a shortcut at once or the resolver later as
the reference build's c-ares does; the answer kept, or the no. The queries are named as the IP
version and an address's own family make them; the debug build's `hostip_resolv` line comes with
the `debug-hooks` feature. Not traced: C's DNS filter's own life (`created DNS filter`, `added`,
`cf_dns_start`, `connected filter chain below`, its removal and destruction), its reading of the
answer (`get Nth result`), the chain's connect result C traces under the top filter's name
(`Curl_conn_connect(block=0) -> R, done=D`, `filter returned R`), c-ares's polling (the cache looked in again at each poll, `resolve incomplete`, `still waiting`),
and a SOCKS proxy's lookup of the destination.

The TLS components, as the reference build traces them on the transfer. `SSL` (the origin's
layer) traces the handshake as it is driven (`cf_connect()`, `ossl_connect, step1|2|3`,
`SSL_connect() -> err=-1, detail=2`, `want recv`, `cf_connect() -> R, done=D`, `ossl_connect,
done`), each read and write its BIO makes on the layer below with the length OpenSSL asked for
(`ossl_bio_cf_in_read(len=5) -> 81, 0`, under the `TCP` line of the same call), each receive
with the caller's length and what OpenSSL still holds (`ossl_recv(len=102400) -> 0, 44
(in_pending=1)`), `configuring OpenSSL's x509 trust store` at the first read, and
`adjust_pollset, POLLIN fd=N` (or `POLLOUT`) while its session waits, connecting or not, above
the socket's own pollset line. Its first connect checks the versions allowed first
(`ssl_prefs_check`): a newest older than the oldest fails it, `CURL_SSLVERSION_MAX incompatible
with CURL_SSLVERSION`. Without a component, as text lines: `ALPN: curl offers …`, `SSL
connection using …`, `ALPN: server did not agree on a protocol. Uses default.`, the `Server
certificate:` block, the trust anchors, the verification's lines; and the msg callback's
handshake lines (`TLSv1.3 (OUT), TLS handshake, Client hello (1):`) beside the record bytes as
SSL data. `HTTPS-CONNECT`, the filter C puts above SETUP for an `https` origin with ALPN on and
no forwarding proxy (`multi/state/https.rs`), is rendered in the chain with the DNS filter that
asks for the origin's HTTPS-RR above the name's (`[0][!DNS][!DNS][!HTTPS-CONNECT][!SETUP]`, one
DNS filter for an address) and traces `added` in place of SETUP's, `connect, init`, `HTTPS-RR
not available`, `1st attempt uses h1 from wanted versions`, its `connect -> R, done=D` at the end
of each connect call (after `connect, all attempts failed` for a failure, whose chain C names
truncated at it) and `adjust_pollset -> 0, N socks`. `query ALPN` is traced by the filter a
question of what ALPN agreed is asked of: by `SETUP` as the HTTPS connect filter's attempt
wins, by `HAPPY-EYEBALLS` or `SOCKS` under a tunnel's `CONNECT`, and by the top of the chain as
HTTP starts on a new connection (`http_check_new_conn`: `[TCP]`, `[UNIX]`, `[SOCKS]`,
`[H1-PROXY]`, `[SSL]`); the TLS layer adds what it answers (`query ALPN: returning
'http/1.1'`, `'(nil)'` for none). Each call of the chain's connect ends with its top filter's
`[DNS] Curl_conn_connect(block=0) -> R, done=D`. `SSLS` traces the session cache's lookups,
additions and takings as C's (§4.9). `SSL-PROXY` traces an HTTPS proxy's TLS layer as `SSL`
traces the origin's, its part of a pollset said once, and twice once a tunnel through it is made
(the tunnel's filter asks it again); a tunnel's filter keeps the ALPN question it is asked, so
the proxy's layer answers only when it is the top. The tunnel's answer is read through it a
byte at a time, as C's `recv_CONNECT_resp` reads, each read the socket's. C's `[SHUTDOWN]` lines and a
shutdown's TLS lines are its internal handle's, so not traced (§4.6).

`READ` traces a request's body as C's client readers read it: the reader set as the request is
built (`add buf reader`, `add fread reader`) and each read of it, by the reader C would have, a
buffer, the application's read handler or a mime tree (`cr_buf_read`, `cr_in_read`,
`cr_mime_read` with its special sizes), the line-end conversion and the chunk stage around it
(`cr_lc_read`, `http_chunk`), and `client_read` with the
room the request's buffer had; a body held for a 100 is asked for and gives nothing. The
readers are reset as a request starts and as it ends without error, kept to be rewound when the
next request is to send the body again (a redirect or 417 that asks it, a retry always), and
rewound before that request is issued. A pause the read handler or a tree's part asked for,
lifted, is told to each reader C would stack, by name from the network's side (`unpausing
chunked/cr-exp100/cr-lineconv/cr-in|cr-mime -> 0`, `Curl_creader_unpause`): the slot keeps which
those are, set as HTTP makes the body and let go with the readers, since the lift mostly comes
from a handler while the run is out. Not traced: C's rewind mechanics by name (`cr_in, rewind
via ...`).

Outside a transfer the handle's `DebugHandler` is not reached: it takes a `TransferCx`, which a
handle in no transfer has none of. What C traces there (`CURLOPT_COOKIELIST`'s commands, as
they are set) is handed to a `notes` closure the caller passes, line by line in the transfer's
own formatting; the shim sends those lines to the debug function, or the STDERR stream, once
the handle is no longer borrowed, so the function may call back into it.

C's `CURLE_AGAIN` has three meanings (would-block, "rebuild the sub-chain", "nothing yet") and
"OK with 0 bytes" means EOF; here they are distinct variants. `NO_CONNECTION_AVAILABLE` is
`Acquired::Wait`, never an `Error`. The core's generated enums (`ErrorKind`, `MultiErrorKind`,
`UrlErrorKind`) hold only the codes the core produces; `gen/errors.py` lists the codes only
libcurl's C API produces (`SHIM_ONLY`) and generates them into the shim's `EasyError`,
`MultiError` and `ShareError`, each beside the core's kind and mapped to C with no wildcard.
Shim-only: `CURLE_AGAIN`, `CURLE_NO_CONNECTION_AVAILABLE`, `CURLE_RECURSIVE_API_CALL`,
`CURLE_UNKNOWN_OPTION`; every multi code but out of memory, a bad easy handle, an abort by
callback and an unrecoverable poll; and every share code, as the core's share fails only with
its own `InUse` and `OutOfMemory`. TLS's codes stay in `ErrorKind`, which TLS will produce.
The number of `CURLE_AGAIN`, which the core traces (`-> 81`) but never returns, is a generated
constant of the core's.

### 2.6 Easy

```rust
#[derive(Default)]                 // Default allocates nothing
pub struct Easy {
    options: Options,              // typed groups; handlers are Option<Box<dyn …>> inside
    report: TransferReport,        // the current or last transfer's; replaced whole at Init
    private: Option<Box<Multi>>,   // perform's multi, created on first perform with a waker
                                   // as C's has one, kept after
}
impl Easy {
    pub fn perform(&mut self) -> Result<(), Error>;
    pub fn report(&self) -> &TransferReport;
    pub fn options_mut(&mut self) -> &mut Options;
    pub fn try_clone(&self) -> Result<Easy, OutOfMemory>;   // duphandle: options only
    pub fn reset(&mut self);                                 // keeps `private`, as C
}
```

`perform`:
1. takes `self.private`, or creates it (`ArenaPolicy { initial: 16, .. }`, one `try_box`);
2. `let easy = mem::take(self)`, which leaves an allocation-free default behind;
3. `multi.add(easy, (), &mut NoEvents)`, then `drive_to_completion`, then `remove`;
4. writes the returned `Easy` back into `*self` and puts the private multi into it.

Connections and DNS persist in the private multi across performs (1512, 3208).
`Multi::add` drops an added `Easy`'s private multi (C's `multi_easy` destruction at
multi.c:495), by `Drop`.

### 2.7 Multi, slots and the transfer

```rust
pub trait Host { type Transfer; type Socket: Copy; } // app values per transfer and per socket
pub struct NoHost;                                // Host<Transfer = (), Socket = ()>

type Slots<H> = Arena<Box<Slot<H>>, Transfer>; // boxed, as C's rows hold pointers

pub struct Multi<H: Host = NoHost> {
    slots: Slots<H>,
    dirty: RowSet,                   // transfers to run at the next pass
    timers: TimerQueue<Transfer>,    // one entry per slot, reserved at add
    announce: TimerAnnounce,         // what the timer callback was last told (unit 3230)
    notify: NotifyQueue, delivering: bool,
    caches: Caches,                  // the connection pool and the DNS cache
    tls: Option<TlsShared>,          // what the TLS library keeps across its connections
    shutdowns: ShutdownSet,          // the connections saying goodbye, whichever pool they left
    limits: ConnLimits,              // MAXCONNECTS, MAX_HOST_CONNECTIONS, MAX_TOTAL_CONNECTIONS
    pending_after: Option<TransferId>, // the transfer last let look for a connection again
    sockets: SocketTable<H::Socket>, // fd → users and what each waits for, told, assigned value
    clock: Box<dyn Clock>,
    net: Box<dyn Net + Send>,
    ipv6_works: bool,                // as the network said once (`Curl_probeipv6`)
    waker: Option<TryArc<Waker>>,
    counts: Tally,
    life: Life,                      // Alive | Dead (a callback returned Abort)
    #[cfg(feature = "debug-hooks")]
    warned: bool,                    // a transfer was told the library is a debug build
}

struct Slot<H: Host> {
    owner: H::Transfer,
    easy: Box<Easy>,                 // options + live report; reachable from contexts
    pause: Pause,                    // reachable while the run is out (§3.6)
    judge_pause: bool,               // its own handler paused while it was out
    speedometer: Speedometer,        // beside the pause, which starts it over
    rate: RateLimits,                // the speed limits' buckets, which the pause starts over
    run: Option<Run>,                // see below
    mstate: MState,                  // where it is in C's states, for the trace
    readers: Option<Readers>,        // C's readers of the body, for the unpause trace
}
pub(crate) struct Run {              // created at add, dropped at removal
    state: TransferState,
    deadlines: Deadlines,
    url: Vec<u8>,                    // the request's URL read back whole (C's state.url)
    retries: u8,                     // fresh connections tried this transfer (retrycount)
    first: Option<Origin>,           // the first request's origin (state.initial_origin)
    method: Method,                  // the method, as a redirect changed it (state.httpreq)
    allow_port: bool,                // CURLOPT_PORT still applies (state.allow_port)
    http: follow::Inherited,         // what HTTP's next request takes, HTTP's alone: HTTP/1.0
                                     // seen, Expect refused, the custom method dropped
    last_conn: Option<ConnId>,       // the connection it had last, tried first (§4.6)
}
```

Planned with the step that needs it: an internal owner for transfers the engine makes itself
(`Owner::Internal`, with server push).

A row holds its slot boxed: a slot is most of a kilobyte, and a table starts with C's sixteen
rows, which C's limits on a transfer's memory count as pointers (libtest 500).

The `Easy` is boxed on its own and handed in and out by that box (`Multi::add` takes a
`Box<Easy>`; `Removed` and `AddError` give it back): the C shim keeps a handle's `Easy` in the
same box while it is on its own, so its options and report exist once, wherever the handle is,
and a handle's memory is one `Easy`, not one in the shim's handle and a second in the slot
(libtest 751 adds a thousand handles under a cap). The `Run` lives in the slot, as C's
per-transfer state lives in its `Curl_easy`: one allocation at `add`, not two.

`Slot.run` is `None` in exactly one situation: while the engine has moved the `Run` out to
run it (a step, or `pause_transfer`'s replay of held output), and for that duration the slot is reachable only through `EngineRest`, whose methods
treat the missing run as "this is the transfer being stepped". It is not a lifecycle flag: the
`Run` exists from `add` to `remove`, and `TransferState::Init` and `Completed` are its first and
last variants.

`Multi` borrows nothing: it owns its clock, its `Net` and its caches, so it can move into an
`Easy` or a shim handle.

### 2.8 Handlers

```rust
pub enum Write { Accepted, Pause, Fail, Took(usize) } // Took(n != len) fails, as a short count
pub enum Read { Data(NonZeroUsize), Eof, Pause, Abort } // Data(n > buf.len()) is rejected, not asserted
pub enum ProgressVerdict { Continue, ContinueWithMeter, Abort }
pub trait WriteHandler  { fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write; }
pub trait HeaderHandler { fn header(&self, cx: &mut TransferCx<'_>, line: &[u8], o: HeaderOrigin) -> Write; }
pub trait ReadHandler   { fn read(&self, cx: &mut TransferCx<'_>, buf: &mut [u8]) -> Read; }
pub trait DebugHandler  { fn debug(&self, cx: &mut TransferCx<'_>, k: DebugKind, data: &[u8]); }
pub trait ProgressHandler { fn progress(&self, cx: &mut TransferCx<'_>, p: ProgressNow) -> ProgressVerdict; }
pub trait TextSink      { fn write(&self, text: &[u8]); }  // CURLOPT_STDERR; None is the process's
pub trait PrereqHandler { fn prereq(&self, cx: &mut TransferCx<'_>, p: &PrereqInfo) -> Result<(), Abort>; }
pub trait Rewind        { fn rewind(&self, cx: &mut TransferCx<'_>) -> Result<(), RewindFailed>; }
pub struct Handler<T: ?Sized>(TryArc<Box<T>>);    // Clone shares it; Handler::write(h) etc. box one
pub trait MultiEvents<H: Host> {
    fn socket(&mut self, cx: &mut EventCx<'_, H>, who: TransferId, s: SocketKey,
              what: SocketWhat, assigned: Option<H::Socket>) -> Result<(), Abort>;
    fn timer(&mut self, cx: &mut EventCx<'_, H>, t: TimerChange) -> Result<(), Abort>;
    fn notify(&mut self, cx: &mut NotifyCx<'_, H>, n: Notification);
    fn wants_sockets(&self) -> bool;     // C keeps socket bookkeeping only with socket_cb set
    fn wants_timer(&self) -> bool;
}
```

Handlers live in `Options::callbacks` as `Handler<dyn …>`, shared: a copy of the options
(`curl_easy_duphandle`) shares each handler, as C's copies share a callback and its userdata
pointer. So a handler is called through `&self`, and every handler trait is `Send + Sync`: a
copy of a handle sent to another thread calls the same handler, so its state is behind a lock
or an atomic. With that, `Easy` is `Send` (a compile-time assertion holds it), its private
multi too, whose clock and network are boxed `Send`; a multi is not `Sync`. The shim's
adapters, which hold a handle's pointer and the application's userdata, are declared `Send +
Sync` on C's contract that one thread at a time uses a handle.

`TransferCx` names no `Host`: the handlers live in an `Easy`, which has none. It wraps a
crate-private object-safe trait, `TransferCalls`, which the step context implements for each
`H`. The calls api.c allows a transfer callback that need `H` (a message's owner value, a
socket's assigned value) are offered without the `H` part or not at all.

---

## 3. The multi loop and the transfer state machine

### 3.1 Transfer states

```rust
pub(crate) enum TransferState {
    Init,                              // added, not yet run
    Pending(Plan),                     // PENDING: no lease, runs only when its time is up
    Setup(Plan),                       // CONNECT from PENDING: let look for a connection again
    Connecting(Connecting),            // holds a lease on a ConnSlot::Connecting
    ProtoConnect(Attached),            // PROTOCONNECT, PROTOCONNECTING
    Do(Attached),                      // DO..DOING_MORE
    Did(Attached),                     // DID: one step, to Exchanging or, with nothing to exchange, Done
    Exchanging(Attached),              // PERFORMING
    RateLimiting(Attached),            // RATELIMITING: over a speed limit, waits on its timer
    Done(Done),                        // multi_done pending; always holds the lease
    Completed(Completed),              // terminal until remove
}
type Origin = TryArc<Peer>;          // the request's peer, shared with its connection's route
pub(crate) struct Plan { proto: ProtoState, route: Tcp }  // the leg's route, built in start_leg
pub(crate) struct Connecting { lease: ConnLease, proto: ProtoState, route: Tcp,
                               handshake: Option<Box<Handshake>>,
                               https: Option<HttpsConnect>,       // the HTTPS connect filter
                               negotiate: Option<Box<Negotiate>> } // the tunnel's, across a redial
pub(crate) struct Attached { lease: ConnLease, proto: ProtoState, origin: Option<Origin> }
pub(crate) struct Done { lease: ConnLease, proto: Option<ProtoState>, result: Result<(), ErrorKind>,
                         premature: bool, reached: Reached, origin: Option<Origin>,
                         next: AfterRequest }
enum Reached { Unmade, Made, Exchanged }  // DID's times taken; the exchange ran to its end
pub(crate) enum AfterRequest { Complete, Retry, Follow { location: Vec<u8>, code: u16 } }
                                                  // the protocol's `exchanged` decides it
pub(crate) struct Completed { outcome: Result<(), ErrorKind>, message: Message }
pub(crate) enum Message { Unread, Read }
```

`Pending` and `Setup` hold what the setup made before it looked for a connection, so that only
the search is made again: the route, built once per leg, which `Connecting` keeps and reads its
destination and target from. Its IP version alone is read again as a waiting transfer looks
again, as C, which makes its connection anew then, reads `set.ipver`.

**The protocol decides what follows an exchange; the engine carries it out.** When an exchange
is complete, the engine asks the protocol (`ProtoState::exchanged`), which answers with an
`Ended`: `Then(next)`, the `AfterRequest` to go to `Done` with, or `Unfollowed(location)`, a
`Location:` the engine keeps where it would have led (FOLLOW_FAKE, generic in C's multi.c too).
HTTP's answer holds everything HTTP-specific: a 417 or an answerable 401/407 made again as a
`Follow` to the request's own URL, the challenges applied to `Easy::auth` and the report, a
redirect followed (§6.4); every other protocol completes. It is asked at the exchange's end,
before the progress pass that follows the step and before `multi_done`, as C's http.c sets
`req.newurl` while it reads the head: the progress callback sees the report already updated, and a
failure in deciding fails the request with it, premature. A retry is the engine's own
(`retry_request`, before the protocol is asked), and the protocol's `done` is told the
`AfterRequest` only to leave out "Empty reply" for a retry. The engine keeps the generic
follow mechanics of C's multi.c: the redirect limit, counting and resolving the location, the
port's leave, rewinding the body, "Issue another request", and starting the next leg
(`follow_leg`, `retry_leg`, `next_leg`); what a redirect changes of the next request is the
protocol's (`ProtoState::redirected`). The leg's `Plan` is built from where it leads.

**A speed limit is a state of its own** (`RateLimiting`, C's RATELIMITING), not a flag on
`Exchanging`. `Exchanging` asks the limits (`mspeed_check`) before its step and after one that
leaves the request going: over either, it moves to `RateLimiting`, its `TooFast` timer armed for
the wait and its run in the next pass called off; under them, the timer is armed for the next
tokens. `RateLimiting` waits on nothing but that timer (no pollset), and at each wake fails at
the time limit, takes the progress and low-speed check, and goes back to `Exchanging` at once
once the limits allow. C's state changes inside `mspeed_check`, so the move to RATELIMITING and
back is traced there, before the timer is armed, among its `[RLIMIT]` lines.

**A transfer runs as legs.** Init runs C's pretransfer once (the report restarted, `Starts::op`,
the option's URL parsed) and `start_leg` for the first request: `Starts::single`, the limits
armed, the application's CONNECT_TO list read again from its source (as C walks it for each
connection it sets up; the header lists are read again as each request and each `CONNECT` is
built), POSTQUEUE, the URL read back into `Run::url`, the protocol and a connection.
`Curl_retry_request` is the engine's: a request that got nothing back over a reused connection
(`ProtoState::retryable`: HTTP with no head line and no body byte), at the end of the exchange,
on a receive error, or on a send error at DO, closes the connection and goes to
`Done { next: Retry }`; the protocol's `done` then says no "Empty reply" (C's
`conn->bits.retry`), and the Done step parses `Run::url` again, traces "Issue another request to
this URL", counts a new request in the header store, marks REDIRECT, clears the expected sizes
and starts the next leg. The fifth retry of a transfer fails it with SendError.

- **The lease is released in exactly one place**: the `Done` step runs C's `multi_done` order —
  protocol `done` if past PROTOCONNECT, `pgrs_done` if past CONNECTING, then
  `pool.release(lease, verdict)` — and goes to `Completed`. Because `Done` owns the lease until
  that last step, a connection can never return to the pool before the protocol has finished
  with it. Output still held at `Done` is that of a failed request and is dropped with the
  protocol; a request that succeeds reaches `Done` only with nothing held (§3.2).
- **A failure without a connection** (Init's setup) goes straight to `Completed`. A failure
  holding a lease, from `Connecting` on, goes through `Done { result: Err(..), premature: true
  }`. `TransferState::fail(self, err)` picks the route from the variant, and a transfer already
  in `Done` or `Completed` keeps its result, as `multi_done` runs once. `abandon` is `remove`'s
  premature end.
- **`enter_completed` is the one exit hook for the report**: the times a jump to the end skipped
  and the total (`mstate_enter_completed`, `Curl_pgrsCompleted`); the step that enters
  `Completed` clears the deadlines and queues the message and EASY_DONE.
- Planned: **server push and `add_perform`** enter `Exchanging` through a typed constructor,
  `TransferState::pushed(lease, proto)`.

### 3.2 Per-request substates

A request's substates belong to its protocol, inside `ProtoState`; the engine sees only
`ProtoStep { Done, Blocked, AtReadLimit }` from a step and asks whether output is held. The HTTP driver
(`proto/http.rs`) keeps the head being sent (`out`, `sent`), the response's `Stage { Head,
Body(Body), Done }`, with `Body` the framing decided once at the end of the head (length,
chunked, until close), and whether the response is interim. Each C flag is a variant there:
`k->header` is `Stage::Head`, `download_done` is `Stage::Done`, and `chunk`, `ignore_cl`,
`http_bodyless`, `size`/`maxdownload` are the `Body` and the pipeline's `Expect`. The send side
is the send buffer with what of it has gone, and beside it one enum for where sending stands:

```rust
enum Sending { Idle /* before DO */, Head { left: NonZeroUsize, then: AfterHead },
               HeadSent, AwaitingContinue(Instant), Body(Reading), Done, Aborted }
enum AfterHead { Continue /* held for a 100 */, Body(Reading) }
struct Reading { eos_read: bool, announced: bool /* the head said Expect: 100-continue */ }
```

C's `sendbuf_hds_len` is `Head`'s `left`, `eos_read` is `Reading`'s, `upload_done` is `Done` or
`Aborted`, `upload_aborted` is `Aborted`, and `cr_exp100`'s states are `AfterHead::Continue`
and `HeadSent` (`EXP100_SENDING_REQUEST`, before and after the head has gone),
`AwaitingContinue` and a `Reading` that is `announced` (`EXP100_SEND_DATA`;
`http_exp100_is_selected` is any of them). A body held for a 100 is
never read behind the head, so it cannot be held and read at once; a 100 or an error response
that lets the body go on turns either holding state into a `Reading`. Nothing in it is
HTTP/1's framing: HTTP/2 keeps one per stream. Whether the connection is used again is not
part of it: the request's own decision (`streamclose`, `closing`), what the response's head
says (`Connection: close`, a body read until the connection closes) and what its body showed
(more than expected, or any where none was) stay separate sources, read together at the
request's end.
The request is over when its response is and nothing more of it is to send.

A step reads first, until the socket has nothing, the response is over or receiving pauses, and
at most eleven times (`sendrecv_dl`'s `maxloops`), then sends what is left with at most one more
buffer of the body (`Curl_sendrecv`), so a response that comes while the body goes is heard
within a buffer. A response that ends on a connection that is to close stops the sending, as
the server may close it now ("we are done reading and this is set to close, stop send"), and
the connection's end stops it too (`Curl_req_stop_send_recv`): either is `Sending::Aborted`, a
body waiting for a 100 included, with nothing more sent. A step that stops at the eleventh read says `ProtoStep::AtReadLimit`, and the engine,
past the step's timeout and progress checks, marks the transfer dirty (`Curl_multi_mark_dirty`):
it runs in the next pass without waiting on its socket, and the multi's timeout is 0 until then.
A peer that sends faster than it is read thus cannot keep a pass from ending, so the time limits,
the progress handler and the other transfers get their turn as in C. C's other exits from that
loop: a receive limit spent ends the step without a dirty mark, the engine then waiting for
the limit's timer (§5.3), and bytes held where a poll cannot see them, which run the transfer
again (`data_pending`, §4.3: what a layer holds, as TLS holds decrypted bytes, or the stream's
`rx`). One that asks for another request, by a location to
follow or for credentials, weighs what of the body is left (`http_perhapsrewind`, in the head
parser, fed an `Unsent` with each piece): 2000 bytes or more, or an unknown amount, and the
connection closes rather than carry it, the response ending at its head; less, and it goes to be
dropped on a connection kept.

The pipeline and the done gate belong to the engine. Each protocol owns a `Pipeline`
(accounting, the write handlers, held output) and drives it; the engine moves `Exchanging` to
`Done` only when the protocol says `Done` and `holds_output()` is false, so a protocol cannot
end a request whose paused output is still held, whatever it does with its own stages.

Which ways a request moves bytes (C's `req.io_flags`) is `Directions`, never stored: it is
derived from the protocol's state where a pause is judged (`TransferState::directions`), none
before DID and none from Done on (§3.6).

### 3.3 Transitions

| From | To | Condition and work (C's order) |
|---|---|---|
| Init | Exchanging setup | pretransfer: fresh `TransferReport` (header store empties), cookies and resolve list, `Starts::op`; on failure `fail` → Completed |
| (setup) | Connecting / Exchanging / Pending | `Starts::single`; arm Total and Connect; `pool.acquire(route)` → `Connecting(lease)`, `Ready(lease)` (reused or `file:`), or `Wait` |
| Pending | Setup | `schedule_pending` (one per call, round robin after `pending_after`, marked dirty): after a connection is given back, after a setup finds or makes one, when a transfer is removed, and when a woken one fails; or its own step finding its time up ("PENDING handle timeout", after the timeout's failure is traced once) |
| Setup | Connecting / Pending / Completed | the search again, as from setup; past its time, fails with the timeout traced a second time |
| Connecting | ProtoConnect | the slot became `Open`; not advanced while `recv != Running` |
| ProtoConnect | Do | the protocol's connect is done (none has one yet) |
| Do | Do / Did / Done | `ProtoState::do_it` made the request (`DoStep::Made`), or a piece of it (`More`, `file:`'s each piece read or written, C's one call: the step stays in Do, with no progress pass of its own, so the drive's clock read times each piece); prereq callback at DO entry; DID entry marks PRETRANSFER (+POSTTRANSFER if nothing to send); a failure is Done, not premature, before DID |
| Did | Exchanging / Done | past its time, fails (C's loop-top `multi_handle_timeout`; `file:` writes its whole upload first); Done at once if the protocol exchanges nothing more (`file:`, C's DID without sockets); an HTTP-family protocol yields once when more than one transfer is alive (C returns CURLM_OK there) |
| Exchanging | Done | request complete with output not held, or a retry: `next` is Complete or Retry (Follow with redirects); FOLLOW_FAKE writes `report.redirect_url` |
| connected | Done(Err) | progress callback abort |
| any live | fail | an error, a timeout, `remove`, or a dead multi (AbortedByCallback) |
| Done | (leg) / Completed | `multi_done`'s order; Retry (and Follow) start the next leg |
| Completed{Unread} | Completed{Read} | `info_read` |

"Setup" is not a resting state: C's SETUP and CONNECT always run in the same pass, so they are
one step that produces `Connecting`, or `ProtoConnect` for a protocol without a network, or
`Pending` when the connection limits leave no room ("No more connections allowed to host",
"No connections available, total of N reached."). A `Pending` transfer is not run with the
others: its step does nothing until its time is up. The row for Follow describes a later
step of milestone 2.

Setup parses the URL as `parseurlandfillconn` does: with the URL rules, guessing a scheme, and
accepting one libcurl does not know (the protocol lookup refuses it next). A default protocol is
given to a URL that has no scheme of its own; for `file` the scheme is looked for before parsing,
since a bare path is no URL.

Timeout errors come from one function on the state, producing C's texts: in `Connecting`,
"Resolving timed out after N milliseconds" or "Connection timed out after N milliseconds";
elsewhere "Operation timed out after N milliseconds with X out of Y bytes received". A setup
that fails or times out with its first hop connected keeps what is known of it, as
`Curl_conn_report_failed` does: the connection's ends (`CURLINFO_PRIMARY_IP` and the rest) and
`TIMER_CONNECT` at the moment TCP connected, so a TLS handshake cut short still reports them
(5029); attempts still racing report nothing.

### 3.4 Deadlines and timers

```rust
pub(crate) struct Deadlines {
    total: Option<TimeLimit>, connect: Option<TimeLimit>,
    armed: [Option<Instant>; TimerKind::COUNT],   // C's per-transfer expire list
}
pub(crate) enum TimerKind { Total, Connect, Proto, AsyncName, HappyEyeballs, SpeedCheck,
                            TooFast, Quic, FtpAccept, AlpnEyeballs, Shutdown, ServerResponse }
impl Deadlines {
    fn start_leg(&mut self, now: Instant);                 // SETUP: arms Total and Connect
    fn arm_in(&mut self, kind: TimerKind, now: Instant, wait: Duration);
    fn clear(&mut self, kind: TimerKind); fn clear_all(&mut self);
    fn wake_at(&self) -> Option<Instant>;                  // earliest armed timer
    fn expire(&mut self, now: Instant);                    // an expiry pass consumed them
    fn time_left(&self, starts: Starts, now: Instant, phase: Phase) -> TimeLeft;  // timeleft_now_ms
}
pub(crate) struct Starts { op: Instant, single: Instant }  // in Timings: TIMER_STARTOP, _STARTSINGLE
```

- **The C behaviour is ported**: `start_leg` arms `Total` and `Connect` from the leg's start
  (C arms EXPIRE_TIMEOUT and EXPIRE_CONNECTTIMEOUT at every SETUP, multi.c:2497), and
  `time_left` judges the total limit from `Starts::op` and the connect limit (300 s when unset)
  from `Starts::single` (connect.c:70), in C's whole-millisecond arithmetic, where a limit
  reached exactly counts as passed by 1 ms. The connect timer is armed only when the limit is
  set, as in C. A timer stays armed after its instant until an expiry pass consumes it
  (`add_next_timeout`), so a timer armed in the past still wakes the transfer at once. The N
  in the error text follows C's two checks: the multi-level check reports the time since
  `Starts::single` while connecting and since `Starts::op` after (multi.c:1820), the check at the
  end of a receive/send pass always since `Starts::single` (transfer.c:382-393).
- `MultiPending` is not a kind: C declares EXPIRE_MULTI_PENDING (urldata.h:498) and never arms
  it.
- `Proto` is the protocol's own wait, HTTP's for a 100 (EXPIRE_100_TIMEOUT) among them: never
  stored apart from the protocol's state, it is derived after every step from
  `TransferState::wake_at`, as `Directions` is, and armed or cleared there. One kind serves
  every protocol, as a transfer runs one at a time.
- `AlpnEyeballs` (EXPIRE_ALPN_EYEBALLS, half the happy eyeballs delay, 100 ms by default) is
  armed as the HTTPS connect filter's attempt starts while its ballers are not complete: with a
  second baller, or with the origin's HTTPS-RR answer still to come. With one baller, as here,
  that is a host name whose HTTPS-RR is not known as the attempt starts (`localhost`, which 758
  uses, or a name `CURLOPT_RESOLVE` gives, which answers the addresses only); never an address,
  which asks for none, nor a name whose answer is cached. Once armed it is not cleared when the
  attempt wins: it stays in the transfer's pollset lines until `[TIMEOUT] all cleared` at
  COMPLETED. The engine resolves no HTTPS-RR (that waits for c-ares) and has the answer the
  reference build's resolver gives a name without one: it looks for the record in the DNS cache
  as the setup's first connect starts, as C's does (`queries=HTTPS -> 0 not found`, `hostip_resolv
  started -> 81`), and at the setup's next connect has the answer, none, as C's local resolver
  gives it before the attempt is looked at again, keeping it in the cache (`cache negative name
  resolve for H:P type=HTTPS`). A later setup for the name finds it (`Hostname H was found in DNS
  cache`, `HTTPS-RR H:P: -`) and arms nothing.
- `Shutdown`: the shutdown set's deadline is the multi's, not a transfer's: C arms EXPIRE_SHUTDOWN on its internal
  handle for the earliest deadline of the connections shutting down (cshutdn.c:359–367). Built:
  the `ShutdownSet` keeps it as one `Option<Instant>` of its own beside the `TimerQueue`, not a
  row in it (a row would need a transfer's slot). Only a pass of the set arms it, at the least
  time left of its connections, replacing what was armed, as `Curl_expire` does; a connection
  joining arms nothing. `due`, `multi_timeout` and the timer announcement take the earlier of
  it and the queue's head; once past, it marks the set dirty as an expired transfer is. Nothing
  traces it, as C's internal handle has no debug function.
- **`TimerQueue`** is an indexed binary min-heap with one entry per transfer, holding
  `deadlines.wake_at()` of that transfer, keyed by its `Key` with the position index by row.
  Capacity is reserved at `add`, and `update(key, Option<Instant>)` is O(log n) with no
  allocation. Transfers due at the same instant come out in the order they were queued, as from
  C's splay tree; an update to an unchanged instant keeps the transfer's place. C instead
  re-queues a transfer whose first timer is re-armed or cleared even when its earliest instant
  stays the same, which only reorders transfers due in the same microsecond. It is an index over
  `Deadlines`, rewritten after each step of that transfer, never consulted for "is it late".
  Unit 1309's due order (from test1309's expected output) ports against it.
- **`TimerAnnounce`** owns the unit 3230 dedupe, in the core because Rust users of
  `socket_action` need the same contract: call the timer callback only on a change (clear after
  set, set after none, different absolute expiry), 0 ms whenever a dirty transfer is in process
  (re-announced at each new instant, as C compares the time of the check), and
  `socket_action(Timeout)` forgets the last value so it is re-announced. Waits are rounded up to
  whole milliseconds and capped at `INT_MAX`. A callback `Abort` makes the multi `Dead`.

### 3.5 The pass

```rust
impl<H: Host> Multi<H> {
    pub fn new(opts: MultiOptions, env: Env) -> Result<Self, OutOfMemory>;
    // Env { net: Box<dyn Net>, clock: Box<dyn Clock>, resolver: Box<dyn Resolver>,
    //       arena: ArenaPolicy, waker: Option<TryArc<Waker>> }
    pub fn add(&mut self, easy: Easy, owner: H::Transfer, ev: &mut dyn MultiEvents<H>)
        -> Result<TransferId, AddError>;          // AddError hands the Easy back
    pub fn remove(&mut self, id: TransferId, ev: &mut dyn MultiEvents<H>)
        -> Option<Removed<H>>;     // None: not in this multi; Removed { easy, owner, status }
    pub fn perform(&mut self, ev: &mut dyn MultiEvents<H>) -> Result<Running, MultiError>;
    pub fn socket_action(&mut self, what: SocketEvent, ev: &mut dyn MultiEvents<H>)
        -> Result<Running, MultiError>;
    pub fn socket_all(&mut self, ev: &mut dyn MultiEvents<H>) -> Result<Running, MultiError>;
    pub fn pause(&mut self, id: TransferId, p: PauseRequest, ev: &mut dyn MultiEvents<H>)
        -> Result<(), Error>;
    pub fn info_read(&mut self) -> Option<Message<'_, H>>;   // lowest slot first
    pub fn timeout(&self) -> Option<Duration>;
    pub fn wait(&mut self, extra: &mut [PollFd<'_>], max: Duration, mode: WaitMode)
        -> Result<u32, MultiError>;
    pub fn waker(&self) -> Option<TryArc<Waker>>;            // Send + Sync, for curl_multi_wakeup
    pub fn assign(&mut self, s: SocketKey, v: H::Socket) -> Result<(), MultiError>;
    pub fn easy_mut(&mut self, id: TransferId) -> Option<&mut Easy>;
    pub fn report(&self, id: TransferId) -> Option<&TransferReport>;
    pub fn counts(&self) -> Counts;
}
pub fn drive_to_completion<H: Host>(m: &mut Multi<H>, id: TransferId,
                                    ev: &mut dyn MultiEvents<H>) -> Result<Result<(), Error>, MultiError>;
```

**`add`** reserves everything the engine's tables can need for the transfer: the arena row,
the timer-queue entry, the dirty-set capacity, two notification entries and two socket-user
entries. It marks the transfer dirty and calls `timer_update`, so the timer callback sees 0 ms
inside `curl_multi_add_handle` (multi.c:550). On OOM nothing is left behind and the `Easy` is
returned.

**`remove`**: a transfer that is not `Completed` gives back its lease as a premature end and
leaves no message, as `curl_multi_remove_handle` (multi.c:780), with its slot still in place so
the connection's end is traced to it ("closing connection #N", as `multi_done` runs attached);
forget its socket interest (socket callback REMOVE inside the call, multi.c:821); release the
timer entry; remove the row; `schedule_pending`; `timer_update` (multi.c:868). The `Easy` and the
owner value come back even when the timer callback aborts; `status` carries the abort. Removing
an id that is not in this multi returns `None`, which the shim maps to `CURLM_OK` (3105).
Dropping a `Multi` removes every transfer still in it (`curl_multi_cleanup`).

**`perform`** (multi.c:2898), with `now` read once:
0. drive the `ShutdownSet` (`Curl_cshutdn_perform`), as C's internal handle is the first of
   its process set and is run on every `perform`;
1. run every process transfer in ascending slot order with an index cursor, so a transfer
   added during the walk at a higher slot runs in the same pass;
2. `schedule_pending` if a pass flagged a connection change: a closing connection closed by
   the set (`Curl_multi_connchanged`), and later multiplexing;
3. dispatch notifications;
4. sweep the timer queue for entries before `now`; a late `Pending` transfer goes to setup and
   fails there with the timeout;
5. `timer_update`.
`perform` does not re-assess pollsets or call the socket callback, as in C.

**`socket_action`** (multi.c:3249):
1. `now = clock.now()`;
2. for a socket: mark every user dirty (a connection user marks the `ShutdownSet` dirty, which
   `run_dirty` drives first and counts as one that ran, as C's internal handle);
   `ev_bitmask` is not passed to the core; an unknown socket does nothing. For `Timeout`:
   forget the announced expiry and drain the waker;
3. mark expired timer entries dirty, then `run_dirty(now)`, which after each transfer
   re-assesses that transfer's pollset and calls the socket callback for the changes, at once;
4. if anything ran: `now2 = clock.now()`, expire and `run_dirty(now2)` exactly once more;
5. `schedule_pending` if flagged, dispatch notifications, `timer_update`. A socket callback's
   abort ends the call after step 3 or 4 with `AbortedByCallback`, before notifications and the
   timer, as `multi_socket`'s `goto out`.

The `SocketTable` (`multi/sockets.rs`, C's `multi_ev.c`) is the one record of who waits on each
socket: an entry holds its users and what each waits for, what the application was last told,
and the value it assigned; a transfer keeps no copy and is found by asking the table. It is kept
only while the events want sockets, as C keeps it only with a socket callback. A transfer is
assessed after it runs in `socket_action`, inside `pause` when the pause changed and the
transfer is not done (easy.c:1233, after the timer), and with nothing to wait on inside `remove`
(`Curl_multi_ev_xfer_done`); `perform` assesses nothing. A change is told when the sockets'
users together want something else than the application last heard; an announcement whose
callback aborts is not recorded, so no REMOVE follows it. The shim's `curl_multi_cleanup` tells
the socket callback but not the timer.

**`wait`** (multi.c:1522) polls the multi's sockets, the application's `extra` descriptors and,
when the wait will be one (`WaitMode::Poll`, or anything else to poll), the waker, through
`Net::poll`, for `max` capped by `timeout()`. `WaitMode::Wait` with nothing to poll returns at
once; `Poll` sleeps. The waker's event is drained and not counted; `extra`'s events are copied
back into its entries; a failed poll is `UnrecoverablePoll`, a signal ending it early counts as
nothing ready. A negative timeout is the shim's BAD_FUNCTION_ARGUMENT. `Net` has `poll` for the
waits, and `connect` and `close` for connections; a `Socket` says how its readiness is learned:
a descriptor to poll, or, for a fake one, what it is ready for now and when it will be.
`FakeNet` polls real descriptors without waiting and, when none is ready, moves the
`ManualClock` to the first fake socket's answer or on by the whole timeout. What each transfer
waits on is one computation, `TransferState::pollset` over `Pool::socket` (C's
`Curl_multi_pollset`), which `wait`, `Multi::sockets` and the shim's `fdset` and `waitfds` all
read: a setup waits to write on its attempt's socket unless receiving is paused. `drive_to_completion` is
`easy_transfer`:
`wait(Poll, 1 s)`, `perform`, until the transfer completes; its message is read, other
transfers' are not. A transfer not in the multi, checked every round as a callback may take it
out, is `BadEasyHandle`.

`run_dirty` iterates by index cursor, re-reading the dirty set after each transfer; a transfer
marked dirty by a callback at a higher index is visited in the same pass (C's `bset_next`).

**`run_single(id, now)`** moves the `Run` out of the slot, and loops
while the step returns `Wake::Again`: deadline check for connected states, dispatch on the
variant, the extra deadline check before DO, then `is_finished` (error → `fail`; else the
progress callback once connected, `Abort` → `Done(Err)`). It puts the `Run` back before
`assess` and before the next transfer runs. A dead multi completes the transfer with
AbortedByCallback.

### 3.6 Call-outs and contexts

```rust
pub struct EngineRest<'a, H: Host> {      // the multi minus what the step holds
    slots: &'a mut Slots<H>,              // the stepping slot's `run` is moved out
    pool: &'a mut PoolRef, sockets: &'a mut SocketTable<H>, timers: &'a mut TimerQueue,
    announce: &'a mut TimerAnnounce, sched: &'a mut Sched, notify: &'a mut NotifyQueue,
    net: &'a mut dyn Net, now: Instant, life: &'a mut MultiLife,
}
pub struct TransferCx<'a> { calls: &'a mut dyn TransferCalls }
pub(crate) struct StepCx<'a, H: Host> {     // implements TransferCalls
    me: TransferId,
    me_basis: PollBasis,                  // my pollset before pause masking, computed at call-out
    rest: EngineRest<'a, H>,
    events: &'a mut dyn MultiEvents<H>,
}
impl TransferCx<'_> {                        // api.c's "may recurse" column
    pub fn me(&self) -> TransferId;
    pub fn info(&self, id: TransferId) -> Option<&TransferReport>;
    pub fn header(&self, id: TransferId, q: HeaderQuery) -> Result<HeaderView<'_>, HeaderError>;
    pub fn options_mut(&mut self, id: TransferId) -> Option<&mut Options>;
    pub fn pause(&mut self, id: TransferId, p: PauseRequest) -> Result<(), Error>;
    pub fn duplicate(&self, id: TransferId) -> Result<Easy, OutOfMemory>;
    pub fn info_read(&mut self) -> Option<(TransferId, Result<(), Error>)>;  // no owner value
    pub fn counts(&self) -> Counts;
    pub fn set_notify(&mut self, kind: NotifyKind, on: bool);
}
pub struct EventCx<'a, H: Host>  { /* the same methods except `pause` (api.c no_event_cb) */ }
pub struct NotifyCx<'a, H: Host> { /* + add, remove, wait, poll, timeout: api.c allow_ntfy_cb */ }
pub enum NotifyKind { InfoRead, EasyDone }               // CURLMNOTIFY_*, all off until enabled
pub enum Notification { InfoRead, EasyDone(TransferId) } // Copy: borrows nothing
```

`NotifyCx::add` and `remove` call the timer, whose `MultiEvents` is the one already borrowed
for the `notify` call, so they take it as an argument and the handler passes `self`; a timer
callback nested inside them gets its own `EventCx`.

The rules that keep this sound:
- **During a call-out, the engine holds only owned values moved out of their homes**: the
  stepping transfer's `Run` and, while delivering received bytes, the connection's
  `RecvBuf` (taken with `mem::take`, which allocates nothing, and put back after delivery).
  The pool, the other slots and every table stay in `EngineRest`. No iterator over engine state
  is live across a call-out. An option is never moved out: a callback reaches the options and
  may set them (`TransferCx::options_mut`), so a trace line that names one is formatted while
  it is borrowed and traced once it is not (`trace::line`, `trace::reason`).
- **The stepping transfer's pollset during its own callback** is `me_basis` (computed from
  the state and the layers' interest just before the call-out; neither can change while the
  engine is suspended in the callback) masked by `shared.pause`, which the callback may change.
  So `pause` from a write callback calls `timer_update` and `assess(me)` synchronously, and the
  socket callback runs inside `curl_easy_pause` as in C. For any other transfer the pollset is
  computed from its `Run`, which is in its slot. Built so far: neither call happens inside a
  pause from the transfer's own handler; the timer hears at the end of the pass and the socket
  callback after the step. `me_basis` comes with step 13, the first state that waits on its
  socket while a handler runs.
- **Whether a pause blocks a transfer** is judged against the ways its request moves bytes,
  `Directions` (C's `REQ_IO_RECV` and `REQ_IO_SEND`), derived from its protocol when judged:
  none before DID (so a pause never blocks a setup) and none from Done on; between, receiving
  if it exchanges and sending while it has more to send. A transfer runs again unless the
  pause stops every way it moves (`Curl_xfer_is_blocked`). A pause from the transfer's own
  handler, its run out of the slot, sets `judge_pause`; the engine judges it when the run is
  back (`put_back`), against the protocol as the step left it.
- **A call on a sibling transfer** routes to that slot. A sibling's unpause flushes its
  pipeline synchronously by the same rule as a step: its `Run` is moved out for the flush
  and put back after, so the handlers it calls get a context whose `EngineRest` does not alias
  it. A `pause` reaching a transfer whose `Run` is already out (the stepping one, or one being
  flushed) finds no pipeline to flush and only changes the value; nesting is bounded by that,
  not by a counter.
- **A connection being driven** is driven in its lease: `ConnLease::connect` moves the
  machine out of the lease's `ConnSlot::Connecting`, drives it and puts the result back, the
  pool not borrowed at all. The machine is part of the stepping transfer's `Run`, so it is one
  of the owned values moved out. A drive takes a `&mut dyn ConnCx` (§4.7), implemented over
  the `StepCx` (`DriveCx`), and makes call-outs through it: trace lines (`SETUP`, `TCP`, the
  chain's), the socket callback's REMOVE as an attempt's socket closes (`DriveCx` is the
  drive's network, and builds an `Announcing` for each close, never held across the drive),
  and the socket hooks (OPENSOCKET, SOCKOPT), the transfer's own handlers called with a
  `TransferCx` over the step, and a failure's first reason (`failf`). The context reaches no
  pool. A drive traces its own lines, in C's order among them: its attempts' and their
  sockets' (`HAPPY-EYEBALLS`, `TCP`, `Trying`, a failure), a close's `Curl_multi_will_close`, a
  redial's `retrying connect`. What it reports as `Progress` the transfer traces after it (the
  name's lookup, the winner's peer, the timers), and the chain's lines with it.
- **Outside a step** (`wait`, the timeout, `fdset`, `waitfds`, `assess`), a trace line for a
  transfer is made through a `StepCx` built for a transfer whose `Run` is in its slot, as
  `trace_membership` and `mark_expired_dirty` build one. `wait` takes the events for that, and
  traces in C's order: each process transfer's pollset and its timers, the transfer whose timer
  gives the multi's timeout, `multi_wait` on the last, then the poll; the socket list is built
  after those call-outs, so no borrow of a socket is live across a debug handler. A pollset's
  trace reads what it says from the run first (`PollsetTrace`), so the run stays in its slot
  while the debug handler runs.
- **Nested flushes cannot happen.** A callback of the transfer being stepped or replayed runs
  with its `Run` out, so `pause(me, Cont)` there only flips the value and marks it dirty; the
  replay under way sees it before its next entry (3235, 3236), and one that had stopped resumes
  at the transfer's next step, which replays before it reads. The progress and prereq callbacks
  (7e) are made between pipeline calls, so the step replays right after they return.
- **Event call-outs** (socket, timer) are made between transfers with no `Run` moved out;
  `EventCx` cannot pause.
- **Notifications** are dispatched at the end of `perform`/`socket_action` with no borrow live;
  `NotifyCx` borrows the whole multi minus the call-out entry points. A stale id resolves to
  nothing and is dropped; internal transfers are never passed (3107). A transfer that completes
  queues `EasyDone`, then `InfoRead` if no other message was unread (`mstate_enter_done`,
  `multi_addmsg`); removing one queues nothing. A kind is queued only while enabled and
  delivered only if still enabled. Room for two entries per row is reserved at `add` and the
  queue is empty between passes, so queueing never allocates and C's deferred
  `CURLM_OUT_OF_MEMORY` has no counterpart.

**Handlers are read at each call.** Before a call-out the engine clones the shared handle from
`easy.options.callbacks` (no allocation), builds the context and calls it, leaving the options
alone. A handler installed from inside its own call wins, and the next piece of the same write
uses it (fix 8940c1436b, #23085). A handler called again from inside itself (through a
sibling's unpause, say) is the application's to allow: its state is in cells.

### 3.7 Counts and messages

`Counts { running, pending, done_unread, current, added_ever }` lives in a `Tally` whose only
writers are its methods for a transfer added, refused after adding, completed and removed. After
every `add`, `remove`, `perform` and `socket_action`, the debug build recounts from the states
and checks the counts, that no `Run` is out of its slot or resting in `Done`, that the timer
queue holds exactly each transfer's next wake-up, that the pool holds exactly the leased
connections, that every dirty row names a transfer, and, outside delivery, that no notification
is left queued (`multi/check.rs`). `running_handles` is "added and not `Completed`" (Init and
Pending count).
`info_read` returns the lowest-slot `Completed { message: Unread }`, sets it `Read`, and reports
the number still unread.

---

## 4. Connection filters, pool and resolver

### 4.1 Connection slots

```rust
pub(crate) enum ConnSlot { Connecting(ConnectMachine), Open(Conn), Failed(ConnNumber) }

pub(crate) struct Conn {
    number: ConnNumber, route: Route,
    transport: Transport,              // Tcp(Stream), a Unix socket's too | Local; later Udp
    remote: Option<Remote>,            // Inet(SocketAddr) | Unix(UnixPeer); none without a
                                       // network; the local end is the socket's
    created: Instant, connected_at: Instant,
    use_: Use,                         // Leased(n) | Idle { since }
    served: bool,                      // carried a request before (C's bits.reuse)
    socks5_authenticated: bool,        // its SOCKS5 proxy authenticated the user
    seen_version: Option<ResponseVersion>,                   // C's httpversion_seen
    close: bool,                       // not reusable, released as Close: the response
                                       // said so, or the peer closed (EOF read)
}
pub(crate) struct Stream {             // conn/stream.rs
    socket: Sock,                      // the socket and the closer it was opened with (§4.6)
    layers: LayerStack,                // empty for plain TCP, one pointer (§4.3)
    rx: RecvBuf,                       // received, not yet used; grown fallibly before a read
}
```

One `Stream` type, owned by `Dialed` and then by the `Conn` it becomes, gives one read path:
`recv(cx, max)` fills `rx` through the layers (`RecvBuf::fill`, where a read that reports more
than the room it had is an error from the socket, `InvalidData`, not an assertion), `send`
writes through them; `Conn::recv` adds that bytes received and not used, which only a
handshake's read past its answer leaves (D11), are given first without asking the socket, and
that the end of input marks the connection `close`. A connection's multiplexing (`Session`,
`Mux`, §4.4) comes with stage 5, and until then `Use::Leased(n)` is asserted to be 1.
`Stream` does not rule out a second stream on one `Conn`, which FTP's data connection needs.

Protocols without a network (`file:`, C's PROTOPT_NONETWORK) lease a `Conn` with
`Transport::Local`: no socket, no layers, never pooled for reuse (released as Close), with an
empty `rx` that allocates nothing; the file protocol reads the file into the pipeline itself. This
keeps one lease-holding path through `Done` for every protocol, as C attaches a connection for
`file:` too.

`ConnLease::connect` drives the machine of the slot its lease holds by one event and replaces
the slot in the lease: `Established(conn)` makes it `Open`, a failure `Failed`, which holds
nothing open and goes when its lease is released. The `ConnId` and every outstanding lease
survive the handshake. Send,
receive, reuse matching, health checks and upkeep exist only on `Conn`. A `Connecting` slot with
a matching route counts toward the limits and makes `acquire` return
`Wait(Multiplexable(id))` when the needle wants PIPEWAIT (C's `seen_pending_conn`).

### 4.2 Connection setup is a typed pipeline

```rust
pub(crate) enum ConnectMachine {
    Resolving(Resolving),          // owns its ResolveId; the answer lands here
    Racing(Eyeballs),              // owns the DnsAnswer and up to 6 Attempts
    Alpn(AlpnRace),                // owns two whole sub-machines (stage 4/5)
    Socks(SocksHandshake), Tunnel(TunnelHandshake), Tls(TlsHandshake),
}
impl ConnectMachine {
    fn drive(self, cx: &mut dyn ConnCx, setup: Setup) -> Result<Drove, ConnectError>;
}
pub(crate) enum Drove { Connecting(ConnectMachine, Progress), Established(Conn) }
pub(crate) enum Progress { Trying(SocketAddr), Waiting }
pub(crate) enum ConnectError { Unresolved, Immediate { .. }, Attempt { remote, local, error } }
```

The enum is the target shape; what is built is a struct with a `Stage { Resolving,
Racing(Racing), Tunnel(Dialed) }`. Resolving answers what C answers without a resolver backend: an IP literal,
and the loopback addresses for `localhost` and the names under it. `Eyeballs` holds the `Answer`
and picks the next address as `cf_ip_ballers_run` does, the families alternating, IPv6 first;
`IpVersion` limits a name's addresses, never a literal's. `Racing` runs up to six attempts, oldest
first (`IP_HE_MAX_CONCURRENT_ATTEMPTS`, the oldest closed to make room): the next starts once
none runs or the happy eyeballs delay (`CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`, passed on each
drive) has passed since the last started; a failed attempt is traced and dropped; the first to
connect wins and the others close. `Progress::Waiting { until }` names when the next attempt is
due, which the transfer arms as `TimerKind::Eyeballs` and clears when the setup ends. Unit 2600's
cases are a test of the machine over a manual clock. A drive moves the machine by at most one
event and returns it, in place in its slot (§3.6). The transfer's step drives it again for as
long as one call of C's `Curl_conn_connect` would go on (`multi/state.rs`'s `connecting`): through
a name resolved, an attempt failed or connected at once and a handshake made; a connect under
way ends the call, as `cf_tcp_connect` returns at once on `EINPROGRESS`, and the attempt is first
polled at the transfer's next run, so its socket is waited on and announced to the socket
callback first. A drive traces its attempts in C's words as it makes them ("  Trying …",
"connect to … from … failed: …"), and the transfer what the drive reports ("Established
connection to … ", then `failf`'s "Failed to connect to H:P after N ms: …" or "Could not
resolve host: …"). A reason an attempt gives for failing the transfer (`failed to open
socket`, a bind's) is let go as the race starts the next attempt, connects, or ends with none
left (`Curl_reset_fail`), as is what the application's error buffer was told: the reason kept
is the race's, or none. The machine
is driven in its lease, the pool not borrowed (§3.6), and reaches the transfer only through its
`ConnCx`; `Setup` carries the transfer's settings for the drive (the eyeballs delay, the
scope, the socket options, the names' rules). A transfer whose receiving is paused is not driven (`multistate_connecting`), and the
connect limit is judged before each drive. A resolved name is reported as `cf_dns_report`
reports it ("Host H:P was resolved.", then each family's addresses), read back from the
machine through the pool, and NAMELOOKUP is marked when it resolves. Whether IPv6 works is the
multi's, asked of its `Net` once as the multi is made (`Net::probe_ipv6`, an IPv6 datagram socket
opened and closed, as `Curl_probeipv6` in `Curl_multi_handle`) and reached by the drive through
`ConnCx::ipv6_works`: without it a name is resolved for IPv4 alone, and for IPv6 alone not at
all (`Unresolved::NoIpv6`, `can_resolve_dns_queries`). An IPv6 attempt's address
carries C's `conn->scope_id`: `CURLOPT_ADDRESS_SCOPE`, else the destination peer's scope, else,
for a link-local address, the first non-loopback interface's with a link-local address
(`Net::link_local_scope`, cf-socket.c's `get_scope_id`), which `Progress::Trying` carries for
its trace; an attempt that fails at once is traced as tried first, as C opens and traces the
socket before its connect.

- Each stage owns what the previous stage produced: `Resolving` yields `DnsAnswer`, which
  builds `Eyeballs`; the winning attempt's socket becomes the `Stream` of the next stage, and
  every handshake runs over that `Stream`. A handshake whose layer goes on working once it is
  done (TLS) pushes it on the stream; SOCKS and the HTTP proxy's tunnel, which only pass bytes
  once connected, are recorded as made on the `Dialed` connection that owns the stream
  (`Made`, a few bits in its padding, so no byte more for any transfer), not as boxed layers
  that do nothing. Happy eyeballs never reads DNS sideways (C's
  `Curl_conn_dns_get_ai`), and the resolve record lives with the machine that started it, not
  on whichever transfer happens to call.
- A setup that makes a handshake does not end at the winning attempt: a route through SOCKS
  or an HTTP proxy that tunnels (`Tcp::handshakes`), or a transfer that sends the PROXY line
  (`Setup::haproxy`, the creating transfer's, as the line is not part of the route), has the
  machine keep its socket as `Stage::Dialed(Dialed)`, with a receive buffer, and return
  `Progress::Dialed`. The machine does only the I/O of the handshake; the transfer
  (`multi/state/tunnel.rs`) makes it. It renders the `CONNECT` with the proxy's side of its
  `Auth`, sends it and reads the answer through `ConnLease::dialed`, parses it with
  `proto::http1::tunnel::Answer`, and delivers each line through its own pipeline as
  `HeaderOrigin::Connect`, so the report, header handler and auth state are the transfer's to
  write. It reads until the socket would block or the answer is whole, as C does, and takes
  stock of the transfer (`progress::update`) as C's byte-at-a-time read does: once for each
  byte of the answer, the byte after a header line counted before the line is taken in, once
  for the connection's end, and once each time it returns for more or has the answer. The
  SOCKS handshake, like C's, takes none. A 407 is answered with another `CONNECT` on the same connection, its body dropped;
  a 2xx records the tunnel made, and the next handshake follows; the last makes the `Conn`
  (`ConnLease::handshaken`), keeping what came after the answer, and it is traced as
  established only then.
- SOCKS likewise (`multi/state/socks.rs`, over the sans-IO `conn::socks::Handshake`). For SOCKS4
  and SOCKS5, which resolve the destination here, the machine resolves it as it dials, through
  the same cache, and the `Dialed` stage carries the answer. A failure is `ErrorKind::Proxy` with
  the `ProxyError` kept for `CURLINFO_PROXY_ERROR`; a SOCKS5 proxy that authenticated the user
  marks the `Conn`, which alone serves a transfer insisting on it (`CURLAUTH_ONLY`).
- SOCKS5's GSS-API method is offered where the handle has a GSS-API library and the options
  allow it. Picked, it is three more states of the same `Handshake` (`conn/socks/gss.rs`): the
  context is made with the proxy's service (`rcmd`, or the credentials', which a disallowed
  basic method takes away as C unlinks them) and stepped one RFC 1961 message at a time, then
  the protection level is asked and read, wrapped by the context or, in NEC's way, as it is. The
  context lives in the boxed handshake, so nothing grows on `Connecting` or `Conn`; it is
  dropped with the handshake, or as soon as the proxy grants no protection. C makes the socket
  blocking for the whole exchange (`Curl_blockread_all`); here each message is sent and read as
  the socket lets it, the same bytes (`DIVERGENCE.md`). The handshake says what a failed send,
  read or close means in the message under way, and the connect deadline reached while one is
  awaited fails its read as C's blocking read does, and a GSS-API failure is traced as C's
  `failf`s are, the library's words for the call, the step's, then "Unable to negotiate SOCKS5
  GSS-API context.", the first of them the transfer's reason. Protection granted fails once
  the request went (`CURLPX_GSSAPI_PROTECTION`), as C does.
- A SOCKS pre-proxy (`CURLOPT_PRE_PROXY`) sits in front of an HTTP proxy only, set on its
  `ProxyRoute` through `ProxyRoute::behind`, which asserts it; alone, it is the route's SOCKS
  proxy. The route then dials the pre-proxy first (`Tcp::destination`), its SOCKS handshake asks
  for the HTTP proxy (`Tcp::socks` gives the leg), and a tunnelling HTTP proxy's `CONNECT`
  follows over the same `Dialed` stage; a SOCKS5 authentication is kept on `Dialed` and carried
  to the `Conn`. Reuse compares the pre-proxy too.
- A new connection sends the PROXY protocol's line over `Dialed`, after any proxy's handshake,
  if the transfer asks (`multi/state/haproxy.rs`, `cf-haproxy.c`), with the addresses of the
  socket to the first hop, before it is open and traced as established. Whether it asks is
  read once, as the setup reaches that stage, as `cf_setup_add_haproxy` reads it: as the
  attempt wins for a route without a proxy's handshake (`Setup::haproxy`), else as the last of
  them is made (`ConnLease::proxied`); `Dialed` carries the answer to the handshake chosen
  next, the chain traced and the chain left once up. A reused one sends none, and reuse does
  not ask, as in C.
- A proxy that closes the connection on its 407 starts the setup over from resolving
  (`ConnLease::redial`, cf-setup.c's "AGAIN"), counted by the machine, at most 5. Each connection to
  the proxy counts toward `CURLINFO_NUM_CONNECTS` as it is made.
- **Handshake order** is decided in one place, `handshake_due` (`multi/state.rs`), from the
  route, the transfer's PROXY line and what `Dialed::made` records, in cf-setup.c's order
  (299–359): the eyeballs race, then SOCKS, then the proxy's TLS (stage 4), then the HTTP
  proxy's `CONNECT`, then the PROXY line, then the origin's TLS. Each handshake, once made,
  ends with none under way, and the step goes on to the next within the same call, tracing
  SETUP's `added` line for it; with none left the connection is open. A redial starts a new `Dialed`, with
  nothing made. The PROXY line goes over `Dialed` before the connection is `Open`, so no `Open`
  connection exists with it unsent, and a transfer taken out mid-setup gives back a
  connection that is not open, which closes. The transfer drives each handshake, its I/O over
  the `Dialed` stream; the drivers take the transfer's `Connecting` for its route, its
  pipeline (the CONNECT answer's lines) and its lease (a redial), so another stream (FTP's data
  connection) needs them split from it first (open, with FTP).
- **C's filter chain is rendered, not built.** The setup filters (SETUP, DNS, HAPPY-EYEBALLS,
  HTTP-PROXY, HAPROXY) exist in C only until the chain connects and are then removed
  (`Curl_conn_remove_setup_filters`, cfilters.c:434–450); here the typed machine stands for
  them, and `conn/chain.rs` renders the chain C would have at each point for the trace
  (`cf_setup_connect [0][!DNS][!SETUP][!HAPPY-EYEBALLS]`,
  `connected [0][DNS][SETUP][HAPPY-EYEBALLS][TCP]`, `reduced to [0][TCP]`), allocating nothing. The handshakes made and the stream's layers
  are C's reduced chain: `[TCP]`, `[SOCKS][TCP]`, `[H1-PROXY][TCP]`, `[H1-PROXY][SOCKS][TCP]` behind
  a pre-proxy. For a SOCKS5 proxy that is not to resolve the name, C adds a second DNS filter
  for the destination, which the rendered chain shows as `[!DNS][!DNS]` (`--socks5`, and a
  SOCKS5 pre-proxy; `--socks5-hostname` has one).
- **Socket open order** is the attempt's, in C's sequence (`cf_socket_open`, `do_connect`):
  the OPENSOCKET callback, which may change the address, or `Net::open`, a non-blocking socket;
  the "Trying" trace; TCP_NODELAY (on by default, url.c:410, cf-socket.c:1322), and keepalive
  with its idle time, interval and count only while it is on; the SOCKOPT callback
  (`AlreadyConnected` wins the attempt as it opens, with no connect to check; any other failure
  closes the socket and is AbortedByCallback); non-blocking, for a socket the application
  opened; `cf_socket_open() -> 0`; TCP_FASTOPEN_CONNECT; the connect and the local address.
  `Socket::set`, `set_nonblocking` and `connect` are each one system call. A socket that does
  not open, or closes as it is set, is traced as C traces it, with neither address known or the
  local one not, and the setup's failure is the last attempt's kind (`ConnectError::Failed`).
  The local end is bound between the SOCKOPT callback and non-blocking (`conn/bind.rs`,
  `bindlocal`), as the route's `LocalBind` says (`CURLOPT_INTERFACE`, `LOCALPORT`,
  `LOCALPORTRANGE`): an interface by name with `SO_BINDTODEVICE`, else by its address
  (`Net::interface_address`, `Curl_if2ip`), else a host's, resolved for the connection's family
  alone through the DNS cache, which keeps no negative entry for it; then the ports of the range
  in turn. A failure closes the socket as one not opened; an address of the other family fails
  the attempt as `CouldntConnect`, letting the next address be tried, any other as
  `InterfaceFailed`.
- **Unix sockets.** A transfer over the network with `Sockets::unix` set connects to that
  socket in place of its host (`url_set_conn_origin_etc`): the route's `via` is a `Peer` at it
  (`PeerAt::Unix` or `AbstractUnix`, the path as its host, compared exactly), no connect-to entry
  is read and no proxy is chosen. A SOCKS proxy at `localhost` with a path is at the Unix socket
  of that path (`conn/proxy.rs`). The setup makes the socket's one address rather than resolving
  (`Addresses::Unix`; a path its address cannot hold fails as `CouldntResolveHost`), and its
  attempt opens an `AF_UNIX` socket (`Remote::Unix`, which `Net::open`, `Socket::connect`, the
  opener hook and `Ends` carry) with none of TCP's options or bind; its filter traces as `UNIX`,
  its address as the path (nothing for an abstract name) at port 0, and the infos give it no
  ports.
- Happy-eyeballs parameters are C's: 25 ms AAAA wait, `happy_eyeballs_timeout` attempt delay, at
  most 6 concurrent attempts, IPv6 first then alternating. Unit 2600 is ported before a second
  attempt is implemented.

### 4.3 Established layers

```rust
pub(crate) trait Layer: Send + Debug {           // conn/layer.rs; C's Curl_cftype
    fn connect(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind>;
    fn recv(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, buf: &mut [u8])
        -> io::Result<Recv>;
    fn send(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, bytes: &[u8]) -> io::Result<Sent>;
    fn adjust_pollset(&self, wanted: Events) -> Events;      // TLS wants OUT while reading
    fn data_pending(&self, below: Below<'_>) -> bool;         // bytes a poll cannot see
    fn is_alive(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Alive;
    fn shutdown(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind>;
    fn query(&self, q: LayerQuery) -> Option<LayerAnswer>;    // TLS's objects, ALPN, waits
}
pub enum Handshake { Done, Waiting }                         // public: a TLS session returns it
pub(crate) enum Alive { Dead, Alive { input_pending: bool } }
pub(crate) struct Below<'a> { layers: &'a mut [Box<dyn Layer>], socket: &'a dyn Socket }
pub(crate) struct LayerStack { layers: Option<Box<Vec<Box<dyn Layer>>>> }   // bottom first
pub(crate) trait LayerCx {
    fn now(&self) -> Instant;
    fn of(&mut self, c: Component, line: fmt::Arguments<'_>);   // CURL_TRC_CF
    fn info(&mut self, line: fmt::Arguments<'_>);                // infof
    fn socket_failed(&mut self, e: &io::Error) {}                // state.os_errno
}
```

Layers form a **pull chain**, as C's filters do (cfilters.h:217–232, cfilters.c:186–222): a
read asks the top layer for at most the caller's length, and each layer reads from the one
below it as it needs, down to the socket. C's `destroy` is `Drop`, and its `cntrl` codes are
typed methods. Pulling keeps the sizes the caller asked for down to the layer that reframes
the bytes (`SSL_read(len)` is the caller's length; below it, the lengths are those OpenSSL's
BIO asks for: a record's 5-byte header and then the record during the handshake, the room
of its own buffer after), on which decision 20's read cap and the eleven-read loop (§3.2)
depend; a push chain with a buffer between layers would not keep them. `Below` is the stack
split at the layer being called, ending at the socket, so a TLS layer's BIO reads and writes
the layer below without aliasing its own state.

`LayerStack` holds the layers that work on the bytes, boxed, behind one pointer, as every
transfer's state holds its connection inline (§8.2); for TCP, a SOCKS proxy or a tunnel it is
empty and allocates nothing. Only TLS pushes a layer, and pushing one allocates.
The stack answers for the stream: `data_pending` is true while a layer holds bytes or the
stream's `rx` is not empty (bytes that came after a tunnel's or a SOCKS proxy's answer, which
`Conn::recv` gives before it reads again, as a layer gives what it holds); a read that would
block while data is pending runs the transfer again (`sendrecv_dl` and
`Curl_conn_data_pending`, through the step's `AtReadLimit` without its trace line). The pollset
of an exchanging transfer passes through each layer's `adjust_pollset`, top down, unless the
transfer waits for nothing, as `Curl_conn_adjust_pollset` gates a connected chain. C's other
run-again, from the pollset (`multi_adjust_pollset`'s "still buffered input -> mark as dirty",
and its line), is not ported: whether the engine, whose step runs a transfer again on pending
data, can make a pollset with input buffered is open. The pool's health check asks `is_alive` down the chain, as
`Curl_conn_is_alive` does (cf-socket.c:1811–1846, conncache.c:1041–1068), the socket at the
bottom polled at once: an error or a hang-up is dead, anything to read is input pending, and
input pending on an idle HTTP/1 connection makes it unhealthy (1701).

`LayerCx` is an argument, never stored, which removes C's `CF_DATA_SAVE/RESTORE` and its
dangling-easy class. Inside a step it is the transfer's (`ConnCx`, §4.7, extends it); a pool
section has a silent one. A call on the socket that fails, a receive or a send at the bottom of
`Below`, or an attempt to connect in the drive, is told to `socket_failed`, which the
transfer's context keeps in its report as C's socket filter keeps `os_errno` (cf-socket.c), and
a silent one drops; the report starts over without it with each transfer. A layer asks another layer something only through `query`. Only
`conn::*` and `multi::wait` call `Net`.

TLS's is the one layer pushed outside the tests (`conn::tls::TlsLayer`, §4.9): pushed by the
setup's last handshake, connected there through `connect` (`Stream::connect`, the top layer's
handshake over the ones below), and kept once the connection is up. A test's transfer may name
another (`Options::layer`, `cfg(test)`) that each direct connection it makes puts on its
stream once up, and `conn::layer::testing` holds those that arm each call (`Upper`,
`Holdback`, `WantsOut`, `Dying`). `shutdown` is called by the discard and the `ShutdownSet`
(§4.6), from the top layer down, one at a time, a layer done never asked again: TLS's says
goodbye, and `Lingering` (test-util, pushed on every connection a multi makes under
`Multi::linger_connections`) waits as one would. `LayerCx`'s trace is the connect machine's (`ConnCx` extends it) and, through `TlsIo`, a TLS
library's.

The bytes a tunnel's handshake read past its answer, which `rx` holds, are the first bytes the
TLS layer pushed over that stream reads: they move into the layer once, as it is pushed
(`Stream::push_over_received`), and its session reads them through `TlsIo` before it reads
below. That is what C's byte-at-a-time read of the answer comes to: whatever followed the
answer reaches the TLS handshake first, on both legs. A binding crate cannot implement
`Layer`, which stays crate-private: the core's `TlsLayer` implements it over the public
`curl_core::tls::TlsSession` a library makes (§4.9).

`LayerCx` carries what a TLS layer reaches through the transfer: `bytes(kind, data)` for the
SSL data a handshake and its records make (C's msg callback, `CURLINFO_SSL_DATA_IN`/`OUT`),
`configure_tls(native)`, the application's context handler (`CURLOPT_SSL_CTX_FUNCTION`),
called through the transfer's context, and `pause_recv`, a handshake waiting for the
application (`Curl_xfer_pause_recv`); the silent context of a pool section has none of them, as
C's internal handle has no debug function and no SSL_CTX callback. A connection's layers are
asked from the top (`LayerStack::query`, the first that answers): `LayerQuery::TlsNative` is
answered by the origin's TLS layer with its library's objects (§4.9), `LayerQuery::Alpn` with
the protocol its peer chose of the offer, and `LayerQuery::TlsWaits` with what its session
waits for, which the pollset's trace says. The key log is not on `LayerCx`: the shim's
root and the tool own it and hand it to the backend.

### 4.4 Multiplexing

Milestone 4, steps 52 and 51, as review M3 §2.1, §2.3 and §2.4 decide it, in two stages: HTTP/2
with one stream per connection first, a connection leased by one transfer at a time as an HTTP/1
one is (built); then the `Attached` place and multiplexing (planned).

**The session.** HTTP/2 is spoken by a session a binding crate makes (nghttp2,
`crates/curl-nghttp2`), behind the core's `http2::Http2` and `http2::Session`, as TLS is behind
`TlsSession`, with a fake for the tests (`http2::fake`, frames as lines): the core feeds it the
connection's bytes and takes the bytes it wants sent; it hands back events per stream (headers,
data, end, window, close, reset) and per connection (settings, goaway). An event the caller
cannot take fails the session's reading, as C's callbacks return `NGHTTP2_ERR_CALLBACK_FAILURE`;
what C's callbacks call back into the session for (consuming, resetting, resuming) is done once
the read returns. The session lives on the `Conn` (`proto::http2::H2Conn`, with the bytes it
gave that the connection has not taken), beside its layer stack, not as a `Layer`: a `Layer`
moves one byte stream, and the session moves many (review §2.3, option two). It is made by the
connection's first request, which finds what the connection speaks (`http_check_new_conn`):
HTTP/2 if TLS's ALPN agreed on `h2`, which is offered first where the handle has an HTTP/2
library and its version allows it (`alpn_get_spec`), or by prior knowledge with nothing between;
the connection then speaks HTTP/2 for good. A step takes the session off the connection for the
call that drives it and puts it back after (`with_session`), so the lease is free beside it. The connection-wide operations ask the session
first: the pool's health check lets it consume pending frames (an idle HTTP/2 connection with
a SETTINGS or PING to read is healthy, so the input-pending rule is HTTP/1's alone), its
shutdown sends GOAWAY, and `curl_easy_upkeep` sends PING past the interval. The pool checks a
multiplexed connection at most once a second (`lastchecked_ms`).

**The head.** A response head reaches the HTTP head parser as C hands it on: the status as
`HTTP/2 <code> \r\n` and each field as `name: value\r\n`, through one entry that takes a whole
line (`HeadParser::line`, C's `http_rw_hd`), with no folding, no hold of a last line, no line
limit and no HTTP/0.9 decision; `feed` stays HTTP/1's assembler in front of it (review §2.4).
The per-line work (cookies, file time, codings, Negotiate, the header store) is `head_input`'s
for either. A request is made as C makes it, its head rendered in HTTP/1's form with `HTTP/2`
in its request line and traced as sent; as it is sent, the head is read back into the stream's
fields (`proto::http2::fields_of`, C's `Curl_h1_req_parse_read` and `Curl_http_req_to_h2`):
`:method`, `:scheme`, `:authority` from `Host:` and `:path` first, names in lowercase, the
connection's own headers left out, `TE` only as `trailers`. Neither chunked framing nor an
added `Expect:` goes over HTTP/2. The body goes into the stream's buffer, at most 64 KiB, which
the session frames as the peer's window lets it; the body's end with no bytes left goes as an
empty send (`req_flush`). What the session reads for the stream is handed on as it reads it,
as C's callbacks write it: the head a line at a time, the body as the connection's would be,
consumed as delivered, and the trailers once the stream closes. The stream's close is the
response's end, as a connection's end is HTTP/1's (`stream_recv`,
`http2_handle_stream_close`): a reset fails it, but for a refused stream, made again
(`REFUSED_STREAM, retrying a fresh connect`); one closed before its head ended fails it too. A
request over that is done with its stream open resets it (`http2_data_done`).

**Upgrade.** Over clear text, a transfer that wants HTTP/2 by an upgrade
(`CURL_HTTP_VERSION_2_0`) and has a library asks for one on a connection that speaks HTTP/1
(`H1_HD_UPGRADE`): `Upgrade: h2c` and `HTTP2-Settings:`, its settings in base64url, both named
in `Connection:` after `TE`, and no `Expect:`. A 101 to it, its head handed on as an interim
one, switches the connection: the session is made from the settings the request sent, the
response comes on stream 1, the head parser reads a new head in HTTP/2 (`HeadParser::restart`),
and what followed the 101 is fed to the session (`Curl_http2_upgrade`). A server that does not
take it answers in HTTP/1.1.

**The connection's life.** An idle HTTP/2 connection with input waiting is not dead as an HTTP/1
one is: the pool's health check has the session read the frames, and it is alive unless the
session failed, a GOAWAY came or the session wants nothing more (`http2_connisalive`). A
connection that shuts down says GOAWAY first, with C's debug data (`cf_h2_shutdown`). Not
yet: `curl_easy_upkeep`'s PING, a paused stream's window, and the `CF` traces of
`--trace-config http/2`.

**Ownership, once multiplexed** (review §2.1, approved). A connection that multiplexes lives
in its pool place, `Attached { slot, users }`; an attached lease is a key, the `ConnId` and the
stream. A step moves the `Conn` out of the place for its duration and back after, a third
owned value decision 9 allows; the place says it is out meanwhile, and a lookup that finds it
out is a bug. What the session reads for another transfer's stream is delivered at once, in
the order C delivers it: input hands back `(TransferId, event)`, and the engine delivers each
sibling's bytes by moving that sibling's `Run` out in turn, as the unpause replay does (§5.3),
the stepping transfer's own connection out with it. A paused sibling's bytes wait in its
pipeline's paused output, as C's client writer holds them. A pause or an unpause aimed at a
sibling while the connection is out with another transfer is kept and told to the session as
the connection goes back, before any other work, so the WINDOW_UPDATE goes out where C's
does. The last lease given back decides the connection's fate as `multi_done_locked` does; a
GOAWAY or a connection error ends every stream on it.

### 4.5 Route and reuse

```rust
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Route {
    dest: Destination,                 // host:port, or connect-to / UDS peer
    transport: TransportKind,
    proxy: Option<ProxyRoute>,         // type, peer, credentials
    tls: Option<TryArc<TlsIdentity>>,  // every field that affects the handshake (§4.9)
    ip: IpPrefs, local: LocalBind,
    proto: ProtoFamily, scheme: SchemeConfig,
}
```

Built so far: `enum Route { Local, Tcp(Tcp) }`, with `Tcp { origin, via, ip, proxy, tls }`. `Peer` is C's
`struct Curl_peer`: the `Scheme` (the protocol's name and whether it keeps connections,
`PROTOPT_CONN_REUSE`), the host as the URL names it, the port, the IPv6 zone and its scope (a
numeric zone as it is, a name as its interface's index by `if_nametoindex`, one naming no
interface none; `CURLOPT_ADDRESS_SCOPE` replaces the zone on the URL's peer), made once per
leg and shared by the transfer, as its origin, and the connection it sets up. A host the URL,
a proxy's URL or a connect-to entry names in Unicode keeps its ASCII form beside it (C's
`hostname` apart from `user_hostname`), which the handle's IDN library makes
(`Libraries::idn`, libidn2's `idn2_lookup_ul` in `crates/curl-idn2`, non-transitional IDNA
2008, then 2003's transitional): the name it is resolved, sent (`Host:`, a forwarding proxy's
target, `CONNECT`), matched, verified and looked up in `.netrc` by; a name that does not
convert, or converts to nothing, fails the transfer as a malformed URL. Without an IDN
library the name goes as it is, as from a C build without one. The traces that show a host
show it as the URL names it. `Url::get_with` converts a host for `CURLU_PUNYCODE` and
`CURLU_PUNY2IDN` with the library the shim gives it. `via` is the
peer a connect-to entry names in the origin's place (C's `via_peer`, `conn/connect_to.rs`),
none when it names the origin itself; the setup resolves and connects to `via` if there is
one, and the traces name it where C's do. Matching is `Route::serves`: the same origin by
`Peer`'s `Eq`, which is `Curl_peer_equal` (the host in any case, and the zone by its scope,
or by its text when it has none), the same `via` or none on both, the same `IpVersion` unless the
transfer takes any (`url_match_conn`, `url_match_destination`), and an equal `TlsIdentity` or
none on both (`url_match_ssl_use`, `url_match_ssl_config`), and the same local end
(`url_match_connect_config`): the same interface as written, or none on both, and the same
ports when the transfer names an interface or a port. An `https` peer is not an `http` one,
its scheme being part of `Peer`'s `Eq`, so plain HTTP never takes a TLS connection. It,
`ProxyRoute`'s key, `Peer`'s `Eq` and `TlsIdentity`'s `eq` destructure every field without `..`,
so a field added later does not compile until it is compared; the exceptions are named where
they are made (the transfer's `IpVersion::Any`; `auth_only`, which `Conn::serves` checks against
what the connection did; a peer's host, compared as its name; whether ALPN is offered, which C
keeps on the handle).

The proxy is chosen at setup, after the connect-to entries (`Curl_proxy_init_conn`): the
options' (`Options::proxy`), or else the one the environment names for the scheme
(`conn/proxy.rs`, `detect`, never `HTTP_PROXY` in upper case), unless the no-proxy list names
the origin's host (`excluded`, unit 1614's cases); an empty proxy turns the environment's off.
`ProxyRoute { kind, peer, creds, forward, pre }` joins the route, the SOCKS pre-proxy in front of
an HTTP one shared (`TryArc`), as few routes have one, and two routes match only through
the same proxy, compared without its scheme, as the same user and the same way
(`proxy_info_matches`, `origin_is_proxy`). A plain HTTP request goes whole to an HTTP proxy
(`forward`): the route's origin is then the proxy's peer, so one connection serves any origin
through it and the traces name the proxy, and the request names the whole URL without its
fragment or credentials (`Request::forward`, made from the `Url` before it goes to the report)
with `Proxy-Connection: Keep-Alive`; the response's `Proxy-Connection` keeps or closes the
connection (`Asked::http_proxy`). A tunnel (`CURLOPT_HTTPPROXYTUNNEL`, a connect-to peer, or
an `https` origin, which never goes whole) is set up with `CONNECT` (`multi/state/tunnel.rs`), SOCKS4, 4a and 5 with their handshakes
(`conn/socks.rs`, driven from `multi/state/socks.rs`), over the connection to the proxy the
setup dialed. An HTTPS proxy (`https://`, refused as `NotBuiltIn` without a TLS library)
speaks TLS before anything else goes to it (§4.9).

`Route` is computed once per leg from the `Target` and options and never mutated. Matching is
`candidate.route.reusable_for(&needle)`: `Eq` on each sub-struct plus the deliberate
asymmetries (a TLS connection may serve the plain scheme, STARTTLS reuse with
`PROTOPT_SSL_REUSE`, HTTP-version allowances, MAXLIFETIME, busy non-multiplexed, max streams,
another multi). A field added to `TlsIdentity` or `SchemeConfig` joins the comparison by
construction, which is the class behind CVE-2021-22924, CVE-2022-27782 and CVE-2023-27535/27538.
The transfer's authority (origin, credentials) lives on its `Target`, never written onto a
shared connection (C's `url_conn_reuse_adjust` has no counterpart). Idle connections are
health-checked before reuse; input pending on an idle HTTP/1 connection makes it unhealthy
(1701).

The one exception is HTTP Negotiate, whose authentication C binds to the connection
(`proto/http/negotiate.rs`, lib/http_negotiate.c). Its state lives on the `Conn`, as
`negotiate: Option<Box<Negotiate>>`, made the first time a transfer negotiates on it: for the
origin and for the HTTP proxy each, C's `http_negotiate_state` and `proxy_negotiate_state` and
a `negotiatedata` (the context, the step's progress, the `Persistent-Auth` flags), and for the
origin the binding — the origin and the credentials (C's `creds` and `creds_origin`) the
connection authenticated as. A tunnel's `CONNECT` negotiates with the proxy before there is a
`Conn`: the transfer setting it up holds the box in `Connecting` (kept across a redial, as C
keeps it on the connection whose filters it makes again) and hands it to the `Conn` as the
connection comes up. The pool asks `Conn::serves_auth` with the transfer's `Wants` (whether it
wants Negotiate, its credentials and its origin; whether it wants Negotiate of the proxy with
credentials for it) after `Route::serves`, as C's `url_match_auth` and `url_match_auth_nego`:
a connection bound to credentials serves only those, one mid-handshake with the origin serves
only a transfer negotiating as the same credentials with the same origin, and one negotiating
with its proxy only a transfer negotiating with it — the proxy's credentials, its service
among them, are the route's. The delegation asked (`CURLOPT_GSSAPI_DELEGATION`) is part of
the `Tcp` route, compared in `Route::serves` (url.c:882). A connection whose handshake with
either peer is in progress (state `Recv`) is kept even when the transfer forbade reuse, as
multi.c keeps it. Negotiate runs only with a GSS-API library on the handle; without one the
challenges are still read, so `CURLINFO_HTTPAUTH_AVAIL` has the bit, which the shim reports only
where the build claims SPNEGO.

Over HTTPS each step is bound to the origin's TLS channel. Before a step, after the checks of
an empty challenge, the request asks the connection's `Stream` for its `channel_binding`, which
only the origin's TLS layer answers (`TlsSession::channel_binding`: RFC 5929's
`tls-server-end-point:` and the certificate's hash, nothing, or a failure). The proxy's
Negotiate gets the origin's binding too, never the HTTPS proxy's, as C's
`Curl_ssl_get_channel_binding` finds only the `SSL` filter. A failure resets that side and fails
the request; while a tunnel is set up there is no binding, the origin's TLS having no peer yet.

### 4.6 Pool and lease

```rust
#[must_use]
pub struct ConnLease { id: ConnId, conn: Option<ConnSlot>, home: Home }  // no Clone/Copy
pub enum Home { Multi, Share(Share) }      // the pool the lease came from and goes back to
impl ConnLease {
    pub fn connect(&mut self, cx: &mut dyn ConnCx, setup: Setup)
        -> Result<Connected, ConnectError>;                     // Connecting, Established, AlreadyUp
    pub fn get(&mut self) -> &mut Conn;                                         // once up
    pub fn home(&self) -> &Home;
}
impl Pool {
    pub fn find(&mut self, here: &Home, route: &Route, rules: ReuseRules, net: &mut dyn Net,
                now: Instant, notes: &mut Vec<PoolNote>) -> Result<Option<ConnLease>, OutOfMemory>;
    pub fn add(&mut self, here: &Home, route: Route, closer: Closer, limits: AddLimits,
               net: &mut dyn Net, now: Instant) -> Result<Acquired, OutOfMemory>;
    pub fn release(&mut self, here: &Home, lease: ConnLease, finish: Finish, limit: Limit,
                   net: &mut dyn Net, now: Instant) -> Released;
    pub fn close_idle(&mut self, net: &mut dyn Net);                            // multi drop
}
enum Place {                               // where a connection in the table is
    Idle(ConnSlot),                        // kept for another transfer; always open
    Leased(Leased),                        // its one lease has it
    Reserved(ConnSlot),                    // CONNECT_ONLY, kept for its handle; always open
    Attached { users: .. },                // multiplexed, leased by several (before stage 5)
}
pub(crate) struct Sock { socket: Box<dyn Socket>, closer: Closer }   // closed only by Net::close
pub(crate) enum Closer { System, Hook(Handler<dyn SocketCloser>) }
```

- A transfer searches before it adds (`find`, `Curl_cpool_find`), unless the transfer wants a fresh
  connection (`CURLOPT_FRESH_CONNECT`, but for a redirect's request): at most once a second it first prunes
  the idle connections that are not healthy, silently, as C's prune traces to its internal
  handle; then it takes the transfer's last connection if that is idle and serves it, so a
  transfer sticks to its connection (the `ConnId` its `Run` keeps from its last lease, none at
  `add`, as C's `last_cpid`), else the first idle connection, in table order, whose route is
  equal. One
  alive longer than the searching transfer's `max_age` is closed and passed over before its
  health is checked; one idle longer than its `max_idle`, or with anything to read, is closed as
  dead. What the search did comes back as `PoolNote`s, which the transfer traces in
  C's words ("Too old connection (…), disconnect it", "Connection N seems to be dead,
  terminating", "shutting down connection #N"). The rules are the searching transfer's, as C's
  match and the settings it copies to its internal handle make them. A reused connection is
  driven like a new one and says `AlreadyUp`, with no trace and no times, as
  `Curl_conn_connect` returns at once. Finding none, it adds one within the multi's
  `max_host` and `max_total` (`cpool_check_limits`): past either, the idle connection longest
  unused is closed to make room, first among those to the same destination (C's `destination`:
  the peer connected to, host and port in any case, IPv6 scope, any scheme), then among all;
  with no room left it returns `Wait`. A connection without a network is added unchecked, and
  counts toward the total.
- `release` decides the connection's fate as `multi_done_locked` does, from what the pool knows
  (other leases, the route's reuse rules, a close mark) and what the transfer reports in
  `Finish` (premature, reuse forbidden by `CURLOPT_FORBID_REUSE`):
  `Released::{Idle, Evicted, Closed, Terminated}` so far,
  traced as "Connection #N to host H:P left intact", nothing, "shutting down connection #N",
  "closing connection #N". A connection kept idle may leave the pool over its `Limit`
  (`cpool_conn_now_idle`): the multi's `max_connects` (`CURLMOPT_MAXCONNECTS`; an easy
  handle's own multi takes `CURLOPT_MAXCONNECTS`), or with none set twice the transfers in the
  multi, closing then only a connection idle for a second. Over it, the idle connection
  longest unused is closed, and the transfer traces "Connection pool is full, closing the
  oldest of N/M"; its close traces nowhere, as C's goes to the internal handle. `Evicted` is
  the released connection closed so. The limit is the multi's, not the pool's, so that the
  application's callbacks can set it while the pool is in use. A connection's use is one fact,
  `Use::{Leased(n), Idle { since }}`.
- The connection table starts empty and doubles from 16 when full (`ArenaPolicy::DOUBLING`), as
  `Curl_cpool_add` grows its table.
- The pool knows every connection by its place. An idle one is in the pool; a leased one's
  slot is in its lease, which the pool alone issues and consumes, so it counts the leases itself; a connection's lease count, its `Session` users and the transfer's
  variant cannot disagree because only `acquire` and `release` change them. The per-route index
  is maintained by those same functions; a dangling id in it is an assertion, never repaired.
- A debug-build drop check on `ConnLease` asserts it was released (internal invariant).
- **A lease knows its home.** `find` and `add` stamp the lease with the pool they run in,
  which `EngineRest::pool_section` hands its section beside the pool, and `release` asserts the lease's `Home` is the pool it is given back
  to, shares compared by pointer. Ids alone cannot tell: a share's arena and a multi's hand out
  equal ids. `Home` allocates nothing; an identity by counter would be global mutable state, and
  by address would move with the multi.
- **Places.** Built: `Leased`, `Idle` and `Reserved`. A transfer that only connects
  (`Options::connect_only`, `CURLOPT_CONNECT_ONLY` 1) never searches, is done once connected
  without a request (`multistate_do`), and gives its connection back as `Finish::reserve`: the
  pool keeps it `Reserved`, whatever its protocol, unless it must close, as C keeps one with
  `bits.connect_only`. A reserved connection is never found, pruned, closed to make room or by
  the idle limit, but counts toward the limits (3231, 3232). The handle names it by its last
  connection (`Easy::last_conn`, C's `last_cpid`): set as a transfer acquires one, forgotten as
  the handle joins a multi or changes to or from a share that keeps connections (3234), and by
  a lookup that finds it gone. `multi::raw` sends and receives on it for the handle
  (`Multi::send_raw`/`recv_raw` for one added, `send_raw_for`/`recv_raw_for` for one a
  handle's own multi ran; `curl_easy_send`, `curl_easy_recv`), refusing a handle that does not
  only connect or whose connection is gone as C does; a failure is kept in the report and told
  to the error sink, and traced nowhere, as no transfer runs. `Multi::active_socket` tells the
  socket of the connection a transfer holds or its pool keeps (`CURLINFO_ACTIVESOCKET`,
  `LASTSOCKET`). The connection closes at once, said "closing connection #N", as the handle
  leaves a multi of the application's, or, in a handle's own multi
  (`Multi::make_handle_own`, C's `multi_easy`), as the handle's next transfer is added if the
  handle used it; else as the pool goes. `ConnectOnly::WebSocket` (2) makes its request and
  reserves the connection after, for WebSockets, which the build does not speak. `Attached { users }` comes before stage 5, for a connection several transfers lease
  at once (a pool place, not the transfer state of §3.1 that holds a lease). Until then every
  lease count is asserted to be 1. A connection shutting down is in no pool: its multi's
  `ShutdownSet` owns it (below).
- **Shutting down** (built, `conn/shutdown.rs`). Every path on which a connection
  leaves a pool (given back to close, evicted, found dead or too old, pruned, closed for room,
  a cleanup) goes through one discard, shaped as `cpool_discard_conn` (conncache.c:187–247): an
  aborted transfer's or a CONNECT_ONLY connection is terminated at once, as a shutdown would
  tell the server the transfer succeeded; else it gets one `Layer::shutdown` try with the
  silent context (`Curl_cshutdn_try_once`); done, it is closed (with the 1 KB drain below);
  not done, it joins the `ShutdownSet` of the releasing transfer's multi, whichever pool it
  came from, a share's included (conncache.c:242), and is terminated when there is no multi
  (a share's cleanup). A share's pool evicting for room terminates after the one try, as
  `cpool_evict_conn` does for a pool with no multi of its own. The set is the one owner,
  holding the connection with its stream, settings and closer, each under a `ClosingId` of
  the set's own, as a connection there is no longer in an arena. It is capped as C caps it:
  `max_total` less the connections in the releasing multi's own pool, 1 when none is left,
  and with no limit `max(n / 4, 128)` for `n` in that pool; past the cap the oldest closing
  connection is terminated. A termination from the set reads nothing first: the drain is part
  of a shutdown, not of a close. Closing connections
  count toward the host and total limits a new connection is checked against
  (`cpool_check_limits`): after the oldest idle ones, the oldest closing ones to the same
  destination, then any, are terminated to make room, and only what cannot be closed makes the
  transfer wait. Each connection's deadline is its `ConnSettings`' shutdown timeout, always
  C's default of 2 s (`set.shutdowntimeout` is set by no option), counted from the first try;
  the earliest is the set's own deadline (§3.4). Under a share's lock the room a new
  connection checks for is the share's pool and the multi's set together. `perform` and `socket_action` drive the set (`Curl_cshutdn_perform`),
  `wait`, `fdset` and `waitfds` include its sockets, and a multi's cleanup gives it one
  best-effort pass (timeout 0), or with `debug-hooks` waits `CURL_GRACEFUL_SHUTDOWN` ms. Its
  sockets are owned by the connection (`SocketOwner::Conn`, §4.7): as a connection moves into
  the set its socket stays registered, its transfer gone from it (C's `removed transfer,
  total=0/1 (xfer/conn)`) and no socket callback made; the callback hears `remove` when the
  set closes it, through the internal `CURL *` (`SocketFor::Multi`, §7.5), at the latest at
  the multi's cleanup (758's sequence). A share's connection joining the set is announced
  once the share's lock is let go, where C announces it under the lock. Nothing of it is traced: C's `[SHUTDOWN]` lines and the shutdown's TLS
  lines are on its internal handle. A kept-alive TLS connection sends its close_notify from
  the cleanup's pass, as the reference does. Plain TCP never waits in the set: C's TCP shutdown
  finishes in one call (cf-socket.c:1094–1114). A transfer arms SHUTDOWN itself only for a TLS
  or FTP shutdown it makes on its own connection (vtls.c:1572; ftp.c:562, through
  `Curl_xfer_set_shutdown`), with STARTTLS and FTP.
- On a share's pool, `find`, `add` and `release` are each one use of it under its lock, and a
  transfer joining its multi is one more with nothing done (`Curl_cpool_xfer_init`). Test 1554
  pins this sequence (SHARE, CONNECT ×3 on first perform; CONNECT on return), so these four
  never merge or split.
- Leaving the pool, a connection is closed at once. Every close of an established TCP connection
  but a terminated one (`Released::Terminated`, an aborted transfer's) first reads up to 1 KB
  from the socket and drops it, as C's `cf_socket_shutdown` does (cf-socket.c:1102–1110) on
  each non-aborted close (`cpool_discard_conn`): given back to close (`Released::Closed`),
  evicted, found dead or too old, pruned, closed for room, or closed at a multi's or share's
  cleanup. A setup's sockets are closed without it, as C's socket filter is not connected yet.
  A connection whose layers shut down gracefully (TLS's close_notify) is in the
  `ShutdownSet` instead until they are done (above).
- **The closer is carried from creation.** `Pool::add` captures the creating transfer's
  closer (CLOSESOCKETFUNCTION and its data, else the system's) and the connect machine gives it
  to every socket the connection opens, the attempts included, as C copies it onto the
  connection (url.c:1167) for `socket_close` to use whoever closes (cf-socket.c:535–556; its
  return is ignored, and an accepted socket is closed without it). A socket is a `Sock`, which
  only `Net::close` consumes; dropping one unclosed is a debug-build assertion.
- **Socket close order** is enforced by the network the pool is handed: inside a multi it is
  `Announcing` (`EngineRest::net`, `EngineRest::pool_section`), whose `close` forgets the socket
  in the `SocketTable` first (socket callback REMOVE if the application was told of it, C's
  `Curl_multi_will_close`), then closes it through its closer. Every pool path that closes a
  socket goes through it, so none can skip the order. A share's pool section holds the sockets
  it closes (`CloseLater`) and closes them once the lock is let go, so neither the socket
  callback nor the closer runs under a share's lock. It holds as many as a lease given back
  closes (each attempt of a setup, and one idle connection over the limit) without allocating;
  a search or an addition, which may close any idle connection, first makes room for one socket
  for each connection in the pool, under the lock, and fails for memory without it
  (`pool_search`). A socket with no room is an assertion, never a close under the lock.

### 4.6.1 The share

`Share` (`share.rs`, `CURLSH`) keeps what it is asked to (`Share::keep`, `CURLSHOPT_SHARE`):
idle connections (`Kind::Connections`), names (`Kind::Names`), cookies (`Kind::Cookies`), each
behind a mutex of its own, and the network its idle connections close through at the end, as
C's share closes them through its own internal handle. Each closes through the closer its
socket was opened with (§4.6): the CLOSESOCKETFUNCTION, with its CLOSESOCKETDATA, of the
transfer that made the connection, even once that handle is gone, as C keeps both on the
connection (url.c:1167) and `curl_share_cleanup` closes through them; so does a multi's
cleanup for its own pool, and an easy handle's cleanup for its private multi's. What it
keeps cannot change while a handle holds it (`Share::holders`). A handle holds its share
(`Easy::set_share`, C's `data->share`): kept through `reset`, not copied by `try_clone`, as C's
`duphandle` links none. Each transfer uses its share's pool, names or jar where the share keeps
that kind, else its multi's (or, for cookies, its handle's), whichever multi or thread runs it,
so a connection one handle's multi made is reused by the next (tests 2051, 2052, 3225).

Each use is one short section under that kind's mutex, with nothing called out from inside:
a search of the pool, an addition to it, a release; a lookup, a name kept, the names pruned at
a transfer's end; a cookie file read, a `Set-Cookie:` stored, a `Cookie:` line built, the
application's calls on the jar, a save. Sockets a pool section closes are held and closed once
the lock is let go (`CloseLater`), as closing one tells the socket callback; what a cookie
section would trace is held and traced after (`Held`). A connection a transfer uses is out of
the pool, its lease's, until it is released to the pool `ConnLease::home` names.

The application's lock functions are told around each use, for the kinds the share keeps,
where and as C calls them (test 506 for names and cookies, 1554 for connections): the handle
holds them as a watch with its share (`Easy::set_share_watched`, a `ShareLock`), and they are
called outside the share's own mutex, so they can neither guard nor break it. Some of C's
lock points do nothing here and are told all the same: a transfer joining its multi, a setup
letting go of its answer (`Curl_dns_entry_unlink`), the jar's start and a flush with no file.
The cookie files a transfer starts with are told as one use around the whole walk, warnings
and what each file's lines say traced inside it, as C locks once around it; each file is read
under the mutex in a section of its own. The share's cleanup tells CONNECT around closing its connections with no handle, where C gives
its internal one. A share's idle connections close when its last clone drops, each given its
one shutdown try with no clock (so in time) and terminated.

### 4.7 No admin easy

```rust
pub(crate) trait ConnCx: LayerCx {         // the connection context C's admin handle stands in for
    fn net(&mut self) -> &mut dyn Net;
    fn names(&mut self) -> Names<'_>;       // the multi's DnsCache, or the share's under its lock
    fn open_socket(&mut self, address: &mut SocketAddr) -> Opened;  // OPENSOCKET, or the network
    fn configure_socket(&mut self, socket: &dyn Socket) -> Configured; // SOCKOPT
    fn fail(&mut self, reason: fmt::Arguments<'_>); // failf: the first reason is kept
}
```

Connection-level work takes a `ConnCx`: a connect drive (`DriveCx`, over the stepping
transfer's `StepCx`, §3.6), and pruning, health checks, upkeep, shutdown and shutdown pollsets.
The settings a connection needs after its transfer (shutdown timeout, no_signal) are captured
per connection at creation, from the creating transfer's options and the multi's, as
`ConnSettings`, instead of C's `Curl_get_admin` copying the last caller's settings; the closer
is captured the same way (§4.6). The reuse limits (max idle, max age) are the searching
transfer's, passed to `find`. Connection-owned sockets appear in the `SocketTable` with a
`SocketOwner::Conn(ClosingId)` user while the connection is in the `ShutdownSet` (§4.6).

Built: `ConnCx` and `DriveCx`; the tests drive with `Plain`, which traces nothing and has no
hooks. The closer is not a call-out: it is captured with the connection (§4.6). `ConnSettings`
(the shutdown timeout, in ms) and `SocketOwner::Conn`; a shutdown's context is `Silent`.

### 4.8 Resolver

```rust
pub trait Resolver {
    fn start(&mut self, name: &[u8], family: Family, waiter: Waiter) -> Result<Resolve, ResolveFailure>;
    fn answer(&mut self, id: ResolveId) -> Option<Result<Vec<IpAddr>, ResolveFailure>>;
    fn wait(&mut self, id: ResolveId) -> Result<Vec<IpAddr>, ResolveFailure>;
    fn cancel(&mut self, id: ResolveId);
    fn answered(&mut self, each: &mut dyn FnMut(Waiter, ResolveId));
    fn waker(&self) -> Option<TryArc<Waker>>;
    fn explain(&self, why: ResolveFailure) -> Option<&'static str>;
}
pub enum Resolve { Answer(Vec<IpAddr>), Pending(ResolveId) }
```

The network has its resolver, as it has its sockets, lent to a closure (`Net::with_resolver`,
so that a network a test shares behind a lock lends it too): the system's network the system's
resolver, the tests' fake network names it answers for, at once or when the test lets them. `ResolveId` names one resolve of the resolver's, never reused, so a stale one fails closed
(C's `Curl_resolv_has_answers` fails open). `Waiter` is the transfer that started it (C's
`mid` in each queued item): the multi asks the resolver which have answered each time it runs
its own work, before the transfers (C's admin handle, `Curl_async_thrdd_multi_process`), and
runs those again. The resolvers come in order: the shortcuts (IP literals and `localhost`),
then the resolver; the resolver-start callback is announced for the shortcuts too (655 and
464).

The setup's own resolve waits in `Stage::Resolving`, its `ResolveId` held, its answer asked for each time the
transfer is run, cancelled as the setup closes; one dropped neither answered nor cancelled
aborts, as its answer would stay in the resolver. What it finds goes to the cache as before.
The other resolves wait where they are, as C's do (`Curl_resolv_blocking`): the interface a
socket binds to, by name, and, until step 48b makes it wait as the setup's own resolve does
(C's second DNS filter), a SOCKS proxy's destination resolved here. The system's resolver asks `getaddrinfo` and answers at once, as C's
synchronous resolver and the c-ares-like build do; the threaded resolver (step 48b) answers
later, from a thread pool, waking the multi.

The threaded resolver (`conn/threaded.rs`, `lib/vdns/asyn-thrdd.c` with `thrdpool.c` and
`thrdqueue.c`) is the build's when curl-core's `threaded-resolver` feature is on, which the shim
and the tool forward: one build has one resolver, as C's configure makes it. `SystemNet` holds
it, one per multi as C's queue is: a multi made for an easy handle's transfer keeps at most 2
threads, idle ones let go after 10 ms; any other at most 20
(`CURLMOPT_RESOLVE_THREADS_MAX`), after 2 seconds; none are kept when idle. A resolve of both
families is two queries, IPv6's queued first, each a thread's `getaddrinfo`; its answer is
both's addresses, IPv6's first, or, with none, a failure that is negative (kept as "the name
does not exist") only if every query said so. A worker that finishes a query wakes the multi
through the resolver's own eventfd (C's `wakeup_internal`), which the multi polls, and tells
the socket callback of, as its own socket while any transfer is alive; the multi drains it and
takes the answers before running its transfers. A thread that cannot be started leaves its
query queued, and the next start or pass tries again. Dropping the resolver lets its threads
go: each ends as its query does, and the multi's cleanup waits for them unless
`CURLMOPT_QUICK_EXIT` is set.

While a transfer is alive (from its first run to its message read, or its removal: C's
`xfers_really_alive`), the multi listens on the resolver's eventfd, if its resolver lends one:
the socket callback is told of it, as the multi's own socket, as the first transfer comes alive,
before that transfer's sockets, and told to remove it as the last is done; `wait` and the fd
set poll it, and `wait` counts it among the descriptors ready (`multi_assess_wakeup`).

The pool's settings are the resolver's, under its lock; the multi reaches them through a
`ResolverThreads` handle the resolver lends with its eventfd, so that an option set inside a
socket or timer callback, while a transfer holds the network, still reaches them. The most
threads (`CURLMOPT_RESOLVE_THREADS_MAX`) is taken by the shim only in a build with the feature,
which refuses 0 and anything past `UINT32_MAX`, as C's `#ifdef` does; raising it while a query
waits for a thread wakes the multi, whose next pass starts one. A quick exit
(`CURLMOPT_QUICK_EXIT`, and an easy handle's `CURLOPT_QUICK_EXIT` for `curl_easy_perform`'s
multi) leaves the threads running as the resolver goes rather than joining them; the tool asks
for it always but in the debug build, where only `CURL_QUICK_EXIT` does.

A resolve that answers later says how it was queued (`Queued`: its id, and which families went
as a query of their own), which the answer, or the failure, carries back to the transfer's DNS
trace: each query as queued, `queueing query [transfer/id] AAAA name:port`, IPv6's first, and
each query's addresses as taken, `Host name:port resolved IPv4: ...`, IPv4's first, `(none)` for
none, in the places C's lines fall among the cache's. They are written, with the rest of the
lookup's lines, as the answer is taken; the passes between, and C's DNS filter's own lines,
are not traced, as they are not for the system's resolver either. A name not answered within
the connect limit times out as "Resolving", not "Connection".

Built so far (step 48b): the pool, its queries and answers, the eventfd it wakes, `SystemNet`
holding it in a build with the feature, the multi listening on that eventfd, the two options,
the resolver's DNS lines, and the debug build's variables (`DebugVars`, read as the resolver is
made: `CURL_DBG_RESOLV_DELAY`, `_FAIL_DELAY`, `_FAIL_NEGATIVE`, `_MAX_THREADS`,
`CURL_DBG_THRDPOOL_FAIL_STARTS`). A thread that cannot be started leaves its queries queued;
the resolver then asks to be tried again in 100 ms (`Resolver::retry`), which the setup arms as
its `ASYNC_NAME` timer, and the next pass starts one. The debug build's
`CURL_DBG_RESOLV_FAIL_IPV6`, `hostip_resolv`'s for every resolver, is read as the multi is made:
a resolve of IPv6 addresses alone then fails before the cache and the shortcuts are asked
(`Unresolved::DebugFailIpv6`), for the setup and for a bind alike. Left out by decision: the
blocking resolve's `await` lines (`Curl_async_await`'s "await, waiting Nms") and the thread
queue's own trace (`thrdq`), which no test reads and whose count depends on the threads'
timing. Not ported: C's re-query, for `AF_UNSPEC`, of an IPv6 answer
with a link-local address but no scope (`async_thrdd_item_missing_scope`), a workaround for a
glibc that gives scopes only to `AF_UNSPEC` queries. Reproduced against glibc 2.43 (a DNS
server in a network namespace answering `fe80::1`), neither query gives a scope, so the
re-query gains nothing; the connect fills a link-local address's missing scope from the
interface, as cf-socket.c does. Only pytest's test_21_16 looks for the re-query's line, and it
needs a build that overrides DNS, which the threaded oracle is not.
`DnsCache` is in the multi's `Caches`, or a share's (section 4.6.1): entries by name, in
any case, and port, each a `TryRc<Answer>` that the connect machine using it shares, recording
the family asked (`dns_queries`): an answer for one family is no answer for both. A setup
looks in the cache first (`hostip_resolv`), then asks the shortcuts, then the resolver, and
keeps what they answer for the cache's timeout (`CURLOPT_DNS_CACHE_TIMEOUT`, the transfer's: 60
seconds unless set, for ever at -1). That a name does not exist, or has no address of the family
asked, is kept too, as an answer with no addresses ("Negative DNS entry"), which ages twice as
fast; that the resolver could not answer is not. A name's HTTPS-RR answer is an entry of its
own beside its addresses (C's `CURL_DNST_HTTPS`), that it has none, aging as a negative answer
does; it shares the name with the addresses' answer. A resolver's failure is said as it answers,
with the resolver's reason if it gives one (`Resolver::explain`: c-ares's "Domain name not
found" for the resolvers that stand in for the reference build's, none for the threaded
resolver, as C's gives none), then said again without it. `CURLOPT_RESOLVE` entries are read into the cache when a transfer
starts, once for each time the list is set (`Options::resolve` carries a stamp, the easy the
stamp it last read), as its source has them then; a list set while one is read, from the
debug handler, is taken as read too, as C clears `state.resolve` after reading. They are permanent unless given with `+`, and `*` answers for any name on
its port. A transfer's end prunes what has gone stale (`multi_done`).

### 4.9 TLS

Built (steps 43d to 43h): the seam, the layer, the identity reuse compares, the `https`
scheme and the setup's TLS stage, the goodbye through the shutdown set, driven in the core's
tests by a fake library (`tls::fake::FakeTls`); and OpenSSL's session in curl-openssl (**The
BIO**, the context, **Verification** and the host check), which the tool and the C ABI give
every handle (`Libraries::tls`), reporting `https`, `SSL` and `OpenSSL/3.5.9` as C's build does
(`curl -V`, `curl_version_info`); the CA store each multi keeps for its next connections
(`TlsShared`); close_notify (**Shutdown**); **The session cache** and the key log.
MILESTONES.md step 43 lists the sub-steps.

```rust
// curl_core::tls, public: the seam a TLS library implements (curl-openssl)
pub trait TlsBackend: Send + Sync {
    fn session(&self, identity: &TryArc<TlsIdentity>, peer: &TlsPeer<'_>, alpn: Alpn,
               shared: &TlsShared) -> Result<Box<dyn TlsSession>, ErrorKind>;
    fn ca_defaults(&self) -> CaDefaults;           // the build's CA file and path
    fn id(&self) -> &dyn fmt::Display;             // `OpenSSL/3.5.9`, as a session's key names it
}
pub enum Alpn { None, Http11, Http10 }             // the offer, from the HTTP version
#[derive(Clone)] pub struct TlsShared(/* TryArc<Mutex<Option<Box<dyn Any + Send>>>> */);
impl TlsShared {                                   // the library's per-multi state, its own type
    pub fn with<T: Any + Send, R>(&self, make: impl FnOnce() -> T, f: impl FnOnce(&mut T) -> R)
        -> Result<Option<R>, OutOfMemory>;         // none: another library's state is there
}
pub trait TlsSession: Send {                       // one connection's TLS, never Sync
    fn handshake(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind>;
    fn recv(&mut self, io: &mut TlsIo<'_>, buf: &mut [u8]) -> io::Result<Recv>;
    fn send(&mut self, io: &mut TlsIo<'_>, bytes: &[u8]) -> io::Result<Sent>;
    fn shutdown(&mut self, io: &mut TlsIo<'_>) -> Result<Handshake, ErrorKind>;
    fn waits(&self) -> TlsWait;                    // Nothing, Recv or Send: C's io_need
    fn pending(&self) -> bool;                     // decrypted bytes not yet read
    fn native(&self) -> Option<TlsNative>;         // the library's objects, once made
    fn chosen(&self) -> Option<Chosen>;           // what the peer chose by ALPN, once done
}
#[derive(Clone, Copy)] pub struct TlsNative {     // opaque to the core, which passes it on
    context: NonNull<c_void>, session: Option<NonNull<c_void>>,  // SSL_CTX *, SSL *
}
pub struct TlsIo<'a> { /* Below<'a>, &'a mut dyn LayerCx, the early bytes; private */ }
impl TlsIo<'_> {                                   // what a library's BIO and callbacks reach
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<Recv>;   // the early bytes first
    pub fn send(&mut self, bytes: &[u8]) -> io::Result<Sent>;
    pub fn trace(&mut self, line: fmt::Arguments<'_>); pub fn info(&mut self, ..);
    pub fn fail(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind; // failf
    pub fn record(&mut self, way: TlsWay, bytes: &[u8]); // CURLINFO_SSL_DATA_IN/OUT
    pub fn debugs(&self) -> bool;                  // a debug handler is set (fdebug)
    pub fn now(&self) -> Instant;                  // the pass's time (Curl_pgrs_now)
    pub fn configures_context(&self) -> bool;      // CURLOPT_SSL_CTX_FUNCTION is set
    pub fn configure_context(&mut self, native: TlsNative) -> Result<(), ErrorKind>;
    pub fn pause_recv(&mut self);                  // Curl_xfer_pause_recv
    pub fn peer_alive(&mut self) -> bool;          // is_alive of the layers below
    pub fn unix_time(&self) -> i64;                // time(NULL), a ticket's lifetime's start
    pub fn caches_sessions(&self) -> bool;         // Curl_ssl_scache_use
    pub fn take_session(&mut self) -> Option<TlsTicket>;   // Curl_ssl_scache_take
    pub fn keep_session(&mut self, t: TlsTicket);          // Curl_ssl_scache_put
    pub fn return_session(&mut self, t: Option<TlsTicket>); // Curl_ssl_scache_return
    pub fn forget_sessions(&mut self);             // Curl_ssl_scache_remove_all
}
pub struct TlsTicket { pub data: Vec<u8>, pub version: u16, pub alpn: Option<Chosen>,
                       pub earlydata_max: usize, /* valid_until */ }
pub struct TlsPeer<'a> { pub name: &'a [u8], pub port: u16, pub kind: TlsPeerKind }
pub struct TlsIdentity { pub verify_peer: bool, pub verify_host: bool, pub options: TlsOptions,
                         pub ca_defaults: CaDefaults }
```

**The seam.** The dependency runs from the binding to the core, as the decoders' does, so the
core names no library's type. `Layer` stays crate-private; the core's `conn::tls::TlsLayer`
implements it over the `Box<dyn TlsSession>` a library makes: `connect` is the handshake,
`recv` and `send` pass the caller's buffer and length as they are, `adjust_pollset` replaces
what the transfer wants with what the session waits for (`Curl_ssl_adjust_pollset`'s
`set_out_only` and `set_in_only`: OUT while a read must write), `data_pending` is the session's
`pending` and the early bytes, `is_alive` passes down, and `shutdown` is the session's. A
library's error is its `ErrorKind`, and it gives the text it fails with itself (`TlsIo::fail`,
C's failf), as C's filters each give theirs: a read or a send through a session that said why
it failed is not said for again by HTTP, and a socket failing under a session is said first,
as the socket says it (`Recv failure:`, `Send failure:`). A handle
reaches its library through one `SharedLibraries` (the decoders, the Ed25519 signer, the
TLS library, the GSS-API library), the shim's statics or the tool's shared value, so a handle
carries one pointer for all of them; `Easy: Default` takes `Libraries::NONE`. Without a TLS library `https` is a scheme the
build leaves out (`Protocol "https" is disabled`, `UnsupportedProtocol`), as in C built
without TLS; the shim and the tool give every handle OpenSSL. One library
is built, OpenSSL 3.0
or later, checked at build (curl-openssl's build script reads the version openssl-sys found,
`DEP_OPENSSL_VERSION_NUMBER`, and refuses LibreSSL) and at init (`OpenSSL_version_num`): an
older library is a backend that is not there. `curl_global_sslset` answers OK for
`CURLSSLBACKEND_OPENSSL` or `"openssl"`, also after init, and `CURLSSLSET_UNKNOWN_BACKEND` for
any other, with only OpenSSL available.

**The stage.** `https` is HTTP over TLS (`proto::http::HTTPS`, port 443, which `Host:` and the
signatures leave out): its route carries a `TlsIdentity`, which is what C's `PROTOPT_SSL` comes
to here, and through an HTTP proxy it always tunnels (`Curl_proxy_init_conn`). A connection on
such a route is dialed for its handshakes, and the origin's TLS is the last of them
(`handshake_due`, after SOCKS, the tunnel and the PROXY line): `multi/state/tls.rs` asks the
library for a session with the origin as the peer (no SNI for an address, `TlsPeerKind`),
pushes its layer on the stream with the bytes the stream received and did not use, and moves
the handshake on as the socket lets it, waiting for what the layer says beside the socket's own
IN; the connect limit covers it (`Connection timed out after N milliseconds`). `SETUP` traces
`added SSL filter for origin`, and the chain shows `[SSL]` right below SETUP until the setup
filters go (`reduced to [0][SSL][TCP]`). As it is up, `TIMER_APPCONNECT` is marked, then
`TIMER_CONNECT`. Secure cookies go over it and may be set from it (`Curl_secure_context`).

**The BIO.** curl-openssl drives OpenSSL as `lib/vtls/openssl.c` does, through a BIO method of
its own whose read and write go to the layer below, so the `SSL *` and `SSL_CTX *` the
application is handed look as they do in C, and the trace shows OpenSSL's own read pattern.
For the length of each `SSL_*` call the BIO's data points at a slot on the stack holding the
`TlsIo` and the call's result; the trampolines read through it, set the retry flags and note the
peer's close; the slot is set before the call and cleared after, and the callbacks run only
inside those calls, on that thread (the SAFETY invariant of `bio.rs`). No callback touches the
session's own fields while the `SSL_*` call holds them. The X509 store is set up at the first
read, as C does, so the ClientHello goes out before the CA file is read (`recv(len=5) -> 81`,
then `configuring OpenSSL's x509 trust store`). No option C does not set (read-ahead among
them), so the record pattern is the same library's on both legs. `ERR_clear_error` precedes
each call; `SSL_ERROR_WANT_*` is would-block, `ZERO_RETURN` the end, `SYSCALL` the socket's
error; a NULL from a constructor is `OutOfMemory`. OpenSSL allocates from libc, outside the
debug tracker, as in C: `CRYPTO_set_mem_functions` is process-wide and fails once the
application has used OpenSSL, so it is not called.

**Verification.** The CA default is decided at build time as CMake decides it
(CMakeLists.txt:1475), by curl-openssl's build script: `CURL_CA_BUNDLE` and `CURL_CA_PATH`
from the environment (`none`, `auto` or a path), else found on the building machine unless it
builds for another: the first of CMake's five bundles that exists
(`/etc/ssl/certs/ca-certificates.crt` here), and `/etc/ssl/certs` as the path if it holds
hashed certificates (`xxxxxxxx.0`; none here); one set explicitly stops the other being looked
for; no fallback to OpenSSL's own paths. They are `&'static str` (`TlsBackend::ca_defaults`),
so a handle holds no CA string until the application sets one, and `CURLINFO_CAINFO` returns
the constant whatever the handle set, as C's does. The tool
reads `CURL_CA_BUNDLE`, `SSL_CERT_DIR` and `SSL_CERT_FILE` as tool_operate.c does.
**The CA store cache** (`Curl_ssl_setup_x509_store`, curl-openssl's `cache.rs`): a store a
connection loads is kept for the multi's next ones, which take it at their first read instead of
loading (nothing traced: no `configuring OpenSSL's x509 trust store`, `SSL Trust Anchors:` or
`CAfile:`), while it is younger than the taking transfer's `CURLOPT_CA_CACHE_TIMEOUT`
(`CaCache` in the TLS options, a day unless set, `Forever` for -1, `Off` for 0; not compared for
reuse, as `alpn`) on the multi's clock, and was loaded for the same CA file, CA path (as they
resolve) and partial-chain bit; a store loaded in its place is kept from then. Only a verified
peer with no blob, no CRL and no `NATIVE_CA` takes or keeps one. It is OpenSSL's state in the
multi's `TlsShared`, which the multi makes with its first session (`Multi::tls`, beside the
caches, never a share's, as C keeps it in `multi->proto_hash`) and hands to every session; the
session keeps a clone until its store is set up, so a connection does not keep it alive, and it
goes with the multi. `curl_easy_perform`'s private multi lasts from one perform to the next, so
a handle's later performs take its store, as C's `multi_easy` does. Without room for it, a store
is loaded and not kept, as C does. A CA file that cannot be read
fails the first read's setup and, as in C, is tried and said again by the handshake's step (77,
`error adding trust anchors from file:` twice).
A revocation list (`CURLOPT_CRLFILE`, `--crlfile`) is loaded into the store after the trust
anchors, by OpenSSL's file lookup, and turns the CRL check on for every certificate of the chain
(` CRLfile:`; a file holding no list fails the setup with 82, `error loading CRL file:`); with
one no chain is taken as partial (OpenSSL's issue 5081), and its store is not kept for the multi.
The host check is hostcheck.c's, ported (unit 1397), after `ossl_verifyhost`
(`subjectAltName: "localhost" matches cert's "localhost"`); the failure texts are C's
(`SSL certificate problem: …`). OpenSSL's verify result is the report's
(`CURLINFO_SSL_VERIFYRESULT`, `%{ssl_verify_result}`): 1 from the session's first step, then
the library's code once the peer is checked or its handshake fails verifying; like C's
`set.ssl.certverifyresult` it is the handle's, kept as transfers start over and cleared by a
reset. With the peer unverified (`-k`) no CA is loaded, even one given (`SSL Trust: peer
verification disabled`), and the result is traced and ignored (`OpenSSL verify result: 14`,
`SSL certificate verification failed, continuing anyway!`); a pinned key (`--pinnedpubkey`) is checked after, `-k` or not (90,
`SSL: public key does not match pinned public key`): the library gives the DER of the peer's
SubjectPublicKeyInfo and the core compares it (`tls::pin_peer_pubkey`, vtls.c's
`Curl_pin_peer_pubkey`), by the base64 of its SHA-256 (`sha256//`, several `;` apart, ` public key
hash:` said) or as a file of it in DER or PEM.

**The client's certificate** (`cert.rs`, `client_cert`) is loaded into the context before the
session is made, when a certificate, a blob or a type is set: PEM as a chain (from a file, or
from memory as `SSL_CTX_use_certificate_chain_file` reads one), DER, or PKCS#12 with its CAs
added to the chain; the key from its own file or blob, of its own type, or else the
certificate's with the certificate's type, then checked against it. A password reaches OpenSSL
through `passwd_callback`, held by the session as long as the context that points at it. An
engine's or a provider's certificate or key fails as C's does with none set (`crypto engine not
set, cannot load certificate`, 58); an unknown type is 43, as C. The tool's `--cert` splits
`name:password` as `parse_cert_parameter` does, `\` escaping a colon or itself.

**The peer's chain** (`CURLOPT_CERTINFO`, a per-handle bit in `Tls` that the identity does not
compare) is read first in the peer check (`certinfo.rs`, `ossl_certchain`): each certificate's
fields as `label:value` lines worded as C's, into a `CertInfo` the transfer's report holds
(`info.certs`, through `LayerCx::certinfo_report`), so a peer that then fails its check has
been reported all the same, and a chain longer than 100 fails the handshake (35). The report's
restart clears it. The shim answers `CURLINFO_CERTINFO` with the handle's `struct curl_certinfo`,
made again only when the chain differs; the tool asks for it whenever `-w` is given, for
`%{certs}` and `%{num_certs}`. A resumed session skips it, as its chain is not sent.

**Engines and providers** (`engine.rs`, `CURLOPT_SSLENGINE` and `_DEFAULT`, handle fields in
`TlsOptions` the identity does not compare) are selected first in `step1`, as
`ossl_set_engine`: an engine of that id, started (66 if it will not start), else a provider
`name[:properties]` loaded into a library context of the session's own with `base` beside it
(53 if it cannot be; 43 for no name or one over 128), the context then made in it
(`SSL_CTX_new_ex`) and no store kept for the multi (`USING_PROVIDER`); an engine is made the
default for every algorithm when asked (54). OpenSSL 3.5's engines (`afalg`, `loader_attic`,
and any `OPENSSL_ENGINES` holds) are found by id; `dynamic` will not start. A `PROV`
certificate or key is read from the provider's store (`providerload`, `providercheck`), a
PKCS#11 URI selecting `pkcs11` when none is; an `ENG` certificate is the engine's
`LOAD_CERT_CTRL` command's (`engineload`) and an `ENG` key `ENGINE_load_private_key`'s
(`enginecheck`), its prompt for the default password answered with the key's password by a UI
method of C's (`ssl_ui_reader`, `ssl_ui_writer`). The peer tests build an engine of that kind
(`tests/peer/curltest_engine.c`). `CURLINFO_SSL_ENGINES` and the tool's `--engine list` list
the library's engines, once it is initialised.

**The issuer and the stapled status** follow the verify result, as in `Curl_ossl_check_peer_cert`.
With `CURLOPT_SSL_VERIFYSTATUS` (`--cert-status`) the session asks for a stapled OCSP response
and `ocsp.rs` checks it as `verifystatus` does: there, successful, signed by the verified chain
against the context's store, naming the peer's certificate, current within five minutes' skew,
and good; each shortfall is 91 in C's words. A resumed session is not checked, as in C; a
transfer that checks the status resumes none, so only a session C's FTP data connection
borrows would be. `CURLOPT_ISSUERCERT` or its blob then names the
certificate that must have issued the peer's (`ossl_check_issuer`): 83 if it cannot be read or
did not, said only when the peer is verified. The pinned key comes last.

**Identity and reuse.** `Tcp` holds `tls: Option<TryArc<TlsIdentity>>`: the verify bits and a
copy of the transfer's cold `TlsOptions`, every field `match_ssl_primary_config` compares
(versions, the options bits, the status check, CA file, path and blob, the CRL, the issuer, the
client certificate and key with their formats and password, the cipher lists, curves,
signature algorithms, the pinned key), made per leg, shared by the route and the connection,
so `ConnSlot` and `Slot` keep their sizes (224 and 952 bytes measured with it, under their 232
and 976 pins, the SOCKS pre-proxy shared to make room). Its `eq` destructures every field: the
paths, blobs and keys exactly (`Curl_safecmp`), the lists and formats in any case
(`curl_strequal`), the password in constant time (`Curl_timestrcmp`); ALPN is not compared.
A transfer that verifies never takes a connection made without (the CVE-2021-22924 class). The
CA file and path keep the build's default apart from none (`CaSetting`), and the identity
carries the library's defaults, so it compares the file and path they resolve to: a handle that
names the default's path matches one that keeps the default, as C finds them, having copied the
default into the setting (`Curl_ssl_filter_config_tmp_init`). An HTTPS proxy's route carries an
identity of its own (`ProxyRoute::tls`, `TlsIdentity::of_proxy`), C's `proxy_ssl_config`: the
proxy's options (`Proxy::tls`, `CURLOPT_PROXY_SSL*`), its CA defaulting as the origin's, without
curves or signature algorithms, which C has no proxy options for, and with the origin's ALPN,
CA cache, engine and session cache, which C keeps once for both. The proxy key compares it
(`url_match_proxy_use`), so a connection never serves a transfer whose proxy TLS differs,
whatever its origin's; sessions with the proxy share the multi's cache, keyed by the proxy as a
peer.

**The session cache** (`tls/cache.rs`, vtls_scache.c) keeps what peers give to resume. Its one
owner is the multi (`Caches::sessions`, 25 peers, `curl_easy_perform`'s own multi 3 as
easy.c's), or the share in its place when the share keeps `Kind::SslSessions`
(`CURL_LOCK_DATA_SSL_SESSION`, 25 peers, made as it is kept and dropped as it is let go): a
transfer uses its share's if it has one (`cf_ssl_scache_get`). It is reached only through
the layer context (`LayerCx::tls_sessions`), the share's under its lock with the application's
lock function told first and its unlock last, as `Curl_ssl_scache_lock` nests them; the
multi's lent out of the multi for the call. A peer is a slot, made as first needed up to the
cache's count: found by its key and by the client certificate and key password it was added
with (a certificate blob is named by its address in C, so its sessions are never found again;
here likewise); a new peer takes a free slot, else one holding no session, else the least
recently taken from. A peer keeps two tickets: one before TLS 1.3 replaces the others, one of
TLS 1.3 joins those still good, the oldest dropped; a lifetime is cut to a week for TLS 1.3, a
day before, and none given is a day; a ticket out of date is dropped as it is looked at. A
ticket taken is TLS 1.3's alone, never given back (RFC 8446 C.4); one before is kept again.
The key (`SessionPeer`, made with the TLS layer, `Curl_ssl_peer_key_make`) is the origin and
every setting a session must share, each text after its length, a blob by its SHA-256, a
relative path made absolute (`realpath`) or the key made local (`:L`), and the library's id:
`https:localhost:18443:KEY-V3:TLSVER-6-0:CA-58:<CA file>:IMPL-13:OpenSSL/3.5.9:G`, with
`NO-VRFY-PEER:NO-VRFY-HOST` and no CA for an unverified peer, and a connect-to's peer
(`CHOST`, `CPORT`) while either check is off. `CURLOPT_SSL_SESSIONID_CACHE` (`--no-sessionid`)
is the connection's (`TlsOptions::session_cache`, not compared for reuse, as C): off, nothing
is looked up or kept. OpenSSL's session takes one at its first step, between SNI and ALPN,
unless the status is to be checked (`ossl_init_session_and_alpns`: `SSL reusing session with
ALPN '-'`, `SSL verify result: 0`, or why it was not), and keeps each session the library
tells of (`SSL_CTX_sess_set_new_cb`, `SSL_SESS_CACHE_NO_INTERNAL`) as its DER through the BIO's
slot: before TLS 1.3 at the handshake's end, TLS 1.3's NewSessionTicket messages as the
transfer reads its response. A peer that fails its check has its sessions forgotten. A ticket
arriving while a connection says goodbye has no transfer to be kept for and is dropped; C
keeps it in the multi's cache through its internal handle (not built, MILESTONES.md). The trace is C's under `ssls`.
`curl_easy_ssls_import` and `export` answer `CURLE_NOT_BUILT_IN`, as a C build without
`USE_SSLS_EXPORT`, and `SSLS-EXPORT` is not reported.

**The key log** (`tls/keylog.rs`, keylog.c): the file `SSLKEYLOGFILE` names, opened to append
by the shim's first global init (also `curl_easy_init`'s, for a program that made none) and
closed by its last cleanup, and opened by the tool as it starts: each owns one `KeyLog`, the
shim's a static in its root, the tool's in the value `main` holds, handed as a `SharedKeyLog` to
the OpenSSL value its handles are given (`OpenSsl::logging_keys_to`); the core keeps none. Each
session OpenSSL makes holds its own `SharedKeyLog`, so the log outlives its owner while a
session does. OpenSSL here is built without its own (`OPENSSL_NO_SSLKEYLOG`), so as C the
session sets the library's keylog callback while the log is open, whose lines are written
whole, a line end added (NSS's format: five secrets for TLS 1.3, `CLIENT_RANDOM` before it);
each handshake done says `SSLKEYLOGFILE set, all TLS secrets are logged to '<file>'`.

**The application's hands on the library.** A library's objects reach the application as a
`TlsNative`: two pointers the core never looks through, the context and, once made, the
session's own object. `CURLOPT_SSL_CTX_FUNCTION` is a transfer call-out (api.c's
`easy_fsslctx`), so it is a `TlsContextHandler` in the TLS options' cold group (the handle's:
the identity a connection keeps holds none), called through the transfer's context
(`TlsIo::configure_context`, `LayerCx::configure_tls`) with the context alone; its error fails
the transfer with its kind (`error signaled by SSL ctx callback`). A transfer's handlers reach the
objects of the origin's connection it holds (`TransferCx::tls_native`, `EventCx`, `NotifyCx` and
`Multi::tls_native` alike, by id): through the run in its slot, its connection's layers asked
(`LayerQuery::TlsNative`); for the stepping transfer, whose run is out of its slot, the step
lends what its connection answers to its `StepCx` for the step, and the context handler's call
lends the context it is given, as C's getinfo finds them on `data->conn`. None once the request
is over (`Done`), as `multi_done` lets the connection go, nor without a connection. A session may
stop the transfer's receiving (`TlsIo::pause_recv`, C's `Curl_xfer_pause_recv`): its handshake
is not moved on and its pollset is empty (`paused 0/1 (r/w)`), its socket removed, until the
application unpauses it. OpenSSL's objects are its `SSL_CTX` and `SSL`; its session calls the
handler before `SSL_new`, its trust store set up first (C's #11800), and pauses so for
`SSL_ERROR_WANT_RETRY_VERIFY` (`SSL_connect() -> want retry_verify`), a verify callback the
application installed asking to be retried (lib758). The shim keeps each handle's function and
data (`CURLOPT_SSL_CTX_FUNCTION`, `_DATA`), copied by `curl_easy_duphandle` and cleared by a
reset, and calls the function with the handle and the `SSL_CTX`; a code the transfer can end
with is its result, any other an abort (DIVERGENCE.md). `CURLINFO_TLS_SSL_PTR` and `TLS_SESSION`
point at the handle's `curl_tlssessioninfo`, `CURLSSLBACKEND_OPENSSL` with the `SSL` or the
`SSL_CTX`, NULL while the transfer holds no connection, as C's getinfo answers. The SSL data (`CURLINFO_SSL_DATA_IN`,
`OUT`) and the msg callback's text lines go through `TlsIo::bytes` and `info`.

**ALPN.** Until HTTP/2 (stage 5) the offer is a C build's without nghttp2: `http/1.1` alone,
one baller (`1st attempt uses h1 from wanted versions`); the reference offers `h2,http/1.1`, so
the goldens are its `--http1.1` runs. `ENABLE_ALPN` off offers none. The HTTPS-CONNECT race and
its timer are rendered and armed as §2.5 and §3.4 say; SNI is sent for a host name, never for an
IP literal.

**The chain.** The origin's TLS is the last handshake (`handshake_due`), pushed as a layer over
the stream once the others are made: `[SSL][TCP]`, `[SSL][SOCKS][TCP]`, `[SSL][H1-PROXY][TCP]`.
An HTTPS proxy's TLS is made after the eyeballs race and any SOCKS pre-proxy, before the
proxy's `CONNECT`, and stays a layer: `[SSL][H1-PROXY][SSL-PROXY][TCP]` through a tunnel, TLS in
TLS, the origin's layer's `Below` being the proxy's layer; `[SSL-PROXY][TCP]` for a request
forwarded to the proxy, whose SETUP line C words `added SSL filter for origin`. The race does
not apply to the proxy's handshake. The two sides are `TlsSide`, the layer's filter
(`Component::SslProxy`) telling its session it is the proxy's (`TlsIo::for_proxy`): it offers
`http/1.1` by ALPN (`cf_ssl_proxy_create`), names the peer's certificate `Proxy certificate:`,
keeps its verification apart (`Report::proxy_verify_result`), answers neither the TLS library's
objects nor the waits of the origin's layer, and does not mark `TIMER_APPCONNECT`.

**Shutdown.** A TLS layer's `shutdown` is its session's: the discard's one try, then the
multi's `ShutdownSet` until the peer's goodbye or the connection's 2 s. OpenSSL's is
`ossl_shutdown` with C's `send_shutdown` set, once, and only after a handshake that was done: it
reads first for a close_notify the peer sent, and sends nothing to a peer that closed after it;
else it sends close_notify (`SSL_shutdown`) and reads for the peer's, waiting as the read or the
send says; a read that fails ends it. An aborted transfer's connection is terminated by §4.6's
discard and says nothing, as a goodbye would tell the server the transfer went well. So
close_notify goes on every graceful close, as the reference sends it: after the server's own
(`openssl s_server -www`), and from the cleanup's pass for a connection still kept.

**Errors.** The kinds `ErrorKind` kept get their producers: `SslConnectError` 35,
`PeerFailedVerification` 60, `SslCacertBadfile` 77, `SslCipher` 59, `SslCertproblem` 58,
`SslClientcert` 98, `SslPinnedpubkeynotmatch` 90, `SslInvalidcertstatus` 91, `SslCrlBadfile`
82, `SslIssuerError` 83, the engine's 53, 54 and 66, `RecvError` 56 and `SendError` 55 from TLS
I/O, `OperationTimedout` 28 for a handshake past the connect limit. They come as C's do: a
server that wants a client certificate the client lacks fails the first send, not the
handshake, under TLS 1.3 (`OpenSSL SSL_write: … Connection reset by peer, errno 104`, 55, or
`OpenSSL SSL_read: OpenSSL/3.5.9: error:0A00045C:…certificate required`, 56, when the alert is
read first: the failures `SSL_read` and `SSL_write` raise print `ossl_strerror`'s whole buffer,
the version before the error), and
OpenSSL 3.5 loads `--engine` as a provider (`Failed to initialize provider: …`, 53; `--engine
list` lists `dynamic`).

---

## 5. The data path and callbacks

### 5.1 Receive

A protocol reaches its connection through `StepCx::conn(&lease)`; `do_it`, `step` and `done`
are given the lease the transfer's state holds. Inside an `Exchanging` step of `http:`:
1. what is left of the request's head is sent (`Conn::send`, traced as HEADER_OUT as it goes);
   the request owns its send buffer, as C's `req.sendbuf` is per request;
2. reads follow until one would block, the response is over, receiving pauses or eleven reads
   were made (`sendrecv_dl`'s `maxloops`, §3.2): each `Conn::recv` reads into `conn.rx`, which
   the step takes out (`mem::take`), feeds whole to the head parser, the body and the chunk
   decoder, and puts back emptied. A read that would block while the stream has data pending
   runs the transfer again (§4.3);
3. EOF decides: a head cut short with a size known is "transfer closed with N bytes remaining to
   read" (18), a short body "end of response with N bytes missing" (18), unfinished chunks
   "transfer closed with outstanding read data remaining" (18), an `UntilClose` body ends. A
   connection that read EOF is not reused. A request on a reused connection that delivered
   nothing is made again on a fresh one (`AfterRequest::Retry`, at most `MAX_RETRIES` times).
4. `ProtoState::done`, before the last progress pass (`multi_done` calls the handler's `done`
   first), delivers a line the head parser still holds after the trace of whatever failed, as
   `Curl_http_done` does, ignoring what comes of it, and judges GOT_NOTHING ("Empty reply from
   server", 52, the connection closed).
While exchanging, the transfer waits on its socket for what the protocol says: IN while the
response is not over and receiving is not paused, OUT while the head has more to send.

Reads are capped at the transfer's BUFFERSIZE (`Limits::buffer_size`: 16384 unless set; the
tool sets 100 KiB, or its `--limit-rate` under that), by the receive limit's tokens, and at
`size - bytecount` in a body of known size on
non-multiplexed connections, as transfer.c's `xfer_recv_resp` does. The cap is redundant with a per-connection buffer (leftovers would simply
wait in `conn.rx`), but it fixes how `DATA_IN` traces are chunked and when unsolicited input is
seen; it is dropped only after a C-leg comparison on 1701 and 3223.

C reads into the multi's `xfer_buf`, the largest BUFFERSIZE any of its transfers asked for, but
`Curl_xfer_recv` cuts a network read to the transfer's own; `conn.rx` grows to that size before
a read, fallibly. A `file:` read takes the transfer's BUFFERSIZE less one, where C's takes the
multi's buffer whole: a file read beside a transfer with a larger buffer is read in larger
pieces there.

### 5.2 Response pipeline

```rust
pub(crate) struct Pipeline {
    raw_trace: bool,                             // DATA_IN of raw bytes before any decoding
    framing: BodyDecoder,                        // None | Length{left} | Chunked | UntilClose
    codings: Option<Box<Codings>>,               // transfer decoders, gate, content decoders
    accountant: BodyAccountant,                  // STARTTRANSFER, maxdownload, max_filesize (raw), short EOS
    out: ClientOut,
}
pub(crate) enum ClientOut { Direct, Held(HeldOutput), Failed }
pub(crate) struct HeldOutput { bytes: Vec<u8>, entries: Vec<Entry>, first: usize, held: usize }  // cap 64 MiB
```

- **Order is the chain's**: raw trace, transfer decoding (chunks, then the `Codings`' transfer
  decoders), accounting, pause gate, content decoders (last listed runs first), client output. The header collector writes into the
  report's `HeaderStore` from the response parser, before the line reaches `out`.
- **`ClientOut`** passes body in pieces of at most 16384 bytes whatever BUFFERSIZE is, header
  lines whole; with `include_header` a line goes to the write handler, then the header handler.
  Once anything is held, every later write is appended behind it and the entries replayed in
  order, so interleaving is kept. An included header line is body and joins the body entry
  before it; each header-handler line is its own entry. Consecutive body entries extend the
  last range: O(1) per append (C's quadratic class). The cap counts what is still held;
  delivered bytes are compacted away once more than the cap has gone, by moving, never
  allocating.
- **The gate** (`cw-pause`) exists from the first decoder that may make more than it reads
  (`Decoder::blows_up`, C's `CURL_CW_FLAG_BLOWUP`), so a response without one runs as it
  would with no gate. Body and header lines alike pass through it, the body in pieces of at
  most 4096 bytes; while a handler's pause holds output (`pause.recv == Held`, the one test
  `ClientOut`'s replay uses too) it holds what comes, still encoded and without a cap, and
  hands it on in order when the output is flushed. The transfer holds output while it does.
  `Write::Pause` → `Held` with the unconsumed piece kept and `pause.recv = Held`; on a protocol
  without pause support (`file://`) it is WriteError "Write callback asked for PAUSE when not
  supported". `Write::Fail`, or `Write::Took` short of the piece (WriteError "Failure writing
  output to destination, passed N returned M"), → `Failed`, a terminal variant with no path to a
  handler (#13337). Held beyond 64 MiB → TooLarge "pause buffer not large enough".
  `max_filesize` against delivered bytes is checked before each piece; SIZE_DELIVERED is bumped
  after the handler returns.
- **Decoders** (`coding::Decoder`, C's unencoding writers) are stacked as a `Content-Encoding`
  line is read, before it is traced, when the request asked for codings (`accept_encoding`), the
  application does not want them raw (`raw_content`) and the response is not bodyless. Each
  name stacks one: `identity` and `none` a decoder passing the body by, a name the handle has no
  decoder for one that fails at the first body byte ("Unrecognized content encoding type"); a
  sixth is BadContentEncoding at once. The last stacked undoes first. The decoders are the
  handle's (`Easy::set_libraries`, kept through `reset`), given by the tool and the shim from the
  binding crates, as the public suffixes are; `Accept-Encoding` lists them for
  `AcceptEncoding::All`. Transfer codings other than chunked, asked for with `TE: gzip` (only
  where the handle undoes gzip), are stacked the same way when the body starts, and undone
  before the body is counted, so the size downloaded is the decoded one, as in C. A decoder writes to a `coding::Sink`, which also answers whether the
  transfer's time is up and says a failure as the transfer's error.
- **Accounting after the call**: the handler is called with a context that borrows the report;
  the context is dropped; then `accountant` bumps SIZE_DOWNLOAD. The borrow checker enforces the
  order, which reproduces "dlnow inside the write callback excludes this chunk".
- **EOS is an event**, after the last piece, never a flag copied onto split pieces (#23461).
- Decoders check `deadlines.expired(now)` every 1 MiB of output ("Operation timed out while
  decoding payload"); a second gzip member is a WriteError; an unknown coding fails on the first
  body byte.

### 5.3 Pause

```rust
pub struct Pause { recv: RecvPause, send: SendPause }
pub enum RecvPause { Running, Stopped, Held }
pub enum SendPause { Running, Paused }
```

- `curl_easy_pause(RECV)` outside a write callback → `Stopped`: no new socket reads; the buffer
  in progress still flows through the pipeline (C sets only the rate-limit block).
- `Write::Pause` → `Held`: delivery stops at once and output is held.
- `Read::Pause` and an API send pause → `SendPause::Paused`.
- `CONT` → `Running`, flush held output (synchronously where the `Run` is in its slot, §3.6), reset
  the token bucket and the speed window, tell a mux (`stream_pause`).
- A new request (redirect, retry) starts with both `Running`. `Held` goes with the output it
  held when the transfer completes; a `Stopped` the application asked for stays.
- Derived effects: `Connecting` does not advance while `recv != Running`; the pollset drops IN
  while `recv != Running` and OUT while `send == Paused`; speed checks are skipped while either
  is paused; `Exchanging` does not reach `Done` while `recv == Held`.

`pause` (core of `curl_easy_pause`):
1. no lease held → BadFunctionArgument;
2. apply per direction; an unpause of held output flushes when the `Run` is in its slot, and a
   failed flush is `pause`'s error, leaving the output `Failed` for the next step to report;
3. unless blocked in every wanted direction, mark the transfer dirty;
4. if anything changed: `timer_update`, then `assess(id)`; an `Abort` from either is
   AbortedByCallback.

The speed limits are `RateLimits` in the slot beside the pause (`progress/rate.rs`, C's
`Curl_rlimit`): a token bucket per direction, its rate read from the options at each use (so a
rate set mid-transfer applies, as C's setopt changes the bucket). C's `blocked` is the pause
itself: a paused direction has no tokens, spends none and waits for none, and its unpause
starts the bucket over, the time paused earning nothing. The receive bucket starts over at the
body's first write, tuned for its size if known, and takes the body's bytes as counted (before
content decoding); the send bucket starts over at the body's first read and takes the body's
bytes as sent, framing included. A read is cut to the receive tokens and stops when they are
spent; a read of the upload likewise, and one send carries at most a second's worth of body
(`xfer_send`). file:// is not limited (DIVERGENCE.md).

### 5.4 Send side

```rust
pub(crate) struct Upload { source: Source /* None | Bytes(TryArc<Vec<u8>>) | Lent | Read { handler, rewind, size }
                                             | Mime(MimeReader) */,
                           read: u64, latch: Latch /* Open | Eof | Errored */, called: bool }
pub(crate) struct Body { upload: Upload, chain: Chain }   // upload/chain.rs: what a request reads
struct Chain { chunks: Option<ChunkEncoder>, lines: Option<Box<LineConv>> }   // a slot per C phase
```

`Upload` is C's client readers at `CURL_CR_CLIENT` (`cr_null`, `cr_buf`, `cr_in`, `cr_mime`) as
one struct, made per request from `options.upload`. What it gives goes through `Chain`, the
readers C stacks above it in phase order (`cr_lc` at `CONTENT_ENCODE`, `cr_chunked` at
`TRANSFER_ENCODE`): sans-IO stages, each owning its fixed buffer, one slot per phase rather than
a list of boxes. A read of the `Body` asks the last stage: one with output gives it; one without
names the room in its buffer it wants filled (`wants`), the stage before it, or the source, fills
it, and it frames what came (`got`, with the trailers at the end for the chunk stage). The protocol
reads only the `Body`. `Expect: 100-continue` is not a stage: C's `cr_exp100` only holds reads
back, which `Sending::AwaitingContinue` does (§6.1). `CURLOPT_CRLF` is the `LineConv` stage
(C's `cr_lc`), added for any body not known to be empty, `file:`'s too: each LF not after a CR
goes as CRLF, a CR ending one read carried to the next; a read with no LF passes through, one
with an LF is converted into the stage's buffer, boxed and grown fallibly as only such a body
needs it. It makes the body's size unknown (`Body::size`, C's total length), so HTTP sends it
chunked, while `Expect: 100-continue` still weighs the client's size, as `addexpect` does.
SMTP's dot-stuffing and FTP's ASCII line ends become stages when those protocols come.

- The request head is rendered into the request's own send buffer, as C's `req.sendbuf` is per
  request, measured first so that it takes one allocation; body bytes are pulled from the `Body`
  into the remaining space (the first read is reduced by the head length, as C's shared chunk).
  HEADER_OUT and DATA_OUT are traced for the bytes `Net::send` accepted, split at the head
  length; SIZE_UPLOAD counts accepted body bytes only (`upload::sent`), as sent: a chunked
  body's framing included.
- A read handler is given room for `min(free space, what is left of a known size, rate
  tokens)`. The read that completes a known size ends the body; a size of 0 never calls the
  handler. It is latched at EOF and on error (Abort is AbortedByCallback; more than the room is
  ReadError "read function returned funny value") and not called again until a rewind. EOF
  short of a known size is ReadError "client read function EOF fail, only X/Y of needed bytes
  read". `Read::Data` carries a `NonZeroUsize`: the shim maps C's 0 to `Eof`.
- `Read::Pause` pauses the transfer's sending (`SendPause::Asked`) and gives nothing; on a
  protocol that cannot pause it is ReadError "Read callback asked for PAUSE when not supported".
- COPYPOSTFIELDS is `Bytes`. Non-copied POSTFIELDS is `Lent`, a shim `LentBytes` over the
  app's pointer (§7.6) that copies from an offset the `Upload` keeps; the core never holds a raw
  borrow, and it reads at transfer time as C does. Like `Bytes` (C's `cr_buf`), lent bytes keep
  their size whatever the coding.
- HTTP/1's chunked coding is the chain's `ChunkEncoder` (`http1/chunked.rs`, C's `cr_chunked`):
  once what it framed is taken, it reads the body into its own buffer, at least 1 KiB however
  little room the send buffer has, otherwise what fits framed (at most 64 KiB); each read is a
  chunk, and the body's end `0\r\n\r\n`. Whether a body goes chunked is decided as each request
  is built, from the header lists read again then (`Options::reread_headers`, as C walks them in
  `Curl_http`): the application's `Transfer-Encoding` line, or else a body of unknown size. A
  POST read from a handler and asked chunked is read to its end, whatever size it was given
  (`Upload::read_to_end`, `set_reader`).
- A body needs a rewind (`Upload::needs_rewind`, which the head parser's `Unsent` carries and
  "Need to rewind upload for next request" says) once any of it was read (`Bytes`, `Lent`:
  C's `cr_buf`, copied or not; `Mime`, C's `cr_mime`) or the handler was called (`Read`).
  `Upload::rewind` is a no-op otherwise; `Bytes` and `Lent` start over and `Read` calls its
  `Rewind` (shim: SEEKFUNCTION(0), IOCTLFUNCTION, fseek iff the default fread), without one or
  on its failure SendFailRewind "necessary data rewind was not possible".
- Resume is the protocols': a file:// upload skips the offset in its read loop (§5.6), FTP seeks
  or reads and discards. C's reader-level `resume_from` is never called and is not ported.
- The protocol announces the body's size (CONTENT_LENGTH_UPLOAD) and, for a request with a
  body, marks POSTTRANSFER when the body is sent rather than at DID.

#### 5.4.1 MIME

```rust
pub struct Mime { boundary: Boundary, parts: Vec<Part> }                  // mime/mod.rs
pub struct Part { name, filename, mime_type: Option<Vec<u8>>, headers: Vec<Vec<u8>>,
                  encoder: Option<Encoder>, content: Content, reached: Reached }
pub enum Content { None, Bytes(TryArc<Vec<u8>>), File(FileData /* path, size if regular */),
                   Read { handler, rewind: Option<Handler<dyn Rewind>>, size: Option<u64> },
                   Parts(Mime) }
pub enum Encoder { Binary, EightBit, SevenBit, Base64, QuotedPrintable }
pub trait MimeSource: Send + Sync { fn mime(&self) -> Result<Option<TryArc<Mime>>, MimeError>;
                                    fn sent_head(&self) -> Option<&SentHead> { None } }
pub(crate) struct MimeReader { mime: TryArc<Mime>, cursor: Cursor /* a tree beside the parts */,
                               size: Option<u64>, head: Vec<Vec<u8>> /* the top part's headers */ }
```

- **The tree is a value; the reading is the reader's.** `Mime` says what to send and nothing of
  how far it has been read. `MimeReader` (`mime/read.rs`), made per request inside `Upload`,
  holds a cursor per part, built at once beside the tree: C's `mime_state`, `encstate` and
  `lastreadstatus`, and the open file. The headers C prepares into `curlheaders`
  (`Curl_mime_prepare_headers`) are computed when the reader is made: `Content-Disposition`
  (`form-data` inside a `multipart/form-data`, else `attachment` for a named part), the type
  given or guessed from the file name's extension, `Content-Transfer-Encoding` for an encoder,
  names escaped as `CURLOPT_MIME_OPTIONS` asks (C's form or mail table). Strategy is Form; Mail
  comes with SMTP. More than 40 levels is TooLarge.
- **The top part is the body, its headers the request's.** As C's `MIME_BODY_ONLY`, the body is
  the boundaries and parts; the top part's headers (`Content-Type: multipart/form-data;
  boundary=…`, the application's own `Content-Type` value in place of the type) go in the
  request head after `Content-Length` (`http_add_content_hds`), and the application's
  `Content-Type` line is left out of its headers (`Curl_add_custom_headers`).
  An authentication probe, sent without the body, sends the lines the last request that sent a
  tree sent, as C sends the `curlheaders` it made last: the source keeps them
  (`MimeSource::sent_head`, a `SentHead`), and clears them as the post is set again (the
  shim's `forget_post_state`, C's `state.mimepost` cleared); before any request has sent a
  tree, a probe sends none.
- **Size as C's `mime_size`.** Each part: its headers with CRLFs, the blank line and its
  content, encoded: base64's computed, quoted-printable's unknown unless empty, the others the
  content's. A boundary line is 52 bytes, the last 54 with its dashes. Unknown if any part's
  is: a callback part without a size, a file that is not regular, subparts with one. Unknown
  makes the request chunked on HTTP/1.1, and `Expect: 100-continue` is added as for any body
  over 1 MiB or of unknown size, from the reader's size (C's `Curl_creader_client_length`).
- **Reading as C's `Curl_mime_read`.** One fill reads boundaries, headers and in-memory bytes
  as far as its room goes, but calls at most one handler or file read (C's `hasread`, and only
  in-memory bytes are `MIME_FAST_READ`), then stops: the pieces a chunked body is cut into are
  C's (645, 667, 668). A part of known size is not read past it, and a file that came short is
  at its end without another read (`feof`). Encoders keep a 256-byte input buffer per part and
  lines of at most 76; a read with no more than 4 bytes of room reads 256 into a side buffer
  first, as `cr_mime_read`'s `tmpbuf` does, so a base64 group always fits.
- **Failures** are latched as `Upload`'s: Abort is AbortedByCallback "operation aborted by
  callback"; a handler's failure or its -2, a file that cannot be opened, a failed read of a
  file that is not regular, a 7bit byte at or over 0x80, "read error getting mime data" (a
  failed read of a regular file ends the part there, as C's `fread` does, for the size check);
  a handler giving more than its room, "read function returned funny value"; the end short of a
  known size, "client mime read EOF fail, only X/Y of needed bytes read"; all ReadError. A pause
  is kept in each part it passes through, with the transfer's count of lifted handler pauses
  (`Last::Paused(Lifts)`, `lastreadstatus`): a fill that gave bytes before its handler paused
  gives them, and the next read gives the pause without calling the handler. The pause holds
  while the count is the one it was kept with; an unpause moves the count when it lifts
  `SendPause::Asked` or a pause a part kept since the last lift, the transfer's send running
  or not, as C's `curl_easy_pause` unpauses a paused reader (`Curl_creader_is_paused`), and every kept pause is then stale and reads as a fine status (`mime_unpause`).
  No unpause reaches into the reader, so none can miss a part.
- **Rewind.** Whether a request's reading reached a part since it last started over is kept
  in the part (`Part::reached`, a shared flag the copies a source makes of one part hold), as C
  keeps its part state past `MIMESTATE_BEGIN` from one request and one transfer to the next. A
  part counts as reached once its headers are read, before its content. Making the reader
  starts over every part reached (`Curl_creader_set_mime`'s `mime_rewind`), and
  `Upload::rewind` the whole tree: a `Read` part's `Rewind` is called (C's seek function),
  even if its handler never was; its failure, a part without one, or a file that is not regular
  is SendFailRewind "Cannot rewind mime/post data"; bytes and nothing start over, and a regular
  file is opened again at its next read. A part of nothing is the exception to C, which fails it
  (DIVERGENCE.md).
- **One tree, the application's.** The application gives `UploadSource::Mime(Handler<dyn
  MimeSource>)`; the core asks it for the tree each time it builds a request with a body, as it
  reads a header list again (`LineSource`, DESIGN.md), so a tree changed between performs
  (653) or given subparts after setopt (695) is sent as it is then, and one that is gone (`None`)
  is an empty POST, `Content-Length: 0`, as C's unbound part is (584, 654). The tree a request
  gets is shared (`TryArc`), not copied, and is dropped with the request.
- **Its C shape stays in the shim.** `curl_mime` and `curl_mimepart` are the shim's
  (`curl-sys-abi/src/mime.rs`): boxed nodes with the links C's API needs (a tree attached once,
  `curl_mime_subparts` taking ownership, `curl_mime_free` freeing its subtree without
  recursion, the free callback called when a part's content goes). The shim's `MimeSource`
  builds a core `Mime` from them at each request: bytes shared, strings and header lines copied,
  a callback part's read and rewind handlers adapters over that part. CURLOPT_MIMEPOST keeps a
  pointer to the application's `curl_mime` and the `curl_mime` a link back to the handle, so
  `curl_mime_free` takes it from the handle (C's `mime_subparts_unbind`) and the handle never
  holds a dangling pointer. `curl_easy_duphandle` copies the tree into one the copy owns and
  frees (`Curl_mime_duppart`); a tree past 40 levels fails the copy.
- **The boundary** is 24 dashes and 22 characters of `[A-Za-z0-9]`, each from a 32-bit random
  number below the largest multiple of 62 (`Curl_rand_alnum`), drawn when the tree is made
  (`curl_mime_init`): from curl-os's `getrandom`, or under debug-hooks from `CURL_ENTROPY` as C's
  debug build draws them (its first four bytes a big-endian seed, one more per draw, kept in
  the shim's root where C keeps a static).
- **Allocation.** The tree, the cursors and the prepared headers are fallible, made when the
  reader is; reading allocates nothing. A handle pays little for MIME it does not use: the core's
  `UploadSource::Mime` is a pointer, `CURLOPT_MIME_OPTIONS` lives in a `Cold` group, and the
  shim's handle holds a pointer to the tree and which body a POST sends (`PostBody`: its own,
  the MIME tree or the form chain, C's `HTTPREQ_POST`, `_POST_MIME` and `_POST_FORM`).
- **The form API is a tree made from a chain.** `curl_formadd` builds the application's
  `curl_httppost` chain from the allocator it installed, with C's checks and codes
  (`curl-sys-abi/src/formdata.rs`); `curl_formfree` frees it. `CURLOPT_HTTPPOST` keeps the
  chain's pointer; the first request that sends it makes a `curl_mime` tree of it through the
  tree's own API (`Curl_getformdata`), a stream part reading with the read function set then,
  and the handle keeps that tree until the chain is set again, `CURLOPT_MIMEPOST` is set or
  the handle goes (C's `state.formp`), so contents lent by pointer are copied at that request.
- **Read outside a transfer.** `mime::read_whole` reads a tree as one part that is not
  `MIME_BODY_ONLY`, its own headers first, in C's pieces, for `curl_formget`; with no transfer to
  call a handler in, the shim reads a callback part whole first, and the core fails one it
  meets.

### 5.5 Progress and timings

`Timings` holds per-leg sums (each at least 1 µs, one STARTTRANSFER per leg) plus points
(REDIRECT) and is written by the engine as C's set points occur: STARTOP at Init, STARTSINGLE per
leg, POSTQUEUE at acquire, NAMELOOKUP at the first answer, CONNECT/APPCONNECT from the connect
machine's stats event, PRETRANSFER at DID, POSTTRANSFER at DID with nothing to send or at upload
done, STARTTRANSFER at the first non-CONNECT client write, TOTAL every progress pass and at
completion; a jump to completion from before DID marks PRE, POST and START together.

The report starts whole at Init (`Curl_pgrsStart`). `Sizes` (download, delivered; upload with the send side)
count the current request and start over at each leg's connection (`Curl_init_transfer`); with
one leg per transfer, until redirects and retries, the fresh report already does that. Inside a
write handler the download size leaves out the write in progress, the delivered size only the
piece in progress. A transfer the dead multi ends before it ran gets a report started and
completed at once.

`options.progress` is `Off` (NOPROGRESS, the default), `Meter`, or `Handler(h)`; the shim
derives it from NOPROGRESS and the two callbacks. `ProgressNow` gives sizes not known as `None`;
the shim passes 0. Stock is taken at every pass whatever the mode (`Speedometer::take_stock`,
C's `progress_calc`): the average speeds into the report, TOTAL as of then, and the current speed
over the last five one-second records. The handler is called, or the meter drawn, only when not
`Off`:
- after every receive/send pass, with the low-speed check unless the request is done or either
  direction is paused; while `LowSpeed` is set the check re-arms `SpeedCheck` for a second;
- after every step that went well while holding a connection (the tail of `multi_runsingle`'s
  loop), with held output a handler unpaused replayed at once. Every C state from CONNECT on
  that holds a connection is a step of its own, so the counts are C's: file:// pins them,
  two before DO and three after it; a piece of DO is not a C state, and has none;
- in `file:`'s DO, after each piece, with the low-speed check, at the start of the step after
  it (C's `Curl_pgrsCheck`, which reads the clock after the piece);
- at each wake of `RateLimiting`, with the low-speed check;
- a last call from the `Done` step, shown whatever the time but only if the request is done or a
  second has passed, unless the outcome is AbortedByCallback or the request never got past
  connecting (C's `mstate > MSTATE_CONNECTING`): a failed resolve or connect shows nothing. An `Abort` there fails a transfer
  that had succeeded. "Done" is C's `req.done`: the exchange ran to its end (`Reached::Exchanged`).
  A request with nothing to exchange, as file://'s, never is, so a quick one draws its meter once.
An unpause of a direction starts the records over; any unpause that leaves the transfer
running forgets the slow time. The meter's titles are written once per handle, its line is
drawn at most once a second and at the end, and only `Meter` ends the line with a newline
(`ContinueWithMeter` leaves it to the application). The meter's columns are unit 1636's; the
low-speed check is unit 1606's. Its "Resuming transfer from byte position" line comes with
resume (7f).

---

### 5.6 `file:`

`proto/file.rs` is `lib/file.c`: no network (`Reach::Local`: a pausing write is WriteError, a
pausing read ReadError, header lines are not kept for the headers API), and no exchange after
DO, so `Did` goes straight to `Done`.
- **At setup**, before a connection is leased (`file_connect`): the path, URL-encoded then
  decoded with only a zero byte rejected (UrlMalformat), is opened to read unless the request
  is an upload; a failure is FileCouldntReadFile, ending the transfer from `Init`.
- **Download, all in DO:** the file's status gives the file time, the headers (Content-Length
  and Accept-ranges for a file, Last-Modified in UTC, the blank line) and the announced size;
  a head request stops there. Resume is C's range arithmetic in signed offsets (`setup_range`,
  `Curl_range`): `At(n)` skips n, BadDownloadResume past the size; `AtEnd` is C's -1, the
  last byte. The body is read in pieces of the transfer buffer less one, no further than the
  size at the status, a progress check after each; a directory is its names but those
  starting with a dot, a line each, without checks. A last progress update ends DO.
- **Upload, all in DO:** a path with nothing after its first slash is FileCouldntReadFile;
  the file is opened emptied, or appended to on resume, with `new_file_mode` (WriteError).
  The body is read through `Upload` in 64 KiB pieces, the resume point (`AtEnd`: the file's
  size) skipped, each piece written (SendError), counted without a DATA_OUT trace and
  checked; a last update ends DO.
- Files are opened, renamed and removed and directories listed through `curl_os::fs`, which
  copies neither the path nor an entry's name.

## 6. HTTP/1.x

### 6.1 Request

```rust
pub(crate) struct RequestHead<'o> {
    method: &'o [u8], target: &'o [u8], version: Version,
    host: &'o [u8], port: Option<u16>, user_agent: Option<&'o [u8]>, headers: &'o UserHeaders,
}
pub struct UserHeaders { lines: Vec<UserHeader> }      // each line classified once, when given
struct UserHeader { line: Vec<u8>, name: (usize, usize) /* trimmed */, asks: Asks }
enum Asks { Value, Blank, Nothing }
pub(crate) fn render_h1(head: &RequestHead<'_>, gate: &CredentialGate, out: &mut Vec<u8>)
    -> Result<(), ErrorKind>;                         // past 1 MiB less a byte: TooLarge
```

- **Order is the declaration order of `Part`**, which rendering walks, so the sequence of
  `http_hd_t` is a property of the type: request line, Host, Proxy-Authorization,
  Authorization, Range, User-Agent, Accept, TE, Accept-Encoding, Referer, Proxy-Connection,
  Transfer-Encoding, Alt-Used, Upgrade, Cookie, conditionals, custom headers in the order given,
  content headers, Connection, blank line. A part no option asks for yet renders nothing.
- **`UserHeaders` classifies each line once**: `Name;` sends an empty header, a line with no
  colon or nothing after it sends nothing, any other goes as given. Two lookups stay distinct, as
  in C: whether a line *replaces* a library header is a case-blind prefix of the untrimmed line
  followed by `:` or `;` (`Curl_checkheaders`), so `Accept:` drops the default Accept but
  `Accept :x` does not; what a line *is* for the gate and the skips uses the trimmed name, so
  `Authorization :` is still an Authorization. A custom Host is `Host:` plus the bytes after the
  name (1121, 1292), and `Host:` alone removes it (461); every other duplicate goes in order.
  Connection is assembled last: the first with a value, trimmed, then the rest as given.
- **One credential gate.** `CredentialGate::new(initial, now, other_hosts)` compares the origins
  once per request (`Curl_peer_equal`). A custom Host is reached only through
  `UserHeaders::host(SameOrigin)`, and Authorization and Cookie lines only through
  `UserHeaders::sendable(Option<Trusted>)`, where `Trusted` is the same origin or
  `CURLOPT_UNRESTRICTED_AUTH`: a new emit site cannot skip the gate.
- **One typed request for every version.** h2 and h3 (stage 5) encode the same `RequestHead`;
  C's render-to-HTTP/1-then-reparse (`Curl_h1_req_parse_read`) has no counterpart, and the H1
  request parser survives only as test support (unit 2603).
- `Expect: 100-continue`, asked for or added (`addexpect`), holds the body back: it is not
  read behind the head. Once the head has drained, the request is `Sending::HeadSent` until
  the body is next asked for, in a later pass, as C's readers are asked before the send buffer
  is flushed; from then it is `Sending::AwaitingContinue` until a deadline (`continue_wait`),
  not asking to write, the deadline its `wake_at`. A 100,
  the deadline ("Done waiting for 100-continue") or keep-sending-on-error opens it. A final
  response of 300 or more before the body has gone, the connection not closing anyway, stops
  the send ("HTTP error before end of send, stop sending", then "abort upload") and the
  connection is not used again, unless keep-sending-on-error. A 417 makes the request again
  without it, on a second leg (`follow::Inherited::no_expect`).
  Unknown body length on HTTP/1.1 uses the chunk encoder (chunks ≤ 64 KiB, trailers from the
  trailer handler); on HTTP/1.0 it is UploadFailed.

### 6.2 Response

```rust
pub(crate) struct HeadParser { line: Vec<u8> /* 100 KiB less a byte */, maybe_folded, unfolding,
                               lines: u32, status: Option<Status>, request_bytes: u64, .. }
pub(crate) enum HeadEvent<'a> { Line(Line<'a>), Http09(&'a [u8]) }
pub(crate) struct Line<'a> { bytes: &'a [u8], kind: LineKind, then: Result<(), HeadError> }
pub(crate) enum LineKind { Status(Status), Header, End { interim: bool } }
pub enum BodyFraming { None, Length(u64), Chunked, UntilClose }
fn decide_framing(meta: &ResponseMeta, method: &Method<'_>, opts: &FramingOptions)
    -> Result<BodyFraming, Error>;
```

- `feed(&mut self, input, &mut transfer_bytes) -> Result<(usize, Option<HeadEvent>), HeadError>`
  is pure and gives out at most one line per call, assembled in the parser's own buffer as C's
  `headerb` is (a line over 100 KiB less a byte is `TooLarge`, silently). Folding lives in the
  parser, not in transfer state (1274): a header line at the end of the input waits for the next
  byte, and a blank-led continuation is joined by one space.
- A line is given out only once it is good: the status line read (and the version checked
  against the request's), the line verified (NUL, stray CR, missing colon → 8). The driver then
  delivers it (HEADER_IN, the handlers, the store) and raises its `then`: the size limits count a
  line only after the handlers had it, as `Curl_bump_headersize` does, and a blank line ending a
  head whose code is below 100 fails after it is delivered. A first line that is no HTTP is
  `Http09` (or 8 on a reused connection or after a status line, 1 when 0.9 is not allowed),
  decided on a partial line as soon as it cannot become `HTTP/`.
- What a line says is applied as it arrives, with C's gates (`framing.rs`'s `Meta`): the status
  line makes the response bodyless (1xx, 204 and 304, the last two with a size of 0) and an
  HTTP/1.0 one closing; `Content-Length` is read only when the response may have a body, the
  option does not ignore it and no other coding than chunked came before it, and a second value
  must equal the first (8); `Transfer-Encoding` is read only when not bodyless, not a HEAD and
  not a 304, each coding stacked as `Curl_build_unencoding_stack` stacks it, and one other than
  chunked closes the connection and voids the length; `Connection: close` counts on HTTP/1,
  `keep-alive` on 1.0 only. An infof C writes while reading a line rides on it as a `Note`, to be
  traced before the line is delivered.
- **Framing is folded once, at the final blank line, by `Meta::decide`**: a HEAD and a size of 0
  have no body, chunked is `Chunked`, a size is `Length`, anything else `UntilClose`; an HTTP/1.1
  body with no size, no chunks and no close closes ("no chunk, no close, no size"), and a size
  past `max_filesize` is 63 after the blank line is delivered. These are the inputs pinned by 365,
  2918, 1722, 1723, 2119, 334, 499, 1484, 178, 394 and 282. A 1xx is interim but for a 101
  nothing asked to upgrade to, which C takes for the final response (`http_on_101_upgrade`): it
  ends the head without `decide`, its body all that follows until the connection closes, its
  lines still a 1xx's; to a request not sent as HTTP/1.1 it is 8 once its head is delivered.
  An upgrade the request asked for (h2c, WebSocket) takes the bytes after it instead.
- **Every peer limit is an `Error`**: 100 KiB per line, 300 KiB per response and 20× that per
  transfer (one counter per limit in `HeaderBudget`), 5000 stored headers, 17 hex digits per
  chunk size, 4 KiB per trailer line, 5 codings.
- **`ChunkDecoder`** (`chunked.rs`) is C's HEX/LF/DATA/POSTLF/TRAILER/STOP/DONE machine as an
  enum, fed like the head parser and giving out data from the input, a trailer line (CRLF
  ended, verified as a header with the final head's line count, counted against the head limit
  in its `then`) or the end. The size state swallows everything up to its LF, extensions
  included. Raw (`--raw`), the driver delivers each piece of input as it came and the decoder
  only reads the body to its end. Its errors say what C says: a reason where C gives one, then
  "… in chunked-encoding"; the input ending first is 18. A failure delivering data or a trailer
  (the header store refusing a colon-less fold, say) is reported by the driver as the delivery's
  own error, then "Failed reading the chunked-encoded stream"; input left after the end is traced
  as "Leftovers after chunking: N bytes".
- The status line: `HTTP/1.[01] DDD` and anything after, `HTTP/2 DDD ` and `HTTP/3 DDD `; a bad
  1.x subversion or an unknown major version is 1, another major version than the request's is
  8, and any other line starting `HTTP/` in some case is a 200 in HTTP/1.0 (the HTTP200ALIASES
  check, which always knows `HTTP/`).
- GOT_NOTHING is computed in one place, `HeadParser::got_nothing`, from the request's head
  bytes and the body's, less the interim heads' up to the last that ended.
- The pipeline's accountant is told what the final head expects (`Pipeline::expect`: size,
  most to deliver, no body wanted). Past the most, the rest is excess: traced, not written, and
  the connection given up, the body complete. A body where none was wanted is dropped, and the
  connection with it; the response stands, as a head was read. `Pipeline::end` fails a body
  short of its size with "end of response with N bytes missing" (18).

### 6.3 Header store

```rust
pub struct HeaderStore { generation: u32, request: u16, bytes: Vec<u8>, entries: Vec<Entry> }
struct Entry { name: Range<u32>, value: Range<u32>, origin: HeaderOrigin, request: u16 }
pub struct HeaderCursor { generation: u32, entry: u32 }
impl HeaderStore {
    pub fn get(&self, name: &[u8], index: usize, origins: Origins, request: Request)
        -> Result<HeaderView<'_>, HeaderError>;              // curl_easy_header
    pub fn next(&self, origins: Origins, request: Request, prev: Option<HeaderCursor>)
        -> Option<HeaderView<'_>>;                           // curl_easy_nextheader
}
pub enum Request { Last, Nth(u16) }                           // C's -1 and n
pub enum HeaderError { NoHeaders, NoRequest, Missing, BadIndex }
```

It lives in `TransferReport`, so it spans every request of the transfer and stays readable after
`perform` returns, until the next transfer's Init, a reset or the `Easy` is dropped (headers.c).
`Pipeline::header` stores each line before delivering it; a status line goes through
`Pipeline::status`, which does not (`CLIENTWRITE_STATUS`). `push` keeps `Curl_headers_push`'s
rules: the blank line is skipped, a line without CR or LF or all blank is WeirdServerReply, the
5001st header TooLarge, one without a colon (or with a NUL before it) BadFunctionArgument; the
value is trimmed of blanks at both ends, the name keeps what precedes the colon. Growth is
fallible. Each new store's generation is the last one's plus one, so a `HeaderCursor` from an
earlier transfer or from before a reset fails its generation check and the shim returns NULL
from `curl_easy_nextheader`, where C chases a freed list node. A bad origin mask or a request
below -1 is the shim's BAD_ARGUMENT. `next` counts a header's index and amount by scanning,
where C sorts once per walk and caches; a walk over all 5000 headers is quadratic until a
measurement says it matters.

### 6.4 Redirects and auth

The head parser keeps a response's `Location:` as the server gave it (`http_header_l`), on any
response, interim ones too, checked before the line is traced: an empty one or a repeat is
ignored, a different second one fails WeirdServerReply. Where it leads is resolved by
`http1::follow` against the request's URL, parsed again from `Run::url` as C's `state.uh` was
(credentials and all), never against the report's URL. A Location not followed is resolved at
the end of a complete exchange, C's FOLLOW_FAKE: any scheme accepted, read back without
credentials, or kept as given if it does not resolve, into `report.redirect_url`
(`CURLINFO_REDIRECT_URL`); the report starts empty with each transfer.

A Location is followed when it came with a 3xx and following is on (C's `req.newurl`), decided
by the head parser as it takes the line and handed to the engine by HTTP's `exchanged` (§3.1). Its body is not delivered: on a connection that closes
the response ends at its head (`Framing::Abandoned`), on a kept one the body is read and dropped.
A complete exchange ends `Done { next: AfterRequest::Follow(location) }`; the Done step releases
the connection first, then `follow_leg` checks the limit (past it, FOLLOW_FAKE's URL is kept and
the transfer fails TooManyRedirects), counts the redirect in the report (C's
`state.followlocation`, which is also what "this is a follow" means), resolves the location as
FOLLOW_REDIR does and starts the next leg through `next_leg`, the tail it shares with a retry.
That leg's URL replaces `Run::url` whole (C's `state.url`). Every leg's scheme must be in
`Options::schemes.allowed` (`CURLOPT_PROTOCOLS_STR`, all unless set), and a redirect's in
`Options::schemes.redirect` too (`CURLOPT_REDIR_PROTOCOLS_STR`, C's `CURLPROTO_REDIR` unless set:
HTTP, HTTPS, FTP, FTPS), checked as the leg starts (`url_set_conn_scheme`). `Run::first` holds the first leg's origin (`state.initial_origin`):
each request's `CredentialGate` is fixed when the request is made, from that origin and its own.
The gate holds back what the application said; credentials in the request's own URL go to its
origin regardless (`Trusted::own_url`), as C takes them per leg in `url_set_data_creds`. Each
request composes its `Credentials` so (`for_request`): the application's `Login`, if the gate
trusts the origin; the URL's parts in place of the login's unless the login named a user. The
`Trusted` leave travels inside them, so no credentials reach a header without it. A `.netrc`
file (`Options::netrc`) is read last, per request, for the request's own host: never over the
login, over the URL's only to complete them, or, when required, to replace their password
(`netrc_lookup`); an entry found replaces the user and password and goes to its host wherever
the transfer started. `netrc.rs` is the file's parser, a port of `lib/netrc.c` bounded as C's
is. Unlike C, the entry is not written into the request's URL: the next leg looks it up again.
C reads the file before it checks the protocol, so a URL no HTTP request is made for (another
protocol's, or one `CURLOPT_PROTOCOLS_STR` refuses) has it read by the leg itself
(`proto::netrc_before_protocol`, from the application's and the URL's credentials): a required
file missing or malformed fails it with `ReadError`, and an entry not found is said, before the
protocol is refused.
What one request takes from the ones before it is on `Run`, reset at a transfer's start: the
first origin and the method (C's `state.httpreq`), which any protocol's request reads, and
HTTP's own, `http1::follow::Inherited`, which the engine holds for HTTP and never reads:
whether the custom method is still sent (`state.http_ignorecustom`), whether a response said
HTTP/1.0 (`rcvd_min`, which makes the later requests HTTP/1.0; HTTP's `done` records it) and
whether Expect was refused. A request is given them as `Before` and copies what it needs when
it is made. Following a
redirect, in C's order: the old request's body is rewound (`Curl_req_soft_reset`), "Issue
another request" is said, then HTTP's `redirected`: `FIRSTONLY` drops the custom method,
`follow::switches_to_get` decides from `(code, method, POSTREDIR)` and `switch_to_get` applies
it (a HEAD stays one).
A failed rewind fails the transfer unless the next request is a GET. A retry rewinds the same
way. A 417 to a body sent behind `Expect: 100-continue` makes the exchange end with a Follow
to the request's own URL, as C's `newurl` does: counted as a redirect, and with
`no_expect` set so the library adds no Expect again. The connection is kept if the
body was still held, and closed if some of it went. A URL the application keeps (`SharedUrl`, `CURLOPT_CURLU`, which the shim's `CURLU *` is) goes
before the text URL: each transfer reads it as it starts, taking a copy of it as the first leg's
parsed URL; it is reached only inside a closure, so no borrow of it outlives the read.
`Options::port` replaces the port of that first URL, and of each leg after, until a redirect
leads to an absolute URL (`Run::allow_port`); as C sets it only in `state.uh`, it goes into
where the request goes and what a relative redirect resolves against (`request_url`), never into
`Run::url`, so the URL a retry traces, the report keeps and a referer names is the one asked for. The referer a request sends is the report's (`state.referer`): the application's, copied
at the transfer's start, until a redirect followed with AUTOREFERER replaces it with the URL it
came from, without credentials or fragment.
Authenticating is `Auth`, on the `Easy` as C keeps `state.authhost`, `state.authproxy` and
`state.authproblem` on the handle: a `PeerAuth` for the origin and one for the proxy a request
goes to whole, and one problem flag that stops both. Each side's method picked outlives the
transfer, cut to the methods wanted as the next one starts (`start`; the proxy's are
`Options::proxy.auth`). `Picked` tells a method not yet picked from a pick that found nothing
(C's `CURLAUTH_PICKNONE`), which sends nothing until the next transfer. Each request asks each side
what to send (`output`, from a `Secret`: the request's `Credentials` for the origin, the
route's `ProxyCreds` for the proxy, never a token; the method and the path): the proxy's
first, as `Proxy-Authorization`, and only to a proxy the request goes to whole. One method
wanted is sent at once, more wait for a peer to choose. Basic and Bearer are done once sent;
AWS SigV4, never a proxy's and never offered by a peer, is in use at once when it is the one
method wanted and sends nothing itself: the request signs itself where it renders
(`proto::http::sigv4`, with what the request will be: method, path, query, the application's
headers, the POST data), and the lines it makes go where `Authorization` goes. An HTTP
message signature (RFC 9421, `proto::http::httpsig`) is the same, but signs with its own key
(`Options::http.signing.message`, in the `Cold` group that holds SigV4's parameters too), so it
is used without credentials as well, and only for an origin the request's gate trusts; its
`Signature-Input` and `Signature` go where `Authorization` goes, unless the application sends
either. HMAC-SHA256 is the core's; Ed25519 is the handle's `Libraries`' signer, which gets the
key's 32 bytes and the signature base and gives the 64 bytes sent (curl-openssl's, as C's
`Curl_ed25519_sign`: a key or signing OpenSSL refuses is `AuthError`, untraced; one too old for
this build, or a handle with no signer, is not built in, as in a C build whose TLS library lacks
it). Digest is in use from the start and done only once it answers a challenge, so a request
with a body sent before that is a probe: `Content-Length: 0` in place of the application's, no
body read (`authneg`). The request hands its response's head parser an `AuthAsked`, and the
parser reads a 401's `WWW-Authenticate:` and a 407's `Proxy-Authenticate:` lines into each
side's `Challenges` as they come, as it reads
`Location:`, so that at the head's end it knows, before the End line is delivered, whether
the response is answered again (`AuthAct`, which picks for the origin on a 401 and for the
proxy, never Bearer, on a 407: its body dropped as a followed redirect's is) and whether
fail-on-error lets it through. A probe let through is made again with its body. The
exchange's end moves the challenges into `HostAuth`: the methods offered and not picked from
stay open across responses and transfers until a pick, as C's `avail` does, so a Digest
challenge met while Digest is still open is a duplicate and not read (test 2027). The Digest
challenge read is kept with the peer that sent it, the request's URL host for the origin's and
the connection's for the proxy's, and the credentials first answering it; asked for by another
peer or with other credentials it is not there. An answered 401
ends `Follow` to the request's own URL, counted as a redirect, keeping `Options::port`. Each
request counts what it moves from nothing (`Sizes::new_request`, `Curl_pgrsReset`); heads and
request bytes are counted over the transfer. The hashes Digest computes with (MD5, SHA-256,
SHA-512/256) and SigV4's HMAC-SHA256 are `crate::hash`, fixed state and no allocation, ported
from C's built-ins.

### 6.5 Cookies

The jar is `cookie::Jar`, a port of `lib/cookie.c` that keeps C's 63 buckets, its hash and the
order within each bucket, which decide the order `CURLINFO_COOKIELIST` lists and the cap of
150 a request sends applies in; it does no I/O and reads no clock. It is the `Easy`'s
(`cookies: Option<Jar>`, C's `cookies` with `cookie_engine`), on once `Cookies::files` names
any file or `save_to` is set, or the application turns it on (`enable_cookies`,
`add_cookie`); it is kept through `reset`, and a duplicate gets an empty one if the original's
is on. A share that keeps cookies (`Kind::Cookies`, `CURL_LOCK_DATA_COOKIE`) has its jar used
in place of the handle's own, whose presence then only says the jar is on: one operation at a
time under the share's lock (section 4.6.1), as C locks `CURL_LOCK_DATA_COOKIE` around each, so
handles on different threads take turns with it.
As each transfer starts (pretransfer, before the resolve list), the files are read into it
again, live cookies kept over a file's, and it is started (`running`): a jar not started is
not written. The request's `Cookie:` line is the jar's matches for the cookie host (a custom
`Host:`'s name where the first origin sends one, else the URL's host) and the URL's path,
then `Cookies::send` if the gate trusts the origin and the application sends no `Cookie:` of
its own, under C's 8190-byte cap. A `Set-Cookie:` line is stored before it is traced, 50 a
request at most. `Easy::save_cookies` writes the jar to `save_to` (`Curl_flush_cookies`):
the shim at `curl_easy_cleanup` and FLUSH, the tool as each transfer's handle is done with.
Files are written whole and renamed into place (`save::replace`, C's `Curl_fopen`). Domains
are checked against public suffixes through `cookie::PublicSuffixes`, which `curl-psl`
implements over libpsl; core cannot make one, so the handle is given it
(`Easy::set_public_suffixes`, kept through `reset`, shared by duplicates): the tool gives
every handle one list, as its share's `CURL_LOCK_DATA_PSL` does, and the shim each handle its
own, loaded at the first question, as C's per-multi cache is. A handle given none behaves as
C built without libpsl: a domain needs a dot not at its end, or to be `localhost`
(`bad_domain`). A list that cannot be loaded refuses every domain, as C's does.

### 6.6 HSTS

`hsts::Hsts` is C's cache (`lib/hsts.c`), the hosts to reach only over HTTPS: each with whether
its subdomains are included and when it expires, at most 10000 kept, oldest first. A handle has
one once the application turns it on (`Easy::enable_hsts`, `add_hsts_file`: `CURLOPT_HSTS_CTRL`,
`CURLOPT_HSTS`), kept through `reset`; a share does not keep one yet (milestone 7). As each
transfer starts (pretransfer) the files named are read into it, then what the application's
reader gives (`HstsReader`, `CURLOPT_HSTSREADFUNCTION`). As each leg starts, after the
application's port is applied, an `http` URL to a host it keeps, by the host's own entry or the
longest including it, is switched to `https`: the URL read back is the transfer's and the
report's, and the trace says "Switched from HTTP to HTTPS due to HSTS". A
`Strict-Transport-Security:` field is kept from a response over HTTPS, or over HTTP when the
debug build's `CURL_HSTS_HTTP` says so; one the cache cannot take is said and passed over. The
time is the clock's, or the debug build's `CURL_TIME`. The cache is written as the handle goes
(`Easy::save_hsts`, which the shim's cleanup and the tool's handle call), to
`HstsOptions::file` or the file last read, unless the cache's file is read-only
(`CacheFile::ReadOnly`, `CURLHSTS_READONLYFILE`, which C never honours: DIVERGENCE.md), then to
the application's writer (`HstsWriter`). A copy of the handle reads its file and reader into a
new cache of the same file mode, then takes the entries alive; the shim makes the copy's
adapters before that read (`Easy::try_clone_with`), so the application's reader is handed the
copy, as C hands it `outcurl`.

### 6.7 Alternative services

`altsvc::AltSvc` is C's cache (`lib/altsvc.c`): for an origin spoken to by one HTTP version,
another host, port and version it may be reached by, until when, at most 5000 kept, oldest
first. A handle has one once the application turns it on (`Easy::enable_alt_svc`,
`add_alt_svc_file`: `CURLOPT_ALTSVC_CTRL`, `CURLOPT_ALTSVC`), kept through `reset`; it and
the HSTS cache share one box, made the first time either is turned on (`HostCaches`), which
keeps a handle that turns on neither within its byte budget. The file is read as it is named,
not as transfers start. As each leg picks its peer, an origin no connect-to entry sends
elsewhere, over `https` (or any URL with the debug build's `CURL_ALTSVC_HTTP`), and not made in
HTTP/1.0, is looked up by its ASCII name and port as an HTTP/1 origin, for an alternative of a
version the control allows and the build speaks, which is HTTP/1 alone until HTTP/2 (step 52).
One on another host or port is the peer, as a connect-to entry's is: traced "Alt-svc connecting
from ...", and named by the request's `Alt-Used:` unless the application sends its own. An
`Alt-Svc:` field from a response over HTTPS, or HTTP with `CURL_ALTSVC_HTTP`, is parsed as C
parses it, the cache taken out of the handle meanwhile so that what parsing says is traced as
it is said. The cache is written as the handle goes (`Easy::save_alt_svc`, the shim's cleanup
and the tool's handle), to `AltSvcOptions::file` or the file last read, unless read-only. A copy
of the handle has an empty cache of the same control, which reads the file named; C's copy
loses the control (DIVERGENCE.md).

---

## 7. The C ABI mapping: the hard cases

### 7.1 Handles

```rust
struct ShimEasy {                         // what CURL * points to; stable address
    magic: Cell<u32>,
    internal: bool,                       // a multi's own handle (C's `state.internal`): no call may use it
    stack: EasyStack,                     // easy calls under way (C's `data->callstack`)
    home: RefCell<Home>,                  // Detached(Easy) | Added { multi: NonNull<ShimMulti>, id } | Nowhere (mid-add)
    ccb: Cell<CCallbacks>,                // C fn pointers + userdata, read by the adapters when they run
    set: Cell<CSettings>,                 // what setopt keeps that the core holds only combined
    errbuf: Cell<*mut c_char>,            // CURLOPT_ERRORBUFFER
    private: Cell<Option<NonNull<ShimMulti>>>, // curl_easy_perform's multi, kept across performs
    msg: UnsafeCell<CURLMsg>,             // what info_read points into
}
struct ShimMulti {
    magic: AtomicU32,                     // curl_multi_wakeup reads it from other threads
    stack: MultiStack,                    // depth, the innermost Frame, event and notify counts
    core: UnsafeCell<Multi<CHost>>,       // CHost { Transfer = NonNull<ShimEasy> }
    waker: Option<TryArc<Waker>>,         // curl_multi_wakeup without touching `core`
    cb: Cell<MultiCallbacks>,             // timer and notify functions and data
    admin: ShimEasy,                      // the CURL * a notification about the multi names
}
enum Frame { Transfer(NonNull<TransferCx<'static>>), Event(NonNull<EventCx<'static, CHost>>),
             Notify(NonNull<NotifyCx<'static, CHost>>) }
```

The getinfo string copies and the header slots join `ShimEasy` with the infos and
`curl_easy_header`.

### 7.2 Re-entrant calls: one gate

Every exported function enters its handle's stack first (`gate/`): `MultiStack::enter(call)`
for a multi call, `EasyStack::enter(call, multi)` for an easy call on a handle in `multi`. Each
applies `TABLE[call]` as api.c does (recursion, `allow_ntfy_cb`, `no_event_cb`, the depth limits
of 15 and 7) and returns an entry that pops the call when dropped. A multi entry carries the
`Reach` its call has, decided before the call counts itself:

1. A frame is present: the call goes through the context the running callback lent (`Frame`'s
   methods reach the target transfer by id, the caller's own or a sibling's); a call that context
   cannot make (an add or a remove outside a notification) is RECURSIVE_API_CALL.
2. No frame and nothing under way: `Direct`, the call borrows `&mut Multi` from the `UnsafeCell`
   (no frame means no outstanding borrow of `core`; a frame is pushed only while the core is
   suspended in a call-out on this thread).
3. No frame but a call under way: another thread's call, refused.

An easy call reaches its `Easy` through `ShimEasy::with_easy`: in the handle, or in its multi by
the same rule. The callback adapters (`callbacks.rs`) and `ShimEvents` push the frame around each
C call with `MultiStack::lend` and restore the previous one after it; panics abort, so the pop
cannot be skipped. The `'static` in `Frame` is lifetime erasure confined to the lend: the
adapter turns its `&mut` context into the raw pointer before calling C and does not use the
reference again until `lend` returns, so the only access path during the C call is the frame.
`ShimEvents` holds `&ShimMulti`: every field it reaches is behind a `Cell` or never changes, and
`core` only through the gate. A call on a handle in another multi takes that multi's own path.

`TABLE` is generated from `lib/api.c`'s `eapi_fn_props`, `mapi_fn_props` and the event-callback
flag (`gen/api.py`), and a shim test parses the C file and compares the columns. The Rust API
has no depth limits because the context types bound nesting.

The adapters are installed only where C's default differs from the core's: the write adapter
always (the body goes to the application's C stream, never Rust's standard output), the header
one with a header function or data, the debug one with a debug function, the text one with a
STDERR stream other than standard error, ERRORBUFFER's with a buffer, and the progress and read
ones as the settings call for. A handle allocates about what C's does (751).

An adapter holds its handle's address, so a copy must never keep the original's: the copy would
call the application with the original's `CURL *`, freed once the original is cleaned up. One
function makes a handle's adapters whole, `ShimEasy::adapt`: it drops whatever adapters the
options hold and makes every one again from the handle's C-side settings (the callbacks and
settings, ERRORBUFFER, the socket and `SSL_CTX` functions). A new handle and a copy
(`ShimEasy::boxed`, which `curl_easy_duphandle` reaches with a copy of the original's C side)
and `curl_easy_reset` call it, and nothing else makes a set of them; a setopt adds or drops only
the adapter of the option it sets. An option that brings a new adapter is made in `adapt` from
its C-side setting, and gets a test that a copy calls through itself once the original is
freed.

### 7.3 `curl_easy_pause`

- Detached handle, or no lease → CURLE_BAD_FUNCTION_ARGUMENT.
- `Added { multi, id }` with a `Transfer` frame → `cx.pause(id, req)`: own transfer or sibling;
  a sibling's write callbacks run inside, and the timer and socket callbacks hear of the
  change at the end of the pass (§7.8).
- `Event` frame → RECURSIVE_API_CALL (`no_event_cb`).
- No frame → `Multi::pause(id, req, &mut ShimEvents)`: flush (write callbacks), then the timer
  callback, then the socket callback, inside the call, as easy.c:1187-1236.

### 7.4 `curl_easy_perform`, `curl_easy_perform_ev`, cleanup

- `perform`: reject if `Added`; close a leftover CONNECT_ONLY connection; take or create the
  private `ShimMulti` (policy 16/1, as every `ShimMulti`, so ids equal C's); copy MAXCONNECTS
  and QUICK_EXIT; move the `Easy` in
  (`home = Added { private, id }`); `drive_to_completion` (the same core function `Easy::perform`
  uses, plus frames); remove; move the `Easy` back. An internal multi error maps to OutOfMemory
  or BadFunctionArgument.
- `perform_ev` (debug-hooks): the same, driven through `socket_action` by `drive_by_events`,
  with an event table owned by that call, not C's `static struct events` (easy.c:705); any
  multi error → CURLE_URL_MALFORMAT, as C. The table holds what the timer and socket callbacks
  were told, sockets by key; the multi polls them by resolving each key to the socket a
  transfer waits on (`poll_watched`), never from its own list, so an announcement missed
  stalls the transfer instead of passing unseen. `Easy::perform_ev` and the tool's
  `--test-event` use the same driver.
- `curl_multi_add_handle` of an easy with a private multi drops that multi; already added →
  ADDED_ALREADY; the core names the new transfer to the host (`MultiEvents::added`) before the
  timer callback hears of it, so the shim attaches the handle first and a setopt from that
  callback reaches it, as in C; dead multi → ABORTED_BY_CALLBACK until no transfer remains (530, 758); clears
  ERRORBUFFER and os_errno.
- `curl_easy_cleanup` on an added handle removes it first (753, 1939). `curl_multi_cleanup`
  removes every app transfer, returning each `Easy` to its `ShimEasy`, drops internal ones, then
  terminates connections (timeout 0 unless CURL_GRACEFUL_SHUTDOWN).
- `curl_multi_remove_handle`: not added → OK (3105); wrong multi → BAD_EASY_HANDLE.

### 7.5 Socket and timer callbacks, info_read, counts

- Socket callback: `SocketWhat` → `CURL_POLL_*`; the easy argument is the owner's `ShimEasy`
  for `SocketFor::Transfer`, or the multi's internal handle (`admin`) for `SocketFor::Multi`,
  a closing connection's socket (non-NULL, as C passes its admin easy); `socketp` is the `assign`ed value; `-1` → `Abort` → dead multi. `curl_multi_assign`
  inside the callback goes through `EventCx::assign`. From a transfer's own handler it answers
  CURLM_BAD_SOCKET, where C assigns: a handler's `TransferCx` does not reach the socket table,
  and is not generic over the host whose socket value it would store.
- Timer callback: `TimerChange::Set(d)` → `long` ms capped at INT_MAX; `Clear` → -1.
- `curl_multi_info_read` writes `CURLMSG_DONE`, the `CURL *` and the mapped code into
  `ShimEasy.msg` and returns a pointer to it: valid until that easy is removed or cleaned up.
- `CURLMINFO_XFERS_*` from `census()`, which every context has, so they read the same from any
  callback as from outside: RUNNING is the transfers worked on, those `counts().running` gives
  `curl_multi_perform` less the ones in `Pending` (C's process set; no "minus admin" because
  there is no admin row in the counts), PENDING is the ones in `Pending`, DONE is unread
  messages (2453). A run out of its slot, being stepped, is neither.
- `curl_multi_wait`: negative timeout → BAD_FUNCTION_ARGUMENT; capped at `timeout()`; no fds →
  returns at once (`wait`) or sleeps (`poll`); the waker is polled only when waiting and is not
  counted; extra revents use the CURL_WAIT_POLL* bits. Up to ten sockets and ten descriptors
  are kept on the stack, as C's `a_few_on_stack`, so a loop of waits allocates nothing (671,
  whose easy loop polls with no timeout while a response drains). `waitfds` too small → OUT_OF_MEMORY with
  the needed count. `fdset` skips sockets above FD_SETSIZE; both include closing connections.

### 7.6 Callback adapters (C shapes stay here)

- **Write**: `(ptr, 1, len, userdata)`; CURL_WRITEFUNC_PAUSE → `Write::Pause`; CURL_WRITEFUNC_ERROR
  → `Fail` ("client returned ERROR on write of N bytes"); any other count `n` → `Took(n)`, which
  the core reports when it is not all; NULL → fwrite to WRITEDATA or stdout. The adapter
  reads `ccb` at call time, so a setopt of WRITEFUNCTION/WRITEDATA inside the callback applies to
  the next piece.
- **Header**: HEADERFUNCTION, else WRITEFUNCTION if HEADERDATA is set, else discard; userdata is
  always HEADERDATA.
- **Read**: `n > nmemb` passed through as `Read::Data(n)` for the core to reject ("read function
  returned funny value"); READFUNC_ABORT → `Abort`; READFUNC_PAUSE → `Pause`.
- **MIME parts' callbacks** (`curl_mime_data_cb`): read as Read is, but (size_t)-1, C's
  `READ_ERROR`, is `Fail`, and so is -2, which C loops on (DIVERGENCE.md); the rewind adapter
  calls the seek function, failing without one (`mime_part_rewind`), when the core starts the
  part over, which it does only for a part reached (§5.4.1): the shim's part holds the
  `Reached` each tree built of it shares, so it lasts from one perform to the next and is
  cleared as the part's content is set again; the free function runs when the part's content is replaced or
  freed, once for each copy `curl_easy_duphandle` made.
- **Progress**: XFERINFO if set, else PROGRESS with doubles; CURL_PROGRESSFUNC_CONTINUE →
  `ContinueWithMeter`.
- **Rewind**: SEEKFUNCTION(0), then IOCTLFUNCTION(RESTARTREAD), then fseek iff READFUNCTION is the
  default, else fail.
- **Non-copied POSTFIELDS**: a shim `LentBytes` over the app's pointer and POSTFIELDSIZE, read at
  transfer time (SAFETY: the CURLOPT_POSTFIELDS contract keeps the buffer alive). Setting it after
  `add_handle` takes effect (1531).
- **Sockets**: OPEN/SOCKOPT/CLOSESOCKETFUNCTION as the core's `SocketOpener`,
  `SocketConfigurer` and `SocketCloser` handlers, kept in the options' cold `Sockets` group
  with the TCP options (`CURLOPT_TCP_NODELAY`, `_KEEPALIVE`, `_KEEPIDLE`, `_KEEPINTVL`,
  `_KEEPCNT`, `_FASTOPEN`; the group is made only for a value off its default). The opener and
  configurer are adapters reading the function and data at call time, called as transfer
  callbacks (api.c:117, 121); the opener is given a `Curl_sockaddr_ex` with room for either
  family, and the shim adopts the descriptor it returns (`curl_os::net::adopt`). The closer
  holds the function and data it was made with, as a connection outlives its handle and a
  share's cleanup closes with no handle; it gets no context. The functions and data live in
  a store the handle makes when one is first set (8 bytes a handle), copied by
  `curl_easy_duphandle`, whose adapters `ShimEasy::adapt` makes again for the copy (§7.2), and
  cleared by `curl_easy_reset`.

### 7.7 setopt, getinfo, headers, errors

- `curl_easy_setopt` reads its argument by the id's type class (long, pointer, function,
  offset, blob), checks it as setopt.c does and applies it where `with_easy` finds the `Easy`
  (frame → `options_mut(id)`, else `multi.easy_mut(id)`, else the detached one). Callback
  options update `ccb`, and install or drop the adapter they need. An id
  `inventory/options.json` lists (`gen/setopt.py`) that the shim does not implement yet is
  CURLE_NOT_BUILT_IN; any other, CURLE_UNKNOWN_OPTION.
- `curl_easy_getinfo`: frame → `cx.info(id)`; else `multi.report(id)` or the detached report.
  Strings are copied into `InfoStrings`. CURL_TIME and CURL_DEBUG_SIZE overrides apply here
  under debug-hooks.
- `curl_easy_header` copies into `hdr_out[0]`; `nextheader` into `hdr_out[1]`, with the anchor
  holding a `HeaderCursor`; the reserved origin bit 1<<27 is set by the shim.
- `ErrorKind` → `CURLcode` through the existing generated match, no wildcard; the detail goes to
  ERRORBUFFER as `failf` gives it: the core tells `Callbacks::failure` a transfer's first reason,
  and the shim's sink copies it, in a multi as in a perform. Shim-only codes: RECURSIVE_API_CALL, CURLE_AGAIN from `Recv::WouldBlock` in
  `curl_easy_recv`/`send`, CURLM_BAD_SOCKET, CURLM_BAD_FUNCTION_ARGUMENT.
- Every function the system's libcurl exports is exported, so a program linked against it
  loads (Fedora's binaries bind every symbol as they start). The entry points of what the build
  leaves out answer as C's build without them does (`unbuilt.rs`): WebSockets and TLS session
  export `CURLE_NOT_BUILT_IN`, a server push's headers NULL. `curl_easy_option_*` walk C's
  table, generated from `lib/easyoptions.c` and checked against the inventory
  (`gen/easyoptions.py`). `curl_multi_get_handles` answers NULL inside a transfer's callback,
  as `curl_multi_info_read` does here, where the handles are not reached.

### 7.8 Deliberate differences from C

Each is either unobservable through the ABI or a fixed bug:
- Stale notifications, socket users and the pending cursor resolve to nothing (generational
  ids); C may hand them to whatever easy reuses the mid.
- `remove` runs the completion hook (C bypasses it at multi.c:815).
- A transfer the timer callback refuses inside `add` is not counted as running. C takes it out
  of its table but leaves its process bit and `xfers_alive`, so `running_handles` stays one too
  high for the life of the multi, and the debug build asserts at the next perform
  (multi.c:2916). It still counts towards `CURLMINFO_XFERS_ADDED`, as in C.
- `EXPIRE_MULTI_PENDING` does not exist (never armed in C).
- Connection settings are captured per connection, not last-writer-wins on an admin easy.
- `curl_easy_reset` cannot desynchronise socket bookkeeping: the announced pollset lives in the
  multi's slot, not in the easy's meta hash.
- `curl_easy_nextheader` with a stale `prev` returns NULL instead of reading freed memory.
- A pause from a transfer's own handler tells the timer and socket callbacks at the end of the
  pass, not inside `curl_easy_pause`; the announcement still comes before the multi call
  returns, so an event loop sees the same.
- `curl_easy_perform_ev` keeps its event state per call, not in a process-wide static. After
  the timer runs out it holds no timer until the multi sets one; C's `wait_or_timeout` sets 0
  there, and polls without waiting until a socket is ready when the multi never set one.
- A transfer without a URL starts a fresh report. C fails it in `Curl_pretransfer` before
  `Curl_pgrsStart`, so it completes on the previous transfer's start time, or on a zero one.
- file:// fails with ReadError where reading the file, its status or its directory fails; C
  ends the transfer successfully at a failed read or listing, and reads a file it cannot stat.
  Its descriptors are opened close-on-exec.

---

## 8. Allocation, OOM and testing without a network

### 8.1 Where memory is allocated

| What | When | Bound |
|---|---|---|
| arena row, timer entry, dirty capacity, socket-user and notification capacity | `add` (fails with the `Easy` handed back) | transfers added |
| `Box<Slot>` (the `Run` in it) | `add` | one per transfer |
| `Box<Easy>` | the shim's `curl_easy_init` and `curl_easy_duphandle`; `Easy::perform` | one per handle; one per `Easy::perform`, freed when it returns |
| `ConnectMachine`, attempts' sockets, `Conn` buffers, layer pipes | acquire / stage entry | limits, BUFFERSIZE, UPLOAD_BUFFERSIZE |
| `HeaderStore` growth | per line, after the budget check | 300 KiB/response, 20× per transfer, 5000 |
| `HeldOutput` | only while held | 64 MiB → TooLarge |
| `UserHeaders`, `Url`, option strings | setopt | per handle; shared strings are `TryRc` |
| a cold option group (`Cold<T>`: proxy, login, `.netrc`, cookies, signing, size and speed limits, custom request parts) | the first setopt of one of its options | one per group per handle |
| a Digest challenge's state | a response's Digest challenge | one per peer per handle |
| socket table entries beyond the reserved two | connect-machine stage entry, before the socket opens | 6 attempts + ALPN racers |
| error detail | on error | dropped if boxing it fails |
| request head | once, measured before it is written | 1 MiB → TooLarge |
| `Conn` receive buffer, head parser line | grows to the largest read and line | BUFFERSIZE, 100 KiB |
| trace lines, polling | none: stack buffers; a poll of one socket or of none makes no list | — |
| the TLS options (`Cold<TlsOptions>`; the SSL_CTX handler among them, and the proxy's in `Cold<Proxy>`) | the first setopt of one | one group per handle |
| a route's `TlsIdentity` | the leg's route, for a TLS route | one per leg, shared with the connection it makes |
| a TLS layer (`TlsLayer` and the library's session), the layer stack, the handshake's marker | the handshake's start | one per TLS layer; OpenSSL's own memory is libc's, uncounted |
| the multi's `TlsShared` and the library's state boxed in it (OpenSSL's: the kept store, the identity it was loaded for shared) | the multi's first TLS session; the state at its first store set up | one per multi |
| session cache entries | a ticket kept | 25 peers × 2 tickets (3 peers for `perform`'s multi) |

Nothing allocates per chunk. Peer-sized reservations happen after the limit check, so a hostile
peer gets a protocol error, not an out-of-memory one.

### 8.2 OOM tests and budgets

- `curl_alloc::track::fail_after(n, scenario)` runs a scenario with only `n` tracked
  allocations allowed, for n = 0, 1, … until a run has nothing refused; every run must end in
  `OutOfMemory` (or an earlier clean error), never abort, and leave `track::live_tracked()` where
  it was. The scenarios are harness-free test binaries (`crates/curl-core/tests/torture.rs`), as
  the limit is process-wide. Scenarios: add/perform/remove, a plain GET (a run that succeeds
  must have sent the whole request), a reused GET, a redirect, pause and replay.
  `track::fail_once_after` refuses one allocation alone, the rest allowed: the GET is also run
  so, and every such run must fail, for a refusal taken for success is a failure swallowed. The fake
  network and its peer are made untracked and hold room for a test's sockets and requests, so
  that what is refused is the library's.
- Budgets count allocations on the test's thread (`curl_alloc::track::count_allocations`). They
  are set as each scenario lands, at what this design calls for: the first, a plain GET over
  `FakeNet`, is fixed beside the test (`GET_BUDGET`) at 46, some of these taking more than one: the multi; the easy's URL, user
  agent and handlers; the transfer's place in the multi and its slot, boxed so the table's
  empty rows cost little, as C's hold pointers; the URL as fetched and its parts; the URL read
  back once parsed, as C reads it back; the target grown by its query; the protocol's state;
  the peer; the effective URL kept for the report; the answer for the host kept in the DNS
  cache (its name, its addresses, the answer shared, the cache's table); the list of connect
  attempts; the socket; the request head; the receive buffer; the head parser's line; the
  header store; and the content type. `Stream`, `Sock`, `Closer::System`, `Home` and an empty
  `LayerStack` allocate nothing, so step 40 leaves the budget as it is.
- The core's own part of an HTTPS GET is pinned over the fake TLS library
  (`HTTPS_FAKE_GET_BUDGET`, 55): the plain GET's 46, then the route's `TlsIdentity` (shared with
  the connection), the handshake under way, the library's session (the fake's one box), its
  layer, the stream's layer stack and its list, the multi's `TlsShared` with the fake's state
  in its box, and the key the connection's sessions are kept by. The same GET is run with each
  allocation refused in turn and alone; its server says goodbye back at once, so the
  connection's shutdown, as the multi goes, finishes in its one try and joins no set.
  `GET_BUDGET` stays 46: a plain GET makes no TLS group, identity or layer.
- Over OpenSSL, `crates/curl-openssl/tests/peer.rs` pins three, as the core cannot depend on
  the binding; OpenSSL's own allocations are libc's, not counted, as C's tracker does not count
  them, and the ALPN list and trace text are on the stack:
  - an HTTPS GET against the same GET over plain HTTP (`HTTPS_GET_EXTRA`, 18): the route's
    `TlsIdentity` and the CA file's copy in it, the layer, the stack's box and list, the
    handshake's marker, the session's box and its copy of the host name, the host name and CA
    file ended by a zero byte for OpenSSL, freed as the calls return, the multi's `TlsShared`
    and the box of OpenSSL's CA store cache in it, the key the connection's sessions are kept
    by, and, as the server's two TLS 1.3 tickets arrive, the multi's session cache: its slots,
    the slot's copy of the key and its list, and each ticket's DER;
  - a GET through an HTTPS proxy against the same through an HTTP proxy
    (`HTTPS_PROXY_GET_EXTRA`, 19): the 18, to the proxy, and the proxy route's cold part that
    holds the proxy's identity;
  - a second HTTPS GET in the multi, resuming the first's ticket on a new connection, against
    the first (`RESUMED_GET_FEWER`, 16 fewer): the multi's, the DNS cache's, the CA store's and
    the session cache's first-time allocations are not made again, the CA file is not read
    again, and a resumed session is given one ticket, not two; its TLS layer costs the first's.
  The same file's torture scenario refuses each allocation of a verified HTTPS GET with a
  pinned key's file, a client certificate, a CRL and the chain reported, with the rest and
  alone: every run fails (or, alone, succeeds whole where C lets that allocation fail, a
  ticket's copy for the cache) and leaves nothing allocated.
- Test 1's 140-allocation and 136000-byte limit is whole-process (argv, option parsing, output
  and trace files, the library). The tool's count is measured on `file://` in the milestone,
  before `http` is reported.
- `runtests.pl -t` over the milestone's tests checks the same at process level, against a torture
  run of the C build.

### 8.3 Fakes and test ports

- **`FakeNet`** (feature `test-util`): peers per address that accept, accept late, refuse or
  never answer, and fd numbers that reuse closed ones to exercise the socket table. A
  `Conversation` scripts what the next connection to an address says: like the suite's server,
  the peer answers each request's head with its next reply, then closes or stays open after the
  last, and keeps what it was sent for the test to compare; an idle connection whose reply was
  read whole has nothing waiting, so the pool's health check keeps it; a test can hang a peer up. Would-block points and partial sends
  are added when a case needs them. **`ManualClock`**: `wait` advances it to the next deadline
  when nothing is ready, so timeout tests take microseconds.
- **`RecordingEvents`** logs every socket, timer and notify call; **recording handlers** can run a
  scripted action through their context (pause, setopt, getinfo, sibling calls) to test
  re-entrancy. Golden call sequences for 530, 758, 1540, 1555, 2453, 3235 and 3236 come from the C
  leg's run of the libtest and are replayed against the core over `FakeNet`.
- **`tls::fake::FakeTls`** (test-util), a TLS library whose wire form a `Conversation` can
  script: a handshake of text lines (the client's hello a request head the peer answers, the
  server's welcome read as one record, the client's finished line), records of ROT13'd bytes
  behind a hex length, and a goodbye each way. It arms each path of the layer (a read that must
  write, partial records, bytes it holds, a shutdown that waits for the peer) and logs what it
  was asked (the peer, the identity's verify bit, the room of each read); a session allocates
  nothing past its box. `Conversation::stalling_sends_after` stalls sends mid-conversation.
  `Lingering` (test-util), a layer whose shutdown waits a number of passes or for its peer,
  arms the `ShutdownSet` without TLS (`multi::shutdown_tests`).
- **curl-openssl's peer** (`tests/peer.rs`): a server thread speaking TLS through the `openssl`
  crate on a loopback socket, with certificates made per test and signed by a CA made per
  test, so the OpenSSL paths have cargo tests over the system's network: a verified GET, the
  host check, an unverified peer, an unknown issuer, a missing CA file, the build's default CA,
  the BIO's read lengths, and the budget. The C captures that pin TLS's lines and 758's
  callback sequence (the
  retry-verify pause, and the socket kept through a connection's shutdown until the multi's
  cleanup) are the goldens.
- **Pure units**: `ResponseHeadParser`, `ChunkDecoder`, `decide_framing`, `render_h1`,
  `UserHeaders`, `Url` and the `Pipeline`, fed whole, one byte at a time, and at every split point.
- **A fixture runner reading `tests/data`** for the HTTP milestone set
  (`proto/http/suite.rs`): at test time it takes each case's reply, maps its command line to
  typed options, and compares the request the peer got, the output (as `-i` writes it), the
  dumped headers and the error code with the case's, after variable substitution, as
  `runtests.pl` compares them. The peer closes when the suite's server would. A case it cannot
  map is listed as skipped with why; a case that fails for want of a feature is listed as known,
  and the test fails when it starts passing. Nothing is generated, so the cases stay the single
  source. It is armed by a broken framing rule. When it says green and `runtests.pl` says red,
  the mapping has drifted: the runner is the fixture bug until shown otherwise.
- **Ported unit tests**, named after their originals: 1303, 1309, 3230 (table generated), 1399,
  1606, 1636, 1625, 1626, 2602, 2603, 1675, 2600, and 1560 growing with the URL parser.
- **Property tests**: random add/remove/pause/socket events checking the invariants (counts equal
  the recount, every lease released exactly once, the socket aggregate equals the OR of its users'
  announced pollsets, stale ids fail).
- **Malformed input never panics**: one property per parser at the trust boundary (the response
  head, chunked bodies, a proxy's answer, header fields, challenges, Digest, SOCKS replies,
  connect-to and resolve entries, proxy URLs and no-proxy lists, cookies, netrc, dates, URLs,
  the header store; in the tool, configuration files, globs, `--write-out` formats, file names
  from headers, protocol lists and numeric arguments). Inputs are built from each parser's
  words and from valid samples with bytes spliced in, under any options; the incremental
  parsers are fed whole and in random pieces and must agree, never stall, and keep within their
  buffers. The strategies are in each crate's `untrusted.rs`; `PROPTEST_CASES` raises the
  counts for a longer hunt. That a line's notes fit `Notes`' four slots is checked over every
  mix of what adds one.
- **`runtests.pl` on both legs** is the floor, read through its skipped line for every flip.

---

## 9. Choices made for compatibility

- **TLS** uses a custom BIO method over the layer below, as C does (section 4.9).
- **getinfo is live** during a transfer, and the header store spans it (sections 5.5, 6.3).
- **Total timeout**: C's two anchors are kept (section 3.4).
- **Read cap** at the response's remaining size is kept (section 5.1).
- **Read size** is the transfer's BUFFERSIZE, as `Curl_xfer_recv` cuts C's per-multi buffer to
  it (section 5.1).
- **`socket_action` reads the clock a second time** after it ran something, as C does (section
  3.5).
- **The share lock** is taken at C's four points in the Rust default too (section 4.6).
- **Connection-owned sockets** reach the socket callback with a non-NULL internal `CURL *`, as
  C passes its admin easy (section 7.5).
- **The Rust multi stores the application's values** (`Multi<H: Host>`), so the shim keeps no
  second map (section 2.7).
- **Sockets and polling** are `curl-os` modules over `libc`.
- **The URL parser** is built for what each milestone needs, behind its final type; unit 1560 is
  reported partial until it is complete.
- **Allocation budgets** are set when each scenario lands, at what this design calls for (section
  8.2).
- **The differences in section 7.8** are kept: each is unobservable through the ABI or a fixed
  bug.
