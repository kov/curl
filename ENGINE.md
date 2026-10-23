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
   the variant. The only stored set is `dirty`, which is a genuine separate fact (a work queue).
   Counters are an index with one writer (the transition function) and a full recount in the
   debug build after every pass.
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
   before. Operations that need a handshaken connection exist only on `Open`. A `Closing`
   state, for connections shut down gracefully, comes with TLS and the shutdown set.
7. **Generational ids everywhere**: `TransferId`, `ConnId` (whose generation is the
   "Connection #N" number), `ResolveId`, `HeaderCursor`. A stale id fails its own lookup.

**Call-outs and re-entrancy**

8. **Every call-out receives a context, and the context is the api.c table as types.**
   `TransferCx` (write, header, read, debug, progress, prereq, seek), `EventCx` (socket and
   timer callbacks: no `pause`) and `NotifyCx` (adds `add`, `remove`). A method exists on a
   context only if C allows that call from that callback. Contexts reach every other transfer
   and the multi's tables through `EngineRest`.
9. **No engine borrow is live across a call-out except two owned values moved out of their
   homes**: the stepping transfer's `Run` and its connection's receive buffer. Everything
   else stays in `EngineRest`, which the context borrows.
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
    `SendPause::{Running, Paused}`. `Stopped` is an API pause (the current buffer still
    finishes); `Held` is a callback pause (output is held at once). Rate limiting is a separate
    fact.
13. **The response pipeline is a fixed struct**, ordered by its fields, not a phase-sorted list.
    Paused output is ranges into one buffer, O(1) per append, EOS a separate event.
14. **Multiplexed connections buffer per stream inside the mux**, so a paused stream never
    holds the connection's shared receive buffer.
15. **`TransferReport` is created whole at transfer start, written live by the engine during
    the transfer, and stays in the `Easy` afterwards.** getinfo inside a callback reads it live
    (lib1541, lib1485). The header store is part of it and spans every request of the transfer.

**Ownership and API**

16. **`Multi::add` takes the `Easy` by value and `remove` gives it back.** `Easy::perform`
    moves itself into its private multi with `mem::take` and back, so `Easy` has no
    "None during perform" field.
17. **No admin easy.** Connection-level work takes a connection context with settings captured
    per connection.
18. **The clock is owned** (`Box<dyn Clock>`), read once per pass and passed down as `now`.
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
curl-sys-abi  the shim: handles, frames, callback adapters, generated setopt and api table
curl-tool     drives transfers through the Rust API
```

`curl-os` exposes safe functions; it does not implement `curl-core` traits (that would be a
dependency cycle). `curl-core::conn::io::SystemNet` adapts `curl-os` to the `Net` trait in safe
code. The libraries the core does not depend on (libpsl and the decoders) are handed to a
handle by whoever builds it: the shim and the tool.

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
  share.rs                   Share, Kind, ShareLock: what transfers of several handles keep
  cookie.rs                  Jar, Cookie, Suffixes: the cookie jar (cookie.c)
  netrc.rs                   .netrc files: the file's path, its entries for a host
  coding.rs                  Coding, Decoder, Decoders, AcceptEncoding: the content codings
  hash.rs                    MD5, SHA-256 and SHA-512/256, for Digest
  save.rs                    a file written whole under a name of its own, then renamed
  multi/
    mod.rs                   Multi<H>, Host, Slot, ConnLimits, the public API
    state.rs                 Run, TransferState and its variant structs, StepCx, the steps;
                             state/tunnel.rs, state/socks.rs, state/haproxy.rs: the
                             CONNECT and SOCKS handshakes and the PROXY line a transfer
                             makes
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
    connect_to.rs            the CURLOPT_CONNECT_TO entry matcher and parser
    dns.rs                   DnsCache, Answer, the CURLOPT_RESOLVE entry parser
    buf.rs                   RecvBuf
    io.rs                    Net, Socket, SystemNet, FakeNet (test-util)
  deliver/                   BodyAccountant, ClientOut; held.rs: HeldOutput;
                             decode.rs: Gate, the decoders' chain;
                             pause.rs: Pause, PauseRequest, Directions
  progress/                  Speedometer, the low-speed check; meter.rs, the meter's text
  upload/                    Upload, Readout (C's client readers); chain.rs: Body, Chain
  mime/                      Mime, Part, Content, Encoder, MimeSource; read.rs: MimeReader
  proto/
    mod.rs                   ProtoState (File, Http; test-util: Null, Stall, Script, Tcp),
                             Inherited
    file.rs
    http.rs, http/           the HTTP/1 driver: the request sent, the response read;
                             auth.rs (Basic, Bearer), digest.rs, cookies.rs (the jar as
                             HTTP uses it); suite.rs, C's test cases over the fake network
    script.rs                the test protocol `script:` (test-util)
    http1/                   the parsers and the renderer, sans-IO: request.rs, response.rs,
                             framing.rs, chunked.rs (decoder and encoder), fields.rs,
                             follow.rs (where a `Location:` leads); tunnel.rs, CONNECT and
                             the proxy's answer; fixture.rs, the test cases' sections (tests)
  untrusted.rs, test_cell.rs input for the never-panics properties; a Cell for handlers (tests)
```

Planned, not built: `conn/layer.rs` (Layer, LayerStack), `conn/mux.rs`, `conn/shutdown.rs`
(ShutdownSet, with TLS), a `Resolver` for names the cache and the shortcuts do not answer, and
`DebugNet`.

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

`Multi` owns `Box<dyn Clock>`. A pass reads `now` once at entry; steps, decoders, limiters and
filters receive it as an argument and never read the clock. `socket_action` keeps C's second
read after it ran something (§3.5). Timing records (`Timings::mark`) take the pass's `now`; under
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
inside `add`, which has no transfer context.

Outside a transfer the handle's `DebugHandler` is not reached: it takes a `TransferCx`, which a
handle in no transfer has none of. What C traces there (`CURLOPT_COOKIELIST`'s commands, as
they are set) is handed to a `notes` closure the caller passes, line by line in the transfer's
own formatting; the shim sends those lines to the debug function, or the STDERR stream, once
the handle is no longer borrowed, so the function may call back into it.

C's `CURLE_AGAIN` has three meanings (would-block, "rebuild the sub-chain", "nothing yet") and
"OK with 0 bytes" means EOF; here they are distinct variants. `NO_CONNECTION_AVAILABLE` is
`Acquired::Wait`, never an `Error`. The generated enums (`ErrorKind`, `MultiErrorKind`,
`ShareErrorKind`) hold every code C's headers define, as `gen/errors.py` emits them all; nothing
in the types separates the codes only the shim produces. The engine never constructs `Again`,
`NoConnectionAvailable`, `RecursiveApiCall` or `UnknownOption`, nor most multi codes, but a Rust
caller matching on the enums still meets them. Moving those codes into an enum of the shim's is
milestone 3's.

### 2.6 Easy

```rust
#[derive(Default)]                 // Default allocates nothing
pub struct Easy {
    options: Options,              // typed groups; handlers are Option<Box<dyn …>> inside
    report: TransferReport,        // the current or last transfer's; replaced whole at Init
    private: Option<Box<Multi>>,   // perform's multi, created on first perform, kept after
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
    limits: ConnLimits,              // MAXCONNECTS, MAX_HOST_CONNECTIONS, MAX_TOTAL_CONNECTIONS
    pending_after: Option<TransferId>, // the transfer last let look for a connection again
    sockets: SocketTable<H::Socket>, // fd → users and what each waits for, told, assigned value
    clock: Box<dyn Clock>,
    net: Box<dyn Net + Send>,
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
    run: Option<Run>,                // see below
}
pub(crate) struct Run {              // created at add, dropped at removal
    state: TransferState,
    deadlines: Deadlines,
    url: Vec<u8>,                    // the request's URL read back whole (C's state.url)
    retries: u8,                     // fresh connections tried this transfer (retrycount)
    inherited: Inherited,            // what a request takes from the ones before it: the
                                     // first origin, the method a redirect changed, HTTP/1.0
                                     // seen, Expect refused, whether CURLOPT_PORT applies
    #[cfg(feature = "debug-hooks")]
    warn: bool,                      // this transfer says the library is a debug build
}
```

Planned with the steps that need them: an internal owner for transfers the engine makes itself
(`Owner::Internal`, with server push), the shutdown set, and, in `Run`, the rate-limit state.

A row holds its slot boxed: a slot is most of a kilobyte, and a table starts with C's sixteen
rows, which C's limits on a transfer's memory count as pointers (libtest 500).

The `Easy` is boxed on its own and handed in and out by that box (`Multi::add` takes a
`Box<Easy>`; `Removed` and `AddError` give it back): the C shim keeps a handle's `Easy` in the
same box while it is on its own, so its options and report exist once, wherever the handle is,
and a handle's memory is one `Easy`, not one in the shim's handle and a second in the slot
(libtest 751 adds a thousand handles under a cap). The `Run` lives in the slot, as C's
per-transfer state lives in its `Curl_easy`: one allocation at `add`, not two.

`Slot.run` is `None` in exactly one situation: while the engine has moved the `Run` out to
step it, and for that duration the slot is reachable only through `EngineRest`, whose methods
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
type Origin = TryRc<Peer>;           // the request's peer, shared with its connection's route
pub(crate) struct Plan { proto: ProtoState, route: Tcp }  // the leg's route, built in start_leg
pub(crate) struct Connecting { lease: ConnLease, proto: ProtoState, route: Tcp,
                               handshake: Option<Box<Handshake>> }
pub(crate) struct Attached { lease: ConnLease, proto: ProtoState, origin: Option<Origin> }
pub(crate) struct Done { lease: ConnLease, proto: Option<ProtoState>, result: Result<(), ErrorKind>,
                         premature: bool, reached: Reached, origin: Option<Origin>,
                         next: AfterRequest }
enum Reached { Unmade, Made, Exchanged }  // DID's times taken; the exchange ran to its end
pub(crate) enum AfterRequest { Complete, Retry, Follow { location: Vec<u8>, code: u16 } }
                                                  // the protocol's done is told which
pub(crate) struct Completed { outcome: Result<(), ErrorKind>, message: Message }
pub(crate) enum Message { Unread, Read }
```

`Pending` and `Setup` hold what the setup made before it looked for a connection, so that only
the search is made again: the route, built once per leg, which `Connecting` keeps and reads its
destination and target from. Its IP version alone is read again as a waiting transfer looks
again, as C, which makes its connection anew then, reads `set.ipver`. A redirect is
`AfterRequest::Follow`, which the protocol's `done` decides from a `Location:` (§6.4); the next
leg's `Plan` is built from where it leads.

**A speed limit is a state of its own** (`RateLimiting`, C's RATELIMITING), not a flag on
`Exchanging`. `Exchanging` asks the limits (`mspeed_check`) before its step and after one that
leaves the request going: over either, it moves to `RateLimiting`, its `TooFast` timer armed for
the wait and its run in the next pass called off; under them, the timer is armed for the next
tokens. `RateLimiting` waits on nothing but that timer (no pollset), and at each wake fails at
the time limit, takes the progress and low-speed check, and goes back to `Exchanging` at once
once the limits allow.

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
               AwaitingContinue(Instant), Body(Reading), Done, Aborted }
enum AfterHead { Continue /* held for a 100 */, Body(Reading) }
struct Reading { eos_read: bool, announced: bool /* the head said Expect: 100-continue */ }
```

C's `sendbuf_hds_len` is `Head`'s `left`, `eos_read` is `Reading`'s, `upload_done` is `Done` or
`Aborted`, `upload_aborted` is `Aborted`, and `cr_exp100`'s states are `AfterHead::Continue`
(`EXP100_SENDING_REQUEST`), `AwaitingContinue` and a `Reading` that is `announced`
(`EXP100_SEND_DATA`; `http_exp100_is_selected` is any of the three). A body held for a 100 is
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
the limit's timer (§5.3), and no layer holds
received bytes a poll cannot see (`data_pending`; TLS will). One that asks for another request, by a location to
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
| Do | Did / Done | `ProtoState::do_it` made the request; prereq callback at DO entry; DID entry marks PRETRANSFER (+POSTTRANSFER if nothing to send); a failure is Done, not premature, before DID |
| Did | Exchanging / Done | Done at once if the protocol exchanges nothing more (`file:`, C's DID without sockets); an HTTP-family protocol yields once when more than one transfer is alive (C returns CURLM_OK there) |
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
elsewhere "Operation timed out after N milliseconds with X out of Y bytes received".

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
1. run every process transfer in ascending slot order with an index cursor, so a transfer
   added during the walk at a higher slot runs in the same pass;
2. `schedule_pending` if a pass flagged a connection change (graceful shutdowns and
   multiplexing flag it; neither exists yet, so nothing does);
3. dispatch notifications;
4. sweep the timer queue for entries before `now`; a late `Pending` transfer goes to setup and
   fails there with the timeout;
5. `timer_update`.
`perform` does not re-assess pollsets or call the socket callback, as in C.

**`socket_action`** (multi.c:3249):
1. `now = clock.now()`;
2. for a socket: mark every user dirty (a connection user is driven through `ShutdownSet`);
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
- **A connection being driven** is driven in its lease: `ConnLease::connect` replaces the
  lease's `ConnSlot::Connecting` with the drive's result, the pool not borrowed at all, and no
  call-out to the application happens during a drive. The socket open hooks
  (OPENSOCKET, SOCKOPT) will be the first call-outs inside one; their context carries no pool
  access, and they are the reason a drive may later move the machine out of its slot (§4.2).
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
                           // Closing(Box<Closing>) comes with the shutdown set

pub(crate) struct Conn {
    route: Route,
    number: ConnNumber,
    transport: Transport,              // Tcp(Socket) | Unix(Socket) | Local | later Udp; owns the socket
    layers: LayerStack,                // InlineVec<Box<dyn Layer>, 4>; empty for plain TCP
    session: Session,                  // Exclusive | Mux(Box<dyn Mux>)
    rx: RecvBuf,                       // received, not yet used; grown fallibly before a read
    created: Instant, idle_since: Option<Instant>,
    served: bool,                      // carried a request before (C's bits.reuse)
    close: bool,                       // not reusable, released as Close: the response
                                       // said so, or the peer closed (EOF read)
    info: ConnInfo,                    // primary/local addresses, HTTP version seen
}
```

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
    fn drive(self, net: &mut dyn Net, now: Instant) -> Result<Drove, ConnectError>;
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
cases are a test of the machine over a manual clock. A drive moves the machine by at most one event and returns it, in
place in its slot (§3.6); the transfer traces it in C's
words ("  Trying …", "connect to … from … failed: …", "Established connection to … ", then
`failf`'s "Failed to connect to H:P after N ms: …" or "Could not resolve host: …"). The machine
never reaches a transfer, so it is driven while the pool holding it is borrowed, and the
transfer's handlers run outside that borrow. As `cf_tcp_connect` does, the socket is polled
with a zero timeout right after its connect starts, so an answer already there is taken in the
same pass. A transfer whose receiving is paused is not driven (`multistate_connecting`), and the
connect limit is judged before each drive. A resolved name is reported as `cf_dns_report`
reports it ("Host H:P was resolved.", then each family's addresses), read back from the
machine through the pool, and NAMELOOKUP is marked when it resolves. An IPv6 attempt's address
carries C's `conn->scope_id`: `CURLOPT_ADDRESS_SCOPE`, else the destination peer's scope, else,
for a link-local address, the first non-loopback interface's with a link-local address
(`Net::link_local_scope`, cf-socket.c's `get_scope_id`), which `Progress::Trying` carries for
its trace; an attempt that fails at once is traced as tried first, as C opens and traces the
socket before its connect.

- Each stage owns what the previous stage produced: `Resolving` yields `DnsAnswer`, which
  builds `Eyeballs`; the winning `Attempt`'s `Transport` builds the next stage; each handshake
  pushes its finished `Layer`. Happy eyeballs never reads DNS sideways (C's
  `Curl_conn_dns_get_ai`), and the resolve record lives with the machine that started it, not
  on whichever transfer happens to call.
- A route through a proxy that makes a handshake (`Tcp::handshakes`: SOCKS, or an HTTP proxy
  that tunnels) does not end at the winning attempt: the machine keeps its socket as `Stage::Tunnel(Dialed)`, with a receive buffer, and
  returns `Progress::Dialed`. The machine does only the I/O of the handshake; the transfer
  (`multi/state/tunnel.rs`) makes it. It renders the `CONNECT` with the proxy's side of its
  `Auth`, sends it and reads the answer through `Pool::dialed`, parses it with
  `proto::http1::tunnel::Answer`, and delivers each line through its own pipeline as
  `HeaderOrigin::Connect`, so the report, header handler and auth state are the transfer's to
  write. It reads until the socket would block or the answer is whole, as C does, and takes
  stock of the transfer (`progress::update`) as C's byte-at-a-time read does: once for each
  byte of the answer, the byte after a header line counted before the line is taken in, once
  for the connection's end, and once each time it returns for more or has the answer. The
  SOCKS handshake, like C's, takes none. A 407 is answered with another `CONNECT` on the same connection, its body dropped;
  a 2xx makes the `Conn` (`Pool::tunneled`), keeping what came after the answer, and is
  traced as established only then.
- SOCKS likewise (`multi/state/socks.rs`, over the sans-IO `conn::socks::Handshake`). For SOCKS4
  and SOCKS5, which resolve the destination here, the machine resolves it as it dials, through
  the same cache, and the `Dialed` stage carries the answer. A failure is `ErrorKind::Proxy` with
  the `ProxyError` kept for `CURLINFO_PROXY_ERROR`; a SOCKS5 proxy that authenticated the user
  marks the `Conn`, which alone serves a transfer insisting on it (`CURLAUTH_ONLY`).
- A SOCKS pre-proxy (`CURLOPT_PRE_PROXY`) sits in front of an HTTP proxy only, set on its
  `ProxyRoute` through `ProxyRoute::behind`, which asserts it; alone, it is the route's SOCKS
  proxy. The route then dials the pre-proxy first (`Tcp::destination`), its SOCKS handshake asks
  for the HTTP proxy (`Tcp::socks` gives the leg), and a tunnelling HTTP proxy's `CONNECT`
  follows over the same `Dialed` stage; a SOCKS5 authentication is kept on `Dialed` and carried
  to the `Conn`. Reuse compares the pre-proxy too.
- A new connection, once up whichever way, sends the PROXY protocol's line first if the transfer
  asks (`multi/state/haproxy.rs`, `cf-haproxy.c`), with the addresses of the socket to the first
  hop, before it is traced as established. A reused one sends none, and reuse does not ask, as in
  C.
- A proxy that closes the connection on its 407 starts the setup over from resolving
  (`Pool::redial`, cf-setup.c's "AGAIN"), counted by the machine, at most 5. Each connection to
  the proxy counts toward `CURLINFO_NUM_CONNECTS` as it is made.
- Socket open order is one function in `conn::io` with C's sequence: OPENSOCKET callback (or
  `Net::open`), "Trying" trace, nodelay/keepalive, SOCKOPT callback (`AlreadyConnected` skips
  connect; other failure is AbortedByCallback), bind, nonblock, connect.
- Happy-eyeballs parameters are C's: 25 ms AAAA wait, `happy_eyeballs_timeout` attempt delay, at
  most 6 concurrent attempts, IPv6 first then alternating. Unit 2600 is ported before a second
  attempt is implemented.

### 4.3 Established layers

```rust
pub trait Layer {
    fn handshake(&mut self, cx: &mut LayerCx<'_>, below: &mut Pipe) -> Result<Handshake, Error>;
    fn decode(&mut self, cx: &mut LayerCx<'_>, input: &[u8], out: &mut Pipe) -> Result<usize, Error>;
    fn encode(&mut self, cx: &mut LayerCx<'_>, input: &[u8], out: &mut Pipe) -> Result<usize, Error>;
    fn interest(&self) -> Interest;
    fn pending(&self) -> bool;                    // plaintext buffered inside
    fn shutdown(&mut self, cx: &mut LayerCx<'_>, below: &mut Pipe) -> Result<Handshake, Error>;
    fn query(&self, q: LayerQuery) -> Option<LayerAnswer>;  // ALPN, certificates, tunnel status
    fn kind(&self) -> LayerKind;                  // Tls | HttpTunnel | Socks | HaProxy
}
pub struct LayerCx<'a> { now: Instant, trace: &'a mut Trace<'a>, hooks: &'a mut ConnectHooks<'a> }
```

Layers are sans-IO: bytes go up `transport → layers[0].decode → … → conn.rx` and down the
reverse way, with a small `Pipe` buffer between adjacent layers, allocated when the layer is
pushed. With no layers, `recv` writes straight into `conn.rx`. Only `conn::*` and `multi::wait`
call `Net`. `LayerCx` is an argument, never stored, which removes C's `CF_DATA_SAVE/RESTORE`
and its dangling-easy class. A layer asks another layer something only through `query`.

TLS (stage 4) drives OpenSSL as `lib/vtls/openssl.c` does: a custom BIO method whose read and
write go to the layer below (here, the layer's input and output `Pipe`s), so the `SSL *` and
`SSL_CTX *` handed to the application look as they do in C.

### 4.4 Multiplexing

```rust
pub trait Mux {
    fn open_stream(&mut self, id: TransferId, head: &RequestHead<'_>, now: Instant) -> Result<(), Error>;
    /// Connection bytes in. Stream data is buffered per stream inside the session; `note`
    /// reports only which transfers became runnable.
    fn input(&mut self, data: &[u8], now: Instant, note: &mut dyn FnMut(TransferId, StreamNote))
        -> Result<usize, Error>;
    fn read_stream(&mut self, id: TransferId, out: &mut RecvBuf) -> Result<StreamRead, Error>;
    fn output(&mut self, out: &mut SendBuf, now: Instant) -> Result<(), Error>;
    fn stream_pause(&mut self, id: TransferId, recv: RecvPause);   // window updates
    fn close_stream(&mut self, id: TransferId);
    fn concurrency_left(&self) -> u32;
}
pub enum StreamNote { Readable, Closed, Reset }
```

A note only marks the transfer dirty; each transfer drains its own stream during its own step,
so a step never builds a callback context for another transfer, and the borrow rules of §3.6
hold unchanged when HTTP/2 lands. Because data waits per stream inside the session, a paused
stream never pins `conn.rx`, which the other streams need. Streams are keyed by `TransferId`, so
a stale stream fails its lookup. The trait is defined in the first milestone and implemented at
stage 5.

### 4.5 Route and reuse

```rust
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Route {
    dest: Destination,                 // host:port, or connect-to / UDS peer
    transport: TransportKind,
    proxy: Option<ProxyRoute>,         // type, peer, credentials
    tls: Option<TlsIdentity>,          // every field that affects the handshake
    ip: IpPrefs, local: LocalBind,
    creds: Option<CredsBinding>,       // connection-bound auth (Negotiate)
    proto: ProtoFamily, scheme: SchemeConfig,
}
```

Built so far: `enum Route { Local, Tcp(Tcp) }`, with `Tcp { origin, via, ip, proxy }`. `Peer` is C's
`struct Curl_peer`: the `Scheme` (the protocol's name and whether it keeps connections,
`PROTOPT_CONN_REUSE`), the host as the URL names it, the port, the IPv6 zone and its scope (a
numeric zone as it is, a name as its interface's index by `if_nametoindex`, one naming no
interface none; `CURLOPT_ADDRESS_SCOPE` replaces the zone on the URL's peer), made once per
leg and shared by the transfer, as its origin, and the connection it sets up. `via` is the
peer a connect-to entry names in the origin's place (C's `via_peer`, `conn/connect_to.rs`),
none when it names the origin itself; the setup resolves and connects to `via` if there is
one, and the traces name it where C's do. Matching is `Route::serves`: the same origin by
`Peer`'s `Eq`, which is `Curl_peer_equal` (the host in any case, and the zone by its scope,
or by its text when it has none), the same `via` or none on both, and the same `IpVersion` unless the
transfer takes any (`url_match_conn`, `url_match_destination`). It, `ProxyRoute`'s key and
`Peer`'s `Eq` destructure every field without `..`, so a field added later does not compile until
it is compared; the exceptions are named where they are made (the transfer's `IpVersion::Any`;
`auth_only`, which `Conn::serves` checks against what the connection did; a peer's host,
compared as its name).

The proxy is chosen at setup, after the connect-to entries (`Curl_proxy_init_conn`): the
options' (`Options::proxy`), or else the one the environment names for the scheme
(`conn/proxy.rs`, `detect`, never `HTTP_PROXY` in upper case), unless the no-proxy list names
the origin's host (`excluded`, unit 1614's cases); an empty proxy turns the environment's off.
`ProxyRoute { kind, peer, creds, forward }` joins the route, and two routes match only through
the same proxy, compared without its scheme, as the same user and the same way
(`proxy_info_matches`, `origin_is_proxy`). A plain HTTP request goes whole to an HTTP proxy
(`forward`): the route's origin is then the proxy's peer, so one connection serves any origin
through it and the traces name the proxy, and the request names the whole URL without its
fragment or credentials (`Request::forward`, made from the `Url` before it goes to the report)
with `Proxy-Connection: Keep-Alive`; the response's `Proxy-Connection` keeps or closes the
connection (`Asked::http_proxy`). A tunnel (`CURLOPT_HTTPPROXYTUNNEL`, or a connect-to peer)
is set up with `CONNECT` (`multi/state/tunnel.rs`), SOCKS4, 4a and 5 with their handshakes
(`conn/socks.rs`, driven from `multi/state/socks.rs`), over the connection to the proxy the
setup dialed. An HTTPS proxy fails with `NotBuiltIn` until TLS is built.

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

### 4.6 Pool and lease

```rust
#[must_use]
pub struct ConnLease { id: ConnId, conn: Option<ConnSlot>, home: Option<Share> }  // no Clone/Copy
impl ConnLease {
    pub fn connect(&mut self, net: &mut dyn Net, now: Instant, setup: Setup<'_>)
        -> Result<Connected, ConnectError>;                     // Connecting, Established, AlreadyUp
    pub fn get(&mut self) -> &mut Conn;                                         // once up
    pub fn home(&self) -> Option<&Share>;                     // the share whose pool it is from
}
impl Pool {
    pub fn find(&mut self, route: &Route, rules: ReuseRules, net: &mut dyn Net, now: Instant,
                notes: &mut Vec<PoolNote>) -> Result<Option<ConnLease>, OutOfMemory>;
    pub fn add(&mut self, route: Route, limits: AddLimits, net: &mut dyn Net, now: Instant)
        -> Result<Acquired, OutOfMemory>;
    pub fn release(&mut self, lease: ConnLease, finish: Finish, limit: Limit, net: &mut dyn Net,
                   now: Instant) -> Released;
    pub fn get_conn(&self, id: ConnId) -> Option<&Conn>;               // idle only; stale: None
    pub fn close_idle(&mut self, net: &mut dyn Net);                            // multi drop
}
```

- A transfer searches before it adds (`find`, `Curl_cpool_find`), unless the transfer wants a fresh
  connection (`CURLOPT_FRESH_CONNECT`, but for a redirect's request): at most once a second it first prunes
  the idle connections that are not healthy, silently, as C's prune traces to its internal
  handle; then it takes the first idle connection, in table order, whose route is equal. One
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
- The pool owns every connection, busy or idle. It is the only issuer and consumer of leases,
  so it counts them itself; a connection's lease count, its `Session` users and the transfer's
  variant cannot disagree because only `acquire` and `release` change them. The per-route index
  is maintained by those same functions; a dangling id in it is an assertion, never repaired.
- A debug-build drop check on `ConnLease` asserts it was released (internal invariant).
- On a share's pool, `find`, `add` and `release` are each one use of it under its lock, and a
  transfer joining its multi is one more with nothing done (`Curl_cpool_xfer_init`). Test 1554
  pins this sequence (SHARE, CONNECT ×3 on first perform; CONNECT on return), so these four
  never merge or split.
- Leaving the pool, a connection is closed at once. Planned with TLS: it becomes `Closing` in
  the multi's `ShutdownSet` (graceful TLS close_notify, TCP drain of up to 1 KB, scheme
  disconnect handler once) or is terminated at once (aborted, CONNECT_ONLY, share-owned pool),
  and closing connections count toward host and total limits, as in C.
- **Socket close order** is enforced by the network the pool is handed: inside a multi it is
  `Announcing` (`EngineRest::net`, `EngineRest::pool_section`), whose `close` forgets the socket in the `SocketTable`
  first (socket callback REMOVE if the application was told of it, C's
  `Curl_multi_will_close`), then closes it through `Net::close`, where the shim is to call CLOSESOCKETFUNCTION once the
  socket hooks land (the option is not wired yet). Every pool path that closes a socket goes through it, so none can skip
  the order.

### 4.6.1 The share

`Share` (`share.rs`, `CURLSH`) keeps what it is asked to (`Share::keep`, `CURLSHOPT_SHARE`):
idle connections (`Kind::Connections`), names (`Kind::Names`), cookies (`Kind::Cookies`), each
behind a mutex of its own, and the network its idle connections close through at the end, as
C's share closes them through its own internal handle, and so, it is assumed, never through
CLOSESOCKETFUNCTION: not yet checked against C, to be tested when the socket hooks land. What it
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
its internal one. A share's idle connections close when its last clone drops.

### 4.7 No admin easy

Pruning, health checks, upkeep, shutdown and shutdown pollsets take
`ConnCx { now, net, trace, limits: &ConnLimits }`. `ConnLimits` (shutdown timeout, no_signal) are
captured per connection at creation from the creating transfer's options and the multi's
options, instead of C's `Curl_get_admin` copying the last caller's settings. The reuse limits
(max idle, max age) are the searching transfer's, passed to `acquire`.
Connection-owned sockets appear in the `SocketTable` with a `SocketOwner::Conn(ConnId)` user.

### 4.8 Resolver

```rust
pub trait Resolver {
    fn start(&mut self, host: &Host, port: Port, family: Family, now: Instant) -> Result<Resolve, Error>;
    fn poll(&mut self, id: ResolveId, now: Instant) -> Result<Option<DnsAnswer>, Error>;
    fn sockets(&self, out: &mut dyn FnMut(SocketKey, Interest));   // SocketOwner::Resolver
    fn cancel(&mut self, id: ResolveId);
}
pub enum Resolve { Answer(DnsAnswer), Pending(ResolveId) }
```

`ResolveId` is a generational key into the resolver's own arena; a stale id fails closed (C's
`Curl_resolv_has_answers` fails open). The resolvers come in order: the shortcuts (IP literals
and `localhost`), then getaddrinfo, then c-ares; the resolver-start callback is announced for
the shortcuts too (655 and 464).

Built so far: the shortcuts, the system's resolver and the cache. The resolver is not yet the
trait above: `Net::resolve(name, Family)` asks `getaddrinfo` and waits for its answer, as C's
synchronous resolver does, so the fake network that stands in for the system's sockets stands
in for its names too; the trait comes with c-ares, the first resolver that answers later.
`DnsCache` is in the multi's `Caches`, or a share's (section 4.6.1): entries by name, in
any case, and port, each a `TryRc<Answer>` that the connect machine using it shares, recording
the family asked (`dns_queries`): an answer for one family is no answer for both. A setup
looks in the cache first (`hostip_resolv`), then asks the shortcuts, then the resolver, and
keeps what they answer for the cache's timeout (`CURLOPT_DNS_CACHE_TIMEOUT`, the transfer's: 60
seconds unless set, for ever at -1). That a name does not exist, or has no address of the family
asked, is kept too, as an answer with no addresses ("Negative DNS entry"), which ages twice as
fast; that the resolver could not answer is not. A failure gives
the reference build's reason, c-ares's ("Domain name not found"), then fails again without it. `CURLOPT_RESOLVE` entries are read into the cache when a transfer
starts, once for each time the list is set (`Options::resolve` carries a stamp, the easy the
stamp it last read), as its source has them then; a list set while one is read, from the
debug handler, is taken as read too, as C clears `state.resolve` after reading. They are permanent unless given with `+`, and `*` answers for any name on
its port. A transfer's end prunes what has gone stale (`multi_done`).

---

## 5. The data path and callbacks

### 5.1 Receive

A protocol reaches its connection through `StepCx::conn(&lease)`; `do_it`, `step` and `done`
are given the lease the transfer's state holds. Inside an `Exchanging` step of `http:`:
1. what is left of the request's head is sent (`Conn::send`, traced as HEADER_OUT as it goes);
   the request owns its send buffer, as C's `req.sendbuf` is per request;
2. reads follow until one would block, the response is over or receiving pauses: each
   `Conn::recv` reads into `conn.rx`, which the step takes out (`mem::take`), feeds whole to the
   head parser, the body and the chunk decoder, and puts back emptied. C's cap of 11 reads per
   pass is not kept: a readable socket is read until it would block;
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
  handle's (`Easy::set_decoders`, kept through `reset`), given by the tool and the shim from the
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
struct Chain { chunks: Option<ChunkEncoder> /* a slot per C phase: line ends join it */ }
```

`Upload` is C's client readers at `CURL_CR_CLIENT` (`cr_null`, `cr_buf`, `cr_in`, `cr_mime`) as
one struct, made per request from `options.upload`. What it gives goes through `Chain`, the
readers C stacks above it in phase order (`cr_lc` at `CONTENT_ENCODE`, `cr_chunked` at
`TRANSFER_ENCODE`): sans-IO stages, each owning its fixed buffer, one slot per phase rather than
a list of boxes. A read of the `Body` asks the last stage: one with output gives it; one without
names the room in its buffer it wants filled (`wants`), the stage before it, or the source, fills
it, and it frames what came (`got`, with the trailers at the end for the chunk stage). The protocol
reads only the `Body`. `Expect: 100-continue` is not a stage: C's `cr_exp100` only holds reads
back, which `Sending::AwaitingContinue` does (§6.1). SMTP's dot-stuffing and line ends
(`CURLOPT_CRLF`, FTP ASCII) become stages when those protocols come.

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
- `Read::Pause` pauses the transfer's sending (`SendPause::Paused`) and gives nothing; on a
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
pub trait MimeSource: Send + Sync { fn mime(&self) -> Result<Option<TryArc<Mime>>, MimeError>; }
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
  callback"; a handler's failure, a file that cannot be opened, a failed read of a file that
  is not regular, a 7bit byte at or over 0x80, "read error getting mime data" (a failed read
  of a regular file ends the part there, as C's `fread` does, for the size check); a handler
  giving more than its room, "read function returned funny value"; the end short of a known
  size, "client mime read EOF fail, only X/Y of needed bytes read"; all ReadError. A pause is
  not latched: the transfer reads no more until it is unpaused, when the part's handler is
  called again (`mime_unpause`).
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
  two before DO and three after it;
- at each wake of `RateLimiting`, with the low-speed check;
- a last call from the `Done` step, shown whatever the time but only if the request is done or a
  second has passed, unless the outcome is AbortedByCallback. An `Abort` there fails a transfer
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
  read behind the head, and once the head has drained the request is `Sending::AwaitingContinue`
  until a deadline (`continue_wait`), not asking to write, the deadline its `wake_at`. A 100,
  the deadline ("Done waiting for 100-continue") or keep-sending-on-error opens it. A final
  response of 300 or more before the body has gone, the connection not closing anyway, stops
  the send ("HTTP error before end of send, stop sending", then "abort upload") and the
  connection is not used again, unless keep-sending-on-error. A 417 makes the request again
  without it, on a second leg (`Inherited::no_expect`).
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
  2918, 1722, 1723, 2119, 334, 499, 1484, 178, 394 and 282.
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
by the head parser as it takes the line. Its body is not delivered: on a connection that closes
the response ends at its head (`Framing::Abandoned`), on a kept one the body is read and dropped.
A complete exchange ends `Done { next: AfterRequest::Follow(location) }`; the Done step releases
the connection first, then `follow_leg` checks the limit (past it, FOLLOW_FAKE's URL is kept and
the transfer fails TooManyRedirects), counts the redirect in the report (C's
`state.followlocation`, which is also what "this is a follow" means), resolves the location as
FOLLOW_REDIR does and starts the next leg through `next_leg`, the tail it shares with a retry.
That leg's URL replaces `Run::url` whole (C's `state.url`). A redirect reaches only HTTP and FTP
schemes (`CURLPROTO_REDIR`). `Inherited::first`, in the `Run`, holds the first leg's origin (`state.initial_origin`):
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
What one request takes from the ones before it is `Inherited` on `Run`, reset at a transfer's
start: the first origin, the method (C's `state.httpreq`), whether the custom method is still
sent (`state.http_ignorecustom`) and whether a response said HTTP/1.0 (`rcvd_min`, which makes
the later requests HTTP/1.0). A request copies what it needs of it when it is made. Following a
redirect, in C's order: the old request's body is rewound (`Curl_req_soft_reset`), "Issue
another request" is said, `FIRSTONLY` drops the custom method, `follow::switches_to_get`
decides from `(code, method, POSTREDIR)` and `switch_to_get` applies it (a HEAD stays one).
A failed rewind fails the transfer unless the next request is a GET. A retry rewinds the same
way. A 417 to a body sent behind `Expect: 100-continue` makes the exchange end with a Follow
to the request's own URL, as C's `newurl` does: counted as a redirect, and with
`Inherited::no_expect` set so the library adds no Expect again. The connection is kept if the
body was still held, and closed if some of it went. A URL the application keeps (`SharedUrl`, `CURLOPT_CURLU`, which the shim's `CURLU *` is) goes
before the text URL: each transfer reads it as it starts, taking a copy of it as the first leg's
parsed URL; it is reached only inside a closure, so no borrow of it outlives the read.
`Options::port` replaces the port of that first URL, and of each leg after, until a redirect
leads to an absolute URL (`Inherited::allow_port`); as C sets it only in `state.uh`, it goes into
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
either. HMAC-SHA256 only: Ed25519 is not built in, as in a C build without a TLS library that
has it. Digest is in use from the start and done only once it answers a challenge, so a request
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
ones as the settings call for. A handle allocates about what C's does (751). A copy's
adapters are its own, installed in place of the ones it was cloned with.

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

- Socket callback: `SocketWhat` → `CURL_POLL_*`; the easy argument is the owner's `ShimEasy`,
  or `conn_easy` for connection-owned and resolver sockets (non-NULL, as C passes its admin
  easy); `socketp` is the `assign`ed value; `-1` → `Abort` → dead multi. `curl_multi_assign`
  inside the callback goes through `EventCx::assign`. From a transfer's own handler it answers
  CURLM_BAD_SOCKET, where C assigns: a handler's `TransferCx` does not reach the socket table,
  and is not generic over the host whose socket value it would store.
- Timer callback: `TimerChange::Set(d)` → `long` ms capped at INT_MAX; `Clear` → -1.
- `curl_multi_info_read` writes `CURLMSG_DONE`, the `CURL *` and the mapped code into
  `ShimEasy.msg` and returns a pointer to it: valid until that easy is removed or cleaned up.
- `CURLMINFO_XFERS_*` from `counts()`: RUNNING is process transfers (no "minus admin" because
  there is no admin row in the counts), DONE is unread messages (2453).
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
  `READ_ERROR`, is `Fail`, and so is -2, which C loops on; the rewind adapter
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
- **Sockets**: OPEN/SOCKOPT/CLOSESOCKETFUNCTION as a `SocketHooks` impl; the shim makes a
  `Socket` from the application's fd in `curl-os`.

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
| a cold option group (`Cold<T>`: proxy, login, `.netrc`, cookies, signing) | the first setopt of one of its options | one per group per handle |
| a Digest challenge's state | a response's Digest challenge | one per peer per handle |
| socket table entries beyond the reserved two | connect-machine stage entry, before the socket opens | 6 attempts + ALPN racers |
| error detail | on error | dropped if boxing it fails |
| request head | once, measured before it is written | 1 MiB → TooLarge |
| `Conn` receive buffer, head parser line | grows to the largest read and line | BUFFERSIZE, 100 KiB |
| trace lines, polling | none: stack buffers; a poll of one socket or of none makes no list | — |

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
  `FakeNet`, is fixed beside the test at 38: the multi, the easy's URL, user agent and
  handlers, the transfer's place in the multi, then the URL as fetched and its parts, the
  protocol's state, the destination, the socket, the request head, the receive buffer, the
  head parser's line, the header store and the content type. The host is copied three times
  (the request, the origin, the destination), two more than one owner needs.
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

- **TLS** uses a custom BIO method over the layer below, as C does (section 4.3).
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
