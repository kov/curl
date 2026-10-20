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
   both derived from the same stored instants. The timer queue is an index over it.
5. **Connection identity is an immutable `Route`; reuse matching follows its `Eq`.** A new
   field joins the comparison automatically. Nothing on a pooled connection is rewritten on
   reuse.
6. **A connection is `ConnSlot::{Connecting, Open, Closing}` under a stable `ConnId`.**
   `Connecting` holds a typed `ConnectMachine` (resolve, eyeballs, SOCKS, tunnel, TLS), each
   stage owning the output of the one before. Operations that need a handshaken connection
   exist only on `Open`.
7. **Generational ids everywhere**: `TransferId`, `ConnId` (whose generation is the
   "Connection #N" number), `ResolveId`, `HeaderCursor`. A stale id fails its own lookup.

**Call-outs and re-entrancy**

8. **Every call-out receives a context, and the context is the api.c table as types.**
   `TransferCx` (write, header, read, debug, progress, prereq, seek), `EventCx` (socket and
   timer callbacks: no `pause`) and `NotifyCx` (adds `add`, `remove`). A method exists on a
   context only if C allows that call from that callback. Contexts reach every other transfer
   and the multi's tables through `EngineRest`.
9. **No engine borrow is live across a call-out except two owned values moved out of their
   homes**: the stepping transfer's `Box<Run>` and its connection's receive buffer. Everything
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
    the operation start), both derived from `Deadlines`. A single anchor needs a test on the C
    build reproducing the late wake-up first.

**Delivery**

22. **Compatibility wins over efficiency.** Where the two pull apart, the engine does what C
    does, and a more efficient variant can come later as an opt-in. Section 9 lists the choices
    this settles.

---

## 2. Module and type layout

### 2.1 Crates

```
curl-alloc     rc.rs      TryRc<T>, TryArc<T>: fallible reference-counted pointers, sized T only
curl-os      + net.rs     nonblocking TCP/UDP/Unix sockets over OwnedFd (new unsafe module)
             + poll.rs    poll(2) over a slice of PollFd (new unsafe module)
             + wake.rs    socketpair waker, Send + Sync (new unsafe module)
curl-core    #![forbid(unsafe_code)]; depends on curl-alloc and curl-os (feature "net")
curl-sys-abi the shim: handles, frames, callback adapters, generated setopt and api table
curl-tool    drives transfers through the Rust API
```

`curl-os` exposes safe functions; it does not implement `curl-core` traits (that would be a
dependency cycle). `curl-core::conn::io::SystemNet` adapts `curl-os` to the `Net` trait in safe
code.

### 2.2 `curl-core` modules

```
curl-core/src/
  error.rs, error/kinds.rs   existing; Error gains Option<Detail> (boxed fallibly)
  version.rs                 existing; reports protocols as they land (file, then http)
  time.rs                    Instant, TimeLimit, Clock, SystemClock, ManualClock (test-util)
  id.rs                      Arena<T>, ArenaPolicy, Key<T>; TransferId, ConnId, ConnNumber
  url/                       Url, Host, Port, Origin; urlapi.c-compatible parser
  options/                   typed config groups: Network, Http, Output, Limits, Callbacks…
  easy.rs                    Easy, Easy::perform
  report.rs                  TransferReport, Timings, Sizes, HeaderStore, HeaderCursor
  handler.rs                 handler traits and their verdict enums
  trace.rs                   infof/debug formatting on a stack buffer
  multi/
    mod.rs                   Multi<H>, Host, public API, drive_to_completion
    slot.rs                  Slot, TransferShared, Run, the transition function
    state.rs                 TransferState and its variant structs
    step.rs                  run_single and the per-state steps
    sched.rs                 dirty set, pending cursor, Counts
    timers.rs                Deadlines, TimerQueue, TimerAnnounce
    sockets.rs               SocketTable, pollset diff, announce
    notify.rs                NotifyQueue
    cx.rs                    EngineRest, TransferCx, EventCx, NotifyCx
    wait.rs                  wait/poll/fdset/waitfds over Net
  conn/
    mod.rs                   ConnSlot, Conn, Route, ConnLease
    pool.rs                  Pool, SharedPool (the four lock points)
    connect.rs               ConnectMachine and its stages
    layer.rs                 Layer, Pipe, LayerStack, TunnelEvent
    mux.rs                   Mux, StreamNote (impls at stage 5)
    io.rs                    Net trait, SystemNet, FakeNet (test-util), DebugNet (debug-hooks)
    shutdown.rs              ShutdownSet
  resolve/                   Resolver trait, Literal, DnsCache, ResolveId
  deliver/                   Pipeline, BodyAccountant, PauseGate, ContentDecoder, ClientOut
  upload/                    BodySource, Upload, ChunkEncoder, Rewind
  proto/
    mod.rs                   ProtoState enum (File, Http1; later variants)
    file.rs
    http1/                   request.rs, response.rs, chunked.rs, follow.rs, auth.rs
  share.rs                   Share, Lock trait
```

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
own when the connection is gone.

### 2.4 Time

```rust
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);                         // µs since the clock's epoch; saturating ops
pub struct TimeLimit(NonZeroU64);                // ms; C's 0 ("no limit") is None
pub trait Clock { fn now(&self) -> Instant; }
pub struct SystemClock { base: std::time::Instant }
#[cfg(any(test, feature = "test-util"))]
pub struct ManualClock(TryRc<Cell<u64>>);        // tests hold a second handle and advance it
```

`Multi` owns `Box<dyn Clock>`. A pass reads `now` once at entry; steps, decoders, limiters and
filters receive it as an argument and never read the clock. `socket_action` keeps C's second
read after it ran something (§3.5). Timing records (`Timings::mark`) take the pass's `now`; under
`ManualClock` everything is deterministic.

### 2.5 Errors and outcomes

```rust
pub struct Error { kind: ErrorKind, detail: Option<Box<Detail>> }  // detail dropped on OOM, kind kept
pub enum Recv { Data(NonZeroUsize), Eof, WouldBlock }
pub enum Sent { Bytes(NonZeroUsize), WouldBlock }
pub enum Acquire { Ready(ConnLease, Reused), Connecting(ConnLease), Wait(WaitReason) }
pub enum WaitReason { HostLimit, TotalLimit, Multiplexable(ConnId) }
pub enum ConnectStep<S> { Pending(Interest, Option<Instant>), Next(S), Restart(RestartReason) }
pub enum Wake { Again, Idle }          // Again: run this transfer again in the same pass
```

C's `CURLE_AGAIN` has three meanings (would-block, "rebuild the sub-chain", "nothing yet") and
"OK with 0 bytes" means EOF; here they are distinct variants. `NO_CONNECTION_AVAILABLE` is
`Acquire::Wait`, never an `Error`. `Again`, `NoConnectionAvailable` and `RecursiveApiCall`
remain in the generated `ErrorKind` (error/kinds.rs:145, :161, :169) because the generator emits
every code; the engine never constructs them, and the error generator marks them as shim-only
so the type system enforces it.

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
pub trait Host { type Transfer; type Socket; }   // app values per transfer and per socket
pub struct NoHost;                                // Host<Transfer = (), Socket = ()>

pub struct Multi<H: Host = NoHost> {
    slots: Arena<Slot<H>>,
    sched: Sched,                    // dirty set, pending cursor, Counts
    timers: TimerQueue,              // one entry per slot, reserved at add
    announce: TimerAnnounce,         // what the timer callback was last told (unit 3230)
    sockets: SocketTable<H>,         // fd → users, announced interest, assigned app value
    notify: NotifyQueue,
    pool: PoolRef,                   // own, or the share's
    dns: DnsRef,
    shutdowns: ShutdownSet,
    net: Box<dyn Net>,
    clock: Box<dyn Clock>,
    waker: Option<TryArc<Waker>>,
    opts: MultiOptions,
    life: MultiLife,                 // Alive | Dead (a callback returned Abort)
}

pub(crate) struct Slot<H: Host> {
    owner: Owner<H::Transfer>,       // App(value) | Internal { parent: Option<TransferId> }
    easy: Easy,                      // options + live report; reachable from contexts
    shared: TransferShared,          // reachable from contexts while the run is moved out
    run: Option<Box<Run>>,           // see below
}
pub(crate) struct TransferShared {
    pause: Pause,
    announced: PollSet,              // what this transfer last contributed to the SocketTable
}
pub(crate) struct Run {              // created at add, dropped at removal
    state: TransferState,
    deadlines: Deadlines,
    url: UrlState, follow: FollowState, auth: AuthState,
    rate: RateLimits, speed: SpeedCheck,
}
```

`Slot.run` is `None` in exactly one situation: while the engine has moved the `Box<Run>` out to
step it, and for that duration the slot is reachable only through `EngineRest`, whose methods
treat the missing run as "this is the transfer being stepped". It is not a lifecycle flag: the
`Run` exists from `add` to `remove`, and `TransferState::Init` and `Completed` are its first and
last variants.

`Multi` borrows nothing: it owns its clock, its `Net` and its caches, so it can move into an
`Easy` or a shim handle.

### 2.8 Handlers

```rust
pub enum Write { Accepted, Pause, Fail }          // the shim maps a short count to Fail
pub enum Read { Data(usize), Eof, Pause, Abort }   // Data(n > buf.len()) is rejected, not asserted
pub enum ProgressVerdict { Continue, ContinueWithMeter, Abort }
pub trait WriteHandler  { fn write(&mut self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write; }
pub trait HeaderHandler { fn header(&mut self, cx: &mut TransferCx<'_>, line: &[u8], o: HeaderOrigin) -> Write; }
pub trait ReadHandler   { fn read(&mut self, cx: &mut TransferCx<'_>, buf: &mut [u8]) -> Read; }
pub trait DebugHandler  { fn debug(&mut self, cx: &mut TransferCx<'_>, k: DebugKind, data: &[u8]); }
pub trait ProgressHandler { fn progress(&mut self, cx: &mut TransferCx<'_>, p: Progress) -> ProgressVerdict; }
pub trait PrereqHandler { fn prereq(&mut self, cx: &mut TransferCx<'_>, p: &PrereqInfo) -> Result<(), Abort>; }
pub trait Rewind {
    fn rewind(&mut self, cx: &mut TransferCx<'_>) -> RewindResult;      // Ok | Fail
    fn seek(&mut self, cx: &mut TransferCx<'_>, to: u64) -> SeekResult; // Ok | CantSeek | Fail
}
pub trait MultiEvents<H: Host> {
    fn socket(&mut self, cx: &mut EventCx<'_, H>, who: SocketOwner<'_, H>, s: SocketKey,
              what: SocketWhat, assigned: Option<&H::Socket>) -> Result<(), Abort>;
    fn timer(&mut self, cx: &mut EventCx<'_, H>, t: TimerUpdate) -> Result<(), Abort>;
    fn notify(&mut self, cx: &mut NotifyCx<'_, H>, n: Notification<'_, H>);
    fn wants_sockets(&self) -> bool;     // C keeps socket bookkeeping only with socket_cb set
    fn wants_timer(&self) -> bool;
}
```

`TransferCx` is generic over `H` in the code; the lifetime-only form above is shorthand.

---

## 3. The multi loop and the transfer state machine

### 3.1 Transfer states

```rust
pub(crate) enum TransferState {
    Init,                              // added, not yet run
    Pending(Pending),                  // waiting for a connection slot
    Connecting(Connecting),            // holds a lease on a ConnSlot::Connecting
    Protocol(ProtoPhase),              // PROTOCONNECT..DOING_MORE
    Exchanging(Exchanging),            // DID..PERFORMING, RATELIMITING
    Done(Done),                        // multi_done pending; always holds the lease
    Completed(Completed),              // terminal until remove
}
pub(crate) struct Plan { target: Target, leg: Leg }        // the product of C's SETUP
pub(crate) struct Pending { plan: Plan, reason: WaitReason }
pub(crate) struct Connecting { plan: Plan, lease: ConnLease }
pub(crate) struct ProtoPhase { plan: Plan, lease: ConnLease, proto: ProtoState, step: ProtoStep }
pub(crate) struct Exchanging { plan: Plan, lease: ConnLease, proto: ProtoState, req: Request,
                               throttle: Option<Instant> }
pub(crate) struct Done { lease: ConnLease, proto: Option<ProtoState>, result: Result<(), Error>,
                         premature: bool, next: AfterRequest }
pub(crate) enum AfterRequest { Complete, Follow(FollowKind, Target), Retry(Target) }
pub(crate) struct Completed { outcome: Result<(), Error>, message: Message }
pub(crate) enum Message { Unread, Read }
```

- **The lease is released in exactly one place**: `Done::finish(self, cx) -> Result<Next, _>`
  runs C's `multi_done` order — shut down resolves, protocol `done` if past PROTOCONNECT,
  `pgrs_done` if past CONNECTING, flush the pipeline, `DataDone` to the layers, then
  `pool.release(lease, verdict)` (Keep, Idle, Close, Terminate), then `schedule_pending`.
  Because `Done` owns the lease until that last step, a connection can never return to the pool
  before the protocol has finished with it.
- **A failure without a connection** (Init's pretransfer, Pending's timeout, a Connect error
  before a lease exists) goes straight to `Completed`. A failure holding a lease goes through
  `Done { result: Err(..), premature: true }`. `TransferState::fail(self, err, cx)` picks the
  route from the variant; nothing else constructs `Completed`.
- **`enter_completed` is the one exit hook**: completion timings, `pgrs_completed`, EASY_DONE
  if not already queued from `Done`, clear the deadlines, enqueue the message (or the internal
  parent's callback). `remove` and the dead-multi path call it through `fail`.
- **Server push and `add_perform`** use a typed constructor, `TransferState::pushed(lease,
  proto)`, which enters `Exchanging` directly. "Really alive" is derived as "has left `Init`".
- **Follow and retry** build a new `Plan` from `AfterRequest`. `Deadlines` keeps `started_op`
  and sets a fresh `started_single`.

### 3.2 Per-request substates

```rust
pub(crate) struct Request { send: SendSide, recv: RecvSide }
pub(crate) enum SendSide { Head(HeadSending), AwaitingContinue(Instant), Body(BodySending), Done, Aborted }
pub(crate) enum RecvSide { Head(ResponseHeadParser), Body(BodyReader), Done }
pub(crate) struct BodyReader { framing: BodyDecoder, pipeline: Pipeline }
```

Each C flag becomes a variant: `k->header` is `RecvSide::Head`, `download_done` is `RecvSide::Done`,
`upload_done`/`eos_read`/`eos_sent` are the `SendSide` progression, `upload_aborted` is
`SendSide::Aborted`, `expect100` is `AwaitingContinue`, and `chunk`, `ignore_cl`,
`http_bodyless`, `size`/`maxdownload` are the `BodyDecoder` decided once at the end of the
headers. Which directions the request still drives (C's `req.io_flags`) is a function of the two
sides, not a stored field.

"Not done while paused" is structural: `Exchanging` steps to `Done` only on
`(RecvSide::Done, ClientOut::Direct)`; a held output keeps it in `Exchanging`.

### 3.3 Transitions

| From | To | Condition and work (C's order) |
|---|---|---|
| Init | Exchanging setup | pretransfer: fresh `TransferReport` (header store empties), cookies and resolve list, `started_op`; on failure `fail` → Completed |
| (setup) | Connecting / Exchanging / Pending | `started_single`; arm Total and Connect; `pool.acquire(route)` → `Connecting(lease)`, `Ready(lease)` (reused or `file:`), or `Wait` |
| Pending | (setup) | `schedule_pending` (one per call, round robin from `pending_cursor`), dirty while pending, or the expiry sweep finding it late |
| Connecting | Protocol | the slot became `Open`; not advanced while `recv != Running` |
| Protocol | Exchanging | protocol connect and DO done; prereq callback at DO entry; DID entry marks PRETRANSFER (+POSTTRANSFER if nothing to send) |
| Exchanging | yields | at DID, an HTTP-family protocol yields once when more than one transfer is alive (C returns CURLM_OK there) |
| Exchanging | Done | request complete with output not held: `next` is Complete, Follow or Retry; FOLLOW_FAKE writes `report.would_redirect` |
| connected | Done(Err) | progress callback abort |
| any live | fail | an error, a timeout, `remove`, or a dead multi (AbortedByCallback) |
| Done | (setup) / Completed | `finish`; Follow and Retry go back to setup with the new `Plan` |
| Completed{Unread} | Completed{Read} | `info_read` |

"Setup" is not a resting state: C's SETUP and CONNECT always run in the same pass, so they are
one step that produces `Pending`, `Connecting` or `Exchanging`.

Timeout errors come from one function on the state, producing C's texts: in `Connecting`,
"Resolving timed out after N milliseconds" or "Connection timed out after N milliseconds";
elsewhere "Operation timed out after N milliseconds with X out of Y bytes received".

### 3.4 Deadlines and timers

```rust
pub(crate) struct Deadlines {
    started_op: Instant,                 // once per transfer (C TIMER_STARTOP)
    started_single: Instant,             // per leg (C TIMER_STARTSINGLE)
    total: Option<TimeLimit>, connect: Option<TimeLimit>,
    armed: [Option<Instant>; TimerKind::COUNT],   // C's per-transfer expire list
}
pub(crate) enum TimerKind { Total, Connect, Expect100, AsyncName, HappyEyeballs, SpeedCheck,
                            TooFast, Quic, FtpAccept, AlpnEyeballs, Shutdown, ServerResponse }
impl Deadlines {
    fn start_leg(&mut self, now: Instant);                 // SETUP: arms Total and Connect
    fn arm_in(&mut self, kind: TimerKind, now: Instant, wait: Duration);
    fn clear(&mut self, kind: TimerKind); fn clear_all(&mut self);
    fn wake_at(&self) -> Option<Instant>;                  // earliest armed timer
    fn expire(&mut self, now: Instant);                    // an expiry pass consumed them
    fn time_left(&self, now: Instant, phase: Phase) -> TimeLeft;   // timeleft_now_ms
    fn since_op_ms(&self, now: Instant) -> u64;            // the N in the error texts:
    fn since_leg_ms(&self, now: Instant) -> u64;           //   which one, see below
}
```

- **The C behaviour is ported**: `start_leg` arms `Total` and `Connect` from `started_single`
  (C arms EXPIRE_TIMEOUT and EXPIRE_CONNECTTIMEOUT at every SETUP, multi.c:2497), and
  `time_left` judges the total limit from `started_op` and the connect limit (300 s when unset)
  from `started_single` (connect.c:70), in C's whole-millisecond arithmetic, where a limit
  reached exactly counts as passed by 1 ms. The connect timer is armed only when the limit is
  set, as in C. A timer stays armed after its instant until an expiry pass consumes it
  (`add_next_timeout`), so a timer armed in the past still wakes the transfer at once. The N
  in the error text follows C's two checks: the multi-level check reports `since_leg_ms` while
  connecting and `since_op_ms` after (multi.c:1820), the check at the end of a receive/send pass
  always `since_leg_ms` (transfer.c:382-393).
- `MultiPending` is not a kind: C declares EXPIRE_MULTI_PENDING (urldata.h:498) and never arms
  it.
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
    pub fn wait(&mut self, extra: &mut [WaitFd], max: Duration, mode: WaitMode)
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
leaves no message, as `curl_multi_remove_handle` (multi.c:780); forget its socket interest (socket callback REMOVE inside the call, multi.c:821); release the
timer entry; remove the row; `schedule_pending`; `timer_update` (multi.c:868). The `Easy` and the
owner value come back even when the timer callback aborts; `status` carries the abort. Removing
an id that is not in this multi returns `None`, which the shim maps to `CURLM_OK` (3105).
Dropping a `Multi` removes every transfer still in it (`curl_multi_cleanup`).

**`perform`** (multi.c:2898), with `now` read once:
1. run every process transfer in ascending slot order with an index cursor, so a transfer
   added during the walk at a higher slot runs in the same pass;
2. `schedule_pending` if a pass flagged a connection change;
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
5. `schedule_pending` if flagged, dispatch notifications, `timer_update`.

`run_dirty` iterates by index cursor, re-reading the dirty set after each transfer; a transfer
marked dirty by a callback at a higher index is visited in the same pass (C's `bset_next`).

**`run_single(id, now)`** moves the `Box<Run>` out of the slot (a pointer move), and loops
while the step returns `Wake::Again`: deadline check for connected states, dispatch on the
variant, the extra deadline check before DO, then `is_finished` (error → `fail`; else the
progress callback once connected, `Abort` → `Done(Err)`). It puts the `Run` back before
`assess` and before the next transfer runs. A dead multi completes the transfer with
AbortedByCallback.

### 3.6 Call-outs and contexts

```rust
pub struct EngineRest<'a, H: Host> {      // the multi minus what the step holds
    slots: &'a mut Arena<Slot<H>>,        // the stepping slot's `run` is moved out
    pool: &'a mut PoolRef, sockets: &'a mut SocketTable<H>, timers: &'a mut TimerQueue,
    announce: &'a mut TimerAnnounce, sched: &'a mut Sched, notify: &'a mut NotifyQueue,
    net: &'a mut dyn Net, now: Instant, life: &'a mut MultiLife,
}
pub struct TransferCx<'a, H: Host> {
    me: TransferId,
    me_basis: PollBasis,                  // my pollset before pause masking, computed at call-out
    flush: Option<&'a mut Pipeline>,      // Some only where C would let a nested flush run
    rest: EngineRest<'a, H>,
    events: &'a mut dyn MultiEvents<H>,
}
impl<H: Host> TransferCx<'_, H> {            // api.c's "may recurse" column
    pub fn info(&self, id: TransferId) -> Option<&TransferReport>;
    pub fn header(&self, id: TransferId, q: HeaderQuery) -> Result<HeaderView<'_>, HeaderError>;
    pub fn options_mut(&mut self, id: TransferId) -> Option<&mut Options>;
    pub fn pause(&mut self, id: TransferId, p: PauseRequest) -> Result<(), Error>;
    pub fn duplicate(&self, id: TransferId) -> Result<Easy, OutOfMemory>;
    pub fn info_read(&mut self) -> Option<Message<'_, H>>;
    pub fn assign(&mut self, s: SocketKey, v: H::Socket) -> Result<(), MultiError>;
    pub fn counts(&self) -> Counts;
    pub fn set_notify(&mut self, kind: NotifyKind, on: bool);
}
pub struct EventCx<'a, H: Host>  { /* the same methods except `pause` (api.c no_event_cb) */ }
pub struct NotifyCx<'a, H: Host> { /* + add, remove, wait, poll, timeout: api.c allow_ntfy_cb */ }
```

The rules that keep this sound:
- **During a call-out, the engine holds only owned values moved out of their homes**: the
  stepping transfer's `Box<Run>` and, while delivering received bytes, the connection's
  `RecvBuf` (taken with `mem::take`, which allocates nothing, and put back after delivery).
  The pool, the other slots and every table stay in `EngineRest`. No iterator over engine state
  is live across a call-out.
- **The stepping transfer's pollset during its own callback** is `me_basis` (computed from
  the state and the layers' interest just before the call-out; neither can change while the
  engine is suspended in the callback) masked by `shared.pause`, which the callback may change.
  So `pause` from a write callback calls `timer_update` and `assess(me)` synchronously, and the
  socket callback runs inside `curl_easy_pause` as in C. For any other transfer the pollset is
  computed from its `Run`, which is in its slot.
- **A call on a sibling transfer** routes to that slot. A sibling's unpause flushes its
  pipeline synchronously by the same rule as a step: its `Box<Run>` is moved out for the flush
  and put back after, so the handlers it calls get a context whose `EngineRest` does not alias
  it. A `pause` reaching a transfer whose `Run` is already out (the stepping one, or one being
  flushed) gets no `flush` and only changes the value; nesting is bounded by that, not by a
  counter.
- **A connection being driven** is moved out the same way: `ConnectMachine::drive(self)` takes
  the `Box` out of `ConnSlot::Connecting` and the pool puts the result back; no call-out to the
  application happens while it is out except the socket open hooks, whose context carries no
  pool access.
- **Nested flushes cannot happen.** A context built for a callback that runs during a replay of
  held output has `flush: None`, so `pause(me, Cont)` there only flips the value; the outer
  replay loop sees it before the next entry (3235, 3236). The progress and prereq callbacks are
  made with the pipeline not borrowed, so their contexts get `flush: Some(..)` and an unpause
  there flushes synchronously, as in C.
- **Event call-outs** (socket, timer) are made between transfers with no `Run` moved out;
  `EventCx` cannot pause.
- **Notifications** are dispatched at the end of `perform`/`socket_action` with no borrow live;
  `NotifyCx` borrows the whole multi minus the call-out entry points. A stale id resolves to
  nothing and is dropped; internal transfers are never passed (3107).

**Handler take-and-restore.** Before a call-out the engine takes the handler out of
`easy.options.callbacks` (`Option::take`), builds the context, calls it, and puts it back only if
the slot is still empty. A handler installed from inside its own call wins, and the next piece
of the same write uses it (fix 8940c1436b, #23085). A handler is never invoked re-entrantly
because it is not in its slot while it runs; the engine `expect`s it present on entry, an
internal invariant.

### 3.7 Counts and messages

`Counts { running, pending, done_unread, current, added_ever }` is written only by the transition
function as states change, and is checked against a full recount from the states after every pass
in the debug build. `running_handles` is "added and not `Completed`" (Init and Pending count).
`info_read` returns the lowest-slot `Completed { message: Unread }`, sets it `Read`, and reports
the number still unread.

---

## 4. Connection filters, pool and resolver

### 4.1 Connection slots

```rust
pub(crate) enum ConnSlot { Connecting(Box<ConnectMachine>), Open(Conn), Closing(Box<Closing>) }

pub(crate) struct Conn {
    route: Route,
    number: ConnNumber,
    transport: Transport,              // Tcp(Socket) | Unix(Socket) | Local | later Udp; owns the socket
    layers: LayerStack,                // InlineVec<Box<dyn Layer>, 4>; empty for plain TCP
    session: Session,                  // Exclusive | Mux(Box<dyn Mux>)
    rx: RecvBuf, tx: SendBuf,          // sized once at creation, reused across requests
    created: Instant, idle_since: Option<Instant>,
    close: Option<CloseReason>,        // Some: not reusable, released as Close
    info: ConnInfo,                    // primary/local addresses, HTTP version seen
}
```

Protocols without a network (`file:`, C's PROTOPT_NONETWORK) lease a `Conn` with
`Transport::Local`: no socket, no layers, never pooled for reuse (released as Close), with empty
`rx`/`tx` that allocate nothing; the file protocol reads the file into the pipeline itself. This
keeps one lease-holding path through `Done` for every protocol, as C attaches a connection for
`file:` too.

`ConnectMachine::drive` returns `ConnectStep`; on `Next(Established(conn))` the pool replaces
the slot in place, so the `ConnId` and every outstanding lease survive the handshake. Send,
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
    fn drive(self, io: &mut ConnIo<'_>, cx: &mut ConnCx<'_>)
        -> Result<ConnectStep<ConnectMachine>, Error>;
}
```

- Each stage owns what the previous stage produced: `Resolving` yields `DnsAnswer`, which
  builds `Eyeballs`; the winning `Attempt`'s `Transport` builds the next stage; each handshake
  pushes its finished `Layer`. Happy eyeballs never reads DNS sideways (C's
  `Curl_conn_dns_get_ai`), and the resolve record lives with the machine that started it, not
  on whichever transfer happens to call.
- `ConnectStep::Restart(ProxyClosedForAuth)` is C's "AGAIN means rebuild the sub-chain", counted
  by the machine, at most 5 (cf-setup.c).
- The tunnel handshake reads through its own transport and layers, not through "the first
  connected filter from the top". It emits `TunnelEvent`s (status line, header lines, auth
  challenge, response code); the transfer applies them to its report, header callback and auth
  state. A filter never writes into a transfer.
- Proxy authentication state is passed in as `&mut ProxyAuth` from the transfer for the call.
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
pub struct ConnLease { id: ConnId }          // no Clone/Copy; only Pool creates or consumes one
impl Pool {
    pub fn xfer_init(&mut self, lock: &dyn Lock);                               // lock point 1
    pub fn acquire(&mut self, route: &Route, wants: ReuseWants, now: Instant)
        -> Result<Acquire, Error>;                                               // lock points 2, 3
    pub fn get(&mut self, lease: &ConnLease) -> &mut ConnSlot;                  // cannot fail
    pub fn release(&mut self, lease: ConnLease, finish: Finish) -> Released;   // lock point 4
    pub fn get_conn(&self, id: ConnId) -> Option<&Conn>;                        // stale: None
}
```

- `release` decides the connection's fate as `multi_done_locked` does, from what the pool knows
  (other leases, the route's reuse rules, a close mark) and what the transfer reports in
  `Finish` (premature, reuse forbidden): `Released::{InUse, Idle, Closed, Terminated}`.
- The pool owns every connection, busy or idle. It is the only issuer and consumer of leases,
  so it counts them itself; a connection's lease count, its `Session` users and the transfer's
  variant cannot disagree because only `acquire` and `release` change them. The per-route index
  is maintained by those same functions; a dangling id in it is an assertion, never repaired.
- A debug-build drop check on `ConnLease` asserts it was released (internal invariant).
- `acquire` takes the share lock exactly at `find` and at `add`, as two separate critical
  sections; `xfer_init` and `release` take it once each. Test 1554 pins this sequence (SHARE,
  CONNECT ×3 on first perform; CONNECT on return), so these four never merge or split.
- Leaving the pool, a connection becomes `Closing` in the multi's `ShutdownSet` (graceful TLS
  close_notify, TCP drain of up to 1 KB, scheme disconnect handler once) or is terminated at once
  (aborted, CONNECT_ONLY, share-owned pool). Closing connections count toward host and total
  limits, as in C.
- **Socket close order** is enforced by `Pool::close`: forget the socket in the `SocketTable`
  first (socket callback REMOVE, C's `Curl_multi_will_close`), then drop the transport through
  `Net::close`, which the shim maps to CLOSESOCKETFUNCTION.

### 4.7 No admin easy

Pruning, health checks, upkeep, shutdown and shutdown pollsets take
`ConnCx { now, net, trace, limits: &ConnLimits }`. `ConnLimits` (shutdown timeout, max idle,
max age, no_signal) are captured per connection at creation from the creating transfer's options
and the multi's options, instead of C's `Curl_get_admin` copying the last caller's settings.
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
`Curl_resolv_has_answers` fails open). The first milestone ships `Literal` (IP literals and
`localhost`, with the resolver-start callback announced for both, 655 and 464), then a
getaddrinfo resolver, then c-ares. The DNS cache is the multi's or the share's, behind `Lock`;
CURLOPT_RESOLVE entries are permanent; negative entries only for an authoritative NXDOMAIN.

---

## 5. The data path and callbacks

### 5.1 Receive

Inside an `Exchanging` step:
1. `pool.get(&lease)` gives the `Conn`; up to 10 rounds of `transport.recv` → layers →
   `conn.rx`, unless `recv != Running` or the request no longer receives;
2. the step takes `conn.rx` out (`mem::take`), releases the pool borrow, and feeds
   `proto.on_input(Input::Data(rx.filled()), now, &mut req, &mut cx)`, which returns how much
   it consumed; then puts `rx` back with the remainder;
3. `Recv::Eof` becomes `Input::Eof`, which decides: GOT_NOTHING (52), a short body (18), the end
   of an `UntilClose` body, the HTTP/0.9 flush, or `Retry` on a reused connection that delivered
   nothing (at most 5).

Reads are capped at `size - bytecount` on non-multiplexed connections, as transfer.c's
`xfer_recv_resp` does. The cap is redundant with a per-connection buffer (leftovers would simply
wait in `conn.rx`), but it fixes how `DATA_IN` traces are chunked and when unsolicited input is
seen; it is dropped only after a C-leg comparison on 1701 and 3223.

Each read asks for at most the multi's read size: the largest BUFFERSIZE any of its transfers
has read with so far, since C's per-multi `xfer_buf` is replaced only when a transfer needs a
larger one (multi.c:4028). `conn.rx` grows to that size before a read, fallibly. C's `borrowed`
flag (multi.c:4023) becomes the move-out above, which the compiler checks.

### 5.2 Response pipeline

```rust
pub(crate) struct Pipeline {
    raw_trace: bool,                             // DATA_IN of raw bytes before any decoding
    framing: BodyDecoder,                        // None | Length{left} | Chunked | UntilClose
    accountant: BodyAccountant,                  // STARTTRANSFER, maxdownload, max_filesize (raw), short EOS
    gate: PauseGate,                             // ≤4 KiB pieces into decoders; holds encoded input while Held
    decoders: InlineVec<ContentDecoder, 5>,      // a 6th coding is BadContentEncoding at parse
    out: ClientOut,
}
pub(crate) enum ClientOut { Direct, Held(HeldOutput), Failed }
pub(crate) struct HeldOutput { bytes: Vec<u8>, entries: VecDeque<(OutKind, Range<u32>)> }  // cap 64 MiB
```

- **Order is the field order**: raw trace, transfer decoding, accounting, pause gate, content
  decoders (last listed runs first), client output. The header collector writes into the
  report's `HeaderStore` from the response parser, before the line reaches `out`.
- **`ClientOut`** passes body in pieces of at most 16384 bytes whatever BUFFERSIZE is, header
  lines whole; with `include_header` a line goes to the write handler, then the header handler.
  A switch of output kind with held entries flushes them first, preserving interleaving.
  Consecutive body entries extend the last range: O(1) per append (C's quadratic class).
  `Write::Pause` → `Held` with the unconsumed piece kept and `pause.recv = Held`; on a protocol
  without pause support (`file://`) it is WriteError "Write callback asked for PAUSE when not
  supported". `Write::Fail` or a short count → `Failed`, a terminal variant with no path to a
  handler (#13337). Held beyond 64 MiB → TooLarge "pause buffer not large enough".
  `max_filesize` against delivered bytes is checked before each piece; SIZE_DELIVERED is bumped
  after the handler returns.
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
- `CONT` → `Running`, flush held output (synchronously where `flush` is reachable, §3.6), reset
  the token bucket and the speed window, tell a mux (`stream_pause`).
- A new request (redirect, retry) starts with both `Running`.
- Derived effects: `Connecting` does not advance while `recv != Running`; the pollset drops IN
  while `recv != Running` and OUT while `send == Paused`; speed checks are skipped while either
  is paused; `Exchanging` does not reach `Done` while `recv == Held`.

`pause` (core of `curl_easy_pause`):
1. no lease held → BadFunctionArgument;
2. apply per direction; an unpause of recv flushes when `flush` is reachable;
3. unless blocked in every wanted direction, mark the transfer dirty;
4. if anything changed: `timer_update`, then `assess(id)`; an `Abort` from either is
   AbortedByCallback.

The rate limiter is `RateLimits` on the `Run`, a separate fact consulted only while `Running`;
limiting is the `throttle: Option<Instant>` deadline on `Exchanging`, armed as TOOFAST.

### 5.4 Send side

```rust
pub(crate) enum BodySource { Null, Shared(TryRc<Vec<u8>>), Callback(ReadState), Mime(MimeReader) }
pub(crate) struct Upload { source: BodySource, crlf: Option<LineConv>, chunked: Option<ChunkEncoder>,
                           known_len: Option<u64>, sent: u64, latch: ReadLatch /* Open|Eof|Errored */ }
```

- The request head is rendered straight into `conn.tx`; body bytes are pulled from `Upload`
  into the remaining space (the first read is reduced by the head length, as C's shared chunk).
  HEADER_OUT and DATA_OUT are traced for the bytes `Net::send` accepted, split at the head
  length; SIZE_UPLOAD counts accepted body bytes only.
- The read handler is clamped to `min(free space, remaining length, rate tokens)`, latched at EOF
  and on error, never called after EOF until a rewind; EOF short of a known length is
  ReadError "client read function EOF fail, only X/Y of needed bytes read".
- COPYPOSTFIELDS is `Shared`. Non-copied POSTFIELDS is a shim `ReadHandler` over the app's
  pointer (§7.6); the core never holds a raw borrow, and it reads at transfer time as C does.
- `Upload::rewind` is a no-op if the source was never read; otherwise `Rewind::rewind` (shim:
  SEEKFUNCTION, IOCTLFUNCTION, fseek iff the default fread) or SendFailRewind. Resume: `seek`,
  and on `CantSeek` read and discard in 4 KiB pieces; nothing left → PartialFile "File already
  completely uploaded".

### 5.5 Progress and timings

`Timings` holds per-leg sums (each at least 1 µs, one STARTTRANSFER per leg) plus points
(REDIRECT) and is written by the engine as C's set points occur: STARTOP at Init, STARTSINGLE per
leg, POSTQUEUE at acquire, NAMELOOKUP at the first answer, CONNECT/APPCONNECT from the connect
machine's stats event, PRETRANSFER at DID, POSTTRANSFER at DID with nothing to send or at upload
done, STARTTRANSFER at the first non-CONNECT client write, TOTAL every progress pass and at
completion; a jump to completion from before DID marks PRE, POST and START together.

The progress handler runs only with progress enabled: after every receive/send pass (with the
speed check), at the tail of every `run_single` iteration once connected, in throttled states,
and a final forced call from `Done::finish` unless the outcome is AbortedByCallback or the
transfer never connected. The meter is core code writing to the stderr sink, redrawn at most once
per second (unit 1636).

---

## 6. HTTP/1.x

### 6.1 Request

```rust
pub struct RequestHead<'o> {
    method: Method<'o>, target: RequestTarget<'o>, version: HttpVersion,
    builtin: EnumMap<BuiltinHeader, Builtin<'o>>, user: &'o UserHeaders,
}
pub enum Builtin<'o> { Default, Suppressed, Replaced(&'o [u8]) }
pub struct UserHeaders { text: Vec<u8>, index: Vec<UserHeader> }   // built once at setopt
pub enum UserHeader { Value { name: Range<u32>, value: Range<u32> }, Blank { name: Range<u32> },
                      Remove { name: Range<u32> } }
pub fn render_h1(head: &RequestHead<'_>, gate: &CredentialGate, out: &mut SendBuf)
    -> Result<HeadLen, Error>;                                         // > 1 MiB: TooLarge
```

- **Order is the declaration order of `BuiltinHeader`**, so rendering iterates the enum and the
  sequence of http.c:2899 is a property of the type: request line, Host, Proxy-Authorization,
  Authorization, Range, User-Agent, Accept, TE, Accept-Encoding, Referer, Proxy-Connection,
  Transfer-Encoding, Alt-Used, Upgrade, Cookie, conditionals, custom headers in the order given,
  Content-Length, Content-Type, Expect, Connection, blank line.
- **`UserHeaders` is indexed once**, replacing about 15 linear `Curl_checkheaders` scans per
  request. Its constructor holds the rules: `Name;` sends an empty header, `Name:` removes it,
  colon-less lines are dropped, the first Host wins (1121), `-H host:` removes Host (461),
  `Host;`/`Accept;` send blanks (1292), the name is trimmed so `Authorization :` is recognised.
- **One credential gate.** `CredentialGate::for_target(&Target)` compares the current origin with
  the initial origin once per request. Authorization, Cookie and a custom Host render only
  through methods that take the gate's `SameOrigin` token, so a new emit site cannot skip the
  check.
- **One typed request for every version.** h2 and h3 (stage 5) encode the same `RequestHead`;
  C's render-to-HTTP/1-then-reparse (`Curl_h1_req_parse_read`) has no counterpart, and the H1
  request parser survives only as test support (unit 2603).
- `Expect: 100-continue` is `SendSide::AwaitingContinue(deadline)`, armed when the head has
  drained, released by a 100, the timeout or keep-sending-on-error; a 417 retries without it.
  Unknown body length on HTTP/1.1 uses the chunk encoder (chunks ≤ 64 KiB, trailers from the
  trailer handler); on HTTP/1.0 it is UploadFailed.

### 6.2 Response

```rust
pub struct ResponseHeadParser { line: LineAssembler /* 100 KiB cap, fold state inside */,
                                lines: u32, budget: HeaderBudget }
pub enum HeadEvent<'b> { Status(StatusLine), Header(HeaderLine<'b>), Interim(u16), Final(FinalHead), Http09 }
pub struct FinalHead { status: u16, version: H1Version, framing: BodyFraming, close: bool }
pub enum BodyFraming { None, Length(u64), Chunked, UntilClose }
fn decide_framing(meta: &ResponseMeta, method: &Method<'_>, opts: &FramingOptions)
    -> Result<BodyFraming, Error>;
```

- `feed(&mut self, bytes, now) -> Result<(usize, Option<HeadEvent>), Error>` is pure: complete
  lines are borrowed from `conn.rx`; only a split or folded line is copied into the assembler.
  Folding state lives in the assembler, not in transfer state (1274).
- Per line: `verify_header` (NUL, stray CR, missing colon → 8); trace HEADER_IN; the header
  handler; `include_header` output; the `HeaderStore`; size accounting; the facts that decide
  framing are recorded in `ResponseMeta`.
- **Framing is decided once, at the blank line, by `decide_framing`**: 1xx, 204, 304 and HEAD
  have no body; TE overrides CL and a non-chunked final coding is `UntilClose` plus close;
  `--ignore-content-length`; conflicting CL → 8; unsolicited TE → error; HTTP/1.0 closes unless
  keep-alive. These are the inputs pinned by 365, 2918, 1722, 1723, 2119, 334, 499, 1484.
- **Every peer limit is an `Error`**: 100 KiB per line, 300 KiB per response and 20× that per
  transfer (one counter per limit in `HeaderBudget`), 5000 stored headers, 17 hex digits per
  chunk size, 4 KiB per trailer line, 5 codings.
- **`ChunkDecoder`** is C's HEX/LF/DATA/POSTLF/TRAILER/STOP/DONE machine as an enum. The
  chunk-extension state swallows bytes up to LF on purpose and says so. Trailers go to the sink
  as `HeaderOrigin::Trailer`; `--raw` passes the bytes through while still parsing.
- The status line: `HTTP/1.[01] DDD`, `HTTP/2 DDD`, `HTTP/3 DDD`, HTTP200ALIASES; version
  mismatch and unknown subversion are errors; on a bad first line the reused-connection and
  version-seen cases are 8, HTTP/0.9 not allowed is 1, otherwise the bytes are an HTTP/0.9 body.
- GOT_NOTHING is computed in one place from the response-phase byte counts, discounting 1xx.

### 6.3 Header store

```rust
pub struct HeaderStore { gen: StoreGen, buf: Vec<u8>, entries: Vec<HeaderEntry> }
pub struct HeaderEntry { name: Range<u32>, value: Range<u32>, origin: HeaderOrigin, request: u16 }
pub struct HeaderCursor { gen: StoreGen, index: u32 }
```

It lives in `TransferReport`, so it spans every request of the transfer and stays readable after
`perform` returns, until the next transfer's Init or the `Easy` is dropped (headers.c). Growth is
`try_reserve` after the budget check. A `HeaderCursor` from an earlier transfer fails its
generation check and the shim returns NULL from `curl_easy_nextheader`, where C chases a freed
list node.

### 6.4 Redirects and auth

`http1::follow(&FinalHead, &Target, &FollowPolicy) -> Result<FollowDecision, Error>` builds the
next `Target` whole; it replaces the old one, so no stale URL copy exists between the decision
and the next leg (C's `state.up`). 301/302/303 method switching is a pure function of
`(status, method, policy)`; FOLLOW_FAKE fills `report.would_redirect`; MAXREDIRS gives 47.
Auth is `AuthState` on the `Run`: `input(challenge)`, `act(status) -> Option<Retry>`,
`output(&CredentialGate) -> AuthHeaders`; stage 3 covers Basic, Digest and Bearer.

---

## 7. The C ABI mapping: the hard cases

### 7.1 Handles

```rust
struct ShimEasy {                         // what CURL * points to; stable address
    magic: u32,
    home: Home,                           // Detached(Easy) | Added { multi: NonNull<ShimMulti>, id: TransferId }
    private: Option<Box<ShimMulti>>,      // curl_easy_perform's multi, kept across performs
    ccb: CCallbacks,                      // C fn pointers + userdata for every callback
    strings: InfoStrings,                 // getinfo char* copies: until next transfer or cleanup
    hdr_out: [CHeader; 2],                // curl_easy_header / nextheader result slots
    msg: CURLMsg,                         // what info_read points into
    errbuf: Option<NonNull<c_char>>,
}
struct ShimMulti {
    core: UnsafeCell<Multi<CHost>>,       // CHost { Transfer = NonNull<ShimEasy>, Socket = *mut c_void }
    frame: Cell<Option<Frame>>,           // the live context, set only while a C callback runs
    conn_easy: Box<ShimEasy>,             // the CURL * passed for connection-owned sockets
    cb: CMultiCallbacks,
    waker: Option<TryArc<Waker>>,         // curl_multi_wakeup without touching `core`
}
enum Frame { Transfer(NonNull<TransferCx<'static, CHost>>), Event(NonNull<EventCx<'static, CHost>>),
             Notify(NonNull<NotifyCx<'static, CHost>>) }
```

### 7.2 Re-entrant calls: one gate

Every exported function that touches a multi goes through one of two functions:

```rust
fn with_multi<R>(m: &ShimMulti, call: ApiCall,
                 via_frame: impl FnOnce(&mut Frame) -> R,
                 direct: impl FnOnce(&mut Multi<CHost>) -> R) -> Result<R, Recursive>;
fn with_easy<R>(e: &ShimEasy, call: ApiCall, …) -> Result<R, Recursive>;
```

1. A frame is present: if `TABLE[call]` does not allow the call in that frame kind, return
   CURLE_/CURLM_RECURSIVE_API_CALL; otherwise call the context method (`via_frame`), which
   reaches the target transfer by id, whether it is the caller's own or a sibling.
2. No frame: form `&mut Multi` from the `UnsafeCell` (SAFETY: no frame means no outstanding
   borrow of `core`; a frame is pushed only while the core is suspended in a call-out on this
   thread).

`ShimMulti` is only ever reached through raw pointers while `core` is borrowed; the
`MultiEvents` adapter the shim hands the core borrows `&Cell<Option<Frame>>`, `&CMultiCallbacks`
and `&ShimEasy` (the connection easy), never `&ShimMulti`. The callback adapters push the frame
around each C call and restore the previous one after it; panics abort, so the pop cannot be
skipped. The `'static` in `Frame` is lifetime erasure confined to the push/pop pair: the adapter turns
its `&mut TransferCx` into the raw pointer before calling C and does not use the reference again
until after the pop, so the only access path during the C call is the frame. A call on a
handle in another multi takes path 2 on that multi.

`TABLE` is generated from `lib/api.c`'s `eapi_fn_props`, `mapi_fn_props` and the event-callback
flag into the shim (the extraction goes through `inventory/`), and a shim test parses the C file
and compares the columns. C's recursion depth limits (15 for multi calls, 7 for easy calls) are kept in
the shim, as api.c applies them; the Rust API has no depth limits because the context types bound nesting. CI
greps that every `extern "C"` function in `easy.rs` and `multi.rs` calls a gate.

### 7.3 `curl_easy_pause`

- Detached handle, or no lease → CURLE_BAD_FUNCTION_ARGUMENT.
- `Added { multi, id }` with a `Transfer` frame → `cx.pause(id, req)`: own transfer or sibling;
  the timer and socket callbacks run inside, the write callbacks run inside if `flush` is
  reachable.
- `Event` frame → RECURSIVE_API_CALL (`no_event_cb`).
- No frame → `Multi::pause(id, req, &mut ShimEvents)`: flush (write callbacks), then the timer
  callback, then the socket callback, inside the call, as easy.c:1187-1236.

### 7.4 `curl_easy_perform`, `curl_easy_perform_ev`, cleanup

- `perform`: reject if `Added`; close a leftover CONNECT_ONLY connection; take or create the
  private `ShimMulti` (policy 16/1); copy MAXCONNECTS and QUICK_EXIT; move the `Easy` in
  (`home = Added { private, id }`); `drive_to_completion` (the same core function `Easy::perform`
  uses, plus frames); remove; move the `Easy` back. An internal multi error maps to OutOfMemory
  or BadFunctionArgument.
- `perform_ev` (debug-hooks): the same, driven through `socket_action` with an event table owned
  by that call, not C's `static struct events` (easy.c:705); any multi error →
  CURLE_URL_MALFORMAT, as C.
- `curl_multi_add_handle` of an easy with a private multi drops that multi; already added →
  ADDED_ALREADY; dead multi → ABORTED_BY_CALLBACK until no transfer remains (530, 758); clears
  ERRORBUFFER and os_errno.
- `curl_easy_cleanup` on an added handle removes it first (753, 1939). `curl_multi_cleanup`
  removes every app transfer, returning each `Easy` to its `ShimEasy`, drops internal ones, then
  terminates connections (timeout 0 unless CURL_GRACEFUL_SHUTDOWN).
- `curl_multi_remove_handle`: not added → OK (3105); wrong multi → BAD_EASY_HANDLE.

### 7.5 Socket and timer callbacks, info_read, counts

- Socket callback: `SocketWhat` → `CURL_POLL_*`; the easy argument is the owner's `ShimEasy`,
  or `conn_easy` for connection-owned and resolver sockets (non-NULL, as C passes its admin
  easy); `socketp` is the `assign`ed value; `-1` → `Abort` → dead multi. `curl_multi_assign`
  inside the callback goes through `EventCx::assign`.
- Timer callback: `TimerUpdate::In(d)` → `long` ms capped at INT_MAX; `Clear` → -1.
- `curl_multi_info_read` writes `CURLMSG_DONE`, the `CURL *` and the mapped code into
  `ShimEasy.msg` and returns a pointer to it: valid until that easy is removed or cleaned up.
- `CURLMINFO_XFERS_*` from `counts()`: RUNNING is process transfers (no "minus admin" because
  there is no admin row in the counts), DONE is unread messages (2453).
- `curl_multi_wait`: negative timeout → BAD_FUNCTION_ARGUMENT; capped at `timeout()`; no fds →
  returns at once (`wait`) or sleeps (`poll`); the waker is polled only when waiting and is not
  counted; extra revents use the CURL_WAIT_POLL* bits. `waitfds` too small → OUT_OF_MEMORY with
  the needed count. `fdset` skips sockets above FD_SETSIZE; both include closing connections.

### 7.6 Callback adapters (C shapes stay here)

- **Write**: `(ptr, 1, len, userdata)`; CURL_WRITEFUNC_PAUSE → `Write::Pause`; CURL_WRITEFUNC_ERROR
  → `Fail` ("client returned ERROR on write of N bytes"); `n != len` → `Fail` ("Failure writing
  output to destination, passed N returned M"); NULL → fwrite to WRITEDATA or stdout. The adapter
  reads `ccb` at call time, so a setopt of WRITEFUNCTION/WRITEDATA inside the callback applies to
  the next piece.
- **Header**: HEADERFUNCTION, else WRITEFUNCTION if HEADERDATA is set, else discard; userdata is
  always HEADERDATA.
- **Read**: `n > nmemb` passed through as `Read::Data(n)` for the core to reject ("read function
  returned funny value"); READFUNC_ABORT → `Abort`; READFUNC_PAUSE → `Pause`.
- **Progress**: XFERINFO if set, else PROGRESS with doubles; CURL_PROGRESSFUNC_CONTINUE →
  `ContinueWithMeter`.
- **Rewind**: SEEKFUNCTION(0), then IOCTLFUNCTION(RESTARTREAD), then fseek iff READFUNCTION is the
  default, else fail.
- **Non-copied POSTFIELDS**: a shim `ReadHandler` over the app's pointer and POSTFIELDSIZE, read at
  transfer time (SAFETY: the CURLOPT_POSTFIELDS contract keeps the buffer alive). Setting it after
  `add_handle` takes effect (1531).
- **Sockets**: OPEN/SOCKOPT/CLOSESOCKETFUNCTION as a `SocketHooks` impl; the shim makes a
  `Socket` from the application's fd in `curl-os`.

### 7.7 setopt, getinfo, headers, errors

- `curl_easy_setopt` dispatch is generated from `inventory/options.json`: a `Detached` handle
  writes its `Easy`; an `Added` one goes through `with_easy` (frame → `options_mut(id)`, else
  `multi.easy_mut(id)`). Callback options update `ccb` only.
- `curl_easy_getinfo`: frame → `cx.info(id)`; else `multi.report(id)` or the detached report.
  Strings are copied into `InfoStrings`. CURL_TIME and CURL_DEBUG_SIZE overrides apply here
  under debug-hooks.
- `curl_easy_header` copies into `hdr_out[0]`; `nextheader` into `hdr_out[1]`, with the anchor
  holding a `HeaderCursor`; the reserved origin bit 1<<27 is set by the shim.
- `ErrorKind` → `CURLcode` through the existing generated match, no wildcard; the detail goes to
  ERRORBUFFER. Shim-only codes: RECURSIVE_API_CALL, CURLE_AGAIN from `Recv::WouldBlock` in
  `curl_easy_recv`/`send`, CURLM_BAD_SOCKET, CURLM_BAD_FUNCTION_ARGUMENT.

### 7.8 Deliberate differences from C

Each is either unobservable through the ABI or a fixed bug:
- Stale notifications, socket users and the pending cursor resolve to nothing (generational
  ids); C may hand them to whatever easy reuses the mid.
- `remove` runs the completion hook (C bypasses it at multi.c:815).
- `EXPIRE_MULTI_PENDING` does not exist (never armed in C).
- Connection settings are captured per connection, not last-writer-wins on an admin easy.
- `curl_easy_reset` cannot desynchronise socket bookkeeping: the announced pollset lives in the
  multi's slot, not in the easy's meta hash.
- `curl_easy_nextheader` with a stale `prev` returns NULL instead of reading freed memory.
- `curl_easy_perform_ev` keeps its event state per call, not in a process-wide static.

---

## 8. Allocation, OOM and testing without a network

### 8.1 Where memory is allocated

| What | When | Bound |
|---|---|---|
| arena row, timer entry, dirty capacity, socket-user and notification capacity | `add` (fails with the `Easy` handed back) | transfers added |
| `Box<Run>` | `add` | one per transfer |
| `ConnectMachine`, attempts' sockets, `Conn` buffers, layer pipes | acquire / stage entry | limits, BUFFERSIZE, UPLOAD_BUFFERSIZE |
| `HeaderStore` growth | per line, after the budget check | 300 KiB/response, 20× per transfer, 5000 |
| `HeldOutput` | only while held | 64 MiB → TooLarge |
| `UserHeaders`, `Url`, option strings | setopt | per handle; shared strings are `TryRc` |
| socket table entries beyond the reserved two | connect-machine stage entry, before the socket opens | 6 attempts + ALPN racers |
| error detail | on error | dropped if boxing it fails |
| trace lines, request head, header parsing | none: stack buffers and `conn.tx` | — |

Nothing allocates per chunk. Peer-sized reservations happen after the limit check, so a hostile
peer gets a protocol error, not an out-of-memory one.

### 8.2 OOM tests and budgets

- `fail_each_allocation(|| scenario())` runs a scenario under the tracker's limit for N = 1, 2, …
  until it completes, and asserts every run ends in `OutOfMemory` (or an earlier clean error),
  never aborts, and leaves the tracker leak-free. Scenarios: add/perform/remove, a plain GET, a
  reused GET, a redirect, pause and replay.
- Budgets count allocations on the test's thread (`curl_alloc::track::count_allocations`). They
  are set as each scenario lands, at what this design calls for: the first, a plain GET over
  `FakeNet`, is fixed when that commit lands and recorded beside the test.
- Test 1's 140-allocation and 136000-byte limit is whole-process (argv, option parsing, output
  and trace files, the library). The tool's count is measured on `file://` in the milestone,
  before `http` is reported.
- `runtests.pl -t` over the milestone's tests checks the same at process level, against a torture
  run of the C build.

### 8.3 Fakes and test ports

- **`FakeNet`** (feature `test-util`): scripted peers per address — expected bytes in, bytes out,
  would-block points, partial sends, EOF, resets, connect refusal, and fd numbers that reuse closed
  ones to exercise the socket table. **`ManualClock`**: `wait` advances it to the next deadline
  when nothing is ready, so timeout tests take microseconds.
- **`RecordingEvents`** logs every socket, timer and notify call; **recording handlers** can run a
  scripted action through their context (pause, setopt, getinfo, sibling calls) to test
  re-entrancy. Golden call sequences for 530, 758, 1540, 1555, 2453, 3235 and 3236 come from the C
  leg's run of the libtest and are replayed against the core over `FakeNet`.
- **Pure units**: `ResponseHeadParser`, `ChunkDecoder`, `decide_framing`, `render_h1`,
  `UserHeaders`, `Url` and the `Pipeline`, fed whole, one byte at a time, and at every split point.
- **A fixture runner generated from `tests/data`** for the HTTP milestone set: the generator
  writes the reply, the options mapped to typed options, the expected `<protocol>` after variable
  substitution, the expected output and error code. A Rust test drives `Multi` over `FakeNet`
  playing the server. It is trusted only after it fails on a deliberately broken framing rule.
  When it says green and `runtests.pl` says red, the mapping has drifted: the runner is the
  fixture bug until shown otherwise.
- **Ported unit tests**, named after their originals: 1303, 1309, 3230 (table generated), 1399,
  1606, 1636, 1625, 1626, 2602, 2603, 1675, 2600, and 1560 growing with the URL parser.
- **Property tests**: random add/remove/pause/socket events checking the invariants (counts equal
  the recount, every lease released exactly once, the socket aggregate equals the OR of its users'
  announced pollsets, stale ids fail).
- **`runtests.pl` on both legs** is the floor, read through its skipped line for every flip.

---

## 9. Choices made for compatibility

- **TLS** uses a custom BIO method over the layer below, as C does (section 4.3).
- **getinfo is live** during a transfer, and the header store spans it (sections 5.5, 6.3).
- **Total timeout**: C's two anchors are kept (section 3.4).
- **Read cap** at the response's remaining size is kept (section 5.1).
- **Read size** follows C's per-multi buffer, the largest BUFFERSIZE seen (section 5.1).
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
