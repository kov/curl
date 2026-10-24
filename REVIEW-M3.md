# Design review after milestone 3

Reviewed commit: `ddf03b7e51` ("MILESTONES: mark step 44 and milestone 3 done"). The only later
commit on master, `4d4feeb126`, changes MILESTONES.md alone, so every line cited below still
holds there.

## How the review was run

The review was one multi-agent workflow. Eight reviewers, one per dimension, read the code, the
design documents and the C tree:

- the engine's state model;
- connections, layers and the pool;
- the protocol seam for the protocols still to come;
- the parsers and the trust boundary;
- unsafe code, FFI and the shim;
- C idioms in the Rust API;
- the library's C compatibility;
- the tool's C compatibility.

Each reported finding then went to its own adversarial verifier. The verifier re-read every
cited Rust line, read the C source behind every claim about C, and checked the finding against
DIVERGENCE.md, ENGINE.md 7.8 and MILESTONES.md. Its default was to refute.

The eight reviewers raised 33 findings. The verifiers refuted 7 (listed at the end), confirmed
2 and corrected 24. After the overlapping ones were merged, 24 findings remain below.

No code was built or run for the review itself. Where a verifier measured something, the
finding says so. Before any C-matching fix lands, the C build in this tree is run on its case,
as CLAUDE.md requires.

Each finding gives its severity and its type:

- **Design change**: acting on it changes DESIGN.md or ENGINE.md. These wait for the user.
- **C behaviour**: it brings observable behaviour in line with C and changes no design.
- **Tenet**: it brings the code in line with a CLAUDE.md tenet without changing the design or
  the behaviour.

| # | Finding | Severity | Type |
|---|---|---|---|
| 1.1 | Connection setup is split between the transfer and the connection | high | Design change |
| 1.2 | Shim adapters hold a raw `NonNull<ShimEasy>` kept valid by hand-written steps | medium | Design change |
| 1.3 | `&'static Libraries` and `&'static KeyLog` force process-wide statics | medium | Design change |
| 1.4 | The process set is read from the trace's `MState`, not the variant | low | C behaviour |
| 1.5 | ENGINE.md §1.3, §2.7 and §3.1 describe fields the code does not have | low | Tenet (docs) |
| 2.1 | Who owns a multiplexed connection, and how HTTP/2 delivers, is undecided | medium | Design change |
| 2.2 | The I/O seams assume a byte stream; QUIC and HTTP/3 have no place | medium | Design change |
| 2.3 | A session beside the layer stack misses health, shutdown and keep-alive | medium | Design change |
| 2.4 | `HeadParser` has no whole-line entry for HTTP/2, HTTP/3 and RTSP | medium | Design change |
| 2.5 | Peer-chosen size limits are re-derived by hand at each buffer | low | Design change |
| 2.6 | Range parsing is private to `file.rs`, in signed offsets with sentinels | low | Design change |
| 2.7 | The tool hand-copies C header constants the shim generates | low | Tenet (generator) |
| 3.1 | A 101 never ends the response head | medium | C behaviour |
| 3.2 | No CA-certificate help text after exit 60 | medium | C behaviour |
| 3.3 | Pool search ignores the transfer's last connection | low | C behaviour |
| 3.4 | Header lines with an empty name are sent | low | C behaviour |
| 3.5 | The cookie hash reads bytes ≥ 0x80 unsigned | low | C behaviour |
| 3.6 | `-f` with `--retry-max-time` exits 22 where C exits 0 | low | Divergence, needs approval |
| 3.7 | Digest parsing takes out-of-memory for the end of the challenge | low | Tenet |
| 3.8 | `Sock` and `ConnLease` drop guards are debug-only | low | Tenet |
| 3.9 | Lengths travel apart from their buffers at a few parser boundaries | low | Tenet |
| 3.10 | C's setopt ranges are re-implemented by each caller | low | Tenet |
| 3.11 | `Easy`'s cookie methods return the whole transfer `ErrorKind` | low | Tenet |
| 3.12 | The report hands out bare connection and transfer numbers | low | Tenet |

---

## Focus 1: does the overall design need to change after milestones 1–3?

Mostly no. The central decisions held up under three milestones:

- one transfer-state enum with the lease inside it;
- generational ids;
- a `Route` compared field by field;
- the gate for re-entrant calls;
- the pull chain of layers.

The verifiers checked and dismissed suspected drift in `Run`'s generic fields (`method`,
`allow_port`, `first`), which mirror C's `UrlState`, and in `judge_pause` and `TlsNative`
lending. What has to change before stage 5 is one piece of the setup's ownership. The other
findings here are smaller.

### 1.1 Connection setup is split between the transfer and the connection, so the ALPN race cannot be built

- **Severity:** high (two findings merged: one high, one medium after verification).
- **Type:** Design change.
- **Files:**
  - `crates/curl-core/src/multi/state.rs:162-190`, `:2048-2100`, `:2310-2326`
  - `crates/curl-core/src/multi/state/tunnel.rs:58-63`, `socks.rs:39-44`, `https.rs:30-34`,
    `https.rs:184-209`, `tls.rs:53-163`
  - `crates/curl-core/src/conn/connect.rs:41-95`, `:421-426`, `:707`, `:941-985`
  - `ENGINE.md:38-41`, `:1222-1237`, `:1342-1348`
  - C: `lib/cf-https-connect.c:168-178`, `:222-235`, `:360-387`, `:442-474`, `:518-546`;
    `lib/cf-ip-happy.c:73-89`, `:160-177`; `lib/cf-setup.c:193-259`; `lib/urldata.h:370`
- **Evidence:**
  - The connection's machine is `Stage { Resolving, Racing, Dialed }`.
  - A race attempt is a bare socket, `struct Attempt { remote: Remote, socket: Sock }`, and the
    race ends when TCP connects. `won` then moves to one `Stage::Dialed`, and
    `Stage::Dialed(_) => unreachable!("a dialed setup is driven by its handshakes")`.
  - The handshake under way (`Socks`, `Connect`, `Haproxy`, `Tls`), the HTTPS-connect head and
    the tunnel's Negotiate live in the transfer's `Connecting` instead:
    `handshake: Option<Box<Handshake>>`, `https: Option<HttpsConnect>`,
    `negotiate: Option<Box<Negotiate>>`.
  - Each driver unwraps that one slot with `unreachable!`. `HttpsConnect` pairs `record` with
    `started: bool`, and its `start` asserts `Record::Unasked => unreachable!`.
  - Negotiate is handed to the connection at the end, with
    `*c.lease.get().negotiate_mut() = c.negotiate.take();`.
  - In C, each HTTPS-connect baller is a whole setup chain with its own TLS
    (`Curl_cf_setup_insert_after(cf, data, b->transport, CURL_CF_SSL_ENABLE)`). Each
    happy-eyeballs attempt owns a filter sub-chain (TCP, QUIC, HTTP/3 proxy, UDP or Unix).
  - With nghttp2, h2 and h1 race as two TLS handshakes over two TCP connections. Through an
    HTTP proxy, h3 makes two tunnels for one transfer.
  - ENGINE.md §4.2 promises `ConnectMachine::Alpn(AlpnRace)` owning "two whole sub-machines",
    yet ENGINE.md:1346-1348 schedules taking the drivers out of the transfer only "with FTP"
    (stage 6). The two dates contradict each other: as built, a sub-machine of the race cannot
    make its own TLS handshake.
- **Recommendation:**
  1. Move the split before stage 5 (milestone 4's step 52 needs the ALPN race).
  2. Make the handshakes stages that the connection's machine owns, beside `Dialed`'s stream
     (`Dialed { made, step: Option<HandshakeStep> }`), and drop `Handshake::Tls`'s marker:
     the layer on the stream is the state.
  3. Make `HttpsConnect` the machine's head, with its record and `started` folded into one
     enum.
  4. Keep the proxy's Negotiate once per connection, at the top, as C's
     `proxy_negotiate_state`.
  5. Have the drivers reach the transfer's part through call-outs on `ConnCx`: the CONNECT
     answer's header lines, auth, the header lists, the TLS options and context callback, the
     redial.
  6. Let an `Attempt` be a boxed sub-pipeline (transport plus handshakes up to "connected"),
     so `AlpnRace` owns two of them, and FTP's data connection can reuse the pipeline later.
  7. `TransferState::Connecting` then keeps `{ lease, proto, route }`.
  8. Update ENGINE.md §1.6, §3.1 and §4.2 (including the stale `Tunnel(Dialed)`, which is
     `Dialed(Dialed)` in the code), and record the reordering in MILESTONES.md.

### 1.2 Shim adapters hold a raw `NonNull<ShimEasy>`, kept valid by hand-written steps

- **Severity:** medium.
- **Type:** Design change.
- **Files:**
  - `crates/curl-sys-abi/src/callbacks.rs:131-158`, `:224-237`, `:285-308`, `:370-386`
  - `crates/curl-sys-abi/src/easy.rs:521-578`, `sockets.rs:62-90`, `tls.rs:42-57`
  - `crates/curl-core/src/options/mod.rs:2030-2032`, `crates/curl-core/src/tls.rs:599-623`
  - `sabotage/entries/sockets.txt:112-135`
- **Evidence:**
  - `pub(crate) struct Adapter(pub(crate) NonNull<ShimEasy>)` is dereferenced on every
    callback. Its SAFETY comment rests on "a copy of the options is given its own adapters".
  - `Easy::try_clone` copies every handler still pointing at the original. A copy gets its own
    adapters only through three separate steps in `curl_easy_duphandle`: `install` through
    `ShimEasy::boxed`, `copy_sockets` and `copy_tls`.
  - Each step has a test and a sabotage entry, but nothing structural makes a new
    handler-bearing option re-point. If one is missed, the copy calls the application with the
    original's `CURL *`: a use-after-free once the original is cleaned up.
  - Milestone 4 adds such options: the HSTS read and write functions, and `resolver_start`.
- **Recommendation:**
  1. One shim function re-derives every adapter from the shim's C-side settings: callbacks,
     progress, upload, the socket opener and configurer, and the TLS context.
     `ShimEasy::boxed`, `curl_easy_reset` and `duphandle` all call it, and nothing else
     re-points.
  2. Optionally, move the TLS `context` handler out of `TlsOptions`, so `TlsIdentity` cannot
     hold one.
  3. Record the rule in ENGINE.md 7.1 and 7.2.
  4. For each callback option milestone 4 adds, add one dup-free-run test with a sabotage
     entry.
  5. Longer term: reach the handle through the transfer (a per-transfer host value) instead of
     a stored pointer.

### 1.3 `&'static Libraries` and `&'static KeyLog` force process-wide statics on every embedder

- **Severity:** medium.
- **Type:** Design change.
- **Files:**
  - `crates/curl-core/src/libraries.rs:15-28`, `easy.rs:69`, `easy.rs:216-218`
  - `crates/curl-openssl/src/ssl.rs:41-53`, `crates/curl-core/src/tls/keylog.rs:20-22`
  - `crates/curl-tool/src/operate.rs:3478-3483`, `main.rs:99`
  - `DESIGN.md:316-319`, `ENGINE.md:134-140`, `:2109-2112`
- **Evidence:**
  - `Libraries` holds `Option<&'static dyn TlsBackend>`, and the same for Ed25519 and GSS.
    `Easy` takes `&'static Libraries`, and `OpenSsl` takes `keylog: Option<&'static KeyLog>`.
  - `KeyLog` is a `Mutex<Option<Open>>`, opened and closed at run time. An owner of a key log
    must therefore make a process-wide mutable static, or leak one.
  - The tool does make one: `pub(crate) static KEYLOG` and `static OPENSSL`, opened from
    `main`.
  - This contradicts DESIGN.md:317-319, which says the tracker and the captured command line
    are "the only globals outside the shim's root", and ENGINE.md:2111, which says the tool
    "owns one `KeyLog` in its root".
  - Tests leak to meet the bound: `Box::leak(Box::new(Libraries { .. }))`, at about a dozen
    sites.
  - `Components` already has the needed shape: `enum Backing { Shared(TryArc<..>),
    Static(&'static ..) }`.
- **Recommendation:**
  1. Give `Libraries` and `OpenSsl`'s key log an owned, shared form beside the static one, as
     `Components` does.
  2. Have the tool own its key log and libraries in a value `main` holds.
  3. Keep the shim's statics, which the C ABI demands.
  4. Update ENGINE.md:134-140 and :2109-2112.
  5. Do it before milestone 4 adds stateful backends (HSTS and alt-svc caches, the threaded
     resolver), so those do not start out as statics.

### 1.4 The process set is read from the trace's `MState`, not from the variant

- **Severity:** low.
- **Type:** C behaviour (a trace line).
- **Files:**
  - `crates/curl-core/src/multi/mod.rs:500`, `:560-564`, `:671-674`, `:703-713`, `:1152-1165`
  - `crates/curl-core/src/multi/state.rs:1292-1297`, `:3501-3552`
  - `ENGINE.md:27-29`, `:373-376`, `:383-384`
  - C: `lib/multi.c:867`, `:1144-1150`, `:1203-1210`, `:1259-1268`, `:1549-1559`,
    `:3850-3861`
- **Evidence:**
  - `in_process` tests `slot.mstate != MState::Pending && !state.is_completed()`, while
    `census_of` counts pending from the variant. Invariant 3 says these are "functions of the
    variant".
  - `wake_pending` turns `Pending` into `Setup` and leaves `slot.mstate` at `Pending` until the
    woken transfer is stepped, so `trace_pollsets` skips it.
  - In C, `move_pending_to_connect` puts the transfer in `process` and in CONNECT at once.
    `multi_wait` and `curl_multi_fdset` then trace its empty pollset:
    `[CONNECT] pollset[], timeouts=N, paused 0/0 (r/w)`.
  - With `MAX_HOST_CONNECTIONS=1`: remove A while B waits, then `curl_multi_wait`. C traces
    B's line; the rewrite traces nothing. Counts, sockets and timeouts agree.
  - `check.rs` never compares `mstate` with the variant.
- **Recommendation:**
  1. Derive `in_process` from the variant.
  2. Have `wake_pending` enter CONNECT and trace `-> [CONNECT]` where C does. This replaces
     the "traced entering CONNECT at its next step" exception at ENGINE.md:383-384.
  3. Add the `mstate`/variant agreement to `check.rs`.
  4. Pin it with a multi test of the case above, armed by restoring the old test in
     `in_process`.

### 1.5 ENGINE.md §1.3, §2.7 and §3.1 describe fields and invariants the code does not have

- **Severity:** low.
- **Type:** Tenet ("keep ENGINE.md true"). Documentation only.
- **Files:** `ENGINE.md:27-29`, `:556-604`, `:614-617`, `:670-689`;
  `crates/curl-core/src/multi/mod.rs:161-284`; `crates/curl-core/src/multi/state.rs:63-85`,
  `:162-179`, `:222`.
- **Evidence:**
  - `Run` has no `warn` field, though ENGINE.md lists one.
  - `Slot` has `rate` and `mstate`, which ENGINE.md omits.
  - `Multi` has `tls`, `shutdowns` and `ipv6_works`, which ENGINE.md omits.
  - ENGINE.md:604 still calls the shutdown set and the rate-limit state "planned", though both
    are built.
  - `Connecting` has `https` and `negotiate`, which §3.1 omits.
  - `Origin` is `TryArc<Peer>`, not `TryRc<Peer>`.
  - `pause_transfer` also takes `Slot.run` out (ENGINE.md:614-617 names only the step).
- **Recommendation:** bring the listings in line with the code, and reword invariant 3 to match
  1.4's fix.

---

## Focus 2: should the design change now, for the protocols and parsers to come?

Yes, for stage 5. Milestone 4's steps 51 (`Attached`) and 52 (HTTP/2) build on four decisions
ENGINE.md leaves open or states two ways:

- who owns a multiplexed connection;
- how stream data reaches sibling transfers;
- where the session sits relative to the connection-wide operations;
- how an HTTP/2 response head reaches the HTTP head parser.

QUIC has no design at all.

The verifiers refuted the broader claims about stage 6:

- that `Route` equality cannot express STARTTLS;
- that per-connection protocol state has nowhere to go;
- that the PROTOPT flags are worked out by hand.

Each of those restated a gap MILESTONES.md already plans, without showing the plan is wrong.

### 2.1 Who owns a multiplexed connection, and how HTTP/2 delivers a stream's data, is undecided and stated two ways

- **Severity:** medium (two findings merged).
- **Type:** Design change.
- **Files:**
  - `crates/curl-core/src/conn/pool.rs:31-37`, `:213-219`, `:439-471`, `:744`
  - `crates/curl-core/src/conn/mod.rs:988-995`, `crates/curl-core/src/proto/http.rs:1526`,
    `:1744-1763`
  - `ENGINE.md:18-23`, `:58-60`, `:79-80`, `:1105-1110`, `:1200-1202`, `:1485-1507`, `:1629`,
    `:1680-1682`, `:2295-2296`
  - `DESIGN.md:108-109`, `MILESTONES.md:749-753`
  - C: `lib/http2.c:289-309`, `:953-960`, `:1309-1342`, `:2630-2676`; `lib/transfer.c:885-893`;
    `lib/cfilters.c:930-933`
- **Evidence:**
  - `ConnLease { id, conn: Option<ConnSlot>, home }` owns its connection inline. The pool keeps
    only `Place::Leased { route }`, and `release` asserts one lease. The protocol does all its
    I/O through `lease.get()`.
  - The planned `Attached { users }` is "a pool place", but nothing says where a shared `Conn`
    and its session live while one attached transfer's step has them.
  - Decision 9 allows only two owned values out across a call-out, the `Run` and the receive
    buffer.
  - The data path is stated two ways:
    - Decision 14, §4.4 and DESIGN.md:108 buffer stream data per stream "so a step never
      builds a callback context for another transfer".
    - MILESTONES.md:749 (now milestone 4's step 52) plans the opposite, "a sibling stream's
      data delivered at once, as C does".
  - C delivers at once: `on_data_chunk_recv` finds the sibling by stream id and calls
    `Curl_xfer_write_resp` on it.
  - A pause in C reaches the shared session immediately and sends WINDOW_UPDATE
    (`http2_data_pause`, `h2_progress_egress`).
  - ENGINE.md §4.4 also says the `Mux` trait "is defined in the first milestone". No `Mux`
    exists in `crates/`.
- **Recommendation:** decide before step 51, in ENGINE.md §1.6, §1.9, §1.14, §4.4 and §4.6.
  1. A shareable connection lives in its pool place. An attached lease is a key (`ConnId`
     plus stream); the step moves the `Conn` out for its duration, and decision 9 counts it as
     a third owned value.
  2. Keep C's delivery order, as "do what the C does" requires. `Mux` input hands back
     `(TransferId, bytes)`, and the engine delivers each sibling's bytes by moving that
     sibling's `Run` out in turn, as the unpause flush at ENGINE.md:1105-1110 already does.
     A paused sibling's bytes wait in its pipeline's paused output, as C's client writer holds
     them.
  3. Define what a pause or unpause targeting a sibling does while the connection is out with
     another transfer, keeping C's immediate WINDOW_UPDATE where the wire order shows it.
  4. Delete the per-stream-buffering text and the "defined in the first milestone" claim, and
     make DESIGN.md:108 agree.

### 2.2 The I/O seams assume a byte stream; QUIC, HTTP/3 and the HTTP/3 proxy have no place

- **Severity:** medium.
- **Type:** Design change. This is a planning gap for milestone 5; it is raised now because
  step 52's `Mux` should not be shaped around HTTP/2 alone.
- **Files:**
  - `ENGINE.md:866-867`, `:1178`, `:1487-1507`
  - `crates/curl-core/src/conn/layer.rs:243-330`, `conn/io.rs:129-166`, `:281-283`,
    `conn/mod.rs:763-767`
  - `crates/curl-core/src/tls.rs:46-59`, `:141-181`, `:239-244`
  - `crates/curl-os/src/net.rs:160`, `:184`
  - C: `lib/vquic/cf-ngtcp2.c:1053-1068`, `cf-ngtcp2-cmn.c:1019`, `:1574`, `vquic.c:400-500`,
    `:630-1008`, `vquic-tls.c:75-79`, `:150-164`; `lib/cf-setup.c:235-259`;
    `lib/http_proxy.c:600-634`
- **Evidence:**
  - `Below` ends at a stream `Socket` with only `recv`/`send`.
  - `Net::open` opens "a nonblocking stream socket ... TCP or Unix" (`SOCK_STREAM`).
  - `Transport` is `Local | Tcp(Stream)`, with "later Udp".
  - The planned `Mux::input(&[u8])`/`output(SendBuf)` takes connection bytes.
  - `TlsBackend` makes only record-stream sessions, and `Alpn` has no h3.
  - C's HTTP/3 filter peeks the UDP socket and does `sendmsg`/`recvmmsg` with GSO, GRO and ECN.
    Over a CONNECT-UDP tunnel it sends one whole datagram per call.
  - C arms `EXPIRE_QUIC` on the transfer.
  - QUIC's TLS shares context setup and peer checks with TCP's (`Curl_ossl_ctx_init`,
    `Curl_ossl_check_peer_cert`).
- **Recommendation:** write the QUIC shape into ENGINE.md §4.1, §4.3, §4.4 and §4.9 before
  step 52 defines `Mux`.
  1. A `Transport::Quic` holding the session and its UDP socket or tunnel.
  2. A one-datagram-per-call contract over a tunnel.
  3. A socket kind on `Net::open`, and packet-level calls on a datagram socket.
  4. `Mux` as a driver over its own transport, reporting its next expiry for the existing
     `TimerKind::Quic`.
  5. A QUIC entry point on `TlsBackend` that shares CA loading, verification, pinning, the
     session cache, the key log and the `SSL_CTX` callback with `session()`.
  6. h3 in `Alpn`.
  7. A note on the capsule layer over h1, h2 or h3 proxy tunnels.

### 2.3 A session beside the layer stack misses the connection-wide operations

- **Severity:** medium.
- **Type:** Design change.
- **Files:**
  - `ENGINE.md:1199-1203`, `:1484-1503`
  - `crates/curl-core/src/conn/pool.rs:1038-1078`, `conn/shutdown.rs:86-119`,
    `conn/layer.rs:179-240`
  - C: `lib/http2.c:557-590`, `:2580-2620`, `:2708-2735`, `:2785-2800`;
    `lib/conncache.c:892-928`, `:1041-1086`
- **Evidence:**
  - Shutdown, its pollset and the health check reach only the layer stack
    (`stream.shutdown`, `stream.shutdown_pollset`, `stream.is_alive`).
  - `health` rejects any idle connection with input waiting ("it is HTTP/1's").
  - `Layer` has no keep-alive.
  - §4.4's `Mux` has no shutdown, liveness, keep-alive, data-pending or pollset method.
  - In C the h2 session is a filter, so:
    - shutdown sends GOAWAY;
    - upkeep sends PING;
    - liveness reads and processes pending frames and clears `input_pending`;
    - the pool exempts multiplexed connections from the input-pending rule and polls them at
      most once a second (`lastchecked_ms`).
  - Built as §4.4 has it, an idle h2 connection holding an unread SETTINGS or PING frame
    would be closed as unhealthy instead of reused.
- **Recommendation:**
  1. Decide in §4.3 and §4.4 whether the session is the top `Layer`, as in C, or a sibling of
     the stack that `Stream`'s connection-wide calls ask first.
  2. Either way: liveness consumes pending frames, the input-pending rule applies only to
     connections that do not multiplex, and C's once-a-second check comes in.
  3. Add `keep_alive` to `curl_easy_upkeep`'s path.

### 2.4 `HeadParser` fuses HTTP/1 line assembly with the response's semantics and has no whole-line entry

- **Severity:** medium.
- **Type:** Design change. Needed at step 52.
- **Files:**
  - `crates/curl-core/src/proto/http1/response.rs:312-382`, `:408-417`, `:432-523`,
    `:586-635`
  - `crates/curl-core/src/proto/http1/tunnel.rs:91-100`, `:316-386`
  - `crates/curl-core/src/proto/http.rs:1857-2125`
  - `ENGINE.md:2595-2672`, `MILESTONES.md:748`
  - C: `lib/http2.c:1553-1600`; `lib/http.c:3184-3231`, `:4301-4340`, `:4412-4425`,
    `:4662-4677`; `lib/rtsp.c:870`
- **Evidence:**
  - The status line, `Meta`, framing and size counting are reachable only through `feed`, the
    HTTP/1 assembler. `line_out` is private.
  - A header line that ends the input is held to see whether the next byte folds it.
  - The `HTTP/` prefix is hard-coded in `looks` and `read_status`, yet `read_status` already
    accepts `HTTP/2` and `HTTP/3` status lines.
  - C rebuilds each HTTP/2 field as `name: value\r\n` and the status as `HTTP/2 <code> \r\n`,
    and passes each through `http_rw_hd` with no folding, no hold, no line limit and no HTTP/0.9
    decision.
  - RTSP and `CURLOPT_HTTP200ALIASES` widen the prefix.
  - The per-line work in `head_input` (cookies, filetime, codings, Negotiate, the header
    store) is reachable only from HTTP/1's `HeadEvent::Line`.
- **Recommendation:**
  1. Split a `ResponseHead::line(&[u8])` out of `line_out`, as C's `http_rw_hd`, and make
     `feed` the HTTP/1 assembler in front of it.
  2. Put a status-line dialect in `Exchange` (`Http { aliases }`, `Rtsp`).
  3. Move `head_input`'s per-line handling into one function every HTTP version's stream
     calls.
  4. Add `HeaderOrigin::Pseudo` with HTTP/2.
  5. Record the plan in ENGINE.md §6.2 beside the field sink.

### 2.5 "Peer-chosen sizes are bounded first" is re-derived by hand at each buffer

- **Severity:** low.
- **Type:** Design change (a new type in `curl-alloc`; no behaviour changes).
- **Files:**
  - `crates/curl-core/src/proto/http1/response.rs:19`, `:384-389`
  - `crates/curl-core/src/proto/http1/tunnel.rs:19`, `:367-373`
  - `crates/curl-core/src/proto/http1/chunked.rs:18`, `:284`, `:311`
  - `crates/curl-core/src/proto/http1/digest.rs:14-16`, `:341-350`
  - `crates/curl-core/src/netrc.rs:14-18`, `:128`, `:144`, `:249`
  - `crates/curl-core/src/conn/buf.rs:34-56`
  - `DESIGN.md:285-287`
  - C: `lib/curlx/dynbuf.c:67-85`, `dynbuf.h:65-82`, `lib/pingpong.c:130-131`, `:272`
- **Evidence:**
  - C has one mechanism: `dyn_nappend` refuses when `len + idx + 1 > toobig`.
  - The Rust re-encodes that `-1` four different ways (`MAX_LINE = 100*1024-1` with `>`,
    `MAX_LINE = 16384` with `>= MAX_LINE - 1`, `4096-1` with `+2 >` and `+1 >`, and a private
    `Bounded` in `digest.rs`), each guarding a plain `Vec` a new append site can skip.
  - All are correct today. Stage 6 adds six more such limits.
- **Recommendation:**
  1. Add a capped byte buffer to `curl-alloc`, built from C's `toobig` verbatim. The `+1` lives
     once inside it, with a boundary test, and it never hands out `&mut Vec`.
  2. Name its limits after C's constants, and migrate the sites above.
  3. Before stage 6, decide whether pingpong parses over `RecvBuf` (which then needs a cap) or
     copies into its own capped buffer as C does.

### 2.6 Range parsing is private to `file.rs`, in C's signed offsets with -1 sentinels

- **Severity:** low.
- **Type:** Design change (before stage 6).
- **Files:**
  - `crates/curl-core/src/proto/file.rs:185-218`, `:451-460`, `:485-555`
  - `crates/curl-core/src/options/mod.rs:43`, `:420-428`, `:1036-1043`
  - `ENGINE.md:2547-2550`
  - C: `lib/curl_range.c:35-89`, `lib/file.c:565-610`, `lib/ftp.c:1787-1842`, `:2321`
- **Evidence:**
  - The only parse is `file.rs`'s private `span`, which returns
    `Span { resume: i64, max: Option<i64>, from: i64, to: i64 }`.
  - `Resume::AtEnd` is fed in as `b"-1-"`, and the caller does `expected = -1` and
    `resume += st_size`.
  - C's `Curl_range` serves file and FTP alike.
- **Recommendation:**
  1. Move the parse to a shared module with a typed result: `From(u64)`, `Last(NonZeroU64)`,
     `Between { from, to }`.
  2. Each protocol keeps its own C resolution: file's `st_size` arithmetic and lseek quirk;
     FTP's "Offset beyond file size" and `REST -N`.
  3. Update ENGINE.md 5.6.

### 2.7 The tool hand-copies C header constants that the shim generates

- **Severity:** low.
- **Type:** Tenet ("generated code is generated"). The generator changes; the design does not.
- **Files:** `crates/curl-tool/src/easysrc.rs:71-224`, `:1042-1071`;
  `crates/curl-tool/src/operate.rs:2745-2750`; `crates/curl-sys-abi/src/ffi.rs:1`, `:1212-1230`;
  `gen/cli.py`; C: `src/tool_setopt.c:40-152`.
- **Evidence:**
  - The `--libcurl` tables (`PROXY_TYPES`, `HTTP_VERSIONS`, `SSL_VERSIONS_MAX`, the `AUTH_*`
    bits) retype curl.h's names and numbers by hand. The shim generates the same numbers from
    `inventory/abi.json`.
  - The only check compares the copies with a third set of hand-typed literals.
  - All values agree today. Stage 6 adds `CURLUSESSL`, `CURLFTPSSL_CCC` and the SSH and FTP
    tables.
- **Recommendation:**
  1. Generate the `setopt_nv_*` tables and the constants from `abi.json` through `gen/cli.py`.
  2. Keep the tool's encoders hand-written.

---

## Focus 3: are the tenets kept, and is the code compatible with C?

Largely yes. The unsafe code is confined to the listed modules. Both profiles set
`panic = "abort"`, so nothing unwinds into C. The verifiers found no unsafe outside the list
and no panic reachable from peer bytes.

The C differences found are few and small. The verifiers confirmed each one against the C
source; the C build will be run on each before its fix lands.

### 3.1 A 101 never ends the response head

- **Severity:** medium.
- **Type:** C behaviour.
- **Files:** `crates/curl-core/src/proto/http1/response.rs:419-423`, `:448-452`, `:470-477`;
  `crates/curl-core/src/proto/http1/framing.rs:414-415`;
  `crates/curl-core/src/proto/http.rs:2079-2096`; C: `lib/http.c:3829`, `:3950-4036`,
  `:4184-4199`, `:4525`.
- **Evidence:**
  - `let interim = (100..200).contains(&status.code)` treats every 1xx as interim, and the
    version is compared by major number only.
  - C sends 101 to `http_on_101_upgrade`:
    - a request not sent as HTTP/1.1 fails with "server sent 101 response while not talking
      HTTP/1.1" (8);
    - otherwise, with no h2c or WebSocket upgrade asked for, "We silently accept this as the
      final response". The head ends, `http_on_response` skips size, fail and auth handling,
      and what follows is body until the server closes.
  - So `HTTP/1.1 101 Switching Protocols` followed by bytes, answering a request whose
    `Upgrade:` header the user added, is a success in C. In Rust it is
    `InvalidStatusLine` (8).
  - A 101 answering `-0` is 8 in C. Rust waits for another head.
- **Recommendation:**
  1. At the blank line, special-case 101: refuse it unless HTTP/1.1 was sent; otherwise end the
     head as final with `UntilClose` framing, skipping the final-response steps C's
     `goto out` skips.
  2. Add a test of each case, checked against the C build.
  3. h2c (step 52) and WebSocket (stage 6) later take over the bytes at that point.

### 3.2 The tool never prints C's CA-certificate help after a verification failure

- **Severity:** medium.
- **Type:** C behaviour.
- **Files:** `crates/curl-tool/src/operate.rs:3026-3042`, `crates/curl-tool/src/msgs.rs:65-73`,
  `crates/curl-tool/src/operate/parallel.rs:412`; C: `src/tool_operate.c:90-95`, `:623-630`.
- **Evidence:**
  - C's `post_check_result` follows `curl: (60) ...` with `CURL_CA_CERT_ERRORMSG` ("More
    details here: https://curl.se/docs/sslcerts.html ..."), under the same
    `!silent || showerror` gate.
  - `settle` has no branch on `PeerFailedVerification`, and no text from the message appears
    under `crates/`.
- **Recommendation:**
  1. After the error line, write the text byte for byte when the kind is
     `PeerFailedVerification`, through `msgs.error_line`.
  2. Test it against an untrusted certificate, without `-k`, with `-s` and with `-sS`.

### 3.3 Pool search ignores the transfer's last connection

- **Severity:** low.
- **Type:** C behaviour.
- **Files:** `crates/curl-core/src/conn/pool.rs:617-700`,
  `crates/curl-core/src/multi/state.rs:3608-3619`, `ENGINE.md:1635-1638`; C:
  `lib/conncache.c:308-320`, `:801-834`; `lib/multi.c:542`, `:942-946`.
- **Evidence:**
  - C records `last_conn_id`/`last_cpid` on attach and tests that connection first, "so that
    connection use gets 'sticky'". It is cleared on each `curl_multi_add_handle`.
  - `Pool::find` takes the first idle match in table order.
  - Case: A and B fetch `http://h/` at once, on connections #0 and #1. A finishes. B follows a
    302 to `http://h/b`. C reuses #1; Rust reuses #0. `CURLINFO_CONN_ID`, the reuse trace and
    later eviction order differ.
- **Recommendation:**
  1. Keep the transfer's last `ConnId`, cleared at add, and pass it in `pool::Wanted`.
  2. `find` tries it first, with the same verdicts, then skips it in the walk. A stale id
     fails its own lookup.
  3. Update ENGINE.md:1638, and test both the follow case and the re-add case.

### 3.4 Application header lines with an empty name are sent

- **Severity:** low.
- **Type:** C behaviour.
- **Files:** `crates/curl-core/src/proto/http1/request.rs:302`, `:314-345`, `:790-822`; C:
  `lib/http.c:1866-1885`, `:1927-1933`; `lib/curlx/strparse.c:61-68`;
  `lib/http_proxy.c:135`.
- **Evidence:**
  - C's `curlx_str_until` fails on a zero-length span, so `":foo"` and `";"` are skipped.
  - Rust's `classify` makes `";"` a blank header and `":foo"` a value, and sends `":"` and
    `":foo"`.
  - The CONNECT path already drops them (`!name.is_empty()`).
- **Recommendation:**
  1. `Asks::Nothing` when the untrimmed span before the first `;` or `:` is empty.
     `"  ;"` and `" :v"` still behave as C.
  2. Add a test from `-H ':foo' -H ';'`, checked against the C build.

### 3.5 The cookie hash reads bytes ≥ 0x80 unsigned; C sign-extends them on x86_64

- **Severity:** low.
- **Type:** C behaviour.
- **Files:** `crates/curl-core/src/cookie.rs:662-667`, `:1148-1153`;
  `crates/curl-core/src/easy.rs:382`; `crates/curl-core/src/cookie/tests.rs:57-73`; C:
  `lib/cookie.c:191-203`, `:1632-1634`; `lib/strcase.h:37-40`.
- **Evidence:**
  - C: `(size_t)Curl_raw_toupper(*domain++)`, where `Curl_raw_toupper` returns a `char`, which
    is signed on x86_64.
  - Rust: `u64::from(b.to_ascii_uppercase())`.
  - `bücher.de` lands in bucket 59 in C and 14 in Rust, so `CURLINFO_COOKIELIST`, which walks
    the buckets, lists such a jar in a different order.
  - Sending and the jar file are unaffected.
- **Recommendation:**
  1. Hash `(b.to_ascii_uppercase() as c_char) as u64`, which follows the platform's `char`.
  2. Correct the comment.
  3. Add a non-ASCII row to `hashes_as_c`, with its value taken from the C build, and a
     listing-order test.

### 3.6 `-f` with `--retry-max-time` exits 22 where C exits 0 when Retry-After is too long

- **Severity:** low.
- **Type:** Divergence. It needs the user's approval, and is not implemented.
- **Files:** `crates/curl-tool/src/operate.rs:868`, `:1384-1393`, `:1446-1458`;
  `crates/curl-tool/tests/http.rs:1016-1058`; C: `src/tool_operate.c:395-403`, `:455-456`,
  `:520-523`, `:774-780`.
- **Evidence:**
  - C's `retry_sleep` warns "The Retry-After: time would make this command line exceed the
    maximum allowed time for retries.", clears `*retryp` and returns 0.
  - `retrycheck` then returns `CURLE_OK`, so after `curl: (22) ...` C exits 0 and
    `%{exitcode}` is 0.
  - Rust warns the same and keeps 22.
  - Command line: `curl -f --retry 3 --retry-max-time 10 URL` against a 503 with
    `Retry-After: 60`.
- **Recommendation:**
  1. Either match C (exit 0), or keep 22 as a failure C reports as success. Keeping 22 needs a
     DIVERGENCE.md entry and a pinning test.
  2. Confirm C's exit on the C build first.
  3. The verifier recommends keeping 22, as C turns a failed transfer into success. The choice
     is the user's.

### 3.7 Digest challenge parsing takes running out of memory for the end of the challenge

- **Severity:** low.
- **Type:** Tenet ("never paper over a real error").
- **Files:** `crates/curl-core/src/proto/http1/digest.rs:85-128`, `:148-153`;
  `crates/curl-core/src/proto/http1/auth.rs:714-720`; C: `lib/vauth/digest.c:60-130`,
  `:542-560`.
- **Evidence:**
  - `content.try_push(b).ok()?` turns a refused allocation into `None`, which `read` treats as
    the end of the challenge.
  - Depending on where the refusal falls, Digest is refused (the transfer goes on), or a
    challenge missing its realm, opaque, qop or algorithm is answered.
  - C parses into a fixed stack buffer and fails `strdup`s with `CURLE_OUT_OF_MEMORY`.
- **Recommendation:**
  1. Parse into a fixed buffer, and copy fallibly only what is kept.
  2. Add a fail-each-allocation test asserting `DigestError::OutOfMemory`, with a sabotage
     entry.

### 3.8 The drop guards on `Sock` and `ConnLease` are debug-only

- **Severity:** low.
- **Type:** Tenet ("when the language can't enforce it, crash loudly").
- **Files:** `crates/curl-core/src/conn/io.rs:168-170`, `:225-233`, `:1574-1583`;
  `crates/curl-core/src/conn/pool.rs:308-316`, `:786-794`; `crates/curl-os/src/net.rs:235-244`;
  `crates/curl-sys-abi/src/sockets.rs:247-249`; `Cargo.toml:24-28`; C:
  `lib/cf-socket.c:535-557`.
- **Evidence:**
  - In a release build, a `Sock` dropped unclosed would close the application's descriptor
    through `OwnedFd`, skipping `CURLOPT_CLOSESOCKETFUNCTION` and the multi's bookkeeping.
  - A `ConnLease` dropped unreleased would leak its pool place silently.
  - No current path does either.
- **Recommendation:**
  1. Use `assert!` (keeping the `panicking()` escape). Both profiles abort on panic.
  2. Ungate the `should_panic` tests.

### 3.9 Lengths travel apart from their buffers at a few parser boundaries

- **Severity:** low.
- **Type:** Tenet ("two values that must agree are one value").
- **Files:** `crates/curl-core/src/proto/http1/chunked.rs:394-430`;
  `crates/curl-core/src/upload/chain.rs:185-227`;
  `crates/curl-core/src/conn/socks.rs:518-568`, `:624-636`, `:787-809`;
  `crates/curl-core/src/conn/socks/gss.rs:219-221`.
- **Evidence:**
  - `ChunkEncoder::got(n)` trusts a count for the slice `wants` handed out.
  - The SOCKS reply parsers index fixed offsets that are safe only because a separate
    `wants()` table agrees with each parser's highest index.
  - Both are correct today.
- **Recommendation:**
  1. Have `got` check against what `wants` handed out (or return a slot that takes the count).
  2. Have each fixed-size reply parser take `&[u8; N]` from `first_chunk`.

### 3.10 C's setopt ranges are re-implemented by each caller

- **Severity:** low.
- **Type:** Tenet.
- **Files:** `crates/curl-core/src/options/mod.rs:1316-1384`, `:1766-1775`;
  `crates/curl-sys-abi/src/setopt/mod.rs:684-715`; `crates/curl-tool/src/operate.rs:2736-2784`;
  C: `lib/setopt.c:1025`, `:1046`.
- **Evidence:**
  - The shim and the tool each clamp `MAXREDIRS` to 0x7fff and `EXPECT_100_TIMEOUT_MS` to
    0xffff.
  - The core types have unbounded public fields, though `BufferSize::clamped` shows the
    pattern.
  - They agree today.
- **Recommendation:**
  1. Add `MaxRedirects::clamped` and `ContinueWait::clamped`, used by both callers.
  2. Keep the tool's raw value for `--libcurl`.

### 3.11 `Easy`'s cookie methods return the whole transfer `ErrorKind`

- **Severity:** low.
- **Type:** Tenet ("the Rust API is the product").
- **Files:** `crates/curl-core/src/easy.rs:138`, `:256`, `:281-458`;
  `crates/curl-core/src/proto/http/cookies.rs:257-284`;
  `crates/curl-sys-abi/src/setopt/mod.rs:1577-1593`; `crates/curl-tool/src/operate.rs:1296`.
- **Evidence:**
  - `add_cookie`, `clear_cookies`, `clear_session_cookies` and `cookie_list` fail only for
    memory. `reload_cookies` fails for memory or a read.
  - `save_cookies` flattens its own precise `SaveError`.
  - Neighbours such as `try_clone` and `enable_cookies` already return `OutOfMemory`.
- **Recommendation:**
  1. Return narrow errors from these methods.
  2. Map them to `CURLE_*` only in the shim.

### 3.12 The transfer report hands out bare connection and transfer numbers

- **Severity:** low.
- **Type:** Tenet ("every integer that means something has a newtype").
- **Files:** `crates/curl-core/src/report.rs:276-323`; `crates/curl-core/src/conn/mod.rs:80-88`;
  `crates/curl-core/src/conn/pool.rs:495`; `crates/curl-core/src/multi/mod.rs:417`; callers in
  `curl-tool` and `getinfo.rs`.
- **Evidence:**
  - `conn_number` strips the core's `ConnNumber` to `u64`.
  - `transfer_number` has no newtype at all.
  - The `CURLINFO_CONN_ID` doc paragraph sits above `verify_result` instead of `conn_number`.
- **Recommendation:**
  1. Return `ConnNumber` and a new `TransferNumber`, converting at the shim and the tool.
  2. Move the doc paragraph.
  3. The verify code stays the backend's own, as C's is.

---

## Refuted

These were raised and then refuted by their verifiers. They are recorded here so they are not
raised again.

- **HTTP's cross-request memory (`Run.http`) in the generic engine.** ENGINE.md §2.7 records
  the layout deliberately, and the generic fields mirror C's `UrlState`.
- **`Route` equality cannot express STARTTLS or per-protocol reuse.** It restates a planned
  gap. HTTP has no `PROTOPT_SSL_REUSE`, so nothing built differs from C.
- **Setup welded to `Connecting`, blocking FTP's data connection.** ENGINE.md:1345-1348
  already records the coupling and its plan. The finding that does stand is 1.1, about the
  plan's timing.
- **Per-connection protocol state as HTTP fields on `Conn`, with nowhere for QUIT or LOGOUT
  to run.** MILESTONES.md already plans connection-scoped protocol state with the first
  stage-6 protocol.
- **PROTOPT flags worked out by hand; ALPN offered for any TLS origin.** Only https carries
  `PROTOPT_ALPN` in C, so nothing built differs. The scheme facts are already planned to be
  generated.
- **`CURLAUTH_ONLY` as a member of the method set.** The state it allows does no harm, and
  the handshake rejects it as C does.
