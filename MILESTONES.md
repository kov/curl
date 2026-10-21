# Milestones

The order the engine is built in, as commit-sized steps. `ENGINE.md` holds the design they
implement. Each step records its status: **done** (with the commit), **in progress**, or
**to do**. When a step lands, is split, or is reordered, this file changes in the same commit,
along with the tests it flipped as `runtests.pl` reported them.

## Milestone 1: `file://`, then HTTP/1.1 GET

Status: steps 1 to 12 are **done**; every other step is **to do**.

Constraints the order follows, checked in the tree:
- `runtests.pl` gates every test on the protocols in the `Protocols:` line of `curl -V`
  (runtests.pl:1080, "curl lacks $1 support"). Nothing flips until the tool reports the protocol,
  and reporting it turns that protocol's skips into failures until the rings land.
- `runner.pm:824-880` always adds `--output`, `--include` (unless `no-include`) and
  `--trace-ascii FILE --trace-time`, so the debug handler, the trace format and `-i` output are
  needed for the first flip of each protocol.
- `RUNTESTS_ARGS` is `-a -n -j8` (`inventory/measure/suite.py:23`), with no `-e`; event mode and
  `curl_easy_perform_ev` are not on the first path.
- Test 1's allocation limit covers the whole tool process.
- SCOPE stage 3 orders `file://` before HTTP/1.1.

Each step: the formatter, `cargo clippy -- -D warnings`, the touched tests, and every new test
armed by breaking what it checks (for example, removing the generation bump must fail the
stale-id test). Every flip is checked on both legs through `runtests.pl`'s skipped line. The
suite-test lists below are taken from the inventory and the test files; each step regenerates
its list from `inventory/tests.json` and drops any test whose servers or features it does not
yet meet.

**Prerequisites (Rust tests only)**

1. **alloc: add fallible reference-counted pointers.** **Done.** `TryRc<T>` and `TryArc<T>`
   for sized `T`, without weak references; shared bytes are `TryRc<Vec<u8>>`. Tests: both fail
   past the tracker's limit without aborting; the last handle drops the value once; handles
   cross threads.
2. **core: depend on curl-alloc; add Instant, Clock and the arena.** **Done.** `time.rs`
   (`Instant`, `Clock`, `SystemClock`, `ManualClock` behind `test-util`) and `id/` (`Arena`,
   `Key`, `ArenaPolicy`, `Vacancy`). Tests: a stale key fails after its row is reused; a seeded
   add/remove churn gets the ids C's real multi gives it, recorded by `gen/arena.py` through a
   harness linked against `libcurlu`. Growth failing under the allocation limit is exercised by
   step 5's add/perform/remove torture scenario.
3. **url: add the Url type and urlapi.c's parser.** **Done.** `url/`: a whole URL parsed with
   every `curl_url_set` flag, and every part got with every `curl_url_get` flag but the IDN
   conversions; the known schemes generated from `lib/protocol.c` by `gen/schemes.py`. Tests,
   generated from the C tests by `gen/url_c_tests.py`: lib1560's `get_parts_list` and
   `get_url_list` as the reference build compiles them (173 and 226 rows, with the 4 and 1 that
   ask for IDN conversions left out), and unit1395's pairs
   (ported as `unit1395_dot_segments`); plus the branches those tables do not reach, with C's
   answers. Not yet: setting single parts, relative URLs and appending to the query (lib1560's
   other tables), IDN. Test 1560 itself runs once the shim exports `curl_url_*`.
4. **core: add Deadlines, TimerQueue and TimerAnnounce; check the ports.** **Done.**
   `multi/timers.rs` and `TimeLimit`. Ports: unit 1309 (removal, the due order test1309
   expects, the rounded-up wait), unit 1303 (its 34 cases of time left, connect versus total),
   both with their data generated from the C tests by `gen/timer_c_tests.py`, and unit 3230
   (the timer callback's dedupe, a sequence of calls rather than a table). Tests: the two anchors told apart, timers consumed by an expiry pass, an
   unchanged wake-up keeping its place, a stale key caught. `inventory/measure/ported.py` lists
   each unit-test program as ported or missing from the Rust tests named after it, and fails on
   a port of a program that does not exist. A new leg (`start_leg`, as at a follow) keeps `started_op` and resets
   `started_single`, pinned by the two-anchor test.
5. **The multi, in five commits.**
   - **5a. conn: add a networkless connection pool.** **Done.** `conn/`: `Pool`, `ConnLease`,
     `ConnNumber`, `Route::LOCAL`. C attaches a connection to a `file:` transfer too, numbered
     in the pool ("Connection #N") and closed at done, since the scheme forbids reuse. Tests:
     numbers count from 0 and are never reused; a released local connection is closed, or
     terminated after a premature end; a dropped lease is caught in debug builds.
   - **5b. multi: add Easy and the transfer state machine with a null protocol.** **Done.**
     `Easy` and `Options` (the URL and the two limits), `Multi`, `Host`/`NoHost`, `Slot`, `Run`,
     the dirty `RowSet`, `Counts`, `TransferState` with the variants a networkless transfer
     reaches (`Init`, `Exchanging`, `Done`, `Completed`), the test-only `null:` (completes at
     once) and `stall:` (never does) protocols, `add`/`remove`/`perform`/
     `socket_action(Timeout)`/`info_read`/`counts`/`timeout`, the transfer.c timeout check, and
     a `Drop` that removes every transfer; step 4's timers wired in. The setup step parses the
     URL with `GUESS_SCHEME | NON_SUPPORT_SCHEME` and fails a scheme this build lacks with
     UnsupportedProtocol (23), and a missing URL with URL_MALFORMAT. Tests: info_read order;
     remove twice (3105); the timer callback inside `add` and `remove`; the dead multi (530:
     an abort inside `add` refuses the transfer, a dead multi fails its transfers, takes no
     more until empty, and tells the timer nothing); `running` counting transfers not yet run;
     a timed-out transfer failing with OPERATION_TIMEDOUT. `drive_to_completion` waits for
     step 6's `wait`. `TransferReport` comes with step 7.
   - **5c. multi: add the event contexts and notifications.** **Done.** `EventCx` for the
     timer callback and `NotifyCx` for `notify`, each with the calls api.c allows there that
     exist so far (`info_read`, `counts`, `set_notify`, `options`, `options_mut`, `duplicate`;
     `NotifyCx` adds `add`, `remove`, `timeout`); `Notification`, `NotifyKind`, and
     `NotifyQueue` dispatched at the end of `perform` and `socket_action`. Tests: the order C's
     notify callback sees (`EasyDone`, then `InfoRead` once per batch of unread messages), kinds
     off until enabled and dropped when turned off before delivery, a transfer removed inside a
     callback getting nothing, `add` and `remove` from a notification, `info_read` from the
     timer callback. `EngineRest`, `TransferCx` and the handler traits come with step 7, whose
     callbacks are the first to need them.
   - **5d. multi: check the invariants.** **Done.** The counts behind a `Tally` with one method
     per event; `multi/check.rs` recounting and cross-checking every table after each `add`,
     `remove`, `perform` and `socket_action` in the debug build; a proptest property test of
     random adds, removes, passes, clock moves, reads, notification switches, timer aborts and
     removals from inside notifications against a model of what the application sees. It
     found that a transfer refused inside `add` counts as added, as in C; C's leaked running
     count for it is recorded as a deliberate difference.
   - **5e. multi: survive allocation failure.** **Done.** `track::fail_after` and
     `track::live_tracked` in curl-alloc; `tests/torture.rs`, which runs 20 completing, failing
     and timing-out transfers through add, both passes, a timeout, reads and removes once for
     each of its 113 allocations, refusing that one and every later one: the arena's growth
     past 16 rows among them. Every run ends cleanly with nothing left allocated, and a pass
     allocates nothing. curl-core dev-depends on itself with `test-util`, so a plain
     `cargo test` builds the test doubles and runs it.
6. **os: add sockets, polling and the waker.** **Done.** `curl-os` (feature `net`): `net.rs`
   (nonblocking TCP: connect, recv, send, `SO_ERROR`; UDP and Unix sockets when a protocol
   needs them), `poll.rs`, `wake.rs` (a socket pair in safe code), with the CLAUDE.md unsafe list
   updated; core `Net` (just `poll` so far), `SystemNet`, `FakeNet`; `Env` gains the network and
   the waker; `Multi::wait` with `WaitMode::{Wait, Poll}`, `Multi::waker`,
   `drive_to_completion`. Loopback tests for connect done or in progress, refusal, would-block
   both ways, data then EOF, an interrupted poll and a woken wait. `fdset` and `waitfds` are the
   shim's, built from step 11's `Multi::sockets`, as no transfer owns a socket before then.

**`file://` end to end**

7. **deliver: add the pipeline, client output and pause.** In parts:
   - 7a. **Done.** `EngineRest`, `TransferCx` and the write and header handlers, shared and read
     at each call; the callbacks options; the test protocol `script:` (header lines and body
     pieces). The other handlers come with the parts that call them. Test: a handler replaced
     inside its own call.
   - 7b. **Done.** `Pipeline`: raw trace, the accountant's byte count and size limit,
     `ClientOut` Direct/Failed with the delivered-size check; the debug handler; the output
     options. The accountant's STARTTRANSFER mark is 7c's, its `maxdownload` cut and short-body
     end step 13's, with framing. Tests: 16 KiB pieces; header lines whole; `-i` order;
     `Failed` is terminal.
   - 7c. **Done.** `TransferReport`, `Timings`, `Sizes` and `HeaderStore`, with the
     accountant's STARTTRANSFER and download size and `TransferCx::info`. Ports unit 1399. Test:
     getinfo inside callbacks.
   - 7d. **Done.** `Pause`, `PauseRequest`, `ClientOut::Held` with `HeldOutput`, and
     `Multi::pause`/`TransferCx::pause`, a sibling's unpause replaying at once. Tests: pause and
     replay with interleaving (3235/3236 shapes), the kept piece, the 64 MiB cap, a pause
     where none is supported, the timer told of an unpause. The timer and socket callbacks
     inside `TransferCx::pause` (decision 10) come with step 13; until then the timer hears of
     it at the end of the pass and the socket callback after the step.
   - 7e. **Done.** `Speedometer`, the low-speed check and `SpeedCheck` timer, the progress
     handler (`Progress`, `ProgressNow`, `ProgressVerdict`) and the meter on a `TextSink`; the
     report's speeds, expected download size and running total; script pieces for a size and
     a wait. Ports units 1606 and 1636 (generated from the C tests). Tests: calls per pass,
     aborts, the meter's once-a-second line and titles once per handle, the speed check and
     pause.
   - 7f. **Done.** `Upload` from `options.upload` (none, shared bytes, a `ReadHandler` with an
     optional `Rewind` and size): the length clamp, the EOF and error latches, read pause,
     rewind; the report's upload size, expected size and speed; POSTTRANSFER when a body is
     sent; script pieces that send and rewind. Resume is the protocols' (step 8 for file://,
     the FTP stage): C's reader-level resume is dead code.
   - 7g. **Done.** The pause torture scenario: a transfer whose handlers pause again and again,
     replayed by unpauses from outside while it sends a body and reports progress, run with
     every allocation refused in turn.
8. **proto: add file:// and Easy::perform.** **Done.** The PROTOCONNECT, DO and DID steps, with
   progress counts pinned against C on file://; `curl_os::fs`; `proto/file.rs` (downloads,
   directory listings, head, resume, uploads and upload resume; no pause support: PAUSE is a
   WriteError, READFUNC_PAUSE a ReadError); `url_rules` (DISALLOW_USER, PATH_AS_IS) in setup;
   `version` reporting `file`; `Easy::perform` in a private multi, returning `Error`. RANGE and
   TIMECONDITION, which file.c honours, come with the options that set them.
9. **tool: run file:// transfers through the core.** **Done.** Each URL is a node with its output
   and upload, run in turn (`operate.rs`): output to standard output, nowhere or a file created at
   the first byte (`output.rs`), `-i`, `-s`/`-S`, `-v`, `--trace`/`--trace-ascii`/`--trace-time`
   (`trace.rs`, with `curl_os::time`), the result line and exit status, `-C`, `-T`,
   `--skip-existing`, `--remote-time`, `-w` with the variables a file transfer reports
   (`write_out.rs`), `--proto-default` (DEFAULT_PROTOCOL in setup). What the parser accepts but
   the transfers cannot do yet is refused with "not implemented yet": URL globbing, `-T -`, `-vv`,
   `--proto`, `--proto-redir`, the etag options, `--no-clobber`, `--remove-on-error`, an upload to
   a URL without a file name, the `-w` variables and functions not written yet.
   `crates/curl-tool/tests/transfers.rs` runs on either tool (`CURL_TOOL_UNDER_TEST`). Measured
   2026-10-20: `curl -s -o O file://…` makes 25 allocations, the C tool 59. Flips: 200–205, 231,
   288, 686, 1145, 1146, 1220, 1440–1442, 1445, 1469, 1490, 1491, 2036, 2044, 2071, 2072, 3016,
   3203, 4040.
10. **abi: add easy and multi handles.** **Done.** `ShimEasy` (`easy.rs`) holds its `Easy` while
    on its own and names it in its multi while added; `ShimMulti` (`multi.rs`) holds its core
    behind the gate (`gate/`, `TABLE` generated from `lib/api.c`), which hands a call either the
    core or the context the running callback lent (`Frame`). `ShimEvents` runs the timer and
    notify callbacks. The callback adapters (`callbacks.rs`) read the application's functions
    when they run, and are installed only where C's default differs from the core's, so a
    handle allocates about what C's does (751). `curl_easy_setopt` (`setopt/`) checks each
    option as setopt.c does; an id libcurl knows but the shim lacks is `CURLE_NOT_BUILT_IN`
    (`gen/setopt.py` lists the ids). `curl_easy_getinfo` answers the report's fields.
    `curl_easy_perform` runs in a private `ShimMulti`; `curl_easy_pause`; the multi entry
    points (`fdset` and `waitfds` list no sockets until step 11). A handler explains its own
    failure (`TransferCx::fail`) and the core adds no reason of its own. Flips: 502, 751, 1508,
    1550, 1558, 1564, 1592, 1791, 2414, 3105. Left for the options and steps that need them:
    `CURLINFO_EFFECTIVE_URL` (1990), the debug build's `CURL_TIME` getinfo override, C's
    "boolean setopt got unsupported argument" text, multi calls from a transfer's own callback
    (`info_read` and the counts answer `RECURSIVE_API_CALL`), `curl_easy_perform_ev`, and the
    multi options past the timer and notify callbacks.

**HTTP/1.1 GET**

11. **conn: add plain TCP connections to the pool**, in five parts.
    - **a. The connect path.** **Done.** `TransferState::Connecting` holds a lease on a
      `ConnSlot::Connecting`, whose `ConnectMachine` goes `Resolving` (IP literals only) →
      `Racing` (one attempt) → established in the slot it started in, or `Failed`. `Net` has
      `connect` and `close`; `FakeNet` has peers by address (accepts, accepts after a delay,
      refuses, silent). C's traces and texts for refusal, an immediate failure, an unresolved
      name and the connect timeout, and the connection's end ("closing connection #N",
      "shutting down connection #N", which `file:` transfers now trace too). `wait` polls the
      connecting sockets. `tcp:` is the test protocol that connects and completes.
    - **b. Pool semantics.** **Done.** Routes with the protocol's reuse flag; a connection
      finished with stays idle ("left intact") and an equal route reuses it ("Reusing existing
      tcp: connection", no connect and no times); the search prunes once a second and closes
      matches too old or not healthy, with C's traces; idle connections close with their multi;
      the table doubles from 16; the four lock points, pinned by a recording `Lock` test with
      1554's sequence. Left for the steps that need them: MAXCONNECTS and the pool-full eviction
      ("Connection pool is full, closing the oldest of N/M"), FORBID_REUSE and the protocol's
      close mark, the total and per-host limits, and setopt for MAXAGE_CONN and
      MAXLIFETIME_CONN.
    - **c. The transfers' sockets.** **Done.** One pollset per transfer, from its state and its
      connection's socket (a setup waits to write unless receiving is paused), behind `wait`,
      `Multi::sockets` and the shim's `fdset` and `waitfds`; a transfer removed, or left in a
      multi that goes, traces "closing connection #N". Plain TCP closes at once, as
      `cf_socket_shutdown` is done in one call, so `ShutdownSet` comes with TLS; the 1 KB drain
      before the close comes with step 12's reads.
    - **d. The socket callback.** **Done.** `SocketTable`, `Host::Socket`,
      `MultiEvents::socket`, `socket_action` on a socket, `assign`, each transfer's pollset
      re-assessed after it runs in `socket_action` and inside `remove` and `pause`, and REMOVE
      before a socket closes through the pool's `Announcing` network; the shim's
      SOCKETFUNCTION, SOCKETDATA and `curl_multi_assign`. Left: the timer and socket callbacks
      inside a pause from a transfer's own handler (step 13, whose responses are the first
      requests to wait on their socket while a handler runs), `curl_multi_assign` from a transfer's
      handler (BAD_SOCKET until `TransferCx` can reach the table), and `curl_multi_socket_all`.
    - **e. The pollset's basis.** **Done.** `Directions`, the ways a request moves bytes (C's
      `REQ_IO_*`): none before DID, set there from the protocol, sending cleared once the body
      is sent. A pause blocks a transfer only when it stops every way it moves
      (`Curl_xfer_is_blocked`), so it never blocks a setup or `file:`.
12. **http1: render requests behind the credential gate.** **Done.** `RequestHead`,
    `UserHeaders`, `render_h1`, `CredentialGate` in `proto/http1/request.rs`. Fixture tests
    compare byte-exactly with the `<protocol>` of 1, 14, 47, 461, 1121, 1292; the application's
    headers, Connection, the gate and the 1 MiB cap have their own. The parts no option asks for
    yet (authentication, range, cookies, conditionals, content headers and the rest) render
    nothing, and the options that feed a head (`-H`, the user agent, the version) come with the
    protocol in step 14.
13. **http1: parse responses and decide framing.** `ResponseHeadParser`, `decide_framing`,
    `ChunkDecoder`, trailers, GOT_NOTHING, every limit, the accountant's `maxdownload` cut and
    short-body end ("end of response with N bytes missing"). Byte-fed tests at every split point from
    the fixtures of 1274, 1430–1433, 1466, 365, 2918, 1722, 1723, 2119, 772, 773, 497, 747, 1154,
    34, 36, 207, 1416, 1417, 2106. Ports units 1625, 1626. Built in five parts, each its own
    commit, pure and fed bytes by tests; the protocol drives them from step 14.
    - **a. Field helpers.** **Done.** `proto/http1/fields.rs`: a header's value
      (`Curl_copy_header_value`, unit 1626), whether it lists a token (`Curl_compareheader`,
      unit 1625), and whether a line is one (`Curl_verify_header`).
    - **b. Lines and the status line.** **Done.** `proto/http1/response.rs`: `HeadParser`
      assembles lines over any split, joins folds, decides HTTP/0.9, reads the status line
      and counts the request's and the transfer's head bytes, giving out one line at a time
      in `http_rw_hd`'s order. Tests feed 1274, 1430–1433, 1466 and 497 whole, split at every
      byte and a byte at a time; the status-line and bad-line cases were checked against the
      C binary.
    - **c. What the headers say, and the framing.** **Done.** `proto/http1/framing.rs`:
      Content-Length, Transfer-Encoding, Connection, Content-Type and Trailer applied as each
      header arrives, with C's gates; the framing and the close folded at the final blank
      line; max-filesize at the head. Fixtures 365, 2918, 1722, 1723, 2119, 334, 499, 1484,
      178, 394, 282, 262, 398, 415, 2105, 129 and 1473, and the cases no fixture pins checked
      against the C binary. Decoding codings other than chunked, Content-Encoding,
      Content-Range and Location come with the steps that use them.
    - **d. Chunks and trailers.** **Done.** `proto/http1/chunked.rs`: `ChunkDecoder` with
      trailers, raw mode and the hex and trailer limits. Fixtures 34, 36, 207, 266, 326,
      1116, 1416, 1417, 1482, 1483, 1493 and 2106, fed whole, split at every byte and a byte
      at a time, and the grammar's corners checked against the C binary.
    - **e. Accounting.** **Done.** `deliver::Expect` and the accountant's cut at the expected
      size ("Excess found writing body…", the connection given up), the short body at the end
      (18), a body where none was wanted dropped with the connection, and
      `HeadParser::got_nothing`, the interim heads' bytes deducted. Messages checked against the
      C binary.
14. **http1: run requests, and the fixture runner.** In three parts:
    - **a. Bytes on a connection.** **Done.** `Socket::recv` and `send`; a connection's `rx` and
      `tx` (`conn/buf.rs`), `Conn::recv` behind what waits and `Conn::flush`; `FakeNet`
      conversations, a peer that replies to a request's head and then closes or not, and keeps
      what it was sent.
    - **b. The HTTP/1 driver.** **To do.** `http:` as a protocol: the head rendered at DO and
      sent, the response read and parsed, delivered through the pipeline with what its head
      expects, the body framed by length, chunks or the close, the end judged (nothing, short,
      outstanding chunks), the connection kept or closed. Armed end to end on test 1 over
      `FakeNet`.
    - **c. The fixture runner.** **To do.** Generated from `tests/data`: the milestone set's
      cases without servercmd, driven over `FakeNet` and `ManualClock`; armed by breaking a
      framing rule. Adds the plain-GET allocation budget test, set at this design's count.
15. **tool: run HTTP transfers.** The tool maps the remaining milestone options (`-H`, `-A`,
    `-e`, `-0`/`--http1.0`/`--http1.1`/`--http0.9`, `-D`, `--raw`, `--ignore-content-length`,
    `--max-filesize`, `--show-headers`, `-f`, `-N`, `--tr-encoding`). Measure test 1's
    whole-process count against its 140/136000 limit.
16. **version: report http**, as soon as the basic GET works. Ring A flips: 1, 14, 22, 23, 47, 59, 151, 260, 334, 367, 461, 1109,
    1121, 1292 and the `-A`/`-e`/`-0` cases. Tests 1, 497, 747 and 767 also need their
    `<limits>`.
17. **Ring B, chunked and transfer codings:** 34, 207, 266, 319, 326, 365, 1116, 1416, 1417,
    1482, 1483, 1493–1496, 1722, 1723, 2106, 2119, 2918.
18. **Ring C, response errors and limits:** 30, 37, 282, 1665; 178, 262, 394, 398, 415, 1473,
    2105; 129, 1430–1433, 1466; 497, 747, 1154, 1205.
19. **Ring D:** HTTP/0.9 (66, 1144, 1172, 1174, 1266, 1267); 1xx (1033, 1115, 1480); folding
    (1274); a body on HEAD (499, 1484); 395, 767–773.
20. **Ring E, tool options:** 292, 293, 393, 457, 24, 152, 269, 419, 26 and the remaining
    servercmd cases. At the end, the 102-test set passes on both legs or each remaining test is
    listed with its reason.
21. **abi: the HTTP libtests.** Easy: 566, 1485, 1532, 1541, 1556, 1594, 1595, 1596, 1649, 1907,
    2306, 2308, 3010. Headers: 1940, 1942, 1943. Multi: 528, 535, 573, 580, 581, 1500, 2405,
    2412, 2453. Re-entrancy and events: 1555, 3107, 530, 758.

After the milestone, each ring has its seam: T1 (`-w`, `-m`, `--fail-with-body`, `-#`,
`--stderr`), pool reuse and limits with the getaddrinfo resolver, redirects, multi-URL, then event
mode and `-e`.
