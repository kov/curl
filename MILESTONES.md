# Milestones

The order the engine is built in, as commit-sized steps. `ENGINE.md` holds the design they
implement. Each step records its status: **done** (with the commit), **in progress**, or
**to do**. When a step lands, is split, or is reordered, this file changes in the same commit,
along with the tests it flipped as `runtests.pl` reported them.

## Milestone 1: `file://`, then HTTP/1.1 GET

Status: **done**. Every ring passes through runtests.pl on both legs; the libtests that wait on
later work are listed in step 21.

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
    the debug build's `CURL_TIME` getinfo override, C's "boolean setopt got unsupported
    argument" text, multi calls from a transfer's own callback (`info_read` and the counts
    answer `RECURSIVE_API_CALL`), a setopt from the timer callback during `curl_multi_add_handle`
    (`RECURSIVE_API_CALL`, where C allows it), `curl_easy_perform_ev`, and the multi options
    past the timer and notify callbacks.

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
    - **a. Bytes on a connection.** **Done.** `Socket::recv` and `send`; a connection's `rx`
      (`conn/buf.rs`), `Conn::recv` behind what waits and `Conn::send`; `FakeNet`
      conversations, a peer that replies to a request's head and then closes or not, and keeps
      what it was sent.
    - **b. The HTTP/1 driver.** **Done.** `proto/http.rs`: `http:` as a protocol, the head
      rendered at DO and sent, the response read and parsed, each line traced and delivered,
      the body framed by length (reads capped at its end), chunks or the close, the end judged
      (nothing, short, outstanding chunks, a head cut short), a held line delivered at done,
      the connection kept or closed. `Options::http` holds what the driver reads. Armed end to
      end on tests 1, 266 and 326 over `FakeNet`, the outcomes and texts taken from the C
      binary. Not yet: a request body, retrying a reused connection that delivered nothing,
      C's debug-build-only trace lines.
    - **c. The fixture runner.** **Done.** `proto/http/suite.rs` reads the milestone set's
      cases from `tests/data` and runs them over `FakeNet` and `ManualClock`: 72 of 81 run
      (the rest need a server command, `-f`, `-o`, a stderr check, or a reply where 419 has
      none), and all but 367 (Basic auth from the URL) pass; armed by breaking a framing rule. It found
      the second `Location` (772) and HEAD over HTTP/0.9 (1144). The plain-GET torture
      scenario and allocation budget (38) are in `tests/torture.rs`; the scenario found memory
      failures reported as `UrlMalformat`, `CouldntConnect` and `RecvError`.
15. **tool: run HTTP transfers.** **Done.** The tool maps `-H`, `-A`, `-e`, `-0`/`--http1.0`/
    `--http1.1`/`--http0.9`, `-D`, `--raw`, `--ignore-content-length`, `--max-filesize`, `-I`,
    `-f` and `-N`, checked against the C tool by `crates/curl-tool/tests/http.rs`; the library
    gained the referer and failing on error codes. `--tr-encoding` and `-H @file` stay refused.
    Test 1 as runtests.pl runs it makes 60 allocations and 41357 bytes at most (the C tool 95
    and 126805), within its 140/136000.
16. **version: report http.** **Done.** `curl -V` lists `http`; the tool shows HTTP headers
    for `-i`/`-I` and maps `-m`, `--connect-timeout` and `-g` (runtests.pl checks its servers
    with them); the request sends Basic credentials from the URL (367). Ring A (1, 14, 22, 23,
    47, 59, 151, 260, 334, 367, 461, 1109, 1121, 1292) passes through runtests.pl on the Rust
    leg, test 1 within its `<limits>`; 497, 747 and 767's limits are checked with their rings.
17. **Ring B, chunked and transfer codings.** **Done.** 34, 207, 266, 319, 326, 365, 1116, 1416,
    1417, 1482, 1483, 1493–1496, 1722, 1723, 2106, 2119, 2918 pass.
18. **Ring C, response errors and limits.** **Done.** 30, 37, 282, 1665; 178, 262, 394, 398, 415,
    1473, 2105; 129, 1430–1433, 1466; 497, 747, 1154, 1205 pass, each within its `<limits>`.
19. **Ring D.** **Done.** HTTP/0.9 (66, 1144, 1172, 1174, 1266, 1267); 1xx (1033, 1115, 1480);
    folding (1274); a body on HEAD (499, 1484); 395, 767–773 pass.
20. **Ring E, tool options.** **Done.** 292, 293, 393, 457, 24, 152, 269, 419 and 26 pass; HTTP
    resume (`-C`, `Range`, the 416 read and dropped) came with them. The 84 ring tests of steps
    16 to 20 pass on both legs.
21. **abi: the HTTP libtests.** **Done**, but for those that wait on later work. Easy: 566, 1485,
    1532, 1541, 1556, 1594, 1595, 1596, 1649, 1907, 2306, 2308. Multi: 528, 535, 573, 580, 581, 1500,
    2405, 2412, 2453. Re-entrancy and events: 1555, 3107, 530. The shim gained the HTTP options,
    the response's infos, `curl_easy_recv`/`curl_easy_send` and the headers API (`headers-api`
    ON); the date parser (`date.rs`, lib517 and unit4781's tables) gives `curl_getdate` (517)
    and Retry-After dates. Waiting: 3010 (`CURLINFO_REDIRECT_URL`), 1940, 1942 and 1943 (they
    set `CURLOPT_FOLLOWLOCATION`), all with redirects; 758 needs an HTTPS server.

## Milestone 2: more than one leg, the resolver, and the rest of HTTP/1.1

Status: **in progress**. The rest of SCOPE stage 3: what a transfer needs to make a second
request (redirects, retries, authentication), names resolved and connections limited, request
bodies, cookies, proxies and compression, with the tool's T1 ring and its multi-URL and event
modes. Each step opens with the change to the engine it stands on, then the features, then the
tests it flips, checked on both legs as in milestone 1. At its end, the sabotage sweep and
cargo-mutants run on the milestone's diff.

22. **core: run a transfer as legs.** **Done.** Setup splits into a pretransfer run once per
    transfer and `start_leg`, run per request; `Run` keeps the request's URL, read back whole,
    and the retry count. `Done` carries `AfterRequest { Complete, Retry }`. First user:
    `Curl_retry_request`, a request that got nothing back over a reused connection made again
    on a fresh one, up to five times a transfer, with C's traces (checked against the C build
    with a libcurl program and a server closing the reused connection). Witnessed by core
    tests; no C test flips by itself.
23. **conn: resolve names and limit connections.** **Done.** A list `Pollset`
    in place of one socket; a refcounted `Peer` as the one owner of the host, shared by the
    transfer and its connection and matched for reuse as `Curl_peer_equal` does (case, zone);
    `localhost` and its names resolved as C resolves them, the answer reported, its addresses
    limited by `CURLOPT_IPRESOLVE` (`-4`, `-6`; test 389); happy eyeballs, its attempts raced
    as unit 2600 has them; IPv6 reported as a feature (tests 240, 242); a DNS cache on the
    multi and `--resolve` read into it (tests 1317, 1318, 1322, 1324, 1458, 3019);
    `--connect-to` (tests 1659, 2049, 2054, 3020); MAXCONNECTS, MAXAGE_CONN and
    MAXLIFETIME_CONN (tests 1506, 1510, 1542); the per-host and total limits, a transfer
    waiting for room in `Pending` (test 1557); FORBID_REUSE and FRESH_CONNECT; the
    getaddrinfo resolver, with negative answers kept and the resolver's reason in a failure
    (test 241); `CURLOPT_DNS_CACHE_TIMEOUT`. Tests 3231 and 3232 wait for CONNECT_ONLY.
24. **tool: the T1 ring.** **To do.** The `-w` variables, `--fail-with-body`, `-#` and
    `--stderr`, with the report fields they read.
25. **http: send request bodies.** **To do.** Opening commit: `Directions` refreshed by the
    engine from the protocol after each call, its other writers removed and the debug check
    comparing them. Then the send side's states (`SendSide`), POSTFIELDS, the read callback,
    PUT, chunked upload, `Expect: 100-continue` with the 417 retry as a second leg, and a
    rewind for a new leg. The method's options (NOBODY, POST, UPLOAD, HTTPGET) combine in the
    shim.
26. **http: follow redirects.** **To do.** Opening commit: relative URL resolution and the
    part setters (the rest of lib1560). Then FOLLOWLOCATION, MAXREDIRS, 301/302/303 method
    changes, the credential gate's first origin kept in `Run`, credentials and a custom Host
    dropped across hosts through the gate,
    `-e ";auto"` and `CURLINFO_REDIRECT_URL`. Flips 3010, 1940, 1942 and 1943 and the
    followlocation family.
27. **tool: several URLs, then globbing.** **To do.** The tool's transfers share their
    connections and DNS cache, as C's share handle has them (tests 2051, 2052 and 3225 with
    step 24's `%{num_connects}`). Opening commit: the multi's tables that a share can hold in
    its place (the pool and the DNS cache) grouped, so that `EngineRest`, `Announcing` and
    `Telling` stop each listing their own subset of them. Globbing is refused with exit 125 until then (test 2053).
28. **multi: event mode.** **To do.** `curl_easy_perform_ev`, `curl_multi_assign` from a
    transfer's own handler, the socket and timer callbacks inside a pause from a transfer's own
    handler (step 11d), and a setopt from the timer callback during `curl_multi_add_handle`
    (step 10).
29. **http: authenticate.** **To do.** Basic from the options, then netrc, Bearer and Digest,
    and the 401/407 retry as a second leg; FAILONERROR's 401/407 exception (step 15) with it.
30. **http: cookies.** **To do.** Who owns the jar is decided first (the easy handle, or the
    share); then the parser, with the date parser, `-b` and `-c`, and the request's `Cookie`.
31. **http: proxies.** **To do.** Opening commit: the route built in setup from the target,
    the proxy options and the scheme table, each trace's host checked on the C leg. Then the
    absolute request target and Proxy-Authorization; then CONNECT, after the dial result is
    split from the pooled `Conn` (§4.2's `TunnelEvent` and `&mut ProxyAuth`); then SOCKS.
32. **http: decompress.** **To do.** Opening commit: the pause gate holding encoded bytes, as
    C's does, and an empty decoder slot, pinned to change no trace or piece size. Then a
    binding crate per library (zlib, brotli, zstd), `--compressed`, `--tr-encoding` and
    Content-Encoding.

Later, with the protocol that needs it: the scheme facts (family, PROTOPT flags, default port)
generated from `gen/schemes.py` rather than copied by hand, by stage 4 at the latest; resting
connect and DO states and connection-scoped protocol state, with the first stage-6 protocol or
STARTTLS; the request renderer writing each part through a field sink, when HTTP/2 starts.
