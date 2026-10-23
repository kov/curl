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
   needs them), `poll.rs`, `wake.rs` (an eventfd, as C's), with the CLAUDE.md unsafe list
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
    gained the referer and failing on error codes. `--tr-encoding` and `-H @file` came later.
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

Status: **done**. The rest of SCOPE stage 3: what a transfer needs to make a second
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
24. **tool: the T1 ring.** **Done.** The `-w` variables read from the transfer report (the
    response, the URL and its parts, the times, sizes and speeds, the content type, the
    connection's ends and count, the header count), `-w @file` and `%output{}`;
    `--fail-with-body`; `-#`; `--stderr`, pointing descriptor 2 as C's `freopen` does; and
    the getinfo answers for the same report fields. Tests 15, 57, 192, 349, 360, 361, 423,
    435, 978, 990, 991, 1148, 1188, 1223, 1271, 1278, 1429, 1438, 1439, 1721 and 3014 pass,
    and libtest 500 within its memory limit now that a multi's rows hold their transfers
    boxed. The rest of the ring waits on the steps named for it below: `%{method}` and
    `%{referer}` are tested only through redirects.
25. **http: send request bodies.** **Done.** `Directions` derived from the protocol where a
    pause is judged, no longer stored; a body of known size sent behind the head from one
    64 KiB send buffer, with its `Content-Length`, a POST's form type and C's end-of-send
    trace; a body of unknown size, or one the application asks so, sent chunked, ending
    with the trailer handler's trailers; `Expect: 100-continue`, waited for until a 100 or
    the timeout, and an error response before the body has gone stopping it or not
    (`KEEP_SENDING_ON_ERROR`); `CURLOPT_CUSTOMREQUEST`; the method's options (NOBODY, POST,
    POSTFIELDS, COPYPOSTFIELDS, POSTFIELDSIZE, UPLOAD, HTTPGET) combined in the shim; the
    tool's `-d` family, `--json`, `-X`, `-T -` and `--expect100-timeout`. T1 tests 1295,
    1740, 1741 and 2093. The 417 retry and the body's rewind for a new leg come with step
    26's legs; `-T .` (standard input without blocking) is still refused.
26. **http: follow redirects.** **Done.** Relative URL resolution and the part setters
    (lib1560's tables), the shim's `curl_url_*` (1559, 1921, 1965, 1967, 1989) and
    `CURLOPT_CURLU`, read as each transfer starts (658, 674, 1518, 1567, 1977), with
    `CURLOPT_PORT` (1906). `CURLINFO_REDIRECT_URL`; FOLLOWLOCATION, MAXREDIRS and
    UNRESTRICTED_AUTH, with the tool's `-L`, `--follow`, `--location-trusted` and
    `--max-redirs`; the credential gate's first origin kept in `Run`, so the application's
    Authorization, Cookie and Host stay with it while a redirect's own URL credentials go to
    its host; 301/302/303 method changes with POSTREDIR and `--post30x`, the custom method as
    the follow mode says; the request body rewound for a redirect or a retry; an HTTP/1.0
    response making the transfer's later requests HTTP/1.0; a 417 making the request again
    without `Expect` (357); AUTOREFERER and `-e ";auto"`. The infos and variables
    `%{method}`, `%{referer}`, `%{redirect_url}` and `%{num_redirects}`. T1 tests 193, 1029,
    1067, 1089, 1090, 1159, 1197, 1261, 1270, 2081 and 3015 pass, and 3010, 1940, 1942, 1943
    and the followlocation family; 1080 and 1081 need step 27's several URLs, and 1560 https
    and IDN in the build. Not done: a redirect before a large body is all sent closing the
    connection instead of sending the rest (`http_perhapsrewind`'s abort half), and a
    connection's own memory of HTTP/1.0 (`conn->httpversion_seen`).
27. **tool: several URLs, then globbing.** **Done**, but for what waits on later work. The
    multi's pool and DNS cache are one `Caches`, and `Telling` the one bundle of what the
    socket callback reaches, which `EngineRest` and `Announcing` hold; the tool's transfers share
    one `Share`, so they reuse connections and names across URLs (2051, 2052, 3225, 3226, 1080, 1081); `-O` and `--remote-name-all` (422,
    681, 690, 691, 1334-1347, 1644, 3008, 3009, 3013), `--no-clobber` (481, 1681, 1683, 4644)
    and `--output-dir` (1682); URL and upload file globbing, with output names reading the
    patterns, and an upload's file name added to a URL whose path has none (74, 75, 86, 87,
    214, 490-492, 759, 761, 994, 2053 and others); `--create-dirs` (3011, 3031); `-J`, from
    `Content-Disposition` or a redirect's `Location` (1210, 1310-1313, 1338-1341, 1368-1371,
    1422, 1460, 1487, 1492, 1584, 1585, 1641-1643, 3012, 3037); `-K` and the default `.curlrc`,
    a file's text kept while what was parsed from it lives (17, 56, 411, 430-436, 468, 1639,
    3228 and others); `--retry`, its delay, time limit and `--retry-all-errors`, the output cut
    back or kept and resumed between attempts (197, 198, 366, 752, 1269, 1497, 1633-1637, 1673,
    1716, 1909, 3035, 3036); URLs read from a file with `--url @file` (2012); `-R`, from
    HTTP's `Last-Modified` (762, 1443). Waiting: `--retry-connrefused`, for the connect's
    errno in the report.
28. **multi: event mode.** **Done**, but for what waits on later work. `drive_by_events`,
    behind `curl_easy_perform_ev`, `Easy::perform_ev` and the tool's `--test-event`; the
    regression list passes under `runtests.pl -e` on both legs. The core names a new transfer
    to the host (`MultiEvents::added`) before the add's timer callback, so a setopt from it
    reaches the handle. Waiting: `curl_multi_assign` from a transfer's own handler, for a
    `TransferCx` that reaches the socket table; the timer and socket callbacks inside a pause
    from a transfer's own handler, which come at the end of the pass instead (ENGINE.md 7.8).
29. **http: authenticate.** **Done**, but for what waits on later work. Basic from the options, then netrc, Bearer and
    Digest, and the 401/407 retry as a second leg; FAILONERROR's 401/407 exception (step 15)
    with it. T1 tests 1876 and 1877. Done: the login (`CURLOPT_USERPWD`, `USERNAME`,
    `PASSWORD`, `XOAUTH2_BEARER`, the tool's `-u` and `--oauth2-bearer`) composed with the
    URL's per request, gated to the first origin; `.netrc` files (`CURLOPT_NETRC`,
    `NETRC_FILE`, `--netrc`, `--netrc-optional`, `--netrc-file`); the methods asked for
    (`CURLOPT_HTTPAUTH`, `--basic`, `--anyauth`), a 401's challenges read and answered as a
    second request, FAILONERROR's 401 exception, `CURLINFO_HTTPAUTH_AVAIL` and `_USED`; Basic,
    Bearer and Digest (`--digest`; MD5, SHA-256 and SHA-512/256) with its body-less probe. T1
    tests 1876 and 1877 pass; the 44 Digest tests pass on both legs, though `runtests.pl` skips
    them on the Rust leg, which claims no NTLM, Kerberos or SPNEGO and so no `crypto`. They
    are run with the gate forced open by `inventory/measure/gated.py`, a regression net kept
    out of the score; delete it when the Rust build claims one of the three.
    Waiting: NTLM and Negotiate, refused as not built until their own steps, as a C build
    without them refuses; 407, with the proxies
    (step 31);
    `http_perhapsrewind`'s early close of a large body, and its "Need to rewind" line on an
    auth reload, with step 34.
30. **http: cookies.** **Done**, but for what waits on later work. The jar (ENGINE.md 6.5),
    the handle's or its share's, borrowed per operation, so a share's serves a C multi's
    transfers too; its files read as each transfer starts; `Set-Cookie:` stored and the
    request's `Cookie:` sent; `CURLOPT_COOKIE`, `COOKIEFILE`, `COOKIEJAR`, `COOKIESESSION`,
    `COOKIELIST` and `CURLINFO_COOKIELIST`; the tool's `-b`, `-c` and `-j`; public suffixes
    through libpsl (`curl-psl`); the shim's `curl_share_*`, with the lock functions called
    for the share itself. The 45 cookie and PSL tests the Rust leg runs pass. Waiting: the proxy tests, with step 31; the lock
    functions at the pool's and the jar's sites (1554), with the share's planned split
    (ENGINE.md 4.6.1); `CONNECT_ONLY` (3234).
31. **http: proxies.** **Done**, but for what waits on later work. The proxy chosen at setup from the options or
    the environment and the no-proxy list, joining the route (ENGINE.md 4.5); a plain HTTP
    request forwarded whole, with `Proxy-Connection`; `CURLOPT_PROXY`, `NOPROXY`,
    `PROXYPORT`, `PROXYTYPE`, `HTTPPROXYTUNNEL` and `CURLINFO_USED_PROXY`; the tool's `-x`,
    `--noproxy`, `--proxy1.0` and `-p`; Proxy-Authorization and the proxy's 407, with
    `CURLOPT_PROXYUSERPWD`, `PROXYUSERNAME`, `PROXYPASSWORD`, `PROXYAUTH`,
    `CURLINFO_PROXYAUTH_*` and the tool's `-U`, `--proxy-anyauth`, `--proxy-basic` and
    `--proxy-digest`; tunnels with `CONNECT` (ENGINE.md 4.2), for `-p` or a connect-to
    peer, answering the proxy's 407 on the same connection or a new one, with
    `CURLINFO_HTTP_CONNECTCODE`, `%{http_connect}`, `CURLOPT_SUPPRESS_CONNECT_HEADERS` and
    `--suppress-connect-headers`; a 407's challenge read only from a forwarding proxy (gated
    test 1616); SOCKS4, 4a and 5 (ENGINE.md 4.2), with `CURLOPT_SOCKS5_AUTH`,
    `CURLINFO_PROXY_ERROR` and the tool's `--socks4`, `--socks4a`, `--socks5` and
    `--socks5-hostname`; the proxy's own headers, with `CURLOPT_PROXYHEADER`,
    `CURLOPT_HEADEROPT` and `--proxy-header`; the PROXY protocol's line, with
    `CURLOPT_HAPROXYPROTOCOL`, `CURLOPT_HAPROXY_CLIENT_IP`, `--haproxy-protocol` and
    `--haproxy-clientip`; a SOCKS pre-proxy in front of the HTTP proxy, with
    `CURLOPT_PRE_PROXY` and `--preproxy`. HTTPS proxies wait on TLS.
32. **http: decompress.** **Done**, but for 3236. The pause gate holds a paused body still
    coded, as C's does; Content-Encoding and `Accept-Encoding` (`--compressed`), Transfer-Encoding
    and `TE` (`--tr-encoding`), and `--raw` for both, with a binding crate per library:
    `curl-zlib` (`deflate`, `gzip`), `curl-brotli` (`br`) and `curl-zstd`. The 28 compression
    tests run on both legs and 27 pass; 3236 waits on C's `write` trace component
    (`curl_global_trace`), which opens milestone 3.
33. **http: the headers API, and time conditions.** **Done.** Each request's headers kept for
    `curl_easy_header` and `curl_easy_nextheader`, by origin and request across redirects, and
    the tool's `%header{}` and `%{header_json}` reading them (421, 764, 765, 1670, 1671). `-z`
    and `CURLOPT_TIMECONDITION` over HTTP and FILE: the conditional header, a document ruled
    out ending as a 304 would, and `CURLINFO_CONDITION_UNMET` (77, 78, 249, 1126–1128, 1239,
    1424, 1511, 1593). FTP's waits on FTP.
34. **core: read the response while the body goes.** **Done.** A step reads first, then sends
    what is left with at most one more buffer of the body, as C's `Curl_sendrecv` does
    (ENGINE.md 3.2), and a response asking for another request weighs what of the body is left
    (`http_perhapsrewind`): 2000 bytes or more, or an unknown amount, and the connection closes
    rather than carry it ("close instead of sending N more bytes"); less, and it goes to be
    dropped on a connection kept. Against a server answering a 30 MB PUT's head with a 307,
    or a 401 to `--anyauth`, before reading the body, the trace matches C's line for line, and
    both reload on a new connection after under a few MB. No suite test sees it; Rust tests do,
    from a redirect, a challenge, a body of unknown size and one with little left. `perf.py`
    cannot measure the Rust leg (its scorecard runs over TLS); measured 2026-10-21 instead,
    release builds, a 256 MiB PUT and GET over plain HTTP to a local server, medians of 9:
    upload client CPU 0.065 s before, 0.072 s after, C 0.078 s; downloads unchanged at 0.025 s.

35. **share: safe across threads.** **Done**: the share keeps each kind behind its own lock,
    with the application's lock functions told around each use (506, 1554); the shim's
    `CURLSH` is `Sync`, tested by two threads through the C ABI and, for the jar, under Miri;
    `Easy` is `Send`, its handlers `Send + Sync`. Not done: 3234, which waits on
    `CURLOPT_CONNECT_ONLY`. C's
    `CURLSH` may be used from several threads, guarded by the application's lock functions;
    ours is `TryRc` and `RefCell`, so that is a data race. The share becomes `Send + Sync`
    with its own locks, one per kind of data, so safety never rests on the application's:
    those are still called where and as C calls them, with no internal lock held across them
    or across any callback. What it holds becomes `Send` (connections and sockets, `Net`, the
    DNS cache, the jar), and so does `Easy`, held to it by a compile-time assertion; a
    fallible `TryArc` joins `curl-alloc`; DESIGN.md's threading decision changes to say the
    share is `Sync` and the multi is not. Asking a share for only some kinds (DNS without
    connections) comes with it, as C does. Tested by two threads through the C ABI with no
    lock functions, under Miri where it reaches.

36. **tool: the remaining HTTP/1.1 options.** **Done.** `-G`/
    `--get` and `--url-query` (2008); `-r`/`CURLOPT_RANGE`, with the 206 and 416 answers
    (gated 1001), and `CURLOPT_RESUME_FROM` -1 on a GET sending C's `Range: bytes=-N-`;
    `--limit-rate` (729, `MAX_RECV_SPEED_LARGE`, `MAX_SEND_SPEED_LARGE`), reading at most
    `CURLOPT_BUFFERSIZE` at a time; `--request-target` (1613); every `-w` variable and
    `%{json}` (970, 972), and `%time{}`; `--aws-sigv4`; HTTP message signatures
    (`CURLAUTH_HTTPSIG`) with HMAC-SHA256, and Ed25519 on the OpenSSL binding (step 43b); `--ipfs-gateway` (1851); the linked libraries in `curl_version` and `-V`; the
    tool's locale taken from the environment for all but numbers, as C's `LC_ALL` is.
37. **http: multipart/MIME.** **Done**, but for what waits on other protocols. The upload
    source is a source plus a chain of reader stages (ENGINE.md 5.4); the MIME tree a value in
    the core, read again at each request, with its encoders, size, rewind and the
    `Content-Type` boundary; `CURLOPT_MIMEPOST` and the shim's `curl_mime_*`;
    `CURLOPT_HTTPPOST` with `curl_formadd`, `curl_formget` and `curl_formfree`; the tool's
    `-F`, `--form-string` and `--form-escape`; `CURLOPT_UPLOAD_BUFFERSIZE`. Every MIME and
    form test the Rust leg runs passes (49). Waiting: SMTP (646, 648, 649, 652, 1187), IMAP
    (647, 1553, 1590), TLS (304, 1972), NTLM (170), the `crypto` gate (258, 259),
    `--libcurl` (1404) and the manual (1708).
38. **Matching C, and what the milestone's reviews found.** **Done.**
    - The application's lists (`HTTPHEADER`, `PROXYHEADER`, `CONNECT_TO`, `RESOLVE`) read at
      each leg, as C reads them per request, not copied at setopt; the WebKit backend's pattern
      (set once, appended to after) tested through the C ABI on both legs.
    - The read half bounded to C's 11 reads a pass, then run again while data may be pending, so
      a fast peer cannot starve timeouts, progress or other transfers.
    - The tool's password prompt for `-u` and `-U` without one (`checkpasswd`).
    - Unknown `CURLOPT_HTTPAUTH`/`PROXYAUTH` bits accepted and ignored, as C does.
    - file:// reads on through a failed `fstat`, without a size, as C does.
    - `curl_multi_waitfds` folds a socket listed twice into one entry (`cwfds_add_sock`).
    - `Route` compared field by field with nothing left out by `..`, built once per leg.
    - No option taken from its home across a trace a debug handler can see.
    - The send side's flags as one state enum.
    - A property test per parser entry point: malformed input returns an error, never panics.
    - A 401's retry trace names the URL as given, not with `CURLOPT_PORT` applied.
    - IPv6 zone ids applied to the socket address, with C's link-local fallback.
    - `DIVERGENCE.md` lists each deliberate, permanent difference from C with its pinning test;
      temporary gaps stay in this file.
    - Smaller differences from C found while closing the milestone: `-o` output buffered as C's
      (a failed write reported at close, "Failed writing body"), and its "passed N returned M"
      on a short write; the application's and a cookie file's cookies counted toward a
      transfer's limit of 50; `CURLOPT_IPRESOLVE` read again while a transfer waits for a
      connection; a RESOLVE list set while one is read dropped; cookie files loaded as each is
      traced; a chunked POST decided when the request is built, not at setopt; the CONNECT
      and SOCKS handshakes' read loops; the end of a body whose size was known.

## Milestone 3: connections in layers, then TLS

Status: **in progress**. Opens with what TLS stands on, decided at milestone 2's review.

39. **Component tracing.** **Done**, but for what waits on later steps. `curl_global_trace`
    and `--trace-config`: one process-wide setting in the shim's root, read live through a
    shared handle the core is given; C's components, syntax and `ids`/`time` prefixes;
    `CURL_DEBUG` in the debug build. The lines of the components built so far, as ENGINE.md
    describes them: MULTI, TCP, WRITE, READ, TIMER, HAPPY-EYEBALLS and DNS, each later protocol
    bringing its own. The debug handler reachable outside a transfer, so `COOKIELIST`'s cookie
    lines are traced where C traces them. Closes 3236, 3235, 1515 and 19. Waiting: the
    connection setup filter's and the pollset's lines (step 40), and 758 (step 43).
40. **The engine rewrite:** **Done.** Who owns a connection (exclusive leases checked against their home
    pool; the socket's closer carried from its creation) and the layer stack as a pull chain
    like C's filters, one `Stream` owned by a dialed socket and a connection alike (ENGINE.md
    4.1–4.3, 4.6). With them, the trace lines C makes from inside a connect and from `wait`:
    SETUP, `cf_setup_connect`, `connected` and `reduced to`, the TCP socket's lines, the
    pollset and `multi_wait`, a timer's `expires in` and the `gives multi timeout` line. The
    DNS and happy eyeballs filters' own lines stay untraced (ENGINE.md 2.5). Each trace
    sub-step is proved by goldens taken from C captures, and one `tests/data` case for the
    lines that carry no descriptor, time or port, on both legs.
    - **a. Captures and design.** **Done.** The C build's traces of each case the step
      reproduces (direct, refused, connect timeout, reuse, `Connection: close`, SOCKS5 and
      5h, CONNECT, a 407 that redials, HAPROXY, a pre-proxy, IPv6 refused beside IPv4, event
      mode), and a C program showing a share's cleanup closes through the creating transfer's
      CLOSESOCKETFUNCTION; ENGINE.md rewritten for the design.
    - **b. `Stream`.** **Done.** TCP_NODELAY set by default, as C does, first. Then one `Stream` (socket
      and receive buffer) owned by `Dialed` and `Conn`, one read path, `RecvBuf::fill`, a read
      over its room an error; the sizes of `ConnSlot` and `Slot` pinned.
    - **c. A lease's home.** **Done.** `Home` stamped by `find` and `add` inside the pool section,
      checked by `release`; `set_home` goes.
    - **d. The closer.** **Done.** `Sock` and `Closer`, captured at `Pool::add` and carried by every
      socket the connection opens; a share's and a multi's idle connections close through it
      at cleanup. Then the 1 KB drain before a clean close.
    - **e. The layer stack.** **Done.** `Layer`, `Below`, `LayerStack` and `LayerCx`; the
      stream reads and writes through it, the pollset passes through it, the health check asks
      `is_alive`, and data pending runs the transfer again; bytes read past a tunnel's answer
      are given first.
    - **f. A drive's context.** **Done.** `ConnCx`, over the step's context, given to each
      drive; the lines step 39 traces still reported through `Progress`.
    - **g. Handshakes in C's order** over the `Dialed` stream. **Done.** The PROXY line before
      the connection is open, SOCKS and the tunnel recorded as made on the dialed connection,
      the order decided in one place.
    - **h. The chain's trace:** SETUP's lines and `cf_setup_connect`, `connected`, `reduced
      to` and `failed to connect`, rendered from the machine's stage. **Done.** A step drives
      the setup for as long as one call of C's connect goes on; a connect under way is polled
      at the next run.
    - **i. The TCP socket's trace** (`cf_socket_open`, local address, `connected`,
      `adjust_pollset`, `poll/select error`, `destroy`) and `Curl_multi_will_close`. **Done.**
      The drive traces its attempts itself, in C's order; `adjust_pollset` goes with j's
      pollset line.
    - **j. The trace of `wait`:** pollsets, `expires in`, `gives multi timeout` and
      `multi_wait`, from a traced internal `multi_timeout`. **Done.** With them the socket's
      `adjust_pollset` lines and event mode's `multi_run_dirty`; its `ev …` lines are not
      traced.
    - **k. The shim's socket hooks:** OPENSOCKETFUNCTION, SOCKOPTFUNCTION and
      CLOSESOCKETFUNCTION (585, 1522, 1530, 1960); the socket options as C sets them (TCP keepalive on
      by default in the tool, `--tcp-nodelay`, `--tcp-fastopen`, `--keepalive*`, `--ip-tos`,
      `--vlan-priority`, `--mptcp`) and their setopts. **Done.** Each socket is opened,
      set and connected in `cf_socket_open`'s order, through the application's opener,
      configurer and closer; the tool sets its flags as `tcp_setopts` does, with its own
      opener for `--mptcp` and configurer for `--ip-tos` and `--vlan-priority`. The waker is
      an eventfd, as C's.
    - **l. Closing the step:** the sabotage sweep over conn, multi and share, and
      cargo-mutants on the step's diff. **Done.** The sweep over the connection, multi,
      share, layer, chain, TCP, wait, socket and pool entries has no hole; cargo-mutants'
      survivors on h–j are tested.
41. **Error codes only the shim produces** in a shim-side enum, before TLS's codes go live.
    **Done.**
42. **HTTP's decisions after an exchange** moved from the engine into `proto/http`. **Done.**
    The protocol decides what follows an exchange as it ends (`ProtoState::exchanged`), and
    what a redirect changes of the next request (`redirected`); the engine keeps C's generic
    follow mechanics. The redirect schemes come from an option with C's default list.
43. **TLS through OpenSSL** (ENGINE.md 4.9 and 4.6's shutdown set). In progress.
    - **a. Captures, the red list and the design.** **Done.** The reference build's traces of
      HTTPS against stunnel and `openssl s_server` (`-k`, verified, a verify failure, wrong
      names, mTLS, pinning, reuse, a resumed session, close_notify, CONNECT and HTTPS proxies,
      engines), each also with `--http1.1`, and lib758's callback sequence; the red list below;
      ENGINE.md and DESIGN.md written for the design.
    - **b. curl-openssl and Ed25519 signatures.** **Done.** openssl-sys 0.9.117, declarations only, never
      `vendored`; OpenSSL 3.0 or later, checked at build and at init; httpsig signs Ed25519
      through the handle's `Libraries` (5000, 5001, 5003–5007, 5011–5014, 5018, 5021–5025).
    - **c. `Closing`.** **Done.** The multi's `ShutdownSet`, its SHUTDOWN deadline, sockets
      owned by a connection and announced with the internal `CURL *`, every discard through
      one path; armed with a test layer whose shutdown waits. No runtests change.
    - **d. TLS in the core.** **Done.** `curl_core::tls` (the seam a library implements),
      `TlsLayer`, `Cold<TlsOptions>`, `TlsIdentity` on `Route` and compared for reuse, `https`
      with a TLS library and the origin's handshake as the setup's last stage, the bytes past a
      tunnel's answer read first, the goodbye through the shutdown set; over `FakeTls`, with an
      HTTPS GET budget of 52 over it. No runtests change: the shim and the tool name no TLS
      library until e1, which also brings the CA default.
    - **e1. The OpenSSL layer and the flip.** The BIO, the context, verification and hostcheck
      (1397), the CA default and store cache, the tool's `-k`, `--cacert`, `--capath`, version
      and cipher options, `curl_global_sslset`; `https`, `SSL` and `OpenSSL/3.5.9` reported.
    - **e2. Client certificates, pinning, CRL, issuer, OCSP stapling, certinfo, engines.**
    - **f. The application's hands on OpenSSL.** `SSL_CTX_FUNCTION`, `TLS_SSL_PTR` and
      `TLS_SESSION`, the retry-verify pause; close_notify as `Closing`'s first producer.
    - **g. ALPN's trace.** HTTPS-CONNECT in the chain, ALPN_EYEBALLS armed where C's
      outstanding HTTPS-RR query arms it (sabotage: arm it for an IP literal or a cached
      name), `query ALPN` on every new connection (step 40's goldens updated), SSL's lines.
    - **h. The session cache**, the share's `SSL_SESSION` kind, `--no-sessionid`, the key log.
    - **i. HTTPS proxy.** `SSL-PROXY`, TLS in TLS, the proxy's TLS options; `HTTPS-proxy`
      reported (1630–1632, 3401).
    - **j. Closing the step.** Torture against the C build on a subset, the budgets, the sweep
      and cargo-mutants.

    Green at the flip (e1) means no test that passed before fails. Measured 2026-10-23 with
    the tool claiming `https`, `SSL` and `OpenSSL/3.5.9`, over the 199 tests that need TLS or
    name it: 1244, 1939, 1941, 1945, 2824 and 4657 then pass already and must stay green, with
    1827, which passes today. The 52 that run and fail, each with what closes it:
    - e1: 94, 300–306, 309–312, 325, 364, 410, 414, 474, 560, 1561, 1562, 1849, 2009–2011,
      2118, 2885, 3000, 3001, 3102, 3106, 3208, 3305, 3611, 5029;
    - e2: 308, 313, 417, 2034, 2035, 2037, 2038, 2041, 2042, 2048, 2088, 2089;
    - f: 758, 1587. h: 2090, 3207. Step 46 (`--libcurl`): 1481, 1679.

    Skipped at the flip by their prechecks: 678 (`CAINFO_BLOB`, e1), 2095 (`SSLCERT_BLOB`,
    e2), 307 (engines, skipped on the C leg too). Skipped for what is built elsewhere: HSTS
    (446, 780–783, 1586, 3109), alt-svc (358, 359) and DoH (2100, 2117), stage 7; Unix sockets
    (1470), step 46; GSS-API (1582) and `crypto` (1647, 1933–1938 and 14 more), step 44;
    `HTTPS-proxy` (1630–1632, 3401) until i; HTTP/2 and HTTP/3, stage 5; the FTP, mail, MQTT
    and Gopher servers and their TLS forms, stage 6; NTLM, Schannel, ECH, `SSLS-EXPORT` (1678)
    and 4656, not in this build. Every one of the 199 that runs on the C leg passes there
    (2095 failed once in that run, 56, and passes alone).
44. **GSS-API** (Kerberos, SPNEGO, `--negotiate`, `--proxy-negotiate`): the Rust build then
    claims them, `crypto` turns on, and `inventory/measure/gated.py` is deleted.
45. **The tool's options that need no new engine work,** built alongside step 40. **Done.**
    `--variable` and the `--expand-` prefix (`tool_vars.c`), `--styled-output`,
    `--fail-early`, `--rate`; `--disallow-username-in-url`, `--speed-limit`, `--speed-time`
    and `--create-file-mode` wired to what the core has; `--retry-connrefused`; the deprecated
    `--random-file` and `--egd-file` as C's no-ops. The socket options are step 40k's.
46. **The tool's larger pieces:** `--libcurl` (`tool_easysrc.c`: the C program a command line
    amounts to; 1400–1404, 1465, 1687 and the other `--libcurl` tests), `--manual` (the
    built-in manual, `tool_hugehelp.c`: 1708, and the hint C's error messages end with),
    `--xattr` (644, 687, 688), and `--parallel` (the tool driving a multi handle; 496). After
    step 40: `--interface` and `--local-port` (a bind before the connect: 1045, 1046,
    1082–1085) and `--unix-socket` and `--abstract-unix-socket` (a connect that is not TCP:
    1268, 1435, 1436). The options still refused that need neither TLS nor a missing
    protocol: `-T .` (uploading standard input without blocking, 1498), `--test-duphandle`,
    `--socks5-basic` and `--socks5-gssapi` (wired to the SOCKS5 methods), `--crlf`,
    `--doh-url` (2101) and the `--dns-*` options (c-ares). Done: `-H @file`,
    `--etag-compare` and `--etag-save`.

After this milestone: **a corpus of real command lines**, as compatibility guidance. Some
thousands of curl invocations sampled from public shell scripts, Dockerfiles, CI configurations
and documentation, kept under `inventory/` with their sources and parsed as a shell would (quotes,
globs, variables). It ranks which options, combinations and spellings are used, to order and
weigh the work, and each line is run through both tools' option parsing, without a transfer, to
diff what they accept, warn about and refuse. It is also the evidence for a difference from C
(DIVERGENCE.md): whether anyone relies on the C behaviour.

Later, with the protocol that needs it: the scheme facts (family, PROTOPT flags, default port)
generated from `gen/schemes.py` rather than copied by hand, by stage 4 at the latest; resting
connect and DO states and connection-scoped protocol state, with the first stage-6 protocol or
STARTTLS; the request renderer writing each part through a field sink, when HTTP/2 starts;
HTTP/2 delivering a sibling stream's data to its transfer at once, as C does, rather than
buffering it per stream; FTP's data connection as a second chain beside the control
connection's, and its FTP_ACCEPT and SERVER_RESPONSE timers traced; `CURLOPT_CONNECT_ONLY`
with the pool's `Reserved` place (3231, 3232, 3234); the pool's `Attached` place for a
connection several transfers lease, before stage 5; with it and HTTP/2, `CURLOPT_PIPEWAIT`:
with `-Z`, C's transfers to one host wait for a connection that may multiplex ("Found pending
candidate for reuse and CURLOPT_PIPEWAIT is set") where the engine opens connections side by
side, `--parallel-immediate` does nothing yet, and C lets one waiting transfer retry per
perform where the engine lets several; ALPN offering `h2`, and TLS early data, with HTTP/2;
`curl_easy_ssls_import` and `export` (`SSLS-EXPORT`, 1678) with stage 7's shared state;
`curl_multi_assign` from a transfer's own handler, if the corpus shows it used.

After the port, as an addition: a rustls backend behind the same `curl_core::tls` traits, to
shrink the C the library depends on.
