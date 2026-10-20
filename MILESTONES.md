# Milestones

The order the engine is built in, as commit-sized steps. `ENGINE.md` holds the design they
implement. Each step records its status: **done** (with the commit), **in progress**, or
**to do**. When a step lands, is split, or is reordered, this file changes in the same commit,
along with the tests it flipped as `runtests.pl` reported them.

## Milestone 1: `file://`, then HTTP/1.1 GET

Status: steps 1 and 2 are **done**; every other step is **to do**.

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
3. **url: add the Url type and a parser for the milestone's subset**: `file:` paths, scheme
   guessing (22), empty path to "/", query without path (59, 260), fragment dropped (1109),
   userinfo (367), unsupported scheme as UnsupportedProtocol (23). The covered rows of unit
   1560 are generated into a table; the ported-test checker reports 1560 as partial.
4. **core: add Deadlines, TimerQueue and TimerAnnounce.** Ports unit 1309 (against the queue's
   insert/best/remove), unit 1303 (connect versus total, each from its own anchor), and unit
   3230 (table generated from the C test). A test pins that a follow keeps `started_op` and
   resets `started_single`.
5. **multi: add the transfer state machine with a null protocol.** `Multi`, `Slot`, `Run`,
   `TransferState`, `Sched`, `NotifyQueue`, the three contexts, `add`/`remove`/`perform`/
   `socket_action`/`info_read`/`counts`, `drive_to_completion`, a test-only protocol that
   completes immediately, `FakeNet`, `RecordingEvents`. Tests: info_read order; remove twice
   (3105 semantics); the timer callback inside `add` and `remove`; the dead multi (530/758
   semantics); generation tests for notifications and the timer queue; property tests for the
   invariants; the add/perform/remove torture scenario.
6. **os: add sockets, polling and the waker.** `curl-os` `net.rs`, `poll.rs`, `wake.rs`, with the
   CLAUDE.md unsafe list updated in the same commit; core
   `SystemNet`; `Multi::wait`/`poll`/`fdset`/`waitfds`/`waker`. Loopback tests for
   connect-in-progress, EOF and would-block.

**`file://` end to end**

7. **deliver: add the pipeline, client output and pause.** `Pipeline` (raw trace, accountant,
   `ClientOut` Direct/Held/Failed), `Pause`, `Upload` with rewind and resume, `Timings`, `Sizes`,
   progress and the meter, `TransferReport`, `HeaderStore`. Ports units 1399, 1606, 1636. Tests:
   16 KiB pieces; header lines whole; `-i` order; `Failed` is terminal; a handler replaced inside
   its own call; pause and replay with interleaving (3235/3236 shapes); getinfo inside callbacks;
   the pause torture scenario.
8. **proto: add file:// and Easy::perform.** `proto/file.rs` (no pause support: PAUSE is a
   WriteError, READFUNC_PAUSE a ReadError), the private multi, `version` reporting `file`. Tests:
   a networkless `Easy::perform` of a file URL, upload and resume.
9. **tool: run file:// transfers through the core.** Map `Operation` to `Easy`: the URL,
   `-o`, `-i`, `-s`/`-S`, `-v`, `--trace-ascii`/`--trace`/`--trace-time` with
   `tool_cb_dbg.c`'s format, the exit code and the "curl: (N) msg" line, `-C`, `-T`, `-w` for the
   fields the file tests use. Measure the tool's whole-process allocation count for a file
   transfer and record it. Flips: 200, 201, 203, 1145, 1146, 1220, 2071, 2072, 231, 3016, 3203,
   1445, 1491; then 204, 205, 1490 (upload); then 1440, 1441, 1442 (`-w`). 202 waits for
   multi-URL support.
10. **abi: add easy and multi handles.** `ShimEasy`, `ShimMulti`, the `with_multi`/`with_easy`
    gate, `TABLE` generated from `lib/api.c` with its comparison test, `ShimEvents`, the callback
    adapters, generated setopt for the options so far, getinfo, `curl_easy_perform`, `pause`,
    `perform_ev`, the multi entry points. Flips: 1508, 3105, 1564, 2414 (and any `file://`-only
    libtests the inventory lists).

**HTTP/1.1 GET**

11. **conn: add the pool, leases and plain TCP connections.** `ConnSlot`, `Conn`, `Route`,
    `ConnLease`, `Pool` with the four lock points (a recording `Lock` test pins the 1554
    sequence), `ConnectMachine` with `Resolving` (`Literal`) → `Racing` (one attempt) →
    established, socket open and close order, `ShutdownSet`. `FakeNet` tests: refusal ("Failed
    to connect to … after N ms"), connect timeout under `ManualClock`, REMOVE before the close
    hook.
12. **http1: render requests behind the credential gate.** `RequestHead`, `UserHeaders`,
    `render_h1`, `CredentialGate`. Fixture tests compare byte-exactly with the `<protocol>` of 1,
    14, 47, 461, 1121, 1292.
13. **http1: parse responses and decide framing.** `ResponseHeadParser`, `decide_framing`,
    `ChunkDecoder`, trailers, GOT_NOTHING, every limit. Byte-fed tests at every split point from
    the fixtures of 1274, 1430–1433, 1466, 365, 2918, 1722, 1723, 2119, 772, 773, 497, 747, 1154,
    34, 36, 207, 1416, 1417, 2106. Ports units 1625, 1626.
14. **http1: generate the fixture runner from tests/data.** The milestone set's cases without
    servercmd, driven over `FakeNet` and `ManualClock`; armed by breaking a framing rule. Adds the
    plain-GET allocation budget test, set at this design's count.
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
