# Where the rewrite differs from C

The rewrite does what the C does, except where the C's behaviour is a clear bug (see
`CLAUDE.md`), is undefined by its API, or hands out something the rewrite does not have. Each
such difference is deliberate and permanent, and is listed here with the test that pins it: the
test asserts the rewrite's behaviour and its comment says what C does. Behaviour not built yet is
not a difference: it is tracked in `MILESTONES.md`.

## Failures C reports as success

- **An upload that cannot be read fails.** `curl -T dir URL`, or any upload whose file fails a
  read, exits 26 (`CURLE_READ_ERROR`). C's tool takes the failed read for the end of the file,
  sends what it has (nothing, for a directory) and exits 0. A sample of 161 shell scripts on
  GitHub using `-T` (measured 2026-10-21) had no argument that could name a directory. Pinned by
  `an_upload_that_cannot_be_read_fails` (`crates/curl-tool/tests/transfers.rs`).

- **A `file://` download whose read fails is a read error.** A `read()` failing anywhere in the
  file, or a `readdir()` failing partway through a directory listing, ends the transfer with 26
  (`CURLE_READ_ERROR`). C's `file_do` (`lib/file.c`) takes either for the end of the data and
  succeeds with a truncated body: `curl file:///proc/self/mem` exits 0 with an empty body.
  Pinned by `a_file_that_cannot_be_read_fails`, `a_read_failing_partway_fails` and
  `a_listing_failing_partway_fails` (`crates/curl-core/src/proto/file/tests.rs`).

## Input C misreads

- **A zero byte in a config file line ends that line, and nothing else.** C's `get_line`
  (`src/tool_parsecfg.c`) reads in 128-byte `fgets` pieces and takes each as a string: the rest
  of a piece after a zero is lost, its newline with it, so the next line is glued onto this one
  (`write-out "A` NUL, then `-s` on the next line, becomes `write-out "A-s`); and a piece that
  starts with a zero ends the file there, every later line unread. Pinned by
  `a_zero_byte_ends_its_line_alone` (`crates/curl-tool/src/config.rs`).

## Undefined behaviour in C, defined here

- **A header pointer libcurl did not hand out leads nowhere.** `curl_easy_nextheader` given a
  `prev` that is not a header it returned, such as a copy of one, returns NULL; C reads its
  internal anchor through whatever the pointer points at. Pinned by
  `headers_are_looked_up_and_walked_as_in_c` (`crates/curl-sys-abi/src/handle_tests.rs`).

- **A header cursor from an earlier transfer leads nowhere**, where C reads the freed header
  store. Pinned by `a_cursor_from_an_earlier_transfer_leads_nowhere`
  (`crates/curl-core/src/report/headers.rs`).

## Handles the application never made

- **The connection lock at share cleanup is called with no handle.** When `curl_share_cleanup`
  closes the share's connections, the lock and unlock functions get NULL for the handle; C
  gives them the share's internal admin handle, an easy handle the application never created.
  Pinned by `a_share_is_held_and_locked_as_in_c` (`crates/curl-sys-abi/src/handle_tests.rs`).
