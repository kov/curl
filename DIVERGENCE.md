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

- **A send limit does not cut a `file://` upload short.** The whole body is written to the file
  whatever `CURLOPT_MAX_SEND_SPEED_LARGE` or `--limit-rate` says. C's `file_upload`
  (`lib/file.c`) reads through the limit, takes the read it refuses once a second's worth is
  spent for the end of the body, and succeeds with the file truncated: `curl --limit-rate 1000
  -T` a 5000-byte file to `file://` writes 1000 bytes and exits 0. Pinned by
  `a_send_limit_does_not_cut_an_upload_short` (`crates/curl-core/src/proto/file/tests.rs`).

- **An environment variable whose copy cannot be allocated is out of memory.** The proxy
  variables (`http_proxy`, `NO_PROXY` and the rest), `NETRC` and `HOME` for the `.netrc` file,
  and the tool's `CURL_HOME`, `XDG_CONFIG_HOME` and `IPFS_PATH` are copied as they are read; a
  copy refused fails the transfer or the command with `CURLE_OUT_OF_MEMORY`. C's `curl_getenv` returns NULL then, which reads as unset: a proxy the
  environment names is passed over and the transfer goes direct. Pinned by
  `a_refused_copy_is_out_of_memory` (`crates/curl-os/tests/env_oom.rs`) and
  `finds_the_file_as_c` (`crates/curl-core/src/netrc.rs`).

## Options C loses

- **A duplicated handle keeps its speed limits.** `curl_easy_duphandle` copies
  `CURLOPT_MAX_RECV_SPEED_LARGE` and `CURLOPT_MAX_SEND_SPEED_LARGE`, and its transfers are
  limited by them. C copies the rates but not the limiters they were set into, so its copy's
  transfers run unlimited but for the cut of each send to the send rate: a 60000-byte
  download at 20000 bytes a second takes 3 s on a handle and none on its copy. Pinned by
  `speed_limits_are_kept_and_copied` (`crates/curl-sys-abi/src/handle_tests.rs`).

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

- **An empty query key is signed as nothing.** AWS SigV4 (`--aws-sigv4`, `CURLOPT_AWS_SIGV4`)
  signs a query part with an empty key, `?=x`, as `=x` in its canonical query. C passes the
  empty key's buffer, NULL, to a `%s` (`canon_query`, `lib/http_aws_sigv4.c`), which its printf
  writes as `(nil)`: it signs `(nil)=x`, a request no server computes the same signature for.
  Measured against the C build: its string to sign for `GET /f?=x` hashes the canonical request
  with `(nil)=x`. Pinned by `canonical_queries_as_unit_1980`
  (`crates/curl-core/src/proto/http/sigv4/tests.rs`).

## Handles the application never made

- **The connection lock at share cleanup is called with no handle.** When `curl_share_cleanup`
  closes the share's connections, the lock and unlock functions get NULL for the handle; C
  gives them the share's internal admin handle, an easy handle the application never created.
  Pinned by `a_share_is_held_and_locked_as_in_c` (`crates/curl-sys-abi/src/handle_tests.rs`).
