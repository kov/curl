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

- **A form part whose file cannot be read fails the transfer, unless its size is known.** A
  part sending a file that is not a regular file, such as `-F a=@dir` or
  `curl_mime_filedata` naming a directory, ends the transfer with 26 (`CURLE_READ_ERROR`) when
  its read fails. C's `mime_file_read` (`lib/mime.c`) passes on `fread`'s short count, which
  reads as the part's end: it sends the part empty, the rest of the form after it, and exits 0.
  Measured against the C build with `-F a=@dir -F b=c`. A regular file, whose size the body's
  length was counted with, ends there as in C, and the body's size check fails it. Pinned by
  `a_file_that_fails_to_read_ends_or_fails` (`crates/curl-core/src/mime/tests.rs`).

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

- **`--parallel` exits with the first failure.** A transfer that fails while more are waiting
  to be added is not forgotten. C's `parallel_transfers` (`src/tool_operate.c:2059`) assigns
  `s->result = add_parallel_transfers(...)` on each pass while transfers are left to add, so a
  failure recorded before that pass is overwritten. `curl -sS -Z --parallel-max 1 -f` with a
  URL answering 404 and then two answering 200 prints the 404's error and exits 0; without the
  cap, or with the failing URL last, it exits 22. Pinned by
  `parallel_transfers_keep_the_first_failure` (`crates/curl-tool/tests/transfers.rs`).

## Loops C never leaves

- **A form part's read function answering -2 fails the transfer.** -2 is
  `CURL_READFUNC_STOP_FILLING`, which no part's read function may give; here it is a read error,
  26 (`CURLE_READ_ERROR`). C's `read_part_content` (`lib/mime.c`) takes it for "nothing now" and
  asks the function again for ever: measured against the C build, the transfer had not returned
  when a 10 s `timeout` killed it. Pinned by `a_part_read_answering_stop_filling_fails`
  (`crates/curl-sys-abi/src/handle_tests.rs`).

## Bodies C cannot send again

- **A form part of nothing is sent again.** A part given a name but no content
  (`curl_mime_addpart` with no `curl_mime_data` or the like) is posted again by a second
  transfer, or by a request sent again, as it was the first time. C gives such a part no seek
  function, so `mime_part_rewind` fails it once it was read: the second `curl_easy_perform`
  of the tree fails with 65 (`CURLE_SEND_FAIL_REWIND`), "Cannot rewind mime/post data".
  Measured against the C build. Pinned by `a_tree_posted_again_starts_over_what_was_reached`
  (`crates/curl-sys-abi/src/handle_tests.rs`) and `a_part_reached_before_starts_over_as_c_s`
  (`crates/curl-core/src/mime/tests.rs`).

## Options C loses

- **A duplicated handle keeps its speed limits.** `curl_easy_duphandle` copies
  `CURLOPT_MAX_RECV_SPEED_LARGE` and `CURLOPT_MAX_SEND_SPEED_LARGE`, and its transfers are
  limited by them. C copies the rates but not the limiters they were set into, so its copy's
  transfers run unlimited but for the cut of each send to the send rate: a 60000-byte
  download at 20000 bytes a second takes 3 s on a handle and none on its copy. Pinned by
  `speed_limits_are_kept_and_copied` (`crates/curl-sys-abi/src/handle_tests.rs`).

## Reads C makes smaller

- **A proxy's answer to `CONNECT` is read in bulk.** The tunnel reads what the socket holds, up
  to 16384 bytes, and keeps what follows the answer in the connection's receive buffer, where
  the transfer through the tunnel reads it first. C's `recv_CONNECT_resp`
  (`lib/cf-h1-proxy.c:520`) reads the answer one byte at a time "to avoid a race condition": its
  filter has no way to hand bytes past the answer back up the chain. The bytes on the wire and
  their order are the same; here there are fewer `recv` calls, and fewer `recv` lines in the
  TCP component's trace: C traces a `recv(len=1)` for each byte of the answer (measured against
  the C build: 19 for `HTTP/1.1 200 OK` and its blank line). To be looked at again against the
  command-line corpus. Pinned by `bytes_after_a_tunnel_s_answer_are_read_first`
  (`crates/curl-core/src/proto/http/tests.rs`).

## Waits C times from the clock's origin

- **A speed limit's first step is a whole second from the first look at it.** Before the body
  starts (`Curl_rlimit_start`), a transfer under `--limit-rate` or `CURLOPT_MAX_RECV_SPEED_LARGE`
  arms its `TOOFAST` timer for the limit's next tokens a second on. C's bucket is never
  initialised (`Curl_rlimit_init`, `lib/ratelimit.c`, has no caller): its time is zero, the origin
  of `CLOCK_MONOTONIC_RAW`, so the first step's end falls at the clock's next whole second, a
  wait anywhere from 0 to 1000 ms that depends on how long the machine has been up (measured
  against the C build: each run's first wait was 1 s less the raw clock's fraction of a second).
  Once the body starts, both buckets start afresh and agree. Matching it would mean timing every
  multi from the raw clock's origin. Pinned by `a_limit_s_first_step_is_a_whole_one`
  (`crates/curl-core/src/proto/http/tests/timer_trace.rs`).

## Input C misreads

- **A zero byte in a config file line ends that line, and nothing else.** C's `get_line`
  (`src/tool_parsecfg.c`) reads in 128-byte `fgets` pieces and takes each as a string: the rest
  of a piece after a zero is lost, its newline with it, so the next line is glued onto this one
  (`write-out "A` NUL, then `-s` on the next line, becomes `write-out "A-s`); and a piece that
  starts with a zero ends the file there, every later line unread. Pinned by
  `a_zero_byte_ends_its_line_alone` (`crates/curl-tool/src/config.rs`).

- **A zero byte in a `-F` header file line ends that line, and nothing else.** The file a form
  part's `headers=@file` names is read with the same `get_line` as a config file
  (`read_field_headers`, `src/tool_formparse.c`), and the rewrite reads it as it reads a config
  file: the rest of a line after a zero is dropped, and the next line is a header of its own.
  In C, `-F 'a=b;headers=@file'` with `X-A: 1` NUL `zz`, then `X-B: 2` sends one header
  `X-A: 1X-B: 2`, and a line starting with a zero ends the file: the headers after it are not
  sent. Measured against the C build. Pinned by `a_zero_byte_ends_its_header_line_alone`
  (`crates/curl-tool/src/form.rs`).

- **A zero byte in a line of a `--url @file` ends that line, and nothing else.** The file of
  URLs is read with the same `get_line` as a config file (`parse_url`, `src/tool_getparam.c`),
  and the rewrite reads it as it reads a config file: the rest of a line after a zero is
  dropped, and the next line is a URL of its own. In C, a file holding
  `http://127.0.0.1:PORT/a` NUL `zz`, then `http://127.0.0.1:PORT/b`, makes one request,
  `GET /ahttp://127.0.0.1:PORT/b`, and a line starting with a zero ends the file: the URLs
  after it are not fetched. Measured against the C build. Pinned by
  `a_zero_byte_ends_its_url_line_alone` (`crates/curl-tool/src/config.rs`).

- **A zero byte in a line of a `-H @file` ends that line, and nothing else.** The file of
  headers `-H @file` and `--proxy-header @file` name is read with the same `get_line`
  (`parse_header`, `src/tool_getparam.c`), and the rewrite reads it as it reads a file of URLs:
  the rest of a line after a zero is dropped, and the next line is a header of its own. In C, a
  file holding `X-Z: a` NUL `zz`, then `X-After: z`, sends one header `X-Z: aX-After: z`, and a
  line starting with a zero ends the file: the headers after it are not sent. Measured against
  the C build. Pinned by `a_zero_byte_ends_a_header_file_line_alone`
  (`crates/curl-tool/src/config.rs`).

- **Blanks after the last signed component are blanks.** `--httpsig-headers "method  "`
  (`CURLOPT_HTTPSIG_HEADERS`), with more than one blank after its last component, fails in C
  with `httpsig: too many signature components (max 16)`: `parse_components`
  (`lib/http_httpsig.c`) leaves its cursor on the second blank when it stops at the end, and
  reads anything under the cursor as a seventeenth component. Here the components are signed;
  a seventeenth is refused as in C. Measured against the C build: `"method "` signs, `"method  "`
  fails with 43. Pinned by `signs_the_components_named`
  (`crates/curl-core/src/proto/http/httpsig/tests.rs`).

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

- **The form API refuses or leaves empty what C dereferences as NULL.** `curl_formadd` given a
  NULL `CURLFORM_FILENAME` or `CURLFORM_BUFFER` returns `CURL_FORMADD_NULL`, as it does for
  other NULL values; C takes the length of the NULL and crashes. A `CURLFORM_CONTENTTYPE` given
  after a field's last `CURLFORM_FILE` makes a part with that type and no file; sending the
  form, or `curl_formget`, then gives it no content, where C compares the missing file name
  with `-` and crashes. Both crashes measured against the C build. Pinned by
  `formadd_refuses_as_c_does` and `a_type_past_the_last_file_is_a_part_without_content`
  (`crates/curl-sys-abi/src/formdata.rs`).

## Handles the application never made

- **The connection lock at share cleanup is called with no handle.** When `curl_share_cleanup`
  closes the share's connections, the lock and unlock functions get NULL for the handle; C
  gives them the share's internal admin handle, an easy handle the application never created.
  Pinned by `a_share_is_held_and_locked_as_in_c` (`crates/curl-sys-abi/src/handle_tests.rs`).
