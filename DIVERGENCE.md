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

- **The origin's Negotiate token goes through a tunnel.** `curl -p -x proxy --negotiate URL`
  sends the origin `Authorization: Negotiate` with the request the tunnel carries. C's
  `CONNECT` makes the origin's authentication too (`Curl_http_output_auth` with `is_connect`
  runs both sides): the origin's first token is made then, sent nowhere, and its state is left
  done, so the request through the tunnel goes without it and the 401 that follows ends the
  transfer, its empty challenge read as a refusal; C then traces "Server auth using Negotiate"
  twice and exits 0 with the 401's body. Measured against the C build with its GSS-API stub.
  Pinned by `the_origin_s_token_goes_through_the_tunnel`
  (`crates/curl-core/src/proto/http/tests/negotiate.rs`).

- **A file of lines that cannot be read fails the command line.** A file read a line at a
  time, `-K file`, `--url @file`, `-H @file`, `--proxy-header @file` or `-F
  'name=value;headers=@file'`, that opens but fails a read, such as a directory, fails the way
  each option fails a line C's `my_get_line` (`src/tool_parsecfg.c`) sets its error flag for:
  an error reading a file (exit 26), and for `-F` `Failed to read field headers` and a bad use
  of the option (exit 2). C's `get_line` takes the failed `fgets` for the end of the file:
  `curl -K dir URL`, `curl --url @dir URL`, `curl -H @dir URL` and `curl -F
  'a=b;headers=@dir' URL` fetch `URL` and exit 0, the file read as empty. Measured against the
  C build. Pinned by `a_file_of_lines_that_cannot_be_read_fails`
  (`crates/curl-tool/tests/transfers.rs`) and `a_header_file_that_cannot_be_read_is_refused`
  (`crates/curl-tool/src/form.rs`).

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

- **`--silent` keeps an upload of standard input without blocking quiet.** `curl -s -T . URL`
  draws no progress meter. To let the paused upload go on, C's tool sets `CURLOPT_NOPROGRESS`
  to 0 with a progress callback (`tool_readbusy_cb`, `src/tool_cb_rea.c`) that has the library
  draw its meter unless `--no-progress-meter` or output to a terminal says not to: `--silent`
  is not counted, and C draws the meter on standard error under `-s`. Measured against the C
  build. Pinned by `a_silent_upload_of_standard_input_draws_no_meter`
  (`crates/curl-tool/tests/http.rs`).

## State C carries across transfers

- **`--etag-compare` sends one `If-None-Match:` a transfer.** Each transfer of a URL pattern
  reads the file again and sends its ETag once. C's `etag_compare` (`src/tool_operate.c`) adds
  the header to the operation's own list, `add2list(&config->headers, header)`, for every
  transfer it makes, so the n-th transfer of `curl 'http://h/{x,y}' --etag-compare f` sends n
  of them, the earlier files' ETags first. Measured against the C build. Pinned by
  `each_transfer_compares_one_etag` (`crates/curl-tool/tests/http.rs`).

- **An `--etag-save` file that does not open passes over its operation.** The warning is
  given, the rest of the operation's URLs are not transferred, and the next operation runs as
  given; with none, `no transfer performed` and exit 26 as in C. C's `single_transfer` breaks
  out leaving the operation's URL walk (`state->urlnode`) where it was: the next operation's
  options are applied to this one's URL, and its own URLs are not reached. `curl --etag-save
  nowhere/t http://a/ --next http://b/` warns, then fetches `http://a/` with the next
  operation's options and says `(3) URL using bad/illegal format or missing URL` instead of
  fetching `http://b/`; with a pattern, `http://a/{x,y}`, it exits 3 without a word. Measured against the C build.
  Pinned by `an_etag_file_that_does_not_open_passes_over_its_urls`
  (`crates/curl-tool/tests/http.rs`).

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

- **`CURLOPT_SSLVERSION` refuses a newest version of SSL 2 or 3.** `Curl_setopt_SSLVERSION`
  (`lib/setopt.c`) refuses SSL 2 and 3 as the oldest version but takes them as the newest
  (`CURL_SSLVERSION_MAX_*` has no such value; `2 << 16` and `3 << 16` pass its range check), and
  the transfer then fails its handshake, `CURL_SSLVERSION_MAX incompatible with
  CURL_SSLVERSION`, unless the oldest is `CURL_SSLVERSION_TLSv1`, when OpenSSL is given no
  newest at all. Measured against the C build: the option returns 0 and the transfer fails with
  35. Here the option is refused with `CURLE_BAD_FUNCTION_ARGUMENT`, as the same values are as
  the oldest. Pinned by `tls_options_are_kept_as_c_keeps_them`
  (`crates/curl-sys-abi/src/handle_tests.rs`).

## Undefined behaviour in C, defined here

- **A blob option's bytes are copied, `CURL_BLOB_NOCOPY` or not.** C keeps the application's
  pointer for a `CURL_BLOB_NOCOPY` blob (`Curl_setblobopt`, `lib/setopt.c`) and reads it when it
  uses the option: memory freed before then is read after its free, and bytes changed before
  then are the ones used. Here the bytes are copied as the option is set, so the bytes given
  are the ones used. Pinned by `tls_options_are_kept_as_c_keeps_them`
  (`crates/curl-sys-abi/src/handle_tests.rs`).

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

## Codes C passes through

- **An `SSL_CTX` function's code that no transfer ends with is an abort.** A
  `CURLOPT_SSL_CTX_FUNCTION` that returns a code fails the transfer with it, as in C, when the
  code is one a transfer can end with. C returns any other code as the transfer's result too:
  measured against the C build, 1000 from the function is 1000 from `curl_easy_perform`, and
  `CURLE_UNKNOWN_OPTION` is 48; `CURLE_AGAIN` trips an assertion in `Curl_ossl_ctx_init` on the
  debug build. A transfer's result here is one of the codes it can end with, so such a code
  fails it with `CURLE_ABORTED_BY_CALLBACK`, as a callback that stopped it, with C's `error
  signaled by SSL ctx callback`. Pinned by `a_function_s_code_is_the_transfer_s_if_it_can_be`
  (`crates/curl-sys-abi/src/tls.rs`) and `the_ssl_ctx_function_s_code_fails_the_transfer`
  (`crates/curl-sys-abi/src/tls_tests.rs`).

## Handles the application never made

- **The connection lock at share cleanup is called with no handle.** When `curl_share_cleanup`
  closes the share's connections, the lock and unlock functions get NULL for the handle; C
  gives them the share's internal admin handle, an easy handle the application never created.
  Pinned by `a_share_is_held_and_locked_as_in_c` (`crates/curl-sys-abi/src/handle_tests.rs`).
