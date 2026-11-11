# Where the rewrite differs from C

The rewrite does what the C does, except where the C's behaviour is a clear bug (see
`CLAUDE.md`), is undefined by its API, or hands out something the rewrite does not have. Each
such difference is deliberate and permanent, and is listed here with the test that pins it: the
test asserts the rewrite's behaviour and its comment says what C does. Behaviour not built yet is
not a difference: it is tracked in `MILESTONES.md`. The last two sections are the exception, and
say so: differences found and not yet brought to C's, and weaknesses kept because C has them.

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

- **`-f` keeps a failure it gives up retrying for its wait.** With `--fail` or
  `--fail-with-body`, `--retry` and `--retry-max-time`, a response that would be tried again
  but whose `Retry-After:` would go past the limit fails the command, 22, as the same response
  does with no retries left. C's `retry_sleep` (`src/tool_operate.c`) gives up the retry there
  and `retrycheck` returns `CURLE_OK`, so after `curl: (22) The requested URL returned error:
  503` C exits 0, and `%{exitcode}` says 0. Measured against the C build with `curl -sS -f
  --retry 3 --retry-max-time 10` and a 503 with `Retry-After: 60`. Pinned by
  `a_failure_not_retried_for_its_wait_still_fails` (`crates/curl-tool/tests/http.rs`).

- **IMAP output paused as a fetched message came whole is delivered.** When a FETCH's whole
  literal arrives with its line and the write callback pauses on it, the transfer stays in its
  exchange until the application unpauses, and the held body is then written. C has nothing to
  exchange after DO there (`Curl_xfer_setup_nop`), goes from DID to DONE, and drops what the
  writer holds: the transfer reports success with 0 bytes written after the unpause. Measured
  against the C build with a C program. Pinned by `a_paused_body_holds_the_transfer_open`
  (`crates/curl-core/src/proto/imap/tests/over_the_wire.rs`).

- **A resumed upload with no seek function sends the bytes after its point.** An FTP or SFTP
  upload resumed at an offset (`CURLOPT_RESUME_FROM_LARGE`) whose application set no
  `CURLOPT_SEEKFUNCTION` has the bytes before the point read and dropped, as when the seek
  function answers `CURL_SEEKFUNC_CANTSEEK`. C seeks nothing and reads nothing then, so the
  stream's first bytes are stored at the resume point and the remote file is silently wrong:
  measured against the C build, a resume at 20 stored bytes 0 to 20 there. Pinned by
  `a_resumed_body_asks_the_seek_function` (`crates/curl-sys-abi/src/handle_tests.rs`), its run
  without a seek function.

## Loops C never leaves

- **A form part's read function answering -2 fails the transfer.** -2 is
  `CURL_READFUNC_STOP_FILLING`, which no part's read function may give; here it is a read error,
  26 (`CURLE_READ_ERROR`). C's `read_part_content` (`lib/mime.c`) takes it for "nothing now" and
  asks the function again for ever: measured against the C build, the transfer had not returned
  when a 10 s `timeout` killed it. Pinned by `a_part_read_answering_stop_filling_fails`
  (`crates/curl-sys-abi/src/handle_tests.rs`).

- **A GSS-API status the library has no words for is said without them.** SOCKS5's GSS-API
  method lays a failed call's status out as `check_gss_err` does (`lib/socks_gssapi.c`), the
  major code's text, `.\n`, the minor code's; for each it asks `gss_display_status` once. C asks
  again while the call fails and says no more follows (`while(!msg_ctx)`), which is for ever for
  a minor code the library does not know: measured against the C build with its GSS-API stub,
  whose `C` answer to a Kerberos context fails with such a code, the transfer had not returned
  when a 10 s `timeout` killed it. Here it fails, 97, the minor code's text empty. Pinned by
  `a_status_without_words_is_said_without_them` (`crates/curl-gssapi/tests/socks.rs`). MIT
  krb5's alone: GNU GSS has words for the stub's code, and C's GNU GSS build says them and
  fails, 97, as here (measured 2026-11-07).

- **An SFTP upload with `--ftp-create-dirs` makes the directories once.** When the file
  cannot be opened, the directories up to it are made, and an open refused again fails the
  upload, as C's libssh2 code does (`secondCreateDirs`, `lib/vssh/libssh2.c:1022`). C's libssh
  code, whose library the rewrite binds, sets the same flag (`lib/vssh/libssh.c:1087`) and never
  reads it, so a server that keeps refusing the file is asked to make the directories again
  for as long as it refuses. Measured 2026-11-01 on C's libssh build, uploading to a path
  that is a directory, which OpenSSH's server refuses with `SSH_FX_FAILURE`: 4900 rounds in 5 s,
  when `timeout` killed it; here one round, exit 79. Pinned by
  `a_file_refused_again_is_not_tried_again` and `missing_directories_are_made_once`
  (`crates/curl-core/src/proto/ssh/tests.rs`).

## Waits C makes blocking

- **SOCKS5's GSS-API messages are sent and read as the socket lets them.** C makes the socket
  blocking for the whole RFC 1961 exchange (`Curl_SOCKS5_gssapi_negotiate`, then
  `Curl_blockread_all` for each reply), so every other transfer of the multi waits on the proxy
  until it answers or the transfer's time runs out. Here each message is a state of the SOCKS
  handshake, sent and read without blocking, the other transfers going on meanwhile. The bytes
  on the wire, the lines said, and a read whose time runs out failing the method (97, "Failed
  to receive GSS-API authentication response.") are C's, measured against the C build with its
  GSS-API stub and a hand-rolled RFC 1961 proxy. Pinned by
  `a_socks5_proxy_authenticates_by_gss_api` and
  `an_unanswered_message_fails_its_read_when_the_time_is_out`
  (`crates/curl-core/src/proto/http/tests/socks_gss.rs`).

- **IMAP's answer after a FETCH or an APPEND, SMTP's after a mail's body, and FTP's after a
  transfer's data and after each command that follows it, are awaited without stalling the
  multi.** C reads the tagged answer that follows a fetched literal, or an APPEND's body and its
  empty line, in `imap_done`, the answer to a mail's body and its end-of-data dot in
  `smtp_done`, and FTP's 226 and the answers to `-Q -command`s in `ftp_done`, blocking
  (`imap_block_statemach`, `smtp_block_statemach`, `getftpresponse`, `ftp_sendquote`), so every
  other transfer of the multi waits on the server. Here the transfer waits in DONE
  for what the answer's read waits for, the others going on meanwhile; the bytes on the wire,
  the trace but for the wait's pollset lines, the progress meter, the timing and the result
  are C's. Measured against the C build with `curl -Z` and a server that answers a second
  late: C's `LIST` beside an APPEND took 1.003 s, ours 1.5 ms; C's `VRFY` beside a mail, to a
  server that greets half a second late, took 1.005 s, ours 0.504 s; measured 2026-10-30, C's
  FTP download beside one whose 226 comes a second after its data, from a server greeting it
  half a second late, took 1.051 s, ours 0.551 s. FTP's TLS handshakes, which C makes
  blocking (`Curl_conn_connect` with `blocking`), wait the same way: the control connection's
  after `AUTH` is taken (`ftp_state_auth_resp`), and a protected data connection's
  (`ftp_initiate_transfer`); each waits for the server's flight as a connection's own
  handshake does, the other transfers going on meanwhile. Their bytes on the wire and their
  result are C's, and so is what the end of C's connect says: the handshake's time
  (`PGRS-APPCONNECT`, `%{time_appconnect}`), "Established connection" again for the control
  connection and "Established 2nd connection" for the data, after the handshake. The control
  connection's connect also says each of its calls, `Curl_conn_connect(block=1) -> 0, done=0`,
  and once done the chain it says `connected` and `reduced to`. Not said are the blocking
  connect's waits, `do poll` and `Curl_poll() -> 1`, which the multi's pollset and wait lines
  stand in for; their timing was not measured against the C build. As C's blocking connect
  polls the data connection alone, so does the transfer's pollset while a passive data
  connection's handshake waits: input the control connection's TLS holds unread is no reason
  to run again (`a_data_connection_s_handshake_waits_on_it_alone`). A resolve of the data
  connection's name still going on through its handshake is looked at in each call, as C's
  DNS filter does, but C's threaded resolver hands its answers over only in the multi's own
  run (`Curl_async_thrdd_multi_process`, with `ENABLE_INTERNAL_WAKEUP`), never inside the
  blocking connect: an AAAA answered meanwhile is not taken, and goes with the filter as the
  chain connects. Ours takes it and says it (`Host ... was resolved.`), as C does over c-ares;
  `a_data_connection_s_late_resolve_lasts_through_its_tls` pins it.
  The same holds for the goodbye on a closing connection: FTP's, POP3's and SMTP's `QUIT` and
  IMAP's `LOGOUT` await a reply as C's do, but in the shutdown set, the other transfers going
  on meanwhile. So an application driving the multi by its socket callback may be told to
  watch a plain control connection for input while it waits, and hears its removal later,
  where C closes it before DONE ends. Both give up after a second with nothing more of the
  answer, and within the shutdown's 2 s. What ends the wait differs: C's FTP, SMTP and IMAP
  waits end at the first byte that can be read, which they leave unread (their state machines
  fail without the transfer's state, `FAILED_INIT`), where ours read a whole reply, IMAP's the
  tagged one after its `BYE`; C's POP3 reads a whole reply, as ours does. A whole reply is read
  no further than 64 KB, as much as C holds of one (`DYN_PINGPPONG_CMD`): past that the
  connection closes with the rest unread, as C's does after the first byte. Measured against
  the C build: a silent server is let go after 1.03 s, a partial reply at once by C's FTP,
  SMTP and IMAP, and a reply streamed without end after its first byte. A connection awaiting
  its answer stays in the set past the set's cap, which C's never meets, up to twice the cap;
  past that, and where there is no set or no memory to grow it, the answer is waited for in
  place, blocking the multi as C does. A new connection that needs the room such a connection
  holds under `CURLMOPT_MAX_TOTAL_CONNECTIONS` or the host limit waits for the answer where C
  blocks for it: measured with a limit of 1 and a server answering `QUIT` half a second late,
  C connects to the next host just after the answer, as ours does, but its multi is blocked
  meanwhile. Pinned by
  `a_transfer_needing_room_waits_for_the_answer_to_quit`,
  `an_endless_answer_to_quit_is_read_no_further_than_64_kb`
  (`crates/curl-core/src/proto/ftp/tests.rs`),
  `a_full_set_keeps_those_awaiting_an_answer_to_twice_its_cap`,
  `room_held_by_a_goodbye_awaiting_its_answer_is_waited_for`
  (`crates/curl-core/src/multi/shutdown_tests.rs`), and
  `quit_waits_a_second_for_its_answer`
  (`crates/curl-core/src/proto/pop3/tests.rs`,
  `crates/curl-core/src/proto/smtp/tests/over_the_wire.rs`),
  `logout_waits_for_its_tagged_answer_past_its_bye`
  (`crates/curl-core/src/proto/imap/tests/over_the_wire.rs`),
  `quit_waits_for_an_answer_no_longer_than_a_second_of_silence`
  (`crates/curl-core/src/proto/ftp/tests.rs`), and by
  `an_answer_awaited_in_done_stalls_no_other_transfer`
  (`crates/curl-core/src/proto/imap/tests/over_the_wire.rs`,
  `crates/curl-core/src/proto/smtp/tests/over_the_wire.rs` and
  `crates/curl-core/src/proto/ftp/tests.rs`), and by
  `a_handshake_after_auth_stalls_no_other_transfer`,
  `a_data_connection_s_handshake_stalls_no_other_transfer` and
  `quit_awaiting_its_answer_stalls_no_other_transfer`
  (`crates/curl-core/src/proto/ftp/tests.rs`).

- **A TELNET exchange leaves the multi's other transfers moving.** C runs the whole exchange
  in `telnet_do`, polling in its own loop until the server closes (`lib/telnet.c`), so every
  other transfer of the multi waits for it. Here each pass of that loop is a step of the
  transfer's DO, the others going on meanwhile. Measured 2026-11-01 with `curl -Z` and a
  TELNET server that closes after a second, beside an HTTP server that answers in 0.3 s: the
  HTTP transfer took 1.304 s on C's build, 0.301 s here. Pinned by
  `an_exchange_stalls_no_other_transfer` (`crates/curl-core/src/proto/telnet/tests.rs`).

- **Schannel's sends and renegotiations wait without stalling the multi.** C's
  `schannel_send` sends each record whole, waiting on the socket (`SOCKET_WRITABLE` with the
  transfer's time left) whenever it takes only part, and `schannel_recv_renegotiate` waits on
  the socket, up to `MAX_RENEG_BLOCK_TIME`, for the direction the renegotiation needs (TLS
  1.3's tickets take every connection through it), so every other transfer of the multi waits
  for the peer meanwhile. Here the session keeps what is left of the record, or where the
  renegotiation stands, says what it waits for, and is called again once the socket is ready:
  the rest of the record goes before anything else, and the renegotiation's own time limit and
  failure text are C's. The bytes on the wire are C's; the waits are not timed against C's
  build. The renegotiation's wait has no test of its own. Pinned by
  `a_record_half_sent_is_waited_for_by_the_multi` (`crates/curl-schannel/tests/peer.rs`,
  Windows only).

- **The wait for TLS to end after FTP's `CCC` leaves the multi's other transfers moving.** C
  waits in `Curl_ssl_cfilter_remove` (`vtls_shutdown_blocking`), so every other transfer of the
  multi waits on the server's close_notify. Here it waits in the state after `CCC`, for what
  the shutdown waits for, the others going on meanwhile. The commands that follow and the
  result are C's. Measured 2026-11-01 with `curl -Z`, active `CCC` and a server whose
  close_notify comes a second after its answer, beside an HTTP server that answers in 0.3 s:
  the HTTP transfer took 1.007 s on C's build, 0.303 s here, both downloads then sending `PWD`,
  `EPSV`, `PASV`, `QUIT` and exiting 13. Pinned by `a_ccc_s_shutdown_stalls_no_other_transfer`
  (`crates/curl-core/src/proto/ftp/tests.rs`).

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

- **A read-only HSTS file is not written.** With `CURLOPT_HSTS_CTRL` set to `CURLHSTS_ENABLE |
  CURLHSTS_READONLYFILE`, the file named by `CURLOPT_HSTS` is read and never written back, as
  the option's documentation says; a copy of the handle keeps the mode. C's `Curl_hsts_save`
  tests the flag, but `CURLOPT_HSTS_CTRL` never sets it, so cleanup rewrites the file:
  measured against the C build, a file holding a comment and no entries is replaced by C's
  two-line header. Pinned by `a_read_only_file_is_not_written_back`
  (`crates/curl-core/src/proto/http/tests/hsts.rs`) and `a_read_only_hsts_file_is_not_written`
  (`crates/curl-sys-abi/src/handle_tests.rs`).

- **A duplicated handle keeps its alt-svc control.** `curl_easy_duphandle` of a handle with
  `CURLOPT_ALTSVC_CTRL` set gives a copy whose cache behaves the same: a read-only file stays
  unwritten, and only the versions allowed are taken. C's copy makes its cache with the default
  control (`Curl_altsvc_init` in `curl_easy_duphandle`), so a copy of a handle told not to write
  its file writes it as it goes. Pinned by `a_read_only_file_is_kept_and_a_copy_reads_the_file`
  (`crates/curl-core/src/proto/http/tests/alt_svc.rs`).

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

- **On Windows, every `-T .` of a run reads standard input's one relay.** The first sets up
  the thread that reads standard input into a loopback connection, and each later `-T .` reads
  the same connection, so what the thread has read goes to the next upload. C keeps the
  connection's reading socket in a static (`win32_stdin_read_thread`, `src/tool_doswin.c`) and
  hands it to each `-T .`, but closes it as each transfer ends (`post_per_transfer`'s
  `sclose(per->infd)`): the next `-T .` is handed the closed socket, warns `fcntl failed on
  fd=N: No such file or directory`, reads it as ended and uploads nothing, and a socket opened
  meanwhile may have been given the same number. Uploading standard input with
  `-T .` first to `file:///C:/no/such/x` and then to `file:///C:/t/dst` in one run leaves
  `dst` empty on C's Windows build and holds the input here.
  Measured against the C build on Windows. Pinned by
  `a_second_upload_of_standard_input_reads_what_the_first_left`
  (`crates/curl-tool/tests/http.rs`).

- **A connection a 101's body ended by closing is not kept.** A 101 nothing asked to upgrade
  to is the final response, and its body runs until the server closes the connection; the
  rewrite then drops the connection and traces `shutting down connection #0`. C's
  `http_on_101_upgrade` (`lib/http.c`) accepts the 101 with `k->header = FALSE` and returns
  before the response's end is worked out, so nothing marks the connection for closing: it
  goes back to the pool, closed by the server, with `Connection #0 to host ... left intact`.
  `curl -v` against a server
  that sends `HTTP/1.1 101 Switching Protocols`, `Upgrade: x`, a body and closes shows it.
  Measured against the C build. Pinned by `a_switch_nothing_asked_for_is_the_response`
  (`crates/curl-core/src/proto/http/tests.rs`).

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
  (`crates/curl-core/src/proto/http/tests.rs`). Not for `scp:` and `sftp:`, whose library is
  handed the socket and reads past any buffer of ours: their tunnel reads the answer a byte at
  a time, as C's, so the SSH banner stays in the socket.

## Reads C makes larger

- **An HTTP/2 step's last read of the connection takes what is left of its allowance.** The
  session reads the layers below 16 KiB at a time, as C reads into its input queue's chunks,
  until a buffer's worth (`CURLOPT_BUFFERSIZE`) came in the step; the last read asks for what is
  left of that buffer. C's `h2_progress_ingress` asks a whole chunk on every read
  (`Curl_cf_recv_bufq` with no limit), so it can take up to 16 KiB less one byte past the
  buffer, and with a buffer under 16 KiB reads a whole chunk at once. Here a step on a shared
  connection takes no more than its buffer of what is meant for its siblings. The bytes and
  their order are the same; the last `ingress: read` line of a step, and the TLS or socket read
  under it, may be smaller than C's. Pinned by `a_step_reads_a_buffer_of_the_connection_at_most`
  (`crates/curl-core/src/proto/http/tests/h2.rs`).

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

- **An SFTP quote command's group or owner is read as a number, over libssh2.** `chgrp` and
  `chown` take a decimal id up to what a `curl_off_t` holds, as C's libssh2 build means to
  (`curlx_str_number` bounded by `ULONG_MAX`, `lib/vssh/libssh2.c`). That bound is -1 as a
  `curl_off_t` where a `long` is 64 bits, so C reads no id at all: its debug build aborts on
  `DEBUGASSERT(max >= 0)` in `str_num_base`, and its release build, which takes any digit as
  past the bound, fails every such command with `Syntax error: chgrp gid not a number` (21,
  `CURLE_QUOTE_ERROR`). Measured against the C debug build: `-Q "chgrp 1000 file"` over SFTP
  aborts it; the release build's answer is read from the code. C's libssh build bounds the id by
  `UINT_MAX` and reads it. Pinned by `chgrp_and_chown_take_an_id_past_32_bits`
  (`crates/curl-core/src/proto/ssh/libssh2/tests.rs`).

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

- **An FTP listing that starts with its total is read.** A wildcard download
  (`CURLOPT_WILDCARDMATCH`) of a directory whose `LIST` answer starts `total 12`, as `ls -l`
  writes it and Unix servers send it, gets the files the listing names. C's
  `parse_unix_totalsize` (`lib/ftplistparser.c`) checks the total at its line feed, then falls
  through with that same line feed into the next line's file type, which it is not: every such
  listing fails with 87 (`CURLE_FTP_BAD_FILE_LIST`), "Unable to parse FTP file list". Measured
  against the C build, its lines ending in CRLF and in a bare line feed; the same listing
  without its total line downloads. A first line that only starts with `t` fails as in C.
  Pinned by `a_wildcard_download_reads_past_the_listing_s_total`
  (`crates/curl-core/src/proto/ftp/tests.rs`) and `a_listing_that_starts_with_its_total_is_read`
  (`crates/curl-core/src/proto/ftp/list/tests.rs`).

- **An `Alt-Svc:` field from an origin named by a dot alone is passed over.** For
  `http://./`, `Curl_altsvc_parse` (`lib/altsvc.c`) returns `CURLE_OUT_OF_MEMORY` when
  `altsvc_createid` refuses the source host, empty once its trailing dot is gone, and the
  transfer fails with 27 although no allocation failed. Here the alternative is not kept and
  the response is read on. Pinned by `an_origin_named_by_a_dot_alone_keeps_nothing`
  (`crates/curl-core/src/altsvc/tests.rs`).

- **An RTSP SETUP sends the application's `Transport:` header once.** With `Transport:` among
  the application's headers, C's `rtsp_setup_request` (`lib/rtsp.c`) keeps the header line
  `Curl_checkheaders` found as its own transport header and sends it, without its line end,
  ahead of the application's headers, which carry it again: the first copy runs into the line
  after it. Here it goes once, with the application's other headers. Pinned by
  `the_application_s_transport_goes_once` (`crates/curl-core/src/proto/http/tests/rtsp.rs`).

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
  with `(nil)=x`. Pinned by `canonical_queries_c_leaves_out`
  (`crates/curl-core/src/proto/http/sigv4/tests.rs`).

- **The form API refuses or leaves empty what C dereferences as NULL.** `curl_formadd` given a
  NULL `CURLFORM_FILENAME` or `CURLFORM_BUFFER` returns `CURL_FORMADD_NULL`, as it does for
  other NULL values; C takes the length of the NULL and crashes. A `CURLFORM_CONTENTTYPE` given
  after a field's last `CURLFORM_FILE` makes a part with that type and no file; sending the
  form, or `curl_formget`, then gives it no content, where C compares the missing file name
  with `-` and crashes. Both crashes measured against the C build. Pinned by
  `formadd_refuses_as_c_does` and `a_type_past_the_last_file_is_a_part_without_content`
  (`crates/curl-sys-abi/src/formdata.rs`).

- **A GSS-API stub's context is nothing to the library, and fails.** In the debug build, a SOCKS5
  GSS-API context the stub (`CURL_STUB_GSS_CREDS`) completed is then asked who it authenticated
  (`gss_inquire_context`), which the stub has no stand-in for: C hands the stub's context to the
  library, which crashes (measured against the C build: a segmentation fault). Here the library
  is not asked; the call fails as on a context it never made, "GSS-API error:
  gss_inquire_context failed: ...", then "Failed to determine username.", 97. Pinned by
  `the_stub_s_context_names_no_user` (`crates/curl-gssapi/tests/socks.rs`).

- **On Windows, a time or a format the C library cannot take is refused first.** A time before
  1970 or after the year 3000 (`_gmtime64_s`, `_localtime64_s`), or a `strftime` format with a
  conversion the C library does not know, gives no time and no text: `curl_os::time` checks
  both before calling. The UCRT documents that these calls hand such an argument to the
  invalid-parameter handler, which by default ends the process. That documented behaviour has
  not been measured against the C build. Pinned by `refuses_what_the_c_library_cannot_take`
  (`crates/curl-os/src/time.rs`, run on Windows).

## Traces C cuts short

- **With the ids on, traced bytes reach the debug handler whole.** `Curl_debug`
  (`lib/curl_trc.c`) writes the ids and then the bytes into one line with `"%.*s"` when the
  two fit a trace line, so the handler sees them cut at their first zero byte: a TLS record of
  271 bytes arrives as 7 or 9, and so does any body or header holding a zero. Here the bytes
  after the ids are the bytes traced, zeros and all. Pinned by
  `traced_bytes_with_the_ids_keep_a_zero_byte` (`crates/curl-core/src/proto/http/tests.rs`).

## What C's quiche filter drops

- **A stream reset over quiche keeps the peer's code.** quiche gives the code a stream was reset
  with (`QUICHE_H3_EVENT_RESET`); C's filter marks the stream reset and never sets its
  `error3`, so every reset says `reset by server (error 0x0 NO_ERROR)`, and one refused with
  `H3_REQUEST_REJECTED` is not made again on a new connection, as C's ngtcp2 filter makes it,
  but fails. Here the code is the peer's, said and acted on as over ngtcp2. Read from
  `lib/vquic/cf-quiche.c`; no test server here resets a stream to show it. Pinned by
  `a_request_quiche_s_peer_refuses_is_made_again`
  (`crates/curl-core/src/proto/http/tests/h3_trace.rs`).
- **An interim response over quiche ends its head.** C's filter writes a head's end only at
  the first body bytes or the stream's end, once (`resp_hds_complete`), so a 1xx head runs into
  the final one's status line. Here each head ends as its fields do, as over ngtcp2. Read from
  `lib/vquic/cf-quiche.c`; neither suite has a server that sends a 1xx over HTTP/3. Pinned by
  `an_interim_head_over_quiche_ends_before_the_final_one`
  (`crates/curl-core/src/proto/http/tests/h3_trace.rs`).

## Error numbers C leaves stale

- **A server that closes before its greeting is said with `errno: 0`**, in `response reading
  failed (errno: 0)`; C says `errno: 115`, the `EINPROGRESS` its connect left behind. Pinned by
  `a_server_that_closes_fails_the_read` (`crates/curl-core/src/proto/pop3/tests.rs`).

## Sockets C hands over

- **An SCP or SFTP transfer through an HTTPS proxy fails before SSH starts.** The SSH library
  reads and writes the connection's socket itself, so it is handed the socket only while no
  layer of the rewrite works on its bytes; under the proxy's TLS it is not, and the transfer
  fails with 2 (`CURLE_FAILED_INIT`), "Could not set socket". C's libssh build hands the
  library the raw socket whatever filters are over it (`myssh_connect`, `lib/vssh/libssh.c`),
  and the library's writes bypass the proxy's TLS: SSH goes onto the connection in clear, in
  the middle of the TLS session, where the proxy reads it as broken records. It fails with 2,
  "Failure establishing ssh session". Measured 2026-11-01 on C's libssh build, against a
  proxy that grants the tunnel: `SSH-2.0-libssh_0.12.2` was next on its TCP stream, and its
  TLS read failed. Pinned by `the_socket_is_not_handed_over_under_a_proxy_s_tls`
  (`crates/curl-core/src/proto/ssh/tests.rs`). The libssh2 build reads and writes the proxy's
  TLS as C's does.
- **SCP or SFTP over libssh2 through an HTTP/2 proxy fails before SSH starts.** C's sets
  libssh2's send and receive callbacks over the connection's filters for an HTTPS proxy alone
  (`CURLPROXY_HTTPS`, `ssh_connect`); under one that speaks HTTP/2 (`CURLPROXY_HTTPS2`) it
  hands the library the raw socket, past the proxy's TLS, as its libssh build does above. The
  rewrite refuses such a transfer with 2 (`CURLE_FAILED_INIT`), "SSH is not built over this
  proxy's TLS", where C's fails as its libssh build does above. Pinned by
  `only_an_https_proxy_s_tls_is_read_through_pipes`
  (`crates/curl-core/src/proto/ssh/libssh2/tests.rs`).

## Codes C passes through

- **An `SSL_CTX` function's code that no transfer ends with is an abort.** A
  `CURLOPT_SSL_CTX_FUNCTION` that returns a code fails the transfer with it, as in C, when the
  code is one a transfer can end with. C returns any other code as the transfer's result too:
  measured against the C build, 1000 from the function is 1000 from `curl_easy_perform`;
  `CURLE_AGAIN` trips an assertion in `Curl_ossl_ctx_init` on the debug build. A transfer's result here is one of the codes it can end with, so such a code
  fails it with `CURLE_ABORTED_BY_CALLBACK`, as a callback that stopped it, with C's `error
  signaled by SSL ctx callback`. Pinned by `a_function_s_code_is_the_transfer_s_if_it_can_be`
  (`crates/curl-sys-abi/src/tls.rs`) and `the_ssl_ctx_function_s_code_fails_the_transfer`
  (`crates/curl-sys-abi/src/tls_tests.rs`).

## A tunnel C asks for and cannot use

- **TFTP through a proxy, its socket bound to an address or a port, or through SOCKS.** Through
  an HTTP proxy's tunnel, a socket `--interface 127.0.0.1` or `--local-port` bound is spared
  the transfer's bind. C then sends its request on that socket, which is connected to the proxy,
  and fails with 55, "Received too short packet" once the proxy closes; here the send fails
  with 55, "Failed sending data to the peer", nothing sent after the tunnel's request (measured
  2026-11-01; `a_socket_bound_to_a_port_fails_to_send_through_a_tunnel`,
  `crates/curl-core/src/proto/tftp/tests.rs`). Through a SOCKS proxy, C opens a UDP socket to
  the proxy and fails with 97, "Send failure: Destination address required", sending nothing;
  here the SOCKS handshake is made over TCP and fails with 97 with what that finds (measured
  2026-11-01; `a_socks_proxy_is_spoken_to_over_tcp`). Neither gets a transfer through, on either
  side.

## Frames C sends beside a transfer

- **A PING on an HTTP/2 connection with streams open goes with their transfer's next send.**
  `curl_easy_upkeep` on such a connection queues the PING in the session, and the next send
  of a transfer on it frames and sends it. C's `http2_send_ping` sends it at once
  (`nghttp2_session_send`), framing with it whatever request body the streams have buffered,
  which its read callback reaches in the stream's own buffer; here the body is the transfer's,
  reached only from its step, and a send without it would fail the stream. An idle connection
  has no stream open, and is sent its PING at once as in C. A share's connection lent to a
  multi is asked of that multi, which keeps it alive as one of its transfers sends on it or
  gives it back, judged due at the time asked; C's share pool reaches it and sends the PING at
  once. Pinned by `a_connection_in_use_is_pinged_with_its_transfer_s_next_send` and
  `a_share_s_connection_lent_elsewhere_is_kept_alive_as_asked`
  (`crates/curl-core/src/proto/http/tests/h2.rs`).

- **An HTTP/2 stream paused or unpaused by a sibling's handler is told the peer in its own
  step.** When a handler of one transfer pauses or unpauses another whose stream shares its
  connection, while its own step has that connection out, the stream learns of it at once but
  its window is set, and a grown one's WINDOW_UPDATE sent, as its own transfer next reads, and
  `stream now (un)paused` is not said. C's `curl_easy_pause` reaches the stream's filter from
  inside the sibling's write (`http2_data_pause`) and sends the update there; here the session
  is the stepping transfer's until its step ends. A pause from outside any step, the common
  case, tells the peer before it returns as C does. Pinned by
  `a_stream_unpaused_in_a_siblings_step_opens_its_window_in_its_own`
  (`crates/curl-core/src/proto/http/tests/h2.rs`).

## Replies C is documented not to send

- **A passive `CCC` never answers the server's close_notify.** `CURLFTPSSL_CCC_PASSIVE` is
  documented to send no reply, and OpenSSL's shutdown sends none when the server's close_notify
  is there at its first read. When that read finds nothing and the close_notify comes before
  its second, a moment later in the same call, C's `ossl_shutdown` takes the
  `SSL_ERROR_ZERO_RETURN` there for a mutual shutdown and calls `SSL_shutdown`, which sends
  ours, and the server, gone to clear text, reads it as the start of the next command. Here
  the second read's close_notify is not answered either. Over loopback on macOS the server's
  close_notify landed in that moment in 5 of 20 runs; C's debug build against a server sending
  its answer and close_notify in one write, its reads capped to the answer's record and half
  of them made to block (`CURL_DBG_SOCK_RMAX=31`, `CURL_DBG_SOCK_RBLOCK=50`), sent a TLS record
  after a passive `CCC` in 7 of 20 runs (both measured 2026-11-08). Pinned by
  `a_passive_ccc_reading_the_close_notify_on_its_second_try_answers_none`
  (`crates/curl-openssl/tests/peer/ccc.rs`), which holds the client's first read until the
  close_notify is sent.

## Changing a handle's share

- **`CURLOPT_SHARE` from a callback is refused.** A callback running on the handle's multi gets
  `CURLE_BAD_FUNCTION_ARGUMENT` whether or not the transfer has a connection, and says nothing; C
  takes the change until the transfer has one, and traces "Cannot change share object while in
  use" once it does. The step in progress holds the transfer's `Easy` and may be using
  the share the change would replace. Pinned by `a_callback_cannot_change_the_share`
  (`crates/curl-sys-abi/src/handle_tests.rs`).
- **A share that stops keeping TLS sessions under a use leaves it no cache.** An application
  that unshares `CURL_LOCK_DATA_SSL_SESSION` on one thread while a handle links on another can
  have a transfer, an import or an export that chose the share's cache find it gone. C uses the
  cache it has freed; here the use goes on with no cache: an import is refused, an export gives
  nothing and a transfer neither takes nor gives a session, each lock call still made. Pinned by
  `sessions_gone_under_a_use_are_no_cache` (`crates/curl-core/src/multi/ssls/tests.rs`) and
  `sessions_gone_under_a_transfer_s_use_are_no_cache`
  (`crates/curl-core/src/proto/http/tests/tls.rs`).

## Public suffix locks

- **The lock functions hear of the public suffix list after the jar has used it.** The order of
  lock calls is C's, the list's inside the jar's, but where the share keeps cookies the jar's own
  mutex is held as the list is asked, and the application is never called under it. So a
  `CURL_LOCK_DATA_PSL` call comes once the jar's use is done, before its unlock, and where a file's
  lines are traced, before those lines rather than among them. Pinned by
  `the_public_suffixes_are_told_inside_the_jar_as_c_locks_them`
  (`crates/curl-core/src/proto/http/tests.rs`).

## The HSTS cache on a share

- **HSTS files named with no cache are not read.** A handle that named a file and then left a
  share keeping HSTS, or turned `CURLOPT_HSTS_CTRL` off while on it, has no cache and its files
  still named. Its next transfer in C fails the assertion in `Curl_hsts_loadfile`, and reads through
  the null pointer in a build without assertions (reproduced on the debug build). Here the files
  stay named and unread, and the transfer runs without a cache. Pinned by
  `files_named_with_no_cache_are_not_read` (`crates/curl-core/src/proto/http/tests/hsts.rs`).
- **A share's HSTS cache is not held across the application's reader and writer.** C runs both on
  the live cache, without telling the lock functions. Here the reader's entries are kept one at a
  time and the writer is given a copy of the entries taken as the save starts, so that no callback
  runs under the share's own lock. A writer changing the cache sees no change in what it is given.
  Pinned by `a_share_s_cache_is_not_locked_across_the_application` (same file).

## Handles the application never made

- **The connection lock at share cleanup is called with no handle.** When `curl_share_cleanup`
  closes the share's connections, the lock and unlock functions get NULL for the handle; C
  gives them the share's internal admin handle, an easy handle the application never created.
  Pinned by `a_share_is_held_and_locked_as_in_c` (`crates/curl-sys-abi/src/handle_tests.rs`).

## Handles C closes inside a read

- **A pushed transfer that cannot start goes as its parent's step ends.** When the push
  callback has returned `CURL_PUSH_OK` and the pushed transfer then cannot be set up, which
  only running out of memory causes, both close the handle the callback took without a
  `CURLMSG_DONE`, and cancel its stream. C does it at once, inside the read of the
  PUSH_PROMISE (`discard_newhandle`, through `Curl_multi_remove_handle`). Here the transfer is
  taken out when the parent's step ends, the first point at which the connection it was
  attached to is back with the multi. Until then the rest of that read is handled: the parent's
  callbacks run for the frames after the promise, the handle is still among the multi's
  (`curl_multi_get_handles`, its counts), and its "removed from multi" trace line, timer and
  socket calls come after the parent's. Pinned by
  `a_push_that_cannot_start_leaves_nothing_running` (`crates/curl-core/tests/torture.rs`),
  which checks that the parent's body is written by the time the handle is given back.

## Probes C removes inside their master's step

- **A DoH probe still running as its master's connection is set up goes when the step ends.**
  When the chain of an `https` transfer resolving over DoH connects with its HTTPS record's
  probe unanswered, both let go of the record's resolve there and trace `[DoH] probe done`
  right after its `destroy async` line. C removes the probe at that point, inside the master's
  step (`doh_close`, through `Curl_multi_remove_handle`): with the multi's and DoH's traces on,
  the probe's `multi_done … premature=1`, `closing connection` and `removed from multi` lines
  come before `[DoH] probe done`, and the connection it closes makes the master's next state
  trace `multi changed, check CONNECT_PEND queue`. Here the probe is taken out of the multi
  when the step ends (`Multi::reap`): the same lines come after `[DoH] probe done`, and the
  change is seen at the end of the call, so the master traces no `CONNECT_PEND` line. Measured
  against the C build. Pinned by `a_probe_removed_as_its_master_connects_ends_after_the_step`
  (`crates/curl-core/src/multi/doh_tests.rs`).

## Sessions C reads again

- **An HTTP/2 session whose read failed is not read again.** When nghttp2 fails a read of the
  connection's bytes (`nghttp2 recv error`, its callbacks refusing a frame: a PUSH_PROMISE for
  another authority, or memory), the transfer reading fails with 56. C leaves the bytes it
  gave in the connection's buffer (`h2_process_pending_input` skips none on failure), and the
  next transfer on the connection gives them to the session again from their start, though
  the session took some of them already. What follows is whatever nghttp2 makes of the
  repeat: against a server sending such a promise, a GOAWAY with `COMPRESSION_ERROR` (`nghttp2
  shuts down connection with error 9`), and the other transfers fail with 16 then; a failure
  between frames would have the session read those frames twice. Here the session is marked
  failed once: every other transfer on it is woken and fails with 16 as it runs, with C's
  `[0] ingress: session is closed` and `premature DATA_DONE, RST stream`, no stream is reset
  on it, and the connection is closed, with the GOAWAY its shutdown sends. Without the mark
  they would wait for their timeouts, as nothing more comes to read. Measured against the C
  build with three transfers over one connection and such a promise (2026-11-04: C 56, 16,
  16 within 0.1 s; the rewrite 56, 16, 16 at once). Pinned by
  `a_failed_read_fails_every_stream_on_the_connection`
  (`crates/curl-core/src/proto/http/tests/h2.rs`) and, for a pushed transfer refused memory,
  `a_push_that_cannot_start_leaves_nothing_running` (`crates/curl-core/tests/torture.rs`).

- **A failure of an HTTP/3 connection runs every transfer on it at once.** When a read of a
  QUIC connection fails, or the library's call on it does (a stream's bytes the HTTP/3
  library refuses, which closes the connection), the transfer whose step met it fails with
  56, and each other transfer on the connection fails with 56 as it next runs, as C's do.
  C's ngtcp2 filter has the others run only on their own socket's events and timers
  (`cf_ngtcp2_recv`; its quiche filter marks them, `cf_quiche_do_expire`): a step that read
  the failure without its socket's event, a transfer's timer run first as an event loop does,
  leaves them waiting for a datagram that will not come on a closed connection, or for a timer
  they may not have. Here every other transfer on the connection is run at once. Where the
  socket's event ran them all anyway, both builds give the same codes and lines: three
  transfers over one connection against a server breaking one stream's framing, driven by
  `curl_multi_perform` and by `curl_multi_socket_action` (2026-11-04: 56 for each, the 50
  lines after the failed read identical). Pinned by
  `a_failed_read_run_by_a_timer_fails_the_other_transfer_at_once`
  (`crates/curl-core/src/proto/http/tests/h3_trace.rs`).

## Descriptors C shares with a library

- **libssh is handed a copy of the connection's socket.** C gives libssh the connection's own
  descriptor (`SSH_OPTIONS_FD`), and libssh closes it on some failures, behind the connection
  that also closes it. Here the session gets a duplicate (`F_DUPFD_CLOEXEC`) and closes only
  that, so the connection's socket is closed once, by the connection. The copy takes a
  descriptor number of its own, so the descriptor numbers in an SSH transfer's trace after it
  differ from C's; no runtests or pytest case compares them. Pinned by
  `a_failed_connect_leaves_the_connection_s_socket` and
  `a_session_never_connected_closes_its_copy` (`crates/curl-libssh/src/tests.rs`).

## Blocks C sizes exactly

- **`curl_url_get` asks the application's allocator for the room a part may need.** The result
  is written straight into the block, which keeps test 1560 inside its allocation limit. For a
  whole URL the block can be larger than the string by about 32 bytes plus the shown host's
  length; the bytes returned are C's. A URL with no host or scheme reports that even when the
  allocator would fail, since no block is asked for first. The URL's lock is held across the
  application's `curl_global_init_mem` malloc, so a malloc callback calling `curl_url_*` on the
  same handle deadlocks. Pinned by `calls_cost_what_c_s_do` (`crates/curl-sys-abi/src/url.rs`).

## TLS sessions from outside

- **A session of no ticket is exported, not an abort.** A file or blob holding a version byte and
  no ticket imports in both, and resumes nothing in both. C's debug build then aborts on its
  `DEBUGASSERT(s->sdata)` as it exports (`Curl_ssl_session_pack`), measured with `--ssl-sessions`;
  by its source its release build writes an empty ticket, as the rewrite does: what is imported is
  not trusted to be anything. Pinned by `a_blob_may_say_nothing`
  (`crates/curl-core/src/tls/cache/spack/tests.rs`).

## Names C reads two ways

- **`--remove-on-error` removes a partial output with a name outside ASCII on Windows' Unicode
  build.** The name the command line gave is UTF-8 there, and the rewrite opens, checks and
  removes it as UTF-8. C's tool checks it with `curlx_stat`, which converts it to UTF-16, but
  removes it with `unlink` (`_unlink`), which reads it in the ANSI code page: `curl
  --remove-on-error -o café URL` on a transfer that fails warns `Failed removing: café` and
  leaves the partial file, as Microsoft's curl.exe 8.21.0 and C's build from this tree with
  `ENABLE_UNICODE` both do. The library's own removals of a temporary file it failed to rename
  (`Curl_fopen`'s callers) take the same path. Pinned by `removes_a_partial_output_by_its_name`
  (`crates/curl-tool/tests/http.rs`).

## Allocations the platform makes

- **On macOS, the threaded resolver's lock allocates on its first use, and that allocation
  cannot fail.** Rust's standard `Mutex` on macOS boxes a pthread mutex the first time it is
  locked, through an allocation the standard library aborts on rather than returns. The library's
  and the tool's locks are `curl_alloc::Lock`, which allocates nothing (`DESIGN.md`); the
  threaded resolver keeps a `Mutex`, as its `Condvar` waits on nothing else, beside the thread it
  starts, which allocates infallibly already. The standard streams' locks are made before memory
  tracking starts, as C's tracker never sees the C library's stdio internals
  (`curl_alloc::track`). Linux and Windows locks allocate nothing. Pinned by
  `a_lock_allocates_nothing` (`crates/curl-alloc/src/lock.rs`), which counts no allocation for a
  `Lock` and, on macOS, one for a `Mutex`.
- **In the Windows Unicode build, no file name's UTF-16 is counted by the debug build.** Every
  file call (`curl_os::fs`) converts the name to UTF-16 for the system's wide calls, and makes a
  name past `MAX_PATH` absolute, in memory the tracker does not count, as C's `win32-fopen.c`
  does with the system's `malloc` for `fopen`, `open` and `stat`. C's Unicode build converts
  the name of `curlx_CreateFile` (the tool's file times), `curlx_FindFirstFile` (a `file:`
  directory's listing) and `curlx_win32_rename` with `curlx_convert_UTF8_to_wchar`, which its
  tracker counts and `CURL_MEMLIMIT` can refuse; the Rust build makes those calls with one
  allocation fewer each, none of which `CURL_MEMLIMIT` refuses. The ANSI build counts none on
  either side. Pinned by `takes_a_long_name_without_allocating` (`crates/curl-os/tests/fs_alloc.rs`)
  and `removes_a_partial_file_named_long_without_allocating` (`crates/curl-tool/src/operate.rs`).

## A TLS library C links and the rewrite does not

- **Over Rustls, `CURLINFO_TLS_SSL_PTR` gives `CURLSSLBACKEND_RUSTLS` and a NULL `internals`.**
  C's gives rustls-ffi's `rustls_connection *`, which an application may pass back to
  rustls-ffi's own functions. The rewrite calls the rustls crate itself and links no rustls-ffi,
  so it has no such object to give, and an object of rustls-ffi's layout cannot be made in safe
  Rust. An application calling rustls-ffi on what it got passes it NULL: the pytest suite's
  libtest clients do (`cli_hx_download`'s `rustls_connection_get_protocol_version`, asserting
  the version is not 0, and `cli_tls_session_reuse`, asserting `internals` is not NULL), and
  those 56 cases fail on the Rustls build alone (`score.py --rustls`, 2026-11-07). Pinned by
  `the_library_s_objects_are_not_handed_out` (`crates/curl-rustls/src/tests.rs`).
- **Over Rustls, the version string names rustls-ffi, which the build does not link.** C's says
  `rustls-ffi/0.15.5/rustls/0.23.46/aws-lc-rs`; the rewrite says the same, naming the rustls-ffi
  release whose behaviour it ports and the rustls that release pins, which is the one it is
  built with. `runtests.pl` and the pytest suite know a Rustls build by the `rustls-ffi` in it,
  and an application matching on it finds what it would in C's. Pinned by
  `the_version_names_the_rustls_linked` (`crates/curl-rustls/src/tests/real.rs`), which also
  ties the rustls named to the one in `Cargo.lock`.

## Differences not yet brought to C's

Unlike the rest of this file, these are not deliberate: found by reading both sides, and by the
rule of `CLAUDE.md` each is to be brought to C's behaviour, with a test, and then removed from
here. They are listed so that none is read as C's behaviour meanwhile; none has a test that pins
it.

- **An indefinite-length `notAfter` that ends a certificate's validity is read.** C requires the
  date to end where the validity's content ends (`lib/vtls/x509asn1.c`), which an
  indefinite-length date with its end-of-contents octets does not; the core's reader
  (`crates/curl-core/src/tls/x509.rs`) only requires that nothing follows it. The reader serves
  wolfSSL's key pinning, Schannel's checks and certificate info. No test.
- **`curl_easy_cleanup` keeps a handle its multi failed to remove.** When `curl_multi_remove_handle`
  fails inside it (a timer callback refusing, or a call from inside a callback), cleanup returns
  without freeing the handle, so its cookie jar, HSTS and alt-svc files are not written
  (`crates/curl-sys-abi/src/easy.rs`); C's `Curl_close` frees it regardless. No test.

## Residuals shared with C

Weaknesses the rewrite has because C has them, kept to do what C does. Closing one would be a
deliberate difference and is the owner's call.

- **OpenSSL's configuration file is always loaded.** `init_ssl`
  (`crates/curl-openssl/src/sys.rs`) asks OpenSSL to load its configuration, as C's default
  does; C's opt-out for CVE-2019-5443, `CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG`, has no
  counterpart. A build against an OpenSSL whose configuration directory a user can write loads
  a file planted there. The OpenSSL this project builds with on Windows (vcpkg's
  `libcrypto-3-x64.dll`) names `C:\Program Files\Common Files\SSL`, which users can only read.
  No test.
- **Saving a cache empties it before the new contents exist.** `save::replace` opens the target
  for writing, truncating it, before the temporary file is made, as `Curl_fopen` does: an
  unwritable directory or a full disk leaves an empty HSTS, alt-svc or cookie file. The tests in
  `crates/curl-core/src/save.rs` cover success only; no test pins the failure.
