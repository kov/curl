# Hand-off: milestone 4 on `cloud/m4`

State left by the cloud session that worked milestone 4 (steps 47–54), for whoever picks it up.
This branch is `cloud/m4` at `ae4124e` plus this `handoff/` directory, which is not meant to be
merged: copy what is useful into your checkout. `cloud/m4` itself does not carry it, because
its rules keep planning files and session tooling off it.

The milestone review is `REVIEW-M3.md` on branch `review/m3` (`20e0fee`). Its findings 1.2,
1.3, 2.7 and 3.7–3.12 are done on `cloud/m4`; finding 2.1's ownership model is to be written
into ENGINE.md as step 51 starts.

## Where it stands

- **Step 47 (the corpus): done.** 1402 of 1411 invocations agree between the C and the Rust
  tool; the rest wait on later options (`--http2`, FTP) or are `-V`. Sweep and cargo-mutants
  closed: no mutant missed after `e303988`.
- **Step 48 (the threaded resolver):**
  - **48a, the resolver seam: done.**
  - **48b, the resolver: done** but for three items:
    - `CURL_DBG_RESOLV_FAIL_IPV6`. It is `hostip_resolv`'s, for every resolver. Its "DEBUG fail
      ipv6 resolve" line falls between the hostip_resolv line and the cache lookup, so it needs
      the lookup lines written on the resolve's first pass; today they are written when the
      answer comes. pytest test_21_04 uses it.
    - The blocking resolve's `await, waiting Nms` lines, and the thread queue's own trace
      (`CURL_DEBUG=threads`).
    - The link-local AAAA re-query (`AF_UNSPEC`, "re-queueing query … for AF_UNSPEC
      resolve"). Reproduce glibc's missing scope id first, as CLAUDE.md asks for a C
      workaround. It needs `curl_os::resolve::lookup` to keep each address's scope. Only
      test_21_16 uses it, and that test is skipped without DNS override.

    ENGINE.md §4.8 describes what is built.
  - **48c: to do.**
    - The `threaded-resolver` feature is forwarded by curl-sys-abi and curl-tool already.
    - Make version and the feature list report `AsynchDNS` and threaded-resolver. Until then
      runtests skips 3026 ("lacks threadsafe").
    - A threaded build must not add c-ares's reason to "Could not resolve host:
      x (Domain name not found)": see `connect_failed` in `multi/state.rs` and
      `resolve_host` in `conn/bind.rs`. Tie it to the resolver (a trait method or the
      failure's data), not to a cfg on the trace.
    - Run the Rust leg built with the feature against `build/c-threaded`: the full suite
      under valgrind, then pytest test_21 (`CURL_DBG_*` variables are in).
  - **48d: to do.** `sabotage/sweep.py dns multi trace` from a clean worktree, and
    cargo-mutants over `2b6a502..HEAD`, crate by crate (see below). Expect the tool's
    `operate::quick_exit` to survive: it only decides whether exit joins resolver threads.
    Exclude it in `.cargo/mutants.toml` with a comment.
- **Steps 49–54: to do**, as MILESTONES.md has them.
- **Standing user decisions** are in the commits and DIVERGENCE.md. The latest: step 48 is
  option (a), the resolver chosen by a cargo feature; the measurement build keeps the
  answer-at-once resolver checked against the c-ares oracle, and the drop-in library uses
  the threaded one checked against `build/c-threaded` (recorded in SCOPE.md). c-ares
  bindings come with milestone 7's `--dns-*`. A divergence from C needs the user's
  approval; matching C does not.

## Container setup (Ubuntu 24.04 cloud container)

- **Packages:** about 86 apt packages, among them apache2 and apache2-dev, dante-server,
  openssh-server, stunnel4, vsftpd, nghttp2-proxy, krb5-user, libkrb5-dev, libnghttp2-dev,
  libpsl-dev, libssh2-1-dev, libzstd-dev, libidn2-dev, libc-ares-dev, python3-pytest,
  python3-websockets, debhelper.
- **cargo-mutants** 27.1.0 by `cargo install`.
- **c-ares 1.34.5** built from source into `build/deps/c-ares` (sources in `build/deps/src`);
  build/c links it by RPATH.
- **Oracles**, both configured with CMake:
  - `cmake -C handoff/oracle/c-cache.cmake` gives `build/c`, the reference: debug, c-ares,
    HTTPS-RR, OpenSSL 3.0.13, no HTTP/3.
  - `-C handoff/oracle/c-threaded-cache.cmake` gives `build/c-threaded`: threaded resolver,
    no c-ares.
  - Both link with `-Wl,-z,lazy`. Ubuntu links with `-z now`, and then the single `libtests`
    binary fails to load against a library still missing exports; Fedora, the reference,
    binds lazily.
- **`scripts/nghttpx-v4`** goes to `/usr/local/bin/nghttpx-v4`. The container has no IPv6, and
  nghttpx's `*` frontends try it. `scripts/testenv.sh` points `NGHTTPX` at it, sets `USER`
  for pytest, and unsets the container's proxy variables, which the library under test would
  otherwise read.
- **Memory caps.** cgroup v1 with no systemd bus: `scripts/memcap.sh <GiB> cmd`, at most 12
  GiB here (13 was refused). The sweep calls `systemd-run`, so put `scripts/` first on
  `PATH` for it (`PATH=handoff/scripts:$PATH`); `scripts/systemd-run` stands in.

## Scripts (`handoff/scripts`)

Run from the repository root.

| script | what |
|---|---|
| `memcap.sh <GiB> cmd…` | runs cmd in a capped memory cgroup |
| `testenv.sh cmd…` | runs cmd without proxy variables, with `NGHTTPX` and `USER` set |
| `rust_leg.py [--no-build] <runtests args>` | lays out `build/rust` as `inventory/measure/score.py` does and runs runtests there. `-a -j4 <tests>` runs under valgrind. Never pass `-n`: it hides every leak |
| `c_suite.py` | runs the C suite on `build/c` as `baseline.py --run` does, without rebuilding |
| `arm.py <entries file> N` | plants the last N sabotage entries by hand, one at a time, runs each witness (lib tests only) and restores the file: RED, SURVIVED or BROKEN. Quicker than the sweep before a commit; the sweep is still the step's close |
| `stale.py` | lists sabotage entries whose `old` text no longer appears exactly once; clearer than `sabotage_entries_are_current`'s failure |
| `run_mutants.sh <worktree> <base> <name> <args>` | cargo-mutants over one crate's diff, capped and resumable; the header has the four crates' arguments |
| `autofix.py cargo build --message-format=json …` | applies rustc's machine-applicable fixes, once per span |
| `echo_server.py`, `reply_server.py` | one-shot servers for poking a tool by hand |
| `systemd-run`, `nghttpx-v4` | stand-ins, see above |

## Oracle checks (`handoff/oracle`)

Small C programs run against `build/c` and `build/c-threaded` to settle a behaviour before
porting it. Build with `gcc x.c -Iinclude -Lbuild/c/lib -lcurl-d` and run with
`LD_LIBRARY_PATH=build/c/lib`.

- `resolve_options.c` prints `CURLMOPT_RESOLVE_THREADS_MAX` and `QUICK_EXIT`'s codes.
- The cookie and pending-transfer programs come from earlier steps; `sticky_server.py` serves
  `sticky.c`.

## Results (`handoff/results`)

- `c-threaded-suite.log`: build/c-threaded's full suite under valgrind. 2003 of 2006 OK, no
  valgrind errors, failing 1275 2100 2600. build/c fails those and 2104 (1992/1996).
- `rust-leg-valgrind-suite.log`: the Rust leg under valgrind at finding 1.2's commit. 1246 of
  1279 OK, no valgrind errors. The 33 failures are origin/master's: 96 509 543 556 558 655
  696 760 1013 1014 1275 1396 1471 1472 1521 1536 1537 1543 1605 1911 1912 1918 1919 1990
  2082 2084 2085 3025 3033 3101 3231 3232 3234.
- `rust-leg-master-suite.log`: the same at origin/master. It shows the socket-path trap below.
- `cargo-test-baseline.log`: `cargo test --workspace` at master. 1735 passed, 3 failed, all
  three the container's.
- `mutants/<crate>-<outcome>.txt`: step 47's cargo-mutants outcomes. The tool's one miss is
  closed by `e303988`.
- `../status.html`: the last status page (also at
  https://claude.ai/artifact/UbexBLFmQkdPc5vRk8eeD3).

## Traps found the hard way

- **Container failures.** These fail in this container on every branch:
  - No IPv6: `the_system_s_ipv6_probe_is_the_system_s` and `the_probe_finds_ipv6`.
  - OpenSSL 3.0 has only the dynamic engine: `init_loads_the_built_in_engines` and the peer
    engine test, which panics `main` and so hides every peer test after it.
  - OpenSSL 3.0 words one alert "sslv3 alert", which `peer/failures.rs:296` does not expect.

  The peer harness has no `--skip`. A bare argument is a name filter, so give cargo-mutants
  filters after a second `--`.
- **Socket paths.** runtests' servers fail with "socket path must be shorter than 108 chars"
  in a worktree under a long path, the scratchpad's for one. Keep worktrees for runtests
  short, under `build/`.
- **Valgrind.** Two suppressions in `tests/valgrind.supp` are this branch's (`d2ff527`,
  `4108959`):
  - std's stack-overflow handler keeps its thread-info block only through an interior
    pointer, because of the debug allocator's header. It reproduces on Rust 1.97 and 1.99.
  - MIT krb5's own `gss_display_status` leak, under the Rust callers.
- **The sweep** needs a clean tree and edits files in place. `pkill -f` with a pattern that
  matches your own shell's command line kills the shell.
- **Witness names.** A sabotage witness in an integration test is named without its file,
  as `curl-tool the_key_log_is_opened_at_start`.
- **Test asserts.** An `assert!` holding the threaded resolver's lock poisons it, and the
  resolver's drop then aborts the test binary: read the value first, then assert. `Waker::drain`
  returns Ok whether or not anything was pending; poll the descriptor to tell.
- **The fake network.** A late name whose `Late` gate is already released answers at once
  and queues nothing. Release it after the transfer's first pass.
- **Slot sizes.** `a_connection_s_slot_and_a_transfer_s_stay_their_size` guards the
  per-handle cost. Data added to `Found`, `Asked` or `Pending` grows it; store a compact form
  in the setup (see `Came`, and `Pending::queried`).
- **Restarts.** The container restarted once and killed a long cargo-mutants run;
  `--iterate` resumes it.
