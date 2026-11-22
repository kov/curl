# Backlog

Work agreed on and not yet scheduled. Each entry says what is wrong or missing, the shape of the
fix, and where to start. An entry leaves this file when its work lands, or moves to
[`MILESTONES.md`](MILESTONES.md) when it is scheduled as a step.

## libssh's run result travels with the step that ends it

`SshConn::actual` (`crates/curl-core/src/proto/ssh/mod.rs`) is C's `actualcode`: a step that
fails stores its failure in the field and moves to the disconnect or close states, and
`session_free` returns it at the end of the run. Twenty-one sites write or read it. A step that
moves on without setting it, or sets it and then succeeds, ends the run with the wrong result,
and nothing in the types stops it.

The libssh2 backend (`proto/ssh/libssh2.rs`) has no such field: each state's work returns a
`Halt` (`Again` or `Fail`), and the failure is carried to the state that ends the run. The fix
is to drive libssh's states the same way, so that the failure is a value the next state is
handed instead of a field it reads. This means porting the libssh state machine
(`lib/vssh/libssh.c`, 3,268 lines) to that pattern state by state. Each state's tests stay as
they are, and the traces must not change.

## The TLS library our symbols bind to is the family we were built for

`TlsNative` carries a `TlsKind` that the ngtcp2 and quiche crates check before casting a TLS
library's pointers. Nothing checks that the library the calls actually reach belongs to that
family, for example when two OpenSSL-like libraries are loaded in one process or one is
interposed. Add a check, once per process in each backend's initialisation:

- Take the address of a function the backend calls, such as `SSL_new`.
- Find the object that defines it with `dladdr`; on Windows, `GetModuleHandleEx` with
  `FROM_ADDRESS`.
- In that object, look up a symbol only that family exports, with `dlsym` (`GetProcAddress` on
  Windows). Candidates to confirm on banana, where every backend is built:
  - OpenSSL 3: `OSSL_PROVIDER_load`, with the `OPENSSL_3.0.0` version, through `dlvsym`.
  - AWS-LC: `awslc_api_version_num`.
  - BoringSSL: `BORINGSSL_self_test`, and none of AWS-LC's.
  - GnuTLS: `gnutls_global_init`.
  - wolfSSL: `wolfSSL_Init`.
  - mbedTLS: `mbedtls_ssl_init`.
  - LibreSSL: no marker settled.

Notes on the design:

- **What it checks.** It checks the object the calls go to, not what is loaded, since an
  application may load another TLS library for itself.
- **Static links.** A library linked statically is defined in our own object. That binding
  cannot be interposed, so it passes.
- **On a mismatch.** The backend refuses to initialise. C has no such check, so this goes in
  `DIVERGENCE.md`.
- **New unsafe module.** It needs one, for example `crates/curl-os/src/dl.rs`, named in
  `CLAUDE.md`'s list.
- **Assumption to test.** It assumes an unversioned `SSL_new` from another library cannot
  satisfy our versioned reference. Test that with `LD_PRELOAD` against the release library.
- **Ruled out.** Telling a library apart by one of its objects: none of these libraries has a
  stable type tag, and every query function reads the pointer first.
