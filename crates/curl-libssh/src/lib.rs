//! SCP and SFTP from libssh (`lib/vssh/libssh.c`): the session over a
//! socket the connection hands it, its host key and logins, and the SCP
//! channel, SFTP session, file and directory it has open, each freed
//! with it. The calls are libssh's, one for one with C's.

#![allow(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

mod sys;

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::ssh::{
    Aio, AttrChange, Attrs, Auth, Failed, HostKey, KeyType, KnownHosts, KnownKey, Methods,
    OpenMode, PollFlags, Rc, Refused, ScpRequest, Session, Ssh,
};

/// libssh, as C's build uses it.
#[derive(Debug)]
pub struct Libssh;

/// The library each handle speaks SSH with.
pub static LIBSSH: Libssh = Libssh;

/// The library's version, as `curl -V` names it after `libssh/`
/// (`ssh_version(0)`): its number, crypto library and compression.
pub fn version() -> &'static str {
    version_c().to_str().expect("libssh's version is ASCII")
}

/// The library's version as `curl_version_info` gives it, a C string the
/// library keeps.
pub fn version_c() -> &'static CStr {
    // SAFETY: with 0, `ssh_version` returns the library's version, a
    // static string of its own.
    let v = unsafe { sys::ssh_version(0) };
    assert!(!v.is_null(), "libssh names its version");
    // SAFETY: as above, a C string libssh keeps for good.
    unsafe { CStr::from_ptr(v) }
}

impl Ssh for Libssh {
    fn session(&self) -> Option<Box<dyn Session>> {
        // SAFETY: no arguments; a new session or NULL.
        let session = unsafe { sys::ssh_new() };
        if session.is_null() {
            return None;
        }
        let made = Libsession {
            session,
            pubkey: ptr::null_mut(),
            privkey: ptr::null_mut(),
            scp: ptr::null_mut(),
            sftp: ptr::null_mut(),
            file: ptr::null_mut(),
            dir: ptr::null_mut(),
            quote_attrs: ptr::null_mut(),
            recv_aio: ptr::null_mut(),
            send_aio: ptr::null_mut(),
            socket: Socket::None,
        };
        // A box that cannot be made drops the session, which frees it.
        let boxed: Box<dyn Session> = curl_alloc::try_box(made).ok()?;
        Some(boxed)
    }
}

/// A session and what it has open, each NULL until made: C's `ssh_conn`'s
/// libssh handles.
#[derive(Debug)]
struct Libsession {
    session: sys::ssh_session,
    pubkey: sys::ssh_key,
    privkey: sys::ssh_key,
    scp: sys::ssh_scp,
    sftp: sys::sftp_session,
    file: sys::sftp_file,
    dir: sys::sftp_dir,
    quote_attrs: sys::sftp_attributes,
    recv_aio: sys::sftp_aio,
    send_aio: sys::sftp_aio,
    /// The session's own copy of the socket it was handed.
    socket: Socket,
}

/// Who has the session's copy of its socket to close. libssh closes the
/// socket it is given when a call of its fails on it, and when the
/// session is freed still holding it, but not once it has said its
/// goodbye: so it is handed a copy of its own, which the connection's
/// socket outlives whatever libssh does with it, and which is closed
/// here once libssh has let go of it open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Socket {
    None,
    /// Handed to libssh, not yet taken up by a connect: libssh's to
    /// forget, ours to close.
    Given(c_int),
    /// Taken up by a connect: open while libssh's socket has it.
    Taken(c_int),
    /// Let go of by libssh, open, after its goodbye: ours to close.
    LetGo(c_int),
}

// SAFETY: libssh's handles are tied to no thread: a session and what it
// has open are used by one thread at a time, whoever owns this, as C's
// connection uses them from whichever thread runs its transfer.
unsafe impl Send for Libsession {}

/// `text` with a NUL after it, for libssh; one with a NUL inside is none
/// libssh could be given, nor memory for it.
fn terminated(text: &[u8]) -> Result<Vec<u8>, Refused> {
    if text.contains(&0) {
        return Err(Refused);
    }
    let mut z = Vec::new();
    z.try_reserve_exact(text.len() + 1).map_err(|_| Refused)?;
    z.try_extend_from_slice(text)?;
    z.try_push(0)?;
    Ok(z)
}

/// A C string's bytes, copied.
///
/// # Safety
///
/// `s` is NULL or a C string that lives for the call.
unsafe fn copied(s: *const c_char) -> Result<Option<Vec<u8>>, OutOfMemory> {
    if s.is_null() {
        return Ok(None);
    }
    // SAFETY: not NULL, a C string, as the caller says.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    let mut out = Vec::new();
    out.try_extend_from_slice(bytes)?;
    Ok(Some(out))
}

/// A string libssh made, freed with `ssh_string_free_char`.
struct LibsshString(*mut c_char);

impl LibsshString {
    fn copied(&self) -> Result<Option<Vec<u8>>, OutOfMemory> {
        // SAFETY: NULL or a C string libssh made, alive until dropped.
        unsafe { copied(self.0) }
    }
}

impl Drop for LibsshString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: a string libssh made, freed once, here.
            unsafe { sys::ssh_string_free_char(self.0) };
        }
    }
}

/// A string `ssh_pki_export_pubkey_base64` made, freed with the system's
/// `free`, as libssh allocated it.
struct Exported(*mut c_char);

impl Drop for Exported {
    fn drop(&mut self) {
        // SAFETY: NULL, or memory libssh took from the system allocator,
        // freed once, here.
        unsafe { sys::free(self.0.cast()) };
    }
}

/// A key libssh made, freed with it.
struct Key(sys::ssh_key);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: NULL, its no-op, or a key libssh made, freed once.
        unsafe { sys::ssh_key_free(self.0) };
    }
}

/// Attributes libssh made, freed with it.
struct Attributes(sys::sftp_attributes);

impl Attributes {
    /// The fields the state machine reads, copied.
    fn copied(&self) -> Result<Option<Attrs>, OutOfMemory> {
        if self.0.is_null() {
            return Ok(None);
        }
        // SAFETY: attributes libssh made, alive until dropped, read only.
        let a = unsafe { &*self.0 };
        Ok(Some(Attrs {
            // SAFETY: NULL or a C string of the attributes'.
            name: unsafe { copied(a.name) }?,
            // SAFETY: as above.
            longname: unsafe { copied(a.longname) }?,
            flags: a.flags,
            size: a.size,
            permissions: a.permissions,
            mtime: a.mtime,
        }))
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: NULL, its no-op, or attributes libssh made, freed once.
        unsafe { sys::sftp_attributes_free(self.0) };
    }
}

/// What libssh's `rc` says of a call that may wait.
fn rc(rc: c_int) -> Rc {
    match rc {
        sys::SSH_OK => Rc::Ok,
        sys::SSH_AGAIN => Rc::Again,
        _ => Rc::Error,
    }
}

/// A call that succeeds with 0 and fails with any other number.
fn zero_ok(n: c_int) -> Rc {
    match n {
        0 => Rc::Ok,
        sys::SSH_AGAIN => Rc::Again,
        _ => Rc::Error,
    }
}

fn auth(rc: c_int) -> Auth {
    match rc {
        sys::SSH_AUTH_SUCCESS => Auth::Success,
        sys::SSH_AUTH_DENIED => Auth::Denied,
        sys::SSH_AUTH_PARTIAL => Auth::Partial,
        sys::SSH_AUTH_INFO => Auth::Info,
        sys::SSH_AUTH_AGAIN => Auth::Again,
        _ => Auth::Error,
    }
}

fn key_type(kind: c_int) -> KeyType {
    match kind {
        sys::SSH_KEYTYPE_RSA => KeyType::Rsa,
        sys::SSH_KEYTYPE_RSA1 => KeyType::Rsa1,
        sys::SSH_KEYTYPE_ECDSA
        | sys::SSH_KEYTYPE_ECDSA_P256
        | sys::SSH_KEYTYPE_ECDSA_P384
        | sys::SSH_KEYTYPE_ECDSA_P521 => KeyType::Ecdsa,
        sys::SSH_KEYTYPE_ED25519 => KeyType::Ed25519,
        sys::SSH_KEYTYPE_DSS => KeyType::Dss,
        _ => KeyType::Other,
    }
}

/// `key`'s fingerprint of `kind`, if libssh makes one of `N` bytes.
fn fingerprint<const N: usize>(key: sys::ssh_key, kind: c_int) -> Option<[u8; N]> {
    let mut hash = ptr::null_mut();
    let mut len = 0;
    // SAFETY: a key libssh made, and out-pointers it sets to a hash of its
    // own and its length.
    let rc = unsafe { sys::ssh_get_publickey_hash(key, kind, &raw mut hash, &raw mut len) };
    let got = if rc == sys::SSH_OK && len == N && !hash.is_null() {
        // SAFETY: libssh made `len` bytes at `hash`, alive until cleaned.
        let bytes = unsafe { core::slice::from_raw_parts(hash, len) };
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Some(out)
    } else {
        None
    };
    if !hash.is_null() {
        // SAFETY: the hash libssh made, cleaned once, here.
        unsafe { sys::ssh_clean_pubkey_hash(&raw mut hash) };
    }
    got
}

/// `key` in base64, as libssh exports it.
fn base64_of(key: sys::ssh_key) -> Option<Vec<u8>> {
    let mut b64 = ptr::null_mut();
    // SAFETY: a key libssh made, and an out-pointer it sets to a string of
    // its own.
    let rc = unsafe { sys::ssh_pki_export_pubkey_base64(key, &raw mut b64) };
    let made = Exported(b64);
    if rc != sys::SSH_OK {
        return None;
    }
    // SAFETY: NULL or the C string libssh made, alive until `made` drops.
    unsafe { copied(made.0) }.ok().flatten()
}

impl Libsession {
    /// Set the option `kind` to `value`.
    fn set(&mut self, kind: c_int, value: *const c_void) -> Result<(), Refused> {
        // SAFETY: the session libssh made, and a value of the type the
        // option takes, which libssh copies.
        let rc = unsafe { sys::ssh_options_set(self.session, kind, value) };
        if rc == sys::SSH_OK {
            Ok(())
        } else {
            Err(Refused)
        }
    }

    /// Set the string option `kind` to `value`.
    fn set_str(&mut self, kind: c_int, value: &[u8]) -> Result<(), Refused> {
        let z = terminated(value)?;
        self.set(kind, z.as_ptr().cast())
    }

    fn sftp(&self) -> sys::sftp_session {
        assert!(!self.sftp.is_null(), "an SFTP call within its session");
        self.sftp
    }

    fn file(&self) -> sys::sftp_file {
        assert!(!self.file.is_null(), "a file call on an open file");
        self.file
    }

    fn scp(&self) -> sys::ssh_scp {
        assert!(!self.scp.is_null(), "an SCP call on its channel");
        self.scp
    }

    /// An SFTP call on a path, its answer `call` makes of it; a path
    /// libssh cannot be given fails it.
    fn on_path<T>(
        &mut self,
        path: &[u8],
        failed: T,
        call: impl FnOnce(sys::sftp_session, *const c_char) -> T,
    ) -> T {
        let sftp = self.sftp();
        match terminated(path) {
            Ok(z) => call(sftp, z.as_ptr().cast()),
            Err(Refused) => failed,
        }
    }

    /// An SFTP call on two paths.
    fn on_paths(
        &mut self,
        one: &[u8],
        two: &[u8],
        call: impl FnOnce(sys::sftp_session, *const c_char, *const c_char) -> c_int,
    ) -> Rc {
        let sftp = self.sftp();
        match (terminated(one), terminated(two)) {
            (Ok(a), Ok(b)) => zero_ok(call(sftp, a.as_ptr().cast(), b.as_ptr().cast())),
            _ => Rc::Error,
        }
    }

    /// Attributes of `path` a call of libssh's gives.
    fn attributes(
        &mut self,
        path: &[u8],
        call: unsafe extern "C" fn(sys::sftp_session, *const c_char) -> sys::sftp_attributes,
    ) -> Result<Option<Attrs>, OutOfMemory> {
        let made = self.on_path(path, ptr::null_mut(), |sftp, p| {
            // SAFETY: the SFTP session, and a C string libssh reads for
            // the call.
            unsafe { call(sftp, p) }
        });
        Attributes(made).copied()
    }
}

impl Session for Libsession {
    fn set_host(&mut self, host: &[u8]) -> Result<(), Refused> {
        self.set_str(sys::SSH_OPTIONS_HOST, host)
    }

    fn parse_config(&mut self) -> Result<(), Refused> {
        // SAFETY: the session; NULL reads the default files.
        let rc = unsafe { sys::ssh_options_parse_config(self.session, ptr::null()) };
        if rc == sys::SSH_OK {
            Ok(())
        } else {
            Err(Refused)
        }
    }

    fn set_socket(&mut self, fd: i32) -> Result<(), Refused> {
        assert_eq!(self.socket, Socket::None, "a session is handed one socket");
        // SAFETY: a descriptor number the caller has open; the copy, if
        // made, is this session's.
        let copy = unsafe { sys::fcntl(fd, sys::F_DUPFD_CLOEXEC, 0) };
        if copy < 0 {
            return Err(Refused);
        }
        self.socket = Socket::Given(copy);
        self.set(sys::SSH_OPTIONS_FD, (&raw const copy).cast())
    }

    fn set_user(&mut self, user: &[u8]) -> Result<(), Refused> {
        self.set_str(sys::SSH_OPTIONS_USER, user)
    }

    fn set_known_hosts(&mut self, file: &[u8]) -> Result<(), Refused> {
        self.set_str(sys::SSH_OPTIONS_KNOWNHOSTS, file)?;
        // libssh has two, both set to the one file "to avoid surprises".
        self.set_str(sys::SSH_OPTIONS_GLOBAL_KNOWNHOSTS, file)
    }

    fn set_port(&mut self, port: u16) -> Result<(), Refused> {
        let port = c_uint::from(port);
        self.set(sys::SSH_OPTIONS_PORT, (&raw const port).cast())
    }

    fn set_compression(&mut self) -> Result<(), Refused> {
        self.set_str(sys::SSH_OPTIONS_COMPRESSION, b"zlib,zlib@openssh.com,none")
    }

    fn import_pubkey_file(&mut self, file: &[u8]) -> Result<(), Refused> {
        let z = terminated(file)?;
        let mut key = ptr::null_mut();
        // SAFETY: a C string, and an out-pointer libssh sets to a key of
        // its own.
        let rc = unsafe { sys::ssh_pki_import_pubkey_file(z.as_ptr().cast(), &raw mut key) };
        drop(Key(core::mem::replace(&mut self.pubkey, key)));
        if rc == sys::SSH_OK {
            Ok(())
        } else {
            Err(Refused)
        }
    }

    fn has_pubkey(&self) -> bool {
        !self.pubkey.is_null()
    }

    fn set_blocking(&mut self, blocking: bool) {
        // SAFETY: the session.
        unsafe { sys::ssh_set_blocking(self.session, c_int::from(blocking)) };
    }

    fn poll_flags(&self) -> PollFlags {
        // SAFETY: the session.
        let dir = unsafe { sys::ssh_get_poll_flags(self.session) };
        PollFlags {
            read: dir & sys::SSH_READ_PENDING != 0,
            write: dir & sys::SSH_WRITE_PENDING != 0,
        }
    }

    fn error(&self) -> Result<Vec<u8>, OutOfMemory> {
        // SAFETY: the session, whose error text libssh keeps until its next
        // call.
        let text = unsafe { sys::ssh_get_error(self.session.cast()) };
        // SAFETY: NULL or the session's C string, copied at once.
        Ok(unsafe { copied(text) }?.unwrap_or_default())
    }

    fn connect(&mut self) -> Rc {
        // A connect takes up the socket as it starts.
        if let Socket::Given(fd) = self.socket {
            self.socket = Socket::Taken(fd);
        }
        // SAFETY: the session.
        rc(unsafe { sys::ssh_connect(self.session) })
    }

    fn host_key(&mut self) -> Option<HostKey> {
        let mut key = ptr::null_mut();
        // SAFETY: the session, and an out-pointer libssh sets to a key of
        // its own.
        let rc = unsafe { sys::ssh_get_server_publickey(self.session, &raw mut key) };
        let key = Key(key);
        if rc != sys::SSH_OK || key.0.is_null() {
            return None;
        }
        Some(HostKey {
            sha256: fingerprint(key.0, sys::SSH_PUBLICKEY_HASH_SHA256),
            md5: fingerprint(key.0, sys::SSH_PUBLICKEY_HASH_MD5),
            base64: base64_of(key.0),
            // SAFETY: a key libssh made.
            kind: key_type(unsafe { sys::ssh_key_type(key.0) }),
        })
    }

    fn known_host(&mut self) -> (KnownHosts, Option<Result<KnownKey, Failed>>) {
        let mut entry = ptr::null_mut();
        // SAFETY: the session, and an out-pointer libssh sets to an entry
        // of its own.
        let state = unsafe { sys::ssh_session_get_known_hosts_entry(self.session, &raw mut entry) };
        let known = match state {
            sys::SSH_KNOWN_HOSTS_OK => KnownHosts::Ok,
            sys::SSH_KNOWN_HOSTS_CHANGED => KnownHosts::Changed,
            sys::SSH_KNOWN_HOSTS_OTHER => KnownHosts::Other,
            sys::SSH_KNOWN_HOSTS_NOT_FOUND => KnownHosts::NotFound,
            sys::SSH_KNOWN_HOSTS_UNKNOWN => KnownHosts::Unknown,
            _ => KnownHosts::Error,
        };
        if entry.is_null() {
            return (known, None);
        }
        let key = {
            // SAFETY: the entry libssh made, alive until freed below.
            let e = unsafe { &*entry };
            (!e.publickey.is_null()).then(|| {
                base64_of(e.publickey)
                    .map(|b64| KnownKey {
                        base64: Some(b64),
                        // SAFETY: the entry's key, which libssh made.
                        kind: key_type(unsafe { sys::ssh_key_type(e.publickey) }),
                    })
                    .ok_or(Failed)
            })
        };
        // SAFETY: the entry libssh made, freed once, here.
        unsafe { sys::ssh_knownhosts_entry_free(entry) };
        (known, key)
    }

    fn update_known_hosts(&mut self) -> Rc {
        // SAFETY: the session.
        rc(unsafe { sys::ssh_session_update_known_hosts(self.session) })
    }

    fn auth_none(&mut self) -> Auth {
        // SAFETY: the session; NULL for the user it was set with.
        auth(unsafe { sys::ssh_userauth_none(self.session, ptr::null()) })
    }

    fn auth_list(&mut self) -> Methods {
        // SAFETY: the session; NULL for the user it was set with.
        let methods = unsafe { sys::ssh_userauth_list(self.session, ptr::null()) };
        Methods(methods.cast_unsigned())
    }

    fn try_publickey(&mut self) -> Auth {
        // SAFETY: the session, and the public key it read, NULL if none.
        auth(unsafe { sys::ssh_userauth_try_publickey(self.session, ptr::null(), self.pubkey) })
    }

    fn import_privkey_file(&mut self, file: &[u8], passphrase: Option<&[u8]>) -> Rc {
        let (Ok(file), Ok(pass)) = (terminated(file), passphrase.map(terminated).transpose())
        else {
            return Rc::Error;
        };
        let pass = pass.as_ref().map_or(ptr::null(), |p| p.as_ptr().cast());
        let mut key = ptr::null_mut();
        // SAFETY: C strings, or NULL for no passphrase, no callback, and an
        // out-pointer libssh sets to a key of its own.
        let got = unsafe {
            sys::ssh_pki_import_privkey_file(
                file.as_ptr().cast(),
                pass,
                ptr::null(),
                ptr::null_mut(),
                &raw mut key,
            )
        };
        drop(Key(core::mem::replace(&mut self.privkey, key)));
        rc(got)
    }

    fn auth_publickey(&mut self) -> Auth {
        // SAFETY: the session, and the private key it read.
        auth(unsafe { sys::ssh_userauth_publickey(self.session, ptr::null(), self.privkey) })
    }

    fn auth_publickey_auto(&mut self, passphrase: Option<&[u8]>) -> Auth {
        let Ok(pass) = passphrase.map(terminated).transpose() else {
            return Auth::Error;
        };
        let pass = pass.as_ref().map_or(ptr::null(), |p| p.as_ptr().cast());
        // SAFETY: the session, and a C string or NULL.
        auth(unsafe { sys::ssh_userauth_publickey_auto(self.session, ptr::null(), pass) })
    }

    fn auth_gssapi(&mut self) -> Auth {
        // SAFETY: the session.
        auth(unsafe { sys::ssh_userauth_gssapi(self.session) })
    }

    fn auth_kbdint(&mut self) -> Auth {
        // SAFETY: the session; NULL for its user and the default methods.
        auth(unsafe { sys::ssh_userauth_kbdint(self.session, ptr::null(), ptr::null()) })
    }

    fn kbdint_prompts(&mut self) -> i32 {
        // SAFETY: the session.
        unsafe { sys::ssh_userauth_kbdint_getnprompts(self.session) }
    }

    fn kbdint_answer(&mut self, i: u32, answer: &[u8]) -> i32 {
        let Ok(z) = terminated(answer) else {
            return -1;
        };
        // SAFETY: the session, and a C string libssh copies.
        unsafe { sys::ssh_userauth_kbdint_setanswer(self.session, i, z.as_ptr().cast()) }
    }

    fn auth_password(&mut self, password: &[u8]) -> Auth {
        let Ok(z) = terminated(password) else {
            return Auth::Error;
        };
        // SAFETY: the session; NULL for its user, and a C string.
        auth(unsafe { sys::ssh_userauth_password(self.session, ptr::null(), z.as_ptr().cast()) })
    }

    fn disconnect(&mut self) {
        if let Socket::Taken(fd) = self.socket {
            // SAFETY: the session.
            let held = unsafe { sys::ssh_get_fd(self.session) } == fd;
            // The goodbye lets go of a socket still open; one a failure
            // closed is gone.
            self.socket = if held {
                Socket::LetGo(fd)
            } else {
                Socket::None
            };
        }
        // SAFETY: the session.
        unsafe { sys::ssh_disconnect(self.session) };
    }

    fn scp_new(&mut self, write: bool, path: &[u8]) -> bool {
        let Ok(z) = terminated(path) else {
            return false;
        };
        let mode = if write {
            sys::SSH_SCP_WRITE
        } else {
            sys::SSH_SCP_READ
        };
        self.scp_free();
        // SAFETY: the session, and a C string libssh copies.
        self.scp = unsafe { sys::ssh_scp_new(self.session, mode, z.as_ptr().cast()) };
        !self.scp.is_null()
    }

    fn has_scp(&self) -> bool {
        !self.scp.is_null()
    }

    fn scp_init(&mut self) -> Rc {
        // SAFETY: the channel.
        rc(unsafe { sys::ssh_scp_init(self.scp()) })
    }

    fn scp_push_file(&mut self, path: &[u8], size: u64, mode: u32) -> Rc {
        let Ok(z) = terminated(path) else {
            return Rc::Error;
        };
        let scp = self.scp();
        // SAFETY: the channel, and a C string libssh reads for the call.
        rc(unsafe { sys::ssh_scp_push_file64(scp, z.as_ptr().cast(), size, mode.cast_signed()) })
    }

    fn scp_pull_request(&mut self) -> ScpRequest {
        // SAFETY: the channel.
        match unsafe { sys::ssh_scp_pull_request(self.scp()) } {
            sys::SSH_SCP_REQUEST_NEWFILE => ScpRequest::NewFile,
            _ => ScpRequest::Other,
        }
    }

    fn scp_size(&mut self) -> u64 {
        // SAFETY: the channel.
        unsafe { sys::ssh_scp_request_get_size64(self.scp()) }
    }

    fn scp_read(&mut self, buf: &mut [u8]) -> Result<usize, Failed> {
        let scp = self.scp();
        // SAFETY: the channel, and a buffer of `buf.len()` bytes libssh
        // writes no more than.
        let n = unsafe { sys::ssh_scp_read(scp, buf.as_mut_ptr().cast(), buf.len()) };
        usize::try_from(n).map_err(|_| Failed)
    }

    fn scp_write(&mut self, bytes: &[u8]) -> Rc {
        let scp = self.scp();
        // SAFETY: the channel, and `bytes.len()` bytes libssh reads.
        rc(unsafe { sys::ssh_scp_write(scp, bytes.as_ptr().cast(), bytes.len()) })
    }

    fn scp_close(&mut self) -> Rc {
        // SAFETY: the channel.
        rc(unsafe { sys::ssh_scp_close(self.scp()) })
    }

    fn scp_free(&mut self) {
        if !self.scp.is_null() {
            // SAFETY: the channel libssh made, freed once: its pointer is
            // cleared.
            unsafe { sys::ssh_scp_free(self.scp) };
            self.scp = ptr::null_mut();
        }
    }

    fn sftp_new(&mut self) -> bool {
        self.sftp_free();
        // SAFETY: the session.
        self.sftp = unsafe { sys::sftp_new(self.session) };
        !self.sftp.is_null()
    }

    fn has_sftp(&self) -> bool {
        !self.sftp.is_null()
    }

    fn sftp_init(&mut self) -> Rc {
        // SAFETY: the SFTP session.
        rc(unsafe { sys::sftp_init(self.sftp()) })
    }

    fn sftp_error(&mut self) -> u32 {
        // SAFETY: the SFTP session.
        let code = unsafe { sys::sftp_get_error(self.sftp()) };
        code.cast_unsigned()
    }

    fn canonicalize(&mut self, path: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
        let made = self.on_path(path, ptr::null_mut(), |sftp, p| {
            // SAFETY: the SFTP session, and a C string libssh reads.
            unsafe { sys::sftp_canonicalize_path(sftp, p) }
        });
        LibsshString(made).copied()
    }

    fn opendir(&mut self, path: &[u8]) -> bool {
        self.dir = self.on_path(path, ptr::null_mut(), |sftp, p| {
            // SAFETY: the SFTP session, and a C string libssh reads.
            unsafe { sys::sftp_opendir(sftp, p) }
        });
        !self.dir.is_null()
    }

    fn readdir(&mut self) -> Result<Option<Attrs>, OutOfMemory> {
        assert!(!self.dir.is_null(), "a listing of an open directory");
        // SAFETY: the SFTP session and its open directory.
        let made = unsafe { sys::sftp_readdir(self.sftp(), self.dir) };
        Attributes(made).copied()
    }

    fn dir_eof(&mut self) -> bool {
        assert!(!self.dir.is_null(), "a listing of an open directory");
        // SAFETY: the open directory.
        unsafe { sys::sftp_dir_eof(self.dir) != 0 }
    }

    fn closedir(&mut self) {
        if !self.dir.is_null() {
            // SAFETY: the open directory, closed once: its pointer is
            // cleared.
            unsafe { sys::sftp_closedir(self.dir) };
            self.dir = ptr::null_mut();
        }
    }

    fn lstat(&mut self, path: &[u8]) -> Result<Option<Attrs>, OutOfMemory> {
        self.attributes(path, sys::sftp_lstat)
    }

    fn readlink(&mut self, path: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
        let made = self.on_path(path, ptr::null_mut(), |sftp, p| {
            // SAFETY: the SFTP session, and a C string libssh reads.
            unsafe { sys::sftp_readlink(sftp, p) }
        });
        LibsshString(made).copied()
    }

    fn stat(&mut self, path: &[u8]) -> Result<Option<Attrs>, OutOfMemory> {
        self.attributes(path, sys::sftp_stat)
    }

    fn stat_to_change(&mut self, path: &[u8]) -> bool {
        let made = self.on_path(path, ptr::null_mut(), |sftp, p| {
            // SAFETY: the SFTP session, and a C string libssh reads.
            unsafe { sys::sftp_stat(sftp, p) }
        });
        drop(Attributes(core::mem::replace(&mut self.quote_attrs, made)));
        !self.quote_attrs.is_null()
    }

    fn setstat_kept(&mut self, path: &[u8], change: AttrChange) -> Rc {
        assert!(!self.quote_attrs.is_null(), "attributes kept to change");
        {
            // SAFETY: the attributes kept, which libssh made and this owns,
            // changed through no other pointer.
            let a = unsafe { &mut *self.quote_attrs };
            match change {
                AttrChange::Gid(gid) => {
                    a.gid = gid;
                    a.flags |= sys::SSH_FILEXFER_ATTR_UIDGID;
                }
                AttrChange::Uid(uid) => {
                    a.uid = uid;
                    a.flags |= sys::SSH_FILEXFER_ATTR_UIDGID;
                }
                AttrChange::Permissions(mode) => {
                    a.permissions = mode;
                    a.flags |= sys::SSH_FILEXFER_ATTR_PERMISSIONS;
                }
                AttrChange::Atime(t) => {
                    a.atime = t;
                    a.flags |= sys::SSH_FILEXFER_ATTR_ACMODTIME;
                }
                AttrChange::Mtime(t) => {
                    a.mtime = t;
                    a.flags |= sys::SSH_FILEXFER_ATTR_ACMODTIME;
                }
            }
        }
        let attrs = self.quote_attrs;
        self.on_path(path, Rc::Error, |sftp, p| {
            // SAFETY: the SFTP session, a C string, and the attributes
            // kept, which libssh reads.
            zero_ok(unsafe { sys::sftp_setstat(sftp, p, attrs) })
        })
    }

    fn symlink(&mut self, target: &[u8], dest: &[u8]) -> Rc {
        self.on_paths(target, dest, |sftp, t, d| {
            // SAFETY: the SFTP session and two C strings libssh reads.
            unsafe { sys::sftp_symlink(sftp, t, d) }
        })
    }

    fn mkdir(&mut self, path: &[u8], mode: u32) -> Rc {
        self.on_path(path, Rc::Error, |sftp, p| {
            // SAFETY: the SFTP session, and a C string libssh reads.
            zero_ok(unsafe { sys::sftp_mkdir(sftp, p, mode) })
        })
    }

    fn rename(&mut self, from: &[u8], to: &[u8]) -> Rc {
        self.on_paths(from, to, |sftp, f, t| {
            // SAFETY: the SFTP session and two C strings libssh reads.
            unsafe { sys::sftp_rename(sftp, f, t) }
        })
    }

    fn rmdir(&mut self, path: &[u8]) -> Rc {
        self.on_path(path, Rc::Error, |sftp, p| {
            // SAFETY: the SFTP session, and a C string libssh reads.
            zero_ok(unsafe { sys::sftp_rmdir(sftp, p) })
        })
    }

    fn unlink(&mut self, path: &[u8]) -> Rc {
        self.on_path(path, Rc::Error, |sftp, p| {
            // SAFETY: the SFTP session, and a C string libssh reads.
            zero_ok(unsafe { sys::sftp_unlink(sftp, p) })
        })
    }

    fn open(&mut self, path: &[u8], mode: OpenMode, perms: u32) -> bool {
        let flags = match mode {
            OpenMode::Read => sys::O_RDONLY,
            OpenMode::Truncate => sys::O_WRONLY | sys::O_CREAT | sys::O_TRUNC,
            OpenMode::Append => sys::O_WRONLY | sys::O_CREAT | sys::O_APPEND,
            OpenMode::Write => sys::O_WRONLY,
        };
        self.close_file();
        self.file = self.on_path(path, ptr::null_mut(), |sftp, p| {
            // SAFETY: the SFTP session, and a C string libssh reads.
            unsafe { sys::sftp_open(sftp, p, flags, perms) }
        });
        !self.file.is_null()
    }

    fn has_file(&self) -> bool {
        !self.file.is_null()
    }

    fn close_file(&mut self) {
        if !self.file.is_null() {
            // SAFETY: the open file, closed once: its pointer is cleared.
            unsafe { sys::sftp_close(self.file) };
            self.file = ptr::null_mut();
        }
    }

    fn seek(&mut self, offset: u64) -> Rc {
        // SAFETY: the open file.
        zero_ok(unsafe { sys::sftp_seek64(self.file(), offset) })
    }

    fn fstat(&mut self) -> Result<Option<Attrs>, OutOfMemory> {
        // SAFETY: the open file.
        let made = unsafe { sys::sftp_fstat(self.file()) };
        Attributes(made).copied()
    }

    fn file_nonblocking(&mut self) {
        // SAFETY: the open file.
        unsafe { sys::sftp_file_set_nonblocking(self.file()) };
    }

    fn begin_read(&mut self, len: usize) -> Rc {
        let file = self.file();
        // SAFETY: the open file, and the slot for the read under way, which
        // libssh sets.
        let n = unsafe { sys::sftp_aio_begin_read(file, len, &raw mut self.recv_aio) };
        if n == sys::SSH_ERROR as isize {
            Rc::Error
        } else {
            Rc::Ok
        }
    }

    fn wait_read(&mut self, buf: &mut [u8]) -> Aio {
        // SAFETY: the read under way, which libssh frees and clears unless
        // it waits, and a buffer of `buf.len()` bytes it writes no more
        // than.
        let n = unsafe {
            sys::sftp_aio_wait_read(&raw mut self.recv_aio, buf.as_mut_ptr().cast(), buf.len())
        };
        aio(n)
    }

    fn begin_write(&mut self, bytes: &[u8]) -> Rc {
        let file = self.file();
        // SAFETY: the open file, `bytes.len()` bytes libssh copies, and the
        // slot for the write under way, which libssh sets.
        let n = unsafe {
            sys::sftp_aio_begin_write(
                file,
                bytes.as_ptr().cast(),
                bytes.len(),
                &raw mut self.send_aio,
            )
        };
        if n == sys::SSH_ERROR as isize {
            Rc::Error
        } else {
            Rc::Ok
        }
    }

    fn wait_write(&mut self) -> Aio {
        // SAFETY: the write under way, which libssh frees and clears unless
        // it waits.
        aio(unsafe { sys::sftp_aio_wait_write(&raw mut self.send_aio) })
    }

    fn free_aio(&mut self) {
        for slot in [&mut self.send_aio, &mut self.recv_aio] {
            if !slot.is_null() {
                // SAFETY: a read or write under way, freed once: its
                // pointer is cleared.
                unsafe { sys::sftp_aio_free(*slot) };
                *slot = ptr::null_mut();
            }
        }
    }

    fn sftp_free(&mut self) {
        self.free_aio();
        self.close_file();
        // C leaves a listing cut short open, and its memory with it.
        self.closedir();
        if !self.sftp.is_null() {
            // SAFETY: the SFTP session, freed once: its pointer is cleared.
            unsafe { sys::sftp_free(self.sftp) };
            self.sftp = ptr::null_mut();
        }
    }
}

/// What an asynchronous wait's `n` says.
fn aio(n: isize) -> Aio {
    if n == sys::SSH_AGAIN as isize {
        Aio::Again
    } else {
        usize::try_from(n).map_or(Aio::Error, Aio::Done)
    }
}

impl Drop for Libsession {
    /// What C's cleanup frees (`sshc_cleanup`): the SFTP session and what
    /// it has open, the SCP channel, the kept attributes and keys, then
    /// the session, and its copy of the socket if libssh has let go of it
    /// open: one it still holds, it closes as it is freed.
    fn drop(&mut self) {
        self.sftp_free();
        self.scp_free();
        drop(Attributes(core::mem::replace(
            &mut self.quote_attrs,
            ptr::null_mut(),
        )));
        drop(Key(core::mem::replace(&mut self.privkey, ptr::null_mut())));
        drop(Key(core::mem::replace(&mut self.pubkey, ptr::null_mut())));
        // SAFETY: the session libssh made, freed once, here, after what it
        // had open.
        unsafe { sys::ssh_free(self.session) };
        if let Socket::Given(fd) | Socket::LetGo(fd) = self.socket {
            // SAFETY: the session's copy of the socket, which libssh never
            // took up or let go of open, closed once, here.
            unsafe { sys::close(fd) };
        }
    }
}

#[cfg(test)]
mod tests;
