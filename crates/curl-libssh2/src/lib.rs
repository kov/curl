//! SCP and SFTP from libssh2 (`lib/vssh/libssh2.c`): the session over the
//! socket the connection lends it, its known-hosts collection and agent,
//! its logins, and the SCP channel, SFTP session and file or directory it
//! has open, each freed with it. The calls are libssh2's, one for one
//! with C's.

#![allow(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

mod sys;

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;
use std::sync::OnceLock;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::ssh2::{
    AttrFlags, Attrs, Blocking, Check, Code, Crypto, DirEntry, Failed, Fx, Gave, HostKeyType,
    Identity, KeyForm, KnownEntry, KnownKeyType, Let, OpenMode, Pipes, PollFlags, Session2, Ssh2,
    Statvfs, Took,
};
use curl_os::socket::BorrowedSocket;

/// libssh2, as C's build uses it.
#[derive(Debug)]
pub struct Libssh2;

/// The library each handle speaks SSH with.
pub static LIBSSH2: Libssh2 = Libssh2;

/// The library's version, as `curl -V` names it after `libssh2/`
/// (`libssh2_version(0)`).
pub fn version() -> &'static str {
    version_c().to_str().expect("libssh2's version is ASCII")
}

/// The library's version as `curl_version_info` gives it, a C string the
/// library keeps.
pub fn version_c() -> &'static CStr {
    // SAFETY: with 0, `libssh2_version` returns the library's version, a
    // static string of its own.
    let v = unsafe { sys::libssh2_version(0) };
    assert!(!v.is_null(), "libssh2 names its version");
    // SAFETY: as above, a C string libssh2 keeps for good.
    unsafe { CStr::from_ptr(v) }
}

/// libssh2's own setup, once for the process, as C's global init makes
/// it (`Curl_ssh_init`); whether it went well.
fn init() -> bool {
    static INIT: OnceLock<bool> = OnceLock::new();
    *INIT.get_or_init(|| {
        // SAFETY: with 0, the library sets up its crypto; once, here,
        // before any session is made.
        unsafe { sys::libssh2_init(0) == 0 }
    })
}

impl Ssh2 for Libssh2 {
    fn session(&self) -> Option<Box<dyn Session2>> {
        if !init() {
            return None;
        }
        let shared = Box::into_raw(curl_alloc::try_box(Shared::default()).ok()?);
        // The library's own allocators: C's go to the C library's
        // untracked ones, as these do.
        // SAFETY: NULL functions ask for the library's defaults; the
        // abstract pointer is the session's `Shared`, which outlives it.
        let session = unsafe {
            sys::libssh2_session_init_ex(ptr::null(), ptr::null(), ptr::null(), shared.cast())
        };
        if session.is_null() {
            // SAFETY: made by `Box::into_raw` above, and named by nothing
            // else.
            drop(unsafe { Box::from_raw(shared) });
            return None;
        }
        let made = Libsession {
            session,
            kh: ptr::null_mut(),
            found: ptr::null_mut(),
            agent: ptr::null_mut(),
            identity: ptr::null_mut(),
            prev_identity: ptr::null_mut(),
            sftp: ptr::null_mut(),
            handle: ptr::null_mut(),
            channel: ptr::null_mut(),
            shared,
            scratch: Vec::new(),
            name: [0; PATH_MAX + 1],
            long: [0; PATH_MAX + 1],
        };
        // A box that cannot be made drops the session, which frees it.
        let boxed: Box<dyn Session2> = curl_alloc::try_box(made).ok()?;
        Some(boxed)
    }

    fn crypto(&self) -> Crypto {
        // SAFETY: no arguments; the backend the library was built with.
        match unsafe { sys::libssh2_crypto_engine() } {
            sys::libssh2_openssl => Crypto::OpenSsl,
            sys::libssh2_gcrypt => Crypto::Gcrypt,
            sys::libssh2_mbedtls => Crypto::MbedTls,
            sys::libssh2_wincng => Crypto::WinCng,
            sys::libssh2_os400qc3 => Crypto::Os400Qc3,
            _ => Crypto::Other,
        }
    }
}

/// The size of C's buffers for a name, a link's target or a listing's
/// line (`CURL_PATH_MAX`).
const PATH_MAX: usize = 1024;

/// What the session's callbacks reach through its abstract pointer, which
/// names this from the session's making to its freeing: the password the
/// keyboard-interactive callback answers with, and the pipes the send and
/// receive callbacks use once they are set.
#[derive(Debug, Default)]
struct Shared {
    password: Vec<u8>,
    pipes: Option<Pipes>,
}

/// A session and what it has open, each NULL until made: C's `ssh_conn`'s
/// libssh2 handles.
#[derive(Debug)]
struct Libsession {
    session: *mut sys::LIBSSH2_SESSION,
    kh: *mut sys::LIBSSH2_KNOWNHOSTS,
    /// The known-hosts entry the last check found, which the collection
    /// owns.
    found: *mut sys::libssh2_knownhost,
    agent: *mut sys::LIBSSH2_AGENT,
    /// The agent's identity got, and the one passed over last, which the
    /// agent owns.
    identity: *mut sys::libssh2_agent_publickey,
    prev_identity: *mut sys::libssh2_agent_publickey,
    sftp: *mut sys::LIBSSH2_SFTP,
    handle: *mut sys::LIBSSH2_SFTP_HANDLE,
    channel: *mut sys::LIBSSH2_CHANNEL,
    /// Made by `Box::into_raw`, freed after the session: never a
    /// reference while a libssh2 call runs, as its callbacks reach it.
    shared: *mut Shared,
    /// The C strings of a call that may be made again and again while it
    /// would wait, its room kept from one to the next.
    scratch: Vec<u8>,
    /// C's `readdir_filename` and `readdir_longentry`.
    name: [u8; PATH_MAX + 1],
    long: [u8; PATH_MAX + 1],
}

// SAFETY: libssh2's handles are tied to no thread: a session and what it
// has open are used by one thread at a time, whoever owns this, as C's
// connection uses them from whichever thread runs its transfer.
unsafe impl Send for Libsession {}

/// `text` up to its first zero byte, as C reads a string, with a NUL
/// after it, for libssh2.
fn terminated(text: &[u8]) -> Result<Vec<u8>, Code> {
    let text = text.split(|&b| b == 0).next().unwrap_or_default();
    let mut z = Vec::new();
    z.try_reserve_exact(text.len() + 1)
        .map_err(|_| Code::ALLOC)?;
    z.try_extend_from_slice(text).map_err(|_| Code::ALLOC)?;
    z.try_push(0).map_err(|_| Code::ALLOC)?;
    Ok(z)
}

/// `texts`, each up to its first zero byte with a NUL after it, one after
/// the other in `scratch`, emptied first, whose room is kept for the next
/// call: where each starts.
fn terminate<const N: usize>(scratch: &mut Vec<u8>, texts: [&[u8]; N]) -> Result<[usize; N], Code> {
    scratch.clear();
    let mut at = [0; N];
    for (start, text) in at.iter_mut().zip(texts) {
        let text = text.split(|&b| b == 0).next().unwrap_or_default();
        *start = scratch.len();
        scratch
            .try_extend_from_slice(text)
            .map_err(|_| Code::ALLOC)?;
        scratch.try_push(0).map_err(|_| Code::ALLOC)?;
    }
    Ok(at)
}

/// A length libssh2 takes as an `unsigned int`; one past it is no path or
/// name C could pass, which C's cast would cut short.
fn uint_len(bytes: &[u8]) -> c_uint {
    c_uint::try_from(bytes.len()).unwrap_or(c_uint::MAX)
}

/// The bytes of a C string libssh2 keeps, up to its NUL; none for NULL.
///
/// # Safety
///
/// `s` is NULL or a C string that lives as long as `'a`.
unsafe fn c_bytes<'a>(s: *const c_char) -> Option<&'a [u8]> {
    if s.is_null() {
        return None;
    }
    // SAFETY: not NULL, a C string, as the caller says.
    Some(unsafe { CStr::from_ptr(s) }.to_bytes())
}

/// A copy of `bytes`.
fn copy(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_extend_from_slice(bytes)?;
    Ok(v)
}

/// What a call answering 0 for success and a negative error came to.
fn rc(rc: c_int) -> Result<(), Code> {
    if rc == 0 { Ok(()) } else { Err(Code(rc)) }
}

/// What a read or write answering a count or a negative error came to.
fn count(n: isize) -> Result<usize, Code> {
    usize::try_from(n).map_err(|_| Code(i32::try_from(n).unwrap_or(i32::MIN)))
}

/// A known-hosts entry's key type, from its type mask.
fn known_kind(typemask: c_int) -> KnownKeyType {
    let bits = (typemask & sys::LIBSSH2_KNOWNHOST_KEY_MASK) >> sys::LIBSSH2_KNOWNHOST_KEY_SHIFT;
    KnownKeyType(u8::try_from(bits).expect("four bits"))
}

/// The type mask bits of a known-hosts entry's key type.
fn known_bits(kind: KnownKeyType) -> c_int {
    (c_int::from(kind.0) << sys::LIBSSH2_KNOWNHOST_KEY_SHIFT) & sys::LIBSSH2_KNOWNHOST_KEY_MASK
}

// An `unsigned long` is 32 bits on Windows, 64 elsewhere.
#[allow(clippy::useless_conversion)]
fn from_attrs(a: &sys::LIBSSH2_SFTP_ATTRIBUTES) -> Attrs {
    Attrs {
        flags: AttrFlags(u64::from(a.flags)),
        filesize: a.filesize,
        uid: u64::from(a.uid),
        gid: u64::from(a.gid),
        permissions: u64::from(a.permissions),
        atime: u64::from(a.atime),
        mtime: u64::from(a.mtime),
    }
}

/// Attributes as libssh2 takes them, each field cut to an `unsigned
/// long` as C's are.
fn to_attrs(a: &Attrs) -> sys::LIBSSH2_SFTP_ATTRIBUTES {
    let ulong = |v: u64| v as c_ulong;
    sys::LIBSSH2_SFTP_ATTRIBUTES {
        flags: ulong(a.flags.0),
        filesize: a.filesize,
        uid: ulong(a.uid),
        gid: ulong(a.gid),
        permissions: ulong(a.permissions),
        atime: ulong(a.atime),
        mtime: ulong(a.mtime),
    }
}

/// The keyboard-interactive callback (`kbd_callback`): a question asked
/// alone answered with the password, copied with the C library's
/// `malloc`, which libssh2 frees it with.
unsafe extern "C" fn kbd_callback(
    _name: *const c_char,
    _name_len: c_int,
    _instruction: *const c_char,
    _instruction_len: c_int,
    num_prompts: c_int,
    _prompts: *const sys::LIBSSH2_USERAUTH_KBDINT_PROMPT,
    responses: *mut sys::LIBSSH2_USERAUTH_KBDINT_RESPONSE,
    abstract_: *mut *mut c_void,
) {
    if num_prompts != 1 {
        return;
    }
    // SAFETY: as `shared` says.
    let shared = unsafe { shared(abstract_) };
    let password = &shared.password;
    // SAFETY: room for the password and its NUL, or NULL.
    let text = unsafe { libc::malloc(password.len() + 1) }.cast::<u8>();
    let length = if text.is_null() {
        0
    } else {
        // SAFETY: `text` has room for the password and its NUL.
        unsafe { ptr::copy_nonoverlapping(password.as_ptr(), text, password.len()) };
        // SAFETY: as above, its last byte.
        let end = unsafe { text.add(password.len()) };
        // SAFETY: as above.
        unsafe { end.write(0) };
        c_uint::try_from(password.len()).unwrap_or(c_uint::MAX)
    };
    // SAFETY: libssh2 passes one response for each of its prompts, of
    // which there is one.
    let response = unsafe { &mut *responses };
    response.text = text.cast();
    response.length = length;
}

/// The session's `Shared`, from inside one of its callbacks.
///
/// # Safety
///
/// `abstract_` is what libssh2 passes a callback of the session's: a
/// pointer to its abstract pointer, which names the session's `Shared`,
/// reached by nothing else while the libssh2 call that runs the callback
/// does.
unsafe fn shared<'a>(abstract_: *mut *mut c_void) -> &'a mut Shared {
    // SAFETY: as the caller says.
    let named = unsafe { *abstract_ };
    // SAFETY: as the caller says.
    unsafe { &mut *named.cast::<Shared>() }
}

/// The receive callback over the session's pipes (`ssh_tls_recv`): what
/// came for it, or `-EAGAIN` while nothing has.
unsafe extern "C" fn pipe_recv(
    _socket: sys::libssh2_socket_t,
    buffer: *mut c_void,
    length: usize,
    _flags: c_int,
    abstract_: *mut *mut c_void,
) -> isize {
    // SAFETY: as `shared` says.
    let shared = unsafe { shared(abstract_) };
    let Some(pipes) = shared.pipes.as_mut() else {
        return -1;
    };
    if length == 0 {
        return 0;
    }
    // SAFETY: libssh2 passes room for `length` bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(buffer.cast::<u8>(), length) };
    match pipes.take(buf) {
        Took::Bytes(n) => isize::try_from(n).expect("at most the buffer's length"),
        Took::Wait => -(libc::EAGAIN as isize),
        Took::End => 0,
        Took::Broken => -1,
    }
}

/// The send callback over the session's pipes (`ssh_tls_send`): all of
/// `buffer` taken, or `-EAGAIN` while what it took before has not gone.
unsafe extern "C" fn pipe_send(
    _socket: sys::libssh2_socket_t,
    buffer: *const c_void,
    length: usize,
    _flags: c_int,
    abstract_: *mut *mut c_void,
) -> isize {
    // SAFETY: as `shared` says.
    let shared = unsafe { shared(abstract_) };
    let Some(pipes) = shared.pipes.as_mut() else {
        return -1;
    };
    if length == 0 {
        return 0;
    }
    // SAFETY: libssh2 passes `length` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(buffer.cast::<u8>(), length) };
    match pipes.give(bytes) {
        Gave::All => isize::try_from(length).expect("a buffer's length"),
        Gave::Wait => -(libc::EAGAIN as isize),
        Gave::Broken => -1,
    }
}

impl Libsession {
    /// The session's `Shared`, while no libssh2 call runs: `&mut self`
    /// makes none.
    fn shared(&mut self) -> &mut Shared {
        // SAFETY: made by `Box::into_raw` and freed only on drop; no
        // callback reaches it while no call of the session's runs.
        unsafe { &mut *self.shared }
    }

    fn sftp(&self) -> *mut sys::LIBSSH2_SFTP {
        assert!(!self.sftp.is_null(), "an SFTP call within its session");
        self.sftp
    }

    fn handle(&self) -> *mut sys::LIBSSH2_SFTP_HANDLE {
        assert!(!self.handle.is_null(), "a file call on an open file");
        self.handle
    }

    fn channel(&self) -> *mut sys::LIBSSH2_CHANNEL {
        assert!(!self.channel.is_null(), "a channel call on an open channel");
        self.channel
    }

    fn kh(&self) -> *mut sys::LIBSSH2_KNOWNHOSTS {
        assert!(!self.kh.is_null(), "a known-hosts call on its collection");
        self.kh
    }

    fn agent(&self) -> *mut sys::LIBSSH2_AGENT {
        assert!(!self.agent.is_null(), "an agent call on the agent");
        self.agent
    }

    fn errno(&self) -> Code {
        // SAFETY: the session libssh2 made.
        Code(unsafe { sys::libssh2_session_last_errno(self.session) })
    }

    /// What a call that made a handle, or NULL, came to.
    fn made<T>(&self, p: *mut T) -> Result<*mut T, Code> {
        if p.is_null() {
            Err(self.errno())
        } else {
            Ok(p)
        }
    }

    /// Open `path` with `flags`, `mode` and `kind`.
    fn open(&mut self, path: &[u8], flags: c_ulong, mode: c_long, kind: c_int) -> Result<(), Code> {
        // SAFETY: the SFTP session, and the path's bytes for the call.
        let h = unsafe {
            sys::libssh2_sftp_open_ex(
                self.sftp(),
                path.as_ptr().cast(),
                uint_len(path),
                flags,
                mode,
                kind,
            )
        };
        self.handle = self.made(h)?;
        Ok(())
    }

    /// `libssh2_sftp_symlink_ex` of `kind` for `path` into the name
    /// buffer: the bytes it wrote, or what it failed with.
    fn symlink_into(&mut self, path: &[u8], kind: c_int) -> Result<usize, Code> {
        // SAFETY: the SFTP session, the path's bytes for the call, and the
        // buffer of `PATH_MAX` bytes, its last left for a NUL.
        let n = unsafe {
            sys::libssh2_sftp_symlink_ex(
                self.sftp(),
                path.as_ptr().cast(),
                uint_len(path),
                self.name.as_mut_ptr().cast(),
                PATH_MAX as c_uint,
                kind,
            )
        };
        usize::try_from(n)
            .map(|n| n.min(PATH_MAX))
            .map_err(|_| Code(n))
    }

    /// Free the channel, keeping it if the call would wait and `let_go`
    /// says to.
    fn freed(&mut self, rc: c_int, let_go: Let) -> Result<bool, Code> {
        if rc == sys::LIBSSH2_ERROR_EAGAIN && let_go == Let::Wait {
            return Err(Code(rc));
        }
        Ok(rc >= 0)
    }
}

impl Session2 for Libsession {
    fn set_read_timeout(&mut self, secs: i64) {
        // SAFETY: the session libssh2 made.
        unsafe { sys::libssh2_session_set_read_timeout(self.session, secs as c_long) };
    }

    fn enable_compression(&mut self) -> Result<(), Code> {
        // SAFETY: the session libssh2 made, and a flag of its.
        let n = unsafe { sys::libssh2_session_flag(self.session, sys::LIBSSH2_FLAG_COMPRESS, 1) };
        if n < 0 { Err(Code(n)) } else { Ok(()) }
    }

    fn set_blocking(&mut self, blocking: Blocking) {
        let b = c_int::from(blocking == Blocking::Yes);
        // SAFETY: the session libssh2 made.
        unsafe { sys::libssh2_session_set_blocking(self.session, b) };
    }

    fn set_hostkey_methods(&mut self, prefs: &[u8]) -> Result<(), Code> {
        let z = terminated(prefs)?;
        // SAFETY: the session libssh2 made, and a C string it copies.
        rc(unsafe {
            sys::libssh2_session_method_pref(
                self.session,
                sys::LIBSSH2_METHOD_HOSTKEY,
                z.as_ptr().cast(),
            )
        })
    }

    fn last_error(&self) -> (Code, Vec<u8>) {
        let mut msg = ptr::null_mut();
        // SAFETY: the session libssh2 made, and an out-pointer it sets to
        // a message of its own, alive until its next call.
        let n = unsafe {
            sys::libssh2_session_last_error(self.session, &raw mut msg, ptr::null_mut(), 0)
        };
        // SAFETY: NULL or the session's message, alive for this call.
        let text = unsafe { c_bytes(msg) }.unwrap_or_default();
        (Code(n), copy(text).unwrap_or_default())
    }

    fn last_errno(&self) -> Code {
        self.errno()
    }

    fn block_directions(&self) -> PollFlags {
        // SAFETY: the session libssh2 made.
        let dir = unsafe { sys::libssh2_session_block_directions(self.session) };
        PollFlags {
            read: dir & sys::LIBSSH2_SESSION_BLOCK_INBOUND != 0,
            write: dir & sys::LIBSSH2_SESSION_BLOCK_OUTBOUND != 0,
        }
    }

    fn knownhost_init(&mut self) -> Result<(), Failed> {
        assert!(self.kh.is_null(), "one known-hosts collection a session");
        // SAFETY: the session libssh2 made.
        self.kh = unsafe { sys::libssh2_knownhost_init(self.session) };
        if self.kh.is_null() {
            Err(Failed)
        } else {
            Ok(())
        }
    }

    fn has_knownhosts(&self) -> bool {
        !self.kh.is_null()
    }

    fn knownhost_readfile(&mut self, file: &[u8]) -> Result<(), Code> {
        let z = terminated(file)?;
        // SAFETY: the collection, and a C string for the call.
        let n = unsafe {
            sys::libssh2_knownhost_readfile(
                self.kh(),
                z.as_ptr().cast(),
                sys::LIBSSH2_KNOWNHOST_FILE_OPENSSH,
            )
        };
        if n < 0 { Err(Code(n)) } else { Ok(()) }
    }

    fn knownhost_entries(&self) -> Result<Vec<KnownEntry>, OutOfMemory> {
        let mut entries = Vec::new();
        let mut store: *mut sys::libssh2_knownhost = ptr::null_mut();
        loop {
            let prev = store;
            // SAFETY: the collection, an out-pointer it sets to an entry of
            // its own, and NULL or the entry it gave last.
            let n = unsafe { sys::libssh2_knownhost_get(self.kh(), &raw mut store, prev) };
            if n != 0 || store.is_null() {
                return Ok(entries);
            }
            // SAFETY: an entry the collection keeps, read only.
            let e = unsafe { &*store };
            let entry = KnownEntry {
                // SAFETY: NULL or the entry's own C strings.
                name: unsafe { c_bytes(e.name) }.map(copy).transpose()?,
                // SAFETY: as above.
                key: unsafe { c_bytes(e.key) }.map(copy).transpose()?,
                kind: known_kind(e.typemask),
            };
            entries.try_push(entry)?;
        }
    }

    fn knownhost_check(
        &mut self,
        host: &[u8],
        port: Option<u16>,
        key: &[u8],
        form: KeyForm,
        kind: KnownKeyType,
    ) -> Result<(Check, Option<Vec<u8>>), OutOfMemory> {
        let host = terminated(host).map_err(|_| OutOfMemory)?;
        let enc = match form {
            KeyForm::Raw => sys::LIBSSH2_KNOWNHOST_KEYENC_RAW,
            KeyForm::Base64 => sys::LIBSSH2_KNOWNHOST_KEYENC_BASE64,
        };
        let typemask = sys::LIBSSH2_KNOWNHOST_TYPE_PLAIN | enc | known_bits(kind);
        let mut found = ptr::null_mut();
        // SAFETY: the collection, the host's C string and the key's bytes
        // for the call, and an out-pointer it sets to an entry of its own.
        let n = unsafe {
            sys::libssh2_knownhost_checkp(
                self.kh(),
                host.as_ptr().cast(),
                port.map_or(-1, c_int::from),
                key.as_ptr().cast(),
                key.len(),
                typemask,
                &raw mut found,
            )
        };
        let check = match n {
            sys::LIBSSH2_KNOWNHOST_CHECK_MATCH => Check::Match,
            sys::LIBSSH2_KNOWNHOST_CHECK_MISMATCH => Check::Mismatch,
            sys::LIBSSH2_KNOWNHOST_CHECK_NOTFOUND => Check::NotFound,
            _ => Check::Failure,
        };
        let matched = matches!(check, Check::Match | Check::Mismatch);
        self.found = if matched { found } else { ptr::null_mut() };
        let known = if matched && !found.is_null() {
            // SAFETY: an entry the collection keeps, read only.
            let key = unsafe { (*found).key };
            // SAFETY: NULL or the entry's C string.
            unsafe { c_bytes(key) }.map(copy).transpose()?
        } else {
            None
        };
        Ok((check, known))
    }

    fn knownhost_del_found(&mut self) {
        if !self.found.is_null() {
            // SAFETY: the collection, and the entry of its the last check
            // found, deleted once.
            unsafe { sys::libssh2_knownhost_del(self.kh(), self.found) };
            self.found = ptr::null_mut();
        }
    }

    fn knownhost_add(&mut self, host: &[u8], key: &[u8], kind: KnownKeyType) -> Result<(), Code> {
        let host = terminated(host)?;
        let typemask = sys::LIBSSH2_KNOWNHOST_TYPE_PLAIN
            | sys::LIBSSH2_KNOWNHOST_KEYENC_RAW
            | known_bits(kind);
        // SAFETY: the collection, the host's C string and the key's bytes,
        // which it copies, and no salt, comment or store.
        rc(unsafe {
            sys::libssh2_knownhost_addc(
                self.kh(),
                host.as_ptr().cast(),
                ptr::null(),
                key.as_ptr().cast(),
                key.len(),
                ptr::null(),
                0,
                typemask,
                ptr::null_mut(),
            )
        })
    }

    fn knownhost_writefile(&mut self, file: &[u8]) -> Result<(), Code> {
        let z = terminated(file)?;
        // SAFETY: the collection, and a C string for the call.
        rc(unsafe {
            sys::libssh2_knownhost_writefile(
                self.kh(),
                z.as_ptr().cast(),
                sys::LIBSSH2_KNOWNHOST_FILE_OPENSSH,
            )
        })
    }

    fn knownhost_free(&mut self) {
        if !self.kh.is_null() {
            // SAFETY: the collection, freed once, here.
            unsafe { sys::libssh2_knownhost_free(self.kh) };
            self.kh = ptr::null_mut();
            self.found = ptr::null_mut();
        }
    }

    fn handshake(&mut self, socket: Option<BorrowedSocket<'_>>) -> Result<(), Code> {
        let Some(socket) = socket else {
            return Err(Code::SOCKET_NONE);
        };
        let raw = curl_os::socket::raw(socket);
        #[cfg(windows)]
        let raw = sys::libssh2_socket_t::try_from(raw).expect("a SOCKET is pointer-wide");
        // SAFETY: the session libssh2 made, and the connection's open
        // socket, which outlives the session, as the connection frees its
        // SSH state before it closes its socket.
        rc(unsafe { sys::libssh2_session_handshake(self.session, raw) })
    }

    fn use_pipes(&mut self) {
        self.shared().pipes = Some(Pipes::default());
        let recv: sys::recv_func = pipe_recv;
        let send: sys::send_func = pipe_send;
        // SAFETY: the callback of the type `LIBSSH2_CALLBACK_RECV` says,
        // cast to the generic type libssh2 takes and casts back before
        // calling.
        let recv = unsafe { core::mem::transmute::<sys::recv_func, sys::libssh2_cb_generic>(recv) };
        // SAFETY: as above, of `LIBSSH2_CALLBACK_SEND`'s type.
        let send = unsafe { core::mem::transmute::<sys::send_func, sys::libssh2_cb_generic>(send) };
        // SAFETY: the session libssh2 made, and a callback that reads the
        // pipes of the `Shared` its abstract pointer names.
        let _before = unsafe {
            sys::libssh2_session_callback_set2(self.session, sys::LIBSSH2_CALLBACK_RECV, Some(recv))
        };
        // SAFETY: as above.
        let _before = unsafe {
            sys::libssh2_session_callback_set2(self.session, sys::LIBSSH2_CALLBACK_SEND, Some(send))
        };
    }

    fn pipes(&mut self) -> Option<&mut Pipes> {
        self.shared().pipes.as_mut()
    }

    fn host_key(&self) -> Option<(&[u8], HostKeyType)> {
        let mut len = 0;
        let mut kind = 0;
        // SAFETY: the session libssh2 made, and out-pointers it sets.
        let key =
            unsafe { sys::libssh2_session_hostkey(self.session, &raw mut len, &raw mut kind) };
        if key.is_null() {
            return None;
        }
        // SAFETY: `len` bytes the session keeps until freed.
        let bytes = unsafe { core::slice::from_raw_parts(key.cast::<u8>(), len) };
        let kind = match kind {
            sys::LIBSSH2_HOSTKEY_TYPE_RSA => HostKeyType::Rsa,
            sys::LIBSSH2_HOSTKEY_TYPE_DSS => HostKeyType::Dss,
            sys::LIBSSH2_HOSTKEY_TYPE_ECDSA_256 => HostKeyType::Ecdsa256,
            sys::LIBSSH2_HOSTKEY_TYPE_ECDSA_384 => HostKeyType::Ecdsa384,
            sys::LIBSSH2_HOSTKEY_TYPE_ECDSA_521 => HostKeyType::Ecdsa521,
            sys::LIBSSH2_HOSTKEY_TYPE_ED25519 => HostKeyType::Ed25519,
            _ => HostKeyType::Unknown,
        };
        Some((bytes, kind))
    }

    fn host_key_sha256(&self) -> Option<[u8; 32]> {
        // SAFETY: the session libssh2 made.
        let h =
            unsafe { sys::libssh2_hostkey_hash(self.session, sys::LIBSSH2_HOSTKEY_HASH_SHA256) };
        if h.is_null() {
            return None;
        }
        let mut out = [0u8; 32];
        // SAFETY: a SHA-256 hash of 32 bytes the session keeps.
        out.copy_from_slice(unsafe { core::slice::from_raw_parts(h.cast::<u8>(), 32) });
        Some(out)
    }

    fn host_key_md5(&self) -> Option<[u8; 16]> {
        // SAFETY: the session libssh2 made.
        let h = unsafe { sys::libssh2_hostkey_hash(self.session, sys::LIBSSH2_HOSTKEY_HASH_MD5) };
        if h.is_null() {
            return None;
        }
        let mut out = [0u8; 16];
        // SAFETY: an MD5 hash of 16 bytes the session keeps.
        out.copy_from_slice(unsafe { core::slice::from_raw_parts(h.cast::<u8>(), 16) });
        Some(out)
    }

    fn userauth_list(&mut self, user: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
        // SAFETY: the session libssh2 made, and the user's bytes for the
        // call; a list the session keeps, or NULL.
        let list = unsafe {
            sys::libssh2_userauth_list(self.session, user.as_ptr().cast(), uint_len(user))
        };
        // SAFETY: NULL or the session's C string, alive for this call.
        unsafe { c_bytes(list) }.map(copy).transpose()
    }

    fn authenticated(&self) -> bool {
        // SAFETY: the session libssh2 made.
        unsafe { sys::libssh2_userauth_authenticated(self.session) != 0 }
    }

    fn auth_publickey_fromfile(
        &mut self,
        user: &[u8],
        public: Option<&[u8]>,
        private: &[u8],
        passphrase: &[u8],
    ) -> Result<(), Code> {
        let [public_at, private, passphrase] = terminate(
            &mut self.scratch,
            [public.unwrap_or_default(), private, passphrase],
        )?;
        let z = &self.scratch;
        let public = public.map_or(ptr::null(), |_| z[public_at..].as_ptr());
        // SAFETY: the session libssh2 made, the user's bytes, and C strings
        // (the public key's or NULL) for the call.
        rc(unsafe {
            sys::libssh2_userauth_publickey_fromfile_ex(
                self.session,
                user.as_ptr().cast(),
                uint_len(user),
                public.cast(),
                z[private..].as_ptr().cast(),
                z[passphrase..].as_ptr().cast(),
            )
        })
    }

    fn auth_password(&mut self, user: &[u8], password: &[u8]) -> Result<(), Code> {
        // SAFETY: the session libssh2 made, the user's and password's bytes
        // for the call, and no callback for an expired password.
        rc(unsafe {
            sys::libssh2_userauth_password_ex(
                self.session,
                user.as_ptr().cast(),
                uint_len(user),
                password.as_ptr().cast(),
                uint_len(password),
                ptr::null(),
            )
        })
    }

    fn auth_keyboard_interactive(&mut self, user: &[u8], password: &[u8]) -> Result<(), Code> {
        let kept = &mut self.shared().password;
        kept.clear();
        kept.try_extend_from_slice(password.split(|&b| b == 0).next().unwrap_or_default())
            .map_err(|_| Code::ALLOC)?;
        // SAFETY: the session, the user's bytes for the call, and the
        // callback, which reads the password of the `Shared` the abstract
        // pointer names.
        let n = unsafe {
            sys::libssh2_userauth_keyboard_interactive_ex(
                self.session,
                user.as_ptr().cast(),
                uint_len(user),
                Some(kbd_callback),
            )
        };
        rc(n)
    }

    fn agent_init(&mut self) -> Result<(), Failed> {
        // SAFETY: the session libssh2 made.
        self.agent = unsafe { sys::libssh2_agent_init(self.session) };
        if self.agent.is_null() {
            Err(Failed)
        } else {
            Ok(())
        }
    }

    fn has_agent(&self) -> bool {
        !self.agent.is_null()
    }

    fn agent_connect(&mut self) -> Result<(), Code> {
        // SAFETY: the agent libssh2 made.
        let n = unsafe { sys::libssh2_agent_connect(self.agent()) };
        if n < 0 { Err(Code(n)) } else { Ok(()) }
    }

    fn agent_list_identities(&mut self) -> Result<(), Code> {
        // SAFETY: the agent libssh2 made.
        let n = unsafe { sys::libssh2_agent_list_identities(self.agent()) };
        if n < 0 { Err(Code(n)) } else { Ok(()) }
    }

    fn agent_rewind(&mut self) {
        self.prev_identity = ptr::null_mut();
    }

    fn agent_get_identity(&mut self) -> Result<Identity, Code> {
        // SAFETY: the agent libssh2 made, an out-pointer it sets to an
        // identity of its own, and NULL or the one passed over last.
        let n = unsafe {
            sys::libssh2_agent_get_identity(
                self.agent(),
                &raw mut self.identity,
                self.prev_identity,
            )
        };
        match n {
            0 => Ok(Identity::Got),
            1 => Ok(Identity::End),
            n => Err(Code(n)),
        }
    }

    fn agent_comment(&self) -> &[u8] {
        if self.identity.is_null() {
            return b"(nil)";
        }
        // SAFETY: an identity the agent keeps, read only.
        let comment = unsafe { (*self.identity).comment };
        // SAFETY: NULL or the identity's C string, alive with the agent.
        unsafe { c_bytes(comment) }.unwrap_or(b"(nil)")
    }

    fn agent_userauth(&mut self, user: &[u8]) -> Result<(), Code> {
        let [user] = terminate(&mut self.scratch, [user])?;
        assert!(!self.identity.is_null(), "an identity got to log in with");
        let user = self.scratch[user..].as_ptr();
        // SAFETY: the agent libssh2 made, the user's C string for the call,
        // and an identity of the agent's.
        let n = unsafe { sys::libssh2_agent_userauth(self.agent(), user.cast(), self.identity) };
        if n < 0 { Err(Code(n)) } else { Ok(()) }
    }

    fn agent_skip(&mut self) {
        self.prev_identity = self.identity;
    }

    fn agent_disconnect(&mut self) -> Result<(), Code> {
        // SAFETY: the agent libssh2 made.
        let n = unsafe { sys::libssh2_agent_disconnect(self.agent()) };
        if n < 0 { Err(Code(n)) } else { Ok(()) }
    }

    fn agent_free(&mut self) {
        if !self.agent.is_null() {
            // SAFETY: the agent, freed once, here, with the identities it
            // owns.
            unsafe { sys::libssh2_agent_free(self.agent) };
            self.agent = ptr::null_mut();
            self.identity = ptr::null_mut();
            self.prev_identity = ptr::null_mut();
        }
    }

    fn sftp_init(&mut self) -> Result<(), Code> {
        // SAFETY: the session libssh2 made.
        let s = unsafe { sys::libssh2_sftp_init(self.session) };
        self.sftp = self.made(s)?;
        Ok(())
    }

    fn has_sftp(&self) -> bool {
        !self.sftp.is_null()
    }

    // An `unsigned long` is 32 bits on Windows, 64 elsewhere.
    #[allow(clippy::useless_conversion)]
    fn sftp_last_error(&self) -> Fx {
        // SAFETY: the SFTP session.
        Fx(u64::from(unsafe {
            sys::libssh2_sftp_last_error(self.sftp())
        }))
    }

    fn sftp_realpath(&mut self, path: &[u8]) -> Result<&[u8], Code> {
        let n = self.symlink_into(path, sys::LIBSSH2_SFTP_REALPATH)?;
        if n == 0 {
            return Err(Code::NONE);
        }
        Ok(&self.name[..n])
    }

    fn sftp_open(&mut self, path: &[u8], mode: OpenMode, perms: u32) -> Result<(), Code> {
        let flags = match mode {
            OpenMode::Read => sys::LIBSSH2_FXF_READ,
            OpenMode::Truncate => {
                sys::LIBSSH2_FXF_WRITE | sys::LIBSSH2_FXF_CREAT | sys::LIBSSH2_FXF_TRUNC
            }
            OpenMode::Append => {
                sys::LIBSSH2_FXF_WRITE | sys::LIBSSH2_FXF_CREAT | sys::LIBSSH2_FXF_APPEND
            }
            OpenMode::Write => sys::LIBSSH2_FXF_WRITE,
        };
        self.open(path, flags, c_long::from(perms), sys::LIBSSH2_SFTP_OPENFILE)
    }

    fn sftp_opendir(&mut self, path: &[u8]) -> Result<(), Code> {
        self.open(path, 0, 0, sys::LIBSSH2_SFTP_OPENDIR)
    }

    fn has_handle(&self) -> bool {
        !self.handle.is_null()
    }

    fn sftp_stat(&mut self, path: &[u8]) -> Result<Attrs, Code> {
        let mut a = sys::LIBSSH2_SFTP_ATTRIBUTES::default();
        // SAFETY: the SFTP session, the path's bytes for the call, and the
        // attributes it fills.
        rc(unsafe {
            sys::libssh2_sftp_stat_ex(
                self.sftp(),
                path.as_ptr().cast(),
                uint_len(path),
                sys::LIBSSH2_SFTP_STAT,
                &raw mut a,
            )
        })?;
        Ok(from_attrs(&a))
    }

    fn sftp_setstat(&mut self, path: &[u8], attrs: &Attrs) -> Result<(), Code> {
        let mut a = to_attrs(attrs);
        // SAFETY: the SFTP session, the path's bytes for the call, and the
        // attributes it sends.
        rc(unsafe {
            sys::libssh2_sftp_stat_ex(
                self.sftp(),
                path.as_ptr().cast(),
                uint_len(path),
                sys::LIBSSH2_SFTP_SETSTAT,
                &raw mut a,
            )
        })
    }

    fn sftp_seek(&mut self, offset: u64) {
        // SAFETY: the open file.
        unsafe { sys::libssh2_sftp_seek64(self.handle(), offset) };
    }

    fn sftp_readdir(&mut self) -> Result<Option<DirEntry<'_>>, Code> {
        let mut a = sys::LIBSSH2_SFTP_ATTRIBUTES::default();
        self.long[0] = 0;
        // SAFETY: the open directory, the two buffers of `PATH_MAX` bytes,
        // the last of each left for a NUL, and the attributes it fills.
        let n = unsafe {
            sys::libssh2_sftp_readdir_ex(
                self.handle(),
                self.name.as_mut_ptr().cast(),
                PATH_MAX,
                self.long.as_mut_ptr().cast(),
                PATH_MAX,
                &raw mut a,
            )
        };
        let n = usize::try_from(n).map_err(|_| Code(n))?;
        if n == 0 {
            return Ok(None);
        }
        let n = n.min(PATH_MAX);
        self.long[PATH_MAX] = 0;
        let long_len = self.long.iter().position(|&b| b == 0).unwrap_or(PATH_MAX);
        Ok(Some(DirEntry {
            name: &self.name[..n],
            longentry: &self.long[..long_len],
            attrs: from_attrs(&a),
        }))
    }

    fn sftp_readlink(&mut self, path: &[u8]) -> Result<&[u8], Code> {
        let n = self.symlink_into(path, sys::LIBSSH2_SFTP_READLINK)?;
        // C reads the target as the C string the buffer holds.
        self.name[n.min(PATH_MAX)] = 0;
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(PATH_MAX);
        Ok(&self.name[..len])
    }

    fn sftp_symlink(&mut self, path: &[u8], target: &[u8]) -> Result<(), Code> {
        // SAFETY: the SFTP session, and both paths' bytes for the call; a
        // link's target is only read.
        rc(unsafe {
            sys::libssh2_sftp_symlink_ex(
                self.sftp(),
                path.as_ptr().cast(),
                uint_len(path),
                target.as_ptr().cast_mut().cast(),
                uint_len(target),
                sys::LIBSSH2_SFTP_SYMLINK,
            )
        })
    }

    fn sftp_mkdir(&mut self, path: &[u8], mode: u32) -> Result<(), Code> {
        // SAFETY: the SFTP session, and the path's bytes for the call.
        rc(unsafe {
            sys::libssh2_sftp_mkdir_ex(
                self.sftp(),
                path.as_ptr().cast(),
                uint_len(path),
                c_long::from(mode),
            )
        })
    }

    fn sftp_rename(&mut self, from: &[u8], to: &[u8]) -> Result<(), Code> {
        let flags = sys::LIBSSH2_SFTP_RENAME_OVERWRITE
            | sys::LIBSSH2_SFTP_RENAME_ATOMIC
            | sys::LIBSSH2_SFTP_RENAME_NATIVE;
        // SAFETY: the SFTP session, and both paths' bytes for the call.
        rc(unsafe {
            sys::libssh2_sftp_rename_ex(
                self.sftp(),
                from.as_ptr().cast(),
                uint_len(from),
                to.as_ptr().cast(),
                uint_len(to),
                flags,
            )
        })
    }

    fn sftp_rmdir(&mut self, path: &[u8]) -> Result<(), Code> {
        // SAFETY: the SFTP session, and the path's bytes for the call.
        rc(
            unsafe {
                sys::libssh2_sftp_rmdir_ex(self.sftp(), path.as_ptr().cast(), uint_len(path))
            },
        )
    }

    fn sftp_unlink(&mut self, path: &[u8]) -> Result<(), Code> {
        // SAFETY: the SFTP session, and the path's bytes for the call.
        rc(unsafe {
            sys::libssh2_sftp_unlink_ex(self.sftp(), path.as_ptr().cast(), uint_len(path))
        })
    }

    fn sftp_statvfs(&mut self, path: &[u8]) -> Result<Statvfs, Code> {
        let mut v = sys::LIBSSH2_SFTP_STATVFS::default();
        // SAFETY: the SFTP session, the path's bytes for the call, and the
        // structure it fills.
        rc(unsafe {
            sys::libssh2_sftp_statvfs(self.sftp(), path.as_ptr().cast(), path.len(), &raw mut v)
        })?;
        Ok(Statvfs {
            bsize: v.f_bsize,
            frsize: v.f_frsize,
            blocks: v.f_blocks,
            bfree: v.f_bfree,
            bavail: v.f_bavail,
            files: v.f_files,
            ffree: v.f_ffree,
            favail: v.f_favail,
            fsid: v.f_fsid,
            flag: v.f_flag,
            namemax: v.f_namemax,
        })
    }

    fn sftp_read(&mut self, buf: &mut [u8]) -> Result<usize, Code> {
        // SAFETY: the open file, and the buffer to fill.
        count(unsafe { sys::libssh2_sftp_read(self.handle(), buf.as_mut_ptr().cast(), buf.len()) })
    }

    fn sftp_write(&mut self, bytes: &[u8]) -> Result<usize, Code> {
        // SAFETY: the open file, and the bytes to send.
        count(unsafe { sys::libssh2_sftp_write(self.handle(), bytes.as_ptr().cast(), bytes.len()) })
    }

    fn sftp_close(&mut self, let_go: Let) -> Result<(), Code> {
        // SAFETY: the open file or directory, freed by the call unless it
        // would wait.
        let n = unsafe { sys::libssh2_sftp_close_handle(self.handle()) };
        let closed = self.freed(n, let_go)?;
        self.handle = ptr::null_mut();
        if closed { Ok(()) } else { Err(Code(n)) }
    }

    fn sftp_shutdown(&mut self, let_go: Let) -> Result<(), Code> {
        // SAFETY: the SFTP session, freed by the call unless it would wait.
        let n = unsafe { sys::libssh2_sftp_shutdown(self.sftp()) };
        let done = self.freed(n, let_go)?;
        self.sftp = ptr::null_mut();
        if done { Ok(()) } else { Err(Code(n)) }
    }

    fn scp_recv(&mut self, path: &[u8]) -> Result<i64, Code> {
        let [at] = terminate(&mut self.scratch, [path])?;
        let path = &self.scratch[at..];
        // SAFETY: a `struct stat` of zero bytes is a valid one.
        let mut sb: sys::libssh2_struct_stat = unsafe { core::mem::zeroed() };
        // SAFETY: the session libssh2 made, the path's C string for the
        // call, and the status it fills.
        let ch = unsafe { sys::libssh2_scp_recv2(self.session, path.as_ptr().cast(), &raw mut sb) };
        self.channel = self.made(ch)?;
        Ok(sb.st_size)
    }

    fn scp_send(&mut self, path: &[u8], mode: u32, size: i64) -> Result<(), Code> {
        let [at] = terminate(&mut self.scratch, [path])?;
        let path = &self.scratch[at..];
        // SAFETY: the session libssh2 made, and the path's C string for the
        // call; no times.
        let ch = unsafe {
            sys::libssh2_scp_send64(
                self.session,
                path.as_ptr().cast(),
                mode as c_int,
                size,
                0,
                0,
            )
        };
        self.channel = self.made(ch)?;
        Ok(())
    }

    fn has_channel(&self) -> bool {
        !self.channel.is_null()
    }

    fn channel_read(&mut self, buf: &mut [u8]) -> Result<usize, Code> {
        // SAFETY: the open channel, and the buffer to fill.
        count(unsafe {
            sys::libssh2_channel_read_ex(self.channel(), 0, buf.as_mut_ptr().cast(), buf.len())
        })
    }

    fn channel_write(&mut self, bytes: &[u8]) -> Result<usize, Code> {
        // SAFETY: the open channel, and the bytes to send.
        count(unsafe {
            sys::libssh2_channel_write_ex(self.channel(), 0, bytes.as_ptr().cast(), bytes.len())
        })
    }

    fn channel_send_eof(&mut self) -> Result<(), Code> {
        // SAFETY: the open channel.
        rc(unsafe { sys::libssh2_channel_send_eof(self.channel()) })
    }

    fn channel_wait_eof(&mut self) -> Result<(), Code> {
        // SAFETY: the open channel.
        rc(unsafe { sys::libssh2_channel_wait_eof(self.channel()) })
    }

    fn channel_wait_closed(&mut self) -> Result<(), Code> {
        // SAFETY: the open channel.
        rc(unsafe { sys::libssh2_channel_wait_closed(self.channel()) })
    }

    fn channel_free(&mut self, let_go: Let) -> Result<(), Code> {
        // SAFETY: the open channel, freed by the call unless it would wait.
        let n = unsafe { sys::libssh2_channel_free(self.channel()) };
        let freed = self.freed(n, let_go)?;
        self.channel = ptr::null_mut();
        if freed { Ok(()) } else { Err(Code(n)) }
    }

    fn disconnect(&mut self) -> Result<(), Code> {
        // SAFETY: the session libssh2 made, and C strings of its own.
        rc(unsafe {
            sys::libssh2_session_disconnect_ex(
                self.session,
                sys::SSH_DISCONNECT_BY_APPLICATION,
                c"Shutdown".as_ptr(),
                c"".as_ptr(),
            )
        })
    }

    fn has_session(&self) -> bool {
        !self.session.is_null()
    }

    fn session_free(&mut self, let_go: Let) -> Result<(), Code> {
        assert!(!self.session.is_null(), "a session freed once");
        // SAFETY: the session, freed by the call unless it would wait.
        let n = unsafe { sys::libssh2_session_free(self.session) };
        let freed = self.freed(n, let_go)?;
        self.session = ptr::null_mut();
        if freed { Ok(()) } else { Err(Code(n)) }
    }
}

impl Drop for Libsession {
    /// What is still open freed, blocking, in C's order (`sshc_cleanup`
    /// from the connection's destructor), each let go of whatever its
    /// call says.
    fn drop(&mut self) {
        self.knownhost_free();
        if !self.agent.is_null() {
            let _ignored = self.agent_disconnect();
            self.agent_free();
        }
        if !self.handle.is_null() {
            let _ignored = self.sftp_close(Let::Go);
        }
        if !self.channel.is_null() {
            let _ignored = self.channel_free(Let::Go);
        }
        if !self.sftp.is_null() {
            let _ignored = self.sftp_shutdown(Let::Go);
        }
        if !self.session.is_null() {
            let _ignored = self.session_free(Let::Go);
        }
        // SAFETY: made by `Box::into_raw`, and reached by no callback with
        // the session freed.
        drop(unsafe { Box::from_raw(self.shared) });
    }
}

#[cfg(test)]
mod tests;
