//! A scripted wolfSSL for the session's tests: each call made of it is
//! written down in order and answers as the world says, and a call that
//! may read or write runs a script of what the library would do inside it
//! through the same `Call` the real library's callbacks reach. A scripted
//! socket carries what it writes and reads.

use std::ffi::{CStr, c_void};
use std::ptr::NonNull;
use std::sync::{Arc, Mutex, MutexGuard};

use curl_alloc::{OutOfMemory, TryArc};
use curl_core::error::ErrorKind;
pub(crate) use curl_core::tls::Wire;
use curl_core::tls::{DriveCall, TlsCx};

use crate::library::{
    self, AlpnGot, Call, FileType, Moved, NewSession, NoCtx, PeerCert, Rc, Resume, Tls12Keys, Words,
};
use crate::sys;

/// wolfSSL's `SOCKET_ERROR_E`: the BIO failed.
pub(crate) const SOCKET_ERROR_E: i32 = -308;
/// wolfSSL's `SOCKET_PEER_CLOSED_E`: the BIO read the end.
pub(crate) const SOCKET_PEER_CLOSED_E: i32 = -397;

/// One thing the library does inside a call.
#[derive(Clone, Debug)]
pub(crate) enum Act {
    /// It writes these bytes: a wait or a failure ends the call so.
    Push(&'static [u8]),
    /// It reads up to this many bytes: none, the call waits.
    Pull(usize),
    /// It hands the caller of a read these bytes, decrypted.
    Deliver(&'static [u8]),
    /// It tells of a new session.
    Session(NewSession),
    /// It answers this, which `wolfSSL_get_error` details so.
    Return(Rc, i32),
}

/// What the fake library holds, and what it was asked.
#[derive(Debug)]
pub(crate) struct World {
    /// Each call made, in order.
    pub(crate) calls: Vec<String>,
    /// The calls, by name, that answer this number the next time, in
    /// place of their default.
    pub(crate) answers: Vec<(&'static str, Rc)>,
    /// The calls, by name, that refuse what they are given.
    pub(crate) refuse: Vec<&'static str>,
    /// The scripts of the calls that may move bytes, by name, each run
    /// once in order.
    pub(crate) scripts: Vec<(&'static str, Vec<Act>)>,
    /// What `wolfSSL_get_error` says of the last call's answer.
    pub(crate) detail: i32,
    pub(crate) no_ctx: Option<NoCtx>,
    pub(crate) no_ssl: bool,
    pub(crate) version: &'static [u8],
    pub(crate) cipher: Option<&'static [u8]>,
    pub(crate) ciphers: Vec<&'static [u8]>,
    pub(crate) session_early: u32,
    pub(crate) alpn: AlpnGot,
    pub(crate) peer: PeerCert,
    pub(crate) check_ip: Option<Rc>,
    pub(crate) check_host: Option<Rc>,
    pub(crate) resume: Resume,
    pub(crate) early_rejected: bool,
    pub(crate) pending: bool,
    pub(crate) sent_shutdown: bool,
    pub(crate) wants: (bool, bool),
    pub(crate) keys: Option<Tls12Keys>,
    /// The stores made, by number; a store's references may not be
    /// counted where this says.
    pub(crate) stores: u32,
    pub(crate) uncounted: bool,
    /// What the session's pulls read, in order.
    pub(crate) pulled: Vec<u8>,
    /// The ECHConfigList `wolfSSL_GetEchConfigs` answers, none for a
    /// failure.
    pub(crate) ech_configs: Option<Vec<u8>>,
}

impl Default for World {
    fn default() -> World {
        World {
            calls: Vec::new(),
            answers: Vec::new(),
            refuse: Vec::new(),
            scripts: Vec::new(),
            detail: 0,
            no_ctx: None,
            no_ssl: false,
            version: b"TLSv1.3",
            cipher: Some(b"TLS13-AES128-GCM-SHA256"),
            ciphers: vec![
                b"TLS13-AES128-GCM-SHA256",
                b"ECDHE-RSA-AES128-GCM-SHA256",
                b"TLS13-AES256-GCM-SHA384",
                b"ECDHE-ECDSA-AES256-GCM-SHA384",
            ],
            session_early: 0,
            alpn: AlpnGot::NotFound,
            peer: PeerCert::Der(b"leaf-der".to_vec()),
            check_ip: Some(1),
            check_host: Some(1),
            resume: Resume::Done,
            early_rejected: false,
            pending: false,
            sent_shutdown: false,
            wants: (false, false),
            keys: None,
            stores: 0,
            uncounted: false,
            pulled: Vec::new(),
            ech_configs: None,
        }
    }
}

impl World {
    /// `name`'s answer, written down: the world's, if it has one, else
    /// `default`.
    fn answer(&mut self, name: &'static str, line: String, default: Rc) -> Rc {
        self.calls.push(line);
        match self.answers.iter().position(|(n, _)| *n == name) {
            Some(at) => self.answers.remove(at).1,
            None => default,
        }
    }

    /// `name` written down: whether it takes what it is given.
    fn takes(&mut self, name: &'static str, line: String) -> bool {
        self.calls.push(line);
        !self.refuse.contains(&name)
    }

    fn script(&mut self, name: &'static str) -> Option<Vec<Act>> {
        let at = self.scripts.iter().position(|(n, _)| *n == name)?;
        Some(self.scripts.remove(at).1)
    }

    /// The calls whose name starts with `prefix`, in order.
    pub(crate) fn made(&self, prefix: &str) -> Vec<&str> {
        self.calls
            .iter()
            .map(String::as_str)
            .filter(|c| c.starts_with(prefix))
            .collect()
    }
}

/// The fake library; each test makes its own, and leaks it, as the
/// session holds its library for good.
#[derive(Debug)]
pub(crate) struct Fake(pub(crate) Arc<Mutex<World>>);

/// Every library made, so that what is leaked stays reachable: Miri does
/// not take it for a leak.
static MADE: Mutex<Vec<&'static Fake>> = Mutex::new(Vec::new());

impl Fake {
    /// A library over `world`.
    pub(crate) fn new(world: World) -> &'static Fake {
        let lib = Box::leak(Box::new(Fake(Arc::new(Mutex::new(world)))));
        MADE.lock().unwrap_or_else(|e| e.into_inner()).push(lib);
        lib
    }

    pub(crate) fn w(&self) -> MutexGuard<'_, World> {
        self.0.lock().unwrap()
    }
}

/// A store of the fake library's, by number.
#[derive(Debug)]
pub(crate) struct FakeStore(u32, Arc<Mutex<World>>);

impl library::Store for FakeStore {
    fn another(&self) -> Option<FakeStore> {
        let mut w = self.1.lock().unwrap();
        w.calls.push(format!("up_ref({})", self.0));
        (!w.uncounted).then(|| FakeStore(self.0, self.1.clone()))
    }
}

impl library::Wolfssl for Fake {
    type Ctx = FakeCtx;
    type Store = FakeStore;
    type Method = ();

    fn ctx(&self, _: &TryArc<()>) -> Result<FakeCtx, NoCtx> {
        let mut w = self.w();
        w.calls.push("ctx".into());
        if let Some(no) = w.no_ctx {
            return Err(no);
        }
        w.stores += 1;
        let store = w.stores;
        Ok(FakeCtx {
            world: self.0.clone(),
            store,
        })
    }

    fn new_store(&self) -> Option<FakeStore> {
        let mut w = self.w();
        w.stores += 1;
        let n = w.stores;
        w.calls.push(format!("new_store -> {n}"));
        (!w.refuse.contains(&"new_store")).then(|| FakeStore(n, self.0.clone()))
    }

    fn strerror(&self, error: u32) -> Words {
        let words: &[u8] = match error.cast_signed() {
            -188 => b"ASN no signer error to confirm failure",
            -308 => b"error state on socket",
            _ => b"",
        };
        Words::new(words, error)
    }

    fn cipher(&self, index: usize) -> Option<&'static [u8]> {
        self.w().ciphers.get(index).copied()
    }
}

/// The fake library's context.
#[derive(Debug)]
pub(crate) struct FakeCtx {
    world: Arc<Mutex<World>>,
    /// The number of its store.
    store: u32,
}

fn text(c: &CStr) -> String {
    c.to_string_lossy().into_owned()
}

fn bytes(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

impl FakeCtx {
    fn w(&self) -> MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }
}

impl library::Ctx for FakeCtx {
    type Store = FakeStore;
    type Ssl = FakeSsl;

    fn min_version(&mut self, version: u16) -> bool {
        self.w()
            .takes("min_version", format!("min_version({version:#x})"))
    }

    fn max_version(&mut self, version: u16) -> bool {
        self.w()
            .takes("max_version", format!("max_version({version:#x})"))
    }

    fn cipher_list(&mut self, list: Option<&CStr>) -> bool {
        let shown = list.map_or("null".into(), text);
        self.w()
            .takes("cipher_list", format!("cipher_list({shown})"))
    }

    fn groups(&mut self, list: &CStr) -> bool {
        self.w().takes("groups", format!("groups({})", text(list)))
    }

    fn cert_chain_buffer(&mut self, pem: &[u8]) -> Rc {
        self.w()
            .answer("cert", format!("cert_chain_buffer({})", bytes(pem)), 1)
    }

    fn cert_chain_file(&mut self, file: &CStr) -> Rc {
        self.w()
            .answer("cert", format!("cert_chain_file({})", text(file)), 1)
    }

    fn cert_buffer(&mut self, cert: &[u8], kind: FileType) -> Rc {
        self.w()
            .answer("cert", format!("cert_buffer({}, {kind:?})", bytes(cert)), 1)
    }

    fn cert_file(&mut self, file: &CStr, kind: FileType) -> Rc {
        self.w()
            .answer("cert", format!("cert_file({}, {kind:?})", text(file)), 1)
    }

    fn key_buffer(&mut self, key: &[u8], kind: FileType) -> Rc {
        self.w()
            .answer("key", format!("key_buffer({}, {kind:?})", bytes(key)), 1)
    }

    fn key_file(&mut self, file: &CStr, kind: FileType) -> Rc {
        self.w()
            .answer("key", format!("key_file({}, {kind:?})", text(file)), 1)
    }

    fn verify(&mut self, peer: bool) {
        self.w().calls.push(format!("verify({peer})"));
    }

    fn sni(&mut self, name: &[u8]) -> bool {
        self.w().takes("sni", format!("sni({})", bytes(name)))
    }

    fn tell_sessions(&mut self) {
        self.w().calls.push("tell_sessions".into());
    }

    fn system_ca(&mut self) -> bool {
        self.w().takes("system_ca", "system_ca".into())
    }

    fn ca_buffer(&mut self, pem: &[u8]) -> bool {
        self.w()
            .takes("ca_buffer", format!("ca_buffer({})", bytes(pem)))
    }

    fn ca_locations(&mut self, file: Option<&CStr>, path: Option<&CStr>) -> bool {
        let (f, p) = (file.map(text), path.map(text));
        self.w()
            .takes("ca_locations", format!("ca_locations({f:?}, {p:?})"))
    }

    fn uses_store(&self, store: &FakeStore) -> bool {
        self.store == store.0
    }

    fn store(&self) -> Option<FakeStore> {
        let mut w = self.w();
        w.calls.push(format!("store -> {}", self.store));
        (!w.uncounted).then(|| FakeStore(self.store, self.world.clone()))
    }

    fn set_store(&mut self, store: FakeStore) {
        self.w().calls.push(format!("set_store({})", store.0));
        self.store = store.0;
    }

    fn native(&self) -> NonNull<c_void> {
        NonNull::<u64>::dangling().cast()
    }

    fn ssl(&mut self) -> Result<FakeSsl, OutOfMemory> {
        let mut w = self.w();
        w.calls.push("ssl".into());
        if w.no_ssl {
            return Err(OutOfMemory);
        }
        Ok(FakeSsl(self.world.clone()))
    }
}

/// What a call into the QUIC library is lent: the fake's call and session,
/// and the check, each borrowed for the length of the call.
struct Driving<'d, 's, 'a> {
    call: &'d mut Call<'s, 'a>,
    ssl: &'d mut FakeSsl,
    check: &'d mut dyn FnMut(&mut FakeSsl, &mut TlsCx<'_>) -> Result<(), ErrorKind>,
}

impl DriveCall for Driving<'_, '_, '_> {
    fn handshake_done(&mut self) -> Result<(), ErrorKind> {
        self.ssl.note("handshake_done".into());
        (self.check)(self.ssl, self.call.io.cx())
    }

    fn with_cx(&mut self, f: &mut dyn FnMut(&mut TlsCx<'_>)) {
        f(self.call.io.cx());
    }
}

/// The fake library's session object.
#[derive(Debug)]
pub(crate) struct FakeSsl(Arc<Mutex<World>>);

impl FakeSsl {
    fn w(&self) -> MutexGuard<'_, World> {
        self.0.lock().unwrap()
    }

    fn note(&self, line: String) {
        self.w().calls.push(line);
    }

    /// Run `name`'s script, else `default`, inside `call`, reading into
    /// `buf` if given: the call's answer, its detail kept for `error`. The
    /// world is not held while the script reaches the callbacks.
    fn run(
        &mut self,
        name: &'static str,
        call: &mut Call<'_, '_>,
        mut buf: Option<&mut [u8]>,
        default: Vec<Act>,
    ) -> Rc {
        let acts = self.w().script(name).unwrap_or(default);
        let (rc, detail) = 'run: {
            for act in acts {
                match act {
                    Act::Push(bytes) => match call.send(bytes) {
                        Moved::Bytes(_) => {}
                        Moved::Again => break 'run (-1, sys::WOLFSSL_ERROR_WANT_WRITE),
                        Moved::Failed | Moved::Refused => break 'run (-1, SOCKET_ERROR_E),
                    },
                    Act::Pull(n) => {
                        let mut room = vec![0u8; n];
                        match call.recv(&mut room) {
                            Moved::Bytes(0) => break 'run (-1, SOCKET_PEER_CLOSED_E),
                            Moved::Bytes(k) => self.w().pulled.extend_from_slice(&room[..k]),
                            Moved::Again => break 'run (-1, sys::WOLFSSL_ERROR_WANT_READ),
                            Moved::Failed | Moved::Refused => break 'run (-1, SOCKET_ERROR_E),
                        }
                    }
                    Act::Deliver(bytes) => {
                        let buf = buf.as_deref_mut().expect("a read");
                        buf[..bytes.len()].copy_from_slice(bytes);
                        break 'run (Rc::try_from(bytes.len()).unwrap(), 0);
                    }
                    Act::Session(made) => call.new_session(made),
                    Act::Return(rc, detail) => break 'run (rc, detail),
                }
            }
            (1, 0)
        };
        self.w().detail = detail;
        rc
    }
}

impl library::Ssl for FakeSsl {
    fn resume(&mut self, der: &[u8]) -> Resume {
        let mut w = self.w();
        w.calls.push(format!("resume({})", bytes(der)));
        w.resume
    }

    fn version_name(&self) -> &'static [u8] {
        self.w().version
    }

    fn before_tls13(&self) -> bool {
        self.w().version != b"TLSv1.3"
    }

    fn cipher_name(&self) -> Option<&'static [u8]> {
        self.w().cipher
    }

    fn session_max_early_data(&self) -> u32 {
        self.w().session_early
    }

    fn max_early_data(&mut self, most: u32) {
        self.note(format!("max_early_data({most})"));
    }

    fn alpn(&mut self, list: &[u8]) -> bool {
        self.w().takes("alpn", format!("alpn({})", bytes(list)))
    }

    fn ech_configs_base64(&mut self, b64: &[u8]) -> bool {
        self.w().takes(
            "ech_configs_base64",
            format!("ech_configs_base64({})", bytes(b64)),
        )
    }

    fn set_ech_configs(&mut self, list: &[u8]) -> bool {
        self.w().takes(
            "set_ech_configs",
            format!("set_ech_configs({} bytes)", list.len()),
        )
    }

    fn ech_configs(&self) -> Option<Vec<u8>> {
        let mut w = self.w();
        w.calls.push("ech_configs".into());
        w.ech_configs.clone()
    }

    fn min_version(&mut self, version: u16) -> bool {
        self.w()
            .takes("ssl_min_version", format!("ssl_min_version({version:#x})"))
    }

    fn keep_arrays(&mut self) {
        self.note("keep_arrays".into());
    }

    fn free_arrays(&mut self) {
        self.note("free_arrays".into());
    }

    fn tls12_keys(&self) -> Option<Tls12Keys> {
        self.w().keys.clone()
    }

    fn check_domain(&mut self, name: &CStr) -> bool {
        self.w()
            .takes("check_domain", format!("check_domain({})", text(name)))
    }

    fn quic_codepoint(&mut self) {
        self.note("quic_codepoint".into());
    }

    fn bio(&mut self) -> Result<(), OutOfMemory> {
        self.note("bio".into());
        Ok(())
    }

    /// The script `drive` runs inside the call, then `op`.
    fn drive(
        &mut self,
        call: &mut Call<'_, '_>,
        check: &mut dyn FnMut(&mut FakeSsl, &mut TlsCx<'_>) -> Result<(), ErrorKind>,
        op: &mut dyn FnMut(&mut dyn DriveCall),
    ) {
        self.note("drive".into());
        self.run("drive", call, None, Vec::new());
        op(&mut Driving {
            call,
            ssl: self,
            check,
        });
    }

    fn connect(&mut self, call: &mut Call<'_, '_>) -> Rc {
        self.note("connect".into());
        self.run("connect", call, None, vec![Act::Return(1, 0)])
    }

    fn error(&self, rc: Rc) -> i32 {
        if rc > 0 { 0 } else { self.w().detail }
    }

    fn wants_read(&self) -> bool {
        self.w().wants.0
    }

    fn wants_write(&self) -> bool {
        self.w().wants.1
    }

    fn write_early(&mut self, call: &mut Call<'_, '_>, bytes: &[u8]) -> (Rc, usize) {
        self.note(format!("write_early({})", bytes.len()));
        let all = Rc::try_from(bytes.len()).unwrap();
        let rc = self.run("write_early", call, None, vec![Act::Return(all, 0)]);
        (rc, usize::try_from(rc).unwrap_or(0))
    }

    fn early_rejected(&self) -> bool {
        self.w().early_rejected
    }

    fn read(&mut self, call: &mut Call<'_, '_>, buf: &mut [u8]) -> Rc {
        self.note(format!("read({})", buf.len()));
        self.run(
            "read",
            call,
            Some(buf),
            vec![Act::Return(-1, sys::WOLFSSL_ERROR_WANT_READ)],
        )
    }

    fn write(&mut self, call: &mut Call<'_, '_>, bytes: &[u8]) -> Rc {
        self.note(format!("write({})", bytes.len()));
        let all = Rc::try_from(bytes.len()).unwrap();
        self.run("write", call, None, vec![Act::Return(all, 0)])
    }

    fn shutdown(&mut self, call: &mut Call<'_, '_>) -> Rc {
        self.note("shutdown".into());
        self.run("shutdown", call, None, vec![Act::Return(1, 0)])
    }

    fn sent_shutdown(&self) -> bool {
        self.w().sent_shutdown
    }

    fn pending(&self) -> bool {
        self.w().pending
    }

    fn peer_cert(&self) -> PeerCert {
        self.w().peer.clone()
    }

    fn check_ip(&self, ip: &CStr) -> Option<Rc> {
        let mut w = self.w();
        w.calls.push(format!("check_ip({})", text(ip)));
        w.check_ip
    }

    fn check_host(&self, name: &[u8]) -> Option<Rc> {
        let mut w = self.w();
        w.calls.push(format!("check_host({})", bytes(name)));
        w.check_host
    }

    fn alpn_selected(&self) -> AlpnGot {
        self.w().alpn.clone()
    }

    fn native(&self) -> NonNull<c_void> {
        NonNull::<u32>::dangling().cast()
    }
}
