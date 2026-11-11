//! A scripted GnuTLS for the session's tests: each call made of it is
//! written down in order, answers as the world says, and a call that may
//! read or write the connection runs a script of what the library would
//! do inside it — writing, reading, telling of a handshake message or a
//! secret — through the same `Call` the real library's callbacks reach.
//! A scripted socket carries what it writes and reads.

use curl_alloc::{Lock, LockGuard};
use std::ffi::CStr;
use std::sync::Arc;

use curl_core::error::ErrorKind;
pub(crate) use curl_core::tls::Wire;
use curl_core::tls::{DriveCall, TlsCx};

use crate::library::{self, Call, Format, Moved, Rc, Stapled};
use crate::sys;

/// One thing the library does inside a call.
#[derive(Clone, Debug)]
pub(crate) enum Act {
    /// It writes these bytes: a wait or a failure below ends the call.
    Push(&'static [u8]),
    /// It writes these bytes, and goes on whatever came of it.
    TryPush(&'static [u8]),
    /// It reads up to this many bytes: none come, the call waits.
    Pull(usize),
    /// It hands the caller of a receive these bytes, decrypted.
    Deliver(&'static [u8]),
    /// It handled a handshake message of this type, the peer's if `true`.
    Hook(u32, bool),
    /// It tells of a secret, with this label.
    Secret(&'static [u8]),
    /// Its direction, for the call that waits.
    WantsWrite(bool),
    /// It answers.
    Return(isize),
}

/// The peer's certificate, as the world has it.
#[derive(Clone, Debug)]
pub(crate) struct Leaf {
    pub(crate) cn: Result<&'static [u8], Rc>,
    pub(crate) expiration: i64,
    pub(crate) activation: i64,
    pub(crate) host_ok: bool,
    pub(crate) issued: bool,
    pub(crate) public_key: Option<&'static [u8]>,
}

/// What the fake library holds, and what it was asked.
#[derive(Debug)]
pub(crate) struct World {
    /// Each call made, in order.
    pub(crate) calls: Vec<String>,
    /// The calls, by name, that answer this number the next time, in
    /// place of their default.
    pub(crate) answers: Vec<(&'static str, Rc)>,
    /// The scripts of the calls that may move bytes, by name, each run
    /// once in order.
    pub(crate) scripts: Vec<(&'static str, Vec<Act>)>,
    pub(crate) wants_write: bool,
    pub(crate) version: i32,
    pub(crate) alpn: &'static [u8],
    pub(crate) early_accepted: bool,
    pub(crate) max_early: usize,
    pub(crate) data: &'static [u8],
    pub(crate) chain: Option<Vec<&'static [u8]>>,
    pub(crate) status: Result<u32, Rc>,
    pub(crate) stapled: Stapled,
    pub(crate) leaf: Leaf,
    pub(crate) pending: bool,
    /// What the session's pulls read, in order.
    pub(crate) pulled: Vec<u8>,
}

impl Default for World {
    fn default() -> World {
        World {
            calls: Vec::new(),
            answers: Vec::new(),
            scripts: Vec::new(),
            wants_write: false,
            version: sys::GNUTLS_TLS1_3,
            alpn: b"",
            early_accepted: false,
            max_early: 0,
            data: b"",
            chain: Some(vec![b"leaf-der"]),
            status: Ok(0),
            stapled: Stapled::Status(sys::GNUTLS_OCSP_CERT_GOOD as u32),
            leaf: Leaf {
                cn: Ok(b"example.com"),
                expiration: 100,
                activation: -100,
                host_ok: true,
                issued: true,
                public_key: Some(b"spki"),
            },
            pending: false,
            pulled: Vec::new(),
        }
    }
}

impl World {
    pub(crate) fn call(&mut self, line: String) {
        self.calls.push(line);
    }

    /// `name`'s answer, written down: the world's, if it has one, else
    /// `default`.
    fn answer(&mut self, name: &'static str, line: String, default: Rc) -> Rc {
        self.calls.push(line);
        match self.answers.iter().position(|(n, _)| *n == name) {
            Some(at) => self.answers.remove(at).1,
            None => default,
        }
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
pub(crate) struct Fake(pub(crate) Arc<Lock<World>>);

/// Every library made, so that what is leaked stays reachable: Miri
/// does not take it for a leak.
static MADE: Lock<Vec<&'static Fake>> = Lock::new(Vec::new());

impl Fake {
    /// A library over `world`.
    pub(crate) fn new(world: World) -> &'static Fake {
        let lib = Box::leak(Box::new(Fake(Arc::new(Lock::new(world)))));
        MADE.lock().unwrap_or_else(|e| e.into_inner()).push(lib);
        lib
    }

    pub(crate) fn w(&self) -> LockGuard<'_, World> {
        self.0.lock().unwrap()
    }
}

fn lock(world: &Arc<Lock<World>>) -> LockGuard<'_, World> {
    world.lock().unwrap()
}

/// The library's words for a number.
fn words(rc: Rc) -> &'static [u8] {
    match rc {
        sys::GNUTLS_E_AGAIN => b"Resource temporarily unavailable, try again.",
        sys::GNUTLS_E_FATAL_ALERT_RECEIVED => b"A TLS fatal alert has been received.",
        sys::GNUTLS_E_WARNING_ALERT_RECEIVED => b"A TLS warning alert has been received.",
        sys::GNUTLS_E_NO_CERTIFICATE_FOUND => b"No certificate was found.",
        _ => b"an error",
    }
}

impl library::Gnutls for Fake {
    type Creds = FakeCreds;
    type Session = FakeSession;
    type Cert = FakeCert;

    fn creds(&self) -> Result<FakeCreds, Rc> {
        let rc = self.w().answer("creds", "creds".into(), 0);
        if rc < 0 {
            return Err(rc);
        }
        Ok(FakeCreds(self.0.clone()))
    }

    fn session(&self, flags: u32) -> Result<FakeSession, Rc> {
        let rc = self
            .w()
            .answer("session", format!("session(flags={flags:x})"), 0);
        if rc < 0 {
            return Err(rc);
        }
        Ok(FakeSession(self.0.clone()))
    }

    fn cert(&self) -> Result<FakeCert, Rc> {
        let rc = self.w().answer("cert", "cert".into(), 0);
        if rc < 0 {
            return Err(rc);
        }
        Ok(FakeCert(self.0.clone()))
    }

    fn strerror(&self, rc: Rc) -> &'static [u8] {
        words(rc)
    }

    fn is_fatal(&self, rc: Rc) -> bool {
        rc < 0
            && !matches!(
                rc,
                sys::GNUTLS_E_AGAIN
                    | sys::GNUTLS_E_INTERRUPTED
                    | sys::GNUTLS_E_WARNING_ALERT_RECEIVED
                    | sys::GNUTLS_E_REHANDSHAKE
            )
    }
}

/// Credentials, which write their loads down.
#[derive(Debug)]
pub(crate) struct FakeCreds(Arc<Lock<World>>);

fn text(c: &CStr) -> String {
    String::from_utf8_lossy(c.to_bytes()).into_owned()
}

impl library::Creds for FakeCreds {
    fn system_trust(&self) -> Rc {
        lock(&self.0).answer("system_trust", "system_trust".into(), 0)
    }
    fn trust_mem(&self, pem: &[u8]) -> Rc {
        lock(&self.0).answer("trust_mem", format!("trust_mem({})", pem.len()), 0)
    }
    fn allow_v1_ca(&self) {
        lock(&self.0).call("allow_v1_ca".into());
    }
    fn trust_file(&self, file: &CStr) -> Rc {
        lock(&self.0).answer("trust_file", format!("trust_file({})", text(file)), 0)
    }
    fn trust_dir(&self, dir: &CStr) -> Rc {
        lock(&self.0).answer("trust_dir", format!("trust_dir({})", text(dir)), 0)
    }
    fn crl_file(&self, file: &CStr) -> Rc {
        lock(&self.0).answer("crl_file", format!("crl_file({})", text(file)), 0)
    }
    fn pkcs12_file(&self, file: &CStr, password: &CStr) -> Rc {
        lock(&self.0).answer(
            "pkcs12_file",
            format!("pkcs12_file({}, {})", text(file), text(password)),
            0,
        )
    }
    fn key_file(&self, cert: &CStr, key: &CStr, format: Format, password: Option<&CStr>) -> Rc {
        lock(&self.0).answer(
            "key_file",
            format!(
                "key_file({}, {}, {format:?}, {:?})",
                text(cert),
                text(key),
                password.map(text)
            ),
            0,
        )
    }
}

/// A session, which runs the world's scripts.
#[derive(Debug)]
pub(crate) struct FakeSession(Arc<Lock<World>>);

impl FakeSession {
    fn w(&self) -> LockGuard<'_, World> {
        lock(&self.0)
    }

    /// Run `name`'s script, else `default`, inside `call`, receiving into
    /// `buf` if given: the call's answer. The world is not held while the
    /// script reaches the callbacks, which may come back to it.
    fn run(
        &mut self,
        name: &'static str,
        call: &mut Call<'_, '_, FakeCreds>,
        mut buf: Option<&mut [u8]>,
        default: Vec<Act>,
    ) -> isize {
        let acts = self.w().script(name).unwrap_or(default);
        for act in acts {
            match act {
                Act::Push(bytes) => match call.push(bytes) {
                    Moved::Bytes(_) => {}
                    Moved::Again => return sys::GNUTLS_E_AGAIN as isize,
                    Moved::Failed => return -53,
                },
                Act::TryPush(bytes) => {
                    call.push(bytes);
                }
                Act::Pull(n) => {
                    let mut room = vec![0u8; n];
                    let world = self.0.clone();
                    let mut set = |_: &FakeCreds| {
                        lock(&world).answer("credentials", "credentials (pull)".into(), 0)
                    };
                    match call.pull(&mut room, &mut set) {
                        Moved::Bytes(0) => return -110,
                        Moved::Bytes(k) => self.w().pulled.extend_from_slice(&room[..k]),
                        Moved::Again => return sys::GNUTLS_E_AGAIN as isize,
                        Moved::Failed => return -54,
                    }
                }
                Act::Deliver(bytes) => {
                    let buf = buf.as_deref_mut().expect("a receive");
                    buf[..bytes.len()].copy_from_slice(bytes);
                    return bytes.len() as isize;
                }
                Act::Hook(kind, incoming) => {
                    if call.handshake_message(kind, incoming) {
                        let (data, version, early) = {
                            let w = self.w();
                            (w.data.to_vec(), w.version, w.max_early)
                        };
                        call.keep_ticket(data, version, early);
                    }
                }
                Act::Secret(label) => {
                    call.keylog_secret(label, &[7; 32], b"secret");
                }
                Act::WantsWrite(w) => self.w().wants_write = w,
                Act::Return(rc) => return rc,
            }
        }
        0
    }
}

/// What the QUIC library's call is lent: the session, its call, and the
/// check, each reached for the length of one method.
struct Driving<'d, 's, 'a> {
    session: &'d mut FakeSession,
    call: &'d mut Call<'s, 'a, FakeCreds>,
    check: &'d mut dyn FnMut(&mut FakeSession, &mut TlsCx<'_>) -> Result<(), ErrorKind>,
}

impl DriveCall for Driving<'_, '_, '_> {
    fn handshake_done(&mut self) -> Result<(), ErrorKind> {
        (self.check)(self.session, self.call.io.cx())
    }

    fn with_cx(&mut self, f: &mut dyn FnMut(&mut TlsCx<'_>)) {
        f(self.call.io.cx());
    }
}

impl library::Session for FakeSession {
    type Creds = FakeCreds;
    type Cert = FakeCert;

    fn server_name(&mut self, name: &[u8]) -> Rc {
        let line = format!("server_name({})", String::from_utf8_lossy(name));
        self.w().answer("server_name", line, 0)
    }
    fn default_priority(&mut self) -> Rc {
        self.w()
            .answer("default_priority", "default_priority".into(), 0)
    }
    fn priority<'p>(&mut self, priority: &'p CStr) -> Result<(), (Rc, Option<&'p [u8]>)> {
        let rc = self
            .w()
            .answer("priority", format!("priority({})", text(priority)), 0);
        if rc < 0 {
            let bytes = priority.to_bytes();
            return Err((rc, Some(&bytes[bytes.len() / 2..])));
        }
        Ok(())
    }
    fn credentials(&mut self, _: &FakeCreds) -> Rc {
        self.w().answer("credentials", "credentials".into(), 0)
    }
    fn status_request(&mut self) -> Rc {
        self.w()
            .answer("status_request", "status_request".into(), 0)
    }
    fn set_data(&mut self, data: &[u8]) -> Rc {
        let line = format!("set_data({})", String::from_utf8_lossy(data));
        self.w().answer("set_data", line, 0)
    }
    fn data(&mut self) -> Result<Vec<u8>, ErrorKind> {
        let mut w = self.w();
        w.call("data".into());
        Ok(w.data.to_vec())
    }
    fn max_early_data(&mut self) -> usize {
        self.w().max_early
    }
    fn alpn(&mut self, protocols: &[&[u8]]) -> Rc {
        let names: Vec<_> = protocols
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
        self.w()
            .answer("alpn", format!("alpn({})", names.join(",")), 0)
    }
    fn log_keys(&mut self) {
        self.w().call("log_keys".into());
    }
    fn hook(&mut self) {
        self.w().call("hook".into());
    }
    fn quic_hook(&mut self, tickets: bool) {
        self.w().call(format!("quic_hook(tickets={tickets})"));
    }
    /// The script of `drive` runs first, as GnuTLS's callbacks would
    /// inside the QUIC library's call, then the call itself.
    fn drive(
        &mut self,
        call: &mut Call<'_, '_, FakeCreds>,
        check: &mut dyn FnMut(&mut FakeSession, &mut TlsCx<'_>) -> Result<(), ErrorKind>,
        op: &mut dyn FnMut(&mut dyn DriveCall),
    ) {
        self.w().call("drive".into());
        self.run("drive", call, None, Vec::new());
        let mut driving = Driving {
            session: self,
            call,
            check,
        };
        op(&mut driving);
    }

    fn handshake(&mut self, call: &mut Call<'_, '_, FakeCreds>) -> Rc {
        self.w().call("handshake".into());
        self.run("handshake", call, None, vec![Act::Return(0)]) as Rc
    }
    fn send(&mut self, call: &mut Call<'_, '_, FakeCreds>, bytes: &[u8]) -> isize {
        self.w().call(format!("send({})", bytes.len()));
        let all = bytes.len() as isize;
        self.run("send", call, None, vec![Act::Return(all)])
    }
    fn recv(&mut self, call: &mut Call<'_, '_, FakeCreds>, buf: &mut [u8]) -> isize {
        self.w().call(format!("recv({})", buf.len()));
        self.run("recv", call, Some(buf), vec![Act::Return(0)])
    }
    fn send_early(&mut self, call: &mut Call<'_, '_, FakeCreds>, bytes: &[u8]) -> isize {
        self.w().call(format!("send_early({})", bytes.len()));
        let all = bytes.len() as isize;
        self.run("send_early", call, None, vec![Act::Return(all)])
    }
    fn bye(&mut self, call: &mut Call<'_, '_, FakeCreds>) -> Rc {
        self.w().call("bye".into());
        self.run("bye", call, None, vec![Act::Return(0)]) as Rc
    }

    fn wants_write(&mut self) -> bool {
        self.w().wants_write
    }
    fn alert_name(&mut self) -> Option<&'static [u8]> {
        Some(b"Handshake failed")
    }
    fn pending(&self) -> bool {
        self.w().pending
    }
    fn version(&mut self) -> i32 {
        self.w().version
    }
    fn version_name(&mut self) -> Option<&'static [u8]> {
        match self.w().version {
            sys::GNUTLS_TLS1_2 => Some(b"TLS1.2"),
            sys::GNUTLS_TLS1_3 => Some(b"TLS1.3"),
            _ => None,
        }
    }
    fn suite_name(&mut self) -> Option<&'static [u8]> {
        Some(b"ECDHE_RSA_AES_128_GCM_SHA256")
    }
    fn alpn_selected(&mut self) -> &[u8] {
        self.w().alpn
    }
    fn early_data_accepted(&mut self) -> bool {
        self.w().early_accepted
    }
    fn peers(&self) -> Option<impl ExactSizeIterator<Item = &[u8]> + Clone> {
        self.w().chain.clone().map(Vec::into_iter)
    }
    fn verify_peers(&self) -> Result<u32, Rc> {
        let mut w = self.w();
        w.call("verify_peers".into());
        w.status
    }
    fn stapled_status(&self, _: &FakeCert) -> Stapled {
        let mut w = self.w();
        w.call("stapled_status".into());
        w.stapled
    }
    fn native(&self) -> curl_core::tls::TlsNative {
        let s = core::ptr::NonNull::dangling();
        curl_core::tls::TlsNative::other(s, Some(s))
    }
}

/// A certificate, the world's leaf whatever it imports.
#[derive(Debug)]
pub(crate) struct FakeCert(Arc<Lock<World>>);

impl FakeCert {
    fn leaf(&self) -> Leaf {
        lock(&self.0).leaf.clone()
    }
}

impl library::Cert for FakeCert {
    fn import(&mut self, data: &[u8], format: Format) -> Rc {
        let line = format!("import({}, {format:?})", String::from_utf8_lossy(data));
        lock(&self.0).answer("import", line, 0)
    }
    fn common_name<'b>(&self, buf: &'b mut [u8; 65]) -> Result<&'b [u8], Rc> {
        let cn = self.leaf().cn?;
        let out = &mut buf[..cn.len()];
        out.copy_from_slice(cn);
        Ok(out)
    }
    fn expiration(&self) -> i64 {
        self.leaf().expiration
    }
    fn activation(&self) -> i64 {
        self.leaf().activation
    }
    fn matches_host(&self, name: &CStr) -> bool {
        lock(&self.0).call(format!("matches_host({})", text(name)));
        self.leaf().host_ok
    }
    fn issued_by(&self, _: &Self) -> bool {
        lock(&self.0).call("issued_by".into());
        self.leaf().issued
    }
    fn key_algorithm(&self) -> Option<&'static [u8]> {
        Some(b"RSA")
    }
    fn version(&self) -> i32 {
        3
    }
    fn subject(&self) -> Result<Vec<u8>, Rc> {
        Ok(b"CN=example.com".to_vec())
    }
    fn issuer(&self) -> Result<Vec<u8>, Rc> {
        Ok(b"CN=Test CA".to_vec())
    }
    fn public_key(&self) -> Option<Vec<u8>> {
        self.leaf().public_key.map(<[u8]>::to_vec)
    }
}
