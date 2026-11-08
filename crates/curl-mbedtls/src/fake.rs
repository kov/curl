//! A scripted mbedTLS for the session's tests: each call made of it is
//! written down in order and answers as the world says, and a call that
//! may read, write or verify runs a script of what the library would do
//! inside it through the same `Call` the real library's callbacks reach.
//! A scripted socket carries what it writes and reads.

use curl_alloc::{Lock, LockGuard};
use std::ffi::{CStr, c_void};
use std::ptr::NonNull;
use std::sync::Arc;

use curl_alloc::{OutOfMemory, TryArc};
pub(crate) use curl_core::tls::Wire;

use crate::library::{self, Call, Chain, KeyCopy, Moved, Rc, Resume, Saved, Words};
use crate::sys;

/// One thing the library does inside a call.
#[derive(Clone, Debug)]
pub(crate) enum Act {
    /// It writes these bytes: a wait or a failure ends the call so.
    Push(&'static [u8]),
    /// It reads up to this many bytes: none, the call waits.
    Pull(usize),
    /// It hands the caller of a read these bytes, decrypted.
    Deliver(&'static [u8]),
    /// It checked the chain's certificate at this depth and found these
    /// flags.
    Verify(i32, u32),
    /// It answers.
    Return(Rc),
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
    /// The flags each verify left, in order.
    pub(crate) flags_left: Vec<u32>,
    pub(crate) rng: Result<(), Rc>,
    pub(crate) key_signs: bool,
    pub(crate) version: i32,
    pub(crate) suite: i32,
    pub(crate) alpn: Option<&'static [u8]>,
    pub(crate) peer: Option<&'static [u8]>,
    pub(crate) public_key: Result<&'static [u8], KeyCopy>,
    pub(crate) chain: Vec<&'static [u8]>,
    pub(crate) info: Option<&'static [u8]>,
    pub(crate) resume: Resume,
    pub(crate) saved: Saved,
    pub(crate) pending: bool,
    /// What the session's pulls read, in order.
    pub(crate) pulled: Vec<u8>,
    /// What the configuration was given: the suites, the ALPN names.
    pub(crate) suites: Vec<i32>,
}

impl Default for World {
    fn default() -> World {
        World {
            calls: Vec::new(),
            answers: Vec::new(),
            scripts: Vec::new(),
            flags_left: Vec::new(),
            rng: Ok(()),
            key_signs: true,
            version: sys::MBEDTLS_SSL_VERSION_TLS1_3,
            suite: 0x1301,
            alpn: None,
            peer: Some(b"leaf-der"),
            public_key: Ok(b"spki"),
            chain: vec![b"leaf-der", b"ca-der"],
            info: Some(b"cert. version     : 3\n"),
            resume: Resume::Done,
            saved: Saved::Data(b"saved".to_vec()),
            pending: false,
            pulled: Vec::new(),
            suites: Vec::new(),
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

/// Every library made, so that what is leaked stays reachable: Miri does
/// not take it for a leak.
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

/// The library's words for a number.
fn words(rc: Rc) -> &'static [u8] {
    match rc {
        sys::MBEDTLS_ERR_X509_CERT_VERIFY_FAILED => b"X509 - Certificate verification failed",
        sys::MBEDTLS_ERR_SSL_ALLOC_FAILED => b"SSL - Memory allocation failed",
        _ => b"an error",
    }
}

impl library::Explain for Fake {
    fn verify_info(&self, flags: u32) -> Words {
        Words::new(format!("flags {flags:#x}\n").as_bytes())
    }
}

impl library::Mbedtls for Fake {
    type Rng = ();
    type Conn = FakeConn;

    fn rng(&self) -> Result<(), Rc> {
        self.w().rng
    }

    fn conn(&self, _: &TryArc<()>) -> Result<FakeConn, OutOfMemory> {
        self.w().calls.push("conn".into());
        Ok(FakeConn(self.0.clone()))
    }

    fn strerror(&self, rc: Rc) -> Words {
        Words::new(words(rc))
    }

    fn suites(&self) -> &'static [i32] {
        &[0x1302, 0x1301, 0xC02B, 0xC02F]
    }

    fn suite_name(&self, id: i32) -> &'static [u8] {
        match id {
            0x1301 => b"TLS1-3-AES-128-GCM-SHA256",
            0x1302 => b"TLS1-3-AES-256-GCM-SHA384",
            0xC02B => b"TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256",
            0xC02F => b"TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256",
            _ => b"unknown",
        }
    }

    fn public_key(&self, der: &[u8]) -> Result<Vec<u8>, KeyCopy> {
        let mut w = self.w();
        w.calls
            .push(format!("public_key({})", String::from_utf8_lossy(der)));
        w.public_key.map(<[u8]>::to_vec)
    }
}

/// One connection of the fake library.
#[derive(Debug)]
pub(crate) struct FakeConn(Arc<Lock<World>>);

/// A chain of the world's, from some depth on: its certificates' DER,
/// and the leaf's text as the library writes it.
pub(crate) struct FakeChain {
    pub(crate) ders: Vec<&'static [u8]>,
    pub(crate) info: Option<&'static [u8]>,
}

impl Chain for FakeChain {
    fn info(&self) -> Option<Vec<u8>> {
        self.info.map(<[u8]>::to_vec)
    }

    fn ders(&self, most: usize) -> Result<Vec<&[u8]>, OutOfMemory> {
        Ok(self.ders.iter().take(most).copied().collect())
    }
}

fn text(c: &CStr) -> String {
    c.to_string_lossy().into_owned()
}

impl FakeConn {
    fn w(&self) -> LockGuard<'_, World> {
        self.0.lock().unwrap()
    }

    fn answer(&self, name: &'static str, line: String) -> Rc {
        self.w().answer(name, line, 0)
    }

    fn note(&self, line: &str) {
        self.w().calls.push(line.into());
    }

    /// Run `name`'s script, else `default`, inside `call`, reading into
    /// `buf` if given: the call's answer. The world is not held while the
    /// script reaches the callbacks.
    fn run(
        &mut self,
        name: &'static str,
        call: &mut Call<'_, '_>,
        mut buf: Option<&mut [u8]>,
        default: Vec<Act>,
    ) -> Rc {
        let acts = self.w().script(name).unwrap_or(default);
        for act in acts {
            match act {
                Act::Push(bytes) => match call.send(bytes) {
                    Moved::Bytes(_) => {}
                    Moved::Again => return sys::MBEDTLS_ERR_SSL_WANT_WRITE,
                    Moved::Failed => return -1,
                },
                Act::Pull(n) => {
                    let mut room = vec![0u8; n];
                    match call.recv(&mut room) {
                        // `MBEDTLS_ERR_SSL_CONN_EOF`.
                        Moved::Bytes(0) => return -0x7280,
                        Moved::Bytes(k) => self.w().pulled.extend_from_slice(&room[..k]),
                        Moved::Again => return sys::MBEDTLS_ERR_SSL_WANT_READ,
                        Moved::Failed => return -1,
                    }
                }
                Act::Deliver(bytes) => {
                    let buf = buf.as_deref_mut().expect("a read");
                    buf[..bytes.len()].copy_from_slice(bytes);
                    return Rc::try_from(bytes.len()).unwrap();
                }
                Act::Verify(depth, mut flags) => {
                    let chain = {
                        let w = self.w();
                        let from = usize::try_from(depth).unwrap();
                        FakeChain {
                            ders: w.chain[from..].to_vec(),
                            info: w.info,
                        }
                    };
                    call.verify(depth, &chain, &mut flags);
                    self.w().flags_left.push(flags);
                }
                Act::Return(rc) => return rc,
            }
        }
        0
    }
}

impl library::Conn for FakeConn {
    fn ca_parse(&mut self, data: &[u8]) -> Rc {
        self.answer("ca_parse", format!("ca_parse({data:?})"))
    }

    fn ca_parse_file(&mut self, file: &CStr) -> Rc {
        self.answer("ca_parse_file", format!("ca_parse_file({})", text(file)))
    }

    fn ca_parse_path(&mut self, dir: &CStr) -> Rc {
        self.answer("ca_parse_path", format!("ca_parse_path({})", text(dir)))
    }

    fn cert_parse_file(&mut self, file: &CStr) -> Rc {
        self.answer(
            "cert_parse_file",
            format!("cert_parse_file({})", text(file)),
        )
    }

    fn cert_parse(&mut self, data: &[u8]) -> Rc {
        self.answer("cert_parse", format!("cert_parse({data:?})"))
    }

    fn key_parse_file(&mut self, file: &CStr, password: Option<&CStr>) -> Rc {
        let pass = password.map(text);
        self.answer(
            "key_parse_file",
            format!("key_parse_file({}, {pass:?})", text(file)),
        )
    }

    fn key_parse(&mut self, key: &[u8], password: Option<&[u8]>) -> Rc {
        self.answer("key_parse", format!("key_parse({key:?}, {password:?})"))
    }

    fn key_signs(&self) -> bool {
        self.w().key_signs
    }

    fn crl_parse_file(&mut self, file: &CStr) -> Rc {
        self.answer("crl_parse_file", format!("crl_parse_file({})", text(file)))
    }

    fn defaults(&mut self) -> Rc {
        self.answer("defaults", "defaults".into())
    }

    fn signal_tickets(&mut self) {
        self.note("signal_tickets");
    }

    fn verify_hook(&mut self) {
        self.note("verify_hook");
    }

    fn verify_required(&mut self) {
        self.note("verify_required");
    }

    fn profile_next(&mut self) {
        self.note("profile_next");
    }

    fn versions(&mut self, min: i32, max: i32) {
        self.note(&format!("versions({min:#x}, {max:#x})"));
    }

    fn use_rng(&mut self) {
        self.note("use_rng");
    }

    fn setup(&mut self) -> Rc {
        self.answer("setup", "setup".into())
    }

    fn bio(&mut self) {
        self.note("bio");
    }

    fn ciphersuites(&mut self, suites: Vec<i32>) -> Result<(), OutOfMemory> {
        let mut w = self.w();
        w.calls.push(format!("ciphersuites({suites:x?})"));
        w.suites = suites;
        Ok(())
    }

    fn default_ciphersuites(&mut self) {
        self.note("default_ciphersuites");
    }

    fn renegotiation(&mut self) {
        self.note("renegotiation");
    }

    fn tickets_off(&mut self) {
        self.note("tickets_off");
    }

    fn resume(&mut self, data: &[u8]) -> Resume {
        let mut w = self.w();
        w.calls
            .push(format!("resume({})", String::from_utf8_lossy(data)));
        w.resume
    }

    fn ca_chain(&mut self) {
        self.note("ca_chain");
    }

    fn own_cert(&mut self) {
        self.note("own_cert");
    }

    fn hostname(&mut self, name: &CStr) -> Rc {
        self.answer("hostname", format!("hostname({})", text(name)))
    }

    fn alpn(&mut self, names: &[&[u8]]) -> Result<Rc, OutOfMemory> {
        let names: Vec<_> = names.iter().map(|n| String::from_utf8_lossy(n)).collect();
        Ok(self.answer("alpn", format!("alpn({})", names.join(","))))
    }

    fn config(&self) -> NonNull<c_void> {
        NonNull::<u64>::dangling().cast()
    }

    fn native(&self) -> NonNull<c_void> {
        NonNull::<u32>::dangling().cast()
    }

    fn handshake(&mut self, call: &mut Call<'_, '_>) -> Rc {
        self.note("handshake");
        self.run("handshake", call, None, vec![Act::Return(0)])
    }

    fn read(&mut self, call: &mut Call<'_, '_>, buf: &mut [u8]) -> Rc {
        self.note(&format!("read({})", buf.len()));
        self.run("read", call, Some(buf), vec![Act::Return(0)])
    }

    fn write(&mut self, call: &mut Call<'_, '_>, bytes: &[u8]) -> Rc {
        self.note(&format!("write({})", bytes.len()));
        let all = Rc::try_from(bytes.len()).unwrap();
        self.run("write", call, None, vec![Act::Return(all)])
    }

    fn close_notify(&mut self, call: &mut Call<'_, '_>) -> Rc {
        self.note("close_notify");
        self.run("close_notify", call, None, vec![Act::Return(0)])
    }

    fn suite(&self) -> i32 {
        self.w().suite
    }

    fn version_name(&self) -> &'static [u8] {
        if self.w().version == sys::MBEDTLS_SSL_VERSION_TLS1_3 {
            b"TLSv1.3"
        } else {
            b"TLSv1.2"
        }
    }

    fn version(&self) -> i32 {
        self.w().version
    }

    fn alpn_selected(&self) -> Option<&[u8]> {
        self.w().alpn
    }

    fn peer_cert(&self) -> Option<&[u8]> {
        self.w().peer
    }

    fn saved(&mut self) -> Result<Saved, OutOfMemory> {
        let mut w = self.w();
        w.calls.push("saved".into());
        Ok(match &w.saved {
            Saved::Data(d) => Saved::Data(d.clone()),
            Saved::GetFailed(rc) => Saved::GetFailed(*rc),
            Saved::Empty => Saved::Empty,
            Saved::SaveFailed(rc) => Saved::SaveFailed(*rc),
        })
    }

    fn pending(&self) -> bool {
        self.w().pending
    }
}
