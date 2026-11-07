//! A scripted rustls for the session's tests: each call made of it is
//! written down in order and answers as the world says. A connection's
//! records go out and come in through the same `Call` the real library's
//! I/O reaches, over a scripted socket, and what each processing of the
//! records read makes of them is scripted too.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use curl_alloc::OutOfMemory;
use curl_core::tls::SharedKeyLog;
pub(crate) use curl_core::tls::Wire;

use crate::library::{self, Call, Errno, Moved, Plain, Suite, TLS1_3};
use crate::result::Code;

/// What one processing of the records read makes of them.
#[derive(Clone, Debug)]
pub(crate) enum Ev {
    /// A record to send goes out.
    Queue(&'static [u8]),
    /// Plain text to read.
    Plain(&'static [u8]),
    /// The handshake is over.
    Done,
    /// The peer's close_notify.
    CloseNotify,
    /// It fails.
    Fail(Code),
}

/// What the fake library holds, and what it was asked.
#[derive(Debug)]
pub(crate) struct World {
    /// Each call made, in order.
    pub(crate) calls: Vec<String>,
    /// The calls, by name, that fail with this result the next time.
    pub(crate) answers: Vec<(&'static str, Code)>,
    pub(crate) suites: Vec<Suite>,
    /// The connection is handshaking.
    pub(crate) handshaking: bool,
    /// Records waiting to go out, the first perhaps partly sent.
    pub(crate) out: VecDeque<Vec<u8>>,
    /// Plain text waiting to be read.
    pub(crate) plain: Vec<u8>,
    pub(crate) close_notify: bool,
    /// The connection below ended.
    pub(crate) eof: bool,
    /// What each processing does, in order; one past the last does
    /// nothing.
    pub(crate) processes: VecDeque<Vec<Ev>>,
    /// How much a read of the records asks for.
    pub(crate) room: usize,
    /// A read of the records fails so, the next time.
    pub(crate) read_tls_fails: Option<Errno>,
    /// Each write of the records in turn fails so, or is made where
    /// `None`; past the script's end, each is made.
    pub(crate) write_tls_fails: VecDeque<Option<Errno>>,
    /// A write of plain text takes at most this many bytes.
    pub(crate) write_room: Option<usize>,
    /// A read of plain text fails so, the next time.
    pub(crate) read_fails: Option<Plain>,
    pub(crate) alpn: Option<&'static [u8]>,
    pub(crate) version: u16,
    pub(crate) suite_name: &'static str,
    pub(crate) group_name: &'static str,
    /// The peer's chain, each certificate's DER.
    pub(crate) certs: Vec<&'static [u8]>,
    /// What the records read held, in order.
    pub(crate) pulled: Vec<u8>,
    /// The key log the configuration was given.
    pub(crate) key_log: Option<SharedKeyLog>,
}

impl Default for World {
    fn default() -> World {
        World {
            calls: Vec::new(),
            answers: Vec::new(),
            suites: vec![
                Suite {
                    id: 0x1302,
                    tls13: true,
                },
                Suite {
                    id: 0x1301,
                    tls13: true,
                },
                Suite {
                    id: 0xC02C,
                    tls13: false,
                },
                Suite {
                    id: 0xC02F,
                    tls13: false,
                },
            ],
            handshaking: true,
            out: VecDeque::new(),
            plain: Vec::new(),
            close_notify: false,
            eof: false,
            processes: VecDeque::new(),
            room: 4096,
            read_tls_fails: None,
            write_tls_fails: VecDeque::new(),
            write_room: None,
            read_fails: None,
            alpn: None,
            version: TLS1_3,
            suite_name: "TLS13_AES_256_GCM_SHA384",
            group_name: "X25519MLKEM768",
            certs: Vec::new(),
            pulled: Vec::new(),
            key_log: None,
        }
    }
}

impl World {
    /// A handshake of one round: the hello goes out, the server's reply
    /// comes in and finishes it, and the Finished goes out after.
    pub(crate) fn one_round() -> World {
        let mut w = World::default();
        w.out.push_back(b"hello".to_vec());
        w.processes
            .push_back(vec![Ev::Done, Ev::Queue(b"finished")]);
        w
    }

    /// `name`'s answer, written down: the world's, if it has one.
    fn answer(&mut self, name: &'static str, line: String) -> Result<(), Code> {
        self.calls.push(line);
        match self.answers.iter().position(|(n, _)| *n == name) {
            Some(at) => Err(self.answers.remove(at).1),
            None => Ok(()),
        }
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

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

impl library::Rustls for Fake {
    /// Whether a verifier was set, which rustls-ffi's build requires.
    type Builder = bool;
    type Roots = String;
    type Crls = String;
    type Verifier = String;
    type Key = String;
    type Config = ();
    type Conn = FakeConn;

    fn suites(&self) -> Result<Vec<Suite>, OutOfMemory> {
        Ok(self.w().suites.clone())
    }

    fn builder(&self, suites: &[Suite], versions: &[u16]) -> Result<bool, OutOfMemory> {
        let ids: Vec<_> = suites.iter().map(|s| format!("{:04x}", s.id)).collect();
        let versions: Vec<_> = versions.iter().map(|v| format!("{v:04x}")).collect();
        self.w().calls.push(format!(
            "builder([{}], [{}])",
            ids.join(","),
            versions.join(",")
        ));
        Ok(false)
    }

    fn roots(&self, pem: &[u8]) -> Result<String, Code> {
        self.w().answer("roots", format!("roots({})", text(pem)))?;
        Ok(text(pem))
    }

    fn crls(&self, pem: &[u8]) -> Result<String, Code> {
        self.w().answer("crls", format!("crls({})", text(pem)))?;
        Ok(text(pem))
    }

    fn webpki(&self, roots: String, crls: Option<String>) -> Result<String, Code> {
        self.w()
            .answer("webpki", format!("webpki({roots}, {crls:?})"))?;
        Ok("webpki".into())
    }

    fn platform(&self) -> Result<String, Code> {
        self.w().answer("platform", "platform".into())?;
        Ok("platform".into())
    }

    fn certified_key(&self, chain: &[u8], key: &[u8]) -> Result<String, Code> {
        self.w().answer(
            "certified_key",
            format!("certified_key({}, {})", text(chain), text(key)),
        )?;
        Ok("key".into())
    }

    fn keys_match(&self, key: &String) -> Result<(), Code> {
        self.w().answer("keys_match", format!("keys_match({key})"))
    }

    fn alpn(&self, _: &mut bool, names: &[&[u8]]) -> Result<(), OutOfMemory> {
        let names: Vec<_> = names.iter().map(|n| text(n)).collect();
        self.w().calls.push(format!("alpn({})", names.join(",")));
        Ok(())
    }

    fn verify_none(&self, set: &mut bool) {
        *set = true;
        self.w().calls.push("verify_none".into());
    }

    fn verifier(&self, set: &mut bool, verifier: String) {
        *set = true;
        self.w().calls.push(format!("verifier({verifier})"));
    }

    fn certify(&self, _: &mut bool, key: String) {
        self.w().calls.push(format!("certify({key})"));
    }

    fn key_log(&self, _: &mut bool, log: SharedKeyLog) {
        let mut w = self.w();
        w.calls.push("key_log".into());
        w.key_log = Some(log);
    }

    fn build(&self, set: bool) -> Result<(), Code> {
        self.w().answer("build", "build".into())?;
        if set {
            Ok(())
        } else {
            Err(Code::NoServerCertVerifier)
        }
    }

    fn connect(&self, _: (), name: &[u8]) -> Result<FakeConn, Code> {
        self.w()
            .answer("connect", format!("connect({})", text(name)))?;
        Ok(FakeConn(self.0.clone()))
    }
}

/// One connection of the fake library.
#[derive(Debug)]
pub(crate) struct FakeConn(Arc<Mutex<World>>);

impl FakeConn {
    fn w(&self) -> MutexGuard<'_, World> {
        self.0.lock().unwrap()
    }
}

impl library::Conn for FakeConn {
    fn read_tls(&mut self, call: &mut Call<'_, '_>) -> Result<usize, Errno> {
        let (room, fails) = {
            let mut w = self.w();
            w.calls.push("read_tls".into());
            (w.room, w.read_tls_fails.take())
        };
        if let Some(e) = fails {
            return Err(e);
        }
        let mut buf = vec![0u8; room];
        // The world is not held while the I/O reaches the session.
        match call.recv(&mut buf) {
            Moved::Bytes(0) => {
                self.w().eof = true;
                Ok(0)
            }
            Moved::Bytes(n) => {
                self.w().pulled.extend_from_slice(&buf[..n]);
                Ok(n)
            }
            Moved::Again => Err(Errno::Again),
            Moved::Failed => Err(Errno::Invalid),
        }
    }

    fn write_tls(&mut self, call: &mut Call<'_, '_>) -> Result<usize, Errno> {
        let (record, fails) = {
            let mut w = self.w();
            w.calls.push("write_tls".into());
            (
                w.out.front().cloned(),
                w.write_tls_fails.pop_front().flatten(),
            )
        };
        if let Some(e) = fails {
            return Err(e);
        }
        let record = record.unwrap_or_default();
        match call.send(&record) {
            Moved::Bytes(n) => {
                let mut w = self.w();
                if n == record.len() {
                    w.out.pop_front();
                } else {
                    w.out[0].drain(..n);
                }
                Ok(n)
            }
            Moved::Again => Err(Errno::Again),
            Moved::Failed => Err(Errno::Invalid),
        }
    }

    fn process_new_packets(&mut self) -> Result<(), Code> {
        let mut w = self.w();
        w.calls.push("process".into());
        let evs = w.processes.pop_front().unwrap_or_default();
        for ev in evs {
            match ev {
                Ev::Queue(r) => w.out.push_back(r.to_vec()),
                Ev::Plain(p) => w.plain.extend_from_slice(p),
                Ev::Done => w.handshaking = false,
                Ev::CloseNotify => w.close_notify = true,
                Ev::Fail(code) => return Err(code),
            }
        }
        Ok(())
    }

    fn wants_read(&self) -> bool {
        let w = self.w();
        w.out.is_empty() && !w.close_notify
    }

    fn wants_write(&self) -> bool {
        !self.w().out.is_empty()
    }

    fn is_handshaking(&self) -> bool {
        self.w().handshaking
    }

    fn read(&mut self, buf: &mut [u8]) -> Plain {
        let mut w = self.w();
        w.calls.push(format!("read({})", buf.len()));
        if let Some(p) = w.read_fails.take() {
            return p;
        }
        if !w.plain.is_empty() {
            let n = buf.len().min(w.plain.len());
            buf[..n].copy_from_slice(&w.plain[..n]);
            w.plain.drain(..n);
            return Plain::Read(n);
        }
        if w.close_notify {
            Plain::Read(0)
        } else if w.eof {
            Plain::UnexpectedEof
        } else {
            Plain::Empty
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<usize, Code> {
        let mut w = self.w();
        w.answer("write", format!("write({})", bytes.len()))?;
        let n = w.write_room.map_or(bytes.len(), |r| r.min(bytes.len()));
        if n > 0 {
            let mut record = b"E:".to_vec();
            record.extend_from_slice(&bytes[..n]);
            w.out.push_back(record);
        }
        Ok(n)
    }

    fn send_close_notify(&mut self) {
        let mut w = self.w();
        w.calls.push("send_close_notify".into());
        w.out.push_back(b"close_notify".to_vec());
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.w().alpn
    }

    fn version(&self) -> u16 {
        self.w().version
    }

    fn suite_name(&self) -> &str {
        self.w().suite_name
    }

    fn group_name(&self) -> &str {
        self.w().group_name
    }

    fn peer_cert(&self, i: usize) -> Option<&[u8]> {
        self.w().certs.get(i).copied()
    }
}

impl Drop for FakeConn {
    fn drop(&mut self) {
        if let Ok(mut w) = self.0.lock() {
            w.calls.push("free".into());
        }
    }
}
