//! Transfers over a fake SSH library, whose server is a list of files:
//! the logins, SFTP and SCP downloads, the quote commands, a listing, and
//! the socket handed to the library past an HTTP proxy's tunnel.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use super::*;
use crate::conn::io::{Conversation, FakeNet, Peer as Net};
use crate::easy::Easy;
use crate::handler::{DebugHandler, Write as Wrote, WriteHandler};
use crate::id::ArenaPolicy;
use crate::libraries::{Libraries, SharedLibraries};
use crate::multi::{Env, Multi, NoEvents, TransferCx, TransferId, drive_to_completion};
use crate::options::Options;
use crate::ssh::{Failed, KnownKey, Refused, Session, Ssh};
use crate::time::ManualClock;
use curl_alloc::OutOfMemory;

const PORT: u16 = 8022;
const PROXY_PORT: u16 = 8080;
const HOME: &[u8] = b"/home/u";

/// What the fake server holds, and what it was asked, shared by the
/// sessions it makes.
#[derive(Debug, Default)]
struct World {
    /// Each file's path and bytes.
    files: Vec<(Vec<u8>, Vec<u8>)>,
    /// Each link's path and target.
    links: Vec<(Vec<u8>, Vec<u8>)>,
    /// The logins the server offers.
    methods: u32,
    /// The password it takes.
    password: Vec<u8>,
    /// Each call the state machine made of note, in order.
    calls: Vec<String>,
    /// What the known-hosts file says of the server's key.
    known: Option<KnownHosts>,
    /// The keyboard-interactive login asks one question, the password.
    asks: bool,
    /// Every file opened to write is refused as missing.
    refuses_writes: bool,
}

impl World {
    fn call(&mut self, what: &str, args: &[&[u8]]) {
        let mut said = what.to_owned();
        for a in args {
            said.push(' ');
            said.push_str(&String::from_utf8_lossy(a));
        }
        self.calls.push(said);
    }

    fn file(&self, path: &[u8]) -> Option<usize> {
        self.files.iter().position(|(p, _)| p == path)
    }
}

/// The fake library: each session it makes reaches the one world.
#[derive(Debug)]
struct FakeSsh(Arc<Mutex<World>>);

impl Ssh for FakeSsh {
    fn session(&self) -> Option<Box<dyn Session>> {
        Some(Box::new(FakeSession {
            world: self.0.clone(),
            pubkey: false,
            scp: None,
            sftp: false,
            file: None,
            dir: None,
            reading: None,
            writing: None,
            error: 0,
            kept: None,
        }))
    }
}

/// A file open: its index in the world's, and where reads and writes are.
#[derive(Debug)]
struct Open {
    at: usize,
    pos: usize,
}

#[derive(Debug)]
struct FakeSession {
    world: Arc<Mutex<World>>,
    pubkey: bool,
    /// The SCP channel: whether it writes, and its path.
    scp: Option<(bool, Vec<u8>, usize)>,
    sftp: bool,
    file: Option<Open>,
    /// The directory listed: its entries left.
    dir: Option<Vec<Attrs>>,
    reading: Option<usize>,
    writing: Option<usize>,
    error: u32,
    kept: Option<Attrs>,
}

impl FakeSession {
    fn w(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    fn attrs(name: &[u8], size: usize, link: bool) -> Attrs {
        let kind = if link { "l" } else { "-" };
        let long = format!(
            "{kind}rw-r--r--    1 u        u        {size:>8} Jan  1 00:00 {}",
            String::from_utf8_lossy(name)
        );
        Attrs {
            name: Some(name.to_vec()),
            longname: Some(long.into_bytes()),
            flags: Attrs::SIZE | Attrs::PERMISSIONS,
            size: size as u64,
            permissions: if link { 0o120_777 } else { 0o100_644 },
            mtime: 1_000,
        }
    }

    /// A call that fails as for a missing file.
    fn missing(&mut self) -> Rc {
        self.error = SSH_FX_NO_SUCH_FILE;
        Rc::Error
    }
}

impl Session for FakeSession {
    fn set_host(&mut self, host: &[u8]) -> Result<(), Refused> {
        self.w().call("set_host", &[host]);
        Ok(())
    }
    fn parse_config(&mut self) -> Result<(), Refused> {
        Ok(())
    }
    fn set_socket(&mut self, _: i32) -> Result<(), Refused> {
        self.w().call("set_socket", &[]);
        Ok(())
    }
    fn set_user(&mut self, user: &[u8]) -> Result<(), Refused> {
        self.w().call("set_user", &[user]);
        Ok(())
    }
    fn set_known_hosts(&mut self, _: &[u8]) -> Result<(), Refused> {
        Ok(())
    }
    fn set_port(&mut self, _: u16) -> Result<(), Refused> {
        Ok(())
    }
    fn set_compression(&mut self) -> Result<(), Refused> {
        Ok(())
    }
    fn import_pubkey_file(&mut self, file: &[u8]) -> Result<(), Refused> {
        self.w().call("import_pubkey_file", &[file]);
        self.pubkey = true;
        Ok(())
    }
    fn has_pubkey(&self) -> bool {
        self.pubkey
    }
    fn set_blocking(&mut self, _: bool) {}
    fn poll_flags(&self) -> PollFlags {
        PollFlags::default()
    }
    fn error(&self) -> Result<Vec<u8>, OutOfMemory> {
        Ok(b"fake failure".to_vec())
    }
    fn connect(&mut self) -> Rc {
        self.w().call("connect", &[]);
        Rc::Ok
    }
    fn host_key(&mut self) -> Option<crate::ssh::HostKey> {
        Some(crate::ssh::HostKey {
            sha256: Some([1; 32]),
            md5: Some([2; 16]),
            base64: Some(b"AAAA".to_vec()),
            kind: KeyType::Ed25519,
        })
    }
    fn known_host(&mut self) -> (KnownHosts, Option<Result<KnownKey, Failed>>) {
        let known = self.w().known.unwrap_or(KnownHosts::NotFound);
        let key = (known != KnownHosts::NotFound).then(|| {
            Ok(KnownKey {
                base64: Some(b"BBBB".to_vec()),
                kind: KeyType::Ed25519,
            })
        });
        (known, key)
    }
    fn update_known_hosts(&mut self) -> Rc {
        self.w().call("update_known_hosts", &[]);
        Rc::Ok
    }
    fn auth_none(&mut self) -> Auth {
        Auth::Denied
    }
    fn auth_list(&mut self) -> Methods {
        Methods(self.w().methods)
    }
    fn try_publickey(&mut self) -> Auth {
        Auth::Success
    }
    fn import_privkey_file(&mut self, file: &[u8], _: Option<&[u8]>) -> Rc {
        self.w().call("import_privkey_file", &[file]);
        Rc::Ok
    }
    fn auth_publickey(&mut self) -> Auth {
        self.w().call("auth_publickey", &[]);
        Auth::Success
    }
    fn auth_publickey_auto(&mut self, _: Option<&[u8]>) -> Auth {
        Auth::Denied
    }
    fn auth_gssapi(&mut self) -> Auth {
        Auth::Denied
    }
    fn auth_kbdint(&mut self) -> Auth {
        let mut w = self.w();
        if !w.asks {
            return Auth::Denied;
        }
        w.call("auth_kbdint", &[]);
        // Asked, then answered right: done.
        match w.calls.iter().rfind(|c| c.starts_with("kbdint_answer")) {
            None => Auth::Info,
            Some(a) if a.as_bytes().ends_with(&w.password) => Auth::Success,
            Some(_) => Auth::Denied,
        }
    }
    fn kbdint_prompts(&mut self) -> i32 {
        1
    }
    fn kbdint_answer(&mut self, _: u32, answer: &[u8]) -> i32 {
        self.w().call("kbdint_answer", &[answer]);
        0
    }
    fn auth_password(&mut self, password: &[u8]) -> Auth {
        let mut w = self.w();
        w.call("auth_password", &[password]);
        if w.password == password {
            Auth::Success
        } else {
            Auth::Denied
        }
    }
    fn disconnect(&mut self) {
        self.w().call("disconnect", &[]);
    }
    fn scp_new(&mut self, write: bool, path: &[u8]) -> bool {
        self.scp = Some((write, path.to_vec(), 0));
        true
    }
    fn has_scp(&self) -> bool {
        self.scp.is_some()
    }
    fn scp_init(&mut self) -> Rc {
        Rc::Ok
    }
    fn scp_push_file(&mut self, path: &[u8], _: u64, _: u32) -> Rc {
        let mut w = self.w();
        w.call("scp_push_file", &[path]);
        let at = match w.file(path) {
            Some(at) => at,
            None => {
                w.files.push((path.to_vec(), Vec::new()));
                w.files.len() - 1
            }
        };
        w.files[at].1.clear();
        drop(w);
        self.scp.as_mut().unwrap().2 = at;
        Rc::Ok
    }
    fn scp_pull_request(&mut self) -> ScpRequest {
        let path = self.scp.as_ref().unwrap().1.clone();
        let found = self.w().file(&path);
        match found {
            Some(at) => {
                self.scp.as_mut().unwrap().2 = at;
                ScpRequest::NewFile
            }
            None => ScpRequest::Other,
        }
    }
    fn scp_size(&mut self) -> u64 {
        let at = self.scp.as_ref().unwrap().2;
        self.w().files[at].1.len() as u64
    }
    fn scp_read(&mut self, buf: &mut [u8]) -> Result<usize, Failed> {
        let at = self.scp.as_ref().unwrap().2;
        let pos = self.reading.unwrap_or(0);
        let w = self.w();
        let rest = &w.files[at].1[pos..];
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        drop(w);
        self.reading = Some(pos + n);
        Ok(n)
    }
    fn scp_write(&mut self, bytes: &[u8]) -> Rc {
        let at = self.scp.as_ref().unwrap().2;
        self.w().files[at].1.extend_from_slice(bytes);
        Rc::Ok
    }
    fn scp_close(&mut self) -> Rc {
        Rc::Ok
    }
    fn scp_free(&mut self) {
        self.scp = None;
    }
    fn sftp_new(&mut self) -> bool {
        self.sftp = true;
        true
    }
    fn has_sftp(&self) -> bool {
        self.sftp
    }
    fn sftp_init(&mut self) -> Rc {
        Rc::Ok
    }
    fn sftp_error(&mut self) -> u32 {
        self.error
    }
    fn canonicalize(&mut self, path: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
        assert_eq!(path, b".");
        Ok(Some(HOME.to_vec()))
    }
    fn opendir(&mut self, path: &[u8]) -> bool {
        let w = self.w();
        let mut entries = Vec::new();
        for (p, bytes) in &w.files {
            if let Some(name) = p.strip_prefix(path) {
                entries.push(Self::attrs(name, bytes.len(), false));
            }
        }
        for (p, target) in &w.links {
            if let Some(name) = p.strip_prefix(path) {
                entries.push(Self::attrs(name, target.len(), true));
            }
        }
        drop(w);
        self.dir = Some(entries);
        true
    }
    fn readdir(&mut self) -> Result<Option<Attrs>, OutOfMemory> {
        let dir = self.dir.as_mut().unwrap();
        Ok((!dir.is_empty()).then(|| dir.remove(0)))
    }
    fn dir_eof(&mut self) -> bool {
        self.dir.as_ref().is_some_and(Vec::is_empty)
    }
    fn closedir(&mut self) {
        self.dir = None;
    }
    fn lstat(&mut self, path: &[u8]) -> Result<Option<Attrs>, OutOfMemory> {
        let w = self.w();
        Ok(w.links
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, target)| Attrs {
                flags: Attrs::PERMISSIONS,
                permissions: 0o120_777,
                ..Self::attrs(b"", target.len(), true)
            })
            .map(|a| Attrs { name: None, ..a }))
    }
    fn readlink(&mut self, path: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
        let w = self.w();
        Ok(w.links
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, t)| t.clone()))
    }
    fn stat(&mut self, path: &[u8]) -> Result<Option<Attrs>, OutOfMemory> {
        let w = self.w();
        Ok(w.file(path)
            .map(|at| Self::attrs(path, w.files[at].1.len(), false)))
    }
    fn stat_to_change(&mut self, path: &[u8]) -> bool {
        let found = self.stat(path).unwrap();
        self.kept = found;
        if self.kept.is_none() {
            self.error = SSH_FX_NO_SUCH_FILE;
        }
        self.kept.is_some()
    }
    fn setstat_kept(&mut self, path: &[u8], change: AttrChange) -> Rc {
        let said = format!("{change:?}");
        self.w().call("setstat", &[path, said.as_bytes()]);
        Rc::Ok
    }
    fn symlink(&mut self, target: &[u8], dest: &[u8]) -> Rc {
        self.w().call("symlink", &[target, dest]);
        Rc::Ok
    }
    fn mkdir(&mut self, path: &[u8], _: u32) -> Rc {
        self.w().call("mkdir", &[path]);
        Rc::Ok
    }
    fn rename(&mut self, from: &[u8], to: &[u8]) -> Rc {
        let mut w = self.w();
        w.call("rename", &[from, to]);
        match w.file(from) {
            Some(at) => {
                w.files[at].0 = to.to_vec();
                Rc::Ok
            }
            None => {
                drop(w);
                self.missing()
            }
        }
    }
    fn rmdir(&mut self, path: &[u8]) -> Rc {
        self.w().call("rmdir", &[path]);
        Rc::Ok
    }
    fn unlink(&mut self, path: &[u8]) -> Rc {
        let mut w = self.w();
        w.call("unlink", &[path]);
        match w.file(path) {
            Some(at) => {
                w.files.remove(at);
                Rc::Ok
            }
            None => {
                drop(w);
                self.missing()
            }
        }
    }
    fn open(&mut self, path: &[u8], mode: OpenMode, _: u32) -> bool {
        let mut w = self.w();
        w.call("open", &[path]);
        if mode != OpenMode::Read && w.refuses_writes {
            drop(w);
            self.error = SSH_FX_NO_SUCH_FILE;
            return false;
        }
        let at = match (w.file(path), mode) {
            (Some(at), OpenMode::Truncate) => {
                w.files[at].1.clear();
                at
            }
            (Some(at), _) => at,
            (None, OpenMode::Read) => {
                drop(w);
                self.error = SSH_FX_NO_SUCH_FILE;
                return false;
            }
            (None, _) => {
                w.files.push((path.to_vec(), Vec::new()));
                w.files.len() - 1
            }
        };
        let pos = if mode == OpenMode::Append {
            w.files[at].1.len()
        } else {
            0
        };
        drop(w);
        self.file = Some(Open { at, pos });
        true
    }
    fn has_file(&self) -> bool {
        self.file.is_some()
    }
    fn close_file(&mut self) {
        self.file = None;
    }
    fn seek(&mut self, offset: u64) -> Rc {
        self.file.as_mut().unwrap().pos = offset as usize;
        Rc::Ok
    }
    fn fstat(&mut self) -> Result<Option<Attrs>, OutOfMemory> {
        let at = self.file.as_ref().unwrap().at;
        let w = self.w();
        Ok(Some(Self::attrs(
            &w.files[at].0,
            w.files[at].1.len(),
            false,
        )))
    }
    fn file_nonblocking(&mut self) {}
    fn begin_read(&mut self, len: usize) -> Rc {
        assert!(self.reading.is_none(), "one read under way at a time");
        self.reading = Some(len);
        Rc::Ok
    }
    fn wait_read(&mut self, buf: &mut [u8]) -> Aio {
        let len = self.reading.take().expect("a read begun");
        let open = self.file.as_mut().unwrap();
        let w = self.world.lock().unwrap();
        let rest = &w.files[open.at].1[open.pos.min(w.files[open.at].1.len())..];
        let n = rest.len().min(len).min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        open.pos += n;
        Aio::Done(n)
    }
    fn begin_write(&mut self, bytes: &[u8]) -> Rc {
        let open = self.file.as_mut().unwrap();
        let mut w = self.world.lock().unwrap();
        let file = &mut w.files[open.at].1;
        file.truncate(open.pos);
        file.extend_from_slice(bytes);
        open.pos += bytes.len();
        self.writing = Some(bytes.len());
        Rc::Ok
    }
    fn wait_write(&mut self) -> Aio {
        Aio::Done(self.writing.take().expect("a write begun"))
    }
    fn free_aio(&mut self) {
        self.reading = None;
        self.writing = None;
    }
    fn sftp_free(&mut self) {
        self.sftp = false;
    }
}

/// Collects the body.
#[derive(Clone, Default)]
struct Body(Arc<Mutex<Vec<u8>>>);

impl WriteHandler for Body {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Wrote {
        self.0.lock().unwrap().extend_from_slice(body);
        Wrote::Took(body.len())
    }
}

/// Collects the trace's text.
#[derive(Clone, Default)]
struct Text(Arc<Mutex<Vec<u8>>>);

impl Text {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl DebugHandler for Text {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::Text {
            self.0.lock().unwrap().extend_from_slice(data);
        }
    }
}

/// A fake world with `files` in the home directory, offering the public
/// key and password logins, the password `secret`.
fn world(files: &[(&str, &str)]) -> Arc<Mutex<World>> {
    world_with(files, |_| {})
}

/// The same, `set` changing it.
fn world_with(files: &[(&str, &str)], set: impl FnOnce(&mut World)) -> Arc<Mutex<World>> {
    let mut w = World {
        files: files
            .iter()
            .map(|(p, b)| (p.as_bytes().to_vec(), b.as_bytes().to_vec()))
            .collect(),
        methods: Methods::PUBLICKEY | Methods::PASSWORD,
        password: b"secret".to_vec(),
        ..World::default()
    };
    set(&mut w);
    Arc::new(Mutex::new(w))
}

/// A multi whose server at `port` takes `talk`.
fn serving(port: u16, talk: &Conversation) -> Multi {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], port));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Net::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    Multi::new(env).unwrap()
}

/// A peer that says nothing: the fake library never reads it.
fn silent() -> Conversation {
    Conversation::replies(&[], false)
}

/// A transfer of `url` over `world`'s library, added to `m`, its body and
/// trace kept.
fn added(
    m: &mut Multi,
    world: &Arc<Mutex<World>>,
    url: &str,
    set: impl FnOnce(&mut Options),
) -> (TransferId, Body, Text) {
    let ssh: &'static FakeSsh = Box::leak(Box::new(FakeSsh(world.clone())));
    let mut e = Easy::new();
    e.set_libraries(
        SharedLibraries::new(Libraries {
            ssh: Some(ssh),
            ..Libraries::NONE
        })
        .unwrap(),
    );
    let url = url.replace("PORT", &PORT.to_string());
    let body = Body::default();
    let text = Text::default();
    let o = e.options_mut();
    o.set_url(Some(url.as_bytes())).unwrap();
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.output.verbose = true;
    o.callbacks.write = Some(crate::handler::Handler::write(body.clone()).unwrap());
    o.callbacks.debug = Some(crate::handler::Handler::debug(text.clone()).unwrap());
    let ssh = o.ssh.make_mut().unwrap();
    ssh.private_key = Some(b"/keys/id".to_vec());
    ssh.public_key = Some(b"/keys/id.pub".to_vec());
    set(o);
    (m.add(Box::new(e), (), &mut NoEvents).unwrap(), body, text)
}

/// Run `url` to its end over a fresh multi and world: its result, body,
/// trace and the calls the library was made.
fn run(
    files: &[(&str, &str)],
    url: &str,
    set: impl FnOnce(&mut Options),
) -> (Result<(), ErrorKind>, Vec<u8>, String, Vec<String>) {
    run_in(&world(files), url, set)
}

/// The same over `w`.
fn run_in(
    w: &Arc<Mutex<World>>,
    url: &str,
    set: impl FnOnce(&mut Options),
) -> (Result<(), ErrorKind>, Vec<u8>, String, Vec<String>) {
    let mut m = serving(PORT, &silent());
    let (id, body, text) = added(&mut m, w, url, set);
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    m.remove(id, &mut NoEvents).unwrap();
    drop(m);
    let calls = w.lock().unwrap().calls.clone();
    let body = body.0.lock().unwrap().clone();
    (result, body, text.text(), calls)
}

/// An SFTP download: the session handed the socket, logged in with the
/// key files, the file opened from the home directory and read whole;
/// the session said goodbye as its connection closed.
#[test]
fn an_sftp_file_is_downloaded() {
    let (result, body, said, calls) = run(
        &[("/home/u/f", "hello\n")],
        "sftp://u@127.0.0.1:PORT/~/f",
        |_| {},
    );
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"hello\n");
    for line in [
        "SSH authentication methods available: public key, password\n",
        "Authentication using SSH public key file\n",
        "Completed public key authentication\n",
        "Authentication complete\n",
    ] {
        assert!(said.contains(line), "{line:?} in {said}");
    }
    let want = [
        "set_host 127.0.0.1",
        "set_socket",
        "set_user u",
        "import_pubkey_file /keys/id.pub",
        "connect",
        "import_privkey_file /keys/id",
        "auth_publickey",
        "open /home/u/f",
        "disconnect",
    ];
    assert_eq!(calls, want);
}

/// An SCP download reads the size the server offers.
#[test]
fn an_scp_file_is_downloaded() {
    let (result, body, said, calls) = run(
        &[("/tmp/f", "over scp")],
        "scp://u@127.0.0.1:PORT/tmp/f",
        |_| {},
    );
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"over scp");
    assert!(said.contains("SSH CONNECT phase done\n"), "{said}");
    assert_eq!(calls.last().map(String::as_str), Some("disconnect"));
}

/// A file the server does not have fails the SCP download as not found,
/// with the library's words.
#[test]
fn a_missing_scp_file_is_not_found() {
    let (result, _, said, _) = run(&[], "scp://u@127.0.0.1:PORT/tmp/f", |_| {});
    assert_eq!(result, Err(ErrorKind::RemoteFileNotFound), "{said}");
    assert!(said.contains("fake failure"), "{said}");
}

/// Without a key to log in with, the password is tried, and a wrong one
/// is denied.
#[test]
fn the_password_logs_in_when_the_key_may_not() {
    let only_password = |pass: &'static str| {
        let url = format!("sftp://u:{pass}@127.0.0.1:PORT/~/f");
        run(&[("/home/u/f", "x")], &url, |o| {
            o.ssh.make_mut().unwrap().auth_types = SshAuthTypes(SshAuthTypes::PASSWORD);
        })
    };
    let (result, body, said, calls) = only_password("secret");
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"x");
    assert!(
        said.contains("Completed password authentication\n"),
        "{said}"
    );
    assert!(
        calls.contains(&"auth_password secret".to_owned()),
        "{calls:?}"
    );
    let (result, _, said, _) = only_password("wrong");
    assert_eq!(result, Err(ErrorKind::LoginDenied), "{said}");
}

/// The quote commands run before the transfer, on paths read as C reads
/// them; a failing one starting with `*` is let pass.
#[test]
fn quote_commands_run_before_the_transfer() {
    let (result, body, said, calls) = run(
        &[("/home/u/a", "moved")],
        "sftp://u@127.0.0.1:PORT/~/b",
        |o| {
            let line = o.line.make_mut().unwrap();
            line.quote
                .set([
                    &b"rename /home/u/a \"/home/u/b\""[..],
                    b"*rm /home/u/gone",
                    b"chmod 644 /home/u/b",
                    b"mkdir /home/u/d",
                    b"ln /home/u/b /home/u/l",
                ])
                .unwrap();
        },
    );
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"moved");
    let ran: Vec<_> = calls
        .iter()
        .filter(|c| !c.starts_with("set_") && !c.starts_with("import") && *c != "connect")
        .map(String::as_str)
        .collect();
    assert_eq!(
        ran,
        [
            "auth_publickey",
            "rename /home/u/a /home/u/b",
            "unlink /home/u/gone",
            "setstat /home/u/b Permissions(420)",
            "mkdir /home/u/d",
            "symlink /home/u/l /home/u/b",
            "open /home/u/b",
            "disconnect",
        ]
    );
}

/// A failing quote command fails the transfer, with the library's words,
/// unless it starts with `*`; `statvfs` is unknown, as in C's libssh
/// build.
#[test]
fn a_failing_quote_command_fails_the_transfer() {
    let quoted = |cmd: &'static [u8]| {
        run(
            &[("/home/u/f", "x")],
            "sftp://u@127.0.0.1:PORT/~/f",
            move |o| {
                o.line.make_mut().unwrap().quote.set([cmd]).unwrap();
            },
        )
    };
    let (result, body, said, _) = quoted(b"rm /home/u/gone");
    assert_eq!(result, Err(ErrorKind::QuoteError), "{said}");
    assert!(body.is_empty());
    assert!(said.contains("rm command failed: fake failure\n"), "{said}");
    let (result, _, said, _) = quoted(b"statvfs /home/u");
    assert_eq!(result, Err(ErrorKind::QuoteError), "{said}");
    assert!(said.contains("Unknown SFTP command\n"), "{said}");
    let (result, _, said, _) = quoted(b"rm /home/u/f extra");
    assert_eq!(result, Err(ErrorKind::QuoteError), "{said}");
    assert!(
        said.contains("Suspicious data after the command line\n"),
        "{said}"
    );
    let (result, _, said, _) = quoted(b"chmod 99999 /home/u/f");
    assert_eq!(result, Err(ErrorKind::QuoteError), "{said}");
    assert!(
        said.contains("Syntax error: chmod permissions not a number\n"),
        "{said}"
    );
}

/// A directory's listing is its entries' `ls -l` lines, a link's target
/// after it, or their names alone if asked.
#[test]
fn a_directory_is_listed() {
    let w = world(&[("/d/file", "abc")]);
    w.lock()
        .unwrap()
        .links
        .push((b"/d/link".to_vec(), b"file".to_vec()));
    let mut m = serving(PORT, &silent());
    let (id, body, text) = added(&mut m, &w, "sftp://u@127.0.0.1:PORT/d/", |_| {});
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()), "{}", text.text());
    let listed = String::from_utf8(body.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        listed,
        "-rw-r--r--    1 u        u               3 Jan  1 00:00 file\n\
         lrw-r--r--    1 u        u               4 Jan  1 00:00 link -> file\n"
    );
    let (id, body, text) = added(&mut m, &w, "sftp://u@127.0.0.1:PORT/d/", |o| {
        o.line.make_mut().unwrap().list_only = true;
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()), "{}", text.text());
    assert_eq!(*body.0.lock().unwrap(), b"file\nlink\n");
}

/// A range asks for its part of the file only.
#[test]
fn a_range_reads_its_part() {
    let (result, body, said, _) = run(
        &[("/home/u/f", "0123456789")],
        "sftp://u@127.0.0.1:PORT/~/f",
        |o| o.range = Some(b"2-4".to_vec()),
    );
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"234");
}

/// A resumed download is asked for as the range from its resume point,
/// and the resume point is applied again to what the range left, as C
/// applies both (`setup_range`, `myssh_in_SFTP_DOWNLOAD_STAT`): from 3 of
/// ten bytes, four come, as C's libssh build gives them. A point at the
/// end or past it, or the last byte's (`-1`), is a range error.
#[test]
fn a_resumed_download_applies_its_point_as_c_does() {
    use crate::options::Resume;
    let resumed = |at: Resume| {
        run(
            &[("/home/u/f", "0123456789")],
            "sftp://u@127.0.0.1:PORT/~/f",
            move |o| o.resume = Some(at),
        )
    };
    let from = |n| Resume::At(std::num::NonZeroU64::new(n).unwrap());
    let (result, body, said, _) = resumed(from(3));
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"3456");
    for at in [from(10), from(11), Resume::AtEnd] {
        let (result, body, said, _) = resumed(at);
        assert_eq!(result, Err(ErrorKind::RangeError), "{at:?}: {said}");
        assert!(body.is_empty());
    }
    let (_, _, said, _) = resumed(from(11));
    assert!(
        said.contains("Offset (11) was beyond file size (10)\n"),
        "{said}"
    );
}

/// Through an HTTP proxy's tunnel, the library is handed the socket with
/// the server's banner unread in it: the proxy's answer is read a byte
/// at a time, as C reads it, so nothing past it waits in a buffer of
/// ours, where the library would never see it.
#[test]
fn the_socket_is_handed_over_past_a_tunnel() {
    let banner = b"SSH-2.0-OpenSSH_9.9\r\n";
    let answer = [&b"HTTP/1.1 200 Connection established\r\n\r\n"[..], banner].concat();
    let talk = Conversation::replies(&[&answer], false).per_send();
    let w = world(&[("/home/u/f", "tunneled")]);
    let mut m = serving(PROXY_PORT, &talk);
    let (id, body, text) = added(&mut m, &w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("http://127.0.0.1:{PROXY_PORT}").into_bytes());
        proxy.tunnel = true;
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let said = text.text();
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(*body.0.lock().unwrap(), b"tunneled");
    let sent = String::from_utf8_lossy(&talk.received()).into_owned();
    assert!(
        sent.starts_with("CONNECT 127.0.0.1:8022 HTTP/1.1\r\n"),
        "{sent}"
    );
    assert!(w.lock().unwrap().calls.contains(&"set_socket".to_owned()));
    // One read for each byte of the answer, the banner left.
    assert_eq!(talk.reads().0, answer.len() - banner.len(), "{said}");
}

/// Through a SOCKS5 proxy, the library is handed the socket with the
/// server's banner unread in it, though it came in the read of the
/// proxy's grant: the grant is read no further than it goes, as C reads
/// it.
#[test]
fn the_socket_is_handed_over_past_a_socks_grant() {
    let banner = b"SSH-2.0-OpenSSH_9.9\r\n";
    let [hi, lo] = PORT.to_be_bytes();
    let granted = [5, 0, 0, 1, 127, 0, 0, 1, hi, lo];
    let answer = [&granted[..], banner].concat();
    let talk = Conversation::replies(&[&[5, 0], &answer], false).per_send();
    let w = world(&[("/home/u/f", "via socks")]);
    let mut m = serving(PROXY_PORT, &talk);
    let (id, body, text) = added(&mut m, &w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        o.proxy.make_mut().unwrap().url =
            Some(format!("socks5://127.0.0.1:{PROXY_PORT}").into_bytes());
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let said = text.text();
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(*body.0.lock().unwrap(), b"via socks");
    assert!(w.lock().unwrap().calls.contains(&"set_socket".to_owned()));
}

/// A connection serves a later transfer only if it found the same key
/// files (`ssh_config_matches`).
#[test]
fn a_connection_is_reused_only_with_the_same_key_files() {
    let connects = |second_key: &'static [u8]| {
        let w = world(&[("/home/u/f", "x")]);
        let mut m = serving(PORT, &silent());
        for key in [&b"/keys/id"[..], second_key] {
            let (id, body, text) = added(&mut m, &w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
                o.ssh.make_mut().unwrap().private_key = Some(key.to_vec());
            });
            let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
            assert_eq!(result, Ok(()), "{}", text.text());
            assert_eq!(*body.0.lock().unwrap(), b"x");
            m.remove(id, &mut NoEvents).unwrap();
        }
        drop(m);
        let calls = w.lock().unwrap().calls.clone();
        calls.iter().filter(|c| *c == "connect").count()
    };
    assert_eq!(connects(b"/keys/id"), 1);
    assert_eq!(connects(b"/keys/other"), 2);
}

/// The server's key is checked against the SHA-256 fingerprint given, as
/// base64 without its padding, else the MD5 one, in hex.
#[test]
fn the_host_key_s_fingerprints_are_checked() {
    let fingerprinted = |set: fn(&mut crate::options::Ssh)| {
        run(
            &[("/home/u/f", "x")],
            "sftp://u@127.0.0.1:PORT/~/f",
            move |o| set(o.ssh.make_mut().unwrap()),
        )
    };
    let (result, _, said, _) = fingerprinted(|s| {
        s.host_key_sha256 = Some(b"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_vec())
    });
    assert_eq!(result, Ok(()), "{said}");
    assert!(
        said.contains("SSH SHA256 fingerprint: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n"),
        "{said}"
    );
    let (result, _, said, _) =
        fingerprinted(|s| s.host_key_sha256 = Some(b"AAAAAAAAAAAAAAAAAAAA".to_vec()));
    assert_eq!(result, Err(ErrorKind::PeerFailedVerification), "{said}");
    assert!(
        said.contains("Denied establishing ssh session: mismatch SHA256 fingerprint."),
        "{said}"
    );
    let (result, _, said, _) =
        fingerprinted(|s| s.host_key_md5 = Some(b"02020202020202020202020202020202".to_vec()));
    assert_eq!(result, Ok(()), "{said}");
    let (result, _, said, _) =
        fingerprinted(|s| s.host_key_md5 = Some(b"03020202020202020202020202020202".to_vec()));
    assert_eq!(result, Err(ErrorKind::PeerFailedVerification), "{said}");
    assert!(
        said.contains("Denied establishing ssh session: mismatch MD5 fingerprint."),
        "{said}"
    );
}

/// Decides as it was made to, keeping how the keys compared.
struct Decides(crate::handler::KeyVerdict, Arc<Mutex<Vec<KeyMatch>>>);

impl crate::handler::SshKeyHandler for Decides {
    fn check(
        &self,
        _: &mut TransferCx<'_>,
        known: Option<crate::handler::HostKey<'_>>,
        found: crate::handler::HostKey<'_>,
        matched: KeyMatch,
    ) -> crate::handler::KeyVerdict {
        assert_eq!(found.base64, b"AAAA");
        assert_eq!(known.is_some(), matched != KeyMatch::Missing);
        self.1.lock().unwrap().push(matched);
        self.0
    }
}

/// With a known-hosts file, a key it has is fine and one it lacks is
/// not; a key handler decides either way, and a key it would have added
/// is added to the file.
#[test]
fn the_known_hosts_file_and_the_key_handler_decide() {
    use crate::handler::KeyVerdict as V;
    let checked = |known: KnownHosts, verdict: Option<V>| {
        let w = world_with(&[("/home/u/f", "x")], |w| w.known = Some(known));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handler =
            verdict.map(|v| crate::handler::Handler::ssh_key(Decides(v, seen.clone())).unwrap());
        let (result, _, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
            let ssh = o.ssh.make_mut().unwrap();
            ssh.known_hosts = Some(b"/kh".to_vec());
            ssh.key_handler = handler;
        });
        let seen = seen.lock().unwrap().clone();
        (result, said, calls, seen)
    };
    let (result, said, _, _) = checked(KnownHosts::Ok, None);
    assert_eq!(result, Ok(()), "{said}");
    let (result, said, _, _) = checked(KnownHosts::NotFound, None);
    assert_eq!(result, Err(ErrorKind::PeerFailedVerification), "{said}");
    let (result, said, _, seen) = checked(KnownHosts::NotFound, Some(V::Fine));
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(seen, [KeyMatch::Missing]);
    let (result, said, _, seen) = checked(KnownHosts::Changed, Some(V::Reject));
    assert_eq!(result, Err(ErrorKind::PeerFailedVerification), "{said}");
    assert_eq!(seen, [KeyMatch::Mismatch]);
    let (result, said, calls, _) = checked(KnownHosts::NotFound, Some(V::FineAddToFile));
    assert_eq!(result, Ok(()), "{said}");
    assert!(
        calls.contains(&"update_known_hosts".to_owned()),
        "{calls:?}"
    );
}

/// The keyboard-interactive login answers its one question with the
/// password.
#[test]
fn the_keyboard_interactive_login_answers_with_the_password() {
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.methods = Methods::INTERACTIVE;
        w.asks = true;
    });
    let (result, body, said, calls) = run_in(&w, "sftp://u:secret@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"x");
    assert!(
        said.contains("completed keyboard interactive authentication\n"),
        "{said}"
    );
    assert!(
        calls.contains(&"kbdint_answer secret".to_owned()),
        "{calls:?}"
    );
}

/// An upload whose file cannot be opened makes the directories up to it
/// once, then fails if the file still cannot be opened, where C's
/// libssh code would make them again for ever.
#[test]
fn missing_directories_are_made_once() {
    let w = world_with(&[], |w| w.refuses_writes = true);
    let (result, _, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/a/b/f", |o| {
        o.method = crate::options::Method::Upload;
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(b"up".to_vec()).unwrap(),
        );
        o.line.make_mut().unwrap().ftp.create_dirs = CreateDirs::Create;
    });
    assert_eq!(result, Err(ErrorKind::RemoteFileNotFound), "{said}");
    let tried: Vec<_> = calls
        .iter()
        .filter(|c| c.starts_with("open") || c.starts_with("mkdir"))
        .map(String::as_str)
        .collect();
    assert_eq!(
        tried,
        [
            "open /home/u/a/b/f",
            "mkdir /home",
            "mkdir /home/u",
            "mkdir /home/u/a",
            "mkdir /home/u/a/b",
            "open /home/u/a/b/f",
        ]
    );
}

/// An upload goes to the file, made if it is not there.
#[test]
fn an_sftp_file_is_uploaded() {
    let w = world(&[]);
    let (result, _, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        o.method = crate::options::Method::Upload;
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(b"uploaded".to_vec()).unwrap(),
        );
    });
    assert_eq!(result, Ok(()), "{said}");
    let w = w.lock().unwrap();
    assert_eq!(w.files, [(b"/home/u/f".to_vec(), b"uploaded".to_vec())]);
}
