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
    /// SCP's reads end this many bytes short of the size it offers.
    short_by: usize,
    /// So many of SFTP's reads, and of its renames, wait first.
    read_waits: usize,
    rename_waits: usize,
    /// SFTP's writes fail; and so many of its reads, from the
    /// `reads_fail_from`th of the world's on (counted from 1).
    writes_fail: bool,
    reads_fail: usize,
    reads_fail_from: usize,
    reads: usize,
    /// The private key's login is refused.
    key_refused: bool,
    /// The calls, by name, whose first answer is to wait.
    waiting: Vec<&'static str>,
    /// The GSS-API login, and the agent's, succeed.
    gssapi_ok: bool,
    agent_ok: bool,
    /// The keyboard-interactive login asks a round of no questions after
    /// the password's, and refuses an answer given.
    kbd_extra: bool,
    answer_refused: bool,
    /// A file opened to write is refused with this SFTP code.
    open_code: Option<u32>,
    /// The known-hosts file's key is of a type the library has no name for.
    known_other: bool,
    /// The trace says the SSH component's lines.
    trace_ssh: bool,
    /// An open file says it is this big, or says no size.
    stated_size: Option<u64>,
    no_size_flag: bool,
    /// The private key's login answers this.
    key_answer: Option<Auth>,
    /// The keyboard-interactive login waits once at each of these of its
    /// calls, counted from 1.
    kbd_waits_at: Vec<usize>,
    /// So many opens to write are refused as missing, and each directory
    /// made fails with this code.
    refused_opens: usize,
    mkdir_code: Option<u32>,
    /// A listed link says nothing of its permissions.
    link_without_flag: bool,
    /// What the session says a call that would wait waits for.
    poll: PollFlags,
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

    /// Whether `name`'s call answers that it waits, the first time.
    fn waits(&mut self, name: &'static str) -> bool {
        let at = self.waiting.iter().position(|&n| n == name);
        if let Some(at) = at {
            self.waiting.remove(at);
            self.call("waits", &[name.as_bytes()]);
        }
        at.is_some()
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
    fn set_port(&mut self, port: u16) -> Result<(), Refused> {
        self.w().call("set_port", &[port.to_string().as_bytes()]);
        Ok(())
    }
    fn set_compression(&mut self) -> Result<(), Refused> {
        self.w().call("set_compression", &[]);
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
        self.w().poll
    }
    fn error(&self) -> Result<Vec<u8>, OutOfMemory> {
        Ok(b"fake failure".to_vec())
    }
    fn connect(&mut self) -> Rc {
        let mut w = self.w();
        if w.waits("connect") {
            return Rc::Again;
        }
        w.call("connect", &[]);
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
        let kind = if self.w().known_other {
            KeyType::Other
        } else {
            KeyType::Ed25519
        };
        let key = (known != KnownHosts::NotFound).then(|| {
            Ok(KnownKey {
                base64: Some(b"BBBB".to_vec()),
                kind,
            })
        });
        (known, key)
    }
    fn update_known_hosts(&mut self) -> Rc {
        self.w().call("update_known_hosts", &[]);
        Rc::Ok
    }
    fn auth_none(&mut self) -> Auth {
        if self.w().waits("auth_none") {
            return Auth::Again;
        }
        Auth::Denied
    }
    fn auth_list(&mut self) -> Methods {
        Methods(self.w().methods)
    }
    fn try_publickey(&mut self) -> Auth {
        let mut w = self.w();
        if w.waits("try_publickey") {
            return Auth::Again;
        }
        w.call("try_publickey", &[]);
        Auth::Success
    }
    fn import_privkey_file(&mut self, file: &[u8], _: Option<&[u8]>) -> Rc {
        self.w().call("import_privkey_file", &[file]);
        Rc::Ok
    }
    fn auth_publickey(&mut self) -> Auth {
        let mut w = self.w();
        if w.waits("auth_publickey") {
            return Auth::Again;
        }
        w.call("auth_publickey", &[]);
        if let Some(answer) = w.key_answer {
            return answer;
        }
        if w.key_refused {
            Auth::Denied
        } else {
            Auth::Success
        }
    }
    fn auth_publickey_auto(&mut self, _: Option<&[u8]>) -> Auth {
        let mut w = self.w();
        if w.waits("auth_publickey_auto") {
            return Auth::Again;
        }
        w.call("auth_publickey_auto", &[]);
        if w.agent_ok {
            Auth::Success
        } else {
            Auth::Denied
        }
    }
    fn auth_gssapi(&mut self) -> Auth {
        let mut w = self.w();
        if w.waits("auth_gssapi") {
            return Auth::Again;
        }
        w.call("auth_gssapi", &[]);
        if w.gssapi_ok {
            Auth::Success
        } else {
            Auth::Denied
        }
    }
    fn auth_kbdint(&mut self) -> Auth {
        let mut w = self.w();
        if !w.asks {
            return Auth::Denied;
        }
        if w.waits("auth_kbdint") {
            return Auth::Again;
        }
        let next = w.calls.iter().filter(|c| *c == "auth_kbdint").count() + 1;
        if let Some(at) = w.kbd_waits_at.iter().position(|&n| n == next) {
            w.kbd_waits_at.remove(at);
            return Auth::Again;
        }
        w.call("auth_kbdint", &[]);
        // Asked, then answered right: done, past a round of no questions
        // if it has one.
        let rounds = w.calls.iter().filter(|c| *c == "auth_kbdint").count();
        match w.calls.iter().rfind(|c| c.starts_with("kbdint_answer")) {
            None => Auth::Info,
            Some(a) if a.as_bytes().ends_with(&w.password) => {
                if w.kbd_extra && rounds == 2 {
                    Auth::Info
                } else {
                    Auth::Success
                }
            }
            Some(_) => Auth::Denied,
        }
    }
    fn kbdint_prompts(&mut self) -> i32 {
        let w = self.w();
        let rounds = w.calls.iter().filter(|c| *c == "auth_kbdint").count();
        i32::from(rounds == 1)
    }
    fn kbdint_answer(&mut self, _: u32, answer: &[u8]) -> i32 {
        let mut w = self.w();
        w.call("kbdint_answer", &[answer]);
        if w.answer_refused { -1 } else { 0 }
    }
    fn auth_password(&mut self, password: &[u8]) -> Auth {
        let mut w = self.w();
        if w.waits("auth_password") {
            return Auth::Again;
        }
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
        let end = w.files[at].1.len() - w.short_by;
        let rest = &w.files[at].1[pos.min(end)..end];
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        drop(w);
        self.reading = Some(pos + n);
        Ok(n)
    }
    fn scp_write(&mut self, bytes: &[u8]) -> Rc {
        if self.w().writes_fail {
            return Rc::Error;
        }
        let at = self.scp.as_ref().unwrap().2;
        self.w().files[at].1.extend_from_slice(bytes);
        Rc::Ok
    }
    fn scp_close(&mut self) -> Rc {
        let mut w = self.w();
        if w.waits("scp_close") {
            return Rc::Again;
        }
        w.call("scp_close", &[]);
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
                let mut entry = Self::attrs(name, target.len(), true);
                if w.link_without_flag {
                    entry.flags = Attrs::SIZE;
                }
                entries.push(entry);
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
        let mut w = self.w();
        w.call("mkdir", &[path]);
        if let Some(code) = w.mkdir_code {
            drop(w);
            self.error = code;
            return Rc::Error;
        }
        Rc::Ok
    }
    fn rename(&mut self, from: &[u8], to: &[u8]) -> Rc {
        let mut w = self.w();
        if w.rename_waits > 0 {
            w.rename_waits -= 1;
            return Rc::Again;
        }
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
        if mode != OpenMode::Read && w.refused_opens > 0 {
            w.refused_opens -= 1;
            drop(w);
            self.error = SSH_FX_NO_SUCH_FILE;
            return false;
        }
        if let Some(code) = w.open_code.filter(|_| mode != OpenMode::Read) {
            drop(w);
            self.error = code;
            return false;
        }
        if mode != OpenMode::Read {
            w.call("open mode", &[format!("{mode:?}").as_bytes()]);
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
        self.w().call("seek", &[offset.to_string().as_bytes()]);
        self.file.as_mut().unwrap().pos = offset as usize;
        Rc::Ok
    }
    fn fstat(&mut self) -> Result<Option<Attrs>, OutOfMemory> {
        let at = self.file.as_ref().unwrap().at;
        let w = self.w();
        let mut attrs = Self::attrs(&w.files[at].0, w.files[at].1.len(), false);
        if let Some(size) = w.stated_size {
            attrs.size = size;
        }
        if w.no_size_flag {
            attrs.flags = Attrs::PERMISSIONS;
        }
        Ok(Some(attrs))
    }
    fn file_nonblocking(&mut self) {}
    fn begin_read(&mut self, len: usize) -> Rc {
        assert!(self.reading.is_none(), "one read under way at a time");
        self.reading = Some(len);
        Rc::Ok
    }
    fn wait_read(&mut self, buf: &mut [u8]) -> Aio {
        {
            let mut w = self.world.lock().unwrap();
            if w.read_waits > 0 {
                w.read_waits -= 1;
                w.call("wait_read again", &[]);
                assert!(self.reading.is_some(), "a read begun");
                return Aio::Again;
            }
            w.reads += 1;
            if w.reads >= w.reads_fail_from && w.reads_fail > 0 {
                w.reads_fail -= 1;
                w.call("read fails", &[]);
                self.reading = None;
                return Aio::Error;
            }
        }
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
        if self.w().writes_fail {
            return Rc::Error;
        }
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

impl crate::handler::HeaderHandler for Body {
    fn header(
        &self,
        _: &mut TransferCx<'_>,
        line: &[u8],
        _: crate::handler::HeaderOrigin,
    ) -> Wrote {
        self.0.lock().unwrap().extend_from_slice(line);
        Wrote::Accepted
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
    added_with_tls(m, world, url, None, set)
}

/// The same, given `tls` as its TLS library if any.
fn added_with_tls(
    m: &mut Multi,
    world: &Arc<Mutex<World>>,
    url: &str,
    tls: Option<crate::libraries::Library<dyn crate::tls::TlsBackend>>,
    set: impl FnOnce(&mut Options),
) -> (TransferId, Body, Text) {
    let ssh: &'static FakeSsh = Box::leak(Box::new(FakeSsh(world.clone())));
    let mut e = Easy::new();
    if world.lock().unwrap().trace_ssh {
        let c = crate::components::Components::new().unwrap();
        c.configure(b"ssh,multi");
        e.set_components(Some(c));
    }
    e.set_libraries(
        SharedLibraries::new(Libraries {
            ssh: Some(ssh),
            tls,
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
        "set_port 8022",
        "import_pubkey_file /keys/id.pub",
        "connect",
        "try_publickey",
        "import_privkey_file /keys/id",
        "auth_publickey",
        "open /home/u/f",
        "disconnect",
    ];
    assert_eq!(calls, want);
}

/// Compression is asked of the library when the transfer asks for it.
#[test]
fn compression_is_asked_for_when_wanted() {
    for wanted in [false, true] {
        let (result, _, said, calls) =
            run(&[("/home/u/f", "x")], "sftp://u@127.0.0.1:PORT/~/f", |o| {
                o.ssh.make_mut().unwrap().compression = wanted
            });
        assert_eq!(result, Ok(()), "{said}");
        assert_eq!(calls.contains(&"set_compression".to_owned()), wanted);
    }
}

/// The default private key is the first of `~/.ssh/id_rsa`,
/// `~/.ssh/id_dsa`, `id_rsa` and `id_dsa` there is, else none.
#[test]
fn the_default_private_key_is_the_first_there_is() {
    let there = |names: &'static [&'static [u8]]| {
        move |f: &[u8]| -> Result<bool, ErrorKind> { Ok(names.contains(&f)) }
    };
    let first = |home: Option<&[u8]>, names| super::first_private_key(home, there(names)).unwrap();
    let all: &[&[u8]] = &[b"/h/.ssh/id_rsa", b"/h/.ssh/id_dsa", b"id_rsa", b"id_dsa"];
    assert_eq!(first(Some(b"/h"), all), b"/h/.ssh/id_rsa");
    assert_eq!(first(Some(b"/h"), &all[1..]), b"/h/.ssh/id_dsa");
    assert_eq!(first(Some(b"/h"), &all[2..]), b"id_rsa");
    assert_eq!(first(None, all), b"id_rsa");
    assert_eq!(first(Some(b"/h"), &all[3..]), b"id_dsa");
    assert_eq!(first(Some(b"/h"), &[]), b"");
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
                    b"chgrp 12 /home/u/b",
                    b"chown 34 /home/u/b",
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
            "try_publickey",
            "auth_publickey",
            "rename /home/u/a /home/u/b",
            "unlink /home/u/gone",
            "setstat /home/u/b Permissions(420)",
            "setstat /home/u/b Gid(12)",
            "setstat /home/u/b Uid(34)",
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
    let (result, _, said, _) = quoted(b"rm \"/home/u/f");
    assert_eq!(result, Err(ErrorKind::QuoteError), "{said}");
    assert!(
        said.contains("Syntax error: Bad first parameter\n"),
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
    // Past the middle, the point is compared with what the range left,
    // as C compares it: at it, nothing is left to get; past it, the point
    // is beyond.
    let (result, body, said, _) = resumed(from(5));
    assert_eq!(result, Ok(()), "{said}");
    assert!(body.is_empty());
    assert!(
        said.contains("File already completely downloaded\n"),
        "{said}"
    );
    let (result, _, said, _) = resumed(from(6));
    assert_eq!(result, Err(ErrorKind::BadDownloadResume), "{said}");
    assert!(
        said.contains("Offset (6) was beyond file size (4)\n"),
        "{said}"
    );
}

/// An SCP upload offers the file at its size and writes it; one of no
/// known size is refused, as SCP needs the size first.
#[test]
fn an_scp_file_is_uploaded() {
    let w = world(&[]);
    let (result, _, said, calls) = run_in(&w, "scp://u@127.0.0.1:PORT/tmp/f", |o| {
        o.method = crate::options::Method::Upload;
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(b"over scp".to_vec()).unwrap(),
        );
    });
    assert_eq!(result, Ok(()), "{said}");
    assert!(
        calls.contains(&"scp_push_file /tmp/f".to_owned()),
        "{calls:?}"
    );
    assert_eq!(
        w.lock().unwrap().files,
        [(b"/tmp/f".to_vec(), b"over scp".to_vec())]
    );
}

/// A file shorter than the server said is a partial one.
#[test]
fn a_short_scp_file_is_partial() {
    let w = world(&[("/tmp/f", "0123456789")]);
    w.lock().unwrap().short_by = 4;
    let (result, body, said, _) = run_in(&w, "scp://u@127.0.0.1:PORT/tmp/f", |_| {});
    assert_eq!(result, Err(ErrorKind::PartialFile), "{said}");
    assert_eq!(body, b"012345");
    assert!(
        said.contains("transfer closed with 4 bytes remaining to read\n"),
        "{said}"
    );
}

/// Without an SSH library, the schemes are not supported.
#[test]
fn ssh_wants_an_ssh_library() {
    for url in ["scp://127.0.0.1:8022/f", "sftp://127.0.0.1:8022/f"] {
        let mut m = serving(PORT, &silent());
        let mut e = Easy::new();
        e.set_libraries(SharedLibraries::new(Libraries::NONE).unwrap());
        e.options_mut().set_url(Some(url.as_bytes())).unwrap();
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        assert_eq!(result, Err(ErrorKind::UnsupportedProtocol), "{url}");
    }
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

/// Through an HTTPS proxy's tunnel, the library is not handed the socket:
/// the proxy's TLS works on its bytes, which the library would read and
/// write past. C's libssh build hands it the socket all the same, and SSH
/// goes out in clear, past the TLS, in the middle of the proxy's TLS
/// session (DIVERGENCE.md).
#[test]
fn the_socket_is_not_handed_over_under_a_proxy_s_tls() {
    use crate::tls::fake::{self, FakeTls, WELCOME};
    let tls = |plain: &[u8]| fake::records(plain).unwrap();
    let answer = tls(b"HTTP/1.1 200 Connection established\r\n\r\n");
    let talk = Conversation::replies(&[WELCOME, &answer], false).per_send();
    let w = world(&[("/home/u/f", "tunneled")]);
    let mut m = serving(PROXY_PORT, &talk);
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
    let library = crate::libraries::Library::Static(backend as &dyn crate::tls::TlsBackend);
    let url = "sftp://u@127.0.0.1:PORT/~/f";
    let (id, body, text) = added_with_tls(&mut m, &w, url, Some(library), |o| {
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("https://127.0.0.1:{PROXY_PORT}").into_bytes());
        proxy.tunnel = true;
    });
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let said = text.text();
    assert_eq!(result, Err(ErrorKind::FailedInit), "{said}");
    assert!(said.contains("Could not set socket"), "{said}");
    let sent = fake::read_client(&talk.received()).unwrap();
    let sent = String::from_utf8_lossy(&sent).into_owned();
    assert!(
        sent.contains("CONNECT 127.0.0.1:8022 HTTP/1.1\r\n"),
        "{sent}"
    );
    assert!(!w.lock().unwrap().calls.contains(&"set_socket".to_owned()));
    assert!(body.0.lock().unwrap().is_empty());
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
    // One character short is no match, though the rest is.
    let (result, _, said, _) = fingerprinted(|s| {
        s.host_key_sha256 = Some(b"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ".to_vec())
    });
    assert_eq!(result, Err(ErrorKind::PeerFailedVerification), "{said}");
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
/// once, then fails if the file still cannot be opened, as C's libssh2
/// code gives up (`secondCreateDirs`), where its libssh code sets the
/// flag and never reads it, making them again for as long as the open
/// fails (DIVERGENCE.md).
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

/// A file refused twice is not tried a third time, though it would open
/// then: the directories are made once (DIVERGENCE.md).
#[test]
fn a_file_refused_again_is_not_tried_again() {
    let w = world_with(&[], |w| w.refused_opens = 2);
    let (result, _, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/a/f", |o| {
        uploads(o, b"up");
        o.line.make_mut().unwrap().ftp.create_dirs = CreateDirs::Create;
    });
    assert_eq!(result, Err(ErrorKind::RemoteFileNotFound), "{said}");
    let opens = calls.iter().filter(|c| c.starts_with("open /")).count();
    assert_eq!(opens, 2, "{calls:?}");
    assert!(w.lock().unwrap().files.is_empty());
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

/// A multi whose server at `PORT` always has something to read, so
/// that a wait on the session's socket ends at once.
fn chatty() -> Multi {
    serving(
        PORT,
        &Conversation::replies(&[b"SSH-2.0-x\r\n"], false).greeting(),
    )
}

/// Run `url` over `w` on `m` to its end, as `run_in`.
fn run_on(
    m: &mut Multi,
    w: &Arc<Mutex<World>>,
    url: &str,
    set: impl FnOnce(&mut Options),
) -> (Result<(), ErrorKind>, Vec<u8>, String) {
    let (id, body, text) = added(m, w, url, set);
    let result = drive_to_completion(m, id, &mut NoEvents).unwrap();
    m.remove(id, &mut NoEvents).unwrap();
    let body = body.0.lock().unwrap().clone();
    (result, body, text.text())
}

/// An SFTP read that waits is waited on, then taken where it was asked
/// for, its room unchanged.
#[test]
fn a_read_that_waits_is_taken_after_its_wait() {
    let w = world_with(&[("/home/u/f", "waited for")], |w| w.read_waits = 2);
    let mut m = chatty();
    let (result, body, said) = run_on(&mut m, &w, "sftp://u@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"waited for");
    let waits = w
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|c| *c == "wait_read again")
        .count();
    assert_eq!(waits, 2);
}

/// An SFTP download whose first read fails on a reused connection, with
/// nothing received, is made again on a fresh one (`Curl_retry_request`),
/// its post-quote run once, after the download made again, not after the
/// one given up. An upload whose write fails so is not made again, as C
/// retries no upload outside HTTP.
#[test]
fn a_download_that_gets_nothing_on_a_reused_connection_is_made_again() {
    let connects = |w: &Arc<Mutex<World>>| {
        w.lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| *c == "connect")
            .count()
    };
    let w = world_with(&[("/home/u/f", "x"), ("/home/u/g", "y")], |w| {
        w.reads_fail = 1;
        // The first transfer reads its one byte once, its size known.
        w.reads_fail_from = 2;
    });
    let mut m = serving(PORT, &silent());
    let (result, body, said) = run_on(&mut m, &w, "sftp://u@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!((result, body), (Ok(()), b"x".to_vec()), "{said}");
    let (result, body, said) = run_on(&mut m, &w, "sftp://u@127.0.0.1:PORT/~/g", |o| {
        let line = o.line.make_mut().unwrap();
        line.postquote
            .set([&b"rename /home/u/g /home/u/h"[..]])
            .unwrap();
    });
    assert_eq!((result, body), (Ok(()), b"y".to_vec()), "{said}");
    drop(m);
    assert_eq!(
        connects(&w),
        2,
        "made again on a fresh connection: {:?}",
        w.lock().unwrap().calls
    );
    let calls = w.lock().unwrap().calls.clone();
    let renames = calls.iter().filter(|c| c.starts_with("rename ")).count();
    assert_eq!(renames, 1, "{calls:?}");
    assert!(calls.contains(&"read fails".to_owned()), "{calls:?}");

    let w = world_with(&[("/home/u/f", "x")], |_| {});
    let mut m = serving(PORT, &silent());
    let (result, _, said) = run_on(&mut m, &w, "sftp://u@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    w.lock().unwrap().writes_fail = true;
    let (result, _, said) = run_on(&mut m, &w, "sftp://u@127.0.0.1:PORT/~/up", |o| {
        uploads(o, b"z");
    });
    assert!(result.is_err(), "{said}");
    drop(m);
    assert_eq!(connects(&w), 1, "an upload is not made again");

    // A download that got some of its body before its read failed is not
    // made again: its files say no size, so each is read to its end.
    let w = world_with(&[("/home/u/f", "x"), ("/home/u/g", "y")], |w| {
        w.no_size_flag = true;
        w.reads_fail = 1;
        // The first transfer's byte and its end, then the second's byte.
        w.reads_fail_from = 4;
    });
    let mut m = serving(PORT, &silent());
    let (result, _, said) = run_on(&mut m, &w, "sftp://u@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    let (result, body, said) = run_on(&mut m, &w, "sftp://u@127.0.0.1:PORT/~/g", |_| {});
    assert!(result.is_err(), "{said}");
    assert_eq!(body, b"y");
    drop(m);
    assert_eq!(
        connects(&w),
        1,
        "a download that got bytes is not made again"
    );
}

/// A command after the transfer that waits is waited on as the transfer
/// ends, and the next transfer finds its connection.
#[test]
fn a_command_after_the_transfer_may_wait() {
    let w = world_with(&[("/home/u/f", "x")], |w| w.rename_waits = 3);
    let mut m = serving(PORT, &silent());
    let (result, body, said) = run_on(&mut m, &w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        let line = o.line.make_mut().unwrap();
        line.postquote
            .set([&b"rename /home/u/f /home/u/g"[..]])
            .unwrap();
    });
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"x");
    let (result, body, said) = run_on(&mut m, &w, "sftp://u@127.0.0.1:PORT/~/g", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"x");
    drop(m);
    let w = w.lock().unwrap();
    assert_eq!(w.calls.iter().filter(|c| *c == "connect").count(), 1);
    assert!(w.calls.contains(&"rename /home/u/f /home/u/g".to_owned()));
}

/// Run a transfer of `~/f` with `set` choosing its quote commands: what its
/// header handler was told.
fn told_by_quotes(set: impl FnOnce(&mut crate::options::Line)) -> Vec<u8> {
    let w = world_with(&[("/home/u/f", "x")], |_| {});
    let headers = Body::default();
    let given = headers.clone();
    let (result, body, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        o.callbacks.header = Some(crate::handler::Handler::header(given).unwrap());
        set(o.line.make_mut().unwrap());
    });
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"x");
    headers.0.lock().unwrap().clone()
}

/// `pwd` before the transfer says the path. Its answer is no HTTP header:
/// kept for the headers API, it would be refused and fail the transfer.
#[test]
fn pwd_before_the_transfer_says_the_path() {
    let told = told_by_quotes(|line| line.quote.set([&b"pwd"[..]]).unwrap());
    assert_eq!(told, b"257 \"/home/u/f\" is current directory.\n");
}

/// `pwd` after the transfer, whose path has gone by then, says C's text for
/// a missing path and does not fail the transfer (test 3652).
#[test]
fn pwd_after_the_transfer_says_no_path() {
    let told = told_by_quotes(|line| line.postquote.set([&b"pwd"[..]]).unwrap());
    assert_eq!(told, b"257 \"(nil)\" is current directory.\n");
}

/// An SFTP write that fails fails the upload as a send error.
#[test]
fn a_failing_write_fails_the_upload() {
    let w = world_with(&[], |w| w.writes_fail = true);
    let (result, _, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        o.method = crate::options::Method::Upload;
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(b"up".to_vec()).unwrap(),
        );
    });
    assert_eq!(result, Err(ErrorKind::SendError), "{said}");
}

/// A refused key's login is said with libssh's number for the refusal,
/// and the password is tried next.
#[test]
fn a_refused_key_falls_back_to_the_password() {
    let w = world_with(&[("/home/u/f", "x")], |w| w.key_refused = true);
    let (result, body, said, _) = run_in(&w, "sftp://u:secret@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"x");
    assert!(
        said.contains("Failed public key authentication (rc: 1)\n"),
        "{said}"
    );
    assert!(
        said.contains("Completed password authentication\n"),
        "{said}"
    );
}

/// An SFTP status code is the failure C makes of it
/// (`sftp_error_to_CURLE`).
#[test]
fn sftp_codes_are_c_s_failures() {
    use super::sftp_failure;
    assert_eq!(sftp_failure(0), Ok(()));
    for (code, kind) in [
        (2, ErrorKind::RemoteFileNotFound),
        (10, ErrorKind::RemoteFileNotFound),
        (3, ErrorKind::RemoteAccessDenied),
        (12, ErrorKind::RemoteAccessDenied),
        (11, ErrorKind::RemoteFileExists),
        (4, ErrorKind::Ssh),
    ] {
        assert_eq!(sftp_failure(code), Err(kind), "{code}");
    }
}

/// An upload the server refuses fails with the failure its code is.
#[test]
fn a_refused_upload_fails_as_its_code_says() {
    for (code, kind) in [
        (3, ErrorKind::RemoteAccessDenied),
        (11, ErrorKind::RemoteFileExists),
    ] {
        let w = world_with(&[], |w| w.open_code = Some(code));
        let (result, _, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
            uploads(o, b"up");
        });
        assert_eq!(result, Err(kind), "{code}: {said}");
    }
}

/// `o` uploads `bytes`.
fn uploads(o: &mut Options, bytes: &[u8]) {
    o.method = crate::options::Method::Upload;
    o.upload =
        crate::options::UploadSource::Bytes(curl_alloc::TryArc::try_new(bytes.to_vec()).unwrap());
}

/// An upload resumed is stored as C's libssh build stores it: from a
/// point, the body's bytes past it written there; from the end, past
/// what is stored, or whole if nothing is; appended, all of it after
/// what is stored. Each checked against the C build with libssh, `curl
/// -T` with `-C 3`, `-C -` and `--append`.
#[test]
fn a_resumed_upload_is_stored_as_c_stores_it() {
    use crate::options::Resume;
    let at = |n| Some(Resume::At(std::num::NonZeroU64::new(n).unwrap()));
    let cases: [(&str, Option<Resume>, bool, &str, &str); 5] = [
        ("abcdef", at(3), false, "abc3456789", "Write"),
        ("abcd", Some(Resume::AtEnd), false, "abcd456789", "Write"),
        ("", Some(Resume::AtEnd), false, "0123456789", "Truncate"),
        ("abcdefghijkl", None, false, "0123456789", "Truncate"),
        ("abcd", None, true, "abcd0123456789", "Append"),
    ];
    for (stored, resume, append, want, mode) in cases {
        let files: &[(&str, &str)] = if stored.is_empty() {
            &[]
        } else {
            &[("/home/u/f", stored)]
        };
        let w = world(files);
        let (result, _, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
            uploads(o, b"0123456789");
            o.resume = resume;
            o.line.make_mut().unwrap().ftp.append = append;
        });
        assert_eq!(result, Ok(()), "{stored:?}: {said}");
        let file = w.lock().unwrap().files[0].1.clone();
        assert_eq!(String::from_utf8(file).unwrap(), want, "{stored:?}");
        assert!(calls.contains(&format!("open mode {mode}")), "{calls:?}");
        assert_eq!(calls.iter().any(|c| c.starts_with("seek")), mode == "Write");
    }
}

/// A resume point past several of the skipped reads' buffers is passed
/// whole, and one past the body fails as C's does when it cannot seek.
#[test]
fn a_resumed_upload_skips_to_its_point() {
    use crate::options::Resume;
    let body: Vec<u8> = (0..10_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let stored = "x".repeat(6_000);
    let w = world(&[("/home/u/f", &stored)]);
    let (result, _, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        uploads(o, &body);
        o.resume = Some(Resume::At(std::num::NonZeroU64::new(5_000).unwrap()));
    });
    assert_eq!(result, Ok(()), "{said}");
    assert!(calls.contains(&"seek 5000".to_owned()), "{calls:?}");
    let file = w.lock().unwrap().files[0].1.clone();
    assert_eq!(&file[..5_000], &stored.as_bytes()[..5_000]);
    assert_eq!(&file[5_000..], &body[5_000..]);
    let w = world(&[("/home/u/f", "abcdef")]);
    let (result, _, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        uploads(o, b"0123456789");
        o.resume = Some(Resume::At(std::num::NonZeroU64::new(11).unwrap()));
    });
    assert_eq!(result, Err(ErrorKind::FtpCouldntUseRest), "{said}");
    assert!(said.contains("Failed to read data\n"), "{said}");
    assert_eq!(w.lock().unwrap().files[0].1, b"abcdef");
}

/// The upload's handler, reading `body` from where its seek put it.
struct Seekable {
    body: &'static [u8],
    at: Arc<Mutex<usize>>,
    /// What the seek answers.
    seeks: Result<(), crate::handler::SeekFailed>,
}

impl crate::handler::ReadHandler for Seekable {
    fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> crate::handler::Read {
        let mut at = self.at.lock().unwrap();
        let n = self.body.len().saturating_sub(*at).min(buf.len());
        if n == 0 {
            return crate::handler::Read::Eof;
        }
        buf[..n].copy_from_slice(&self.body[*at..*at + n]);
        *at += n;
        std::num::NonZeroUsize::new(n).map_or(crate::handler::Read::Eof, crate::handler::Read::Data)
    }
}

impl crate::handler::Rewind for Seekable {
    fn rewind(&self, _: &mut TransferCx<'_>) -> Result<(), crate::handler::RewindFailed> {
        unreachable!("not rewound")
    }

    fn seek(&self, _: &mut TransferCx<'_>, offset: u64) -> Result<(), crate::handler::SeekFailed> {
        if self.seeks.is_ok() {
            *self.at.lock().unwrap() = usize::try_from(offset).unwrap();
        }
        self.seeks
    }
}

/// A resumed upload whose source seeks starts there, the size left
/// announced; past the source's size it fails with C's reason, after the
/// seek, as `curl -T f -C 11` does with libssh. A seek that fails fails
/// it, and one that cannot reads to the point.
#[test]
fn a_resumed_upload_seeks_its_source() {
    use crate::handler::{Handler, SeekFailed};
    use crate::options::{Resume, UploadSource};
    let resumed = |from: u64, seeks: Result<(), SeekFailed>| {
        let w = world(&[("/home/u/f", "abcdef")]);
        let at = Arc::new(Mutex::new(0));
        let (result, _, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
            o.method = crate::options::Method::Upload;
            let source = || Seekable {
                body: b"0123456789",
                at: at.clone(),
                seeks,
            };
            o.upload = UploadSource::Read {
                handler: Handler::read(source()).unwrap(),
                rewind: Some(Handler::rewind(source()).unwrap()),
                size: Some(10),
            };
            o.resume = Some(Resume::At(std::num::NonZeroU64::new(from).unwrap()));
        });
        let file = w.lock().unwrap().files[0].1.clone();
        (result, said, String::from_utf8(file).unwrap())
    };
    let (result, said, file) = resumed(4, Ok(()));
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(file, "abcd456789");
    let (result, said, file) = resumed(11, Ok(()));
    assert_eq!(result, Err(ErrorKind::BadFunctionArgument), "{said}");
    assert!(said.contains("Resume point beyond size\n"), "{said}");
    assert_eq!(file, "abcdef");
    let (result, said, file) = resumed(3, Err(SeekFailed::Fail));
    assert_eq!(result, Err(ErrorKind::FtpCouldntUseRest), "{said}");
    assert!(said.contains("Could not seek stream\n"), "{said}");
    assert_eq!(file, "abcdef");
    let (result, said, file) = resumed(3, Err(SeekFailed::CantSeek));
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(file, "abc3456789");
    let (result, said, _) = resumed(11, Err(SeekFailed::CantSeek));
    assert_eq!(result, Err(ErrorKind::FtpCouldntUseRest), "{said}");
    assert!(said.contains("Failed to read data\n"), "{said}");
}

/// `atime` and `mtime` set the time given, a date C's parser reads; one
/// it cannot read, or past 32 bits, is a quote error.
#[test]
fn quote_commands_set_times() {
    let quoted = |cmd: &'static [u8]| {
        run(
            &[("/home/u/f", "x")],
            "sftp://u@127.0.0.1:PORT/~/f",
            move |o| o.line.make_mut().unwrap().quote.set([cmd]).unwrap(),
        )
    };
    let (result, _, said, calls) = quoted(b"mtime \"1 Jan 2024 00:00:00 GMT\" /home/u/f");
    assert_eq!(result, Ok(()), "{said}");
    assert!(
        calls.contains(&"setstat /home/u/f Mtime(1704067200)".to_owned()),
        "{calls:?}"
    );
    let (result, _, said, calls) = quoted(b"atime \"1 Jan 2024 00:00:00 GMT\" /home/u/f");
    assert_eq!(result, Ok(()), "{said}");
    assert!(
        calls.contains(&"setstat /home/u/f Atime(1704067200)".to_owned()),
        "{calls:?}"
    );
    let (result, _, said, _) = quoted(b"atime nonsense /home/u/f");
    assert_eq!(result, Err(ErrorKind::QuoteError), "{said}");
    assert!(said.contains("incorrect date format for atime\n"), "{said}");
    let (result, _, said, _) = quoted(b"mtime nonsense /home/u/f");
    assert!(said.contains("incorrect date format for mtime\n"), "{said}");
    assert_eq!(result, Err(ErrorKind::QuoteError));
    let (result, _, said, _) = quoted(b"mtime \"1 Jan 2200 00:00:00 GMT\" /home/u/f");
    assert_eq!(result, Err(ErrorKind::QuoteError), "{said}");
    assert!(said.contains("date overflow\n"), "{said}");
    let (result, _, said, calls) = quoted(b"mtime \"7 Feb 2106 06:28:15 GMT\" /home/u/f");
    assert_eq!(result, Ok(()), "{said}");
    assert!(
        calls.contains(&"setstat /home/u/f Mtime(4294967295)".to_owned()),
        "{calls:?}"
    );
}

/// Each login, and the connect, waits on the socket when the library
/// says to, and goes on where it was.
#[test]
fn logins_that_wait_go_on_where_they_were() {
    let logged_in = |set: fn(&mut World), user: &str| {
        let w = world_with(&[("/home/u/f", "x")], set);
        let mut m = chatty();
        let url = format!("sftp://{user}@127.0.0.1:PORT/~/f");
        let (result, body, said) = run_on(&mut m, &w, &url, |_| {});
        drop(m);
        let w = w.lock().unwrap();
        assert!(w.waiting.is_empty(), "every wait taken: {:?}", w.waiting);
        (result, body, said, w.calls.clone())
    };
    let (result, body, said, _) = logged_in(
        |w| w.waiting = vec!["connect", "auth_none", "try_publickey", "auth_publickey"],
        "u",
    );
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"x");
    let (result, _, said, _) = logged_in(
        |w| {
            w.key_refused = true;
            w.waiting = vec!["auth_password"];
        },
        "u:secret",
    );
    assert_eq!(result, Ok(()), "{said}");
    assert!(
        said.contains("Completed password authentication\n"),
        "{said}"
    );
    let (result, _, said, _) = logged_in(
        |w| {
            w.key_refused = true;
            w.methods |= Methods::GSSAPI_MIC;
            w.gssapi_ok = true;
            w.waiting = vec!["auth_gssapi"];
        },
        "u",
    );
    assert_eq!(result, Ok(()), "{said}");
    assert!(said.contains("Completed gssapi authentication\n"), "{said}");
    let (result, _, said, _) = logged_in(
        |w| {
            w.key_refused = true;
            w.methods |= Methods::INTERACTIVE;
            w.asks = true;
            w.waiting = vec!["auth_kbdint", "auth_kbdint"];
        },
        "u:secret",
    );
    assert_eq!(result, Ok(()), "{said}");
    assert!(
        said.contains("completed keyboard interactive authentication\n"),
        "{said}"
    );
}

/// Without a private key, the agent's and the default keys log in, and
/// may wait first.
#[test]
fn the_agent_logs_in_without_a_private_key() {
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.agent_ok = true;
        w.waiting = vec!["auth_publickey_auto"];
    });
    let mut m = chatty();
    let (result, body, said) = run_on(&mut m, &w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        let ssh = o.ssh.make_mut().unwrap();
        ssh.private_key = None;
        ssh.public_key = None;
        ssh.auth_types = crate::options::SshAuthTypes::ANY;
    });
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"x");
    assert!(
        said.contains("Completed public key authentication\n"),
        "{said}"
    );
    assert!(
        w.lock()
            .unwrap()
            .calls
            .contains(&"auth_publickey_auto".to_owned())
    );
}

/// The keyboard-interactive login takes a round of no questions after
/// the password's; an answer the library refuses falls to the password.
#[test]
fn the_interactive_login_takes_its_rounds() {
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.key_refused = true;
        w.methods = Methods::PUBLICKEY | Methods::INTERACTIVE;
        w.asks = true;
        w.kbd_extra = true;
    });
    let (result, _, said, calls) = run_in(&w, "sftp://u:secret@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(calls.iter().filter(|c| *c == "auth_kbdint").count(), 3);
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.key_refused = true;
        w.methods |= Methods::INTERACTIVE;
        w.asks = true;
        w.answer_refused = true;
    });
    let (result, _, said, calls) = run_in(&w, "sftp://u:secret@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    assert!(
        said.contains("Completed password authentication\n"),
        "{said}"
    );
    assert_eq!(calls.iter().filter(|c| *c == "auth_kbdint").count(), 1);
}

/// The setup says the key files a public key login is to use, unless
/// the transfer may not log in so.
#[test]
fn the_key_files_are_said() {
    let w = world(&[("/home/u/f", "x")]);
    let (_, _, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |_| {});
    assert!(
        said.contains("SSH: public key file '/keys/id.pub'\n"),
        "{said}"
    );
    assert!(
        said.contains("SSH: private key file '/keys/id'\n"),
        "{said}"
    );
    let (_, _, said, _) = run_in(&w, "sftp://u:secret@127.0.0.1:PORT/~/f", |o| {
        o.ssh.make_mut().unwrap().auth_types =
            crate::options::SshAuthTypes(crate::options::SshAuthTypes::PASSWORD);
    });
    assert!(!said.contains("SSH: public key file"), "{said}");
}

/// The SSH component's trace says each move of the state machine by the
/// states' C names, and where each run stopped.
#[test]
fn the_ssh_trace_says_the_states() {
    let w = world_with(&[("/home/u/f", "x")], |w| w.trace_ssh = true);
    let (result, _, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    for line in [
        "[SSH] [SSH_INIT] -> [SSH_S_STARTUP]\n",
        "[SSH] [SSH_AUTH_DONE] -> [SSH_SFTP_INIT]\n",
        "[SSH] [SSH_STOP] statemachine() -> 0, block=0\n",
    ] {
        assert!(said.contains(line), "{line:?} in {said}");
    }
}

/// An SSH request reads its credentials once, as C's every transfer
/// does (`url_set_data_creds_netrc`): the credentials it sets out with are
/// said as the handle's before, none on its first transfer, and once.
#[test]
fn the_credentials_are_said_once_as_the_handle_s_before() {
    let w = world_with(&[("/home/u/f", "x")], |w| w.trace_ssh = true);
    let (result, _, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    let lines: Vec<&str> = said
        .lines()
        .filter(|l| l.contains("transfer credentials"))
        .collect();
    assert_eq!(
        lines,
        ["[MULTI] [CONNECT] transfer credentials: -"],
        "{said}"
    );
}

/// The SSH component's trace says the pollset the session's wait asks
/// for, its flags in hex, and nothing of one made while it asks for
/// nothing.
#[test]
fn the_ssh_trace_says_what_its_pollset_waits_for() {
    let said = |set: fn(&mut World)| {
        let w = world_with(&[("/home/u/f", "x")], |w| {
            w.trace_ssh = true;
            set(w);
        });
        let (result, _, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |_| {});
        assert_eq!(result, Ok(()), "{said}");
        said
    };
    let waiting = said(|w| {
        // Once as it connects, and again once it is waited on.
        w.waiting = vec!["connect", "connect"];
        w.poll = PollFlags {
            read: true,
            write: true,
        };
    });
    assert!(waiting.contains("[SSH] pollset, flags=3\n"), "{waiting}");
    let reading = said(|w| {
        w.read_waits = 1;
        w.poll = PollFlags {
            read: true,
            write: false,
        };
    });
    assert!(reading.contains("[SSH] pollset, flags=1\n"), "{reading}");
    assert!(!reading.contains("flags=3"), "{reading}");
    // A connect that waits with the session asking for nothing: the
    // pollset hears the live session, unsaid.
    let quiet = said(|w| w.waiting = vec!["connect", "connect"]);
    assert!(quiet.contains("connect -> EAGAIN"), "{quiet}");
    assert!(!quiet.contains("[SSH] pollset"), "{quiet}");
    // What the multi waits on is what was said: both ways, then a read,
    // then the live session's input, though it asked for nothing.
    let polled = |said: &str| -> Vec<String> {
        said.lines()
            .filter(|l| l.contains("[PROTOCONNECTING] pollset[fd="))
            .map(str::to_owned)
            .collect()
    };
    assert!(
        polled(&waiting)
            .iter()
            .any(|l| l.contains(" IN") && l.contains("OUT")),
        "{waiting}"
    );
    assert!(
        polled(&quiet)
            .iter()
            .any(|l| l.contains("pollset[fd=1000 IN]")),
        "{quiet}"
    );
}

/// An SCP channel's close that waits is waited on as the upload ends.
#[test]
fn an_scp_close_that_waits_is_waited_on() {
    let w = world_with(&[], |w| w.waiting = vec!["scp_close"]);
    let mut m = chatty();
    let (result, _, said) = run_on(&mut m, &w, "scp://u@127.0.0.1:PORT/tmp/f", |o| {
        uploads(o, b"over scp");
    });
    assert_eq!(result, Ok(()), "{said}");
    drop(m);
    let w = w.lock().unwrap();
    assert!(w.waiting.is_empty());
    assert!(w.calls.contains(&"scp_close".to_owned()), "{:?}", w.calls);
    assert_eq!(w.files, [(b"/tmp/f".to_vec(), b"over scp".to_vec())]);
}

/// A known-hosts key of a type the library has no name for is refused.
#[test]
fn a_known_key_of_no_known_type_is_refused() {
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.known = Some(KnownHosts::Ok);
        w.known_other = true;
    });
    let (result, _, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        o.ssh.make_mut().unwrap().known_hosts = Some(b"/k".to_vec());
    });
    assert_eq!(result, Err(ErrorKind::PeerFailedVerification), "{said}");
}

/// A download reads what the file says its size is, and to its end when
/// it says none.
#[test]
fn a_download_reads_the_size_the_file_says() {
    let read = |set: fn(&mut World)| {
        let w = world_with(&[("/home/u/f", "0123456789")], set);
        let (result, body, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |_| {});
        assert_eq!(result, Ok(()), "{said}");
        body
    };
    assert_eq!(read(|w| w.stated_size = Some(4)), b"0123");
    assert_eq!(read(|w| w.no_size_flag = true), b"0123456789");
    assert_eq!(
        read(|w| {
            w.stated_size = Some(4);
            w.no_size_flag = true;
        }),
        b"0123456789"
    );
}

/// An SCP write that fails fails the upload as an SSH error.
#[test]
fn a_failing_scp_write_is_an_ssh_error() {
    let w = world_with(&[], |w| w.writes_fail = true);
    let (result, _, said, _) = run_in(&w, "scp://u@127.0.0.1:PORT/tmp/f", |o| {
        uploads(o, b"over scp");
    });
    assert_eq!(result, Err(ErrorKind::Ssh), "{said}");
}

/// A key login that fails is said with libssh's number for its answer.
#[test]
fn a_failed_key_login_says_libssh_s_number() {
    for (answer, n) in [(Auth::Partial, "2"), (Auth::Error, "-1")] {
        let w = world_with(&[("/home/u/f", "x")], |w| w.key_answer = Some(answer));
        let (result, _, said, _) = run_in(&w, "sftp://u:secret@127.0.0.1:PORT/~/f", |_| {});
        assert_eq!(result, Ok(()), "{said}");
        let line = format!("Failed public key authentication (rc: {n})\n");
        assert!(said.contains(&line), "{line:?} in {said}");
    }
}

/// The public key is offered first only without a passphrase.
#[test]
fn the_public_key_is_offered_without_a_passphrase() {
    let w = world(&[("/home/u/f", "x")]);
    let (result, _, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    assert!(calls.contains(&"try_publickey".to_owned()), "{calls:?}");
    let w = world(&[("/home/u/f", "x")]);
    let (result, _, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        o.tls.options.make_mut().unwrap().key_password = Some(b"pass".to_vec());
    });
    assert_eq!(result, Ok(()), "{said}");
    assert!(!calls.contains(&"try_publickey".to_owned()), "{calls:?}");
}

/// An empty private key is none: without the agent allowed, the public
/// key login is not tried.
#[test]
fn an_empty_private_key_is_none() {
    let w = world(&[("/home/u/f", "x")]);
    let (result, _, said, calls) = run_in(&w, "sftp://u:secret@127.0.0.1:PORT/~/f", |o| {
        let ssh = o.ssh.make_mut().unwrap();
        ssh.private_key = Some(Vec::new());
        ssh.auth_types = crate::options::SshAuthTypes(
            crate::options::SshAuthTypes::PUBLICKEY | crate::options::SshAuthTypes::PASSWORD,
        );
    });
    assert_eq!(result, Ok(()), "{said}");
    assert!(
        said.contains("Completed password authentication\n"),
        "{said}"
    );
    assert!(
        !calls.iter().any(|c| c.starts_with("auth_publickey")),
        "{calls:?}"
    );
}

/// The keyboard-interactive login waits in any of its rounds and goes
/// on where it was.
#[test]
fn the_interactive_login_waits_in_its_rounds() {
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.key_refused = true;
        w.methods = Methods::PUBLICKEY | Methods::INTERACTIVE;
        w.asks = true;
        w.kbd_extra = true;
        w.kbd_waits_at = vec![2, 3];
    });
    let mut m = chatty();
    let (result, _, said) = run_on(&mut m, &w, "sftp://u:secret@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    assert!(
        said.contains("completed keyboard interactive authentication\n"),
        "{said}"
    );
    drop(m);
    let w = w.lock().unwrap();
    assert!(w.kbd_waits_at.is_empty());
    assert_eq!(w.calls.iter().filter(|c| *c == "auth_kbdint").count(), 3);
    assert!(!w.calls.iter().any(|c| c.starts_with("auth_password")));
}

/// A directory there already, or refused, is passed as the upload's are
/// made; one failing otherwise fails the upload with its code.
#[test]
fn a_directory_failing_to_be_made_is_passed_or_fails() {
    let upload = |code: u32| {
        let w = world_with(&[], |w| {
            w.refused_opens = 1;
            w.mkdir_code = Some(code);
        });
        let (result, _, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/a/f", |o| {
            uploads(o, b"up");
            o.line.make_mut().unwrap().ftp.create_dirs = CreateDirs::Create;
        });
        (result, said, w)
    };
    for code in [11, 4, 3] {
        let (result, said, w) = upload(code);
        assert_eq!(result, Ok(()), "{code}: {said}");
        assert_eq!(w.lock().unwrap().files[0].1, b"up");
    }
    let (result, said, _) = upload(2);
    assert_eq!(result, Err(ErrorKind::RemoteFileNotFound), "{said}");
}

/// A listed entry is a link only if it says its permissions.
#[test]
fn a_link_is_one_by_its_permissions() {
    let w = world_with(&[("/d/file", "abc")], |w| {
        w.links.push((b"/d/link".to_vec(), b"file".to_vec()));
        w.link_without_flag = true;
    });
    let (result, body, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/d/", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    let listed = String::from_utf8(body).unwrap();
    assert!(listed.ends_with(" link\n"), "{listed}");
}
