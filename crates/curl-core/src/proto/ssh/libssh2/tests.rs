//! Transfers over a fake libssh2, whose server is a list of files: the
//! calls made of it in C's order, the known-hosts entry that picks the
//! host key type, a login that waits, an upload's directories, and the
//! quote commands.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use super::*;
use crate::conn::io::{Conversation, FakeNet, Peer as Net};
use crate::easy::Easy;
use crate::handler::{DebugHandler, Handler, SshHostKeyHandler, Write as Wrote, WriteHandler};
use crate::id::ArenaPolicy;
use crate::libraries::{Libraries, SharedLibraries};
use crate::multi::{Env, Multi, NoEvents, TransferCx, drive_to_completion};
use crate::options::Options;
use crate::ssh::SshLibrary;
use crate::ssh2::{DirEntry, Failed, Gave, KnownEntry, Pipes, Ssh2, Statvfs, Took};
use crate::time::ManualClock;
use curl_alloc::OutOfMemory;
use curl_os::socket::BorrowedSocket;
use std::time::Duration;

const PORT: u16 = 8022;
const HOME: &[u8] = b"/home/u";
const HOST_KEY: &[u8] = b"the server's key";
const PROXY_PORT: u16 = 8080;
/// What the session says first, and what the server does, over pipes.
const HELLO: &[u8] = b"SSH-2.0-libssh2_fake\r\n";
const BANNER: &[u8] = b"SSH-2.0-OpenSSH_9.9\r\n";

/// What the fake server holds, and what it was asked.
#[derive(Debug)]
struct World {
    files: Vec<(Vec<u8>, Vec<u8>)>,
    /// Each call the state machine made, in order.
    calls: Vec<String>,
    /// The known-hosts collection's entries, and the type of the key the
    /// collection holds for the server.
    known: Vec<KnownEntry>,
    known_kind: Option<KnownKeyType>,
    /// The key types the collection has no entry of for the server.
    absent: Vec<KnownKeyType>,
    /// The calls, by name, whose first answer is to wait.
    waiting: Vec<&'static str>,
    /// Every call answers that it waits the first time it is made.
    wait_all: bool,
    waited: Vec<&'static str>,
    /// The calls, by name, that fail with the code the next time; and the
    /// SFTP status some of them leave.
    fails: Vec<(&'static str, Code)>,
    leaves: Vec<(&'static str, Fx)>,
    /// The calls, by name, that wait each time, the clock moved on a
    /// quarter of a second by each.
    stuck: Vec<&'static str>,
    clock: Option<ManualClock>,
    /// What the session waits for when a call would wait.
    dirs: PollFlags,
    /// The multi's own trace on too, with the SSH component's.
    trace_multi: bool,
    /// The sizes the transfer announced: the download's and the upload's.
    sizes: (Option<u64>, Option<u64>),
    /// The multi's internal trace, as C's debug build writes it under
    /// `CURL_DEBUG`: what is done for no transfer, a goodbye among it.
    internal: Internal,
    /// The library's last failure, as its error and its words say it.
    last: Code,
    error: Vec<u8>,
    /// What the SFTP server said last (`libssh2_sftp_last_error`).
    fx: Fx,
    /// Every file opened to write is refused as missing.
    refuses_writes: bool,
    /// Each attribute set, by path.
    set: Vec<(Vec<u8>, Attrs)>,
    /// What a session over pipes read of the server's banner.
    heard: Vec<u8>,
    /// The ways the server lets the user log in; none if it let the user
    /// in already (`authenticated`) or the call failed.
    authlist: Option<Vec<u8>>,
    authenticated: bool,
    /// The agent's identities, by comment, and whether each logs in; none
    /// for an agent that cannot be made.
    agent: Option<Vec<(Vec<u8>, bool)>>,
    /// The keyboard-interactive login works.
    keyboard: bool,
    /// The server's key and its type, and its fingerprints.
    host: Option<(Vec<u8>, HostKeyType)>,
    sha256: Option<[u8; 32]>,
    md5: Option<[u8; 16]>,
    /// A directory's entries: name, `ls -l` line and attributes; and each
    /// link's target, by path.
    dir: Vec<(Vec<u8>, Vec<u8>, Attrs)>,
    links: Vec<(Vec<u8>, Vec<u8>)>,
    /// Attributes a stat answers with in place of the file's.
    attrs: Vec<(Vec<u8>, Attrs)>,
    statvfs: Statvfs,
    /// The SFTP session's home directory.
    home: Vec<u8>,
    /// Each file opened, how and with what permissions; each directory
    /// made's permissions; the read timeout set.
    opened: Vec<(Vec<u8>, OpenMode, u32)>,
    dir_modes: Vec<u32>,
    read_timeout: Option<i64>,
    /// The transfer traces SSH's states; and the file time it reported.
    trace_ssh: bool,
    filetime: Option<i64>,
}

impl Default for World {
    fn default() -> World {
        World {
            files: Vec::new(),
            calls: Vec::new(),
            known: Vec::new(),
            known_kind: None,
            absent: Vec::new(),
            waiting: Vec::new(),
            wait_all: false,
            waited: Vec::new(),
            fails: Vec::new(),
            leaves: Vec::new(),
            stuck: Vec::new(),
            clock: None,
            dirs: PollFlags {
                read: true,
                write: false,
            },
            trace_multi: false,
            sizes: (None, None),
            internal: Internal::default(),
            last: Code(-31),
            error: b"fake failure".to_vec(),
            fx: Fx::NO_SUCH_FILE,
            refuses_writes: false,
            set: Vec::new(),
            heard: Vec::new(),
            authlist: Some(b"publickey,password".to_vec()),
            authenticated: false,
            agent: None,
            keyboard: false,
            host: Some((HOST_KEY.to_vec(), HostKeyType::Ed25519)),
            sha256: Some([7; 32]),
            md5: Some([7; 16]),
            dir: Vec::new(),
            links: Vec::new(),
            attrs: Vec::new(),
            statvfs: Statvfs::default(),
            home: HOME.to_vec(),
            opened: Vec::new(),
            dir_modes: Vec::new(),
            read_timeout: None,
            trace_ssh: false,
            filetime: None,
        }
    }
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

    /// Whether `name`'s call answers that it waits, this time.
    fn waits(&mut self, name: &'static str) -> bool {
        if self.stuck.contains(&name) {
            self.call("waits", &[name.as_bytes()]);
            let waited = self
                .calls
                .iter()
                .filter(|c| c.starts_with("waits "))
                .count();
            assert!(waited < 50, "the goodbye never gave up on {name}");
            if let Some(clock) = &self.clock {
                clock.advance(Duration::from_millis(250));
            }
            return true;
        }
        let at = self.waiting.iter().position(|&n| n == name);
        if let Some(at) = at {
            self.waiting.remove(at);
            self.call("waits", &[name.as_bytes()]);
            return true;
        }
        if self.wait_all && !self.waited.contains(&name) {
            self.waited.push(name);
            self.call("waits", &[name.as_bytes()]);
            return true;
        }
        false
    }

    /// `name`'s call, made, but not written down: a wait, or a failure,
    /// as the world says.
    fn quietly(&mut self, name: &'static str) -> Result<(), Code> {
        if self.waits(name) {
            return Err(Code::EAGAIN);
        }
        if let Some(at) = self.fails.iter().position(|(n, _)| *n == name) {
            let (_, code) = self.fails.remove(at);
            self.call("fails", &[name.as_bytes()]);
            self.last = code;
            if let Some(&(_, fx)) = self.leaves.iter().find(|(n, _)| *n == name) {
                self.fx = fx;
            }
            return Err(code);
        }
        Ok(())
    }

    /// `name`'s call, made: a wait, or a failure, as the world says.
    fn answer(&mut self, name: &'static str, args: &[&[u8]]) -> Result<(), Code> {
        if self.waits(name) {
            self.last = Code::EAGAIN;
            return Err(Code::EAGAIN);
        }
        if let Some(at) = self.fails.iter().position(|(n, _)| *n == name) {
            let (_, code) = self.fails.remove(at);
            self.call("fails", &[name.as_bytes()]);
            self.last = code;
            if let Some(&(_, fx)) = self.leaves.iter().find(|(n, _)| *n == name) {
                self.fx = fx;
            }
            return Err(code);
        }
        self.call(name, args);
        Ok(())
    }
}

#[derive(Debug)]
struct FakeSsh2(Arc<Mutex<World>>);

impl Ssh2 for FakeSsh2 {
    fn session(&self) -> Option<Box<dyn Session2>> {
        Some(Box::new(FakeSession {
            world: self.0.clone(),
            kh: false,
            sftp: false,
            file: None,
            writing: None,
            dir: None,
            channel: false,
            session: true,
            agent: None,
            comment: Vec::new(),
            home: Vec::new(),
            target: Vec::new(),
            entry: (Vec::new(), Vec::new()),
            pipes: None,
            said_hello: false,
        }))
    }

    fn crypto(&self) -> Crypto {
        Crypto::OpenSsl
    }
}

#[derive(Debug)]
struct FakeSession {
    world: Arc<Mutex<World>>,
    kh: bool,
    sftp: bool,
    /// The file open to read: its index, and where reads are.
    file: Option<(usize, usize)>,
    /// The file open to write, by path.
    writing: Option<Vec<u8>>,
    /// The directory open to list: the next entry's index.
    dir: Option<usize>,
    channel: bool,
    session: bool,
    /// The agent made: the next identity's index.
    agent: Option<usize>,
    comment: Vec<u8>,
    home: Vec<u8>,
    target: Vec<u8>,
    entry: (Vec<u8>, Vec<u8>),
    /// Once set, the handshake says hello and reads the banner through
    /// them.
    pipes: Option<Pipes>,
    said_hello: bool,
}

impl FakeSession {
    /// A call that frees what it closes (`freed`): let go of unless it
    /// would wait and `let_go` says to wait.
    fn freeing(&self, name: &'static str, let_go: Let) -> (Result<(), Code>, bool) {
        let rc = self.called(name, &[]);
        let kept = rc == Err(Code::EAGAIN) && let_go == Let::Wait;
        (rc, !kept)
    }

    /// A call that never waits in libssh2 (a file's, or a setting's):
    /// failing as the world says, else written down.
    fn settled(&self, name: &'static str, args: &[&[u8]]) -> Result<(), Code> {
        let mut w = self.w();
        if let Some(at) = w.fails.iter().position(|(n, _)| *n == name) {
            let (_, code) = w.fails.remove(at);
            w.call("fails", &[name.as_bytes()]);
            w.last = code;
            return Err(code);
        }
        w.call(name, args);
        Ok(())
    }

    fn w(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    /// `name`'s call: a wait or a failure where the world says so.
    fn called(&self, name: &'static str, args: &[&[u8]]) -> Result<(), Code> {
        self.w().answer(name, args)
    }
}

impl Session2 for FakeSession {
    fn set_read_timeout(&mut self, secs: i64) {
        self.w().read_timeout = Some(secs);
    }
    fn enable_compression(&mut self) -> Result<(), Code> {
        self.settled("enable_compression", &[])
    }
    fn set_blocking(&mut self, _: Blocking) {}
    fn set_hostkey_methods(&mut self, prefs: &[u8]) -> Result<(), Code> {
        self.settled("set_hostkey_methods", &[prefs])
    }
    fn last_error(&self) -> (Code, Vec<u8>) {
        let w = self.w();
        (w.last, w.error.clone())
    }
    fn last_errno(&self) -> Code {
        self.w().last
    }
    fn block_directions(&self) -> PollFlags {
        self.w().dirs
    }
    fn knownhost_init(&mut self) -> Result<(), Failed> {
        self.kh = true;
        Ok(())
    }
    fn has_knownhosts(&self) -> bool {
        self.kh
    }
    fn knownhost_readfile(&mut self, file: &[u8]) -> Result<(), Code> {
        self.settled("knownhost_readfile", &[file])
    }
    fn knownhost_entries(&self) -> Result<Vec<KnownEntry>, OutOfMemory> {
        Ok(self.w().known.clone())
    }
    fn knownhost_check(
        &mut self,
        host: &[u8],
        port: Option<u16>,
        _: &[u8],
        _: KeyForm,
        kind: KnownKeyType,
    ) -> Result<(Check, Option<Vec<u8>>), OutOfMemory> {
        let port = port.map_or("-1".to_owned(), |p| p.to_string());
        let mut w = self.w();
        w.call("knownhost_check", &[host, port.as_bytes()]);
        if w.absent.contains(&kind) {
            return Ok((Check::NotFound, None));
        }
        Ok(match w.known_kind {
            Some(k) if k == kind => (Check::Match, Some(b"QUFBQQ==".to_vec())),
            Some(KnownKeyType(15)) => (Check::Failure, None),
            Some(_) => (Check::Mismatch, Some(b"QUFBQQ==".to_vec())),
            None => (Check::NotFound, None),
        })
    }
    fn knownhost_del_found(&mut self) {
        self.w().call("knownhost_del_found", &[]);
    }
    fn knownhost_add(&mut self, host: &[u8], _: &[u8], kind: KnownKeyType) -> Result<(), Code> {
        self.settled("knownhost_add", &[host, kind.0.to_string().as_bytes()])
    }
    fn knownhost_writefile(&mut self, file: &[u8]) -> Result<(), Code> {
        self.settled("knownhost_writefile", &[file])
    }
    fn knownhost_free(&mut self) {
        self.kh = false;
    }
    fn handshake(&mut self, _: Option<BorrowedSocket<'_>>) -> Result<(), Code> {
        if let Some(pipes) = self.pipes.as_mut() {
            if !self.said_hello {
                match pipes.give(HELLO) {
                    Gave::All => self.said_hello = true,
                    Gave::Wait => return Err(Code::EAGAIN),
                    Gave::Broken => return Err(Code::SOCKET_SEND),
                }
            }
            let mut w = self.world.lock().unwrap();
            while !w.heard.ends_with(b"\r\n") {
                let mut buf = [0; 8];
                match pipes.take(&mut buf) {
                    Took::Bytes(n) => w.heard.extend_from_slice(&buf[..n]),
                    Took::Wait => return Err(Code::EAGAIN),
                    Took::End | Took::Broken => return Err(Code(-43)),
                }
            }
            drop(w);
        }
        self.called("handshake", &[])
    }
    fn use_pipes(&mut self) {
        self.pipes = Some(Pipes::default());
    }
    fn pipes(&mut self) -> Option<&mut Pipes> {
        self.pipes.as_mut()
    }
    fn host_key(&self) -> Option<(&[u8], HostKeyType)> {
        // The key is the world's; it lives as long as the test does.
        let host = self.w().host.clone()?;
        let (key, kind) = Box::leak(Box::new(host));
        Some((&key[..], *kind))
    }
    fn host_key_sha256(&self) -> Option<[u8; 32]> {
        self.w().sha256
    }
    fn host_key_md5(&self) -> Option<[u8; 16]> {
        self.w().md5
    }
    fn userauth_list(&mut self, user: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
        if self.called("userauth_list", &[user]).is_err() {
            return Ok(None);
        }
        Ok(self.w().authlist.clone())
    }
    fn authenticated(&self) -> bool {
        self.w().authenticated
    }
    fn auth_publickey_fromfile(
        &mut self,
        user: &[u8],
        public: Option<&[u8]>,
        private: &[u8],
        passphrase: &[u8],
    ) -> Result<(), Code> {
        self.called(
            "auth_publickey_fromfile",
            &[user, public.unwrap_or(b"(none)"), private, passphrase],
        )
    }
    fn auth_password(&mut self, user: &[u8], password: &[u8]) -> Result<(), Code> {
        self.called("auth_password", &[user, password])
    }
    fn auth_keyboard_interactive(&mut self, user: &[u8], password: &[u8]) -> Result<(), Code> {
        self.called("auth_keyboard_interactive", &[user, password])?;
        if self.w().keyboard {
            Ok(())
        } else {
            Err(Code(-18))
        }
    }
    fn agent_init(&mut self) -> Result<(), Failed> {
        if self.settled("agent_init", &[]).is_err() || self.w().agent.is_none() {
            return Err(Failed);
        }
        self.agent = Some(0);
        Ok(())
    }
    fn has_agent(&self) -> bool {
        self.agent.is_some()
    }
    fn agent_connect(&mut self) -> Result<(), Code> {
        self.called("agent_connect", &[])
    }
    fn agent_list_identities(&mut self) -> Result<(), Code> {
        self.called("agent_list_identities", &[])
    }
    fn agent_rewind(&mut self) {
        self.agent = Some(0);
    }
    fn agent_get_identity(&mut self) -> Result<Identity, Code> {
        self.called("agent_get_identity", &[])?;
        let at = self.agent.expect("an agent");
        let ids = self.w().agent.clone().unwrap_or_default();
        match ids.get(at) {
            Some((comment, _)) => {
                self.comment = comment.clone();
                Ok(Identity::Got)
            }
            None => Ok(Identity::End),
        }
    }
    fn agent_comment(&self) -> &[u8] {
        &self.comment
    }
    fn agent_userauth(&mut self, user: &[u8]) -> Result<(), Code> {
        let comment = self.comment.clone();
        self.called("agent_userauth", &[user, &comment])?;
        let at = self.agent.expect("an agent");
        let ids = self.w().agent.clone().unwrap_or_default();
        if ids[at].1 { Ok(()) } else { Err(Code(-18)) }
    }
    fn agent_skip(&mut self) {
        self.agent = self.agent.map(|a| a + 1);
    }
    fn agent_disconnect(&mut self) -> Result<(), Code> {
        self.called("agent_disconnect", &[])
    }
    fn agent_free(&mut self) {
        self.agent = None;
    }
    fn sftp_init(&mut self) -> Result<(), Code> {
        self.called("sftp_init", &[])?;
        self.sftp = true;
        Ok(())
    }
    fn has_sftp(&self) -> bool {
        self.sftp
    }
    fn sftp_last_error(&self) -> Fx {
        self.w().fx
    }
    fn sftp_realpath(&mut self, path: &[u8]) -> Result<&[u8], Code> {
        self.called("sftp_realpath", &[path])?;
        let home = self.w().home.clone();
        self.home = home;
        Ok(&self.home)
    }
    fn sftp_open(&mut self, path: &[u8], mode: OpenMode, perms: u32) -> Result<(), Code> {
        self.called("sftp_open", &[path])?;
        let mut w = self.w();
        w.opened.push((path.to_vec(), mode, perms));
        if mode == OpenMode::Read {
            let at = w.files.iter().position(|(p, _)| p == path);
            drop(w);
            let at = at.ok_or(Code::SFTP_PROTOCOL)?;
            self.file = Some((at, 0));
        } else if w.refuses_writes {
            return Err(Code::SFTP_PROTOCOL);
        } else {
            if mode == OpenMode::Truncate || !w.files.iter().any(|(p, _)| p == path) {
                w.files.retain(|(p, _)| p != path);
                w.files.push((path.to_vec(), Vec::new()));
            }
            drop(w);
            self.writing = Some(path.to_vec());
        }
        Ok(())
    }
    fn sftp_opendir(&mut self, path: &[u8]) -> Result<(), Code> {
        self.called("sftp_opendir", &[path])?;
        self.dir = Some(0);
        Ok(())
    }
    fn has_handle(&self) -> bool {
        self.file.is_some() || self.writing.is_some() || self.dir.is_some()
    }
    fn sftp_stat(&mut self, path: &[u8]) -> Result<Attrs, Code> {
        self.called("sftp_stat", &[path])?;
        let w = self.w();
        if let Some((_, a)) = w.attrs.iter().find(|(p, _)| p == path) {
            return Ok(*a);
        }
        let (_, bytes) = w
            .files
            .iter()
            .find(|(p, _)| p == path)
            .ok_or(Code::SFTP_PROTOCOL)?;
        Ok(Attrs {
            flags: AttrFlags(AttrFlags::SIZE.0 | AttrFlags::UIDGID.0),
            filesize: bytes.len() as u64,
            uid: 1,
            gid: 2,
            ..Attrs::default()
        })
    }
    fn sftp_setstat(&mut self, path: &[u8], attrs: &Attrs) -> Result<(), Code> {
        self.called("sftp_setstat", &[path])?;
        self.w().set.push((path.to_vec(), *attrs));
        Ok(())
    }
    fn sftp_seek(&mut self, to: u64) {
        self.w().call("sftp_seek", &[to.to_string().as_bytes()]);
        if let Some((at, _)) = self.file {
            self.file = Some((at, usize::try_from(to).unwrap()));
        }
    }
    fn sftp_readdir(&mut self) -> Result<Option<DirEntry<'_>>, Code> {
        self.called("sftp_readdir", &[])?;
        let at = self.dir.expect("a directory open");
        let w = self.w();
        let Some((name, long, attrs)) = w.dir.get(at).cloned() else {
            return Ok(None);
        };
        drop(w);
        self.dir = Some(at + 1);
        self.entry = (name, long);
        Ok(Some(DirEntry {
            name: &self.entry.0,
            longentry: &self.entry.1,
            attrs,
        }))
    }
    fn sftp_readlink(&mut self, path: &[u8]) -> Result<&[u8], Code> {
        self.called("sftp_readlink", &[path])?;
        let w = self.w();
        let target = w
            .links
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, t)| t.clone());
        drop(w);
        self.target = target.ok_or(Code::SFTP_PROTOCOL)?;
        Ok(&self.target)
    }
    fn sftp_symlink(&mut self, path: &[u8], target: &[u8]) -> Result<(), Code> {
        self.called("sftp_symlink", &[path, target])
    }
    fn sftp_mkdir(&mut self, path: &[u8], mode: u32) -> Result<(), Code> {
        self.called("sftp_mkdir", &[path])?;
        self.w().dir_modes.push(mode);
        Ok(())
    }
    fn sftp_rename(&mut self, from: &[u8], to: &[u8]) -> Result<(), Code> {
        self.called("sftp_rename", &[from, to])
    }
    fn sftp_rmdir(&mut self, path: &[u8]) -> Result<(), Code> {
        self.called("sftp_rmdir", &[path])
    }
    fn sftp_unlink(&mut self, path: &[u8]) -> Result<(), Code> {
        self.called("sftp_unlink", &[path])
    }
    fn sftp_statvfs(&mut self, path: &[u8]) -> Result<Statvfs, Code> {
        self.called("sftp_statvfs", &[path])?;
        Ok(self.w().statvfs)
    }
    fn sftp_read(&mut self, buf: &mut [u8]) -> Result<usize, Code> {
        self.w().quietly("read")?;
        let (at, pos) = self.file.expect("a file open to read");
        let w = self.w();
        let bytes = &w.files[at].1[pos.min(w.files[at].1.len())..];
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        drop(w);
        self.file = Some((at, pos + n));
        Ok(n)
    }
    fn sftp_write(&mut self, bytes: &[u8]) -> Result<usize, Code> {
        self.w().quietly("write")?;
        let path = self.writing.clone().expect("a file open to write");
        let mut w = self.w();
        let file = w.files.iter_mut().find(|(p, _)| *p == path).unwrap();
        file.1.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn sftp_close(&mut self, let_go: Let) -> Result<(), Code> {
        let (rc, freed) = self.freeing("sftp_close", let_go);
        if freed {
            self.file = None;
            self.writing = None;
            self.dir = None;
        }
        rc
    }
    fn sftp_shutdown(&mut self, let_go: Let) -> Result<(), Code> {
        let (rc, freed) = self.freeing("sftp_shutdown", let_go);
        if freed {
            self.sftp = false;
        }
        rc
    }
    fn scp_recv(&mut self, path: &[u8]) -> Result<i64, Code> {
        self.called("scp_recv", &[path])?;
        let w = self.w();
        let at = w.files.iter().position(|(p, _)| p == path);
        let at = at.ok_or(Code::SCP_PROTOCOL)?;
        let size = w.files[at].1.len() as i64;
        drop(w);
        self.file = Some((at, 0));
        self.channel = true;
        Ok(size)
    }
    fn scp_send(&mut self, path: &[u8], mode: u32, size: i64) -> Result<(), Code> {
        let said = format!("{mode:o} {size}");
        self.called("scp_send", &[path, said.as_bytes()])?;
        let mut w = self.w();
        w.files.retain(|(p, _)| p != path);
        w.files.push((path.to_vec(), Vec::new()));
        drop(w);
        self.writing = Some(path.to_vec());
        self.channel = true;
        Ok(())
    }
    fn has_channel(&self) -> bool {
        self.channel
    }
    fn channel_read(&mut self, buf: &mut [u8]) -> Result<usize, Code> {
        self.sftp_read(buf)
    }
    fn channel_write(&mut self, bytes: &[u8]) -> Result<usize, Code> {
        self.sftp_write(bytes)
    }
    fn channel_send_eof(&mut self) -> Result<(), Code> {
        self.called("channel_send_eof", &[])
    }
    fn channel_wait_eof(&mut self) -> Result<(), Code> {
        self.called("channel_wait_eof", &[])
    }
    fn channel_wait_closed(&mut self) -> Result<(), Code> {
        self.called("channel_wait_closed", &[])
    }
    fn channel_free(&mut self, let_go: Let) -> Result<(), Code> {
        let (rc, freed) = self.freeing("channel_free", let_go);
        if freed {
            self.channel = false;
            self.file = None;
            self.writing = None;
        }
        rc
    }
    fn disconnect(&mut self) -> Result<(), Code> {
        self.called("disconnect", &[])
    }
    fn has_session(&self) -> bool {
        self.session
    }
    fn session_free(&mut self, let_go: Let) -> Result<(), Code> {
        let (rc, freed) = self.freeing("session_free", let_go);
        if freed {
            self.session = false;
        }
        rc
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

/// Collects the trace's text, and the data it traces.
#[derive(Clone, Default)]
struct Text(Arc<Mutex<Vec<u8>>>, Arc<Mutex<Traced>>);

/// The data a trace says, piece by piece.
type Traced = Vec<(DebugKind, Vec<u8>)>;

impl DebugHandler for Text {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        match kind {
            DebugKind::Text => self.0.lock().unwrap().extend_from_slice(data),
            DebugKind::DataIn | DebugKind::DataOut | DebugKind::HeaderIn | DebugKind::HeaderOut => {
                self.1.lock().unwrap().push((kind, data.to_vec()));
            }
            _ => {}
        }
    }
}

fn world_with(files: &[(&str, &str)], set: impl FnOnce(&mut World)) -> Arc<Mutex<World>> {
    let mut w = World {
        files: files
            .iter()
            .map(|(p, b)| (p.as_bytes().to_vec(), b.as_bytes().to_vec()))
            .collect(),
        ..World::default()
    };
    set(&mut w);
    Arc::new(Mutex::new(w))
}

/// Run `url` to its end over `w`'s library: its result, body, trace and
/// the calls the library was made.
fn run_in(
    w: &Arc<Mutex<World>>,
    url: &str,
    set: impl FnOnce(&mut Options),
) -> (Result<(), ErrorKind>, Vec<u8>, String, Vec<String>) {
    let silent = Conversation::replies(&[], false);
    let (result, body, text) = run_over(w, url, PORT, &silent, None, set);
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    let calls = w.lock().unwrap().calls.clone();
    (result, body, said, calls)
}

/// The same, the peer at `port` saying `talk`, with `tls` as the TLS
/// library if any: the trace whole.
fn run_over(
    w: &Arc<Mutex<World>>,
    url: &str,
    port: u16,
    talk: &Conversation,
    tls: Option<crate::libraries::Library<dyn crate::tls::TlsBackend>>,
    set: impl FnOnce(&mut Options),
) -> (Result<(), ErrorKind>, Vec<u8>, Text) {
    let clock = ManualClock::new().unwrap();
    w.lock().unwrap().clock = Some(clock.clone());
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
    let mut m: Multi = Multi::new(env).unwrap();
    let ssh: &'static FakeSsh2 = Box::leak(Box::new(FakeSsh2(w.clone())));
    let mut e = Easy::new();
    let components = crate::components::Components::new().unwrap();
    let (trace_ssh, trace_multi) = {
        let w = w.lock().unwrap();
        (w.trace_ssh, w.trace_multi)
    };
    if trace_ssh || trace_multi {
        components.configure(if trace_multi {
            &b"ssh,multi"[..]
        } else {
            b"ssh"
        });
        e.set_components(Some(components.clone()));
    }
    let internal = w.lock().unwrap().internal.clone();
    m.trace_internally_to(components, Handler::text(internal).unwrap());
    e.set_libraries(
        SharedLibraries::new(Libraries {
            ssh: Some(SshLibrary::Libssh2(ssh)),
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
    // Each wait waits on the fake clock: a run of many has longer.
    let waits = w.lock().unwrap().wait_all;
    o.limits.total = crate::time::TimeLimit::from_millis(if waits { 1_000_000 } else { 10_000 });
    o.output.verbose = true;
    o.callbacks.write = Some(Handler::write(body.clone()).unwrap());
    o.callbacks.debug = Some(Handler::debug(text.clone()).unwrap());
    let ssh = o.ssh.make_mut().unwrap();
    ssh.private_key = Some(b"/keys/id".to_vec());
    ssh.public_key = Some(b"/keys/id.pub".to_vec());
    set(o);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    let removed = m.remove(id, &mut NoEvents).unwrap();
    let report = removed.easy.report();
    w.lock().unwrap().filetime = report.filetime();
    w.lock().unwrap().sizes = (
        report.sizes().download_expected(),
        report.sizes().upload_expected(),
    );
    drop(m);
    let body = body.0.lock().unwrap().clone();
    (result, body, text)
}

/// Collects the multi's internal trace.
#[derive(Clone, Debug, Default)]
struct Internal(Arc<Mutex<Vec<u8>>>);

/// What the internal trace says as connection #0's protocol is told to
/// shut down: a line of C's debug build alone.
fn shutdown_said() -> &'static str {
    if cfg!(feature = "debug-hooks") {
        "* connection #0, shutdown protocol handler (aborted=0)\n"
    } else {
        ""
    }
}

impl Internal {
    fn said(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl crate::handler::TextSink for Internal {
    fn write(&self, text: &[u8]) {
        self.0.lock().unwrap().extend_from_slice(text);
    }
}

/// An SFTP download makes libssh2's calls in C's order: the handshake,
/// the login with the key files, the SFTP session and its home, the file
/// opened, stated by path and read, then closed, the SFTP session shut
/// down and the session said goodbye to and freed as the connection
/// closes.
#[test]
fn an_sftp_file_is_downloaded_in_c_s_order() {
    let w = world_with(&[("/home/u/f", "hello\n")], |_| {});
    let (result, body, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"hello\n");
    for line in [
        "SSH: libssh2 cryptography backend: openssl compatible\n",
        "SSH: user 'u'\n",
        "SSH: no knownhosts file configured\n",
        "SSH: host offers authentication via: publickey,password\n",
        "SSH: trying public key file '/keys/id.pub'\n",
        "SSH: authenticated via publickey\n",
        "SSH: authentication complete\n",
    ] {
        assert!(said.contains(line), "{line:?} in {said}");
    }
    let want = [
        "handshake",
        "userauth_list u",
        "auth_publickey_fromfile u /keys/id.pub /keys/id ",
        "sftp_init",
        "sftp_realpath .",
        "sftp_open /home/u/f",
        "sftp_stat /home/u/f",
        "sftp_close",
        "sftp_shutdown",
        "disconnect",
        "session_free",
    ];
    assert_eq!(calls, want);
}

/// A login that would wait is made again, the same, once the socket is
/// ready, and the run goes on from it.
#[test]
fn a_login_that_waits_is_made_again() {
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.waiting = vec!["handshake", "auth_publickey_fromfile", "sftp_open"];
    });
    let (result, body, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"x");
    let logins: Vec<_> = calls
        .iter()
        .filter(|c| c.contains("auth_publickey_fromfile"))
        .collect();
    assert_eq!(
        logins,
        [
            "waits auth_publickey_fromfile",
            "auth_publickey_fromfile u /keys/id.pub /keys/id "
        ]
    );
}

/// The known-hosts entry of the host at its port picks the type of key
/// the server is asked for, not one of another host whose name starts the
/// same, before it; then the key found is checked against the file, its
/// entry named by the port.
#[test]
fn the_host_s_known_hosts_entry_picks_its_key_type() {
    let entry = |name: &str, kind| KnownEntry {
        name: Some(name.as_bytes().to_vec()),
        key: Some(b"QUFBQQ==".to_vec()),
        kind,
    };
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.known = vec![
            entry("[127.0.0.10]:8022", KnownKeyType::SSHRSA),
            entry("[127.0.0.1]:8023", KnownKeyType::ECDSA_256),
            entry("[127.0.0.1]:8022", KnownKeyType::ED25519),
        ];
        w.known_kind = Some(KnownKeyType::ED25519);
    });
    let (result, _, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        o.ssh.make_mut().unwrap().known_hosts = Some(b"/known".to_vec());
    });
    assert_eq!(result, Ok(()), "{said}");
    assert!(
        said.contains("SSH: found host '127.0.0.1' in '/known'\n"),
        "{said}"
    );
    assert!(
        said.contains("SSH: set 'ssh-ed25519' as hostkey type\n"),
        "{said}"
    );
    assert!(
        said.contains("SSH: knownhost entry matches host key\n"),
        "{said}"
    );
    assert_eq!(
        calls[..4],
        [
            "knownhost_readfile /known",
            "set_hostkey_methods ssh-ed25519",
            "handshake",
            "knownhost_check 127.0.0.1 8022",
        ]
    );
}

/// Without an entry for the host, the server picks the key type, and a
/// key the file does not have is refused by C's own key check.
#[test]
fn a_host_the_known_hosts_file_lacks_is_refused() {
    let w = world_with(&[("/home/u/f", "x")], |_| {});
    let (result, _, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        o.ssh.make_mut().unwrap().known_hosts = Some(b"/known".to_vec());
    });
    assert_eq!(result, Err(ErrorKind::PeerFailedVerification), "{said}");
    assert!(
        said.contains("SSH: did not find host '127.0.0.1' in '/known'\n"),
        "{said}"
    );
    assert!(said.contains("SSH: host check 2, key: <none>\n"), "{said}");
    assert!(said.contains("SSH: knownhost check failed\n"), "{said}");
    assert!(
        !calls.iter().any(|c| c.starts_with("set_hostkey")),
        "{calls:?}"
    );
}

/// The keys a host key handler was asked of, and their types.
type Asked = Arc<Mutex<Vec<(KeyType, Vec<u8>)>>>;

struct Answers(bool, Asked);

impl SshHostKeyHandler for Answers {
    fn check(&self, _: &mut TransferCx<'_>, kind: KeyType, key: &[u8]) -> bool {
        self.1.lock().unwrap().push((kind, key.to_vec()));
        self.0
    }
}

/// The application's host key handler decides on the raw key in place of
/// the known-hosts file.
#[test]
fn the_host_key_handler_decides_on_the_raw_key() {
    for fine in [true, false] {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let w = world_with(&[("/home/u/f", "x")], |_| {});
        let handler = Handler::ssh_host_key(Answers(fine, asked.clone())).unwrap();
        let (result, _, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
            let ssh = o.ssh.make_mut().unwrap();
            ssh.known_hosts = Some(b"/known".to_vec());
            ssh.host_key_handler = Some(handler);
        });
        assert_eq!(
            *asked.lock().unwrap(),
            [(KeyType::Ed25519, HOST_KEY.to_vec())]
        );
        assert!(
            !calls.iter().any(|c| c.starts_with("knownhost_check")),
            "{calls:?}"
        );
        if fine {
            assert_eq!(result, Ok(()), "{said}");
            assert!(
                said.contains("SSH: verified public key via callback\n"),
                "{said}"
            );
        } else {
            assert_eq!(result, Err(ErrorKind::PeerFailedVerification), "{said}");
            assert!(
                said.contains("SSH: callback failed host public key verification\n"),
                "{said}"
            );
        }
    }
}

/// An upload whose file cannot be made makes the directories to it, each
/// once, and tries once more; failing again, it fails.
#[test]
fn an_upload_s_directories_are_made_once() {
    let w = world_with(&[], |w| w.refuses_writes = true);
    let (result, _, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/a/b/f", |o| {
        o.method = crate::options::Method::Upload;
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(b"up".to_vec()).unwrap(),
        );
        o.line.make_mut().unwrap().ftp.create_dirs = CreateDirs::Create;
    });
    assert_eq!(result, Err(ErrorKind::RemoteFileNotFound), "{said}");
    let made: Vec<_> = calls
        .iter()
        .filter(|c| c.starts_with("sftp_mkdir") || c.starts_with("sftp_open"))
        .collect();
    assert_eq!(
        made,
        [
            "sftp_open /home/u/a/b/f",
            "sftp_mkdir /home",
            "sftp_mkdir /home/u",
            "sftp_mkdir /home/u/a",
            "sftp_mkdir /home/u/a/b",
            "sftp_open /home/u/a/b/f",
        ]
    );
    assert!(
        said.contains("Creating the dir/file failed: No such file or directory\n"),
        "{said}"
    );
}

/// An SFTP upload writes the file.
#[test]
fn an_sftp_file_is_uploaded() {
    let w = world_with(&[], |_| {});
    let (result, _, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        o.method = crate::options::Method::Upload;
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(b"over sftp".to_vec()).unwrap(),
        );
    });
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(
        w.lock().unwrap().files,
        [(b"/home/u/f".to_vec(), b"over sftp".to_vec())]
    );
}

/// The quote commands set what they name: a group or owner past what an
/// `unsigned int` holds is taken, where C's libssh2 build, bounding it by
/// an `unsigned long` read as a negative `curl_off_t`, takes none.
#[test]
fn chgrp_and_chown_take_an_id_past_32_bits() {
    let w = world_with(&[("/home/u/f", "x")], |_| {});
    let (result, _, said, _) = run_in(&w, "sftp://u@127.0.0.1:PORT/~/f", |o| {
        let line = o.line.make_mut().unwrap();
        line.quote
            .set([
                &b"chgrp 4294967296 /home/u/f"[..],
                b"chown 12 /home/u/f",
                b"chmod 640 /home/u/f",
            ])
            .unwrap();
    });
    assert_eq!(result, Ok(()), "{said}");
    let set = w.lock().unwrap().set.clone();
    let [(_, chgrp), (_, chown), (_, chmod)] = set[..] else {
        panic!("{set:?}");
    };
    assert_eq!(
        (chgrp.flags, chgrp.uid, chgrp.gid),
        (AttrFlags::UIDGID, 1, 1 << 32)
    );
    assert_eq!(
        (chown.flags, chown.uid, chown.gid),
        (AttrFlags::UIDGID, 12, 2)
    );
    assert_eq!(
        (chmod.flags, chmod.permissions),
        (AttrFlags::PERMISSIONS, 0o640)
    );
}

/// An SCP download reads the channel and frees it, keeping the session
/// for the connection's next transfer.
#[test]
fn an_scp_file_is_downloaded() {
    let w = world_with(&[("/tmp/f", "scp bytes")], |_| {});
    let (result, body, said, calls) = run_in(&w, "scp://u@127.0.0.1:PORT/tmp/f", |_| {});
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"scp bytes");
    assert!(said.contains("SSH: connection established\n"), "{said}");
    let at = calls.iter().position(|c| c == "scp_recv /tmp/f").unwrap();
    assert_eq!(
        calls[at..],
        [
            "scp_recv /tmp/f",
            "channel_free",
            "disconnect",
            "session_free"
        ]
    );
}

/// Through an HTTPS proxy, the session reads and writes the proxy's TLS
/// through its pipes, as C's does through its callbacks: it says so, its
/// hello goes out inside the TLS records after the CONNECT, the server's
/// banner comes back to it out of them, and each piece is traced as data.
#[test]
fn ssh_goes_through_an_https_proxy_s_tls() {
    use crate::tls::fake::{self, FakeTls, WELCOME};
    let tls = |plain: &[u8]| fake::records(plain).unwrap();
    let answer = tls(b"HTTP/1.1 200 Connection established\r\n\r\n");
    let banner = tls(BANNER);
    let talk = Conversation::replies(&[WELCOME, &answer, &banner], false).per_send();
    let w = world_with(&[("/home/u/f", "tunneled")], |_| {});
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::new().unwrap()));
    let library = crate::libraries::Library::Static(backend as &dyn crate::tls::TlsBackend);
    let url = "sftp://u@127.0.0.1:PORT/~/f";
    let (result, body, text) = run_over(&w, url, PROXY_PORT, &talk, Some(library), |o| {
        let proxy = o.proxy.make_mut().unwrap();
        proxy.url = Some(format!("https://127.0.0.1:{PROXY_PORT}").into_bytes());
        proxy.tunnel = true;
    });
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    assert_eq!(result, Ok(()), "{said}");
    assert_eq!(body, b"tunneled");
    assert!(said.contains("SSH: using HTTPS proxy\n"), "{said}");
    assert_eq!(w.lock().unwrap().heard, BANNER);
    let wire = talk.received();
    let sent = fake::read_client(&wire).unwrap();
    let sent = String::from_utf8_lossy(&sent).into_owned();
    let connect = sent
        .find("CONNECT 127.0.0.1:8022 HTTP/1.1\r\n")
        .expect(&sent);
    let hello = std::str::from_utf8(HELLO).unwrap();
    let at = sent.find(hello).expect(&sent);
    assert!(connect < at, "{sent}");
    // Inside the records, never in clear.
    assert!(!wire.windows(HELLO.len()).any(|w| w == HELLO));
    let data = text.1.lock().unwrap().clone();
    assert!(
        data.contains(&(DebugKind::DataOut, HELLO.to_vec())),
        "{data:?}"
    );
    // In as many pieces as the session asked for, then the body.
    let came: Vec<u8> = data
        .iter()
        .filter(|(kind, _)| *kind == DebugKind::DataIn)
        .flat_map(|(_, d)| d.clone())
        .collect();
    assert_eq!(came, [BANNER, b"tunneled"].concat(), "{data:?}");
}

/// The pipes give the session what came, as much as it asks for at a
/// time, and ask for more only once it has all of it; what it sends is
/// taken whole, and more only once that has gone; the connection's end
/// and its failures are what the session is told after what came before
/// them.
#[test]
fn the_pipes_move_what_the_session_asks_for() {
    let mut p = Pipes::default();
    let mut buf = [0; 4];
    assert_eq!(p.wanted(), None);
    assert_eq!(p.take(&mut buf), Took::Wait);
    assert_eq!(p.wanted(), Some(4));
    p.room(4).unwrap()[..3].copy_from_slice(b"abc");
    p.came(3);
    assert_eq!(p.wanted(), None);
    let mut two = [0; 2];
    assert_eq!(p.take(&mut two), Took::Bytes(2));
    assert_eq!(&two, b"ab");
    assert_eq!(p.wanted(), None, "a byte still waits for it");
    assert_eq!(p.take(&mut buf), Took::Bytes(1));
    assert_eq!(buf[0], b'c');
    assert_eq!(p.wanted(), None, "all taken, nothing asked for again yet");
    assert_eq!(p.take(&mut buf), Took::Wait);
    assert_eq!(p.wanted(), Some(4));
    p.room(4).unwrap();
    p.came(0);
    assert_eq!(p.wanted(), Some(4), "nothing came");

    assert_eq!(p.give(b"hi"), Gave::All);
    assert_eq!(p.give(b"more"), Gave::Wait);
    assert_eq!(p.outbound(), b"hi");
    p.sent(1);
    assert_eq!(p.outbound(), b"i");
    p.sent(1);
    assert_eq!(p.give(b"more"), Gave::All);

    p.end();
    assert_eq!(p.take(&mut buf), Took::End);
    assert_eq!(p.wanted(), None);
    p.break_off();
    assert_eq!(p.take(&mut buf), Took::Broken);
    assert_eq!(p.give(b"x"), Gave::Broken);
}

/// The session reads and writes through pipes under an HTTPS proxy alone,
/// as C's does; under a proxy asked to speak HTTP/2, whose TLS it is not
/// handed the socket past, the transfer is refused (DIVERGENCE.md); with
/// no layer over the socket, it reads the socket.
#[test]
fn only_an_https_proxy_s_tls_is_read_through_pipes() {
    use crate::options::ProxyType;
    assert_eq!(over_layers(Some(ProxyType::Https), false), Ok(true));
    assert_eq!(over_layers(Some(ProxyType::Https2), false), Err(()));
    assert_eq!(over_layers(Some(ProxyType::Https3), false), Err(()));
    assert_eq!(over_layers(None, false), Err(()));
    assert_eq!(over_layers(None, true), Ok(false));
    assert_eq!(over_layers(Some(ProxyType::Socks5), true), Ok(false));
    assert_eq!(over_layers(Some(ProxyType::Http), true), Ok(false));
}

// The state machine through the scripted library: each state's waits,
// failures and words, as `lib/vssh/libssh2.c` has them.

const URL: &str = "sftp://u@127.0.0.1:PORT/~/f";

/// A run's outcome: its result, body, trace and the library's calls.
type Outcome = (Result<(), ErrorKind>, Vec<u8>, String, Vec<String>);

/// `url` run over a world holding `/home/u/f` as `body`, set by `world`.
fn over(
    body: &str,
    url: &str,
    world: impl FnOnce(&mut World),
    set: impl FnOnce(&mut Options),
) -> Outcome {
    let w = world_with(&[("/home/u/f", body)], world);
    run_in(&w, url, set)
}

/// An upload of `bytes`.
fn uploads(o: &mut Options, bytes: &[u8]) {
    o.method = crate::options::Method::Upload;
    o.upload =
        crate::options::UploadSource::Bytes(curl_alloc::TryArc::try_new(bytes.to_vec()).unwrap());
}

/// The quote commands before the transfer.
fn quotes(o: &mut Options, cmds: &[&str]) {
    let line = o.line.make_mut().unwrap();
    line.quote.set(cmds.iter().map(|c| c.as_bytes())).unwrap();
}

/// The known-hosts file is `/known`.
fn known(o: &mut Options) {
    o.ssh.make_mut().unwrap().known_hosts = Some(b"/known".to_vec());
}

/// `said` has each of `lines`, whole.
#[track_caller]
fn says(said: &str, lines: &[&str]) {
    for line in lines {
        let line = format!("{line}\n");
        assert!(said.contains(&line), "{line:?} in {said}");
    }
}

/// C's numbers and words for SFTP's statuses and the session's errors,
/// as `sftp_libssh2_error_to_CURLE`, `sftp_libssh2_strerror` and
/// `libssh2_session_error_to_CURLE` have them, by the headers' numbers.
#[test]
fn c_s_numbers_and_words_for_libssh2_s_failures() {
    use ErrorKind as E;
    let sftp = [
        (0, Ok(()), "Unknown error in libssh2"),
        (1, Err(E::Ssh), "Unknown error in libssh2"),
        (2, Err(E::RemoteFileNotFound), "No such file or directory"),
        (3, Err(E::RemoteAccessDenied), "Permission denied"),
        (4, Err(E::Ssh), "Operation failed"),
        (5, Err(E::Ssh), "Bad message from SFTP server"),
        (6, Err(E::Ssh), "Not connected to SFTP server"),
        (7, Err(E::Ssh), "Connection to SFTP server lost"),
        (8, Err(E::Ssh), "Operation not supported by SFTP server"),
        (9, Err(E::Ssh), "Invalid handle"),
        (10, Err(E::RemoteFileNotFound), "No such file or directory"),
        (11, Err(E::RemoteFileExists), "File already exists"),
        (12, Err(E::RemoteAccessDenied), "File is write protected"),
        (13, Err(E::Ssh), "No media"),
        (14, Err(E::RemoteDiskFull), "Disk full"),
        (15, Err(E::RemoteDiskFull), "User quota exceeded"),
        (16, Err(E::Ssh), "Unknown principal"),
        (17, Err(E::RemoteAccessDenied), "File lock conflict"),
        (18, Err(E::QuoteError), "Directory not empty"),
        (19, Err(E::Ssh), "Not a directory"),
        (20, Err(E::Ssh), "Invalid filename"),
        (21, Err(E::Ssh), "Link points to itself"),
        (22, Err(E::Ssh), "Unknown error in libssh2"),
    ];
    for (n, kind, text) in sftp {
        assert_eq!(sftp_failure(Fx(n)), kind, "{n}");
        assert_eq!(sftp_text(Fx(n)), text, "{n}");
    }
    let session = [
        (0, Ok(())),
        (-37, Err(Halt::Again)),
        (-28, Err(Halt::Fail(E::RemoteFileNotFound))),
        (-1, Err(Halt::Fail(E::CouldntConnect))),
        (-6, Err(Halt::Fail(E::OutOfMemory))),
        (-7, Err(Halt::Fail(E::SendError))),
        (-10, Err(Halt::Fail(E::PeerFailedVerification))),
        (-11, Err(Halt::Fail(E::PeerFailedVerification))),
        (-18, Err(Halt::Fail(E::PeerFailedVerification))),
        (-19, Err(Halt::Fail(E::PeerFailedVerification))),
        (-15, Err(Halt::Fail(E::LoginDenied))),
        (-30, Err(Halt::Fail(E::OperationTimedout))),
        (-9, Err(Halt::Fail(E::OperationTimedout))),
        (-31, Err(Halt::Fail(E::Ssh))),
        (-5, Err(Halt::Fail(E::Ssh))),
    ];
    for (n, ran) in session {
        assert_eq!(session_failure(Code(n)), ran, "{n}");
    }
    // The names C's code tests for, by the headers' numbers.
    let codes = [
        (Code::NONE, 0),
        (Code::SOCKET_NONE, -1),
        (Code::ALLOC, -6),
        (Code::SOCKET_SEND, -7),
        (Code::TIMEOUT, -9),
        (Code::HOSTKEY_INIT, -10),
        (Code::HOSTKEY_SIGN, -11),
        (Code::PASSWORD_EXPIRED, -15),
        (Code::PUBLICKEY_UNRECOGNIZED, -18),
        (Code::PUBLICKEY_UNVERIFIED, -19),
        (Code::SCP_PROTOCOL, -28),
        (Code::SOCKET_TIMEOUT, -30),
        (Code::SFTP_PROTOCOL, -31),
        (Code::EAGAIN, -37),
    ];
    for (code, n) in codes {
        assert_eq!(code.0, n);
        assert_eq!(code.again(), n == -37);
    }
    assert_eq!(KnownKeyType(9).bits(), 9 << 18);
    assert_eq!(KnownKeyType::ED25519.bits(), 0x1c_0000);
    let flags = AttrFlags(AttrFlags::SIZE.0 | AttrFlags::PERMISSIONS.0);
    assert!(flags.has(AttrFlags::SIZE) && flags.has(AttrFlags::PERMISSIONS));
    assert!(!flags.has(AttrFlags::UIDGID) && !flags.has(AttrFlags::ACMODTIME));
    assert!(offers(b"publickey,password", b"password"));
    assert!(!offers(b"publickey,password", b"keyboard-interactive"));
    assert!(!offers(b"pass", b"password"));
    assert_eq!(text(b"ab\0cd"), b"ab");
}

/// The states' names, as C traces them going from one to the next.
#[test]
fn the_states_are_traced_by_c_s_names() {
    let w = world_with(&[("/home/u/f", "x")], |w| w.trace_ssh = true);
    let (result, _, said, _) = run_in(&w, URL, |_| {});
    assert_eq!(result, Ok(()), "{said}");
    says(
        &said,
        &[
            "[SSH_STOP] -> [SSH_INIT]",
            "[SSH_INIT] -> [SSH_S_STARTUP]",
            "[SSH_S_STARTUP] -> [SSH_HOSTKEY]",
            "[SSH_HOSTKEY] -> [SSH_AUTHLIST]",
            "[SSH_AUTHLIST] -> [SSH_AUTH_PKEY_INIT]",
            "[SSH_AUTH_PKEY_INIT] -> [SSH_AUTH_PKEY]",
            "[SSH_AUTH_PKEY] -> [SSH_AUTH_DONE]",
            "[SSH_AUTH_DONE] -> [SSH_SFTP_INIT]",
            "[SSH_SFTP_INIT] -> [SSH_SFTP_REALPATH]",
            "[SSH_SFTP_REALPATH] -> [SSH_STOP]",
            "[SSH_SFTP_QUOTE_INIT] -> [SSH_SFTP_GETINFO]",
            "[SSH_SFTP_GETINFO] -> [SSH_SFTP_TRANS_INIT]",
            "[SSH_SFTP_TRANS_INIT] -> [SSH_SFTP_DOWNLOAD_INIT]",
            "[SSH_SFTP_DOWNLOAD_INIT] -> [SSH_SFTP_DOWNLOAD_STAT]",
            "[SSH_SFTP_DOWNLOAD_STAT] -> [SSH_STOP]",
            "[SSH_STOP] -> [SSH_SFTP_CLOSE]",
            "[SSH_SFTP_CLOSE] -> [SSH_STOP]",
            "[SSH_STOP] statemachine() -> 0, block=0",
            "CONNECT phase done",
            "DO phase starts",
            "SFTP DONE done",
        ],
    );
}

/// Each call that would wait is made again, the same, and the run comes
/// to what it comes to without the waits: the waits are all that differ
/// in what the library is asked, each way of logging in and the goodbye
/// among it.
#[test]
fn every_call_that_waits_is_made_again() {
    type Set = fn(&mut Options);
    type Tweak = fn(&mut World);
    let key_refused: Tweak = |w| w.fails = vec![("auth_publickey_fromfile", Code(-18))];
    let to_agent: Tweak = |w| {
        w.fails = vec![
            ("auth_publickey_fromfile", Code(-18)),
            ("auth_password", Code(-18)),
        ];
        w.agent = Some(vec![(b"one".to_vec(), false), (b"two".to_vec(), true)]);
    };
    let to_keyboard: Tweak = |w| {
        w.fails = vec![
            ("auth_publickey_fromfile", Code(-18)),
            ("auth_password", Code(-18)),
        ];
    };
    let closes: Set = |o| o.limits.reuse.forbid = true;
    let logins: [(&str, Set, Tweak); 6] = [
        (URL, |_| {}, key_refused),
        (URL, |_| {}, to_agent),
        (URL, closes, to_agent),
        (URL, |_| {}, to_keyboard),
        (URL, closes, |_| {}),
        ("scp://u@127.0.0.1:PORT/home/u/f", closes, |_| {}),
    ];
    let flows: [(&str, Set); 8] = [
        (URL, |_| {}),
        (URL, |o| uploads(o, b"up")),
        ("sftp://u@127.0.0.1:PORT/~/d/", |_| {}),
        (URL, |o| {
            quotes(
                o,
                &[
                    "chmod 600 /home/u/f",
                    "chown 3 /home/u/f",
                    "ln /home/u/f /home/u/l",
                    "mkdir /home/u/n",
                    "rename /home/u/n /home/u/m",
                    "rmdir /home/u/m",
                    "rm /home/u/l",
                    "statvfs /home/u",
                ],
            );
            o.line
                .make_mut()
                .unwrap()
                .postquote
                .set([&b"rm /home/u/f"[..]])
                .unwrap();
        }),
        ("scp://u@127.0.0.1:PORT/home/u/f", |_| {}),
        ("scp://u@127.0.0.1:PORT/home/u/up", |o| {
            uploads(o, b"scp up")
        }),
        (URL, |o| {
            known(o);
            o.ssh.make_mut().unwrap().key_handler = Some(
                Handler::ssh_key(Verdict(KeyVerdict::FineAddToFile, Default::default())).unwrap(),
            );
        }),
        (URL, |o| o.filetime = true),
    ];
    let flows = flows
        .into_iter()
        .map(|(url, set)| (url, set, (|_| {}) as Tweak));
    for (url, set, tweak) in flows.chain(logins) {
        let world = |w: &mut World| {
            w.dir = vec![
                (b"a".to_vec(), b"-rw a".to_vec(), Attrs::default()),
                (
                    b"l".to_vec(),
                    b"lrw l".to_vec(),
                    Attrs {
                        flags: AttrFlags::PERMISSIONS,
                        permissions: 0o120777,
                        ..Attrs::default()
                    },
                ),
            ];
            w.links = vec![(b"/home/u/d/l".to_vec(), b"a".to_vec())];
            w.authlist = Some(b"publickey,password,keyboard-interactive".to_vec());
            tweak(w);
        };
        let plain = world_with(&[("/home/u/f", "body")], world);
        let (r1, b1, s1, c1) = run_in(&plain, url, set);
        let waits = world_with(&[("/home/u/f", "body")], |w| {
            world(w);
            w.wait_all = true;
        });
        let (r2, b2, s2, c2) = run_in(&waits, url, set);
        assert_eq!(r1, r2, "{url}: {s1}\n---\n{s2}");
        // A wait is never said as a failure by the transfer's states: no
        // line carries libssh2's number for it. (Freeing the session as it
        // closes says any failure, a wait's too, as C's `sshc_cleanup`.)
        assert!(!s2.contains("-37"), "{url}: {s2}");
        assert_eq!(b1, b2, "{url}");
        let mut c2: Vec<_> = c2
            .into_iter()
            .filter(|c| !c.starts_with("waits "))
            .collect();
        // An agent's login that waits asks for its identity again, the
        // same one, as C's does (`SSH_AUTH_AGENT`).
        c2.dedup_by(|a, b| a == b && a == "agent_get_identity");
        assert_eq!(c1, c2, "{url}");
        let (p, q) = (plain.lock().unwrap(), waits.lock().unwrap());
        assert_eq!(p.files, q.files, "{url}");
        assert_eq!(p.set, q.set, "{url}");
        assert!(
            q.calls.iter().filter(|c| c.starts_with("waits ")).count() > 5,
            "{url}"
        );
    }
}

/// A key handler's verdict, and what it was told.
struct Verdict(KeyVerdict, Told);

/// What a key handler was told: the file's key, the server's, the
/// check's outcome and the key's type.
type Told = Arc<Mutex<Vec<(Option<Vec<u8>>, Vec<u8>, KeyMatch, KeyType)>>>;

impl crate::handler::SshKeyHandler for Verdict {
    fn check(
        &self,
        _: &mut TransferCx<'_>,
        known: Option<HostKey<'_>>,
        found: HostKey<'_>,
        matched: KeyMatch,
    ) -> KeyVerdict {
        assert_eq!(found.encoding, KeyEncoding::Raw);
        if let Some(k) = &known {
            assert_eq!(k.encoding, KeyEncoding::Base64Text);
        }
        self.1.lock().unwrap().push((
            known.map(|k| k.key.to_vec()),
            found.key.to_vec(),
            matched,
            found.kind,
        ));
        self.0
    }
}

/// The handshake, the first login calls and SFTP's start each fail as C
/// says they do.
#[test]
fn the_connect_s_failures_are_c_s() {
    let fails = |name, code| move |w: &mut World| w.fails = vec![(name, Code(code))];
    let (r, _, said, _) = over("x", URL, fails("handshake", -5), |_| {});
    assert_eq!(r, Err(ErrorKind::FailedInit), "{said}");
    says(
        &said,
        &["Failure establishing ssh session: -5, fake failure"],
    );

    let (r, _, said, _) = over("x", URL, fails("sftp_init", -31), |_| {});
    assert_eq!(r, Err(ErrorKind::FailedInit), "{said}");
    says(&said, &["Failure initializing sftp session: fake failure"]);

    // The list of logins not had: the library's error is the failure.
    for (code, kind) in [(-9, ErrorKind::OperationTimedout), (-5, ErrorKind::Ssh)] {
        let (r, _, said, _) = over("x", URL, fails("userauth_list", code), |_| {});
        assert_eq!(r, Err(kind), "{said}");
    }
    // Or the user is let in without one.
    let (r, _, said, calls) = over(
        "x",
        URL,
        |w| {
            w.authlist = None;
            w.authenticated = true;
        },
        |_| {},
    );
    assert_eq!(r, Ok(()), "{said}");
    says(
        &said,
        &[
            "SSH: user accepted with no authentication",
            "SSH: authentication complete",
        ],
    );
    assert!(!calls.iter().any(|c| c.starts_with("auth_")), "{calls:?}");

    for (fx, kind) in [
        (Fx::NO_SUCH_FILE, ErrorKind::RemoteFileNotFound),
        (Fx::PERMISSION_DENIED, ErrorKind::RemoteAccessDenied),
        (Fx::OK, ErrorKind::Ssh),
    ] {
        let (r, _, said, _) = over(
            "x",
            URL,
            |w| {
                w.fails = vec![("sftp_realpath", Code(-31))];
                w.fx = fx;
                w.trace_ssh = true;
            },
            |_| {},
        );
        assert_eq!(r, Err(kind), "{said}");
        says(
            &said,
            &[&format!(
                "error = {} makes libcurl = {}",
                fx.0,
                kind.number()
            )],
        );
    }
}

/// The logins in C's order: the key files, the password, the agent's
/// identities one by one, then keyboard-interactive, each said as C says
/// it; none taken is an authentication failure.
#[test]
fn the_logins_are_tried_in_c_s_order() {
    let all = b"publickey,password,keyboard-interactive".to_vec();
    // The key files refused, the password taken.
    let (r, _, said, calls) = over(
        "x",
        URL,
        |w| w.fails = vec![("auth_publickey_fromfile", Code(-18))],
        |_| {},
    );
    assert_eq!(r, Ok(()), "{said}");
    says(
        &said,
        &[
            "SSH: trying public key file '/keys/id.pub'",
            "SSH: trying private key file '/keys/id'",
            "SSH: publickey authentication denied: fake failure",
            "SSH: initialized password authentication",
        ],
    );
    assert!(
        calls.contains(&"fails auth_publickey_fromfile".to_owned()),
        "{calls:?}"
    );
    assert!(
        calls.iter().any(|c| c.starts_with("auth_password u")),
        "{calls:?}"
    );

    // A -1 sets no words of its own.
    let (_, _, said, _) = over(
        "x",
        URL,
        |w| w.fails = vec![("auth_publickey_fromfile", Code(-1))],
        |_| {},
    );
    says(
        &said,
        &["SSH: publickey authentication denied: Reason unknown (-1)"],
    );

    // Neither: the agent's identities, the second taking.
    let agent = |w: &mut World| {
        w.fails = vec![
            ("auth_publickey_fromfile", Code(-18)),
            ("auth_password", Code(-18)),
        ];
        w.agent = Some(vec![(b"one".to_vec(), false), (b"two".to_vec(), true)]);
    };
    let (r, _, said, calls) = over("x", URL, agent, |_| {});
    assert_eq!(r, Ok(()), "{said}");
    says(
        &said,
        &[
            "SSH: trying publickey authentication via agent",
            "SSH: agent authenticated user 'u' with key 'two'",
        ],
    );
    let tried: Vec<_> = calls
        .iter()
        .filter(|c| c.starts_with("agent_userauth"))
        .collect();
    assert_eq!(tried, ["agent_userauth u one", "agent_userauth u two"]);

    // The agent's each failure, then keyboard-interactive.
    for (fail, line) in [
        (None, "SSH: could not create agent object"),
        (Some("agent_connect"), "SSH: failure connecting to agent"),
        (
            Some("agent_list_identities"),
            "SSH: failure requesting identities to agent",
        ),
        (
            Some("agent_get_identity"),
            "SSH: failure requesting identities to agent",
        ),
    ] {
        let (r, _, said, calls) = over(
            "x",
            URL,
            |w| {
                w.fails = vec![
                    ("auth_publickey_fromfile", Code(-18)),
                    ("auth_password", Code(-18)),
                ];
                if let Some(fail) = fail {
                    w.agent = Some(vec![(b"one".to_vec(), true)]);
                    w.fails.push((fail, Code(-42)));
                }
                w.authlist = Some(all.clone());
                w.keyboard = true;
            },
            |_| {},
        );
        assert_eq!(r, Ok(()), "{line}: {said}");
        says(
            &said,
            &[line, "SSH: initialized keyboard interactive authentication"],
        );
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("auth_keyboard_interactive u")),
            "{calls:?}"
        );
    }
    // No identity takes.
    let (_, _, said, _) = over(
        "x",
        URL,
        |w| {
            w.fails = vec![
                ("auth_publickey_fromfile", Code(-18)),
                ("auth_password", Code(-18)),
            ];
            w.agent = Some(vec![(b"one".to_vec(), false)]);
        },
        |_| {},
    );
    says(
        &said,
        &[
            "SSH: no agent identity would match",
            "Authentication failure",
        ],
    );

    // Keyboard-interactive refused fails the login at once.
    let (r, _, said, _) = over(
        "x",
        URL,
        |w| {
            w.authlist = Some(b"keyboard-interactive".to_vec());
        },
        |_| {},
    );
    assert_eq!(r, Err(ErrorKind::LoginDenied), "{said}");
    assert!(!said.contains("Authentication failure"), "{said}");

    // What the server does not offer is not tried; nothing left fails.
    let (r, _, said, calls) = over(
        "x",
        URL,
        |w| w.authlist = Some(b"hostbased".to_vec()),
        |_| {},
    );
    assert_eq!(r, Err(ErrorKind::LoginDenied), "{said}");
    says(
        &said,
        &[
            "SSH: host offers authentication via: hostbased",
            "Authentication failure",
        ],
    );
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("auth_") || c.starts_with("agent_")),
        "{calls:?}"
    );

    // What the user may not use is not tried either.
    let (r, _, said, calls) = over(
        "x",
        URL,
        |w| w.authlist = Some(all.clone()),
        |o| {
            o.ssh.make_mut().unwrap().auth_types = SshAuthTypes::PASSWORD;
        },
    );
    assert_eq!(r, Ok(()), "{said}");
    assert!(
        !calls.iter().any(|c| c.starts_with("auth_publickey")),
        "{calls:?}"
    );
    let (r, _, said, calls) = over(
        "x",
        URL,
        |w| {
            w.authlist = Some(all.clone());
            w.keyboard = true;
            w.agent = Some(vec![(b"one".to_vec(), true)]);
        },
        |o| o.ssh.make_mut().unwrap().auth_types = SshAuthTypes::KEYBOARD,
    );
    assert_eq!(r, Ok(()), "{said}");
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("auth_p") || c.starts_with("agent_")),
        "{calls:?}"
    );
    assert!(
        calls.iter().any(|c| c.starts_with("auth_keyboard")),
        "{calls:?}"
    );
}

/// The host's entry in the known-hosts file picks the server's key type
/// by C's names for them; an entry C cannot read is said and passed
/// over; a hashed entry is looked up by its key, once for each type the
/// collection lacks.
#[test]
fn the_known_hosts_entry_s_key_type_is_asked_for() {
    let entry = |name: Option<&str>, kind| KnownEntry {
        name: name.map(|n| n.as_bytes().to_vec()),
        key: Some(b"QUFBQQ==".to_vec()),
        kind,
    };
    for (kind, method) in [
        (KnownKeyType::ED25519, "ssh-ed25519"),
        (KnownKeyType::ECDSA_521, "ecdsa-sha2-nistp521"),
        (KnownKeyType::ECDSA_384, "ecdsa-sha2-nistp384"),
        (KnownKeyType::ECDSA_256, "ecdsa-sha2-nistp256"),
        (KnownKeyType::SSHRSA, "rsa-sha2-256,rsa-sha2-512,ssh-rsa"),
        (KnownKeyType::SSHDSS, "ssh-dss"),
    ] {
        let (_, _, said, calls) = over(
            "x",
            URL,
            |w| {
                w.known = vec![
                    entry(Some("[127.0.0.1"), kind),
                    entry(Some("127.0.0.1"), kind),
                ]
            },
            known,
        );
        says(
            &said,
            &[
                "SSH: invalid host pattern [127.0.0.1 in /known",
                "SSH: found host '127.0.0.1' in '/known'",
                &format!("SSH: set '{method}' as hostkey type"),
            ],
        );
        assert!(
            calls.contains(&format!("set_hostkey_methods {method}")),
            "{calls:?}"
        );
    }
    let (r, _, said, _) = over(
        "x",
        URL,
        |w| w.known = vec![entry(Some("127.0.0.1"), KnownKeyType::RSA1)],
        known,
    );
    assert_eq!(r, Err(ErrorKind::Ssh), "{said}");
    says(&said, &["Found host key type RSA1 which is not supported"]);
    let (r, _, said, _) = over(
        "x",
        URL,
        |w| w.known = vec![entry(Some("127.0.0.1"), KnownKeyType(9))],
        known,
    );
    assert_eq!(r, Err(ErrorKind::Ssh), "{said}");
    says(&said, &["Unknown host key type: 2359296"]);
    // The library refusing the type: its words, its error's failure.
    for (code, kind) in [
        (-5, ErrorKind::Ssh),
        (-6, ErrorKind::OutOfMemory),
        (-37, ErrorKind::Ssh),
    ] {
        let (r, _, said, _) = over(
            "x",
            URL,
            |w| {
                w.known = vec![entry(Some("127.0.0.1"), KnownKeyType::ED25519)];
                w.fails = vec![("set_hostkey_methods", Code(code))];
            },
            known,
        );
        assert_eq!(r, Err(kind), "{code}: {said}");
        says(
            &said,
            &["libssh2 method 'ssh-ed25519' failed: fake failure"],
        );
    }
    // A hashed entry, by its key: a type found absent is not asked again.
    let (_, _, said, calls) = over(
        "x",
        URL,
        |w| {
            w.known = vec![
                entry(None, KnownKeyType::SSHRSA),
                entry(None, KnownKeyType::SSHRSA),
                entry(None, KnownKeyType::ED25519),
            ];
            w.known_kind = Some(KnownKeyType::ED25519);
            w.absent = vec![KnownKeyType::SSHRSA];
        },
        known,
    );
    says(
        &said,
        &[
            "SSH: found host '127.0.0.1' in '/known'",
            "SSH: set 'ssh-ed25519' as hostkey type",
        ],
    );
    let checks = calls
        .iter()
        .take_while(|c| *c != "handshake")
        .filter(|c| c.starts_with("knownhost_check"))
        .count();
    assert_eq!(checks, 2, "{calls:?}");
    // The port given with the host, as it is not SSH's own: each check
    // before the handshake.
    let before: Vec<_> = calls
        .iter()
        .take_while(|c| *c != "handshake")
        .filter(|c| c.starts_with("knownhost_check"))
        .collect();
    assert_eq!(before, ["knownhost_check 127.0.0.1 8022"; 2], "{calls:?}");
    // A wrong port, or another host, is not the host's entry.
    let (_, _, said, calls) = over(
        "x",
        URL,
        |w| {
            w.known = vec![
                entry(Some("[127.0.0.1]:22"), KnownKeyType::ED25519),
                entry(Some("[127.0.0.1]:x"), KnownKeyType::ED25519),
                entry(Some("[127.0.0.12]:8022"), KnownKeyType::ED25519),
                // As long as the host's name, not it.
                entry(Some("[127.0.0.2]:8022"), KnownKeyType::ED25519),
                entry(Some("127.0.0.12"), KnownKeyType::ED25519),
            ];
        },
        known,
    );
    says(&said, &["SSH: did not find host '127.0.0.1' in '/known'"]);
    assert!(
        !calls.iter().any(|c| c.starts_with("set_hostkey")),
        "{calls:?}"
    );
    // A fingerprint to check skips it all.
    let (_, _, said, _) = over(
        "x",
        URL,
        |w| w.known = vec![entry(Some("127.0.0.1"), KnownKeyType::ED25519)],
        |o| {
            known(o);
            o.ssh.make_mut().unwrap().host_key_md5 =
                Some(b"07070707070707070707070707070707".to_vec());
        },
    );
    assert!(!said.contains("found host"), "{said}");
    let (_, _, said, _) = over(
        "x",
        URL,
        |w| w.known = vec![entry(Some("127.0.0.1"), KnownKeyType::ED25519)],
        |o| {
            known(o);
            o.ssh.make_mut().unwrap().host_key_sha256 = Some(b"x".to_vec());
        },
    );
    assert!(!said.contains("found host"), "{said}");
    // The file not read is said, and the run goes on.
    let (r, _, said, _) = over(
        "x",
        URL,
        |w| w.fails = vec![("knownhost_readfile", Code(-5))],
        |o| {
            known(o);
            o.ssh.make_mut().unwrap().key_handler =
                Some(Handler::ssh_key(Verdict(KeyVerdict::Fine, Default::default())).unwrap());
        },
    );
    assert_eq!(r, Ok(()), "{said}");
    says(&said, &["SSH: failed to read known hosts from /known"]);
}

/// The server's key against the file, each check's outcome told to the
/// key handler with the keys, its verdict done as C does it: added to
/// the collection, written to the file, the old entry dropped, or
/// refused; without a handler, a match alone is let in.
#[test]
fn the_key_handler_decides_on_the_known_hosts_check() {
    use KeyVerdict as V;
    for (kind, matched, shown) in [
        (
            Some(KnownKeyType::ED25519),
            KeyMatch::Ok,
            "0, key: QUFBQQ==",
        ),
        (
            Some(KnownKeyType::SSHRSA),
            KeyMatch::Mismatch,
            "1, key: QUFBQQ==",
        ),
        (None, KeyMatch::Missing, "2, key: <none>"),
        (Some(KnownKeyType(15)), KeyMatch::Failure, "3, key: <none>"),
    ] {
        for verdict in [
            V::Fine,
            V::FineAddToFile,
            V::FineReplace,
            V::Reject,
            V::Defer,
        ] {
            let told = Arc::new(Mutex::new(Vec::new()));
            let handler = Handler::ssh_key(Verdict(verdict, told.clone())).unwrap();
            let (r, _, said, calls) = over(
                "x",
                URL,
                |w| w.known_kind = kind,
                |o| {
                    known(o);
                    o.ssh.make_mut().unwrap().key_handler = Some(handler);
                },
            );
            let case = format!("{matched:?} {verdict:?}");
            says(&said, &[&format!("SSH: host check {shown}")]);
            let known_key = kind.filter(|k| k.0 != 15).map(|_| b"QUFBQQ==".to_vec());
            assert_eq!(
                *told.lock().unwrap(),
                [(known_key, HOST_KEY.to_vec(), matched, KeyType::Ed25519)],
                "{case}"
            );
            let has = |name: &str| calls.iter().any(|c| c.starts_with(name));
            match verdict {
                V::Reject => {
                    assert_eq!(r, Err(ErrorKind::PeerFailedVerification), "{case}");
                    says(&said, &["SSH: knownhost check failed"]);
                }
                V::Defer => {
                    assert_eq!(r, Err(ErrorKind::PeerFailedVerification), "{case}");
                    assert!(!said.contains("knownhost check failed"), "{case}: {said}");
                }
                _ => {
                    assert_eq!(r, Ok(()), "{case}: {said}");
                    let matches = matched == KeyMatch::Ok;
                    assert_eq!(
                        said.contains("SSH: knownhost entry matches host key\n"),
                        matches,
                        "{case}"
                    );
                    assert_eq!(
                        has("knownhost_del_found"),
                        verdict == V::FineReplace,
                        "{case}"
                    );
                    assert_eq!(
                        calls.contains(&"knownhost_add [127.0.0.1]:8022 7".to_owned()),
                        !matches,
                        "{case}: {calls:?}"
                    );
                    let writes = !matches && verdict != V::Fine;
                    assert_eq!(
                        calls.contains(&"knownhost_writefile /known".to_owned()),
                        writes,
                        "{case}"
                    );
                }
            }
        }
    }
    // Without a handler: a match alone.
    for (kind, fine) in [
        (Some(KnownKeyType::ED25519), true),
        (Some(KnownKeyType::SSHRSA), false),
    ] {
        let (r, _, said, _) = over("x", URL, |w| w.known_kind = kind, known);
        assert_eq!(r.is_ok(), fine, "{said}");
    }
    // A failed add or write is said, and let pass.
    for (fail, line) in [
        (
            "knownhost_add",
            "WARNING: adding the known host [127.0.0.1]:8022 failed",
        ),
        ("knownhost_writefile", "WARNING: writing /known failed"),
    ] {
        let handler = Handler::ssh_key(Verdict(V::FineAddToFile, Default::default())).unwrap();
        let (r, _, said, _) = over(
            "x",
            URL,
            |w| w.fails = vec![(fail, Code(-5))],
            |o| {
                known(o);
                o.ssh.make_mut().unwrap().key_handler = Some(handler);
            },
        );
        assert_eq!(r, Ok(()), "{said}");
        says(&said, &[line]);
    }
    // A host with no key, or of a type the file cannot hold, is refused.
    for (host, line) in [
        (None, "SSH: host offers no public key"),
        (
            Some(HostKeyType::Unknown),
            "SSH: unsupported host key type for knownhosts check",
        ),
    ] {
        let handler = Handler::ssh_key(Verdict(V::Fine, Default::default())).unwrap();
        let (r, _, said, _) = over(
            "x",
            URL,
            |w| w.host = host.map(|k| (HOST_KEY.to_vec(), k)),
            |o| {
                known(o);
                o.ssh.make_mut().unwrap().key_handler = Some(handler);
            },
        );
        assert_eq!(r, Err(ErrorKind::PeerFailedVerification), "{said}");
        says(&said, &[line, "SSH: knownhost check failed"]);
    }
    // The type each host key is told as, and looked up as.
    for (host, kt, bits) in [
        (HostKeyType::Rsa, KeyType::Rsa, 2),
        (HostKeyType::Dss, KeyType::Dss, 3),
        (HostKeyType::Ecdsa256, KeyType::Ecdsa, 4),
        (HostKeyType::Ecdsa384, KeyType::Ecdsa, 5),
        (HostKeyType::Ecdsa521, KeyType::Ecdsa, 6),
        (HostKeyType::Ed25519, KeyType::Ed25519, 7),
    ] {
        let told = Arc::new(Mutex::new(Vec::new()));
        let handler = Handler::ssh_key(Verdict(V::Fine, told.clone())).unwrap();
        let (_, _, _, calls) = over(
            "x",
            URL,
            |w| w.host = Some((HOST_KEY.to_vec(), host)),
            |o| {
                known(o);
                o.ssh.make_mut().unwrap().key_handler = Some(handler);
            },
        );
        assert_eq!(told.lock().unwrap()[0].3, kt);
        assert!(
            calls.contains(&format!("knownhost_add [127.0.0.1]:8022 {bits}")),
            "{calls:?}"
        );
        let asked = Arc::new(Mutex::new(Vec::new()));
        let handler = Handler::ssh_host_key(Answers(true, asked.clone())).unwrap();
        let _verified = over(
            "x",
            URL,
            |w| w.host = Some((HOST_KEY.to_vec(), host)),
            |o| {
                o.ssh.make_mut().unwrap().host_key_handler = Some(handler);
            },
        );
        assert_eq!(asked.lock().unwrap()[0].0, kt);
    }
    let asked = Arc::new(Mutex::new(Vec::new()));
    let handler = Handler::ssh_host_key(Answers(true, asked.clone())).unwrap();
    let _verified = over(
        "x",
        URL,
        |w| w.host = Some((HOST_KEY.to_vec(), HostKeyType::Unknown)),
        |o| {
            o.ssh.make_mut().unwrap().host_key_handler = Some(handler);
        },
    );
    assert_eq!(asked.lock().unwrap()[0].0, KeyType::Other);
    // The host key handler with no key to give is a refusal.
    let handler = Handler::ssh_host_key(Answers(true, Default::default())).unwrap();
    let (r, _, _, _) = over(
        "x",
        URL,
        |w| w.host = None,
        |o| {
            o.ssh.make_mut().unwrap().host_key_handler = Some(handler);
        },
    );
    assert_eq!(r, Err(ErrorKind::PeerFailedVerification));
}

/// The fingerprints given are checked before anything else: SHA256's in
/// base64, compared up to its padding, MD5's in hex, in any case; a
/// match skips the known-hosts file.
#[test]
fn the_fingerprints_given_are_checked() {
    let mut sha = Vec::new();
    crate::base64::encode(&[7; 32], &mut sha).unwrap();
    let sha = String::from_utf8(sha).unwrap();
    let unpadded = sha.trim_end_matches('=').to_owned();
    let md5 = "07".repeat(16);
    let set_sha = |want: &str| {
        let want = want.as_bytes().to_vec();
        move |o: &mut Options| {
            known(o);
            o.ssh.make_mut().unwrap().host_key_sha256 = Some(want);
        }
    };
    for want in [&sha, &unpadded] {
        let (r, _, said, calls) = over("x", URL, |_| {}, set_sha(want));
        assert_eq!(r, Ok(()), "{said}");
        says(
            &said,
            &[
                &format!("SSH: SHA256 public key '{want}'"),
                &format!("SSH: SHA256 fingerprint '{sha}'"),
                "SSH: SHA256 checksum match",
            ],
        );
        assert!(
            !calls.iter().any(|c| c.starts_with("knownhost_check")),
            "{calls:?}"
        );
    }
    for want in [
        &unpadded[1..],
        &format!("{}x", &unpadded[..unpadded.len() - 1]),
        &format!("{unpadded}A"),
    ] {
        let (r, _, said, _) = over("x", URL, |_| {}, set_sha(want));
        assert_eq!(r, Err(ErrorKind::PeerFailedVerification), "{want}: {said}");
        says(
            &said,
            &[&format!(
                "Denied establishing ssh session: mismatch SHA256 fingerprint. Remote {sha} is not equal to {want}"
            )],
        );
    }
    let (r, _, said, _) = over("x", URL, |w| w.sha256 = None, set_sha(&sha));
    assert_eq!(r, Err(ErrorKind::PeerFailedVerification), "{said}");
    says(
        &said,
        &["Denied establishing ssh session: SHA256 fingerprint not available"],
    );

    let set_md5 = |want: String| {
        move |o: &mut Options| {
            known(o);
            o.ssh.make_mut().unwrap().host_key_md5 = Some(want.into_bytes());
        }
    };
    let (r, _, said, calls) = over(
        "x",
        URL,
        |w| w.md5 = Some([0xab; 16]),
        set_md5("AB".repeat(16)),
    );
    assert_eq!(r, Ok(()), "{said}");
    says(
        &said,
        &[
            &format!("SSH: MD5 public key '{}'", "AB".repeat(16)),
            &format!("SSH: MD5 fingerprint '{}'", "ab".repeat(16)),
            "SSH: MD5 checksum match",
        ],
    );
    assert!(
        !calls.iter().any(|c| c.starts_with("knownhost_check")),
        "{calls:?}"
    );
    let (r, _, said, _) = over("x", URL, |_| {}, set_md5("08".repeat(16)));
    assert_eq!(r, Err(ErrorKind::PeerFailedVerification), "{said}");
    says(
        &said,
        &[&format!(
            "Denied establishing ssh session: mismatch MD5 fingerprint. Remote {md5} is not equal to {}",
            "08".repeat(16)
        )],
    );
    let (r, _, said, _) = over("x", URL, |w| w.md5 = None, set_md5(md5.clone()));
    assert_eq!(r, Err(ErrorKind::PeerFailedVerification), "{said}");
    says(
        &said,
        &["Denied establishing ssh session: MD5 fingerprint not available"],
    );
    // Both given: both checked.
    let (r, _, said, _) = over(
        "x",
        URL,
        |_| {},
        move |o| {
            set_sha(&sha)(o);
            o.ssh.make_mut().unwrap().host_key_md5 = Some(md5.into_bytes());
        },
    );
    assert_eq!(r, Ok(()), "{said}");
    says(
        &said,
        &["SSH: SHA256 checksum match", "SSH: MD5 checksum match"],
    );
}

/// Each quote command calls what C's calls with its paths, those of two
/// paths read both; a command read wrong, or failing, fails the transfer
/// with C's words, unless it starts with `*`, which lets it fail.
#[test]
fn the_quote_commands_are_c_s() {
    let run = |cmds: &[&str], world: fn(&mut World)| {
        let cmds: Vec<String> = cmds.iter().map(|c| c.to_string()).collect();
        over("x", URL, world, move |o| {
            let cmds: Vec<&str> = cmds.iter().map(String::as_str).collect();
            quotes(o, &cmds);
        })
    };
    let (r, _, said, calls) = run(
        &[
            "ln /home/u/f /home/u/l",
            "symlink /home/u/f /home/u/s",
            "mkdir /home/u/n",
            "rename /home/u/n /home/u/m",
            "rmdir /home/u/m",
            "rm /home/u/l",
        ],
        |_| {},
    );
    assert_eq!(r, Ok(()), "{said}");
    says(&said, &["SSH: sending quote commands"]);
    let quoted: Vec<_> = calls
        .iter()
        .skip_while(|c| !c.starts_with("sftp_realpath"))
        .skip(1)
        .take(6)
        .collect();
    assert_eq!(
        quoted,
        [
            "sftp_symlink /home/u/f /home/u/l",
            "sftp_symlink /home/u/f /home/u/s",
            "sftp_mkdir /home/u/n",
            "sftp_rename /home/u/n /home/u/m",
            "sftp_rmdir /home/u/m",
            "sftp_unlink /home/u/l",
        ]
    );
    // Read wrong.
    for (cmd, line) in [
        ("chmod", "Syntax error command 'chmod', missing parameter"),
        (
            "chmod 600",
            "Syntax error in chmod 600: Bad second parameter",
        ),
        (
            "chgrp 600",
            "Syntax error in chgrp 600: Bad second parameter",
        ),
        ("ln /a", "Syntax error in ln/symlink: Bad second parameter"),
        (
            "symlink /a",
            "Syntax error in ln/symlink: Bad second parameter",
        ),
        ("rename /a", "Syntax error in rename: Bad second parameter"),
        ("mkdir /a /b", "Suspicious data after the command line"),
        ("rmdir /a /b", "Suspicious data after the command line"),
        ("rm /a /b", "Suspicious data after the command line"),
        ("statvfs /a /b", "Suspicious data after the command line"),
        ("rename /a /b /c", "Suspicious data after the command line"),
        ("foo /a", "Unknown SFTP command"),
        ("rm \"/a", "Syntax error: Bad first parameter to 'rm \"/a'"),
        (
            "chmod 600 \"/a",
            "Syntax error in chmod 600 \"/a: Bad second parameter",
        ),
        (
            "chmod abc /home/u/f",
            "Syntax error: chmod permissions not a number",
        ),
        (
            "chgrp abc /home/u/f",
            "Syntax error: chgrp gid not a number",
        ),
        (
            "chown abc /home/u/f",
            "Syntax error: chown uid not a number",
        ),
        (
            "atime yesterday /home/u/f",
            "incorrect date format for atime",
        ),
        (
            "mtime yesterday /home/u/f",
            "incorrect date format for mtime",
        ),
        (
            "*chmod abc /home/u/f",
            "Syntax error: chmod permissions not a number",
        ),
    ] {
        let (r, _, said, calls) = run(&[cmd], |_| {});
        assert_eq!(r, Err(ErrorKind::QuoteError), "{cmd}: {said}");
        says(&said, &[line]);
        assert!(
            !calls.iter().any(|c| c.starts_with("sftp_open")),
            "{cmd}: {calls:?}"
        );
    }
    // Failing.
    for (cmd, fail, line) in [
        (
            "ln /home/u/f /home/u/l",
            "sftp_symlink",
            "symlink \"/home/u/f\" to \"/home/u/l\" failed: File already exists",
        ),
        (
            "mkdir /home/u/n",
            "sftp_mkdir",
            "mkdir \"/home/u/n\" failed: File already exists",
        ),
        (
            "rename /home/u/n /home/u/m",
            "sftp_rename",
            "rename \"/home/u/n\" to \"/home/u/m\" failed: File already exists",
        ),
        (
            "rmdir /home/u/m",
            "sftp_rmdir",
            "rmdir \"/home/u/m\" failed: File already exists",
        ),
        (
            "rm /home/u/l",
            "sftp_unlink",
            "rm \"/home/u/l\" failed: File already exists",
        ),
        (
            "statvfs /home/u",
            "sftp_statvfs",
            "statvfs \"/home/u\" failed: File already exists",
        ),
        (
            "chmod 600 /home/u/f",
            "sftp_setstat",
            "Attempt to set SFTP stats for \"/home/u/f\" failed: File already exists",
        ),
        (
            "chown 3 /home/u/f",
            "sftp_stat",
            "Attempt to get SFTP stats failed: File already exists",
        ),
    ] {
        let fails = |w: &mut World, fail: &'static str| {
            w.fails = vec![(fail, Code(-31))];
            w.fx = Fx::FILE_ALREADY_EXISTS;
        };
        let cmds = [cmd.to_owned()];
        let (r, _, said, calls) = over("x", URL, |w| fails(w, fail), |o| quotes(o, &[&cmds[0]]));
        assert_eq!(r, Err(ErrorKind::QuoteError), "{cmd}: {said}");
        says(&said, &[line]);
        assert!(
            !calls.iter().any(|c| c.starts_with("sftp_open")),
            "{cmd}: {calls:?}"
        );
        // Let fail.
        let starred = [format!("*{cmd}")];
        let (r, _, said, _) = over("x", URL, |w| fails(w, fail), |o| quotes(o, &[&starred[0]]));
        assert_eq!(r, Ok(()), "{cmd}: {said}");
    }
    for cmd in ["*chgrp abc /home/u/f", "*chown abc /home/u/f"] {
        let (r, _, said, _) = run(&[cmd], |_| {});
        assert_eq!(r, Ok(()), "{cmd}: {said}");
    }
}

/// What each attribute command sets: the owner's or group's number, the
/// permissions in octal, the access or modification time; all but
/// chmod's on the file's own attributes, read first.
#[test]
fn the_attribute_commands_set_what_they_name() {
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.attrs = vec![(
            b"/home/u/f".to_vec(),
            Attrs {
                flags: AttrFlags(0xf),
                filesize: 1,
                uid: 5,
                gid: 6,
                permissions: 0o100644,
                atime: 7,
                mtime: 8,
            },
        )];
    });
    let (r, _, said, calls) = run_in(&w, URL, |o| {
        quotes(
            o,
            &[
                "chgrp 9 /home/u/f",
                "chown 10 /home/u/f",
                "chmod 0751 /home/u/f",
                "atime \"Sun, 01 Jan 2023 00:00:00 GMT\" /home/u/f",
                "mtime \"Mon, 02 Jan 2023 00:00:00 GMT\" /home/u/f",
            ],
        );
    });
    assert_eq!(r, Ok(()), "{said}");
    let set: Vec<Attrs> = w.lock().unwrap().set.iter().map(|(_, a)| *a).collect();
    let stated = Attrs {
        flags: AttrFlags(0xf),
        filesize: 1,
        uid: 5,
        gid: 6,
        permissions: 0o100644,
        atime: 7,
        mtime: 8,
    };
    assert_eq!(
        set,
        [
            Attrs {
                flags: AttrFlags::UIDGID,
                gid: 9,
                ..stated
            },
            Attrs {
                flags: AttrFlags::UIDGID,
                uid: 10,
                ..stated
            },
            Attrs {
                flags: AttrFlags::PERMISSIONS,
                permissions: 0o751,
                ..Attrs::default()
            },
            Attrs {
                flags: AttrFlags::ACMODTIME,
                atime: 1_672_531_200,
                ..stated
            },
            Attrs {
                flags: AttrFlags::ACMODTIME,
                mtime: 1_672_617_600,
                ..stated
            },
        ]
    );
    let stats = calls.iter().filter(|c| *c == "sftp_stat /home/u/f").count();
    // Four commands' reads, and the download's.
    assert_eq!(stats, 5, "{calls:?}");
    // A permission past 07777 is no number.
    let (r, _, said, _) = run_in(&w, URL, |o| quotes(o, &["chmod 10000 /home/u/f"]));
    assert_eq!(r, Err(ErrorKind::QuoteError), "{said}");
}

/// `pwd` answers as FTP's does, in the header; `statvfs` gives the file
/// system's numbers there; quote commands after the transfer run once its
/// file is closed.
#[test]
fn pwd_statvfs_and_the_commands_after() {
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.statvfs = Statvfs {
            bsize: 1,
            frsize: 2,
            blocks: 3,
            bfree: 4,
            bavail: 5,
            files: 6,
            ffree: 7,
            favail: 8,
            fsid: 9,
            flag: 10,
            namemax: 11,
        };
    });
    let mut headers = Vec::new();
    let (r, _, said, calls) = {
        let text = Text::default();
        let collected = text.clone();
        let out = run_in(&w, URL, |o| {
            quotes(o, &["pwd", "statvfs /home/u"]);
            o.line
                .make_mut()
                .unwrap()
                .postquote
                .set([&b"rm /home/u/f"[..], b"PWD"])
                .unwrap();
            o.callbacks.header = Some(Handler::header(Headers(collected)).unwrap());
        });
        headers.extend_from_slice(&text.0.lock().unwrap());
        out
    };
    assert_eq!(r, Ok(()), "{said}");
    let headers = String::from_utf8(headers).unwrap();
    assert_eq!(
        headers,
        "257 \"/home/u/f\" is current directory.\n\
         statvfs:\nf_bsize: 1\nf_frsize: 2\nf_blocks: 3\nf_bfree: 4\nf_bavail: 5\n\
         f_files: 6\nf_ffree: 7\nf_favail: 8\nf_fsid: 9\nf_flag: 10\nf_namemax: 11\n\
         257 \"(nil)\" is current directory.\n"
    );
    let close = calls.iter().position(|c| c == "sftp_close").unwrap();
    let rm = calls
        .iter()
        .position(|c| c == "sftp_unlink /home/u/f")
        .unwrap();
    assert!(close < rm, "{calls:?}");
    assert_eq!(
        said.matches("SSH: sending quote commands\n").count(),
        2,
        "{said}"
    );
}

/// Collects the header lines.
struct Headers(Text);

impl crate::handler::HeaderHandler for Headers {
    fn header(
        &self,
        _: &mut TransferCx<'_>,
        line: &[u8],
        _: crate::handler::HeaderOrigin,
    ) -> Wrote {
        self.0.0.lock().unwrap().extend_from_slice(line);
        Wrote::Took(line.len())
    }
}

/// A download's range and resume point, read against the file's size as
/// C's are: the file sought to, the size announced, a point past the end
/// refused.
#[test]
fn a_download_s_range_and_resume_point() {
    use crate::options::{Resume, ResumeOffset};
    let get = |set: &dyn Fn(&mut Options)| over("0123456789", URL, |_| {}, |o| set(o));
    for (range, body, seek) in [
        ("2-4", "234", Some("2")),
        ("-3", "789", Some("7")),
        ("5-", "56789", Some("5")),
    ] {
        let (r, b, said, calls) = get(&|o| o.range = Some(range.as_bytes().to_vec()));
        assert_eq!(r, Ok(()), "{range}: {said}");
        assert_eq!(String::from_utf8(b).unwrap(), body, "{range}");
        let seeks: Vec<_> = calls
            .iter()
            .filter(|c| c.starts_with("sftp_seek"))
            .collect();
        assert_eq!(seeks, [&format!("sftp_seek {}", seek.unwrap())], "{range}");
    }
    for (range, line) in [
        ("12-", "Offset (12) was beyond file size (10)"),
        ("5-2", "Bad range: start offset larger than end offset"),
    ] {
        let (r, _, said, _) = get(&|o| o.range = Some(range.as_bytes().to_vec()));
        assert_eq!(r, Err(ErrorKind::RangeError), "{range}: {said}");
        says(&said, &[line]);
    }
    let resume =
        |n: u64| move |o: &mut Options| o.resume = Some(Resume::At(ResumeOffset::new(n).unwrap()));
    let (r, b, said, _) = get(&resume(4));
    assert_eq!((r, b), (Ok(()), b"456789".to_vec()), "{said}");
    // At the end, the range from it is empty, as C reads it.
    let (r, _, said, _) = get(&resume(10));
    assert_eq!(r, Err(ErrorKind::RangeError), "{said}");
    says(&said, &["Bad range: start offset larger than end offset"]);
    let (r, _, said, _) = get(&resume(11));
    assert_eq!(r, Err(ErrorKind::RangeError), "{said}");
    // A size not given reads to the end; one past what a `curl_off_t`
    // holds is refused.
    let sizeless = |size: u64, flags| {
        move |w: &mut World| {
            w.attrs = vec![(
                b"/home/u/f".to_vec(),
                Attrs {
                    flags,
                    filesize: size,
                    ..Attrs::default()
                },
            )];
        }
    };
    for world in [sizeless(5, AttrFlags::UIDGID), sizeless(0, AttrFlags::SIZE)] {
        let (r, b, said, _) = over("0123456789", URL, world, |_| {});
        assert_eq!((r, b), (Ok(()), b"0123456789".to_vec()), "{said}");
    }
    let (r, b, said, _) = over("0123456789", URL, sizeless(5, AttrFlags::SIZE), |_| {});
    assert_eq!((r, b), (Ok(()), b"01234".to_vec()), "{said}");
    let (r, _, said, _) = over(
        "0123456789",
        URL,
        sizeless(u64::MAX, AttrFlags::SIZE),
        |_| {},
    );
    assert_eq!(r, Err(ErrorKind::BadDownloadResume), "{said}");
    says(&said, &["Bad file size (-1)"]);
    // Stat failing reads to the end too.
    let (r, b, said, _) = over(
        "0123456789",
        URL,
        |w| w.fails = vec![("sftp_stat", Code(-31))],
        |_| {},
    );
    assert_eq!((r, b), (Ok(()), b"0123456789".to_vec()), "{said}");
    // A resume point against a size unknown is past it.
    let (r, _, said, _) = over("0123456789", URL, sizeless(5, AttrFlags::UIDGID), resume(3));
    assert_eq!(r, Err(ErrorKind::BadDownloadResume), "{said}");
    says(&said, &["Offset (3) was beyond file size (0)"]);
    let (r, _, said, _) = over("0123456789", URL, sizeless(5, AttrFlags::UIDGID), |o| {
        o.resume = Some(Resume::AtEnd)
    });
    assert_eq!(r, Err(ErrorKind::BadDownloadResume), "{said}");
    says(&said, &["Offset (-1) was beyond file size (0)"]);
    // The file not opened.
    let (r, _, said, _) = over(
        "x",
        URL,
        |w| {
            w.fails = vec![("sftp_open", Code(-31))];
            w.fx = Fx::PERMISSION_DENIED;
        },
        |_| {},
    );
    assert_eq!(r, Err(ErrorKind::RemoteAccessDenied), "{said}");
    says(
        &said,
        &["Could not open remote file for reading: Permission denied"],
    );
    // The file's time, asked for.
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.attrs = vec![(
            b"/home/u/f".to_vec(),
            Attrs {
                flags: AttrFlags(0xf),
                filesize: 1,
                mtime: 1234,
                ..Attrs::default()
            },
        )];
    });
    let (r, _, _, _) = run_in(&w, URL, |o| o.filetime = true);
    assert_eq!(r, Ok(()));
    assert_eq!(w.lock().unwrap().filetime, Some(1234));
    let w = world_with(&[("/home/u/f", "x")], |_| {});
    assert_eq!(run_in(&w, URL, |_| {}).0, Ok(()));
    assert_eq!(w.lock().unwrap().filetime, None);
}

/// An upload opens its file to truncate, to append, or, from a resume
/// point, to write past what it skips; the point at the end is the
/// stored file's size; the open's failure is said as C says it.
#[test]
fn an_upload_s_open_and_resume_point() {
    use crate::options::{Resume, ResumeOffset};
    let up = |stored: &str, set: &dyn Fn(&mut Options), world: &dyn Fn(&mut World)| {
        let w = world_with(&[("/home/u/f", stored)], |w| world(w));
        let out = run_in(&w, URL, |o| {
            uploads(o, b"abcdef");
            set(o);
        });
        let w = w.lock().unwrap();
        (out, w.files.clone(), w.opened.clone(), w.calls.clone())
    };
    let ((r, _, said, _), files, opened, _) = up("old", &|_| {}, &|_| {});
    assert_eq!(r, Ok(()), "{said}");
    assert_eq!(files, [(b"/home/u/f".to_vec(), b"abcdef".to_vec())]);
    assert_eq!(opened, [(b"/home/u/f".to_vec(), OpenMode::Truncate, 0o644)]);

    let ((r, _, said, _), files, opened, calls) =
        up("abc", &|o| o.resume = Some(Resume::AtEnd), &|_| {});
    assert_eq!(r, Ok(()), "{said}");
    assert_eq!(files, [(b"/home/u/f".to_vec(), b"abcdef".to_vec())]);
    assert_eq!(opened[0].1, OpenMode::Write);
    assert!(calls.contains(&"sftp_seek 3".to_owned()), "{calls:?}");

    let ((r, _, said, _), files, _, calls) = up(
        "abcd",
        &|o| o.resume = Some(Resume::At(ResumeOffset::new(2).unwrap())),
        &|_| {},
    );
    assert_eq!(r, Ok(()), "{said}");
    assert_eq!(files, [(b"/home/u/f".to_vec(), b"abcdcdef".to_vec())]);
    assert!(calls.contains(&"sftp_seek 2".to_owned()), "{calls:?}");

    let ((r, _, said, _), files, opened, calls) = up(
        "xy",
        &|o| o.line.make_mut().unwrap().ftp.append = true,
        &|_| {},
    );
    assert_eq!(r, Ok(()), "{said}");
    assert_eq!(opened[0].1, OpenMode::Append);
    assert_eq!(files, [(b"/home/u/f".to_vec(), b"xyabcdef".to_vec())]);
    assert!(
        !calls.iter().any(|c| c.starts_with("sftp_seek")),
        "{calls:?}"
    );

    // Appending from a resume point skips nothing and seeks nowhere.
    let ((r, _, said, _), files, opened, calls) = up(
        "abc",
        &|o| {
            o.resume = Some(Resume::AtEnd);
            o.line.make_mut().unwrap().ftp.append = true;
        },
        &|_| {},
    );
    assert_eq!(r, Ok(()), "{said}");
    assert_eq!(opened[0].1, OpenMode::Append);
    assert_eq!(files, [(b"/home/u/f".to_vec(), b"abcabcdef".to_vec())]);
    assert!(
        !calls.iter().any(|c| c.starts_with("sftp_seek")),
        "{calls:?}"
    );

    // The point at the end of a file not there is its start.
    let ((r, _, said, _), _, opened, _) = up("abc", &|o| o.resume = Some(Resume::AtEnd), &|w| {
        w.fails = vec![("sftp_stat", Code(-31))]
    });
    assert_eq!(r, Ok(()), "{said}");
    assert_eq!(opened[0].1, OpenMode::Truncate);
    let ((r, _, said, _), _, _, _) = up("abc", &|o| o.resume = Some(Resume::AtEnd), &|w| {
        w.attrs = vec![(
            b"/home/u/f".to_vec(),
            Attrs {
                flags: AttrFlags::SIZE,
                filesize: u64::MAX,
                ..Attrs::default()
            },
        )];
    });
    assert_eq!(r, Err(ErrorKind::BadDownloadResume), "{said}");
    says(&said, &["Bad file size (-1)"]);

    // The permissions asked for.
    let ((_, _, _, _), _, opened, _) = up(
        "",
        &|o| o.new_file_mode = crate::options::FileMode::new(0o600).unwrap(),
        &|_| {},
    );
    assert_eq!(opened[0].2, 0o600);

    for (code, fx, kind, line) in [
        (
            -7,
            Fx::PERMISSION_DENIED,
            ErrorKind::Ssh,
            "Upload failed: ssh error (0/-7)",
        ),
        (
            -31,
            Fx::PERMISSION_DENIED,
            ErrorKind::RemoteAccessDenied,
            "Upload failed: Permission denied (3/-31)",
        ),
        (
            -31,
            Fx::OK,
            ErrorKind::Ssh,
            "Upload failed: ssh error (0/-31)",
        ),
        (
            -31,
            Fx::FILE_ALREADY_EXISTS,
            ErrorKind::RemoteFileExists,
            "Upload failed: File already exists (11/-31)",
        ),
        // Missing, without directories to make.
        (
            -31,
            Fx::NO_SUCH_FILE,
            ErrorKind::RemoteFileNotFound,
            "Upload failed: No such file or directory (2/-31)",
        ),
    ] {
        let ((r, _, said, _), _, _, _) = up("", &|_| {}, &|w| {
            w.fails = vec![("sftp_open", Code(code))];
            w.fx = fx;
        });
        assert_eq!(r, Err(kind), "{line}: {said}");
        says(&said, &[line]);
    }
}

/// The directories an upload makes: each from the root, with the mode
/// asked for, one there already or refused passed, any other failure
/// the transfer's; a file at the root makes none.
#[test]
fn an_upload_s_directories_and_their_failures() {
    let made = |url: &str, world: &dyn Fn(&mut World)| {
        let w = world_with(&[], |w| {
            w.refuses_writes = true;
            w.fx = Fx::NO_SUCH_PATH;
            world(w);
        });
        let out = run_in(&w, url, |o| {
            uploads(o, b"x");
            o.line.make_mut().unwrap().ftp.create_dirs = CreateDirs::Create;
            o.ssh.make_mut().unwrap().new_directory_mode =
                crate::options::FileMode::new(0o700).unwrap();
        });
        let modes = w.lock().unwrap().dir_modes.clone();
        (out, modes)
    };
    let ((r, _, said, calls), modes) = made("sftp://u@127.0.0.1:PORT/a/b", &|_| {});
    assert_eq!(r, Err(ErrorKind::RemoteFileNotFound), "{said}");
    says(
        &said,
        &[
            "SFTP: creating directory '/a'",
            "Creating the dir/file failed: No such file or directory",
        ],
    );
    assert_eq!(modes, [0o700]);
    assert_eq!(
        calls.iter().filter(|c| c.starts_with("sftp_open")).count(),
        2,
        "{calls:?}"
    );

    for (fx, passed) in [
        (Fx::FILE_ALREADY_EXISTS, true),
        (Fx::FAILURE, true),
        (Fx::PERMISSION_DENIED, true),
        (Fx::NO_SPACE_ON_FILESYSTEM, false),
    ] {
        let ((r, _, said, calls), _) = made("sftp://u@127.0.0.1:PORT/a/b/c", &|w| {
            w.fails = vec![("sftp_mkdir", Code(-31))];
            w.leaves = vec![("sftp_mkdir", fx)];
        });
        let mkdirs = calls
            .iter()
            .filter(|c| c.starts_with("sftp_mkdir") || c.ends_with("sftp_mkdir"))
            .count();
        if passed {
            assert!(r.is_err(), "{said}");
            assert_eq!(mkdirs, 2, "{fx:?}: {calls:?}");
        } else {
            assert_eq!(r, Err(ErrorKind::RemoteDiskFull), "{said}");
            assert_eq!(mkdirs, 1, "{calls:?}");
        }
    }
    // A missing file's every status that makes directories.
    for fx in [Fx::NO_SUCH_FILE, Fx::FAILURE, Fx::NO_SUCH_PATH] {
        let ((_, _, _, calls), _) = made("sftp://u@127.0.0.1:PORT/a/b", &|w| w.fx = fx);
        assert!(calls.iter().any(|c| c.starts_with("sftp_mkdir")), "{fx:?}");
    }
    let ((_, _, _, calls), _) = made("sftp://u@127.0.0.1:PORT/a/b", &|w| {
        w.fx = Fx::PERMISSION_DENIED
    });
    assert!(
        !calls.iter().any(|c| c.starts_with("sftp_mkdir")),
        "{calls:?}"
    );
    // Not asked to make them.
    let w = world_with(&[], |w| {
        w.refuses_writes = true;
        w.fx = Fx::NO_SUCH_FILE;
    });
    let (_, _, _, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/a/b", |o| uploads(o, b"x"));
    assert!(
        !calls.iter().any(|c| c.starts_with("sftp_mkdir")),
        "{calls:?}"
    );
    // At the root, nothing to make.
    let ((r, _, said, calls), _) = made("sftp://u@127.0.0.1:PORT/", &|_| {});
    assert!(r.is_err(), "{said}");
    assert!(
        !calls.iter().any(|c| c.starts_with("sftp_mkdir")),
        "{calls:?}"
    );
}

/// A directory's listing: its names alone, or each `ls -l` line, a link's
/// target after it; C's words for each failure.
#[test]
fn a_directory_is_listed_as_c_lists_it() {
    let dir = |w: &mut World| {
        w.dir = vec![
            (
                b"a".to_vec(),
                b"-rw-r--r-- a".to_vec(),
                Attrs {
                    flags: AttrFlags::PERMISSIONS,
                    permissions: 0o100644,
                    ..Attrs::default()
                },
            ),
            (
                b"l".to_vec(),
                b"lrwxrwxrwx l".to_vec(),
                Attrs {
                    flags: AttrFlags::PERMISSIONS,
                    permissions: 0o120777,
                    ..Attrs::default()
                },
            ),
            // The link's bits without the flag that says they are given.
            (
                b"m".to_vec(),
                b"?--------- m".to_vec(),
                Attrs {
                    flags: AttrFlags::SIZE,
                    permissions: 0o120777,
                    ..Attrs::default()
                },
            ),
            (
                b"d".to_vec(),
                b"drwx------ d".to_vec(),
                Attrs {
                    flags: AttrFlags::PERMISSIONS,
                    permissions: 0o040700,
                    ..Attrs::default()
                },
            ),
        ];
        w.links = vec![(b"/home/u/d/l".to_vec(), b"a".to_vec())];
    };
    let url = "sftp://u@127.0.0.1:PORT/~/d/";
    let (r, b, said, calls) = over("x", url, dir, |_| {});
    assert_eq!(r, Ok(()), "{said}");
    assert_eq!(
        String::from_utf8(b).unwrap(),
        "-rw-r--r-- a\nlrwxrwxrwx l -> a\n?--------- m\ndrwx------ d\n"
    );
    assert!(
        calls.contains(&"sftp_opendir /home/u/d/".to_owned()),
        "{calls:?}"
    );
    let (r, b, said, _) = over("x", url, dir, |o| {
        o.line.make_mut().unwrap().list_only = true
    });
    assert_eq!(r, Ok(()), "{said}");
    assert_eq!(String::from_utf8(b).unwrap(), "a\nl\nm\nd\n");
    // No body: not opened.
    let (r, b, _, calls) = over("x", url, dir, |o| o.method = crate::options::Method::Head);
    assert_eq!((r, b), (Ok(()), Vec::new()));
    assert!(
        !calls.iter().any(|c| c.starts_with("sftp_opendir")),
        "{calls:?}"
    );
    // Failures.
    let (r, _, said, _) = over(
        "x",
        url,
        |w| {
            dir(w);
            w.fails = vec![("sftp_opendir", Code(-31))];
            w.fx = Fx::FAILURE;
        },
        |_| {},
    );
    assert_eq!(r, Err(ErrorKind::Ssh), "{said}");
    says(
        &said,
        &["Could not open directory for reading: Operation failed"],
    );
    for (fx, kind, line) in [
        (
            Fx::OK,
            ErrorKind::Ssh,
            "Could not open remote file for reading: Unknown error in libssh2 :: -31",
        ),
        (
            Fx::PERMISSION_DENIED,
            ErrorKind::RemoteAccessDenied,
            "Could not open remote file for reading: Permission denied :: -31",
        ),
        (
            Fx::EOF,
            ErrorKind::Ssh,
            "Could not open remote file for reading: Unknown error in libssh2 :: -31",
        ),
    ] {
        let (r, _, said, calls) = over(
            "x",
            url,
            |w| {
                dir(w);
                w.fails = vec![("sftp_readdir", Code(-31))];
                w.fx = fx;
            },
            |_| {},
        );
        assert_eq!(r, Err(kind), "{said}");
        says(&said, &[line]);
        assert!(calls.contains(&"sftp_close".to_owned()), "{calls:?}");
    }
    let (r, _, said, _) = over(
        "x",
        url,
        |w| {
            dir(w);
            w.fails = vec![("sftp_readlink", Code(-31))];
        },
        |_| {},
    );
    assert_eq!(r, Err(ErrorKind::OutOfMemory), "{said}");
}

/// SCP: the upload's channel opened at the file's size and mode, written
/// and ended in C's order; each channel call's failure said and passed
/// over; the open's failure the upload's or the download's.
#[test]
fn scp_s_channel_as_c_drives_it() {
    let url = "scp://u@127.0.0.1:PORT/home/u/up";
    let w = world_with(&[], |_| {});
    let (r, _, said, calls) = run_in(&w, url, |o| {
        uploads(o, b"scp up");
        o.new_file_mode = crate::options::FileMode::new(0o640).unwrap();
    });
    assert_eq!(r, Ok(()), "{said}");
    assert_eq!(
        w.lock().unwrap().files,
        [(b"/home/u/up".to_vec(), b"scp up".to_vec())]
    );
    let at = calls
        .iter()
        .position(|c| c.starts_with("scp_send"))
        .unwrap();
    assert_eq!(
        calls[at..at + 5],
        [
            "scp_send /home/u/up 640 6",
            "channel_send_eof",
            "channel_wait_eof",
            "channel_wait_closed",
            "channel_free"
        ]
    );
    for (fail, line) in [
        (
            "channel_send_eof",
            "Failed to send libssh2 channel EOF: -5 fake failure",
        ),
        (
            "channel_wait_eof",
            "Failed to get channel EOF: -5 fake failure",
        ),
        (
            "channel_wait_closed",
            "Channel failed to close: -5 fake failure",
        ),
        (
            "channel_free",
            "Failed to free libssh2 scp subsystem: -5 fake failure",
        ),
    ] {
        let w = world_with(&[], |w| w.fails = vec![(fail, Code(-5))]);
        let (r, _, said, _) = run_in(&w, url, |o| uploads(o, b"scp up"));
        assert_eq!(r, Ok(()), "{fail}: {said}");
        says(&said, &[line]);
    }
    for (code, kind) in [
        (-28, ErrorKind::UploadFailed),
        (-5, ErrorKind::UploadFailed),
        (-15, ErrorKind::LoginDenied),
        (-7, ErrorKind::SendError),
    ] {
        let w = world_with(&[], |w| w.fails = vec![("scp_send", Code(code))]);
        let (r, _, said, _) = run_in(&w, url, |o| uploads(o, b"scp up"));
        assert_eq!(r, Err(kind), "{code}: {said}");
        says(&said, &["fake failure"]);
    }
    for (code, kind) in [
        (-28, ErrorKind::RemoteFileNotFound),
        (-5, ErrorKind::Ssh),
        (-7, ErrorKind::SendError),
    ] {
        let w = world_with(&[("/home/u/f", "x")], |w| {
            w.fails = vec![("scp_recv", Code(code))]
        });
        let (r, _, said, _) = run_in(&w, "scp://u@127.0.0.1:PORT/home/u/f", |_| {});
        assert_eq!(r, Err(kind), "{code}: {said}");
        says(&said, &["fake failure"]);
    }
    // A download's channel is not ended, only freed.
    let w = world_with(&[("/home/u/f", "x")], |_| {});
    let (_, _, _, calls) = run_in(&w, "scp://u@127.0.0.1:PORT/home/u/f", |_| {});
    assert!(
        !calls.iter().any(|c| c.starts_with("channel_send_eof")),
        "{calls:?}"
    );
}

/// What the session is set to, and what closing says when it fails.
#[test]
fn the_session_s_settings_and_its_closing() {
    let w = world_with(&[("/home/u/f", "x")], |_| {});
    let (r, _, said, calls) = run_in(&w, URL, |o| {
        o.line.make_mut().unwrap().server_response = crate::time::TimeLimit::from_millis(2500);
        o.ssh.make_mut().unwrap().compression = true;
    });
    assert_eq!(r, Ok(()), "{said}");
    assert_eq!(w.lock().unwrap().read_timeout, Some(2));
    assert!(
        calls.contains(&"enable_compression".to_owned()),
        "{calls:?}"
    );
    let (r, _, said, calls) = over(
        "x",
        URL,
        |w| w.fails = vec![("enable_compression", Code(-5))],
        |o| {
            o.ssh.make_mut().unwrap().compression = true;
        },
    );
    assert_eq!(r, Ok(()), "{said}");
    says(&said, &["SSH: failed to enable compression for session"]);
    let _ = calls;
    let (_, _, _, calls) = over("x", URL, |_| {}, |_| {});
    assert!(
        !calls.contains(&"enable_compression".to_owned()),
        "{calls:?}"
    );
    let w = world_with(&[("/home/u/f", "x")], |_| {});
    assert_eq!(run_in(&w, URL, |_| {}).0, Ok(()));
    assert_eq!(w.lock().unwrap().read_timeout, None);

    let (r, _, said, _) = over(
        "x",
        URL,
        |w| w.fails = vec![("sftp_close", Code(-5))],
        |_| {},
    );
    assert_eq!(r, Ok(()), "{said}");
    says(&said, &["Failed to close libssh2 file: -5 fake failure"]);
    // The goodbye goes on past each failure, to the session's freeing.
    for fail in ["sftp_shutdown", "disconnect"] {
        let (r, _, said, calls) = over(
            "x",
            URL,
            |w| w.fails = vec![(fail, Code(-5))],
            |o| o.limits.reuse.forbid = true,
        );
        assert_eq!(r, Ok(()), "{said}");
        assert_eq!(
            calls.last().map(String::as_str),
            Some("session_free"),
            "{calls:?}"
        );
    }
}

/// The goodbye, done for no transfer, is said in the multi's internal
/// trace as C's debug build says it on its internal handle: the SSH
/// trace's states between `DISCONNECT starts now` and its end, and each
/// call's failure in C's words, the goodbye going on past it.
#[test]
fn the_goodbye_is_said_for_no_transfer() {
    let states = |failed: Option<(usize, &str)>| {
        let mut lines = vec![
            "* [SSH] DISCONNECT starts now",
            "* [SSH] [SSH_STOP] -> [SSH_SFTP_SHUTDOWN]",
            "* [SSH] [SSH_SFTP_SHUTDOWN] -> [SSH_SESSION_DISCONNECT]",
            "* [SSH] [SSH_SESSION_DISCONNECT] -> [SSH_SESSION_FREE]",
            "* [SSH] [SSH_SESSION_FREE] -> [SSH_STOP]",
            "* [SSH] [SSH_STOP] statemachine() -> 0, block=0",
            "* [SSH] DISCONNECT is done -> 0",
        ];
        if let Some((at, line)) = failed {
            lines.insert(at, line);
        }
        format!("{}{}\n", shutdown_said(), lines.join("\n"))
    };
    for (fail, failed) in [
        ("none", None),
        (
            "sftp_shutdown",
            Some((2, "* Failed to stop libssh2 sftp subsystem")),
        ),
        (
            "disconnect",
            Some((3, "* Failed to disconnect libssh2 session: -5 fake failure")),
        ),
        (
            "session_free",
            Some((4, "* Failed to free libssh2 session: -5 fake failure")),
        ),
    ] {
        let w = world_with(&[("/home/u/f", "x")], |w| {
            w.trace_ssh = true;
            w.fails = vec![(fail, Code(-5))];
        });
        let (r, _, said, _) = run_in(&w, URL, |o| o.limits.reuse.forbid = true);
        assert_eq!(r, Ok(()), "{said}");
        assert_eq!(w.lock().unwrap().internal.said(), states(failed), "{fail}");
        // None of it the transfer's.
        assert!(!said.contains("DISCONNECT"), "{said}");
    }
    // Kept for reuse, it closes with the multi: said there too, the SSH
    // trace off.
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.fails = vec![("disconnect", Code(-5))]
    });
    let (r, _, said, _) = run_in(&w, URL, |_| {});
    assert_eq!(r, Ok(()), "{said}");
    assert_eq!(
        w.lock().unwrap().internal.said(),
        format!(
            "{}* Failed to disconnect libssh2 session: -5 fake failure\n",
            shutdown_said()
        )
    );
}

/// The SSH trace says the pollset the session's wait asks for, its flags
/// in hex: the session's wait over the body's way, as it reads or writes;
/// nothing of one made while it asks for nothing, the multi then waiting
/// on the live session's input (`Curl_ssh_pollset`).
#[test]
fn the_ssh_trace_says_what_the_session_waits_for() {
    let said = |url: &str, dirs: (bool, bool), waiting: Vec<&'static str>, upload: bool| {
        let w = world_with(&[("/home/u/f", "x")], |w| {
            w.trace_multi = true;
            w.dirs = PollFlags {
                read: dirs.0,
                write: dirs.1,
            };
            w.waiting = waiting;
        });
        let (r, _, said, _) = run_in(&w, url, |o| {
            if upload {
                uploads(o, b"up");
            }
        });
        assert_eq!(r, Ok(()), "{said}");
        said
    };
    let polled = |said: &str| -> Vec<String> {
        said.lines()
            .filter(|l| l.contains("pollset[fd="))
            .map(str::to_owned)
            .collect()
    };
    // The handshake waits both ways: once as it connects, and again
    // once it is waited on.
    let both = said(URL, (true, true), vec!["handshake", "handshake"], false);
    assert!(both.contains("[SSH] pollset, flags=3\n"), "{both}");
    assert!(
        polled(&both)
            .iter()
            .any(|l| l.contains(" IN") && l.contains("OUT")),
        "{both}"
    );
    // A read that waits for the session to send waits to send.
    let sending = said(URL, (false, true), vec!["read", "read"], false);
    assert!(sending.contains("[SSH] pollset, flags=2\n"), "{sending}");
    assert!(!sending.contains("flags=1"), "{sending}");
    // A write that waits for the session to read waits to read.
    let reading = said(URL, (true, false), vec!["write", "write"], true);
    assert!(reading.contains("[SSH] pollset, flags=1\n"), "{reading}");
    assert!(!reading.contains("flags=2"), "{reading}");
    // A session asking for nothing: unsaid, the multi waits on its input.
    let quiet = said(URL, (false, false), vec!["handshake", "handshake"], false);
    assert!(!quiet.contains("[SSH] pollset"), "{quiet}");
    assert!(
        polled(&quiet)
            .iter()
            .any(|l| l.contains("pollset[fd=1000 IN]")),
        "{quiet}"
    );
}

/// The sizes a transfer announces, as C's: a download's of the file the
/// server stated, none if its stat fails; an upload's of its source, less
/// the point it resumes from, and none for an empty one
/// (`sftp_download_stat`, `sftp_upload_init`).
#[test]
fn the_sizes_announced_are_c_s() {
    use crate::options::{Resume, ResumeOffset};
    let sizes = |stored: &str, world: &dyn Fn(&mut World), set: &dyn Fn(&mut Options)| {
        let w = world_with(&[("/home/u/f", stored)], |w| world(w));
        let (r, _, said, calls) = run_in(&w, URL, |o| set(o));
        assert_eq!(r, Ok(()), "{said}");
        let w = w.lock().unwrap();
        (w.sizes, calls, w.files.clone())
    };
    let (s, _, _) = sizes("0123456789", &|_| {}, &|_| {});
    assert_eq!(s.0, Some(10));
    let (s, _, _) = sizes(
        "0123456789",
        &|w| w.fails = vec![("sftp_stat", Code(-31))],
        &|_| {},
    );
    assert_eq!(s.0, None);
    // An upload, from its start: no seek.
    let (s, calls, _) = sizes("old", &|_| {}, &|o| uploads(o, b"abcdef"));
    assert_eq!(s.1, Some(6));
    assert!(
        !calls.iter().any(|c| c.starts_with("sftp_seek")),
        "{calls:?}"
    );
    let (s, _, _) = sizes("old", &|_| {}, &|o| {
        uploads(o, b"abcdef");
        o.resume = Some(Resume::At(ResumeOffset::new(2).unwrap()));
    });
    assert_eq!(s.1, Some(4));
    let (s, _, _) = sizes("old", &|_| {}, &|o| uploads(o, b""));
    assert_eq!(s.1, None);
    // Resumed at the end of a file that is there and empty: from its
    // start, the file truncated.
    let (_, calls, files) = sizes(
        "",
        &|w| {
            w.attrs = vec![(
                b"/home/u/f".to_vec(),
                Attrs {
                    flags: AttrFlags::SIZE,
                    filesize: 0,
                    ..Attrs::default()
                },
            )];
        },
        &|o| {
            uploads(o, b"abc");
            o.resume = Some(Resume::AtEnd);
        },
    );
    assert_eq!(files, [(b"/home/u/f".to_vec(), b"abc".to_vec())]);
    assert!(
        !calls.iter().any(|c| c.starts_with("sftp_seek")),
        "{calls:?}"
    );
}

/// An upload's resume point at the end, its stat waiting: waited on, the
/// file then written past what it holds, from as far into the source.
#[test]
fn an_upload_s_stat_that_waits_is_made_again() {
    let w = world_with(&[("/home/u/f", "abc")], |w| w.waiting = vec!["sftp_stat"]);
    let (r, _, said, calls) = run_in(&w, URL, |o| {
        // As much of the source skipped as the file holds.
        uploads(o, b"abcdef");
        o.resume = Some(crate::options::Resume::AtEnd);
    });
    assert_eq!(r, Ok(()), "{said}");
    let w = w.lock().unwrap();
    assert_eq!(w.opened[0].1, OpenMode::Write, "{calls:?}");
    assert_eq!(
        w.files,
        [(b"/home/u/f".to_vec(), b"abcdef".to_vec())],
        "{calls:?}\n{said}"
    );
}

/// A file's time whose stat fails is unknown, the download going on.
#[test]
fn a_file_time_not_stated_is_unknown() {
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.attrs = vec![(
            b"/home/u/f".to_vec(),
            Attrs {
                flags: AttrFlags(0xf),
                filesize: 1,
                mtime: 1234,
                ..Attrs::default()
            },
        )];
        w.fails = vec![("sftp_stat", Code(-31))];
    });
    let (r, b, said, calls) = run_in(&w, URL, |o| o.filetime = true);
    assert_eq!((r, b), (Ok(()), b"x".to_vec()), "{said}");
    assert_eq!(w.lock().unwrap().filetime, None);
    assert_eq!(
        calls.iter().filter(|c| *c == "sftp_stat /home/u/f").count(),
        1,
        "{calls:?}"
    );
}

/// An upload to the root that the server refuses is refused as any, no
/// directory to make for it.
#[test]
fn an_upload_to_the_root_makes_no_directory() {
    let w = world_with(&[], |w| {
        w.refuses_writes = true;
        w.fx = Fx::NO_SUCH_FILE;
    });
    let (r, _, said, calls) = run_in(&w, "sftp://u@127.0.0.1:PORT/", |o| {
        uploads(o, b"x");
        o.line.make_mut().unwrap().ftp.create_dirs = CreateDirs::Create;
    });
    assert_eq!(r, Err(ErrorKind::RemoteFileNotFound), "{said}");
    says(&said, &["Upload failed: No such file or directory (2/-31)"]);
    assert_eq!(
        calls.iter().filter(|c| c.starts_with("sftp_open")).count(),
        1,
        "{calls:?}"
    );
}

/// A date past what 32 bits hold is refused where a `long` is 32 bits
/// (Windows), as C's is, and set elsewhere.
#[test]
fn a_late_date_is_refused_only_where_a_long_cannot_hold_it() {
    let (r, _, said, _) = over(
        "x",
        URL,
        |_| {},
        |o| {
            quotes(o, &["mtime \"Sat, 01 Jan 2107 00:00:00 GMT\" /home/u/f"]);
        },
    );
    if size_of::<std::ffi::c_long>() < size_of::<i64>() {
        assert_eq!(r, Err(ErrorKind::QuoteError), "{said}");
        says(&said, &["date overflow"]);
    } else {
        assert_eq!(r, Ok(()), "{said}");
    }
}

/// An upload's write failing fails it with the session's failure, as C's
/// `sftp_send` and `scp_send` map it; a read callback's abort is the
/// abort.
#[test]
fn an_upload_s_failures_are_c_s() {
    for url in [URL, "scp://u@127.0.0.1:PORT/home/u/up"] {
        let w = world_with(&[], |w| w.fails = vec![("write", Code(-1))]);
        let (r, _, said, _) = run_in(&w, url, |o| uploads(o, b"abc"));
        assert_eq!(r, Err(ErrorKind::CouldntConnect), "{url}: {said}");
    }
    struct Aborts;
    impl crate::handler::ReadHandler for Aborts {
        fn read(&self, _: &mut TransferCx<'_>, _: &mut [u8]) -> crate::handler::Read {
            crate::handler::Read::Abort
        }
    }
    let w = world_with(&[], |_| {});
    let (r, _, said, _) = run_in(&w, URL, |o| {
        o.method = crate::options::Method::Upload;
        o.upload = crate::options::UploadSource::Read {
            handler: Handler::read(Aborts).unwrap(),
            rewind: None,
            size: Some(3),
        };
    });
    assert_eq!(r, Err(ErrorKind::AbortedByCallback), "{said}");
}

/// Host-based login is tried only if the user may and the server offers
/// it, and goes straight on to the agent's (`SSH_AUTH_HOST`).
#[test]
fn host_based_login_is_visited_only_when_offered_and_allowed() {
    use crate::options::SshAuthTypes;
    let states = |authlist: &[u8], types: SshAuthTypes| {
        let authlist = authlist.to_vec();
        let w = world_with(&[("/home/u/f", "x")], move |w| {
            w.trace_ssh = true;
            w.authlist = Some(authlist);
            w.fails = vec![
                ("auth_publickey_fromfile", Code(-18)),
                ("auth_password", Code(-18)),
            ];
        });
        let (_, _, said, _) = run_in(&w, URL, |o| o.ssh.make_mut().unwrap().auth_types = types);
        said
    };
    let all = SshAuthTypes::ANY;
    let no_host = SshAuthTypes::from_bits(!0x04);
    for said in [
        states(b"publickey,password,keyboard-interactive", all),
        states(
            b"publickey,password,hostbased,keyboard-interactive",
            no_host,
        ),
    ] {
        says(
            &said,
            &["[SSH] [SSH_AUTH_HOST_INIT] -> [SSH_AUTH_AGENT_INIT]"],
        );
        assert!(!said.contains("[SSH_AUTH_HOST]"), "{said}");
    }
    let said = states(b"publickey,password,hostbased,keyboard-interactive", all);
    says(
        &said,
        &[
            "[SSH] [SSH_AUTH_HOST_INIT] -> [SSH_AUTH_HOST]",
            "[SSH] [SSH_AUTH_HOST] -> [SSH_AUTH_AGENT_INIT]",
        ],
    );
}

/// The goodbye waits on a session that keeps waiting a second at most,
/// then frees it all, blocking, each failure said.
#[test]
fn the_goodbye_waits_a_second_at_most() {
    let w = world_with(&[("/home/u/f", "x")], |w| w.stuck = vec!["disconnect"]);
    let (r, _, said, calls) = run_in(&w, URL, |o| o.limits.reuse.forbid = true);
    assert_eq!(r, Ok(()), "{said}");
    // Each wait a quarter of a second: given up on past the second.
    let disconnects: Vec<_> = calls.iter().filter(|c| c.ends_with("disconnect")).collect();
    assert_eq!(disconnects, ["waits disconnect"; 5], "{calls:?}");
    assert_eq!(
        calls.last().map(String::as_str),
        Some("session_free"),
        "{calls:?}"
    );
    assert_eq!(
        w.lock().unwrap().internal.said(),
        format!("{}* Disconnect timed out\n", shutdown_said())
    );
}

/// A broken SCP download's channel, still open as the connection closes,
/// is freed by the goodbye, its wait waited on.
#[test]
fn a_channel_left_open_is_freed_by_the_goodbye() {
    struct Fails;
    impl WriteHandler for Fails {
        fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Wrote {
            Wrote::Fail
        }
    }
    let w = world_with(&[("/home/u/f", "x")], |w| w.waiting = vec!["channel_free"]);
    let (r, _, said, calls) = run_in(&w, "scp://u@127.0.0.1:PORT/home/u/f", |o| {
        o.callbacks.write = Some(Handler::write(Fails).unwrap());
        o.limits.reuse.forbid = true;
    });
    assert_eq!(r, Err(ErrorKind::WriteError), "{said}");
    let at = calls
        .iter()
        .position(|c| c == "waits channel_free")
        .expect("waited");
    assert_eq!(
        calls[at..],
        [
            "waits channel_free",
            "channel_free",
            "disconnect",
            "session_free"
        ]
    );
    let internal = w.lock().unwrap().internal.said();
    assert!(!internal.contains("scp subsystem"), "{internal}");
}

/// A body's read failing fails the download with the session's failure,
/// as C's `sftp_recv` and `scp_recv` map it.
#[test]
fn a_read_that_fails_fails_the_download() {
    for url in [URL, "scp://u@127.0.0.1:PORT/home/u/f"] {
        let w = world_with(&[("/home/u/f", "body")], |w| {
            w.fails = vec![("read", Code(-7))]
        });
        let (r, b, said, _) = run_in(&w, url, |_| {});
        assert_eq!(
            (r, b),
            (Err(ErrorKind::SendError), Vec::new()),
            "{url}: {said}"
        );
    }
}

/// A write callback that fails, breaking a download midway.
struct Fails;

impl WriteHandler for Fails {
    fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Wrote {
        Wrote::Fail
    }
}

/// Past its second, the goodbye frees what is still open blocking, as
/// C's `sshc_cleanup` does as it disconnects: each call that waits let go
/// of, said with its wait's number, and the rest freed after it.
#[test]
fn the_goodbye_frees_all_past_its_deadline() {
    let goodbye = |url: &str, stuck: &'static str, broken: bool| {
        let w = world_with(&[("/home/u/f", "x")], |w| w.stuck = vec![stuck]);
        let (_, _, said, calls) = run_in(&w, url, |o| {
            o.limits.reuse.forbid = true;
            if broken {
                o.callbacks.write = Some(Handler::write(Fails).unwrap());
            }
        });
        let internal = w.lock().unwrap().internal.said();
        (calls, internal, said)
    };
    for (url, stuck, broken, line, after) in [
        (
            URL,
            "sftp_close",
            true,
            "* Failed to close libssh2 file: -37 ",
            &["sftp_shutdown", "session_free"][..],
        ),
        (
            "scp://u@127.0.0.1:PORT/home/u/f",
            "channel_free",
            true,
            "* Failed to free libssh2 scp subsystem: -37 ",
            &["session_free"][..],
        ),
        (
            URL,
            "sftp_shutdown",
            false,
            "* Failed to stop libssh2 sftp subsystem: -37 ",
            &["session_free"][..],
        ),
    ] {
        let (calls, internal, said) = goodbye(url, stuck, broken);
        assert!(
            internal.contains("* Disconnect timed out\n"),
            "{stuck}: {internal}"
        );
        let timed_out = internal.find("Disconnect timed out").unwrap();
        assert!(
            internal[timed_out..].contains(line),
            "{stuck}: {internal}\n{said}"
        );
        let last = calls
            .iter()
            .rposition(|c| *c == format!("waits {stuck}"))
            .unwrap();
        assert_eq!(calls[last + 1..], *after, "{stuck}: {calls:?}");
    }
}

/// The agent the login used is let go of as the session is freed, a
/// failure said and passed, not taken for a wait.
#[test]
fn the_agent_is_let_go_of_as_the_session_is_freed() {
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.fails = vec![
            ("auth_publickey_fromfile", Code(-18)),
            ("auth_password", Code(-18)),
            ("agent_disconnect", Code(-5)),
        ];
        w.agent = Some(vec![(b"one".to_vec(), true)]);
    });
    let (r, _, said, calls) = run_in(&w, URL, |o| o.limits.reuse.forbid = true);
    assert_eq!(r, Ok(()), "{said}");
    let freeing: Vec<_> = calls.iter().skip_while(|c| *c != "disconnect").collect();
    assert_eq!(
        freeing,
        ["disconnect", "fails agent_disconnect", "session_free"],
        "{calls:?}"
    );
    let internal = w.lock().unwrap().internal.said();
    assert!(
        internal.contains("* Failed to disconnect from libssh2 agent: -5 fake failure\n"),
        "{internal}"
    );
}

/// A broken SCP download's channel failing to be freed by the goodbye is
/// said and passed, the goodbye going on.
#[test]
fn a_channel_that_fails_to_be_freed_is_passed() {
    let w = world_with(&[("/home/u/f", "x")], |w| {
        w.fails = vec![("channel_free", Code(-5))]
    });
    let (r, _, said, calls) = run_in(&w, "scp://u@127.0.0.1:PORT/home/u/f", |o| {
        o.callbacks.write = Some(Handler::write(Fails).unwrap());
        o.limits.reuse.forbid = true;
    });
    assert_eq!(r, Err(ErrorKind::WriteError), "{said}");
    let at = calls
        .iter()
        .position(|c| c == "fails channel_free")
        .expect("tried");
    assert_eq!(
        calls[at..],
        ["fails channel_free", "disconnect", "session_free"]
    );
    let internal = w.lock().unwrap().internal.said();
    assert!(
        internal.contains("* Failed to free libssh2 scp subsystem: -5 fake failure\n"),
        "{internal}"
    );
}

/// A body longer than a step reads at most a step's reads at a time, the
/// rest left for the next step, which the multi says (`sendrecv_dl`).
#[test]
fn a_long_body_is_read_a_step_s_reads_at_a_time() {
    let long = "x".repeat(11 * 1024 + 1);
    let w = world_with(&[("/home/u/f", &long)], |w| w.trace_multi = true);
    let (r, b, said, _) = run_in(&w, URL, |o| {
        o.limits.buffer_size = crate::options::BufferSize::clamped(1024);
    });
    assert_eq!(r, Ok(()), "{said}");
    assert_eq!(b.len(), long.len());
    assert!(
        said.contains("sendrecv_dl() no EAGAIN/pending data, mark as dirty"),
        "{said}"
    );
}

/// A download that failed runs no commands after it: C's `sftp_done`
/// runs them only for a transfer that went well.
#[test]
fn a_failed_download_runs_no_commands_after_it() {
    let w = world_with(&[("/home/u/f", "x")], |_| {});
    let (r, _, said, calls) = run_in(&w, URL, |o| {
        o.callbacks.write = Some(Handler::write(Fails).unwrap());
        o.line
            .make_mut()
            .unwrap()
            .postquote
            .set([&b"rm /home/u/f"[..]])
            .unwrap();
    });
    assert_eq!(r, Err(ErrorKind::WriteError), "{said}");
    assert!(
        !calls.iter().any(|c| c.starts_with("sftp_unlink")),
        "{calls:?}"
    );
}
