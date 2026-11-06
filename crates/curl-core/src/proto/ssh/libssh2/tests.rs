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
use crate::ssh2::{DirEntry, Failed, KnownEntry, Ssh2, Statvfs};
use crate::time::ManualClock;
use curl_alloc::OutOfMemory;
use curl_os::socket::BorrowedSocket;

const PORT: u16 = 8022;
const HOME: &[u8] = b"/home/u";
const HOST_KEY: &[u8] = b"the server's key";

/// What the fake server holds, and what it was asked.
#[derive(Debug, Default)]
struct World {
    files: Vec<(Vec<u8>, Vec<u8>)>,
    /// Each call the state machine made, in order.
    calls: Vec<String>,
    /// The known-hosts collection's entries, and the type of the key the
    /// collection holds for the server.
    known: Vec<KnownEntry>,
    known_kind: Option<KnownKeyType>,
    /// The calls, by name, whose first answer is to wait.
    waiting: Vec<&'static str>,
    /// Every file opened to write is refused as missing.
    refuses_writes: bool,
    /// Each attribute set, by path.
    set: Vec<(Vec<u8>, Attrs)>,
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
        let at = self.waiting.iter().position(|&n| n == name);
        if let Some(at) = at {
            self.waiting.remove(at);
            self.call("waits", &[name.as_bytes()]);
        }
        at.is_some()
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
            channel: false,
            session: true,
            home: HOME.to_vec(),
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
    channel: bool,
    session: bool,
    home: Vec<u8>,
}

impl FakeSession {
    fn w(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    /// `name`'s call: a wait the first time the world says so.
    fn called(&self, name: &'static str, args: &[&[u8]]) -> Result<(), Code> {
        let mut w = self.w();
        if w.waits(name) {
            return Err(Code::EAGAIN);
        }
        w.call(name, args);
        Ok(())
    }
}

impl Session2 for FakeSession {
    fn set_read_timeout(&mut self, _: i64) {}
    fn enable_compression(&mut self) -> Result<(), Code> {
        Ok(())
    }
    fn set_blocking(&mut self, _: Blocking) {}
    fn set_hostkey_methods(&mut self, prefs: &[u8]) -> Result<(), Code> {
        self.called("set_hostkey_methods", &[prefs])
    }
    fn last_error(&self) -> (Code, Vec<u8>) {
        (Code(-31), b"fake failure".to_vec())
    }
    fn last_errno(&self) -> Code {
        Code::NONE
    }
    fn block_directions(&self) -> PollFlags {
        PollFlags {
            read: true,
            write: false,
        }
    }
    fn knownhost_init(&mut self) -> Result<(), Failed> {
        self.kh = true;
        Ok(())
    }
    fn has_knownhosts(&self) -> bool {
        self.kh
    }
    fn knownhost_readfile(&mut self, file: &[u8]) -> Result<(), Code> {
        self.called("knownhost_readfile", &[file])
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
        Ok(match w.known_kind {
            Some(k) if k == kind => (Check::Match, Some(b"QUFBQQ==".to_vec())),
            Some(_) => (Check::Mismatch, Some(b"QUFBQQ==".to_vec())),
            None => (Check::NotFound, None),
        })
    }
    fn knownhost_del_found(&mut self) {}
    fn knownhost_add(&mut self, host: &[u8], _: &[u8], _: KnownKeyType) -> Result<(), Code> {
        self.called("knownhost_add", &[host])
    }
    fn knownhost_writefile(&mut self, file: &[u8]) -> Result<(), Code> {
        self.called("knownhost_writefile", &[file])
    }
    fn knownhost_free(&mut self) {
        self.kh = false;
    }
    fn handshake(&mut self, _: Option<BorrowedSocket<'_>>) -> Result<(), Code> {
        self.called("handshake", &[])
    }
    fn host_key(&self) -> Option<(&[u8], HostKeyType)> {
        Some((HOST_KEY, HostKeyType::Ed25519))
    }
    fn host_key_sha256(&self) -> Option<[u8; 32]> {
        Some([7; 32])
    }
    fn host_key_md5(&self) -> Option<[u8; 16]> {
        Some([7; 16])
    }
    fn userauth_list(&mut self, user: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
        self.w().call("userauth_list", &[user]);
        Ok(Some(b"publickey,password".to_vec()))
    }
    fn authenticated(&self) -> bool {
        false
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
    fn auth_password(&mut self, user: &[u8], _: &[u8]) -> Result<(), Code> {
        self.called("auth_password", &[user])
    }
    fn auth_keyboard_interactive(&mut self, _: &[u8], _: &[u8]) -> Result<(), Code> {
        Err(Code(-18))
    }
    fn agent_init(&mut self) -> Result<(), Failed> {
        Err(Failed)
    }
    fn has_agent(&self) -> bool {
        false
    }
    fn agent_connect(&mut self) -> Result<(), Code> {
        Err(Code(-42))
    }
    fn agent_list_identities(&mut self) -> Result<(), Code> {
        Err(Code(-42))
    }
    fn agent_rewind(&mut self) {}
    fn agent_get_identity(&mut self) -> Result<Identity, Code> {
        Ok(Identity::End)
    }
    fn agent_comment(&self) -> &[u8] {
        b""
    }
    fn agent_userauth(&mut self, _: &[u8]) -> Result<(), Code> {
        Err(Code(-18))
    }
    fn agent_skip(&mut self) {}
    fn agent_disconnect(&mut self) -> Result<(), Code> {
        Ok(())
    }
    fn agent_free(&mut self) {}
    fn sftp_init(&mut self) -> Result<(), Code> {
        self.called("sftp_init", &[])?;
        self.sftp = true;
        Ok(())
    }
    fn has_sftp(&self) -> bool {
        self.sftp
    }
    fn sftp_last_error(&self) -> Fx {
        Fx::NO_SUCH_FILE
    }
    fn sftp_realpath(&mut self, path: &[u8]) -> Result<&[u8], Code> {
        self.called("sftp_realpath", &[path])?;
        Ok(&self.home)
    }
    fn sftp_open(&mut self, path: &[u8], mode: OpenMode, _: u32) -> Result<(), Code> {
        self.called("sftp_open", &[path])?;
        let mut w = self.w();
        if mode == OpenMode::Read {
            let at = w.files.iter().position(|(p, _)| p == path);
            drop(w);
            let at = at.ok_or(Code::SFTP_PROTOCOL)?;
            self.file = Some((at, 0));
        } else if w.refuses_writes {
            return Err(Code::SFTP_PROTOCOL);
        } else {
            w.files.retain(|(p, _)| p != path);
            w.files.push((path.to_vec(), Vec::new()));
            drop(w);
            self.writing = Some(path.to_vec());
        }
        Ok(())
    }
    fn sftp_opendir(&mut self, path: &[u8]) -> Result<(), Code> {
        self.called("sftp_opendir", &[path])
    }
    fn has_handle(&self) -> bool {
        self.file.is_some() || self.writing.is_some()
    }
    fn sftp_stat(&mut self, path: &[u8]) -> Result<Attrs, Code> {
        self.called("sftp_stat", &[path])?;
        let w = self.w();
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
    fn sftp_seek(&mut self, _: u64) {}
    fn sftp_readdir(&mut self) -> Result<Option<DirEntry<'_>>, Code> {
        Ok(None)
    }
    fn sftp_readlink(&mut self, _: &[u8]) -> Result<&[u8], Code> {
        Err(Code::SFTP_PROTOCOL)
    }
    fn sftp_symlink(&mut self, path: &[u8], target: &[u8]) -> Result<(), Code> {
        self.called("sftp_symlink", &[path, target])
    }
    fn sftp_mkdir(&mut self, path: &[u8], _: u32) -> Result<(), Code> {
        self.called("sftp_mkdir", &[path])
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
        Ok(Statvfs::default())
    }
    fn sftp_read(&mut self, buf: &mut [u8]) -> Result<usize, Code> {
        let (at, pos) = self.file.expect("a file open to read");
        let w = self.w();
        let bytes = &w.files[at].1[pos..];
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        drop(w);
        self.file = Some((at, pos + n));
        Ok(n)
    }
    fn sftp_write(&mut self, bytes: &[u8]) -> Result<usize, Code> {
        let path = self.writing.clone().expect("a file open to write");
        let mut w = self.w();
        let file = w.files.iter_mut().find(|(p, _)| *p == path).unwrap();
        file.1.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn sftp_close(&mut self, _: Let) -> Result<(), Code> {
        self.called("sftp_close", &[])?;
        self.file = None;
        self.writing = None;
        Ok(())
    }
    fn sftp_shutdown(&mut self, _: Let) -> Result<(), Code> {
        self.called("sftp_shutdown", &[])?;
        self.sftp = false;
        Ok(())
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
    fn scp_send(&mut self, path: &[u8], _: u32, _: i64) -> Result<(), Code> {
        self.called("scp_send", &[path])?;
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
        Ok(bytes.len())
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
    fn channel_free(&mut self, _: Let) -> Result<(), Code> {
        self.called("channel_free", &[])?;
        self.channel = false;
        self.file = None;
        Ok(())
    }
    fn disconnect(&mut self) -> Result<(), Code> {
        self.called("disconnect", &[])
    }
    fn has_session(&self) -> bool {
        self.session
    }
    fn session_free(&mut self, _: Let) -> Result<(), Code> {
        self.called("session_free", &[])?;
        self.session = false;
        Ok(())
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

impl DebugHandler for Text {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::Text {
            self.0.lock().unwrap().extend_from_slice(data);
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
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Net::Accepts)
        .with_conversation(at, Conversation::replies(&[], false));
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let ssh: &'static FakeSsh2 = Box::leak(Box::new(FakeSsh2(w.clone())));
    let mut e = Easy::new();
    e.set_libraries(
        SharedLibraries::new(Libraries {
            ssh: Some(SshLibrary::Libssh2(ssh)),
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
    o.callbacks.write = Some(Handler::write(body.clone()).unwrap());
    o.callbacks.debug = Some(Handler::debug(text.clone()).unwrap());
    let ssh = o.ssh.make_mut().unwrap();
    ssh.private_key = Some(b"/keys/id".to_vec());
    ssh.public_key = Some(b"/keys/id.pub".to_vec());
    set(o);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    m.remove(id, &mut NoEvents).unwrap();
    drop(m);
    let calls = w.lock().unwrap().calls.clone();
    let body = body.0.lock().unwrap().clone();
    let said = String::from_utf8_lossy(&text.0.lock().unwrap()).into_owned();
    (result, body, said, calls)
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
