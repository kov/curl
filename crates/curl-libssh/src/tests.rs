use super::*;
use std::io::{Read as _, Write as _};
use std::mem::{offset_of, size_of};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};

/// The values and layouts `sys.rs` declares are the headers', in
/// `csrc/layout.c`'s order: a value or field out of step reads or writes
/// the wrong bytes, which no other test would see.
#[test]
fn the_declarations_are_the_headers() {
    use sys::*;
    type A = sftp_attributes_struct;
    type K = ssh_knownhosts_entry;
    let ours: [i64; LAYOUT_LEN] = [
        SSH_OK.into(),
        SSH_ERROR.into(),
        SSH_AGAIN.into(),
        SSH_AUTH_SUCCESS.into(),
        SSH_AUTH_DENIED.into(),
        SSH_AUTH_PARTIAL.into(),
        SSH_AUTH_INFO.into(),
        SSH_AUTH_AGAIN.into(),
        SSH_AUTH_ERROR.into(),
        SSH_OPTIONS_HOST.into(),
        SSH_OPTIONS_PORT.into(),
        SSH_OPTIONS_FD.into(),
        SSH_OPTIONS_USER.into(),
        SSH_OPTIONS_KNOWNHOSTS.into(),
        SSH_OPTIONS_COMPRESSION.into(),
        SSH_OPTIONS_GLOBAL_KNOWNHOSTS.into(),
        SSH_READ_PENDING.into(),
        SSH_WRITE_PENDING.into(),
        SSH_KNOWN_HOSTS_ERROR.into(),
        SSH_KNOWN_HOSTS_NOT_FOUND.into(),
        SSH_KNOWN_HOSTS_UNKNOWN.into(),
        SSH_KNOWN_HOSTS_OK.into(),
        SSH_KNOWN_HOSTS_CHANGED.into(),
        SSH_KNOWN_HOSTS_OTHER.into(),
        SSH_KEYTYPE_DSS.into(),
        SSH_KEYTYPE_RSA.into(),
        SSH_KEYTYPE_RSA1.into(),
        SSH_KEYTYPE_ECDSA.into(),
        SSH_KEYTYPE_ED25519.into(),
        SSH_KEYTYPE_ECDSA_P256.into(),
        SSH_KEYTYPE_ECDSA_P384.into(),
        SSH_KEYTYPE_ECDSA_P521.into(),
        SSH_PUBLICKEY_HASH_MD5.into(),
        SSH_PUBLICKEY_HASH_SHA256.into(),
        SSH_SCP_WRITE.into(),
        SSH_SCP_READ.into(),
        SSH_SCP_REQUEST_NEWFILE.into(),
        O_RDONLY.into(),
        O_WRONLY.into(),
        O_CREAT.into(),
        O_TRUNC.into(),
        O_APPEND.into(),
        SSH_FILEXFER_ATTR_UIDGID.into(),
        SSH_FILEXFER_ATTR_PERMISSIONS.into(),
        SSH_FILEXFER_ATTR_ACMODTIME.into(),
        size_of::<A>() as i64,
        offset_of!(A, name) as i64,
        offset_of!(A, longname) as i64,
        offset_of!(A, flags) as i64,
        offset_of!(A, r#type) as i64,
        offset_of!(A, size) as i64,
        offset_of!(A, uid) as i64,
        offset_of!(A, gid) as i64,
        offset_of!(A, owner) as i64,
        offset_of!(A, group) as i64,
        offset_of!(A, permissions) as i64,
        offset_of!(A, atime64) as i64,
        offset_of!(A, atime) as i64,
        offset_of!(A, atime_nseconds) as i64,
        offset_of!(A, createtime) as i64,
        offset_of!(A, createtime_nseconds) as i64,
        offset_of!(A, mtime64) as i64,
        offset_of!(A, mtime) as i64,
        offset_of!(A, mtime_nseconds) as i64,
        offset_of!(A, acl) as i64,
        offset_of!(A, extended_count) as i64,
        offset_of!(A, extended_type) as i64,
        offset_of!(A, extended_data) as i64,
        size_of::<K>() as i64,
        offset_of!(K, hostname) as i64,
        offset_of!(K, unparsed) as i64,
        offset_of!(K, publickey) as i64,
        offset_of!(K, comment) as i64,
        size_of::<mode_t>() as i64,
        SSH_FILEXFER_ATTR_SIZE.into(),
    ];
    // SAFETY: a table of `LAYOUT_LEN` numbers C defines, read only.
    let theirs = unsafe { curl_libssh_values };
    for (i, (o, t)) in ours.iter().zip(theirs.iter()).enumerate() {
        assert_eq!(o, t, "entry {i} of csrc/layout.c");
    }
}

/// The version is libssh's own words, its number first.
#[test]
fn the_version_is_libssh_s() {
    let v = version();
    assert!(v.starts_with("0."), "{v}");
}

/// libssh failing to look the peer up (no host to look up) is its error,
/// which C takes as a key missing, not a state it does not know, which C
/// takes as a key mismatched.
#[test]
fn a_failed_known_hosts_lookup_is_an_error() {
    let mut session = LIBSSH.session().expect("a session");
    assert_eq!(session.known_host(), (KnownHosts::Error, None));
}

/// A setting with a NUL inside is refused before libssh is asked; one
/// libssh takes is taken.
#[test]
fn settings_are_given_as_c_strings() {
    let mut session = LIBSSH.session().expect("a session");
    assert_eq!(session.set_host(b"a\0b"), Err(Refused));
    assert_eq!(session.set_host(b"example.com"), Ok(()));
    assert_eq!(session.set_port(2222), Ok(()));
    assert_eq!(session.set_compression(), Ok(()));
    assert_eq!(session.set_user(b"someone"), Ok(()));
    assert_eq!(session.set_user(b"some\0one"), Err(Refused));
    assert_eq!(session.set_known_hosts(b"/k\0h"), Err(Refused));
    assert!(!session.has_pubkey());
    assert_eq!(
        session.import_pubkey_file(b"/nonexistent/key.pub"),
        Err(Refused)
    );
    assert!(!session.has_pubkey());
}

/// Whether `fd` is open.
fn is_open(fd: i32) -> bool {
    // SAFETY: a descriptor number, only asked about (`F_GETFD`).
    unsafe { sys::fcntl(fd, 1) >= 0 }
}

/// A connected pair, the second end's reads given up after ten seconds.
/// The time is set as the pair is made: macOS refuses it (`EINVAL`) on a
/// socket shut down for writing whose peer has closed.
fn pair() -> (UnixStream, UnixStream) {
    let (ours, theirs) = UnixStream::pair().unwrap();
    theirs
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    (ours, theirs)
}

/// Read `peer`, an end `pair` made, to its end: it ends once no copy of
/// the other end is open, within ten seconds.
fn read_to_end(peer: &mut UnixStream) {
    let mut sink = Vec::new();
    peer.read_to_end(&mut sink).unwrap();
}

/// A connect that fails on what the peer says closes libssh's copy of
/// the socket, and leaves the connection's open: once that is closed, the
/// peer sees the end.
#[test]
fn a_failed_connect_leaves_the_connection_s_socket() {
    let (ours, mut theirs) = pair();
    theirs.write_all(b"no banner\r\n").unwrap();
    theirs.shutdown(std::net::Shutdown::Write).unwrap();
    let mut session = LIBSSH.session().expect("a session");
    session.set_host(b"localhost").unwrap();
    session.set_socket(Some(ours.as_fd())).unwrap();
    session.set_blocking(Blocking::Yes);
    assert_eq!(session.connect(), Rc::Error);
    let said = session.error().unwrap();
    assert!(said.len() > 1 && !said.contains(&0), "the failure is said");
    assert!(said.is_ascii(), "{said:?}");
    session.disconnect();
    drop(session);
    assert!(is_open(ours.as_raw_fd()));
    drop(ours);
    read_to_end(&mut theirs);
}

/// A socket with no descriptor is one libssh cannot be handed.
#[test]
fn a_socket_without_a_descriptor_is_refused() {
    let mut session = LIBSSH.session().expect("a session");
    assert_eq!(session.set_socket(None), Err(Refused));
}

/// A session never connected closes its copy as it is freed.
#[test]
fn a_session_never_connected_closes_its_copy() {
    let (ours, mut theirs) = pair();
    let mut session = LIBSSH.session().expect("a session");
    session.set_socket(Some(ours.as_fd())).unwrap();
    drop(session);
    drop(ours);
    read_to_end(&mut theirs);
}

/// An `sshd` in inetd mode over a socket pair, and the keys it is set
/// up with, in a directory of their own.
struct Sshd {
    child: Child,
    dir: std::path::PathBuf,
}

impl Sshd {
    /// One serving the peer of the end it gives.
    fn serving() -> (Sshd, UnixStream) {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("curl-libssh-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for key in ["host", "user"] {
            let made = Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(dir.join(key))
                .status()
                .expect("ssh-keygen, which the SSH tests need");
            assert!(made.success());
        }
        let (ours, theirs) = UnixStream::pair().unwrap();
        let theirs = OwnedFd::from(theirs);
        let child = Command::new("/usr/sbin/sshd")
            .arg("-i")
            .args(["-f", "/dev/null", "-h"])
            .arg(dir.join("host"))
            .arg("-o")
            .arg(format!(
                "AuthorizedKeysFile={}",
                dir.join("user.pub").display()
            ))
            .args(["-o", "StrictModes=no", "-o", "PidFile=none"])
            .args(["-o", "Subsystem=sftp /usr/libexec/openssh/sftp-server"])
            .stdin(Stdio::from(theirs.try_clone().unwrap()))
            .stdout(Stdio::from(theirs))
            .stderr(Stdio::null())
            .spawn()
            .expect("/usr/sbin/sshd, which the SSH tests need");
        (Sshd { child, dir }, ours)
    }

    /// A session logged in over `ours`.
    fn session(&self, ours: &UnixStream) -> Box<dyn Session> {
        let mut session = LIBSSH.session().expect("a session");
        session.set_host(b"localhost").unwrap();
        session.set_socket(Some(ours.as_fd())).unwrap();
        session
            .set_user(std::env::var("USER").unwrap().as_bytes())
            .unwrap();
        session.set_blocking(Blocking::Yes);
        assert_eq!(session.connect(), Rc::Ok);
        assert_eq!(session.auth_none(), Auth::Denied);
        assert!(session.auth_list().has(Methods::PUBLICKEY));
        let public = self.dir.join("user.pub");
        assert!(!session.has_pubkey());
        session
            .import_pubkey_file(public.to_str().unwrap().as_bytes())
            .unwrap();
        assert!(session.has_pubkey());
        let key = self.dir.join("user");
        let key = key.to_str().unwrap().as_bytes();
        assert_eq!(session.import_privkey_file(key, None), Rc::Ok);
        assert_eq!(session.auth_publickey(), Auth::Success);
        session
    }

    /// It ends, as the last copy of the other end closes, within ten
    /// seconds: one copy left open keeps it waiting.
    fn ends(mut self) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while self.child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() > deadline {
                self.child.kill().unwrap();
                panic!("sshd still waits: a copy of the socket is open");
            }
            std::thread::yield_now();
        }
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

/// A session that said its goodbye lets go of its socket open, and closes
/// its copy as it is freed: the server sees the end once the connection
/// closes its own.
#[test]
fn a_session_that_said_goodbye_closes_its_copy() {
    let (sshd, ours) = Sshd::serving();
    let mut session = sshd.session(&ours);
    let key = session.host_key().expect("the server's key");
    assert_eq!(key.kind, KeyType::Ed25519);
    assert!(key.sha256.is_some() && key.md5.is_some() && key.base64.is_some());
    assert_eq!(session.sftp_new(), Ok(()));
    assert_eq!(session.sftp_init(), Rc::Ok);
    let home = session.canonicalize(b".").unwrap().expect("a home");
    assert!(home.starts_with(b"/"));
    session.sftp_free();
    session.disconnect();
    drop(session);
    assert!(is_open(ours.as_raw_fd()));
    drop(ours);
    sshd.ends();
}

/// A session freed with no goodbye closes the socket libssh holds, its
/// copy, and leaves the connection's open.
#[test]
fn a_session_freed_without_goodbye_closes_its_copy() {
    let (sshd, ours) = Sshd::serving();
    let session = sshd.session(&ours);
    drop(session);
    assert!(is_open(ours.as_raw_fd()));
    drop(ours);
    sshd.ends();
}

/// libssh's numbers, as the session's answers name them.
#[test]
fn libssh_s_numbers_are_named() {
    assert_eq!(rc(sys::SSH_OK), Rc::Ok);
    assert_eq!(rc(sys::SSH_AGAIN), Rc::Again);
    assert_eq!(rc(sys::SSH_ERROR), Rc::Error);
    let auths = [
        (sys::SSH_AUTH_SUCCESS, Auth::Success),
        (sys::SSH_AUTH_DENIED, Auth::Denied),
        (sys::SSH_AUTH_PARTIAL, Auth::Partial),
        (sys::SSH_AUTH_INFO, Auth::Info),
        (sys::SSH_AUTH_AGAIN, Auth::Again),
        (sys::SSH_AUTH_ERROR, Auth::Error),
    ];
    for (n, a) in auths {
        assert_eq!(auth(n), a, "{n}");
    }
    let kinds = [
        (sys::SSH_KEYTYPE_DSS, KeyType::Dss),
        (sys::SSH_KEYTYPE_RSA, KeyType::Rsa),
        (sys::SSH_KEYTYPE_RSA1, KeyType::Rsa1),
        (sys::SSH_KEYTYPE_ECDSA, KeyType::Ecdsa),
        (sys::SSH_KEYTYPE_ECDSA_P256, KeyType::Ecdsa),
        (sys::SSH_KEYTYPE_ECDSA_P384, KeyType::Ecdsa),
        (sys::SSH_KEYTYPE_ECDSA_P521, KeyType::Ecdsa),
        (sys::SSH_KEYTYPE_ED25519, KeyType::Ed25519),
        (0, KeyType::Other),
    ];
    for (n, k) in kinds {
        assert_eq!(key_type(n), k, "{n}");
    }
    assert_eq!(terminated(b"ab").unwrap(), b"ab\0");
    assert_eq!(terminated(b"").unwrap(), b"\0");
    assert_eq!(terminated(b"a\0b"), Err(Refused));
}

/// `bytes` in base64, without its padding, as `ssh-keygen -l` writes a
/// SHA-256 fingerprint.
fn base64_unpadded(bytes: &[u8]) -> String {
    const ABC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut n = [0u8; 3];
        n[..chunk.len()].copy_from_slice(chunk);
        let v = u32::from(n[0]) << 16 | u32::from(n[1]) << 8 | u32::from(n[2]);
        for i in 0..=chunk.len() {
            out.push(char::from(ABC[(v >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

/// What `ssh-keygen -l -E <hash>` says of `key`: its fingerprint field.
fn keygen_fingerprint(key: &std::path::Path, hash: &str) -> String {
    let out = Command::new("ssh-keygen")
        .args(["-l", "-E", hash, "-f"])
        .arg(key)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    text.split(' ').nth(1).unwrap().to_owned()
}

impl Sshd {
    /// A session over `ours`, its known-hosts file `known`, connected.
    fn connected(&self, ours: &UnixStream, known: &std::path::Path) -> Box<dyn Session> {
        let mut session = LIBSSH.session().expect("a session");
        session.set_host(b"localhost").unwrap();
        session.set_socket(Some(ours.as_fd())).unwrap();
        let known = known.to_str().unwrap().as_bytes();
        session.set_known_hosts(known).unwrap();
        session.set_blocking(Blocking::Yes);
        assert_eq!(session.connect(), Rc::Ok);
        session
    }

    /// Whether it ended, within `secs` seconds, all copies of the other end
    /// still open.
    fn ended(&mut self, secs: u64) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        while std::time::Instant::now() < deadline {
            if self.child.try_wait().unwrap().is_some() {
                return true;
            }
            std::thread::yield_now();
        }
        false
    }
}

/// The server's key is the one it was given: its fingerprints are those
/// `ssh-keygen` makes, its base64 the public file's; and the known-hosts
/// file says whether it is known, changed or not there, until
/// the session adds it.
#[test]
fn the_host_key_is_the_server_s_and_known_as_the_file_says() {
    let (sshd, ours) = Sshd::serving();
    let host = sshd.dir.join("host.pub");
    let public = std::fs::read_to_string(&host).unwrap();
    let base64 = public.split(' ').nth(1).unwrap().to_owned();
    let known = sshd.dir.join("known_hosts");
    let mut session = sshd.connected(&ours, &known);
    let key = session.host_key().expect("the server's key");
    assert_eq!(key.kind, KeyType::Ed25519);
    let sha256 = format!("SHA256:{}", base64_unpadded(&key.sha256.unwrap()));
    assert_eq!(sha256, keygen_fingerprint(&host, "sha256"));
    let md5: Vec<_> = key
        .md5
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        format!("MD5:{}", md5.join(":")),
        keygen_fingerprint(&host, "md5")
    );
    assert_eq!(key.base64.as_deref(), Some(base64.as_bytes()));
    // No file is no entry: libssh looks in the system's file too.
    assert_eq!(session.known_host(), (KnownHosts::Unknown, None));
    std::fs::write(&known, "").unwrap();
    assert_eq!(session.known_host(), (KnownHosts::Unknown, None));
    let user = std::fs::read_to_string(sshd.dir.join("user.pub")).unwrap();
    let other = user.split(' ').take(2).collect::<Vec<_>>().join(" ");
    std::fs::write(&known, format!("localhost {other}\n")).unwrap();
    // libssh gives the file's entry only for a key that matches.
    assert_eq!(session.known_host(), (KnownHosts::Changed, None));
    std::fs::write(&known, "").unwrap();
    assert_eq!(session.update_known_hosts(), Rc::Ok);
    let (state, entry) = session.known_host();
    assert_eq!(state, KnownHosts::Ok);
    let entry = entry.expect("the file's key").unwrap();
    assert_eq!(entry.base64.as_deref(), Some(base64.as_bytes()));
    session.disconnect();
    drop(session);
    drop(ours);
    sshd.ends();
}

/// A goodbye ends the server's side while the socket is still open.
#[test]
fn a_goodbye_ends_the_server_s_side() {
    let (mut sshd, ours) = Sshd::serving();
    let mut session = sshd.session(&ours);
    assert!(!sshd.ended(1), "the server waits while not told");
    session.disconnect();
    assert!(sshd.ended(10), "the server heard the goodbye");
    drop(session);
    drop(ours);
    sshd.ends();
}

/// A path as libssh is given it.
fn bytes(path: &std::path::Path) -> &[u8] {
    path.to_str().unwrap().as_bytes()
}

/// Read the open file to its end, `chunk` bytes a read.
fn read_all(session: &mut dyn Session, chunk: usize) -> Vec<u8> {
    let mut got = Vec::new();
    loop {
        assert_eq!(session.begin_read(chunk), Ok(()));
        let mut buf = vec![0u8; chunk];
        match session.wait_read(&mut buf) {
            Aio::Done(0) => return got,
            Aio::Done(n) => got.extend_from_slice(&buf[..n]),
            other => panic!("{other:?}"),
        }
    }
}

/// Write `data` to the open file.
fn write_all(session: &mut dyn Session, data: &[u8]) {
    assert_eq!(session.begin_write(data), Ok(()));
    assert_eq!(session.wait_write(), Aio::Done(data.len()));
}

/// SFTP's files are written, appended to, overwritten where sought,
/// read, stated and changed; links made, read and stated as links;
/// directories made, listed and removed; files renamed and removed; and
/// what fails is said by the server's code.
#[test]
fn sftp_files_and_directories_are_the_server_s() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let (sshd, ours) = Sshd::serving();
    let mut session = sshd.session(&ours);
    assert!(!session.has_sftp());
    assert_eq!(session.sftp_new(), Ok(()));
    assert!(session.has_sftp());
    assert_eq!(session.sftp_init(), Rc::Ok);
    let d = sshd.dir.join("files");
    std::fs::create_dir(&d).unwrap();
    let f = d.join("f");
    assert!(!session.has_file());
    assert_eq!(session.open(bytes(&f), OpenMode::Truncate, 0o640), Ok(()));
    assert!(session.has_file());
    write_all(&mut *session, b"hello");
    session.close_file();
    assert!(!session.has_file());
    assert_eq!(session.open(bytes(&f), OpenMode::Append, 0o640), Ok(()));
    write_all(&mut *session, b" there");
    session.close_file();
    assert_eq!(session.open(bytes(&f), OpenMode::Write, 0), Ok(()));
    assert_eq!(session.seek(1), Ok(()));
    write_all(&mut *session, b"E");
    let open = session.fstat().unwrap();
    assert_eq!(open.size, Some(11));
    session.close_file();
    assert_eq!(std::fs::read(&f).unwrap(), b"hEllo there");
    assert_eq!(session.open(bytes(&f), OpenMode::Read, 0), Ok(()));
    assert_eq!(read_all(&mut *session, 4), b"hEllo there");
    session.close_file();
    assert_eq!(session.open(bytes(&f), OpenMode::Read, 0), Ok(()));
    assert_eq!(session.seek(6), Ok(()));
    assert_eq!(read_all(&mut *session, 64), b"there");
    session.close_file();

    let stated = session.stat(bytes(&f)).unwrap();
    assert_eq!(stated.size, Some(11));
    assert_eq!(
        stated.permissions,
        Some(std::fs::metadata(&f).unwrap().mode())
    );
    assert_eq!(session.stat_to_change(bytes(&f)), Ok(()));
    assert_eq!(
        session.setstat_kept(bytes(&f), AttrChange::Permissions(0o600)),
        Ok(())
    );
    let mode = std::fs::metadata(&f).unwrap().permissions().mode();
    assert_eq!(mode & 0o7777, 0o600);
    assert_eq!(session.stat_to_change(bytes(&f)), Ok(()));
    assert_eq!(
        session.setstat_kept(bytes(&f), AttrChange::Mtime(1_000_000)),
        Ok(())
    );
    assert_eq!(std::fs::metadata(&f).unwrap().mtime(), 1_000_000);

    let l = d.join("l");
    assert_eq!(session.symlink(bytes(&f), bytes(&l)), Ok(()));
    assert_eq!(std::fs::read_link(&l).unwrap(), f);
    assert_eq!(
        session.readlink(bytes(&l)).unwrap().as_deref(),
        Some(bytes(&f))
    );
    let link = session.lstat(bytes(&l)).unwrap();
    assert_eq!(link.permissions.unwrap() & 0o170000, 0o120000);
    let m = d.join("m");
    assert_eq!(session.rename(bytes(&l), bytes(&m)), Ok(()));
    assert!(std::fs::symlink_metadata(&m).is_ok() && std::fs::symlink_metadata(&l).is_err());
    let sub = d.join("sub");
    assert_eq!(session.mkdir(bytes(&sub), 0o750), Ok(()));
    assert!(sub.is_dir());

    assert_eq!(session.opendir(bytes(&d)), Ok(()));
    let mut names = Vec::new();
    while let Some(entry) = session.readdir().unwrap() {
        let name = entry.name.unwrap();
        if name == b"f" {
            let long = String::from_utf8(entry.longname.unwrap()).unwrap();
            assert!(long.starts_with("-rw-------"), "{long}");
            assert_eq!(entry.size, Some(11));
        }
        names.push(String::from_utf8(name).unwrap());
    }
    session.closedir();
    names.sort();
    assert_eq!(names, [".", "..", "f", "m", "sub"]);

    assert_eq!(session.rmdir(bytes(&sub)), Ok(()));
    assert_eq!(session.unlink(bytes(&m)), Ok(()));
    assert!(!sub.exists() && std::fs::symlink_metadata(&m).is_err());
    assert_eq!(
        session.stat(bytes(&m)),
        Err(AttrsError::Status(SftpStatus::NoSuchFile))
    );
    assert_eq!(
        session.unlink(bytes(&m)),
        Err(NotDone::Failed(SftpStatus::NoSuchFile))
    );
    assert_eq!(session.readlink(bytes(&m)).unwrap(), None);
    assert_eq!(session.opendir(bytes(&m)), Err(SftpStatus::NoSuchFile));
    assert!(session.open(b"a\0b", OpenMode::Read, 0).is_err());
    assert!(session.rename(b"a\0b", bytes(&f)).is_err());

    session.sftp_free();
    assert!(!session.has_sftp());
    session.disconnect();
    drop(session);
    drop(ours);
    sshd.ends();
}

/// An SCP upload is written where pushed, at its size and mode, and a
/// download offers the file at its size and reads it.
#[test]
fn scp_files_are_pushed_and_pulled() {
    use std::os::unix::fs::PermissionsExt as _;
    let (sshd, ours) = Sshd::serving();
    let mut session = sshd.session(&ours);
    let d = sshd.dir.join("scp");
    std::fs::create_dir(&d).unwrap();
    assert_eq!(session.scp_new(ScpWay::Write, bytes(&d)), Ok(()));
    assert!(session.has_scp());
    assert_eq!(session.scp_init(), Rc::Ok);
    assert_eq!(session.scp_push_file(b"up", 7, 0o640), Rc::Ok);
    assert_eq!(session.scp_write(b"over "), Rc::Ok);
    assert_eq!(session.scp_write(b"it"), Rc::Ok);
    assert_eq!(session.scp_close(), Rc::Ok);
    session.scp_free();
    assert!(!session.has_scp());
    let up = d.join("up");
    assert_eq!(std::fs::read(&up).unwrap(), b"over it");
    let mode = std::fs::metadata(&up).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o640);

    std::fs::write(d.join("down"), b"from the server").unwrap();
    assert_eq!(
        session.scp_new(ScpWay::Read, bytes(&d.join("down"))),
        Ok(())
    );
    assert_eq!(session.scp_init(), Rc::Ok);
    assert_eq!(session.scp_pull_request(), ScpRequest::NewFile);
    assert_eq!(session.scp_size(), 15);
    let mut got = Vec::new();
    while got.len() < 15 {
        let mut buf = [0u8; 4];
        let n = session.scp_read(&mut buf).unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, b"from the server");
    session.scp_free();
    session.disconnect();
    drop(session);
    drop(ours);
    sshd.ends();
}
