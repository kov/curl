//! SCP and SFTP (`lib/vssh/libssh.c`, `lib/vssh/vssh.c`): a connection
//! handed whole to the SSH library, which reads and writes its socket
//! itself, past every layer and buffer of ours; a login once per
//! connection, by public key, GSS-API, keyboard-interactive or password;
//! then per transfer an SCP channel, which ends the connection with the
//! transfer, or SFTP's quote commands, listing, download or upload over
//! its session, which outlives it.
//!
//! The state machine is C's, state for state and trace for trace
//! (`myssh_statemachine`): what libssh is called with, and when, is what
//! goes on the wire. Its sessions are nonblocking while they connect and
//! log in, then blocking, as C sets them: SFTP's from its start, SCP's
//! from its channel's, only an SFTP file's reads and writes left
//! nonblocking.

mod path;

use std::fmt;
use std::num::NonZeroU32;

use curl_alloc::{TryArc, TryVec as _};

use super::{Connect, DoPhase, DoStep, Finish, ProtoStep, Waiting};
use crate::auth::creds::{CredentialGate, Credentials, Takes};
use crate::components::Component;
use crate::conn::io::{Events, Sent};
use crate::conn::line::LineConn;
use crate::conn::{ConnLease, Peer, RouteCold, Scheme};
use crate::deliver::{self, Directions, Expect, Pause, Pipeline, Reach};
use crate::error::{ErrorKind, url_error};
use crate::handler::{DebugKind, KeyMatch, KeyVerdict};
use crate::idn::Idn;
use crate::multi::Host;
use crate::multi::state::{AfterRequest, StepCx};
use crate::options::{CreateDirs, Resume, SshAuthTypes};
use crate::progress::rate::Way;
use crate::report::Timer;
use crate::ssh::{
    Aio, AttrChange, AttrsError, Auth, Blocking, KeyType, KnownHosts, Methods, NotDone, OpenMode,
    PollFlags, Rc, ScpRequest, ScpWay, Session, SftpStatus,
};
use crate::trace;
use crate::upload::Upload;
use crate::upload::chain::Body;
use crate::upload::sending::{Outlet, Sending};
use crate::url::{GetOptions, Part, Url};
use path::{Home, RangeError};

/// The key files a connection logs in with, as its first transfer found
/// them (`Curl_ssh_setup_pkey`), kept on its route; none of them where
/// public-key logins are not allowed.
#[derive(Debug, Default)]
pub(crate) struct Keys {
    /// The private key file: the one given, or the first of the default
    /// ones that exists, or empty if none does.
    private: Option<Vec<u8>>,
    /// The public key file, if given and not empty: else libssh reads it
    /// from the private one.
    public: Option<Vec<u8>>,
    /// What the private key is decrypted with (`CURLOPT_KEYPASSWD`); not
    /// compared for reuse, as C compares it not.
    passphrase: Option<Vec<u8>>,
}

impl Keys {
    /// Whether a connection that found `self` serves a transfer that
    /// finds `other`: the same files (`ssh_config_matches`).
    pub(crate) fn same(&self, other: &Keys) -> bool {
        self.private == other.private && self.public == other.public
    }

    /// The transfer's, as its options and the files at hand say.
    fn find<H: Host>(cx: &StepCx<'_, H>) -> Result<Keys, ErrorKind> {
        let options = cx.easy().options();
        let ssh = &options.ssh;
        if !ssh.auth_types.allows(SshAuthTypes::PUBLICKEY) {
            return Ok(Keys::default());
        }
        let private = match ssh.private_key.as_deref() {
            Some(given) => copy(given)?,
            None => default_private_key()?,
        };
        let public = ssh
            .public_key
            .as_deref()
            .filter(|k| k.first().is_some_and(|&b| b != 0))
            .map(copy)
            .transpose()?;
        let passphrase = options
            .tls
            .options
            .key_password
            .as_deref()
            .map(copy)
            .transpose()?;
        Ok(Keys {
            private: Some(private),
            public,
            passphrase,
        })
    }

    /// The private key file, as libssh is given it: up to a zero byte,
    /// as C reads its string; none, or empty, for libssh's defaults.
    fn private(&self) -> Option<&[u8]> {
        self.private.as_deref().map(c_string)
    }
}

/// The first of the default private key files that exists, or empty:
/// `~/.ssh/id_rsa`, `~/.ssh/id_dsa`, then `id_rsa` and `id_dsa` here.
fn default_private_key() -> Result<Vec<u8>, ErrorKind> {
    let home = curl_os::env::var(b"HOME").map_err(|_| ErrorKind::OutOfMemory)?;
    first_private_key(home.as_deref(), exists)
}

/// The first of the default private key files under `home`, then here,
/// that `exists` says is there, or empty (`default_private_key`).
fn first_private_key(
    home: Option<&[u8]>,
    exists: impl Fn(&[u8]) -> Result<bool, ErrorKind>,
) -> Result<Vec<u8>, ErrorKind> {
    if let Some(home) = home {
        for name in [&b"/.ssh/id_rsa"[..], b"/.ssh/id_dsa"] {
            let mut file = copy(home)?;
            file.try_extend_from_slice(name)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            if exists(&file)? {
                return Ok(file);
            }
        }
    }
    for name in [&b"id_rsa"[..], b"id_dsa"] {
        if exists(name)? {
            return copy(name);
        }
    }
    Ok(Vec::new())
}

/// Whether `file` names one there is (`stat` succeeds).
fn exists(file: &[u8]) -> Result<bool, ErrorKind> {
    if file.contains(&0) {
        return Ok(false);
    }
    let mut z = copy(file)?;
    z.try_push(0).map_err(|_| ErrorKind::OutOfMemory)?;
    let c = std::ffi::CStr::from_bytes_with_nul(&z).expect("one zero byte, at the end");
    Ok(curl_os::fs::stat(c).is_ok())
}

/// A copy of `bytes`.
fn copy(bytes: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut v = Vec::new();
    v.try_extend_from_slice(bytes)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    Ok(v)
}

/// `bytes` up to its first zero byte, as C reads a string.
fn c_string(bytes: &[u8]) -> &[u8] {
    bytes.split(|&b| b == 0).next().unwrap_or_default()
}

/// Where the state machine is (`sshstate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Stop,
    Init,
    SStartup,
    Hostkey,
    Authlist,
    AuthPkeyInit,
    AuthPkey,
    AuthPassInit,
    AuthPass,
    AuthGssapi,
    AuthKeyInit,
    AuthKey,
    AuthDone,
    SftpInit,
    SftpRealpath,
    SftpQuoteInit,
    SftpPostquoteInit,
    SftpQuote,
    SftpNextQuote,
    SftpQuoteStat(QuoteChange),
    SftpQuoteSetstat,
    SftpQuoteSymlink,
    SftpQuoteMkdir,
    SftpQuoteRename,
    SftpQuoteRmdir,
    SftpQuoteUnlink,
    SftpGetinfo,
    SftpFiletime,
    SftpTransInit,
    SftpUploadInit,
    SftpCreateDirsInit,
    SftpCreateDirs,
    SftpCreateDirsMkdir,
    SftpReaddirInit,
    SftpReaddir,
    SftpReaddirLink,
    SftpReaddirBottom,
    SftpReaddirDone,
    SftpDownloadInit,
    SftpDownloadStat,
    SftpClose,
    SftpShutdown,
    ScpTransInit,
    ScpUploadInit,
    ScpDownloadInit,
    ScpDownload,
    ScpDone,
    ScpSendEof,
    ScpChannelFree,
    SessionDisconnect,
    SessionFree,
}

impl State {
    /// Its name, as C's trace gives it (`Curl_ssh_statename`).
    fn name(self) -> &'static str {
        match self {
            State::Stop => "SSH_STOP",
            State::Init => "SSH_INIT",
            State::SStartup => "SSH_S_STARTUP",
            State::Hostkey => "SSH_HOSTKEY",
            State::Authlist => "SSH_AUTHLIST",
            State::AuthPkeyInit => "SSH_AUTH_PKEY_INIT",
            State::AuthPkey => "SSH_AUTH_PKEY",
            State::AuthPassInit => "SSH_AUTH_PASS_INIT",
            State::AuthPass => "SSH_AUTH_PASS",
            State::AuthGssapi => "SSH_AUTH_GSSAPI",
            State::AuthKeyInit => "SSH_AUTH_KEY_INIT",
            State::AuthKey => "SSH_AUTH_KEY",
            State::AuthDone => "SSH_AUTH_DONE",
            State::SftpInit => "SSH_SFTP_INIT",
            State::SftpRealpath => "SSH_SFTP_REALPATH",
            State::SftpQuoteInit => "SSH_SFTP_QUOTE_INIT",
            State::SftpPostquoteInit => "SSH_SFTP_POSTQUOTE_INIT",
            State::SftpQuote => "SSH_SFTP_QUOTE",
            State::SftpNextQuote => "SSH_SFTP_NEXT_QUOTE",
            State::SftpQuoteStat(_) => "SSH_SFTP_QUOTE_STAT",
            State::SftpQuoteSetstat => "SSH_SFTP_QUOTE_SETSTAT",
            State::SftpQuoteSymlink => "SSH_SFTP_QUOTE_SYMLINK",
            State::SftpQuoteMkdir => "SSH_SFTP_QUOTE_MKDIR",
            State::SftpQuoteRename => "SSH_SFTP_QUOTE_RENAME",
            State::SftpQuoteRmdir => "SSH_SFTP_QUOTE_RMDIR",
            State::SftpQuoteUnlink => "SSH_SFTP_QUOTE_UNLINK",
            State::SftpGetinfo => "SSH_SFTP_GETINFO",
            State::SftpFiletime => "SSH_SFTP_FILETIME",
            State::SftpTransInit => "SSH_SFTP_TRANS_INIT",
            State::SftpUploadInit => "SSH_SFTP_UPLOAD_INIT",
            State::SftpCreateDirsInit => "SSH_SFTP_CREATE_DIRS_INIT",
            State::SftpCreateDirs => "SSH_SFTP_CREATE_DIRS",
            State::SftpCreateDirsMkdir => "SSH_SFTP_CREATE_DIRS_MKDIR",
            State::SftpReaddirInit => "SSH_SFTP_READDIR_INIT",
            State::SftpReaddir => "SSH_SFTP_READDIR",
            State::SftpReaddirLink => "SSH_SFTP_READDIR_LINK",
            State::SftpReaddirBottom => "SSH_SFTP_READDIR_BOTTOM",
            State::SftpReaddirDone => "SSH_SFTP_READDIR_DONE",
            State::SftpDownloadInit => "SSH_SFTP_DOWNLOAD_INIT",
            State::SftpDownloadStat => "SSH_SFTP_DOWNLOAD_STAT",
            State::SftpClose => "SSH_SFTP_CLOSE",
            State::SftpShutdown => "SSH_SFTP_SHUTDOWN",
            State::ScpTransInit => "SSH_SCP_TRANS_INIT",
            State::ScpUploadInit => "SSH_SCP_UPLOAD_INIT",
            State::ScpDownloadInit => "SSH_SCP_DOWNLOAD_INIT",
            State::ScpDownload => "SSH_SCP_DOWNLOAD",
            State::ScpDone => "SSH_SCP_DONE",
            State::ScpSendEof => "SSH_SCP_SEND_EOF",
            State::ScpChannelFree => "SSH_SCP_CHANNEL_FREE",
            State::SessionDisconnect => "SSH_SESSION_DISCONNECT",
            State::SessionFree => "SSH_SESSION_FREE",
        }
    }
}

/// The attribute a quote command changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuoteChange {
    Chgrp,
    Chmod,
    Chown,
    Atime,
    Mtime,
}

/// How far the keyboard-interactive login is (`kbd_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kbd {
    /// Not begun, or begun again.
    Asking,
    /// The password is given, the server's verdict awaited.
    Answered,
    /// The server asked a round of no questions, its verdict still awaited.
    Confirming,
}

/// Which of the transfer's command lists a quote command is of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Quotes {
    /// Before the transfer (`CURLOPT_QUOTE`).
    Before,
    /// After it (`CURLOPT_POSTQUOTE`).
    After,
}

/// What SSH keeps on its connection (`struct ssh_conn`).
#[derive(Debug)]
pub(crate) struct SshConn {
    /// The library's session, none once it is freed (`SSH_SESSION_FREE`).
    session: Option<Box<dyn Session>>,
    /// SFTP's, not SCP's.
    sftp: bool,
    state: State,
    /// Where the state machine goes once the one it is in is over
    /// (`nextstate`, none for `SSH_NO_STATE`).
    next: Option<State>,
    /// What the state machine's run comes to as it stops (`actualcode`).
    actual: Result<(), ErrorKind>,
    /// What the session waits for, after a call that would have waited
    /// (`waitfor`).
    waitfor: PollFlags,
    /// How the server lets the user log in (`auth_methods`).
    methods: Methods,
    authed: bool,
    /// How far the keyboard-interactive login is.
    kbd: Kbd,
    /// The SFTP session's home directory (`homedir`).
    home: Option<Vec<u8>>,
    /// What of its route few routes have: the credentials and key files
    /// it logs in with, its first transfer's.
    cold: Option<TryArc<RouteCold>>,
    /// The quote command being run: its list, and where in it.
    quote: Option<(Quotes, usize)>,
    /// The quote command's paths (`quote_path1`, `quote_path2`).
    path1: Option<Vec<u8>>,
    path2: Option<Vec<u8>>,
    /// The quote command may fail: it started with `*` (`acceptfail`).
    accept_fail: bool,
    /// The change to the attributes of `path2` the quote command makes.
    change: Option<AttrChange>,
    /// The listing's line being made (`readdir_buf`).
    listing: Vec<u8>,
    /// The link a listed entry is (`readdir_linkPath`).
    link: Option<Vec<u8>>,
    /// Where in the request's path the next directory to make ends
    /// (`slash_pos`).
    slash: usize,
    /// The upload's directories were made once (`secondCreateDirs`).
    second_create_dirs: bool,
    /// The SFTP read under way, by the length it asked for
    /// (`sftp_recv_state`).
    reading: Option<usize>,
    /// The SFTP write under way (`sftp_send_state`).
    writing: bool,
}

/// What C's SSH trace says (`CURL_TRC_SSH`), from a transfer's step or
/// from a connection's shutdown.
trait Says {
    fn ssh(&mut self, args: fmt::Arguments<'_>);
}

impl<H: Host> Says for StepCx<'_, H> {
    fn ssh(&mut self, args: fmt::Arguments<'_>) {
        trace::of(self, Component::Ssh, args);
    }
}

/// The trace of the work a shutdown does for no transfer.
struct LayerSays<'a>(&'a mut dyn crate::conn::layer::LayerCx);

impl Says for LayerSays<'_> {
    fn ssh(&mut self, args: fmt::Arguments<'_>) {
        if let Some(t) = self.0.trace() {
            t.line(Component::Ssh, args);
        }
    }
}

/// How a state's work went, for the run of the state machine: on, or
/// waiting on the socket (`SSH_AGAIN`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    On,
    Again,
}

impl SshConn {
    fn session(&mut self) -> &mut dyn Session {
        self.session
            .as_deref_mut()
            .expect("the state machine works on a live session")
    }

    /// The library's words for its last failure, or none.
    fn error_text(&self) -> Vec<u8> {
        self.session
            .as_deref()
            .and_then(|s| s.error().ok())
            .unwrap_or_default()
    }

    /// Move the state on, said as C says it (`myssh_to`).
    fn to(&mut self, says: &mut dyn Says, state: State) {
        if self.state != state {
            says.ssh(format_args!(
                "[{}] -> [{}]",
                self.state.name(),
                state.name()
            ));
        }
        self.state = state;
    }

    /// The session is ended, and the run comes to `kind`
    /// (`myssh_to_ERROR`).
    fn goto_error(&mut self, says: &mut dyn Says, kind: ErrorKind) -> Flow {
        self.to(says, State::SessionDisconnect);
        self.actual = Err(kind);
        Flow::On
    }

    /// The file is closed, and the run comes to the SFTP failure
    /// (`myssh_to_SFTP_CLOSE`).
    fn goto_close(&mut self, says: &mut dyn Says, status: SftpStatus) -> Flow {
        self.to(says, State::SftpClose);
        self.actual = sftp_failure(status);
        Flow::On
    }

    /// What the session waits for, if a call would have (`block`), as the
    /// pollset says it (`myssh_block2waitfor`).
    fn block2waitfor(&mut self, block: bool) {
        self.waitfor = match (&self.session, block) {
            (Some(s), true) => s.poll_flags(),
            _ => PollFlags::default(),
        };
    }

    /// Say goodbye to the server as the connection shuts down, its state
    /// unknown or not (`scp_disconnect`, `sftp_disconnect`): SFTP's
    /// session freed first, then the SSH session's.
    pub(crate) fn goodbye(&mut self, cx: &mut dyn crate::conn::layer::LayerCx) {
        let says = &mut LayerSays(cx);
        if self.sftp {
            says.ssh(format_args!("DISCONNECT starts now"));
        }
        if self.session.is_some() {
            let first = if self.sftp {
                State::SftpShutdown
            } else {
                State::SessionDisconnect
            };
            self.to(says, first);
            // None of these states waits: the run reaches its end.
            while self.state != State::Stop {
                match self.state {
                    State::SftpShutdown => self.sftp_shutdown(says),
                    State::SessionDisconnect => self.session_disconnect(says),
                    State::SessionFree => {
                        let _result = self.session_free(says);
                    }
                    other => unreachable!("a shutdown runs no {}", other.name()),
                }
                says.ssh(format_args!(
                    "[{}] statemachine() -> 0, block=0",
                    self.state.name()
                ));
            }
        }
        if self.sftp {
            says.ssh(format_args!("DISCONNECT is done"));
        }
    }

    /// `SSH_SFTP_SHUTDOWN`: what a broken transfer left open closed, then
    /// the SFTP session.
    fn sftp_shutdown(&mut self, says: &mut dyn Says) {
        let s = self.session();
        s.set_blocking(Blocking::No);
        s.free_aio();
        s.close_file();
        s.sftp_free();
        self.reading = None;
        self.writing = false;
        self.home = None;
        self.to(says, State::SessionDisconnect);
    }

    /// `SSH_SESSION_DISCONNECT`: a channel, file or SFTP session still
    /// open freed first, then the goodbye said.
    fn session_disconnect(&mut self, says: &mut dyn Says) {
        let s = self.session();
        s.scp_free();
        s.close_file();
        s.sftp_free();
        s.disconnect();
        self.home = None;
        self.to(says, State::SessionFree);
    }

    /// `SSH_SESSION_FREE`: the session freed, and all kept with it; what
    /// the run came to given (`myssh_in_SESSION_FREE`). The connection is
    /// not to be used again, which its owner reads from the session
    /// gone.
    fn session_free(&mut self, says: &mut dyn Says) -> Result<(), ErrorKind> {
        self.session = None;
        self.waitfor = PollFlags::default();
        self.to(says, State::Stop);
        self.actual
    }
}

/// The failure an SFTP status is (`sftp_error_to_CURLE`).
fn sftp_failure(status: SftpStatus) -> Result<(), ErrorKind> {
    match status {
        SftpStatus::Unsaid => Ok(()),
        SftpStatus::NoSuchFile | SftpStatus::NoSuchPath => Err(ErrorKind::RemoteFileNotFound),
        SftpStatus::PermissionDenied | SftpStatus::WriteProtect => {
            Err(ErrorKind::RemoteAccessDenied)
        }
        SftpStatus::FileAlreadyExists => Err(ErrorKind::RemoteFileExists),
        SftpStatus::Failure | SftpStatus::Other(_) => Err(ErrorKind::Ssh),
    }
}

/// A mode's type bits, and a link's (`SSH_S_IFMT`, `SSH_S_IFLNK`).
const S_IFMT: u32 = 0o170_000;
const S_IFLNK: u32 = 0o120_000;

/// A transfer over SCP or SFTP (`struct SSHPROTO` and the request's
/// state).
#[derive(Debug)]
pub(crate) struct Request {
    pipeline: Pipeline,
    peer: Peer,
    /// The transfer's credentials, until its route takes them.
    credentials: Option<Credentials>,
    /// The transfer's key files, until its route takes them.
    keys: Option<Keys>,
    /// The URL's path, encoded (`state.up.path`).
    url_path: Vec<u8>,
    /// The path the request works on, decoded (`sshp->path`).
    path: Option<Vec<u8>>,
    upload: bool,
    no_body: bool,
    /// Where the transfer starts (`state.resume_from`): -1 for the end.
    resume_from: i64,
    /// The range asked for, or the resume point's (`state.range` while
    /// `use_range`).
    range: Option<Vec<u8>>,
    /// The upload's size, if known (`state.infilesize`).
    infilesize: Option<u64>,
    /// The upload, from its open until its body is made.
    source: Option<Upload>,
    /// The size of the body to receive, if known (`req.size`).
    size: Option<u64>,
    /// The ways the request moves bytes once made (`xfer_setup`).
    ways: Directions,
    /// The body is being read (`KEEP_RECV`).
    receiving: bool,
    /// The upload as it goes out.
    sending: Option<Box<Sending>>,
    /// Where a read lands.
    buf: Vec<u8>,
    /// What the session waits for, as the connection's state machine or
    /// a read or write last left it.
    waitfor: PollFlags,
    /// The connection has a session still.
    live: bool,
}

impl Request {
    /// A transfer of `url`, SFTP's if `sftp`: its peer, the credentials
    /// its URL and the application give, a `.netrc`'s if asked for, and
    /// its key files (`myssh_setup_connection`).
    pub(crate) fn new<H: Host>(
        url: &Url,
        sftp: bool,
        before: super::Before<'_>,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Request, ErrorKind> {
        let host = url.get(Part::Host, GetOptions::NONE).map_err(url_error)?;
        let port = url
            .get(
                Part::Port,
                GetOptions {
                    default_port: true,
                    ..GetOptions::NONE
                },
            )
            .map_err(url_error)?;
        let port = std::str::from_utf8(&port)
            .ok()
            .and_then(|p| p.parse().ok())
            .ok_or(ErrorKind::UrlMalformat)?;
        let name: &[u8] = if sftp { b"sftp" } else { b"scp" };
        let scheme = Scheme::named(name).expect("libcurl knows SCP and SFTP");
        let scope = cx.easy().options().address_scope;
        let idn = cx.easy().libraries().idn;
        let peer = super::url_peer((scheme, host, port), url, scope, idn)?;
        let gate = match before.first {
            None => CredentialGate::FIRST,
            Some(first) => {
                let other_hosts = cx.easy().options().http.unrestricted_auth;
                CredentialGate::new(first, &peer, other_hosts)
            }
        };
        let takes = Takes::of(Some(scheme));
        let credentials = super::request_credentials(cx, gate.trusted(), url, takes)?;
        let credentials = super::with_netrc(credentials, peer.name(), takes, cx)?;
        let encoded = GetOptions {
            url_encode: true,
            ..GetOptions::NONE
        };
        let url_path = url.get(Part::Path, encoded).map_err(url_error)?;
        let options = cx.easy().options();
        // A resume point is asked for as the range from it (`setup_range`).
        let resume_from = match options.resume {
            Some(Resume::At(n)) => i64::try_from(n.get()).unwrap_or(i64::MAX),
            Some(Resume::AtEnd) => -1,
            None => 0,
        };
        let range = if resume_from != 0 {
            let mut r = Vec::new();
            let text = curl_alloc::try_format(format_args!("{resume_from}-"))
                .map_err(|_| ErrorKind::OutOfMemory)?;
            r.try_extend_from_slice(text.as_bytes())
                .map_err(|_| ErrorKind::OutOfMemory)?;
            Some(r)
        } else {
            options.range.as_deref().map(copy).transpose()?
        };
        Ok(Request {
            pipeline: Pipeline::new(Reach::Network),
            peer,
            credentials,
            keys: Some(Keys::find(cx)?),
            url_path,
            path: None,
            upload: options.method == crate::options::Method::Upload,
            no_body: options.method == crate::options::Method::Head,
            resume_from,
            range,
            infilesize: None,
            source: None,
            size: None,
            ways: Directions::default(),
            receiving: false,
            sending: None,
            buf: Vec::new(),
            waitfor: PollFlags::default(),
            live: false,
        })
    }

    /// What the setup says of the key files, once the transfer is out of
    /// the queue (`Curl_ssh_setup_pkey`).
    pub(crate) fn set_up_said<H: Host>(&self, cx: &mut StepCx<'_, H>) {
        if !cx
            .easy()
            .options()
            .ssh
            .auth_types
            .allows(SshAuthTypes::PUBLICKEY)
        {
            return;
        }
        let Some(keys) = self.keys.as_ref() else {
            return;
        };
        if let Some(public) = keys.public.as_deref() {
            trace::info_with(cx, &[b"SSH: public key file '", c_string(public), b"'"]);
        }
        match keys.private.as_deref() {
            Some(private) => {
                trace::info_with(cx, &[b"SSH: private key file '", c_string(private), b"'"]);
            }
            None => trace::info(
                cx,
                format_args!("SSH: public key auth without private key set!"),
            ),
        }
    }

    /// The peer it connects to.
    pub(crate) fn network(
        &self,
        url: &Url,
        scope: Option<NonZeroU32>,
        idn: Option<&dyn Idn>,
    ) -> Result<Peer, ErrorKind> {
        let mut host = Vec::new();
        host.try_extend_from_slice(self.peer.shown())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let (scheme, port) = (self.peer.scheme(), self.peer.port());
        super::url_peer((scheme, host, port), url, scope, idn)
    }

    pub(crate) fn scheme(&self) -> Scheme {
        self.peer.scheme()
    }

    /// Its credentials, which its route takes.
    pub(crate) fn take_login(&mut self) -> Option<Credentials> {
        self.credentials.take()
    }

    /// Its key files, which its route takes.
    pub(crate) fn take_keys(&mut self) -> Option<Keys> {
        self.keys.take()
    }

    pub(crate) fn pipeline_mut(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    pub(crate) fn holds_output(&self) -> bool {
        self.pipeline.holds_output()
    }

    /// Whether the request, once made, moves bytes: its body to read or
    /// send (`recv_idx`, `send_idx`).
    pub(crate) fn exchanges(&self) -> bool {
        self.ways.recv || self.ways.send
    }

    /// Whether it has its upload to send.
    pub(crate) fn sending(&self) -> bool {
        self.ways.send && self.sending.is_some()
    }

    /// Whether nothing came back for the request, which waits for a body
    /// it has not read to its end: one that may be made again on a fresh
    /// connection, its reused one having died (`Curl_retry_request` for a
    /// scheme outside HTTP's, which retries no upload). What a quote
    /// command writes as a header does not count: C counts only HTTP's
    /// and the line protocols' headers (`req.headerbytecount`).
    pub(crate) fn received_nothing(&self) -> bool {
        !self.upload && !self.no_body && self.receiving && self.pipeline.bytecount() == 0
    }

    /// What it waits for on its connection while it connects or is made
    /// (`Curl_ssh_pollset`).
    fn pollset(&self, io: Directions) -> Events {
        match self.waited(io) {
            Some(events) => events,
            None if self.live => Events::IN,
            None => Events::NONE,
        }
    }

    /// What the session's wait, else the body's way `io`, asks for, if
    /// either asks: the pollset C traces as it makes it.
    fn waited(&self, io: Directions) -> Option<Events> {
        let (read, write) = if self.waitfor.read || self.waitfor.write {
            (self.waitfor.read, self.waitfor.write)
        } else {
            (io.recv, io.send)
        };
        let mut events = Events::NONE;
        if read {
            events = events | Events::IN;
        }
        if write {
            events = events | Events::OUT;
        }
        (read || write).then_some(events)
    }

    /// What its pollset says as it is made, while it connects or is made
    /// or, once `made`, as its body moves: the session's wait or the
    /// body's way, as C says it only then (`Curl_ssh_pollset`).
    pub(crate) fn pollset_said(&self, made: bool) -> Option<Events> {
        if made {
            self.waited(Directions {
                recv: self.receiving,
                send: self.sending.is_some(),
            })
        } else {
            self.waited(Directions::default())
        }
    }

    /// What it waits for once made: the session's wait, else its body's
    /// way, pause or not, as C's SSH pollset ignores a pause.
    pub(crate) fn interest(&self, _: Pause) -> Events {
        self.pollset(Directions {
            recv: self.receiving,
            send: self.sending.is_some(),
        })
    }

    /// Run the state machine as far as the session lets it now
    /// (`myssh_multi_statemach`): whether it stopped. A session freed
    /// leaves the connection to close.
    fn run<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        let sc = ssh_of(lease);
        let (result, block) = self.machine(cx, sc);
        let stopped = sc.state == State::Stop;
        sc.block2waitfor(block);
        self.waitfor = sc.waitfor;
        self.live = sc.session.is_some();
        if !self.live {
            lease.get().mark_close();
        }
        result.map(|()| stopped)
    }

    /// The state machine (`myssh_statemachine`): run until it stops or a
    /// call would wait; what the run came to, and whether it waits.
    fn machine<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        sc: &mut SshConn,
    ) -> (Result<(), ErrorKind>, bool) {
        let mut result = Ok(());
        let mut flow;
        loop {
            flow = Flow::On;
            match sc.state {
                State::Init => {
                    sc.second_create_dirs = false;
                    sc.next = None;
                    sc.actual = Ok(());
                    sc.session().set_blocking(Blocking::No);
                    sc.to(cx, State::SStartup);
                }
                State::SStartup => flow = self.s_startup(cx, sc),
                State::Hostkey => {
                    if self.is_known(cx, sc) {
                        sc.to(cx, State::Authlist);
                    } else {
                        sc.goto_error(cx, ErrorKind::PeerFailedVerification);
                    }
                }
                State::Authlist => flow = authlist(cx, sc),
                State::AuthPkeyInit => flow = auth_pkey_init(cx, sc),
                State::AuthPkey => flow = auth_pkey(cx, sc),
                State::AuthGssapi => flow = auth_gssapi(cx, sc),
                State::AuthKeyInit => {
                    if allows(cx, SshAuthTypes::KEYBOARD) {
                        sc.to(cx, State::AuthKey);
                    } else {
                        to_passwd(cx, sc);
                    }
                }
                State::AuthKey => flow = auth_key(cx, sc),
                State::AuthPassInit => {
                    if allows(cx, SshAuthTypes::PASSWORD) {
                        sc.to(cx, State::AuthPass);
                    } else {
                        sc.goto_error(cx, ErrorKind::LoginDenied);
                    }
                }
                State::AuthPass => flow = auth_pass(cx, sc),
                State::AuthDone => auth_done(cx, sc),
                State::SftpInit => sftp_init(cx, sc),
                State::SftpRealpath => sftp_realpath(cx, sc),
                State::SftpQuoteInit => self.sftp_quote_init(cx, sc),
                State::SftpPostquoteInit => {
                    if cx.easy().options().line.postquote.iter().next().is_some() {
                        trace::info(cx, format_args!("Sending quote commands"));
                        sc.quote = Some((Quotes::After, 0));
                        sc.to(cx, State::SftpQuote);
                    } else {
                        sc.to(cx, State::Stop);
                    }
                }
                State::SftpQuote => self.sftp_quote(cx, sc),
                State::SftpNextQuote => {
                    sc.path1 = None;
                    sc.path2 = None;
                    let (list, at) = sc.quote.expect("a quote command was run");
                    sc.quote = Some((list, at + 1));
                    if quote_command(cx, list, at + 1).is_some() {
                        sc.to(cx, State::SftpQuote);
                    } else if let Some(next) = sc.next.take() {
                        sc.to(cx, next);
                    } else {
                        sc.to(cx, State::SftpGetinfo);
                    }
                }
                State::SftpQuoteStat(kind) => sftp_quote_stat(cx, sc, kind),
                State::SftpQuoteSetstat => {
                    let path = sc.path2.take().unwrap_or_default();
                    let change = sc.change.expect("a stat kept a change to make");
                    let rc = sc.session().setstat_kept(&path, change);
                    sc.path2 = Some(path);
                    flow = quote_done(cx, sc, rc, "setstat");
                }
                State::SftpQuoteSymlink => {
                    let (from, to) = (sc.path1.take(), sc.path2.take());
                    let rc = sc.session().symlink(
                        to.as_deref().unwrap_or_default(),
                        from.as_deref().unwrap_or_default(),
                    );
                    (sc.path1, sc.path2) = (from, to);
                    flow = quote_done(cx, sc, rc, "symlink");
                }
                State::SftpQuoteMkdir => {
                    let path = sc.path1.take().unwrap_or_default();
                    let mode = u32::from(cx.easy().options().ssh.new_directory_mode.bits());
                    let rc = sc.session().mkdir(&path, mode);
                    sc.path1 = Some(path);
                    flow = quote_done(cx, sc, rc, "mkdir");
                }
                State::SftpQuoteRename => {
                    let (from, to) = (sc.path1.take(), sc.path2.take());
                    let rc = sc.session().rename(
                        from.as_deref().unwrap_or_default(),
                        to.as_deref().unwrap_or_default(),
                    );
                    (sc.path1, sc.path2) = (from, to);
                    flow = quote_done(cx, sc, rc, "rename");
                }
                State::SftpQuoteRmdir => {
                    let path = sc.path1.take().unwrap_or_default();
                    let rc = sc.session().rmdir(&path);
                    sc.path1 = Some(path);
                    flow = quote_done(cx, sc, rc, "rmdir");
                }
                State::SftpQuoteUnlink => {
                    let path = sc.path1.take().unwrap_or_default();
                    let rc = sc.session().unlink(&path);
                    sc.path1 = Some(path);
                    flow = quote_done(cx, sc, rc, "rm");
                }
                State::SftpGetinfo => {
                    let next = if cx.easy().options().filetime {
                        State::SftpFiletime
                    } else {
                        State::SftpTransInit
                    };
                    sc.to(cx, next);
                }
                State::SftpFiletime => self.sftp_filetime(cx, sc),
                State::SftpTransInit => {
                    let next = if self.upload {
                        State::SftpUploadInit
                    } else if self.path().last() == Some(&b'/') {
                        State::SftpReaddirInit
                    } else {
                        State::SftpDownloadInit
                    };
                    sc.to(cx, next);
                }
                State::SftpUploadInit => self.sftp_upload_init(cx, sc),
                State::SftpCreateDirsInit => {
                    if self.path().len() > 1 {
                        sc.slash = 1;
                        sc.to(cx, State::SftpCreateDirs);
                    } else {
                        sc.to(cx, State::SftpUploadInit);
                    }
                }
                State::SftpCreateDirs => {
                    let path = self.path();
                    match path[sc.slash..].iter().position(|&b| b == b'/') {
                        Some(i) => {
                            sc.slash += i;
                            let dir = &path[..sc.slash];
                            trace::info_with(cx, &[b"Creating directory '", dir, b"'"]);
                            sc.to(cx, State::SftpCreateDirsMkdir);
                        }
                        None => sc.to(cx, State::SftpUploadInit),
                    }
                }
                State::SftpCreateDirsMkdir => flow = self.sftp_create_dirs_mkdir(cx, sc),
                State::SftpReaddirInit => self.sftp_readdir_init(cx, sc),
                State::SftpReaddir => self.sftp_readdir(cx, sc),
                State::SftpReaddirLink => sftp_readdir_link(cx, sc),
                State::SftpReaddirBottom => self.sftp_readdir_bottom(cx, sc),
                State::SftpReaddirDone => {
                    sc.session().closedir();
                    self.xfer_setup(cx, Directions::default());
                    sc.to(cx, State::Stop);
                }
                State::SftpDownloadInit => self.sftp_download_init(cx, sc),
                State::SftpDownloadStat => self.sftp_download_stat(cx, sc),
                State::SftpClose => {
                    sc.session().close_file();
                    self.path = None;
                    cx.ssh(format_args!("SFTP DONE done"));
                    match sc.next {
                        Some(next) if next != State::SftpClose => {
                            sc.to(cx, next);
                            sc.next = Some(State::SftpClose);
                        }
                        _ => sc.to(cx, State::Stop),
                    }
                }
                State::SftpShutdown => sc.sftp_shutdown(cx),
                State::ScpTransInit => self.scp_trans_init(cx, sc),
                State::ScpUploadInit => self.scp_upload_init(cx, sc),
                State::ScpDownloadInit => {
                    if sc.session().scp_init() == Rc::Ok {
                        sc.to(cx, State::ScpDownload);
                    } else {
                        let text = sc.error_text();
                        let kind = trace::fail_with(cx, ErrorKind::CouldntConnect, &[&text]);
                        sc.goto_error(cx, kind);
                    }
                }
                State::ScpDownload => self.scp_download(cx, sc),
                State::ScpDone => {
                    let next = if self.upload {
                        State::ScpSendEof
                    } else {
                        State::ScpChannelFree
                    };
                    sc.to(cx, next);
                }
                State::ScpSendEof => {
                    if sc.session().has_scp() {
                        match sc.session().scp_close() {
                            Rc::Again => flow = Flow::Again,
                            Rc::Ok => {}
                            Rc::Error => {
                                let text = sc.error_text();
                                trace::info_with(
                                    cx,
                                    &[b"Failed to close libssh scp channel: ", &text],
                                );
                            }
                        }
                    }
                    if flow == Flow::On {
                        sc.to(cx, State::ScpChannelFree);
                    }
                }
                State::ScpChannelFree => {
                    let s = sc.session();
                    s.scp_free();
                    cx.ssh(format_args!("SCP DONE phase complete"));
                    sc.session().set_blocking(Blocking::No);
                    sc.to(cx, State::SessionDisconnect);
                }
                State::SessionDisconnect => sc.session_disconnect(cx),
                State::SessionFree => result = sc.session_free(cx),
                State::Stop => {
                    // An internal error, as C's `SSH_QUIT` and default.
                    sc.next = None;
                    sc.to(cx, State::Stop);
                }
            }
            if flow == Flow::Again || sc.state == State::Stop {
                break;
            }
        }
        let block = flow == Flow::Again;
        if result.is_ok() && sc.state == State::Stop {
            result = sc.actual;
        }
        let code = match result {
            Ok(()) => 0,
            Err(e) => e.number(),
        };
        cx.ssh(format_args!(
            "[{}] statemachine() -> {code}, block={}",
            sc.state.name(),
            u8::from(block)
        ));
        (result, block)
    }

    /// The request's path, worked out as its DO started.
    fn path(&self) -> &[u8] {
        self.path
            .as_deref()
            .expect("the request's path is worked out first")
    }

    /// `SSH_S_STARTUP`: the session set up over the socket.
    fn s_startup<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) -> Flow {
        let rc = sc.session().connect();
        sc.block2waitfor(rc == Rc::Again);
        match rc {
            Rc::Again => {
                cx.ssh(format_args!("connect -> EAGAIN"));
                Flow::Again
            }
            Rc::Error => {
                let kind = trace::fail(
                    cx,
                    ErrorKind::FailedInit,
                    format_args!("Failure establishing ssh session"),
                );
                sc.goto_error(cx, kind)
            }
            Rc::Ok => {
                sc.to(cx, State::Hostkey);
                Flow::On
            }
        }
    }

    /// Whether the server's key is the one expected: its SHA-256 or MD5
    /// fingerprint the one given, else as the known-hosts file and the
    /// application's key handler decide, else any (`myssh_is_known`).
    fn is_known<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) -> bool {
        let Some(key) = sc.session().host_key() else {
            return false;
        };
        let ssh = &cx.easy().options().ssh;
        if let Some(want) = ssh.host_key_sha256.as_deref() {
            let want = match copy(c_string(want)) {
                Ok(w) => w,
                Err(_) => return false,
            };
            let Some(sha) = key.sha256 else {
                trace::fail(
                    cx,
                    ErrorKind::PeerFailedVerification,
                    format_args!(
                        "Denied establishing ssh session: SHA256 fingerprint not available"
                    ),
                );
                return false;
            };
            let mut found = Vec::new();
            if crate::base64::encode(sha.iter().copied(), sha.len(), &mut found).is_err() {
                return false;
            }
            trace::info_with(cx, &[b"SSH SHA256 fingerprint: ", &found]);
            // The two compared up to their padding.
            let unpadded = |s: &[u8]| s.iter().position(|&b| b == b'=').unwrap_or(s.len());
            let (w, f) = (unpadded(&want), unpadded(&found));
            if w != f || want[..w] != found[..w] {
                trace::fail_with(
                    cx,
                    ErrorKind::PeerFailedVerification,
                    &[
                        b"Denied establishing ssh session: mismatch SHA256 fingerprint. Remote ",
                        &found,
                        b" is not equal to ",
                        &want,
                    ],
                );
                return false;
            }
            return true;
        }
        if let Some(want) = ssh.host_key_md5.as_deref() {
            let want = match copy(c_string(want)) {
                Ok(w) => w,
                Err(_) => return false,
            };
            let Some(md5) = key.md5 else {
                trace::fail(
                    cx,
                    ErrorKind::PeerFailedVerification,
                    format_args!("Denied establishing ssh session: MD5 fingerprint not available"),
                );
                return false;
            };
            let mut found = [0u8; 32];
            for (i, b) in md5.iter().enumerate() {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                found[2 * i] = HEX[usize::from(b >> 4)];
                found[2 * i + 1] = HEX[usize::from(b & 0xf)];
            }
            trace::info_with(cx, &[b"SSH MD5 fingerprint: ", &found]);
            if !found.eq_ignore_ascii_case(&want) {
                trace::fail_with(
                    cx,
                    ErrorKind::PeerFailedVerification,
                    &[
                        b"Denied establishing ssh session: mismatch MD5 fingerprint. Remote ",
                        &found,
                        b" is not equal to ",
                        &want,
                    ],
                );
                return false;
            }
            return true;
        }
        if ssh.known_hosts.is_none() {
            return true;
        }
        let handler = ssh.key_handler.clone();
        let (state, entry) = sc.session().known_host();
        let known = match entry {
            None => None,
            Some(Err(_)) => return false,
            Some(Ok(known)) => match known.base64 {
                None => None,
                Some(base64) if known.kind != KeyType::Other => Some((base64, known.kind)),
                Some(_) => return false,
            },
        };
        let matched = match state {
            KnownHosts::Ok => KeyMatch::Ok,
            KnownHosts::NotFound | KnownHosts::Unknown | KnownHosts::Error => KeyMatch::Missing,
            KnownHosts::Other | KnownHosts::Changed => KeyMatch::Mismatch,
        };
        let Some(handler) = handler else {
            return matched == KeyMatch::Ok;
        };
        let Some(found) = key.base64.as_deref() else {
            return false;
        };
        if key.kind == KeyType::Other {
            return false;
        }
        let verdict = handler.check(
            &mut crate::multi::TransferCx::new(cx),
            known.as_ref().map(|(b, kind)| crate::handler::HostKey {
                base64: b,
                kind: *kind,
            }),
            crate::handler::HostKey {
                base64: found,
                kind: key.kind,
            },
            matched,
        );
        match verdict {
            KeyVerdict::FineAddToFile => sc.session().update_known_hosts() == Rc::Ok,
            KeyVerdict::Fine => true,
            KeyVerdict::Reject | KeyVerdict::Defer | KeyVerdict::FineReplace => false,
        }
    }

    /// `SSH_SFTP_QUOTE_INIT`: the request's path worked out, then the
    /// quote commands before it, if any.
    fn sftp_quote_init<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
        let home = sc.home.as_deref().unwrap_or_default();
        match path::working_path(&self.url_path, Home::Sftp(home)) {
            Err(e) => {
                sc.actual = Err(e);
                sc.to(cx, State::Stop);
            }
            Ok(p) => {
                self.path = Some(p);
                if cx.easy().options().line.quote.iter().next().is_some() {
                    trace::info(cx, format_args!("Sending quote commands"));
                    sc.quote = Some((Quotes::Before, 0));
                    sc.to(cx, State::SftpQuote);
                } else {
                    sc.to(cx, State::SftpGetinfo);
                }
            }
        }
    }

    /// `SSH_SFTP_QUOTE`: the next quote command read, and the state that
    /// runs it chosen (`myssh_in_SFTP_QUOTE`).
    fn sftp_quote<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
        let (list, at) = sc.quote.expect("a quote command to run");
        let given = quote_command(cx, list, at).expect("the quote command is in its list");
        let cmd = match copy(c_string(given)) {
            Ok(cmd) => cmd,
            Err(e) => return quote_failed(cx, sc, e),
        };
        // A command starting with `*` may fail, as if it did not.
        let (cmd, accept) = match cmd.strip_prefix(b"*") {
            Some(rest) => (rest, true),
            None => (&cmd[..], false),
        };
        sc.accept_fail = accept;
        if cmd.eq_ignore_ascii_case(b"pwd") {
            // An FTP-like answer for the header handler, as FTP's `PWD`. After
            // the transfer the path has gone, and C's `%s` says so.
            let path = self.path.as_deref().unwrap_or(b"(nil)");
            let mut said = Vec::new();
            let made = said
                .try_extend_from_slice(b"257 \"")
                .and_then(|()| said.try_extend_from_slice(c_string(path)))
                .and_then(|()| said.try_extend_from_slice(b"\" is current directory.\n"));
            if made.is_err() {
                return quote_failed(cx, sc, ErrorKind::OutOfMemory);
            }
            trace::bytes(cx, DebugKind::HeaderOut, b"PWD\n");
            trace::bytes(cx, DebugKind::HeaderIn, &said);
            match self.pipeline.protocol_header(cx, &said) {
                Err(e) => quote_failed(cx, sc, e),
                Ok(()) => sc.to(cx, State::SftpNextQuote),
            }
            return;
        }
        // The arguments follow the command after a space.
        let Some(space) = cmd.iter().position(|&b| b == b' ') else {
            let kind = trace::fail(
                cx,
                ErrorKind::QuoteError,
                format_args!("Syntax error in SFTP command. Supply parameter(s)"),
            );
            return quote_failed(cx, sc, kind);
        };
        let home = sc.home.as_deref().unwrap_or_default();
        let rest = &cmd[space..];
        let (first, rest) = match path::quoted_path(rest, home) {
            Ok(read) => read,
            Err(e) => {
                bad_parameter(cx, e, "Syntax error: Bad first parameter");
                return quote_failed(cx, sc, e);
            }
        };
        sc.path1 = Some(first);
        let second = |cx: &mut StepCx<'_, H>, sc: &mut SshConn, why: &str| -> Option<Vec<u8>> {
            let home = sc.home.as_deref().unwrap_or_default();
            match path::quoted_path(rest, home) {
                Ok((p, [])) => Some(p),
                Ok(_) => {
                    suspicious(cx, sc);
                    None
                }
                Err(e) => {
                    bad_parameter(cx, e, why);
                    sc.path1 = None;
                    quote_failed(cx, sc, e);
                    None
                }
            }
        };
        let starts = |prefix: &[u8]| cmd.starts_with(prefix);
        let change = if starts(b"chgrp ") {
            Some(QuoteChange::Chgrp)
        } else if starts(b"chmod ") {
            Some(QuoteChange::Chmod)
        } else if starts(b"chown ") {
            Some(QuoteChange::Chown)
        } else if starts(b"atime ") {
            Some(QuoteChange::Atime)
        } else if starts(b"mtime ") {
            Some(QuoteChange::Mtime)
        } else {
            None
        };
        if let Some(kind) = change {
            let why = "Syntax error in chgrp/chmod/chown/atime/mtime: Bad second parameter";
            if let Some(p) = second(cx, sc, why) {
                sc.path2 = Some(p);
                sc.change = None;
                sc.to(cx, State::SftpQuoteStat(kind));
            }
        } else if starts(b"ln ") || starts(b"symlink ") {
            if let Some(p) = second(cx, sc, "Syntax error in ln/symlink: Bad second parameter") {
                sc.path2 = Some(p);
                sc.to(cx, State::SftpQuoteSymlink);
            }
        } else if starts(b"mkdir ") {
            one_path(cx, sc, rest, State::SftpQuoteMkdir);
        } else if starts(b"rename ") {
            if let Some(p) = second(cx, sc, "Syntax error in rename: Bad second parameter") {
                sc.path2 = Some(p);
                sc.to(cx, State::SftpQuoteRename);
            }
        } else if starts(b"rmdir ") {
            one_path(cx, sc, rest, State::SftpQuoteRmdir);
        } else if starts(b"rm ") {
            one_path(cx, sc, rest, State::SftpQuoteUnlink);
        } else {
            // `statvfs` among them: C's libssh code has it only where
            // `HAS_STATVFS_SUPPORT` is defined, which nothing defines.
            let kind = trace::fail(
                cx,
                ErrorKind::QuoteError,
                format_args!("Unknown SFTP command"),
            );
            sc.path1 = None;
            sc.path2 = None;
            quote_failed(cx, sc, kind);
        }
    }

    /// `SSH_SFTP_FILETIME`: the remote file's time, if the server says.
    fn sftp_filetime<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
        let path = self.path.take().unwrap_or_default();
        let attrs = sc.session().stat(&path);
        self.path = Some(path);
        match attrs {
            Err(AttrsError::OutOfMemory) => {
                sc.goto_error(cx, ErrorKind::OutOfMemory);
                return;
            }
            Ok(attrs) => cx.report_mut().set_filetime(i64::from(attrs.mtime)),
            Err(AttrsError::Status(_)) => {}
        }
        sc.to(cx, State::SftpTransInit);
    }

    /// `SSH_SFTP_UPLOAD_INIT`: the file opened to write, at the resume
    /// point, its directories made first if asked and missing, and the
    /// upload set up (`myssh_in_UPLOAD_INIT`).
    fn sftp_upload_init<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
        if self.resume_from < 0 {
            let path = self.path.take().unwrap_or_default();
            let attrs = sc.session().stat(&path);
            self.path = Some(path);
            match attrs {
                Err(AttrsError::OutOfMemory) => {
                    sc.goto_error(cx, ErrorKind::OutOfMemory);
                    return;
                }
                // C reads the field whether or not the server gave it, which
                // the library leaves zero then.
                Ok(attrs) => match i64::try_from(attrs.size.unwrap_or_default()) {
                    Ok(size) => self.resume_from = size,
                    Err(_) => {
                        let size = attrs.size.unwrap_or_default() as i64;
                        let kind = trace::fail(
                            cx,
                            ErrorKind::BadDownloadResume,
                            format_args!("Bad file size ({size})"),
                        );
                        sc.goto_error(cx, kind);
                        return;
                    }
                },
                Err(AttrsError::Status(_)) => self.resume_from = 0,
            }
        }
        let options = cx.easy().options();
        let append = options.line.ftp.append;
        let mode = if append {
            OpenMode::Append
        } else if self.resume_from > 0 {
            // Seeking, never appending: a server may write all at the end
            // of a file opened to append.
            OpenMode::Write
        } else {
            OpenMode::Truncate
        };
        let perms = u32::from(options.new_file_mode.bits());
        let create_dirs = options.line.ftp.create_dirs != CreateDirs::No;
        let path = self.path.take().unwrap_or_default();
        let opened = sc.session().open(&path, mode, perms);
        self.path = Some(path);
        if let Err(status) = opened {
            let missing = matches!(
                status,
                SftpStatus::NoSuchFile | SftpStatus::Failure | SftpStatus::NoSuchPath
            );
            // Made once only: a server that keeps refusing the file is not
            // asked again for ever, as C's libssh2 code asks.
            if missing && create_dirs && self.path().len() > 1 && !sc.second_create_dirs {
                sc.second_create_dirs = true;
                sc.to(cx, State::SftpCreateDirsInit);
            } else {
                sc.goto_close(cx, status);
            }
            return;
        }
        let mut upload = match Upload::open(cx) {
            Ok(u) => u,
            Err(e) => {
                sc.goto_error(cx, e);
                return;
            }
        };
        self.infilesize = upload.size();
        if self.resume_from > 0 && !append {
            let from = self.resume_from.unsigned_abs();
            if let Err(e) = upload.resume_from(cx, from) {
                sc.goto_error(cx, e);
                return;
            }
            if let Some(size) = self.infilesize.filter(|&s| s > 0) {
                if from > size {
                    let kind = trace::fail(
                        cx,
                        ErrorKind::BadFunctionArgument,
                        format_args!("Resume point beyond size"),
                    );
                    sc.goto_error(cx, kind);
                    return;
                }
                self.infilesize = Some(size - from);
                crate::upload::announce_size(cx, self.infilesize);
            }
            if let Err(status) = sc.session().seek(from) {
                sc.goto_close(cx, status);
                return;
            }
        }
        if self.infilesize.is_some_and(|s| s > 0) {
            crate::upload::announce_size(cx, self.infilesize);
        }
        if let Err(e) = self.start_sending(cx, upload) {
            sc.goto_error(cx, e);
            return;
        }
        self.xfer_setup(
            cx,
            Directions {
                recv: false,
                send: true,
            },
        );
        sc.writing = false;
        sc.to(cx, State::Stop);
    }

    /// The upload's body made, to be sent once the request is.
    fn start_sending<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        mut upload: Upload,
    ) -> Result<(), ErrorKind> {
        // C makes its reader as the body is first read.
        upload.trace_set_when_read();
        let mut body = Body::new(upload);
        if cx.easy().options().crlf {
            body.convert_lines().map_err(|_| ErrorKind::OutOfMemory)?;
        }
        let room = cx.easy().options().limits.upload_buffer.get();
        self.sending = Some(Sending::new(body, room)?);
        Ok(())
    }

    /// `SSH_SFTP_CREATE_DIRS_MKDIR`: the directory up to the next slash
    /// made; one there already, or refused, is passed, as one further
    /// down may still be made.
    fn sftp_create_dirs_mkdir<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        sc: &mut SshConn,
    ) -> Flow {
        let mode = u32::from(cx.easy().options().ssh.new_directory_mode.bits());
        let dir_end = sc.slash;
        let path = self.path.take().unwrap_or_default();
        let rc = sc.session().mkdir(&path[..dir_end], mode);
        self.path = Some(path);
        if rc == Err(NotDone::Again) {
            return Flow::Again;
        }
        sc.slash += 1;
        if let Err(NotDone::Failed(status)) = rc
            && !matches!(
                status,
                SftpStatus::FileAlreadyExists | SftpStatus::Failure | SftpStatus::PermissionDenied
            )
        {
            return sc.goto_close(cx, status);
        }
        sc.to(cx, State::SftpCreateDirs);
        Flow::On
    }

    /// `SSH_SFTP_READDIR_INIT`: the directory opened to list, unless no
    /// body is wanted.
    fn sftp_readdir_init<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
        self.pipeline.announce_size(cx, None);
        if self.no_body {
            sc.to(cx, State::Stop);
            return;
        }
        let path = self.path.take().unwrap_or_default();
        let opened = sc.session().opendir(&path);
        self.path = Some(path);
        if let Err(status) = opened {
            let text = sc.error_text();
            trace::fail_with(
                cx,
                ErrorKind::Ssh,
                &[b"Could not open directory for reading: ", &text],
            );
            sc.goto_close(cx, status);
            return;
        }
        sc.to(cx, State::SftpReaddir);
    }

    /// `SSH_SFTP_READDIR`: the next entry, its name alone for a list of
    /// names, else its `ls -l` line, a link's target to add to it.
    fn sftp_readdir<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
        sc.listing.clear();
        let entry = match sc.session().readdir() {
            Ok(entry) => entry,
            Err(AttrsError::OutOfMemory) => {
                sc.to(cx, State::SftpClose);
                sc.actual = Err(ErrorKind::OutOfMemory);
                return;
            }
            Err(AttrsError::Status(status)) => {
                let text = sc.error_text();
                trace::fail_with(
                    cx,
                    ErrorKind::Ssh,
                    &[b"Could not open remote directory for reading: ", &text],
                );
                sc.goto_close(cx, status);
                return;
            }
        };
        let Some(attrs) = entry else {
            sc.to(cx, State::SftpReaddirDone);
            return;
        };
        let name = attrs.name.as_deref().unwrap_or_default();
        if cx.easy().options().line.list_only {
            let mut line = Vec::new();
            if line
                .try_extend_from_slice(name)
                .and_then(|()| line.try_push(b'\n'))
                .is_err()
            {
                sc.to(cx, State::SftpClose);
                sc.actual = Err(ErrorKind::OutOfMemory);
                return;
            }
            if let Err(e) = self.pipeline.body(cx, &line) {
                sc.to(cx, State::Stop);
                sc.actual = Err(e);
            }
            return;
        }
        let long = attrs.longname.as_deref().unwrap_or_default();
        if sc.listing.try_extend_from_slice(long).is_err() {
            sc.actual = Err(ErrorKind::OutOfMemory);
            sc.to(cx, State::Stop);
            return;
        }
        let link = attrs.permissions.is_some_and(|p| p & S_IFMT == S_IFLNK);
        if link {
            let mut link_path = Vec::new();
            let made = link_path
                .try_extend_from_slice(c_string(self.path()))
                .and_then(|()| link_path.try_extend_from_slice(name));
            if made.is_err() {
                sc.to(cx, State::SftpClose);
                sc.actual = Err(ErrorKind::OutOfMemory);
                return;
            }
            sc.link = Some(link_path);
            sc.to(cx, State::SftpReaddirLink);
        } else {
            sc.to(cx, State::SftpReaddirBottom);
        }
    }

    /// `SSH_SFTP_READDIR_BOTTOM`: the entry's line ended and written.
    fn sftp_readdir_bottom<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
        let written = match sc.listing.try_push(b'\n') {
            Err(_) => Err(ErrorKind::OutOfMemory),
            Ok(()) => self.pipeline.body(cx, &sc.listing),
        };
        match written {
            Err(e) => {
                sc.to(cx, State::Stop);
                sc.actual = Err(e);
            }
            Ok(()) => sc.to(cx, State::SftpReaddir),
        }
    }

    /// `SSH_SFTP_DOWNLOAD_INIT`: the file opened to read, its reads
    /// nonblocking.
    fn sftp_download_init<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
        let perms = u32::from(cx.easy().options().new_file_mode.bits());
        let path = self.path.take().unwrap_or_default();
        let opened = sc.session().open(&path, OpenMode::Read, perms);
        self.path = Some(path);
        if let Err(status) = opened {
            let text = sc.error_text();
            trace::fail_with(
                cx,
                ErrorKind::Ssh,
                &[b"Could not open remote file for reading: ", &text],
            );
            sc.goto_close(cx, status);
            return;
        }
        sc.session().file_nonblocking();
        sc.to(cx, State::SftpDownloadStat);
    }

    /// `SSH_SFTP_DOWNLOAD_STAT`: the file's size, the range and the resume
    /// point applied to it, and the download set up
    /// (`myssh_in_SFTP_DOWNLOAD_STAT`).
    fn sftp_download_stat<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
        let attrs = match sc.session().fstat() {
            Ok(attrs) => Some(attrs),
            Err(AttrsError::Status(_)) => None,
            Err(AttrsError::OutOfMemory) => {
                sc.goto_error(cx, ErrorKind::OutOfMemory);
                return;
            }
        };
        // The size as C reads it, a signed number.
        let sized = attrs.and_then(|a| a.size).filter(|&stated| stated != 0);
        let mut size: i64;
        // The request's size, -1 if unknown (`req.size`).
        let mut req_size: i64;
        match sized {
            None => {
                // The server does not say, or the file is empty.
                req_size = -1;
                self.pipeline.announce_size(cx, None);
                size = 0;
            }
            Some(stated) => {
                size = stated as i64;
                if size < 0 {
                    let kind = trace::fail(
                        cx,
                        ErrorKind::BadDownloadResume,
                        format_args!("Bad file size ({size})"),
                    );
                    sc.goto_error(cx, kind);
                    return;
                }
                if let Some(range) = self.range.as_deref() {
                    let (from, len) = match path::range(range, size) {
                        Ok(r) => r,
                        Err(e) => {
                            match e {
                                RangeError::Beyond { from, size } => trace::fail(
                                    cx,
                                    ErrorKind::RangeError,
                                    format_args!("Offset ({from}) was beyond file size ({size})"),
                                ),
                                RangeError::Backwards => trace::fail(
                                    cx,
                                    ErrorKind::RangeError,
                                    format_args!("Bad range: start offset larger than end offset"),
                                ),
                                RangeError::Silent => ErrorKind::RangeError,
                            };
                            sc.goto_error(cx, ErrorKind::RangeError);
                            return;
                        }
                    };
                    if let Err(status) = sc.session().seek(from.unsigned_abs()) {
                        sc.goto_close(cx, status);
                        return;
                    }
                    size = len;
                }
                req_size = size;
                self.pipeline.announce_size(cx, Some(size.unsigned_abs()));
            }
        }
        if self.resume_from != 0 {
            if self.resume_from < 0 {
                if size < -self.resume_from {
                    let from = self.resume_from;
                    let kind = trace::fail(
                        cx,
                        ErrorKind::BadDownloadResume,
                        format_args!("Offset ({from}) was beyond file size ({size})"),
                    );
                    sc.goto_error(cx, kind);
                    return;
                }
                self.resume_from += size;
            } else if size < self.resume_from {
                let from = self.resume_from;
                let kind = trace::fail(
                    cx,
                    ErrorKind::BadDownloadResume,
                    format_args!("Offset ({from}) was beyond file size ({size})"),
                );
                sc.goto_error(cx, kind);
                return;
            }
            req_size = size - self.resume_from;
            let announced = u64::try_from(req_size).ok();
            self.pipeline.announce_size(cx, announced);
            if let Err(status) = sc.session().seek(self.resume_from.unsigned_abs()) {
                sc.goto_close(cx, status);
                return;
            }
        }
        if req_size == 0 {
            self.xfer_setup(cx, Directions::default());
            trace::info(cx, format_args!("File already completely downloaded"));
            sc.to(cx, State::Stop);
            return;
        }
        self.receive(cx, u64::try_from(req_size).ok());
        sc.reading = None;
        sc.to(cx, State::Stop);
    }

    /// The body set up to be read, `size` bytes of it if known
    /// (`Curl_xfer_setup_recv`).
    fn receive<H: Host>(&mut self, cx: &mut StepCx<'_, H>, size: Option<u64>) {
        self.xfer_setup(
            cx,
            Directions {
                recv: true,
                send: false,
            },
        );
        if let Some(size) = size.filter(|&s| s > 0) {
            self.pipeline.announce_size(cx, Some(size));
        }
        self.size = size;
        self.pipeline.expect(Expect {
            size,
            max: size,
            ..Expect::default()
        });
        self.receiving = !self.no_body;
    }

    /// The ways the request moves bytes, said as C says them.
    fn xfer_setup<H: Host>(&mut self, cx: &mut StepCx<'_, H>, ways: Directions) {
        crate::multi::mstate::xfer_setup(cx, ways);
        self.ways = ways;
    }

    /// `SSH_SCP_TRANS_INIT`: the request's path worked out, the session
    /// made blocking, and the channel opened to write or read the file.
    fn scp_trans_init<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
        match path::working_path(&self.url_path, Home::Scp) {
            Err(e) => {
                sc.actual = Err(e);
                sc.to(cx, State::Stop);
                return;
            }
            Ok(p) => self.path = Some(p),
        }
        // SCP's calls cannot answer that they would wait.
        sc.session().set_blocking(Blocking::Yes);
        let path = self.path.take().unwrap_or_default();
        let made = if self.upload {
            let upload = match Upload::open(cx) {
                Ok(u) => u,
                Err(e) => {
                    self.path = Some(path);
                    sc.goto_error(cx, e);
                    return;
                }
            };
            self.infilesize = upload.size();
            if self.infilesize.is_none() {
                self.path = Some(path);
                let kind = trace::fail(
                    cx,
                    ErrorKind::UploadFailed,
                    format_args!("SCP requires a known file size for upload"),
                );
                sc.goto_error(cx, kind);
                return;
            }
            self.source = Some(upload);
            let made = sc.session().scp_new(ScpWay::Write, &path);
            sc.to(cx, State::ScpUploadInit);
            made
        } else {
            let made = sc.session().scp_new(ScpWay::Read, &path);
            sc.to(cx, State::ScpDownloadInit);
            made
        };
        self.path = Some(path);
        if made.is_err() {
            let text = sc.error_text();
            let kind = trace::fail_with(cx, ErrorKind::UploadFailed, &[&text]);
            sc.goto_error(cx, kind);
        }
    }

    /// `SSH_SCP_UPLOAD_INIT`: the channel started, the file offered at
    /// its size, and the upload set up.
    fn scp_upload_init<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
        let size = self.infilesize.unwrap_or_default();
        let mode = u32::from(cx.easy().options().new_file_mode.bits());
        let path = self.path.take().unwrap_or_default();
        let pushed = sc.session().scp_init() == Rc::Ok
            && sc.session().scp_push_file(&path, size, mode) == Rc::Ok;
        self.path = Some(path);
        if !pushed {
            let text = sc.error_text();
            let kind = trace::fail_with(cx, ErrorKind::UploadFailed, &[&text]);
            sc.goto_error(cx, kind);
            return;
        }
        let upload = self
            .source
            .take()
            .expect("the upload opened with its channel");
        if let Err(e) = self.start_sending(cx, upload) {
            sc.goto_error(cx, e);
            return;
        }
        self.xfer_setup(
            cx,
            Directions {
                recv: false,
                send: true,
            },
        );
        sc.to(cx, State::Stop);
    }

    /// `SSH_SCP_DOWNLOAD`: the file the server offers, at its size, set
    /// up to be read.
    fn scp_download<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
        if sc.session().scp_pull_request() != ScpRequest::NewFile {
            let text = sc.error_text();
            let kind = trace::fail_with(cx, ErrorKind::RemoteFileNotFound, &[&text]);
            sc.goto_error(cx, kind);
            return;
        }
        let size = sc.session().scp_size();
        if i64::try_from(size).is_err() {
            sc.goto_error(cx, ErrorKind::TooLarge);
            return;
        }
        self.receive(cx, Some(size));
        sc.to(cx, State::Stop);
    }

    /// Read the body on, at most as many reads as a step makes
    /// (`sendrecv_dl`, `scp_recv`, `sftp_recv`).
    fn read_body<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        sc: &mut SshConn,
    ) -> Result<ProtoStep, ErrorKind> {
        let mut reads = 0;
        loop {
            if !self.receiving {
                return Ok(ProtoStep::Done);
            }
            if cx.pause().recv_paused() {
                return Ok(ProtoStep::Blocked);
            }
            if reads == super::http::MAX_READS {
                return Ok(ProtoStep::AtReadLimit);
            }
            let max = cx.easy().options().limits.buffer_size.get();
            let max = match cx.rate_allowance(Way::Recv) {
                Some(..=0) => return Ok(ProtoStep::Blocked),
                Some(allowed) => max.min(usize::try_from(allowed).unwrap_or(usize::MAX)),
                None => max,
            };
            // A size known is all that is read (`xfer_recv_resp`).
            let max = match self.size {
                Some(size) => {
                    let left = size.saturating_sub(self.pipeline.bytecount());
                    max.min(usize::try_from(left).unwrap_or(usize::MAX))
                }
                None => max,
            };
            // A read under way waits with the room it asked for.
            let len = sc.reading.unwrap_or(max);
            if len == 0 {
                self.read_end(cx)?;
                continue;
            }
            if self.buf.len() < len {
                self.buf.clear();
                crate::proto::http::zeros(&mut self.buf, len)
                    .map_err(|_| ErrorKind::OutOfMemory)?;
            }
            reads += 1;
            let buf = &mut self.buf[..len];
            let n = if sc.sftp {
                if sc.reading.is_none() {
                    if sc.session().begin_read(len).is_err() {
                        return Err(ErrorKind::RecvError);
                    }
                    sc.reading = Some(len);
                }
                let waited = sc.session().wait_read(buf);
                sc.block2waitfor(waited == Aio::Again);
                self.waitfor = sc.waitfor;
                match waited {
                    Aio::Again => return Ok(ProtoStep::Blocked),
                    Aio::Error => return Err(ErrorKind::RecvError),
                    Aio::Done(n) => {
                        sc.reading = None;
                        n
                    }
                }
            } else {
                sc.session().scp_read(buf).map_err(|_| ErrorKind::Ssh)?
            };
            if n == 0 {
                self.read_end(cx)?;
                continue;
            }
            let fed = self.pipeline.body(cx, &self.buf[..n]);
            deliver::write_resp(cx, n, false, fed);
            fed?;
            if self.pipeline.body_done() {
                self.receiving = false;
            }
        }
    }

    /// The body's end, read or reached by its size. The end goes through
    /// the writers, which fail a body short of its size as a partial file
    /// (`cw_download_write`); `Curl_sendrecv`'s own check never sees a
    /// difference after them, as a read takes no more than is left.
    fn read_end<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        trace::debug_info(cx, format_args!("sendrecv_dl: we are done"));
        let ended = self.pipeline.end(cx);
        deliver::write_resp(cx, 0, true, ended);
        self.receiving = false;
        ended
    }

    /// Move the exchange on: the body read, or the upload sent.
    pub(crate) fn step<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        self.pipeline.flush(cx)?;
        let sc = ssh_of(lease);
        if self.receiving {
            let read = self.read_body(cx, sc);
            match read {
                Ok(ProtoStep::AtReadLimit) => crate::multi::mstate::trace(
                    cx,
                    format_args!("sendrecv_dl() no EAGAIN/pending data, mark as dirty"),
                ),
                Err(e) => {
                    let code = e.number();
                    trace::debug_info(cx, format_args!("sendrecv_dl() -> {code}"));
                }
                Ok(_) => {}
            }
            return read;
        }
        let Some(sending) = self.sending.as_mut() else {
            return Ok(ProtoStep::Done);
        };
        let mut outlet = SshOutlet { sc, failed: None };
        let sent = sending.send_to(cx, &mut outlet);
        let failed = outlet.failed;
        self.waitfor = sc.waitfor;
        match sent {
            Err(_) if failed.is_some() => Err(failed.expect("a failure kept")),
            Ok(ProtoStep::Done) => {
                self.sending = None;
                Ok(ProtoStep::Done)
            }
            other => other,
        }
    }

    /// The transfer is over, with `result` so far (`scp_done`,
    /// `sftp_done`): a transfer that went well closes its channel or file
    /// and runs the commands after it, unless the request is to be made
    /// again on a fresh connection (`next`, C's `bits.retry`), the
    /// progress done; SCP's ends its session too.
    pub(crate) fn done<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        result: Result<(), ErrorKind>,
        premature: bool,
        next: &AfterRequest,
        exchanged: bool,
    ) -> Finish {
        if result.is_ok() && lease.conn().keeps_line() {
            let sc = ssh_of(lease);
            if sc.sftp {
                // After the file is closed, as a command may need it so.
                if !premature
                    && *next != AfterRequest::Retry
                    && cx.easy().options().line.postquote.iter().next().is_some()
                {
                    sc.next = Some(State::SftpPostquoteInit);
                }
                sc.to(cx, State::SftpClose);
            } else {
                sc.to(cx, State::ScpDone);
            }
            return self.finishing(cx, lease, exchanged);
        }
        self.over(cx, result, exchanged)
    }

    /// Run the state machine on as `done` started it, which C runs
    /// blocking (`myssh_block_statemach`), each pass the progress
    /// checked: a call that would wait leaves it waiting in DONE.
    pub(crate) fn finishing<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        exchanged: bool,
    ) -> Finish {
        let ran = self.run(cx, lease);
        let checked = crate::progress::check(cx, exchanged);
        match (ran, checked) {
            (Err(e), _) | (Ok(_), Err(e)) => self.over(cx, Err(e), exchanged),
            (Ok(true), Ok(_)) => self.over(cx, Ok(()), exchanged),
            (Ok(false), Ok(_)) => Finish::Waiting,
        }
    }

    /// The end: the progress done, an abort it asks for the result
    /// (`myssh_done`).
    fn over<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        result: Result<(), ErrorKind>,
        exchanged: bool,
    ) -> Finish {
        if crate::progress::finish(cx, exchanged).is_err() {
            return Finish::Done(Err(ErrorKind::AbortedByCallback));
        }
        self.receiving = false;
        self.sending = None;
        Finish::Done(result)
    }

    /// The connection's SSH state, made the first time (`myssh_connect`):
    /// the session made and handed the socket, the host, user, known-hosts
    /// file, port, compression and public key set.
    fn conn_state<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let sftp = self.peer.scheme() == Scheme::of("sftp");
        cx.ssh(format_args!("myssh_connect"));
        let Some(library) = cx.easy().libraries().ssh else {
            return Err(ErrorKind::UnsupportedProtocol);
        };
        let Some(mut session) = library.session() else {
            return Err(trace::fail(
                cx,
                ErrorKind::FailedInit,
                format_args!("Failure initializing ssh session"),
            ));
        };
        let cold = lease.conn().net_route().and_then(|r| r.cold.clone());
        // An IPv6 address in its brackets, else the name as looked up.
        let host = if self.peer.ipv6() {
            self.peer.shown()
        } else {
            self.peer.name()
        };
        if session.set_host(host).is_err() {
            return Err(trace::fail(
                cx,
                ErrorKind::FailedInit,
                format_args!("Could not set remote host"),
            ));
        }
        if session.parse_config().is_err() {
            trace::info(cx, format_args!("Could not parse SSH configuration files"));
        }
        // The library reads the socket itself: no layer of ours may work
        // on its bytes, nor any received wait unused.
        let carrier = lease.get().carrier();
        let Some(socket) = carrier.bare_socket() else {
            return Err(trace::fail(
                cx,
                ErrorKind::FailedInit,
                format_args!("Could not set socket: bytes past the tunnel are held"),
            ));
        };
        let fd = socket.key().get();
        cx.ssh(format_args!("myssh_connect, set socket={fd}"));
        if session.set_socket(socket.descriptor()).is_err() {
            return Err(trace::fail(
                cx,
                ErrorKind::FailedInit,
                format_args!("Could not set socket"),
            ));
        }
        let login = cold.as_deref().and_then(|c| c.login.as_ref());
        let user = login.map_or(&[][..], |l| c_string(l.user()));
        if !user.is_empty() {
            trace::info_with(cx, &[b"User: ", user]);
            if session.set_user(user).is_err() {
                return Err(trace::fail(
                    cx,
                    ErrorKind::FailedInit,
                    format_args!("Could not set user"),
                ));
            }
        }
        if let Some(known) = cx.easy().options().ssh.known_hosts.as_deref() {
            let known = copy(c_string(known))?;
            trace::info_with(cx, &[b"Known hosts: ", &known]);
            if session.set_known_hosts(&known).is_err() {
                return Err(trace::fail(
                    cx,
                    ErrorKind::FailedInit,
                    format_args!("Could not set known hosts file path"),
                ));
            }
        }
        if self.peer.port() != 0 && session.set_port(self.peer.port()).is_err() {
            return Err(trace::fail(
                cx,
                ErrorKind::FailedInit,
                format_args!("Could not set remote port"),
            ));
        }
        if cx.easy().options().ssh.compression && session.set_compression().is_err() {
            return Err(trace::fail(
                cx,
                ErrorKind::FailedInit,
                format_args!("Could not set compression"),
            ));
        }
        let keys = cold.as_deref().and_then(|c| c.ssh.as_ref());
        if let Some(public) = keys.and_then(|k| k.public.as_deref())
            && session.import_pubkey_file(c_string(public)).is_err()
        {
            return Err(trace::fail(
                cx,
                ErrorKind::FailedInit,
                format_args!("Could not load public key file"),
            ));
        }
        let sc = SshConn {
            session: Some(session),
            sftp,
            state: State::Stop,
            next: None,
            actual: Ok(()),
            waitfor: PollFlags::default(),
            methods: Methods::default(),
            authed: false,
            kbd: Kbd::Asking,
            home: None,
            cold,
            quote: None,
            path1: None,
            path2: None,
            accept_fail: false,
            change: None,
            listing: Vec::new(),
            link: None,
            slash: 0,
            second_create_dirs: false,
            reading: None,
            writing: false,
        };
        let line = curl_alloc::try_box(LineConn::Ssh(
            curl_alloc::try_box(sc).map_err(|_| ErrorKind::OutOfMemory)?,
        ))
        .map_err(|_| ErrorKind::OutOfMemory)?;
        lease.get().put_line(line);
        let sc = ssh_of(lease);
        sc.to(cx, State::Init);
        Ok(())
    }
}

/// The transfer's quote command `at` of `list`, if it has one.
fn quote_command<'c, H: Host>(cx: &'c StepCx<'_, H>, list: Quotes, at: usize) -> Option<&'c [u8]> {
    let line = &cx.easy().options().line;
    match list {
        Quotes::Before => line.quote.iter().nth(at),
        Quotes::After => line.postquote.iter().nth(at),
    }
}

/// The quote commands end on `kind` (`myssh_quote_error` without a
/// command, and its like in `myssh_in_SFTP_QUOTE`): the file closed, and
/// nothing after.
fn quote_failed<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn, kind: ErrorKind) {
    sc.path1 = None;
    sc.path2 = None;
    sc.to(cx, State::SftpClose);
    sc.next = None;
    sc.actual = Err(kind);
}

/// A quote command's path that did not read, said as C says it.
fn bad_parameter<H: Host>(cx: &mut StepCx<'_, H>, e: ErrorKind, why: &str) {
    if e == ErrorKind::OutOfMemory {
        trace::fail(cx, e, format_args!("Out of memory"));
    } else {
        trace::fail(cx, e, format_args!("{why}"));
    }
}

/// Bytes after a command's last path (`quote_error`).
fn suspicious<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
    let kind = trace::fail(
        cx,
        ErrorKind::QuoteError,
        format_args!("Suspicious data after the command line"),
    );
    quote_failed(cx, sc, kind);
}

/// A command of one path: nothing after it.
fn one_path<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn, rest: &[u8], state: State) {
    if rest.is_empty() {
        sc.to(cx, state);
    } else {
        suspicious(cx, sc);
    }
}

/// A quote command's call came to `rc`: the next command, unless it
/// failed and may not (`myssh_quote_error` with the command's name).
fn quote_done<H: Host>(
    cx: &mut StepCx<'_, H>,
    sc: &mut SshConn,
    rc: Result<(), NotDone>,
    name: &str,
) -> Flow {
    match rc {
        Err(NotDone::Again) => Flow::Again,
        Err(NotDone::Failed(_)) if !sc.accept_fail => {
            let text = sc.error_text();
            let kind = trace::fail_with(
                cx,
                ErrorKind::QuoteError,
                &[name.as_bytes(), b" command failed: ", &text],
            );
            quote_failed(cx, sc, kind);
            Flow::On
        }
        _ => {
            sc.to(cx, State::SftpNextQuote);
            Flow::On
        }
    }
}

/// `SSH_SFTP_QUOTE_STAT`: the file's attributes read and the command's
/// change to them made, to be sent.
fn sftp_quote_stat<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn, kind: QuoteChange) {
    let path2 = sc.path2.take().unwrap_or_default();
    let stated = sc.session().stat_to_change(&path2);
    sc.path2 = Some(path2);
    if let Err(status) = stated {
        let code = status.number();
        let kind = trace::fail(
            cx,
            ErrorKind::QuoteError,
            format_args!("Attempt to get SFTP stats failed: {code}"),
        );
        return quote_failed(cx, sc, kind);
    }
    let arg = sc.path1.as_deref().unwrap_or_default();
    let number = |max: u32, base: u32| path::number(arg, i64::from(max), base).map(|(n, _)| n);
    let change = match kind {
        QuoteChange::Chgrp => match number(u32::MAX, 10) {
            Ok(n) => AttrChange::Gid(n as u32),
            Err(_) => {
                let kind = trace::fail(
                    cx,
                    ErrorKind::QuoteError,
                    format_args!("Syntax error: chgrp gid not a number"),
                );
                return quote_failed(cx, sc, kind);
            }
        },
        QuoteChange::Chmod => match number(0o7777, 8) {
            Ok(n) => AttrChange::Permissions(n as u32),
            Err(_) => {
                let kind = trace::fail(
                    cx,
                    ErrorKind::QuoteError,
                    format_args!("Syntax error: chmod permissions not a number"),
                );
                return quote_failed(cx, sc, kind);
            }
        },
        QuoteChange::Chown => match number(u32::MAX, 10) {
            Ok(n) => AttrChange::Uid(n as u32),
            Err(_) => {
                let kind = trace::fail(
                    cx,
                    ErrorKind::QuoteError,
                    format_args!("Syntax error: chown uid not a number"),
                );
                return quote_failed(cx, sc, kind);
            }
        },
        QuoteChange::Atime | QuoteChange::Mtime => {
            let date = match crate::date::parse(arg) {
                Err(_) => {
                    let name = if kind == QuoteChange::Atime {
                        "atime"
                    } else {
                        "mtime"
                    };
                    let kind = trace::fail(
                        cx,
                        ErrorKind::QuoteError,
                        format_args!("incorrect date format for {name}"),
                    );
                    return quote_failed(cx, sc, kind);
                }
                Ok(date) if date > 0xffff_ffff => {
                    let kind =
                        trace::fail(cx, ErrorKind::QuoteError, format_args!("date overflow"));
                    return quote_failed(cx, sc, kind);
                }
                Ok(date) => date as u32,
            };
            if kind == QuoteChange::Atime {
                AttrChange::Atime(date)
            } else {
                AttrChange::Mtime(date)
            }
        }
    };
    sc.change = Some(change);
    sc.to(cx, State::SftpQuoteSetstat);
}

/// Whether the application lets the user log in by `way`.
fn allows<H: Host>(cx: &StepCx<'_, H>, way: SshAuthTypes) -> bool {
    cx.easy().options().ssh.auth_types.allows(way)
}

/// The password the connection logs in with, up to a zero byte.
fn password(sc: &SshConn) -> Result<Vec<u8>, ErrorKind> {
    let login = sc.cold.as_deref().and_then(|c| c.login.as_ref());
    copy(login.map_or(&[][..], |l| c_string(l.secret().password())))
}

/// The key files the connection logs in with.
fn keys(sc: &SshConn) -> Option<&Keys> {
    sc.cold.as_deref().and_then(|c| c.ssh.as_ref())
}

/// The password login, if the server offers it, else a failed one
/// (`myssh_to_PASSWD_AUTH`).
fn to_passwd<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) -> Flow {
    if sc.methods.has(Methods::PASSWORD) {
        sc.to(cx, State::AuthPassInit);
        Flow::On
    } else {
        sc.goto_error(cx, ErrorKind::LoginDenied)
    }
}

/// Keyboard-interactive, if offered, else on (`myssh_to_KEY_AUTH`).
fn to_key_auth<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) -> Flow {
    if sc.methods.has(Methods::INTERACTIVE) {
        sc.to(cx, State::AuthKeyInit);
        Flow::On
    } else {
        to_passwd(cx, sc)
    }
}

/// GSS-API, if offered, else on (`myssh_to_GSSAPI_AUTH`).
fn to_gssapi<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) -> Flow {
    if sc.methods.has(Methods::GSSAPI_MIC) {
        sc.to(cx, State::AuthGssapi);
        Flow::On
    } else {
        to_key_auth(cx, sc)
    }
}

/// `SSH_AUTHLIST`: no login tried first, then the ways the server offers
/// read, and the first the transfer may use chosen.
fn authlist<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) -> Flow {
    sc.authed = false;
    match sc.session().auth_none() {
        Auth::Again => return Flow::Again,
        Auth::Success => {
            sc.authed = true;
            trace::info(cx, format_args!("Authenticated with none"));
            sc.to(cx, State::AuthDone);
            return Flow::On;
        }
        Auth::Error => return sc.goto_error(cx, ErrorKind::LoginDenied),
        Auth::Denied | Auth::Partial | Auth::Info => {}
    }
    sc.methods = sc.session().auth_list();
    let m = sc.methods;
    if m != Methods::NONE {
        trace::info(
            cx,
            format_args!(
                "SSH authentication methods available: {}{}{}{}",
                if m.has(Methods::PUBLICKEY) {
                    "public key, "
                } else {
                    ""
                },
                if m.has(Methods::GSSAPI_MIC) {
                    "GSSAPI, "
                } else {
                    ""
                },
                if m.has(Methods::INTERACTIVE) {
                    "keyboard-interactive, "
                } else {
                    ""
                },
                if m.has(Methods::PASSWORD) {
                    "password"
                } else {
                    ""
                },
            ),
        );
    }
    let private = keys(sc)
        .and_then(Keys::private)
        .is_some_and(|k| !k.is_empty());
    if m.has(Methods::PUBLICKEY) && (private || allows(cx, SshAuthTypes::AGENT)) {
        sc.to(cx, State::AuthPkeyInit);
        trace::info(cx, format_args!("Authentication using SSH public key file"));
    } else if m.has(Methods::GSSAPI_MIC) {
        sc.to(cx, State::AuthGssapi);
    } else if m.has(Methods::INTERACTIVE) {
        sc.to(cx, State::AuthKeyInit);
    } else if m.has(Methods::PASSWORD) {
        sc.to(cx, State::AuthPassInit);
    } else {
        return sc.goto_error(cx, ErrorKind::LoginDenied);
    }
    Flow::On
}

/// `SSH_AUTH_PKEY_INIT`: the private key given, its public key offered
/// first if given and no passphrase is, or else the agent's and the
/// default keys.
fn auth_pkey_init<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) -> Flow {
    if !allows(cx, SshAuthTypes::PUBLICKEY) {
        return to_gssapi(cx, sc);
    }
    let (private, passphrase) = match keys(sc) {
        Some(k) => (
            k.private().filter(|p| !p.is_empty()).map(copy).transpose(),
            k.passphrase
                .as_deref()
                .map(|p| copy(c_string(p)))
                .transpose(),
        ),
        None => (Ok(None), Ok(None)),
    };
    let (Ok(private), Ok(passphrase)) = (private, passphrase) else {
        return sc.goto_error(cx, ErrorKind::OutOfMemory);
    };
    match private {
        Some(private) => {
            if sc.session().has_pubkey() && passphrase.is_none() {
                match sc.session().try_publickey() {
                    Auth::Again => return Flow::Again,
                    Auth::Success => {}
                    _ => return to_gssapi(cx, sc),
                }
            }
            if sc
                .session()
                .import_privkey_file(&private, passphrase.as_deref())
                != Rc::Ok
            {
                let kind = trace::fail_with(
                    cx,
                    ErrorKind::LoginDenied,
                    &[b"Could not load private key file ", &private],
                );
                return sc.goto_error(cx, kind);
            }
            sc.to(cx, State::AuthPkey);
            Flow::On
        }
        None => match sc.session().auth_publickey_auto(passphrase.as_deref()) {
            Auth::Again => Flow::Again,
            Auth::Success => {
                sc.authed = true;
                trace::info(cx, format_args!("Completed public key authentication"));
                sc.to(cx, State::AuthDone);
                Flow::On
            }
            _ => to_gssapi(cx, sc),
        },
    }
}

/// `SSH_AUTH_PKEY`: the private key's login.
fn auth_pkey<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) -> Flow {
    match sc.session().auth_publickey() {
        Auth::Again => Flow::Again,
        Auth::Success => {
            sc.authed = true;
            trace::info(cx, format_args!("Completed public key authentication"));
            sc.to(cx, State::AuthDone);
            Flow::On
        }
        rc => {
            let n = rc.number();
            trace::info(
                cx,
                format_args!("Failed public key authentication (rc: {n})"),
            );
            to_gssapi(cx, sc)
        }
    }
}

/// `SSH_AUTH_GSSAPI`: a GSS-API login, if the transfer may.
fn auth_gssapi<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) -> Flow {
    if !allows(cx, SshAuthTypes::GSSAPI) {
        return to_key_auth(cx, sc);
    }
    match sc.session().auth_gssapi() {
        Auth::Again => Flow::Again,
        Auth::Success => {
            sc.authed = true;
            trace::info(cx, format_args!("Completed gssapi authentication"));
            sc.to(cx, State::AuthDone);
            Flow::On
        }
        _ => to_key_auth(cx, sc),
    }
}

/// `SSH_AUTH_KEY`: the keyboard-interactive login.
fn auth_key<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) -> Flow {
    match interactive(sc) {
        Rc::Again => Flow::Again,
        Rc::Ok => {
            sc.authed = true;
            trace::info(
                cx,
                format_args!("completed keyboard interactive authentication"),
            );
            sc.to(cx, State::AuthDone);
            Flow::On
        }
        Rc::Error => to_passwd(cx, sc),
    }
}

/// The keyboard-interactive exchange: one question, answered with the
/// password, then none (`myssh_auth_interactive`).
fn interactive(sc: &mut SshConn) -> Rc {
    loop {
        match sc.kbd {
            Kbd::Asking => {
                match sc.session().auth_kbdint() {
                    Auth::Again => return Rc::Again,
                    Auth::Info => {}
                    _ => return Rc::Error,
                }
                if sc.session().kbdint_prompts() != Ok(1) {
                    return Rc::Error;
                }
                let Ok(password) = password(sc) else {
                    return Rc::Error;
                };
                if sc.session().kbdint_answer(0, &password).is_err() {
                    return Rc::Error;
                }
                sc.kbd = Kbd::Answered;
            }
            Kbd::Answered => match sc.session().auth_kbdint() {
                Auth::Again => return Rc::Again,
                Auth::Success => break,
                Auth::Info => {
                    if sc.session().kbdint_prompts() != Ok(0) {
                        return Rc::Error;
                    }
                    sc.kbd = Kbd::Confirming;
                }
                _ => {
                    sc.kbd = Kbd::Asking;
                    return Rc::Error;
                }
            },
            Kbd::Confirming => match sc.session().auth_kbdint() {
                Auth::Again => return Rc::Again,
                Auth::Success => break,
                _ => {
                    sc.kbd = Kbd::Asking;
                    return Rc::Error;
                }
            },
        }
    }
    sc.kbd = Kbd::Asking;
    Rc::Ok
}

/// `SSH_AUTH_PASS`: the password login.
fn auth_pass<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) -> Flow {
    let Ok(password) = password(sc) else {
        return sc.goto_error(cx, ErrorKind::OutOfMemory);
    };
    match sc.session().auth_password(&password) {
        Auth::Again => Flow::Again,
        Auth::Success => {
            sc.authed = true;
            trace::info(cx, format_args!("Completed password authentication"));
            sc.to(cx, State::AuthDone);
            Flow::On
        }
        _ => sc.goto_error(cx, ErrorKind::LoginDenied),
    }
}

/// `SSH_AUTH_DONE`: logged in, the application connected; on to SFTP's
/// session, or SCP's connect done.
fn auth_done<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
    if !sc.authed {
        let kind = trace::fail(
            cx,
            ErrorKind::LoginDenied,
            format_args!("Authentication failure"),
        );
        sc.goto_error(cx, kind);
        return;
    }
    trace::info(cx, format_args!("Authentication complete"));
    cx.mark(Timer::AppConnect);
    if sc.sftp {
        sc.to(cx, State::SftpInit);
    } else {
        trace::info(cx, format_args!("SSH CONNECT phase done"));
        sc.to(cx, State::Stop);
    }
}

/// `SSH_SFTP_INIT`: the session blocking from now on, and the SFTP
/// subsystem started over it.
fn sftp_init<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
    sc.session().set_blocking(Blocking::Yes);
    if sc.session().sftp_new().is_err() {
        let text = sc.error_text();
        let kind = trace::fail_with(
            cx,
            ErrorKind::CouldntConnect,
            &[b"Failure initializing sftp session: ", &text],
        );
        sc.goto_error(cx, kind);
        return;
    }
    if sc.session().sftp_init() != Rc::Ok {
        let text = sc.error_text();
        trace::fail_with(
            cx,
            ErrorKind::Ssh,
            &[b"Failure initializing sftp session: ", &text],
        );
        let kind = sftp_failure(SftpStatus::Failure).expect_err("FAILURE is one");
        sc.goto_error(cx, kind);
        return;
    }
    sc.to(cx, State::SftpRealpath);
}

/// `SSH_SFTP_REALPATH`: the home directory, the connect's last step.
fn sftp_realpath<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
    let home = match sc.session().canonicalize(b".") {
        Ok(Some(home)) => home,
        Ok(None) => {
            sc.goto_error(cx, ErrorKind::CouldntConnect);
            return;
        }
        Err(_) => {
            sc.goto_error(cx, ErrorKind::OutOfMemory);
            return;
        }
    };
    let recent = match copy(c_string(&home)) {
        Ok(r) => r,
        Err(e) => {
            sc.goto_error(cx, e);
            return;
        }
    };
    if cx.report_mut().set_ftp_entry_path(recent).is_err() {
        sc.goto_error(cx, ErrorKind::OutOfMemory);
        return;
    }
    sc.home = Some(home);
    cx.ssh(format_args!("CONNECT phase done"));
    sc.to(cx, State::Stop);
}

/// `SSH_SFTP_READDIR_LINK`: a link's target, added to its entry's line.
fn sftp_readdir_link<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut SshConn) {
    let link = sc.link.take().unwrap_or_default();
    let attrs = match sc.session().lstat(&link) {
        Ok(attrs) => attrs,
        Err(AttrsError::Status(status)) => {
            let text = sc.error_text();
            trace::fail_with(
                cx,
                ErrorKind::Ssh,
                &[b"Could not read symlink for reading: ", &text],
            );
            sc.goto_close(cx, status);
            return;
        }
        Err(AttrsError::OutOfMemory) => {
            sc.to(cx, State::SftpClose);
            sc.actual = Err(ErrorKind::OutOfMemory);
            return;
        }
    };
    let target = match attrs.name {
        Some(name) => Ok(Some(name)),
        None => sc.session().readlink(&link),
    };
    let added = target.map_err(|_| ()).and_then(|target| {
        sc.listing
            .try_extend_from_slice(b" -> ")
            .and_then(|()| {
                // A target the server does not give is C's `%s` of NULL.
                sc.listing
                    .try_extend_from_slice(target.as_deref().unwrap_or(b"(nil)"))
            })
            .map_err(|_| ())
    });
    if added.is_err() {
        sc.to(cx, State::SftpClose);
        sc.actual = Err(ErrorKind::OutOfMemory);
        return;
    }
    sc.to(cx, State::SftpReaddirBottom);
}

/// The upload's bytes go to the SCP channel, blocking, or as SFTP's
/// asynchronous writes, one under way at a time (`scp_send`,
/// `sftp_send`).
struct SshOutlet<'s> {
    sc: &'s mut SshConn,
    /// The failure a write came to, past the send failure it is told as.
    failed: Option<ErrorKind>,
}

impl<H: Host> Outlet<H> for SshOutlet<'_> {
    fn put(&mut self, _: &mut StepCx<'_, H>, bytes: &[u8]) -> std::io::Result<Sent> {
        let sc = &mut *self.sc;
        let n = std::num::NonZeroUsize::new(bytes.len()).expect("a write of something");
        if !sc.sftp {
            if sc.session().scp_write(bytes) == Rc::Ok {
                return Ok(Sent::Bytes(n));
            }
            self.failed = Some(ErrorKind::Ssh);
            return Err(std::io::Error::other("SCP write failed"));
        }
        if !sc.writing {
            sc.session().file_nonblocking();
            if sc.session().begin_write(bytes).is_err() {
                self.failed = Some(ErrorKind::SendError);
                return Err(std::io::Error::other("SFTP write failed"));
            }
            sc.writing = true;
        }
        let waited = sc.session().wait_write();
        sc.block2waitfor(waited == Aio::Again);
        match waited {
            Aio::Again => Ok(Sent::WouldBlock),
            Aio::Error => {
                sc.writing = false;
                self.failed = Some(ErrorKind::SendError);
                Err(std::io::Error::other("SFTP write failed"))
            }
            Aio::Done(written) => {
                sc.writing = false;
                Ok(std::num::NonZeroUsize::new(written).map_or(Sent::WouldBlock, Sent::Bytes))
            }
        }
    }
}

/// The connection's SSH state.
fn ssh_of(lease: &mut ConnLease) -> &mut SshConn {
    match lease.get().line_mut() {
        Some((LineConn::Ssh(sc), _)) => sc,
        _ => unreachable!("an SSH transfer's connection keeps SSH's state"),
    }
}

impl super::Phases for Request {
    fn connect<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Connect, ErrorKind> {
        if !lease.conn().keeps_line() {
            self.conn_state(cx, lease)?;
        }
        Ok(if self.run(cx, lease)? {
            Connect::Done
        } else {
            Connect::Waiting
        })
    }

    fn make<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        asked: DoPhase,
    ) -> Result<DoStep, ErrorKind> {
        let ran = match asked {
            DoPhase::Do => {
                self.size = None;
                let sc = ssh_of(lease);
                sc.actual = Ok(());
                sc.second_create_dirs = false;
                crate::progress::reset(cx);
                cx.ssh(format_args!("DO phase starts"));
                let first = if sc.sftp {
                    State::SftpQuoteInit
                } else {
                    State::ScpTransInit
                };
                sc.to(cx, first);
                self.run(cx, lease)?
            }
            DoPhase::Doing => self.run(cx, lease)?,
            DoPhase::More => unreachable!("SSH has no second half"),
        };
        if ran {
            cx.ssh(format_args!("DO phase is complete"));
            Ok(DoStep::Did)
        } else {
            Ok(DoStep::Doing)
        }
    }

    fn waits(&self, _: Waiting) -> Events {
        self.pollset(Directions::default())
    }
}

#[cfg(test)]
mod tests;
