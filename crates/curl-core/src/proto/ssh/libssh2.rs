//! SCP and SFTP over libssh2 (`lib/vssh/libssh2.c`): the session over the
//! connection's own socket, every call nonblocking; the host key checked
//! against the fingerprints, the application's host key handler or the
//! known-hosts file (whose entry for the host picks the key type asked
//! for first); the logins by public key, password, the agent, then
//! keyboard-interactive; then per transfer an SCP channel, which the
//! connection outlives, or SFTP's quote commands, listing, download or
//! upload over its session.
//!
//! The state machine is C's, state for state and trace for trace
//! (`ssh_statemachine`): what libssh2 is called with, and when, is what
//! goes on the wire. What the request keeps, its path, range and body,
//! is the one `Request` both libraries' machines share, as C's
//! `SSHPROTO` is; what C's `vssh.c` shares, the key files, the paths and
//! the range, is the parent module's.

use std::fmt;
use std::time::Duration;

use curl_alloc::{TryArc, TryVec as _};

use super::path::{self, Home, RangeError};
use super::{Keys, Quotes, Request, S_IFLNK, S_IFMT, c_string, copy, quote_command};
use crate::components::Component;
use crate::conn::io::{Events, Sent, SocketPoll};
use crate::conn::layer::{LayerCalls as _, LayerCx};
use crate::conn::line::LineConn;
use crate::conn::mux::Carrier;
use crate::conn::{ConnLease, RouteCold};
use crate::deliver::{self, Directions};
use crate::error::ErrorKind;
use crate::handler::{DebugKind, HostKey, KeyEncoding, KeyMatch, KeyVerdict};
use crate::multi::Host;
use crate::multi::state::{AfterRequest, StepCx};
use crate::options::{CreateDirs, SshAuthTypes};
use crate::progress::rate::Way;
use crate::proto::{Connect, DoPhase, DoStep, Finish, ProtoStep};
use crate::report::Timer;
use crate::ssh::{KeyType, OpenMode, PollFlags};
use crate::ssh2::{
    AttrFlags, Attrs, Blocking, Check, Code, Crypto, Fx, HostKeyType, Identity, KeyForm,
    KnownKeyType, Let, Session2,
};
use crate::trace;
use crate::upload::Upload;
use crate::upload::sending::Outlet;

/// SSH's own port, which known-hosts entries name no port for
/// (`PORT_SSH`).
const PORT_SSH: u16 = 22;

/// Where the state machine is (`sshstate`, as `vssh.c` names them).
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
    AuthAgentInit,
    AuthAgentList,
    AuthAgent,
    AuthHostInit,
    AuthHost,
    AuthKeyInit,
    AuthKey,
    AuthDone,
    SftpInit,
    SftpRealpath,
    SftpQuoteInit,
    SftpPostquoteInit,
    SftpQuote,
    SftpNextQuote,
    SftpQuoteStat,
    SftpQuoteSetstat,
    SftpQuoteSymlink,
    SftpQuoteMkdir,
    SftpQuoteRename,
    SftpQuoteRmdir,
    SftpQuoteUnlink,
    SftpQuoteStatvfs,
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
    ScpDone,
    ScpSendEof,
    ScpWaitEof,
    ScpWaitClose,
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
            State::AuthAgentInit => "SSH_AUTH_AGENT_INIT",
            State::AuthAgentList => "SSH_AUTH_AGENT_LIST",
            State::AuthAgent => "SSH_AUTH_AGENT",
            State::AuthHostInit => "SSH_AUTH_HOST_INIT",
            State::AuthHost => "SSH_AUTH_HOST",
            State::AuthKeyInit => "SSH_AUTH_KEY_INIT",
            State::AuthKey => "SSH_AUTH_KEY",
            State::AuthDone => "SSH_AUTH_DONE",
            State::SftpInit => "SSH_SFTP_INIT",
            State::SftpRealpath => "SSH_SFTP_REALPATH",
            State::SftpQuoteInit => "SSH_SFTP_QUOTE_INIT",
            State::SftpPostquoteInit => "SSH_SFTP_POSTQUOTE_INIT",
            State::SftpQuote => "SSH_SFTP_QUOTE",
            State::SftpNextQuote => "SSH_SFTP_NEXT_QUOTE",
            State::SftpQuoteStat => "SSH_SFTP_QUOTE_STAT",
            State::SftpQuoteSetstat => "SSH_SFTP_QUOTE_SETSTAT",
            State::SftpQuoteSymlink => "SSH_SFTP_QUOTE_SYMLINK",
            State::SftpQuoteMkdir => "SSH_SFTP_QUOTE_MKDIR",
            State::SftpQuoteRename => "SSH_SFTP_QUOTE_RENAME",
            State::SftpQuoteRmdir => "SSH_SFTP_QUOTE_RMDIR",
            State::SftpQuoteUnlink => "SSH_SFTP_QUOTE_UNLINK",
            State::SftpQuoteStatvfs => "SSH_SFTP_QUOTE_STATVFS",
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
            State::ScpDone => "SSH_SCP_DONE",
            State::ScpSendEof => "SSH_SCP_SEND_EOF",
            State::ScpWaitEof => "SSH_SCP_WAIT_EOF",
            State::ScpWaitClose => "SSH_SCP_WAIT_CLOSE",
            State::ScpChannelFree => "SSH_SCP_CHANNEL_FREE",
            State::SessionDisconnect => "SSH_SESSION_DISCONNECT",
            State::SessionFree => "SSH_SESSION_FREE",
        }
    }
}

/// What SSH keeps on its connection over libssh2 (`struct ssh_conn`),
/// and what C keeps per transfer beside its request (`SSHPROTO`'s
/// attributes and listing buffers), which a connection serves one at a
/// time.
#[derive(Debug)]
pub(crate) struct Ssh2Conn {
    /// The library's session, none once it is freed (`SSH_SESSION_FREE`).
    session: Option<Box<dyn Session2>>,
    /// SFTP's, not SCP's.
    sftp: bool,
    state: State,
    /// Where the state machine goes once the one it is in is over
    /// (`nextstate`, none for `SSH_NO_STATE`).
    next: Option<State>,
    /// What the session waits for, after a call that would have waited
    /// (`waitfor`).
    waitfor: PollFlags,
    /// The ways the server lets the user log in, as it listed them
    /// (`authlist`).
    authlist: Vec<u8>,
    authed: bool,
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
    /// The attributes a quote command sets (`quote_attrs`).
    quote_attrs: Attrs,
    /// The listing's line being made (`readdir`).
    listing: Vec<u8>,
    /// The link a listed entry is (`readdir_link`).
    link: Vec<u8>,
    /// Where in the request's path the next directory to make ends
    /// (`slash_pos`).
    slash: usize,
    /// The upload's directories were made once (`secondCreateDirs`).
    second_create_dirs: bool,
}

/// What C's trace says, from a transfer's step or from a connection's
/// shutdown: the SSH trace (`CURL_TRC_SSH`), the verbose lines
/// (`infof`) and a failure (`failf`).
trait Says {
    fn ssh(&mut self, args: fmt::Arguments<'_>);
    fn info(&mut self, args: fmt::Arguments<'_>);
    fn info_with(&mut self, parts: &[&[u8]]);
}

impl<H: Host> Says for StepCx<'_, H> {
    fn ssh(&mut self, args: fmt::Arguments<'_>) {
        trace::of(self, Component::Ssh, args);
    }

    fn info(&mut self, args: fmt::Arguments<'_>) {
        trace::info(self, args);
    }

    fn info_with(&mut self, parts: &[&[u8]]) {
        trace::info_with(self, parts);
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

    fn info(&mut self, args: fmt::Arguments<'_>) {
        if let Some(t) = self.0.trace() {
            t.info_line(args);
        }
    }

    fn info_with(&mut self, parts: &[&[u8]]) {
        if let Some(t) = self.0.trace() {
            t.info_line_with(parts);
        }
    }
}

/// What a connection logs in with, each up to a zero byte.
struct Login<'a> {
    user: &'a [u8],
    password: &'a [u8],
    keys: Option<&'a Keys>,
}

/// Why a state's work stopped the run: the session would wait
/// (`CURLE_AGAIN`), or it failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Halt {
    Again,
    Fail(ErrorKind),
}

impl From<ErrorKind> for Halt {
    fn from(kind: ErrorKind) -> Halt {
        Halt::Fail(kind)
    }
}

/// How a state's work went.
type Ran = Result<(), Halt>;

/// The failure an SFTP status is (`sftp_libssh2_error_to_CURLE`); none
/// for `LIBSSH2_FX_OK`.
fn sftp_failure(fx: Fx) -> Result<(), ErrorKind> {
    match fx {
        Fx::OK => Ok(()),
        Fx::NO_SUCH_FILE | Fx::NO_SUCH_PATH => Err(ErrorKind::RemoteFileNotFound),
        Fx::PERMISSION_DENIED | Fx::WRITE_PROTECT | Fx::LOCK_CONFLICT => {
            Err(ErrorKind::RemoteAccessDenied)
        }
        Fx::NO_SPACE_ON_FILESYSTEM | Fx::QUOTA_EXCEEDED => Err(ErrorKind::RemoteDiskFull),
        Fx::FILE_ALREADY_EXISTS => Err(ErrorKind::RemoteFileExists),
        Fx::DIR_NOT_EMPTY => Err(ErrorKind::QuoteError),
        _ => Err(ErrorKind::Ssh),
    }
}

/// The SFTP failure as a state's result.
fn sftp_ran(fx: Fx) -> Ran {
    sftp_failure(fx).map_err(Halt::Fail)
}

/// C's words for an SFTP status (`sftp_libssh2_strerror`).
fn sftp_text(fx: Fx) -> &'static str {
    match fx {
        Fx::NO_SUCH_FILE => "No such file or directory",
        Fx::PERMISSION_DENIED => "Permission denied",
        Fx::FAILURE => "Operation failed",
        Fx::BAD_MESSAGE => "Bad message from SFTP server",
        Fx::NO_CONNECTION => "Not connected to SFTP server",
        Fx::CONNECTION_LOST => "Connection to SFTP server lost",
        Fx::OP_UNSUPPORTED => "Operation not supported by SFTP server",
        Fx::INVALID_HANDLE => "Invalid handle",
        Fx::NO_SUCH_PATH => "No such file or directory",
        Fx::FILE_ALREADY_EXISTS => "File already exists",
        Fx::WRITE_PROTECT => "File is write protected",
        Fx::NO_MEDIA => "No media",
        Fx::NO_SPACE_ON_FILESYSTEM => "Disk full",
        Fx::QUOTA_EXCEEDED => "User quota exceeded",
        Fx::UNKNOWN_PRINCIPAL => "Unknown principal",
        Fx::LOCK_CONFLICT => "File lock conflict",
        Fx::DIR_NOT_EMPTY => "Directory not empty",
        Fx::NOT_A_DIRECTORY => "Not a directory",
        Fx::INVALID_FILENAME => "Invalid filename",
        Fx::LINK_LOOP => "Link points to itself",
        _ => "Unknown error in libssh2",
    }
}

/// The failure a session's error is (`libssh2_session_error_to_CURLE`):
/// none for `LIBSSH2_ERROR_NONE`, and a wait for `LIBSSH2_ERROR_EAGAIN`.
fn session_failure(code: Code) -> Ran {
    let kind = match code {
        Code::NONE => return Ok(()),
        Code::EAGAIN => return Err(Halt::Again),
        Code::SCP_PROTOCOL => ErrorKind::RemoteFileNotFound,
        Code::SOCKET_NONE => ErrorKind::CouldntConnect,
        Code::ALLOC => ErrorKind::OutOfMemory,
        Code::SOCKET_SEND => ErrorKind::SendError,
        Code::HOSTKEY_INIT
        | Code::HOSTKEY_SIGN
        | Code::PUBLICKEY_UNRECOGNIZED
        | Code::PUBLICKEY_UNVERIFIED => ErrorKind::PeerFailedVerification,
        Code::PASSWORD_EXPIRED => ErrorKind::LoginDenied,
        Code::SOCKET_TIMEOUT | Code::TIMEOUT => ErrorKind::OperationTimedout,
        _ => ErrorKind::Ssh,
    };
    Err(Halt::Fail(kind))
}

/// The type of a host key as a key handler is told it
/// (`convert_ssh2_keytype`).
fn key_type(kind: HostKeyType) -> KeyType {
    match kind {
        HostKeyType::Rsa => KeyType::Rsa,
        HostKeyType::Dss => KeyType::Dss,
        HostKeyType::Ecdsa256 | HostKeyType::Ecdsa384 | HostKeyType::Ecdsa521 => KeyType::Ecdsa,
        HostKeyType::Ed25519 => KeyType::Ed25519,
        HostKeyType::Unknown => KeyType::Other,
    }
}

/// The known-hosts key type a host key is looked up as, if it has one.
fn known_type(kind: HostKeyType) -> Option<KnownKeyType> {
    match kind {
        HostKeyType::Rsa => Some(KnownKeyType::SSHRSA),
        HostKeyType::Dss => Some(KnownKeyType::SSHDSS),
        HostKeyType::Ecdsa256 => Some(KnownKeyType::ECDSA_256),
        HostKeyType::Ecdsa384 => Some(KnownKeyType::ECDSA_384),
        HostKeyType::Ecdsa521 => Some(KnownKeyType::ECDSA_521),
        HostKeyType::Ed25519 => Some(KnownKeyType::ED25519),
        HostKeyType::Unknown => None,
    }
}

/// `list` names `method` (`strstr`).
fn offers(list: &[u8], method: &[u8]) -> bool {
    list.windows(method.len()).any(|w| w == method)
}

/// `bytes` in C's `%s`: up to a zero byte.
fn text(bytes: &[u8]) -> &[u8] {
    c_string(bytes)
}

impl Ssh2Conn {
    fn session(&mut self) -> &mut dyn Session2 {
        self.session
            .as_deref_mut()
            .expect("the state machine works on a live session")
    }

    /// The library's words for its last failure.
    fn error_text(&self) -> Vec<u8> {
        self.session
            .as_deref()
            .map(|s| s.last_error().1)
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

    /// Move what waits between a session over pipes and the connection's
    /// layers: whether anything moved, for the call that would have
    /// waited to be made again now. Nothing moves for a session over the
    /// socket.
    fn pump(&mut self, cx: &mut dyn LayerCx, carrier: &mut Carrier<'_>) -> bool {
        self.session
            .as_deref_mut()
            .is_some_and(|s| pump(s, cx, carrier))
    }

    /// What the session waits for, if a call would have (`block`)
    /// (`ssh_block2waitfor`).
    fn block2waitfor(&mut self, block: bool) {
        let mut dir = match (&self.session, block) {
            (Some(s), true) => s.block_directions(),
            _ => PollFlags::default(),
        };
        // What the session sent through its pipes and the connection has
        // not taken yet waits for the connection to take more.
        if let Some(pipes) = self.session.as_deref_mut().and_then(|s| s.pipes()) {
            dir.write |= !pipes.outbound().is_empty();
        }
        self.waitfor = dir;
    }

    /// The session, and what the connection logs in with, borrowed apart:
    /// a login that would wait is called again with the same, so nothing
    /// of it is copied each time.
    fn login(&mut self) -> (&mut dyn Session2, Login<'_>) {
        let cold = self.cold.as_deref();
        let login = cold.and_then(|c| c.login.as_ref());
        let session = self
            .session
            .as_deref_mut()
            .expect("the state machine works on a live session");
        (
            session,
            Login {
                user: login.map_or(&[][..], |l| c_string(l.user())),
                password: login.map_or(&[][..], |l| c_string(l.secret().password())),
                keys: cold.and_then(|c| c.ssh.as_ref()),
            },
        )
    }

    /// The key files the connection logs in with.
    fn keys(&self) -> Option<&Keys> {
        self.cold.as_deref().and_then(|c| c.ssh.as_ref())
    }

    /// Free what the session has open, then the session (`sshc_cleanup`):
    /// a call that would wait stops it, unless `block`, where what it
    /// frees is let go of whatever the call says.
    fn cleanup(&mut self, says: &mut dyn Says, block: bool) -> Ran {
        let let_go = if block { Let::Go } else { Let::Wait };
        let Some(s) = self.session.as_deref_mut() else {
            return Ok(());
        };
        s.knownhost_free();
        let said = |says: &mut dyn Says, s: &dyn Session2, what: &str, rc: Code| {
            let text = s.last_error().1;
            says.info_with(&[what.as_bytes(), format_code(rc).as_bytes(), b" ", &text]);
        };
        if s.has_agent() {
            let rc = s.agent_disconnect();
            if let Err(rc) = rc {
                said(says, s, "Failed to disconnect from libssh2 agent: ", rc);
                if !block && rc.again() {
                    return Err(Halt::Again);
                }
            }
            s.agent_free();
        }
        if s.has_handle()
            && let Err(rc) = s.sftp_close(let_go)
        {
            said(says, s, "Failed to close libssh2 file: ", rc);
            if !block && rc.again() {
                return Err(Halt::Again);
            }
        }
        if s.has_channel()
            && let Err(rc) = s.channel_free(let_go)
        {
            said(says, s, "Failed to free libssh2 scp subsystem: ", rc);
            if !block && rc.again() {
                return Err(Halt::Again);
            }
        }
        if s.has_sftp()
            && let Err(rc) = s.sftp_shutdown(let_go)
        {
            said(says, s, "Failed to stop libssh2 sftp subsystem: ", rc);
            if !block && rc.again() {
                return Err(Halt::Again);
            }
        }
        if s.has_session()
            && let Err(rc) = s.session_free(let_go)
        {
            said(says, s, "Failed to free libssh2 session: ", rc);
            if !block && rc.again() {
                return Err(Halt::Again);
            }
        }
        self.session = None;
        self.path1 = None;
        self.path2 = None;
        self.home = None;
        Ok(())
    }

    /// `SSH_SFTP_SHUTDOWN`: what a broken transfer left open closed, then
    /// the SFTP session.
    fn sftp_shutdown(&mut self, says: &mut dyn Says) -> Ran {
        self.close_handle(says)?;
        let s = self.session();
        if s.has_sftp() {
            match s.sftp_shutdown(Let::Wait) {
                Err(rc) if rc.again() => return Err(Halt::Again),
                Err(_) => says.info(format_args!("Failed to stop libssh2 sftp subsystem")),
                Ok(()) => {}
            }
        }
        self.home = None;
        self.to(says, State::SessionDisconnect);
        Ok(())
    }

    /// The file or directory open closed, a failure said.
    fn close_handle(&mut self, says: &mut dyn Says) -> Ran {
        let s = self.session();
        if s.has_handle() {
            match s.sftp_close(Let::Wait) {
                Err(rc) if rc.again() => return Err(Halt::Again),
                Err(rc) => {
                    let text = s.last_error().1;
                    says.info_with(&[
                        b"Failed to close libssh2 file: ",
                        format_code(rc).as_bytes(),
                        b" ",
                        &text,
                    ]);
                }
                Ok(()) => {}
            }
        }
        Ok(())
    }

    /// `SSH_SESSION_DISCONNECT`: a channel still open freed first, then
    /// the goodbye said.
    fn session_disconnect(&mut self, says: &mut dyn Says) -> Ran {
        let s = self.session();
        if s.has_channel() {
            match s.channel_free(Let::Wait) {
                Err(rc) if rc.again() => return Err(Halt::Again),
                Err(rc) => {
                    let text = s.last_error().1;
                    says.info_with(&[
                        b"Failed to free libssh2 scp subsystem: ",
                        format_code(rc).as_bytes(),
                        b" ",
                        &text,
                    ]);
                }
                Ok(()) => {}
            }
        }
        let s = self.session();
        match s.disconnect() {
            Err(rc) if rc.again() => return Err(Halt::Again),
            Err(rc) => {
                let text = s.last_error().1;
                says.info_with(&[
                    b"Failed to disconnect libssh2 session: ",
                    format_code(rc).as_bytes(),
                    b" ",
                    &text,
                ]);
            }
            Ok(()) => {}
        }
        self.home = None;
        self.to(says, State::SessionFree);
        Ok(())
    }

    /// `SSH_SESSION_FREE`: the session freed, and all kept with it, the
    /// connection not to be used again, which its owner reads from the
    /// session gone (`connclose`).
    fn session_free(&mut self, says: &mut dyn Says) -> Ran {
        self.cleanup(says, false)?;
        self.next = None;
        self.waitfor = PollFlags::default();
        self.authlist.clear();
        self.authed = false;
        self.quote = None;
        self.accept_fail = false;
        self.second_create_dirs = false;
        self.to(says, State::Stop);
        Ok(())
    }

    /// The run of the shutdown's states, which need no transfer
    /// (`ssh_statemachine` from a disconnect): whether it waits.
    fn shutdown_machine(&mut self, says: &mut dyn Says) -> (Result<(), ErrorKind>, bool) {
        let mut result = Ok(());
        let mut block = false;
        loop {
            let ran = match self.state {
                State::SftpShutdown => self.sftp_shutdown(says),
                State::SessionDisconnect => self.session_disconnect(says),
                State::SessionFree => self.session_free(says),
                State::Stop => Ok(()),
                other => unreachable!("a shutdown runs no {}", other.name()),
            };
            match ran {
                Err(Halt::Again) => {
                    block = true;
                    break;
                }
                Err(Halt::Fail(e)) => {
                    result = Err(e);
                    break;
                }
                Ok(()) if self.state == State::Stop => break,
                Ok(()) => {}
            }
        }
        let code = result.map_or_else(|e: ErrorKind| e.number(), |()| 0);
        says.ssh(format_args!(
            "[{}] statemachine() -> {code}, block={}",
            self.state.name(),
            u8::from(block)
        ));
        (result, block)
    }

    /// Say goodbye to the server as the connection shuts down
    /// (`scp_disconnect`, `sftp_disconnect`): its run blocking, waiting on
    /// the socket at most a second in all by `clock`, read each pass as
    /// C's reads the time (`ssh_block_statemach`), then all freed. With
    /// no clock to wait by, one pass, not blocking.
    pub(crate) fn goodbye(
        &mut self,
        cx: &mut dyn LayerCx,
        mut below: Carrier<'_>,
        clock: Option<&crate::time::SharedClock>,
    ) {
        let start = clock.map(crate::time::SharedClock::now);
        let says = &mut LayerSays(cx);
        if self.session.is_some() {
            let first = if self.sftp {
                says.ssh(format_args!("DISCONNECT starts now"));
                State::SftpShutdown
            } else {
                State::SessionDisconnect
            };
            self.to(says, first);
            let mut result = Ok(());
            while self.state != State::Stop && result.is_ok() {
                let (ran, block) = self.shutdown_machine(says);
                result = ran;
                if result.is_err() {
                    break;
                }
                let (Some(clock), Some(start)) = (clock, start) else {
                    break;
                };
                if clock.now().since(start) > Duration::from_secs(1) {
                    // C's failure, on its internal handle: said there.
                    match says.0.failures() {
                        Some(f) => {
                            let _kept =
                                f.keep(ErrorKind::Ssh, format_args!("Disconnect timed out"));
                        }
                        None => says.info(format_args!("Disconnect timed out")),
                    }
                    break;
                }
                if block {
                    if let Some(s) = self.session.as_deref_mut()
                        && pump(s, says.0, &mut below)
                    {
                        continue;
                    }
                    let dir = self
                        .session
                        .as_deref_mut()
                        .map(|s| {
                            let mut dir = s.block_directions();
                            if let Some(pipes) = s.pipes() {
                                dir.write |= !pipes.outbound().is_empty();
                            }
                            dir
                        })
                        .unwrap_or_default();
                    let mut events = Events::NONE;
                    if dir.read {
                        events = events | Events::IN;
                    }
                    if dir.write {
                        events = events | Events::OUT;
                    }
                    if let Some(socket) = below.stream_socket() {
                        let mut polls = [SocketPoll::new(socket, events)];
                        // What the wait comes to the next call reads.
                        let _waited = crate::conn::io::poll_together(
                            &mut polls,
                            &mut [],
                            Duration::from_secs(1),
                        );
                    }
                }
            }
            if self.sftp {
                let code = result.map_or_else(|e: ErrorKind| e.number(), |()| 0);
                says.ssh(format_args!("DISCONNECT is done -> {code}"));
            }
        }
        let _cleaned = self.cleanup(says, true);
    }
}

/// Move what waits between `session`'s pipes, if it reads and writes
/// through them, and the connection's layers, each piece traced as it
/// moves, as C's callbacks trace it (`ssh_tls_send`, `ssh_tls_recv`):
/// what it sent goes out, as much as the connection takes; then, if it
/// waits to read, what came for it, at most as much as it asked for.
/// Whether anything moved, a failure or the connection's end among it.
fn pump(session: &mut dyn Session2, cx: &mut dyn LayerCx, carrier: &mut Carrier<'_>) -> bool {
    let Some(pipes) = session.pipes() else {
        return false;
    };
    let mut moved = false;
    while !pipes.outbound().is_empty() {
        match carrier.send(cx, pipes.outbound()) {
            Ok(Sent::Bytes(n)) => {
                cx.bytes(DebugKind::DataOut, &pipes.outbound()[..n.get()]);
                pipes.sent(n.get());
                moved = true;
            }
            Ok(Sent::WouldBlock) => break,
            Err(_) => {
                pipes.break_off();
                return true;
            }
        }
    }
    if let Some(wanted) = pipes.wanted() {
        let Some(room) = pipes.room(wanted) else {
            pipes.break_off();
            return true;
        };
        match carrier.recv_into(cx, room) {
            Ok(Some(0)) => {
                pipes.end();
                moved = true;
            }
            Ok(Some(n)) => {
                cx.bytes(DebugKind::DataIn, &room[..n]);
                pipes.came(n);
                moved = true;
            }
            Ok(None) => pipes.came(0),
            Err(_) => {
                pipes.break_off();
                moved = true;
            }
        }
    }
    moved
}

/// Whether the session reads and writes through the connection's layers,
/// under a proxy of `kind` if any, the socket `bare` or not: through an
/// HTTPS proxy, its TLS (`CURLPROXY_HTTPS` in `ssh_connect`); otherwise
/// the socket itself, which no layer of ours may work on, nor any bytes
/// received wait unread in. C's hands the library the socket past an
/// HTTP/2 proxy's TLS, where SSH cannot go: such a transfer is refused.
fn over_layers(kind: Option<crate::options::ProxyType>, bare: bool) -> Result<bool, ()> {
    if kind == Some(crate::options::ProxyType::Https) {
        Ok(true)
    } else if bare {
        Ok(false)
    } else {
        Err(())
    }
}

/// A libssh2 error number, as C's `%d` prints it.
fn format_code(code: Code) -> String {
    curl_alloc::try_format(format_args!("{}", code.0)).unwrap_or_default()
}

/// The connection's SSH state.
fn ssh2_of(lease: &mut ConnLease) -> (&mut Ssh2Conn, Carrier<'_>) {
    match lease.get().line_mut() {
        Some((LineConn::Ssh2(sc), carrier)) => (sc, carrier),
        _ => unreachable!("an SSH transfer's connection keeps SSH's state"),
    }
}

/// The connection's SSH state, if it is libssh2's.
pub(super) fn ssh2_on(line: Option<&LineConn>) -> Option<&Ssh2Conn> {
    match line {
        Some(LineConn::Ssh2(sc)) => Some(sc),
        _ => None,
    }
}

impl Ssh2Conn {
    /// What the session waits for, and whether there is one, for the
    /// pollset (`Curl_ssh_pollset`).
    pub(super) fn waits(&self) -> (PollFlags, bool) {
        (self.waitfor, self.session.is_some())
    }
}

/// Whether the application lets the user log in by `way`.
fn allows<H: Host>(cx: &StepCx<'_, H>, way: SshAuthTypes) -> bool {
    cx.easy().options().ssh.auth_types.allows(way)
}

impl Request {
    /// The connection's SSH state over libssh2, made the first time
    /// (`ssh_connect`): the session made, its read timeout, compression
    /// and known-hosts file set, then the run started.
    fn conn_state2<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        library: &'static dyn crate::ssh2::Ssh2,
    ) -> Result<(), ErrorKind> {
        let sftp = self.base.peer.scheme() == crate::conn::Scheme::of("sftp");
        let crypto = match library.crypto() {
            Crypto::Gcrypt => Some("libgcrypt"),
            Crypto::MbedTls => Some("mbedTLS"),
            Crypto::OpenSsl => Some("openssl compatible"),
            Crypto::Os400Qc3 => Some("OS400QC3"),
            Crypto::WinCng => Some("WinCNG"),
            Crypto::Other => None,
        };
        if let Some(crypto) = crypto {
            trace::info(
                cx,
                format_args!("SSH: libssh2 cryptography backend: {crypto}"),
            );
        }
        let cold = lease.conn().net_route().and_then(|r| r.cold.clone());
        let login = cold.as_deref().and_then(|c| c.login.as_ref());
        let user = login.map_or(&[][..], |l| c_string(l.user()));
        trace::info_with(cx, &[b"SSH: user '", user, b"'"]);
        let Some(mut session) = library.session() else {
            return Err(trace::fail(
                cx,
                ErrorKind::FailedInit,
                format_args!("Failure initializing ssh session"),
            ));
        };
        if let Some(limit) = cx.easy().options().line.server_response {
            let secs = limit.duration().as_millis() / 1000;
            session.set_read_timeout(i64::try_from(secs).unwrap_or(i64::MAX));
        }
        let kind = lease
            .conn()
            .net_route()
            .and_then(|r| r.proxy.as_ref())
            .map(|p| p.kind);
        let bare = lease.get().carrier().bare_socket().is_some();
        match over_layers(kind, bare) {
            Ok(true) => {
                trace::info(cx, format_args!("SSH: using HTTPS proxy"));
                session.use_pipes();
            }
            Ok(false) => {}
            Err(()) => {
                return Err(trace::fail(
                    cx,
                    ErrorKind::FailedInit,
                    format_args!("SSH is not built over this proxy's TLS"),
                ));
            }
        }
        if cx.easy().options().ssh.compression && session.enable_compression().is_err() {
            trace::info(
                cx,
                format_args!("SSH: failed to enable compression for session"),
            );
        }
        if let Some(known) = cx.easy().options().ssh.known_hosts.as_deref() {
            let known = copy(c_string(known))?;
            if session.knownhost_init().is_err() {
                return Err(ErrorKind::FailedInit);
            }
            if session.knownhost_readfile(&known).is_err() {
                trace::info_with(cx, &[b"SSH: failed to read known hosts from ", &known]);
            }
        }
        let sc = Ssh2Conn {
            session: Some(session),
            sftp,
            state: State::Stop,
            next: None,
            waitfor: PollFlags::default(),
            authlist: Vec::new(),
            authed: false,
            home: None,
            cold,
            quote: None,
            path1: None,
            path2: None,
            accept_fail: false,
            quote_attrs: Attrs::default(),
            listing: Vec::new(),
            link: Vec::new(),
            slash: 0,
            second_create_dirs: false,
        };
        let line = curl_alloc::try_box(LineConn::Ssh2(sc)).map_err(|_| ErrorKind::OutOfMemory)?;
        lease.get().put_line(line);
        let (sc, _) = ssh2_of(lease);
        sc.to(cx, State::Init);
        Ok(())
    }

    /// Run the state machine as far as the session lets it now
    /// (`ssh_multi_statemach`): whether it stopped. A session freed
    /// leaves the connection to close.
    fn run2<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        let (sc, mut carrier) = ssh2_of(lease);
        let (result, block) = self.machine2(cx, sc, &mut carrier);
        let stopped = sc.state == State::Stop;
        sc.block2waitfor(block);
        let freed = sc.session.is_none();
        if freed {
            lease.get().mark_close();
        }
        result.map(|()| stopped)
    }

    /// The state machine (`ssh_statemachine`): run until it stops, a call
    /// would wait or a state fails; what the run came to, and whether it
    /// waits.
    fn machine2<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        sc: &mut Ssh2Conn,
        carrier: &mut Carrier<'_>,
    ) -> (Result<(), ErrorKind>, bool) {
        let mut ran;
        loop {
            ran = self.state2(cx, sc, carrier);
            // A session over pipes waits on them: once bytes move, the
            // call is made again, as C's callbacks would have moved them
            // inside it.
            if matches!(ran, Err(Halt::Again)) && sc.pump(cx, carrier) {
                continue;
            }
            if ran.is_err() || sc.state == State::Stop {
                break;
            }
        }
        // What the last call sent goes out now.
        sc.pump(cx, carrier);
        let (result, block) = match ran {
            Err(Halt::Again) => (Ok(()), true),
            Err(Halt::Fail(e)) => (Err(e), false),
            Ok(()) => (Ok(()), false),
        };
        let code = result.map_or_else(|e: ErrorKind| e.number(), |()| 0);
        cx.ssh(format_args!(
            "[{}] statemachine() -> {code}, block={}",
            sc.state.name(),
            u8::from(block)
        ));
        (result, block)
    }

    /// The work of the state the machine is in.
    fn state2<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        sc: &mut Ssh2Conn,
        carrier: &mut Carrier<'_>,
    ) -> Ran {
        match sc.state {
            State::Init => self.init(cx, sc),
            State::SStartup => startup(cx, sc, carrier),
            State::Hostkey => {
                self.check_fingerprint(cx, sc)?;
                sc.to(cx, State::Authlist);
                Ok(())
            }
            State::Authlist => authlist(cx, sc),
            State::AuthPkeyInit => {
                pkey_init(cx, sc);
                Ok(())
            }
            State::AuthPkey => auth_pkey(cx, sc),
            State::AuthPassInit => {
                let next =
                    if allows(cx, SshAuthTypes::PASSWORD) && offers(&sc.authlist, b"password") {
                        State::AuthPass
                    } else {
                        State::AuthHostInit
                    };
                sc.to(cx, next);
                Ok(())
            }
            State::AuthPass => auth_pass(cx, sc),
            State::AuthHostInit => {
                let next = if allows(cx, SshAuthTypes::HOST) && offers(&sc.authlist, b"hostbased") {
                    State::AuthHost
                } else {
                    State::AuthAgentInit
                };
                sc.to(cx, next);
                Ok(())
            }
            State::AuthHost => {
                sc.to(cx, State::AuthAgentInit);
                Ok(())
            }
            State::AuthAgentInit => agent_init(cx, sc),
            State::AuthAgentList => agent_list(cx, sc),
            State::AuthAgent => agent(cx, sc),
            State::AuthKeyInit => {
                let next = if allows(cx, SshAuthTypes::KEYBOARD)
                    && offers(&sc.authlist, b"keyboard-interactive")
                {
                    State::AuthKey
                } else {
                    State::AuthDone
                };
                sc.to(cx, next);
                Ok(())
            }
            State::AuthKey => auth_key(cx, sc),
            State::AuthDone => auth_done(cx, sc),
            State::SftpInit => sftp_init(cx, sc),
            State::SftpRealpath => sftp_realpath(cx, sc),
            State::SftpQuoteInit => self.sftp_quote_init2(cx, sc),
            State::SftpPostquoteInit => {
                if cx.easy().options().line.postquote.iter().next().is_some() {
                    trace::info(cx, format_args!("SSH: sending quote commands"));
                    sc.quote = Some((Quotes::After, 0));
                    sc.to(cx, State::SftpQuote);
                } else {
                    sc.to(cx, State::Stop);
                }
                Ok(())
            }
            State::SftpQuote => {
                let ran = self.sftp_quote2(cx, sc);
                if ran.is_err() {
                    sc.to(cx, State::SftpClose);
                    sc.next = None;
                }
                ran
            }
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
                Ok(())
            }
            State::SftpQuoteStat => {
                let ran = quote_stat(cx, sc);
                if matches!(ran, Err(Halt::Fail(_))) {
                    sc.to(cx, State::SftpClose);
                    sc.next = None;
                }
                ran
            }
            State::SftpQuoteSetstat => {
                let path = sc.path2.take().unwrap_or_default();
                let attrs = sc.quote_attrs;
                let rc = sc.session().sftp_setstat(&path, &attrs);
                sc.path2 = Some(path);
                match rc {
                    Err(rc) if rc.again() => Err(Halt::Again),
                    Err(_) if !sc.accept_fail => {
                        let fx = sc.session().sftp_last_error();
                        let p2 = sc.path2.take().unwrap_or_default();
                        sc.path1 = None;
                        let kind = trace::fail_with(
                            cx,
                            ErrorKind::QuoteError,
                            &[
                                b"Attempt to set SFTP stats for \"",
                                &p2,
                                b"\" failed: ",
                                sftp_text(fx).as_bytes(),
                            ],
                        );
                        sc.to(cx, State::SftpClose);
                        sc.next = None;
                        Err(Halt::Fail(kind))
                    }
                    _ => {
                        sc.to(cx, State::SftpNextQuote);
                        Ok(())
                    }
                }
            }
            State::SftpQuoteSymlink => {
                let (p1, p2) = (sc.path1.take(), sc.path2.take());
                let rc = sc.session().sftp_symlink(
                    p1.as_deref().unwrap_or_default(),
                    p2.as_deref().unwrap_or_default(),
                );
                (sc.path1, sc.path2) = (p1, p2);
                quote_done2(cx, sc, rc, "symlink", true)
            }
            State::SftpQuoteMkdir => {
                let path = sc.path1.take().unwrap_or_default();
                let mode = u32::from(cx.easy().options().ssh.new_directory_mode.bits());
                let rc = sc.session().sftp_mkdir(&path, mode);
                sc.path1 = Some(path);
                quote_done2(cx, sc, rc, "mkdir", false)
            }
            State::SftpQuoteRename => {
                let (p1, p2) = (sc.path1.take(), sc.path2.take());
                let rc = sc.session().sftp_rename(
                    p1.as_deref().unwrap_or_default(),
                    p2.as_deref().unwrap_or_default(),
                );
                (sc.path1, sc.path2) = (p1, p2);
                quote_done2(cx, sc, rc, "rename", true)
            }
            State::SftpQuoteRmdir => {
                let path = sc.path1.take().unwrap_or_default();
                let rc = sc.session().sftp_rmdir(&path);
                sc.path1 = Some(path);
                quote_done2(cx, sc, rc, "rmdir", false)
            }
            State::SftpQuoteUnlink => {
                let path = sc.path1.take().unwrap_or_default();
                let rc = sc.session().sftp_unlink(&path);
                sc.path1 = Some(path);
                quote_done2(cx, sc, rc, "rm", false)
            }
            State::SftpQuoteStatvfs => self.quote_statvfs(cx, sc),
            State::SftpGetinfo => {
                let next = if cx.easy().options().filetime {
                    State::SftpFiletime
                } else {
                    State::SftpTransInit
                };
                sc.to(cx, next);
                Ok(())
            }
            State::SftpFiletime => {
                let path = self.path.take().unwrap_or_default();
                let attrs = sc.session().sftp_stat(&path);
                self.path = Some(path);
                match attrs {
                    Err(rc) if rc.again() => return Err(Halt::Again),
                    Ok(attrs) => cx
                        .report_mut()
                        .set_filetime(i64::try_from(attrs.mtime).unwrap_or(i64::MAX)),
                    Err(_) => {}
                }
                sc.to(cx, State::SftpTransInit);
                Ok(())
            }
            State::SftpTransInit => {
                let next = if self.upload {
                    State::SftpUploadInit
                } else if self.path().last() == Some(&b'/') {
                    State::SftpReaddirInit
                } else {
                    State::SftpDownloadInit
                };
                sc.to(cx, next);
                Ok(())
            }
            State::SftpUploadInit => {
                let ran = self.sftp_upload_init2(cx, sc);
                if matches!(ran, Err(Halt::Fail(_))) {
                    sc.to(cx, State::SftpClose);
                    sc.next = None;
                }
                ran
            }
            State::SftpCreateDirsInit => {
                if self.path().len() > 1 {
                    sc.slash = 1;
                    sc.to(cx, State::SftpCreateDirs);
                } else {
                    sc.to(cx, State::SftpUploadInit);
                }
                Ok(())
            }
            State::SftpCreateDirs => {
                let path = self.path();
                match path[sc.slash..].iter().position(|&b| b == b'/') {
                    Some(i) => {
                        sc.slash += i;
                        let dir = &path[..sc.slash];
                        trace::info_with(cx, &[b"SFTP: creating directory '", text(dir), b"'"]);
                        sc.to(cx, State::SftpCreateDirsMkdir);
                    }
                    None => sc.to(cx, State::SftpUploadInit),
                }
                Ok(())
            }
            State::SftpCreateDirsMkdir => self.create_dirs_mkdir(cx, sc),
            State::SftpReaddirInit => self.readdir_init(cx, sc),
            State::SftpReaddir => {
                let ran = self.readdir(cx, sc);
                if matches!(ran, Err(Halt::Fail(_))) {
                    sc.to(cx, State::SftpClose);
                }
                ran
            }
            State::SftpReaddirLink => readdir_link(cx, sc),
            State::SftpReaddirBottom => self.readdir_bottom(cx, sc),
            State::SftpReaddirDone => {
                if let Err(rc) = sc.session().sftp_close(Let::Wait)
                    && rc.again()
                {
                    return Err(Halt::Again);
                }
                self.xfer_setup(cx, Directions::default());
                sc.to(cx, State::Stop);
                Ok(())
            }
            State::SftpDownloadInit => self.download_init(cx, sc),
            State::SftpDownloadStat => {
                let ran = self.download_stat(cx, sc);
                if matches!(ran, Err(Halt::Fail(_))) {
                    sc.to(cx, State::SftpClose);
                    sc.next = None;
                }
                ran
            }
            State::SftpClose => {
                sc.close_handle(cx)?;
                self.path = None;
                cx.ssh(format_args!("SFTP DONE done"));
                match sc.next {
                    Some(next) if next != State::SftpClose => {
                        sc.to(cx, next);
                        sc.next = Some(State::SftpClose);
                    }
                    _ => sc.to(cx, State::Stop),
                }
                Ok(())
            }
            State::SftpShutdown => sc.sftp_shutdown(cx),
            State::ScpTransInit => self.scp_trans_init2(cx, sc),
            State::ScpUploadInit => self.scp_upload_init2(cx, sc),
            State::ScpDownloadInit => self.scp_download_init(cx, sc),
            State::ScpDone => {
                let next = if self.upload {
                    State::ScpSendEof
                } else {
                    State::ScpChannelFree
                };
                sc.to(cx, next);
                Ok(())
            }
            State::ScpSendEof => {
                channel_step(
                    cx,
                    sc,
                    |s| s.channel_send_eof(),
                    "Failed to send libssh2 channel EOF: ",
                )?;
                sc.to(cx, State::ScpWaitEof);
                Ok(())
            }
            State::ScpWaitEof => {
                channel_step(
                    cx,
                    sc,
                    |s| s.channel_wait_eof(),
                    "Failed to get channel EOF: ",
                )?;
                sc.to(cx, State::ScpWaitClose);
                Ok(())
            }
            State::ScpWaitClose => {
                channel_step(
                    cx,
                    sc,
                    |s| s.channel_wait_closed(),
                    "Channel failed to close: ",
                )?;
                sc.to(cx, State::ScpChannelFree);
                Ok(())
            }
            State::ScpChannelFree => {
                let s = sc.session();
                if s.has_channel() {
                    match s.channel_free(Let::Wait) {
                        Err(rc) if rc.again() => return Err(Halt::Again),
                        Err(rc) => {
                            let text = s.last_error().1;
                            trace::info_with(
                                cx,
                                &[
                                    b"Failed to free libssh2 scp subsystem: ",
                                    format_code(rc).as_bytes(),
                                    b" ",
                                    &text,
                                ],
                            );
                        }
                        Ok(()) => {}
                    }
                }
                cx.ssh(format_args!("SCP DONE phase complete"));
                sc.to(cx, State::Stop);
                Ok(())
            }
            State::SessionDisconnect => sc.session_disconnect(cx),
            State::SessionFree => sc.session_free(cx),
            State::Stop => {
                // An internal error, as C's `SSH_QUIT` and default.
                sc.to(cx, State::Stop);
                Ok(())
            }
        }
    }

    /// `SSH_INIT`: the session nonblocking, and the key type the
    /// known-hosts file has for the host asked for first.
    fn init<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        sc.second_create_dirs = false;
        sc.next = None;
        sc.session().set_blocking(Blocking::No);
        match self.force_knownhost_key_type(cx, sc) {
            Err(e) => {
                sc.to(cx, State::SessionFree);
                Err(Halt::Fail(e))
            }
            Ok(()) => {
                sc.to(cx, State::SStartup);
                Ok(())
            }
        }
    }

    /// The host's entry in the known-hosts file, if it has one, asks the
    /// server for a key of its type first (`ssh_force_knownhost_key_type`),
    /// unless a fingerprint is given to check.
    fn force_knownhost_key_type<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        sc: &mut Ssh2Conn,
    ) -> Result<(), ErrorKind> {
        let ssh = &cx.easy().options().ssh;
        if !sc.session().has_knownhosts()
            || ssh.host_key_md5.is_some()
            || ssh.host_key_sha256.is_some()
        {
            return Ok(());
        }
        let file = copy(c_string(ssh.known_hosts.as_deref().unwrap_or_default()))?;
        let host = copy(self.base.peer.name())?;
        let port = self.base.peer.port();
        let entries = sc
            .session()
            .knownhost_entries()
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let mut absent = [false; KnownKeyType::COUNT];
        let mut found = None;
        for entry in &entries {
            if let Some(name) = entry.name.as_deref() {
                if name.first() == Some(&b'[') {
                    let Some(end) = name.windows(2).position(|w| w == b"]:") else {
                        trace::info_with(
                            cx,
                            &[b"SSH: invalid host pattern ", name, b" in ", &file],
                        );
                        continue;
                    };
                    let digits = &name[end + 2..];
                    if let Ok((n, _)) = path::number(digits, 0xffff, 10)
                        && n == i64::from(port)
                    {
                        let size = end - 1;
                        if size == host.len() && name[1..1 + size] == host[..] {
                            found = Some(entry.kind);
                            break;
                        }
                    }
                } else if name == &host[..] {
                    found = Some(entry.kind);
                    break;
                }
            } else if let Some(key) = entry.key.as_deref() {
                let t = usize::from(entry.kind.0);
                if !absent[t] {
                    let port = (port != PORT_SSH).then_some(port);
                    let (check, _) = sc
                        .session()
                        .knownhost_check(&host, port, key, KeyForm::Base64, entry.kind)
                        .map_err(|_| ErrorKind::OutOfMemory)?;
                    match check {
                        Check::Match => {
                            found = Some(entry.kind);
                            break;
                        }
                        Check::NotFound => absent[t] = true,
                        _ => {}
                    }
                }
            }
        }
        let Some(kind) = found else {
            trace::info_with(
                cx,
                &[b"SSH: did not find host '", &host, b"' in '", &file, b"'"],
            );
            return Ok(());
        };
        trace::info_with(cx, &[b"SSH: found host '", &host, b"' in '", &file, b"'"]);
        let method: &str = match kind {
            KnownKeyType::ED25519 => "ssh-ed25519",
            KnownKeyType::ECDSA_521 => "ecdsa-sha2-nistp521",
            KnownKeyType::ECDSA_384 => "ecdsa-sha2-nistp384",
            KnownKeyType::ECDSA_256 => "ecdsa-sha2-nistp256",
            KnownKeyType::SSHRSA => "rsa-sha2-256,rsa-sha2-512,ssh-rsa",
            KnownKeyType::SSHDSS => "ssh-dss",
            KnownKeyType::RSA1 => {
                return Err(trace::fail(
                    cx,
                    ErrorKind::Ssh,
                    format_args!("Found host key type RSA1 which is not supported"),
                ));
            }
            other => {
                let bits = other.bits();
                return Err(trace::fail(
                    cx,
                    ErrorKind::Ssh,
                    format_args!("Unknown host key type: {bits}"),
                ));
            }
        };
        trace::info(cx, format_args!("SSH: set '{method}' as hostkey type"));
        if let Err(rc) = sc.session().set_hostkey_methods(method.as_bytes()) {
            let text = sc.error_text();
            trace::fail_with(
                cx,
                ErrorKind::Ssh,
                &[b"libssh2 method '", method.as_bytes(), b"' failed: ", &text],
            );
            return match session_failure(rc) {
                Ok(()) => Ok(()),
                Err(Halt::Again) => Err(ErrorKind::Ssh),
                Err(Halt::Fail(e)) => Err(e),
            };
        }
        Ok(())
    }

    /// `SSH_HOSTKEY`: the server's key checked against the fingerprints
    /// given, else the application's host key handler, else the
    /// known-hosts file (`ssh_check_fingerprint`).
    fn check_fingerprint<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        let ssh = &cx.easy().options().ssh;
        let sha256 = ssh
            .host_key_sha256
            .as_deref()
            .map(|w| copy(c_string(w)))
            .transpose()?;
        let md5 = ssh
            .host_key_md5
            .as_deref()
            .map(|w| copy(c_string(w)))
            .transpose()?;
        let denied = |cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn| {
            sc.to(cx, State::SessionFree);
            Err(Halt::Fail(ErrorKind::PeerFailedVerification))
        };
        if let Some(want) = sha256.as_deref() {
            trace::info_with(cx, &[b"SSH: SHA256 public key '", want, b"'"]);
            let Some(sha) = sc.session().host_key_sha256() else {
                trace::fail(
                    cx,
                    ErrorKind::PeerFailedVerification,
                    format_args!(
                        "Denied establishing ssh session: SHA256 fingerprint not available"
                    ),
                );
                return denied(cx, sc);
            };
            let mut found = Vec::new();
            if crate::base64::encode(&sha, &mut found).is_err() {
                return denied(cx, sc);
            }
            trace::info_with(cx, &[b"SSH: SHA256 fingerprint '", &found, b"'"]);
            // The two compared up to their padding.
            let unpadded = |s: &[u8]| s.iter().position(|&b| b == b'=').unwrap_or(s.len());
            let (w, f) = (unpadded(want), unpadded(&found));
            if w != f || want[..w] != found[..w] {
                trace::fail_with(
                    cx,
                    ErrorKind::PeerFailedVerification,
                    &[
                        b"Denied establishing ssh session: mismatch SHA256 fingerprint. Remote ",
                        &found,
                        b" is not equal to ",
                        want,
                    ],
                );
                return denied(cx, sc);
            }
            trace::info(cx, format_args!("SSH: SHA256 checksum match"));
        }
        if let Some(want) = md5.as_deref() {
            trace::info_with(cx, &[b"SSH: MD5 public key '", want, b"'"]);
            let hex = sc.session().host_key_md5().map(|md5| {
                let mut out = [0u8; 32];
                for (i, b) in md5.iter().enumerate() {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    out[2 * i] = HEX[usize::from(b >> 4)];
                    out[2 * i + 1] = HEX[usize::from(b & 0xf)];
                }
                out
            });
            if let Some(hex) = hex.as_ref() {
                trace::info_with(cx, &[b"SSH: MD5 fingerprint '", hex, b"'"]);
            }
            match hex {
                Some(hex) if hex.eq_ignore_ascii_case(want) => {}
                Some(hex) => {
                    trace::fail_with(
                        cx,
                        ErrorKind::PeerFailedVerification,
                        &[
                            b"Denied establishing ssh session: mismatch MD5 fingerprint. Remote ",
                            &hex,
                            b" is not equal to ",
                            want,
                        ],
                    );
                    return denied(cx, sc);
                }
                None => {
                    trace::fail(
                        cx,
                        ErrorKind::PeerFailedVerification,
                        format_args!(
                            "Denied establishing ssh session: MD5 fingerprint not available"
                        ),
                    );
                    return denied(cx, sc);
                }
            }
            trace::info(cx, format_args!("SSH: MD5 checksum match"));
        }
        if sha256.is_some() || md5.is_some() {
            // As already matched, the known hosts are not checked.
            return Ok(());
        }
        if let Some(handler) = cx.easy().options().ssh.host_key_handler.clone() {
            let Some((key, kind)) = sc.session().host_key() else {
                return denied(cx, sc);
            };
            let key = copy(key)?;
            let fine = handler.check(&mut crate::multi::TransferCx::new(cx), key_type(kind), &key);
            if !fine {
                sc.to(cx, State::SessionFree);
                return Err(Halt::Fail(trace::fail(
                    cx,
                    ErrorKind::PeerFailedVerification,
                    format_args!("SSH: callback failed host public key verification"),
                )));
            }
            trace::info(cx, format_args!("SSH: verified public key via callback"));
            return Ok(());
        }
        cx.ssh(format_args!(
            "no host key checksum given, checking knownhosts"
        ));
        self.knownhost(cx, sc)
    }

    /// The server's key checked against the known-hosts file, the key
    /// handler deciding, or C's own, which takes a match alone
    /// (`ssh_knownhost`).
    fn knownhost<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        let Some(file) = cx.easy().options().ssh.known_hosts.as_deref() else {
            trace::info(cx, format_args!("SSH: no knownhosts file configured"));
            return Ok(());
        };
        let file = copy(c_string(file))?;
        let host = copy(self.base.peer.name())?;
        let port = self.base.peer.port();
        let handler = cx.easy().options().ssh.key_handler.clone();
        let mut check = Check::Failure;
        let mut keybit = None;
        let mut found_key = Vec::new();
        let verdict = match sc.session().host_key() {
            None => {
                trace::info(cx, format_args!("SSH: host offers no public key"));
                KeyVerdict::Reject
            }
            Some((key, kind)) => {
                found_key = copy(key)?;
                keybit = known_type(kind);
                match keybit {
                    None => {
                        trace::info(
                            cx,
                            format_args!("SSH: unsupported host key type for knownhosts check"),
                        );
                        KeyVerdict::Reject
                    }
                    Some(bits) => {
                        let at = (port != PORT_SSH).then_some(port);
                        let (c, known) = sc
                            .session()
                            .knownhost_check(&host, at, &found_key, KeyForm::Raw, bits)
                            .map_err(|_| ErrorKind::OutOfMemory)?;
                        check = c;
                        let n = check.number();
                        let shown = known.as_deref().unwrap_or(b"<none>");
                        trace::info_with(
                            cx,
                            &[
                                b"SSH: host check ",
                                format_code(Code(n)).as_bytes(),
                                b", key: ",
                                shown,
                            ],
                        );
                        let matched = match check {
                            Check::Match => KeyMatch::Ok,
                            Check::Mismatch => KeyMatch::Mismatch,
                            Check::NotFound => KeyMatch::Missing,
                            Check::Failure => KeyMatch::Failure,
                        };
                        let kt = key_type(kind);
                        match handler {
                            // C's own: a match alone is fine (`sshkeycallback`).
                            None if matched == KeyMatch::Ok => KeyVerdict::Fine,
                            None => KeyVerdict::Reject,
                            Some(handler) => handler.check(
                                &mut crate::multi::TransferCx::new(cx),
                                known.as_deref().map(|k| HostKey {
                                    key: k,
                                    encoding: KeyEncoding::Base64Text,
                                    kind: kt,
                                }),
                                HostKey {
                                    key: &found_key,
                                    encoding: KeyEncoding::Raw,
                                    kind: kt,
                                },
                                matched,
                            ),
                        }
                    }
                }
            }
        };
        match verdict {
            KeyVerdict::Reject => {
                trace::info(cx, format_args!("SSH: knownhost check failed"));
                sc.to(cx, State::SessionFree);
                Err(Halt::Fail(ErrorKind::PeerFailedVerification))
            }
            // Bail out, keeping the state.
            KeyVerdict::Defer => Err(Halt::Fail(ErrorKind::PeerFailedVerification)),
            KeyVerdict::FineReplace | KeyVerdict::Fine | KeyVerdict::FineAddToFile => {
                if verdict == KeyVerdict::FineReplace {
                    sc.session().knownhost_del_found();
                }
                if check == Check::Match {
                    trace::info(cx, format_args!("SSH: knownhost entry matches host key"));
                    return Ok(());
                }
                let named = if port != PORT_SSH {
                    let mut h = Vec::new();
                    let port_text = curl_alloc::try_format(format_args!("]:{port}"))
                        .map_err(|_| ErrorKind::OutOfMemory)?;
                    h.try_push(b'[')
                        .and_then(|()| h.try_extend_from_slice(&host))
                        .and_then(|()| h.try_extend_from_slice(port_text.as_bytes()))
                        .map_err(|_| ErrorKind::OutOfMemory)?;
                    h
                } else {
                    host
                };
                let bits = keybit.unwrap_or(KnownKeyType(0));
                if sc
                    .session()
                    .knownhost_add(&named, &found_key, bits)
                    .is_err()
                {
                    trace::info_with(
                        cx,
                        &[b"WARNING: adding the known host ", &named, b" failed"],
                    );
                } else if matches!(verdict, KeyVerdict::FineAddToFile | KeyVerdict::FineReplace)
                    && sc.session().knownhost_writefile(&file).is_err()
                {
                    trace::info_with(cx, &[b"WARNING: writing ", &file, b" failed"]);
                }
                Ok(())
            }
        }
    }

    /// `SSH_SFTP_QUOTE_INIT`: the request's path worked out, then the
    /// quote commands before it, if any.
    fn sftp_quote_init2<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        let home = sc.home.as_deref().unwrap_or_default();
        match path::working_path(&self.url_path, Home::Sftp(home)) {
            Err(e) => {
                sc.to(cx, State::Stop);
                Err(Halt::Fail(e))
            }
            Ok(p) => {
                self.path = Some(p);
                if cx.easy().options().line.quote.iter().next().is_some() {
                    trace::info(cx, format_args!("SSH: sending quote commands"));
                    sc.quote = Some((Quotes::Before, 0));
                    sc.to(cx, State::SftpQuote);
                } else {
                    sc.to(cx, State::SftpGetinfo);
                }
                Ok(())
            }
        }
    }

    /// `SSH_SFTP_QUOTE`: the next quote command read, and the state that
    /// runs it chosen (`sftp_quote`).
    fn sftp_quote2<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        let (list, at) = sc.quote.expect("a quote command to run");
        let given = quote_command(cx, list, at).expect("the quote command is in its list");
        let cmd = copy(c_string(given))?;
        sc.accept_fail = false;
        // A command starting with `*` may fail, as if it did not.
        let cmd = match cmd.strip_prefix(b"*") {
            Some(rest) => {
                sc.accept_fail = true;
                rest
            }
            None => &cmd[..],
        };
        if cmd.eq_ignore_ascii_case(b"pwd") {
            // An FTP-like answer for the header handler, as FTP's `PWD`.
            // After the transfer the path has gone, and C's `%s` says so.
            let path = self.path.as_deref().map_or(&b"(nil)"[..], c_string);
            let mut said = Vec::new();
            said.try_extend_from_slice(b"257 \"")
                .and_then(|()| said.try_extend_from_slice(path))
                .and_then(|()| said.try_extend_from_slice(b"\" is current directory.\n"))
                .map_err(|_| ErrorKind::OutOfMemory)?;
            trace::bytes(cx, DebugKind::HeaderOut, b"PWD\n");
            trace::bytes(cx, DebugKind::HeaderIn, &said);
            self.base.pipeline.protocol_header(cx, &said)?;
            sc.to(cx, State::SftpNextQuote);
            return Ok(());
        }
        // The arguments follow the command after a space.
        let Some(space) = cmd.iter().position(|&b| b == b' ') else {
            return Err(Halt::Fail(trace::fail_with(
                cx,
                ErrorKind::QuoteError,
                &[b"Syntax error command '", cmd, b"', missing parameter"],
            )));
        };
        let home = sc.home.clone().unwrap_or_default();
        let (first, rest) = match path::quoted_path(&cmd[space..], &home) {
            Ok(read) => read,
            Err(e) => {
                if e != ErrorKind::OutOfMemory {
                    trace::fail_with(
                        cx,
                        e,
                        &[b"Syntax error: Bad first parameter to '", cmd, b"'"],
                    );
                }
                return Err(Halt::Fail(e));
            }
        };
        sc.path1 = Some(first);
        let starts = |prefix: &[u8]| cmd.starts_with(prefix);
        // The second path, said `why` if it does not read; then nothing
        // after it.
        let second =
            |cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn, why: &[&[u8]]| -> Result<(), Halt> {
                match path::quoted_path(rest, &home) {
                    Ok((p, tail)) => {
                        sc.path2 = Some(p);
                        if tail.is_empty() {
                            Ok(())
                        } else {
                            Err(Halt::Fail(quote_error(cx, sc)))
                        }
                    }
                    Err(e) => {
                        if e != ErrorKind::OutOfMemory {
                            trace::fail_with(cx, e, why);
                        }
                        sc.path1 = None;
                        Err(Halt::Fail(e))
                    }
                }
            };
        // A command of one path: nothing after it.
        let alone = |cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn, state: State| -> Ran {
            if rest.is_empty() {
                sc.to(cx, state);
                Ok(())
            } else {
                Err(Halt::Fail(quote_error(cx, sc)))
            }
        };
        if starts(b"chgrp ")
            || starts(b"chmod ")
            || starts(b"chown ")
            || starts(b"atime ")
            || starts(b"mtime ")
        {
            second(
                cx,
                sc,
                &[b"Syntax error in ", cmd, b": Bad second parameter"],
            )?;
            sc.quote_attrs = Attrs::default();
            sc.to(cx, State::SftpQuoteStat);
            return Ok(());
        }
        if starts(b"ln ") || starts(b"symlink ") {
            second(
                cx,
                sc,
                &[b"Syntax error in ln/symlink: Bad second parameter"],
            )?;
            sc.to(cx, State::SftpQuoteSymlink);
            return Ok(());
        }
        if starts(b"mkdir ") {
            return alone(cx, sc, State::SftpQuoteMkdir);
        }
        if starts(b"rename ") {
            second(cx, sc, &[b"Syntax error in rename: Bad second parameter"])?;
            sc.to(cx, State::SftpQuoteRename);
            return Ok(());
        }
        if starts(b"rmdir ") {
            return alone(cx, sc, State::SftpQuoteRmdir);
        }
        if starts(b"rm ") {
            return alone(cx, sc, State::SftpQuoteUnlink);
        }
        if starts(b"statvfs ") {
            return alone(cx, sc, State::SftpQuoteStatvfs);
        }
        let kind = trace::fail(
            cx,
            ErrorKind::QuoteError,
            format_args!("Unknown SFTP command"),
        );
        sc.path1 = None;
        sc.path2 = None;
        Err(Halt::Fail(kind))
    }

    /// `SSH_SFTP_QUOTE_STATVFS`: the file system's numbers, written as a
    /// header.
    fn quote_statvfs<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        let path = sc.path1.take().unwrap_or_default();
        let rc = sc.session().sftp_statvfs(&path);
        sc.path1 = Some(path);
        let fail = |cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn, kind: ErrorKind| {
            sc.to(cx, State::SftpClose);
            sc.next = None;
            Err(Halt::Fail(kind))
        };
        match rc {
            Err(rc) if rc.again() => return Err(Halt::Again),
            Err(_) if !sc.accept_fail => {
                let fx = sc.session().sftp_last_error();
                let p1 = sc.path1.take().unwrap_or_default();
                let kind = trace::fail_with(
                    cx,
                    ErrorKind::QuoteError,
                    &[b"statvfs \"", &p1, b"\" failed: ", sftp_text(fx).as_bytes()],
                );
                return fail(cx, sc, kind);
            }
            Err(_) => {}
            Ok(v) => {
                let said = curl_alloc::try_format(format_args!(
                    "statvfs:\nf_bsize: {}\nf_frsize: {}\nf_blocks: {}\nf_bfree: {}\n\
                     f_bavail: {}\nf_files: {}\nf_ffree: {}\nf_favail: {}\nf_fsid: {}\n\
                     f_flag: {}\nf_namemax: {}\n",
                    v.bsize,
                    v.frsize,
                    v.blocks,
                    v.bfree,
                    v.bavail,
                    v.files,
                    v.ffree,
                    v.favail,
                    v.fsid,
                    v.flag,
                    v.namemax
                ));
                let Ok(said) = said else {
                    return fail(cx, sc, ErrorKind::OutOfMemory);
                };
                if let Err(e) = self.base.pipeline.protocol_header(cx, said.as_bytes()) {
                    return fail(cx, sc, e);
                }
            }
        }
        sc.to(cx, State::SftpNextQuote);
        Ok(())
    }

    /// `SSH_SFTP_UPLOAD_INIT`: the file opened to write, at the resume
    /// point, its directories made first if asked and missing, and the
    /// upload set up (`sftp_upload_init`).
    fn sftp_upload_init2<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        if self.resume_from < 0 {
            let path = self.path.take().unwrap_or_default();
            let attrs = sc.session().sftp_stat(&path);
            self.path = Some(path);
            match attrs {
                Err(rc) if rc.again() => return Err(Halt::Again),
                Err(_) => self.resume_from = 0,
                Ok(attrs) => {
                    let size = attrs.filesize as i64;
                    if size < 0 {
                        return Err(Halt::Fail(trace::fail(
                            cx,
                            ErrorKind::BadDownloadResume,
                            format_args!("Bad file size ({size})"),
                        )));
                    }
                    self.resume_from = size;
                }
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
        let opened = sc.session().sftp_open(&path, mode, perms);
        self.path = Some(path);
        if let Err(rc) = opened {
            if rc.again() {
                return Err(Halt::Again);
            }
            // Only an SFTP protocol error has the server's word on it.
            let fx = if rc == Code::SFTP_PROTOCOL {
                sc.session().sftp_last_error()
            } else {
                Fx::OK
            };
            if sc.second_create_dirs {
                sc.to(cx, State::SftpClose);
                trace::fail_with(
                    cx,
                    ErrorKind::Ssh,
                    &[b"Creating the dir/file failed: ", sftp_text(fx).as_bytes()],
                );
                return sftp_ran(fx);
            }
            let missing = matches!(fx, Fx::NO_SUCH_FILE | Fx::FAILURE | Fx::NO_SUCH_PATH);
            if missing && create_dirs && self.path().len() > 1 {
                sc.second_create_dirs = true;
                sc.to(cx, State::SftpCreateDirsInit);
                return Ok(());
            }
            sc.to(cx, State::SftpClose);
            // The library may answer that the server said nothing of a
            // failed open.
            let (kind, fx) = match sftp_failure(fx) {
                Ok(()) => (ErrorKind::Ssh, Fx::OK),
                Err(kind) => (kind, fx),
            };
            let why = if fx == Fx::OK {
                "ssh error"
            } else {
                sftp_text(fx)
            };
            return Err(Halt::Fail(trace::fail(
                cx,
                kind,
                format_args!("Upload failed: {why} ({}/{})", fx.0, rc.0),
            )));
        }
        let mut upload = Upload::open(cx)?;
        self.infilesize = upload.size();
        if self.resume_from > 0 && !append {
            let from = self.resume_from.unsigned_abs();
            upload.resume_from(cx, from)?;
            if let Some(size) = self.infilesize.filter(|&s| s > 0) {
                let left = size as i64 - self.resume_from;
                self.infilesize = u64::try_from(left).ok();
                crate::upload::announce_size(cx, self.infilesize);
            }
            sc.session().sftp_seek(from);
        }
        if self.infilesize.is_some_and(|s| s > 0) {
            crate::upload::announce_size(cx, self.infilesize);
        }
        self.start_sending(cx, upload)?;
        self.xfer_setup(
            cx,
            Directions {
                recv: false,
                send: true,
            },
        );
        sc.to(cx, State::Stop);
        Ok(())
    }

    /// `SSH_SFTP_CREATE_DIRS_MKDIR`: the directory up to the next slash
    /// made; one there already, or refused, is passed, as one further
    /// down may still be made.
    fn create_dirs_mkdir<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        let mode = u32::from(cx.easy().options().ssh.new_directory_mode.bits());
        let dir_end = sc.slash;
        let path = self.path.take().unwrap_or_default();
        let rc = sc.session().sftp_mkdir(&path[..dir_end], mode);
        self.path = Some(path);
        if let Err(rc) = rc
            && rc.again()
        {
            return Err(Halt::Again);
        }
        sc.slash += 1;
        if rc.is_err() {
            let fx = sc.session().sftp_last_error();
            if !matches!(
                fx,
                Fx::FILE_ALREADY_EXISTS | Fx::FAILURE | Fx::PERMISSION_DENIED
            ) {
                sc.to(cx, State::SftpClose);
                return sftp_ran(fx);
            }
        }
        sc.to(cx, State::SftpCreateDirs);
        Ok(())
    }

    /// `SSH_SFTP_READDIR_INIT`: the directory opened to list, unless no
    /// body is wanted.
    fn readdir_init<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        self.base.pipeline.announce_size(cx, None);
        if self.no_body {
            sc.to(cx, State::Stop);
            return Ok(());
        }
        let path = self.path.take().unwrap_or_default();
        let opened = sc.session().sftp_opendir(&path);
        self.path = Some(path);
        if let Err(rc) = opened {
            if rc.again() {
                return Err(Halt::Again);
            }
            let fx = sc.session().sftp_last_error();
            trace::fail_with(
                cx,
                ErrorKind::Ssh,
                &[
                    b"Could not open directory for reading: ",
                    sftp_text(fx).as_bytes(),
                ],
            );
            sc.to(cx, State::SftpClose);
            return sftp_ran(fx);
        }
        sc.to(cx, State::SftpReaddir);
        Ok(())
    }

    /// `SSH_SFTP_READDIR`: the next entry, its name alone for a list of
    /// names, else its `ls -l` line, a link's target to add to it
    /// (`sftp_readdir`).
    fn readdir<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        let list_only = cx.easy().options().line.list_only;
        let s = sc.session.as_deref_mut().expect("a live session");
        let entry = match s.sftp_readdir() {
            Err(rc) if rc.again() => return Err(Halt::Again),
            Err(_) => {
                let fx = s.sftp_last_error();
                let errno = s.last_errno();
                let kind = if fx == Fx::OK {
                    ErrorKind::Ssh
                } else {
                    sftp_failure(fx).err().unwrap_or(ErrorKind::Ssh)
                };
                trace::fail(
                    cx,
                    kind,
                    format_args!(
                        "Could not open remote file for reading: {} :: {}",
                        sftp_text(fx),
                        errno.0
                    ),
                );
                sc.to(cx, State::SftpClose);
                return Err(Halt::Fail(kind));
            }
            Ok(None) => {
                sc.to(cx, State::SftpReaddirDone);
                return Ok(());
            }
            Ok(Some(entry)) => entry,
        };
        if list_only {
            let name = copy(entry.name)?;
            self.base.pipeline.body(cx, &name)?;
            self.base.pipeline.body(cx, b"\n")?;
            return Ok(());
        }
        let link = entry.attrs.flags.has(AttrFlags::PERMISSIONS)
            && entry.attrs.permissions & u64::from(S_IFMT) == u64::from(S_IFLNK);
        let added = sc.listing.try_extend_from_slice(entry.longentry);
        let name = copy(entry.name);
        added.map_err(|_| ErrorKind::OutOfMemory)?;
        let name = name?;
        if link {
            sc.link.clear();
            sc.link
                .try_extend_from_slice(c_string(self.path()))
                .and_then(|()| sc.link.try_extend_from_slice(&name))
                .map_err(|_| ErrorKind::OutOfMemory)?;
            sc.to(cx, State::SftpReaddirLink);
        } else {
            sc.to(cx, State::SftpReaddirBottom);
        }
        Ok(())
    }

    /// `SSH_SFTP_READDIR_BOTTOM`: the entry's line ended and written.
    fn readdir_bottom<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        let written = match sc.listing.try_push(b'\n') {
            Err(_) => Err(ErrorKind::OutOfMemory),
            Ok(()) => self.base.pipeline.body(cx, &sc.listing),
        };
        sc.listing.clear();
        match written {
            Err(e) => {
                sc.to(cx, State::Stop);
                Err(Halt::Fail(e))
            }
            Ok(()) => {
                sc.to(cx, State::SftpReaddir);
                Ok(())
            }
        }
    }

    /// `SSH_SFTP_DOWNLOAD_INIT`: the file opened to read.
    fn download_init<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        let perms = u32::from(cx.easy().options().new_file_mode.bits());
        let path = self.path.take().unwrap_or_default();
        let opened = sc.session().sftp_open(&path, OpenMode::Read, perms);
        self.path = Some(path);
        if let Err(rc) = opened {
            if rc.again() {
                return Err(Halt::Again);
            }
            let fx = sc.session().sftp_last_error();
            trace::fail_with(
                cx,
                ErrorKind::Ssh,
                &[
                    b"Could not open remote file for reading: ",
                    sftp_text(fx).as_bytes(),
                ],
            );
            sc.to(cx, State::SftpClose);
            return sftp_ran(fx);
        }
        sc.to(cx, State::SftpDownloadStat);
        Ok(())
    }

    /// `SSH_SFTP_DOWNLOAD_STAT`: the file's size, the range and the resume
    /// point applied to it, and the download set up
    /// (`sftp_download_stat`).
    fn download_stat<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        let path = self.path.take().unwrap_or_default();
        let attrs = sc.session().sftp_stat(&path);
        self.path = Some(path);
        let attrs = match attrs {
            Err(rc) if rc.again() => return Err(Halt::Again),
            Err(_) => None,
            Ok(a) => Some(a),
        };
        // The request's size, -1 if unknown (`req.size`), set unknown as
        // the DO starts.
        let mut req_size: i64 = -1;
        let sized = attrs.filter(|a| a.flags.has(AttrFlags::SIZE) && a.filesize != 0);
        // The size the resume point is read against (`attrs.filesize`).
        let filesize: i64 = match sized {
            None => {
                self.base.pipeline.announce_size(cx, None);
                0
            }
            Some(a) => {
                let mut size = a.filesize as i64;
                if size < 0 {
                    return Err(Halt::Fail(trace::fail(
                        cx,
                        ErrorKind::BadDownloadResume,
                        format_args!("Bad file size ({size})"),
                    )));
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
                            return Err(Halt::Fail(ErrorKind::RangeError));
                        }
                    };
                    sc.session().sftp_seek(from.unsigned_abs());
                    size = len;
                }
                req_size = size;
                self.base
                    .pipeline
                    .announce_size(cx, Some(size.unsigned_abs()));
                a.filesize as i64
            }
        };
        if self.resume_from != 0 {
            if self.resume_from < 0 {
                if filesize < -self.resume_from {
                    let from = self.resume_from;
                    return Err(Halt::Fail(trace::fail(
                        cx,
                        ErrorKind::BadDownloadResume,
                        format_args!("Offset ({from}) was beyond file size ({filesize})"),
                    )));
                }
                self.resume_from += filesize;
            } else if filesize < self.resume_from {
                let from = self.resume_from;
                return Err(Halt::Fail(trace::fail(
                    cx,
                    ErrorKind::BadDownloadResume,
                    format_args!("Offset ({from}) was beyond file size ({filesize})"),
                )));
            }
            req_size = filesize - self.resume_from;
            self.base
                .pipeline
                .announce_size(cx, u64::try_from(req_size).ok());
            sc.session().sftp_seek(self.resume_from.unsigned_abs());
        }
        if req_size == 0 {
            self.xfer_setup(cx, Directions::default());
            trace::info(cx, format_args!("SSH: file already completely downloaded"));
            sc.to(cx, State::Stop);
            return Ok(());
        }
        self.receive(cx, u64::try_from(req_size).ok());
        sc.to(cx, State::Stop);
        Ok(())
    }

    /// `SSH_SCP_TRANS_INIT`: the request's path worked out, and the
    /// channel to be opened to write or read the file.
    fn scp_trans_init2<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        match path::working_path(&self.url_path, Home::Scp) {
            Err(e) => {
                sc.to(cx, State::Stop);
                return Err(Halt::Fail(e));
            }
            Ok(p) => self.path = Some(p),
        }
        if self.upload {
            let upload = Upload::open(cx)?;
            self.infilesize = upload.size();
            if self.infilesize.is_none() {
                let kind = trace::fail(
                    cx,
                    ErrorKind::UploadFailed,
                    format_args!("SCP requires a known file size for upload"),
                );
                sc.to(cx, State::ScpChannelFree);
                return Err(Halt::Fail(kind));
            }
            self.source = Some(upload);
            sc.to(cx, State::ScpUploadInit);
        } else {
            sc.to(cx, State::ScpDownloadInit);
        }
        Ok(())
    }

    /// `SSH_SCP_UPLOAD_INIT`: the channel opened to write the file at its
    /// size, and the upload set up.
    fn scp_upload_init2<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        let size = self.infilesize.unwrap_or_default();
        let mode = u32::from(cx.easy().options().new_file_mode.bits());
        let path = self.path.take().unwrap_or_default();
        let sent = sc
            .session()
            .scp_send(&path, mode, i64::try_from(size).unwrap_or(i64::MAX));
        self.path = Some(path);
        if let Err(rc) = sent {
            if rc.again() {
                return Err(Halt::Again);
            }
            let (code, text) = sc.session().last_error();
            sc.to(cx, State::ScpChannelFree);
            let kind = match session_failure(code) {
                Ok(()) => return Ok(()),
                Err(Halt::Again) => return Err(Halt::Again),
                // Generic failures are the upload's.
                Err(Halt::Fail(ErrorKind::Ssh | ErrorKind::RemoteFileNotFound)) => {
                    ErrorKind::UploadFailed
                }
                Err(Halt::Fail(kind)) => kind,
            };
            return Err(Halt::Fail(trace::fail_with(cx, kind, &[&text])));
        }
        crate::upload::announce_size(cx, self.infilesize);
        let upload = self
            .source
            .take()
            .expect("the upload opened with its channel");
        self.start_sending(cx, upload)?;
        self.xfer_setup(
            cx,
            Directions {
                recv: false,
                send: true,
            },
        );
        sc.to(cx, State::Stop);
        Ok(())
    }

    /// `SSH_SCP_DOWNLOAD_INIT`: the channel opened to read the file, at
    /// the size the server gives.
    fn scp_download_init<H: Host>(&mut self, cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
        let path = self.path.take().unwrap_or_default();
        let got = sc.session().scp_recv(&path);
        self.path = Some(path);
        match got {
            Err(rc) if rc.again() => Err(Halt::Again),
            Err(_) => {
                let (code, text) = sc.session().last_error();
                // What C's `failf` says, whatever the failure is.
                trace::fail_with(cx, ErrorKind::Ssh, &[&text]);
                sc.to(cx, State::ScpChannelFree);
                session_failure(code)
            }
            Ok(size) => {
                self.receive(cx, u64::try_from(size).ok());
                sc.to(cx, State::Stop);
                Ok(())
            }
        }
    }

    /// Read the body on, at most as many reads as a step makes
    /// (`sendrecv_dl`, `scp_recv`, `sftp_recv`).
    fn read_body2<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        sc: &mut Ssh2Conn,
        carrier: &mut Carrier<'_>,
    ) -> Result<ProtoStep, ErrorKind> {
        let mut reads = 0;
        loop {
            if !self.receiving {
                return Ok(ProtoStep::Done);
            }
            if cx.pause().recv_paused() {
                return Ok(ProtoStep::Blocked);
            }
            if reads == crate::proto::http::MAX_READS {
                return Ok(ProtoStep::AtReadLimit);
            }
            let max = cx.easy().options().limits.buffer_size.get();
            let max = match cx.rate_allowance(Way::Recv) {
                Some(..=0) => return Ok(ProtoStep::Blocked),
                Some(allowed) => max.min(usize::try_from(allowed).unwrap_or(usize::MAX)),
                None => max,
            };
            // A size known is all that is read (`xfer_recv_resp`).
            let len = match self.size {
                Some(size) => {
                    let left = size.saturating_sub(self.base.pipeline.bytecount());
                    max.min(usize::try_from(left).unwrap_or(usize::MAX))
                }
                None => max,
            };
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
            let s = sc.session.as_deref_mut().expect("a live session");
            let read = if sc.sftp {
                s.sftp_read(buf)
            } else {
                s.channel_read(buf)
            };
            if read == Err(Code::EAGAIN) && sc.pump(cx, carrier) {
                reads -= 1;
                continue;
            }
            sc.block2waitfor(read == Err(Code::EAGAIN));
            let n = match read {
                Err(rc) if rc.again() => return Ok(ProtoStep::Blocked),
                Err(rc) => {
                    return match session_failure(rc) {
                        Ok(()) | Err(Halt::Again) => Ok(ProtoStep::Blocked),
                        Err(Halt::Fail(e)) => Err(e),
                    };
                }
                Ok(n) => n,
            };
            if n == 0 {
                self.read_end(cx)?;
                continue;
            }
            let fed = self.base.pipeline.body(cx, &self.buf[..n]);
            deliver::write_resp(cx, n, false, fed);
            fed?;
            if self.base.pipeline.body_done() {
                self.receiving = false;
            }
        }
    }

    /// Move the exchange on: the body read, or the upload sent.
    pub(super) fn step2<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        self.base.pipeline.flush(cx)?;
        let (sc, mut carrier) = ssh2_of(lease);
        if self.receiving {
            let read = self.read_body2(cx, sc, &mut carrier);
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
        let mut outlet = Ssh2Outlet {
            sc,
            carrier,
            failed: None,
        };
        let sent = sending.send_to(cx, &mut outlet);
        let failed = outlet.failed;
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
    /// again on a fresh connection (`next`, C's `bits.retry`).
    pub(super) fn done2<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        result: Result<(), ErrorKind>,
        premature: bool,
        next: &AfterRequest,
        exchanged: bool,
    ) -> Finish {
        if result.is_ok() && lease.conn().keeps_line() {
            let (sc, _) = ssh2_of(lease);
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
            return self.finishing2(cx, lease, exchanged);
        }
        self.over(cx, result, exchanged)
    }

    /// Run the state machine on as `done` started it
    /// (`ssh_block_statemach`), each pass the progress checked: a call
    /// that would wait leaves it waiting in DONE, as C's waits on the
    /// socket.
    pub(super) fn finishing2<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        exchanged: bool,
    ) -> Finish {
        let ran = self.run2(cx, lease);
        let checked = crate::progress::check(cx, exchanged);
        match (ran, checked) {
            (Err(e), _) | (Ok(_), Err(e)) => self.over(cx, Err(e), exchanged),
            (Ok(true), Ok(_)) => self.over(cx, Ok(()), exchanged),
            (Ok(false), Ok(_)) => Finish::Waiting,
        }
    }

    /// The connect over libssh2: the connection's state made, then the
    /// machine run.
    pub(super) fn connect2<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        library: &'static dyn crate::ssh2::Ssh2,
    ) -> Result<Connect, ErrorKind> {
        if !lease.conn().keeps_line() {
            self.conn_state2(cx, lease, library)?;
        }
        Ok(if self.run2(cx, lease)? {
            Connect::Done
        } else {
            Connect::Waiting
        })
    }

    /// The DO over libssh2 (`ssh_do`, `scp_perform`, `sftp_perform`, and
    /// their `doing`).
    pub(super) fn make2<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        asked: DoPhase,
    ) -> Result<DoStep, ErrorKind> {
        let ran = match asked {
            DoPhase::Do => {
                self.size = None;
                let (sc, _) = ssh2_of(lease);
                sc.second_create_dirs = false;
                crate::progress::reset(cx);
                cx.ssh(format_args!("DO phase starts"));
                let first = if sc.sftp {
                    State::SftpQuoteInit
                } else {
                    State::ScpTransInit
                };
                sc.to(cx, first);
                self.run2(cx, lease)?
            }
            DoPhase::Doing => self.run2(cx, lease)?,
            DoPhase::More => unreachable!("SSH has no second half"),
        };
        if ran {
            cx.ssh(format_args!("DO phase is complete"));
            Ok(DoStep::Did)
        } else {
            Ok(DoStep::Doing)
        }
    }
}

/// `SSH_S_STARTUP`: the session set up over the connection's socket,
/// which a session over pipes is handed all the same, as C's is.
fn startup<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn, carrier: &Carrier<'_>) -> Ran {
    let session = sc.session();
    let socket = match session.pipes() {
        Some(_) => carrier.stream_socket(),
        None => carrier.bare_socket(),
    };
    match session.handshake(socket.and_then(|s| s.descriptor())) {
        Err(rc) if rc.again() => Err(Halt::Again),
        Err(rc) => {
            let text = sc.error_text();
            trace::fail_with(
                cx,
                ErrorKind::FailedInit,
                &[
                    b"Failure establishing ssh session: ",
                    format_code(rc).as_bytes(),
                    b", ",
                    &text,
                ],
            );
            sc.to(cx, State::SessionFree);
            Err(Halt::Fail(ErrorKind::FailedInit))
        }
        Ok(()) => {
            sc.to(cx, State::Hostkey);
            Ok(())
        }
    }
}

/// `SSH_AUTHLIST`: the ways the server lets the user log in, or the user
/// let in already.
fn authlist<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
    let (s, login) = sc.login();
    let list = s
        .userauth_list(login.user)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    let Some(list) = list else {
        if sc.session().authenticated() {
            sc.authed = true;
            trace::info(
                cx,
                format_args!("SSH: user accepted with no authentication"),
            );
            sc.to(cx, State::AuthDone);
            return Ok(());
        }
        let rc = sc.session().last_errno();
        if rc.again() {
            return Err(Halt::Again);
        }
        sc.to(cx, State::SessionFree);
        return session_failure(rc);
    };
    trace::info_with(cx, &[b"SSH: host offers authentication via: ", &list]);
    sc.authlist = list;
    sc.to(cx, State::AuthPkeyInit);
    Ok(())
}

/// `SSH_AUTH_PKEY_INIT`: the key files tried first, if the user may and
/// the server offers it.
fn pkey_init<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) {
    sc.authed = false;
    if allows(cx, SshAuthTypes::PUBLICKEY) && offers(&sc.authlist, b"publickey") {
        let keys = sc.keys();
        let public = keys.and_then(|k| k.public.as_deref()).map(c_string);
        let private = keys.and_then(Keys::private).unwrap_or(b"(nil)");
        let (public, private) = (public.map(copy), copy(private));
        if let Some(Ok(public)) = public {
            trace::info_with(cx, &[b"SSH: trying public key file '", &public, b"'"]);
        }
        if let Ok(private) = private {
            trace::info_with(cx, &[b"SSH: trying private key file '", &private, b"'"]);
        }
        sc.to(cx, State::AuthPkey);
    } else {
        sc.to(cx, State::AuthPassInit);
    }
}

/// `SSH_AUTH_PKEY`: the key files' login.
fn auth_pkey<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
    let (s, login) = sc.login();
    let keys = login.keys;
    let public = keys.and_then(|k| k.public.as_deref()).map(c_string);
    let private = keys.and_then(Keys::private).unwrap_or_default();
    let passphrase = keys
        .and_then(|k| k.passphrase.as_deref())
        .map_or(&b""[..], c_string);
    let rc = s.auth_publickey_fromfile(login.user, public, private, passphrase);
    match rc {
        Err(rc) if rc.again() => Err(Halt::Again),
        Ok(()) => {
            sc.authed = true;
            trace::info(cx, format_args!("SSH: authenticated via publickey"));
            sc.to(cx, State::AuthDone);
            Ok(())
        }
        Err(rc) => {
            // A -1 sets no message: any there is, is an earlier failure's.
            let text = if rc == Code(-1) {
                copy(b"Reason unknown (-1)")?
            } else {
                sc.error_text()
            };
            trace::info_with(cx, &[b"SSH: publickey authentication denied: ", &text]);
            sc.to(cx, State::AuthPassInit);
            Ok(())
        }
    }
}

/// `SSH_AUTH_PASS`: the password login.
fn auth_pass<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
    let (s, login) = sc.login();
    match s.auth_password(login.user, login.password) {
        Err(rc) if rc.again() => Err(Halt::Again),
        Ok(()) => {
            sc.authed = true;
            trace::info(cx, format_args!("SSH: initialized password authentication"));
            sc.to(cx, State::AuthDone);
            Ok(())
        }
        Err(_) => {
            sc.to(cx, State::AuthHostInit);
            Ok(())
        }
    }
}

/// `SSH_AUTH_AGENT_INIT`: the agent connected to, if the user may and
/// the server takes public keys.
fn agent_init<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
    if !(allows(cx, SshAuthTypes::AGENT) && offers(&sc.authlist, b"publickey")) {
        sc.to(cx, State::AuthKeyInit);
        return Ok(());
    }
    trace::info(
        cx,
        format_args!("SSH: trying publickey authentication via agent"),
    );
    if !sc.session().has_agent() && sc.session().agent_init().is_err() {
        trace::info(cx, format_args!("SSH: could not create agent object"));
        sc.to(cx, State::AuthKeyInit);
        return Ok(());
    }
    match sc.session().agent_connect() {
        Err(rc) if rc.again() => Err(Halt::Again),
        Err(_) => {
            trace::info(cx, format_args!("SSH: failure connecting to agent"));
            sc.to(cx, State::AuthKeyInit);
            Ok(())
        }
        Ok(()) => {
            sc.to(cx, State::AuthAgentList);
            Ok(())
        }
    }
}

/// `SSH_AUTH_AGENT_LIST`: the agent's identities asked for.
fn agent_list<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
    match sc.session().agent_list_identities() {
        Err(rc) if rc.again() => Err(Halt::Again),
        Err(_) => {
            trace::info(
                cx,
                format_args!("SSH: failure requesting identities to agent"),
            );
            sc.to(cx, State::AuthKeyInit);
            Ok(())
        }
        Ok(()) => {
            sc.to(cx, State::AuthAgent);
            sc.session().agent_rewind();
            Ok(())
        }
    }
}

/// `SSH_AUTH_AGENT`: the agent's identities tried one at a time.
fn agent<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
    let (s, login) = sc.login();
    let got = match s.agent_get_identity() {
        Err(rc) if rc.again() => return Err(Halt::Again),
        other => other,
    };
    let mut authed = false;
    if got == Ok(Identity::Got) {
        cx.ssh(format_args!(
            "[SSH_AUTH_AGENT_LIST] auth user '{}' for key '{}'",
            curl_alloc::Lossy(login.user),
            curl_alloc::Lossy(s.agent_comment())
        ));
        match s.agent_userauth(login.user) {
            Err(rc) if rc.again() => return Err(Halt::Again),
            // Tried and failed: on to the next identity.
            Err(_) => {
                s.agent_skip();
                return Ok(());
            }
            Ok(()) => authed = true,
        }
    }
    match got {
        Err(_) => trace::info(
            cx,
            format_args!("SSH: failure requesting identities to agent"),
        ),
        Ok(Identity::End) => trace::info(cx, format_args!("SSH: no agent identity would match")),
        Ok(Identity::Got) => {}
    }
    if authed {
        trace::info_with(
            cx,
            &[
                b"SSH: agent authenticated user '",
                login.user,
                b"' with key '",
                s.agent_comment(),
                b"'",
            ],
        );
        sc.authed = true;
        sc.to(cx, State::AuthDone);
    } else {
        sc.to(cx, State::AuthKeyInit);
    }
    Ok(())
}

/// `SSH_AUTH_KEY`: the keyboard-interactive login, its question answered
/// with the password.
fn auth_key<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
    let (s, login) = sc.login();
    match s.auth_keyboard_interactive(login.user, login.password) {
        Err(rc) if rc.again() => Err(Halt::Again),
        Ok(()) => {
            sc.authed = true;
            trace::info(
                cx,
                format_args!("SSH: initialized keyboard interactive authentication"),
            );
            sc.to(cx, State::AuthDone);
            Ok(())
        }
        Err(_) => Err(Halt::Fail(ErrorKind::LoginDenied)),
    }
}

/// `SSH_AUTH_DONE`: logged in, the application connected; on to SFTP's
/// session, or SCP's connect done.
fn auth_done<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
    if !sc.authed {
        let kind = trace::fail(
            cx,
            ErrorKind::LoginDenied,
            format_args!("Authentication failure"),
        );
        sc.to(cx, State::SessionFree);
        return Err(Halt::Fail(kind));
    }
    trace::info(cx, format_args!("SSH: authentication complete"));
    cx.mark(Timer::AppConnect);
    if sc.sftp {
        sc.to(cx, State::SftpInit);
        return Ok(());
    }
    trace::info(cx, format_args!("SSH: connection established"));
    sc.to(cx, State::Stop);
    Ok(())
}

/// `SSH_SFTP_INIT`: the SFTP subsystem started.
fn sftp_init<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
    match sc.session().sftp_init() {
        Err(rc) if rc.again() => Err(Halt::Again),
        Err(_) => {
            let text = sc.error_text();
            trace::fail_with(
                cx,
                ErrorKind::FailedInit,
                &[b"Failure initializing sftp session: ", &text],
            );
            sc.to(cx, State::SessionFree);
            Err(Halt::Fail(ErrorKind::FailedInit))
        }
        Ok(()) => {
            sc.to(cx, State::SftpRealpath);
            Ok(())
        }
    }
}

/// `SSH_SFTP_REALPATH`: the home directory, the connect's last step.
fn sftp_realpath<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
    let home = match sc.session().sftp_realpath(b".") {
        Err(rc) if rc.again() => return Err(Halt::Again),
        Ok(home) => copy(home).map_err(|_| ErrorKind::OutOfMemory),
        Err(_) => {
            sc.to(cx, State::Stop);
            let fx = sc.session().sftp_last_error();
            // A failure not of SFTP's, a time-out or the like.
            let kind = sftp_failure(fx).err().unwrap_or(ErrorKind::Ssh);
            let kind = if fx == Fx::OK { ErrorKind::Ssh } else { kind };
            cx.ssh(format_args!(
                "error = {} makes libcurl = {}",
                fx.0,
                kind.number()
            ));
            return Err(Halt::Fail(kind));
        }
    };
    sc.to(cx, State::Stop);
    let home = home?;
    let recent = copy(c_string(&home))?;
    cx.report_mut()
        .set_ftp_entry_path(recent)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    sc.home = Some(home);
    cx.ssh(format_args!("CONNECT phase done"));
    Ok(())
}

/// Bytes after a command's last path (`quote_error`): its paths let go.
fn quote_error<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> ErrorKind {
    let kind = trace::fail(
        cx,
        ErrorKind::QuoteError,
        format_args!("Suspicious data after the command line"),
    );
    sc.path1 = None;
    sc.path2 = None;
    kind
}

/// A quote command's call came to `rc`: the next command, unless it
/// failed and may not, said as `name "path1"[ to "path2"] failed: `
/// for a command of two paths (`two`) or one.
fn quote_done2<H: Host>(
    cx: &mut StepCx<'_, H>,
    sc: &mut Ssh2Conn,
    rc: Result<(), Code>,
    name: &str,
    two: bool,
) -> Ran {
    match rc {
        Err(rc) if rc.again() => Err(Halt::Again),
        Err(_) if !sc.accept_fail => {
            let fx = sc.session().sftp_last_error();
            let (p1, p2) = (
                sc.path1.take().unwrap_or_default(),
                sc.path2.take().unwrap_or_default(),
            );
            let why = sftp_text(fx).as_bytes();
            let kind = if two {
                trace::fail_with(
                    cx,
                    ErrorKind::QuoteError,
                    &[
                        name.as_bytes(),
                        b" \"",
                        &p1,
                        b"\" to \"",
                        &p2,
                        b"\" failed: ",
                        why,
                    ],
                )
            } else {
                trace::fail_with(
                    cx,
                    ErrorKind::QuoteError,
                    &[name.as_bytes(), b" \"", &p1, b"\" failed: ", why],
                )
            };
            sc.to(cx, State::SftpClose);
            sc.next = None;
            Err(Halt::Fail(kind))
        }
        _ => {
            sc.to(cx, State::SftpNextQuote);
            Ok(())
        }
    }
}

/// `SSH_SFTP_QUOTE_STAT`: the file's attributes read, unless the command
/// sets its permissions, and the command's change to them made, to be
/// sent (`sftp_quote_stat`).
fn quote_stat<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
    let (list, at) = sc.quote.expect("a quote command to run");
    let given = quote_command(cx, list, at).expect("the quote command is in its list");
    let given = c_string(given);
    sc.accept_fail = false;
    let given = match given.strip_prefix(b"*") {
        Some(rest) => {
            sc.accept_fail = true;
            rest
        }
        None => given,
    };
    // The command's name is all this reads of it, its five bytes kept: the
    // state is run again while the stat would wait.
    let mut head = [0u8; 5];
    let n = given.len().min(head.len());
    head[..n].copy_from_slice(&given[..n]);
    let cmd = &head[..];
    let fail = |sc: &mut Ssh2Conn| {
        sc.path1 = None;
        sc.path2 = None;
        Err(Halt::Fail(ErrorKind::QuoteError))
    };
    if !cmd.starts_with(b"chmod") {
        // chown and chgrp set the owner or the group, and the library both:
        // the current ownership is read first.
        let path2 = sc.path2.take().unwrap_or_default();
        let stated = sc.session().sftp_stat(&path2);
        sc.path2 = Some(path2);
        match stated {
            Err(rc) if rc.again() => return Err(Halt::Again),
            Err(_) if !sc.accept_fail => {
                let fx = sc.session().sftp_last_error();
                trace::fail(
                    cx,
                    ErrorKind::QuoteError,
                    format_args!("Attempt to get SFTP stats failed: {}", sftp_text(fx)),
                );
                return fail(sc);
            }
            Err(_) => {}
            Ok(attrs) => sc.quote_attrs = attrs,
        }
    }
    let arg = sc.path1.take().unwrap_or_default();
    // An owner's number up to C's `ULONG_MAX`, as `curl_off_t` holds it.
    let id = || path::number(&arg, i64::MAX, 10).map(|(n, _)| n.unsigned_abs());
    if cmd.starts_with(b"chgrp") {
        match id() {
            Ok(gid) => {
                sc.quote_attrs.gid = gid;
                sc.quote_attrs.flags = AttrFlags::UIDGID;
            }
            Err(_) if !sc.accept_fail => {
                trace::fail(
                    cx,
                    ErrorKind::QuoteError,
                    format_args!("Syntax error: chgrp gid not a number"),
                );
                return fail(sc);
            }
            Err(_) => {}
        }
    } else if cmd.starts_with(b"chmod") {
        let Ok((perms, _)) = path::number(&arg, 0o7777, 8) else {
            trace::fail(
                cx,
                ErrorKind::QuoteError,
                format_args!("Syntax error: chmod permissions not a number"),
            );
            return fail(sc);
        };
        sc.quote_attrs.permissions = perms.unsigned_abs();
        sc.quote_attrs.flags = AttrFlags::PERMISSIONS;
    } else if cmd.starts_with(b"chown") {
        match id() {
            Ok(uid) => {
                sc.quote_attrs.uid = uid;
                sc.quote_attrs.flags = AttrFlags::UIDGID;
            }
            Err(_) if !sc.accept_fail => {
                trace::fail(
                    cx,
                    ErrorKind::QuoteError,
                    format_args!("Syntax error: chown uid not a number"),
                );
                return fail(sc);
            }
            Err(_) => {}
        }
    } else if cmd.starts_with(b"atime") || cmd.starts_with(b"mtime") {
        let date = match crate::date::parse(&arg) {
            Err(_) => {
                let name = curl_alloc::Lossy(&cmd[..5]);
                trace::fail(
                    cx,
                    ErrorKind::QuoteError,
                    format_args!("incorrect date format for {name}"),
                );
                return fail(sc);
            }
            Ok(date) => date,
        };
        // Where a `long` cannot hold more than 32 bits, a later date
        // cannot be sent.
        if size_of::<i64>() > size_of::<std::ffi::c_long>() && date > 0xffff_ffff {
            trace::fail(cx, ErrorKind::QuoteError, format_args!("date overflow"));
            return fail(sc);
        }
        // C's `(unsigned long)` of the date.
        let date = date as u64;
        if cmd.starts_with(b"atime") {
            sc.quote_attrs.atime = date;
        } else {
            sc.quote_attrs.mtime = date;
        }
        sc.quote_attrs.flags = AttrFlags::ACMODTIME;
    }
    sc.path1 = Some(arg);
    sc.to(cx, State::SftpQuoteSetstat);
    Ok(())
}

/// A channel call of SCP's ending: a wait waited on, a failure said and
/// passed over.
fn channel_step<H: Host>(
    cx: &mut StepCx<'_, H>,
    sc: &mut Ssh2Conn,
    call: impl FnOnce(&mut dyn Session2) -> Result<(), Code>,
    what: &str,
) -> Ran {
    let s = sc.session();
    if s.has_channel() {
        match call(s) {
            Err(rc) if rc.again() => return Err(Halt::Again),
            Err(rc) => {
                let text = s.last_error().1;
                trace::info_with(
                    cx,
                    &[what.as_bytes(), format_code(rc).as_bytes(), b" ", &text],
                );
            }
            Ok(()) => {}
        }
    }
    Ok(())
}

/// `SSH_SFTP_READDIR_LINK`: a link's target, added to its entry's line.
fn readdir_link<H: Host>(cx: &mut StepCx<'_, H>, sc: &mut Ssh2Conn) -> Ran {
    let link = std::mem::take(&mut sc.link);
    let s = sc.session.as_deref_mut().expect("a live session");
    let target = match s.sftp_readlink(&link) {
        Err(rc) if rc.again() => {
            sc.link = link;
            return Err(Halt::Again);
        }
        Err(_) => return Err(Halt::Fail(ErrorKind::OutOfMemory)),
        Ok(target) => target,
    };
    let added = sc
        .listing
        .try_extend_from_slice(b" -> ")
        .and_then(|()| sc.listing.try_extend_from_slice(target));
    if added.is_err() {
        sc.to(cx, State::SftpClose);
        return Err(Halt::Fail(ErrorKind::OutOfMemory));
    }
    sc.to(cx, State::SftpReaddirBottom);
    Ok(())
}

/// The upload's bytes go to the SCP channel or the SFTP file, each write
/// nonblocking (`scp_send`, `sftp_send`).
struct Ssh2Outlet<'s> {
    sc: &'s mut Ssh2Conn,
    carrier: Carrier<'s>,
    /// The failure a write came to, past the send failure it is told as.
    failed: Option<ErrorKind>,
}

impl<H: Host> Outlet<H> for Ssh2Outlet<'_> {
    fn put(&mut self, cx: &mut StepCx<'_, H>, bytes: &[u8]) -> std::io::Result<Sent> {
        let sc = &mut *self.sc;
        let wrote = loop {
            let s = sc.session.as_deref_mut().expect("a live session");
            let wrote = if sc.sftp {
                s.sftp_write(bytes)
            } else {
                s.channel_write(bytes)
            };
            let moved = sc.pump(cx, &mut self.carrier);
            if wrote != Err(Code::EAGAIN) || !moved {
                break wrote;
            }
        };
        sc.block2waitfor(wrote == Err(Code::EAGAIN));
        match wrote {
            Err(rc) if rc.again() => Ok(Sent::WouldBlock),
            Err(rc) => {
                self.failed = match session_failure(rc) {
                    Err(Halt::Fail(kind)) => Some(kind),
                    _ => Some(ErrorKind::Ssh),
                };
                Err(std::io::Error::other("SSH write failed"))
            }
            Ok(n) => Ok(std::num::NonZeroUsize::new(n).map_or(Sent::WouldBlock, Sent::Bytes)),
        }
    }
}

#[cfg(test)]
mod tests;
