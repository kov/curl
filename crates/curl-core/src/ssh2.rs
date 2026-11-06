//! What libssh2 does for SCP and SFTP, as `lib/vssh/libssh2.c` calls it:
//! a session over the connected socket it is lent, its known-hosts
//! collection and agent, its logins, and the SCP channel or SFTP session,
//! and file or directory, over it. The core links none; a handle's
//! `Libraries` name the one its build has. Each call is one of the
//! library's, made when C makes it, so what goes on the wire, and when a
//! call waits, is the library's as in C. Every call is nonblocking: one
//! that would wait fails with [`Code::EAGAIN`], to be made again once the
//! socket is ready for what [`Session2::block_directions`] says.

use std::fmt;

use curl_alloc::OutOfMemory;
use curl_os::socket::BorrowedSocket;

pub use crate::ssh::{Blocking, Failed, OpenMode, PollFlags};

/// libssh2.
pub trait Ssh2: fmt::Debug + Send + Sync {
    /// A new session, set to nothing yet (`libssh2_session_init_ex`);
    /// none if the library could not make one.
    fn session(&self) -> Option<Box<dyn Session2>>;
    /// The cryptography library it was built with
    /// (`libssh2_crypto_engine`).
    fn crypto(&self) -> Crypto;
}

/// The cryptography library libssh2 was built with
/// (`libssh2_crypto_engine_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Crypto {
    OpenSsl,
    Gcrypt,
    MbedTls,
    WinCng,
    Os400Qc3,
    /// None, or one C has no name for.
    Other,
}

/// What a libssh2 call failed with (`LIBSSH2_ERROR_*`): its number, as
/// C's traces print it, and whose names C's code tests for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code(pub i32);

impl Code {
    pub const NONE: Code = Code(0);
    pub const SOCKET_NONE: Code = Code(-1);
    pub const ALLOC: Code = Code(-6);
    pub const SOCKET_SEND: Code = Code(-7);
    pub const TIMEOUT: Code = Code(-9);
    pub const HOSTKEY_INIT: Code = Code(-10);
    pub const HOSTKEY_SIGN: Code = Code(-11);
    pub const PASSWORD_EXPIRED: Code = Code(-15);
    /// Also `LIBSSH2_ERROR_AUTHENTICATION_FAILED`.
    pub const PUBLICKEY_UNRECOGNIZED: Code = Code(-18);
    pub const PUBLICKEY_UNVERIFIED: Code = Code(-19);
    pub const SCP_PROTOCOL: Code = Code(-28);
    pub const SOCKET_TIMEOUT: Code = Code(-30);
    pub const SFTP_PROTOCOL: Code = Code(-31);
    /// The call would wait on the socket.
    pub const EAGAIN: Code = Code(-37);

    /// Whether the call would have waited.
    pub fn again(self) -> bool {
        self == Code::EAGAIN
    }
}

/// What an SFTP server said of a failed call (`LIBSSH2_FX_*`, from
/// `libssh2_sftp_last_error`), as C's traces print it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fx(pub u64);

impl Fx {
    pub const OK: Fx = Fx(0);
    pub const EOF: Fx = Fx(1);
    pub const NO_SUCH_FILE: Fx = Fx(2);
    pub const PERMISSION_DENIED: Fx = Fx(3);
    pub const FAILURE: Fx = Fx(4);
    pub const BAD_MESSAGE: Fx = Fx(5);
    pub const NO_CONNECTION: Fx = Fx(6);
    pub const CONNECTION_LOST: Fx = Fx(7);
    pub const OP_UNSUPPORTED: Fx = Fx(8);
    pub const INVALID_HANDLE: Fx = Fx(9);
    pub const NO_SUCH_PATH: Fx = Fx(10);
    pub const FILE_ALREADY_EXISTS: Fx = Fx(11);
    pub const WRITE_PROTECT: Fx = Fx(12);
    pub const NO_MEDIA: Fx = Fx(13);
    pub const NO_SPACE_ON_FILESYSTEM: Fx = Fx(14);
    pub const QUOTA_EXCEEDED: Fx = Fx(15);
    pub const UNKNOWN_PRINCIPAL: Fx = Fx(16);
    pub const LOCK_CONFLICT: Fx = Fx(17);
    pub const DIR_NOT_EMPTY: Fx = Fx(18);
    pub const NOT_A_DIRECTORY: Fx = Fx(19);
    pub const INVALID_FILENAME: Fx = Fx(20);
    pub const LINK_LOOP: Fx = Fx(21);
}

/// The type of the server's host key (`LIBSSH2_HOSTKEY_TYPE_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKeyType {
    Rsa,
    Dss,
    Ecdsa256,
    Ecdsa384,
    Ecdsa521,
    Ed25519,
    /// One the library has no name for.
    Unknown,
}

/// A known-hosts entry's key type (`LIBSSH2_KNOWNHOST_KEY_*` shifted
/// down by `LIBSSH2_KNOWNHOST_KEY_SHIFT`): a number of four bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownKeyType(pub u8);

impl KnownKeyType {
    pub const RSA1: KnownKeyType = KnownKeyType(1);
    pub const SSHRSA: KnownKeyType = KnownKeyType(2);
    pub const SSHDSS: KnownKeyType = KnownKeyType(3);
    pub const ECDSA_256: KnownKeyType = KnownKeyType(4);
    pub const ECDSA_384: KnownKeyType = KnownKeyType(5);
    pub const ECDSA_521: KnownKeyType = KnownKeyType(6);
    pub const ED25519: KnownKeyType = KnownKeyType(7);
    /// The most there may be, past which none is.
    pub const COUNT: usize = 16;

    /// The bits of a known-hosts entry's type mask it is
    /// (`LIBSSH2_KNOWNHOST_KEY_*`), as C's trace prints them.
    pub fn bits(self) -> u32 {
        u32::from(self.0) << 18
    }
}

/// An entry of the known-hosts collection, copied out of the library's
/// (`struct libssh2_knownhost`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownEntry {
    /// Its host name in plain text, none for a hashed one.
    pub name: Option<Vec<u8>>,
    /// Its key, in base64.
    pub key: Option<Vec<u8>>,
    pub kind: KnownKeyType,
}

/// How a key looked up in the known-hosts collection is given
/// (`LIBSSH2_KNOWNHOST_KEYENC_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyForm {
    Raw,
    Base64,
}

/// What the known-hosts collection says of a host's key
/// (`LIBSSH2_KNOWNHOST_CHECK_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    Match,
    Mismatch,
    NotFound,
    Failure,
}

impl Check {
    /// Its number, as C's trace prints it and passes it on as a
    /// `curl_khmatch`.
    pub fn number(self) -> i32 {
        match self {
            Check::Match => 0,
            Check::Mismatch => 1,
            Check::NotFound => 2,
            Check::Failure => 3,
        }
    }
}

/// An SFTP file's attributes (`LIBSSH2_SFTP_ATTRIBUTES`), each field
/// meaningful where its flag says so.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attrs {
    pub flags: AttrFlags,
    pub filesize: u64,
    pub uid: u64,
    pub gid: u64,
    pub permissions: u64,
    pub atime: u64,
    pub mtime: u64,
}

/// Which of an SFTP file's attributes are given (`LIBSSH2_SFTP_ATTR_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttrFlags(pub u64);

impl AttrFlags {
    pub const SIZE: AttrFlags = AttrFlags(0x1);
    pub const UIDGID: AttrFlags = AttrFlags(0x2);
    pub const PERMISSIONS: AttrFlags = AttrFlags(0x4);
    pub const ACMODTIME: AttrFlags = AttrFlags(0x8);

    /// Whether it has `flag`.
    pub fn has(self, flag: AttrFlags) -> bool {
        self.0 & flag.0 != 0
    }
}

/// What a file system says of itself (`LIBSSH2_SFTP_STATVFS`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statvfs {
    pub bsize: u64,
    pub frsize: u64,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub favail: u64,
    pub fsid: u64,
    pub flag: u64,
    pub namemax: u64,
}

/// An entry of the directory open, as `libssh2_sftp_readdir_ex` read it
/// into the session's buffers of 1024 bytes each, as C's are.
#[derive(Debug)]
pub struct DirEntry<'a> {
    pub name: &'a [u8],
    /// Its `ls -l` line, as OpenSSH's server makes one.
    pub longentry: &'a [u8],
    pub attrs: Attrs,
}

/// What the agent gave as its next identity
/// (`libssh2_agent_get_identity`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Identity {
    /// One, kept to log in with.
    Got,
    /// None is left.
    End,
}

/// What a call that frees a handle does with it when it would wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Let {
    /// Keep it, to be freed by the next call.
    Wait,
    /// Forget it whatever the call said, as a blocking cleanup does.
    Go,
}

/// A libssh2 session and what it has open, each one at a time, as C's
/// `ssh_conn` holds them. A call on one not open is a bug of its caller's,
/// and panics. Dropping it frees all of them, as C's connection does
/// (`sshc_cleanup` blocking), and never closes the socket it was lent.
pub trait Session2: fmt::Debug + Send {
    /// Wait no longer than `secs` for a packet
    /// (`libssh2_session_set_read_timeout`).
    fn set_read_timeout(&mut self, secs: i64);
    /// Offer zlib compression (`LIBSSH2_FLAG_COMPRESS`).
    fn enable_compression(&mut self) -> Result<(), Code>;
    fn set_blocking(&mut self, blocking: Blocking);
    /// Prefer the server's host key of these methods
    /// (`libssh2_session_method_pref` of `LIBSSH2_METHOD_HOSTKEY`).
    fn set_hostkey_methods(&mut self, prefs: &[u8]) -> Result<(), Code>;
    /// The last failure's number and the library's words for it
    /// (`libssh2_session_last_error`).
    fn last_error(&self) -> (Code, Vec<u8>);
    /// The last failure's number (`libssh2_session_last_errno`).
    fn last_errno(&self) -> Code;
    /// What the call that would have waited waits for.
    fn block_directions(&self) -> PollFlags;

    // The known-hosts collection (`libssh2_knownhost_*`).

    fn knownhost_init(&mut self) -> Result<(), Failed>;
    fn has_knownhosts(&self) -> bool;
    /// Read the entries of `file`, an OpenSSH known-hosts file.
    fn knownhost_readfile(&mut self, file: &[u8]) -> Result<(), Code>;
    /// The entries, in the collection's order.
    fn knownhost_entries(&self) -> Result<Vec<KnownEntry>, OutOfMemory>;
    /// What the collection says of `key` for `host` at `port` (none for
    /// SSH's own), and the key of the entry it found, kept to delete.
    fn knownhost_check(
        &mut self,
        host: &[u8],
        port: Option<u16>,
        key: &[u8],
        form: KeyForm,
        kind: KnownKeyType,
    ) -> Result<(Check, Option<Vec<u8>>), OutOfMemory>;
    /// Delete the entry the last check found, if it found one.
    fn knownhost_del_found(&mut self);
    /// Add a plain entry of `key`, raw, for `host`.
    fn knownhost_add(&mut self, host: &[u8], key: &[u8], kind: KnownKeyType) -> Result<(), Code>;
    fn knownhost_writefile(&mut self, file: &[u8]) -> Result<(), Code>;
    fn knownhost_free(&mut self);

    /// Set up the session over the socket it is lent, which it reads and
    /// writes until freed: its banner, key exchange and host key
    /// (`libssh2_session_handshake`).
    /// None for a socket of no descriptor the library could read, which
    /// it refuses (`LIBSSH2_ERROR_SOCKET_NONE`).
    fn handshake(&mut self, socket: Option<BorrowedSocket<'_>>) -> Result<(), Code>;
    /// The server's host key, raw, and its type
    /// (`libssh2_session_hostkey`).
    fn host_key(&self) -> Option<(&[u8], HostKeyType)>;
    fn host_key_sha256(&self) -> Option<[u8; 32]>;
    fn host_key_md5(&self) -> Option<[u8; 16]>;

    // The logins (`libssh2_userauth_*`, `libssh2_agent_*`).

    /// The methods the server offers `user`, comma-separated; none if
    /// the call failed or `user` is in already.
    fn userauth_list(&mut self, user: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory>;
    fn authenticated(&self) -> bool;
    fn auth_publickey_fromfile(
        &mut self,
        user: &[u8],
        public: Option<&[u8]>,
        private: &[u8],
        passphrase: &[u8],
    ) -> Result<(), Code>;
    fn auth_password(&mut self, user: &[u8], password: &[u8]) -> Result<(), Code>;
    /// Keyboard-interactive, a question asked alone answered with
    /// `password`.
    fn auth_keyboard_interactive(&mut self, user: &[u8], password: &[u8]) -> Result<(), Code>;
    fn agent_init(&mut self) -> Result<(), Failed>;
    fn has_agent(&self) -> bool;
    fn agent_connect(&mut self) -> Result<(), Code>;
    fn agent_list_identities(&mut self) -> Result<(), Code>;
    /// Start again from the agent's first identity.
    fn agent_rewind(&mut self);
    /// The identity after the one passed over last.
    fn agent_get_identity(&mut self) -> Result<Identity, Code>;
    /// The comment of the identity got.
    fn agent_comment(&self) -> &[u8];
    /// Log `user` in with the identity got.
    fn agent_userauth(&mut self, user: &[u8]) -> Result<(), Code>;
    /// Pass over the identity got.
    fn agent_skip(&mut self);
    fn agent_disconnect(&mut self) -> Result<(), Code>;
    fn agent_free(&mut self);

    // SFTP (`libssh2_sftp_*`).

    fn sftp_init(&mut self) -> Result<(), Code>;
    fn has_sftp(&self) -> bool;
    fn sftp_last_error(&self) -> Fx;
    /// The path `path` resolves to, if the call gave a path of one byte
    /// or more.
    fn sftp_realpath(&mut self, path: &[u8]) -> Result<&[u8], Code>;
    /// Open `path` as a file, its permissions `perms` if made.
    fn sftp_open(&mut self, path: &[u8], mode: OpenMode, perms: u32) -> Result<(), Code>;
    fn sftp_opendir(&mut self, path: &[u8]) -> Result<(), Code>;
    fn has_handle(&self) -> bool;
    fn sftp_stat(&mut self, path: &[u8]) -> Result<Attrs, Code>;
    /// Set `path`'s attributes to `attrs`, whole.
    fn sftp_setstat(&mut self, path: &[u8], attrs: &Attrs) -> Result<(), Code>;
    fn sftp_seek(&mut self, offset: u64);
    /// The open directory's next entry; none past its last.
    fn sftp_readdir(&mut self) -> Result<Option<DirEntry<'_>>, Code>;
    fn sftp_readlink(&mut self, path: &[u8]) -> Result<&[u8], Code>;
    fn sftp_symlink(&mut self, path: &[u8], target: &[u8]) -> Result<(), Code>;
    fn sftp_mkdir(&mut self, path: &[u8], mode: u32) -> Result<(), Code>;
    /// Rename, overwriting, atomically and natively, as C asks.
    fn sftp_rename(&mut self, from: &[u8], to: &[u8]) -> Result<(), Code>;
    fn sftp_rmdir(&mut self, path: &[u8]) -> Result<(), Code>;
    fn sftp_unlink(&mut self, path: &[u8]) -> Result<(), Code>;
    fn sftp_statvfs(&mut self, path: &[u8]) -> Result<Statvfs, Code>;
    fn sftp_read(&mut self, buf: &mut [u8]) -> Result<usize, Code>;
    fn sftp_write(&mut self, bytes: &[u8]) -> Result<usize, Code>;
    /// Close the file or directory open (`libssh2_sftp_close_handle`).
    fn sftp_close(&mut self, let_go: Let) -> Result<(), Code>;
    fn sftp_shutdown(&mut self, let_go: Let) -> Result<(), Code>;

    // SCP (`libssh2_scp_*`, `libssh2_channel_*`).

    /// A channel to read `path` from: the file's size, as the server
    /// gives it.
    fn scp_recv(&mut self, path: &[u8]) -> Result<i64, Code>;
    /// A channel to write `path` to, of `size` bytes and mode `mode`.
    fn scp_send(&mut self, path: &[u8], mode: u32, size: i64) -> Result<(), Code>;
    fn has_channel(&self) -> bool;
    fn channel_read(&mut self, buf: &mut [u8]) -> Result<usize, Code>;
    fn channel_write(&mut self, bytes: &[u8]) -> Result<usize, Code>;
    fn channel_send_eof(&mut self) -> Result<(), Code>;
    fn channel_wait_eof(&mut self) -> Result<(), Code>;
    fn channel_wait_closed(&mut self) -> Result<(), Code>;
    fn channel_free(&mut self, let_go: Let) -> Result<(), Code>;

    /// Say goodbye to the server (`libssh2_session_disconnect`, its
    /// description `Shutdown`).
    fn disconnect(&mut self) -> Result<(), Code>;
    fn has_session(&self) -> bool;
    fn session_free(&mut self, let_go: Let) -> Result<(), Code>;
}
