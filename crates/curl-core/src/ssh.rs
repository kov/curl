//! What an SSH library does for SCP and SFTP, as libssh does for C
//! (`lib/vssh/libssh.c`): a session over a connected socket it is handed,
//! its host key and logins, and the SCP channel or SFTP session over it.
//! The core links none; a handle's `Libraries` name the one its build
//! has. Each call is one of the library's, made when C makes it, so what
//! goes on the wire, and when a call waits, is the library's as in C.

use std::fmt;
use std::ops::BitOr;

use curl_alloc::OutOfMemory;
use curl_os::socket::BorrowedSocket;

/// The SSH library a build has, as C's configure chooses it, and so
/// which of C's files drives it: libssh (`USE_LIBSSH`,
/// `lib/vssh/libssh.c`) or libssh2 (`USE_LIBSSH2`, `lib/vssh/libssh2.c`).
#[derive(Clone, Copy, Debug)]
pub enum SshLibrary {
    Libssh(&'static dyn Ssh),
    Libssh2(&'static dyn crate::ssh2::Ssh2),
}

/// An SSH library.
pub trait Ssh: fmt::Debug + Send + Sync {
    /// A new session, set to nothing yet (`ssh_new`); none if the
    /// library could not make one.
    fn session(&self) -> Option<Box<dyn Session>>;
}

/// How a call that may wait on the socket went (`SSH_OK`, `SSH_AGAIN`,
/// `SSH_ERROR`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rc {
    Ok,
    /// Nonblocking, it waits on the socket: to be called again once that
    /// is ready for what [`Session::poll_flags`] says.
    Again,
    Error,
}

/// How a login step went (`enum ssh_auth_e`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    Success,
    Denied,
    /// Partly: another method is wanted too.
    Partial,
    /// The server asks the keyboard-interactive questions.
    Info,
    Again,
    Error,
}

impl Auth {
    /// The number libssh gives it, as C's trace prints it.
    pub fn number(self) -> i32 {
        match self {
            Auth::Success => 0,
            Auth::Denied => 1,
            Auth::Partial => 2,
            Auth::Info => 3,
            Auth::Again => 4,
            Auth::Error => -1,
        }
    }
}

/// The ways the server lets a user log in (`SSH_AUTH_METHOD_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Methods(u32);

impl Methods {
    pub const NONE: Methods = Methods(0);
    pub const PASSWORD: Methods = Methods(0x0002);
    pub const PUBLICKEY: Methods = Methods(0x0004);
    pub const INTERACTIVE: Methods = Methods(0x0010);
    pub const GSSAPI_MIC: Methods = Methods(0x0020);

    /// The ways the library's bits name.
    pub const fn from_bits(bits: u32) -> Methods {
        Methods(bits)
    }

    /// Whether it has `method`.
    pub fn has(self, method: Methods) -> bool {
        self.0 & method.0 != 0
    }
}

impl BitOr for Methods {
    type Output = Methods;

    fn bitor(self, other: Methods) -> Methods {
        Methods(self.0 | other.0)
    }
}

/// Whether a session's calls wait for the socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blocking {
    Yes,
    No,
}

/// Which way an SCP channel carries its file (`SSH_SCP_WRITE`,
/// `SSH_SCP_READ`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScpWay {
    Write,
    Read,
}

/// What the server says of a failed SFTP call (`SSH_FX_*`, from
/// `sftp_get_error`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SftpStatus {
    /// `SSH_FX_OK`: the call failed with no word from the server on it.
    Unsaid,
    NoSuchFile,
    PermissionDenied,
    Failure,
    NoSuchPath,
    FileAlreadyExists,
    WriteProtect,
    /// Any other code.
    Other(u32),
}

impl SftpStatus {
    /// The status the library's number names.
    pub fn from_number(number: u32) -> SftpStatus {
        match number {
            0 => SftpStatus::Unsaid,
            2 => SftpStatus::NoSuchFile,
            3 => SftpStatus::PermissionDenied,
            4 => SftpStatus::Failure,
            10 => SftpStatus::NoSuchPath,
            11 => SftpStatus::FileAlreadyExists,
            12 => SftpStatus::WriteProtect,
            other => SftpStatus::Other(other),
        }
    }

    /// Its number, as C's trace prints it.
    pub fn number(self) -> u32 {
        match self {
            SftpStatus::Unsaid => 0,
            SftpStatus::NoSuchFile => 2,
            SftpStatus::PermissionDenied => 3,
            SftpStatus::Failure => 4,
            SftpStatus::NoSuchPath => 10,
            SftpStatus::FileAlreadyExists => 11,
            SftpStatus::WriteProtect => 12,
            SftpStatus::Other(other) => other,
        }
    }
}

/// Why an SFTP call that changes something has not done it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotDone {
    /// It waits on the socket (`SSH_AGAIN`), to be called again.
    Again,
    Failed(SftpStatus),
}

/// Why an SFTP call gave no attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttrsError {
    Status(SftpStatus),
    OutOfMemory,
}

impl From<OutOfMemory> for AttrsError {
    fn from(OutOfMemory: OutOfMemory) -> AttrsError {
        AttrsError::OutOfMemory
    }
}

/// What the session waits for on its socket, after a call that would
/// have (`ssh_get_poll_flags`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PollFlags {
    /// `SSH_READ_PENDING`.
    pub read: bool,
    /// `SSH_WRITE_PENDING`.
    pub write: bool,
}

/// A key's type, as libssh names it (`enum ssh_keytypes_e`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Rsa1,
    /// Any ECDSA curve.
    Ecdsa,
    Ed25519,
    Dss,
    /// One curl has no name for.
    Other,
}

/// The server's host key, read as the session found it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKey {
    /// Its SHA-256 fingerprint, if the library made one of 32 bytes.
    pub sha256: Option<[u8; 32]>,
    /// Its MD5 fingerprint, if the library made one of 16 bytes.
    pub md5: Option<[u8; 16]>,
    /// The key in base64, as a known-hosts file holds it, if the library
    /// exported it.
    pub base64: Option<Vec<u8>>,
    pub kind: KeyType,
}

/// What the known-hosts files say of the server's key
/// (`enum ssh_known_hosts_e`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnownHosts {
    Ok,
    Changed,
    Other,
    NotFound,
    Unknown,
    Error,
}

/// A known-hosts file's key for the server, as the session looked it up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownKey {
    /// In base64, if the library exported it.
    pub base64: Option<Vec<u8>>,
    pub kind: KeyType,
}

/// What an SCP channel offers next (`SSH_SCP_REQUEST_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScpRequest {
    NewFile,
    /// Anything else: a directory, its end, a warning, or a failure.
    Other,
}

/// An SFTP file's attributes, copied out of the library's
/// (`sftp_attributes`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attrs {
    pub name: Option<Vec<u8>>,
    /// Its `ls -l` line, as OpenSSH's server makes one.
    pub longname: Option<Vec<u8>>,
    /// Its size, if the server gave one (`SSH_FILEXFER_ATTR_SIZE`).
    pub size: Option<u64>,
    /// Its mode, if the server gave one (`SSH_FILEXFER_ATTR_PERMISSIONS`).
    pub permissions: Option<u32>,
    pub mtime: u32,
}

/// A change to a file's attributes, made to what the server last said of
/// them and sent back whole (`sftp_setstat` of the kept `quote_attrs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttrChange {
    Gid(u32),
    /// Its permissions, which replace the mode's type bits too, as C
    /// sets them.
    Permissions(u32),
    Uid(u32),
    Atime(u32),
    Mtime(u32),
}

/// How an SFTP file is opened (`O_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMode {
    /// `O_RDONLY`.
    Read,
    /// `O_WRONLY | O_CREAT | O_TRUNC`.
    Truncate,
    /// `O_WRONLY | O_CREAT | O_APPEND`.
    Append,
    /// `O_WRONLY`, for a resumed upload that seeks.
    Write,
}

/// How an asynchronous SFTP read or write is waited on
/// (`sftp_aio_wait_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aio {
    /// Done, with this many bytes.
    Done(usize),
    Again,
    Error,
}

/// An SSH session, and the SCP channel, SFTP session, file and directory
/// it has open, each one at a time, as C's `ssh_conn` holds them. A call
/// on one not open is a bug of its caller's, and panics. Dropping it
/// frees all of them, the session last (`sshc_cleanup`), and never closes
/// the socket it was handed: that stays its connection's.
pub trait Session: fmt::Debug + Send {
    // The session's settings (`ssh_options_set`): each fails as the
    // library refuses it.

    /// The host its known-hosts entries are looked up by.
    fn set_host(&mut self, host: &[u8]) -> Result<(), Refused>;
    /// Read the user's and the system's SSH configuration
    /// (`ssh_options_parse_config` of the default files).
    fn parse_config(&mut self) -> Result<(), Refused>;
    /// The connected socket the session reads and writes, which stays the
    /// caller's to close; a socket with no descriptor is one a library
    /// over the system's sockets refuses.
    fn set_socket(&mut self, socket: Option<BorrowedSocket<'_>>) -> Result<(), Refused>;
    fn set_user(&mut self, user: &[u8]) -> Result<(), Refused>;
    /// The known-hosts file, as both the user's and the global one.
    fn set_known_hosts(&mut self, file: &[u8]) -> Result<(), Refused>;
    fn set_port(&mut self, port: u16) -> Result<(), Refused>;
    /// zlib compression, offered before none.
    fn set_compression(&mut self) -> Result<(), Refused>;
    /// The public key file, read now and kept for
    /// [`Session::try_publickey`].
    fn import_pubkey_file(&mut self, file: &[u8]) -> Result<(), Refused>;
    /// Whether the public key file was read.
    fn has_pubkey(&self) -> bool;

    /// Whether the session's calls wait for the socket.
    fn set_blocking(&mut self, blocking: Blocking);
    fn poll_flags(&self) -> PollFlags;
    /// The library's words for the session's last failure
    /// (`ssh_get_error`).
    fn error(&self) -> Result<Vec<u8>, OutOfMemory>;

    /// Set up the session over its socket: its banner, key exchange and
    /// host key (`ssh_connect`).
    fn connect(&mut self) -> Rc;
    /// The server's host key, as the connect found it; none if the
    /// library has none.
    fn host_key(&mut self) -> Option<HostKey>;
    /// What the known-hosts files say of the server's key, and their key
    /// for it if they have one (`ssh_session_get_known_hosts_entry`):
    /// `Some(Err)` if the library could not export it.
    fn known_host(&mut self) -> (KnownHosts, Option<Result<KnownKey, Failed>>);
    /// Add the server's key to the known-hosts file.
    fn update_known_hosts(&mut self) -> Rc;

    // The logins (`ssh_userauth_*`), each as the user set.

    fn auth_none(&mut self) -> Auth;
    fn auth_list(&mut self) -> Methods;
    /// Offer the public key [`Session::import_pubkey_file`] read.
    fn try_publickey(&mut self) -> Auth;
    /// Read the private key file, decrypted with `passphrase`, and keep it
    /// for [`Session::auth_publickey`] (`ssh_pki_import_privkey_file`).
    fn import_privkey_file(&mut self, file: &[u8], passphrase: Option<&[u8]>) -> Rc;
    fn auth_publickey(&mut self) -> Auth;
    /// The agent's keys and the default ones, decrypted with
    /// `passphrase`.
    fn auth_publickey_auto(&mut self, passphrase: Option<&[u8]>) -> Auth;
    fn auth_gssapi(&mut self) -> Auth;
    fn auth_kbdint(&mut self) -> Auth;
    /// How many questions the server asks now.
    fn kbdint_prompts(&mut self) -> Result<u32, Failed>;
    /// Answer the keyboard-interactive question `i`.
    fn kbdint_answer(&mut self, i: u32, answer: &[u8]) -> Result<(), Failed>;
    fn auth_password(&mut self, password: &[u8]) -> Auth;

    /// Say goodbye to the server (`ssh_disconnect`).
    fn disconnect(&mut self);

    // SCP (`ssh_scp_*`).

    /// Open a channel to write `path`, or read it.
    fn scp_new(&mut self, way: ScpWay, path: &[u8]) -> Result<(), Failed>;
    fn has_scp(&self) -> bool;
    fn scp_init(&mut self) -> Rc;
    fn scp_push_file(&mut self, path: &[u8], size: u64, mode: u32) -> Rc;
    fn scp_pull_request(&mut self) -> ScpRequest;
    /// The size of the file the request offers.
    fn scp_size(&mut self) -> u64;
    /// Read into `buf`: how many bytes, or a failure.
    fn scp_read(&mut self, buf: &mut [u8]) -> Result<usize, Failed>;
    fn scp_write(&mut self, bytes: &[u8]) -> Rc;
    fn scp_close(&mut self) -> Rc;
    fn scp_free(&mut self);

    // SFTP (`sftp_*`).

    /// Open the SFTP subsystem.
    fn sftp_new(&mut self) -> Result<(), Failed>;
    fn has_sftp(&self) -> bool;
    fn sftp_init(&mut self) -> Rc;
    fn canonicalize(&mut self, path: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory>;
    fn opendir(&mut self, path: &[u8]) -> Result<(), SftpStatus>;
    /// The next entry of the open directory; none past its last.
    fn readdir(&mut self) -> Result<Option<Attrs>, AttrsError>;
    fn closedir(&mut self);
    fn lstat(&mut self, path: &[u8]) -> Result<Attrs, AttrsError>;
    fn readlink(&mut self, path: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory>;
    fn stat(&mut self, path: &[u8]) -> Result<Attrs, AttrsError>;
    /// Read `path`'s attributes and keep them to change.
    fn stat_to_change(&mut self, path: &[u8]) -> Result<(), SftpStatus>;
    /// Change the attributes kept and send them, whole, for `path`.
    fn setstat_kept(&mut self, path: &[u8], change: AttrChange) -> Result<(), NotDone>;
    /// Make `dest` a link to `target`.
    fn symlink(&mut self, target: &[u8], dest: &[u8]) -> Result<(), NotDone>;
    fn mkdir(&mut self, path: &[u8], mode: u32) -> Result<(), NotDone>;
    fn rename(&mut self, from: &[u8], to: &[u8]) -> Result<(), NotDone>;
    fn rmdir(&mut self, path: &[u8]) -> Result<(), NotDone>;
    fn unlink(&mut self, path: &[u8]) -> Result<(), NotDone>;
    /// Open `path`, closing any file open before.
    fn open(&mut self, path: &[u8], mode: OpenMode, perms: u32) -> Result<(), SftpStatus>;
    fn has_file(&self) -> bool;
    fn close_file(&mut self);
    fn seek(&mut self, offset: u64) -> Result<(), SftpStatus>;
    fn fstat(&mut self) -> Result<Attrs, AttrsError>;
    fn file_nonblocking(&mut self);
    /// Ask for `len` bytes of the file (`sftp_aio_begin_read`).
    fn begin_read(&mut self, len: usize) -> Result<(), Failed>;
    /// The bytes asked for, into `buf`.
    fn wait_read(&mut self, buf: &mut [u8]) -> Aio;
    /// Send `bytes` to be written (`sftp_aio_begin_write`).
    fn begin_write(&mut self, bytes: &[u8]) -> Result<(), Failed>;
    fn wait_write(&mut self) -> Aio;
    /// Let go of any read or write under way (`SFTP_AIO_FREE`).
    fn free_aio(&mut self);
    fn sftp_free(&mut self);
}

/// The library failed a call, and said no more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failed;

/// The library refused a setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused;

impl From<OutOfMemory> for Refused {
    fn from(OutOfMemory: OutOfMemory) -> Refused {
        Refused
    }
}
