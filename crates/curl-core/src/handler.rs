//! What an application gives a transfer to call: where its output goes.
//!
//! Each handler is shared, as C's callback and its userdata pointer are: a
//! copy of the `Easy` (`curl_easy_duphandle`) calls the same one. So a
//! handler is called through `&self` and keeps its state in cells.

use std::fmt;
use std::io;
use std::num::NonZeroUsize;
use std::ops::Deref;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_box};

use crate::conn::io::{Socket, SocketKey, SocketOption};
use crate::error::ErrorKind;
use crate::multi::TransferCx;
use crate::tls::TlsNative;

/// What a write or header handler did with what it was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Write {
    Accepted,
    /// Stop delivering; what was given is delivered again once unpaused
    /// (`CURL_WRITEFUNC_PAUSE`).
    Pause,
    /// The transfer fails with a write error.
    Fail,
    /// This many of the bytes given were taken: any other count than all
    /// of them fails the transfer with a write error, as a destination
    /// that could not take them.
    Took(usize),
}

/// What a read handler gave (`CURLOPT_READFUNCTION`'s return).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    /// This many bytes at the start of the buffer; more than it holds is
    /// a read error.
    Data(NonZeroUsize),
    /// Nothing more to send.
    Eof,
    /// Nothing now; the transfer's sending is paused until unpaused
    /// (`CURL_READFUNC_PAUSE`).
    Pause,
    /// The transfer fails with AbortedByCallback (`CURL_READFUNC_ABORT`).
    Abort,
    /// What there is to send could not be read: the transfer fails with
    /// ReadError.
    Fail,
}

/// Gives what a transfer sends (`CURLOPT_READFUNCTION`).
pub trait ReadHandler: Send + Sync {
    fn read(&self, cx: &mut TransferCx<'_>, buf: &mut [u8]) -> Read;
}

/// Gives the trailers a chunked request body ends with
/// (`CURLOPT_TRAILERFUNCTION`): each line, `Name: value`, added to
/// `lines`; a line without a colon and a space after it is skipped.
pub trait TrailerHandler: Send + Sync {
    fn trailers(&self, cx: &mut TransferCx<'_>, lines: &mut TrailerLines) -> Trailers;
}

/// Whether a trailer handler lets the body end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trailers {
    Done,
    /// The transfer fails with AbortedByCallback.
    Abort,
}

/// The trailer lines a handler gives, each without its line end. A line
/// that could not be kept fails the transfer with OutOfMemory.
#[derive(Debug, Default)]
pub struct TrailerLines {
    lines: Vec<Vec<u8>>,
    lost: bool,
}

impl TrailerLines {
    pub fn add(&mut self, line: &[u8]) -> Result<(), OutOfMemory> {
        let mut copy = Vec::new();
        let kept = copy
            .try_extend_from_slice(line)
            .and_then(|()| self.lines.try_push(copy));
        self.lost |= kept.is_err();
        kept
    }

    /// The lines, or none if one was lost.
    pub(crate) fn lines(&self) -> Result<impl Iterator<Item = &[u8]>, OutOfMemory> {
        if self.lost {
            return Err(OutOfMemory);
        }
        Ok(self.lines.iter().map(Vec::as_slice))
    }
}

/// A rewind that could not be done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewindFailed;

/// Why what a read handler gives was not moved to a point in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeekFailed {
    /// The upload fails (`CURL_SEEKFUNC_FAIL`).
    Fail,
    /// It cannot be moved, and the bytes before the point are read and
    /// dropped instead (`CURL_SEEKFUNC_CANTSEEK`).
    CantSeek,
}

/// Starts what a read handler gives over from the beginning, for a request
/// sent again (`CURLOPT_SEEKFUNCTION` to 0, `CURLOPT_IOCTLFUNCTION`), or
/// from a point in it, for an upload resumed there.
pub trait Rewind: Send + Sync {
    fn rewind(&self, cx: &mut TransferCx<'_>) -> Result<(), RewindFailed>;

    /// Have the next read give the bytes from `offset` on, counted from
    /// the start (`CURLOPT_SEEKFUNCTION` with `SEEK_SET`). By default it
    /// cannot.
    fn seek(&self, _cx: &mut TransferCx<'_>, _offset: u64) -> Result<(), SeekFailed> {
        Err(SeekFailed::CantSeek)
    }
}

/// Where a header line came from (`CURLH_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderOrigin {
    /// The response's head.
    Header,
    /// After the body (`CURLH_TRAILER`).
    Trailer,
    /// A proxy's answer to CONNECT (`CURLH_CONNECT`).
    Connect,
    /// An informational response, 1xx (`CURLH_1XX`).
    Interim,
}

/// Bytes the application holds and lends as a body, of a known length:
/// read where they are as they are sent, not copied when given
/// (`CURLOPT_POSTFIELDS`). The body's position is the transfer's.
pub trait LentBytes: Send + Sync {
    /// How many there are.
    fn size(&self) -> u64;
    /// Copy into `buf` those from `at`, which is below `size`, as many as
    /// fit; how many.
    fn copy_at(&self, at: u64, buf: &mut [u8]) -> usize;
}

/// A list of lines the application keeps, and may change after giving
/// it: read again each time a transfer would read the option it is given
/// for, so that a line added since is seen (`CURLOPT_HTTPHEADER` and the
/// other `curl_slist` options, which C walks where it uses them).
pub trait LineSource: Send + Sync {
    /// Give each line, in order, to `line`; stop at its first error.
    fn lines(
        &self,
        line: &mut dyn FnMut(&[u8]) -> Result<(), OutOfMemory>,
    ) -> Result<(), OutOfMemory>;
}

/// What a trace entry is (`curl_infotype`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugKind {
    Text,
    HeaderIn,
    HeaderOut,
    DataIn,
    DataOut,
    SslDataIn,
    SslDataOut,
}

/// How far a transfer has come, for its progress handler. A size not
/// known is `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProgressNow {
    pub download_total: Option<u64>,
    pub downloaded: u64,
    pub upload_total: Option<u64>,
    pub uploaded: u64,
}

/// What a progress handler wants done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressVerdict {
    Continue,
    /// Go on, and draw the meter as if there were no handler
    /// (`CURL_PROGRESSFUNC_CONTINUE`).
    ContinueWithMeter,
    /// The transfer fails with AbortedByCallback.
    Abort,
}

/// Told of a transfer's progress, about once a second and whenever it
/// moves (`CURLOPT_XFERINFOFUNCTION`).
pub trait ProgressHandler: Send + Sync {
    fn progress(&self, cx: &mut TransferCx<'_>, now: ProgressNow) -> ProgressVerdict;
}

/// Takes text meant for the user: the progress meter, and messages with
/// no debug handler to go to (`CURLOPT_STDERR`).
pub trait TextSink: Send + Sync {
    fn write(&self, text: &[u8]);
}

/// Takes the trace of a verbose transfer (`CURLOPT_DEBUGFUNCTION`).
pub trait DebugHandler: Send + Sync {
    fn debug(&self, cx: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]);
}

/// Takes the body (`CURLOPT_WRITEFUNCTION`), in pieces of at most 16384
/// bytes (`CURL_MAX_WRITE_SIZE`).
pub trait WriteHandler: Send + Sync {
    fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write;
}

/// Takes each header line whole, with its line ending
/// (`CURLOPT_HEADERFUNCTION`).
pub trait HeaderHandler: Send + Sync {
    fn header(&self, cx: &mut TransferCx<'_>, line: &[u8], origin: HeaderOrigin) -> Write;
}

/// Opens the sockets a transfer connects over, in place of the system
/// (`CURLOPT_OPENSOCKETFUNCTION`): a socket of `kind` for `address`'s
/// family, a stream (TCP or Unix) or a UDP socket for QUIC's datagrams,
/// not connected yet, which is made nonblocking once set. It may change `address`, which is then the one connected to. An
/// error fails the attempt, as a socket the system could not open does.
pub trait SocketOpener: Send + Sync {
    fn open(
        &self,
        cx: &mut TransferCx<'_>,
        address: &mut crate::conn::io::Remote,
        kind: crate::conn::io::SocketKind,
    ) -> io::Result<Box<dyn Socket>>;
}

/// Told of each socket a transfer opens, once the library has set it and
/// before it connects, and of each it accepts from a server
/// (`CURLOPT_SOCKOPTFUNCTION`).
pub trait SocketConfigurer: Send + Sync {
    fn configure(&self, cx: &mut TransferCx<'_>, socket: SocketToSet<'_>) -> Configured;
}

/// Told of the connection a request is about to be made over, once
/// connected and before anything of the request is made
/// (`CURLOPT_PREREQFUNCTION`): its ends, those of the connection the
/// transfer last used, none if it used none. An abort fails the
/// transfer with AbortedByCallback.
pub trait PrereqHandler: Send + Sync {
    fn prereq(
        &self,
        cx: &mut TransferCx<'_>,
        ends: Option<&crate::report::Ends>,
    ) -> Result<(), crate::multi::Abort>;
}

/// A host key, as an SSH key handler is given it: base64, as a
/// known-hosts file holds it, and its type.
#[derive(Clone, Copy, Debug)]
pub struct HostKey<'a> {
    pub base64: &'a [u8],
    pub kind: crate::ssh::KeyType,
}

/// How the server's key compares with the known-hosts file's
/// (`enum curl_khmatch`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyMatch {
    Ok,
    Mismatch,
    /// The file has none for the host.
    Missing,
}

/// What an SSH key handler decides of the server's key
/// (`enum curl_khstat`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyVerdict {
    /// Fine, and to be added to the known-hosts file.
    FineAddToFile,
    Fine,
    Reject,
    /// Not now: the connection is refused, as for a rejected key.
    Defer,
    /// Fine, to replace the file's (which libssh's SSH does not do: it
    /// refuses the key).
    FineReplace,
}

/// Decides on an SSH server's key, given the known-hosts file's for the
/// host if it has one, and how they compare (`CURLOPT_SSH_KEYFUNCTION`).
pub trait SshKeyHandler: Send + Sync {
    fn check(
        &self,
        cx: &mut TransferCx<'_>,
        known: Option<HostKey<'_>>,
        found: HostKey<'_>,
        matched: KeyMatch,
    ) -> KeyVerdict;
}

/// Told as each resolve of a name starts, an address or `localhost`
/// answered without a resolver included, but not one the cache answers
/// (`CURLOPT_RESOLVER_START_FUNCTION`). An abort fails the transfer
/// with AbortedByCallback.
pub trait ResolveStartHandler: Send + Sync {
    fn resolve_starts(&self, cx: &mut TransferCx<'_>) -> Result<(), crate::multi::Abort>;
}

/// A socket as a `SocketConfigurer` is given it: its number, and the
/// options it may set.
#[derive(Clone, Copy)]
pub struct SocketToSet<'a>(pub(crate) &'a dyn Socket, pub(crate) SocketPurpose);

impl SocketToSet<'_> {
    pub fn key(&self) -> SocketKey {
        self.0.key()
    }

    /// What the socket is for.
    pub fn purpose(&self) -> SocketPurpose {
        self.1
    }

    pub fn set(&self, option: SocketOption) -> io::Result<()> {
        self.0.set(option)
    }
}

/// What a socket a `SocketConfigurer` is told of is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketPurpose {
    /// One the transfer connects (`CURLSOCKTYPE_IPCXN`).
    Connect,
    /// One the server connected to the port FTP offered it, just
    /// accepted (`CURLSOCKTYPE_ACCEPT`); what is answered of it beyond an
    /// abort changes nothing.
    Accept,
}

/// What a `SocketConfigurer` made of a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Configured {
    /// The socket connects as usual.
    Ok,
    /// The application connected it already: the connect is skipped
    /// (`CURL_SOCKOPT_ALREADY_CONNECTED`).
    AlreadyConnected,
    /// The transfer fails with AbortedByCallback.
    Abort,
}

/// Closes the sockets of the connections a transfer makes, in place of
/// the system (`CURLOPT_CLOSESOCKETFUNCTION`): each is given its
/// descriptor, which it now owns. It is kept with the connection and
/// called whoever closes it, a share's cleanup too, so it is given no
/// transfer.
pub trait SocketCloser: Send + Sync {
    fn close(&self, socket: SocketKey);
}

/// Told of each TLS context a transfer's connection is made with, before
/// the library makes the session of it (`CURLOPT_SSL_CTX_FUNCTION`), to
/// set it up through the library's own API: `native` holds the context
/// alone. An error fails the transfer with its kind.
pub trait TlsContextHandler: Send + Sync {
    fn configure(&self, cx: &mut TransferCx<'_>, native: TlsNative) -> Result<(), ErrorKind>;
}

/// What kind of file a listing says an entry is (`curlfiletype`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
    Symlink,
    DeviceBlock,
    DeviceChar,
    NamedPipe,
    Socket,
    Door,
}

/// A file a wildcard download's listing names and its pattern matched
/// (`struct curl_fileinfo`): what the listing's line says of it, each
/// field the line has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileInfo<'a> {
    pub name: &'a [u8],
    pub kind: FileType,
    /// The permission bits, `rwx` for each of user, group and others
    /// with set-user-id, set-group-id and sticky above them.
    pub perm: Option<u32>,
    pub hardlinks: Option<i64>,
    pub size: Option<u64>,
    /// The fields as the line gives them.
    pub time: &'a [u8],
    pub perm_text: Option<&'a [u8]>,
    pub user: Option<&'a [u8]>,
    pub group: Option<&'a [u8]>,
    /// Where a symbolic link points.
    pub target: Option<&'a [u8]>,
}

impl FileInfo<'_> {
    /// The most bytes its texts take together, a byte after each among
    /// them: they are parts of one line of the listing, which is never
    /// longer.
    pub const MAX_TEXT: usize = 10_000;
}

/// What a wildcard download does with the file it is about to get
/// (`CURL_CHUNK_BGN_FUNC_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkBegin {
    Get,
    /// The file is passed over, and the next one got.
    Skip,
    /// The transfer fails with ChunkFailed.
    Fail,
}

/// Told of each file a wildcard download is about to get, with how many
/// are left to get, this one among them (`CURLOPT_CHUNK_BGN_FUNCTION`).
pub trait ChunkBeginHandler: Send + Sync {
    fn begin(&self, cx: &mut TransferCx<'_>, file: &FileInfo<'_>, remains: usize) -> ChunkBegin;
}

/// Told that a wildcard download is done with a file, got or passed over
/// (`CURLOPT_CHUNK_END_FUNCTION`).
pub trait ChunkEndHandler: Send + Sync {
    fn end(&self, cx: &mut TransferCx<'_>);
}

/// How a name compares with a wildcard download's pattern
/// (`CURL_FNMATCHFUNC_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Matched {
    Match,
    NoMatch,
    /// The pattern could not be compared: the name is passed over.
    Fail,
}

/// Matches each name a wildcard download's listing gives against its
/// pattern, in place of the system's `fnmatch(3)`
/// (`CURLOPT_FNMATCH_FUNCTION`). Out of memory, the listing fails as one
/// that could not be read.
pub trait FnMatchHandler: Send + Sync {
    fn matches(
        &self,
        cx: &mut TransferCx<'_>,
        pattern: &[u8],
        name: &[u8],
    ) -> Result<Matched, OutOfMemory>;
}

/// A handler as a transfer holds it: shared by every copy of the `Easy`.
pub struct Handler<T: ?Sized>(TryArc<Box<T>>);

/// Two handlers are equal if they are the same one.
impl<T: ?Sized> PartialEq for Handler<T> {
    fn eq(&self, other: &Handler<T>) -> bool {
        Handler::ptr_eq(self, other)
    }
}

impl<T: ?Sized> Eq for Handler<T> {}

impl<T: ?Sized> Handler<T> {
    /// A handler already boxed; `Handler::write` and the like box one.
    pub fn new(handler: Box<T>) -> Result<Handler<T>, OutOfMemory> {
        Ok(Handler(TryArc::try_new(handler)?))
    }

    /// Whether `a` and `b` are the same handler.
    pub fn ptr_eq(a: &Handler<T>, b: &Handler<T>) -> bool {
        TryArc::ptr_eq(&a.0, &b.0)
    }
}

impl Handler<dyn SocketCloser> {
    pub fn socket_closer(handler: impl SocketCloser + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn SocketOpener> {
    pub fn socket_opener(handler: impl SocketOpener + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn SocketConfigurer> {
    pub fn socket_configurer(
        handler: impl SocketConfigurer + 'static,
    ) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn PrereqHandler> {
    pub fn prereq(handler: impl PrereqHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn SshKeyHandler> {
    pub fn ssh_key(handler: impl SshKeyHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn ResolveStartHandler> {
    pub fn resolve_start(handler: impl ResolveStartHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn TlsContextHandler> {
    pub fn tls_context(handler: impl TlsContextHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn WriteHandler> {
    pub fn write(handler: impl WriteHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn HeaderHandler> {
    pub fn header(handler: impl HeaderHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn LentBytes> {
    pub fn lent(bytes: impl LentBytes + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(bytes)?)
    }
}

impl Handler<dyn ReadHandler> {
    pub fn read(handler: impl ReadHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn ChunkBeginHandler> {
    pub fn chunk_begin(handler: impl ChunkBeginHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn ChunkEndHandler> {
    pub fn chunk_end(handler: impl ChunkEndHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn FnMatchHandler> {
    pub fn fnmatch(handler: impl FnMatchHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn TrailerHandler> {
    pub fn trailer(handler: impl TrailerHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn Rewind> {
    pub fn rewind(handler: impl Rewind + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn ProgressHandler> {
    pub fn progress(handler: impl ProgressHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn TextSink> {
    pub fn text(handler: impl TextSink + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn DebugHandler> {
    pub fn debug(handler: impl DebugHandler + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(handler)?)
    }
}

impl Handler<dyn crate::mime::MimeSource> {
    pub fn mime(source: impl crate::mime::MimeSource + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(source)?)
    }
}

impl Handler<dyn LineSource> {
    pub fn lines(source: impl LineSource + 'static) -> Result<Self, OutOfMemory> {
        Handler::new(try_box(source)?)
    }
}

impl<T: ?Sized> Clone for Handler<T> {
    fn clone(&self) -> Handler<T> {
        Handler(self.0.clone())
    }
}

impl<T: ?Sized> Deref for Handler<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> fmt::Debug for Handler<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Handler")
    }
}
