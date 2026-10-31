//! The back and forth of the line protocols, FTP, IMAP, POP3 and SMTP
//! (`lib/pingpong.c`): a command written whole and sent in as many goes
//! as the connection takes, and the server's answer read line by line
//! until one ends a reply.
//!
//! It does no I/O and says nothing. The protocol's step reads from its
//! connection into [`Pingpong::push`], one read at a time, and takes the
//! answer out with [`Pingpong::next`]: each line as it is found, for the
//! step to trace (`CURLINFO_HEADER_IN`) and hand to the header handler as
//! C does, and the line that ends a reply with what it says. Which line
//! ends a reply is the protocol's ([`Ends`], C's `endofresp`), asked per
//! line with the protocol's state of the moment. A command is built in
//! the writer's buffer ([`Pingpong::command`]) and its first send says
//! which bytes are traced (`CURLINFO_HEADER_OUT`).

pub(crate) mod drive;
pub(crate) mod ftp;
pub(crate) mod imap;
pub(crate) mod pop3;
pub(crate) mod smtp;
#[cfg(test)]
mod tests;

/// The trace's text and the commands sent, `> ` before each, in the order
/// they went: for the line protocols' tests of what is said around a
/// command.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct Said(pub(crate) std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(test)]
impl crate::handler::DebugHandler for Said {
    fn debug(
        &self,
        _: &mut crate::multi::TransferCx<'_>,
        kind: crate::handler::DebugKind,
        data: &[u8],
    ) {
        let mut said = self.0.lock().unwrap();
        match kind {
            crate::handler::DebugKind::Text => said.extend_from_slice(data),
            crate::handler::DebugKind::HeaderOut => {
                said.extend_from_slice(b"> ");
                said.extend_from_slice(data);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
impl Said {
    /// Its lines that say a command or a change of SASL's state, the
    /// latter without the pointer C's line names.
    pub(crate) fn sasl(&self) -> Vec<String> {
        let said = String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned();
        said.lines()
            .filter_map(|l| {
                if l.starts_with("> ") {
                    Some(l.to_owned())
                } else if l.starts_with("SASL ") {
                    l.split_once(" state change from ")
                        .map(|(_, c)| format!("SASL {c}"))
                } else {
                    None
                }
            })
            .collect()
    }
}

use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::error::ErrorKind;
use crate::multi::timers::TimeLeft;
use crate::time::{Instant, TimeLimit};

/// The most either buffer holds, its zero byte included
/// (`DYN_PINGPPONG_CMD`): a command, or what is held of an answer, is at
/// most one byte less.
pub(crate) const BUFFER_MAX: usize = 64 * 1024;

/// How much one read asks the connection for (`Curl_pp_readresp`'s
/// buffer). What follows a reply in the same read is held after it
/// ([`Pingpong::after_reply`]), so a driver reads no more than this at a
/// time to hold what C holds.
pub(crate) const READ_SIZE: usize = 900;

/// How many full reads one pass makes before it lets the others run
/// (`maxloops`): reading stops at a read shorter than [`READ_SIZE`], at a
/// reply, or after this many.
pub(crate) const MAX_READS: u32 = 10;

/// How long a server has to answer a command when the transfer sets no
/// limit of its own (`PINGPONG_TIMEOUT_MS`).
pub(crate) const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// A reply's code, as its protocol reads it from the line that ends it:
/// FTP's three digits, SMTP's three or, on a line of five bytes, up to
/// five. Zero is a code C reads too, and its steps take a reply of code
/// zero for none (ftp.c's `if(result || !ftpcode)`, smtp.c's
/// `if(!smtpcode)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ReplyCode(u32);

impl ReplyCode {
    pub(crate) fn get(self) -> u32 {
        self.0
    }
}

/// The bytes read for a reply (C's `nread_resp`): every byte pushed since
/// the reply before it ended, those already read past its end included. A
/// reply found in bytes held from before is of size zero, which FTP's
/// blocking read tells apart (ftp.c:720).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) struct ReplySize(usize);

impl ReplySize {
    pub(crate) fn get(self) -> usize {
        self.0
    }
}

/// Which line of an answer ends a reply, and what the reply says: one
/// protocol, in the state it is in (C's `endofresp`). `line` is whole, its
/// LF included and a CR before it kept.
pub(crate) trait Ends {
    type Reply: Copy;

    fn ends(&self, line: &[u8]) -> Option<Self::Reply>;
}

/// What [`Pingpong::next`] found in the bytes held.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Event<'a, R> {
    /// No whole line is held: read, then push what was read.
    NeedMore,
    /// A line that does not end a reply, its LF included: to trace and
    /// deliver, after which it goes.
    Line(&'a [u8]),
    /// The line that ends a reply, its LF included: to trace and deliver,
    /// after which the protocol reads it. It stays until the next call
    /// ([`Pingpong::reply_line`]).
    Reply {
        line: &'a [u8],
        reply: R,
        size: ReplySize,
    },
}

/// Why an answer cannot be read on. Each is for good: the reader answers
/// every later call with the same error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadError {
    /// A whole line holds a zero byte (`WEIRD_SERVER_REPLY`, "NUL byte in
    /// server response line"); it was not given out.
    Nul,
    /// What is held would reach [`BUFFER_MAX`] (`CURLE_TOO_LARGE`).
    TooLarge,
    /// A read gave nothing: the server closed the connection
    /// (`RECV_ERROR`, "response reading failed (errno: %d)").
    Closed,
    OutOfMemory,
}

impl ReadError {
    pub(crate) fn kind(self) -> ErrorKind {
        match self {
            ReadError::Nul => ErrorKind::WeirdServerReply,
            ReadError::TooLarge => ErrorKind::TooLarge,
            ReadError::Closed => ErrorKind::RecvError,
            ReadError::OutOfMemory => ErrorKind::OutOfMemory,
        }
    }

    /// What C fails with, where it says something of its own: the
    /// closing's text carries the socket's errno, the step's to add.
    pub(crate) fn reason(self) -> Option<&'static str> {
        match self {
            ReadError::Nul => Some("NUL byte in server response line"),
            ReadError::TooLarge | ReadError::Closed | ReadError::OutOfMemory => None,
        }
    }
}

/// Why a command cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommandError {
    /// The command, its CRLF included, would reach [`BUFFER_MAX`]
    /// (`CURLE_TOO_LARGE`).
    TooLarge,
    OutOfMemory,
}

impl CommandError {
    pub(crate) fn kind(self) -> ErrorKind {
        match self {
            CommandError::TooLarge => ErrorKind::TooLarge,
            CommandError::OutOfMemory => ErrorKind::OutOfMemory,
        }
    }
}

impl From<OutOfMemory> for CommandError {
    fn from(OutOfMemory: OutOfMemory) -> Self {
        CommandError::OutOfMemory
    }
}

/// Which way the connection is waited on (`Curl_pp_pollset`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Wants {
    /// A command is partly sent: to write.
    Send,
    Recv,
}

/// What is left of the time a server has to answer
/// (`Curl_pp_state_timeleft_ms`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResponseTime {
    /// This much, in whole milliseconds, at least one.
    Left(Duration),
    /// None: the server is late ("server response timeout").
    Out,
}

/// Where the held bytes are as far as the reader is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scan {
    /// No whole line is held: the next read is pushed.
    Starved,
    /// Whole lines may be held: [`Pingpong::next`] looks before anything
    /// more is read.
    Unscanned,
    /// The first this many bytes are a line given out that ends no reply,
    /// which goes at the next call.
    Line(usize),
    /// The first this many bytes are the line that ended a reply, kept
    /// until the next call (C's `nfinal`); what follows them was read with
    /// it (C's `overflow`).
    Reply(usize),
    /// An error, given for every later call.
    Failed(ReadError),
}

/// Where the command in the writer's buffer is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    /// Nothing waits to be sent.
    Idle,
    /// The first this many bytes went; the rest wait (C's `sendleft`).
    Partly(usize),
}

/// One connection's back and forth (C's `struct pingpong`): the answer
/// held, the command being sent, and when the server's time to answer
/// started.
#[derive(Debug)]
pub(crate) struct Pingpong {
    recv: Vec<u8>,
    scan: Scan,
    /// Bytes pushed since the last reply ended (`nread_resp`).
    pushed: usize,
    send: Vec<u8>,
    sent: Sent,
    /// When the server's time to answer started: the last command fully
    /// sent, or the start (`pp->response`).
    response: Instant,
    /// An answer is awaited: from the start, and from each command built,
    /// until a pass of reads ends without the connection blocking it
    /// (`pending_resp`).
    pending: bool,
}

impl Pingpong {
    /// Ready to read a server's first words, its time to answer running
    /// from `now` (`Curl_pp_init`). Allocates nothing.
    pub(crate) fn new(now: Instant) -> Pingpong {
        Pingpong {
            recv: Vec::new(),
            scan: Scan::Starved,
            pushed: 0,
            send: Vec::new(),
            sent: Sent::Idle,
            response: now,
            pending: true,
        }
    }

    /// Whether an answer is still awaited (`pending_resp`): FTP's DONE
    /// reads the one to a command it sent before the transfer ended.
    pub(crate) fn pending_resp(&self) -> bool {
        self.pending
    }

    /// An answer is awaited, the one a command gave the go-ahead for
    /// (FTP's to the transfer it lets go, `ftp_initiate_transfer`).
    pub(crate) fn awaits_answer(&mut self) {
        self.pending = true;
    }

    /// A pass of reads ended neither blocked nor at its most, whether or
    /// not it found a reply: nothing more is awaited (`Curl_pp_readresp`'s
    /// end).
    pub(crate) fn reads_ended(&mut self) {
        self.pending = false;
    }

    /// Takes the bytes of one read (`Curl_pp_readresp`'s read). A read is
    /// taken only once [`next`](Self::next) has said it needs one, or
    /// after a reply nothing followed, as C reads only then; an empty read
    /// is the server closing.
    pub(crate) fn push(&mut self, read: &[u8]) -> Result<(), ReadError> {
        if let Scan::Failed(e) = self.scan {
            return Err(e);
        }
        assert!(
            !self.unscanned(),
            "a read pushed while held lines wait to be read"
        );
        if let Scan::Reply(_) = self.scan {
            // The final line goes before what is read is added to it.
            self.recv.clear();
            self.scan = Scan::Starved;
        }
        if read.is_empty() {
            return Err(self.fail(ReadError::Closed));
        }
        // dynbuf.c:82: the bytes held, those added and a zero byte.
        if self.recv.len() + read.len() + 1 > BUFFER_MAX {
            self.recv = Vec::new();
            return Err(self.fail(ReadError::TooLarge));
        }
        if self.recv.try_extend_from_slice(read).is_err() || self.recv.try_reserve(1).is_err() {
            return Err(self.fail(ReadError::OutOfMemory));
        }
        self.zero_end();
        self.pushed += read.len();
        self.scan = Scan::Unscanned;
        Ok(())
    }

    /// A zero byte just past what is held, in room each push reserves,
    /// as C's buffer keeps one (`curlx_dyn_addn`): a line handed to the
    /// application last in the buffer reads as a C string, which callers
    /// of the header function compare with `strcmp` (test 753).
    fn zero_end(&mut self) {
        if let Some(end) = self.recv.spare_capacity_mut().first_mut() {
            end.write(0);
        }
    }

    /// The next line of the answer held, and whether `ends` says it ends
    /// a reply; the line given out before goes first.
    pub(crate) fn next<E: Ends>(&mut self, ends: &E) -> Result<Event<'_, E::Reply>, ReadError> {
        match self.scan {
            Scan::Failed(e) => return Err(e),
            Scan::Line(n) | Scan::Reply(n) => {
                self.recv.drain(..n);
                self.zero_end();
            }
            Scan::Starved | Scan::Unscanned => {}
        }
        // pingpong.c:276: a line ends at its LF; a CR is part of it.
        let Some(lf) = self.recv.iter().position(|&b| b == b'\n') else {
            self.scan = Scan::Starved;
            return Ok(Event::NeedMore);
        };
        let length = lf + 1;
        // pingpong.c:282: a zero byte anywhere in it, its end included.
        if self.recv[..length].contains(&0) {
            return Err(self.fail(ReadError::Nul));
        }
        let line = &self.recv[..length];
        match ends.ends(line) {
            Some(reply) => {
                self.scan = Scan::Reply(length);
                let size = ReplySize(std::mem::take(&mut self.pushed));
                Ok(Event::Reply { line, reply, size })
            }
            None => {
                self.scan = Scan::Line(length);
                Ok(Event::Line(line))
            }
        }
    }

    /// Whether bytes are held that [`next`](Self::next) has not looked
    /// through yet (C's `overflow`, by which `Curl_pp_statemach` runs the
    /// step without waiting on the connection): what followed a reply,
    /// what is left after bytes were taken from it, or what followed a
    /// line given out. A partial line looked through is not, though
    /// [`more_data`](Self::more_data) counts it.
    pub(crate) fn unscanned(&self) -> bool {
        match self.scan {
            Scan::Unscanned | Scan::Line(_) => true,
            Scan::Reply(n) => self.recv.len() > n,
            Scan::Starved | Scan::Failed(_) => false,
        }
    }

    /// Starts the server's time to answer again at `now`, as FTP does
    /// before it reads the answer that ends a transfer (ftp.c:3604,
    /// ftp.c:3751).
    pub(crate) fn restart_response_timer(&mut self, now: Instant) {
        self.response = now;
    }

    fn fail(&mut self, e: ReadError) -> ReadError {
        self.scan = Scan::Failed(e);
        e
    }

    /// The line that ended the reply just given out, its LF included
    /// (the start of C's `recvbuf`, `nfinal` long).
    pub(crate) fn reply_line(&self) -> Option<&[u8]> {
        match self.scan {
            Scan::Reply(n) => Some(&self.recv[..n]),
            _ => None,
        }
    }

    /// What was read past the end of the reply just given out (C's
    /// `overflow` as the reply is found; [`unscanned`](Self::unscanned)
    /// says what it becomes once bytes are taken from it). A server that sends anything after its answer to
    /// `STARTTLS`, `STLS` or `AUTH TLS` is refused (`WEIRD_SERVER_REPLY`,
    /// smtp.c:1177, ftp.c:3209), as those bytes were not sent under TLS;
    /// an IMAP literal and a POP3 body begin in it.
    pub(crate) fn after_reply(&self) -> Option<&[u8]> {
        match self.scan {
            Scan::Reply(n) => Some(&self.recv[n..]),
            _ => None,
        }
    }

    /// Drops the reply's line and the first `n` bytes after it, which the
    /// protocol took as its own (an IMAP literal, imap.c:1424; a POP3
    /// body, pop3.c:1248); what is left is read as the answer goes on.
    pub(crate) fn consume_after_reply(&mut self, n: usize) {
        let Scan::Reply(line) = self.scan else {
            panic!("bytes taken after a reply when none was given out");
        };
        assert!(
            n <= self.recv.len() - line,
            "more taken after the reply than was read"
        );
        self.recv.drain(..line + n);
        self.zero_end();
        self.scan = if self.recv.is_empty() {
            Scan::Starved
        } else {
            Scan::Unscanned
        };
    }

    /// Everything held of the answer, a reply's line given out included
    /// (C's `recvbuf`, which ftp.c:470 and imap.c:1013 look at).
    pub(crate) fn held(&self) -> &[u8] {
        match self.scan {
            Scan::Failed(_) => &[],
            _ => &self.recv,
        }
    }

    /// Whether more of the answer is held than the line given out and no
    /// command waits to be sent (`Curl_pp_moredata`): a step reads on
    /// without waiting for the connection.
    pub(crate) fn more_data(&self) -> bool {
        let given = match self.scan {
            Scan::Line(n) | Scan::Reply(n) => n,
            Scan::Failed(_) => return false,
            Scan::Starved | Scan::Unscanned => 0,
        };
        self.sent == Sent::Idle && self.recv.len() > given
    }

    /// Builds a command, `prefix` and a space before it when given (an
    /// IMAP tag) and CRLF after it, from `parts` in order
    /// (`Curl_pp_vsendf`). Nothing may wait to be sent from the command
    /// before.
    pub(crate) fn command(
        &mut self,
        prefix: Option<&[u8]>,
        parts: &[&[u8]],
    ) -> Result<Unsent<'_>, CommandError> {
        assert_eq!(
            self.sent,
            Sent::Idle,
            "a command built while the one before is partly sent"
        );
        self.send.clear();
        let prefix_len = prefix.map_or(0, |p| p.len() + 1);
        let len = prefix_len + parts.iter().map(|p| p.len()).sum::<usize>() + 2;
        // dynbuf.c:82, for every piece added: the bytes and a zero byte.
        if len + 1 > BUFFER_MAX {
            self.send = Vec::new();
            return Err(CommandError::TooLarge);
        }
        self.send
            .try_reserve(len)
            .map_err(|_| CommandError::OutOfMemory)?;
        if let Some(prefix) = prefix {
            self.send.try_extend_from_slice(prefix)?;
            self.send.try_extend_from_slice(b" ")?;
        }
        for part in parts {
            self.send.try_extend_from_slice(part)?;
        }
        self.send.try_extend_from_slice(b"\r\n")?;
        self.pending = true;
        Ok(Unsent { pp: self })
    }

    /// What is left to send of a command partly sent: empty when nothing
    /// is (`Curl_pp_flushsend`'s bytes).
    pub(crate) fn unsent(&self) -> &[u8] {
        match self.sent {
            Sent::Idle => &[],
            Sent::Partly(n) => &self.send[n..],
        }
    }

    /// Whether a command is partly sent (`Curl_pp_needs_flush`).
    pub(crate) fn needs_flush(&self) -> bool {
        self.sent != Sent::Idle
    }

    /// `n` more bytes of the command partly sent went, at `now`: once the
    /// last has, the server's time to answer starts. What a flush sends is
    /// not traced (`Curl_pp_flushsend`).
    pub(crate) fn flushed(&mut self, n: usize, now: Instant) {
        let Sent::Partly(sent) = self.sent else {
            panic!("a flush with nothing to send");
        };
        assert!(sent + n <= self.send.len(), "more flushed than was left");
        self.sent_up_to(sent + n, now);
    }

    fn sent_up_to(&mut self, sent: usize, now: Instant) {
        if sent < self.send.len() {
            self.sent = Sent::Partly(sent);
        } else {
            self.sent = Sent::Idle;
            self.response = now;
        }
    }

    /// Which way the connection is waited on.
    pub(crate) fn wants(&self) -> Wants {
        match self.sent {
            Sent::Partly(_) => Wants::Send,
            Sent::Idle => Wants::Recv,
        }
    }

    /// What is left at `now` of the time the server has to answer: the
    /// transfer's `limit` for it (`CURLOPT_SERVER_RESPONSE_TIMEOUT`) or
    /// [`RESPONSE_TIMEOUT`] since the last command went, or less if the
    /// transfer's own time ends sooner (`Curl_pp_state_timeleft_ms`).
    pub(crate) fn time_left(
        &self,
        now: Instant,
        limit: Option<TimeLimit>,
        transfer: TimeLeft,
    ) -> ResponseTime {
        let ms = |d: Duration| i64::try_from(d.as_millis()).unwrap_or(i64::MAX);
        let limit = ms(limit.map_or(RESPONSE_TIMEOUT, TimeLimit::duration));
        let mut left = limit.saturating_sub(ms(now.since(self.response)));
        match transfer {
            TimeLeft::Unlimited => {}
            TimeLeft::Remaining(d) => left = left.min(ms(d)),
            TimeLeft::Expired(d) => left = left.min(-ms(d)),
        }
        match u64::try_from(left) {
            Ok(1..) => ResponseTime::Left(Duration::from_millis(left.unsigned_abs())),
            _ => ResponseTime::Out,
        }
    }
}

/// A command built and not sent yet. Its first send says what is traced;
/// dropped unsent, after a send that failed, nothing waits to be sent.
#[must_use]
#[derive(Debug)]
pub(crate) struct Unsent<'p> {
    pp: &'p mut Pingpong,
}

impl<'p> Unsent<'p> {
    /// The command, CRLF included.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.pp.send
    }

    /// The first send wrote `n` bytes at `now`, none if the connection
    /// would have blocked. Gives the bytes to trace as sent
    /// (`CURLINFO_HEADER_OUT`): those `n`, even none, as C traces what its
    /// first send wrote and nothing of a flush. The rest waits to be
    /// flushed; if all went, the server's time to answer starts.
    pub(crate) fn wrote(self, n: usize, now: Instant) -> &'p [u8] {
        let pp = self.pp;
        assert!(n <= pp.send.len(), "more written than the command holds");
        pp.sent_up_to(n, now);
        &pp.send[..n]
    }
}
