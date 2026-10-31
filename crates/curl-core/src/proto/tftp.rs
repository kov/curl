//! TFTP (`lib/tftp.c`, RFC 1350, with RFC 2347 to 2349's options): a
//! file read or written in blocks of datagrams over an unconnected UDP
//! socket, each block answered, sent again when no answer comes.
//!
//! The connect phase sets the timers and binds the socket; DO sends the
//! request and DOING the rest, as C's do. The server's address is pinned
//! by its first answer, and a datagram from another fails the transfer.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;
use std::time::Duration;

use curl_alloc::TryVec as _;
use curl_os::error::ErrorText;

use super::dict::{peer_of, renetwork};
use super::{Connect, DoPhase, DoStep, ProtoStep, Waiting};
use crate::conn::io::{Events, Remote};
use crate::conn::{ConnLease, Peer, Scheme};
use crate::deliver::{Pipeline, Reach};
use crate::error::{ErrorKind, url_error};
use crate::idn::Idn;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::multi::timers::TimeLeft;
use crate::options::{Method, TftpBlockSize};
use crate::progress;
use crate::time::Instant;
use crate::trace;
use crate::upload::{self, Readout, Upload};
use crate::url::{GetOptions, Part, Url, decode_but_zero};

/// A block's size unless the server agrees to another
/// (`TFTP_BLKSIZE_DEFAULT`).
const BLKSIZE_DEFAULT: usize = 512;

/// What a packet is, its first two bytes, and what else drives the
/// machine (`tftp_event_t`): a packet's opcode is taken for an event
/// whatever it is, as C takes it, so an opcode of 7 is a time-out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Event(u16);

impl Event {
    const INIT: Event = Event(0);
    const RRQ: Event = Event(1);
    const WRQ: Event = Event(2);
    const DATA: Event = Event(3);
    const ACK: Event = Event(4);
    const ERROR: Event = Event(5);
    const OACK: Event = Event(6);
    const TIMEOUT: Event = Event(7);
}

/// Where the exchange is (`tftp_state_t`), its number as C's trace says
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Start = 0,
    Rx = 1,
    Tx = 2,
    Fin = 3,
}

/// Why the exchange ended badly (`tftp_error_t`): the server's code, or
/// no answer in time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Server(u16),
    Timeout,
    NoResponse,
}

impl Failure {
    /// The transfer's error for it (`tftp_translate_code`).
    pub(crate) fn kind(self) -> ErrorKind {
        match self {
            Failure::Server(1) => ErrorKind::TftpNotfound,
            Failure::Server(2) => ErrorKind::TftpPerm,
            Failure::Server(3) => ErrorKind::RemoteDiskFull,
            Failure::Server(0 | 4) => ErrorKind::TftpIllegal,
            Failure::Server(5) => ErrorKind::TftpUnknownid,
            Failure::Server(6) => ErrorKind::RemoteFileExists,
            Failure::Server(7) => ErrorKind::TftpNosuchuser,
            Failure::Server(_) => ErrorKind::AbortedByCallback,
            Failure::Timeout => ErrorKind::OperationTimedout,
            Failure::NoResponse => ErrorKind::CouldntConnect,
        }
    }
}

/// The next block's number, past 65535 to 0 (`NEXT_BLOCKNUM`).
fn next_block(block: u16) -> u16 {
    block.wrapping_add(1)
}

/// The bytes up to the first zero within `len` of `buf`, or `len`
/// (`tftp_strnlen`).
fn strnlen(buf: &[u8]) -> usize {
    buf.iter().position(|&b| b == 0).unwrap_or(buf.len())
}

/// What an OACK says, read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Oack {
    /// The block size agreed, else the default.
    pub(crate) blksize: usize,
    /// The file's size, for a download.
    pub(crate) tsize: Option<u64>,
}

/// Why an OACK was refused, as C says it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OackRefused {
    Malformed,
    TooLarge,
    Zero,
    TooSmall,
    PastRequested(u64),
    /// A size of none, and what followed its digits.
    NoSize(Vec<u8>),
}

impl fmt::Display for OackRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OackRefused::Malformed => f.write_str("Malformed ACK packet, rejecting"),
            OackRefused::TooLarge => write!(
                f,
                "blksize is larger than max supported ({})",
                TftpBlockSize::MAX
            ),
            OackRefused::Zero => f.write_str("invalid blocksize value in OACK packet"),
            OackRefused::TooSmall => write!(
                f,
                "blksize is smaller than min supported ({})",
                TftpBlockSize::MIN
            ),
            OackRefused::PastRequested(n) => {
                write!(f, "server requested blksize larger than allocated ({n})")
            }
            OackRefused::NoSize(rest) => write!(
                f,
                "invalid tsize -:{}:- value in OACK packet",
                curl_alloc::Lossy(rest)
            ),
        }
    }
}

/// A decimal number at the start of `p`, at most `max`, and what follows
/// its digits (`curlx_str_number`).
fn number(p: &[u8], max: u64) -> Option<(u64, &[u8])> {
    let digits = p.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let mut n: u64 = 0;
    for &b in &p[..digits] {
        n = n.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
        if n > max {
            return None;
        }
    }
    Some((n, &p[digits..]))
}

/// Read an OACK's options, each name and value ended by a zero byte
/// (`tftp_parse_option_ack`): the block size checked against what was
/// `requested`, the file's size taken unless `uploading`. Each option is
/// said through `say`.
pub(crate) fn parse_oack(
    mut p: &[u8],
    requested: usize,
    uploading: bool,
    say: &mut dyn FnMut(fmt::Arguments<'_>),
) -> Result<Oack, OackRefused> {
    let mut oack = Oack {
        blksize: BLKSIZE_DEFAULT,
        tsize: None,
    };
    while !p.is_empty() {
        // `tftp_option_get`: the name and the value, each ended within
        // the packet.
        let name_len = strnlen(p);
        if name_len == p.len() {
            return Err(OackRefused::Malformed);
        }
        let rest = &p[name_len + 1..];
        let value_len = strnlen(rest);
        if value_len == rest.len() {
            return Err(OackRefused::Malformed);
        }
        let (option, value) = (&p[..name_len], &rest[..value_len]);
        p = &rest[value_len + 1..];
        say(format_args!(
            "got option=({}) value=({})",
            curl_alloc::Lossy(option),
            curl_alloc::Lossy(value)
        ));
        if option.eq_ignore_ascii_case(b"blksize") {
            let Some((blksize, _)) = number(value, u64::from(TftpBlockSize::MAX)) else {
                return Err(OackRefused::TooLarge);
            };
            if blksize == 0 {
                return Err(OackRefused::Zero);
            }
            if blksize < u64::from(TftpBlockSize::MIN) {
                return Err(OackRefused::TooSmall);
            }
            if blksize > requested as u64 {
                return Err(OackRefused::PastRequested(blksize));
            }
            oack.blksize = usize::try_from(blksize).expect("at most 65464");
            say(format_args!(
                "blksize parsed from OACK ({}) requested ({requested})",
                oack.blksize
            ));
        } else if option.eq_ignore_ascii_case(b"tsize")
            && !uploading
            && let Some((tsize, rest)) = number(value, i64::MAX as u64)
        {
            if tsize == 0 {
                let mut shown = Vec::new();
                shown
                    .try_extend_from_slice(rest)
                    .map_err(|_| OackRefused::Malformed)?;
                return Err(OackRefused::NoSize(shown));
            }
            say(format_args!("tsize parsed from OACK ({tsize})"));
            oack.tsize = Some(tsize);
        }
    }
    Ok(oack)
}

/// The request's first packet (`tftp_send_first`): RRQ or WRQ, the file
/// name and the mode, and unless `options` is none the size, block size
/// and time-out asked for, each as long as C's buffer of `blksize` takes
/// them.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FirstRefused {
    /// "TFTP filename too long".
    NameTooLong,
    /// "TFTP buffer too small for options".
    OptionsTooLong,
    OutOfMemory,
}

pub(crate) fn first_packet(
    out: &mut Vec<u8>,
    upload: bool,
    filename: &[u8],
    ascii: bool,
    blksize: usize,
    options: Option<(u64, usize, i64)>,
) -> Result<(), FirstRefused> {
    let oom = |_| FirstRefused::OutOfMemory;
    let mode: &[u8] = if ascii { b"netascii" } else { b"octet" };
    if filename.len() + mode.len() + 4 > blksize {
        return Err(FirstRefused::NameTooLong);
    }
    out.clear();
    let opcode = if upload { Event::WRQ } else { Event::RRQ };
    out.try_extend_from_slice(&opcode.0.to_be_bytes())
        .map_err(oom)?;
    for part in [filename, mode] {
        out.try_extend_from_slice(part).map_err(oom)?;
        out.try_push(0).map_err(oom)?;
    }
    let Some((tsize, requested, retry_time)) = options else {
        return Ok(());
    };
    let tsize = curl_alloc::try_format(format_args!("{tsize}")).map_err(oom)?;
    let requested = curl_alloc::try_format(format_args!("{requested}")).map_err(oom)?;
    let retry = curl_alloc::try_format(format_args!("{retry_time}")).map_err(oom)?;
    for option in [
        &b"tsize"[..],
        tsize.as_bytes(),
        b"blksize",
        requested.as_bytes(),
        b"timeout",
        retry.as_bytes(),
    ] {
        // `tftp_option_add`: within the default block's room.
        let at = out.len();
        if blksize <= at || option.len() + 1 > blksize - at {
            return Err(FirstRefused::OptionsTooLong);
        }
        out.try_extend_from_slice(option).map_err(oom)?;
        out.try_push(0).map_err(oom)?;
    }
    Ok(())
}

/// A TFTP transfer (`struct tftp_conn`, the request's: its connection is
/// never reused).
#[derive(Debug)]
pub(crate) struct Request {
    pipeline: Pipeline,
    peer: Peer,
    /// The URL's path, its `;mode=` cut off.
    path: Vec<u8>,
    /// The mode is netascii (`prefer_ascii`).
    ascii: bool,
    upload: bool,
    state: State,
    event: Event,
    error: Option<Failure>,
    /// The packet sent last, kept to be sent again, and the one read.
    spacket: Vec<u8>,
    rpacket: Vec<u8>,
    /// The data of the block sent last, past its four bytes of head.
    sbytes: usize,
    /// The packet read last, its length.
    rbytes: usize,
    blksize: usize,
    requested_blksize: usize,
    block: u16,
    retries: i64,
    retry_time: i64,
    retry_max: i64,
    /// When a packet was last read, or a time-out taken, in seconds of
    /// the calendar (`rx_time`).
    rx_time: i64,
    /// The server's address, pinned by its first answer.
    remote: Option<SocketAddr>,
    reader: Option<Upload>,
    /// The upload's bytes sent (`writebytecount`).
    written: u64,
    /// When DOING last looked, for its next look a second on.
    looked: Option<Instant>,
}

impl Request {
    /// A transfer of `url`: its peer, and its path with any `;mode=`
    /// taken off (`tftp_setup_connection`).
    pub(crate) fn new<H: Host>(url: &Url, cx: &mut StepCx<'_, H>) -> Result<Request, ErrorKind> {
        let peer = peer_of(url, b"tftp", cx)?;
        let encoded = GetOptions {
            url_encode: true,
            ..GetOptions::NONE
        };
        let mut path = url.get(Part::Path, encoded).map_err(url_error)?;
        let options = cx.easy().options();
        let mut ascii = options.line.ftp.ascii;
        if path.ends_with(b";mode=netascii") {
            ascii = true;
            path.truncate(path.len() - 14);
        } else if path.ends_with(b";mode=octet") {
            ascii = false;
            path.truncate(path.len() - 11);
        }
        let upload = options.method == Method::Upload;
        Ok(Request {
            pipeline: Pipeline::new(Reach::Network),
            peer,
            path,
            ascii,
            upload,
            state: State::Start,
            event: Event::INIT,
            error: None,
            spacket: Vec::new(),
            rpacket: Vec::new(),
            sbytes: 0,
            rbytes: 0,
            blksize: BLKSIZE_DEFAULT,
            requested_blksize: BLKSIZE_DEFAULT,
            block: 0,
            retries: 0,
            retry_time: 1,
            retry_max: 3,
            rx_time: 0,
            remote: None,
            reader: None,
            written: 0,
            looked: None,
        })
    }

    /// The peer it connects to.
    pub(crate) fn network(
        &self,
        url: &Url,
        scope: Option<NonZeroU32>,
        idn: Option<&dyn Idn>,
    ) -> Result<Peer, ErrorKind> {
        renetwork(&self.peer, url, scope, idn)
    }

    pub(crate) fn scheme(&self) -> Scheme {
        self.peer.scheme()
    }

    pub(crate) fn pipeline_mut(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    pub(crate) fn holds_output(&self) -> bool {
        self.pipeline.holds_output()
    }

    /// TFTP exchanges nothing once its DO is done.
    pub(crate) fn step(&mut self) -> ProtoStep {
        ProtoStep::Done
    }

    /// When DOING looks again whatever the socket says, to see whether
    /// an answer is overdue: a second after it last looked, as C's tool
    /// polls.
    pub(crate) fn due(&self) -> Option<Instant> {
        self.looked.map(|at| at.after(Duration::from_secs(1)))
    }

    /// The transfer's error, if the exchange ended badly
    /// (`tftp_done`'s `tftp_translate_code`).
    pub(crate) fn failed(&self) -> Result<(), ErrorKind> {
        self.error.map_or(Ok(()), |e| Err(e.kind()))
    }

    /// Set the retries to the time the transfer has left
    /// (`tftp_set_timeouts`).
    fn set_timeouts<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        let left_ms: i64 = match cx.time_left() {
            TimeLeft::Expired(_) => {
                return Err(trace::fail(
                    cx,
                    ErrorKind::OperationTimedout,
                    format_args!("Connection time-out"),
                ));
            }
            TimeLeft::Unlimited => 0,
            TimeLeft::Remaining(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        };
        let timeout = if left_ms > 0 && left_ms < 3_600_000 {
            (left_ms + 500) / 1000
        } else {
            15
        };
        self.retry_max = (timeout / 5).clamp(3, 50);
        self.retry_time = (timeout / self.retry_max).max(1);
        let state = self.state as i32;
        let (retry, max) = (self.retry_time, self.retry_max);
        trace::info(
            cx,
            format_args!(
                "set timeouts for state {state}; Total {left_ms}, retry {retry} maxtry {max}"
            ),
        );
        self.rx_time = cx.unix_time();
        Ok(())
    }

    /// Send `len` bytes of the packet to the server, as pinned, or the
    /// connection's peer before it answered.
    fn send<H: Host>(
        &self,
        cx: &mut StepCx<'_, H>,
        lease: &ConnLease,
        len: usize,
    ) -> Result<(), ErrorKind> {
        let to = match self.remote {
            Some(to) => to,
            None => match lease.conn().remote() {
                Some(Remote::Inet(to)) => *to,
                _ => return Err(ErrorKind::FailedInit),
            },
        };
        let Some(socket) = lease.conn().datagram_socket() else {
            return Err(ErrorKind::SendError);
        };
        // A datagram goes whole or not at all.
        match socket.send_to(&self.spacket[..len], to) {
            Ok(_) => Ok(()),
            Err(e) => {
                let why = ErrorText::of(&e);
                Err(trace::fail_with(
                    cx,
                    ErrorKind::SendError,
                    &[why.as_bytes()],
                ))
            }
        }
    }

    /// Set the packet's opcode and block.
    fn head(&mut self, event: Event, block: u16) {
        self.spacket[..2].copy_from_slice(&event.0.to_be_bytes());
        self.spacket[2..4].copy_from_slice(&block.to_be_bytes());
    }

    /// The block number of the packet read.
    fn rblock(&self) -> u16 {
        u16::from_be_bytes([self.rpacket[2], self.rpacket[3]])
    }

    /// Drive the machine with `event` (`tftp_state_machine`).
    fn machine<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        event: Event,
    ) -> Result<(), ErrorKind> {
        match self.state {
            State::Start => {
                trace::debug_info(cx, format_args!("TFTP_STATE_START"));
                self.send_first(cx, lease, event)
            }
            State::Rx => {
                trace::debug_info(cx, format_args!("TFTP_STATE_RX"));
                self.rx(cx, lease, event)
            }
            State::Tx => {
                trace::debug_info(cx, format_args!("TFTP_STATE_TX"));
                self.tx(cx, lease, event)
            }
            State::Fin => {
                trace::info(cx, format_args!("TFTP finished"));
                Ok(())
            }
        }
    }

    /// The START state's events (`tftp_send_first`).
    fn send_first<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        event: Event,
    ) -> Result<(), ErrorKind> {
        match event {
            Event::INIT | Event::TIMEOUT => {
                self.retries += 1;
                if self.retries > self.retry_max {
                    self.error = Some(Failure::NoResponse);
                    self.state = State::Fin;
                    return Ok(());
                }
                let mut size = None;
                if self.upload {
                    let reader = match self.reader.take() {
                        Some(reader) => reader,
                        None => Upload::open(cx)?,
                    };
                    size = reader.size();
                    self.reader = Some(reader);
                    if size.is_some() {
                        upload::announce_size(cx, size);
                    }
                }
                // The slash before the file's name is no part of it
                // (RFC 3617).
                let Some(name) = self.path.get(1..).filter(|n| !n.is_empty()) else {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::TftpIllegal,
                        format_args!("Missing filename"),
                    ));
                };
                let Some(filename) = decode_but_zero(name).map_err(url_error)? else {
                    return Err(ErrorKind::UrlMalformat);
                };
                let options = (!cx.easy().options().small.tftp_no_options).then(|| {
                    let tsize = if self.upload { size.unwrap_or(0) } else { 0 };
                    (tsize, self.requested_blksize, self.retry_time)
                });
                let mut packet = std::mem::take(&mut self.spacket);
                let made = first_packet(
                    &mut packet,
                    self.upload,
                    &filename,
                    self.ascii,
                    self.blksize,
                    options,
                );
                let len = packet.len();
                self.spacket = packet;
                match made {
                    Ok(()) => {}
                    Err(FirstRefused::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
                    Err(FirstRefused::NameTooLong) => {
                        return Err(trace::fail(
                            cx,
                            ErrorKind::TftpIllegal,
                            format_args!("TFTP filename too long"),
                        ));
                    }
                    Err(FirstRefused::OptionsTooLong) => {
                        return Err(trace::fail(
                            cx,
                            ErrorKind::TftpIllegal,
                            format_args!("TFTP buffer too small for options"),
                        ));
                    }
                }
                self.send(cx, lease, len)
            }
            Event::OACK => {
                if self.upload {
                    self.connect_for_tx(cx, lease, event)
                } else {
                    self.connect_for_rx(cx, lease, event)
                }
            }
            Event::ACK => {
                if !self.upload {
                    return Err(ErrorKind::TftpIllegal);
                }
                self.connect_for_tx(cx, lease, event)
            }
            Event::DATA => {
                if self.upload {
                    return Err(ErrorKind::TftpIllegal);
                }
                self.connect_for_rx(cx, lease, event)
            }
            Event::ERROR => {
                self.state = State::Fin;
                Ok(())
            }
            _ => Err(trace::fail(
                cx,
                ErrorKind::TftpIllegal,
                format_args!("tftp_send_first: internal error"),
            )),
        }
    }

    fn connect_for_tx<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        event: Event,
    ) -> Result<(), ErrorKind> {
        trace::info(cx, format_args!("Connected for transmit"));
        self.state = State::Tx;
        self.set_timeouts(cx)?;
        self.tx(cx, lease, event)
    }

    fn connect_for_rx<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        event: Event,
    ) -> Result<(), ErrorKind> {
        trace::info(cx, format_args!("Connected for receive"));
        self.state = State::Rx;
        self.set_timeouts(cx)?;
        self.rx(cx, lease, event)
    }

    /// The RX state's events (`tftp_rx`).
    fn rx<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        event: Event,
    ) -> Result<(), ErrorKind> {
        match event {
            Event::DATA => {
                let rblock = self.rblock();
                if next_block(self.block) == rblock {
                    self.retries = 0;
                } else if self.block == rblock {
                    trace::info(
                        cx,
                        format_args!("Received last DATA packet block {rblock} again."),
                    );
                } else {
                    let next = next_block(self.block);
                    trace::info(
                        cx,
                        format_args!(
                            "Received unexpected DATA packet block {rblock}, expecting block {next}"
                        ),
                    );
                    return Ok(());
                }
                self.block = rblock;
                self.head(Event::ACK, rblock);
                self.send(cx, lease, 4)?;
                self.state = if self.rbytes < self.blksize + 4 {
                    State::Fin
                } else {
                    State::Rx
                };
                self.rx_time = cx.unix_time();
                Ok(())
            }
            Event::OACK => {
                self.block = 0;
                self.retries = 0;
                self.head(Event::ACK, 0);
                self.send(cx, lease, 4)?;
                self.state = State::Rx;
                self.rx_time = cx.unix_time();
                Ok(())
            }
            Event::TIMEOUT => {
                self.retries += 1;
                let (next, retries) = (next_block(self.block), self.retries);
                trace::info(
                    cx,
                    format_args!("Timeout waiting for block {next} ACK. Retries = {retries}"),
                );
                if self.retries > self.retry_max {
                    self.error = Some(Failure::Timeout);
                    self.state = State::Fin;
                    Ok(())
                } else {
                    // The ACK sent last, again.
                    self.send(cx, lease, 4)
                }
            }
            Event::ERROR => {
                self.head(Event::ERROR, self.block);
                // A goodbye, whether it goes or not.
                let _unchecked = self.send(cx, lease, 4);
                self.state = State::Fin;
                Ok(())
            }
            _ => Err(trace::fail(
                cx,
                ErrorKind::TftpIllegal,
                format_args!("tftp_rx: internal error"),
            )),
        }
    }

    /// The TX state's events (`tftp_tx`).
    fn tx<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        event: Event,
    ) -> Result<(), ErrorKind> {
        if !self.upload {
            return Err(ErrorKind::TftpIllegal);
        }
        match event {
            Event::ACK | Event::OACK => {
                if event == Event::ACK {
                    let rblock = self.rblock();
                    // tftpd-hpa acknowledges 65535 as the block number
                    // wraps to 0.
                    if rblock != self.block && !(self.block == 0 && rblock == 65535) {
                        let block = self.block;
                        trace::info(
                            cx,
                            format_args!("Received ACK for block {rblock}, expecting {block}"),
                        );
                        self.retries += 1;
                        if self.retries > self.retry_max {
                            return Err(trace::fail(
                                cx,
                                ErrorKind::SendError,
                                format_args!("tftp_tx: giving up waiting for block {block} ack"),
                            ));
                        }
                        return self.send(cx, lease, 4 + self.sbytes);
                    }
                    self.rx_time = cx.unix_time();
                    self.block = self.block.wrapping_add(1);
                } else {
                    self.block = 1;
                }
                self.retries = 0;
                self.head(Event::DATA, self.block);
                if self.block > 1 && self.sbytes < self.blksize {
                    self.state = State::Fin;
                    return Ok(());
                }
                self.fill(cx)?;
                self.send(cx, lease, 4 + self.sbytes)?;
                self.written += self.sbytes as u64;
                cx.report_mut().sizes_mut().upload += self.sbytes as u64;
                cx.rate_drain(crate::progress::rate::Way::Send, self.sbytes);
                Ok(())
            }
            Event::TIMEOUT => {
                self.retries += 1;
                let (next, retries) = (next_block(self.block), self.retries);
                trace::info(
                    cx,
                    format_args!("Timeout waiting for block {next} ACK. Retries = {retries}"),
                );
                if self.retries > self.retry_max {
                    self.error = Some(Failure::Timeout);
                    self.state = State::Fin;
                    return Ok(());
                }
                self.send(cx, lease, 4 + self.sbytes)?;
                // Sent again: the count stays where it was.
                cx.report_mut().sizes_mut().upload = self.written;
                Ok(())
            }
            Event::ERROR => {
                self.head(Event::ERROR, self.block);
                // A goodbye, whether it goes or not.
                let _unchecked = self.send(cx, lease, 4);
                self.state = State::Fin;
                Ok(())
            }
            Event(n) => {
                trace::fail(
                    cx,
                    ErrorKind::TftpIllegal,
                    format_args!("tftp_tx: internal error, event: {n}"),
                );
                Ok(())
            }
        }
    }

    /// The next block's data, read until the block is full or the upload
    /// gives no more: a block shorter than the block size ends it.
    fn fill<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        let blksize = self.blksize;
        self.spacket.truncate(4);
        self.spacket
            .try_resize(4 + blksize, 0)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        self.sbytes = 0;
        let mut reader = self.reader.take().expect("an upload opened its reader");
        let read = loop {
            let room = blksize - self.sbytes;
            let at = 4 + self.sbytes;
            let got = reader.read(cx, &mut self.spacket[at..at + room], false);
            upload::client_read(cx, room, &got);
            match got {
                Ok(Readout { n, .. }) => {
                    self.sbytes += n;
                    if self.sbytes >= blksize || n == 0 {
                        break Ok(());
                    }
                }
                Err(e) => break Err(e),
            }
        };
        self.reader = Some(reader);
        read
    }

    /// Read the packet waiting, if one does (`tftp_receive_packet`):
    /// whether one was.
    fn receive<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        let Some(socket) = lease.conn().datagram_socket() else {
            return Err(ErrorKind::RecvError);
        };
        let room = self.blksize + 4;
        self.rpacket
            .try_resize(room, 0)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let got = socket.recv_from(&mut self.rpacket[..room]);
        let (n, from) = match got {
            Ok(None) => return Ok(false),
            Ok(Some((n, from))) => (n, Some(from)),
            // A failed read is too short a packet, as C reads it.
            Err(_) => (0, None),
        };
        if let Some(from) = from {
            match self.remote {
                Some(pinned) if pinned != from => {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::RecvError,
                        format_args!("Data received from another address"),
                    ));
                }
                Some(_) => {}
                None => self.remote = Some(from),
            }
        }
        self.rbytes = n;
        if n < 4 {
            trace::fail(
                cx,
                ErrorKind::RecvError,
                format_args!("Received too short packet"),
            );
            // No time-out, but taken as one.
            self.event = Event::TIMEOUT;
            return Ok(true);
        }
        self.event = Event(u16::from_be_bytes([self.rpacket[0], self.rpacket[1]]));
        match self.event {
            Event::DATA => {
                if self.upload {
                    return Err(ErrorKind::TftpIllegal);
                }
                // Neither an empty block nor one sent again goes to the
                // application.
                if n > 4 && next_block(self.block) == self.rblock() {
                    let delivered = self.pipeline.body(cx, &self.rpacket[4..n]);
                    if let Err(e) = delivered {
                        self.machine(cx, lease, Event::ERROR)?;
                        return Err(e);
                    }
                }
            }
            Event::ERROR => {
                self.error = Some(Failure::Server(self.rblock()));
                let text = &self.rpacket[4..n];
                let len = strnlen(text);
                if len < text.len() {
                    trace::info_with(cx, &[b"TFTP error: ", &text[..len]]);
                }
            }
            Event::ACK => {}
            Event::OACK => {
                let uploading = self.upload;
                let requested = self.requested_blksize;
                let packet = &self.rpacket[2..n];
                let mut said = Vec::new();
                let parsed = parse_oack(packet, requested, uploading, &mut |args| {
                    // Said once the packet is let go.
                    if let Ok(line) = curl_alloc::try_format(args) {
                        let _kept = said.try_push(line);
                    }
                });
                for line in &said {
                    trace::info(cx, format_args!("{line}"));
                }
                match parsed {
                    Ok(oack) => {
                        self.blksize = oack.blksize;
                        if let Some(tsize) = oack.tsize {
                            self.pipeline.announce_size(cx, Some(tsize));
                        }
                    }
                    Err(refused) => {
                        return Err(trace::fail(
                            cx,
                            ErrorKind::TftpIllegal,
                            format_args!("{refused}"),
                        ));
                    }
                }
            }
            _ => {
                trace::fail(
                    cx,
                    ErrorKind::TftpIllegal,
                    format_args!("Internal error: Unexpected packet"),
                );
            }
        }
        if let Err(e) = progress::update(cx, false) {
            self.machine(cx, lease, Event::ERROR)?;
            return Err(e);
        }
        Ok(true)
    }

    /// A look at the time and the socket, the machine driven by what is
    /// found (`tftp_multi_statemach`): whether the exchange is over.
    fn look<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        self.looked = Some(cx.now());
        // `tftp_state_timeout`.
        if let TimeLeft::Expired(_) = cx.time_left() {
            self.error = Some(Failure::Timeout);
            self.state = State::Fin;
            return Err(trace::fail(
                cx,
                ErrorKind::OperationTimedout,
                format_args!("TFTP response timeout"),
            ));
        }
        let now = cx.unix_time();
        if now > self.rx_time + self.retry_time {
            // Even though nothing came.
            self.rx_time = now;
            self.machine(cx, lease, Event::TIMEOUT)?;
        } else if self.receive(cx, lease)? {
            let event = self.event;
            self.machine(cx, lease, event)?;
        } else {
            return Ok(false);
        }
        Ok(self.state == State::Fin)
    }

    /// Bind the socket to any address of the peer's family, unless the
    /// transfer bound it already (`tftp_connect`).
    fn bind<H: Host>(&self, cx: &mut StepCx<'_, H>, lease: &ConnLease) -> Result<(), ErrorKind> {
        if cx.easy().options().sockets.local.binds() {
            return Ok(());
        }
        let any = match lease.conn().remote() {
            Some(Remote::Inet(SocketAddr::V6(_))) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let Some(socket) = lease.conn().datagram_socket() else {
            return Ok(());
        };
        if let Err(e) = socket.bind(SocketAddr::new(any, 0)) {
            let why = ErrorText::of(&e);
            return Err(trace::fail_with(
                cx,
                ErrorKind::CouldntConnect,
                &[b"bind() failed; ", why.as_bytes()],
            ));
        }
        Ok(())
    }
}

impl super::Phases for Request {
    /// Size the packets, set the timers and bind the socket
    /// (`tftp_connect`).
    fn connect<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<Connect, ErrorKind> {
        let blksize = cx
            .easy()
            .options()
            .small
            .tftp_blksize
            .map_or(BLKSIZE_DEFAULT, |b| usize::from(b.get()));
        let room = blksize.max(BLKSIZE_DEFAULT) + 4;
        let oom = |_| ErrorKind::OutOfMemory;
        self.rpacket.try_reserve(room).map_err(oom)?;
        self.spacket.try_reserve(room).map_err(oom)?;
        self.spacket
            .try_resize(4, 0)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        // A connection of UDP has little to gain from being kept.
        lease.get().mark_close();
        self.state = State::Start;
        self.error = None;
        self.blksize = BLKSIZE_DEFAULT;
        self.requested_blksize = blksize;
        self.set_timeouts(cx)?;
        self.bind(cx, lease)?;
        Ok(Connect::Done)
    }

    /// Send the request in DO, and read and answer in DOING
    /// (`tftp_do`, `tftp_doing`).
    fn make<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        asked: DoPhase,
    ) -> Result<DoStep, ErrorKind> {
        if asked == DoPhase::Do {
            self.machine(cx, lease, Event::INIT)?;
            if self.state == State::Fin {
                self.failed()?;
                return Ok(DoStep::Did);
            }
            let done = self.look(cx, lease)?;
            if done {
                trace::debug_info(cx, format_args!("DO phase is complete"));
                self.failed()?;
                return Ok(DoStep::Did);
            }
            self.failed()?;
            return Ok(DoStep::Doing);
        }
        if self.look(cx, lease)? {
            trace::debug_info(cx, format_args!("DO phase is complete"));
            return Ok(DoStep::Did);
        }
        // The multi does not check the speed in DOING; TFTP does.
        progress::check(cx, false)?;
        Ok(DoStep::Doing)
    }

    /// Its socket, for the server's packets.
    fn waits(&self, phase: Waiting) -> Events {
        match phase {
            Waiting::Doing => Events::IN,
            _ => phase.c_default(),
        }
    }
}

#[cfg(test)]
mod tests;
