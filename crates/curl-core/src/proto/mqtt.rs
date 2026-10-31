//! MQTT (`lib/mqtt.c`, MQTT 3.1.1) and, over TLS, mqtts: a connection of
//! its own for each transfer, which says CONNECT, then SUBSCRIBEs to the
//! URL's topic and delivers each PUBLISH's payload as the body until the
//! server disconnects, or, for a POST, PUBLISHes the post's bytes to it
//! and DISCONNECTs. All of it happens in DOING, as C's does.

use std::num::NonZeroU32;

use curl_alloc::TryVec as _;

use super::dict::{peer_of, renetwork};
use super::raw::{Got, xfer_recv, xfer_send};
use super::{Connect, DoPhase, DoStep, ProtoStep, Waiting};
use crate::auth::creds::{CredentialGate, Credentials, Takes};
use crate::conn::io::Events;
use crate::conn::{ConnLease, Peer, Scheme};
use crate::deliver::{Pipeline, Reach};
use crate::error::{ErrorKind, url_error};
use crate::handler::DebugKind;
use crate::idn::Idn;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::options::{Method, UploadSource};
use crate::time::Instant;
use crate::trace;
use crate::url::{GetOptions, Part, Url, decode_but_control};

const MSG_CONNECT: u8 = 0x10;
const MSG_PUBLISH: u8 = 0x30;
const MSG_SUBSCRIBE: u8 = 0x82;
const MSG_SUBACK: u8 = 0x90;
const MSG_DISCONNECT: u8 = 0xe0;
const MSG_PINGRESP: u8 = 0xd0;

const CONNACK_LEN: usize = 2;
const SUBACK_LEN: usize = 3;
/// `curl` and eight random letters and digits.
const CLIENT_ID_LEN: usize = 12;
/// The most a packet's remaining length may say (`MAX_MQTT_MESSAGE_SIZE`).
const MAX_MESSAGE: usize = 0xFFF_FFFF;
/// The most of a PUBLISH read at once.
const READ_MAX: usize = 4 * 1024;

/// Where the exchange is (`enum mqttstate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    First,
    RemainingLength,
    Connack,
    Suback,
    SubackComing,
    PubWait,
    PubRemain,
    PostDrain,
    DisconnectDrain,
    /// None to go to (`MQTT_NOSTATE`).
    Unset,
}

impl State {
    /// C's number for it, as `mqtt_doing` says it.
    fn number(self) -> u8 {
        self as u8
    }

    /// Its name in C's debug build.
    fn name(self) -> &'static str {
        match self {
            State::First => "MQTT_FIRST",
            State::RemainingLength => "MQTT_REMAINING_LENGTH",
            State::Connack => "MQTT_CONNACK",
            State::Suback => "MQTT_SUBACK",
            State::SubackComing => "MQTT_SUBACK_COMING",
            State::PubWait => "MQTT_PUBWAIT",
            State::PubRemain => "MQTT_PUB_REMAIN",
            State::PostDrain => "MQTT_POST_DRAIN",
            State::DisconnectDrain => "MQTT_DISCONNECT_DRAIN",
            State::Unset => "NOT A STATE",
        }
    }
}

/// An MQTT transfer, and what C keeps of it on its connection, which no
/// other transfer reuses (`struct MQTT`, `struct mqtt_conn`).
#[derive(Debug)]
pub(crate) struct Request {
    pipeline: Pipeline,
    peer: Peer,
    /// The URL's path, as it is encoded (`state.up.path`).
    path: Vec<u8>,
    /// The transfer's credentials, until CONNECT has sent them.
    credentials: Option<Credentials>,
    state: State,
    /// Where to go once a packet's remaining length is read.
    next: State,
    packet_id: u32,
    /// What of a packet the connection did not take yet.
    unsent: Vec<u8>,
    /// What has been read of a packet's fixed part.
    received: Vec<u8>,
    /// Bytes counted: of the length being read, or of a PUBLISH's payload
    /// still to come.
    npacket: usize,
    remaining_length: usize,
    /// The remaining length's bytes as they come.
    length_bytes: [u8; 4],
    /// When anything was last sent or received.
    last_time: Instant,
    first_byte: u8,
    /// A PINGREQ waits for its answer.
    ping_sent: bool,
}

/// A remaining length in MQTT's variable-length encoding, at most four
/// bytes: those bytes, and how many there are (`mqtt_encode_len`).
pub(crate) fn encode_len(mut len: usize) -> ([u8; 4], usize) {
    let mut out = [0u8; 4];
    let mut i = 0;
    while len > 0 && i < 4 {
        let mut encoded = (len % 0x80) as u8;
        len /= 0x80;
        if len > 0 {
            encoded |= 0x80;
        }
        out[i] = encoded;
        i += 1;
    }
    (out, i)
}

/// The remaining length `bytes` encode, or none if they say more than
/// four bytes do or end in the middle (`mqtt_decode_len`).
pub(crate) fn decode_len(bytes: &[u8]) -> Option<usize> {
    let mut len = 0usize;
    let mut mult = 1usize;
    let mut encoded = 0x80u8;
    let mut i = 0;
    while i < bytes.len() && encoded & 0x80 != 0 {
        if i == 4 {
            return None;
        }
        encoded = bytes[i];
        len += usize::from(encoded & 0x7f) * mult;
        mult *= 128;
        i += 1;
    }
    if encoded & 0x80 != 0 {
        return None;
    }
    Some(len)
}

/// Why a CONNECT packet could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectRefused {
    OutOfMemory,
    /// Larger than a packet may be.
    TooLarge,
    UserTooLong(usize),
    PasswordTooLong(usize),
}

/// The CONNECT packet for `client_id`, `user` and `password`, either
/// empty if not given (`mqtt_connect`).
pub(crate) fn connect_packet(
    client_id: &[u8; CLIENT_ID_LEN],
    user: &[u8],
    password: &[u8],
) -> Result<Vec<u8>, ConnectRefused> {
    let (ulen, plen) = (user.len(), password.len());
    let packet_len = connect_len(ulen, plen);
    if packet_len > MAX_MESSAGE {
        return Err(ConnectRefused::TooLarge);
    }
    let (remain, remain_len) = encode_len(connect_payload(ulen, plen) + 10);
    if ulen > 0xffff {
        return Err(ConnectRefused::UserTooLong(ulen));
    }
    if plen > 0xffff {
        return Err(ConnectRefused::PasswordTooLong(plen));
    }
    let mut flags = 0x02u8; // CleanSession
    if ulen > 0 {
        flags |= 0x80;
    }
    if plen > 0 {
        flags |= 0x40;
    }
    let mut packet = Vec::new();
    packet
        .try_reserve_exact(packet_len)
        .map_err(|_| ConnectRefused::OutOfMemory)?;
    // Within the room reserved: none of these allocate.
    let mut put = |bytes: &[u8]| packet.try_extend_from_slice(bytes);
    let oom = |_| ConnectRefused::OutOfMemory;
    put(&[MSG_CONNECT]).map_err(oom)?;
    put(&remain[..remain_len]).map_err(oom)?;
    // The protocol's name and level, the flags and a keep-alive of 60
    // seconds.
    put(&[0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, flags, 0x00, 0x3c]).map_err(oom)?;
    put(&[0x00, CLIENT_ID_LEN as u8]).map_err(oom)?;
    put(client_id).map_err(oom)?;
    if ulen > 0 {
        put(&(ulen as u16).to_be_bytes()).map_err(oom)?;
        put(user).map_err(oom)?;
    }
    if plen > 0 {
        put(&(plen as u16).to_be_bytes()).map_err(oom)?;
        put(password).map_err(oom)?;
    }
    Ok(packet)
}

/// The length of a CONNECT's payload, for a user and a password of these
/// lengths.
fn connect_payload(ulen: usize, plen: usize) -> usize {
    ulen + plen + CLIENT_ID_LEN + 2 + if ulen > 0 { 2 } else { 0 } + if plen > 0 { 2 } else { 0 }
}

/// The length of the CONNECT packet for a user and a password of these
/// lengths: its fixed header, its variable header of 10 and its payload.
fn connect_len(ulen: usize, plen: usize) -> usize {
    let payload = connect_payload(ulen, plen);
    payload + 10 + encode_len(payload + 10).1 + 1
}

/// The SUBSCRIBE packet for `topic` as packet `id`, at QoS 0.
pub(crate) fn subscribe_packet(topic: &[u8], id: u32) -> Result<Vec<u8>, ErrorKind> {
    let len = topic.len() + 5;
    let (encoded, n) = encode_len(len);
    let mut packet = Vec::new();
    packet
        .try_reserve_exact(len + n + 1)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    let oom = |_| ErrorKind::OutOfMemory;
    packet.try_push(MSG_SUBSCRIBE).map_err(oom)?;
    packet.try_extend_from_slice(&encoded[..n]).map_err(oom)?;
    packet
        .try_extend_from_slice(&[(id >> 8) as u8, id as u8])
        .map_err(oom)?;
    packet
        .try_extend_from_slice(&[(topic.len() >> 8) as u8, topic.len() as u8])
        .map_err(oom)?;
    packet.try_extend_from_slice(topic).map_err(oom)?;
    packet.try_push(0).map_err(oom)?;
    Ok(packet)
}

/// The PUBLISH packet of `payload` to `topic`, at QoS 0.
pub(crate) fn publish_packet(topic: &[u8], payload: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let remaining = payload
        .len()
        .checked_add(2 + topic.len())
        .ok_or(ErrorKind::TooLarge)?;
    let (encoded, n) = encode_len(remaining);
    if remaining > MAX_MESSAGE - n - 1 {
        return Err(ErrorKind::TooLarge);
    }
    let mut packet = Vec::new();
    packet
        .try_reserve_exact(remaining + 1 + n)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    let oom = |_| ErrorKind::OutOfMemory;
    packet.try_push(MSG_PUBLISH).map_err(oom)?;
    packet.try_extend_from_slice(&encoded[..n]).map_err(oom)?;
    packet
        .try_extend_from_slice(&[(topic.len() >> 8) as u8, topic.len() as u8])
        .map_err(oom)?;
    packet.try_extend_from_slice(topic).map_err(oom)?;
    packet.try_extend_from_slice(payload).map_err(oom)?;
    Ok(packet)
}

impl Request {
    /// A transfer of `url`, `mqtts` if `secured`: its peer, its path, and
    /// the credentials its URL and the application give, a `.netrc`'s if
    /// asked for (`mqtt_setup_conn`).
    pub(crate) fn new<H: Host>(
        url: &Url,
        secured: bool,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Request, ErrorKind> {
        let name: &[u8] = if secured { b"mqtts" } else { b"mqtt" };
        let peer = peer_of(url, name, cx)?;
        let takes = Takes::of(Some(peer.scheme()));
        let credentials =
            super::request_credentials(cx, CredentialGate::FIRST.trusted(), url, takes)?;
        let credentials = super::with_netrc(credentials, peer.name(), takes, cx)?;
        let encoded = GetOptions {
            url_encode: true,
            ..GetOptions::NONE
        };
        let path = url.get(Part::Path, encoded).map_err(url_error)?;
        Ok(Request {
            pipeline: Pipeline::new(Reach::Network),
            peer,
            path,
            credentials,
            state: State::First,
            next: State::First,
            packet_id: 0,
            unsent: Vec::new(),
            received: Vec::new(),
            npacket: 0,
            remaining_length: 0,
            length_bytes: [0; 4],
            last_time: cx.now(),
            first_byte: 0,
            ping_sent: false,
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

    /// It is over TLS from the start: its scheme is `mqtts`.
    pub(crate) fn secured(&self) -> bool {
        self.peer.scheme().over_tls()
    }

    pub(crate) fn pipeline_mut(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    pub(crate) fn holds_output(&self) -> bool {
        self.pipeline.holds_output()
    }

    /// MQTT exchanges nothing once its DOING is done.
    pub(crate) fn step(&mut self) -> ProtoStep {
        ProtoStep::Done
    }

    /// Go to `state`, and from `First` on to `next` (`mqstate`), said in
    /// the debug build's trace.
    fn go<H: Host>(&mut self, cx: &mut StepCx<'_, H>, state: State, next: State) {
        let shown = if state == State::First {
            next.name()
        } else {
            ""
        };
        trace::debug_info(
            cx,
            format_args!(
                "{} (from {}) (next is {shown})",
                state.name(),
                self.state.name()
            ),
        );
        self.state = state;
        if state == State::First {
            self.next = next;
        }
    }

    /// Send `packet`, keeping what the connection does not take for
    /// later; what went traced as header bytes (`mqtt_send`).
    fn send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        packet: &[u8],
    ) -> Result<(), ErrorKind> {
        assert!(self.unsent.is_empty(), "a packet waits to be sent");
        let n = xfer_send(cx, lease, packet)?;
        self.last_time = cx.now();
        trace::bytes(cx, DebugKind::HeaderOut, &packet[..n]);
        self.unsent
            .try_extend_from_slice(&packet[n..])
            .map_err(|_| ErrorKind::OutOfMemory)
    }

    /// Send what is left of a packet (`mqtt_flush`).
    fn flush<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        if self.unsent.is_empty() {
            return Ok(());
        }
        let n = xfer_send(cx, lease, &self.unsent)?;
        self.last_time = cx.now();
        trace::bytes(cx, DebugKind::HeaderOut, &self.unsent[..n]);
        self.unsent.drain(..n);
        Ok(())
    }

    /// Read until `n` bytes are held, as many as the connection has now:
    /// whether they are (`mqtt_recv_atleast`). The connection's end is a
    /// failed read.
    fn recv_at_least<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        n: usize,
    ) -> Result<bool, ErrorKind> {
        let held = self.received.len();
        if held < n {
            let mut buf = [0u8; 1024];
            let want = n - held;
            assert!(want < buf.len(), "a fixed part fits the buffer");
            match xfer_recv(cx, lease, &mut buf[..want])? {
                Got::Again => return Ok(false),
                Got::Eof => return Err(ErrorKind::RecvError),
                // Less than the buffer, by the assertion above: far
                // within C's `DYN_MQTT_RECV`.
                Got::Data(got) => {
                    self.received
                        .try_extend_from_slice(&buf[..got])
                        .map_err(|_| ErrorKind::OutOfMemory)?;
                }
            }
        }
        Ok(self.received.len() >= n)
    }

    /// Take the first `n` bytes held (`mqtt_recv_consume`).
    fn consume(&mut self, n: usize) {
        let n = n.min(self.received.len());
        self.received.drain(..n);
    }

    /// Check the CONNACK's answer: whether it was all there
    /// (`mqtt_verify_connack`).
    fn verify_connack<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        if self.remaining_length != 2 {
            return Err(trace::fail(
                cx,
                ErrorKind::WeirdServerReply,
                format_args!(
                    "CONNACK expected Remaining Length 2, got {}",
                    self.remaining_length
                ),
            ));
        }
        if !self.recv_at_least(cx, lease, CONNACK_LEN)? {
            return Ok(false);
        }
        let ack = [self.received[0], self.received[1]];
        trace::bytes(cx, DebugKind::HeaderIn, &ack);
        if ack != [0, 0] {
            self.received.clear();
            return Err(trace::fail(
                cx,
                ErrorKind::WeirdServerReply,
                format_args!("Expected 0000 but got {:02x}{:02x}", ack[0], ack[1]),
            ));
        }
        self.consume(CONNACK_LEN);
        Ok(true)
    }

    /// The topic, the URL's path past its slash decoded
    /// (`mqtt_get_topic`).
    fn topic<H: Host>(&self, cx: &mut StepCx<'_, H>) -> Result<Vec<u8>, ErrorKind> {
        if self.path.len() <= 1 {
            return Err(trace::fail(
                cx,
                ErrorKind::UrlMalformat,
                format_args!("No MQTT topic found. Forgot to URL encode it?"),
            ));
        }
        let topic = decode_but_control(&self.path[1..])
            .map_err(url_error)?
            .ok_or(ErrorKind::UrlMalformat)?;
        if topic.len() > 0xffff {
            return Err(trace::fail(
                cx,
                ErrorKind::UrlMalformat,
                format_args!("Too long MQTT topic"),
            ));
        }
        Ok(topic)
    }

    /// Say CONNECT, the credentials in it then forgotten
    /// (`mqtt_connect`).
    fn connect_send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let credentials = self.credentials.take();
        let (user, password) = match &credentials {
            Some(c) => (c.user(), c.secret().password()),
            None => (&[][..], &[][..]),
        };
        if connect_len(user.len(), password.len()) > MAX_MESSAGE {
            return Err(ErrorKind::WeirdServerReply);
        }
        let mut id = *b"curl\0\0\0\0\0\0\0\0";
        client_id(cx, &mut id[4..])?;
        trace::info_with(cx, &[b"Using client id '", &id, b"'"]);
        let packet = match connect_packet(&id, user, password) {
            Ok(packet) => packet,
            Err(ConnectRefused::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
            Err(ConnectRefused::TooLarge) => return Err(ErrorKind::WeirdServerReply),
            Err(ConnectRefused::UserTooLong(n)) => {
                return Err(trace::fail(
                    cx,
                    ErrorKind::WeirdServerReply,
                    format_args!("Username too long: [{n}]"),
                ));
            }
            Err(ConnectRefused::PasswordTooLong(n)) => {
                return Err(trace::fail(
                    cx,
                    ErrorKind::WeirdServerReply,
                    format_args!("Password too long: [{n}]"),
                ));
            }
        };
        let sent = self.send(cx, lease, &packet);
        // The packet held the password.
        let mut packet = packet;
        packet.fill(0);
        sent
    }

    /// SUBSCRIBE to the topic, as the next packet (`mqtt_subscribe`).
    fn subscribe<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let topic = self.topic(cx)?;
        self.packet_id = self.packet_id.wrapping_add(1);
        let packet = subscribe_packet(&topic, self.packet_id)?;
        self.send(cx, lease, &packet)
    }

    /// Check a SUBACK, its type already read: whether it was all there
    /// (`mqtt_verify_suback`).
    fn verify_suback<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        if self.remaining_length != 3 {
            return Err(trace::fail(
                cx,
                ErrorKind::WeirdServerReply,
                format_args!(
                    "SUBACK expected Remaining Length 3, got {}",
                    self.remaining_length
                ),
            ));
        }
        if !self.recv_at_least(cx, lease, SUBACK_LEN)? {
            return Ok(false);
        }
        let ack = [self.received[0], self.received[1], self.received[2]];
        trace::bytes(cx, DebugKind::HeaderIn, &ack);
        let id = self.packet_id;
        if ack != [(id >> 8) as u8, id as u8, 0] {
            self.received.clear();
            return Err(ErrorKind::WeirdServerReply);
        }
        self.consume(SUBACK_LEN);
        Ok(true)
    }

    /// PUBLISH the post's bytes to the topic (`mqtt_publish`).
    fn publish<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let payload = match &cx.easy().options().upload {
            UploadSource::Bytes(bytes) => {
                let mut copy = Vec::new();
                copy.try_extend_from_slice(bytes)
                    .map_err(|_| ErrorKind::OutOfMemory)?;
                copy
            }
            UploadSource::Lent(lent) => {
                let size = lent.size();
                let mut copy = Vec::new();
                let room = usize::try_from(size).map_err(|_| ErrorKind::BadFunctionArgument)?;
                copy.try_reserve_exact(room)
                    .map_err(|_| ErrorKind::OutOfMemory)?;
                let mut piece = [0u8; 4096];
                while (copy.len() as u64) < size {
                    let n = lent.copy_at(copy.len() as u64, &mut piece);
                    if n == 0 {
                        break;
                    }
                    copy.try_extend_from_slice(&piece[..n])
                        .map_err(|_| ErrorKind::OutOfMemory)?;
                }
                copy
            }
            _ => {
                trace::debug_info(
                    cx,
                    format_args!("mqtt_publish without payload, return bad arg"),
                );
                return Err(ErrorKind::BadFunctionArgument);
            }
        };
        let topic = self.topic(cx)?;
        let packet = publish_packet(&topic, &payload)?;
        self.send(cx, lease, &packet)
    }

    /// Read on a PUBLISH, or what comes after a SUBSCRIBE: whether the
    /// server disconnected (`mqtt_read_publish`).
    fn read_publish<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        if matches!(self.state, State::Suback | State::PubWait) {
            match self.first_byte & 0xf0 {
                MSG_PUBLISH => self.go(cx, State::PubRemain, State::Unset),
                MSG_SUBACK => {
                    self.go(cx, State::SubackComing, State::Unset);
                }
                MSG_DISCONNECT => {
                    trace::info(cx, format_args!("Got DISCONNECT"));
                    return Ok(true);
                }
                _ => return Err(ErrorKind::WeirdServerReply),
            }
            if self.state == State::PubRemain {
                let remaining = self.remaining_length;
                trace::info(cx, format_args!("Remaining length: {remaining} bytes"));
                let max = cx.easy().options().flow.max_filesize;
                if max.is_some_and(|max| remaining as u64 > max.get()) {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::FilesizeExceeded,
                        format_args!("Maximum file size exceeded"),
                    ));
                }
                self.pipeline.announce_size(cx, Some(remaining as u64));
                self.npacket = remaining;
            }
        }
        match self.state {
            State::SubackComing => {
                if self.verify_suback(cx, lease)? {
                    self.go(cx, State::First, State::PubWait);
                }
                Ok(false)
            }
            State::PubRemain => {
                let mut buf = [0u8; READ_MAX];
                let rest = self.npacket.min(buf.len());
                let n = match xfer_recv(cx, lease, &mut buf[..rest])? {
                    Got::Again => {
                        trace::info(cx, format_args!("EEEE AAAAGAIN"));
                        return Ok(false);
                    }
                    Got::Eof => {
                        trace::info(cx, format_args!("server disconnected"));
                        return Err(ErrorKind::PartialFile);
                    }
                    Got::Data(n) => n,
                };
                self.last_time = cx.now();
                self.pipeline.body(cx, &buf[..n])?;
                self.npacket -= n;
                if self.npacket == 0 {
                    self.go(cx, State::First, State::PubWait);
                }
                Ok(false)
            }
            _ => unreachable!("only a PUBLISH or SUBACK is read on"),
        }
    }

    /// Send a PINGREQ if nothing went or came for the upkeep interval
    /// (`mqtt_ping`).
    fn ping<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<(), ErrorKind> {
        let interval = cx.easy().options().limits.reuse.upkeep.0;
        if self.state != State::First || self.ping_sent || interval.is_zero() {
            return Ok(());
        }
        // C counts in whole milliseconds.
        let idle = cx.now().since(self.last_time).as_millis();
        if idle > interval.as_millis() {
            let sent = self.send(cx, lease, &[0xc0, 0x00]);
            if sent.is_ok() {
                self.ping_sent = true;
            }
            trace::info(cx, format_args!("mqtt_ping: sent ping request."));
            sent?;
        }
        Ok(())
    }

    /// A step of the exchange: whether it is over (`mqtt_doing`).
    fn doing<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        if !self.unsent.is_empty() {
            self.flush(cx, lease)?;
            if !self.unsent.is_empty() {
                return Ok(false);
            }
        }
        self.ping(cx, lease)?;
        if !self.unsent.is_empty() {
            return Ok(false);
        }
        let state = self.state.number();
        trace::info(cx, format_args!("mqtt_doing: state [{state}]"));
        match self.state {
            State::First => {
                let mut byte = [0u8; 1];
                match xfer_recv(cx, lease, &mut byte)? {
                    Got::Again => return Ok(false),
                    Got::Eof => {
                        return Err(trace::fail(
                            cx,
                            ErrorKind::RecvError,
                            format_args!("Connection disconnected"),
                        ));
                    }
                    Got::Data(_) => {}
                }
                self.first_byte = byte[0];
                trace::bytes(cx, DebugKind::HeaderIn, &byte);
                self.last_time = cx.now();
                self.npacket = 0;
                self.go(cx, State::RemainingLength, State::Unset);
                self.remaining(cx, lease)
            }
            State::RemainingLength => self.remaining(cx, lease),
            State::Connack => {
                if !self.verify_connack(cx, lease)? {
                    return Ok(false);
                }
                // A form or MIME post is no post here, as C's `httpreq`
                // has it.
                let options = cx.easy().options();
                let posts = options.method == Method::Post
                    && !matches!(options.upload, UploadSource::Mime(_));
                if !posts {
                    self.subscribe(cx, lease)?;
                    self.go(cx, State::First, State::Suback);
                    return Ok(false);
                }
                self.publish(cx, lease)?;
                self.go(cx, State::PostDrain, State::Unset);
                self.drain(cx, lease)
            }
            State::PostDrain | State::DisconnectDrain => self.drain(cx, lease),
            State::Suback | State::PubWait | State::PubRemain | State::SubackComing => {
                self.read_publish(cx, lease)
            }
            State::Unset => Err(trace::fail(
                cx,
                ErrorKind::WeirdServerReply,
                format_args!("State not handled yet"),
            )),
        }
    }

    /// Read on a packet's remaining length, a byte at a time.
    fn remaining<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        let mut last = 0u8;
        loop {
            let mut byte = [0u8; 1];
            match xfer_recv(cx, lease, &mut byte)? {
                Got::Again => return Ok(false),
                // C reads on as if nothing came.
                Got::Eof => break,
                Got::Data(_) => {}
            }
            trace::bytes(cx, DebugKind::HeaderIn, &byte);
            last = byte[0];
            self.length_bytes[self.npacket] = last;
            self.npacket += 1;
            if last & 0x80 == 0 || self.npacket >= 4 {
                break;
            }
        }
        if last & 0x80 != 0 {
            // More than four bytes of length.
            return Err(ErrorKind::WeirdServerReply);
        }
        let Some(len) = decode_len(&self.length_bytes[..self.npacket]) else {
            return Err(ErrorKind::WeirdServerReply);
        };
        self.remaining_length = len;
        self.npacket = 0;
        let kind = self.first_byte & 0xf0;
        let reserved = self.first_byte & 0x0f;
        if (kind == MSG_DISCONNECT || kind == MSG_PINGRESP) && (len > 0 || reserved > 0) {
            let what = if kind == MSG_DISCONNECT {
                "DISCONNECT"
            } else {
                "PINGRESP"
            };
            return Err(trace::fail(
                cx,
                ErrorKind::WeirdServerReply,
                format_args!(
                    "Broker sent malformed {what} (remaining_length={len}, header byte=0x{:02x})",
                    self.first_byte
                ),
            ));
        }
        if len > 0 {
            let next = self.next;
            self.go(cx, next, State::Unset);
            return Ok(false);
        }
        self.go(cx, State::First, State::First);
        let mut done = false;
        if self.first_byte == MSG_DISCONNECT {
            trace::info(cx, format_args!("Got DISCONNECT"));
            done = true;
        }
        if self.first_byte == MSG_PINGRESP {
            trace::info(cx, format_args!("Received ping response."));
            self.ping_sent = false;
            self.go(cx, State::First, State::PubWait);
        }
        Ok(done)
    }

    /// Finish sending the PUBLISH, then say DISCONNECT and finish sending
    /// that: whether it has gone.
    fn drain<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        if self.state == State::PostDrain {
            if !self.unsent.is_empty() {
                return Ok(false);
            }
            self.send(cx, lease, &[MSG_DISCONNECT, 0x00])?;
            self.go(cx, State::DisconnectDrain, State::Unset);
        }
        Ok(self.unsent.is_empty())
    }
}

/// Fill `out` with random letters and digits, each drawn from a 32-bit
/// number of the transfer's random bytes, one at or past the largest
/// multiple of 62 drawn again (`Curl_rand_alnum`).
fn client_id<H: Host>(cx: &mut StepCx<'_, H>, out: &mut [u8]) -> Result<(), ErrorKind> {
    let alnum = crate::mime::ALNUM;
    let space = alnum.len() as u32;
    let libraries = cx.easy().shared_libraries();
    for c in out {
        let r = loop {
            let mut word = [0u8; 4];
            libraries
                .random(&mut word)
                .map_err(|_| ErrorKind::FailedInit)?;
            let r = u32::from_ne_bytes(word);
            if r < u32::MAX - u32::MAX % space {
                break r;
            }
        };
        *c = alnum[(r % space) as usize];
    }
    Ok(())
}

impl super::Phases for Request {
    /// MQTT has no connect of its own; mqtts's TLS is the connection's.
    fn connect<H: Host>(
        &mut self,
        _: &mut StepCx<'_, H>,
        _: &mut ConnLease,
    ) -> Result<Connect, ErrorKind> {
        Ok(Connect::Done)
    }

    /// Say CONNECT in DO, and the rest of the exchange in DOING
    /// (`mqtt_do`, `mqtt_doing`).
    fn make<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        asked: DoPhase,
    ) -> Result<DoStep, ErrorKind> {
        match asked {
            DoPhase::Do => {
                self.last_time = cx.now();
                self.ping_sent = false;
                if let Err(e) = self.connect_send(cx, lease) {
                    let code = e.number();
                    return Err(trace::fail(
                        cx,
                        e,
                        format_args!("Error {code} sending MQTT CONNECT request"),
                    ));
                }
                self.go(cx, State::First, State::Connack);
                Ok(DoStep::Doing)
            }
            DoPhase::Doing => Ok(if self.doing(cx, lease)? {
                DoStep::Did
            } else {
                DoStep::Doing
            }),
            DoPhase::More => unreachable!("MQTT has no second half"),
        }
    }

    /// While the exchange goes on, to send what of a packet is left, or
    /// else what the server says (`mqtt_pollset`).
    fn waits(&self, phase: Waiting) -> Events {
        match phase {
            Waiting::Doing if !self.unsent.is_empty() => Events::OUT,
            Waiting::Doing => Events::IN,
            _ => phase.c_default(),
        }
    }
}

#[cfg(test)]
mod tests;
