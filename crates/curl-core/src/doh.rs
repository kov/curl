//! DNS messages as DNS over HTTPS carries them (`lib/vdns/doh.c`,
//! `lib/vdns/httpsrr.c`): the query a probe posts, and the answer it reads
//! back, which comes from a peer and is never trusted. Sans-IO: bytes in,
//! bytes or a value out, and no input panics.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use curl_alloc::{OutOfMemory, TryVec};

#[cfg(test)]
mod c_tests;
#[cfg(test)]
mod tests;

/// The largest query, from RFCs 1034 and 1035 (`DOH_MAX_DNSREQ_SIZE`).
const MAX_QUERY: usize = 256 + 16;
/// The addresses an answer may give; the rest are ignored (`DOH_MAX_ADDR`).
const MAX_ADDRS: usize = 24;
/// The HTTPS records an answer may give; the rest are ignored
/// (`DOH_MAX_HTTPS`).
const MAX_HTTPS: usize = 4;
/// A record's time to live is at most a day (`MAX_DNS_TTL`).
const MAX_TTL: u32 = 86400;
/// The buffer a name in a record's data is read into (`CURL_MAXLEN_HOST_NAME`
/// in `httpsrr.h`): the name, its dots and C's NUL.
const MAX_TARGET: usize = 253;
/// The ALPN ids a record keeps (`MAX_HTTPSRR_ALPNS`).
const MAX_ALPNS: usize = 4;

const CLASS_IN: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_DNAME: u16 = 39;

/// What a query asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryType {
    A,
    Aaaa,
    Https,
}

impl QueryType {
    fn code(self) -> u16 {
        match self {
            QueryType::A => 1,
            QueryType::Aaaa => 28,
            QueryType::Https => 65,
        }
    }

    /// As the trace names it (`doh_type2name`).
    pub fn name(self) -> &'static str {
        match self {
            QueryType::A => "A",
            QueryType::Aaaa => "AAAA",
            QueryType::Https => "HTTPS",
        }
    }
}

/// Why a query cannot be made or an answer is refused (`DOHcode`), its
/// `Display` the text C traces (`doh_strerror`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DohError {
    BadLabel,
    OutOfRange,
    TooSmall,
    OutOfMemory,
    RdataLength,
    Malformed,
    BadRcode,
    UnexpectedType,
    UnexpectedClass,
    BadId,
    NameTooLong,
    NoSuchName,
}

impl std::fmt::Display for DohError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DohError::BadLabel => "Bad label",
            DohError::OutOfRange => "Out of range",
            DohError::TooSmall => "Too small",
            DohError::OutOfMemory => "Out of memory",
            DohError::RdataLength => "RDATA length",
            DohError::Malformed => "Malformat",
            DohError::BadRcode => "Bad RCODE",
            DohError::UnexpectedType => "Unexpected TYPE",
            DohError::UnexpectedClass => "Unexpected CLASS",
            DohError::BadId => "Bad ID",
            DohError::NameTooLong => "Name too long",
            DohError::NoSuchName => "No such name",
        })
    }
}

/// The DNS message asking for `what` of `name`, ready to post
/// (`doh_req_encode`): a name of labels up to 63 bytes, 255 in all with
/// its root label, which may or may not end in its dot.
pub fn encode_query(name: &[u8], what: QueryType) -> Result<Vec<u8>, DohError> {
    // Twelve bytes of header, the question's four; the name's dots turn into
    // the labels' lengths, with one more for its first and the root's.
    let dotless = u8::from(name.last() != Some(&b'.'));
    let expected = 12 + 1 + name.len() + 4 + usize::from(dotless);
    if expected > MAX_QUERY {
        return Err(DohError::NameTooLong);
    }
    let mut query = Vec::new();
    let oom = |OutOfMemory| DohError::OutOfMemory;
    query
        .try_reserve_exact(expected)
        .map_err(|_| DohError::OutOfMemory)?;
    // Id 0, for caches (RFC 8484); recursion desired; one question.
    query
        .try_extend_from_slice(&[0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .map_err(oom)?;
    let mut rest = name;
    while !rest.is_empty() {
        let dot = rest.iter().position(|&b| b == b'.');
        let label = &rest[..dot.unwrap_or(rest.len())];
        let length = u8::try_from(label.len())
            .ok()
            .filter(|l| (1..=63).contains(l))
            .ok_or(DohError::BadLabel)?;
        query.try_push(length).map_err(oom)?;
        query.try_extend_from_slice(label).map_err(oom)?;
        rest = &rest[label.len() + usize::from(dot.is_some())..];
    }
    query.try_push(0).map_err(oom)?;
    query
        .try_extend_from_slice(&what.code().to_be_bytes())
        .map_err(oom)?;
    query
        .try_extend_from_slice(&CLASS_IN.to_be_bytes())
        .map_err(oom)?;
    Ok(query)
}

/// What an answer gave (`struct dohentry`).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DohAnswer<'a> {
    /// The addresses, the first 24.
    pub addrs: Vec<IpAddr>,
    /// The least of the records' times to live, in seconds, at most a day;
    /// none with no record.
    pub ttl: Option<u32>,
    /// The first four HTTPS records' data.
    pub https: Vec<&'a [u8]>,
}

/// A DNS message read from its start, every read checked against its end.
struct Reader<'a> {
    message: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DohError> {
        let end = self.at.checked_add(n).ok_or(DohError::OutOfRange)?;
        let taken = self.message.get(self.at..end).ok_or(DohError::OutOfRange)?;
        self.at = end;
        Ok(taken)
    }

    fn u16(&mut self) -> Result<u16, DohError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, DohError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Past a name, whose compression pointer is stepped over and never
    /// followed: nothing here reads the name, so no pointer can loop
    /// (`doh_skipqname`).
    fn skip_name(&mut self) -> Result<(), DohError> {
        loop {
            let length = self.take(1)?[0];
            if length & 0xc0 == 0xc0 {
                self.take(1)?;
                return Ok(());
            }
            if length & 0xc0 != 0 {
                return Err(DohError::BadLabel);
            }
            self.take(usize::from(length))?;
            if length == 0 {
                return Ok(());
            }
        }
    }

    /// Past a record of the authority or additional section.
    fn skip_record(&mut self) -> Result<(), DohError> {
        self.skip_name()?;
        self.take(2 + 2 + 4)?;
        let length = self.u16()?;
        self.take(usize::from(length))?;
        Ok(())
    }
}

/// The answer in `message` to a question for `what`, each of its sections
/// read to the message's very end (`doh_resp_decode`).
pub fn decode_answer(message: &[u8], what: QueryType) -> Result<DohAnswer<'_>, DohError> {
    let [a, b, _, flags, qd0, qd1, an0, an1, ns0, ns1, ar0, ar1, ..] = *message else {
        return Err(DohError::TooSmall);
    };
    if a != 0 || b != 0 {
        return Err(DohError::BadId);
    }
    match flags & 0x0f {
        0 => {}
        3 => return Err(DohError::NoSuchName),
        _ => return Err(DohError::BadRcode),
    }
    let mut r = Reader { message, at: 12 };
    for _ in 0..u16::from_be_bytes([qd0, qd1]) {
        r.skip_name()?;
        r.take(4)?;
    }
    let mut answer = DohAnswer::default();
    for _ in 0..u16::from_be_bytes([an0, an1]) {
        r.skip_name()?;
        let kind = r.u16()?;
        // CNAME and DNAME may come before the record asked for.
        if kind != what.code() && kind != TYPE_CNAME && kind != TYPE_DNAME {
            return Err(DohError::UnexpectedType);
        }
        if r.u16()? != CLASS_IN {
            return Err(DohError::UnexpectedClass);
        }
        let ttl = r.u32()?.min(MAX_TTL);
        answer.ttl = Some(answer.ttl.map_or(ttl, |t| t.min(ttl)));
        let length = r.u16()?;
        let data = r.take(usize::from(length))?;
        if kind == what.code() {
            store(data, what, &mut answer)?;
        }
    }
    for _ in 0..u16::from_be_bytes([ns0, ns1]) {
        r.skip_record()?;
    }
    for _ in 0..u16::from_be_bytes([ar0, ar1]) {
        r.skip_record()?;
    }
    if r.at != message.len() {
        return Err(DohError::Malformed);
    }
    Ok(answer)
}

/// A record of the type asked for, kept if there is room (`doh_rdata`).
fn store<'a>(data: &'a [u8], what: QueryType, to: &mut DohAnswer<'a>) -> Result<(), DohError> {
    let oom = |OutOfMemory| DohError::OutOfMemory;
    match what {
        QueryType::A => {
            let bytes: [u8; 4] = data.try_into().map_err(|_| DohError::RdataLength)?;
            if to.addrs.len() < MAX_ADDRS {
                to.addrs
                    .try_push(Ipv4Addr::from(bytes).into())
                    .map_err(oom)?;
            }
        }
        QueryType::Aaaa => {
            let bytes: [u8; 16] = data.try_into().map_err(|_| DohError::RdataLength)?;
            if to.addrs.len() < MAX_ADDRS {
                to.addrs
                    .try_push(Ipv6Addr::from(bytes).into())
                    .map_err(oom)?;
            }
        }
        QueryType::Https => {
            if data.len() < 3 {
                return Err(DohError::RdataLength);
            }
            if to.https.len() < MAX_HTTPS {
                to.https.try_push(data).map_err(oom)?;
            }
        }
    }
    Ok(())
}

/// An HTTP version a record offers (`enum alpnid`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordAlpn {
    H1,
    H2,
    H3,
}

impl RecordAlpn {
    /// `Curl_alpn2alpnid`; one this library does not know is `None`.
    fn of(name: &[u8]) -> Option<RecordAlpn> {
        match name {
            b"h1" | b"http/1.1" => Some(RecordAlpn::H1),
            b"h2" => Some(RecordAlpn::H2),
            b"h3" => Some(RecordAlpn::H3),
            _ => None,
        }
    }
}

/// An HTTPS record's data (`struct Curl_https_rrinfo`).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HttpsRecord {
    pub priority: u16,
    /// As C has it: from DoH a name's dots written out, up to its first NUL;
    /// from c-ares, as c-ares writes it.
    pub target: Vec<u8>,
    /// The versions offered that are known, in the record's order, without
    /// repeats.
    pub alpns: Vec<RecordAlpn>,
    pub no_default_alpn: bool,
    pub mandatory: bool,
    pub port: Option<u16>,
    /// The hints whole, each list checked to be of whole addresses.
    pub ipv4_hints: Vec<Ipv4Addr>,
    pub ipv6_hints: Vec<Ipv6Addr>,
    pub ech: Vec<u8>,
}

/// Why an HTTPS record's data is refused, each its `CURLcode` in C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Too short to hold a priority and a name
    /// (`CURLE_BAD_FUNCTION_ARGUMENT`), or a parameter of the wrong size.
    BadParameter,
    /// The name cannot be read. C reports whatever went wrong with it as
    /// `CURLE_OUT_OF_MEMORY`.
    BadName,
    /// `CURLE_WEIRD_SERVER_REPLY`.
    Weird,
    /// An ALPN list that does not fill its value
    /// (`CURLE_BAD_CONTENT_ENCODING`).
    BadAlpn,
    OutOfMemory,
}

/// A record's target, its labels read to the root's (`doh_decode_rdata_name`):
/// the name with its dots, and what follows it.
fn record_name(data: &[u8]) -> Result<(Vec<u8>, &[u8]), RecordError> {
    let oom = |_| RecordError::OutOfMemory;
    let mut name = Vec::new();
    let mut r = Reader {
        message: data,
        at: 0,
    };
    let mut length = r.take(1).map_err(|_| RecordError::BadName)?[0];
    if length > 63 {
        return Err(RecordError::BadName);
    }
    if length == 0 {
        name.try_push(b'.').map_err(oom)?;
    }
    while length != 0 {
        let label = r
            .take(usize::from(length))
            .map_err(|_| RecordError::BadName)?;
        // The label and its dot, each added only with room for the NUL
        // after them (`curlx_dyn_addn`).
        if name.len() + label.len() + 1 >= MAX_TARGET {
            return Err(RecordError::BadName);
        }
        name.try_extend_from_slice(label).map_err(oom)?;
        name.try_push(b'.').map_err(oom)?;
        length = r.take(1).map_err(|_| RecordError::BadName)?[0];
        if length > 63 {
            return Err(RecordError::BadName);
        }
    }
    Ok((name, &data[r.at..]))
}

/// The record's data decoded, its parameters in increasing order of their
/// keys (`doh_resp_decode_httpsrr`).
pub fn decode_https_record(data: &[u8]) -> Result<HttpsRecord, RecordError> {
    let [p0, p1, rest @ ..] = data else {
        return Err(RecordError::BadParameter);
    };
    if rest.is_empty() {
        return Err(RecordError::BadParameter);
    }
    let mut record = HttpsRecord {
        priority: u16::from_be_bytes([*p0, *p1]),
        ..HttpsRecord::default()
    };
    let (mut target, mut params) = record_name(rest)?;
    // C's name is a string: a NUL in a label ends it there.
    if let Some(nul) = target.iter().position(|&b| b == 0) {
        target.truncate(nul);
    }
    if target.iter().any(|&b| b <= 0x20 || b == 127) {
        return Err(RecordError::Weird);
    }
    record.target = target;
    let mut least = 0u32;
    while let [k0, k1, l0, l1, after @ ..] = params {
        let key = u16::from_be_bytes([*k0, *k1]);
        let length = usize::from(u16::from_be_bytes([*l0, *l1]));
        if u32::from(key) < least || length > after.len() {
            return Err(RecordError::Weird);
        }
        let (value, next) = after.split_at(length);
        record.set_parameter(key, value)?;
        params = next;
        least = u32::from(key) + 1;
    }
    Ok(record)
}

/// The ids of an ALPN list, each prefixed by its length, which must fill
/// `value` (`httpsrr_decode_alpn`); a fifth known one ends it.
fn decode_alpns(record: &mut HttpsRecord, mut value: &[u8]) -> Result<(), RecordError> {
    record.alpns.clear();
    while let [length, after @ ..] = value {
        let length = usize::from(*length);
        if length > after.len() {
            return Err(RecordError::BadAlpn);
        }
        let (name, next) = after.split_at(length);
        if let Some(alpn) = RecordAlpn::of(name) {
            if record.alpns.len() == MAX_ALPNS {
                break;
            }
            if !record.alpns.contains(&alpn) {
                record
                    .alpns
                    .try_push(alpn)
                    .map_err(|_| RecordError::OutOfMemory)?;
            }
        }
        value = next;
    }
    Ok(())
}

impl HttpsRecord {
    /// One parameter taken, its key's earlier value replaced
    /// (`Curl_httpsrr_set`).
    pub fn set_parameter(&mut self, key: u16, value: &[u8]) -> Result<(), RecordError> {
        let oom = |_| RecordError::OutOfMemory;
        match key {
            0 => self.mandatory = true,
            1 => decode_alpns(self, value)?,
            2 => {
                if !value.is_empty() {
                    return Err(RecordError::BadParameter);
                }
                self.no_default_alpn = true;
            }
            3 => {
                let port: [u8; 2] = value.try_into().map_err(|_| RecordError::BadParameter)?;
                self.port = Some(u16::from_be_bytes(port));
            }
            4 => {
                if value.is_empty() || !value.len().is_multiple_of(4) {
                    return Err(RecordError::BadParameter);
                }
                self.ipv4_hints.clear();
                for a in value.as_chunks::<4>().0 {
                    self.ipv4_hints.try_push((*a).into()).map_err(oom)?;
                }
            }
            5 => {
                if value.is_empty() {
                    return Err(RecordError::BadParameter);
                }
                self.ech.clear();
                self.ech.try_extend_from_slice(value).map_err(oom)?;
            }
            6 => {
                if value.is_empty() || !value.len().is_multiple_of(16) {
                    return Err(RecordError::BadParameter);
                }
                self.ipv6_hints.clear();
                for a in value.as_chunks::<16>().0 {
                    self.ipv6_hints.try_push((*a).into()).map_err(oom)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// As the trace shows it (`Curl_httpsrr_print`).
    pub(crate) fn print(&self) -> Result<Vec<u8>, OutOfMemory> {
        let mut out = Vec::new();
        let priority = crate::text::Text::<8>::clipped(format_args!("{} ", self.priority)).0;
        out.try_extend_from_slice(priority.bytes())?;
        out.try_extend_from_slice(if self.target.is_empty() {
            b"."
        } else {
            &self.target
        })?;
        if self.mandatory {
            out.try_extend_from_slice(b" mandatory-keys(ignored)")?;
        }
        for (i, alpn) in self.alpns.iter().enumerate() {
            out.try_extend_from_slice(if i == 0 { b" alpn=" } else { b"," })?;
            out.try_extend_from_slice(match alpn {
                RecordAlpn::H1 => b"http/1.1",
                RecordAlpn::H2 => b"h2",
                RecordAlpn::H3 => b"h3",
            })?;
        }
        let mut say = |args: std::fmt::Arguments<'_>| {
            let text = crate::text::Text::<64>::clipped(args).0;
            out.try_extend_from_slice(text.bytes())
        };
        if let Some(port) = self.port {
            say(format_args!(" port={port}"))?;
        }
        if self.no_default_alpn {
            say(format_args!(" no-default-alpn"))?;
        }
        for (i, ip) in self.ipv6_hints.iter().enumerate() {
            let head = if i == 0 { " ipv6hint=" } else { "," };
            say(format_args!("{head}{ip}"))?;
        }
        for (i, ip) in self.ipv4_hints.iter().enumerate() {
            let head = if i == 0 { " ipv4hint=" } else { "," };
            say(format_args!("{head}{ip}"))?;
        }
        if !self.ech.is_empty() {
            say(format_args!(" ech=<{} bytes>", self.ech.len()))?;
        }
        Ok(out)
    }
}

/// What a resolve of a name's HTTPS record came to.
#[derive(Debug)]
pub enum RecordAnswer {
    Record(HttpsRecord),
    /// The server answered, without one.
    NoRecord,
    /// The server said no such name, which is kept.
    NoSuchName,
    /// Anything else, which says nothing of the name and is not kept.
    Failed,
}
