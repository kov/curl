//! Alternative services (RFC 7838, `lib/altsvc.c`): where a server said
//! its origin can also be reached, by which protocol version, and until
//! when. A transfer to an origin the cache knows connects to the
//! alternative in its place. The cache is read from a file as the
//! application names it and written back as the handle goes.

use std::fmt;

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::date::HttpDate;
use crate::hsts::{LoadError, read_file};
use crate::save::CacheFile;

/// The most entries kept: past it, the oldest goes (`MAX_ALTSVC_ENTRIES`).
const MAX_ENTRIES: usize = 5000;
/// The longest line a file may have (`MAX_ALTSVC_LINE`), and the longest
/// parameter of a field.
const MAX_LINE: usize = 4095;
/// The longest expiry date a file's line may give (`MAX_ALTSVC_DATELEN`).
const MAX_DATE_LEN: usize = 17;
/// The longest host name (`MAX_ALTSVC_HOSTLEN`).
const MAX_HOST_LEN: usize = 2048;
/// The longest protocol name a file's line may give (`MAX_ALTSVC_ALPNLEN`).
const MAX_ALPN_LEN: usize = 10;
/// The longest IPv6 address a field may name (`MAX_IPADR_LEN`).
const MAX_IPV6_LEN: usize = 46;
/// An `ma` past two years counts as two years (`CAP_ALTSVC_MAX_AGE`).
const CAP_MAX_AGE: i64 = 2 * 365 * 24 * 3600;
/// An alternative without `ma` lasts a day.
const DEFAULT_MAX_AGE: i64 = 24 * 3600;

/// A protocol version an origin or its alternative speaks, by its ALPN id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alpn {
    H1,
    H2,
    H3,
}

impl Alpn {
    /// The version an ALPN id names, exactly (`Curl_alpn2alpnid`).
    fn of(name: &[u8]) -> Option<Alpn> {
        match name {
            b"h1" | b"http/1.1" => Some(Alpn::H1),
            b"h2" => Some(Alpn::H2),
            b"h3" => Some(Alpn::H3),
            _ => None,
        }
    }

    /// Its name, as files write it (`Curl_alpnid2str`).
    pub fn name(self) -> &'static str {
        match self {
            Alpn::H1 => "h1",
            Alpn::H2 => "h2",
            Alpn::H3 => "h3",
        }
    }
}

/// The versions alternatives may be taken to (`CURLALTSVC_H1`, `_H2`,
/// `_H3`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Versions {
    pub h1: bool,
    pub h2: bool,
    pub h3: bool,
}

impl Versions {
    /// Whether `alpn` is among them.
    pub fn has(self, alpn: Alpn) -> bool {
        match alpn {
            Alpn::H1 => self.h1,
            Alpn::H2 => self.h2,
            Alpn::H3 => self.h3,
        }
    }
}

/// How the application has the cache behave (`CURLOPT_ALTSVC_CTRL`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AltSvcCtrl {
    /// Whether its file is written back.
    pub file: CacheFile,
    /// The versions alternatives may be taken to.
    pub versions: Versions,
}

impl AltSvcCtrl {
    /// A cache the application has not set: every version the build
    /// speaks (`Curl_altsvc_init`), HTTP/1 and HTTP/2; an alternative in
    /// HTTP/2 is taken only by a handle with a library for it.
    pub const DEFAULT: AltSvcCtrl = AltSvcCtrl {
        file: CacheFile::ReadWrite,
        versions: Versions {
            h1: true,
            h2: true,
            h3: false,
        },
    };
}

/// One end of an alternative: a version, a host and a port.
#[derive(Debug)]
struct End {
    alpn: Alpn,
    /// Without an IPv6 address's brackets.
    host: Vec<u8>,
    port: u16,
}

/// An origin's alternative.
#[derive(Debug)]
struct Entry {
    src: End,
    dst: End,
    /// When it expires, in seconds since 1970.
    expires: i64,
    /// Kept across network changes, which nothing here tells apart.
    persist: bool,
}

/// The alternative a lookup found (`Curl_altsvc_lookup`).
#[derive(Debug, PartialEq, Eq)]
pub struct Alternative<'a> {
    /// Its version.
    pub alpn: Alpn,
    /// Its host, without an IPv6 address's brackets.
    pub host: &'a [u8],
    pub port: u16,
    /// Whether it is the origin's own host and port, only by another
    /// version.
    pub same: bool,
}

/// The cache (C's `struct altsvcinfo`).
#[derive(Debug)]
pub struct AltSvc {
    /// Oldest first.
    entries: Vec<Entry>,
    /// The file last read, written back when no other is named.
    file: Option<Vec<u8>>,
    ctrl: AltSvcCtrl,
}

impl Default for AltSvc {
    fn default() -> Self {
        AltSvc {
            entries: Vec::new(),
            file: None,
            ctrl: AltSvcCtrl::DEFAULT,
        }
    }
}

/// `host` without the brackets of an IPv6 address, if it is longer than
/// two bytes and starts with one.
fn unbracketed(host: &[u8]) -> &[u8] {
    match host {
        [b'[', inner @ .., _] if !inner.is_empty() => inner,
        _ => host,
    }
}

/// Whether `host`, perhaps with one trailing dot, is `check`, in any case
/// (`hostcompare`).
fn same_host(host: &[u8], check: &[u8]) -> bool {
    host.strip_suffix(b".")
        .unwrap_or(host)
        .eq_ignore_ascii_case(check)
}

impl AltSvc {
    /// How the cache behaves.
    pub fn ctrl(&self) -> AltSvcCtrl {
        self.ctrl
    }

    /// Behave as `ctrl` says from now on.
    pub fn set_ctrl(&mut self, ctrl: AltSvcCtrl) {
        self.ctrl = ctrl;
    }

    /// The file last read, if any.
    pub fn file(&self) -> Option<&[u8]> {
        self.file.as_deref()
    }

    /// How many entries it keeps.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Keep an alternative, the oldest going if full; false for a host
    /// that is nothing, which is none (`altsvc_createid`, `altsvc_append`).
    /// The source host loses an IPv6 address's brackets or else one
    /// trailing dot, the destination its brackets.
    fn create(
        &mut self,
        src: (Alpn, &[u8], u16),
        dst: (Alpn, &[u8], u16),
        expires: i64,
        persist: bool,
    ) -> Result<bool, OutOfMemory> {
        let src_host = match unbracketed(src.1) {
            h if h.len() < src.1.len() => h,
            h => h.strip_suffix(b".").unwrap_or(h),
        };
        let dst_host = unbracketed(dst.1);
        if src_host.is_empty() || dst_host.is_empty() {
            return Ok(false);
        }
        let mut s = Vec::new();
        s.try_extend_from_slice(src_host)?;
        let mut d = Vec::new();
        d.try_extend_from_slice(dst_host)?;
        self.entries.try_reserve(1).map_err(|_| OutOfMemory)?;
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.remove(0);
        }
        self.entries.try_push(Entry {
            src: End {
                alpn: src.0,
                host: s,
                port: src.2,
            },
            dst: End {
                alpn: dst.0,
                host: d,
                port: dst.2,
            },
            expires,
            persist,
        })?;
        Ok(true)
    }

    /// Read the entries of the file at `path`, which is then the one
    /// written back; lines that cannot be read are passed over, and a file
    /// that cannot be opened, or is a directory, adds nothing
    /// (`altsvc_load`). A file that cannot be read, or has a line longer
    /// than C's buffer, fails.
    pub fn load(&mut self, path: &[u8], now: i64) -> Result<(), LoadError> {
        let mut name = Vec::new();
        name.try_extend_from_slice(path)?;
        self.file = Some(name);
        let Some(text) = read_file(path)? else {
            return Ok(());
        };
        for line in text.split_inclusive(|&b| b == b'\n') {
            // `Curl_get_line`'s buffer, with the newline it adds to a
            // last line without one.
            if line.len() + usize::from(!line.ends_with(b"\n")) > MAX_LINE {
                return Err(LoadError::TooLarge);
            }
            let blanks = line
                .iter()
                .take_while(|&&b| b == b' ' || b == b'\t')
                .count();
            let line = &line[blanks..];
            if line.first() == Some(&b'#') {
                continue;
            }
            if line.ends_with(b"\n") {
                self.add_line(line, now)?;
            } else {
                // With the newline `Curl_get_line` ends every line with.
                let mut ended = Vec::new();
                ended.try_extend_from_slice(line)?;
                ended.try_push(b'\n')?;
                self.add_line(&ended, now)?;
            }
        }
        Ok(())
    }

    /// Keep a file's line, unless it cannot be read, names a version not
    /// known, or has expired by `now` (`altsvc_add`):
    /// `h2 example.com 443 h3 shiny.example.com 8443 "20191231 10:00:00" 1 0`.
    fn add_line(&mut self, line: &[u8], now: i64) -> Result<(), OutOfMemory> {
        let mut c = Cursor::new(line);
        let mut field = || -> Option<_> {
            let src_alpn = c.word(MAX_ALPN_LEN)?;
            c.space()?;
            let src_host = c.word(MAX_HOST_LEN)?;
            c.space()?;
            let src_port = c.number(65535)?;
            c.space()?;
            let dst_alpn = c.word(MAX_ALPN_LEN)?;
            c.space()?;
            let dst_host = c.word(MAX_HOST_LEN)?;
            c.space()?;
            let dst_port = c.number(65535)?;
            c.space()?;
            let date = c.quoted(MAX_DATE_LEN)?;
            c.space()?;
            let persist = c.number(1)?;
            c.space()?;
            c.number(0)?;
            c.newline().then_some(())?;
            Some((
                src_alpn, src_host, src_port, dst_alpn, dst_host, dst_port, date, persist,
            ))
        };
        let Some((src_alpn, src_host, src_port, dst_alpn, dst_host, dst_port, date, persist)) =
            field()
        else {
            return Ok(());
        };
        // One that cannot be read has expired already.
        let expires = crate::date::parse(date).unwrap_or(0);
        if now >= expires {
            return Ok(());
        }
        let (Some(src_alpn), Some(dst_alpn)) = (Alpn::of(src_alpn), Alpn::of(dst_alpn)) else {
            return Ok(());
        };
        let port = |n: i64| u16::try_from(n).expect("read no larger than 65535");
        self.create(
            (src_alpn, src_host, port(src_port)),
            (dst_alpn, dst_host, port(dst_port)),
            expires,
            persist != 0,
        )?;
        Ok(())
    }

    /// Forget every alternative of the origin `host`:`port` spoken to by
    /// `alpn` (`altsvc_flush`).
    fn flush(&mut self, host: &[u8], port: u16, alpn: Alpn) {
        self.entries.retain(|e| {
            !(e.src.alpn == alpn && e.src.port == port && same_host(host, &e.src.host))
        });
    }

    /// Take what a response's `Alt-Svc:` field, `value`, says of the
    /// origin `host`:`port` it came from by `alpn`, at `now`
    /// (`Curl_altsvc_parse`): `clear` alone forgets the origin's
    /// alternatives; otherwise each alternative of a known version, the
    /// first of them forgetting the origin's earlier ones. What cannot be
    /// read ends the reading; `say` is told what was added and why an
    /// alternative was passed over, as C traces it.
    pub fn parse(
        &mut self,
        value: &[u8],
        origin: (&[u8], u16, Alpn),
        now: i64,
        say: &mut dyn FnMut(fmt::Arguments<'_>),
    ) -> Result<(), OutOfMemory> {
        let (host, port, alpn) = origin;
        let mut c = Cursor::new(value);
        if let Some(word) = c.cspn(b";\n\r")
            && trim_blanks(word).eq_ignore_ascii_case(b"clear")
        {
            self.flush(host, port, alpn);
            return Ok(());
        }
        let mut c = Cursor::new(value);
        let mut flushed = false;
        while !c.rest().is_empty() {
            let Some(name) = c.until(b'=', MAX_LINE) else {
                break;
            };
            let dst_alpn = Alpn::of(trim_blanks(name));
            if !c.single(b'=') {
                break;
            }
            let Some((dst_host, dst_port)) = destination(&mut c, host, say) else {
                break;
            };
            let (max_age, persist) = params(&mut c);
            if let Some(dst_alpn) = dst_alpn {
                if !flushed {
                    self.flush(host, port, alpn);
                    flushed = true;
                }
                let expires = now.checked_add(max_age).unwrap_or(i64::MAX);
                let made = self.create(
                    (alpn, host, port),
                    (dst_alpn, dst_host, dst_port),
                    expires,
                    persist,
                )?;
                // An origin whose host is a dot alone keeps nothing; C
                // fails the transfer for memory there (DIVERGENCE.md).
                if made {
                    let shown = crate::trace::Bytes(dst_host);
                    say(format_args!(
                        "Added alt-svc: {shown}:{dst_port} over {}",
                        dst_alpn.name()
                    ));
                }
            }
            if !c.single(b',') {
                break;
            }
        }
        Ok(())
    }

    /// The first alternative of the origin `host`:`port` spoken to by
    /// `alpn` whose version is among `versions`, at `now`; those expired
    /// go as they are passed (`Curl_altsvc_lookup`).
    pub fn lookup(
        &mut self,
        origin: (&[u8], u16, Alpn),
        versions: Versions,
        now: i64,
    ) -> Option<Alternative<'_>> {
        let (host, port, alpn) = origin;
        let mut at = 0;
        let found = loop {
            let e = self.entries.get(at)?;
            if e.expires < now {
                self.entries.remove(at);
                continue;
            }
            if e.src.alpn == alpn
                && versions.has(e.dst.alpn)
                && e.src.port == port
                && same_host(host, &e.src.host)
            {
                break at;
            }
            at += 1;
        };
        let e = &self.entries[found];
        Some(Alternative {
            alpn: e.dst.alpn,
            host: &e.dst.host,
            port: e.dst.port,
            same: e.dst.port == port && same_host(host, &e.dst.host),
        })
    }

    /// The text of the file the cache is written as, every entry a line
    /// (`Curl_altsvc_save`, `altsvc_out`); one whose date `gmtime` cannot
    /// hold is left out.
    pub fn text(&self) -> Result<Vec<u8>, OutOfMemory> {
        let mut out = Vec::new();
        out.try_extend_from_slice(
            b"# Your alt-svc cache. https://curl.se/docs/alt-svc.html\n\
              # This file was generated by libcurl! Edit at your own risk.\n",
        )?;
        for e in &self.entries {
            let Ok(date) = HttpDate::of(e.expires) else {
                continue;
            };
            let mut line = crate::text::Text::<{ 2 * MAX_HOST_LEN + 80 }>::new();
            let src = Host(&e.src.host);
            let dst = Host(&e.dst.host);
            use fmt::Write as _;
            let mut stamp = crate::text::Text::<24>::new();
            date.write_hsts(&mut stamp).expect("a date fits");
            let written = writeln!(
                line,
                "{} {src} {} {} {dst} {} \"{}\" {} 0",
                e.src.alpn.name(),
                e.src.port,
                e.dst.alpn.name(),
                e.dst.port,
                crate::trace::Bytes(stamp.bytes()),
                u8::from(e.persist),
            );
            written.expect("a line fits");
            out.try_extend_from_slice(line.bytes())?;
        }
        Ok(out)
    }

    /// A new cache for a copy of the handle (`curl_easy_duphandle`): no
    /// entries, the same behaviour.
    pub fn copy_empty(&self) -> AltSvc {
        AltSvc {
            entries: Vec::new(),
            file: None,
            ctrl: self.ctrl,
        }
    }
}

/// A host as a file writes it: an IPv6 address in brackets.
struct Host<'a>(&'a [u8]);

impl fmt::Display for Host<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v6 = std::str::from_utf8(self.0)
            .ok()
            .is_some_and(|s| s.parse::<std::net::Ipv6Addr>().is_ok());
        let host = crate::trace::Bytes(self.0);
        if v6 {
            write!(f, "[{host}]")
        } else {
            write!(f, "{host}")
        }
    }
}

/// The alternative's quoted `host:port`, or `:port` for the origin's own
/// `host` (`altsvc_parse_dest`).
fn destination<'a>(
    c: &mut Cursor<'a>,
    host: &'a [u8],
    say: &mut dyn FnMut(fmt::Arguments<'_>),
) -> Option<(&'a [u8], u16)> {
    if !c.single(b'"') {
        return None;
    }
    let dst = if c.single(b':') {
        host
    } else {
        let dst = if !c.single(b'[') {
            let Some(name) = c.until(b':', MAX_HOST_LEN) else {
                say(format_args!("Bad alt-svc hostname, ignoring."));
                return None;
            };
            name
        } else {
            let Some(address) = c.until(b']', MAX_IPV6_LEN).filter(|_| c.single(b']')) else {
                say(format_args!("Bad alt-svc IPv6 hostname, ignoring."));
                return None;
            };
            address
        };
        if !c.single(b':') {
            return None;
        }
        dst
    };
    let Some(port) = c.number(0xffff) else {
        say(format_args!("Unknown alt-svc port number, ignoring."));
        return None;
    };
    let port = u16::try_from(port).expect("read no larger than 65535");
    c.single(b'"').then_some((dst, port))
}

/// An alternative's `ma` and `persist`, after a `;`; an unknown
/// parameter is passed over, and one that cannot be read ends them
/// (`altsvc_parse_params`).
fn params(c: &mut Cursor<'_>) -> (i64, bool) {
    let mut max_age = DEFAULT_MAX_AGE;
    let mut persist = false;
    c.pass_blanks();
    if !c.single(b';') {
        return (max_age, persist);
    }
    while let Some(name) = c.until(b'=', MAX_LINE) {
        if !c.single(b'=') {
            break;
        }
        let name = trim_blanks(name);
        c.pass_blanks();
        let value = if c.peek() == Some(b'"') {
            c.quoted(MAX_LINE)
        } else {
            c.cspn(b",;\r\n")
        };
        let Some(value) = value else {
            break;
        };
        let value = trim_blanks(value);
        let ma = name.eq_ignore_ascii_case(b"ma");
        if ma || name.eq_ignore_ascii_case(b"persist") {
            let mut v = Cursor::new(value);
            let Some(n) = v.number(i64::MAX).filter(|_| v.rest().is_empty()) else {
                break;
            };
            if ma {
                max_age = n.min(CAP_MAX_AGE);
            } else if n == 1 {
                persist = true;
            }
        }
        c.pass_blanks();
        if !c.single(b';') {
            break;
        }
    }
    (max_age, persist)
}

/// `s` without blanks (spaces and tabs) at either end
/// (`curlx_str_trimblanks`).
fn trim_blanks(s: &[u8]) -> &[u8] {
    let blank = |b: &u8| *b == b' ' || *b == b'\t';
    let start = s.iter().position(|b| !blank(b)).unwrap_or(s.len());
    let end = s.iter().rposition(|b| !blank(b)).map_or(start, |e| e + 1);
    &s[start..end]
}

/// C's string parsers (`lib/curlx/strparse.c`) over bytes that end, as a
/// C string does, at the first zero byte.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn new(s: &'a [u8]) -> Cursor<'a> {
        Cursor(s.split(|&b| b == 0).next().unwrap_or_default())
    }

    fn rest(&self) -> &'a [u8] {
        self.0
    }

    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }

    /// Move over `b` if it is next (`curlx_str_single`).
    fn single(&mut self, b: u8) -> bool {
        match self.0.split_first() {
            Some((&first, rest)) if first == b => {
                self.0 = rest;
                true
            }
            _ => false,
        }
    }

    fn space(&mut self) -> Option<()> {
        self.single(b' ').then_some(())
    }

    fn newline(&mut self) -> bool {
        self.single(b'\n') || self.single(b'\r')
    }

    fn pass_blanks(&mut self) {
        while self.single(b' ') || self.single(b'\t') {}
    }

    /// One byte or more up to `delim` or the end, no more than `max`
    /// (`curlx_str_until`).
    fn until(&mut self, delim: u8, max: usize) -> Option<&'a [u8]> {
        let len = self
            .0
            .iter()
            .position(|&b| b == delim)
            .unwrap_or(self.0.len());
        if len == 0 || len > max {
            return None;
        }
        let (word, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(word)
    }

    /// Up to a space (`curlx_str_word`).
    fn word(&mut self, max: usize) -> Option<&'a [u8]> {
        self.until(b' ', max)
    }

    /// One byte or more, none of them in `reject` (`curlx_str_cspn`).
    fn cspn(&mut self, reject: &[u8]) -> Option<&'a [u8]> {
        let len = self
            .0
            .iter()
            .position(|b| reject.contains(b))
            .unwrap_or(self.0.len());
        if len == 0 {
            return None;
        }
        let (word, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(word)
    }

    /// What is between double quotes, a backslash keeping the byte after
    /// it, no more than `max` bytes; returned as written
    /// (`curlx_str_quotedword`).
    fn quoted(&mut self, max: usize) -> Option<&'a [u8]> {
        let s = self.0.strip_prefix(b"\"")?;
        let mut at = 0;
        while at < s.len() && s[at] != b'"' {
            if s[at] == b'\\' && at + 1 < s.len() {
                at += 1;
                if at > max {
                    return None;
                }
            }
            at += 1;
            if at > max {
                return None;
            }
        }
        if at == s.len() {
            return None;
        }
        self.0 = &s[at + 1..];
        Some(&s[..at])
    }

    /// A decimal number no larger than `max`, digits only
    /// (`curlx_str_number`).
    fn number(&mut self, max: i64) -> Option<i64> {
        let digits = self.0.iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        let mut n: i64 = 0;
        for &d in &self.0[..digits] {
            n = n.checked_mul(10)?.checked_add(i64::from(d - b'0'))?;
            if n > max {
                return None;
            }
        }
        self.0 = &self.0[digits..];
        Some(n)
    }
}

#[cfg(test)]
mod tests;
