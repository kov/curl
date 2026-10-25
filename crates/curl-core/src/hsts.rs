//! HTTP Strict Transport Security (RFC 6797, `lib/hsts.c`): the hosts a
//! server said to reach only over HTTPS, until when, and whether their
//! subdomains too. A plain HTTP URL to one is switched to HTTPS before it
//! connects. The cache is read from files and from the application, and
//! written to a file and to the application.

use std::fmt;

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::date::HttpDate;
use crate::url::is_ip_address;

/// The most entries kept: past it, the oldest goes (`MAX_HSTS_ENTRIES`).
const MAX_ENTRIES: usize = 10000;
/// The longest host name looked up or read (`MAX_HSTS_HOSTLEN`).
pub const MAX_HOST_LEN: usize = 2048;
/// The longest expiry date read (`MAX_HSTS_DATELEN`).
pub const MAX_DATE_LEN: usize = 17;
/// The longest quoted value a header's directive takes (`MAX_HSTS_LINE`).
const MAX_LINE: usize = 4095;
/// A `max-age` past two years counts as two years (`CAP_HSTS_MAX_AGE`).
const CAP_MAX_AGE: i64 = 2 * 365 * 24 * 3600;
/// An entry that never expires (`TIME_T_MAX`), written as `unlimited`.
const UNLIMITED: i64 = i64::MAX;

/// A host to reach only over HTTPS.
#[derive(Debug)]
struct Entry {
    /// Without a trailing dot.
    host: Vec<u8>,
    /// Its subdomains too (`includeSubDomains`).
    subdomains: bool,
    /// When it expires, in seconds since 1970; `UNLIMITED` for never.
    expires: i64,
}

/// An entry as it is read from or given to the application and files:
/// the host, `expire` as `YYYYMMDD HH:MM:SS` or `unlimited`, and whether
/// its subdomains are included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HstsEntry<'a> {
    pub name: &'a [u8],
    pub expire: &'a [u8],
    pub subdomains: bool,
}

/// What a reader gave (`CURLSTS_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HstsRead {
    /// An entry, given to `keep`.
    Given,
    /// No more.
    Done,
    /// The transfer fails, `CURLE_ABORTED_BY_CALLBACK` (`CURLSTS_FAIL`).
    Abort,
    /// It gave no name, or wrote past what an entry holds; the transfer
    /// fails, `CURLE_BAD_FUNCTION_ARGUMENT`.
    Invalid,
}

/// Gives the application's entries as each transfer starts
/// (`CURLOPT_HSTSREADFUNCTION`): each call one, given to `keep`, until it
/// says there are no more. An entry's empty `expire` never expires.
pub trait HstsReader: Send + Sync {
    fn read(
        &self,
        keep: &mut dyn FnMut(HstsEntry<'_>) -> Result<(), BadEntry>,
    ) -> Result<HstsRead, BadEntry>;
}

/// What a writer said of an entry (`CURLSTS_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HstsWrite {
    /// The next, please.
    More,
    /// No more.
    Stop,
    /// No more, and the save fails.
    Fail,
}

/// Is given every entry, its place and the number of them, as the
/// handle goes (`CURLOPT_HSTSWRITEFUNCTION`).
pub trait HstsWriter: Send + Sync {
    fn write(&self, entry: HstsEntry<'_>, index: usize, total: usize) -> HstsWrite;
}

impl crate::handler::Handler<dyn HstsReader> {
    pub fn hsts_reader(reader: impl HstsReader + 'static) -> Result<Self, OutOfMemory> {
        let boxed: Box<dyn HstsReader> = curl_alloc::try_box(reader)?;
        crate::handler::Handler::new(boxed)
    }
}

impl crate::handler::Handler<dyn HstsWriter> {
    pub fn hsts_writer(writer: impl HstsWriter + 'static) -> Result<Self, OutOfMemory> {
        let boxed: Box<dyn HstsWriter> = curl_alloc::try_box(writer)?;
        crate::handler::Handler::new(boxed)
    }
}

/// Why the application's reader stopped the transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PullError {
    /// It said to (`CURLE_ABORTED_BY_CALLBACK`).
    Aborted,
    /// It gave what no entry is (`CURLE_BAD_FUNCTION_ARGUMENT`).
    Invalid,
    OutOfMemory,
}

/// The cache (C's `struct hsts`).
#[derive(Debug, Default)]
pub struct Hsts {
    /// Oldest first.
    entries: Vec<Entry>,
    /// The file last read, written back when no other is named.
    file: Option<Vec<u8>>,
    /// The files read as each transfer starts (C's `state.hstslist`).
    to_read: Vec<Vec<u8>>,
}

/// Why a `Strict-Transport-Security:` header was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StsError {
    /// It says no `max-age`, says one twice or one that is not a number,
    /// or says `includeSubDomains` twice (`CURLE_BAD_FUNCTION_ARGUMENT`).
    Illegal,
    OutOfMemory,
}

impl From<OutOfMemory> for StsError {
    fn from(OutOfMemory: OutOfMemory) -> Self {
        StsError::OutOfMemory
    }
}

/// Why a file could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    OutOfMemory,
    /// It opened but could not be read (`CURLE_READ_ERROR`).
    Read,
    /// A line is longer than C reads one (`CURLE_TOO_LARGE`).
    TooLarge,
}

impl From<OutOfMemory> for LoadError {
    fn from(OutOfMemory: OutOfMemory) -> Self {
        LoadError::OutOfMemory
    }
}

/// The whole of the file at `path`; `None` if it cannot be opened or is
/// a directory.
fn read_file(path: &[u8]) -> Result<Option<Vec<u8>>, LoadError> {
    use std::io::Read as _;
    let mut z = Vec::new();
    z.try_extend_from_slice(path)?;
    z.try_push(0)?;
    let Ok(path) = std::ffi::CStr::from_bytes_with_nul(&z) else {
        return Ok(None);
    };
    let Ok(mut file) = curl_os::fs::open_read(path) else {
        return Ok(None);
    };
    if file.metadata().is_ok_and(|m| m.is_dir()) {
        return Ok(None);
    }
    let mut text = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => return Ok(Some(text)),
            Ok(n) => text.try_extend_from_slice(&chunk[..n])?,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(LoadError::Read),
        }
    }
}

/// An entry given by the application that could not be taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BadEntry {
    /// Its date is longer than a date can be.
    Date,
    OutOfMemory,
}

impl From<OutOfMemory> for BadEntry {
    fn from(OutOfMemory: OutOfMemory) -> Self {
        BadEntry::OutOfMemory
    }
}

/// `name` without one trailing dot.
fn undotted(name: &[u8]) -> &[u8] {
    name.strip_suffix(b".").unwrap_or(name)
}

impl Hsts {
    /// The entry for `host`, or with `subdomain` the one including it
    /// with the longest name, at `now`; those expired go as they are
    /// passed (`hsts_check`).
    fn check(&mut self, host: &[u8], subdomain: bool, now: i64) -> Option<usize> {
        if host.is_empty() || host.len() > MAX_HOST_LEN {
            return None;
        }
        let host = undotted(host);
        self.entries.retain(|e| e.expires > now);
        let mut best: Option<(usize, usize)> = None;
        for (at, e) in self.entries.iter().enumerate() {
            let tail = e.host.len();
            if subdomain && e.subdomains && tail < host.len() {
                let offs = host.len() - tail;
                if host[offs - 1] == b'.'
                    && host[offs..].eq_ignore_ascii_case(&e.host)
                    && best.is_none_or(|(_, len)| tail > len)
                {
                    best = Some((at, tail));
                }
            }
            if host.eq_ignore_ascii_case(&e.host) {
                return Some(at);
            }
        }
        best.map(|(at, _)| at)
    }

    /// Whether `host` is to be reached only over HTTPS at `now`, by an
    /// entry of its own or one that includes its subdomains
    /// (`Curl_hsts_applies`).
    pub fn applies(&mut self, host: &[u8], now: i64) -> bool {
        self.check(host, true, now).is_some()
    }

    /// Keep an entry, the oldest going if full; a host that is a dot
    /// alone is none (`hsts_create`).
    fn create(&mut self, host: &[u8], subdomains: bool, expires: i64) -> Result<(), OutOfMemory> {
        let host = undotted(host);
        if host.is_empty() {
            return Ok(());
        }
        let mut copy = Vec::new();
        copy.try_extend_from_slice(host)?;
        if self.entries.len() == MAX_ENTRIES {
            self.entries.remove(0);
        }
        self.entries.try_push(Entry {
            host: copy,
            subdomains,
            expires,
        })
    }

    /// Take what a `Strict-Transport-Security:` header from `host` says
    /// at `now` (`Curl_hsts_parse`): its `max-age`, which 0 makes the
    /// host's entry go, and `includeSubDomains`. An IP address is never
    /// one (RFC 6797).
    pub fn parse(&mut self, host: &[u8], header: &[u8], now: i64) -> Result<(), StsError> {
        if is_ip_address(host) {
            return Ok(());
        }
        let directives = directives(header)?;
        let Some(max_age) = directives.max_age else {
            return Err(StsError::Illegal);
        };
        if max_age == 0 {
            if let Some(at) = self.check(host, false, now) {
                self.entries.remove(at);
            }
            return Ok(());
        }
        let expires = now.checked_add(max_age).unwrap_or(UNLIMITED);
        match self.check(host, false, now) {
            Some(at) => {
                let e = &mut self.entries[at];
                e.expires = expires;
                e.subdomains = directives.subdomains;
            }
            None => self.create(host, directives.subdomains, expires)?,
        }
        Ok(())
    }

    /// Keep an entry read from a file or the application, unless it has
    /// expired by `now` or is already kept, in which case the later expiry
    /// and the wider reach are kept (`hsts_add_host_expire`). A name with
    /// a leading dot includes its subdomains.
    pub fn add(&mut self, entry: HstsEntry<'_>, now: i64) -> Result<(), BadEntry> {
        if entry.expire.len() > MAX_DATE_LEN {
            return Err(BadEntry::Date);
        }
        let expires = match entry.expire {
            b"unlimited" => UNLIMITED,
            // One that cannot be read has expired already.
            date => crate::date::parse(date).unwrap_or(0),
        };
        if expires <= now {
            return Ok(());
        }
        let (host, subdomains) = match entry.name.strip_prefix(b".") {
            Some(host) => (host, true),
            None => (entry.name, entry.subdomains),
        };
        let host = undotted(host);
        if host.is_empty() {
            return Ok(());
        }
        match self.check(host, false, now) {
            None => self.create(host, subdomains, expires)?,
            Some(at) => {
                let e = &mut self.entries[at];
                if host.eq_ignore_ascii_case(&e.host) {
                    e.expires = e.expires.max(expires);
                    e.subdomains |= subdomains;
                }
            }
        }
        Ok(())
    }

    /// Read the entries of the file at `path`, which is then the one
    /// written back; lines that cannot be read are passed over, and a file
    /// that cannot be opened, or is a directory, adds nothing
    /// (`hsts_load`). A file that cannot be read, or has a line longer
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
            let line = line.trim_ascii_start();
            if line.first() == Some(&b'#') || line.len() <= 1 {
                continue;
            }
            if let Some(entry) = file_line(line) {
                match self.add(entry, now) {
                    Ok(()) | Err(BadEntry::Date) => {}
                    Err(BadEntry::OutOfMemory) => return Err(LoadError::OutOfMemory),
                }
            }
        }
        Ok(())
    }

    /// Keep what the application's reader gives, until it says no more
    /// (`hsts_pull`).
    pub fn pull(&mut self, reader: &dyn HstsReader, now: i64) -> Result<(), PullError> {
        loop {
            let read = reader.read(&mut |entry| {
                let entry = HstsEntry {
                    expire: if entry.expire.is_empty() {
                        b"unlimited"
                    } else {
                        entry.expire
                    },
                    ..entry
                };
                self.add(entry, now)
            });
            match read {
                Ok(HstsRead::Given) => {}
                Ok(HstsRead::Done) => return Ok(()),
                Ok(HstsRead::Abort) => return Err(PullError::Aborted),
                Ok(HstsRead::Invalid) | Err(BadEntry::Date) => return Err(PullError::Invalid),
                Err(BadEntry::OutOfMemory) => return Err(PullError::OutOfMemory),
            }
        }
    }

    /// Give every entry to the application's writer, until it says no
    /// more (`Curl_hsts_save`'s `hsts_push`); false if it said the save
    /// fails, or an entry's date could not be told.
    pub fn push(&self, writer: &dyn HstsWriter) -> bool {
        let mut ok = true;
        self.each(|entry, index, total| match entry {
            None => {
                ok = false;
                false
            }
            Some(entry) => match writer.write(entry, index, total) {
                HstsWrite::More => true,
                HstsWrite::Stop => false,
                HstsWrite::Fail => {
                    ok = false;
                    false
                }
            },
        });
        ok
    }

    /// Read `file` as each transfer starts, from now on.
    pub fn read_at_start(&mut self, file: &[u8]) -> Result<(), OutOfMemory> {
        let mut name = Vec::new();
        name.try_extend_from_slice(file)?;
        self.to_read.try_push(name)
    }

    /// Read the files named to be read as each transfer starts
    /// (`Curl_hsts_loadfiles`).
    pub fn load_named(&mut self, now: i64) -> Result<(), LoadError> {
        let files = std::mem::take(&mut self.to_read);
        let loaded = files.iter().try_for_each(|f| self.load(f, now));
        self.to_read = files;
        loaded
    }

    /// The file last read, if any.
    pub fn file(&self) -> Option<&[u8]> {
        self.file.as_deref()
    }

    /// The text of the file the cache is written as, every entry a line
    /// (`Curl_hsts_save`); one whose date `gmtime` cannot hold is left
    /// out.
    pub fn text(&self) -> Result<Vec<u8>, OutOfMemory> {
        let mut out = Vec::new();
        out.try_extend_from_slice(
            b"# Your HSTS cache. https://curl.se/docs/hsts.html\n\
              # This file was generated by libcurl! Edit at your own risk.\n",
        )?;
        for e in &self.entries {
            let Some(date) = Expire::of(e.expires) else {
                continue;
            };
            let dot: &[u8] = if e.subdomains { b"." } else { b"" };
            for part in [dot, &e.host[..], b" \"", date.bytes(), b"\"\n"] {
                out.try_extend_from_slice(part)?;
            }
        }
        Ok(out)
    }

    /// Each entry, in order, for the application; `None` for one whose
    /// date cannot be told, where C's write stops with an error.
    pub fn each(&self, mut f: impl FnMut(Option<HstsEntry<'_>>, usize, usize) -> bool) {
        let total = self.entries.len();
        for (index, e) in self.entries.iter().enumerate() {
            let date = Expire::of(e.expires);
            let entry = date.as_ref().map(|d| HstsEntry {
                name: &e.host,
                expire: d.bytes(),
                subdomains: e.subdomains,
            });
            if !f(entry, index, total) {
                break;
            }
        }
    }

    /// A copy of the entries alive at `now`, for a copy of the handle
    /// (`Curl_hsts_copy`); the file read is not the copy's.
    pub fn alive_copy(&self, now: i64) -> Result<Hsts, OutOfMemory> {
        let mut copy = Hsts::default();
        for e in self.entries.iter().filter(|e| e.expires > now) {
            copy.create(&e.host, e.subdomains, e.expires)?;
        }
        Ok(copy)
    }

    /// Keep `other`'s entries after these, as they are (`Curl_hsts_copy`
    /// into a cache that read its own first).
    pub fn merge(&mut self, other: Hsts) -> Result<(), OutOfMemory> {
        for e in other.entries {
            self.create(&e.host, e.subdomains, e.expires)?;
        }
        Ok(())
    }

    /// How many files are read as each transfer starts.
    pub fn files_to_read(&self) -> usize {
        self.to_read.len()
    }

    /// How many entries it keeps.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// An expiry as files and the application read it: `YYYYMMDD HH:MM:SS`,
/// or `unlimited`.
struct Expire {
    text: [u8; MAX_DATE_LEN],
    len: usize,
}

impl Expire {
    /// `None` for a time `gmtime` cannot hold.
    fn of(expires: i64) -> Option<Expire> {
        let mut out = Expire {
            text: [0; MAX_DATE_LEN],
            len: 0,
        };
        if expires == UNLIMITED {
            out.text[..9].copy_from_slice(b"unlimited");
            out.len = 9;
            return Some(out);
        }
        let d = HttpDate::of(expires).ok()?;
        let mut w = Writer(&mut out);
        d.write_hsts(&mut w).ok()?;
        Some(out)
    }

    fn bytes(&self) -> &[u8] {
        &self.text[..self.len]
    }
}

struct Writer<'a>(&'a mut Expire);

impl fmt::Write for Writer<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let e = &mut *self.0;
        let end = e.len + s.len();
        e.text
            .get_mut(e.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(s.as_bytes());
        e.len = end;
        Ok(())
    }
}

/// A file's line, `host "date"`, read as C reads it (`hsts_add`): a word,
/// one space, a quoted date, then the line's end.
fn file_line(line: &[u8]) -> Option<HstsEntry<'_>> {
    let host_len = line
        .iter()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(line.len());
    if host_len == 0 || host_len > MAX_HOST_LEN {
        return None;
    }
    let (host, rest) = line.split_at(host_len);
    let rest = rest.strip_prefix(b" ")?;
    let (date, rest) = quoted(rest, MAX_DATE_LEN)?;
    let rest = rest.strip_prefix(b"\r").unwrap_or(rest);
    if !(rest.is_empty() || rest == b"\n") {
        return None;
    }
    Some(HstsEntry {
        name: host,
        expire: date,
        subdomains: false,
    })
}

/// A word in double quotes at the start of `s`, no longer than `max`,
/// and what follows it (`curlx_str_quotedword`).
fn quoted(s: &[u8], max: usize) -> Option<(&[u8], &[u8])> {
    let s = s.strip_prefix(b"\"")?;
    let end = s.iter().position(|&b| b == b'"')?;
    (end <= max).then(|| (&s[..end], &s[end + 1..]))
}

/// What a header's directives say.
#[derive(Default)]
struct Directives {
    max_age: Option<i64>,
    subdomains: bool,
}

/// The directives of a `Strict-Transport-Security:` header, read as C
/// reads them (`Curl_hsts_parse`).
fn directives(header: &[u8]) -> Result<Directives, StsError> {
    let blank = |b: &u8| *b == b' ' || *b == b'\t';
    let mut d = Directives::default();
    let mut p = header;
    loop {
        // Blanks and empty directives.
        loop {
            p = &p[p.iter().take_while(|b| blank(b)).count()..];
            match p.strip_prefix(b";") {
                Some(rest) => p = rest,
                None => break,
            }
        }
        let word_len = p.iter().take_while(|b| !b";=\r\n \t".contains(b)).count();
        if word_len == 0 {
            break;
        }
        let (word, rest) = p.split_at(word_len);
        p = &rest[rest.iter().take_while(|b| blank(b)).count()..];
        let mut value = None;
        if let Some(rest) = p.strip_prefix(b"=") {
            p = &rest[rest.iter().take_while(|b| blank(b)).count()..];
            if p.first() == Some(&b'"') {
                let Some((v, rest)) = quoted(p, MAX_LINE) else {
                    break;
                };
                value = Some(v);
                p = rest;
            } else {
                let len = p.iter().take_while(|b| !b", ;\r\n".contains(b)).count();
                if len == 0 {
                    break;
                }
                value = Some(&p[..len]);
                p = &p[len..];
            }
        }
        if let Some(v) = value.filter(|_| word.eq_ignore_ascii_case(b"max-age")) {
            if d.max_age.is_some() {
                return Err(StsError::Illegal);
            }
            d.max_age = Some(max_age(v)?);
        } else if word.eq_ignore_ascii_case(b"includesubdomains") {
            if d.subdomains {
                return Err(StsError::Illegal);
            }
            d.subdomains = true;
        }
        if p.is_empty() {
            break;
        }
    }
    Ok(d)
}

/// A `max-age` value: the number it starts with, past two years two years
/// (`curlx_str_number`, `CAP_HSTS_MAX_AGE`).
fn max_age(v: &[u8]) -> Result<i64, StsError> {
    let digits = v.iter().take_while(|b| b.is_ascii_digit());
    let mut n: i64 = 0;
    let mut any = false;
    for &d in digits {
        any = true;
        n = n * 10 + i64::from(d - b'0');
        if n > CAP_MAX_AGE {
            return Ok(CAP_MAX_AGE);
        }
    }
    if any { Ok(n) } else { Err(StsError::Illegal) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_728_465_947;

    fn names(h: &Hsts) -> Vec<(String, bool, i64)> {
        h.entries
            .iter()
            .map(|e| {
                (
                    String::from_utf8_lossy(&e.host).into_owned(),
                    e.subdomains,
                    e.expires,
                )
            })
            .collect()
    }

    /// Headers taken or refused, and what is kept after them, as C's
    /// `Curl_hsts_parse` and `hsts_check` have them.
    #[test]
    fn headers_are_taken_as_c_takes_them() {
        let mut h = Hsts::default();
        let mut parse = |host: &str, header: &str| h.parse(host.as_bytes(), header.as_bytes(), NOW);
        assert_eq!(parse("example.com", "max-age=31536000"), Ok(()));
        assert_eq!(parse("example.com", "max-age=\"21536000\""), Ok(()));
        assert_eq!(
            parse("example.com", "max-age=\"21536000"),
            Err(StsError::Illegal)
        );
        assert_eq!(
            parse("example.org", "max-age=\"21536000\"; includeSubDomains"),
            Ok(())
        );
        assert_eq!(parse("example.net", "max-age=0; includeSubDomains"), Ok(()));
        assert_eq!(parse("example.net", "max-age=-1"), Err(StsError::Illegal));
        assert_eq!(parse("example.net", ""), Err(StsError::Illegal));
        assert_eq!(
            parse("example.net", "includeSubDomains; includeSubDomains"),
            Err(StsError::Illegal)
        );
        assert_eq!(
            parse("example.net", "max-age=1; max-age=2"),
            Err(StsError::Illegal)
        );
        assert_eq!(parse("this.example", "max-age  = 1000"), Ok(()));
        assert_eq!(parse("big.example", "max-age=99999999999999999999"), Ok(()));
        assert_eq!(
            parse("127.0.0.1", "max-age=1000"),
            Ok(()),
            "an address is none"
        );
        assert_eq!(parse("anything", "; ; ;max-age=10;"), Ok(()));
        let kept = names(&h);
        assert_eq!(
            kept,
            [
                ("example.com".into(), false, NOW + 21_536_000),
                ("example.org".into(), true, NOW + 21_536_000),
                ("this.example".into(), false, NOW + 1000),
                ("big.example".into(), false, NOW + CAP_MAX_AGE),
                ("anything".into(), false, NOW + 10),
            ]
        );
        assert!(h.applies(b"example.com", NOW));
        assert!(h.applies(b"EXAMPLE.COM.", NOW), "any case, a trailing dot");
        assert!(!h.applies(b"www.example.com", NOW), "no subdomains");
        assert!(h.applies(b"www.example.org", NOW), "subdomains");
        assert!(!h.applies(b"xexample.org", NOW), "a label's end only");
        assert!(!h.applies(b"anything", NOW + 10), "expired");
        assert_eq!(h.len(), 4, "the expired one went");
        // max-age=0 drops the host's own entry, not one including it.
        h.parse(b"www.example.org", b"max-age=0", NOW).unwrap();
        assert!(h.applies(b"www.example.org", NOW));
        h.parse(b"example.org", b"max-age=0", NOW).unwrap();
        assert!(!h.applies(b"www.example.org", NOW));
    }

    /// unit1660: a cache read from test 1660's file, then headers taken or
    /// refused and hosts looked up in turn, printed as the C program
    /// prints them, and the cache written back.
    #[test]
    fn unit1660_hsts_parses_checks_and_saves_as_c() {
        let now: i64 = 1_548_369_261;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("curl-core-hsts1660-{}", std::process::id()));
        std::fs::write(
            &path,
            "# Your HSTS cache. https://curl.se/docs/hsts.html\n\
             # This file was generated by libcurl! Edit at your own risk.\n\
             .readfrom.example \"20211001 04:47:41\"\n\
             .old.example \"20161001 04:47:41\"\n\
             .new.example \"unlimited\"\n",
        )
        .unwrap();
        let mut h = Hsts::default();
        h.load(path.as_os_str().as_encoded_bytes(), now).unwrap();
        std::fs::remove_file(&path).unwrap();
        let rows: &[(&str, Option<&str>, Option<&str>, bool)] = &[
            ("-", Some("readfrom.example"), None, true),
            ("-", Some("old.example"), None, true),
            ("readfrom.example", None, Some("max-age=\"0\""), true),
            ("example.com", None, Some("max-age=\"31536000\"\r\n"), true),
            ("example.com", None, Some("max-age=\"21536000\"\r\n"), true),
            (
                "example.com",
                None,
                Some("max-age=\"21536000\"; \r\n"),
                true,
            ),
            (
                "example.com",
                None,
                Some("max-age=\"21536000\"; includeSubDomains\r\n"),
                true,
            ),
            ("example.org", None, Some("max-age=\"31536000\"\r\n"), true),
            ("this.example", None, Some("max=\"31536\";"), false),
            ("this.example", None, Some("max-age=\"31536"), false),
            ("this.example", None, Some("max-age=31536\""), true),
            ("this.example", None, Some("max-age=0"), true),
            ("another.example", None, Some("includeSubDomains; "), false),
            (
                "example.com",
                None,
                Some("max-age=\"21536000\"; includeSubDomains; max-age=\"3\";"),
                false,
            ),
            (
                "2.example.com",
                None,
                Some("max-age=\"21536000\"; includeSubDomains; includeSubDomains;"),
                false,
            ),
            (
                "3.example.com",
                None,
                Some("max-age=\"21536000\"; include; includeSubDomains;"),
                true,
            ),
            (
                "3.example.com",
                None,
                Some("max-age=\"0\"; includeSubDomains;"),
                true,
            ),
            ("-", Some("foo.example.com"), None, true),
            ("-", Some("foo.xample.com"), None, true),
            (
                "example.net",
                Some("forexample.net"),
                Some("max-age=\"31536000\"\r\n"),
                true,
            ),
            (
                "example.net",
                Some("forexample.net"),
                Some("max-age=\"31536000\"; includeSubDomains\r\n"),
                true,
            ),
            (
                "example.net",
                None,
                Some("max-age=\"0\"; includeSubDomains\r\n"),
                true,
            ),
            ("expire.example", None, Some("max-age=\"7\"\r\n"), true),
        ];
        let mut out = Vec::new();
        let show = |h: &mut Hsts, chost: &str, now: i64, out: &mut Vec<String>| match h.check(
            chost.as_bytes(),
            true,
            now,
        ) {
            None => out.push(format!("'{chost}' is not HSTS")),
            Some(at) => {
                let e = &h.entries[at];
                let sub = if e.subdomains {
                    " includeSubDomains"
                } else {
                    ""
                };
                let host = String::from_utf8_lossy(&e.host);
                out.push(format!("{chost} [{host}]: {}{sub}", e.expires));
            }
        };
        for (i, &(host, chost, hdr, ok)) in rows.iter().enumerate() {
            if let Some(hdr) = hdr {
                let r = h.parse(host.as_bytes(), hdr.as_bytes(), now);
                assert_eq!(r.is_ok(), ok, "row {i}");
                if r.is_err() {
                    out.push(format!("Input {i}: error 43"));
                    continue;
                }
            }
            show(&mut h, chost.unwrap_or(host), now, &mut out);
        }
        h.parse(
            b"prefix.example",
            b"max-age=60; includeSubDomainsExtra",
            now,
        )
        .unwrap();
        assert!(h.check(b"child.prefix.example", true, now).is_none());
        h.parse(b"prefix.example", b"max-age=0", now).unwrap();
        h.parse(b"unknown.example", b"max-age-extra=1; max-age=60", now)
            .unwrap();
        assert!(h.check(b"unknown.example", false, now).is_some());
        h.parse(b"unknown.example", b"max-age=0", now).unwrap();
        out.push(format!("Number of entries: {}", h.len()));
        for delta in 0..10 {
            show(&mut h, "expire.example", now + delta, &mut out);
        }
        let want = "readfrom.example [readfrom.example]: 1633063661 includeSubDomains
'old.example' is not HSTS
'readfrom.example' is not HSTS
example.com [example.com]: 1579905261
example.com [example.com]: 1569905261
example.com [example.com]: 1569905261
example.com [example.com]: 1569905261 includeSubDomains
example.org [example.org]: 1579905261
Input 8: error 43
Input 9: error 43
this.example [this.example]: 1548400797
'this.example' is not HSTS
Input 12: error 43
Input 13: error 43
Input 14: error 43
3.example.com [3.example.com]: 1569905261 includeSubDomains
3.example.com [example.com]: 1569905261 includeSubDomains
foo.example.com [example.com]: 1569905261 includeSubDomains
'foo.xample.com' is not HSTS
'forexample.net' is not HSTS
'forexample.net' is not HSTS
'example.net' is not HSTS
expire.example [expire.example]: 1548369268
Number of entries: 4
expire.example [expire.example]: 1548369268
expire.example [expire.example]: 1548369268
expire.example [expire.example]: 1548369268
expire.example [expire.example]: 1548369268
expire.example [expire.example]: 1548369268
expire.example [expire.example]: 1548369268
expire.example [expire.example]: 1548369268
'expire.example' is not HSTS
'expire.example' is not HSTS
'expire.example' is not HSTS";
        assert_eq!(out.join("\n"), want);
        assert_eq!(
            String::from_utf8(h.text().unwrap()).unwrap(),
            "# Your HSTS cache. https://curl.se/docs/hsts.html\n\
             # This file was generated by libcurl! Edit at your own risk.\n\
             .new.example \"unlimited\"\n\
             .example.com \"20191001 04:47:41\"\n\
             example.org \"20200124 22:34:21\"\n"
        );
    }

    /// A file's lines are read as C reads them, an entry kept unless
    /// expired or kept already, in which case the later expiry and the
    /// wider reach win; it is written back as C writes it.
    #[test]
    fn a_file_is_read_and_written_as_c_does() {
        let mut h = Hsts::default();
        let add = |h: &mut Hsts, name: &str, expire: &str| {
            let line = format!("{name} \"{expire}\"\n");
            if let Some(e) = file_line(line.as_bytes()) {
                h.add(e, NOW).unwrap();
            }
        };
        add(&mut h, "this.example", "99991001 04:47:41");
        add(&mut h, "expired.example", "20011001 04:47:41");
        add(&mut h, ".sub.example", "unlimited");
        add(&mut h, "this.example", "20991001 04:47:41");
        add(&mut h, ".this.example", "20991001 04:47:41");
        add(&mut h, "dotted.example.", "99991001 04:47:41");
        assert!(file_line(b"no-date").is_none());
        assert!(
            file_line(b"two  \"20991001 04:47:41\"\n").is_none(),
            "one space"
        );
        assert!(file_line(b"long \"200001010 04:47:41\"\n").is_none());
        assert_eq!(
            h.add(
                HstsEntry {
                    name: b"x",
                    expire: b"200001010 04:47:41",
                    subdomains: false
                },
                NOW
            ),
            Err(BadEntry::Date)
        );
        let text = String::from_utf8(h.text().unwrap()).unwrap();
        assert_eq!(
            text,
            "# Your HSTS cache. https://curl.se/docs/hsts.html\n\
             # This file was generated by libcurl! Edit at your own risk.\n\
             .this.example \"99991001 04:47:41\"\n\
             .sub.example \"unlimited\"\n\
             dotted.example \"99991001 04:47:41\"\n"
        );
        let copy = h.alive_copy(NOW).unwrap();
        assert_eq!(names(&copy), names(&h));
        assert!(
            h.alive_copy(i64::MAX - 1).unwrap().len() == 1,
            "the unlimited one"
        );
    }
}
