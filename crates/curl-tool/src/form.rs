//! `--form` and `--form-string` (`src/tool_formparse.c`): each argument
//! read into the tool's own tree of parts as it is given, and the tree
//! made a `curl_core::mime::Mime` for each transfer (`tool2curlmime`).

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::num::NonZeroUsize;
use std::sync::Mutex;

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_format};
use curl_core::error::ErrorKind;
use curl_core::handler::{Handler, Read, ReadHandler, Rewind, RewindFailed};
use curl_core::mime::{Boundary, Content, Encoder, FileData, FileError, Mime, Part};
use curl_core::multi::TransferCx;

use crate::easysrc::{self, Source, c_string};
use crate::msgs::Messages;

/// The most parts one level may have (`MAX_FORMPARTS`).
const MAX_PARTS: usize = 100_000;

/// The longest line of a file of headers, its zero byte counted
/// (`HEADER_LINE_BUFFER_SIZE`).
const HEADER_LINE: usize = 8192;

/// The parts the command line gives (C's `mimeroot` and `mimecurrent`).
#[derive(Debug, Default)]
pub(crate) struct Form {
    parts: Vec<ToolPart>,
    /// Where the next part goes: the parts `=(` opened and `=)` has not
    /// closed, each an index into the level above it.
    open: Vec<usize>,
}

/// A part as the command line gives it (`struct tool_mime`).
#[derive(Debug)]
struct ToolPart {
    kind: Kind,
    name: Option<Vec<u8>>,
    filename: Option<Vec<u8>>,
    mime_type: Option<Vec<u8>>,
    encoder: Option<Vec<u8>>,
    headers: Vec<Vec<u8>>,
}

#[derive(Debug)]
enum Kind {
    /// Parts of its own (`TOOLMIME_PARTS`).
    Parts(Vec<ToolPart>),
    /// These bytes (`TOOLMIME_DATA`).
    Data(TryArc<Vec<u8>>),
    /// A file read as it is sent; one given with `@` is named after it
    /// (`TOOLMIME_FILE`), one with `<` is not (`TOOLMIME_FILEDATA`).
    File { path: Vec<u8>, named: bool },
    /// Standard input, `-` (`TOOLMIME_STDIN`, `TOOLMIME_STDINDATA`).
    Stdin { input: Stdin, named: bool },
}

/// Standard input as a part reads it.
#[derive(Debug)]
enum Stdin {
    /// Read whole as the option was given: it was no regular file.
    Read(TryArc<Vec<u8>>),
    /// A regular file, read as it is sent: `size` bytes from `origin`.
    File { origin: u64, size: u64 },
    /// Its reading failed before anything came: read as it is sent, as
    /// far as it goes.
    Unread,
}

/// A part given but not yet placed: what `get_param_part` reads.
struct Given {
    data: Vec<u8>,
    mime_type: Option<Vec<u8>>,
    filename: Option<Vec<u8>>,
    encoder: Option<Vec<u8>>,
    headers: Vec<Vec<u8>>,
    /// What ended it: `;` never, the end of the argument as 0.
    sep: u8,
    /// Where it ended.
    end: usize,
}

/// Which of a part's settings an argument may give.
#[derive(Clone, Copy)]
struct Allowed {
    mime_type: bool,
    filename: bool,
    encoder: bool,
}

const ALL: Allowed = Allowed {
    mime_type: true,
    filename: true,
    encoder: true,
};

/// Why an argument was not taken: it was said, and the option is badly
/// used.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refused;

impl From<OutOfMemory> for Refused {
    fn from(_: OutOfMemory) -> Refused {
        Refused
    }
}

fn copy(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_extend_from_slice(bytes)?;
    Ok(v)
}

/// The byte at `i`, or 0 past the end, as C reads its string.
fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

/// Whether `b` ends a word: `;`, `end` or the end of the string.
fn ends(b: u8, end: u8) -> bool {
    b == 0 || b == b';' || b == end
}

fn starts_with_nocase(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// A word of an argument from `p` (`get_param_word`): quoted, with `\\`
/// and `\"` undone and what follows up to the next `;` or `end` passed
/// over; else up to that. Whether it was quoted, and where it ended.
fn word(
    s: &[u8],
    p: usize,
    end: u8,
    msgs: &Messages,
) -> Result<(Vec<u8>, bool, usize), OutOfMemory> {
    if at(s, p) == b'"' {
        let mut i = p + 1;
        while at(s, i) != 0 {
            if s[i] == b'\\' && matches!(at(s, i + 1), b'\\' | b'"') {
                i += 2;
                continue;
            }
            if s[i] == b'"' {
                let quoted = &s[p + 1..i];
                let mut w = Vec::new();
                w.try_reserve_exact(quoted.len())?;
                let mut j = 0;
                while j < quoted.len() {
                    if quoted[j] == b'\\' && matches!(quoted.get(j + 1), Some(b'\\' | b'"')) {
                        j += 1;
                    }
                    w.try_push(quoted[j])?;
                    j += 1;
                }
                i += 1;
                let mut trailing = false;
                while !ends(at(s, i), end) {
                    trailing |= !is_space(s[i]);
                    i += 1;
                }
                if trailing {
                    msgs.warn(&[b"Trailing data after quoted form parameter"]);
                }
                return Ok((w, true, i));
            }
            i += 1;
        }
        // No closing quote: as if not quoted.
    }
    let mut i = p;
    while !ends(at(s, i), end) {
        i += 1;
    }
    Ok((copy(&s[p..i])?, false, i))
}

/// A word without the blanks after it, unless it was quoted.
fn trimmed(w: (Vec<u8>, bool, usize)) -> (Vec<u8>, usize) {
    let (mut w, quoted, i) = w;
    if !quoted {
        while w.last().is_some_and(|&b| is_blank(b)) {
            w.pop();
        }
    }
    (w, i)
}

/// Read one part's data and settings from `s` at `p`, up to `end`
/// (`get_param_part`), warning of settings not `allowed` here.
fn part(
    s: &[u8],
    mut p: usize,
    end: u8,
    allowed: Allowed,
    msgs: &Messages,
) -> Result<Given, Refused> {
    while is_blank(at(s, p)) {
        p += 1;
    }
    let (data, after) = trimmed(word(s, p, end, msgs)?);
    p = after;
    let mut sep = at(s, p);
    // The type, as where it starts and ends in `s`; a `;` after it
    // continues it until another setting comes.
    let mut mime_type: Option<(usize, usize)> = None;
    let mut type_open = false;
    let mut filename = None;
    let mut encoder = None;
    let mut headers = Vec::new();
    while sep == b';' {
        p += 1;
        while is_blank(at(s, p)) {
            p += 1;
        }
        let rest = &s[p.min(s.len())..];
        if !type_open && starts_with_nocase(rest, b"type=") {
            p += 5;
            while is_blank(at(s, p)) {
                p += 1;
            }
            let start = p;
            while at(s, p) != 0 && !b"()<>@,;:\\\"[]?=\r\n ".contains(&s[p]) {
                p += 1;
            }
            mime_type = Some((start, p));
            type_open = true;
            sep = at(s, p);
        } else if starts_with_nocase(rest, b"filename=") {
            type_open = false;
            p += 9;
            while is_blank(at(s, p)) {
                p += 1;
            }
            let (w, after) = trimmed(word(s, p, end, msgs)?);
            filename = Some(w);
            p = after;
            sep = at(s, p);
        } else if starts_with_nocase(rest, b"headers=") {
            type_open = false;
            p += 8;
            if matches!(at(s, p), b'@' | b'<') {
                p += 1;
                while is_blank(at(s, p)) {
                    p += 1;
                }
                let (file, after) = trimmed(word(s, p, end, msgs)?);
                p = after;
                sep = at(s, p);
                header_file(&file, &mut headers, msgs)?;
            } else {
                while is_blank(at(s, p)) {
                    p += 1;
                }
                let (h, after) = trimmed(word(s, p, end, msgs)?);
                p = after;
                sep = at(s, p);
                if headers.try_push(h).is_err() {
                    msgs.error(&[b"Out of memory for field header"]);
                    return Err(Refused);
                }
            }
        } else if starts_with_nocase(rest, b"encoder=") {
            type_open = false;
            p += 8;
            while is_blank(at(s, p)) {
                p += 1;
            }
            let (w, after) = trimmed(word(s, p, end, msgs)?);
            encoder = Some(w);
            p = after;
            sep = at(s, p);
        } else if type_open {
            // More of the type, without the blanks it ends with.
            let (start, _) = mime_type.expect("a type is open");
            let mut stop = p;
            while !ends(at(s, p), end) {
                if !is_blank(s[p]) {
                    stop = p + 1;
                }
                p += 1;
            }
            mime_type = Some((start, stop));
            sep = at(s, p);
        } else {
            let (w, _, after) = word(s, p, end, msgs)?;
            p = after;
            sep = at(s, p);
            if !w.is_empty() {
                msgs.warn(&[b"skip unknown form field: ", &w]);
            }
        }
    }
    let mime_type = mime_type
        .map(|(start, stop)| copy(&s[start..stop]))
        .transpose()?;
    let warn = |what: &[u8], value: &[u8]| msgs.warn(&[what, value]);
    let mime_type = match mime_type {
        Some(t) if !allowed.mime_type => {
            warn(b"Field content type not allowed here: ", &t);
            None
        }
        t => t,
    };
    let filename = match filename {
        Some(f) if !allowed.filename => {
            warn(b"Field filename not allowed here: ", &f);
            None
        }
        f => f,
    };
    let encoder = match encoder {
        Some(e) if !allowed.encoder => {
            warn(b"Field encoder not allowed here: ", &e);
            None
        }
        e => e,
    };
    Ok(Given {
        data,
        mime_type,
        filename,
        encoder,
        headers,
        sep,
        end: p,
    })
}

/// Add the headers of the file `name` to `headers` (`read_field_headers`):
/// a line by line, comments and blank lines passed over, a line starting
/// with a space joined to the one before. A file that cannot be opened is
/// warned of and passed over; one whose reading fails ends there, as C's
/// `fgets` ends it.
fn header_file(name: &[u8], headers: &mut Vec<Vec<u8>>, msgs: &Messages) -> Result<(), Refused> {
    let mut file = match curl_os::fs::with_c_name(name, curl_os::fs::open_read) {
        Ok(file) => file,
        Err(e) => {
            let why = crate::os_message(&e);
            msgs.warn(&[b"Cannot read from ", name, b": ", why.as_bytes()]);
            return Ok(());
        }
    };
    let mut text = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if text.try_extend_from_slice(&buf[..n]).is_err() {
                    msgs.error(&[b"Out of memory for field headers"]);
                    return Err(Refused);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    for line in text.split_inclusive(|&b| b == b'\n') {
        // A line and its newline fit the buffer C reads it into.
        if line.len() >= HEADER_LINE {
            msgs.error(&[b"Failed to read field headers"]);
            return Err(Refused);
        }
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        // C reads the line as a string.
        let line = &line[..line.iter().position(|&b| b == 0).unwrap_or(line.len())];
        // Comments and blank lines (`my_get_line`).
        match line.iter().find(|&&b| !is_blank(b)) {
            None | Some(b'#') => continue,
            Some(_) => {}
        }
        let folded = line[0] == b' ';
        let mut len = line.len();
        while len > 0 && matches!(line[len - 1], b'\r' | b'\n' | b' ' | b'\t') {
            len -= 1;
        }
        if len == 0 {
            continue;
        }
        let line = &line[..len];
        let added = match headers.last_mut() {
            Some(last) if folded => last.try_extend_from_slice(line),
            _ => copy(line).and_then(|l| headers.try_push(l)),
        };
        if added.is_err() {
            msgs.error(&[b"Out of memory for field headers"]);
            return Err(Refused);
        }
    }
    Ok(())
}

impl ToolPart {
    fn new(kind: Kind) -> ToolPart {
        ToolPart {
            kind,
            name: None,
            filename: None,
            mime_type: None,
            encoder: None,
            headers: Vec::new(),
        }
    }
}

/// A part of standard input (`tool_mime_new_filedata` for `-`): read now
/// unless it is a regular file. `Err` for a read that failed after some
/// of it came.
fn stdin_part(named: bool, msgs: &Messages) -> Result<Kind, Refused> {
    let mut file = curl_os::fs::stdin().ok();
    let regular = file.as_mut().and_then(|f| {
        let origin = f.stream_position().ok()?;
        let meta = f.metadata().ok()?;
        meta.is_file()
            .then(|| (origin, meta.len().saturating_sub(origin)))
    });
    let input = match (regular, file) {
        (Some((origin, size)), _) => Stdin::File { origin, size },
        (None, file) => {
            let mut data = Vec::new();
            let mut buf = [0u8; 4096];
            let failed = match file {
                None => true,
                Some(mut file) => loop {
                    match file.read(&mut buf) {
                        Ok(0) => break false,
                        Ok(n) => data.try_extend_from_slice(&buf[..n])?,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break true,
                    }
                },
            };
            match (failed, data.is_empty()) {
                (false, _) => Stdin::Read(TryArc::try_new(data)?),
                // Nothing came: read again as it is sent.
                (true, true) => Stdin::Unread,
                (true, false) => {
                    msgs.warn(&[b"error while reading standard input"]);
                    return Err(Refused);
                }
            }
        }
    };
    Ok(Kind::Stdin { input, named })
}

/// A part of the file `path`, or of standard input for `-`.
fn file_part(path: &[u8], named: bool, msgs: &Messages) -> Result<Kind, Refused> {
    if path == b"-" {
        return stdin_part(named, msgs);
    }
    Ok(Kind::File {
        path: copy(path)?,
        named,
    })
}

impl Form {
    /// The parts `=(` opened and not closed, the innermost last.
    fn level(&mut self) -> &mut Vec<ToolPart> {
        let mut level = &mut self.parts;
        for &i in &self.open {
            level = match &mut level[i].kind {
                Kind::Parts(parts) => parts,
                _ => unreachable!("an open part has parts"),
            };
        }
        level
    }

    /// Read one `--form` argument, or `--form-string`'s for `literal`
    /// (`formparse`): `Err` once it has been said why not.
    pub(crate) fn add(
        &mut self,
        input: &[u8],
        literal: bool,
        msgs: &Messages,
    ) -> Result<(), Refused> {
        let Some(eq) = input.iter().position(|&b| b == b'=') else {
            msgs.warn(&[b"Illegally formatted input field"]);
            return Err(Refused);
        };
        let name = (eq > 0).then(|| &input[..eq]).map(copy).transpose()?;
        let contp = &input[eq + 1..];
        if contp.first() == Some(&b'(') && !literal {
            // Parts of its own, to come.
            let only_type = Allowed {
                filename: false,
                encoder: false,
                ..ALL
            };
            let given = part(contp, 0, 0, only_type, msgs)?;
            let mut p = ToolPart::new(Kind::Parts(Vec::new()));
            p.headers = given.headers;
            p.mime_type = given.mime_type;
            p.name = name;
            let level = self.level();
            level.try_push(p)?;
            let at = level.len() - 1;
            self.open.try_push(at)?;
        } else if name.is_none() && contp == b")" && !literal {
            if self.open.pop().is_none() {
                msgs.warn(&[b"no multipart to terminate"]);
                return Err(Refused);
            }
        } else if contp.first() == Some(&b'@') && !literal {
            // Files, a part each in a part of them all, or one alone.
            let mut p = 0;
            let mut grouped = None;
            loop {
                p += 1;
                let given = part(contp, p, b',', ALL, msgs)?;
                let in_group = match grouped {
                    Some(g) => g,
                    None => {
                        let g = given.sep == b',';
                        if g {
                            self.level()
                                .try_push(ToolPart::new(Kind::Parts(Vec::new())))?;
                        }
                        grouped = Some(g);
                        g
                    }
                };
                let mut file = ToolPart::new(file_part(&given.data, true, msgs)?);
                file.headers = given.headers;
                file.filename = given.filename;
                file.mime_type = given.mime_type;
                file.encoder = given.encoder;
                let level = self.level();
                if in_group {
                    match &mut level.last_mut().expect("the group, added first").kind {
                        Kind::Parts(files) => files.try_push(file)?,
                        _ => unreachable!("the group has parts"),
                    }
                } else {
                    level.try_push(file)?;
                }
                p = given.end;
                if given.sep != b',' {
                    break;
                }
            }
            if name.is_some() {
                self.level().last_mut().expect("a part was added").name = name;
            }
        } else {
            let (mut p, sep, end) = if contp.first() == Some(&b'<') && !literal {
                let no_filename = Allowed {
                    filename: false,
                    ..ALL
                };
                let given = part(contp, 1, 0, no_filename, msgs)?;
                let mut p = ToolPart::new(file_part(&given.data, false, msgs)?);
                p.headers = given.headers;
                p.mime_type = given.mime_type;
                p.encoder = given.encoder;
                (p, given.sep, given.end)
            } else if literal {
                let data = TryArc::try_new(copy(contp)?)?;
                (ToolPart::new(Kind::Data(data)), 0, 0)
            } else {
                let given = part(contp, 0, 0, ALL, msgs)?;
                let mut p = ToolPart::new(Kind::Data(TryArc::try_new(given.data)?));
                p.headers = given.headers;
                p.filename = given.filename;
                p.mime_type = given.mime_type;
                p.encoder = given.encoder;
                (p, given.sep, given.end)
            };
            if sep != 0 {
                msgs.warn(&[b"garbage at end of field specification: ", &contp[end..]]);
            }
            p.name = name;
            self.level().try_push(p)?;
        }
        Ok(())
    }

    /// The tree a transfer sends (`tool2curlmime`): files looked at now,
    /// each level with a boundary of its own.
    pub(crate) fn mime(&self, msgs: &Messages) -> Result<Mime, ErrorKind> {
        to_mime(&self.parts, msgs)
    }

    /// The calls that build the tree, for `--libcurl`
    /// (`libcurl_generate_mime`): the number of its `curl_mime`.
    pub(crate) fn libcurl(&self, source: &mut Source) -> Result<u32, OutOfMemory> {
        libcurl_mime(&self.parts, source)
    }
}

/// The calls that make a `curl_mime` of `parts`, each part's after it.
fn libcurl_mime(parts: &[ToolPart], source: &mut Source) -> Result<u32, OutOfMemory> {
    let n = source.mime(!parts.is_empty())?;
    let num = try_format(format_args!("{n}"))?;
    for p in parts {
        libcurl_part(p, num.as_bytes(), source)?;
    }
    Ok(n)
}

/// The calls that make part `p` of `curl_mime` `n`
/// (`libcurl_generate_mime_part`): its content, then its encoder, file
/// name, name, type and headers.
fn libcurl_part(p: &ToolPart, n: &[u8], source: &mut Source) -> Result<(), OutOfMemory> {
    let part: &[u8] = b"part";
    source.code(&[part, n, b" = curl_mime_addpart(mime", n, b");"])?;
    let mut filename = p.filename.as_deref();
    match &p.kind {
        Kind::Parts(sub) => {
            let sub = try_format(format_args!("{}", libcurl_mime(sub, source)?))?;
            let sub = sub.as_bytes();
            source.code(&[b"curl_mime_subparts(part", n, b", mime", sub, b");"])?;
            // Freed with its parent, not at the end.
            source.code(&[b"mime", sub, b" = NULL;"])?;
        }
        Kind::Data(data) => {
            let data = easysrc::c_escape(c_string(data))?;
            source.code(&[
                b"curl_mime_data(part",
                n,
                b", \"",
                &data,
                b"\", CURL_ZERO_TERMINATED);",
            ])?;
        }
        Kind::File { path, named } => {
            let path = easysrc::c_escape(c_string(path))?;
            source.code(&[b"curl_mime_filedata(part", n, b", \"", &path, b"\");"])?;
            if !named && filename.is_none() {
                source.code(&[b"curl_mime_filename(part", n, b", NULL);"])?;
            }
        }
        Kind::Stdin { named, .. } => {
            if *named && filename.is_none() {
                filename = Some(b"-");
            }
            source.code(&[
                b"curl_mime_data_cb(part",
                n,
                b", -1, (curl_read_callback)fread, \\",
            ])?;
            source.code(&[b"                  (curl_seek_callback)fseek, NULL, stdin);"])?;
        }
    }
    let settings: [(&[u8], Option<&[u8]>); 4] = [
        (b"curl_mime_encoder(part", p.encoder.as_deref()),
        (b"curl_mime_filename(part", filename),
        (b"curl_mime_name(part", p.name.as_deref()),
        (b"curl_mime_type(part", p.mime_type.as_deref()),
    ];
    for (call, value) in settings {
        if let Some(value) = value {
            let value = easysrc::c_escape(c_string(value))?;
            source.code(&[call, n, b", \"", &value, b"\");"])?;
        }
    }
    if !p.headers.is_empty() {
        let list = source.slist(p.headers.iter().map(Vec::as_slice))?;
        let list = try_format(format_args!("{list}"))?;
        let list = list.as_bytes();
        source.code(&[b"curl_mime_headers(part", n, b", slist", list, b", 1);"])?;
        // Freed with the part.
        source.code(&[b"slist", list, b" = NULL;"])?;
    }
    Ok(())
}

/// The last part of a path, as POSIX `basename` gives it.
fn basename(path: &[u8]) -> &[u8] {
    let trimmed = match path.iter().rposition(|&b| b != b'/') {
        Some(end) => &path[..=end],
        None if path.is_empty() => return b".",
        None => return b"/",
    };
    match trimmed.iter().rposition(|&b| b == b'/') {
        Some(at) => &trimmed[at + 1..],
        None => trimmed,
    }
}

fn oom(_: OutOfMemory) -> ErrorKind {
    ErrorKind::OutOfMemory
}

/// A tree of `parts` (`tool2curlparts`).
fn to_mime(parts: &[ToolPart], msgs: &Messages) -> Result<Mime, ErrorKind> {
    let boundary = Boundary::random().map_err(|_| ErrorKind::OutOfMemory)?;
    let mut mime = Mime::new(boundary);
    if parts.len() > MAX_PARTS + 1 {
        return Err(ErrorKind::BadFunctionArgument);
    }
    for p in parts {
        let mut filename = p.filename.as_deref();
        let content = match &p.kind {
            Kind::Parts(sub) => Content::Parts(to_mime(sub, msgs)?),
            Kind::Data(d) => Content::Bytes(d.clone()),
            Kind::File { path, named } => {
                let file = match FileData::new(path) {
                    Ok(file) => file,
                    Err(FileError::Unreadable) => return Err(ErrorKind::ReadError),
                    Err(FileError::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
                };
                if *named && filename.is_none() {
                    filename = Some(basename(path));
                }
                Content::File(file)
            }
            Kind::Stdin { input, named } => {
                if *named && filename.is_none() {
                    filename = Some(b"-");
                }
                match input {
                    Stdin::Read(d) => Content::Bytes(d.clone()),
                    Stdin::File { origin, size } => stdin_content(*origin, Some(*size), msgs)?,
                    Stdin::Unread => stdin_content(0, None, msgs)?,
                }
            }
        };
        let encoder = match &p.encoder {
            None => None,
            Some(e) => Some(Encoder::from_name(e).ok_or(ErrorKind::BadFunctionArgument)?),
        };
        let mut headers = Vec::new();
        headers
            .try_reserve_exact(p.headers.len())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        for h in &p.headers {
            headers.try_push(copy(h).map_err(oom)?).map_err(oom)?;
        }
        let part = Part {
            name: p.name.as_deref().map(copy).transpose().map_err(oom)?,
            filename: filename.map(copy).transpose().map_err(oom)?,
            mime_type: p.mime_type.as_deref().map(copy).transpose().map_err(oom)?,
            headers,
            encoder,
            content,
            reached: curl_core::mime::Reached::default(),
        };
        mime.add(part).map_err(oom)?;
    }
    Ok(mime)
}

/// Standard input as it is sent: `size` bytes from `origin`, or as far as
/// it goes.
fn stdin_content(origin: u64, size: Option<u64>, msgs: &Messages) -> Result<Content, ErrorKind> {
    let file = curl_os::fs::stdin().map_err(|_| ErrorKind::ReadError)?;
    let state = TryArc::try_new(Mutex::new(StdinState { file, at: 0 })).map_err(oom)?;
    let reader = StdinPart {
        state,
        origin,
        size,
        msgs: *msgs,
    };
    let rewind = StdinPart {
        state: reader.state.clone(),
        origin,
        size,
        msgs: *msgs,
    };
    Ok(Content::Read {
        handler: Handler::read(reader).map_err(oom)?,
        rewind: Some(Handler::rewind(rewind).map_err(oom)?),
        size,
    })
}

#[derive(Debug)]
struct StdinState {
    file: File,
    /// How far into the part it is.
    at: u64,
}

/// Standard input read as a part (`tool_mime_stdin_read`), and started
/// over (`tool_mime_stdin_seek`).
struct StdinPart {
    state: TryArc<Mutex<StdinState>>,
    origin: u64,
    size: Option<u64>,
    msgs: Messages,
}

impl ReadHandler for StdinPart {
    fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> Read {
        let mut st = self.state.lock().expect("no panic holds it");
        let room = match self.size {
            Some(size) if st.at >= size => return Read::Eof,
            Some(size) => buf
                .len()
                .min(usize::try_from(size - st.at).unwrap_or(usize::MAX)),
            None => buf.len(),
        };
        loop {
            match st.file.read(&mut buf[..room]) {
                Ok(n) => {
                    st.at += n as u64;
                    return NonZeroUsize::new(n).map_or(Read::Eof, Read::Data);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    let why = crate::os_message(&e);
                    self.msgs
                        .warn(&[b"Failed to read from stdin: ", why.as_bytes()]);
                    return Read::Abort;
                }
            }
        }
    }
}

impl Rewind for StdinPart {
    fn rewind(&self, _: &mut TransferCx<'_>) -> Result<(), RewindFailed> {
        let mut st = self.state.lock().expect("no panic holds it");
        st.file
            .seek(SeekFrom::Start(self.origin))
            .map_err(|_| RewindFailed)?;
        st.at = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet() -> Messages {
        let mut msgs = Messages::new();
        msgs.silent = true;
        msgs
    }

    fn form(args: &[&str]) -> Form {
        let mut f = Form::default();
        for a in args {
            f.add(a.as_bytes(), false, &quiet()).expect("taken");
        }
        f
    }

    fn data(p: &ToolPart) -> &[u8] {
        match &p.kind {
            Kind::Data(d) => d,
            other => panic!("data, not {other:?}"),
        }
    }

    /// A `;` after a type goes on with it until another setting, with C's
    /// quirks: a lone `;` at the end is the type's, and a backslash ends
    /// it. Quoting undoes `\"` and `\\` in a word.
    #[test]
    fn a_type_runs_on_to_the_next_setting() {
        let f = form(&[
            "a=b;type=text/html;charset=u;filename=f;x=y",
            "c=d;type=t;",
            r#"e="q \" \\ v";type=m\n"#,
        ]);
        assert_eq!(
            f.parts[0].mime_type.as_deref(),
            Some(&b"text/html;charset=u"[..])
        );
        assert_eq!(f.parts[0].filename.as_deref(), Some(&b"f"[..]));
        assert_eq!(f.parts[1].mime_type.as_deref(), Some(&b"t;"[..]));
        assert_eq!(data(&f.parts[2]), br#"q " \ v"#);
        assert_eq!(
            f.parts[2].mime_type.as_deref(),
            Some(&b"m"[..]),
            "a backslash ends a type"
        );
    }

    /// Files after one `@` are a part of their own parts, the field's
    /// name on it; `=(` opens a level that `=)` closes, and a close
    /// without one open is refused.
    #[test]
    fn files_and_levels_nest_as_given() {
        let f = form(&[
            "a=@x;type=t,y",
            "b=(;type=multipart/alternative",
            "c=d",
            "=)",
            "e=f",
        ]);
        let Kind::Parts(files) = &f.parts[0].kind else {
            panic!("a group");
        };
        assert_eq!(f.parts[0].name.as_deref(), Some(&b"a"[..]));
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].mime_type.as_deref(), Some(&b"t"[..]));
        assert!(files[1].name.is_none());
        let Kind::Parts(inner) = &f.parts[1].kind else {
            panic!("a level");
        };
        assert_eq!(
            f.parts[1].mime_type.as_deref(),
            Some(&b"multipart/alternative"[..])
        );
        assert_eq!(inner[0].name.as_deref(), Some(&b"c"[..]));
        assert_eq!(f.parts[2].name.as_deref(), Some(&b"e"[..]));
        let mut f = Form::default();
        assert_eq!(f.add(b"=)", false, &quiet()), Err(Refused));
        assert_eq!(f.add(b"novalue", false, &quiet()), Err(Refused));
    }

    /// A file in the temporary directory, named for the test, holding
    /// `bytes`.
    fn scratch(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("curl-form-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn headers(p: &ToolPart) -> Vec<&[u8]> {
        p.headers.iter().map(Vec::as_slice).collect()
    }

    /// Blanks after `=`, `;` and each setting's name are passed over,
    /// the names in any case; an unquoted word loses the blanks after
    /// it, a quoted one keeps its own; an unknown setting and an empty
    /// one are passed over. As C's tool builds the parts of the same
    /// arguments.
    #[test]
    fn settings_are_read_as_c_reads_them() {
        let f = form(&[
            r#"a= "x\"y\\z" ;filename= "f g" ;Encoder= 8bit ;headers= X-H: v ;TYPE= t/u;p=1"#,
            "b=v ;filename= f ;encoder= base64",
            r#"c=" v ";unknown=1;  ;type=t"#,
            r#"d="v";type=t2 "#,
        ]);
        let a = &f.parts[0];
        assert_eq!(data(a), br#"x"y\z"#);
        assert_eq!(a.filename.as_deref(), Some(&b"f g"[..]));
        assert_eq!(a.encoder.as_deref(), Some(&b"8bit"[..]));
        assert_eq!(headers(a), [b"X-H: v"]);
        assert_eq!(a.mime_type.as_deref(), Some(&b"t/u;p=1"[..]));
        let b = &f.parts[1];
        assert_eq!(data(b), b"v");
        assert_eq!(b.filename.as_deref(), Some(&b"f"[..]));
        assert_eq!(b.encoder.as_deref(), Some(&b"base64"[..]));
        let c = &f.parts[2];
        assert_eq!(data(c), b" v ");
        assert_eq!(c.mime_type.as_deref(), Some(&b"t"[..]));
        assert_eq!(f.parts[3].mime_type.as_deref(), Some(&b"t2"[..]));
    }

    /// `=(` takes only a type; `<` takes no file name. A `)` with a name
    /// is data, not the end of a level; `<` read literally is data too.
    #[test]
    fn each_kind_of_part_takes_its_own_settings() {
        let file = scratch("kinds", b"F");
        let path = file.display();
        let f = form(&[
            "b=(;filename=x;encoder=y;type=multipart/mixed",
            "c=)",
            "=)",
            &format!("d=<{path};filename=x;type=t;encoder=binary"),
        ]);
        let b = &f.parts[0];
        assert!(b.filename.is_none() && b.encoder.is_none());
        assert_eq!(b.mime_type.as_deref(), Some(&b"multipart/mixed"[..]));
        let Kind::Parts(inner) = &b.kind else {
            panic!("a level");
        };
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0].name.as_deref(), Some(&b"c"[..]));
        assert_eq!(data(&inner[0]), b")");
        let d = &f.parts[1];
        let Kind::File { path: got, named } = &d.kind else {
            panic!("a file, not {:?}", d.kind);
        };
        assert_eq!(got, file.as_os_str().as_encoded_bytes());
        assert!(!named);
        assert!(d.filename.is_none());
        assert_eq!(d.mime_type.as_deref(), Some(&b"t"[..]));
        assert_eq!(d.encoder.as_deref(), Some(&b"binary"[..]));
        let mut f = Form::default();
        f.add(b"e=<x", true, &quiet()).unwrap();
        assert_eq!(data(&f.parts[0]), b"<x");
        std::fs::remove_file(&file).unwrap();
    }

    /// A file of headers: comments and blank lines passed over, a line
    /// starting with a space joined to the one before (or alone, first),
    /// trailing blanks and line ends cut; a line as long as C's buffer
    /// refused. As C's tool sends the same files.
    #[test]
    fn header_files_are_read_as_c_reads_them() {
        let lines = scratch(
            "headers",
            b"X-A: 1\n#c\n\n  \n\t# comment\nX-B: 2  \r\n folded\t\r\n\r\n \r\n\tX-T: tab\nX-C:3",
        );
        let lead = scratch("lead", b" lead\n");
        let mut longest = b"X-L: ".to_vec();
        longest.resize(8190, b'v');
        longest.push(b'\n');
        let fits = scratch("fits", &longest);
        longest.insert(5, b'v');
        let too_long = scratch("too-long", &longest);
        let f = form(&[
            &format!("a=b;headers=@{}", lines.display()),
            &format!(
                "a=b;headers=< {};headers=@{}",
                lead.display(),
                fits.display()
            ),
        ]);
        assert_eq!(
            headers(&f.parts[0]),
            [&b"X-A: 1"[..], b"X-B: 2 folded", b"\tX-T: tab", b"X-C:3"]
        );
        let got = headers(&f.parts[1]);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], b" lead");
        assert_eq!(got[1], &longest[..8190]);
        let mut refused = Form::default();
        let arg = format!("a=b;headers=@{}", too_long.display());
        assert_eq!(refused.add(arg.as_bytes(), false, &quiet()), Err(Refused));
        for p in [lines, lead, fits, too_long] {
            std::fs::remove_file(p).unwrap();
        }
    }

    /// POSIX `basename`, which C's tool names a file part with.
    #[test]
    fn basename_is_posix_s() {
        let table: &[(&[u8], &[u8])] = &[
            (b"", b"."),
            (b"/", b"/"),
            (b"///", b"/"),
            (b"a", b"a"),
            (b"a/b", b"b"),
            (b"/a/bc/", b"bc"),
            (b"/a//", b"a"),
        ];
        for &(path, base) in table {
            assert_eq!(
                basename(path),
                base,
                "{:?}",
                path.escape_ascii().to_string()
            );
        }
    }

    /// A file given with `@` is named after it unless a name is given;
    /// one with `<`, and standard input with `<`, are not; standard input
    /// with `@` is named `-`. Each file after one `@` takes its own
    /// settings.
    #[test]
    fn parts_are_named_as_c_names_them() {
        let one = scratch("one.txt", b"1");
        let two = scratch("two.html", b"2");
        let mut f = form(&[
            &format!("e=@{},{};filename=g", one.display(), two.display()),
            &format!("i=@{}", one.display()),
            &format!("j=@{};filename=k", two.display()),
            &format!("l=<{}", one.display()),
        ]);
        for named in [true, false] {
            let mut p = ToolPart::new(Kind::Stdin {
                input: Stdin::Read(TryArc::try_new(b"in".to_vec()).unwrap()),
                named,
            });
            p.name = Some(b"s".to_vec());
            f.parts.push(p);
        }
        let mime = f.mime(&quiet()).unwrap();
        let parts = mime.parts();
        let Content::Parts(group) = &parts[0].content else {
            panic!("a group");
        };
        let base = |p: &std::path::Path| p.file_name().unwrap().as_encoded_bytes().to_vec();
        assert_eq!(parts[0].name.as_deref(), Some(&b"e"[..]));
        assert_eq!(group.parts()[0].filename, Some(base(&one)));
        assert_eq!(group.parts()[1].filename.as_deref(), Some(&b"g"[..]));
        assert_eq!(parts[1].filename, Some(base(&one)));
        assert_eq!(parts[2].filename.as_deref(), Some(&b"k"[..]));
        assert!(parts[3].filename.is_none());
        assert_eq!(parts[4].filename.as_deref(), Some(&b"-"[..]));
        assert!(parts[5].filename.is_none());
        let Content::Bytes(stdin) = &parts[5].content else {
            panic!("bytes");
        };
        assert_eq!(&stdin[..], b"in");
        std::fs::remove_file(one).unwrap();
        std::fs::remove_file(two).unwrap();
    }

    /// One more part than `MAX_FORMPARTS` is taken, as C counts them;
    /// two more are refused.
    #[test]
    fn a_level_holds_as_many_parts_as_c_s() {
        let d = TryArc::try_new(Vec::new()).unwrap();
        let mut f = Form::default();
        for _ in 0..=MAX_PARTS {
            f.parts.push(ToolPart::new(Kind::Data(d.clone())));
        }
        assert_eq!(f.mime(&quiet()).unwrap().parts().len(), MAX_PARTS + 1);
        f.parts.push(ToolPart::new(Kind::Data(d)));
        assert_eq!(f.mime(&quiet()).err(), Some(ErrorKind::BadFunctionArgument));
    }

    /// A file of headers whose reading fails, a directory here, ends
    /// where it fails: C's `fgets` reads that as the end of the file,
    /// and the part is taken without them.
    #[test]
    fn a_header_file_that_cannot_be_read_ends_there() {
        let dir = std::env::temp_dir();
        let arg = format!("a=b;headers=@{}", dir.display());
        let f = form(&[&arg]);
        assert_eq!(data(&f.parts[0]), b"b");
        assert!(f.parts[0].headers.is_empty());
    }

    /// The calls `--libcurl` writes for a tree, as C's tool writes them
    /// (its output for the same `-F` arguments): each part's content,
    /// then its encoder, file name, name, type and headers, a level's
    /// parts in a `curl_mime` of their own.
    #[test]
    fn writes_the_tree_as_c_does() {
        let f = form(&[
            "a=b",
            "c=<up.txt",
            "d=@up.txt;filename=x;type=t/t;encoder=8bit",
            "g=@h.txt;headers=X: 1",
            "h=(;type=multipart/alternative",
            "i=j",
            "=)",
        ]);
        let mut source = Source::default();
        assert_eq!(f.libcurl(&mut source).unwrap(), 1);
        let mut text = Vec::new();
        source.finish_into(&mut text);
        let text = String::from_utf8(text).unwrap();
        let start = text.find("  mime1 = curl_mime_init").unwrap();
        let end = text.find("  curl_easy_cleanup").unwrap();
        assert_eq!(
            &text[start..end],
            "  mime1 = curl_mime_init(curl);
  part1 = curl_mime_addpart(mime1);
  curl_mime_data(part1, \"b\", CURL_ZERO_TERMINATED);
  curl_mime_name(part1, \"a\");
  part1 = curl_mime_addpart(mime1);
  curl_mime_filedata(part1, \"up.txt\");
  curl_mime_filename(part1, NULL);
  curl_mime_name(part1, \"c\");
  part1 = curl_mime_addpart(mime1);
  curl_mime_filedata(part1, \"up.txt\");
  curl_mime_encoder(part1, \"8bit\");
  curl_mime_filename(part1, \"x\");
  curl_mime_name(part1, \"d\");
  curl_mime_type(part1, \"t/t\");
  part1 = curl_mime_addpart(mime1);
  curl_mime_filedata(part1, \"h.txt\");
  curl_mime_name(part1, \"g\");
  curl_mime_headers(part1, slist1, 1);
  slist1 = NULL;
  part1 = curl_mime_addpart(mime1);
  mime2 = curl_mime_init(curl);
  part2 = curl_mime_addpart(mime2);
  curl_mime_data(part2, \"j\", CURL_ZERO_TERMINATED);
  curl_mime_name(part2, \"i\");
  curl_mime_subparts(part1, mime2);
  mime2 = NULL;
  curl_mime_name(part1, \"h\");
  curl_mime_type(part1, \"multipart/alternative\");
"
        );
        assert!(text.contains("  curl_mime *mime1;\n  curl_mimepart *part1;\n  struct curl_slist *slist1;\n  curl_mime *mime2;\n  curl_mimepart *part2;\n"));
        assert!(text.contains("  slist1 = curl_slist_append(slist1, \"X: 1\");\n"));
    }

    /// `--form-string` takes the value as it is.
    #[test]
    fn a_string_is_taken_as_it_is() {
        let mut f = Form::default();
        f.add(b"a=@x;type=y", true, &quiet()).unwrap();
        assert_eq!(data(&f.parts[0]), b"@x;type=y");
        assert!(f.parts[0].mime_type.is_none());
    }
}
