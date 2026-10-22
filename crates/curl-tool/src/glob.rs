//! URL globbing (`tool_urlglob.c`): `{a,b}` sets and `[1-9]` or `[a-z]`
//! ranges in a URL, which expand it into the URL of every combination,
//! and the `#N` and `#<name>` references an output file name makes to
//! them.

use curl_alloc::{OutOfMemory, TryVec as _, try_format};
use curl_core::error::{ErrorKind, UrlErrorKind};
use curl_core::url::{ParseOptions, Url};

use crate::msgs::Messages;
use crate::options::exit_code;

/// The most patterns a URL may have, its fixed parts counted (`add_glob`).
const MAX_PATTERNS: usize = 255;
/// The most elements a set may have.
const MAX_SET: usize = 100_000;
/// The longest name a pattern may have (`MAX_GLOBNAME_LEN`).
const MAX_NAME: usize = 64;
/// The most of an error's message shown (`glob_show_error`'s buffer).
const TEXT_MAX: usize = 511;
/// The longest IPv6 literal a `[` may start (`MAX_IP6LEN`).
const MAX_IP6: usize = 128;

/// A URL's patterns, in order, and where the expansion is.
pub(crate) struct Glob {
    items: Vec<Item>,
    /// The first URL was made.
    started: bool,
}

struct Item {
    kind: Kind,
    /// The pattern's number among those that are not fixed text, from
    /// zero, for `#N`.
    index: Option<usize>,
    /// `{<name>...}` or `[<name>...]`, for `#<name>`.
    name: Option<Vec<u8>>,
}

enum Kind {
    /// A set, or fixed text as a set of one.
    Set { elems: Vec<Vec<u8>>, at: usize },
    /// `[a-z]` with a step.
    Letters {
        min: u32,
        max: u32,
        step: u32,
        at: u32,
    },
    /// `[1-9]` with a step, padded with zeros to `pad` digits.
    Numbers {
        min: i64,
        max: i64,
        step: i64,
        at: i64,
        pad: usize,
    },
}

/// Why a pattern was refused: the error, and what to show of it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GlobError {
    pub(crate) kind: ErrorKind,
    /// The message, if there is one to show; running out of memory has
    /// none.
    what: Option<&'static str>,
    /// The column it is about, from 1, or 0 for none.
    pos: usize,
}

impl GlobError {
    fn new(what: &'static str, pos: usize, kind: ErrorKind) -> GlobError {
        GlobError {
            kind,
            what: Some(what),
            pos,
        }
    }

    fn malformed(what: &'static str, pos: usize) -> GlobError {
        GlobError::new(what, pos, ErrorKind::UrlMalformat)
    }

    /// The message about `text`, the pattern refused, with a caret under
    /// the column if there is one (`glob_show_error`).
    pub(crate) fn show(&self, text: &[u8], msgs: &Messages) {
        let Some(what) = self.what else {
            return;
        };
        // Out of memory, the message is lost and the error stays.
        let _ = self.try_show(what, text, msgs);
    }

    fn try_show(&self, what: &str, text: &[u8], msgs: &Messages) -> Result<(), OutOfMemory> {
        let mut message = Vec::new();
        message.try_extend_from_slice(what.as_bytes())?;
        if self.pos > 0 {
            let head = try_format(format_args!(" in position {}:\n", self.pos))?;
            message.try_extend_from_slice(head.as_bytes())?;
            message.try_extend_from_slice(text)?;
            // The caret under the column: C pads one blank to `pos - 1`.
            let caret = try_format(format_args!("\n{:>width$}^", " ", width = self.pos - 1))?;
            message.try_extend_from_slice(caret.as_bytes())?;
        }
        // C formats it into a buffer of `TEXT_MAX` bytes and its zero.
        message.truncate(TEXT_MAX);
        let code = try_format(format_args!("curl: ({}) ", exit_code(self.kind)))?;
        msgs.error_line(&[code.as_bytes(), &message, b"\n"]);
        Ok(())
    }
}

impl From<OutOfMemory> for GlobError {
    fn from(OutOfMemory: OutOfMemory) -> GlobError {
        GlobError {
            kind: ErrorKind::OutOfMemory,
            what: None,
            pos: 0,
        }
    }
}

/// Whether `url` has anything a glob would read (`glob_url`'s check): one
/// without is taken as it is.
pub(crate) fn has_patterns(url: &[u8]) -> bool {
    url.iter().any(|b| b"{}[]".contains(b))
}

impl Glob {
    /// An expansion of no patterns: a URL taken as it is, whose output
    /// name still reads its references.
    pub(crate) fn literal() -> Glob {
        Glob {
            items: Vec::new(),
            started: false,
        }
    }

    /// `url`'s patterns, and how many URLs they make (`glob_url`).
    pub(crate) fn parse(url: &[u8]) -> Result<(Glob, i64), GlobError> {
        let mut glob = Glob::literal();
        let amount = glob.parse_all(url)?;
        Ok((glob, amount))
    }

    /// `glob_parse`: fixed text up to each `{` or `[`, and the pattern
    /// it starts.
    fn parse_all(&mut self, url: &[u8]) -> Result<i64, GlobError> {
        let mut amount: i64 = 1;
        let mut text = Vec::new();
        let mut at = 0;
        let mut pos = 1;
        let mut index = 0;
        while at < url.len() {
            while at < url.len() && url[at] != b'{' {
                let c = url[at];
                if c == b'[' {
                    // An IPv6 literal, or `[]`, is fixed text.
                    let skip = match ipv6_literal(&url[at..])? {
                        Some(len) => len,
                        None if url.get(at + 1) == Some(&b']') => 2,
                        None => 0,
                    };
                    if skip > 0 {
                        text.try_extend_from_slice(&url[at..at + skip])?;
                        at += skip;
                        continue;
                    }
                    break;
                }
                if c == b'}' || c == b']' {
                    return Err(GlobError::malformed("unmatched close brace/bracket", pos));
                }
                // Only a pattern's bytes may be escaped.
                if c == b'\\' && url.get(at + 1).is_some_and(|n| b"{[}]".contains(n)) {
                    at += 1;
                    pos += 1;
                }
                text.try_push(url[at])?;
                at += 1;
                pos += 1;
            }
            if !text.is_empty() {
                let mut elems = Vec::new();
                elems.try_push(std::mem::take(&mut text))?;
                self.add(
                    Item {
                        kind: Kind::Set { elems, at: 0 },
                        index: None,
                        name: None,
                    },
                    pos,
                )?;
                continue;
            }
            if at == url.len() {
                break;
            }
            let set = url[at] == b'{';
            at += 1;
            pos += 1;
            let start = at;
            let name = match named(&url[at..]) {
                Some(name) => {
                    if self.find(name).is_some() {
                        return Err(GlobError::malformed(
                            "Duplicate glob name",
                            at + name.len() + 2,
                        ));
                    }
                    let mut owned = Vec::new();
                    owned.try_extend_from_slice(name)?;
                    at += name.len() + 2;
                    pos += at - start;
                    Some(owned)
                }
                None => None,
            };
            let kind = if set {
                parse_set(url, &mut at, &mut pos, &mut amount)?
            } else {
                parse_range(url, &mut at, &mut pos, &mut amount)?
            };
            self.add(
                Item {
                    kind,
                    index: Some(index),
                    name,
                },
                pos,
            )?;
            index += 1;
        }
        Ok(amount)
    }

    /// `add_glob`.
    fn add(&mut self, item: Item, pos: usize) -> Result<(), GlobError> {
        self.items.try_push(item)?;
        if self.items.len() > MAX_PATTERNS {
            return Err(GlobError::malformed("too many {} sets", pos));
        }
        Ok(())
    }

    /// The pattern named `name`, in any case but its own
    /// (`glob_find_name`).
    fn find(&self, name: &[u8]) -> Option<&Item> {
        self.items.iter().find(|i| i.name.as_deref() == Some(name))
    }

    /// The pattern `#N` names, from 1: the Nth that is not fixed text.
    fn numbered(&self, n: usize) -> Option<&Item> {
        self.items.iter().find(|i| i.index == Some(n - 1))
    }

    /// The next URL, or `None` after the last (`glob_next_url`): the
    /// rightmost pattern moves on first.
    pub(crate) fn next_url(&mut self) -> Result<Option<Vec<u8>>, OutOfMemory> {
        if self.started {
            let mut carry = true;
            for item in self.items.iter_mut().rev() {
                if !carry {
                    break;
                }
                carry = item.kind.step();
            }
            if carry {
                return Ok(None);
            }
        }
        self.started = true;
        let mut url = Vec::new();
        for item in &self.items {
            item.kind.write(&mut url)?;
        }
        Ok(Some(url))
    }

    /// `name`, an output file name, with each reference to a pattern
    /// replaced by the pattern's current text (`glob_match_url`). `#N`
    /// that names no pattern is kept as it is; `#<name>` that names
    /// none is an error. `upload` is the upload file's expansion, whose
    /// names are looked at after this one's.
    pub(crate) fn output_name(
        &self,
        name: &[u8],
        upload: Option<&Glob>,
    ) -> Result<Vec<u8>, GlobError> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < name.len() {
            let rest = &name[at..];
            let mut found = None;
            if rest[0] == b'#' && rest.get(1).is_some_and(u8::is_ascii_digit) {
                let digits = rest[1..].iter().take_while(|b| b.is_ascii_digit()).count();
                if let Some(n) = number(&rest[1..=digits], self.items.len() as i64)
                    && n > 0
                    && let Some(item) = self.numbered(n as usize)
                {
                    found = Some(item);
                    at += 1 + digits;
                }
            } else if rest.starts_with(b"#<")
                && let Some(wanted) = named(&rest[1..])
            {
                at += wanted.len() + 3;
                let item = self
                    .find(wanted)
                    .or_else(|| upload.and_then(|u| u.find(wanted)));
                match item {
                    Some(item) => found = Some(item),
                    None => {
                        return Err(GlobError::new(
                            "no glob exists with this name",
                            at,
                            ErrorKind::BadFunctionArgument,
                        ));
                    }
                }
            }
            match found {
                Some(item) => item.kind.write(&mut out)?,
                None => {
                    out.try_push(rest[0])?;
                    at += 1;
                }
            }
        }
        Ok(out)
    }
}

impl Kind {
    /// Move on by one; whether it went round to its first.
    fn step(&mut self) -> bool {
        match self {
            Kind::Set { elems, at } => {
                *at += 1;
                if *at == elems.len() {
                    *at = 0;
                    return true;
                }
            }
            Kind::Letters { min, max, step, at } => {
                *at += *step;
                if *at > *max {
                    *at = *min;
                    return true;
                }
            }
            Kind::Numbers {
                min, max, step, at, ..
            } => {
                *at += *step;
                if *at > *max {
                    *at = *min;
                    return true;
                }
            }
        }
        false
    }

    /// The current text, after what `out` holds.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), OutOfMemory> {
        match self {
            Kind::Set { elems, at } => out.try_extend_from_slice(&elems[*at]),
            Kind::Letters { at, .. } => out.try_push(*at as u8),
            Kind::Numbers { at, pad, .. } => {
                let text = try_format(format_args!("{at:0pad$}"))?;
                out.try_extend_from_slice(text.as_bytes())
            }
        }
    }
}

/// `<name>` at the start of `s`: the name, at least a byte and at most
/// `MAX_NAME`, up to a `>` that is there.
fn named(s: &[u8]) -> Option<&[u8]> {
    let rest = s.strip_prefix(b"<")?;
    let len = rest.iter().position(|&b| b == b'>')?;
    (len > 0 && len <= MAX_NAME).then(|| &rest[..len])
}

/// How long the IPv6 literal at the start of `s`, a `[`, is with its
/// `]`, if it is one a URL could have as its host (`peek_ipv6`).
fn ipv6_literal(s: &[u8]) -> Result<Option<usize>, GlobError> {
    let Some(end) = s.iter().position(|&b| b == b']') else {
        return Ok(None);
    };
    let len = end + 1;
    if len >= MAX_IP6 {
        return Ok(None);
    }
    let guess = ParseOptions {
        guess_scheme: true,
        ..ParseOptions::NONE
    };
    match Url::parse(&s[..len], guess) {
        Ok(_) => Ok(Some(len)),
        Err(UrlErrorKind::OutOfMemory) => Err(GlobError::from(OutOfMemory)),
        Err(_) => Ok(None),
    }
}

/// The decimal number `digits` spells, if it is one up to `max`
/// (`curlx_str_number`).
fn number(digits: &[u8], max: i64) -> Option<i64> {
    let mut n: i64 = 0;
    for &d in digits {
        n = n.checked_mul(10)?.checked_add(i64::from(d - b'0'))?;
        if n > max {
            return None;
        }
    }
    (!digits.is_empty()).then_some(n)
}

/// The decimal number at `*at` in `s`, up to `max`, moving past it; on
/// failure `*at` stays.
fn take_number(s: &[u8], at: &mut usize, max: i64) -> Option<i64> {
    let digits = s[*at..].iter().take_while(|b| b.is_ascii_digit()).count();
    let n = number(&s[*at..*at + digits], max)?;
    *at += digits;
    Some(n)
}

/// `byte` at `*at` in `s`, moving past it.
fn take_byte(s: &[u8], at: &mut usize, byte: u8) -> bool {
    let there = s.get(*at) == Some(&byte);
    *at += usize::from(there);
    there
}

/// `amount` times `with`, if it fits (`multiply`).
fn multiply(amount: &mut i64, with: i64) -> bool {
    if with <= 0 || *amount <= 0 {
        *amount = 0;
        return true;
    }
    match amount.checked_mul(with) {
        Some(n) => {
            *amount = n;
            true
        }
        None => false,
    }
}

/// `glob_set`: the elements of the set whose `{` is before `*at`, up to
/// its `}`.
fn parse_set(
    url: &[u8],
    at: &mut usize,
    pos: &mut usize,
    amount: &mut i64,
) -> Result<Kind, GlobError> {
    let open = *at;
    let mut elems = Vec::new();
    let mut elem = Vec::new();
    loop {
        match url.get(*at) {
            None => return Err(GlobError::malformed("unmatched brace", *pos)),
            Some(b'{' | b'[') => return Err(GlobError::malformed("nested brace", *pos)),
            Some(&c @ (b'}' | b',')) => {
                let done = c == b'}';
                if done {
                    if *at == open {
                        return Err(GlobError::malformed("empty string within braces", *pos));
                    }
                    if !multiply(amount, elems.len() as i64 + 1) {
                        return Err(GlobError::malformed("range overflow", 0));
                    }
                }
                if elems.len() >= MAX_SET {
                    return Err(GlobError::malformed("range overflow", 0));
                }
                elems.try_push(std::mem::take(&mut elem))?;
                *at += 1;
                if done {
                    return Ok(Kind::Set { elems, at: 0 });
                }
                *pos += 1;
            }
            Some(b']') => return Err(GlobError::malformed("unexpected close bracket", *pos)),
            Some(&c) => {
                // A backslash takes the byte after it as it is.
                if c == b'\\' && *at + 1 < url.len() {
                    *at += 1;
                    *pos += 1;
                }
                elem.try_push(url[*at])?;
                *at += 1;
                *pos += 1;
            }
        }
    }
}

/// `glob_range`: the range whose `[` is before `*at`, up to its `]`.
fn parse_range(
    url: &[u8],
    at: &mut usize,
    pos: &mut usize,
    amount: &mut i64,
) -> Result<Kind, GlobError> {
    let start = *at;
    let first = url.get(start).copied().unwrap_or(0);
    if first.is_ascii_alphabetic() {
        let mut matched = false;
        // C's `char`: signed.
        let (mut min, mut max) = (0i32, 0i32);
        let mut step: u32 = 1;
        let p = |i: usize| url.get(start + i).copied().unwrap_or(0);
        if p(1) == b'-' && p(2) != 0 && p(3) != 0 {
            min = i32::from(p(0) as i8);
            max = i32::from(p(2) as i8);
            matched = true;
            match p(3) {
                b':' => {
                    let mut q = start + 4;
                    step = match take_number(url, &mut q, 256) {
                        // C keeps the step in an unsigned char.
                        Some(n) if take_byte(url, &mut q, b']') => u32::from(n as u8),
                        _ => 0,
                    };
                    *at = q;
                }
                b']' => *at = start + 4,
                _ => matched = false,
            }
        }
        *pos += *at - start;
        // A start past the end makes the span negative, narrower than any
        // step.
        let span = max - min;
        if !matched
            || step == 0
            || (min == max && step != 1)
            || (min != max && (step as i32 > span || span > i32::from(b'z' - b'a')))
        {
            return Err(GlobError::malformed("bad range", *pos));
        }
        let (min, max) = (u32::from(min as u8), u32::from(max as u8));
        if !multiply(amount, i64::from((max - min) / step + 1)) {
            return Err(GlobError::malformed("range overflow", *pos));
        }
        return Ok(Kind::Letters {
            min,
            max,
            step,
            at: min,
        });
    }
    if !first.is_ascii_digit() {
        return Err(GlobError::malformed("bad range specification", *pos));
    }
    let pad = if first == b'0' {
        url[start..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count()
    } else {
        0
    };
    let (mut min, mut max, mut step) = (0, 0, 0);
    if let Some(n) = take_number(url, at, i64::MAX) {
        min = n;
        if take_byte(url, at, b'-') {
            while matches!(url.get(*at), Some(b' ' | b'\t')) {
                *at += 1;
            }
            if let Some(n) = take_number(url, at, i64::MAX) {
                max = n;
                if take_byte(url, at, b']') {
                    step = 1;
                } else if take_byte(url, at, b':')
                    && let Some(n) = take_number(url, at, i64::MAX)
                    && take_byte(url, at, b']')
                {
                    step = n;
                }
            }
        }
    }
    *pos += *at - start;
    // A start past the end is a step wider than the range.
    if step == 0 || (min == max && step != 1) || (min != max && step > max - min) {
        return Err(GlobError::malformed("bad range", *pos));
    }
    if i64::MAX - step < max {
        return Err(GlobError::malformed("range end/step overflow", *pos));
    }
    if !multiply(amount, (max - min) / step + 1) {
        return Err(GlobError::malformed("range overflow", *pos));
    }
    Ok(Kind::Numbers {
        min,
        max,
        step,
        at: min,
        pad,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(url: &str) -> (Vec<String>, i64) {
        let (mut glob, n) = Glob::parse(url.as_bytes()).unwrap();
        let mut urls = Vec::new();
        while let Some(u) = glob.next_url().unwrap() {
            urls.push(String::from_utf8(u).unwrap());
        }
        (urls, n)
    }

    fn refused(url: &str) -> (Option<&'static str>, usize) {
        let e = Glob::parse(url.as_bytes()).err().unwrap();
        (e.what, e.pos)
    }

    /// The rightmost pattern moves first; numbers keep their zeros.
    #[test]
    fn expands_every_combination() {
        let (urls, n) = all("h/{a,b}/[08-10:2]");
        assert_eq!(urls, ["h/a/08", "h/a/10", "h/b/08", "h/b/10"]);
        assert_eq!(n, 4);
        let (urls, n) = all("h/[a-e:2]{x,}");
        assert_eq!(urls, ["h/ax", "h/a", "h/cx", "h/c", "h/ex", "h/e"]);
        assert_eq!(n, 6);
        // Escapes, IPv6 literals and `[]` are fixed text.
        assert_eq!(all(r"h/\{a\}/{x\,y}").0, ["h/{a}/x,y"]);
        assert_eq!(
            all("http://[::1]:8/[1-2]").0,
            ["http://[::1]:8/1", "http://[::1]:8/2"]
        );
        assert_eq!(all("h/a[]").0, ["h/a[]"]);
        // A range's bounds may be equal, its step as wide as it, and a
        // blank may follow the `-` of numbers.
        assert_eq!(all("h/[a-c]x").0, ["h/ax", "h/bx", "h/cx"]);
        assert_eq!(all("h/[a-c:2]").0, ["h/a", "h/c"]);
        assert_eq!(all("h/[a-a]").0, ["h/a"]);
        assert_eq!(all("h/[a-z]").1, 26);
        assert_eq!(all("h/[3-3]").0, ["h/3"]);
        assert_eq!(all("h/[1- 3]").0, ["h/1", "h/2", "h/3"]);
        assert_eq!(all("h/[1-3:2]").0, ["h/1", "h/3"]);
        // The last end whose step cannot overflow.
        let (_, n) = Glob::parse(b"h/[1-9223372036854775806]").unwrap();
        assert_eq!(n, 9_223_372_036_854_775_806);
        // A name is 1 to 64 bytes: `<>`, or a longer one, is text.
        let long = "a".repeat(64);
        assert_eq!(all(&format!("h/{{<{long}>x}}")).0, ["h/x"]);
        assert_eq!(
            all(&format!("h/{{<{long}a>x}}")).0,
            [format!("h/<{long}a>x")]
        );
        assert_eq!(all("h/{<>a}").0, ["h/<>a"]);
    }

    /// A URL may have 255 patterns, its fixed parts counted, and no more.
    #[test]
    fn counts_its_patterns() {
        let url = |n: usize| -> Vec<u8> {
            (0..n)
                .flat_map(|i| if i % 2 == 0 { &b"a"[..] } else { b"{b}" })
                .copied()
                .collect()
        };
        assert!(Glob::parse(&url(255)).is_ok());
        let e = Glob::parse(&url(256)).err().unwrap();
        assert_eq!((e.what, e.pos), (Some("too many {} sets"), 385));
    }

    /// Errors carry C's words and its column, from 1.
    #[test]
    fn refuses_as_c_does() {
        assert_eq!(
            refused("http://a-site-never-accessed.example.org/[2-1]"),
            (Some("bad range"), 47)
        );
        assert_eq!(refused("h/{a"), (Some("unmatched brace"), 5));
        assert_eq!(refused("h/{a[b]}"), (Some("nested brace"), 5));
        assert_eq!(refused("h/{}"), (Some("empty string within braces"), 4));
        assert_eq!(refused("h/a}"), (Some("unmatched close brace/bracket"), 4));
        assert_eq!(refused("h/[!-z]"), (Some("bad range specification"), 4));
        assert_eq!(refused("h/[a-z:0]"), (Some("bad range"), 10));
        assert_eq!(refused("h/[1-3:5]"), (Some("bad range"), 10));
        assert_eq!(refused("{<n>a}{<n>b}"), (Some("Duplicate glob name"), 10));
        // The columns count escapes, names and the elements before.
        let cases = [
            (r"h/\{a}", "unmatched close brace/bracket", 6),
            ("h/{<>a}x}", "unmatched close brace/bracket", 8),
            ("h/[<n>2-1]", "bad range", 11),
            ("h/{a,b", "unmatched brace", 7),
            (r"h/{a\", "unmatched brace", 6),
            (r"h/{\a", "unmatched brace", 6),
            ("h/[ab]]", "bad range", 4),
            ("h/[a-c", "bad range", 4),
            // C reads the URL up to its zero.
            ("h/[a-\0]x", "bad range", 4),
            ("h/[c-a]", "bad range", 8),
            ("h/[a-a:2]", "bad range", 10),
            ("h/[a-c:3]", "bad range", 10),
            ("h/[A-z]", "bad range", 8),
            ("h/[3-1]", "bad range", 8),
            ("h/[1-3", "bad range", 7),
            ("h/[3-3:2]", "bad range", 10),
            ("h/[1-3:3]", "bad range", 10),
            ("h/[1-9223372036854775807]", "range end/step overflow", 26),
        ];
        for (url, what, pos) in cases {
            assert_eq!(refused(url), (Some(what), pos), "{url}");
        }
    }

    /// `#N` names the Nth pattern; `#<name>` a named one, which must
    /// exist.
    #[test]
    fn names_outputs_from_the_patterns() {
        let (mut glob, _) = Glob::parse(b"h/{a,b}/[<n>1-2]").unwrap();
        glob.next_url().unwrap();
        glob.next_url().unwrap();
        let name = |g: &Glob, n: &str| {
            g.output_name(n.as_bytes(), None)
                .map(|o| String::from_utf8(o).unwrap())
        };
        assert_eq!(name(&glob, "#1-#2-#<n>-#3-#0#").unwrap(), "a-2-2-#3-#0#");
        let e = name(&glob, "x#<m>y").unwrap_err();
        assert_eq!(
            (e.what, e.pos, e.kind),
            (
                Some("no glob exists with this name"),
                5,
                ErrorKind::BadFunctionArgument
            )
        );
        assert_eq!(name(&Glob::literal(), "#1#<").unwrap(), "#1#<");
        // The last pattern can be named.
        let (mut glob, _) = Glob::parse(b"{a,b}").unwrap();
        glob.next_url().unwrap();
        assert_eq!(name(&glob, "#1").unwrap(), "a");
    }
}
