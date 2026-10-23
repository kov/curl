//! Variables: `--variable` sets them, and `{{name}}` in the argument of an
//! option given with the `--expand-` prefix is replaced by one, as
//! `src/var.c` does.

use curl_alloc::{OutOfMemory, TryVec as _, try_format};

use crate::msgs::Messages;
use crate::options::ParamError;
use crate::slurp::{self, As, ReadFailed};

/// The longest expansion, and the longest result of a function, less one
/// (`MAX_EXPAND_CONTENT`, its terminating zero counted).
const MAX_EXPAND: usize = 10_000_000;

/// The longest name, less one (`MAX_VAR_LEN`).
const MAX_NAME: usize = 128;

/// The variables set, the last set first (C's `global->variables`).
#[derive(Debug, Default)]
pub(crate) struct Variables(Vec<Variable>);

#[derive(Debug)]
struct Variable {
    name: Vec<u8>,
    content: Vec<u8>,
}

/// What C's dynamic buffers hold here: at most `MAX_EXPAND` bytes, its
/// zero counted, or out of memory.
struct Buf(Vec<u8>);

impl Buf {
    fn new() -> Buf {
        Buf(Vec::new())
    }

    fn add(&mut self, bytes: &[u8]) -> Result<(), ParamError> {
        if self.0.len() + bytes.len() + 1 > MAX_EXPAND {
            return Err(ParamError::NoMem);
        }
        self.0.try_extend_from_slice(bytes)?;
        Ok(())
    }
}

/// A byte the C tool takes for a name's (`ISALNUM` or `_`).
fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `ISSPACE`.
fn space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `text` as C sees it: up to its first zero byte.
fn c_string(text: &[u8]) -> &[u8] {
    text.split(|&b| b == 0).next().unwrap_or_default()
}

impl Variables {
    fn find(&self, name: &[u8]) -> Option<&Variable> {
        self.0.iter().rev().find(|v| v.name == name)
    }

    /// Set a variable as `--variable` gives it (`setvariable`):
    /// `name=content`, `name@file` (`-` for standard input), or `%name`
    /// to take it from the environment, with `=` or `@` after it for when
    /// it is not set there. `[start-end]` after the name takes those bytes
    /// of the content only, `end` included. Errors are said in `msgs`.
    pub(crate) fn set(&mut self, input: &[u8], msgs: &Messages) -> Result<(), ParamError> {
        let input = c_string(input);
        let (import, line) = match input.strip_prefix(b"%") {
            Some(rest) => (true, rest),
            None => (false, input),
        };
        let nlen = line.iter().take_while(|&&b| name_byte(b)).count();
        let (name, mut line) = line.split_at(nlen);
        if nlen == 0 || nlen >= MAX_NAME {
            let text = try_format(format_args!("Bad variable name length ({nlen}), skipping"))?;
            msgs.warn(&[text.as_bytes()]);
            return Ok(());
        }
        let mut imported = None;
        if import {
            // Not `curl_getenv`, so that a value set empty is one.
            match curl_os::env::var(name)? {
                Some(value) => imported = Some(value),
                None if line.is_empty() => {
                    msgs.error(&[b"Variable '", name, b"' import fail, not set"]);
                    return Err(ParamError::ExpandError);
                }
                None => {}
            }
        }
        let mut start: u64 = 0;
        let mut end: Option<u64> = None;
        if line.first() == Some(&b'[') && line.get(1).is_some_and(u8::is_ascii_digit) {
            const MAX: u64 = i64::MAX.unsigned_abs();
            let (n, rest) =
                crate::options::leading_number(&line[1..], MAX).ok_or(ParamError::VarSyntax)?;
            start = n;
            let rest = rest.strip_prefix(b"-").ok_or(ParamError::VarSyntax)?;
            line = match rest.strip_prefix(b"]") {
                Some(rest) => rest,
                None => {
                    let (n, rest) =
                        crate::options::leading_number(rest, MAX).ok_or(ParamError::VarSyntax)?;
                    end = Some(n);
                    rest.strip_prefix(b"]").ok_or(ParamError::VarSyntax)?
                }
            };
            if end.is_some_and(|end| start > end) {
                return Err(ParamError::VarSyntax);
            }
        }
        // The environment's value is taken whole.
        let content = if let Some(value) = imported {
            value
        } else if let Some(file) = line.strip_prefix(b"@") {
            read_range(file, start, end, msgs)?
        } else if let Some(text) = line.strip_prefix(b"=") {
            let len = text.len() as u64;
            let taken = if start == 0 && end.is_none() {
                text
            } else if start >= len {
                &[]
            } else {
                // No further than the last byte.
                let last = end.unwrap_or(u64::MAX).min(len - 1);
                &text[start as usize..=last as usize]
            };
            let mut copy = Vec::new();
            copy.try_extend_from_slice(taken)?;
            copy
        } else {
            msgs.warn(&[b"Bad --variable syntax, skipping: ", input]);
            return Ok(());
        };
        if self.find(name).is_some() {
            msgs.note(&[b"Overwriting variable '", name, b"'"]);
        }
        let mut copy = Vec::new();
        copy.try_extend_from_slice(name)?;
        self.0.try_push(Variable {
            name: copy,
            content,
        })?;
        Ok(())
    }

    /// `line` with each `{{name}}` replaced by the variable's content, and
    /// `{{name:function:...}}` by what the functions make of it, left to
    /// right; `\{{` is `{{` as it is. `None` when nothing was replaced,
    /// and `line` is used as it is (`varexpand`).
    pub(crate) fn expand(
        &self,
        line: &[u8],
        msgs: &Messages,
    ) -> Result<Option<Vec<u8>>, ParamError> {
        let input = c_string(line);
        let mut line = input;
        let mut out = Buf::new();
        let mut added = false;
        while let Some(at) = find(line, b"{{") {
            if at > 0 && line[at - 1] == b'\\' {
                // Taken as it is, without the backslash.
                out.add(&line[..at - 1])?;
                out.add(b"{{")?;
                line = &line[at + 2..];
                continue;
            }
            let Some(close) = find(&line[at..], b"}}").map(|c| at + c) else {
                msgs.warn(&[b"missing close '}}' in '", input, b"'"]);
                break;
            };
            let inner = &line[at + 2..close];
            // A function ends the name with a colon.
            let colon = inner.iter().position(|&b| b == b':');
            let name = &inner[..colon.unwrap_or(inner.len())];
            if name.is_empty() || name.len() >= MAX_NAME {
                msgs.warn(&[b"bad variable name length '", input, b"'"]);
                out.add(&line[..close + 2])?;
            } else {
                out.add(&line[..at])?;
                if !name.iter().all(|&b| name_byte(b)) {
                    msgs.warn(&[b"bad variable name: ", name]);
                    out.add(&line[at..close + 2])?;
                } else {
                    let content = self.find(name).map(|v| &v[..]);
                    let made;
                    let value = match colon {
                        Some(colon) => {
                            // The functions run to the first `}`, the
                            // list as given being up to the `}}`.
                            let functions = &line[at + 2 + colon..];
                            let given = &line[at + 2 + colon..close];
                            made =
                                functions_on(content.unwrap_or_default(), functions, given, msgs)?;
                            &made[..]
                        }
                        None => content.unwrap_or_default(),
                    };
                    // C cannot show a zero byte.
                    if value.contains(&0) {
                        msgs.error(&[b"variable contains NUL byte"]);
                        return Err(ParamError::ExpandError);
                    }
                    out.add(value)?;
                    added = true;
                }
            }
            line = &line[close + 2..];
        }
        if !added {
            return Ok(None);
        }
        out.add(line)?;
        Ok(Some(out.0))
    }
}

impl core::ops::Deref for Variable {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.content
    }
}

/// Where `needle` first is in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// What the functions in `functions`, each after a colon and up to a `}`,
/// make of `content`, in turn (`varfunc`). `given` is the list as the
/// error about an unknown function shows it.
fn functions_on(
    content: &[u8],
    mut functions: &[u8],
    given: &[u8],
    msgs: &Messages,
) -> Result<Vec<u8>, ParamError> {
    let mut held: Vec<u8> = Vec::new();
    held.try_extend_from_slice(content)?;
    loop {
        match functions.first() {
            None | Some(b'}') => break,
            // Each function starts after a colon.
            Some(_) => functions = &functions[1..],
        }
        let named = |name: &[u8]| {
            functions.starts_with(name) && matches!(functions.get(name.len()), Some(b'}' | b':'))
        };
        // C passes the content on as a string: some functions read it
        // to its first zero byte, and that is where `trim` stops too.
        let c = &held[..];
        let mut out = Buf::new();
        let function: &[u8] = if named(b"trim") {
            let s = c_string(c);
            let from = s.iter().take_while(|&&b| space(b)).count();
            let mut to = c.len();
            while to > from && space(c[to - 1]) {
                to -= 1;
            }
            out.add(&c[from.min(to)..to])?;
            b"trim"
        } else if named(b"json") {
            out.add(&json_quoted(c)?)?;
            b"json"
        } else if named(b"url") {
            if !c.is_empty() {
                out.add(&curl_core::url::escape(c)?)?;
            }
            b"url"
        } else if named(b"b64") {
            out.add(&base64(c)?)?;
            b"b64"
        } else if named(b"64dec") {
            if !c.is_empty() {
                match base64_decode(c_string(c))? {
                    Some(decoded) => out.add(&decoded)?,
                    None => out.add(b"[64dec-fail]")?,
                }
            }
            b"64dec"
        } else {
            msgs.error(&[b"unknown variable function in '", given, b"'"]);
            return Err(ParamError::ExpandError);
        };
        functions = &functions[function.len()..];
        held = out.0;
    }
    Ok(held)
}

/// `bytes` with the characters JSON escapes in a string escaped, without
/// quotes around (`jsonquoted`, not lowercased).
fn json_quoted(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut out = Vec::new();
    for &b in bytes {
        match b {
            b'\\' => out.try_extend_from_slice(b"\\\\")?,
            b'"' => out.try_extend_from_slice(b"\\\"")?,
            0x08 => out.try_extend_from_slice(b"\\b")?,
            0x0c => out.try_extend_from_slice(b"\\f")?,
            b'\n' => out.try_extend_from_slice(b"\\n")?,
            b'\r' => out.try_extend_from_slice(b"\\r")?,
            b'\t' => out.try_extend_from_slice(b"\\t")?,
            0..0x20 => {
                out.try_extend_from_slice(try_format(format_args!("\\u{b:04x}"))?.as_bytes())?
            }
            _ => out.try_push(b)?,
        }
    }
    Ok(out)
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `bytes` in base64, padded (`curlx_base64_encode`).
fn base64(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len().div_ceil(3) * 4)?;
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.try_push(BASE64[(n >> (18 - 6 * i) & 0x3f) as usize])?;
            } else {
                out.try_push(b'=')?;
            }
        }
    }
    Ok(out)
}

/// `text` decoded from base64, or `None` if it is not that: its length a
/// multiple of four, at most two `=` at its end, and only base64's
/// characters before them (`curlx_base64_decode`). Empty text is not
/// base64.
fn base64_decode(text: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
    if text.is_empty() || !text.len().is_multiple_of(4) {
        return Ok(None);
    }
    let padding = text.iter().rev().take_while(|&&b| b == b'=').count();
    if padding > 2 {
        return Ok(None);
    }
    let len = text.len() / 4 * 3 - padding;
    let mut out = Vec::new();
    out.try_reserve_exact(len + 2)?;
    let data = &text[..text.len() - padding];
    for (q, quantum) in text.chunks(4).enumerate() {
        let mut n = 0u32;
        for (i, &b) in quantum.iter().enumerate() {
            // Only the padding counted at the end may be `=`.
            let v = if q * 4 + i >= data.len() {
                0
            } else {
                match BASE64.iter().position(|&c| c == b) {
                    Some(v) => v as u32,
                    None => return Ok(None),
                }
            };
            n = n << 6 | v;
        }
        out.try_extend_from_slice(&n.to_be_bytes()[1..])?;
    }
    out.truncate(len);
    Ok(Some(out))
}

/// The bytes of file `name`, `-` for standard input, from `start` to
/// `end`, both included (`file2memory_range`). A file that cannot be
/// opened is said in `msgs`.
fn read_range(
    name: &[u8],
    start: u64,
    end: Option<u64>,
    msgs: &Messages,
) -> Result<Vec<u8>, ParamError> {
    let read = if name == b"-" {
        slurp::read(name, As::Binary)
    } else {
        match curl_os::fs::with_c_name(name, curl_os::fs::open_read) {
            Ok(mut file) => slurp::read_from(&mut file, As::Binary),
            Err(e) => {
                let why = crate::os_message(&e);
                msgs.error(&[b"Failed to open ", name, b": ", why.as_bytes()]);
                return Err(ParamError::ReadError);
            }
        }
    };
    let mut bytes = match read {
        Ok(bytes) => bytes,
        Err(ReadFailed::OutOfMemory) => return Err(ParamError::NoMem),
        Err(ReadFailed::Open | ReadFailed::Read) => return Err(ParamError::ReadError),
    };
    let len = bytes.len() as u64;
    let to = end.map_or(len, |end| end.saturating_add(1).min(len));
    let from = start.min(to);
    bytes.truncate(to as usize);
    bytes.drain(..from as usize);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet() -> Messages {
        let mut msgs = Messages::new();
        msgs.silent = true;
        msgs
    }

    fn vars(given: &[&str]) -> Variables {
        let mut vars = Variables::default();
        for g in given {
            vars.set(g.as_bytes(), &quiet()).unwrap();
        }
        vars
    }

    fn expand(vars: &Variables, line: &str) -> Result<Option<String>, ParamError> {
        vars.expand(line.as_bytes(), &quiet())
            .map(|o| o.map(|v| String::from_utf8(v).unwrap()))
    }

    /// The cases checked against the C build's `--expand-url`.
    #[test]
    fn expands_as_c_does() {
        let v = vars(&["a=x", "e=", "b=aGk=", "s=  a b \n", "a=y", "q=\"\\\t"]);
        let same = |line: &str, want: &str| {
            assert_eq!(expand(&v, line), Ok(Some(want.to_string())), "{line}");
        };
        same("{{a}}", "y");
        same("1{{a}}2{{none}}3{{e}}4", "1y234");
        same("\\{{a}}{{a}}", "{{a}}y");
        same("{{a}}{{b", "y{{b");
        same("{{a.b}}{{a}}", "{{a.b}}y");
        same("{{}}{{a}}", "{{}}y");
        same("{{a:trim}x}}", "y");
        same(
            "{{s:trim}}|{{s:trim:url}}|{{s:b64}}",
            "a b|a%20b|ICBhIGIgCg==",
        );
        same("{{b:64dec}}|{{b:64dec:b64}}|{{none:64dec}}", "hi|aGk=|");
        same("{{q:json}}", "\\\"\\\\\\t");
        let long = "F".repeat(128);
        same(
            &format!("{{{{{long}}}}}{{{{a}}}}"),
            &format!("{{{{{long}}}}}y"),
        );
        // Nothing replaced: the line is used as it is.
        for line in ["plain", "\\{{a}}", "{{a", "{{a.b}}", "{{}}"] {
            assert_eq!(expand(&v, line), Ok(None), "{line}");
        }
        for line in ["{{a:}}", "{{a:trim,url}}", "{{a:super}}", "{{a:trimx}}"] {
            assert_eq!(expand(&v, line), Err(ParamError::ExpandError), "{line}");
        }
    }

    /// A zero byte cannot be shown; functions see the content to its
    /// first, but for `json` and `url`, which take it whole.
    #[test]
    fn a_zero_byte_is_refused_unless_a_function_takes_it() {
        let mut v = Variables::default();
        v.0.push(Variable {
            name: b"z".to_vec(),
            content: b" \x01\0aGk=\n".to_vec(),
        });
        assert_eq!(expand(&v, "{{z}}"), Err(ParamError::ExpandError));
        assert_eq!(expand(&v, "{{z:trim}}"), Err(ParamError::ExpandError));
        assert_eq!(
            expand(&v, "{{z:trim:json}}"),
            Ok(Some("\\u0001\\u0000aGk=".to_string()))
        );
        assert_eq!(
            expand(&v, "{{z:url}}"),
            Ok(Some("%20%01%00aGk%3D%0A".to_string()))
        );
        assert_eq!(
            expand(&v, "{{z:64dec}}"),
            Ok(Some("[64dec-fail]".to_string()))
        );
    }

    #[test]
    fn decodes_base64_as_c_does() {
        let d = |s: &str| base64_decode(s.as_bytes()).unwrap();
        assert_eq!(d("aGk="), Some(b"hi".to_vec()));
        assert_eq!(d("aGkh"), Some(b"hi!".to_vec()));
        assert_eq!(d("IA=="), Some(b" ".to_vec()));
        assert_eq!(d("aGkhaGk="), Some(b"hi!hi".to_vec()));
        for bad in [
            "", "aGk", "a===", "====", "A=B=", "AB=C", "aG=k", "aG!=", "aGk=aGk=",
        ] {
            assert_eq!(d(bad), None, "{bad}");
        }
        assert_eq!(base64(b"Call me Ishmael").unwrap(), b"Q2FsbCBtZSBJc2htYWVs");
        assert_eq!(base64(b"a").unwrap(), b"YQ==");
        assert_eq!(base64(b"").unwrap(), b"");
    }

    /// `[start-end]` takes those bytes of the content, `end` included and
    /// no further than its last.
    #[test]
    fn takes_a_byte_range_as_c_does() {
        let content = |given: &str| {
            let v = vars(&[given]);
            v.find(b"n")
                .map(|v| String::from_utf8(v.content.clone()).unwrap())
        };
        assert_eq!(content("n[5-9]=0123456789abcdef").as_deref(), Some("56789"));
        assert_eq!(
            content("n[10-30]=0123456789abcdef").as_deref(),
            Some("abcdef")
        );
        assert_eq!(content("n[2-]=abcdef").as_deref(), Some("cdef"));
        assert_eq!(content("n[6-9]=abcdef").as_deref(), Some(""));
        assert_eq!(content("n[0-0]=abcdef").as_deref(), Some("a"));
        // Not a range: the syntax is bad, and skipped.
        assert_eq!(content("n[x]=1"), None);
        assert_eq!(content("n[1-2]x"), None);
        let refused = |given: &str| Variables::default().set(given.as_bytes(), &quiet());
        for bad in [
            "n[1-2",
            "n[1x]=a",
            "n[3-1]=a",
            "n[1-2x]=a",
            "n[99999999999999999999-]=a",
        ] {
            assert_eq!(refused(bad), Err(ParamError::VarSyntax), "{bad}");
        }
        assert_eq!(refused("n@/nonexistent/x"), Err(ParamError::ReadError));
        // A bad name is skipped.
        assert_eq!(refused(&format!("{}=x", "a".repeat(128))), Ok(()));
        assert_eq!(refused("=x"), Ok(()));
    }

    /// The last set is the one used.
    #[test]
    fn the_last_set_wins() {
        let v = vars(&["a=1", "b=2", "a=3"]);
        assert_eq!(expand(&v, "{{a}}{{b}}"), Ok(Some("32".to_string())));
    }
}
