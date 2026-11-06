//! The tables of C's unit tests, read from their source when a port runs
//! (DESIGN.md, "Ported unit tests"), so a port checks the cases its
//! original does rather than a copy of them.
//!
//! A table is a C initializer: braces holding values, each a string
//! (adjacent literals joined, escapes read as C reads them), a group in
//! braces, or a word (a number, a name, `NULL`). Lines of the
//! preprocessor inside it are weighed by the caller: a row is kept when
//! every condition it sits under holds. A test driven by calls rather
//! than a table has its calls' arguments read the same way. A name the
//! source `#define`s as a string stands for that string, in a table or
//! beside a literal, and [`constant`] reads the number a `#define` or an
//! `enum` gives a name.
//!
//! Only tests read it, so it allocates as tests do, and a source it
//! cannot read is a failed test.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::collections::HashMap;
use std::path::Path;

/// One value of a C initializer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// A string literal, or several side by side, as bytes.
    Str(Vec<u8>),
    /// Anything else up to the next comma: a number, a name, `NULL`.
    Word(String),
    /// Values in braces.
    Group(Vec<Value>),
    /// A macro's name and its arguments, such as `OID("\x81")`.
    Call(String, Vec<Value>),
}

impl Value {
    /// The bytes of a string; `None` for `NULL`.
    #[track_caller]
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Str(s) => Some(s),
            Value::Word(w) if w == "NULL" => None,
            other => panic!("not a string: {other:?}"),
        }
    }

    /// The first `len` bytes of a string as C's memory holds it, its
    /// terminating zero byte among them, as a row that gives a string
    /// and a length reads.
    #[track_caller]
    pub fn sized(&self, len: &Value) -> Vec<u8> {
        let len = usize::try_from(len.int()).expect("a length");
        let mut held = self.str().to_vec();
        held.push(0);
        assert!(len <= held.len(), "{len} bytes of {held:?}");
        held.truncate(len);
        held
    }

    /// The bytes of a string that is never `NULL`.
    #[track_caller]
    pub fn str(&self) -> &[u8] {
        self.bytes().expect("a string, not NULL")
    }

    /// The word, as written.
    #[track_caller]
    pub fn word(&self) -> &str {
        match self {
            Value::Word(w) => w,
            other => panic!("not a word: {other:?}"),
        }
    }

    /// The word as a C integer constant: decimal, hex or octal, maybe
    /// negative, its suffixes (`U`, `L`) dropped.
    #[track_caller]
    pub fn int(&self) -> i128 {
        let w = self.word().trim();
        let (neg, w) = match w.strip_prefix('-') {
            Some(rest) => (true, rest.trim()),
            None => (false, w),
        };
        let w = w.trim_end_matches(['u', 'U', 'l', 'L']);
        let n = if let Some(hex) = w.strip_prefix("0x").or_else(|| w.strip_prefix("0X")) {
            i128::from_str_radix(hex, 16)
        } else if w.len() > 1 && w.starts_with('0') {
            i128::from_str_radix(&w[1..], 8)
        } else {
            w.parse()
        };
        let n = n.unwrap_or_else(|_| panic!("not a number: {w}"));
        if neg { -n } else { n }
    }

    /// The arguments of a call of `name`.
    #[track_caller]
    pub fn call(&self, name: &str) -> &[Value] {
        match self {
            Value::Call(n, args) if n == name => args,
            other => panic!("not a call of {name}: {other:?}"),
        }
    }

    /// The values of a group.
    #[track_caller]
    pub fn group(&self) -> &[Value] {
        match self {
            Value::Group(g) => g,
            other => panic!("not a group: {other:?}"),
        }
    }
}

/// The source of `file`, a path from the top of the tree.
#[track_caller]
pub fn source(file: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The rows of the initializer that follows the first `= {` after
/// `name` in `file`, a path from the top of the tree. `holds` is asked
/// of each preprocessor condition a row sits under (`#if X` as `X`,
/// `#ifdef X` as `defined(X)`, `#ifndef X` and an `#else` as `!(X)`), and
/// the row is kept only if it holds for each.
#[track_caller]
pub fn table(file: &str, name: &str, holds: impl Fn(&str) -> bool) -> Vec<Value> {
    table_in(&source(file), file, name, holds)
}

#[track_caller]
fn table_in(src: &str, file: &str, name: &str, holds: impl Fn(&str) -> bool) -> Vec<Value> {
    let at = src
        .find(name)
        .unwrap_or_else(|| panic!("{file}: no {name}"));
    let open = src[at..]
        .find("= {")
        .unwrap_or_else(|| panic!("{file}: no initializer after {name}"))
        + at
        + 2;
    let macros = defines(src);
    let mut p = Parser {
        s: src.as_bytes(),
        at: open,
        conditions: Vec::new(),
        holds: &holds,
        macros: &macros,
    };
    match p.group() {
        Value::Group(rows) => rows,
        _ => unreachable!("a group is a group"),
    }
}

/// The arguments of each call of `name` in `file` that starts a line,
/// as a table's values. The definition, which starts with its type, is
/// not one; a call under a preprocessor condition fails the read.
#[track_caller]
pub fn calls(file: &str, name: &str) -> Vec<Vec<Value>> {
    calls_in(&source(file), name)
}

#[track_caller]
fn calls_in(src: &str, name: &str) -> Vec<Vec<Value>> {
    let call = format!("{name}(");
    let macros = defines(src);
    let mut depth = 0usize;
    let mut found = Vec::new();
    let mut at = 0;
    for line in src.split_inclusive('\n') {
        let text = line.trim_start();
        if text.starts_with("#if") {
            depth += 1;
        } else if text.starts_with("#endif") {
            depth -= 1;
        } else if text.starts_with(&call) {
            assert_eq!(depth, 0, "a call of {name} under a condition: {text}");
            let mut p = Parser {
                s: src.as_bytes(),
                at: at + line.len() - text.len() + call.len(),
                conditions: Vec::new(),
                holds: &|c: &str| panic!("{c} inside a call"),
                macros: &macros,
            };
            found.push(p.items(b')'));
        }
        at += line.len();
    }
    found
}

/// The arguments of each call of `name` in `file` that starts a line or
/// whose result a line assigns (`res = name(`), as a table's values,
/// where every preprocessor condition it sits under holds (`holds` is
/// asked as [`table`] asks it).
#[track_caller]
pub fn every_call(file: &str, name: &str, holds: impl Fn(&str) -> bool) -> Vec<Vec<Value>> {
    every_call_in(&source(file), name, holds)
}

#[track_caller]
fn every_call_in(src: &str, name: &str, holds: impl Fn(&str) -> bool) -> Vec<Vec<Value>> {
    let call = format!("{name}(");
    let macros = defines(src);
    let mut conditions: Vec<(String, bool)> = Vec::new();
    let mut found = Vec::new();
    let mut at = 0;
    for line in src.split_inclusive('\n') {
        let text = line.trim_start();
        if let Some(directive) = text.strip_prefix('#') {
            let directive = directive.trim();
            let (word, rest) = directive
                .split_once(char::is_whitespace)
                .unwrap_or((directive, ""));
            let rest = rest.trim();
            let condition = match word {
                "if" => Some(rest.to_owned()),
                "ifdef" => Some(format!("defined({rest})")),
                "ifndef" => Some(format!("!(defined({rest}))")),
                "else" => {
                    let (c, _) = conditions.pop().expect("an #else inside an #if");
                    let c = format!("!({c})");
                    let held = holds(&c);
                    conditions.push((c, held));
                    None
                }
                "endif" => {
                    conditions.pop().expect("an #endif closes an #if");
                    None
                }
                "elif" => panic!("an #elif around a call of {name}"),
                _ => None,
            };
            if let Some(c) = condition {
                let held = holds(&c);
                conditions.push((c, held));
            }
        } else if conditions.iter().all(|(_, held)| *held) {
            // A call, or an assignment of its result.
            let start = if text.starts_with(&call) {
                Some(0)
            } else {
                let len = text
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(0);
                let after = text[len..].trim_start();
                after
                    .strip_prefix('=')
                    .map(str::trim_start)
                    .filter(|a| len > 0 && !a.starts_with('=') && a.starts_with(&call))
                    .map(|a| text.len() - a.len())
            };
            if let Some(start) = start {
                let mut p = Parser {
                    s: src.as_bytes(),
                    at: at + line.len() - text.len() + start + call.len(),
                    conditions: Vec::new(),
                    holds: &|c: &str| panic!("{c} inside a call"),
                    macros: &macros,
                };
                found.push(p.items(b')'));
            }
        }
        at += line.len();
    }
    found
}

/// The names `src` `#define`s, each with its text: the rest of its line,
/// continued past a backslash, its comments left in. A macro with
/// parameters is not one.
fn defines(src: &str) -> HashMap<String, String> {
    let mut found = HashMap::new();
    let mut lines = src.lines();
    while let Some(line) = lines.next() {
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("define") else {
            continue;
        };
        let rest = rest.trim_start();
        let len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let (name, mut text) = (rest[..len].to_owned(), rest[len..].to_owned());
        if name.is_empty() || text.starts_with('(') {
            continue;
        }
        while text.ends_with('\\') {
            text.pop();
            text.push(' ');
            text.push_str(lines.next().unwrap_or_default());
        }
        found.insert(name, strip_comments(&text));
    }
    found
}

/// `text` without its C comments; a literal's `//` or `/*` is no comment.
fn strip_comments(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            q @ (b'"' | b'\'') => {
                // A literal, with what its backslashes escape.
                let start = i;
                i += 1;
                while i < b.len() && b[i] != q {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i = (i + 1).min(b.len());
                out.extend_from_slice(&b[start..i]);
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = text[i + 2..].find("*/").expect("a comment ends");
                out.push(b' ');
                i += 2 + end + 2;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = text[i..].find('\n').map_or(b.len(), |e| i + e);
                i = end;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).expect("cut at ASCII bytes")
}

/// The number `name` stands for in `file`, a path from the top of the
/// tree: a `#define` of it, or an enumerator (`NAME = value`, or one more
/// than the one before it). A value may add, subtract, multiply and
/// divide numbers and other such names, in parentheses or not, and a
/// cast in it is read past.
#[track_caller]
pub fn constant(file: &str, name: &str) -> i128 {
    constant_in(&source(file), name)
}

#[track_caller]
fn constant_in(src: &str, name: &str) -> i128 {
    let macros = defines(src);
    let enums = enumerators(src);
    let mut e = Expr {
        s: name.as_bytes(),
        at: 0,
        macros: &macros,
        enums: &enums,
        depth: 0,
    };
    let n = e.sum();
    assert_eq!(e.peek(), None, "{name} is not a name");
    n
}

/// The enumerators of each `enum { ... }` in `src`, each with its value's
/// text: what follows its `=`, or the one before it plus one.
fn enumerators(src: &str) -> HashMap<String, String> {
    let mut found = HashMap::new();
    let src = strip_comments(src);
    let mut rest = src.as_str();
    while let Some(at) = rest.find("enum") {
        rest = &rest[at + 4..];
        let Some(open) = rest.find('{') else { break };
        // `enum name {` or `enum {`, nothing else between.
        if !rest[..open]
            .trim()
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        let Some(close) = rest[open..].find('}') else {
            break;
        };
        let body = &rest[open + 1..open + close];
        let mut previous: Option<String> = None;
        for item in body.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let (name, value) = match item.split_once('=') {
                Some((n, v)) => (n.trim().to_owned(), v.trim().to_owned()),
                None => {
                    let v = match &previous {
                        Some(p) => format!("({p}) + 1"),
                        None => "0".to_owned(),
                    };
                    (item.to_owned(), v)
                }
            };
            previous = Some(name.clone());
            found.insert(name, value);
        }
        rest = &rest[open + close..];
    }
    found
}

/// An integer expression of C's, evaluated.
struct Expr<'a> {
    s: &'a [u8],
    at: usize,
    macros: &'a HashMap<String, String>,
    enums: &'a HashMap<String, String>,
    depth: usize,
}

impl Expr<'_> {
    fn peek(&mut self) -> Option<u8> {
        while self.s.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
        self.s.get(self.at).copied()
    }

    #[track_caller]
    fn sum(&mut self) -> i128 {
        let mut n = self.product();
        loop {
            match self.peek() {
                Some(b'+') => {
                    self.at += 1;
                    n += self.product();
                }
                Some(b'-') => {
                    self.at += 1;
                    n -= self.product();
                }
                _ => return n,
            }
        }
    }

    #[track_caller]
    fn product(&mut self) -> i128 {
        let mut n = self.unary();
        loop {
            match self.peek() {
                Some(b'*') => {
                    self.at += 1;
                    n *= self.unary();
                }
                Some(b'/') => {
                    self.at += 1;
                    n /= self.unary();
                }
                _ => return n,
            }
        }
    }

    #[track_caller]
    fn unary(&mut self) -> i128 {
        match self.peek().expect("an expression ends early") {
            b'-' => {
                self.at += 1;
                -self.unary()
            }
            b'(' => {
                self.at += 1;
                let start = self.at;
                let close = self.s[start..]
                    .iter()
                    .position(|&b| b == b')')
                    .expect("a parenthesis closes");
                let inside = std::str::from_utf8(&self.s[start..start + close]).expect("ASCII");
                let words: Vec<&str> = inside.split_whitespace().collect();
                let typ = |w: &&str| {
                    matches!(
                        *w,
                        "int" | "long" | "unsigned" | "short" | "char" | "signed"
                    ) || w.ends_with("_t")
                };
                if !words.is_empty() && words.iter().all(typ) {
                    // A cast: the value cast follows.
                    self.at = start + close + 1;
                    return self.unary();
                }
                let n = self.sum();
                assert_eq!(self.peek(), Some(b')'), "a parenthesis closes");
                self.at += 1;
                n
            }
            b if b.is_ascii_digit() => {
                let start = self.at;
                while self.s.get(self.at).is_some_and(u8::is_ascii_alphanumeric) {
                    self.at += 1;
                }
                let w = std::str::from_utf8(&self.s[start..self.at]).expect("ASCII");
                Value::Word(w.to_owned()).int()
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let start = self.at;
                while self
                    .s
                    .get(self.at)
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                {
                    self.at += 1;
                }
                let name = std::str::from_utf8(&self.s[start..self.at]).expect("ASCII");
                let text = self
                    .macros
                    .get(name)
                    .or_else(|| self.enums.get(name))
                    .unwrap_or_else(|| panic!("no number named {name}"));
                assert!(self.depth < 64, "{name} names itself");
                let mut inner = Expr {
                    s: text.as_bytes(),
                    at: 0,
                    macros: self.macros,
                    enums: self.enums,
                    depth: self.depth + 1,
                };
                let n = inner.sum();
                assert_eq!(inner.peek(), None, "{name} is not a number: {text}");
                n
            }
            other => panic!("{} in an expression", other as char),
        }
    }
}

struct Parser<'a, F> {
    s: &'a [u8],
    at: usize,
    /// The conditions of the `#if`s open, each with whether it holds.
    conditions: Vec<(String, bool)>,
    holds: &'a F,
    /// The source's `#define`s, for the names that stand for strings.
    macros: &'a HashMap<String, String>,
}

impl<F: Fn(&str) -> bool> Parser<'_, F> {
    fn peek(&self) -> u8 {
        *self.s.get(self.at).expect("the initializer ends")
    }

    fn kept(&self) -> bool {
        self.conditions.iter().all(|(_, held)| *held)
    }

    /// Past blanks, comments and preprocessor lines.
    fn skip(&mut self) {
        loop {
            let rest = &self.s[self.at..];
            if rest.first().is_some_and(u8::is_ascii_whitespace) {
                self.at += 1;
            } else if rest.starts_with(b"/*") {
                let end = rest
                    .windows(2)
                    .position(|w| w == b"*/")
                    .expect("a comment ends");
                self.at += end + 2;
            } else if rest.starts_with(b"//") {
                self.at += rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
            } else if rest.starts_with(b"#") && self.line_start() {
                let len = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
                let line = std::str::from_utf8(&rest[..len]).expect("ASCII").trim();
                self.directive(line);
                self.at += len;
            } else {
                return;
            }
        }
    }

    fn line_start(&self) -> bool {
        self.s[..self.at]
            .iter()
            .rev()
            .take_while(|&&b| b != b'\n')
            .all(u8::is_ascii_whitespace)
    }

    fn directive(&mut self, line: &str) {
        let line = line[1..].trim_start();
        let (word, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let rest = rest.trim();
        let condition = match word {
            "if" => rest.to_owned(),
            "ifdef" => format!("defined({rest})"),
            "ifndef" => format!("!(defined({rest}))"),
            "else" => {
                let (c, _) = self.conditions.pop().expect("an #else inside an #if");
                let c = format!("!({c})");
                let held = (self.holds)(&c);
                self.conditions.push((c, held));
                return;
            }
            "endif" => {
                self.conditions.pop().expect("an #endif closes an #if");
                return;
            }
            other => panic!("a #{other} inside a table"),
        };
        let held = (self.holds)(&condition);
        self.conditions.push((condition, held));
    }

    /// A group, at its `{`.
    fn group(&mut self) -> Value {
        assert_eq!(self.peek(), b'{');
        self.at += 1;
        Value::Group(self.items(b'}'))
    }

    /// The values up to `close`, and past it.
    fn items(&mut self, close: u8) -> Vec<Value> {
        let mut values = Vec::new();
        loop {
            self.skip();
            if self.peek() == close {
                self.at += 1;
                return values;
            }
            let kept = self.kept();
            let v = self.value();
            if kept {
                values.push(v);
            }
            self.skip();
            match self.peek() {
                b',' => self.at += 1,
                b if b == close => {}
                b => panic!("{} after a value", b as char),
            }
        }
    }

    fn value(&mut self) -> Value {
        match self.peek() {
            b'{' => self.group(),
            b'"' => Value::Str(self.strings()),
            b'(' if self.cast_string() => self.value(),
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let start = self.at;
                while self.peek().is_ascii_alphanumeric() || self.peek() == b'_' {
                    self.at += 1;
                }
                let name = std::str::from_utf8(&self.s[start..self.at]).expect("ASCII");
                if self.peek() == b'(' {
                    self.at += 1;
                    return Value::Call(name.to_owned(), self.items(b')'));
                }
                self.at = start;
                if self.string_macro().is_some() {
                    return Value::Str(self.strings());
                }
                self.word()
            }
            _ => self.word(),
        }
    }

    /// Literals and names of strings side by side, joined.
    fn strings(&mut self) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            if self.at < self.s.len() && self.peek() == b'"' {
                self.literal(&mut bytes);
            } else if let Some((len, expansion)) = self.string_macro() {
                bytes.extend_from_slice(&expansion);
                self.at += len;
            } else {
                return bytes;
            }
            self.skip();
        }
    }

    /// The length of the name here and the string it stands for, if it
    /// is a name the source defines as a string.
    fn string_macro(&self) -> Option<(usize, Vec<u8>)> {
        let rest = &self.s[self.at..];
        let len = rest
            .iter()
            .position(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
            .unwrap_or(rest.len());
        if len == 0 || rest[0].is_ascii_digit() {
            return None;
        }
        let name = std::str::from_utf8(&rest[..len]).expect("ASCII");
        let text = self.macros.get(name)?;
        let mut inner = Parser {
            s: text.as_bytes(),
            at: 0,
            conditions: Vec::new(),
            holds: self.holds,
            macros: self.macros,
        };
        inner.skip();
        let first = *inner.s.get(inner.at)?;
        if first != b'"' && inner.string_macro().is_none() {
            return None;
        }
        Some((len, inner.strings()))
    }

    /// Past a cast before a string literal, if one is here: a string is
    /// read the same, cast or not.
    fn cast_string(&mut self) -> bool {
        let rest = &self.s[self.at..];
        let Some(close) = rest.iter().position(|&b| b == b')') else {
            return false;
        };
        let after = rest[close + 1..]
            .iter()
            .position(|b| !b.is_ascii_whitespace());
        if after.is_some_and(|a| rest[close + 1 + a] == b'"') {
            self.at += close + 1;
            self.skip();
            return true;
        }
        false
    }

    /// Anything else up to the next comma or close.
    fn word(&mut self) -> Value {
        let start = self.at;
        let mut depth = 0;
        while depth > 0 || !matches!(self.peek(), b',' | b'}' | b')') {
            let rest = &self.s[self.at..];
            if rest.starts_with(b"/*") || rest.starts_with(b"//") {
                break;
            }
            match self.peek() {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            self.at += 1;
        }
        let word = std::str::from_utf8(&self.s[start..self.at]).expect("ASCII");
        Value::Word(word.trim().to_owned())
    }

    /// One string literal, at its `"`, its bytes added to `out`.
    fn literal(&mut self, out: &mut Vec<u8>) {
        self.at += 1;
        loop {
            let b = self.peek();
            self.at += 1;
            match b {
                b'"' => return,
                b'\\' => {
                    let e = self.peek();
                    self.at += 1;
                    let byte = match e {
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'a' => 0x07,
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'v' => 0x0b,
                        b'\\' | b'"' | b'\'' | b'?' => e,
                        b'x' => {
                            // C reads every hex digit that follows.
                            let start = self.at;
                            while self.peek().is_ascii_hexdigit() {
                                self.at += 1;
                            }
                            let digits = std::str::from_utf8(&self.s[start..self.at]).unwrap();
                            u8::from_str_radix(digits, 16)
                                .unwrap_or_else(|_| panic!("\\x{digits} is not a byte"))
                        }
                        b'0'..=b'7' => {
                            let mut n = u32::from(e - b'0');
                            for _ in 0..2 {
                                let d = self.peek();
                                if !(b'0'..=b'7').contains(&d) {
                                    break;
                                }
                                n = n * 8 + u32::from(d - b'0');
                                self.at += 1;
                            }
                            u8::try_from(n).expect("an octal escape of a byte")
                        }
                        other => panic!("the escape \\{}", other as char),
                    };
                    out.push(byte);
                }
                b'\n' => panic!("a string literal across lines"),
                _ => out.push(b),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader reads a table as C does: literals joined, escapes, a
    /// group, words, a macro's call, a cast string, a row under a
    /// condition that does not hold left out.
    #[test]
    fn reads_a_table_as_c_does() {
        let src = "static const struct x t[] = {\n  { \"a\\x41\" \"\\101\\n\", 1, {2, 3} }, /* c */\n#ifdef NOPE\n  { \"gone\", 0 },\n#else\n  { NULL, -0x10L /* c */ },\n#endif\n  { OID(\"\\x81\"), (const uint8_t *)\"\\x82\", (long)2 },\n};";
        let rows = table_in(src, "t.c", "t[]", |c| match c {
            "defined(NOPE)" => false,
            "!(defined(NOPE))" => true,
            other => panic!("{other}"),
        });
        assert_eq!(rows.len(), 3);
        let r = rows[2].group();
        assert_eq!(r[0].call("OID")[0].str(), b"\x81");
        assert_eq!(r[1].str(), b"\x82");
        assert_eq!(r[2].word(), "(long)2");
        let r = rows[0].group();
        assert_eq!(r[0].str(), b"aAA\n");
        assert_eq!(r[1].int(), 1);
        assert_eq!(r[2].group()[1].int(), 3);
        let r = rows[1].group();
        assert_eq!(r[0].bytes(), None);
        assert_eq!(r[1].int(), -16);
    }

    /// A name defined as a string stands for it, beside literals or
    /// alone, through other such names; a name defined otherwise is a
    /// word; what looks like a comment inside a string is the string's.
    #[test]
    fn reads_names_of_strings() {
        let src = "#define A \"ab\" /* c */\n#define B A A \\\n  \"c\"\n#define N 4\n#define U \"http://x/*y\" // c\nstatic const char *t[] = {\n  \"x\" B,\n  A,\n  N,\n  U,\n};";
        let rows = table_in(src, "t.c", "t[]", |c| panic!("{c}"));
        assert_eq!(rows[0].str(), b"xababc");
        assert_eq!(rows[1].str(), b"ab");
        assert_eq!(rows[2].word(), "N");
        assert_eq!(rows[3].str(), b"http://x/*y");
    }

    /// A number defined or enumerated, through other names, sums and
    /// casts.
    #[test]
    fn reads_constants() {
        let src = "#define MAX 5370 /* c */\n#define TWICE (MAX * 2)\nenum {\n  A = 26, /* c */\n  B,\n  C = A + B - (size_t)1,\n};";
        assert_eq!(constant_in(src, "MAX"), 5370);
        assert_eq!(constant_in(src, "TWICE"), 10740);
        assert_eq!(constant_in(src, "B"), 27);
        assert_eq!(constant_in(src, "C"), 52);
    }

    /// Every call of a function a line makes or assigns, where its
    /// conditions hold; a comparison of a call is not one.
    #[test]
    fn reads_every_call() {
        let src = "#ifndef OFF\n  f(\"a\");\n  res = f(\"b\",\n    2);\n#ifdef OFF\n  f(\"gone\");\n#else\n  x=f(\"c\");\n#endif\n  r == f(\"no\");\n#endif\n";
        let calls = every_call_in(src, "f", |c| match c {
            // `#ifndef OFF`, and the `#else` of `#ifdef OFF`.
            "!(defined(OFF))" => true,
            "defined(OFF)" => false,
            other => panic!("{other}"),
        });
        let first: Vec<&[u8]> = calls.iter().map(|c| c[0].str()).collect();
        assert_eq!(first, [&b"a"[..], b"b", b"c"]);
        assert_eq!(calls[1][1].int(), 2);
    }

    /// The calls of a function that start a line, read as a table's rows;
    /// its definition and a call inside an expression are not.
    #[test]
    fn reads_calls_as_rows() {
        let src = "static void f(const char *a,\n int b)\n{\n}\n  f(\"x\" \"y\", (long)2);\n  f(NULL,\n    -1); /* c */\n  r = f(\"z\", 3);\n";
        let calls = calls_in(src, "f");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][0].str(), b"xy");
        assert_eq!(calls[0][1].word(), "(long)2");
        assert_eq!(calls[1][0].bytes(), None);
        assert_eq!(calls[1][1].int(), -1);
    }
}
