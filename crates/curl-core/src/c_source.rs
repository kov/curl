//! The tables of C's unit tests, read from their source when a port runs
//! (DESIGN.md, "Ported unit tests"), so a port checks the cases its
//! original does rather than a copy of them.
//!
//! A table is a C initializer: braces holding values, each a string
//! (adjacent literals joined, escapes read as C reads them), a group in
//! braces, or a word (a number, a name, `NULL`). Lines of the
//! preprocessor inside it are weighed by the caller: a row is kept when
//! every condition it sits under holds. A test driven by calls rather
//! than a table has its calls' arguments read the same way.
//!
//! Only tests read it, so it allocates as tests do, and a source it
//! cannot read is a failed test.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

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
    let mut p = Parser {
        s: src.as_bytes(),
        at: open,
        conditions: Vec::new(),
        holds: &holds,
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
            };
            found.push(p.items(b')'));
        }
        at += line.len();
    }
    found
}

struct Parser<'a, F> {
    s: &'a [u8],
    at: usize,
    /// The conditions of the `#if`s open, each with whether it holds.
    conditions: Vec<(String, bool)>,
    holds: &'a F,
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
            b'"' => {
                let mut bytes = Vec::new();
                while self.peek() == b'"' {
                    self.literal(&mut bytes);
                    self.skip();
                }
                Value::Str(bytes)
            }
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
                self.word()
            }
            _ => self.word(),
        }
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
