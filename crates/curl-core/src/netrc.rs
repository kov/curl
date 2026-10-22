//! `.netrc` files (`lib/netrc.c`): the login and password a file gives
//! for a host, read when a transfer asks for them.
//!
//! The file is the user's, and read as untrusted input: bounded in size,
//! its tokens bounded in length, and anything it does not understand
//! passed over, as C passes it over.

use std::ffi::{CStr, OsString};
use std::os::unix::ffi::OsStringExt as _;

use curl_alloc::{OutOfMemory, TryVec as _};

/// The longest line read, its newline included, as C's line buffer.
const MAX_LINE: usize = 16384 - 1;
/// The most of the file kept, comments left out.
const MAX_FILE: usize = 128 * 1024 - 1;
/// The longest login, password or machine name.
const MAX_TOKEN: usize = 4096 - 1;

/// Why no credentials came from the file (`NETRCcode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetrcError {
    /// No entry matches.
    NoMatch,
    /// The file is malformed: a token or line too long, a quote not
    /// closed, the file too large.
    Syntax,
    /// The file is not there, or is a directory.
    FileMissing,
    OutOfMemory,
}

impl NetrcError {
    /// As C's `Curl_netrc_strerror` says it.
    pub(crate) fn text(self) -> &'static str {
        match self {
            NetrcError::FileMissing => "no such file",
            NetrcError::NoMatch => "no matching entry",
            NetrcError::OutOfMemory => "out of memory",
            NetrcError::Syntax => "syntax error",
        }
    }
}

impl From<OutOfMemory> for NetrcError {
    fn from(_: OutOfMemory) -> Self {
        NetrcError::OutOfMemory
    }
}

/// The credentials an entry gives.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Found {
    pub(crate) user: Vec<u8>,
    pub(crate) password: Vec<u8>,
}

/// Where the file is when the application names none: `$NETRC`, else
/// `.netrc` in `$HOME`, else in the user's home directory.
pub(crate) fn default_path() -> Result<Option<Vec<u8>>, OutOfMemory> {
    if let Some(path) = std::env::var_os("NETRC") {
        return Ok(Some(path.into_vec()));
    }
    let home = match std::env::var_os("HOME") {
        Some(home) => home,
        None => match curl_os::users::home_directory()? {
            Some(home) => home,
            None => return Ok(None),
        },
    };
    let mut path = OsString::into_vec(home);
    path.try_extend_from_slice(b"/.netrc")?;
    Ok(Some(path))
}

/// The file at `path`, its comment lines left out (`file2memory`).
pub(crate) fn load(path: &CStr) -> Result<Vec<u8>, NetrcError> {
    let Ok(mut file) = curl_os::fs::open_read(path) else {
        return Err(NetrcError::FileMissing);
    };
    if file.metadata().is_ok_and(|m| m.is_dir()) {
        return Err(NetrcError::FileMissing);
    }
    read_kept(&mut file)
}

/// What `input` holds, its comment lines left out; a read interrupted is
/// tried again, one failing is malformed, as C's `Curl_get_line` says.
fn read_kept(input: &mut impl std::io::Read) -> Result<Vec<u8>, NetrcError> {
    let mut kept = Kept::default();
    let mut chunk = [0u8; 4096];
    loop {
        match input.read(&mut chunk) {
            Ok(0) => return kept.finish(),
            Ok(n) => kept.feed(&chunk[..n])?,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(NetrcError::Syntax),
        }
    }
}

/// A file's lines as they are read, but those whose first non-blank byte
/// is `#`, each ended by a newline.
#[derive(Default)]
struct Kept {
    text: Vec<u8>,
    /// The line being read.
    line: Vec<u8>,
}

impl Kept {
    fn feed(&mut self, mut bytes: &[u8]) -> Result<(), NetrcError> {
        while !bytes.is_empty() {
            let end = bytes.iter().position(|&b| b == b'\n');
            let take = end.map_or(bytes.len(), |at| at + 1);
            if self.line.len() + take > MAX_LINE {
                return Err(NetrcError::Syntax);
            }
            self.line.try_extend_from_slice(&bytes[..take])?;
            bytes = &bytes[take..];
            if end.is_some() {
                self.keep_line()?;
            }
        }
        Ok(())
    }

    fn keep_line(&mut self) -> Result<(), NetrcError> {
        let blanks = self.line.iter().take_while(|&&b| blank(b)).count();
        let line = &self.line[blanks..];
        if line.first() != Some(&b'#') {
            if self.text.len() + line.len() > MAX_FILE {
                return Err(NetrcError::Syntax);
            }
            self.text.try_extend_from_slice(line)?;
        }
        self.line.clear();
        Ok(())
    }

    /// The text kept, the last line given its newline.
    fn finish(mut self) -> Result<Vec<u8>, NetrcError> {
        if !self.line.is_empty() {
            self.feed(b"\n")?;
        }
        Ok(self.text)
    }
}

#[cfg(test)]
fn without_comments(raw: &[u8]) -> Result<Vec<u8>, NetrcError> {
    let mut kept = Kept::default();
    kept.feed(raw)?;
    kept.finish()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    Eof,
    /// Its text is in the lexer's `literal`.
    Literal,
    Machine,
    Default,
    Account,
    Login,
    Password,
    Macdef,
    Junk,
}

/// The file's tokens, one at a time, one of which can be put back.
struct Lexer<'a> {
    text: &'a [u8],
    at: usize,
    literal: Vec<u8>,
    pushed: Option<Token>,
}

fn blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn newline(b: u8) -> bool {
    b == b'\r' || b == b'\n'
}

impl<'a> Lexer<'a> {
    fn new(text: &'a [u8]) -> Lexer<'a> {
        // C reads the text as a string: a zero byte ends it.
        let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
        Lexer {
            text: &text[..end],
            at: 0,
            literal: Vec::new(),
            pushed: None,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    /// Past blanks, then carriage returns, then a newline, again and
    /// again: blanks after a carriage return not before a newline stop
    /// it, as C's do (`netrc_skip_blanks`).
    fn skip_blanks(&mut self) {
        loop {
            while self.peek().is_some_and(blank) {
                self.at += 1;
            }
            while self.peek() == Some(b'\r') {
                self.at += 1;
            }
            if self.peek() != Some(b'\n') {
                return;
            }
            self.at += 1;
        }
    }

    /// Past the next empty line, which ends a macro.
    fn skip_to_empty_line(&mut self) {
        while let Some(b) = self.peek() {
            self.at += 1;
            if b == b'\n' {
                while self.peek() == Some(b'\r') {
                    self.at += 1;
                }
                if self.peek() == Some(b'\n') {
                    return;
                }
            }
        }
    }

    fn add(&mut self, bytes: &[u8]) -> Result<(), NetrcError> {
        if self.literal.len() + bytes.len() > MAX_TOKEN {
            return Err(NetrcError::Syntax);
        }
        self.literal.try_extend_from_slice(bytes)?;
        Ok(())
    }

    /// A quoted literal, after its opening quote: `\n`, `\r` and `\t`
    /// escaped, any other byte after a backslash taken as it is.
    fn quoted(&mut self) -> Result<(), NetrcError> {
        self.at += 1;
        let mut escape = false;
        while let Some(mut b) = self.peek() {
            self.at += 1;
            if escape {
                escape = false;
                b = match b {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    other => other,
                };
            } else if b == b'\\' {
                escape = true;
                continue;
            } else if b == b'"' {
                return Ok(());
            }
            self.add(&[b])?;
        }
        Err(NetrcError::Syntax)
    }

    /// The next token; a bare word is a literal if one is `wanted`, else
    /// a keyword or junk.
    fn next(&mut self, wanted: bool) -> Result<Token, NetrcError> {
        if let Some(token) = self.pushed.take() {
            return Ok(token);
        }
        self.literal.clear();
        self.skip_blanks();
        match self.peek() {
            None => Ok(Token::Eof),
            Some(b'"') => {
                self.quoted()?;
                Ok(Token::Literal)
            }
            Some(_) => {
                let start = self.at;
                while self.peek().is_some_and(|b| !blank(b) && !newline(b)) {
                    self.at += 1;
                }
                let word = &self.text[start..self.at];
                if wanted {
                    // An empty word, a blank after a carriage return, is
                    // an empty literal.
                    self.add(word)?;
                    return Ok(Token::Literal);
                }
                if word.is_empty() {
                    return Err(NetrcError::Syntax);
                }
                let is = |name: &str| word.eq_ignore_ascii_case(name.as_bytes());
                Ok(if is("machine") {
                    Token::Machine
                } else if is("default") {
                    Token::Default
                } else if is("account") {
                    Token::Account
                } else if is("login") {
                    Token::Login
                } else if is("password") {
                    Token::Password
                } else if is("macdef") {
                    Token::Macdef
                } else {
                    Token::Junk
                })
            }
        }
    }
}

/// The entry being read.
#[derive(Default)]
struct Entry {
    matches_host: bool,
    login: Option<Vec<u8>>,
    password: Option<Vec<u8>>,
}

/// The credentials `text` gives for `host`, and for `user` if one is
/// named: the first entry for the host, or `default`, with a login (the
/// user's, with a password) or a password alone (`netrc_scan`).
pub(crate) fn scan(text: &[u8], host: &[u8], user: Option<&[u8]>) -> Result<Found, NetrcError> {
    let user = user.filter(|u| !u.is_empty());
    let mut lexer = Lexer::new(text);
    let mut entry = Entry::default();
    loop {
        let token = lexer.next(false)?;
        if matches!(
            token,
            Token::Eof | Token::Machine | Token::Default | Token::Macdef
        ) {
            if let Some(found) = end_entry(&mut entry, user)? {
                return Ok(found);
            }
            entry = Entry::default();
        }
        match token {
            Token::Eof => return Err(NetrcError::NoMatch),
            Token::Machine => match lexer.next(true)? {
                Token::Literal => entry.matches_host = lexer.literal.eq_ignore_ascii_case(host),
                other => lexer.pushed = Some(other),
            },
            Token::Default => entry.matches_host = true,
            Token::Account => {
                literal(&mut lexer, false)?;
            }
            Token::Login => {
                if let Some(login) = literal(&mut lexer, entry.matches_host)? {
                    entry.login = Some(login);
                }
            }
            Token::Password => {
                if let Some(password) = literal(&mut lexer, entry.matches_host)? {
                    entry.password = Some(password);
                }
            }
            Token::Macdef => lexer.skip_to_empty_line(),
            Token::Literal | Token::Junk => {}
        }
    }
}

/// The literal after a keyword, copied if it is to be `kept`; anything
/// else is put back.
fn literal(lexer: &mut Lexer<'_>, kept: bool) -> Result<Option<Vec<u8>>, NetrcError> {
    match lexer.next(true)? {
        Token::Literal if kept => {
            let mut copy = Vec::new();
            copy.try_extend_from_slice(&lexer.literal)?;
            Ok(Some(copy))
        }
        Token::Literal => Ok(None),
        other => {
            lexer.pushed = Some(other);
            Ok(None)
        }
    }
}

/// What the entry gives, if it is the one (`netrc_scan_end_entry`).
fn end_entry(entry: &mut Entry, user: Option<&[u8]>) -> Result<Option<Found>, NetrcError> {
    if !entry.matches_host {
        return Ok(None);
    }
    let found = match (&entry.login, user) {
        (Some(login), Some(user)) => login == user && entry.password.is_some(),
        (Some(_), None) => true,
        (None, _) => entry.password.is_some(),
    };
    if !found {
        return Ok(None);
    }
    let user = match user {
        Some(user) => {
            let mut copy = Vec::new();
            copy.try_extend_from_slice(user)?;
            copy
        }
        None => entry.login.take().unwrap_or_default(),
    };
    Ok(Some(Found {
        user,
        password: entry.password.take().unwrap_or_default(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &[u8] = b"machine example.com login admin password passwd\n\
        machine curl.example.com login none password none\n";

    fn found(user: &str, password: &str) -> Result<Found, NetrcError> {
        Ok(Found {
            user: user.as_bytes().to_vec(),
            password: password.as_bytes().to_vec(),
        })
    }

    /// Unit 1304: hosts and users found and not.
    #[test]
    fn finds_entries_as_c() {
        let scan =
            |host: &str, user: Option<&str>| scan(FILE, host.as_bytes(), user.map(str::as_bytes));
        let none = Err(NetrcError::NoMatch);
        assert_eq!(scan("test.example.com", None), none);
        assert_eq!(scan("example.com", Some("me")), none);
        assert_eq!(scan("test.example.com", Some("me")), none);
        assert_eq!(scan("example.com", Some("a")), none);
        assert_eq!(scan("example.com", Some("administrator")), none);
        assert_eq!(scan("example.com", None), found("admin", "passwd"));
        assert_eq!(scan("curl.example.com", None), found("none", "none"));
        assert_eq!(scan("curl.example.com", Some("hilarious")), none);
        assert_eq!(scan("EXAMPLE.com", Some("admin")), found("admin", "passwd"));
        assert_eq!(scan("example.com", Some("")), found("admin", "passwd"));
    }

    /// Unit 1304's empty literals.
    #[test]
    fn reads_empty_literals_as_c() {
        let scan = |text: &str| scan(text.as_bytes(), b"example.com", None);
        assert_eq!(scan("default login \"\""), found("", ""));
        assert_eq!(scan("default password \"\""), found("", ""));
        assert_eq!(
            scan("default login \"\" password secret"),
            found("", "secret")
        );
        assert_eq!(
            scan("default password \"\" login admin"),
            found("admin", "")
        );
        assert_eq!(scan("default login \"\" password \"\""), found("", ""));
        assert_eq!(
            scan("machine \"\" login ignored password ignored"),
            Err(NetrcError::NoMatch)
        );
        assert_eq!(
            scan(
                "machine \"\" login ignored password ignored\n\
                 machine example.com login admin password passwd"
            ),
            found("admin", "passwd")
        );
        assert_eq!(
            scan("machine example.com login \"\" password \"\""),
            found("", "")
        );
    }

    /// Quotes, escapes, macros, keywords in any case, and what is passed
    /// over; a user named is found only with a password.
    #[test]
    fn reads_the_rest_of_the_grammar() {
        let scan =
            |text: &str, user: Option<&str>| scan(text.as_bytes(), b"h", user.map(str::as_bytes));
        assert_eq!(
            scan("MACHINE h LOGIN \"a b\\\"\\n\" PASSWORD p\\x", None),
            found("a b\"\n", "p\\x")
        );
        assert_eq!(
            scan("macdef m\nmachine h login x\n\nmachine h login y", None),
            found("y", ""),
            "a macro runs to an empty line"
        );
        assert_eq!(scan("junk machine h junk login u", None), found("u", ""));
        assert_eq!(
            scan("machine h login u\nmachine h login u password p", Some("u")),
            found("u", "p")
        );
        assert_eq!(scan("machine h password p", Some("me")), found("me", "p"));
        assert_eq!(scan("machine h account a login u", None), found("u", ""));
        assert_eq!(
            scan("machine h login \"open", None),
            Err(NetrcError::Syntax)
        );
        assert_eq!(scan("machine", None), Err(NetrcError::NoMatch));
        assert_eq!(scan("machine h login", None), Err(NetrcError::NoMatch));
        assert_eq!(scan("machine h\0 login u", None), Err(NetrcError::NoMatch));
        // A blank after a carriage return is an empty word: a syntax
        // error where a keyword is due, an empty literal where one is.
        assert_eq!(scan("machine h\r login u", None), Err(NetrcError::Syntax));
        assert_eq!(scan("machine h login\r u", None), found("", ""));
        assert_eq!(scan("machine h\r\nlogin u\r\n", None), found("u", ""));
        let long = format!("machine h login {}", "x".repeat(MAX_TOKEN));
        assert_eq!(scan(&long, None), found(&"x".repeat(MAX_TOKEN), ""));
        let longer = format!("machine h login {}", "x".repeat(MAX_TOKEN + 1));
        assert_eq!(scan(&longer, None), Err(NetrcError::Syntax));
    }

    /// Comment lines go as the file is read; every line ends with a
    /// newline; a line or a file too long is malformed.
    #[test]
    fn leaves_out_comments_and_bounds_lines() {
        assert_eq!(
            without_comments(b"a\n  # c\n\t#d\nb").unwrap(),
            b"a\nb\n".to_vec()
        );
        let line = vec![b'x'; MAX_LINE - 1];
        assert!(without_comments(&line).is_ok());
        let line = vec![b'x'; MAX_LINE];
        assert_eq!(without_comments(&line), Err(NetrcError::Syntax));
        let mut many = Vec::new();
        while many.len() <= MAX_FILE {
            many.extend_from_slice(&[b'x'; 99]);
            many.push(b'\n');
        }
        assert_eq!(without_comments(&many), Err(NetrcError::Syntax));
        let comments: Vec<u8> = many
            .iter()
            .map(|&b| if b == b'x' { b'#' } else { b })
            .collect();
        assert_eq!(
            without_comments(&comments).unwrap(),
            b"".to_vec(),
            "only what is kept counts"
        );
    }

    /// C's bounds (`MAX_NETRC_LINE`, `MAX_NETRC_FILE`, `MAX_NETRC_TOKEN`),
    /// each a buffer of that size with room for its terminator.
    #[test]
    fn bounds_lines_files_and_tokens_as_c() {
        let mut line = vec![b'x'; 16382];
        line.push(b'\n');
        assert!(without_comments(&line).is_ok());
        line.insert(0, b'x');
        assert_eq!(without_comments(&line), Err(NetrcError::Syntax));
        // 131071 bytes kept, in lines.
        let mut file = Vec::new();
        for _ in 0..1310 {
            file.extend_from_slice(&[b'x'; 99]);
            file.push(b'\n');
        }
        file.extend_from_slice(&[b'x'; 70]);
        assert_eq!(without_comments(&file).map(|t| t.len()), Ok(131071));
        file.push(b'x');
        assert_eq!(without_comments(&file), Err(NetrcError::Syntax));
        let token = |n: usize| {
            let text = format!("machine h login {}", "x".repeat(n));
            scan(text.as_bytes(), b"h", None).map(|f| f.user.len())
        };
        assert_eq!(token(4095), Ok(4095));
        assert_eq!(token(4096), Err(NetrcError::Syntax));
    }

    /// A macro ends only at an empty line, carriage returns allowed
    /// before its newline.
    #[test]
    fn ends_a_macro_at_an_empty_line() {
        let scan = |text: &str| scan(text.as_bytes(), b"h", None);
        assert_eq!(
            scan("macdef m\nbody\n\rmachine h login b"),
            Err(NetrcError::NoMatch)
        );
        assert_eq!(
            scan("macdef m\nbody\n\r\r\nmachine h login b"),
            found("b", "")
        );
    }

    /// A read interrupted is made again; one failing is a syntax error,
    /// as C's `Curl_get_line` failing is.
    #[test]
    fn reads_again_when_interrupted() {
        use std::io::{Error, ErrorKind};
        struct Reads(Vec<Result<&'static [u8], ErrorKind>>);
        impl std::io::Read for Reads {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                assert!(!self.0.is_empty(), "read after the end");
                match self.0.remove(0) {
                    Ok(bytes) => {
                        buf[..bytes.len()].copy_from_slice(bytes);
                        Ok(bytes.len())
                    }
                    Err(kind) => Err(Error::from(kind)),
                }
            }
        }
        let mut interrupted = Reads(vec![
            Ok(b"machine h\n"),
            Err(ErrorKind::Interrupted),
            Ok(b"login u"),
            Ok(b""),
        ]);
        assert_eq!(
            read_kept(&mut interrupted),
            Ok(b"machine h\nlogin u\n".to_vec())
        );
        let mut failing = Reads(vec![Ok(b"machine h\n"), Err(ErrorKind::Other)]);
        assert_eq!(read_kept(&mut failing), Err(NetrcError::Syntax));
    }

    /// `$NETRC`, else `.netrc` in `$HOME`.
    #[test]
    fn finds_the_file_as_c() {
        let path = default_path().unwrap();
        if let Some(netrc) = std::env::var_os("NETRC") {
            assert_eq!(path, Some(netrc.into_vec()));
        } else if let Some(home) = std::env::var_os("HOME") {
            let mut want = home.into_vec();
            want.extend_from_slice(b"/.netrc");
            assert_eq!(path, Some(want));
        } else {
            assert!(path.is_none_or(|p| p.ends_with(b"/.netrc")));
        }
    }
}
