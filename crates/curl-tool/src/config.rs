//! Configuration files: finding the default one, as `findfile(".curlrc",
//! ...)` in `src/tool_findfile.c` finds it on Unix, and reading one into
//! options and their arguments, as `parseconfig` in `src/tool_parsecfg.c`
//! reads it.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use curl_alloc::{OutOfMemory, TryVec};

/// Whether the command line lets the default configuration file be read:
/// not if its first argument starts with `-q` or is `--disable`.
pub(crate) fn reads_curlrc(argv: &[OsString]) -> bool {
    argv.get(1).is_none_or(|first| {
        let first = first.as_encoded_bytes();
        !first.starts_with(b"-q") && first != b"--disable"
    })
}

/// Where to look, in order: a variable naming a directory, what to append
/// to it, and whether the file is `curlrc` there rather than `.curlrc`.
const PLACES: &[(&str, &str, bool)] = &[
    ("CURL_HOME", "", false),
    ("XDG_CONFIG_HOME", "", true),
    ("HOME", "", false),
    // `curlrc` is looked for in one directory only: the first of these
    // whose variable is set.
    ("CURL_HOME", "/.config", true),
    ("HOME", "/.config", true),
];

/// The default configuration file, if there is one: the first readable
/// one of the places C looks, and last `.curlrc` in the home directory the
/// user database names. `env` reads a variable, `home` asks the user
/// database, `readable` checks a file can be opened.
pub(crate) fn find_curlrc(
    env: impl Fn(&str) -> Result<Option<OsString>, OutOfMemory>,
    home: impl FnOnce() -> Result<Option<OsString>, OutOfMemory>,
    readable: impl Fn(&Path) -> bool,
) -> Result<Option<PathBuf>, OutOfMemory> {
    let mut without_dot_tried = false;
    for &(var, append, without_dot) in PLACES {
        let Some(dir) = env(var)?.filter(|d| !d.is_empty()) else {
            continue;
        };
        if without_dot {
            if without_dot_tried {
                continue;
            }
            without_dot_tried = true;
        }
        let name: &[u8] = if without_dot { b"curlrc" } else { b".curlrc" };
        let path = join(&[dir.as_bytes(), append.as_bytes(), b"/", name])?;
        if readable(&path) {
            return Ok(Some(path));
        }
    }
    if let Some(dir) = home()? {
        let path = join(&[dir.as_bytes(), b"/.curlrc"])?;
        if readable(&path) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn join(parts: &[&[u8]]) -> Result<PathBuf, OutOfMemory> {
    let mut path = Vec::new();
    for part in parts {
        path.try_extend_from_slice(part)?;
    }
    Ok(PathBuf::from(OsString::from_vec(path)))
}

/// Whether `path` can be opened for reading, as `checkhome` checks it.
pub(crate) fn readable(path: &Path) -> bool {
    curl_os::fs::with_c_name(path.as_os_str().as_bytes(), curl_os::fs::open_read).is_ok()
}

/// The longest line a configuration file may have
/// (`MAX_CONFIG_LINE_LENGTH`).
const MAX_LINE: usize = 10 * 1024 * 1024;

/// One line of a configuration file: an option, with or without its
/// dashes, and what follows it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Entry<'t> {
    /// The line's number, from 1, as C counts them: blank lines and
    /// comments are not.
    pub(crate) number: usize,
    pub(crate) option: &'t [u8],
    /// The argument; a quoted empty one is there, an unquoted one is not.
    pub(crate) argument: Option<&'t [u8]>,
    /// What to warn of, in order, before the option is read.
    pub(crate) warnings: &'static [Warning],
}

/// A line whose argument is likely not what was meant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Warning {
    LeadingSingleQuote,
    UnquotedWhitespace,
}

impl Warning {
    /// The warning's text after the option's name.
    pub(crate) fn text(self) -> &'static [u8] {
        match self {
            Warning::LeadingSingleQuote => {
                b"' uses argument with leading single quote. It is probably a mistake. \
                  Consider double quotes."
            }
            Warning::UnquotedWhitespace => {
                b"' uses argument with unquoted whitespace. This may cause side-effects. \
                  Consider double quotes."
            }
        }
    }
}

/// Why a configuration file was not read whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unread {
    /// A line too long (`my_get_line`'s error).
    TooLong,
    OutOfMemory,
}

/// An entry as places in the text, before the text is borrowed.
struct Spans {
    number: usize,
    option: (usize, usize),
    argument: Option<(usize, usize)>,
    warnings: &'static [Warning],
}

/// The entries of `text`, a configuration file's bytes. Blank lines and
/// those whose first byte not a blank is `#` are passed over. A quoted
/// argument is undone in place, as it is never longer than the quoted.
pub(crate) fn entries(text: &mut [u8]) -> Result<Vec<Entry<'_>>, Unread> {
    let mut spans = Vec::new();
    let mut start = 0;
    let mut number = 0;
    while start < text.len() {
        let end = text[start..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(text.len(), |at| start + at);
        // C reads the line with its newline into a buffer of `MAX_LINE`
        // bytes, its terminating zero counted.
        let newline = usize::from(end < text.len());
        if end - start + newline >= MAX_LINE {
            return Err(Unread::TooLong);
        }
        // C reads it as a string.
        let line_end = text[start..end]
            .iter()
            .position(|&b| b == 0)
            .map_or(end, |at| start + at);
        let first = text[start..line_end].iter().position(|b| !is_blank(*b));
        if first.is_some_and(|at| text[start + at] != b'#') {
            number += 1;
            spans
                .try_push(entry(text, start, line_end, number))
                .map_err(|OutOfMemory| Unread::OutOfMemory)?;
        }
        start = end + 1;
    }
    let text: &[u8] = text;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(spans.len())
        .map_err(|_| Unread::OutOfMemory)?;
    for span in spans {
        let entry = Entry {
            number: span.number,
            option: &text[span.option.0..span.option.1],
            argument: span.argument.map(|(from, to)| &text[from..to]),
            warnings: span.warnings,
        };
        entries
            .try_push(entry)
            .map_err(|OutOfMemory| Unread::OutOfMemory)?;
    }
    Ok(entries)
}

/// The buffer `parse_url` reads a file of URLs with: a line, its newline
/// and a zero byte fit in it.
const URL_LINE_BUFFER: usize = 8092;

/// The buffer `parse_header` reads a file of headers with.
const HEADER_LINE_BUFFER: usize = 1024 * 100;

/// The URLs of `text`, a file of them one a line, as `parse_url` reads it.
pub(crate) fn url_lines(text: &[u8]) -> impl Iterator<Item = Result<&[u8], Unread>> {
    lines(text, URL_LINE_BUFFER)
}

/// The headers of `text`, a file of them one a line, as `parse_header`
/// reads it for `-H @file` and `--proxy-header @file`.
pub(crate) fn header_lines(text: &[u8]) -> impl Iterator<Item = Result<&[u8], Unread>> {
    lines(text, HEADER_LINE_BUFFER)
}

/// The lines of `text` as `my_get_line` reads them into a buffer of
/// `buffer` bytes: blank lines and comments are passed over, the newline
/// is dropped and a carriage return before it kept, and a line is taken
/// up to a zero byte. `Err` for a line longer than the buffer holds with
/// its newline and a zero byte.
fn lines(text: &[u8], buffer: usize) -> impl Iterator<Item = Result<&[u8], Unread>> {
    text.split_inclusive(|&b| b == b'\n')
        .filter_map(move |line| {
            if line.len() + 1 > buffer {
                return Some(Err(Unread::TooLong));
            }
            let line = line.strip_suffix(b"\n").unwrap_or(line);
            let line = &line[..line.iter().position(|&b| b == 0).unwrap_or(line.len())];
            let first = line.iter().position(|b| !is_blank(*b))?;
            (line[first] != b'#').then_some(Ok(line))
        })
}

fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// `parseconfig`'s reading of the line `text[start..end]`, and
/// `extract_param`'s.
fn entry(text: &mut [u8], start: usize, end: usize, number: usize) -> Spans {
    // A name without dashes may be followed by `=` or `:`.
    let dashed = text[start] == b'-';
    let separator = |b: u8| !dashed && (b == b'=' || b == b':');
    let name_end = text[start..end]
        .iter()
        .position(|&b| is_blank(b) || separator(b))
        .map_or(end, |at| start + at);
    // Blanks and separators are passed over, the byte that ended the
    // name among them.
    let mut at = name_end;
    while at < end && (is_blank(text[at]) || separator(text[at])) {
        at += 1;
    }
    let mut quote = false;
    let mut space = false;
    let argument = if at < end && text[at] == b'"' {
        Some(unquote(text, at + 1, end))
    } else {
        quote = at < end && text[at] == b'\'';
        let is_space = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
        let arg_end = text[at..end]
            .iter()
            .position(|&b| is_space(b))
            .map_or(end, |len| at + len);
        // Something after the argument but a comment is likely a mistake.
        if arg_end < end {
            let more = text[arg_end + 1..end].iter().find(|&&b| !is_blank(b));
            space = more.is_some_and(|b| !matches!(b, b'\r' | b'\n' | b'#'));
        }
        (arg_end > at).then_some((at, arg_end))
    };
    let warnings: &[Warning] = match (quote, space) {
        (false, false) => &[],
        (true, false) => &[Warning::LeadingSingleQuote],
        (false, true) => &[Warning::UnquotedWhitespace],
        (true, true) => &[Warning::LeadingSingleQuote, Warning::UnquotedWhitespace],
    };
    Spans {
        number,
        option: (start, name_end),
        argument,
        warnings,
    }
}

/// Undo the quoting of `text[from..end]` up to its closing double quote, in
/// place: `\t`, `\n`, `\r` and `\v` are those bytes, any other escaped
/// byte itself (`unslashquote`). Where the unquoted bytes are.
fn unquote(text: &mut [u8], from: usize, end: usize) -> (usize, usize) {
    let mut read = from;
    let mut write = from;
    while read < end && text[read] != b'"' {
        let mut b = text[read];
        if b == b'\\' {
            read += 1;
            if read == end {
                break;
            }
            b = match text[read] {
                b't' => b'\t',
                b'n' => b'\n',
                b'r' => b'\r',
                b'v' => 0x0b,
                other => other,
            };
        }
        text[write] = b;
        write += 1;
        read += 1;
    }
    (from, write)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(vars: &[(&str, &str)], files: &[&str]) -> Option<String> {
        find_with_home(vars, None, files)
    }

    fn find_with_home(vars: &[(&str, &str)], home: Option<&str>, files: &[&str]) -> Option<String> {
        let env = |v: &str| {
            Ok(vars
                .iter()
                .find(|(k, _)| *k == v)
                .map(|(_, d)| OsString::from(d)))
        };
        let readable = |p: &Path| files.iter().any(|f| Path::new(f) == p);
        find_curlrc(env, || Ok(home.map(OsString::from)), readable)
            .unwrap()
            .map(|p| p.display().to_string())
    }

    /// The order of `findfile` with `CURLRC_DOTSCORE` 1.
    #[test]
    fn looks_where_c_looks() {
        let all = [
            "/c/.curlrc",
            "/x/curlrc",
            "/h/.curlrc",
            "/c/.config/curlrc",
            "/h/.config/curlrc",
        ];
        let vars = [
            ("CURL_HOME", "/c"),
            ("XDG_CONFIG_HOME", "/x"),
            ("HOME", "/h"),
        ];
        assert_eq!(find(&vars, &all).as_deref(), Some("/c/.curlrc"));
        assert_eq!(find(&vars, &all[1..]).as_deref(), Some("/x/curlrc"));
        assert_eq!(find(&vars, &all[2..]).as_deref(), Some("/h/.curlrc"));
        // A set `XDG_CONFIG_HOME` rules out the `.config` directories.
        assert_eq!(find(&vars, &all[3..]), None);
        let no_xdg = [("CURL_HOME", "/c"), ("HOME", "/h")];
        assert_eq!(
            find(&no_xdg, &all[3..]).as_deref(),
            Some("/c/.config/curlrc")
        );
        // So does a set `CURL_HOME`, for `HOME`'s.
        assert_eq!(find(&no_xdg, &all[4..]), None);
        assert_eq!(
            find(&[("HOME", "/h")], &all[4..]).as_deref(),
            Some("/h/.config/curlrc")
        );
        // An empty variable is skipped, and does not count as set.
        let empty_xdg = [("XDG_CONFIG_HOME", ""), ("HOME", "/h")];
        assert_eq!(
            find(&empty_xdg, &all[4..]).as_deref(),
            Some("/h/.config/curlrc")
        );
        assert_eq!(find(&[], &all), None);
    }

    /// Last, `.curlrc` in the user database's home directory, never
    /// `.config/curlrc` there.
    /// A file is readable when it can be opened, and a missing one is
    /// not.
    #[test]
    fn readable_is_whether_it_opens() {
        let path = std::env::temp_dir().join(format!("curl-config-{}", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        assert!(readable(&path));
        std::fs::remove_file(&path).unwrap();
        assert!(!readable(&path));
    }

    #[test]
    fn then_the_users_home() {
        let files = ["/p/.curlrc", "/p/.config/curlrc", "/h/.curlrc"];
        assert_eq!(
            find_with_home(&[], Some("/p"), &files).as_deref(),
            Some("/p/.curlrc")
        );
        assert_eq!(find_with_home(&[], Some("/p"), &files[1..]), None);
        let home = [("HOME", "/h")];
        assert_eq!(
            find_with_home(&home, Some("/p"), &files).as_deref(),
            Some("/h/.curlrc")
        );
        assert_eq!(find_with_home(&[], None, &files), None);
    }

    fn read(text: &str) -> Vec<(usize, String, Option<String>, &'static [Warning])> {
        let mut text = text.as_bytes().to_vec();
        entries(&mut text)
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e.number,
                    String::from_utf8(e.option.to_vec()).unwrap(),
                    e.argument.map(|a| String::from_utf8(a.to_vec()).unwrap()),
                    e.warnings,
                )
            })
            .collect()
    }

    /// `parseconfig`: a name, separators if it has no dashes, then an
    /// argument plain or quoted; comments and blank lines are skipped, and
    /// not counted. A line's first byte starts the name, even a blank.
    #[test]
    fn reads_lines_as_c_does() {
        use Warning::*;
        let s = |t: &str| Some(t.to_string());
        let text = "# comment\n  \nurl = \"http://a/\\\"q\\t\"\n-o:x\nsilent\n\
                    header: 'a b' c\nreferer=\"\"\n\tfail # yes\noutput   y\r\nlast";
        assert_eq!(
            read(text),
            [
                (1, "url".into(), s("http://a/\"q\t"), &[][..]),
                (2, "-o:x".into(), None, &[]),
                (3, "silent".into(), None, &[]),
                (
                    4,
                    "header".into(),
                    s("'a"),
                    &[LeadingSingleQuote, UnquotedWhitespace]
                ),
                (5, "referer".into(), s(""), &[]),
                (6, "".into(), s("fail"), &[]),
                (7, "output".into(), s("y"), &[]),
                (8, "last".into(), None, &[]),
            ]
        );
    }

    /// A comment after blanks on any line, a quote left open, a carriage
    /// return inside the line, and a zero on the last line, which C
    /// reads the line up to.
    #[test]
    fn reads_odd_lines_as_c_does() {
        use Warning::*;
        let s = |t: &str| Some(t.to_string());
        let text = "silent\n  # c\nurl \"abc\nfail\noutput y\rz\nurl x\0y";
        assert_eq!(
            read(text),
            [
                (1, "silent".into(), None, &[][..]),
                (2, "url".into(), s("abc"), &[]),
                (3, "fail".into(), None, &[]),
                (4, "output".into(), s("y"), &[UnquotedWhitespace]),
                (5, "url".into(), s("x"), &[]),
            ]
        );
        assert_eq!(read("url \"abc"), [(1, "url".into(), s("abc"), &[][..])]);
    }

    /// A zero byte ends its line and nothing more: the next line is read
    /// as its own, and so is a line after one starting with a zero. C reads
    /// in 128-byte `fgets` pieces and stops a piece at its zero: the rest
    /// of the piece is lost, its newline with it, and the next line is
    /// glued on (`write-out "A-s`); a piece starting with a zero ends the
    /// file there (DIVERGENCE.md).
    #[test]
    fn a_zero_byte_ends_its_line_alone() {
        let s = |t: &str| Some(t.to_string());
        assert_eq!(
            read("write-out \"A\0zz\n-s\n"),
            [
                (1, "write-out".into(), s("A"), &[][..]),
                (2, "-s".into(), None, &[]),
            ]
        );
        assert_eq!(
            read("write-out X\n\0\nwrite-out Y\n"),
            [
                (1, "write-out".into(), s("X"), &[][..]),
                (2, "write-out".into(), s("Y"), &[]),
            ]
        );
    }

    /// A line, its newline and C's zero fit in 10 MiB, on any line.
    #[test]
    fn refuses_a_line_too_long() {
        let max = 10 * 1024 * 1024;
        let read = |len: usize, newline: bool| {
            let mut text = b"silent\n".to_vec();
            text.resize(text.len() + len, b'#');
            if newline {
                text.push(b'\n');
            }
            entries(&mut text).map(|e| e.len())
        };
        assert_eq!(read(max - 2, true), Ok(1));
        assert_eq!(read(max - 1, true), Err(Unread::TooLong));
        assert_eq!(read(max - 1, false), Ok(1));
        assert_eq!(read(max, false), Err(Unread::TooLong));
    }

    /// One URL a line, comments and blank lines left out, a line as long as
    /// C's buffer holds and no longer.
    #[test]
    fn reads_urls_a_line_each() {
        let urls = |text: &[u8]| -> Vec<Result<Vec<u8>, Unread>> {
            url_lines(text).map(|u| u.map(<[u8]>::to_vec)).collect()
        };
        assert_eq!(
            urls(b"http://a/\n\n  # no\n  http://b/ x\r\nhttp://c/\0rest\nlast"),
            [
                Ok(b"http://a/".to_vec()),
                Ok(b"  http://b/ x\r".to_vec()),
                Ok(b"http://c/".to_vec()),
                Ok(b"last".to_vec()),
            ]
        );
        let mut long = vec![b'a'; 8090];
        long.push(b'\n');
        assert_eq!(urls(&long), [Ok(vec![b'a'; 8090])]);
        long.insert(0, b'a');
        assert_eq!(urls(&long), [Err(Unread::TooLong)]);
        long.pop();
        assert_eq!(urls(&long), [Ok(vec![b'a'; 8091])]);
    }

    /// A zero byte ends its URL line and nothing more: the next line is a
    /// URL of its own, and so is a line after one starting with a zero.
    /// C reads a file of URLs as it reads a config file: `a` NUL `zz`, then
    /// `b`, is one URL `ab`, and a line starting with a zero ends the file
    /// (DIVERGENCE.md).
    #[test]
    fn a_zero_byte_ends_its_url_line_alone() {
        let urls = |text: &[u8]| -> Vec<Vec<u8>> {
            url_lines(text).map(|u| u.unwrap().to_vec()).collect()
        };
        assert_eq!(
            urls(b"http://h/a\0zz\nhttp://h/b\n"),
            [b"http://h/a".to_vec(), b"http://h/b".to_vec()]
        );
        assert_eq!(
            urls(b"http://h/a\n\0\nhttp://h/b\n"),
            [b"http://h/a".to_vec(), b"http://h/b".to_vec()]
        );
    }

    /// One header a line, as `-H @file` reads them: comments and blank
    /// lines left out, a carriage return and leading blanks kept, a line
    /// as long as C's buffer of 100 KiB holds and no longer.
    #[test]
    fn reads_headers_a_line_each() {
        let headers = |text: &[u8]| -> Vec<Result<Vec<u8>, Unread>> {
            header_lines(text).map(|h| h.map(<[u8]>::to_vec)).collect()
        };
        assert_eq!(
            headers(b"One: 1\r\n\r\n \t\n# c\n  # c2\nno-colon\n\tTab: t\nLast: x"),
            [
                Ok(b"One: 1\r".to_vec()),
                Ok(b"\r".to_vec()),
                Ok(b"no-colon".to_vec()),
                Ok(b"\tTab: t".to_vec()),
                Ok(b"Last: x".to_vec()),
            ]
        );
        assert_eq!(headers(b""), []);
        let mut long = vec![b'a'; 102_398];
        long.push(b'\n');
        assert_eq!(headers(&long), [Ok(vec![b'a'; 102_398])]);
        long.insert(0, b'a');
        assert_eq!(headers(&long), [Err(Unread::TooLong)]);
    }

    /// A zero byte ends its header line and nothing more, as it ends a URL
    /// line: in C, `X-A: 1` NUL `zz`, then `X-B: 2`, is one header `X-A:
    /// 1X-B: 2`, and a line starting with a zero ends the file
    /// (DIVERGENCE.md).
    #[test]
    fn a_zero_byte_ends_a_header_file_line_alone() {
        let headers = |text: &[u8]| -> Vec<Vec<u8>> {
            header_lines(text).map(|h| h.unwrap().to_vec()).collect()
        };
        assert_eq!(
            headers(b"X-A: 1\0zz\nX-B: 2\n\0\nX-C: 3\n"),
            [b"X-A: 1".to_vec(), b"X-B: 2".to_vec(), b"X-C: 3".to_vec()]
        );
    }

    #[test]
    fn q_or_disable_first_skips_it() {
        let argv = |a: &[&str]| -> Vec<OsString> { a.iter().map(OsString::from).collect() };
        assert!(reads_curlrc(&argv(&["curl"])));
        assert!(reads_curlrc(&argv(&["curl", "-v", "-q"])));
        assert!(!reads_curlrc(&argv(&["curl", "-q"])));
        assert!(!reads_curlrc(&argv(&["curl", "-qV"])));
        assert!(!reads_curlrc(&argv(&["curl", "--disable"])));
        assert!(reads_curlrc(&argv(&["curl", "--disable-eprt"])));
    }

    const WORDS: &[&[u8]] = &[
        b"url",
        b"--url",
        b"-o",
        b"output",
        b"=",
        b":",
        b" ",
        b"\t",
        b"\"",
        b"\\",
        b"\\t",
        b"\\n",
        b"\\x",
        b"'",
        b"#",
        b"\n",
        b"\r\n",
        b"\r",
        b"\0",
        b"x y",
        b"http://h/",
    ];
    const FILES: &[&[u8]] = &[
        b"url = \"http://x/\"\n# comment\n-o file\n",
        b"--data \"a\\\"b\\tc\"\n  silent\n",
        b"header: 'x y'\nverbose\n",
        b"http://a/\n\n#http://b/\nhttp://c/\0d\n",
    ];

    proptest::proptest! {
        #![proptest_config(crate::untrusted::config(512))]

        /// Any file is read into entries, numbered in order, or refused;
        /// any file of URLs gives its lines or refuses one.
        #[test]
        fn any_file_is_read_or_refused(text in crate::untrusted::input(WORDS, FILES, 40)) {
            let mut text = text;
            for url in url_lines(&text).flatten() {
                proptest::prop_assert!(url.len() < URL_LINE_BUFFER);
            }
            if let Ok(entries) = entries(&mut text) {
                for (i, e) in entries.iter().enumerate() {
                    proptest::prop_assert_eq!(e.number, i + 1);
                }
            }
        }
    }
}
