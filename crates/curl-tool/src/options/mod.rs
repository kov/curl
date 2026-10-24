//! The command line: the option table, how arguments are read, and what
//! each option does.
//!
//! `parse` follows `parse_args` and `getparameter` in
//! `src/tool_getparam.c` and `apply` its option handlers. Arguments stay
//! borrowed from the command line; nothing is copied.

mod apply;
mod cert;
#[allow(
    dead_code,
    reason = "every C error kind is listed; not all are raised yet"
)]
#[rustfmt::skip]
mod errors;
#[rustfmt::skip]
mod help;
mod number;
mod parse;
mod protocols;
#[rustfmt::skip]
mod table;

pub(crate) use apply::{
    Clobber, CommandLine, Fail, Global, HttpVersion, Httpsig, IpVersion, Method, Node, Operation,
    Output, Request, Resume, Trace, Unimplemented, Upload,
};
pub(crate) use errors::{ParamError, exit_code};
pub(crate) use help::{CATEGORIES, HELP, HelpLine};
pub(crate) use number::leading_number;
#[cfg(test)]
pub(crate) use parse::parse_args;
pub(crate) use parse::{Parsed, has_tls, parse};
use table::{MAX_OPTION_LEN, OPTIONS, Opt};

/// What an option takes, as `ARG_*` in C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArgKind {
    /// Nothing.
    None,
    /// Nothing; `--no-` switches it off.
    Bool,
    /// A string.
    String,
    /// A file name.
    File,
    /// A number of seconds, possibly fractional.
    Seconds,
    /// A whole number, not negative.
    Unsigned,
}

impl ArgKind {
    fn takes_argument(self) -> bool {
        !matches!(self, ArgKind::None | ArgKind::Bool)
    }
}

/// An entry of the option table.
#[derive(Debug)]
pub(crate) struct Spec {
    /// The long name, without `--`.
    pub(crate) long: &'static str,
    pub(crate) short: Option<u8>,
    pub(crate) opt: Opt,
    pub(crate) kind: ArgKind,
    /// The short letter switches the option off (`-N` is `--no-buffer`).
    pub(crate) short_negates: bool,
    /// Needs a TLS-capable library.
    pub(crate) needs_tls: bool,
    /// The argument is a secret, such as a password.
    pub(crate) secret: bool,
    /// Accepted and ignored, with a warning.
    pub(crate) deprecated: bool,
}

/// Every option's long name, and what it takes. For tests.
#[cfg(test)]
pub(crate) fn every_option() -> impl Iterator<Item = (&'static str, ArgKind)> {
    OPTIONS.iter().map(|s| (s.long, s.kind))
}

/// Where `--help <option>` finds an option's text in the manual
/// (`tool_help`): the line it starts with, and what ends it.
pub(crate) struct HelpSearch {
    start: [u8; 40],
    len: usize,
    pub(crate) end: &'static [u8],
}

impl HelpSearch {
    pub(crate) fn start(&self) -> &[u8] {
        &self.start[..self.len]
    }
}

/// What to look for in the manual for `topic`: `--name`, `--no-name` for
/// a boolean, or `-x`; `None` for no option.
pub(crate) fn help_search(topic: &[u8]) -> Option<HelpSearch> {
    let spec = match topic {
        [b'-', b'-', name @ ..] => match name.strip_prefix(b"no-") {
            Some(name) => find_long(name).filter(|s| s.kind == ArgKind::Bool),
            None => find_long(name),
        },
        [b'-', letter] => find_short(*letter),
        _ => None,
    }?;
    let letter = spec.short.map(|l| [l]);
    let parts: [&[u8]; 3] = match &letter {
        Some(letter) => [b"\n    -", letter, b", --"],
        None if spec.short_negates => [b"\n    --no-", spec.long.as_bytes(), b""],
        None => [b"\n    ", topic, b""],
    };
    let mut start = [0u8; 40];
    let mut len = 0;
    for part in parts {
        start[len..len + part.len()].copy_from_slice(part);
        len += part.len();
    }
    // The last option's text ends where the files are described.
    let end: &[u8] = if spec.opt == Opt::Xattr {
        b"\nFILES"
    } else {
        b"\n    -"
    };
    Some(HelpSearch { start, len, end })
}

/// The option named `name`, as `findlongopt` finds it.
fn find_long(name: &[u8]) -> Option<&'static Spec> {
    OPTIONS
        .binary_search_by(|s| s.long.as_bytes().cmp(name))
        .ok()
        .map(|i| &OPTIONS[i])
}

/// The option with short letter `letter`, as `findshortopt` finds it:
/// printable ASCII only, and the last entry with the letter.
fn find_short(letter: u8) -> Option<&'static Spec> {
    if letter <= b' ' || letter >= 127 {
        return None;
    }
    OPTIONS.iter().rev().find(|s| s.short == Some(letter))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `find_long` is a binary search, as C's `bsearch`.
    #[test]
    fn table_is_sorted_and_names_fit() {
        assert!(
            OPTIONS
                .windows(2)
                .all(|w| w[0].long.as_bytes() < w[1].long.as_bytes())
        );
        assert!(OPTIONS.iter().all(|s| s.long.len() <= MAX_OPTION_LEN));
        assert!(
            OPTIONS
                .iter()
                .all(|s| find_long(s.long.as_bytes()).is_some_and(|f| f.opt == s.opt))
        );
    }

    /// `--help <option>` looks for the option's line as C's does.
    #[test]
    fn searches_the_manual_as_c_does() {
        let start = |t: &str| help_search(t.as_bytes()).map(|h| h.start().to_vec());
        assert_eq!(start("--verbose"), Some(b"\n    -v, --".to_vec()));
        assert_eq!(start("-v"), Some(b"\n    -v, --".to_vec()));
        assert_eq!(start("--no-clobber"), Some(b"\n    --no-clobber".to_vec()));
        assert_eq!(start("--clobber"), Some(b"\n    --no-clobber".to_vec()));
        assert_eq!(start("--compressed"), Some(b"\n    --compressed".to_vec()));
        assert_eq!(
            start("--no-compressed"),
            Some(b"\n    --no-compressed".to_vec())
        );
        assert_eq!(start("--no-url"), None, "not a boolean");
        assert_eq!(start("--badone"), None);
        assert_eq!(start("-vv"), None);
        assert_eq!(start("verbose"), None);
        assert_eq!(help_search(b"--xattr").unwrap().end, b"\nFILES");
        assert_eq!(help_search(b"--url").unwrap().end, b"\n    -");
        // Every option's fits the manual's search.
        for s in OPTIONS {
            let h = help_search(format!("--{}", s.long).as_bytes()).unwrap();
            assert!(h.len < 40, "{}", s.long);
        }
    }

    #[test]
    fn finds_options() {
        assert_eq!(find_long(b"url").map(|s| s.opt), Some(Opt::Url));
        assert!(find_long(b"ur").is_none(), "no abbreviations");
        assert_eq!(find_short(b'V').map(|s| s.opt), Some(Opt::Version));
        assert_eq!(find_short(b':').map(|s| s.opt), Some(Opt::Next));
        assert!(find_short(0).is_none());
        assert!(find_short(b' ').is_none());
        let buffer = find_short(b'N').unwrap();
        assert!(buffer.short_negates && buffer.long == "buffer");
    }
}
