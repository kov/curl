//! The command line: the option table, how arguments are read, and what
//! each option does.
//!
//! `parse` follows `parse_args` and `getparameter` in
//! `src/tool_getparam.c` and `apply` its option handlers. Arguments stay
//! borrowed from the command line; nothing is copied.

mod apply;
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
    CommandLine, Global, Node, Operation, Output, Request, Resume, Trace, Unimplemented, Upload,
};
pub(crate) use errors::{ParamError, exit_code};
pub(crate) use help::{CATEGORIES, HELP, HelpLine};
pub(crate) use parse::{Parsed, parse};
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
