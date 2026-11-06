//! The operating-system interfaces the rest of the code reaches through
//! safe functions: the process's command line and environment, the
//! terminal, an error's text, matching a name against a pattern, the
//! locale, the C library's text mode, the local time of day, the user
//! database, random bytes, with `net` sockets, polling, the system's
//! resolver and
//! the waker, and with `fs` files, their extended attributes and
//! directories. Linux first, and Windows behind the same API, each as
//! C's build for it does; each module says what it needs of the
//! platform. A socket is named by [`socket`]'s names, the same on each.

/// Whether this is Windows' Unicode build, as C's with `ENABLE_UNICODE`
/// (`UNICODE`): the command line, the program's path and the names of
/// files are UTF-8, converted to and from the UTF-16 of the system's
/// calls, where the build without it takes them in the ANSI code page.
/// The environment is read in the ANSI code page either way, as C's
/// `curl_getenv` reads it. The one switch, the `unicode` feature; what
/// else depends on it reads it here.
pub const UNICODE: bool = cfg!(feature = "unicode");

#[cfg(all(feature = "unicode", not(windows)))]
compile_error!("the `unicode` feature is Windows' Unicode build (`ENABLE_UNICODE`)");

#[cfg(feature = "args")]
pub mod args;
// The reader of C's unit-test tables, for the ports here: curl-core's own
// file, compiled again, as this crate sits below curl-core.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../curl-core/src/c_source.rs"]
mod c_source;
pub mod env;
pub mod error;
pub mod fnmatch;
#[cfg(feature = "fs")]
pub mod fs;
pub mod locale;
#[cfg(feature = "net")]
pub mod net;
#[cfg(feature = "net")]
pub mod poll;
pub mod random;
#[cfg(feature = "net")]
pub mod resolve;
#[cfg(feature = "net")]
pub mod socket;
pub mod terminal;
pub mod text;
pub mod time;
pub mod users;
#[cfg(feature = "net")]
pub mod wake;
#[cfg(feature = "fs")]
pub mod xattr;
