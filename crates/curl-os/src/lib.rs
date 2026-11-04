//! The operating-system interfaces the rest of the code reaches through
//! safe functions: the process's command line and environment, the
//! terminal, an error's text, matching a name against a pattern, the
//! locale, the local time of day, the user database,
//! random bytes, with `net` sockets, polling, the system's resolver and
//! the waker, and with `fs` files, their extended attributes and
//! directories. Linux first, and Windows behind the same API, each as
//! C's build for it does; each module says what it needs of the
//! platform. A socket is named by [`socket`]'s names, the same on each.

#[cfg(feature = "args")]
pub mod args;
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
pub mod time;
pub mod users;
#[cfg(feature = "net")]
pub mod wake;
#[cfg(feature = "fs")]
pub mod xattr;
