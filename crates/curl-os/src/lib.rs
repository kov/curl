//! The operating-system interfaces the rest of the code reaches through
//! safe functions: the process's command line and environment, the
//! terminal, the local time of day, the user database, random bytes,
//! with `net` sockets, polling, the system's resolver and the waker, and
//! with `fs` files and directories. Linux first; each module says what
//! it needs of the platform.

#[cfg(feature = "args")]
pub mod args;
pub mod env;
#[cfg(feature = "fs")]
pub mod fs;
#[cfg(feature = "net")]
pub mod net;
#[cfg(feature = "net")]
pub mod poll;
pub mod random;
#[cfg(feature = "net")]
pub mod resolve;
pub mod terminal;
pub mod time;
pub mod users;
#[cfg(feature = "net")]
pub mod wake;
