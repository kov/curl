//! The operating-system interfaces the rest of the code reaches through
//! safe functions: the process's command line, the terminal, the local
//! time of day, the user database, with `net` sockets, polling and the
//! waker, and with `fs` files and directories. Linux first; each module
//! says what it needs of the platform.

#[cfg(feature = "args")]
pub mod args;
#[cfg(feature = "fs")]
pub mod fs;
#[cfg(feature = "net")]
pub mod net;
#[cfg(feature = "net")]
pub mod poll;
pub mod terminal;
pub mod time;
pub mod users;
#[cfg(feature = "net")]
pub mod wake;
