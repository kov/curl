//! The operating-system interfaces the rest of the code reaches through
//! safe functions: the process's command line, the terminal, the user
//! database, and with `net` sockets, polling and the waker. Linux first;
//! each module says what it needs of the platform.

#[cfg(feature = "args")]
pub mod args;
#[cfg(feature = "net")]
pub mod net;
#[cfg(feature = "net")]
pub mod poll;
pub mod terminal;
pub mod users;
#[cfg(feature = "net")]
pub mod wake;
