//! The operating-system interfaces the rest of the code reaches through
//! safe functions: the process's command line, the terminal, the user
//! database. Linux first; each module says what it needs of the platform.

#[cfg(feature = "args")]
pub mod args;
pub mod terminal;
pub mod users;
