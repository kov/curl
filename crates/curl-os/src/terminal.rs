//! The terminal the process writes to.

#![allow(unsafe_code)]

/// The width of the terminal on standard input, output or error, the
/// first that is one, as `get_terminal_columns` asks in C. `None` when
/// none is a terminal.
pub fn columns() -> Option<u16> {
    [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO]
        .into_iter()
        .find_map(|fd| {
            let mut size = libc::winsize {
                ws_row: 0,
                ws_col: 0,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            // SAFETY: `TIOCGWINSZ` writes a `winsize` to the pointer, which
            // points to one; any descriptor is accepted, and one that is
            // not a terminal fails.
            let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &raw mut size) };
            (rc == 0).then_some(size.ws_col)
        })
}

#[cfg(test)]
mod tests {
    /// Under `cargo test` the standard streams are pipes or files at
    /// least some of the time; whatever they are, the answer is a width or
    /// nothing, never a failure.
    #[test]
    fn answers() {
        let _ = super::columns();
    }
}
