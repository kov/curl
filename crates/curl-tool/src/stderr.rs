//! Standard error, written as C's tool writes `stderr`: unbuffered,
//! through the C library's descriptor 2 in the mode the library keeps for
//! it, text until `-D %` makes it binary, which on Windows puts a
//! carriage return before each line feed and writes text to a console in
//! the ANSI code page ([`curl_os::fs::write_stderr`]).

use std::io;

/// Standard error.
pub(crate) struct Stderr;

impl io::Write for Stderr {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        curl_os::fs::write_stderr(bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The library's text for the user, the progress meter's among them, to
/// standard error, as C's tool gives the library its `stderr`
/// (`CURLOPT_STDERR`). A failed write has nowhere to be reported.
pub(crate) struct LibraryText;

impl curl_core::handler::TextSink for LibraryText {
    fn write(&self, text: &[u8]) {
        let _ = curl_os::fs::write_stderr(text);
    }
}
