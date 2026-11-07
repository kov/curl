//! Bytes and UTF-16 as C's `%s` shows them in a line.

use core::fmt;

pub(crate) use curl_core::tls::Text;

/// UTF-16 shown as UTF-8, each unpaired surrogate as the replacement
/// character.
pub(crate) struct Wide<'a>(pub(crate) &'a [u16]);

impl fmt::Display for Wide<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in char::decode_utf16(self.0.iter().copied()) {
            fmt::Write::write_char(f, c.unwrap_or(char::REPLACEMENT_CHARACTER))?;
        }
        Ok(())
    }
}
