//! Bytes as C's `%s` shows them in a line.

use core::fmt;

/// Bytes shown as text: UTF-8 as it is, each other byte as the
/// character of its number.
pub(crate) struct Text<'a>(pub(crate) &'a [u8]);

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            for &b in chunk.invalid() {
                fmt::Write::write_char(f, char::from(b))?;
            }
        }
        Ok(())
    }
}

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
