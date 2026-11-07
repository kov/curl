//! Bytes as C's `%s` prints them.

use core::fmt;

/// Bytes as C's `%s` shows them: text as it is, any other byte as the
/// character of its number.
pub(crate) struct Text<'a>(pub(crate) &'a [u8]);

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            for &b in chunk.invalid() {
                write!(f, "{}", char::from(b))?;
            }
        }
        Ok(())
    }
}
