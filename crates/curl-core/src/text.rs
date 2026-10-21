//! Text written into a fixed buffer, so writing it allocates nothing.

use std::fmt;

/// Up to `N` bytes of text; a write past them fails.
pub(crate) struct Text<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Text<N> {
    pub(crate) fn new() -> Text<N> {
        Text {
            buf: [0; N],
            len: 0,
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl<const N: usize> fmt::Write for Text<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        let dest = self.buf.get_mut(self.len..end).ok_or(fmt::Error)?;
        dest.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}
