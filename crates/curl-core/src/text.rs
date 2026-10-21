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

    /// Up to `N` bytes of `args`, as C's `snprintf` keeps them; whether
    /// any were cut.
    pub(crate) fn clipped(args: fmt::Arguments<'_>) -> (Text<N>, bool) {
        let mut clip = Clip {
            text: Text::new(),
            cut: false,
        };
        let written = fmt::write(&mut clip, args);
        assert!(written.is_ok() || clip.cut, "only a cut fails the write");
        (clip.text, clip.cut)
    }

    /// Add `bytes`, as many as fit.
    pub(crate) fn push_clipped(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(N - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    /// Keep the first `len` bytes.
    #[cfg_attr(
        not(any(test, feature = "debug-hooks")),
        expect(
            dead_code,
            reason = "only a trace line is cut, and the debug build's is the only one yet"
        )
    )]
    pub(crate) fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }
}

/// What fits of a formatting.
struct Clip<const N: usize> {
    text: Text<N>,
    cut: bool,
}

impl<const N: usize> fmt::Write for Clip<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let before = self.text.len;
        self.text.push_clipped(s.as_bytes());
        if self.text.len - before < s.len() {
            self.cut = true;
            return Err(fmt::Error);
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_what_fits() {
        let (t, cut) = Text::<4>::clipped(format_args!("ab{}", "cdef"));
        assert_eq!((t.bytes(), cut), (&b"abcd"[..], true));
        let (mut t, cut) = Text::<4>::clipped(format_args!("ab"));
        assert_eq!((t.bytes(), cut), (&b"ab"[..], false));
        t.push_clipped(b"xyz");
        assert_eq!(t.bytes(), b"abxy");
        t.truncate(1);
        assert_eq!(t.bytes(), b"a");
        t.truncate(3);
        assert_eq!(t.bytes(), b"a");
    }
}
