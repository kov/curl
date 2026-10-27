//! Growth of `Vec` and `String` that reports allocation failure.
//!
//! Each method reserves first and then grows within the reserved capacity,
//! so the infallible std method it calls never allocates.

#![allow(clippy::disallowed_methods)]

use std::fmt;

use crate::OutOfMemory;

/// Fallible growth for `Vec`.
pub trait TryVec<T> {
    fn try_push(&mut self, value: T) -> Result<(), OutOfMemory>;
    fn try_extend_from_slice(&mut self, values: &[T]) -> Result<(), OutOfMemory>
    where
        T: Clone;
    /// Grows or shrinks it to `len`, filling what is added with `value`.
    fn try_resize(&mut self, len: usize, value: T) -> Result<(), OutOfMemory>
    where
        T: Clone;
}

impl<T> TryVec<T> for Vec<T> {
    fn try_push(&mut self, value: T) -> Result<(), OutOfMemory> {
        self.try_reserve(1)?;
        self.push(value);
        Ok(())
    }

    fn try_extend_from_slice(&mut self, values: &[T]) -> Result<(), OutOfMemory>
    where
        T: Clone,
    {
        self.try_reserve(values.len())?;
        self.extend_from_slice(values);
        Ok(())
    }

    fn try_resize(&mut self, len: usize, value: T) -> Result<(), OutOfMemory>
    where
        T: Clone,
    {
        self.try_reserve(len.saturating_sub(self.len()))?;
        self.resize(len, value);
        Ok(())
    }
}

/// Fallible growth for `String`.
pub trait TryString {
    fn try_push(&mut self, c: char) -> Result<(), OutOfMemory>;
    fn try_push_str(&mut self, s: &str) -> Result<(), OutOfMemory>;
}

impl TryString for String {
    fn try_push(&mut self, c: char) -> Result<(), OutOfMemory> {
        self.try_reserve(c.len_utf8())?;
        self.push(c);
        Ok(())
    }

    fn try_push_str(&mut self, s: &str) -> Result<(), OutOfMemory> {
        self.try_reserve(s.len())?;
        self.push_str(s);
        Ok(())
    }
}

/// `format!` that reports allocation failure.
///
/// Use with `format_args!`: `try_format(format_args!("{x}"))`.
pub fn try_format(args: fmt::Arguments<'_>) -> Result<String, OutOfMemory> {
    struct Out {
        s: String,
        oom: bool,
    }
    impl fmt::Write for Out {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            self.s.try_push_str(s).map_err(|OutOfMemory| {
                self.oom = true;
                fmt::Error
            })
        }
    }
    let mut out = Out {
        s: String::new(),
        oom: false,
    };
    match fmt::write(&mut out, args) {
        Ok(()) => Ok(out.s),
        Err(fmt::Error) if out.oom => Err(OutOfMemory),
        // Only a `Display` impl can fail otherwise, which is a bug in it.
        Err(fmt::Error) => panic!("a formatting trait implementation returned an error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_and_formats() {
        let mut v = Vec::new();
        v.try_push(1u8).unwrap();
        v.try_extend_from_slice(&[2, 3]).unwrap();
        assert_eq!(v, [1, 2, 3]);
        v.try_resize(5, 9).unwrap();
        assert_eq!(v, [1, 2, 3, 9, 9]);
        v.try_resize(2, 0).unwrap();
        assert_eq!(v, [1, 2]);
        assert_eq!(v.try_resize(usize::MAX, 0), Err(OutOfMemory));
        let mut s = String::new();
        s.try_push_str("ab").unwrap();
        s.try_push('c').unwrap();
        assert_eq!(s, "abc");
        assert_eq!(
            try_format(format_args!("{}-{:02}", s, 7)).unwrap(),
            "abc-07"
        );
    }

    #[test]
    fn reports_failure_instead_of_aborting() {
        let mut v: Vec<u8> = Vec::new();
        assert_eq!(
            v.try_reserve(usize::MAX).map_err(OutOfMemory::from),
            Err(OutOfMemory)
        );
    }
}
