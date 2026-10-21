//! Random bytes from the kernel (`getrandom(2)`), for the nonces a
//! protocol makes up.

#![allow(unsafe_code)]

use std::io;

/// Fill `out` with random bytes, waiting for the kernel's pool if it is
/// not ready yet.
pub fn fill(out: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < out.len() {
        let rest = &mut out[filled..];
        // SAFETY: `rest` is valid to write for its length, and
        // `getrandom` writes no more than that.
        let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        match usize::try_from(n) {
            Ok(n) => filled += n,
            Err(_) => {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two fills differ, and fill all of their buffer.
    #[test]
    fn fills_with_different_bytes() {
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, b);
        assert!(a[48..].iter().any(|&x| x != 0), "the end is filled too");
        fill(&mut []).unwrap();
    }
}
