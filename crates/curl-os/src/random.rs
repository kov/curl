//! Random bytes from the kernel (`getrandom(2)`), for the nonces a
//! protocol makes up.

#![allow(unsafe_code)]

use std::io;

/// Fill `out` with random bytes, waiting for the kernel's pool if it is
/// not ready yet.
pub fn fill(out: &mut [u8]) -> io::Result<()> {
    fill_from(out, |rest| {
        // SAFETY: `rest` is valid to write for its length, and
        // `getrandom` writes no more than that.
        let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        usize::try_from(n).map_err(|_| io::Error::last_os_error())
    })
}

/// Fill `out` from `read`, which fills the start of what it is given and
/// says how much; a read a signal interrupted is made again.
fn fill_from(
    out: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> io::Result<usize>,
) -> io::Result<()> {
    let mut filled = 0;
    while filled < out.len() {
        match read(&mut out[filled..]) {
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
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

    /// A read a signal interrupted is made again; any other failure is
    /// the fill's.
    #[test]
    fn retries_only_an_interrupted_read() {
        let mut reads = 0;
        let mut out = [0u8; 4];
        fill_from(&mut out, |rest| {
            reads += 1;
            match reads {
                1 => Err(io::ErrorKind::Interrupted.into()),
                _ => {
                    rest[0] = reads;
                    Ok(1)
                }
            }
        })
        .unwrap();
        assert_eq!(out, [2, 3, 4, 5]);
        let failed = fill_from(&mut out, |_| Err(io::ErrorKind::WouldBlock.into()));
        assert_eq!(failed.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }
}
