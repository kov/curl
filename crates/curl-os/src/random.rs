//! Random bytes from the kernel (`getrandom(2)`; `getentropy` on macOS;
//! on Windows the system's generator), for the nonces a protocol makes
//! up.

#![allow(unsafe_code)]

use std::io;

/// Fill `out` with random bytes from the system's preferred generator
/// (`BCryptGenRandom`), as C's `curlx_win32_random` asks it.
#[cfg(windows)]
pub fn fill(out: &mut [u8]) -> io::Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    fill_from(out, |rest| {
        let n = rest.len().min(u32::MAX as usize);
        let len = u32::try_from(n).expect("at most u32::MAX");
        // SAFETY: `rest` is valid to write for `len` bytes, which the call
        // writes no more than; no algorithm handle is passed, as the flag
        // asks.
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                rest.as_mut_ptr(),
                len,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            // An NTSTATUS is no number `io::Error` knows.
            return Err(io::ErrorKind::Other.into());
        }
        Ok(n)
    })
}

/// Fill `out` with random bytes, waiting for the kernel's pool if it is
/// not ready yet.
#[cfg(target_os = "linux")]
pub fn fill(out: &mut [u8]) -> io::Result<()> {
    fill_from(out, |rest| {
        // SAFETY: `rest` is valid to write for its length, and
        // `getrandom` writes no more than that.
        let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        usize::try_from(n).map_err(|_| io::Error::last_os_error())
    })
}

/// The most `getentropy` fills at once.
#[cfg(target_vendor = "apple")]
const ENTROPY_MOST: usize = 256;

/// Fill `out` with random bytes from the kernel (`getentropy`), at most
/// 256 of them a call, as it takes.
#[cfg(target_vendor = "apple")]
pub fn fill(out: &mut [u8]) -> io::Result<()> {
    fill_from(out, |rest| {
        let n = rest.len().min(ENTROPY_MOST);
        // SAFETY: `rest` is valid to write for `n` bytes, no more than its
        // length, and `getentropy` writes exactly that many.
        if unsafe { libc::getentropy(rest.as_mut_ptr().cast(), n) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n)
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

    /// A fill longer than one call of the kernel's takes (`getentropy`'s
    /// 256 bytes) is filled to its end.
    #[test]
    fn a_long_fill_is_filled_to_its_end() {
        let mut a = [0u8; 1000];
        fill(&mut a).unwrap();
        assert!(a[968..].iter().any(|&x| x != 0), "the end is filled too");
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
