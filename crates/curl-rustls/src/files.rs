//! Reading a file of certificates, a key or revocation lists whole
//! (`read_file_into`).

use std::io::Read as _;

use curl_alloc::{OutOfMemory, TryVec as _};

/// What reading a file came to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Read {
    Data(Vec<u8>),
    /// It would not open, or a read of it failed: a directory is read and
    /// fails.
    Failed,
    /// It does not fit.
    TooLarge,
    OutOfMemory,
}

/// The file `name` whole, if it fits a buffer of `most` bytes with the
/// zero byte C's buffer adds (`curlx_dyn_addn`'s limit).
pub(crate) fn read(name: &[u8], most: usize) -> Read {
    let Ok(mut file) = curl_os::fs::with_c_name(name, curl_os::fs::open_read) else {
        return Read::Failed;
    };
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => return Read::Data(data),
            Ok(n) => {
                if data.len() + n >= most {
                    return Read::TooLarge;
                }
                if let Err(OutOfMemory) = data.try_extend_from_slice(&chunk[..n]) {
                    return Read::OutOfMemory;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Read::Failed,
        }
    }
}
