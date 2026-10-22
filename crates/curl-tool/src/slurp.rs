//! Files an option names, read whole (`file2string`, `file2memory`).

use std::io::Read as _;

use curl_alloc::TryVec as _;

/// Why a file was not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadFailed {
    Open,
    Read,
    OutOfMemory,
}

/// How a file's bytes are taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum As {
    /// Its carriage returns, line feeds and zero bytes left out
    /// (`file2string`).
    Text,
    /// Every byte (`file2memory`).
    Binary,
}

/// The bytes of file `name`, or of standard input for `-`.
pub(crate) fn read(name: &[u8], how: As) -> Result<Vec<u8>, ReadFailed> {
    let mut file = if name == b"-" {
        curl_os::fs::stdin().map_err(|_| ReadFailed::Open)?
    } else {
        let path = <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(name);
        std::fs::File::open(path).map_err(|_| ReadFailed::Open)?
    };
    let mut bytes = Vec::new();
    // A file's size is known: one allocation holds it, as it was then.
    if let Ok(meta) = file.metadata()
        && meta.is_file()
    {
        let size = usize::try_from(meta.len()).map_err(|_| ReadFailed::OutOfMemory)?;
        bytes
            .try_reserve_exact(size)
            .map_err(|_| ReadFailed::OutOfMemory)?;
    }
    let mut buf = [0; 4096];
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ReadFailed::Read),
        };
        let got = &buf[..n];
        let kept = match how {
            As::Binary => bytes.try_extend_from_slice(got),
            As::Text => got
                .split(|&b| matches!(b, b'\r' | b'\n' | 0))
                .try_for_each(|line| bytes.try_extend_from_slice(line)),
        };
        kept.map_err(|_| ReadFailed::OutOfMemory)?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Text leaves out line ends and zero bytes; binary keeps every
    /// byte.
    #[test]
    fn reads_text_and_binary() {
        let dir = std::env::temp_dir().join(format!("curl-slurp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("f");
        std::fs::write(&file, b"a\r\nb\nc\0d\n").unwrap();
        let name = std::os::unix::ffi::OsStrExt::as_bytes(file.as_os_str());
        assert_eq!(read(name, As::Text).unwrap(), b"abcd");
        assert_eq!(read(name, As::Binary).unwrap(), b"a\r\nb\nc\0d\n");
        assert_eq!(read(b"/nonexistent/x", As::Text), Err(ReadFailed::Open));
        // A directory opens, and fails to be read.
        let name = std::os::unix::ffi::OsStrExt::as_bytes(dir.as_os_str());
        assert_eq!(read(name, As::Binary), Err(ReadFailed::Read));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
