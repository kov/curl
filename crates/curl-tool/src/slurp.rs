//! Files an option names, read whole (`file2string`, `file2memory`).

use std::io::Read as _;

use curl_alloc::TryVec as _;
use curl_os::text::{Mode, Reader};

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

/// The bytes of file `name`, opened in `mode` as C opens it, or of
/// standard input for `-`, in the mode the C library keeps for it then.
pub(crate) fn read(name: &[u8], how: As, mode: Mode) -> Result<Vec<u8>, ReadFailed> {
    let (mut file, mode) = if name == b"-" {
        let stdin = curl_os::fs::stdin().map_err(|_| ReadFailed::Open)?;
        (stdin, curl_os::fs::mode(curl_os::fs::Std::In))
    } else {
        let file =
            curl_os::fs::with_c_name(name, curl_os::fs::open_read).map_err(|_| ReadFailed::Open)?;
        (file, mode)
    };
    read_from(&mut file, how, mode)
}

/// The bytes of `file`, open for reading in `mode`, from where it is to
/// its end.
pub(crate) fn read_from(
    file: &mut std::fs::File,
    how: As,
    mode: Mode,
) -> Result<Vec<u8>, ReadFailed> {
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
    let mut file = Reader::new(file, mode);
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
        let name = file.as_os_str().as_encoded_bytes();
        assert_eq!(read(name, As::Text, Mode::Binary).unwrap(), b"abcd");
        assert_eq!(
            read(name, As::Binary, Mode::Binary).unwrap(),
            b"a\r\nb\nc\0d\n"
        );
        assert_eq!(
            read(b"/nonexistent/x", As::Text, Mode::Binary),
            Err(ReadFailed::Open)
        );
        // A directory opens, and fails to be read; on Windows it does not
        // open, as in the C library.
        let name = dir.as_os_str().as_encoded_bytes();
        let failed = if cfg!(windows) {
            ReadFailed::Open
        } else {
            ReadFailed::Read
        };
        assert_eq!(read(name, As::Binary, Mode::Binary), Err(failed));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A file opened as text has its line ends read as a line feed, and
    /// ends at a Ctrl-Z, as the C library reads `"rt"`.
    #[test]
    fn reads_text_mode_as_the_c_library() {
        let dir = std::env::temp_dir().join(format!("curl-slurp-text-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("f");
        std::fs::write(&file, b"a\r\nb\x1ac\n").unwrap();
        let name = file.as_os_str().as_encoded_bytes();
        assert_eq!(read(name, As::Binary, Mode::Text).unwrap(), b"a\nb");
        assert_eq!(read(name, As::Text, Mode::Text).unwrap(), b"ab");
        assert_eq!(
            read(name, As::Binary, Mode::Binary).unwrap(),
            b"a\r\nb\x1ac\n"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
