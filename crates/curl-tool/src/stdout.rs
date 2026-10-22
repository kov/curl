//! Standard output, buffered as C's stdio buffers `stdout`: the body,
//! a trace sent to `-` and `--write-out` all go through the one buffer,
//! in the order written, and a write that fails at the end fails there.

use std::io::{self, IsTerminal as _, Write as _};
use std::sync::Mutex;

use curl_alloc::{OutOfMemory, TryArc, TryVec};

/// glibc sizes the buffer by the file system's block size: 4096 on the
/// common ones.
const BUFFER: usize = 4096;

/// The process's standard output, shared by whatever writes to it.
#[derive(Clone)]
pub(crate) struct Stdout(TryArc<Mutex<Buffered>>);

struct Buffered {
    held: Vec<u8>,
    /// A terminal: each line is written as it ends.
    line: bool,
    /// Where the bytes go: the process's standard output.
    sink: fn(&[u8]) -> io::Result<()>,
}

impl Stdout {
    pub(crate) fn new() -> Result<Stdout, OutOfMemory> {
        let mut held = Vec::new();
        held.try_reserve_exact(BUFFER).map_err(|_| OutOfMemory)?;
        let line = io::stdout().is_terminal();
        Ok(Stdout(TryArc::try_new(Mutex::new(Buffered {
            held,
            line,
            sink: raw,
        }))?))
    }

    /// Write `bytes`, holding them until the buffer is full (or the line
    /// ends, on a terminal).
    pub(crate) fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
        let mut b = self.0.lock().expect("no panic holds it");
        if b.held.len() + bytes.len() > BUFFER {
            b.write_held()?;
        }
        if bytes.len() >= BUFFER {
            (b.sink)(bytes)?;
        } else {
            b.held
                .try_extend_from_slice(bytes)
                .expect("the buffer is reserved whole");
        }
        if b.line && bytes.contains(&b'\n') {
            b.write_held()?;
        }
        Ok(())
    }

    /// Write what is held.
    pub(crate) fn flush(&self) -> io::Result<()> {
        self.0.lock().expect("no panic holds it").write_held()
    }
}

impl Buffered {
    fn write_held(&mut self) -> io::Result<()> {
        // What could not be written is dropped, as stdio drops it.
        let result = (self.sink)(&self.held);
        self.held.clear();
        result
    }
}

fn raw(bytes: &[u8]) -> io::Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(bytes)?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes are held until the buffer would overflow or is flushed; one
    /// write as large as the buffer goes straight through.
    #[test]
    fn holds_until_full() {
        let out = Stdout::new().unwrap();
        out.0.lock().expect("no panic holds it").line = false;
        out.0.lock().expect("no panic holds it").sink = |_| Ok(());
        out.write_all(b"abc").unwrap();
        assert_eq!(out.0.lock().expect("no panic holds it").held, b"abc");
        out.write_all(&[b'x'; BUFFER - 3]).unwrap();
        assert_eq!(out.0.lock().expect("no panic holds it").held.len(), BUFFER);
        out.write_all(b"y").unwrap();
        assert_eq!(out.0.lock().expect("no panic holds it").held, b"y");
        out.write_all(&[b'z'; BUFFER]).unwrap();
        assert!(out.0.lock().expect("no panic holds it").held.is_empty());
        out.write_all(b"q\n").unwrap();
        assert_eq!(out.0.lock().expect("no panic holds it").held, b"q\n");
        out.0.lock().expect("no panic holds it").line = true;
        out.write_all(b"r\n").unwrap();
        assert!(out.0.lock().expect("no panic holds it").held.is_empty());
        out.write_all(b"s").unwrap();
        out.flush().unwrap();
        assert!(out.0.lock().expect("no panic holds it").held.is_empty());
    }
}
