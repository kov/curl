//! Standard output, buffered as C's stdio buffers `stdout`: the body,
//! a trace sent to `-` and `--write-out` all go through the one buffer,
//! in the order written, and a write that fails at the end fails there.

use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;
use std::sync::Mutex;

use curl_alloc::{OutOfMemory, TryArc};

use crate::stdio::{Failed, Layout, Sink, Stdio};

/// The process's standard output, shared by whatever writes to it.
#[derive(Clone)]
pub(crate) struct Stdout(TryArc<Mutex<Stdio<Descriptor>>>);

/// Descriptor 1, through a copy of its own: `std::io::stdout` holds a
/// buffer of its own, and would hide how much each write took.
pub(crate) struct Descriptor(Option<File>);

impl Sink for Descriptor {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match &mut self.0 {
            Some(file) => Sink::write(file, bytes),
            // Descriptor 1 is not open: each write fails.
            None => Err(io::Error::from(io::ErrorKind::NotConnected)),
        }
    }

    fn layout(&self) -> Layout {
        self.0.as_ref().map_or(Layout::UNKNOWN, File::layout)
    }
}

impl Stdout {
    pub(crate) fn new() -> Result<Stdout, OutOfMemory> {
        let fd = io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .ok()
            .map(File::from);
        Ok(Stdout(TryArc::try_new(Mutex::new(Stdio::new(
            Descriptor(fd),
        )))?))
    }

    /// Write `bytes`, held as stdio holds them: how many were taken
    /// (`fwrite`).
    pub(crate) fn fwrite(&self, bytes: &[u8]) -> usize {
        self.0.lock().expect("no panic holds it").fwrite(bytes)
    }

    /// Write `bytes`, held as stdio holds them; all must be taken.
    pub(crate) fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
        if self.fwrite(bytes) == bytes.len() {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::WriteZero))
        }
    }

    /// Write what is held (`fflush`).
    pub(crate) fn flush(&self) -> Result<(), Failed> {
        self.0.lock().expect("no panic holds it").flush()
    }
}
