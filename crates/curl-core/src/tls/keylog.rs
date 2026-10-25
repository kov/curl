//! The file a TLS library logs each connection's secrets to, so that a
//! capture of its traffic can be read (`SSLKEYLOGFILE`, `lib/vtls/keylog.c`),
//! in the NSS key log format: one line per secret.
//!
//! The owner of the libraries a handle is given (the shim's root, the
//! tool) owns one, opened as C opens it at global init and handed to the
//! TLS library as a `SharedKeyLog`; the core keeps none. A session the
//! library makes holds its own `SharedKeyLog`, so the log lasts while any
//! does.

use std::fs::File;
use std::io::Write as _;
use std::ops::Deref;
use std::sync::Mutex;

use curl_alloc::{OutOfMemory, TryArc};

/// The longest line written, its line end included (C's 256 bytes with
/// room for the line end and a zero byte).
const LINE_MAX: usize = 254;

/// The key log: closed until opened, and while the environment names no
/// file to write it to.
#[derive(Debug)]
pub struct KeyLog {
    open: Mutex<Option<Open>>,
}

/// The longest file name kept, the system's (`PATH_MAX`): a longer one
/// opens no file.
const NAME_MAX: usize = 4096;

#[derive(Debug)]
struct Open {
    file: File,
    /// The file's name, as the environment gives it, in its first
    /// `name_len` bytes: kept without the heap, so opening cannot run out
    /// of memory, as C's `getenv` cannot.
    name: [u8; NAME_MAX],
    name_len: usize,
}

impl KeyLog {
    /// A key log not yet opened.
    pub const fn new() -> KeyLog {
        KeyLog {
            open: Mutex::new(None),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Open>> {
        self.open.lock().expect("no panic holds the key log")
    }

    /// Open the file `SSLKEYLOGFILE` names, to append to, unless it is
    /// open (`Curl_tls_keylog_open`). A file that will not open, or no
    /// name, leaves it closed.
    pub fn open(&self) {
        let mut name = [0u8; NAME_MAX];
        // A name too long to keep whole is cut to `NAME_MAX`, which no
        // file has: it opens none.
        if let Some(given) = curl_os::env::var_into(b"SSLKEYLOGFILE", &mut name) {
            self.open_named(given);
        }
    }

    /// Open the file `name`, to append to, unless it is open: as `open`
    /// does with the name the environment gives.
    pub fn open_named(&self, given: &[u8]) {
        let mut open = self.lock();
        if open.is_some() || given.len() >= NAME_MAX {
            return;
        }
        let opened = curl_os::fs::with_c_name(given, |c| {
            curl_os::fs::open_write(c, curl_os::fs::Keep::Everything, 0o666)
        });
        if let Ok(file) = opened {
            let mut name = [0u8; NAME_MAX];
            name[..given.len()].copy_from_slice(given);
            *open = Some(Open {
                file,
                name,
                name_len: given.len(),
            });
        }
    }

    /// Close it (`Curl_tls_keylog_close`).
    pub fn close(&self) {
        *self.lock() = None;
    }

    /// It is open (`Curl_tls_keylog_enabled`).
    pub fn enabled(&self) -> bool {
        self.lock().is_some()
    }

    /// `f` given the name of the file it is open to, if it is.
    pub fn with_name<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        self.lock().as_ref().map(|o| f(&o.name[..o.name_len]))
    }

    /// Write `line`, a line end added if it has none, if it is open and
    /// the line neither empty nor longer than a key log line can be
    /// (`Curl_tls_keylog_write_line`). Whether it was written.
    pub fn write_line(&self, line: &[u8]) -> bool {
        let mut open = self.lock();
        let Some(open) = open.as_mut() else {
            return false;
        };
        if line.is_empty() || line.len() > LINE_MAX {
            return false;
        }
        let mut buf = [0u8; LINE_MAX + 1];
        buf[..line.len()].copy_from_slice(line);
        let mut len = line.len();
        if line.last() != Some(&b'\n') {
            buf[len] = b'\n';
            len += 1;
        }
        // Each line whole, as C's line buffering writes it; a failed
        // write is not said, as `fputs`'s is not.
        let _ = open.file.write_all(&buf[..len]);
        true
    }
}

impl Default for KeyLog {
    fn default() -> KeyLog {
        KeyLog::new()
    }
}

/// A key log as the TLS library and its sessions hold it: one a process
/// keeps for good (the shim's), or one its owner shares, which lasts as
/// long as the last holder (the tool's).
#[derive(Clone, Debug)]
pub struct SharedKeyLog(Backing);

#[derive(Clone, Debug)]
enum Backing {
    Shared(TryArc<KeyLog>),
    Static(&'static KeyLog),
}

impl SharedKeyLog {
    /// A key log of its own, not yet opened.
    pub fn new() -> Result<SharedKeyLog, OutOfMemory> {
        Ok(SharedKeyLog(Backing::Shared(TryArc::try_new(
            KeyLog::new(),
        )?)))
    }

    /// The key log a process keeps for good.
    pub const fn of_static(log: &'static KeyLog) -> SharedKeyLog {
        SharedKeyLog(Backing::Static(log))
    }
}

impl Deref for SharedKeyLog {
    type Target = KeyLog;

    fn deref(&self) -> &KeyLog {
        match &self.0 {
            Backing::Shared(shared) => shared,
            Backing::Static(log) => log,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use super::*;

    /// A key log opened to a file appends each line to what it holds, a
    /// line end added where missing; an empty line or one too long is
    /// not written; closed, it writes nothing.
    #[test]
    fn lines_are_appended_as_the_nss_format_has_them() {
        let path = std::env::temp_dir().join(format!("curl-keylog-{}", std::process::id()));
        std::fs::write(&path, b"before\n").unwrap();
        let log = KeyLog::new();
        assert!(!log.enabled());
        assert!(!log.write_line(b"CLIENT_RANDOM 00 11"));
        log.open_named(path.to_str().unwrap().as_bytes());
        assert!(log.enabled());
        assert_eq!(
            log.with_name(<[u8]>::to_vec).unwrap(),
            path.to_str().unwrap().as_bytes()
        );
        assert!(log.write_line(b"CLIENT_RANDOM 00 11"));
        assert!(log.write_line(b"SERVER_TRAFFIC_SECRET_0 22 33\n"));
        assert!(!log.write_line(b""));
        assert!(!log.write_line(&[b'x'; LINE_MAX + 1]));
        assert!(log.write_line(&[b'y'; LINE_MAX]));
        log.close();
        assert!(!log.enabled());
        assert!(!log.write_line(b"after"));
        let mut want = b"before\nCLIENT_RANDOM 00 11\nSERVER_TRAFFIC_SECRET_0 22 33\n".to_vec();
        want.extend_from_slice(&[b'y'; LINE_MAX]);
        want.push(b'\n');
        assert_eq!(std::fs::read(&path).unwrap(), want);
        std::fs::remove_file(&path).unwrap();
    }

    /// A shared key log lasts while any holder does: a line written
    /// through a clone after the first is dropped reaches the file.
    #[test]
    fn a_shared_log_outlives_the_holder_that_made_it() {
        let path = std::env::temp_dir().join(format!("curl-keylog-shared-{}", std::process::id()));
        let made = SharedKeyLog::new().unwrap();
        made.open_named(path.to_str().unwrap().as_bytes());
        let held = made.clone();
        drop(made);
        assert!(held.write_line(b"CLIENT_RANDOM 00 11"));
        assert_eq!(std::fs::read(&path).unwrap(), b"CLIENT_RANDOM 00 11\n");
        std::fs::remove_file(&path).unwrap();
    }
}
