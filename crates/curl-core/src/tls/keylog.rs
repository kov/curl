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

    /// Take the lock once, so that what std makes on a lock's first use is
    /// made now: a debug build's memory tracking starts after it.
    pub fn make_lock(&self) {
        drop(self.lock());
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
        // The file is open as text (`FOPEN_APPENDTEXT`).
        let _ = curl_os::fs::write_all_as_c(&open.file, curl_os::text::Mode::TEXT, &buf[..len]);
        true
    }
}

/// The longest label a secret is written with
/// (`KEYLOG_LABEL_MAXLEN`: `CLIENT_HANDSHAKE_TRAFFIC_SECRET`'s).
const LABEL_MAX: usize = "CLIENT_HANDSHAKE_TRAFFIC_SECRET".len();

/// The longest secret written (`SECRET_MAXLEN`: TLS 1.2's master key,
/// and a 384-bit hash's).
const SECRET_MAX: usize = 48;

impl KeyLog {
    /// Write the line of `secret` under `label` for the connection of
    /// `client_random`, each in upper-case hex (`Curl_tls_keylog_write`),
    /// for a TLS library that gives the secrets themselves; none for a
    /// label too long, or a secret empty or too long. Whether it was
    /// written.
    pub fn write_secret(&self, label: &[u8], client_random: &[u8; 32], secret: &[u8]) -> bool {
        if label.len() > LABEL_MAX || secret.is_empty() || secret.len() > SECRET_MAX {
            return false;
        }
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut line = [0u8; LABEL_MAX + 1 + 2 * 32 + 1 + 2 * SECRET_MAX + 1];
        let mut at = label.len();
        line[..at].copy_from_slice(label);
        let mut put = |b: u8, at: &mut usize| {
            line[*at] = b;
            *at += 1;
        };
        put(b' ', &mut at);
        for &b in client_random {
            put(HEX[usize::from(b >> 4)], &mut at);
            put(HEX[usize::from(b & 0xf)], &mut at);
        }
        put(b' ', &mut at);
        for &b in secret {
            put(HEX[usize::from(b >> 4)], &mut at);
            put(HEX[usize::from(b & 0xf)], &mut at);
        }
        put(b'\n', &mut at);
        self.write_line(&line[..at])
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

    /// `lines` as the file holds them: opened as text, as C opens it, it
    /// has each line end written as a carriage return and a line feed on
    /// Windows, where C's text mode translates them (C's own key log
    /// reads so there).
    fn as_written(lines: &[u8]) -> Vec<u8> {
        let mut file = Vec::new();
        for &b in lines {
            if cfg!(windows) && b == b'\n' {
                file.push(b'\r');
            }
            file.push(b);
        }
        file
    }

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
        let mut written = b"CLIENT_RANDOM 00 11\nSERVER_TRAFFIC_SECRET_0 22 33\n".to_vec();
        written.extend_from_slice(&[b'y'; LINE_MAX]);
        written.push(b'\n');
        // What the file held before is left as it was.
        let mut want = b"before\n".to_vec();
        want.extend_from_slice(&as_written(&written));
        assert_eq!(std::fs::read(&path).unwrap(), want);
        std::fs::remove_file(&path).unwrap();
    }

    /// A secret is written as C writes it: its label, the client's
    /// random and the secret in upper-case hex; a label too long, or a
    /// secret empty or too long, is not written.
    #[test]
    fn a_secret_is_written_in_upper_case_hex() {
        let path = std::env::temp_dir().join(format!("curl-keylog-secret-{}", std::process::id()));
        let log = KeyLog::new();
        let random: [u8; 32] = core::array::from_fn(|i| (i * 8) as u8);
        assert!(!log.write_secret(b"CLIENT_RANDOM", &random, &[0xab]));
        log.open_named(path.to_str().unwrap().as_bytes());
        assert!(log.write_secret(b"CLIENT_RANDOM", &random, &[0xab, 0x0c]));
        assert!(!log.write_secret(b"CLIENT_RANDOM", &random, &[]));
        assert!(!log.write_secret(b"CLIENT_RANDOM", &random, &[1; SECRET_MAX + 1]));
        assert!(log.write_secret(b"CLIENT_RANDOM", &random, &[0xff; SECRET_MAX]));
        assert!(!log.write_secret(&[b'L'; LABEL_MAX + 1], &random, &[1]));
        assert!(log.write_secret(&[b'L'; LABEL_MAX], &random, &[1]));
        log.close();
        let hex: String = random.iter().map(|b| format!("{b:02X}")).collect();
        let want = format!(
            "CLIENT_RANDOM {hex} AB0C\nCLIENT_RANDOM {hex} {}\n{} {hex} 01\n",
            "FF".repeat(SECRET_MAX),
            "L".repeat(LABEL_MAX)
        );
        assert_eq!(
            String::from_utf8(std::fs::read(&path).unwrap()).unwrap(),
            String::from_utf8(as_written(want.as_bytes())).unwrap()
        );
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
        assert_eq!(
            std::fs::read(&path).unwrap(),
            as_written(b"CLIENT_RANDOM 00 11\n")
        );
        // Windows removes no file open without sharing its deletion.
        drop(held);
        std::fs::remove_file(&path).unwrap();
    }
}
