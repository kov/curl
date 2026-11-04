//! Waiting for sockets: `poll(2)` over a slice of descriptors (`Curl_poll`);
//! on Windows `select`, as C's build there polls.

#![allow(unsafe_code)]

use std::io;
use std::marker::PhantomData;
#[cfg(unix)]
use std::os::fd::{AsRawFd, BorrowedFd};
#[cfg(windows)]
use std::os::windows::io::AsRawSocket as _;
use std::time::Duration;

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock as ws;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::Sleep;

#[cfg(windows)]
use crate::socket::BorrowedSocket;

/// The system's numbers for the events, Winsock's on Windows: there `IN`
/// is `RDNORM` and `RDBAND` together.
#[cfg(unix)]
mod bits {
    pub const IN: i16 = libc::POLLIN;
    pub const RDNORM: i16 = libc::POLLRDNORM;
    pub const RDBAND: i16 = libc::POLLRDBAND;
    pub const PRI: i16 = libc::POLLPRI;
    pub const OUT: i16 = libc::POLLOUT;
    pub const ERR: i16 = libc::POLLERR;
    pub const HUP: i16 = libc::POLLHUP;
    pub const NVAL: i16 = libc::POLLNVAL;
}

#[cfg(windows)]
mod bits {
    use windows_sys::Win32::Networking::WinSock as ws;
    pub const IN: i16 = ws::POLLIN;
    pub const RDNORM: i16 = ws::POLLRDNORM;
    pub const RDBAND: i16 = ws::POLLRDBAND;
    pub const PRI: i16 = ws::POLLPRI;
    pub const OUT: i16 = ws::POLLOUT;
    pub const ERR: i16 = ws::POLLERR;
    pub const HUP: i16 = ws::POLLHUP;
    pub const NVAL: i16 = ws::POLLNVAL;
}

/// What to wait for on a descriptor, and what happened to it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Events(i16);

impl Events {
    pub const NONE: Events = Events(0);
    pub const IN: Events = Events(bits::IN);
    /// Normal data to read; Linux says it with `IN`, when asked.
    pub const RDNORM: Events = Events(bits::RDNORM);
    /// Priority band data to read.
    pub const RDBAND: Events = Events(bits::RDBAND);
    /// Urgent data to read, as TCP's out-of-band byte; on Windows also a
    /// connect that failed.
    pub const PRI: Events = Events(bits::PRI);
    pub const OUT: Events = Events(bits::OUT);
    /// Only ever reported, never asked for.
    pub const ERR: Events = Events(bits::ERR);
    pub const HUP: Events = Events(bits::HUP);
    pub const NVAL: Events = Events(bits::NVAL);

    pub fn contains(self, other: Events) -> bool {
        self.0 & other.0 == other.0
    }

    /// Any of `other` is here.
    pub fn intersects(self, other: Events) -> bool {
        self.0 & other.0 != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for Events {
    type Output = Events;

    fn bitor(self, other: Events) -> Events {
        Events(self.0 | other.0)
    }
}

/// One descriptor to poll, borrowed for as long as the entry lives: the
/// kernel is never handed a descriptor that may have been closed.
#[cfg(unix)]
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PollFd<'a> {
    raw: libc::pollfd,
    _fd: PhantomData<BorrowedFd<'a>>,
}

#[cfg(unix)]
impl<'a> PollFd<'a> {
    pub fn new(fd: BorrowedFd<'a>, events: Events) -> Self {
        PollFd {
            raw: libc::pollfd {
                fd: fd.as_raw_fd(),
                events: events.0,
                revents: 0,
            },
            _fd: PhantomData,
        }
    }

    /// What the last `poll` reported for this descriptor.
    pub fn revents(&self) -> Events {
        Events(self.raw.revents)
    }

    /// Take what a poll of a copy of this entry reported, as when the
    /// entries were polled among others.
    pub fn copy_revents(&mut self, polled: &PollFd<'_>) {
        assert_eq!(
            (self.raw.fd, self.raw.events),
            (polled.raw.fd, polled.raw.events),
            "a copy of this entry"
        );
        self.raw.revents = polled.raw.revents;
    }
}

/// Wait up to `timeout` for any of `fds` to be ready; with none, sleep
/// for `timeout`. Returns how many have events. A signal ending the wait
/// early counts as nothing ready, as in C.
#[cfg(unix)]
pub fn poll(fds: &mut [PollFd<'_>], timeout: Duration) -> io::Result<u32> {
    for fd in fds.iter_mut() {
        fd.raw.revents = 0;
    }
    // Rounded up, so a wait never ends before its time; capped at what
    // `poll` takes.
    let ms = timeout.as_nanos().div_ceil(1_000_000);
    let ms = i32::try_from(ms).unwrap_or(i32::MAX);
    let n = libc::nfds_t::try_from(fds.len()).expect("descriptor counts fit nfds_t");
    // SAFETY: `PollFd` is `repr(transparent)` over `libc::pollfd`, so the
    // slice is `n` valid `pollfd`s; each borrows its descriptor, which
    // therefore stays open for the call. The kernel writes only
    // `revents`, inside the slice.
    let rc = unsafe { libc::poll(fds.as_mut_ptr().cast::<libc::pollfd>(), n, ms) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok(0);
        }
        return Err(err);
    }
    Ok(u32::try_from(rc).expect("poll counts at most the descriptors given"))
}

/// One socket to poll, borrowed for as long as the entry lives: Winsock
/// is never handed a socket that may have been closed. Winsock's `pollfd`
/// (`WSAPOLLFD`) is its shape, though C does not hand it to `WSAPoll`.
#[cfg(windows)]
#[derive(Clone, Copy)]
pub struct PollFd<'a> {
    socket: ws::SOCKET,
    events: i16,
    revents: i16,
    _fd: PhantomData<BorrowedSocket<'a>>,
}

#[cfg(windows)]
impl<'a> PollFd<'a> {
    pub fn new(fd: BorrowedSocket<'a>, events: Events) -> Self {
        PollFd {
            socket: fd.as_raw_socket() as ws::SOCKET,
            events: events.0,
            revents: 0,
            _fd: PhantomData,
        }
    }

    /// What the last `poll` reported for this socket.
    pub fn revents(&self) -> Events {
        Events(self.revents)
    }

    /// Take what a poll of a copy of this entry reported, as when the
    /// entries were polled among others.
    pub fn copy_revents(&mut self, polled: &PollFd<'_>) {
        assert_eq!(
            (self.socket, self.events),
            (polled.socket, polled.events),
            "a copy of this entry"
        );
        self.revents = polled.revents;
    }
}

/// How many sockets a set holds on the stack, as Winsock's own
/// `FD_SETSIZE`; a poll of more holds its sets in memory of its own.
#[cfg(windows)]
const ON_STACK: usize = 64;

/// A Winsock `fd_set`, of any size: a count, then that many sockets. The
/// count is a `u_int` in a slot as wide as a socket, as the C struct lays
/// it out.
#[cfg(windows)]
struct FdSet<'b>(&'b mut [usize]);

#[cfg(windows)]
impl FdSet<'_> {
    fn len(&self) -> usize {
        self.0[0]
    }

    /// Add `s` once, as `FD_SET` does.
    fn add(&mut self, s: ws::SOCKET) {
        if !self.contains(s) {
            let n = self.len();
            self.0[1 + n] = s;
            self.0[0] = n + 1;
        }
    }

    /// Whether `select` left `s` in it (`FD_ISSET`).
    fn contains(&self, s: ws::SOCKET) -> bool {
        self.0[1..=self.len()].contains(&s)
    }

    /// The set for `select`, or null for an empty one, which Winsock
    /// refuses (`our_select`).
    fn as_arg(&mut self) -> *mut ws::FD_SET {
        if self.len() == 0 {
            std::ptr::null_mut()
        } else {
            self.0.as_mut_ptr().cast()
        }
    }
}

/// Wait up to `timeout` for any of `fds` to be ready; with none, sleep for
/// `timeout`. Returns how many have events. As C's `Curl_poll` without
/// `HAVE_POLL`, which C's Windows build lacks: `select` over sets made of
/// the events asked, reading for `RDNORM` and `IN`, writing for `OUT`,
/// exceptions for `RDBAND` and `PRI`, which is where Winsock reports a
/// connect that failed. Each event asked is reported if its set says so;
/// `ERR` and `HUP` never are.
#[cfg(windows)]
pub fn poll(fds: &mut [PollFd<'_>], timeout: Duration) -> io::Result<u32> {
    for fd in fds.iter_mut() {
        fd.revents = 0;
    }
    // Rounded up, so a wait never ends before its time.
    let ms = timeout.as_nanos().div_ceil(1_000_000);
    let room = 1 + fds.len();
    let (mut stack_r, mut stack_w, mut stack_e) =
        ([0; 1 + ON_STACK], [0; 1 + ON_STACK], [0; 1 + ON_STACK]);
    let (mut heap_r, mut heap_w, mut heap_e);
    let (mut read, mut write, mut except) = if fds.len() <= ON_STACK {
        (
            FdSet(&mut stack_r[..room]),
            FdSet(&mut stack_w[..room]),
            FdSet(&mut stack_e[..room]),
        )
    } else {
        heap_r = zeroed_slots(room)?;
        heap_w = zeroed_slots(room)?;
        heap_e = zeroed_slots(room)?;
        (FdSet(&mut heap_r), FdSet(&mut heap_w), FdSet(&mut heap_e))
    };
    for fd in fds.iter() {
        let asked = Events(fd.events);
        if asked.intersects(Events::RDNORM | Events::IN) {
            read.add(fd.socket);
        }
        if asked.intersects(Events::OUT) {
            write.add(fd.socket);
        }
        if asked.intersects(Events::RDBAND | Events::PRI) {
            except.add(fd.socket);
        }
    }
    if read.len() + write.len() + except.len() == 0 {
        // Winsock's `select` takes no empty call: a wait (`curlx_wait_ms`),
        // capped below `INFINITE`.
        let ms = u32::try_from(ms).unwrap_or(u32::MAX - 1).min(u32::MAX - 1);
        if ms > 0 {
            // SAFETY: `Sleep` takes no pointers.
            unsafe { Sleep(ms) };
        }
        return Ok(0);
    }
    let secs = ms / 1000;
    let tv = ws::TIMEVAL {
        tv_sec: i32::try_from(secs).unwrap_or(i32::MAX),
        tv_usec: i32::try_from((ms % 1000) * 1000).expect("under a second"),
    };
    // SAFETY: each set is a count and that many sockets, as `fd_set` is
    // laid out, alive and writable through the call, or null; every
    // socket in them is borrowed by its entry, so open. The first
    // argument is ignored.
    let rc = unsafe {
        ws::select(
            0,
            read.as_arg(),
            write.as_arg(),
            except.as_arg(),
            &raw const tv,
        )
    };
    if rc == ws::SOCKET_ERROR {
        // SAFETY: `WSAGetLastError` only reads the thread's error.
        return Err(io::Error::from_raw_os_error(unsafe {
            ws::WSAGetLastError()
        }));
    }
    if rc == 0 {
        return Ok(0);
    }
    let mut ready = 0;
    for fd in fds.iter_mut() {
        let asked = Events(fd.events);
        let mut got = Events::NONE;
        for (set, events) in [
            (&read, [Events::RDNORM, Events::IN]),
            (&write, [Events::OUT, Events::OUT]),
            (&except, [Events::RDBAND, Events::PRI]),
        ] {
            if set.contains(fd.socket) {
                for e in events {
                    if asked.intersects(e) {
                        got = got | e;
                    }
                }
            }
        }
        fd.revents = got.0;
        if !got.is_empty() {
            ready += 1;
        }
    }
    Ok(ready)
}

/// `n` zeroed slots of a set, in memory of its own.
#[cfg(windows)]
fn zeroed_slots(n: usize) -> io::Result<Vec<usize>> {
    use curl_alloc::TryVec as _;
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    v.try_resize(n, 0)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    Ok(v)
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Write as _;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    use super::*;

    #[test]
    fn events_combine_and_contain() {
        let both = Events::IN | Events::OUT;
        assert!(both.contains(Events::IN));
        assert!(both.contains(Events::OUT));
        assert!(!Events::IN.contains(Events::OUT));
        assert_eq!(Events::IN | Events::IN, Events::IN);
        assert!(Events::NONE.is_empty());
        assert!(!both.is_empty());
        assert!(both.intersects(Events::IN | Events::PRI));
        assert!(!both.intersects(Events::PRI | Events::HUP));
        assert!(!Events::NONE.intersects(Events::NONE));
    }

    #[test]
    fn a_copy_s_events_go_back_to_the_entry() {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"x").unwrap();
        let mut mine = PollFd::new(b.as_fd(), Events::IN | Events::OUT);
        let mut copies = [mine];
        assert_eq!(poll(&mut copies, Duration::from_secs(5)).unwrap(), 1);
        mine.copy_revents(&copies[0]);
        assert_eq!(mine.revents(), Events::IN | Events::OUT);
    }

    #[test]
    #[should_panic = "a copy of this entry"]
    fn events_only_go_back_to_the_entry_polled() {
        let (_a, b) = UnixStream::pair().unwrap();
        let mut mine = PollFd::new(b.as_fd(), Events::IN);
        mine.copy_revents(&PollFd::new(b.as_fd(), Events::OUT));
    }

    #[test]
    fn reports_the_ready_descriptor_only() {
        let (mut a, b) = UnixStream::pair().unwrap();
        let (_c, d) = UnixStream::pair().unwrap();
        a.write_all(b"x").unwrap();
        let mut fds = [
            PollFd::new(b.as_fd(), Events::IN),
            PollFd::new(d.as_fd(), Events::IN),
        ];
        assert_eq!(poll(&mut fds, Duration::from_secs(5)).unwrap(), 1);
        assert!(fds[0].revents().contains(Events::IN));
        assert!(fds[1].revents().is_empty());
    }

    #[test]
    fn waits_out_its_timeout_with_nothing_ready() {
        let (_a, b) = UnixStream::pair().unwrap();
        let mut fds = [PollFd::new(b.as_fd(), Events::IN)];
        let start = Instant::now();
        assert_eq!(poll(&mut fds, Duration::from_millis(30)).unwrap(), 0);
        assert!(start.elapsed() >= Duration::from_millis(30));
        let start = Instant::now();
        assert_eq!(poll(&mut [], Duration::from_millis(30)).unwrap(), 0);
        assert!(
            start.elapsed() >= Duration::from_millis(30),
            "no descriptors: a sleep"
        );
    }

    #[test]
    fn a_sub_millisecond_timeout_still_waits() {
        let start = Instant::now();
        assert_eq!(poll(&mut [], Duration::from_micros(10)).unwrap(), 0);
        assert!(start.elapsed() >= Duration::from_micros(10));
    }

    extern "C" fn ignore(_: libc::c_int) {}

    /// A signal that interrupts the wait ends it with nothing ready.
    #[test]
    #[cfg_attr(miri, ignore = "Miri has no sigaction")]
    fn an_interrupted_wait_reports_nothing_ready() {
        // SAFETY: all-zero bytes are a valid, empty `sigaction`.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = ignore as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: `action` is valid and lives through the call; its handler
        // does nothing, so it is async-signal-safe. `SA_RESTART` is left
        // out on purpose, so that `poll` sees EINTR.
        let rc = unsafe { libc::sigaction(libc::SIGUSR1, &raw const action, std::ptr::null_mut()) };
        assert_eq!(rc, 0);
        // SAFETY: `pthread_self` has no preconditions.
        let me = unsafe { libc::pthread_self() };
        let (_a, b) = UnixStream::pair().unwrap();
        let done = std::sync::atomic::AtomicBool::new(false);
        let start = Instant::now();
        let got = std::thread::scope(|scope| {
            // Signalled until the wait ends, so one sent before it began
            // cannot leave it waiting out its timeout.
            scope.spawn(|| {
                while !done.load(std::sync::atomic::Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(5));
                    // SAFETY: `me` is the scope's thread, which outlives
                    // this one.
                    unsafe { libc::pthread_kill(me, libc::SIGUSR1) };
                }
            });
            let mut fds = [PollFd::new(b.as_fd(), Events::IN)];
            let got = poll(&mut fds, Duration::from_secs(10));
            done.store(true, std::sync::atomic::Ordering::Release);
            got
        });
        assert_eq!(got.unwrap(), 0);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the signal ended the wait"
        );
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    #![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

    use std::io::Write as _;
    use std::net::{TcpListener, TcpStream};
    use std::os::windows::io::AsSocket as _;
    use std::time::Instant;

    use super::*;

    /// A connected pair of loopback sockets.
    fn pair() -> (TcpStream, TcpStream) {
        std::mem::forget(crate::net::Winsock::start().unwrap());
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        (a, b)
    }

    #[test]
    fn events_combine_and_contain() {
        let both = Events::IN | Events::OUT;
        assert!(both.contains(Events::IN));
        assert!(both.contains(Events::OUT));
        assert!(!Events::IN.contains(Events::OUT));
        assert!(
            Events::IN.contains(Events::RDNORM | Events::RDBAND),
            "Winsock's IN"
        );
        assert!(!both.intersects(Events::PRI | Events::HUP));
    }

    #[test]
    fn a_copy_s_events_go_back_to_the_entry() {
        let (mut a, b) = pair();
        a.write_all(b"x").unwrap();
        let mut mine = PollFd::new(b.as_socket(), Events::IN | Events::OUT);
        let mut copies = [mine];
        assert_eq!(poll(&mut copies, Duration::from_secs(5)).unwrap(), 1);
        mine.copy_revents(&copies[0]);
        assert_eq!(mine.revents(), Events::IN | Events::OUT);
    }

    #[test]
    #[should_panic = "a copy of this entry"]
    fn events_only_go_back_to_the_entry_polled() {
        let (_a, b) = pair();
        let mut mine = PollFd::new(b.as_socket(), Events::IN);
        mine.copy_revents(&PollFd::new(b.as_socket(), Events::OUT));
    }

    /// Only the socket that is ready is reported, with what C's
    /// `Curl_poll` over `select` reports: a bit asked is told if it shares
    /// any bit with what was ready, so a socket asked `RDNORM` alone is told
    /// Winsock's whole `IN`, which holds it.
    #[test]
    fn reports_the_ready_socket_only() {
        let (mut a, b) = pair();
        let (_c, d) = pair();
        a.write_all(b"x").unwrap();
        let mut fds = [
            PollFd::new(b.as_socket(), Events::IN),
            PollFd::new(d.as_socket(), Events::IN),
        ];
        assert_eq!(poll(&mut fds, Duration::from_secs(5)).unwrap(), 1);
        assert_eq!(fds[0].revents(), Events::IN);
        assert!(fds[1].revents().is_empty());
        let mut fds = [PollFd::new(b.as_socket(), Events::RDNORM)];
        assert_eq!(poll(&mut fds, Duration::from_secs(5)).unwrap(), 1);
        assert_eq!(fds[0].revents(), Events::IN);
        // The same socket twice is in each set once, and told to both.
        let mut fds = [
            PollFd::new(b.as_socket(), Events::IN),
            PollFd::new(b.as_socket(), Events::OUT),
        ];
        assert_eq!(poll(&mut fds, Duration::from_secs(5)).unwrap(), 2);
        assert_eq!(
            (fds[0].revents(), fds[1].revents()),
            (Events::IN, Events::OUT)
        );
    }

    #[test]
    fn waits_out_its_timeout_with_nothing_ready() {
        let (_a, b) = pair();
        let mut fds = [PollFd::new(b.as_socket(), Events::IN)];
        let start = Instant::now();
        assert_eq!(poll(&mut fds, Duration::from_millis(30)).unwrap(), 0);
        assert!(
            start.elapsed() >= Duration::from_millis(30),
            "{:?}",
            start.elapsed()
        );
        let start = Instant::now();
        assert_eq!(poll(&mut [], Duration::from_millis(30)).unwrap(), 0);
        assert!(
            start.elapsed() >= Duration::from_millis(30),
            "no sockets: a sleep"
        );
        // Asked for nothing, a socket is in no set: a sleep too, as
        // Winsock's `select` refuses empty sets.
        let mut fds = [PollFd::new(b.as_socket(), Events::NONE)];
        let start = Instant::now();
        assert_eq!(poll(&mut fds, Duration::from_millis(30)).unwrap(), 0);
        assert!(
            start.elapsed() >= Duration::from_millis(30),
            "nothing asked: a sleep"
        );
    }

    #[test]
    fn a_sub_millisecond_timeout_still_waits() {
        let start = Instant::now();
        assert_eq!(poll(&mut [], Duration::from_micros(10)).unwrap(), 0);
        assert!(start.elapsed() >= Duration::from_micros(10));
    }

    /// More sockets than Winsock's `FD_SETSIZE` are polled all the same.
    #[test]
    fn polls_more_sockets_than_a_set_holds() {
        let pairs: Vec<_> = (0..ON_STACK + 6).map(|_| pair()).collect();
        let mut last = &pairs[pairs.len() - 1].0;
        last.write_all(b"x").unwrap();
        let mut fds: Vec<_> = pairs
            .iter()
            .map(|(_, b)| PollFd::new(b.as_socket(), Events::IN))
            .collect();
        assert_eq!(poll(&mut fds, Duration::from_secs(5)).unwrap(), 1);
        assert!(fds[..ON_STACK + 5].iter().all(|f| f.revents().is_empty()));
        assert_eq!(fds[ON_STACK + 5].revents(), Events::IN);
    }
}
