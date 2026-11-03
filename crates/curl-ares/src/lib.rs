//! Name resolution by c-ares: a channel for each resolve, driven by the
//! transfer that asked, its sockets in the transfer's pollset, as C's
//! `asyn-ares.c` does it.
#![allow(unsafe_code)]

mod sys;

use core::ffi::{CStr, c_char, c_int, c_void};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::BorrowedFd;
use std::sync::Once;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec, try_box};
use curl_core::conn::io::{
    Connect, DnsAsk, DnsLibrary, DnsRefused, DnsResolve, DnsSay, Events, Family, Partial,
    Readiness, Recv, Remote, ResolveFailure, Sent, Socket, SocketKey, SocketOption, SocketsClosed,
};
use curl_core::doh::{HttpsRecord, RecordAnswer, RecordError};

/// The most addresses kept of one answer (`async_ares_node2addr`).
const MAX_ADDRESSES: usize = 256;

/// The library's version, as `curl_version` names it.
pub fn version() -> &'static str {
    // SAFETY: a null argument is allowed.
    let text = unsafe { sys::ares_version(core::ptr::null_mut()) };
    // SAFETY: c-ares returns a static string.
    let text = unsafe { CStr::from_ptr(text) };
    text.to_str().unwrap_or("?")
}

/// The library's version as a number (`ares_num`), `0x010000` a major.
pub fn version_number() -> u32 {
    let mut number: c_int = 0;
    // SAFETY: `number` is valid to write.
    unsafe { sys::ares_version(&mut number) };
    u32::try_from(number).unwrap_or(0)
}

/// What C's debug build says of servers c-ares will not take.
const BAD_SERVERS: &str = "bad servers set";

/// The c-ares library, for a transfer's `Libraries`.
#[derive(Debug)]
pub struct Ares;

pub static ARES: Ares = Ares;

impl DnsLibrary for Ares {
    fn resolve(
        &self,
        ask: DnsAsk<'_>,
        say: &mut DnsSay<'_>,
    ) -> Result<Box<dyn DnsResolve>, DnsRefused> {
        static INIT: Once = Once::new();
        // SAFETY: called once, before any channel; a failure shows as the
        // channel's own.
        INIT.call_once(|| unsafe {
            sys::ares_library_init(sys::LIB_INIT_ALL);
        });
        let resolving = Resolving::new(ask.closed)?;
        let mut boxed = try_box(resolving).map_err(|OutOfMemory| DnsRefused::OutOfMemory)?;
        boxed.configure(&ask)?;
        boxed.say_servers(say);
        boxed.ask(&ask, say)?;
        boxed.refresh();
        Ok(boxed)
    }
}

/// What the callbacks fill in. Boxed, so the address they hold stays.
#[derive(Debug)]
struct Answers {
    ongoing: u32,
    a_answered: bool,
    aaaa_answered: bool,
    asked_v6: bool,
    asked_v4: bool,
    v6: Vec<IpAddr>,
    v4: Vec<IpAddr>,
    /// C's `ares_status`: the last failure, success never overwritten.
    status: c_int,
    /// A failure other than the name's not existing, or having no records.
    transient: bool,
    /// Anything of ours that ran out, or a record that could not be read.
    failed: Option<DnsRefused>,
    /// An HTTPS query, with what its answer held.
    https: bool,
    record: Option<HttpsRecord>,
    /// Where the sockets the channel closes are told.
    closed: SocketsClosed,
}

/// One resolve: its channel, and what it has found.
#[derive(Debug)]
struct Resolving {
    channel: *mut sys::Channel,
    answers: Box<Answers>,
    wants: Vec<(Box<dyn Socket>, Events)>,
}

// SAFETY: the channel and the callbacks' data are owned here and moved whole;
// c-ares keeps no thread of its own on them and is called through `&mut self`.
unsafe impl Send for Resolving {}

/// The callback's data, `arg`, as the answers it is.
///
/// # Safety
/// `arg` is the `Answers` of a live `Resolving`, not otherwise borrowed while
/// c-ares runs, which it is only called from `&mut self`.
unsafe fn answers<'a>(arg: *mut c_void) -> &'a mut Answers {
    // SAFETY: as this function requires.
    unsafe { &mut *arg.cast::<Answers>() }
}

/// `async_ares_A_cb` and `async_ares_AAAA_cb`: which, by the addresses asked.
unsafe extern "C" fn addresses_done(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    ai: *mut sys::Addrinfo,
    v6: bool,
) {
    // SAFETY: `arg` is what `ask` gave, the channel's `Answers`.
    let a = unsafe { answers(arg) };
    a.ongoing -= 1;
    a.aaaa_answered |= v6;
    a.a_answered |= !v6;
    if status == sys::SUCCESS {
        a.status = sys::SUCCESS;
        // SAFETY: on success c-ares passes a list it gives us to free.
        let nodes = unsafe { (*ai).nodes };
        // SAFETY: the same list, alive until it is freed below.
        let found = unsafe { node_addresses(nodes, v6) };
        // SAFETY: the same list, not used after.
        unsafe { sys::ares_freeaddrinfo(ai) };
        match found {
            Ok(found) if v6 => a.v6 = found,
            Ok(found) => a.v4 = found,
            Err(OutOfMemory) => a.failed = Some(DnsRefused::OutOfMemory),
        }
        return;
    }
    if status != sys::ENOTFOUND && status != sys::ENODATA {
        a.transient = true;
    }
    if a.status != sys::SUCCESS {
        a.status = status;
    }
}

unsafe extern "C" fn v4_done(arg: *mut c_void, status: c_int, t: c_int, ai: *mut sys::Addrinfo) {
    // SAFETY: passed on as it came.
    unsafe { addresses_done(arg, status, t, ai, false) };
}

unsafe extern "C" fn v6_done(arg: *mut c_void, status: c_int, t: c_int, ai: *mut sys::Addrinfo) {
    // SAFETY: passed on as it came.
    unsafe { addresses_done(arg, status, t, ai, true) };
}

/// The addresses of the family asked in the list `node` starts, without
/// repeats, at most 256 (`async_ares_node2addr`).
///
/// # Safety
/// `node` is null or a list as c-ares makes it, alive for the call.
unsafe fn node_addresses(
    mut node: *const sys::AddrinfoNode,
    v6: bool,
) -> Result<Vec<IpAddr>, OutOfMemory> {
    let mut found = Vec::new();
    while !node.is_null() && found.len() < MAX_ADDRESSES {
        // SAFETY: not null, and alive as the caller says.
        let n = unsafe { &*node };
        node = n.ai_next;
        if n.ai_addr.is_null() {
            continue;
        }
        let ip = match n.ai_family {
            libc::AF_INET if !v6 => {
                // SAFETY: of family `AF_INET`, it is a `sockaddr_in`.
                let sa = unsafe { &*n.ai_addr.cast::<libc::sockaddr_in>() };
                IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)))
            }
            libc::AF_INET6 if v6 => {
                // SAFETY: of family `AF_INET6`, it is a `sockaddr_in6`.
                let sa = unsafe { &*n.ai_addr.cast::<libc::sockaddr_in6>() };
                IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr))
            }
            _ => continue,
        };
        if !found.contains(&ip) {
            found.try_push(ip)?;
        }
    }
    Ok(found)
}

/// `async_ares_rr_done`.
unsafe extern "C" fn record_done(
    arg: *mut c_void,
    status: c_int,
    _timeouts: usize,
    dnsrec: *const sys::DnsRecord,
) {
    // SAFETY: `arg` is what `ask` gave, the channel's `Answers`.
    let a = unsafe { answers(arg) };
    a.ongoing -= 1;
    a.status = status;
    if status != sys::ENOTFOUND && status != sys::ENODATA {
        a.transient = true;
    }
    if status != sys::SUCCESS || dnsrec.is_null() {
        return;
    }
    // SAFETY: c-ares passes a record alive for the call.
    match unsafe { https_record(dnsrec) } {
        Ok(record) => a.record = Some(record),
        Err(RecordError::OutOfMemory) => a.failed = Some(DnsRefused::OutOfMemory),
        Err(_) => a.failed = Some(DnsRefused::BadRecord),
    }
}

/// The answer's HTTPS records folded into one, as `Curl_httpsrr_from_ares`
/// folds them: the last's priority, the last target not empty, and each
/// parameter as the last to set it says. An answer with none, of a CNAME
/// alone, is a record of nothing, priority 0, as C's is.
///
/// # Safety
/// `record` is alive for the call.
unsafe fn https_record(record: *const sys::DnsRecord) -> Result<HttpsRecord, RecordError> {
    let mut folded = HttpsRecord::default();
    // SAFETY: `record` is alive, as the caller says.
    let count = unsafe { sys::ares_dns_record_rr_cnt(record, sys::SECTION_ANSWER) };
    for i in 0..count {
        // SAFETY: `record` is alive, and `i` within its count.
        let rr = unsafe { sys::ares_dns_record_rr_get_const(record, sys::SECTION_ANSWER, i) };
        // SAFETY: each use of `rr` below: the record's own, alive with it.
        if unsafe { sys::ares_dns_rr_get_type(rr) } != sys::REC_TYPE_HTTPS {
            continue;
        }
        let into = &mut folded;
        // SAFETY: as above.
        let name = unsafe { sys::ares_dns_rr_get_str(rr, sys::RR_HTTPS_TARGET) };
        if !name.is_null() {
            // SAFETY: not null: a string of the record's.
            let name = unsafe { CStr::from_ptr(name) }.to_bytes();
            if !name.is_empty() {
                into.target.clear();
                into.target
                    .try_extend_from_slice(name)
                    .map_err(|OutOfMemory| RecordError::OutOfMemory)?;
            }
        }
        // SAFETY: as above.
        into.priority = unsafe { sys::ares_dns_rr_get_u16(rr, sys::RR_HTTPS_PRIORITY) };
        // SAFETY: as above.
        let options = unsafe { sys::ares_dns_rr_get_opt_cnt(rr, sys::RR_HTTPS_PARAMS) };
        for o in 0..options {
            let (mut value, mut length) = (core::ptr::null(), 0);
            // SAFETY: as above, `o` within its count, the out pointers valid.
            let key = unsafe {
                sys::ares_dns_rr_get_opt(
                    rr,
                    sys::RR_HTTPS_PARAMS,
                    o,
                    &raw mut value,
                    &raw mut length,
                )
            };
            let value: &[u8] = if value.is_null() {
                &[]
            } else {
                // SAFETY: not null: `length` bytes of the record's.
                unsafe { core::slice::from_raw_parts(value, length) }
            };
            into.set_parameter(key, value)?;
        }
    }
    Ok(folded)
}

/// `sock_state_cb`: a socket with nothing left to wait for is about to close,
/// which the transfer's multi is told as soon as c-ares is done, or as the
/// channel goes.
unsafe extern "C" fn socket_state(arg: *mut c_void, fd: c_int, readable: c_int, writable: c_int) {
    if readable != 0 || writable != 0 {
        return;
    }
    // SAFETY: `arg` is what `new` gave, the channel's `Answers`.
    let a = unsafe { answers(arg) };
    if a.closed.said(SocketKey::new(fd)).is_err() {
        a.failed = Some(DnsRefused::OutOfMemory);
    }
}

/// A copy of `text` ending in the NUL c-ares wants; refused as `why` if it
/// holds one.
fn c_text(text: &[u8], why: &'static str) -> Result<Vec<u8>, DnsRefused> {
    if text.contains(&0) {
        return Err(DnsRefused::BadOption(why));
    }
    let mut c = Vec::new();
    c.try_extend_from_slice(text)
        .map_err(|OutOfMemory| DnsRefused::OutOfMemory)?;
    c.try_push(0)
        .map_err(|OutOfMemory| DnsRefused::OutOfMemory)?;
    Ok(c)
}

impl Resolving {
    fn new(closed: &SocketsClosed) -> Result<Resolving, DnsRefused> {
        let mut answers = try_box(Answers {
            ongoing: 0,
            a_answered: false,
            aaaa_answered: false,
            asked_v6: false,
            asked_v4: false,
            v6: Vec::new(),
            v4: Vec::new(),
            status: sys::ENOTFOUND,
            transient: false,
            failed: None,
            https: false,
            record: None,
            closed: closed.clone(),
        })
        .map_err(|OutOfMemory| DnsRefused::OutOfMemory)?;
        // SAFETY: all zeroes is valid for each field of the options; only the
        // callback's, set below, is read, as the mask says.
        let mut options: sys::Options = unsafe { core::mem::zeroed() };
        options.sock_state_cb = Some(socket_state);
        options.sock_state_cb_data = (&raw mut *answers).cast();
        let mut channel = core::ptr::null_mut();
        // SAFETY: the out pointer and the options are valid for the call.
        let status = unsafe {
            sys::ares_init_options(&raw mut channel, &raw const options, sys::OPT_SOCK_STATE_CB)
        };
        match status {
            sys::SUCCESS => Ok(Resolving {
                channel,
                answers,
                wants: Vec::new(),
            }),
            sys::ENOMEM => Err(DnsRefused::OutOfMemory),
            _ => Err(DnsRefused::Init),
        }
    }

    /// `async_ares_init`'s settings: servers, interface, local addresses.
    fn configure(&mut self, ask: &DnsAsk<'_>) -> Result<(), DnsRefused> {
        #[cfg(feature = "debug-hooks")]
        let mut debug = [0u8; 256];
        #[cfg(feature = "debug-hooks")]
        let servers = curl_os::env::var_into(b"CURL_DNS_SERVER", &mut debug)
            .or(ask.options.servers.as_deref());
        #[cfg(not(feature = "debug-hooks"))]
        let servers = ask.options.servers.as_deref();
        if let Some(servers) = servers {
            let servers = c_text(servers, BAD_SERVERS)?;
            // SAFETY: the channel is ours and the text ends in its NUL.
            let status = unsafe {
                sys::ares_set_servers_ports_csv(self.channel, servers.as_ptr().cast::<c_char>())
            };
            match status {
                sys::SUCCESS => {}
                sys::ENOMEM => return Err(DnsRefused::OutOfMemory),
                _ => return Err(DnsRefused::BadOption(BAD_SERVERS)),
            }
        }
        let interface = c_text(
            ask.options.interface.as_deref().unwrap_or(b""),
            "bad DNS interface",
        )?;
        // SAFETY: as above; c-ares copies the name.
        unsafe { sys::ares_set_local_dev(self.channel, interface.as_ptr().cast::<c_char>()) };
        let v4 = match ask.options.local_ip4.as_deref() {
            None | Some(b"") => 0,
            Some(text) => u32::from(parsed::<Ipv4Addr>(text, "bad DNS IPv4 address")?),
        };
        // SAFETY: the channel is ours; the address is in the host's order.
        unsafe { sys::ares_set_local_ip4(self.channel, v4) };
        let v6 = match ask.options.local_ip6.as_deref() {
            None | Some(b"") => Ipv6Addr::UNSPECIFIED,
            Some(text) => parsed::<Ipv6Addr>(text, "bad DNS IPv6 address")?,
        };
        let octets = v6.octets();
        // SAFETY: the channel is ours; c-ares reads the 16 bytes given.
        unsafe { sys::ares_set_local_ip6(self.channel, octets.as_ptr()) };
        Ok(())
    }

    /// `ares: servers=` as C's trace says it.
    fn say_servers(&self, say: &mut DnsSay<'_>) {
        // SAFETY: the channel is ours.
        let csv = unsafe { sys::ares_get_servers_csv(self.channel) };
        if csv.is_null() {
            say(&[b"ares: servers=(null)"]);
            return;
        }
        // SAFETY: not null: a string c-ares made, freed just after.
        say(&[b"ares: servers=", unsafe { CStr::from_ptr(csv) }.to_bytes()]);
        // SAFETY: the same string, not used after.
        unsafe { sys::ares_free_string(csv.cast()) };
    }

    /// The queries, AAAA's first (`Curl_async_getaddrinfo`).
    fn ask(&mut self, ask: &DnsAsk<'_>, say: &mut DnsSay<'_>) -> Result<(), DnsRefused> {
        let name = c_text(ask.name, "bad name")?;
        let oom = |OutOfMemory| DnsRefused::OutOfMemory;
        let arg: *mut c_void = (&raw mut *self.answers).cast();
        let Some(family) = ask.family else {
            // An HTTPS record, named by its port off HTTPS's.
            let mut qname = Vec::new();
            if ask.port != 443 {
                let port = Digits::of(ask.port);
                qname.try_extend_from_slice(b"_").map_err(oom)?;
                qname.try_extend_from_slice(port.bytes()).map_err(oom)?;
                qname.try_extend_from_slice(b"._https.").map_err(oom)?;
            }
            qname.try_extend_from_slice(ask.name).map_err(oom)?;
            say(&[b"[HTTPS] ares: query records for ", &qname]);
            let qname = c_text(&qname, "bad name")?;
            self.answers.https = true;
            self.answers.ongoing += 1;
            // SAFETY: the channel is ours, the name ends in its NUL, and the
            // answers outlive the channel.
            unsafe {
                sys::ares_query_dnsrec(
                    self.channel,
                    qname.as_ptr().cast::<c_char>(),
                    sys::CLASS_IN,
                    sys::REC_TYPE_HTTPS,
                    record_done,
                    arg,
                    core::ptr::null_mut(),
                )
            };
            return Ok(());
        };
        let service = c_text(Digits::of(ask.port).bytes(), "bad port")?;
        let socktype = if ask.stream {
            libc::SOCK_STREAM
        } else {
            libc::SOCK_DGRAM
        };
        let query = |pf: c_int, callback: sys::AddrinfoCb, answers: &mut Answers| {
            let hints = sys::Hints {
                ai_flags: sys::AI_NUMERICSERV,
                ai_family: pf,
                ai_socktype: socktype,
                ai_protocol: 0,
            };
            answers.ongoing += 1;
            // SAFETY: the channel is ours, the texts end in their NULs, c-ares
            // copies them and the hints, and the answers outlive the channel.
            unsafe {
                sys::ares_getaddrinfo(
                    self.channel,
                    name.as_ptr().cast::<c_char>(),
                    service.as_ptr().cast::<c_char>(),
                    &raw const hints,
                    callback,
                    arg,
                );
            }
        };
        if matches!(family, Family::Any | Family::V6) {
            say(&[b"[AAAA] ares: query records for ", ask.name]);
            self.answers.asked_v6 = true;
            query(libc::AF_INET6, v6_done, &mut self.answers);
        }
        if matches!(family, Family::Any | Family::V4) {
            say(&[b"[A] ares: query records for ", ask.name]);
            self.answers.asked_v4 = true;
            query(libc::AF_INET, v4_done, &mut self.answers);
        }
        Ok(())
    }

    /// The sockets the channel waits on read anew (`Curl_ares_pollset`).
    /// A socket still waited on keeps its entry, so that looking again
    /// allocates nothing, as C's pollset does not: only a socket new to
    /// the channel is boxed.
    fn refresh(&mut self) {
        let mut socks = [sys::SOCKET_BAD; sys::GETSOCK_MAXNUM];
        // SAFETY: the array holds as many as it is said to.
        let bits = unsafe {
            sys::ares_getsock(
                self.channel,
                socks.as_mut_ptr(),
                sys::GETSOCK_MAXNUM as c_int,
            )
        };
        // The first `kept` are the sockets read so far, in the channel's
        // order; the rest are those it may no longer wait on.
        let mut kept = 0;
        for (i, &fd) in socks.iter().enumerate() {
            let mut events = Events::NONE;
            if bits & (1 << i) != 0 {
                events = events | Events::IN;
            }
            if bits & (1 << (i + sys::GETSOCK_MAXNUM)) != 0 {
                events = events | Events::OUT;
            }
            if events == Events::NONE {
                break;
            }
            let key = SocketKey::new(fd);
            let known = self.wants[kept..]
                .iter()
                .position(|(socket, _)| socket.key() == key);
            match known {
                Some(at) => self.wants.swap(kept, kept + at),
                None => {
                    let Ok(socket) = try_box(FdSocket(fd)) else {
                        self.answers.failed = Some(DnsRefused::OutOfMemory);
                        return;
                    };
                    if self
                        .wants
                        .try_push((socket as Box<dyn Socket>, events))
                        .is_err()
                    {
                        self.answers.failed = Some(DnsRefused::OutOfMemory);
                        return;
                    }
                    let last = self.wants.len() - 1;
                    self.wants.swap(kept, last);
                }
            }
            self.wants[kept].1 = events;
            kept += 1;
        }
        self.wants.truncate(kept);
    }
}

/// A port's digits.
struct Digits([u8; 5], usize);

impl Digits {
    fn of(mut port: u16) -> Digits {
        let (mut digits, mut at) = ([0u8; 5], 5);
        loop {
            at -= 1;
            digits[at] = b'0' + (port % 10) as u8;
            port /= 10;
            if port == 0 {
                return Digits(digits, at);
            }
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.0[self.1..]
    }
}

/// `text` as an address, or C's `inet_pton` failing, refused as `why`.
fn parsed<T: core::str::FromStr>(text: &[u8], why: &'static str) -> Result<T, DnsRefused> {
    core::str::from_utf8(text)
        .ok()
        .and_then(|t| t.parse().ok())
        .ok_or(DnsRefused::BadOption(why))
}

impl Drop for Resolving {
    fn drop(&mut self) {
        // SAFETY: the channel is ours and goes here; its callbacks, told it
        // goes, still find the answers.
        unsafe { sys::ares_destroy(self.channel) };
    }
}

impl DnsResolve for Resolving {
    fn perform(&mut self) -> Result<(), OutOfMemory> {
        let mut polls = [libc::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        }; sys::GETSOCK_MAXNUM];
        let mut count = 0;
        for (socket, events) in &self.wants {
            let (mut wanted, fd) = (0, socket.key().get());
            if events.contains(Events::IN) {
                wanted |= libc::POLLIN;
            }
            if events.contains(Events::OUT) {
                wanted |= libc::POLLOUT;
            }
            polls[count] = libc::pollfd {
                fd,
                events: wanted,
                revents: 0,
            };
            count += 1;
        }
        // SAFETY: the array holds `count` entries, and this does not wait.
        let ready = unsafe { libc::poll(polls.as_mut_ptr(), count as libc::nfds_t, 0) };
        if ready <= 0 {
            // Unconditionally, or it would never time out (`Curl_ares_perform`).
            // SAFETY: the channel is ours.
            unsafe { sys::ares_process_fd(self.channel, sys::SOCKET_BAD, sys::SOCKET_BAD) };
        } else {
            for poll in &polls[..count] {
                let read = if poll.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                    poll.fd
                } else {
                    sys::SOCKET_BAD
                };
                let write = if poll.revents & libc::POLLOUT != 0 {
                    poll.fd
                } else {
                    sys::SOCKET_BAD
                };
                // SAFETY: the channel is ours; these are its sockets.
                unsafe { sys::ares_process_fd(self.channel, read, write) };
            }
        }
        self.refresh();
        match self.answers.failed {
            Some(DnsRefused::OutOfMemory) => Err(OutOfMemory),
            _ => Ok(()),
        }
    }

    fn wants(&self) -> &[(Box<dyn Socket>, Events)] {
        &self.wants
    }

    fn due(&self, within: Duration) -> Duration {
        let max = libc::timeval {
            tv_sec: libc::time_t::try_from(within.as_secs()).unwrap_or(libc::time_t::MAX),
            tv_usec: libc::suseconds_t::from(i32::try_from(within.subsec_micros()).unwrap_or(0)),
        };
        let mut out = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        // SAFETY: the channel is ours; both times are valid for the call.
        let t = unsafe { sys::ares_timeout(self.channel, &raw const max, &raw mut out) };
        // SAFETY: what comes back is one of them.
        let t = unsafe { &*t };
        Duration::from_secs(u64::try_from(t.tv_sec).unwrap_or(0))
            + Duration::from_micros(u64::try_from(t.tv_usec).unwrap_or(0))
    }

    fn partial(&self) -> Result<Partial, OutOfMemory> {
        let a = &self.answers;
        let mut addrs = Vec::new();
        addrs.try_extend_from_slice(&a.v6)?;
        addrs.try_extend_from_slice(&a.v4)?;
        Ok(Partial {
            addrs,
            v6_answered: a.aaaa_answered || !a.asked_v6,
            v4_answered: a.a_answered || !a.asked_v4,
        })
    }

    fn ongoing(&self) -> (u32, &'static str) {
        let a = &self.answers;
        // `Curl_resolv_query_str`.
        let responses = match (a.a_answered, a.aaaa_answered) {
            (false, false) => "-",
            (true, false) => "A",
            (false, true) => "AAAA",
            (true, true) => "A+AAAA",
        };
        (a.ongoing, responses)
    }

    fn answer(&mut self) -> Option<Result<Vec<IpAddr>, ResolveFailure>> {
        let a = &mut *self.answers;
        if a.ongoing > 0 {
            return None;
        }
        if matches!(a.failed, Some(DnsRefused::OutOfMemory)) {
            return Some(Err(ResolveFailure::OutOfMemory));
        }
        if a.status == sys::SUCCESS && (!a.v6.is_empty() || !a.v4.is_empty()) {
            let mut addrs = core::mem::take(&mut a.v6);
            if addrs.try_extend_from_slice(&a.v4).is_err() {
                return Some(Err(ResolveFailure::OutOfMemory));
            }
            return Some(Ok(addrs));
        }
        Some(Err(match a.status {
            sys::ENOTFOUND if !a.transient => ResolveFailure::NotFound,
            sys::ENODATA if !a.transient => ResolveFailure::NoData,
            sys::ENOMEM => ResolveFailure::OutOfMemory,
            _ => ResolveFailure::Failed,
        }))
    }

    fn record(&mut self) -> Option<RecordAnswer> {
        let a = &mut *self.answers;
        if a.ongoing > 0 {
            return None;
        }
        if a.failed.is_some() {
            return Some(RecordAnswer::Failed);
        }
        Some(match a.status {
            sys::SUCCESS => match a.record.take() {
                Some(record) => RecordAnswer::Record(record),
                None => RecordAnswer::NoRecord,
            },
            sys::ENOTFOUND | sys::ENODATA => RecordAnswer::NoSuchName,
            _ => RecordAnswer::Failed,
        })
    }

    fn explain(&self) -> Option<&'static str> {
        let status = self.answers.status;
        if status == sys::SUCCESS {
            return None;
        }
        // SAFETY: any status is taken.
        let text = unsafe { sys::ares_strerror(status) };
        // SAFETY: c-ares returns a static string.
        unsafe { CStr::from_ptr(text) }.to_str().ok()
    }

    fn status(&self) -> i32 {
        self.answers.status
    }
}

/// A socket of the channel's, for the transfer's pollset only: c-ares owns it
/// and does everything on it.
#[derive(Debug)]
struct FdSocket(c_int);

fn not_ours() -> io::Error {
    io::Error::from(io::ErrorKind::Unsupported)
}

impl Socket for FdSocket {
    fn key(&self) -> SocketKey {
        SocketKey::new(self.0)
    }

    fn readiness(&self) -> Readiness<'_> {
        // SAFETY: read from the channel, which closes it only as it processes
        // or goes, after which the wants holding this are read anew or gone.
        Readiness::Poll(unsafe { BorrowedFd::borrow_raw(self.0) })
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        Ok(None)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(not_ours())
    }

    fn set(&self, _: SocketOption) -> io::Result<()> {
        Err(not_ours())
    }

    fn set_nonblocking(&self) -> io::Result<()> {
        Err(not_ours())
    }

    fn bind(&self, _: SocketAddr) -> io::Result<()> {
        Err(not_ours())
    }

    fn bind_to_device(&self, _: &[u8]) -> io::Result<()> {
        Err(not_ours())
    }

    fn connect(&self, _: &Remote) -> io::Result<Connect> {
        Err(not_ours())
    }

    fn recv(&self, _: &mut [u8]) -> io::Result<Recv> {
        Err(not_ours())
    }

    fn send(&self, _: &[u8]) -> io::Result<Sent> {
        Err(not_ours())
    }

    fn release(self: Box<Self>) -> SocketKey {
        SocketKey::new(self.0)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use curl_core::doh::RecordAlpn;

    #[test]
    fn a_socket_with_nothing_to_wait_for_is_told_to_close() {
        let closed = SocketsClosed::new().unwrap();
        let mut r = Resolving::new(&closed).unwrap();
        let arg: *mut core::ffi::c_void = (&raw mut *r.answers).cast();
        // SAFETY: `arg` is this resolve's answers, borrowed by nothing here.
        unsafe { socket_state(arg, 7, 1, 0) };
        assert!(closed.take().is_empty(), "it still waits");
        // SAFETY: as above.
        unsafe { socket_state(arg, 7, 0, 0) };
        assert_eq!(closed.take(), [SocketKey::new(7)]);
        assert!(closed.take().is_empty(), "told once");
    }

    #[test]
    fn the_responses_are_named_as_c_names_them() {
        let closed = SocketsClosed::new().unwrap();
        let mut r = Resolving::new(&closed).unwrap();
        for (a, aaaa, named) in [
            (false, false, "-"),
            (true, false, "A"),
            (false, true, "AAAA"),
            (true, true, "A+AAAA"),
        ] {
            r.answers.a_answered = a;
            r.answers.aaaa_answered = aaaa;
            assert_eq!(super::DnsResolve::ongoing(&r).1, named);
        }
    }

    use curl_core::options::DnsOptions;

    fn ask<'a>(name: &'a [u8], family: Option<Family>, options: &'a DnsOptions) -> DnsAsk<'a> {
        DnsAsk {
            name,
            port: 443,
            family,
            stream: true,
            options,
            closed: Box::leak(Box::new(SocketsClosed::new().unwrap())),
        }
    }

    #[test]
    fn a_name_in_the_hosts_file_is_found_and_said() {
        let options = DnsOptions::NONE_SET;
        let mut lines = Vec::new();
        let mut say = |parts: &[&[u8]]| lines.push(parts.concat());
        let mut r = ARES
            .resolve(ask(b"localhost", Some(Family::V4), &options), &mut say)
            .unwrap();
        for _ in 0..100 {
            if r.ongoing().0 == 0 {
                break;
            }
            r.perform().unwrap();
        }
        let found = r.answer().expect("answered").unwrap();
        assert!(
            found.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "{found:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with(b"[A] ares: query records for localhost"))
        );
        assert!(lines.iter().any(|l| l.starts_with(b"ares: servers=")));
    }

    #[test]
    fn bad_settings_are_refused_at_the_resolve() {
        let mut say = |_: &[&[u8]]| {};
        let bad = |set: &dyn Fn(&mut DnsOptions)| {
            let mut options = DnsOptions::NONE_SET;
            set(&mut options);
            let mut say = |_: &[&[u8]]| {};
            ARES.resolve(ask(b"x.test", Some(Family::V4), &options), &mut say)
                .err()
        };
        assert_eq!(
            bad(&|o| o.local_ip4 = Some(b"nope".to_vec())),
            Some(DnsRefused::BadOption("bad DNS IPv4 address"))
        );
        assert_eq!(
            bad(&|o| o.local_ip6 = Some(b"nope".to_vec())),
            Some(DnsRefused::BadOption("bad DNS IPv6 address"))
        );
        assert_eq!(
            bad(&|o| o.servers = Some(b"not a server".to_vec())),
            Some(DnsRefused::BadOption("bad servers set"))
        );
        let options = DnsOptions::NONE_SET;
        assert!(
            ARES.resolve(ask(b"nul\0name", Some(Family::V4), &options), &mut say)
                .is_err()
        );
    }

    /// Looked at again while its query waits, a resolve keeps the entry of
    /// the socket it waits on rather than making it anew: how often the
    /// transfer looks does not change what it allocates.
    #[test]
    #[allow(clippy::disallowed_macros)]
    fn a_socket_still_waited_on_keeps_its_entry() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let servers = format!("127.0.0.1:{}", silent.local_addr().unwrap().port());
        let options = DnsOptions {
            servers: Some(servers.into_bytes()),
            ..DnsOptions::NONE_SET
        };
        let mut say = |_: &[&[u8]]| {};
        let mut r = ARES
            .resolve(ask(b"x.test", Some(Family::V4), &options), &mut say)
            .unwrap();
        let entries = |r: &dyn DnsResolve| {
            r.wants()
                .iter()
                .map(|(socket, _)| (&raw const **socket).cast::<()>())
                .collect::<Vec<_>>()
        };
        r.perform().unwrap();
        let first = entries(&*r);
        assert_eq!(first.len(), 1, "it waits on its server's socket");
        for _ in 0..3 {
            r.perform().unwrap();
            assert_eq!(entries(&*r), first);
        }
        assert!(r.answer().is_none(), "the server says nothing");
    }

    /// The HTTPS record folded from an answer of `records`, each an
    /// answer's type and data, as c-ares hands it to `record_done`.
    fn folded(records: &[(u16, &[u8])]) -> Result<HttpsRecord, RecordError> {
        let mut message = b"\0\0\x81\x80\0\x01\0".to_vec();
        message.push(u8::try_from(records.len()).unwrap());
        message.extend_from_slice(b"\0\0\0\0\x02_1\x06_https\x01x\x04test\0\0\x41\0\x01");
        for (kind, data) in records {
            message.extend_from_slice(b"\xc0\x0c");
            message.extend_from_slice(&kind.to_be_bytes());
            message.extend_from_slice(b"\0\x01\0\0\0\x37");
            message.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            message.extend_from_slice(data);
        }
        let mut record = core::ptr::null_mut();
        // SAFETY: the message's bytes for its length; `record` is written.
        let parsed =
            unsafe { sys::ares_dns_parse(message.as_ptr(), message.len(), 0, &raw mut record) };
        assert_eq!(parsed, sys::SUCCESS);
        // SAFETY: c-ares made it, alive until destroyed below.
        let folded = unsafe { https_record(record) };
        // SAFETY: made by `ares_dns_parse`, and used no more.
        unsafe { sys::ares_dns_record_destroy(record) };
        folded
    }

    /// Several HTTPS records are one, as `Curl_httpsrr_from_ares` folds
    /// them: the last's priority, the last target not empty, and each
    /// parameter the last record to have it says; another type is passed,
    /// and an answer of none is a record of nothing.
    #[test]
    fn an_answers_https_records_are_folded_as_c_folds_them() {
        let a: (u16, &[u8]) = (1, b"\x7f\0\0\x01");
        let two = folded(&[
            a,
            (65, b"\0\x01\0\0\x01\0\x03\x02h3\0\x04\0\x04\x7f\0\0\x02"),
            (65, b"\0\x02\0\0\x01\0\x03\x02h2"),
        ])
        .unwrap();
        assert_eq!(two.priority, 2);
        assert_eq!(two.target, b"");
        assert_eq!(two.alpns, [RecordAlpn::H2]);
        assert_eq!(two.ipv4_hints, [Ipv4Addr::new(127, 0, 0, 2)]);
        let alias = folded(&[
            (65, b"\0\x01\x03alt\x04test\0\0\x01\0\x03\x02h2"),
            (65, b"\0\x01\0\0\x01\0\x09\x08http/1.1"),
        ])
        .unwrap();
        assert_eq!(alias.target, b"alt.test");
        assert_eq!(alias.alpns, [RecordAlpn::H1]);
        assert_eq!(folded(&[a]), Ok(HttpsRecord::default()));
        assert_eq!(
            folded(&[(65, b"\0\x01\0\0\x03\0\x01\x01")]),
            Err(RecordError::BadParameter)
        );
    }

    #[test]
    fn a_version_is_read() {
        assert!(version().starts_with("1."), "{}", version());
        assert!(version_number() >= 0x01_00_00);
    }
}
