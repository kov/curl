//! TELNET (`lib/telnet.c`, RFC 854, with RFC 1143's option negotiation):
//! the server's bytes, its commands taken out and answered, as the body,
//! and what the input handler gives sent to it, until the
//! server closes the connection.
//!
//! C runs the whole exchange within DO, blocking on the socket with a
//! poll of 100 ms between calls of the read function. Here it is DOING:
//! each round of C's loop is a pass, run when the socket has something
//! or 100 ms after the last round. The input is read only in a round, as
//! C reads it only once its poll has seen the server's bytes or waited
//! its 100 ms: the first, from DO, waits like any other, so that what the
//! server says first is answered before the input goes.
//!
//! On Windows C's loop is another (`USE_WINSOCK`): it waits on the
//! socket's events, and reads the input only once 100 ms have passed
//! without one, then until the input has nothing. Here too.

use std::fmt;
use std::time::Duration;

use curl_alloc::TryVec as _;

use super::base::peer_of;
use super::raw::{Got, xfer_recv, xfer_send};
use super::{Before, Connect, DoPhase, DoStep, ProtoStep, Waiting};
use crate::auth::creds::{CredentialGate, Credentials, Takes};
use crate::conn::ConnLease;
use crate::conn::io::Events;
use crate::deliver::{Pipeline, Reach};
use crate::error::ErrorKind;
use crate::handler::Read;
use crate::multi::state::StepCx;
use crate::multi::timers::TimeLeft;
use crate::multi::{Host, TransferCx};
use crate::progress;
use crate::time::Instant;
use crate::trace;
use crate::url::Url;

const TELOPT_BINARY: u8 = 0;
const TELOPT_ECHO: u8 = 1;
const TELOPT_SGA: u8 = 3;
const TELOPT_EXOPL: u8 = 255;
const TELOPT_TTYPE: u8 = 24;
const TELOPT_NAWS: u8 = 31;
const TELOPT_XDISPLOC: u8 = 35;
const TELOPT_NEW_ENVIRON: u8 = 39;
/// The options C negotiates (`CURL_NTELOPTS`).
const NTELOPTS: u8 = 40;

const NEW_ENV_VAR: u8 = 0;
const NEW_ENV_VALUE: u8 = 1;

const SE: u8 = 240;
const SB: u8 = 250;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
const IAC: u8 = 255;

const TELQUAL_IS: u8 = 0;
const TELQUAL_SEND: u8 = 1;
const TELQUAL_INFO: u8 = 2;
const TELQUAL_NAME: u8 = 3;

/// The room for a suboption (`SUBBUFSIZE`).
const SUBBUFSIZE: usize = 512;
/// The most read from the server, or from the read handler, at once.
const BUFFER: usize = 4 * 1024;
/// How long a pass waits for the server before it asks the read handler
/// again.
const INTERVAL: Duration = Duration::from_millis(100);
/// Whether the exchange is C's Windows loop (`USE_WINSOCK`): the input
/// read only after the socket has been quiet for `INTERVAL`, and until
/// it has nothing; no progress taken stock of, nothing counted but the
/// body delivered, and an aborted input a read error.
const WINSOCK: bool = cfg!(windows);

static TELOPTS: [&str; 40] = [
    "BINARY",
    "ECHO",
    "RCP",
    "SUPPRESS GO AHEAD",
    "NAME",
    "STATUS",
    "TIMING MARK",
    "RCTE",
    "NAOL",
    "NAOP",
    "NAOCRD",
    "NAOHTS",
    "NAOHTD",
    "NAOFFD",
    "NAOVTS",
    "NAOVTD",
    "NAOLFD",
    "EXTEND ASCII",
    "LOGOUT",
    "BYTE MACRO",
    "DE TERMINAL",
    "SUPDUP",
    "SUPDUP OUTPUT",
    "SEND LOCATION",
    "TERM TYPE",
    "END OF RECORD",
    "TACACS UID",
    "OUTPUT MARKING",
    "TTYLOC",
    "3270 REGIME",
    "X3 PAD",
    "NAWS",
    "TERM SPEED",
    "LFLOW",
    "LINEMODE",
    "XDISPLOC",
    "OLD-ENVIRON",
    "AUTHENTICATION",
    "ENCRYPT",
    "NEW-ENVIRON",
];

static TELCMDS: [&str; 20] = [
    "EOF", "SUSP", "ABORT", "EOR", "SE", "NOP", "DMARK", "BRK", "IP", "AO", "AYT", "EC", "EL",
    "GA", "SB", "WILL", "WONT", "DO", "DONT", "IAC",
];

/// An option's name, if C names it (`CURL_TELOPT`).
fn telopt(x: u32) -> Option<&'static str> {
    usize::try_from(x)
        .ok()
        .and_then(|i| TELOPTS.get(i))
        .copied()
}

/// A command's name, if C names it (`CURL_TELCMD`).
fn telcmd(x: u32) -> Option<&'static str> {
    x.checked_sub(236)
        .and_then(|i| TELCMDS.get(usize::try_from(i).ok()?))
        .copied()
}

/// What is wanted of an option, by the application or for a
/// suboption.
const NO: u8 = 0;
const YES: u8 = 1;

/// Where an option stands on one side (RFC 1143's states). C asks only
/// to enable options, never to disable one, so neither RFC 1143's
/// WANTNO nor its queue ever arises: only these three.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    No,
    Yes,
    /// Asked for, not yet answered.
    WantYes,
}

/// Where the reader is in the server's bytes (`TelnetReceive`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Receive {
    Data,
    Iac,
    Will,
    Wont,
    Do,
    Dont,
    Cr,
    Sb,
    Se,
}

/// What the exchange does to the world: what it sends, says and
/// delivers.
pub(crate) trait Wire {
    /// Send `bytes`, in order after those sent before, what the
    /// connection does not take now kept to go first next time.
    fn send(&mut self, bytes: &[u8]) -> Result<(), ErrorKind>;
    /// Say a line of the trace, made of `parts`.
    fn info(&mut self, parts: &[&[u8]]);
    /// Say a line of the trace, formatted.
    fn info_fmt(&mut self, args: fmt::Arguments<'_>);
    /// The transfer fails with `kind`, a reason said.
    fn fail(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind;
    /// Deliver body bytes.
    fn body(&mut self, bytes: &[u8]) -> Result<(), ErrorKind>;
}

/// The application's TELNET options, read (`check_telnet_options`).
#[derive(Debug, Default)]
pub(crate) struct Settings {
    ttype: Option<Vec<u8>>,
    xdisploc: Option<Vec<u8>>,
    wsx: u16,
    wsy: u16,
    vars: Vec<Vec<u8>>,
    /// Options the application wants on its side, and on the server's.
    us: Vec<u8>,
    us_off: Vec<u8>,
    him_off: Vec<u8>,
}

/// TELNET's state for a transfer (`struct TELNET`).
#[derive(Debug)]
pub(crate) struct Telnet {
    please_negotiate: bool,
    already_negotiated: bool,
    us: [Side; 256],
    us_preferred: [u8; 256],
    him: [Side; 256],
    him_preferred: [u8; 256],
    subnegotiation: [u8; 256],
    ttype: Option<Vec<u8>>,
    xdisploc: Option<Vec<u8>>,
    wsx: u16,
    wsy: u16,
    state: Receive,
    vars: Vec<Vec<u8>>,
    subbuffer: [u8; SUBBUFSIZE],
    /// Where the suboption is read or written to (`subpointer`).
    subpointer: usize,
    /// Where it ends, once complete (`subend`).
    subend: usize,
}

/// Whether `bytes` has a byte past ASCII (`str_is_nonascii`).
fn non_ascii(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| b & 0x80 != 0)
}

/// A decimal number at the start of `p`, at most `max`, and what follows
/// it (`curlx_str_number`).
fn number(p: &[u8], max: u64) -> Option<(u64, &[u8])> {
    let digits = p.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let mut n: u64 = 0;
    for &b in &p[..digits] {
        n = n.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
        if n > max {
            return None;
        }
    }
    Some((n, &p[digits..]))
}

/// Why the application's options were refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// An option C does not know: said if its name's length is none C
    /// knows (`CURLE_UNKNOWN_OPTION`).
    Unknown {
        said: bool,
    },
    /// An option without `=`, or a window size that is not `WxH`
    /// (`CURLE_SETOPT_OPTION_SYNTAX`).
    Syntax,
    /// A user name past ASCII (`CURLE_BAD_FUNCTION_ARGUMENT`).
    NonAsciiUser,
    OutOfMemory,
}

impl Settings {
    /// The application's `options` and the transfer's `user`, read as C
    /// reads them; the option a refusal is of.
    pub(crate) fn read<'o>(
        user: Option<&[u8]>,
        options: impl IntoIterator<Item = &'o [u8]>,
    ) -> Result<Settings, (Refused, Option<&'o [u8]>)> {
        let oom = |_| (Refused::OutOfMemory, None);
        let mut s = Settings::default();
        if let Some(user) = user {
            if non_ascii(user) {
                return Err((Refused::NonAsciiUser, None));
            }
            // C prints it into 256 bytes, its zero among them.
            let mut var = Vec::new();
            var.try_extend_from_slice(b"USER,").map_err(oom)?;
            let room = 255 - var.len();
            var.try_extend_from_slice(&user[..user.len().min(room)])
                .map_err(oom)?;
            s.vars.try_push(var).map_err(oom)?;
            s.us.try_push(TELOPT_NEW_ENVIRON).map_err(oom)?;
        }
        for option in options {
            let Some(eq) = option.iter().position(|&b| b == b'=') else {
                return Err((Refused::Syntax, Some(option)));
            };
            let (name, arg) = (&option[..eq], &option[eq + 1..]);
            if non_ascii(arg) {
                continue;
            }
            let is = |want: &[u8]| name.eq_ignore_ascii_case(want);
            let copy = |b: &[u8]| {
                let mut v = Vec::new();
                v.try_extend_from_slice(b).map(|()| v)
            };
            match name.len() {
                5 if is(b"TTYPE") => {
                    s.ttype = Some(copy(arg).map_err(oom)?);
                    s.us.try_push(TELOPT_TTYPE).map_err(oom)?;
                }
                8 if is(b"XDISPLOC") => {
                    s.xdisploc = Some(copy(arg).map_err(oom)?);
                    s.us.try_push(TELOPT_XDISPLOC).map_err(oom)?;
                }
                7 if is(b"NEW_ENV") => {
                    s.vars.try_push(copy(arg).map_err(oom)?).map_err(oom)?;
                    s.us.try_push(TELOPT_NEW_ENVIRON).map_err(oom)?;
                }
                2 if is(b"WS") => {
                    let size = number(arg, 0xffff).and_then(|(x, rest)| {
                        let rest = rest.strip_prefix(b"x")?;
                        number(rest, 0xffff).map(|(y, _)| (x, y))
                    });
                    let Some((x, y)) = size else {
                        return Err((Refused::Syntax, Some(option)));
                    };
                    s.wsx = u16::try_from(x).expect("at most 0xffff");
                    s.wsy = u16::try_from(y).expect("at most 0xffff");
                    s.us.try_push(TELOPT_NAWS).map_err(oom)?;
                }
                6 if is(b"BINARY") => {
                    if number(arg, 1).is_some_and(|(n, _)| n != 1) {
                        s.us_off.try_push(TELOPT_BINARY).map_err(oom)?;
                        s.him_off.try_push(TELOPT_BINARY).map_err(oom)?;
                    }
                }
                5 | 8 | 7 | 2 | 6 => return Err((Refused::Unknown { said: false }, Some(option))),
                _ => return Err((Refused::Unknown { said: true }, Some(option))),
            }
        }
        Ok(s)
    }
}

impl Telnet {
    /// The state C starts from, the application's `settings` taken
    /// (`init_telnet`, `check_telnet_options`).
    pub(crate) fn new(settings: Settings) -> Telnet {
        let mut tn = Telnet {
            please_negotiate: false,
            already_negotiated: false,
            us: [Side::No; 256],
            us_preferred: [NO; 256],
            him: [Side::No; 256],
            him_preferred: [NO; 256],
            subnegotiation: [NO; 256],
            ttype: settings.ttype,
            xdisploc: settings.xdisploc,
            wsx: settings.wsx,
            wsy: settings.wsy,
            state: Receive::Data,
            vars: settings.vars,
            subbuffer: [0; SUBBUFSIZE],
            subpointer: 0,
            subend: 0,
        };
        let sga = usize::from(TELOPT_SGA);
        let binary = usize::from(TELOPT_BINARY);
        tn.us_preferred[sga] = YES;
        tn.him_preferred[sga] = YES;
        tn.us_preferred[binary] = YES;
        tn.him_preferred[binary] = YES;
        tn.him_preferred[usize::from(TELOPT_ECHO)] = YES;
        tn.subnegotiation[usize::from(TELOPT_NAWS)] = YES;
        for &o in &settings.us {
            tn.us_preferred[usize::from(o)] = YES;
        }
        for &o in &settings.us_off {
            tn.us_preferred[usize::from(o)] = NO;
        }
        for &o in &settings.him_off {
            tn.him_preferred[usize::from(o)] = NO;
        }
        tn
    }

    /// Whether the server has started negotiating and C's negotiation is
    /// yet to be made: it is made once, after the read that started it.
    pub(crate) fn negotiate_once(&mut self, wire: &mut dyn Wire) {
        if self.please_negotiate && !self.already_negotiated {
            self.negotiate(wire);
            self.already_negotiated = true;
        }
    }

    /// Ask for each option this side or the server's should have
    /// (`telnet_negotiate`), but ECHO, which the server may only offer.
    fn negotiate(&mut self, wire: &mut dyn Wire) {
        for i in 0..NTELOPTS {
            if i == TELOPT_ECHO {
                continue;
            }
            if self.us_preferred[usize::from(i)] == YES {
                self.ask_local(wire, i);
            }
            if self.him_preferred[usize::from(i)] == YES {
                self.ask_remote(wire, i);
            }
        }
    }

    /// Say `cmd` of `option` (`send_negotiation`): a failing send said and
    /// gone past, as C does.
    fn send_negotiation(&mut self, wire: &mut dyn Wire, cmd: u8, option: u8) {
        if let Err(e) = wire.send(&[IAC, cmd, option]) {
            sending_failed(wire, e);
        }
        print_option(wire, "SENT", cmd, option);
    }

    /// Ask the server to enable `option` (`set_remote_option` with
    /// `CURL_YES`, the only way C calls it): asked once, as the
    /// negotiation starts, when it is enabled already or not at all,
    /// never half way, so C's queued cases do not arise.
    fn ask_remote(&mut self, wire: &mut dyn Wire, option: u8) {
        let o = usize::from(option);
        if self.him[o] == Side::No {
            self.him[o] = Side::WantYes;
            self.send_negotiation(wire, DO, option);
        }
    }

    /// Offer to enable `option` here (`set_local_option` with
    /// `CURL_YES`), as `ask_remote` asks.
    fn ask_local(&mut self, wire: &mut dyn Wire, option: u8) {
        let o = usize::from(option);
        if self.us[o] == Side::No {
            self.us[o] = Side::WantYes;
            self.send_negotiation(wire, WILL, option);
        }
    }

    fn rec_will(&mut self, wire: &mut dyn Wire, option: u8) {
        let o = usize::from(option);
        match self.him[o] {
            Side::No => {
                if self.him_preferred[o] == YES {
                    self.him[o] = Side::Yes;
                    self.send_negotiation(wire, DO, option);
                } else {
                    self.send_negotiation(wire, DONT, option);
                }
            }
            Side::WantYes => self.him[o] = Side::Yes,
            Side::Yes => {}
        }
    }

    fn rec_wont(&mut self, wire: &mut dyn Wire, option: u8) {
        let o = usize::from(option);
        match self.him[o] {
            Side::Yes => {
                self.him[o] = Side::No;
                self.send_negotiation(wire, DONT, option);
            }
            Side::WantYes => self.him[o] = Side::No,
            Side::No => {}
        }
    }

    fn rec_do(&mut self, wire: &mut dyn Wire, option: u8) {
        let o = usize::from(option);
        match self.us[o] {
            Side::No => {
                if self.us_preferred[o] == YES {
                    self.us[o] = Side::Yes;
                    self.send_negotiation(wire, WILL, option);
                    if self.subnegotiation[o] == YES {
                        self.send_suboption(wire, option);
                    }
                } else if self.subnegotiation[o] == YES {
                    self.us[o] = Side::Yes;
                    self.send_negotiation(wire, WILL, option);
                    self.send_suboption(wire, option);
                } else {
                    self.send_negotiation(wire, WONT, option);
                }
            }
            Side::WantYes => {
                self.us[o] = Side::Yes;
                if self.subnegotiation[o] == YES {
                    self.send_suboption(wire, option);
                }
            }
            Side::Yes => {}
        }
    }

    fn rec_dont(&mut self, wire: &mut dyn Wire, option: u8) {
        let o = usize::from(option);
        match self.us[o] {
            Side::Yes => {
                self.us[o] = Side::No;
                self.send_negotiation(wire, WONT, option);
            }
            Side::WantYes => self.us[o] = Side::No,
            Side::No => {}
        }
    }

    /// Put `c` in the suboption, if it has room (`CURL_SB_ACCUM`).
    fn sb_accum(&mut self, c: u8) {
        if self.subpointer < SUBBUFSIZE {
            self.subbuffer[self.subpointer] = c;
            self.subpointer += 1;
        }
    }

    /// End the suboption where it is written to (`CURL_SB_TERM`).
    fn sb_term(&mut self) {
        self.subend = self.subpointer;
        self.subpointer = 0;
    }

    /// How much of it is left to read (`CURL_SB_LEN`).
    fn sb_len(&self) -> usize {
        self.subend.saturating_sub(self.subpointer)
    }

    /// Send the window size, as NAWS's suboption (`sendsuboption`): its
    /// head and foot each sent once, its size escaped.
    fn send_suboption(&mut self, wire: &mut dyn Wire, option: u8) {
        if option != TELOPT_NAWS {
            return;
        }
        self.subpointer = 0;
        let [x0, x1] = self.wsx.to_be_bytes();
        let [y0, y1] = self.wsy.to_be_bytes();
        for c in [IAC, SB, TELOPT_NAWS, x0, x1, y0, y1, IAC, SE] {
            self.sb_accum(c);
        }
        self.sb_term();
        let sub = self.subbuffer;
        print_sub(wire, Some(b'>'), &sub[2..], self.sb_len() - 2);
        if let Err(e) = wire.send(&sub[..3]) {
            sending_failed(wire, e);
        }
        // Its result goes unread, as C's does.
        let _unread = send_data(wire, &sub[3..7]);
        if let Err(e) = wire.send(&sub[7..9]) {
            sending_failed(wire, e);
        }
    }

    /// Answer the suboption read (`suboption`): the terminal type, the
    /// display or the variables the server asks for.
    fn suboption(&mut self, wire: &mut dyn Wire) -> Result<(), ErrorKind> {
        if self.sb_len() == 0 {
            return Ok(());
        }
        let sub = self.subbuffer;
        print_sub(wire, Some(b'<'), &sub, self.sb_len() + 2);
        // The option it is of (`CURL_SB_GET`); nothing reads further.
        let what = self.subbuffer[self.subpointer];
        let mut temp = Vec::new();
        let oom = |_| ErrorKind::OutOfMemory;
        match what {
            TELOPT_TTYPE | TELOPT_XDISPLOC => {
                let (value, name) = if what == TELOPT_TTYPE {
                    (self.ttype.as_deref(), "TTYPE")
                } else {
                    (self.xdisploc.as_deref(), "XDISPLOC")
                };
                let Some(value) = value.filter(|v| !v.contains(&IAC)) else {
                    return Err(ErrorKind::BadFunctionArgument);
                };
                if value.len() > 1000 {
                    return Err(
                        wire.fail(ErrorKind::SendError, format_args!("Too long telnet {name}"))
                    );
                }
                temp.try_extend_from_slice(&[IAC, SB, what, TELQUAL_IS])
                    .map_err(oom)?;
                temp.try_extend_from_slice(value).map_err(oom)?;
                temp.try_extend_from_slice(&[IAC, SE]).map_err(oom)?;
            }
            TELOPT_NEW_ENVIRON => {
                temp.try_extend_from_slice(&[IAC, SB, what, TELQUAL_IS])
                    .map_err(oom)?;
                for v in &self.vars {
                    if v.contains(&IAC) {
                        return Err(ErrorKind::BadFunctionArgument);
                    }
                    // Added if it fits C's buffer of 2048.
                    if temp.len() + v.len() + 1 < 2048 - 6 {
                        temp.try_push(NEW_ENV_VAR).map_err(oom)?;
                        match v.iter().position(|&b| b == b',') {
                            None => temp.try_extend_from_slice(v).map_err(oom)?,
                            Some(comma) => {
                                temp.try_extend_from_slice(&v[..comma]).map_err(oom)?;
                                temp.try_push(NEW_ENV_VALUE).map_err(oom)?;
                                temp.try_extend_from_slice(&v[comma + 1..]).map_err(oom)?;
                            }
                        }
                    }
                }
                temp.try_extend_from_slice(&[IAC, SE]).map_err(oom)?;
            }
            _ => return Ok(()),
        }
        if let Err(e) = wire.send(&temp) {
            return Err(sending_failed(wire, e));
        }
        print_sub(wire, Some(b'>'), &temp[2..], temp.len() - 2);
        Ok(())
    }

    /// Read the server's bytes: commands answered, data delivered as the
    /// body, a NUL after a CR taken out (`telrcv`).
    pub(crate) fn receive(&mut self, wire: &mut dyn Wire, inbuf: &[u8]) -> Result<(), ErrorKind> {
        let mut start: Option<usize> = None;
        let skip = |wire: &mut dyn Wire, start: &mut Option<usize>, upto: usize| {
            if let Some(at) = start.take() {
                wire.body(&inbuf[at..upto])?;
            }
            Ok::<(), ErrorKind>(())
        };
        for (i, &c) in inbuf.iter().enumerate() {
            match self.state {
                Receive::Cr => {
                    self.state = Receive::Data;
                    if c == 0 {
                        skip(wire, &mut start, i)?;
                    } else {
                        start.get_or_insert(i);
                    }
                }
                Receive::Data => {
                    if c == IAC {
                        self.state = Receive::Iac;
                        skip(wire, &mut start, i)?;
                    } else {
                        if c == b'\r' {
                            self.state = Receive::Cr;
                        }
                        start.get_or_insert(i);
                    }
                }
                Receive::Iac => match c {
                    WILL => self.state = Receive::Will,
                    WONT => self.state = Receive::Wont,
                    DO => self.state = Receive::Do,
                    DONT => self.state = Receive::Dont,
                    SB => {
                        self.subpointer = 0;
                        self.state = Receive::Sb;
                    }
                    IAC => {
                        self.state = Receive::Data;
                        start.get_or_insert(i);
                    }
                    _ => {
                        self.state = Receive::Data;
                        print_option(wire, "RCVD", IAC, c);
                    }
                },
                Receive::Will => {
                    print_option(wire, "RCVD", WILL, c);
                    self.please_negotiate = true;
                    self.rec_will(wire, c);
                    self.state = Receive::Data;
                }
                Receive::Wont => {
                    print_option(wire, "RCVD", WONT, c);
                    self.please_negotiate = true;
                    self.rec_wont(wire, c);
                    self.state = Receive::Data;
                }
                Receive::Do => {
                    print_option(wire, "RCVD", DO, c);
                    self.please_negotiate = true;
                    self.rec_do(wire, c);
                    self.state = Receive::Data;
                }
                Receive::Dont => {
                    print_option(wire, "RCVD", DONT, c);
                    self.please_negotiate = true;
                    self.rec_dont(wire, c);
                    self.state = Receive::Data;
                }
                Receive::Sb => {
                    if c == IAC {
                        self.state = Receive::Se;
                    } else {
                        self.sb_accum(c);
                    }
                }
                Receive::Se => {
                    if c != SE {
                        if c != IAC {
                            // Only IAC IAC or IAC SE belong here.
                            return Err(wire.fail(
                                ErrorKind::RecvError,
                                format_args!("telnet: suboption error"),
                            ));
                        }
                        self.sb_accum(c);
                        self.state = Receive::Sb;
                    } else {
                        self.sb_accum(IAC);
                        self.sb_accum(SE);
                        self.subpointer -= 2;
                        self.sb_term();
                        self.suboption(wire)?;
                        self.state = Receive::Data;
                    }
                }
            }
        }
        skip(wire, &mut start, inbuf.len())
    }
}

/// Say a send failed, as C's negotiation does, and what it failed with.
fn sending_failed(wire: &mut dyn Wire, e: ErrorKind) -> ErrorKind {
    wire.fail(e, format_args!("Sending data failed: {}", e.message()))
}

/// Send data, each IAC in it doubled (`send_telnet_data`).
pub(crate) fn send_data(wire: &mut dyn Wire, data: &[u8]) -> Result<(), ErrorKind> {
    if !data.contains(&IAC) {
        return wire.send(data);
    }
    let mut out = Vec::new();
    for &b in data {
        out.try_push(b).map_err(|_| ErrorKind::OutOfMemory)?;
        if b == IAC {
            out.try_push(IAC).map_err(|_| ErrorKind::OutOfMemory)?;
        }
    }
    wire.send(&out)
}

/// Say a command or an option's negotiation, as C's verbose trace does
/// (`printoption`).
fn print_option(wire: &mut dyn Wire, direction: &str, cmd: u8, option: u8) {
    let d = direction.as_bytes();
    if cmd == IAC {
        match telcmd(u32::from(option)) {
            Some(name) => wire.info(&[d, b" IAC ", name.as_bytes()]),
            None => wire.info_fmt(format_args!("{direction} IAC {option}")),
        }
        return;
    }
    let fmt = match cmd {
        WILL => "WILL",
        WONT => "WONT",
        DO => "DO",
        DONT => "DONT",
        _ => {
            wire.info_fmt(format_args!("{direction} {cmd} {option}"));
            return;
        }
    };
    let name = match telopt(u32::from(option)) {
        Some(name) => Some(name),
        None if option == TELOPT_EXOPL => Some("EXOPL"),
        None => None,
    };
    match name {
        Some(name) => wire.info(&[d, b" ", fmt.as_bytes(), b" ", name.as_bytes()]),
        None => wire.info_fmt(format_args!("{direction} {fmt} {option}")),
    }
}

/// Say a suboption, each piece a line as C's verbose trace says it
/// (`printsub`): `length` of `p`, which for one `direction` ends in its
/// IAC SE.
fn print_sub(wire: &mut dyn Wire, direction: Option<u8>, p: &[u8], mut length: usize) {
    let name = |x: u32| telopt(x).or_else(|| telcmd(x));
    if let Some(direction) = direction {
        let way: &[u8] = if direction == b'<' { b"RCVD" } else { b"SENT" };
        wire.info(&[way, b" IAC SB "]);
        if length >= 3 {
            let i = u32::from(p[length - 2]);
            let j = u32::from(p[length - 1]);
            if i != u32::from(IAC) || j != u32::from(SE) {
                wire.info(&[b"(terminated by "]);
                match name(i) {
                    Some(n) => wire.info(&[n.as_bytes(), b" "]),
                    None => wire.info_fmt(format_args!("{i} ")),
                }
                match name(j) {
                    Some(n) => wire.info(&[n.as_bytes()]),
                    None => wire.info_fmt(format_args!("{j}")),
                }
                wire.info(&[b", not IAC SE) "]);
            }
        }
        if length >= 2 {
            length -= 2;
        } else {
            return;
        }
    }
    if length <= 1 {
        wire.info(&[b"(Empty suboption?)"]);
        return;
    }
    match telopt(u32::from(p[0])) {
        Some(n)
            if matches!(
                p[0],
                TELOPT_TTYPE | TELOPT_XDISPLOC | TELOPT_NEW_ENVIRON | TELOPT_NAWS
            ) =>
        {
            wire.info(&[n.as_bytes()]);
        }
        Some(n) => wire.info(&[n.as_bytes(), b" (unsupported)"]),
        None => wire.info_fmt(format_args!("{} (unknown)", p[0])),
    }
    if p[0] == TELOPT_NAWS {
        if length > 4 {
            let w = u16::from_be_bytes([p[1], p[2]]);
            let h = u16::from_be_bytes([p[3], p[4]]);
            wire.info_fmt(format_args!("Width: {w} ; Height: {h}"));
        }
        return;
    }
    match p[1] {
        TELQUAL_IS => wire.info(&[b" IS"]),
        TELQUAL_SEND => wire.info(&[b" SEND"]),
        TELQUAL_INFO => wire.info(&[b" INFO/REPLY"]),
        TELQUAL_NAME => wire.info(&[b" NAME"]),
        _ => {}
    }
    match p[0] {
        TELOPT_TTYPE | TELOPT_XDISPLOC => {
            let text = p.get(2..length).unwrap_or_default();
            // C prints it as a string: to its first zero byte.
            let text = &text[..text.iter().position(|&b| b == 0).unwrap_or(text.len())];
            wire.info(&[b" \"", text, b"\""]);
        }
        TELOPT_NEW_ENVIRON => {
            if p[1] == TELQUAL_IS {
                wire.info(&[b" "]);
                for &b in p.get(3..length).unwrap_or_default() {
                    match b {
                        NEW_ENV_VAR => wire.info(&[b", "]),
                        NEW_ENV_VALUE => wire.info(&[b" = "]),
                        _ => wire.info(&[&[b]]),
                    }
                }
            }
        }
        _ => {
            for &b in p.get(2..length).unwrap_or_default() {
                wire.info_fmt(format_args!(" {b:02x}"));
            }
        }
    }
}

/// A TELNET transfer.
#[derive(Debug)]
pub(crate) struct Request {
    pub(super) base: super::base::RequestBase,
    /// The exchange's state, once DO has made it.
    telnet: Option<Box<Telnet>>,
    /// What was sent that the connection has not taken yet.
    unsent: Vec<u8>,
    /// When C's poll began, as DO started or the last round ended: the
    /// next round runs as the server's bytes come, or 100 ms after it.
    poll_since: Option<Instant>,
    /// Where the exchange is C's Windows loop, since when the socket has
    /// been quiet: when its wait started, which each of the socket's
    /// events and each reading of the input starts again.
    quiet_since: Option<Instant>,
}

impl Request {
    /// A transfer of `url`: its peer and the credentials its URL and the
    /// application give.
    pub(crate) fn new<H: Host>(
        url: &Url,
        before: Before<'_>,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Request, ErrorKind> {
        let peer = peer_of(url, b"telnet", cx)?;
        let takes = Takes::of(Some(peer.scheme()));
        // The application's login goes to a redirect's other host only
        // as HTTP's does (`Curl_auth_allowed_to_host`).
        let gate = match before.first {
            None => CredentialGate::FIRST,
            Some(first) => {
                let other_hosts = cx.easy().options().http.unrestricted_auth;
                CredentialGate::new(first, &peer, other_hosts)
            }
        };
        let credentials = super::request_credentials(cx, gate.trusted(), url, takes)?;
        let credentials = super::with_netrc(credentials, peer.name(), takes, cx)?;
        Ok(Request {
            base: super::base::RequestBase {
                peer,
                pipeline: Pipeline::new(Reach::Network),
                credentials,
                gate,
            },
            telnet: None,
            unsent: Vec::new(),
            poll_since: None,
            quiet_since: None,
        })
    }

    /// TELNET exchanges nothing once its DO is done.
    pub(crate) fn step(&mut self) -> ProtoStep {
        ProtoStep::Done
    }

    /// When the next pass runs whatever the socket says.
    pub(crate) fn due(&self) -> Option<Instant> {
        let since = if WINSOCK {
            self.quiet_since
        } else {
            self.poll_since
        };
        since.map(|at| at.after(INTERVAL))
    }

    /// Read the application's options and set up the exchange
    /// (`init_telnet`, `check_telnet_options`).
    fn start<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        // A list the application's source gives is read again now, as C
        // walks it as DO starts.
        if let Some(small) = cx.easy_mut().options_mut().small.made_mut() {
            small.telnet.refill().map_err(|_| ErrorKind::OutOfMemory)?;
        }
        let user = self.base.credentials.as_ref().map(Credentials::user);
        let options = cx.easy().options().small.telnet.iter();
        // The refusal's reason is made while the options are borrowed,
        // and given once they are not.
        let read = Settings::read(user, options).map_err(|(refused, option)| {
            let option = option.unwrap_or_default();
            let why = match refused {
                Refused::Unknown { said: true } => {
                    Some(trace::reason_with(&[b"Unknown telnet option ", option]))
                }
                Refused::Syntax => Some(trace::reason_with(&[
                    b"Syntax error in telnet option: ",
                    option,
                ])),
                _ => None,
            };
            (refused, why)
        });
        let settings = match read {
            Ok(settings) => settings,
            Err((refused, why)) => {
                return Err(match (refused, why) {
                    (Refused::OutOfMemory, _) => ErrorKind::OutOfMemory,
                    (Refused::NonAsciiUser, _) => {
                        trace::debug_info(cx, format_args!("set a non ASCII username in telnet"));
                        ErrorKind::BadFunctionArgument
                    }
                    (Refused::Unknown { .. }, None) => ErrorKind::UnknownOption,
                    (Refused::Unknown { .. }, Some(why)) => {
                        trace::fail_for(cx, ErrorKind::UnknownOption, why)
                    }
                    (Refused::Syntax, why) => {
                        let why = why.expect("a syntax error has its reason");
                        trace::fail_for(cx, ErrorKind::SetoptOptionSyntax, why)
                    }
                });
            }
        };
        let telnet =
            curl_alloc::try_box(Telnet::new(settings)).map_err(|_| ErrorKind::OutOfMemory)?;
        self.telnet = Some(telnet);
        Ok(())
    }

    /// One round of C's loop: what the server sent read and answered,
    /// then what the input handler gives sent, then the time and the
    /// progress taken stock of. Whether the exchange is over.
    fn pass<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        let now = cx.now();
        let Some(over) = self.exchange(cx, lease, now)? else {
            // C's poll still waits.
            return Ok(false);
        };
        if let TimeLeft::Expired(_) = cx.time_left() {
            return Err(trace::fail(
                cx,
                ErrorKind::OperationTimedout,
                format_args!("Time-out"),
            ));
        }
        if !WINSOCK {
            progress::update(cx, false)?;
        }
        Ok(over)
    }

    /// The round's reading and sending: whether the exchange is over, or
    /// none while no round is due.
    fn exchange<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        now: Instant,
    ) -> Result<Option<bool>, ErrorKind> {
        let telnet = self.telnet.as_mut().expect("DO set the exchange up");
        // C's poll begins as DO starts.
        let poll_since = *self.poll_since.get_or_insert(now);
        let mut live = Live {
            cx,
            lease,
            pipeline: &mut self.base.pipeline,
            unsent: &mut self.unsent,
        };
        // C sends all it has before it reads again.
        live.flush()?;
        if !live.unsent.is_empty() {
            return Ok(Some(false));
        }
        let mut buf = [0u8; BUFFER];
        let got = xfer_recv(live.cx, live.lease, &mut buf)?;
        if !WINSOCK {
            // A round: the server's bytes, or its close, or the poll's
            // 100 ms gone by without them. C polls the socket alone, the
            // input being a read function.
            if matches!(got, Got::Again) && now.since(poll_since) < INTERVAL {
                return Ok(None);
            }
            self.poll_since = Some(now);
            trace::debug_info(live.cx, format_args!("telnet_do, poll 1 fds"));
        }
        match got {
            // The server closed the connection: the exchange is over.
            Got::Eof => return Ok(Some(true)),
            Got::Again => {}
            Got::Data(n) => {
                // Counted as read, and again as delivered, as C counts it;
                // its Windows loop counts it delivered only.
                if !WINSOCK {
                    live.cx.report_mut().sizes_mut().download += n as u64;
                }
                telnet.receive(&mut live, &buf[..n])?;
                telnet.negotiate_once(&mut live);
                if WINSOCK {
                    // An event of the socket's: its wait starts again,
                    // and the input waits for the next quiet.
                    self.quiet_since = Some(now);
                    return Ok(Some(false));
                }
            }
        }
        let Some(handler) = live.cx.easy().options().small.input.clone() else {
            return Ok(Some(false));
        };
        if WINSOCK {
            // The first pass, from DO, waits as C's loop begins waiting.
            let quiet = *self.quiet_since.get_or_insert(now);
            if now.since(quiet) < INTERVAL {
                return Ok(Some(false));
            }
            self.quiet_since = Some(now);
            // Read until the input has nothing, as C does; while the
            // connection takes no more, where C's send blocks, it waits.
            while live.unsent.is_empty() {
                match handler.read(&mut TransferCx::new(live.cx), &mut buf) {
                    Read::Data(n) if n.get() > buf.len() => return Err(ErrorKind::ReadError),
                    Read::Data(n) => send_data(&mut live, &buf[..n.get()])?,
                    Read::Eof | Read::Pause => break,
                    Read::Abort | Read::Fail => return Err(ErrorKind::ReadError),
                }
            }
            return Ok(Some(false));
        }
        match handler.read(&mut TransferCx::new(live.cx), &mut buf) {
            Read::Data(n) if n.get() > buf.len() => Err(ErrorKind::ReadError),
            Read::Data(n) => {
                send_data(&mut live, &buf[..n.get()])?;
                live.cx.report_mut().sizes_mut().upload += n.get() as u64;
                Ok(Some(false))
            }
            Read::Eof | Read::Pause => Ok(Some(false)),
            // The exchange ends, well, as C's does.
            Read::Abort => Ok(Some(true)),
            Read::Fail => Err(ErrorKind::ReadError),
        }
    }
}

/// The exchange's world: the connection, the body's way to the
/// application, and what is still to send.
struct Live<'a, 'c, H: Host> {
    cx: &'a mut StepCx<'c, H>,
    lease: &'a mut ConnLease,
    pipeline: &'a mut Pipeline,
    unsent: &'a mut Vec<u8>,
}

impl<H: Host> Live<'_, '_, H> {
    /// Send what the connection takes of what is unsent.
    fn flush(&mut self) -> Result<(), ErrorKind> {
        if self.unsent.is_empty() {
            return Ok(());
        }
        match xfer_send(self.cx, self.lease, self.unsent) {
            Ok(n) => {
                self.unsent.drain(..n);
                Ok(())
            }
            Err(e) => {
                self.unsent.clear();
                Err(e)
            }
        }
    }
}

impl<H: Host> Wire for Live<'_, '_, H> {
    fn send(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        self.unsent
            .try_extend_from_slice(bytes)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        self.flush()
    }

    fn info(&mut self, parts: &[&[u8]]) {
        trace::info_with(self.cx, parts);
    }

    fn info_fmt(&mut self, args: fmt::Arguments<'_>) {
        trace::info(self.cx, args);
    }

    fn fail(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind {
        trace::fail(self.cx, kind, why)
    }

    fn body(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        self.pipeline.body(self.cx, bytes)
    }
}

impl super::Phases for Request {
    /// TELNET has no connect of its own.
    fn connect<H: Host>(
        &mut self,
        _: &mut StepCx<'_, H>,
        _: &mut ConnLease,
    ) -> Result<Connect, ErrorKind> {
        Ok(Connect::Done)
    }

    /// Set the exchange up in DO, then run it in DOING, a round of C's
    /// loop a pass (`telnet_do`).
    fn make<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        asked: DoPhase,
    ) -> Result<DoStep, ErrorKind> {
        if asked == DoPhase::Do {
            self.start(cx)?;
        }
        Ok(if self.pass(cx, lease)? {
            DoStep::Did
        } else {
            DoStep::Doing
        })
    }

    /// While the exchange goes on, the server's bytes, or room to send
    /// what is unsent.
    fn waits(&self, phase: Waiting, _: Option<&crate::conn::line::LineConn>) -> Events {
        match phase {
            Waiting::Doing if !self.unsent.is_empty() => Events::OUT,
            Waiting::Doing => Events::IN,
            _ => phase.c_default(),
        }
    }
}

#[cfg(test)]
mod tests;
