use std::sync::Mutex;

use super::*;
use crate::conn::io::Conversation;
use crate::handler::{Handler, ReadHandler};
use crate::options::Options;
use crate::proto::raw::wire::{Ran, against};

/// What the exchange did: what it sent, said, failed with and
/// delivered.
#[derive(Default)]
struct Rec {
    sent: Vec<u8>,
    said: Vec<String>,
    failed: Vec<(ErrorKind, String)>,
    body: Vec<u8>,
    /// Sends fail with this.
    refuse: Option<ErrorKind>,
}

impl Wire for Rec {
    fn send(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        if let Some(e) = self.refuse {
            return Err(e);
        }
        self.sent.extend_from_slice(bytes);
        Ok(())
    }

    fn info(&mut self, parts: &[&[u8]]) {
        let line: Vec<u8> = parts.concat();
        self.said.push(String::from_utf8_lossy(&line).into_owned());
    }

    fn info_fmt(&mut self, args: fmt::Arguments<'_>) {
        self.said.push(args.to_string());
    }

    fn fail(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind {
        self.failed.push((kind, why.to_string()));
        kind
    }

    fn body(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        self.body.extend_from_slice(bytes);
        Ok(())
    }
}

fn settings(user: Option<&[u8]>, options: &[&[u8]]) -> Settings {
    Settings::read(user, options.iter().copied()).unwrap()
}

fn fresh(options: &[&[u8]]) -> Telnet {
    Telnet::new(settings(None, options))
}

/// Each option C knows is taken by its name, in any case.
#[test]
fn known_options_are_read() {
    let s = settings(
        Some(b"me"),
        &[
            b"TTYPE=vt100",
            b"xdisploc=host:0",
            b"NEW_ENV=A,b",
            b"WS=80x24",
            b"BINARY=0",
        ],
    );
    assert_eq!(s.ttype.as_deref(), Some(&b"vt100"[..]));
    assert_eq!(s.xdisploc.as_deref(), Some(&b"host:0"[..]));
    assert_eq!(s.vars, [&b"USER,me"[..], b"A,b"]);
    assert_eq!((s.wsx, s.wsy), (80, 24));
    assert!(s.us.contains(&TELOPT_NAWS) && s.us.contains(&TELOPT_TTYPE));
    assert_eq!(s.us_off, [TELOPT_BINARY]);
    // BINARY=1, or a value that is no number, leaves binary on.
    for keep in [&b"BINARY=1"[..], b"BINARY=x"] {
        assert!(settings(None, &[keep]).us_off.is_empty(), "{keep:?}");
    }
}

/// An option without `=`, or a window size that is not `WxH` within 16
/// bits, is a syntax error; one C does not know is unknown, said only if
/// its name's length is none C knows.
#[test]
fn bad_options_are_refused() {
    for bad in [&b"TTYPE"[..], b"WS=80", b"WS=80x", b"WS=65536x1", b"WS=x24"] {
        let refused = Settings::read(None, [bad]).unwrap_err();
        assert_eq!(refused, (Refused::Syntax, Some(bad)), "{bad:?}");
    }
    let refused = Settings::read(None, [&b"TTYPF=a"[..]]).unwrap_err();
    assert_eq!(refused.0, Refused::Unknown { said: false });
    let refused = Settings::read(None, [&b"COLOR=red"[..]]).unwrap_err();
    assert_eq!(refused.0, Refused::Unknown { said: false });
    let refused = Settings::read(None, [&b"NOSUCH=1"[..]]).unwrap_err();
    assert_eq!(refused.0, Refused::Unknown { said: false });
    let refused = Settings::read(None, [&b"FAVOURITE=1"[..]]).unwrap_err();
    assert_eq!(refused.0, Refused::Unknown { said: true });
    assert_eq!(
        Settings::read(Some(b"m\xe9"), []).unwrap_err().0,
        Refused::NonAsciiUser
    );
    // An argument past ASCII is passed over, not refused.
    let s = settings(None, &[b"TTYPE=\xe9", b"NOSUCH=\xe9"]);
    assert!(s.ttype.is_none());
}

/// The user goes as a variable, cut short as C's buffer cuts it.
#[test]
fn the_user_is_a_variable() {
    let long = vec![b'u'; 300];
    let s = settings(Some(&long), &[]);
    assert_eq!(s.vars[0].len(), 255);
    assert!(s.us.contains(&TELOPT_NEW_ENVIRON));
    let s = settings(Some(b""), &[]);
    assert_eq!(s.vars, [&b"USER,"[..]]);
}

/// Data passes through: an IAC doubled is one, a NUL after a CR is
/// dropped, and a command is taken out.
#[test]
fn data_passes_through() {
    let mut tn = fresh(&[]);
    let mut w = Rec::default();
    tn.receive(&mut w, b"ab\xff\xffc\r\0d\r\ne\xff\xf1f")
        .unwrap();
    assert_eq!(w.body, b"ab\xffc\rd\r\nef");
    assert_eq!(w.said, ["RCVD IAC NOP"]);
    assert!(w.sent.is_empty());
    // A CR then an IAC: the IAC is data, as C has it.
    let mut w = Rec::default();
    tn.receive(&mut w, b"\r\xffx").unwrap();
    assert_eq!(w.body, b"\r\xffx");
    // A command split across reads is read whole.
    let mut w = Rec::default();
    tn.receive(&mut w, b"a\xff").unwrap();
    tn.receive(&mut w, b"\xf1b").unwrap();
    assert_eq!(w.body, b"ab");
}

/// The server's offers are answered as RFC 1143 has them, with C's
/// preferences, and C's own requests follow once.
#[test]
fn negotiation_answers_the_server() {
    let mut tn = fresh(&[]);
    let mut w = Rec::default();
    // WILL ECHO is welcome, DO TTYPE is not (no type given), DO NAWS is
    // with its size.
    tn.receive(
        &mut w,
        &[
            IAC,
            WILL,
            TELOPT_ECHO,
            IAC,
            DO,
            TELOPT_TTYPE,
            IAC,
            DO,
            TELOPT_NAWS,
        ],
    )
    .unwrap();
    let mut want = vec![
        IAC,
        DO,
        TELOPT_ECHO,
        IAC,
        WONT,
        TELOPT_TTYPE,
        IAC,
        WILL,
        TELOPT_NAWS,
    ];
    want.extend_from_slice(&[IAC, SB, TELOPT_NAWS, 0, 0, 0, 0, IAC, SE]);
    assert_eq!(w.sent, want);
    assert_eq!(
        w.said,
        [
            "RCVD WILL ECHO",
            "SENT DO ECHO",
            "RCVD DO TERM TYPE",
            "SENT WONT TERM TYPE",
            "RCVD DO NAWS",
            "SENT WILL NAWS",
            "SENT IAC SB ",
            "NAWS",
            "Width: 0 ; Height: 0",
        ]
    );
    let mut w = Rec::default();
    tn.negotiate_once(&mut w);
    // BINARY and SGA both ways; ECHO and NAWS are settled already.
    assert_eq!(
        w.sent,
        [
            IAC,
            WILL,
            TELOPT_BINARY,
            IAC,
            DO,
            TELOPT_BINARY,
            IAC,
            WILL,
            TELOPT_SGA,
            IAC,
            DO,
            TELOPT_SGA
        ]
    );
    let mut w = Rec::default();
    tn.negotiate_once(&mut w);
    assert!(w.sent.is_empty());
    // The answers to C's requests settle them, saying nothing back.
    tn.receive(&mut w, &[IAC, DO, TELOPT_BINARY, IAC, WONT, TELOPT_SGA])
        .unwrap();
    assert!(w.sent.is_empty());
    assert_eq!(tn.us[usize::from(TELOPT_BINARY)], YES);
    assert_eq!(tn.him[usize::from(TELOPT_SGA)], NO);
    // Then a DONT turns it off, said.
    tn.receive(&mut w, &[IAC, DONT, TELOPT_BINARY]).unwrap();
    assert_eq!(w.sent, [IAC, WONT, TELOPT_BINARY]);
}

/// Without negotiation from the server, C negotiates nothing: it may be
/// no TELNET server.
#[test]
fn nothing_is_negotiated_unasked() {
    let mut tn = fresh(&[]);
    let mut w = Rec::default();
    tn.receive(&mut w, b"+OK hello\r\n").unwrap();
    tn.negotiate_once(&mut w);
    assert!(w.sent.is_empty());
}

/// The window size is sent each byte of it an IAC doubled.
#[test]
fn the_window_size_is_escaped() {
    let mut tn = fresh(&[b"WS=255x511"]);
    let mut w = Rec::default();
    tn.receive(&mut w, &[IAC, DO, TELOPT_NAWS]).unwrap();
    assert_eq!(
        w.sent,
        [
            IAC,
            WILL,
            TELOPT_NAWS,
            IAC,
            SB,
            TELOPT_NAWS,
            0,
            0xff,
            0xff,
            1,
            0xff,
            0xff,
            IAC,
            SE
        ]
    );
    assert!(w.said.contains(&"Width: 255 ; Height: 511".to_owned()));
}

/// The terminal type and the variables are sent when asked for.
#[test]
fn suboptions_are_answered() {
    let mut tn = fresh(&[b"TTYPE=vt100", b"NEW_ENV=A,b", b"NEW_ENV=C"]);
    let mut w = Rec::default();
    let mut ask = vec![
        IAC,
        DO,
        TELOPT_TTYPE,
        IAC,
        SB,
        TELOPT_TTYPE,
        TELQUAL_SEND,
        IAC,
        SE,
    ];
    ask.extend_from_slice(&[IAC, SB, TELOPT_NEW_ENVIRON, TELQUAL_SEND, IAC, SE]);
    tn.receive(&mut w, &ask).unwrap();
    let mut want = vec![IAC, WILL, TELOPT_TTYPE];
    want.extend_from_slice(&[IAC, SB, TELOPT_TTYPE, TELQUAL_IS]);
    want.extend_from_slice(b"vt100");
    want.extend_from_slice(&[IAC, SE, IAC, SB, TELOPT_NEW_ENVIRON, TELQUAL_IS]);
    want.extend_from_slice(b"\0A\x01b\0C");
    want.extend_from_slice(&[IAC, SE]);
    assert_eq!(w.sent, want);
    let said = w.said.join("|");
    assert!(
        said.contains("RCVD IAC SB |TERM TYPE| SEND| \"\"|SENT IAC SB |TERM TYPE| IS| \"vt100\""),
        "{said}"
    );
    assert!(
        // C's trace starts past the first variable's mark.
        said.contains("SENT IAC SB |NEW-ENVIRON| IS| |A| = |b|, |C"),
        "{said}"
    );
}

/// A type asked for and none given, or one with an IAC in it, fails;
/// one past 1000 bytes fails, said.
#[test]
fn a_bad_type_fails() {
    let ask = [IAC, SB, TELOPT_TTYPE, TELQUAL_SEND, IAC, SE];
    let mut w = Rec::default();
    assert_eq!(
        fresh(&[]).receive(&mut w, &ask),
        Err(ErrorKind::BadFunctionArgument)
    );
    let long = [&b"TTYPE="[..], &[b'v'; 1001]].concat();
    let mut w = Rec::default();
    assert_eq!(
        fresh(&[&long]).receive(&mut w, &ask),
        Err(ErrorKind::SendError)
    );
    assert_eq!(
        w.failed,
        [(ErrorKind::SendError, "Too long telnet TTYPE".to_owned())]
    );
    let ask = [IAC, SB, TELOPT_XDISPLOC, TELQUAL_SEND, IAC, SE];
    let long = [&b"XDISPLOC="[..], &[b'v'; 1001]].concat();
    let mut w = Rec::default();
    assert_eq!(
        fresh(&[&long]).receive(&mut w, &ask),
        Err(ErrorKind::SendError)
    );
    assert_eq!(w.failed[0].1, "Too long telnet XDISPLOC");
}

/// A suboption's answer that cannot be sent fails, said.
#[test]
fn a_failed_suboption_send_fails() {
    let ask = [IAC, SB, TELOPT_TTYPE, TELQUAL_SEND, IAC, SE];
    let mut w = Rec {
        refuse: Some(ErrorKind::SendError),
        ..Rec::default()
    };
    assert_eq!(
        fresh(&[b"TTYPE=x"]).receive(&mut w, &ask),
        Err(ErrorKind::SendError)
    );
    assert_eq!(
        w.failed,
        [(
            ErrorKind::SendError,
            "Sending data failed: Failed sending data to the peer".to_owned()
        )]
    );
}

/// Within a suboption only IAC IAC and IAC SE belong after an IAC.
#[test]
fn a_bad_suboption_fails() {
    let mut w = Rec::default();
    let got = fresh(&[]).receive(&mut w, &[IAC, SB, TELOPT_TTYPE, IAC, b'x']);
    assert_eq!(got, Err(ErrorKind::RecvError));
    assert_eq!(
        w.failed,
        [(ErrorKind::RecvError, "telnet: suboption error".to_owned())]
    );
}

/// A suboption longer than C's buffer keeps what fits, and is read to
/// its end; an empty one is passed over.
#[test]
fn a_long_suboption_is_cut_short() {
    let mut tn = fresh(&[]);
    let mut w = Rec::default();
    let mut long = vec![IAC, SB, 77];
    long.extend_from_slice(&[7; 2000]);
    long.extend_from_slice(&[IAC, SE]);
    long.extend_from_slice(b"after");
    tn.receive(&mut w, &long).unwrap();
    assert_eq!(w.body, b"after");
    assert_eq!(tn.subend, SUBBUFSIZE - 2);
    let mut w = Rec::default();
    tn.receive(&mut w, &[IAC, SB, IAC, SE, b'z']).unwrap();
    assert_eq!(w.body, b"z");
    assert!(w.said.is_empty());
}

/// Data sent has each IAC in it doubled.
#[test]
fn data_sent_is_escaped() {
    let mut w = Rec::default();
    send_data(&mut w, b"a\xffb").unwrap();
    send_data(&mut w, b"plain").unwrap();
    assert_eq!(w.sent, b"a\xff\xffbplain");
}

/// Options and commands C has no name for are said by number.
#[test]
fn unnamed_options_are_said_by_number() {
    let mut w = Rec::default();
    print_option(&mut w, "RCVD", WILL, 200);
    print_option(&mut w, "RCVD", DO, TELOPT_EXOPL);
    print_option(&mut w, "RCVD", IAC, 7);
    print_option(&mut w, "SENT", 9, 1);
    assert_eq!(
        w.said,
        ["RCVD WILL 200", "RCVD DO EXOPL", "RCVD IAC 7", "SENT 9 1"]
    );
    let mut w = Rec::default();
    print_sub(&mut w, Some(b'<'), &[TELOPT_ECHO, 5, 6, 1, 2], 5);
    print_sub(&mut w, Some(b'>'), &[TELOPT_ECHO, IAC, SE], 3);
    assert_eq!(
        w.said,
        [
            "RCVD IAC SB ",
            "(terminated by ",
            "ECHO ",
            "RCP",
            ", not IAC SE) ",
            "ECHO (unsupported)",
            " 06",
            "SENT IAC SB ",
            "(Empty suboption?)"
        ]
    );
    let mut w = Rec::default();
    print_sub(&mut w, None, &[TELOPT_ECHO, 9, 0xab], 3);
    print_sub(&mut w, None, &[99, 9], 2);
    assert_eq!(w.said, ["ECHO (unsupported)", " ab", "99 (unknown)"]);
}

/// What the read handler gives each pass.
struct Input(Mutex<Vec<Vec<u8>>>);

impl ReadHandler for Input {
    fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> Read {
        let mut left = self.0.lock().unwrap();
        if left.is_empty() {
            return Read::Eof;
        }
        let next = left.remove(0);
        if next == b"ABORT" {
            return Read::Abort;
        }
        buf[..next.len()].copy_from_slice(&next);
        Read::Data(std::num::NonZeroUsize::new(next.len()).unwrap())
    }
}

/// A transfer whose input gives `input`, against `talk`.
fn telnet(talk: Conversation, input: &[&[u8]], set: impl FnOnce(&mut Options)) -> (Vec<u8>, Ran) {
    let input = Input(Mutex::new(input.iter().map(|b| b.to_vec()).collect()));
    let input = Handler::read(input).unwrap();
    against(talk, "telnet://127.0.0.1:PORT", |o| {
        o.small.make_mut().unwrap().input = Some(input);
        set(o);
    })
}

/// The server's bytes are the body, what the input gives is sent, and
/// the transfer ends as the server closes.
#[test]
fn a_session_runs_to_the_close() {
    let talk = Conversation::replies(&[b"login: ", b"bye\r\n"], true).greeting();
    let (said, ran) = telnet(talk, &[b"me\xff\r\n"], |_| {});
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert_eq!(said, b"me\xff\xff\r\n");
    assert_eq!(ran.body, b"login: bye\r\n");
    assert!(!ran.stored_headers);
    // What was read counts twice, as read and as delivered; what was
    // sent as the input gave it.
    assert_eq!(ran.counted, (24, 5));
}

/// An input that aborts ends the exchange, well.
#[test]
fn an_aborted_input_ends_it() {
    let talk = Conversation::replies(&[b"hi"], false).greeting();
    let (_, ran) = telnet(talk, &[b"ABORT"], |_| {});
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    assert_eq!(ran.body, b"hi");
}

/// A server that never closes runs the transfer out of time, with C's
/// TELNET reason.
#[test]
fn a_session_times_out_as_c_s_does() {
    let talk = Conversation::replies(&[b"hi"], false).greeting();
    let (_, ran) = telnet(talk, &[], |o| {
        o.limits.total = crate::time::TimeLimit::from_millis(1000);
    });
    assert_eq!(ran.result, Some(Err(ErrorKind::OperationTimedout)));
    assert!(ran.text.contains("Time-out\n"), "{}", ran.text);
    assert!(!ran.text.contains("Operation timed out"), "{}", ran.text);
}

/// Options it does not know fail the transfer as it starts, said as C
/// says it.
#[test]
fn unknown_options_fail_the_transfer() {
    let talk = Conversation::replies(&[b"hi"], true).greeting();
    let (said, ran) = telnet(talk, &[], |o| {
        let small = o.small.make_mut().unwrap();
        small.telnet.set([&b"FAVOURITE=1"[..]]).unwrap();
    });
    assert_eq!(ran.result, Some(Err(ErrorKind::UnknownOption)));
    assert!(
        ran.text.contains("Unknown telnet option FAVOURITE=1\n"),
        "{}",
        ran.text
    );
    assert!(said.is_empty());
    let talk = Conversation::replies(&[b"hi"], true).greeting();
    let (_, ran) = telnet(talk, &[], |o| {
        let small = o.small.make_mut().unwrap();
        small.telnet.set([&b"WS=1"[..]]).unwrap();
    });
    assert_eq!(ran.result, Some(Err(ErrorKind::SetoptOptionSyntax)));
    assert!(
        ran.text.contains("Syntax error in telnet option: WS=1\n"),
        "{}",
        ran.text
    );
}

/// The server's negotiation is answered over the connection, and what
/// the connection does not take at once goes in a later pass.
#[test]
fn negotiation_goes_over_the_wire() {
    let one = std::num::NonZeroUsize::new(1).unwrap();
    let talk = Conversation::replies(&[&[IAC, DO, TELOPT_NAWS]], true)
        .greeting()
        .taking(one)
        .stalling_sends_after(2, 3);
    let (said, ran) = telnet(talk, &[], |o| {
        o.small
            .make_mut()
            .unwrap()
            .telnet
            .set([&b"WS=1x2"[..]])
            .unwrap();
    });
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    let mut want = vec![
        IAC,
        WILL,
        TELOPT_NAWS,
        IAC,
        SB,
        TELOPT_NAWS,
        0,
        1,
        0,
        2,
        IAC,
        SE,
    ];
    // Then C's own requests.
    want.extend_from_slice(&[IAC, WILL, TELOPT_BINARY, IAC, DO, TELOPT_BINARY]);
    want.extend_from_slice(&[IAC, WILL, TELOPT_SGA, IAC, DO, TELOPT_SGA]);
    assert_eq!(said, want);
    assert!(ran.text.contains("RCVD DO NAWS\n"), "{}", ran.text);
}

/// A suboption that fills C's buffer ends within it.
#[test]
fn the_sub_buffer_stays_in_bounds() {
    let mut tn = fresh(&[b"TTYPE=t", b"NEW_ENV=X"]);
    let mut w = Rec::default();
    // IAC SE right after SB, then a full buffer ending IAC IAC IAC SE.
    let mut b = vec![IAC, SB, IAC, SE, IAC, SB];
    b.extend_from_slice(&[TELOPT_TTYPE; 511]);
    b.extend_from_slice(&[IAC, IAC, IAC, SE]);
    let _ = tn.receive(&mut w, &b);
    assert!(tn.subend <= SUBBUFSIZE);
}

static SAMPLES: &[&[u8]] = &[
    b"\xff\xfd\x18\xff\xfa\x18\x01\xff\xf0",
    b"\xff\xfa\x27\x01\xff\xf0\xff\xfb\x01\xff\xfd\x1f",
    b"text\r\0more\r\n\xff\xff\xff\xf1",
    b"\xff\xfa\x1f\x00\x50\x00\x18\xff\xf0\xff\xfe\x00\xff\xfc\x03",
];

static WORDS: &[&[u8]] = &[
    b"\xff", b"\xfa", b"\xf0", b"\xfb", b"\xfc", b"\xfd", b"\xfe", b"\r", b"\0", b"\x18", b"\x27",
    b"\x1f", b"\x01", b"a",
];

/// Any bytes the server sends a fresh exchange, in a sample mutated or
/// a soup of TELNET's bytes, end in an error or a body.
fn survive(bytes: &[u8], split: usize) {
    let mut tn = fresh(&[b"TTYPE=vt100", b"XDISPLOC=d:0", b"NEW_ENV=A,b", b"WS=80x24"]);
    let mut w = Rec::default();
    let at = split.min(bytes.len());
    if tn.receive(&mut w, &bytes[..at]).is_ok() {
        tn.negotiate_once(&mut w);
        let _ = tn.receive(&mut w, &bytes[at..]);
    }
}

proptest::proptest! {
    #![proptest_config(crate::untrusted::config(256))]

    #[test]
    fn mutated_samples_never_panic(
        bytes in crate::untrusted::mutated(SAMPLES),
        split in 0usize..64,
    ) {
        survive(&bytes, split);
    }

    #[test]
    fn soups_never_panic(bytes in crate::untrusted::soup(WORDS, 2048), split in 0usize..2048) {
        survive(&bytes, split);
    }

    /// Any options are read or refused.
    #[test]
    fn any_options_are_read_or_refused(
        options in proptest::collection::vec(proptest::collection::vec(0u8.., 0..24), 0..4),
        user in proptest::option::of(proptest::collection::vec(0u8.., 0..300)),
    ) {
        let _ = Settings::read(user.as_deref(), options.iter().map(Vec::as_slice));
    }
}
