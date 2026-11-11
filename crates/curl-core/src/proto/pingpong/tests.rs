//! The reader and the writer, against what `lib/pingpong.c` does.

use std::time::Duration;

use proptest::prelude::*;

use super::ftp::Ftp;
use super::imap::{self, Continuations, Imap, ImapReply, Tag, Untagged};
use super::pop3::{Pop3, Pop3Reply};
use super::smtp::{Smtp, SmtpReply};
use super::*;
use crate::untrusted;

fn at(ms: u64) -> Instant {
    Instant::EPOCH.after(Duration::from_millis(ms))
}

/// What a reader gave out, owned.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Got<R> {
    Line(Vec<u8>),
    Reply(Vec<u8>, R),
    Failed(ReadError),
}

/// Reads `pieces`, one push each when the reader needs more, until it
/// needs more with none left or fails.
fn read<E: Ends>(ends: &E, pieces: &[&[u8]]) -> (Pingpong, Vec<Got<E::Reply>>) {
    let mut pp = Pingpong::new(Instant::EPOCH);
    let mut got = Vec::new();
    let mut pieces = pieces.iter().filter(|p| !p.is_empty());
    loop {
        match pp.next(ends) {
            Ok(Event::NeedMore) => match pieces.next() {
                Some(p) => {
                    if let Err(e) = pp.push(p) {
                        got.push(Got::Failed(e));
                        break;
                    }
                }
                None => break,
            },
            Ok(Event::Line(l)) => got.push(Got::Line(l.to_vec())),
            Ok(Event::Reply { line, reply, .. }) => got.push(Got::Reply(line.to_vec(), reply)),
            Err(e) => {
                got.push(Got::Failed(e));
                break;
            }
        }
    }
    (pp, got)
}

/// `input` in reads of at most `READ_SIZE`.
fn reads(input: &[u8]) -> Vec<&[u8]> {
    input.chunks(READ_SIZE).collect()
}

fn line<R>(l: &[u8]) -> Got<R> {
    Got::Line(l.to_vec())
}

fn reply<R>(l: &[u8], r: R) -> Got<R> {
    Got::Reply(l.to_vec(), r)
}

fn code(c: u32) -> ReplyCode {
    ReplyCode(c)
}

#[test]
fn a_multi_line_reply_ends_at_the_first_code_and_space() {
    // ftp.c:580: any line of three digits and a space ends it, even one
    // inside the block with another code than its first line's.
    let (_, got) = read(
        &Ftp,
        &[b"230-Welcome\r\n230-more\r\n 230 indented\r\n150 x\r\n230 done\r\n"],
    );
    assert_eq!(
        got,
        [
            line(b"230-Welcome\r\n"),
            line(b"230-more\r\n"),
            line(b" 230 indented\r\n"),
            reply(b"150 x\r\n", code(150)),
            reply(b"230 done\r\n", code(230)),
        ]
    );
}

#[test]
fn a_line_ends_at_its_lf_and_a_cr_is_part_of_it() {
    // pingpong.c:276: only the LF ends a line.
    let (_, got) = read(&Ftp, &[b"220 a\n220-b\r221 c\r\r\n221 d\r\n"]);
    assert_eq!(
        got,
        [
            reply(b"220 a\n", code(220)),
            line(b"220-b\r221 c\r\r\n"),
            reply(b"221 d\r\n", code(221)),
        ]
    );
}

#[test]
fn the_reply_line_and_what_follows_it_stay_until_the_next_call() {
    let mut pp = Pingpong::new(Instant::EPOCH);
    assert_eq!(pp.next(&Ftp), Ok(Event::NeedMore));
    assert_eq!(pp.reply_line(), None);
    pp.push(b"220-hi\r\n220 ok\r\n331 more").unwrap();
    assert_eq!(pp.next(&Ftp), Ok(Event::Line(&b"220-hi\r\n"[..])));
    assert_eq!(pp.reply_line(), None);
    assert_eq!(pp.after_reply(), None);
    let Ok(Event::Reply { line, reply, size }) = pp.next(&Ftp) else {
        panic!("no reply");
    };
    assert_eq!(
        (line, reply, size.get()),
        (&b"220 ok\r\n"[..], code(220), 24)
    );
    assert_eq!(pp.reply_line(), Some(&b"220 ok\r\n"[..]));
    assert_eq!(pp.after_reply(), Some(&b"331 more"[..]));
    assert_eq!(pp.held(), b"220 ok\r\n331 more");
    assert!(pp.more_data());
    // A partial line follows: the reader looks before it reads.
    assert_eq!(pp.next(&Ftp), Ok(Event::NeedMore));
    assert_eq!(pp.after_reply(), None);
    assert_eq!(pp.held(), b"331 more");
    pp.push(b"\r\n").unwrap();
    let Ok(Event::Reply { size, .. }) = pp.next(&Ftp) else {
        panic!("no reply");
    };
    assert_eq!(size.get(), 2);
    assert_eq!(pp.after_reply(), Some(&b""[..]));
    assert!(!pp.more_data());
}

#[test]
fn a_reply_found_in_held_bytes_has_read_nothing() {
    // `nread_resp` counts what was read for the reply; ftp.c:720 tells a
    // reply served from the cache by its size of zero.
    let mut pp = Pingpong::new(Instant::EPOCH);
    pp.push(b"220 a\r\n221 b\r\n").unwrap();
    let Ok(Event::Reply { size, .. }) = pp.next(&Ftp) else {
        panic!("no reply");
    };
    assert_eq!(size.get(), 14);
    let Ok(Event::Reply { size, .. }) = pp.next(&Ftp) else {
        panic!("no reply");
    };
    assert_eq!(size.get(), 0);
}

#[test]
fn bytes_after_a_starttls_reply_are_told() {
    // Test 980: the server pipelines after its answer to STARTTLS, which
    // smtp.c:1177 refuses.
    let mail = Smtp {
        continuations: false,
    };
    let mut pp = Pingpong::new(Instant::EPOCH);
    pp.push(b"454 currently unavailable\r\n235 Authenticated\r\n")
        .unwrap();
    let Ok(Event::Reply { reply, .. }) = pp.next(&mail) else {
        panic!("no reply");
    };
    assert_eq!(reply, SmtpReply::Final(code(454)));
    assert_eq!(pp.after_reply(), Some(&b"235 Authenticated\r\n"[..]));
    // Without them, nothing follows.
    let mut pp = Pingpong::new(Instant::EPOCH);
    pp.push(b"220 go ahead\r\n").unwrap();
    assert!(matches!(pp.next(&mail), Ok(Event::Reply { .. })));
    assert_eq!(pp.after_reply(), Some(&b""[..]));
}

#[test]
fn a_nul_in_a_whole_line_fails_for_good() {
    // pingpong.c:282, before the line is traced.
    let (mut pp, got) = read(&Ftp, &[b"220-a\r\n220 b\0c\r\n"]);
    assert_eq!(got, [line(b"220-a\r\n"), Got::Failed(ReadError::Nul)]);
    assert_eq!(ReadError::Nul.kind(), ErrorKind::WeirdServerReply);
    assert_eq!(pp.next(&Ftp), Err(ReadError::Nul));
    assert_eq!(pp.push(b"x"), Err(ReadError::Nul));
    assert_eq!(pp.held(), b"");
    assert!(!pp.more_data());
    // In a line not yet whole, it is not looked for yet.
    let (_, got) = read(&Ftp, &[b"220 \0"]);
    assert_eq!(got, []);
    // Nor after a reply, until the reader gets to it.
    let mut pp = Pingpong::new(Instant::EPOCH);
    pp.push(b"220 ok\r\n\0\0").unwrap();
    assert!(matches!(pp.next(&Ftp), Ok(Event::Reply { .. })));
    assert_eq!(pp.after_reply(), Some(&b"\0\0"[..]));
}

#[test]
fn what_is_held_is_capped_short_of_64_kib() {
    // dynbuf.c:82: the bytes held, those read and a zero byte, at most
    // DYN_PINGPPONG_CMD.
    let long = [b'x'; BUFFER_MAX];
    let mut pp = Pingpong::new(Instant::EPOCH);
    for piece in long[..BUFFER_MAX - 1].chunks(READ_SIZE) {
        pp.push(piece).unwrap();
        assert_eq!(pp.next(&Ftp), Ok(Event::NeedMore));
    }
    assert_eq!(pp.push(b"\n"), Err(ReadError::TooLarge));
    assert_eq!(ReadError::TooLarge.kind(), ErrorKind::TooLarge);
    assert_eq!(pp.next(&Ftp), Err(ReadError::TooLarge));
    // A line of 65535 bytes, its LF included, is read.
    let mut line = long[..BUFFER_MAX - 2].to_vec();
    line[..4].copy_from_slice(b"220 ");
    line.push(b'\n');
    let (_, got) = read(&Ftp, &reads(&line));
    assert_eq!(got, [reply(&line, code(220))]);
    // A run of CRs is one line.
    let crs = [b'\r'; BUFFER_MAX];
    let (_, got) = read(&Ftp, &reads(&crs));
    assert_eq!(got, [Got::Failed(ReadError::TooLarge)]);
}

#[test]
fn the_cap_counts_what_is_held_once_the_reply_line_goes() {
    // pingpong.c:252: the final line is dropped before the next read is
    // added, so it does not count against the cap.
    let mut first = vec![b'x'; 40_000];
    first[..4].copy_from_slice(b"220 ");
    first.push(b'\n');
    let mut pp = Pingpong::new(Instant::EPOCH);
    for piece in reads(&first) {
        assert_eq!(pp.next(&Ftp), Ok(Event::NeedMore));
        pp.push(piece).unwrap();
    }
    assert!(matches!(pp.next(&Ftp), Ok(Event::Reply { .. })));
    pp.push(&[b'y'; 30_000]).unwrap();
    assert_eq!(pp.held().len(), 30_000);
}

#[test]
fn only_a_line_is_capped_not_a_reply() {
    // Lines that end no reply go as they are read: a reply of many lines
    // is not limited.
    let mut input = Vec::new();
    for _ in 0..2000 {
        input.extend_from_slice(b"230-a line of the banner, long enough\r\n");
    }
    input.extend_from_slice(b"230 done\r\n");
    assert!(input.len() > BUFFER_MAX);
    let (_, got) = read(&Ftp, &reads(&input));
    assert_eq!(got.len(), 2001);
    assert_eq!(got.last(), Some(&reply(b"230 done\r\n", code(230))));
}

#[test]
fn an_empty_read_is_the_server_closing() {
    // pingpong.c:262.
    let mut pp = Pingpong::new(Instant::EPOCH);
    assert_eq!(pp.push(b""), Err(ReadError::Closed));
    assert_eq!(ReadError::Closed.kind(), ErrorKind::RecvError);
    assert_eq!(pp.next(&Ftp), Err(ReadError::Closed));
}

#[test]
#[should_panic(expected = "a read pushed while held lines wait to be read")]
fn a_read_waits_for_the_lines_held() {
    // pingpong.c:258: C reads only when nothing follows the last reply.
    let mut pp = Pingpong::new(Instant::EPOCH);
    pp.push(b"220 a\r\n221 b\r\n").unwrap();
    let _ = pp.next(&Ftp);
    let _ = pp.push(b"x");
}

#[test]
#[should_panic(expected = "a read pushed while held lines wait to be read")]
fn a_read_waits_for_the_line_given_out() {
    let mut pp = Pingpong::new(Instant::EPOCH);
    pp.push(b"220-a\r\n").unwrap();
    let _ = pp.next(&Ftp);
    let _ = pp.push(b"x");
}

#[test]
fn smtp_reads_each_line_of_an_ehlo_answer() {
    let ehlo = Smtp {
        continuations: true,
    };
    let (_, got) = read(
        &ehlo,
        &[b"250-example.com\r\n250-AUTH PLAIN\r\n250 SIZE 100\r\n"],
    );
    assert_eq!(
        got,
        [
            reply(b"250-example.com\r\n", SmtpReply::Continuation),
            reply(b"250-AUTH PLAIN\r\n", SmtpReply::Continuation),
            reply(b"250 SIZE 100\r\n", SmtpReply::Final(code(250))),
        ]
    );
    let (_, got) = read(
        &Smtp {
            continuations: false,
        },
        &[b"250-example.com\r\n250 SIZE 100\r\n"],
    );
    assert_eq!(
        got,
        [
            line(b"250-example.com\r\n"),
            reply(b"250 SIZE 100\r\n", SmtpReply::Final(code(250))),
        ]
    );
}

#[test]
fn pop3_reads_each_capability_and_hands_a_body_on() {
    let (_, got) = read(
        &Pop3 { capa: true },
        &[b"+OK capabilities\r\nTOP\r\nSASL PLAIN\r\n.\r\n"],
    );
    assert_eq!(
        got,
        [
            reply(b"+OK capabilities\r\n", Pop3Reply::More),
            reply(b"TOP\r\n", Pop3Reply::More),
            reply(b"SASL PLAIN\r\n", Pop3Reply::More),
            reply(b".\r\n", Pop3Reply::Ok),
        ]
    );
    // pop3.c:1248: what follows `+OK` to RETR is body, all of it the
    // transfer's, a zero byte and all.
    let mut pp = Pingpong::new(Instant::EPOCH);
    let user = Pop3 { capa: false };
    pp.push(b"+OK 5 octets\r\nhel\0o\r\n.\r\n").unwrap();
    assert!(matches!(pp.next(&user), Ok(Event::Reply { .. })));
    assert_eq!(pp.after_reply(), Some(&b"hel\0o\r\n.\r\n"[..]));
    pp.consume_after_reply(10);
    assert_eq!(pp.held(), b"");
    assert_eq!(pp.reply_line(), None);
    assert_eq!(pp.next(&user), Ok(Event::NeedMore));
}

#[test]
fn an_imap_literal_is_taken_from_what_follows_its_line() {
    // imap.c:1417: the literal's bytes are the transfer's, not lines; the
    // answer goes on after them.
    let fetch = Imap {
        tag: Tag::command(crate::conn::ConnNumber::for_tests(0), 4),
        untagged: Untagged::Named(b"FETCH"),
        continuations: Continuations::Unexpected,
    };
    let mut pp = Pingpong::new(Instant::EPOCH);
    pp.push(b"* 1 FETCH (BODY[TEXT] {7}\r\nA\n\0B\r\n)\r\nA004 OK done\r\n")
        .unwrap();
    let Ok(Event::Reply { line, reply, .. }) = pp.next(&fetch) else {
        panic!("no reply");
    };
    assert_eq!(reply, ImapReply::Untagged);
    let size = imap::literal(line).unwrap();
    assert_eq!(size, 7);
    let after = pp.after_reply().unwrap();
    assert_eq!(&after[..7], b"A\n\0B\r\n)");
    pp.consume_after_reply(6);
    assert_eq!(pp.next(&fetch), Ok(Event::Line(&b")\r\n"[..])));
    assert!(matches!(
        pp.next(&fetch),
        Ok(Event::Reply {
            reply: ImapReply::Ok,
            ..
        })
    ));
    // Taking all that followed leaves the reader to read.
    let mut pp = Pingpong::new(Instant::EPOCH);
    pp.push(b"* 1 FETCH (BODY[TEXT] {9}\r\nhalf").unwrap();
    assert!(matches!(pp.next(&fetch), Ok(Event::Reply { .. })));
    pp.consume_after_reply(4);
    pp.push(b" more").unwrap();
    assert_eq!(pp.held(), b" more");
}

#[test]
#[should_panic(expected = "more taken after the reply than was read")]
fn no_more_is_taken_after_a_reply_than_was_read() {
    let mut pp = Pingpong::new(Instant::EPOCH);
    pp.push(b"220 a\r\nxy").unwrap();
    let _ = pp.next(&Ftp);
    pp.consume_after_reply(3);
}

/// The answers the properties split, one per protocol.
const FTP_ANSWERS: &[&[u8]] = &[
    b"220-Welcome\r\n220-to\r\n220 the server\r\n",
    b"230-a\r\n150 b\n230 c\r\n331 more\r\n",
    b"220 \r\r\n221-\n 221 x\r\n221 \n",
    b"220-a\0\r\n",
    b"227 Entering Passive Mode (127,0,0,1,4,1)\r\n226 done\r\n",
];
const SMTP_ANSWERS: &[&[u8]] = &[
    b"220 hi\r\n250-example.com\r\n250-SIZE\r\n250 AUTH PLAIN\r\n",
    b"250\r\n250-\n2500\n001 x\r\n354 go\r\n",
];
const POP3_ANSWERS: &[&[u8]] = &[
    b"+OK hi <1.2@x>\r\n-ERR no\r\n+ challenge\r\n",
    b"+OK\r\nTOP\r\nUSER\r\n.\r\n-ERR\r\n",
];
const IMAP_ANSWERS: &[&[u8]] = &[
    b"* OK ready\r\n* CAPABILITY IMAP4 STARTTLS\r\nA001 OK done\r\n",
    b"* 1 FETCH (BODY {3}\r\nabc)\r\n+ go\r\n+\r\nA001 NO\r\n",
];

fn smtp() -> Smtp {
    Smtp {
        continuations: true,
    }
}

fn imap_caps() -> Imap<'static> {
    Imap {
        tag: Tag::command(crate::conn::ConnNumber::for_tests(0), 1),
        untagged: Untagged::Named(b"CAPABILITY"),
        continuations: Continuations::Expected,
    }
}

/// Reading `input` in pieces gives out what reading it in one does.
fn same_split<E: Ends>(ends: &E, input: &[u8], pieces: &[&[u8]])
where
    E::Reply: std::fmt::Debug + PartialEq,
{
    let (_, whole) = read(ends, &[input]);
    let (_, split) = read(ends, pieces);
    assert_eq!(split, whole, "{pieces:?}");
}

#[test]
fn a_reply_split_at_any_byte_reads_the_same() {
    fn every_cut<E: Ends>(ends: &E, answers: &[&[u8]])
    where
        E::Reply: std::fmt::Debug + PartialEq,
    {
        for answer in answers {
            for cut in 1..answer.len() {
                same_split(ends, answer, &[&answer[..cut], &answer[cut..]]);
            }
            let bytes: Vec<&[u8]> = answer.chunks(1).collect();
            same_split(ends, answer, &bytes);
        }
    }
    every_cut(&Ftp, FTP_ANSWERS);
    every_cut(&smtp(), SMTP_ANSWERS);
    every_cut(&Pop3 { capa: false }, POP3_ANSWERS);
    every_cut(&Pop3 { capa: true }, POP3_ANSWERS);
    every_cut(&imap_caps(), IMAP_ANSWERS);
}

const WORDS: &[&[u8]] = &[
    b"\r\n",
    b"\n",
    b"\r",
    b"\0",
    b" ",
    b"-",
    b"220",
    b"220 ",
    b"220-",
    b"250",
    b"+OK",
    b"-ERR",
    b"+ ",
    b"+",
    b".",
    b"* ",
    b"A001 ",
    b"OK",
    b"CAPABILITY",
    b"{3}",
    b"\"",
];

proptest! {
    #![proptest_config(untrusted::config(256))]

    #[test]
    fn a_reply_split_anywhere_reads_the_same(
        input in untrusted::input(WORDS, FTP_ANSWERS, 40),
        cuts in untrusted::cuts(),
    ) {
        let pieces = untrusted::pieces(&input, &cuts);
        same_split(&Ftp, &input, &pieces);
        same_split(&smtp(), &input, &pieces);
        same_split(&Pop3 { capa: true }, &input, &pieces);
        same_split(&imap_caps(), &input, &pieces);
    }

    #[test]
    fn no_answer_panics(
        input in untrusted::input(WORDS, IMAP_ANSWERS, 40),
        cuts in untrusted::cuts(),
        take in any::<proptest::sample::Index>(),
    ) {
        let pieces = untrusted::pieces(&input, &cuts);
        let ends = imap_caps();
        let mut pp = Pingpong::new(Instant::EPOCH);
        let mut pieces = pieces.iter();
        for _ in 0..1000 {
            match pp.next(&ends) {
                Ok(Event::NeedMore) => match pieces.next() {
                    Some(p) => { let _ = pp.push(p); }
                    None => break,
                },
                Ok(Event::Line(_)) => {}
                Ok(Event::Reply { line, .. }) => {
                    let _ = imap::literal(line);
                    let n = pp.after_reply().map_or(0, |a| take.index(a.len() + 1));
                    pp.consume_after_reply(n);
                }
                // Read on after a failure: the same failure, no panic.
                Err(e) => {
                    prop_assert_eq!(pp.next(&ends), Err(e));
                    prop_assert_eq!(pp.push(b"x"), Err(e));
                    break;
                }
            }
        }
        let _ = pp.more_data();
    }
}

#[test]
fn a_command_ends_with_crlf_after_its_prefix() {
    let mut pp = Pingpong::new(Instant::EPOCH);
    let cmd = pp.command(None, &[b"USER ", b"anonymous"]).unwrap();
    assert_eq!(cmd.bytes(), b"USER anonymous\r\n");
    assert_eq!(cmd.wrote(16, at(0)), b"USER anonymous\r\n");
    let tag = Tag::command(crate::conn::ConnNumber::for_tests(1), 7);
    let cmd = pp.command(Some(tag.bytes()), &[b"CAPABILITY"]).unwrap();
    assert_eq!(cmd.bytes(), b"B007 CAPABILITY\r\n");
    let _ = cmd.wrote(17, at(0));
    // IMAP's empty command, for an empty SASL response (imap.c:2012).
    let cmd = pp.command(None, &[]).unwrap();
    assert_eq!(cmd.bytes(), b"\r\n");
}

#[test]
fn a_command_is_capped_short_of_64_kib() {
    // dynbuf.c:82: the command, its CRLF and a zero byte.
    let long = [b'x'; BUFFER_MAX];
    let mut pp = Pingpong::new(Instant::EPOCH);
    let cmd = pp.command(None, &[&long[..BUFFER_MAX - 3]]).unwrap();
    assert_eq!(cmd.bytes().len(), BUFFER_MAX - 1);
    drop(cmd);
    assert_eq!(
        pp.command(None, &[&long[..BUFFER_MAX - 2]]).err(),
        Some(CommandError::TooLarge)
    );
    assert_eq!(CommandError::TooLarge.kind(), ErrorKind::TooLarge);
    let tag = Tag::GREETING;
    assert_eq!(
        pp.command(Some(tag.bytes()), &[&long[..BUFFER_MAX - 4]])
            .err(),
        Some(CommandError::TooLarge)
    );
    assert!(
        pp.command(Some(tag.bytes()), &[&long[..BUFFER_MAX - 5]])
            .is_ok()
    );
    // Counted over every part.
    assert_eq!(
        pp.command(None, &[&long[..BUFFER_MAX / 2], &long[..BUFFER_MAX / 2]])
            .err(),
        Some(CommandError::TooLarge)
    );
}

#[test]
fn only_the_first_send_is_traced() {
    // pingpong.c:177: Curl_debug traces what the first send wrote, none
    // if it would have blocked; a flush traces nothing.
    let mut pp = Pingpong::new(Instant::EPOCH);
    let cmd = pp.command(None, &[b"PASV"]).unwrap();
    assert_eq!(cmd.wrote(2, at(5)), b"PA");
    assert!(pp.needs_flush());
    assert_eq!(pp.wants(), Wants::Send);
    assert_eq!(pp.unsent(), b"SV\r\n");
    pp.flushed(1, at(6));
    assert_eq!(pp.unsent(), b"V\r\n");
    pp.flushed(3, at(7));
    assert!(!pp.needs_flush());
    assert_eq!(pp.wants(), Wants::Recv);
    assert_eq!(pp.unsent(), b"");
    let cmd = pp.command(None, &[b"QUIT"]).unwrap();
    assert_eq!(cmd.wrote(0, at(8)), b"");
    assert_eq!(pp.unsent(), b"QUIT\r\n");
}

#[test]
fn a_send_that_failed_leaves_nothing_to_flush() {
    let mut pp = Pingpong::new(Instant::EPOCH);
    drop(pp.command(None, &[b"NOOP"]).unwrap());
    assert!(!pp.needs_flush());
    assert!(pp.command(None, &[b"QUIT"]).is_ok());
}

#[test]
#[should_panic(expected = "a command built while the one before is partly sent")]
fn a_command_waits_for_the_one_partly_sent() {
    let mut pp = Pingpong::new(Instant::EPOCH);
    let _ = pp.command(None, &[b"NOOP"]).unwrap().wrote(1, at(0));
    let _ = pp.command(None, &[b"QUIT"]);
}

#[test]
fn no_more_data_while_a_command_is_partly_sent() {
    let mut pp = Pingpong::new(Instant::EPOCH);
    pp.push(b"220 a\r\n221 b\r\n").unwrap();
    assert!(pp.more_data());
    assert!(matches!(pp.next(&Ftp), Ok(Event::Reply { .. })));
    assert!(pp.more_data());
    let _ = pp.command(None, &[b"NOOP"]).unwrap().wrote(1, at(0));
    assert!(!pp.more_data());
}

#[test]
fn the_time_to_answer_runs_from_the_last_command_sent_whole() {
    let none = TimeLeft::Unlimited;
    let mut pp = Pingpong::new(at(1000));
    let left = |pp: &Pingpong, now: u64, limit: Option<u64>, transfer: TimeLeft| {
        pp.time_left(at(now), limit.and_then(TimeLimit::from_millis), transfer)
    };
    let ms = |ms: u64| ResponseTime::Left(Duration::from_millis(ms));
    // PINGPONG_TIMEOUT_MS from Curl_pp_init's time.
    assert_eq!(left(&pp, 1000, None, none), ms(60_000));
    assert_eq!(left(&pp, 60_999, None, none), ms(1));
    // pingpong.c:66: none left at all is late.
    assert_eq!(left(&pp, 61_000, None, none), ResponseTime::Out);
    assert_eq!(left(&pp, 90_000, None, none), ResponseTime::Out);
    assert_eq!(left(&pp, 1000, Some(500), none), ms(500));
    assert_eq!(left(&pp, 1500, Some(500), none), ResponseTime::Out);
    // The transfer's own time, if it ends sooner.
    let t = |ms: u64| TimeLeft::Remaining(Duration::from_millis(ms));
    assert_eq!(left(&pp, 1000, Some(500), t(200)), ms(200));
    assert_eq!(left(&pp, 1000, Some(500), t(900)), ms(500));
    assert_eq!(
        left(&pp, 1000, None, TimeLeft::Expired(Duration::from_millis(1))),
        ResponseTime::Out
    );
    // Whole milliseconds since the anchor.
    let micro = Instant::EPOCH.after(Duration::from_micros(1_000_999));
    assert_eq!(
        pp.time_left(micro, TimeLimit::from_millis(500), none),
        ms(500)
    );
    // A command partly sent leaves the anchor where it was.
    let cmd = pp.command(None, &[b"NOOP"]).unwrap();
    let _ = cmd.wrote(2, at(5000));
    assert_eq!(left(&pp, 5000, Some(10_000), none), ms(6000));
    pp.flushed(1, at(6000));
    assert_eq!(left(&pp, 6000, Some(10_000), none), ms(5000));
    // Sent whole, it starts again.
    pp.flushed(3, at(7000));
    assert_eq!(left(&pp, 7000, Some(10_000), none), ms(10_000));
    let _ = pp.command(None, &[b"QUIT"]).unwrap().wrote(6, at(9000));
    assert_eq!(left(&pp, 9000, Some(10_000), none), ms(10_000));
    // What arrives does not move it.
    pp.push(b"221 bye\r\n").unwrap();
    let _ = pp.next(&Ftp);
    assert_eq!(left(&pp, 9500, Some(10_000), none), ms(9500));
}

#[test]
fn held_bytes_not_looked_through_are_told_apart_from_a_partial_line() {
    // C's `overflow`, by which Curl_pp_statemach runs the step at once
    // (pingpong.c:86), against `Curl_pp_moredata`.
    let mut pp = Pingpong::new(Instant::EPOCH);
    assert!(!pp.unscanned());
    pp.push(b"* 1 FETCH (BODY {2}\r\nab)\r\nA001 OK\r\n")
        .unwrap();
    assert!(pp.unscanned());
    let fetch = Imap {
        tag: Tag::command(crate::conn::ConnNumber::for_tests(0), 1),
        untagged: Untagged::Named(b"FETCH"),
        continuations: Continuations::Unexpected,
    };
    assert!(matches!(pp.next(&fetch), Ok(Event::Reply { .. })));
    assert!(pp.unscanned());
    // imap.c:1447: what is left after the literal is still to be read.
    pp.consume_after_reply(2);
    assert_eq!(pp.after_reply(), None);
    assert!(pp.unscanned());
    assert_eq!(pp.next(&fetch), Ok(Event::Line(&b")\r\n"[..])));
    assert!(pp.unscanned());
    assert!(matches!(pp.next(&fetch), Ok(Event::Reply { .. })));
    assert!(!pp.unscanned());
    // pingpong.c:337: a partial line looked through is not.
    pp.push(b"A002 O").unwrap();
    assert!(pp.unscanned());
    assert_eq!(pp.next(&fetch), Ok(Event::NeedMore));
    assert!(!pp.unscanned());
    assert!(pp.more_data());
    // Nor anything after a failure.
    assert_eq!(pp.push(b""), Err(ReadError::Closed));
    assert!(!pp.unscanned());
}

#[test]
fn ftp_restarts_the_time_to_answer() {
    // ftp.c:3751: the answer ending a transfer is waited for from now.
    let mut pp = Pingpong::new(at(0));
    pp.restart_response_timer(at(50_000));
    assert_eq!(
        pp.time_left(at(50_000), None, TimeLeft::Unlimited),
        ResponseTime::Left(RESPONSE_TIMEOUT)
    );
}

#[test]
fn a_nul_says_what_c_says() {
    assert_eq!(
        ReadError::Nul.reason(),
        Some("NUL byte in server response line")
    );
    assert_eq!(ReadError::TooLarge.reason(), None);
    assert_eq!(ReadError::Closed.reason(), None);
}

/// One call of C's `Curl_pp_readresp` over `socket`, which gives what is
/// asked of it until it is empty, then would block: up to `MAX_READS`
/// reads of `READ_SIZE` while each fills, none while lines are held, and
/// the first reply found.
fn readresp<E: Ends>(pp: &mut Pingpong, ends: &E, socket: &mut &[u8]) -> Option<E::Reply> {
    let mut reads = 0;
    let mut short = false;
    loop {
        match pp.next(ends).unwrap() {
            Event::Reply { reply, .. } => return Some(reply),
            Event::Line(_) => {}
            // `while(gotbytes == sizeof(buffer))`: a short read ends the
            // call once its lines are looked at.
            Event::NeedMore if short || reads == MAX_READS || socket.is_empty() => return None,
            Event::NeedMore => {
                let (read, rest) = socket.split_at(socket.len().min(READ_SIZE));
                *socket = rest;
                reads += 1;
                short = read.len() < READ_SIZE;
                pp.push(read).unwrap();
            }
        }
    }
}

#[test]
fn what_follows_a_reply_is_what_its_read_held() {
    // A driver reading as C does holds after a reply the rest of the read
    // it ended in, and leaves the rest unread: the bytes STARTTLS is
    // refused over are those.
    let mut answer = b"220 ok\r\n".to_vec();
    answer.extend_from_slice(&[b'x'; 2000]);
    let mut socket = &answer[..];
    let mut pp = Pingpong::new(Instant::EPOCH);
    assert_eq!(readresp(&mut pp, &Ftp, &mut socket), Some(code(220)));
    assert_eq!(pp.after_reply().map(<[u8]>::len), Some(READ_SIZE - 8));
    assert_eq!(socket.len(), 2008 - READ_SIZE);
    // A banner of many lines is read MAX_READS reads at a time.
    let mut banner = Vec::new();
    while banner.len() < 30 * READ_SIZE {
        banner.extend_from_slice(b"220-banner\r\n");
    }
    banner.extend_from_slice(b"220 end\r\n");
    let mut socket = &banner[..];
    let mut pp = Pingpong::new(Instant::EPOCH);
    assert_eq!(readresp(&mut pp, &Ftp, &mut socket), None);
    assert_eq!(socket.len(), banner.len() - MAX_READS as usize * READ_SIZE);
    // Three calls of 10 reads find nothing; the fourth's one short read
    // ends the reply.
    let mut empty = 1;
    while readresp(&mut pp, &Ftp, &mut socket).is_none() {
        empty += 1;
    }
    assert_eq!(empty, 3);
}

/// An answer is awaited from the start and from each command built, until
/// a pass of reads ends (`pending_resp`).
#[test]
fn an_answer_is_pending_from_each_command_to_the_end_of_a_read() {
    let mut pp = Pingpong::new(Instant::EPOCH);
    assert!(pp.pending_resp());
    pp.reads_ended();
    assert!(!pp.pending_resp());
    let unsent = pp.command(None, &[b"NOOP"]).unwrap();
    let _wrote = unsent.wrote(6, Instant::EPOCH);
    assert!(pp.pending_resp());
    pp.reads_ended();
    assert!(!pp.pending_resp());
}

/// A go-ahead to upgrade is taken only where nothing follows it.
#[test]
fn an_upgrade_begins_only_with_nothing_after_its_go_ahead() {
    let mut pp = Pingpong::new(Instant::EPOCH);
    pp.push(b"220 go\r\n").unwrap();
    assert!(matches!(pp.next(&Ftp), Ok(Event::Reply { .. })));
    assert!(pp.begin_upgrade().is_ok());
    let mut pp = Pingpong::new(Instant::EPOCH);
    pp.push(b"220 go\r\nx").unwrap();
    assert!(matches!(pp.next(&Ftp), Ok(Event::Reply { .. })));
    assert_eq!(pp.begin_upgrade(), Err(ErrorKind::WeirdServerReply));
}

/// Only a connection over TLS, or one where TLS is only tried and not
/// offered, logs in without an upgrade; a refused upgrade goes on in the
/// clear only where TLS is tried.
#[test]
fn a_login_without_tls_is_had_only_where_tls_is_not_required() {
    use UseSsl::{All, Control, None as No, Try};
    let gate = |use_ssl, over_tls, offered| match tls_gate(use_ssl, over_tls, offered) {
        TlsGate::Upgrade => 'u',
        TlsGate::Proceed(_) => 'p',
        TlsGate::Refuse => 'r',
    };
    for offered in [false, true] {
        for use_ssl in [No, Try, Control, All] {
            assert_eq!(gate(use_ssl, true, offered), 'p', "{use_ssl:?}");
        }
        assert_eq!(gate(No, false, offered), 'p');
    }
    for use_ssl in [Try, Control, All] {
        assert_eq!(gate(use_ssl, false, true), 'u', "{use_ssl:?}");
    }
    assert_eq!(gate(Try, false, false), 'p');
    assert_eq!(gate(Control, false, false), 'r');
    assert_eq!(gate(All, false, false), 'r');
    assert!(upgrade_refused(Try).is_some());
    for use_ssl in [No, Control, All] {
        assert!(upgrade_refused(use_ssl).is_none(), "{use_ssl:?}");
    }
}
