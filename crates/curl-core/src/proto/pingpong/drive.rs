//! The back and forth driven over a connection (`lib/pingpong.c`'s I/O):
//! a command sent as the connection takes it, the answer read a read at a
//! time and handed line by line to the application, and whether the
//! protocol's step has anything to do now.

use super::{BUFFER_MAX, Ends, MAX_READS, Pingpong, READ_SIZE, ReplySize, ResponseTime, Wants};
use crate::conn::RecvFailed;
use crate::conn::io::{Events, Recv, Sent};
use crate::conn::layer::Lower as _;
use crate::conn::line::Goodbye;
use crate::conn::mux::Carrier;
use crate::deliver::Pipeline;
use crate::error::ErrorKind;
use crate::handler::DebugKind;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::time::{Instant, TimeLimit};
use crate::trace;

/// Build a command, `prefix` and a space before it when given, and send
/// what the connection takes of it now (`Curl_pp_vsendf`): what went is
/// traced as sent, even nothing; the rest waits for [`flush`].
pub(crate) fn send<H: Host>(
    cx: &mut StepCx<'_, H>,
    pp: &mut Pingpong,
    carrier: &mut Carrier<'_>,
    prefix: Option<&[u8]>,
    parts: &[&[u8]],
) -> Result<(), ErrorKind> {
    let unsent = pp.command(prefix, parts).map_err(|e| e.kind())?;
    let n = send_some(cx, carrier, unsent.bytes())?;
    let now = cx.now();
    let wrote = unsent.wrote(n, now);
    trace::bytes(cx, DebugKind::HeaderOut, wrote);
    Ok(())
}

/// Send what is left of a command partly sent, untraced
/// (`Curl_pp_flushsend`).
pub(crate) fn flush<H: Host>(
    cx: &mut StepCx<'_, H>,
    pp: &mut Pingpong,
    carrier: &mut Carrier<'_>,
) -> Result<(), ErrorKind> {
    if !pp.needs_flush() {
        return Ok(());
    }
    let n = send_some(cx, carrier, pp.unsent())?;
    let now = cx.now();
    pp.flushed(n, now);
    Ok(())
}

/// Send what the connection takes of `bytes` now: none if it would block
/// (`CURLE_AGAIN`). The socket says why it failed, as it does for a
/// request's send.
fn send_some<H: Host>(
    cx: &mut StepCx<'_, H>,
    carrier: &mut Carrier<'_>,
    bytes: &[u8],
) -> Result<usize, ErrorKind> {
    match carrier.send(cx, bytes) {
        Ok(Sent::Bytes(n)) => Ok(n.get()),
        Ok(Sent::WouldBlock) => Ok(0),
        Err(_) => Err(ErrorKind::SendError),
    }
}

/// What a pass of reads found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Read<R> {
    /// A reply ended, its line held (`Pingpong::reply_line`).
    Reply(R, ReplySize),
    /// None yet: the connection would block, or the pass read its most.
    Waiting,
}

/// Read the answer on, a read of [`READ_SIZE`] at a time, while nothing
/// whole is held and at most [`super::MAX_READS`] reads, until a line
/// ends a reply or a read comes short (`Curl_pp_readresp`). Each line goes
/// to the trace (`CURLINFO_HEADER_IN`) and to the header handler as it is
/// found, a reply's last among them, starting the response's time if the
/// request's body is `sent` (`CLIENTWRITE_INFO`); `counted` takes every
/// byte read (`req.headerbytecount`).
pub(crate) fn read<H: Host, E: Ends>(
    cx: &mut StepCx<'_, H>,
    pp: &mut Pingpong,
    carrier: &mut Carrier<'_>,
    ends: &E,
    pipeline: &mut Pipeline,
    counted: &mut u64,
    sent: bool,
) -> Result<Read<E::Reply>, ErrorKind> {
    // What is held is looked through first, without a read: it ends a
    // reply, or the step waits on the connection.
    if pp.unscanned() {
        if let Some(reply) = scan(cx, pp, ends, pipeline, sent)? {
            return Ok(reply);
        }
        pp.reads_ended();
        return Ok(Read::Waiting);
    }
    // Don't get stuck: the pass is this many reads, and no more.
    for _ in 0..super::MAX_READS {
        let Some(got) = recv(cx, pp, carrier)? else {
            pp.read_nothing();
            return Ok(Read::Waiting);
        };
        *counted += got as u64;
        if let Some(reply) = scan(cx, pp, ends, pipeline, sent)? {
            return Ok(reply);
        }
        if got != READ_SIZE {
            pp.reads_ended();
            return Ok(Read::Waiting);
        }
    }
    Ok(Read::Waiting)
}

/// The lines held looked through to the end of what came, each traced
/// and given to the header handler: the reply a line ends, if one does.
fn scan<H: Host, E: Ends>(
    cx: &mut StepCx<'_, H>,
    pp: &mut Pingpong,
    ends: &E,
    pipeline: &mut Pipeline,
    sent: bool,
) -> Result<Option<Read<E::Reply>>, ErrorKind> {
    loop {
        let event = pp.next(ends).map_err(|e| read_failed(cx, e))?;
        match event {
            super::Event::NeedMore => return Ok(None),
            super::Event::Line(line) => {
                trace::bytes(cx, DebugKind::HeaderIn, line);
                pipeline.info(cx, line, sent)?;
            }
            super::Event::Reply { line, reply, size } => {
                trace::bytes(cx, DebugKind::HeaderIn, line);
                pipeline.info(cx, line, sent)?;
                pp.reads_ended();
                return Ok(Some(Read::Reply(reply, size)));
            }
        }
    }
}

/// One read from the connection pushed into `pp`: how many bytes, or
/// none if it would block. What was received and not used goes first, no
/// more than a read takes.
fn recv<H: Host>(
    cx: &mut StepCx<'_, H>,
    pp: &mut Pingpong,
    carrier: &mut Carrier<'_>,
) -> Result<Option<usize>, ErrorKind> {
    let said = cx.easy().report().reasons();
    // Read in the multi's buffer, and pushed from there.
    let (got, pushed) = crate::conn::buf::lending(cx, carrier, |cx, carrier| {
        let got = carrier.recv(cx, READ_SIZE);
        let pushed = matches!(got, Ok(Recv::Data(_))).then(|| {
            let rx = carrier.rx_mut();
            let n = rx.filled().len().min(READ_SIZE);
            let pushed = pp.push(&rx.filled()[..n]);
            rx.consume(n);
            pushed.map(|()| n)
        });
        (got, pushed)
    })
    .map_err(|_| ErrorKind::OutOfMemory)?;
    match got {
        Ok(Recv::WouldBlock) => Ok(None),
        Ok(Recv::Eof) => {
            // Closed by the server under a command: not reused.
            carrier.mark_close();
            let e = pp
                .push(&[])
                .expect_err("an empty read is the server closing");
            Err(read_failed(cx, e))
        }
        Ok(Recv::Data(_)) => {
            let n = pushed
                .expect("what came was pushed")
                .map_err(|e| read_failed(cx, e))?;
            Ok(Some(n))
        }
        Err(RecvFailed::OutOfMemory) => Err(ErrorKind::OutOfMemory),
        // A layer that said why it failed, as TLS does, is not said for
        // again.
        Err(RecvFailed::Os(_)) if cx.easy().report().reasons() > said => Err(ErrorKind::RecvError),
        Err(RecvFailed::Os(e)) => {
            let why = curl_os::error::ErrorText::of(&e);
            Err(trace::fail_with(
                cx,
                ErrorKind::RecvError,
                &[b"Recv failure: ", why.as_bytes()],
            ))
        }
    }
}

/// Say a goodbye, `command` after `prefix` if one is given, as a
/// connection shuts down, and read on its answer as far as the connection
/// lets that now (`goodbye_answer`). A command that cannot be built or
/// sent ends it, as a failed `Curl_pp_sendf` ends C's `ftp_quit` and the
/// others' disconnects.
pub(crate) fn goodbye<E: Ends>(
    cx: &mut dyn crate::conn::layer::LayerCx,
    pp: &mut Pingpong,
    carrier: &mut Carrier<'_>,
    ends: &E,
    prefix: Option<&[u8]>,
    command: &[u8],
) -> Goodbye {
    let Ok(unsent) = pp.command(prefix, &[command]) else {
        return Goodbye::Done;
    };
    let n = match carrier.send(cx, unsent.bytes()) {
        Ok(Sent::Bytes(n)) => n.get(),
        Ok(Sent::WouldBlock) => 0,
        Err(_) => return Goodbye::Done,
    };
    let _sent = unsent.wrote(n, cx.now());
    goodbye_answer(cx, pp, carrier, ends)
}

/// Send the rest of a goodbye and read on its answer as a connection
/// shuts down, as far as it lets that now (C's blocking
/// `Curl_pp_statemach` in `ftp_quit` and the others' disconnects): done
/// once a whole reply is read, or the connection fails or closes, or
/// [`GOODBYE_READ_MAX`] bytes of it came with no end; awaited while it
/// would block, or after [`MAX_READS`] reads in one call, as C's
/// `maxloops` lets the others run. What is held is looked through before
/// anything is read, as C reads its `overflow` first. Untraced and given
/// to no application: the transfer is gone (C's internal handle reads
/// it).
pub(crate) fn goodbye_answer<E: Ends>(
    cx: &mut dyn crate::conn::layer::LayerCx,
    pp: &mut Pingpong,
    carrier: &mut Carrier<'_>,
    ends: &E,
) -> Goodbye {
    let mut moved = false;
    if pp.needs_flush() {
        match carrier.send(cx, pp.unsent()) {
            Ok(Sent::Bytes(n)) => {
                pp.flushed(n.get(), cx.now());
                moved = true;
            }
            Ok(Sent::WouldBlock) => {}
            Err(_) => return Goodbye::Done,
        }
        if pp.needs_flush() {
            return Goodbye::Awaited { moved };
        }
    }
    // The pass is this many reads, and no more, as C's `maxloops`.
    for _ in 0..MAX_READS {
        if let Some(done) = goodbye_scan(pp, ends) {
            return done;
        }
        // Read in the multi's buffer, if the work has one, and pushed
        // from there.
        let got = crate::conn::buf::lending(cx, carrier, |cx, carrier| {
            let got = carrier.recv(cx, READ_SIZE);
            let pushed = matches!(got, Ok(Recv::Data(_))).then(|| {
                let rx = carrier.rx_mut();
                let n = rx.filled().len().min(READ_SIZE);
                let pushed = pp.push(&rx.filled()[..n]);
                rx.consume(n);
                pushed
            });
            (got, pushed)
        });
        let Ok((got, pushed)) = got else {
            return Goodbye::Done;
        };
        match got {
            Ok(Recv::WouldBlock) => return Goodbye::Awaited { moved },
            Ok(Recv::Data(_)) => {
                if pushed.expect("what came was pushed").is_err() {
                    return Goodbye::Done;
                }
                moved = true;
            }
            Ok(Recv::Eof) | Err(_) => return Goodbye::Done,
        }
    }
    goodbye_scan(pp, ends).unwrap_or(Goodbye::Awaited { moved })
}

/// A goodbye's answer held looked through: done once a reply ends or the
/// answer fails, or once [`GOODBYE_READ_MAX`] bytes of it came with no
/// end; nothing while more is to be read.
fn goodbye_scan<E: Ends>(pp: &mut Pingpong, ends: &E) -> Option<Goodbye> {
    loop {
        match pp.next(ends) {
            Ok(super::Event::NeedMore) => break,
            Ok(super::Event::Line(_)) => {}
            Ok(super::Event::Reply { .. }) | Err(_) => return Some(Goodbye::Done),
        }
    }
    // A peer that sends on and on is let go unanswered, its rest
    // unread, as C lets it go after the first byte.
    (pp.read_for_reply() >= GOODBYE_READ_MAX).then_some(Goodbye::Done)
}

/// The most of a goodbye's answer read before the connection is let go
/// with the rest unread: as much as C's back and forth holds of one reply
/// (`DYN_PINGPPONG_CMD`, [`BUFFER_MAX`]). C bounds only the line it has
/// not seen the end of, and its goodbye stops at the answer's first byte;
/// a whole reply read here is bounded by this instead, so a server
/// sending lines without end neither grows what is held nor keeps the
/// connection.
pub(crate) const GOODBYE_READ_MAX: usize = BUFFER_MAX;

/// The reader's failure, said as C says it.
fn read_failed<H: Host>(cx: &mut StepCx<'_, H>, e: super::ReadError) -> ErrorKind {
    match e {
        // The server closed the connection: C says the socket's errno,
        // which a clean close leaves at 0.
        super::ReadError::Closed => trace::fail(
            cx,
            e.kind(),
            format_args!("response reading failed (errno: 0)"),
        ),
        _ => match e.reason() {
            Some(why) => trace::fail(cx, e.kind(), format_args!("{why}")),
            None => e.kind(),
        },
    }
}

/// Whether the protocol's step is to run now, and not wait on the
/// connection (`Curl_pp_statemach` without blocking): failed if the
/// server's time to answer, `limit` or a minute, is out already, else
/// the transfer's `SERVER_RESPONSE` timer armed for what is left of it
/// (its `Curl_expire`). It runs if bytes wait where a poll cannot see them, or are
/// held unread, or the socket is ready for what the back and forth waits
/// for, a poll that does not wait.
pub(crate) fn runs<H: Host>(
    cx: &mut StepCx<'_, H>,
    pp: &Pingpong,
    carrier: &mut Carrier<'_>,
    limit: Option<TimeLimit>,
) -> Result<bool, ErrorKind> {
    let left = cx.time_left();
    let now = cx.now();
    match pp.time_left(now, limit, left) {
        ResponseTime::Left(left) => cx.server_response_in(left),
        ResponseTime::Out => {
            return Err(trace::fail(
                cx,
                ErrorKind::OperationTimedout,
                format_args!("server response timeout"),
            ));
        }
    };
    if carrier.reborrow().data_pending() || pp.unscanned() {
        return Ok(true);
    }
    Ok(carrier.ready_now(waits(pp)))
}

/// Where C's blocking drive is in its round (`Curl_pp_statemach` with
/// `block`): polling since an instant, or about to start a round.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Blocking {
    polling: Option<Instant>,
}

/// What C's blocking drive does each time round, for a protocol's DONE
/// (`Curl_pp_statemach` with `block`, as `imap_block_statemach` loops on
/// it), without blocking. A round starts with the server's time to
/// answer, the transfer's own limit among it, failing once out; then
/// polls, at once if bytes are held, at most a second or what is left of
/// that time; then the progress is checked (`Curl_pgrsCheck`, `exchanged`
/// being its `req.done`), and the step runs if the poll found it ready.
/// The poll is the transfer's wait: called again before it ends, nothing
/// happens. No timer is armed for C to hear of; the instant given is when
/// the poll ends, for the transfer to look again then.
pub(crate) fn runs_done<H: Host>(
    cx: &mut StepCx<'_, H>,
    pp: &Pingpong,
    carrier: &mut Carrier<'_>,
    limit: Option<TimeLimit>,
    exchanged: bool,
    round: &mut Blocking,
) -> Result<(bool, Instant), ErrorKind> {
    let said = "server response timeout";
    runs_done_said(cx, pp, carrier, limit, exchanged, round, said, false)
}

/// `runs_done`, the server's time to answer running out said as `said`,
/// and running at once if `read_first`: FTP's own blocking read says it its
/// way and does not wait while its buffer holds anything, the line that
/// ended the last reply among it (`getftpresponse`), so it reads the socket
/// once, whatever that finds, before it first waits.
#[expect(
    clippy::too_many_arguments,
    reason = "the blocking drive's own, with what FTP's differs in"
)]
pub(crate) fn runs_done_said<H: Host>(
    cx: &mut StepCx<'_, H>,
    pp: &Pingpong,
    carrier: &mut Carrier<'_>,
    limit: Option<TimeLimit>,
    exchanged: bool,
    round: &mut Blocking,
    said: &str,
    read_first: bool,
) -> Result<(bool, Instant), ErrorKind> {
    let now = cx.now();
    if let Some(since) = round.polling {
        let ends = poll_ends(cx, pp, limit, since);
        let ready = holds(pp, carrier) || carrier.ready_now(waits(pp));
        if !ready && now < ends {
            return Ok((false, ends));
        }
        round.polling = None;
        crate::progress::check(cx, exchanged)?;
        if ready {
            return Ok((true, now));
        }
    }
    let left = cx.time_left();
    if pp.time_left(now, limit, left) == ResponseTime::Out {
        return Err(trace::fail(
            cx,
            ErrorKind::OperationTimedout,
            format_args!("{said}"),
        ));
    }
    if read_first || holds(pp, carrier) || carrier.ready_now(waits(pp)) {
        crate::progress::check(cx, exchanged)?;
        return Ok((true, now));
    }
    round.polling = Some(now);
    Ok((false, poll_ends(cx, pp, limit, now)))
}

/// When a poll of C's blocking drive started at `since` ends: a second
/// on, or once the server's time to answer is out if that is sooner
/// (`interval_ms`).
fn poll_ends<H: Host>(
    cx: &StepCx<'_, H>,
    pp: &Pingpong,
    limit: Option<TimeLimit>,
    since: Instant,
) -> Instant {
    let left = cx.time_left();
    match pp.time_left(since, limit, left) {
        ResponseTime::Left(left) => since.after(left.min(BLOCKING_POLL)),
        ResponseTime::Out => since,
    }
}

/// Whether bytes wait where a poll cannot see them, or are held unread:
/// the step has something to do without waiting on the connection.
pub(crate) fn holds(pp: &Pingpong, carrier: &mut Carrier<'_>) -> bool {
    carrier.reborrow().data_pending() || pp.unscanned()
}

/// The longest C's blocking drive polls before it checks the progress
/// again (`Curl_pp_statemach`'s `interval_ms`).
pub(crate) const BLOCKING_POLL: std::time::Duration = std::time::Duration::from_secs(1);

/// What a back and forth waits for on its connection (`Curl_pp_pollset`).
pub(crate) fn waits(pp: &Pingpong) -> Events {
    match pp.wants() {
        Wants::Send => Events::OUT,
        Wants::Recv => Events::IN,
    }
}
