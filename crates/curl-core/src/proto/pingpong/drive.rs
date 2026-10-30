//! The back and forth driven over a connection (`lib/pingpong.c`'s I/O):
//! a command sent as the connection takes it, the answer read a read at a
//! time and handed line by line to the application, and whether the
//! protocol's step has anything to do now.

use super::{Ends, Pingpong, READ_SIZE, ReplySize, ResponseTime, Wants};
use crate::conn::RecvFailed;
use crate::conn::io::{Events, Recv, Sent};
use crate::conn::layer::Lower as _;
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
    let mut reads_left = super::MAX_READS;
    loop {
        let mut got = 0;
        if !pp.unscanned() {
            // Don't get stuck.
            if reads_left == 0 {
                return Ok(Read::Waiting);
            }
            reads_left -= 1;
            match recv(cx, pp, carrier)? {
                Some(n) => got = n,
                None => return Ok(Read::Waiting),
            }
            *counted += got as u64;
        }
        loop {
            let event = pp.next(ends).map_err(|e| read_failed(cx, e))?;
            match event {
                super::Event::NeedMore => break,
                super::Event::Line(line) => {
                    trace::bytes(cx, DebugKind::HeaderIn, line);
                    pipeline.info(cx, line, sent)?;
                }
                super::Event::Reply { line, reply, size } => {
                    trace::bytes(cx, DebugKind::HeaderIn, line);
                    pipeline.info(cx, line, sent)?;
                    pp.reads_ended();
                    return Ok(Read::Reply(reply, size));
                }
            }
        }
        if got != READ_SIZE {
            pp.reads_ended();
            return Ok(Read::Waiting);
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
    match carrier.recv(cx, READ_SIZE) {
        Ok(Recv::WouldBlock) => Ok(None),
        Ok(Recv::Eof) => {
            let e = pp
                .push(&[])
                .expect_err("an empty read is the server closing");
            Err(read_failed(cx, e))
        }
        Ok(Recv::Data(_)) => {
            let rx = carrier.rx_mut();
            let n = rx.filled().len().min(READ_SIZE);
            let pushed = pp.push(&rx.filled()[..n]);
            rx.consume(n);
            pushed.map_err(|e| read_failed(cx, e))?;
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
/// connection, and when the server's time to answer runs out, for the
/// step to be woken then (`Curl_pp_statemach` without blocking, its
/// `Curl_expire`): failed if that time, `limit` or a minute, is out
/// already. It runs if bytes wait where a poll cannot see them, or are
/// held unread, or the socket is ready for what the back and forth waits
/// for, a poll that does not wait.
pub(crate) fn runs<H: Host>(
    cx: &mut StepCx<'_, H>,
    pp: &Pingpong,
    carrier: &mut Carrier<'_>,
    limit: Option<TimeLimit>,
) -> Result<(bool, Instant), ErrorKind> {
    let left = cx.time_left();
    let now = cx.now();
    let due = match pp.time_left(now, limit, left) {
        ResponseTime::Left(left) => now.after(left),
        ResponseTime::Out => {
            return Err(trace::fail(
                cx,
                ErrorKind::OperationTimedout,
                format_args!("server response timeout"),
            ));
        }
    };
    if carrier.reborrow().data_pending() || pp.unscanned() {
        return Ok((true, due));
    }
    Ok((carrier.ready_now(waits(pp)), due))
}

/// What a back and forth waits for on its connection (`Curl_pp_pollset`).
pub(crate) fn waits(pp: &Pingpong) -> Events {
    match pp.wants() {
        Wants::Send => Events::OUT,
        Wants::Recv => Events::IN,
    }
}
