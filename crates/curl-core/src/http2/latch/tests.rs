use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A session each of whose calls is counted, and whose `ping` fails as
/// it is told: no failure, or one that ends it or not.
#[derive(Debug)]
struct Counted {
    calls: Arc<AtomicUsize>,
    ping: Option<FrameError>,
}

impl Counted {
    fn count(&self) {
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}

const ENDED: FrameError = FrameError {
    code: -905,
    text: "Too many CONTINUATION frames following a HEADER frame",
    fatal: true,
};

const DEFERRED: FrameError = FrameError {
    code: -508,
    text: "Data transfer deferred",
    fatal: false,
};

impl Session for Counted {
    fn submit_settings(&mut self, _: &[Setting]) -> Result<(), FrameError> {
        self.count();
        Ok(())
    }
    fn set_local_window(&mut self, _: i32) -> Result<(), FrameError> {
        self.count();
        Ok(())
    }
    fn submit_request(
        &mut self,
        _: &[(&[u8], &[u8])],
        _: bool,
        _: u16,
    ) -> Result<StreamId, FrameError> {
        self.count();
        Ok(StreamId(1))
    }
    fn upgrade(&mut self, _: &[u8], _: bool) -> Result<StreamId, FrameError> {
        self.count();
        Ok(StreamId(1))
    }
    fn recv(
        &mut self,
        bytes: &[u8],
        _: &mut dyn FnMut(Event<'_>) -> Heard,
    ) -> Result<usize, FrameError> {
        self.count();
        Ok(bytes.len())
    }
    fn send(
        &mut self,
        _: &mut dyn FnMut(&[u8]) -> Took,
        _: &mut dyn FnMut(StreamId, &mut [u8]) -> BodyRead,
        _: &mut dyn FnMut(Event<'_>) -> Heard,
    ) -> Result<(), FrameError> {
        self.count();
        Ok(())
    }
    fn set_stream_window(&mut self, _: StreamId, _: i32) -> Result<(), FrameError> {
        self.count();
        Ok(())
    }
    fn stream_window(&self, _: StreamId) -> i32 {
        self.count();
        7
    }
    fn stream_recv_length(&self, _: StreamId) -> i32 {
        self.count();
        7
    }
    fn local_window(&self) -> i32 {
        self.count();
        7
    }
    fn peer_enables_push(&self) -> bool {
        self.count();
        true
    }
    fn remote_window(&self) -> i32 {
        self.count();
        7
    }
    fn stream_remote_window(&self, _: StreamId) -> i32 {
        self.count();
        7
    }
    fn submit_window_update(&mut self, _: StreamId, _: i32) -> Result<(), FrameError> {
        self.count();
        Ok(())
    }
    fn consume(&mut self, _: StreamId, _: usize) -> Result<(), FrameError> {
        self.count();
        Ok(())
    }
    fn resume(&mut self, _: StreamId) -> Result<(), FrameError> {
        self.count();
        Ok(())
    }
    fn reset(&mut self, _: StreamId, _: H2Error) -> Result<(), FrameError> {
        self.count();
        Ok(())
    }
    fn goaway(&mut self, _: H2Error, _: &[u8]) -> Result<(), FrameError> {
        self.count();
        Ok(())
    }
    fn ping(&mut self) -> Result<(), FrameError> {
        self.count();
        self.ping.map_or(Ok(()), Err)
    }
    fn wants(&self) -> Wants {
        self.count();
        Wants {
            read: true,
            write: true,
        }
    }
    fn max_concurrent(&self) -> u32 {
        self.count();
        7
    }
}

fn latched(ping: Option<FrameError>) -> (Latched, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let session = Counted {
        calls: calls.clone(),
        ping,
    };
    (Latched::new(Box::new(session)), calls)
}

/// Each call the trait has, made once, and what it answered: `Err` for
/// a failure, the number or truth a question answers as a value.
fn every_call(s: &mut Latched) -> Vec<Result<i64, FrameError>> {
    let id = StreamId(1);
    let mut events = |_: Event<'_>| Heard::Fine;
    let wants = s.wants();
    vec![
        s.submit_settings(&[]).map(|()| 0),
        s.set_local_window(1).map(|()| 0),
        s.submit_request(&[], false, 16).map(|id| i64::from(id.0)),
        s.upgrade(b"", false).map(|id| i64::from(id.0)),
        s.recv(b"ab", &mut events).map(|n| n as i64),
        s.send(
            &mut |_| Took::Blocked,
            &mut |_, _| BodyRead::Later,
            &mut events,
        )
        .map(|()| 0),
        s.set_stream_window(id, 1).map(|()| 0),
        Ok(i64::from(s.stream_window(id))),
        Ok(i64::from(s.stream_recv_length(id))),
        Ok(i64::from(s.local_window())),
        Ok(i64::from(s.peer_enables_push())),
        Ok(i64::from(s.remote_window())),
        Ok(i64::from(s.stream_remote_window(id))),
        s.submit_window_update(id, 1).map(|()| 0),
        s.consume(id, 1).map(|()| 0),
        s.resume(id).map(|()| 0),
        s.reset(id, H2Error::CANCEL).map(|()| 0),
        s.goaway(H2Error::NO_ERROR, b"").map(|()| 0),
        Ok(i64::from(wants.read) + i64::from(wants.write)),
        Ok(i64::from(s.max_concurrent())),
    ]
}

const CALLS: usize = 20;

/// A session that failed fatally reaches the library no more: each call
/// that could fail answers the failure that ended it, and each question
/// answers as C's shim does once its session is not valid, nothing.
/// A failure that does not end it, or none, changes nothing.
#[test]
fn a_session_ended_by_a_fatal_failure_is_called_no_more() {
    for ping in [None, Some(DEFERRED)] {
        let (mut s, calls) = latched(ping);
        assert_eq!(s.ping(), ping.map_or(Ok(()), Err));
        assert_eq!(s.ended(), None);
        let answers = every_call(&mut s);
        assert_eq!(calls.load(Ordering::Relaxed), 1 + CALLS, "{ping:?}");
        assert!(answers.iter().all(Result::is_ok), "{answers:?}");
    }
    let (mut s, calls) = latched(Some(ENDED));
    assert_eq!(s.ping(), Err(ENDED));
    assert_eq!(s.ended(), Some(ENDED));
    let answers = every_call(&mut s);
    assert_eq!(calls.load(Ordering::Relaxed), 1, "the library was called");
    let failed = Err(ENDED);
    let expected = [
        failed,
        failed,
        failed,
        failed,
        failed,
        failed,
        failed, // the calls
        Ok(0),
        Ok(0),
        Ok(0),
        Ok(0),
        Ok(0),
        Ok(0), // the questions
        failed,
        failed,
        failed,
        failed,
        failed, // the calls
        Ok(0),
        Ok(0), // wanting nothing, and no limit said
    ];
    assert_eq!(answers, expected);
    // A ping too, which ended it.
    assert_eq!(s.ping(), Err(ENDED));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}
