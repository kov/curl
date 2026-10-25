//! The application's hands on the TLS library, over the fake: the
//! context handler (`CURLOPT_SSL_CTX_FUNCTION`), the library's objects a
//! transfer's handlers reach (`CURLINFO_TLS_SSL_PTR`), and a handshake
//! that waits for the application's word (`SSL_ERROR_WANT_RETRY_VERIFY`).

use super::*;
use crate::conn::io::Events;
use crate::handler::{ProgressHandler, ProgressNow, ProgressVerdict, TlsContextHandler};
use crate::libraries::{Libraries, Library, SharedLibraries};
use crate::multi::TransferId;
use crate::tls::TlsNative;
use crate::tls::fake::{self, FakeTls, WELCOME};

/// A library's objects as addresses, which a test can keep and compare.
type Seen = (usize, Option<usize>);

fn seen(native: TlsNative) -> Seen {
    (
        native.context().addr().get(),
        native.session().map(|s| s.addr().get()),
    )
}

/// Where a handler was, and the objects it was given or reached there.
type Note = (&'static str, Option<Seen>);

/// What the handlers were given and reached.
#[derive(Clone, Default)]
struct Notes(Arc<Mutex<Vec<Note>>>);

impl Notes {
    fn note(&self, at: &'static str, native: Option<TlsNative>) {
        self.0.lock().unwrap().push((at, native.map(seen)));
    }

    fn all(&self) -> Vec<Note> {
        self.0.lock().unwrap().clone()
    }
}

/// A context handler that notes the context it is given and the
/// transfer's own objects as it reaches them, and answers `answer`.
struct Configure(Notes, Result<(), ErrorKind>);

impl TlsContextHandler for Configure {
    fn configure(&self, cx: &mut TransferCx<'_>, native: TlsNative) -> Result<(), ErrorKind> {
        self.0.note("given", Some(native));
        self.0.note("reached", cx.tls_native(cx.me()));
        self.1
    }
}

/// A write handler that notes the transfer's own objects, and those of
/// the transfer `other` names, if it names one.
struct Reaching(Notes, Arc<Mutex<Option<TransferId>>>);

impl WriteHandler for Reaching {
    fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.0.note("write", cx.tls_native(cx.me()));
        if let Some(other) = *self.1.lock().unwrap() {
            self.0.note("other", cx.tls_native(other));
        }
        Write::Took(body.len())
    }
}

/// A fake library of the test's own, and the libraries naming it.
fn library(backend: FakeTls) -> (&'static FakeTls, SharedLibraries) {
    let backend: &'static FakeTls = Box::leak(Box::new(backend));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        ..Libraries::NONE
    })
    .unwrap();
    (backend, libraries)
}

/// An HTTPS GET of `/` by a handle with `libraries`, set as `set` says.
fn https(libraries: &SharedLibraries, set: impl FnOnce(&mut Options)) -> Box<Easy> {
    let mut e = Easy::new();
    e.set_libraries(libraries.clone());
    let o = e.options_mut();
    let url = format!("https://127.0.0.1:{PORT}/");
    o.set_url(Some(url.as_bytes())).unwrap();
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    set(o);
    Box::new(e)
}

/// The context handler is given the context before the session's own
/// object is made, and the transfer reaches it meanwhile as its
/// connection's (`CURLINFO_TLS_SESSION` in the callback); the write
/// handler reaches the same context and the session's object; and once
/// the transfer is over, nothing.
#[test]
fn the_context_handler_and_the_handlers_reach_the_library_s_objects() {
    let (_, libraries) = library(FakeTls::new().unwrap());
    let [welcome, response] = [WELCOME.to_vec(), fake::records(OK).unwrap()];
    let talk = Conversation::replies(&[&welcome, &response], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let notes = Notes::default();
    let e = https(&libraries, |o| {
        let configure = Configure(notes.clone(), Ok(()));
        o.tls.options.make_mut().unwrap().context = Some(Handler::tls_context(configure).unwrap());
        let write = Reaching(notes.clone(), Arc::default());
        o.callbacks.write = Some(Handler::write(write).unwrap());
    });
    let id = m.add(e, (), &mut NoEvents).unwrap();
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
        Ok(())
    );
    assert_eq!(
        m.tls_native(id),
        None,
        "a transfer over holds no connection"
    );
    let notes = notes.all();
    let [
        ("given", Some(given)),
        ("reached", Some(reached)),
        ("write", Some(write)),
    ] = notes[..]
    else {
        panic!("{notes:?}");
    };
    assert_eq!(given.1, None, "the session's object is made after");
    assert_eq!(reached, given);
    assert_eq!(write.0, given.0, "the same context");
    assert!(write.1.is_some_and(|s| s != write.0), "{write:?}");
}

/// A context handler's error fails the transfer with its kind, said as C
/// says it, before anything is sent.
#[test]
fn the_context_handler_s_error_fails_the_transfer() {
    let (_, libraries) = library(FakeTls::new().unwrap());
    let talk = Conversation::new(WELCOME, false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let notes = Notes::default();
    let e = https(&libraries, |o| {
        let configure = Configure(notes.clone(), Err(ErrorKind::SslCertproblem));
        o.tls.options.make_mut().unwrap().context = Some(Handler::tls_context(configure).unwrap());
    });
    let id = m.add(e, (), &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Err(ErrorKind::SslCertproblem));
    let easy = m.remove(id, &mut NoEvents).unwrap().easy;
    assert_eq!(
        easy.report().failure(),
        Some(&b"error signaled by SSL ctx callback"[..])
    );
    assert_eq!(talk.received(), b"");
}

/// A handler reaches another transfer's objects by its id: those of the
/// connection that transfer holds, not its own.
#[test]
fn a_handler_reaches_another_transfer_s_objects_by_its_id() {
    let (_, libraries) = library(FakeTls::new().unwrap());
    let [welcome, response] = [WELCOME.to_vec(), fake::records(OK).unwrap()];
    let first = Conversation::replies(&[&welcome, &response], false);
    let second = Conversation::replies(&[&welcome, &response], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    // The first transfer holds its connection, its output paused.
    struct Pausing;
    impl WriteHandler for Pausing {
        fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Write {
            Write::Pause
        }
    }
    let one = m
        .add(
            https(&libraries, |o| {
                o.callbacks.write = Some(Handler::write(Pausing).unwrap());
            }),
            (),
            &mut NoEvents,
        )
        .unwrap();
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    let held = m.tls_native(one).expect("the first holds its connection");
    let notes = Notes::default();
    let other = Arc::new(Mutex::new(Some(one)));
    let e = https(&libraries, |o| {
        o.limits.reuse.fresh = true;
        let write = Reaching(notes.clone(), other.clone());
        o.callbacks.write = Some(Handler::write(write).unwrap());
    });
    let two = m.add(e, (), &mut NoEvents).unwrap();
    assert_eq!(
        drive_to_completion(&mut m, two, &mut NoEvents).unwrap(),
        Ok(())
    );
    let notes = notes.all();
    let [("write", Some(own)), ("other", Some(theirs))] = notes[..] else {
        panic!("{notes:?}");
    };
    assert_eq!(theirs, seen(held));
    assert_ne!(own.0, theirs.0, "another connection's context");
}

/// A session that stops the transfer's receiving waits for nothing on
/// the socket and is not moved on, however often the multi runs, until
/// the application unpauses the transfer; then the handshake ends and
/// the transfer with it.
#[test]
fn a_handshake_paused_for_the_application_waits_for_its_word() {
    let (backend, libraries) = library(FakeTls::pausing().unwrap());
    let [welcome, response] = [WELCOME.to_vec(), fake::records(OK).unwrap()];
    let talk = Conversation::replies(&[&welcome, &response], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let id = m.add(https(&libraries, |_| {}), (), &mut NoEvents).unwrap();
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(matches!(
        m.state_of(id),
        crate::multi::state::TransferState::Connecting(_)
    ));
    let mut waits = Events::NONE;
    m.sockets(&mut NoEvents, |_, e| waits = waits | e);
    assert_eq!(waits, Events::NONE, "nothing waited for while paused");
    assert_eq!(backend.log().handshakes, 0);
    assert_eq!(talk.received(), fake::HELLO, "no more sent while paused");
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
        Ok(())
    );
    assert_eq!(backend.log().handshakes, 1);
}

/// A progress handler that notes what the transfer reaches each call.
struct Watching(Notes);

impl ProgressHandler for Watching {
    fn progress(&self, cx: &mut TransferCx<'_>, _: ProgressNow) -> ProgressVerdict {
        self.0.note("progress", cx.tls_native(cx.me()));
        ProgressVerdict::Continue
    }
}

/// The last progress pass, made as the request ends, still reaches the
/// connection's objects, as C's `multi_done` makes it before it detaches
/// the connection: a handler asking for them there gets them, not none.
#[test]
fn the_last_progress_pass_reaches_the_connection_s_objects() {
    let (_, libraries) = library(FakeTls::new().unwrap());
    let [welcome, response] = [WELCOME.to_vec(), fake::records(OK).unwrap()];
    let talk = Conversation::replies(&[&welcome, &response], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let notes = Notes::default();
    let e = https(&libraries, |o| {
        o.progress =
            crate::options::Progress::Handler(Handler::progress(Watching(notes.clone())).unwrap());
    });
    let id = m.add(e, (), &mut NoEvents).unwrap();
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
        Ok(())
    );
    let notes = notes.all();
    let last = notes.last().expect("progress was called");
    assert!(last.1.is_some(), "{notes:?}");
    assert_eq!(
        m.tls_native(id),
        None,
        "a transfer over holds no connection"
    );
}

/// A debug handler that notes what the transfer reaches as the
/// connection's fate is traced.
struct Fated(Notes);

impl crate::handler::DebugHandler for Fated {
    fn debug(&self, cx: &mut TransferCx<'_>, _: crate::handler::DebugKind, bytes: &[u8]) {
        if bytes.starts_with(b"Connection #0 to host") {
            self.0.note("fate", cx.tls_native(cx.me()));
        }
    }
}

/// Once the connection is given back, the transfer reaches none of its
/// objects: what traces its fate is lent nothing of a connection that
/// may be gone (`Curl_detach_connection` before `Curl_cpool_return`).
#[test]
fn nothing_of_the_connection_is_lent_once_it_is_given_back() {
    let (_, libraries) = library(FakeTls::new().unwrap());
    let [welcome, response] = [WELCOME.to_vec(), fake::records(OK).unwrap()];
    let talk = Conversation::replies(&[&welcome, &response], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let notes = Notes::default();
    let e = https(&libraries, |o| {
        o.output.verbose = true;
        o.callbacks.debug = Some(Handler::debug(Fated(notes.clone())).unwrap());
    });
    let id = m.add(e, (), &mut NoEvents).unwrap();
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
        Ok(())
    );
    assert_eq!(notes.all(), [("fate", None)]);
}
