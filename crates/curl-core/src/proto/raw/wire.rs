//! What the small protocols' tests share: a transfer over a fake server,
//! and what its handlers were given.

use curl_alloc::Lock;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::conn::io::{Conversation, FakeNet, Peer as Net};
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{
    DebugHandler, DebugKind, Handler, HeaderHandler, HeaderOrigin, Write, WriteHandler,
};
use crate::id::ArenaPolicy;
use crate::libraries::{Libraries, SharedLibraries};
use crate::multi::{Env, Multi, NoEvents, TransferCx, drive_to_completion};
use crate::options::Options;
use crate::time::ManualClock;

/// The fake server's port.
pub(crate) const PORT: u16 = 8996;

/// What a transfer's handlers were given.
#[derive(Clone, Default)]
struct Seen(Arc<Lock<Ran>>);

/// What came of a transfer.
#[derive(Clone, Debug, Default)]
pub(crate) struct Ran {
    pub(crate) result: Option<Result<(), ErrorKind>>,
    pub(crate) body: Vec<u8>,
    pub(crate) headers: Vec<u8>,
    /// The trace's text.
    pub(crate) text: String,
    /// The bytes traced as sent (`CURLINFO_DATA_OUT`).
    pub(crate) data_out: Vec<u8>,
    /// Header lines were kept for the headers API.
    pub(crate) stored_headers: bool,
    /// The bytes counted as downloaded and uploaded.
    pub(crate) counted: (u64, u64),
}

impl WriteHandler for Seen {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.0.lock().unwrap().body.extend_from_slice(body);
        Write::Took(body.len())
    }
}

impl HeaderHandler for Seen {
    fn header(&self, _: &mut TransferCx<'_>, line: &[u8], _: HeaderOrigin) -> Write {
        self.0.lock().unwrap().headers.extend_from_slice(line);
        Write::Took(line.len())
    }
}

impl DebugHandler for Seen {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        let mut seen = self.0.lock().unwrap();
        match kind {
            DebugKind::Text => seen.text.push_str(&String::from_utf8_lossy(data)),
            DebugKind::DataOut => seen.data_out.extend_from_slice(data),
            _ => {}
        }
    }
}

/// A multi whose server at `PORT` takes `conversations` in turn.
pub(crate) fn serving(conversations: &[&Conversation]) -> Multi {
    serving_on(ManualClock::new().unwrap(), conversations)
}

/// The same, its time `clock`'s.
pub(crate) fn serving_on(clock: ManualClock, conversations: &[&Conversation]) -> Multi {
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let mut net = FakeNet::new(clock.clone()).with_peer(at, Net::Accepts);
    for c in conversations {
        net = net.with_conversation(at, (*c).clone());
    }
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    Multi::new(env).unwrap()
}

/// A verbose transfer of `url`, `PORT` in it replaced, over `m`, set as
/// `set` says.
pub(crate) fn transfer(m: &mut Multi, url: &str, set: impl FnOnce(&mut Options)) -> Ran {
    transfer_tracing(m, url, b"", set)
}

/// The same, `components` traced.
fn transfer_tracing(
    m: &mut Multi,
    url: &str,
    components: &[u8],
    set: impl FnOnce(&mut Options),
) -> Ran {
    let mut e = Easy::new();
    let traced = crate::components::Components::new().unwrap();
    traced.configure(components);
    e.set_components(Some(traced));
    e.set_libraries(SharedLibraries::new(Libraries::NONE).unwrap());
    let seen = Seen::default();
    let o = e.options_mut();
    let url = url.replace("PORT", &PORT.to_string());
    o.set_url(Some(url.as_bytes())).unwrap();
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.output.verbose = true;
    o.callbacks.write = Some(Handler::write(seen.clone()).unwrap());
    o.callbacks.header = Some(Handler::header(seen.clone()).unwrap());
    o.callbacks
        .rare
        .set(
            |r| &mut r.debug,
            Some(Handler::debug(seen.clone()).unwrap()),
        )
        .unwrap();
    set(o);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = drive_to_completion(m, id, &mut NoEvents).unwrap();
    let removed = m.remove(id, &mut NoEvents).unwrap();
    let mut ran = seen.0.lock().unwrap().clone();
    ran.result = Some(result);
    use crate::report::{Origins, Request};
    let stored = removed
        .easy
        .report()
        .headers()
        .next(Origins::ALL, Request::Last, None);
    ran.stored_headers = stored.is_some();
    let sizes = removed.easy.report().sizes();
    ran.counted = (sizes.download(), sizes.upload());
    ran
}

/// One transfer of `url` over a server that talks as `talk` does: what
/// the server was sent, and what came of it.
pub(crate) fn against(
    talk: Conversation,
    url: &str,
    set: impl FnOnce(&mut Options),
) -> (Vec<u8>, Ran) {
    let mut m = serving(&[&talk]);
    let ran = transfer(&mut m, url, set);
    drop(m);
    (talk.received(), ran)
}

/// An answer read to the close ends through the writers, as C's
/// `Curl_xfer_write_resp` writes the end (`CLIENTWRITE_EOS`): the lines
/// C's build traces for `url` over `talk`, in its order.
pub(crate) fn ends_through_the_writers(talk: &Conversation, url: &str) {
    let mut m = serving(&[talk]);
    let ran = transfer_tracing(&mut m, url, b"write", |_| {});
    assert_eq!(ran.result, Some(Ok(())), "{}", ran.text);
    let at = ran
        .text
        .find("[WRITE] download_write body(type=81, blen=0) -> 0\n")
        .unwrap_or_else(|| panic!("the end goes through no writer: {}", ran.text));
    assert!(
        ran.text[at..].starts_with(
            "[WRITE] download_write body(type=81, blen=0) -> 0\n\
             [WRITE] client_write(type=81, len=0) -> 0\n\
             [WRITE] xfer_write_resp(len=0, eos=1) -> 0\n"
        ),
        "{}",
        ran.text
    );
    // Then the request's end, through the writers' last
    // (`Curl_cw_out_done`).
    assert!(
        ran.text[at..].contains("[WRITE] [OUT] done\n"),
        "{}",
        ran.text
    );
}

/// A writer that pauses at its first piece, then takes them all.
#[derive(Clone, Default)]
pub(crate) struct PausesFirst {
    pub(crate) took: Arc<Lock<Vec<u8>>>,
    paused: Arc<crate::test_cell::Cell<bool>>,
}

impl WriteHandler for PausesFirst {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        if !self.paused.replace(true) {
            return Write::Pause;
        }
        self.took.lock().unwrap().extend_from_slice(body);
        Write::Took(body.len())
    }
}

/// A transfer of `url` added to `m`, set as `set` says.
pub(crate) fn added(
    m: &mut Multi,
    url: &str,
    set: impl FnOnce(&mut Options),
) -> crate::multi::TransferId {
    let mut e = Easy::new();
    e.set_libraries(SharedLibraries::new(Libraries::NONE).unwrap());
    let o = e.options_mut();
    let url = url.replace("PORT", &PORT.to_string());
    o.set_url(Some(url.as_bytes())).unwrap();
    set(o);
    m.add(Box::new(e), (), &mut NoEvents).unwrap()
}

/// What the transfers on `m` wait for on their sockets.
pub(crate) fn waits(m: &mut Multi) -> Vec<crate::conn::io::Events> {
    let mut seen = Vec::new();
    m.sockets(&mut NoEvents, |_, events| seen.push(events))
        .unwrap();
    seen
}

/// Output a paused writer holds keeps a transfer of `url` against
/// `talk` from ending, the exchange over or not, until it is taken:
/// what the writer took once unpaused.
pub(crate) fn paused_then_taken(talk: &Conversation, url: &str) -> Vec<u8> {
    use crate::deliver::PauseRequest;
    let mut m = serving(&[talk]);
    let writer = PausesFirst::default();
    let w = writer.clone();
    let id = added(&mut m, url, |o| {
        o.callbacks.write = Some(Handler::write(w).unwrap());
    });
    for _ in 0..10 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(m.info_read().is_none(), "not over while output is held");
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()));
    writer.took.lock().unwrap().clone()
}
