//! What the small protocols' tests share: a transfer over a fake server,
//! and what its handlers were given.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

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
struct Seen(Arc<Mutex<Ran>>);

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
    let clock = ManualClock::new().unwrap();
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
    let mut e = Easy::new();
    e.set_libraries(SharedLibraries::new(Libraries::NONE).unwrap());
    let seen = Seen::default();
    let o = e.options_mut();
    let url = url.replace("PORT", &PORT.to_string());
    o.set_url(Some(url.as_bytes())).unwrap();
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.output.verbose = true;
    o.callbacks.write = Some(Handler::write(seen.clone()).unwrap());
    o.callbacks.header = Some(Handler::header(seen.clone()).unwrap());
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
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
