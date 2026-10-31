//! DICT (`lib/dict.c`, RFC 2229): one request a connection, made of the
//! URL's path, and the server's answer as the body, read until it closes
//! the connection.

use std::num::NonZeroU32;

use curl_alloc::TryVec as _;

use super::raw::{Outgoing, ToClose};
use super::{Connect, DoPhase, DoStep, ProtoStep, Waiting};
use crate::conn::io::Events;
use crate::conn::{ConnLease, Peer, Scheme};
use crate::deliver::{Pause, Pipeline, Reach};
use crate::error::{ErrorKind, url_error};
use crate::handler::DebugKind;
use crate::idn::Idn;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::trace;
use crate::url::{GetOptions, Part, Url, decode_but_control};

/// The longest a looked-up word may be once escaped, its terminator
/// counted (`DYN_DICT_WORD`).
const MAX_WORD: usize = 10000;

/// A DICT transfer.
#[derive(Debug)]
pub(crate) struct Request {
    pipeline: Pipeline,
    peer: Peer,
    /// The URL's path, as it is encoded (`state.up.path`).
    path: Vec<u8>,
    /// The request, once DO has made it.
    out: Outgoing,
    answer: ToClose,
}

/// The request the path asks for, its words escaped: the bytes it sends
/// before `QUIT` (`dict_do`); whether the word was missing. `None` if the
/// path asks for nothing, which C then sends nothing for.
pub(crate) fn request_of(path: &[u8]) -> Result<Option<(Vec<u8>, bool)>, ErrorKind> {
    let starts = |prefixes: &[&[u8]]| {
        prefixes
            .iter()
            .any(|p| path.len() >= p.len() && path[..p.len()].eq_ignore_ascii_case(p))
    };
    let oom = |_| ErrorKind::OutOfMemory;
    let mut out = Vec::new();
    if starts(&[b"/MATCH:", b"/M:", b"/FIND:"]) {
        let (word, rest) = fields(path);
        let (database, rest) = split_colon(rest);
        let (strategy, _) = split_colon(rest);
        let missing = word.is_none_or(<[u8]>::is_empty);
        let word = escape_word(word.filter(|w| !w.is_empty()).unwrap_or(b"default"))?;
        out.try_extend_from_slice(b"MATCH ").map_err(oom)?;
        out.try_extend_from_slice(or_default(database, b"!"))
            .map_err(oom)?;
        out.try_push(b' ').map_err(oom)?;
        out.try_extend_from_slice(or_default(strategy, b"."))
            .map_err(oom)?;
        out.try_push(b' ').map_err(oom)?;
        out.try_extend_from_slice(&word).map_err(oom)?;
        Ok(Some((out, missing)))
    } else if starts(&[b"/DEFINE:", b"/D:", b"/LOOKUP:"]) {
        let (word, rest) = fields(path);
        let (database, _) = split_colon(rest);
        let missing = word.is_none_or(<[u8]>::is_empty);
        let word = escape_word(word.filter(|w| !w.is_empty()).unwrap_or(b"default"))?;
        out.try_extend_from_slice(b"DEFINE ").map_err(oom)?;
        out.try_extend_from_slice(or_default(database, b"!"))
            .map_err(oom)?;
        out.try_push(b' ').map_err(oom)?;
        out.try_extend_from_slice(&word).map_err(oom)?;
        Ok(Some((out, missing)))
    } else {
        let Some(slash) = path.iter().position(|&b| b == b'/') else {
            return Ok(None);
        };
        for &b in &path[slash + 1..] {
            out.try_push(if b == b':' { b' ' } else { b })
                .map_err(oom)?;
        }
        Ok(Some((out, false)))
    }
}

/// The word after the path's first colon, up to the next, and what
/// follows that colon; no word if the path has no colon.
fn fields(path: &[u8]) -> (Option<&[u8]>, Option<&[u8]>) {
    match path.iter().position(|&b| b == b':') {
        None => (None, None),
        Some(at) => {
            let (word, rest) = split_colon(Some(&path[at + 1..]));
            (word, rest)
        }
    }
}

/// `field` up to its first colon, and what follows the colon if it has
/// one.
fn split_colon(field: Option<&[u8]>) -> (Option<&[u8]>, Option<&[u8]>) {
    match field {
        None => (None, None),
        Some(f) => match f.iter().position(|&b| b == b':') {
            Some(at) => (Some(&f[..at]), Some(&f[at + 1..])),
            None => (Some(f), None),
        },
    }
}

/// `field`, or `default` if it is missing or empty.
fn or_default<'a>(field: Option<&'a [u8]>, default: &'a [u8]) -> &'a [u8] {
    field.filter(|f| !f.is_empty()).unwrap_or(default)
}

/// `word` with a backslash before each byte RFC 2229 (2.2) has escaped:
/// controls, space, DEL, quotes and the backslash (`unescape_word`). A
/// word longer than C's buffer takes fails as C's allocation does.
fn escape_word(word: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut out = Vec::new();
    for &b in word {
        // Read as C's `char`, signed on some platforms: a byte past 127
        // is then below space.
        let c = b as std::ffi::c_char;
        let escaped = c <= 32 || c == 127 || b == b'\'' || b == b'"' || b == b'\\';
        let more = if escaped { 2 } else { 1 };
        // The dynamic buffer holds its terminator too, and refuses to
        // reach its limit.
        if out.len() + more + 1 > MAX_WORD {
            return Err(ErrorKind::OutOfMemory);
        }
        if escaped {
            out.try_push(b'\\').map_err(|_| ErrorKind::OutOfMemory)?;
        }
        out.try_push(b).map_err(|_| ErrorKind::OutOfMemory)?;
    }
    Ok(out)
}

impl Request {
    /// A transfer of `url`: its peer and its path.
    pub(crate) fn new<H: Host>(url: &Url, cx: &mut StepCx<'_, H>) -> Result<Request, ErrorKind> {
        let peer = peer_of(url, b"dict", cx)?;
        let encoded = GetOptions {
            url_encode: true,
            ..GetOptions::NONE
        };
        let path = url.get(Part::Path, encoded).map_err(url_error)?;
        Ok(Request {
            pipeline: Pipeline::new(Reach::Network),
            peer,
            path,
            out: Outgoing::default(),
            answer: ToClose::default(),
        })
    }

    /// The peer it connects to.
    pub(crate) fn network(
        &self,
        url: &Url,
        scope: Option<NonZeroU32>,
        idn: Option<&dyn Idn>,
    ) -> Result<Peer, ErrorKind> {
        renetwork(&self.peer, url, scope, idn)
    }

    pub(crate) fn scheme(&self) -> Scheme {
        self.peer.scheme()
    }

    pub(crate) fn pipeline_mut(&mut self) -> &mut Pipeline {
        &mut self.pipeline
    }

    pub(crate) fn holds_output(&self) -> bool {
        self.pipeline.holds_output()
    }

    /// What the answer waits for on the connection's socket: it is read
    /// from DO on, and the transfer ends once it is read whole.
    pub(crate) fn interest(&self, pause: Pause) -> Events {
        if pause.recv_paused() {
            Events::NONE
        } else {
            Events::IN
        }
    }

    pub(crate) fn step<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        self.answer.read(cx, lease, &mut self.pipeline)
    }

    /// Send the rest of the request, traced as it goes (`sendf`): whether
    /// all of it has gone, its answer then read.
    fn send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        let sent = self.out.send(cx, lease, &mut |cx, _, piece| {
            trace::bytes(cx, DebugKind::DataOut, piece);
            Ok(())
        });
        match sent {
            Ok(true) => {
                self.answer.start(cx);
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(e) => Err(trace::fail(
                cx,
                e,
                format_args!("Failed sending DICT request"),
            )),
        }
    }
}

/// The peer of `url`, a URL of `scheme`, at its port or the scheme's.
pub(super) fn peer_of<H: Host>(
    url: &Url,
    scheme: &[u8],
    cx: &mut StepCx<'_, H>,
) -> Result<Peer, ErrorKind> {
    let host = url.get(Part::Host, GetOptions::NONE).map_err(url_error)?;
    let port = url
        .get(
            Part::Port,
            GetOptions {
                default_port: true,
                ..GetOptions::NONE
            },
        )
        .map_err(url_error)?;
    let port = std::str::from_utf8(&port)
        .ok()
        .and_then(|p| p.parse().ok())
        .ok_or(ErrorKind::UrlMalformat)?;
    let scheme = Scheme::named(scheme).expect("libcurl knows the scheme");
    let scope = cx.easy().options().address_scope;
    let idn = cx.easy().libraries().idn;
    super::url_peer((scheme, host, port), url, scope, idn)
}

/// The peer `peer` names, again, for `url`.
pub(super) fn renetwork(
    peer: &Peer,
    url: &Url,
    scope: Option<NonZeroU32>,
    idn: Option<&dyn Idn>,
) -> Result<Peer, ErrorKind> {
    let mut host = Vec::new();
    host.try_extend_from_slice(peer.shown())
        .map_err(|_| ErrorKind::OutOfMemory)?;
    super::url_peer((peer.scheme(), host, peer.port()), url, scope, idn)
}

impl super::Phases for Request {
    /// DICT has no connect of its own.
    fn connect<H: Host>(
        &mut self,
        _: &mut StepCx<'_, H>,
        _: &mut ConnLease,
    ) -> Result<Connect, ErrorKind> {
        Ok(Connect::Done)
    }

    /// Make the request of the decoded path and send it, in DO, and what
    /// of it the connection did not take in DOING: C sends it all in DO,
    /// waiting on the socket as it must.
    fn make<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        asked: DoPhase,
    ) -> Result<DoStep, ErrorKind> {
        if asked == DoPhase::Do {
            let path = decode_but_control(&self.path)
                .map_err(url_error)?
                .ok_or(ErrorKind::UrlMalformat)?;
            let Some((command, missing)) = request_of(&path)? else {
                return Ok(DoStep::Did);
            };
            if missing {
                trace::info(cx, format_args!("lookup word is missing"));
            }
            let client = crate::version::version().version.as_bytes();
            self.out = Outgoing::of(&[
                b"CLIENT libcurl ",
                client,
                b"\r\n",
                &command,
                b"\r\nQUIT\r\n",
            ])?;
        }
        Ok(if self.send(cx, lease)? {
            DoStep::Did
        } else {
            DoStep::Doing
        })
    }

    fn waits(&self, phase: Waiting) -> Events {
        phase.c_default()
    }
}

#[cfg(test)]
mod tests;
