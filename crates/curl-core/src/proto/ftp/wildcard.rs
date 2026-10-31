//! A wildcard download (`CURLOPT_WILDCARDMATCH`, `wc_statemach`): the
//! URL's last part is a pattern. A transfer lists the directory before
//! it, its listing read for the files the pattern matches, then one
//! transfer gets each, and a last one finds nothing left. Each is a
//! request of its own, from INIT to DONE (`multistate_done`), on the one
//! connection; what they have in common is kept here, the transfer's
//! from one to the next, lent to each FTP request as it is made.

use curl_alloc::TryVec as _;

use super::list::Listing;
use super::{FtpConn, Request, Step, copied};
use crate::error::ErrorKind;
use crate::handler::{ChunkBegin, FileType, Matched};
use crate::multi::state::StepCx;
use crate::multi::{Host, TransferCx};
use crate::options::FtpMethod;
use crate::trace;

/// Where the download is (`wildcard_states`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WcState {
    /// Its first request is to list the directory.
    Init,
    /// The listing is being read.
    Matching,
    /// The next file is got.
    Downloading,
    /// The next file is passed over.
    Skip,
    /// The files are all got: the listing's failure, if it failed, is
    /// the download's.
    Clean,
    Done,
    Error,
}

/// A wildcard download, from one of its requests to the next
/// (`struct WildcardData`).
#[derive(Debug)]
pub(crate) struct Wildcard {
    state: WcState,
    /// The URL's path up to the pattern, encoded, its last slash kept.
    path: Vec<u8>,
    /// The listing and the files it named (`ftpwc`, `filelist`), from
    /// the pattern's reading on.
    matching: Option<Box<Matching>>,
}

impl Wildcard {
    pub(crate) fn new() -> Wildcard {
        Wildcard {
            state: WcState::Init,
            path: Vec::new(),
            matching: None,
        }
    }

    /// There is no more to get: the transfer is over (`CURLWC_DONE`).
    pub(crate) fn done(&self) -> bool {
        self.state == WcState::Done
    }
}

/// A listing as it is read, and the pattern its names are matched
/// against.
#[derive(Debug)]
pub(crate) struct Matching {
    listing: Listing,
    pattern: Vec<u8>,
}

impl Matching {
    /// Read `bytes` of the listing, as the transfer's write handler would
    /// take them (`Curl_ftp_parselist`): each name matched against the
    /// pattern by the application's handler, or by the system's
    /// `fnmatch(3)`. All are taken, whatever the listing says.
    pub(crate) fn take<H: Host>(&mut self, cx: &mut StepCx<'_, H>, bytes: &[u8]) {
        let handler = cx.easy().options().line.ftp.fnmatch.clone();
        let pattern = &self.pattern;
        self.listing.feed(bytes, &mut |name| {
            let matched = match &handler {
                Some(h) => h.matches(&mut TransferCx::new(cx), pattern, name),
                None => curl_os::fnmatch::fnmatch(pattern, name).map(|m| match m {
                    curl_os::fnmatch::Matched::Match => Matched::Match,
                    curl_os::fnmatch::Matched::NoMatch => Matched::NoMatch,
                    curl_os::fnmatch::Matched::Fail => Matched::Fail,
                }),
            };
            Ok(matched.map_err(|_| ErrorKind::OutOfMemory)? == Matched::Match)
        });
    }
}

impl Request {
    /// The wildcard download's step as DO starts (`wc_statemach`): its
    /// first request has its path cut at the pattern; the next ones each
    /// the path of the next file the listing named. True if there is no
    /// request to make: the files are all got.
    pub(super) fn wildcard_do<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        reused: bool,
    ) -> Result<bool, ErrorKind> {
        let mut w = self.wildcard.take().expect("a wildcard download");
        let result = self.wildcard_step(cx, pc, reused, &mut w);
        let over = matches!(w.state, WcState::Skip | WcState::Done);
        if w.state == WcState::Matching
            && let Some(matching) = w.matching.take()
        {
            // The listing goes to the reader, not the write handler, as
            // long as the request lasts (`Curl_ftp_listmode`).
            self.pipeline.list_into(matching);
        }
        self.wildcard = Some(w);
        // A download with nothing more to get makes no request, whatever
        // its step said (`ftp_do`).
        if over {
            return Ok(true);
        }
        result.map(|()| false)
    }

    fn wildcard_step<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        reused: bool,
        w: &mut Wildcard,
    ) -> Step {
        loop {
            match w.state {
                WcState::Init => {
                    let result = self.wildcard_init(cx, pc, reused, w);
                    if w.state != WcState::Clean {
                        w.state = if result.is_ok() {
                            WcState::Matching
                        } else {
                            WcState::Error
                        };
                    }
                    return result;
                }
                WcState::Matching => {
                    // The listing is read: back from the reader.
                    if let Some(matching) = self.pipeline.listed() {
                        w.matching = Some(matching);
                    }
                    let listing = &w
                        .matching
                        .as_deref()
                        .expect("made with the pattern")
                        .listing;
                    let (failed, none) = (listing.error().is_some(), listing.files().is_empty());
                    if failed {
                        w.state = WcState::Clean;
                    } else if none {
                        w.state = WcState::Clean;
                        return Err(ErrorKind::RemoteFileNotFound);
                    } else {
                        w.state = WcState::Downloading;
                    }
                }
                WcState::Downloading => {
                    if !self.wildcard_next(cx, pc, reused, w)? {
                        return Ok(());
                    }
                }
                WcState::Skip => {
                    if let Some(end) = cx.easy().options().line.ftp.chunk_end.clone() {
                        end.end(&mut TransferCx::new(cx));
                    }
                    let matching = w.matching.as_deref_mut().expect("files to pass over");
                    matching.listing.pass_first();
                    w.state = if matching.listing.files().is_empty() {
                        WcState::Clean
                    } else {
                        WcState::Downloading
                    };
                }
                WcState::Clean => {
                    let failed = w.matching.as_deref().and_then(|m| m.listing.error());
                    w.state = if failed.is_some() {
                        WcState::Error
                    } else {
                        WcState::Done
                    };
                    return failed.map_or(Ok(()), Err);
                }
                WcState::Done | WcState::Error => {
                    w.matching = None;
                    return Ok(());
                }
            }
        }
    }

    /// The path cut at its last slash, the pattern after it
    /// (`init_wc_data`). A path that ends in a slash, or is empty, has no
    /// pattern: the directory is only listed, as without a wildcard.
    fn wildcard_init<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        reused: bool,
        w: &mut Wildcard,
    ) -> Step {
        let cut = self
            .encoded
            .iter()
            .rposition(|&b| b == b'/')
            .map_or(0, |s| s + 1);
        if cut == self.encoded.len() {
            w.state = WcState::Clean;
            return self.parse_path(cx, pc, reused);
        }
        let pattern = copied(&self.encoded[cut..])?;
        self.encoded.truncate(cut);
        let matching = curl_alloc::try_box(Matching {
            listing: Listing::new(),
            pattern,
        })
        .map_err(|_| ErrorKind::OutOfMemory)?;
        // Each file is reached by its directories: C changes the
        // application's choice for good.
        if cx.easy().options().line.ftp.method == FtpMethod::NoCwd {
            let options = cx.easy_mut().options_mut();
            let line = options
                .line
                .make_mut()
                .map_err(|_| ErrorKind::OutOfMemory)?;
            line.ftp.method = FtpMethod::MultiCwd;
        }
        self.parse_path(cx, pc, reused)?;
        w.path = copied(&self.encoded)?;
        w.matching = Some(matching);
        trace::info(cx, format_args!("Wildcard - Parsing started"));
        Ok(())
    }

    /// The first file left is got, unless the application passes it
    /// over or it is not a file: its path the directory's and its name,
    /// escaped (`CURLWC_DOWNLOADING`). True if it is passed over: the
    /// step goes on.
    fn wildcard_next<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pc: &mut FtpConn,
        reused: bool,
        w: &mut Wildcard,
    ) -> Result<bool, ErrorKind> {
        let matching = w.matching.as_deref_mut().expect("files to get");
        let remains = matching.listing.files().len();
        let entry = matching.listing.files().front().expect("one left");
        let info = entry.info();
        let escaped = crate::url::escape(info.name).map_err(|_| ErrorKind::OutOfMemory)?;
        let mut path = copied(&w.path)?;
        path.try_extend_from_slice(&escaped)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        self.encoded = path;
        trace::info_with(cx, &[b"Wildcard - START of \"", info.name, b"\""]);
        if let Some(begin) = cx.easy().options().line.ftp.chunk_begin.clone() {
            match begin.begin(&mut TransferCx::new(cx), &info, remains) {
                ChunkBegin::Get => {}
                ChunkBegin::Skip => {
                    trace::info_with(cx, &[b"Wildcard - \"", info.name, b"\" skipped by user"]);
                    w.state = WcState::Skip;
                    return Ok(true);
                }
                ChunkBegin::Fail => return Err(ErrorKind::ChunkFailed),
            }
        }
        if info.kind != FileType::File {
            w.state = WcState::Skip;
            return Ok(true);
        }
        if let Some(size) = info.size {
            self.known_filesize = Some(size);
        }
        self.parse_path(cx, pc, reused)?;
        let matching = w.matching.as_deref_mut().expect("files to get");
        matching.listing.pass_first();
        if matching.listing.files().is_empty() {
            // The last: the request after it finds nothing left.
            w.state = WcState::Clean;
        }
        Ok(false)
    }

    /// The request ends (`ftp_done_wildcard`): the application is told
    /// it is done with the file, if it named one, and the file's path is
    /// let go then; its size is known no more.
    pub(super) fn wildcard_done<H: Host>(&mut self, cx: &mut StepCx<'_, H>) {
        if self.wildcard.is_none() {
            return;
        }
        if let Some(end) = cx.easy().options().line.ftp.chunk_end.clone()
            && self.path().file().is_some()
        {
            end.end(&mut TransferCx::new(cx));
            self.parsed = None;
        }
        self.known_filesize = None;
    }

    /// The wildcard download, given back as the request is over, the
    /// listing back from the reader if it was being read.
    pub(crate) fn take_wildcard(&mut self) -> Option<Box<Wildcard>> {
        let mut w = self.wildcard.take()?;
        if let Some(matching) = self.pipeline.listed() {
            w.matching = Some(matching);
        }
        Some(w)
    }
}
