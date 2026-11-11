//! The request a transfer makes next: its URL, redirect or retry, its
//! route and proxy, and the connection it gets for them.

use super::*;
use crate::conn::{OriginTls, RouteTls};
use crate::tls::TlsOrigin;

/// C's pretransfer, once per transfer: the option's URL parsed for the
/// first request.
pub(super) fn pretransfer<H: Host>(
    run: &mut Run,
    cx: &mut StepCx<'_, H>,
) -> Result<Url, ErrorKind> {
    tls_supported(cx)?;
    // The application's own URL goes first, as it is now: the host's,
    // then the options'; one that cannot be read back is none
    // (`Curl_pretransfer`). The host's share goes with this read.
    let host = cx.host_start_url();
    let shared = host.as_ref().or(cx.easy().options().shared_url());
    let shared = shared
        .map(|shared| shared.with(|url| (url.get(Part::Url, GetOptions::NONE), url.try_clone())));
    drop(host);
    let unset = match &shared {
        Some((text, _)) => text.is_err(),
        None => cx.easy().options().url().is_none(),
    };
    if unset {
        return Err(trace::fail(
            cx,
            ErrorKind::UrlMalformat,
            format_args!("No URL set"),
        ));
    }
    // Its text is the text URL from here on, as C keeps it in
    // `STRING_SET_URL`: what a refused `CURLOPT_URL` leaves reported.
    let shared = shared.map(|(text, copy)| {
        let text = text.expect("checked above");
        cx.easy_mut().options_mut().keep_url_text(text);
        copy
    });
    run.retries = 0;
    run.first = None;
    run.method = cx.easy().options().method;
    run.course = Course::START;
    run.http = Inherited::new(cx.easy().options().http.version);
    let options = cx.easy().options();
    let (want, proxy_want) = (options.http.auth.0, options.proxy.auth.0);
    let generation = options.proxy.generation();
    cx.easy_mut().auth.start(want, proxy_want, generation);
    // The application's referer, until a redirect gives another.
    if let Some(given) = &cx.easy().options().http.custom.referer {
        let mut referer = Vec::new();
        referer
            .try_extend_from_slice(given)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        cx.report_mut().set_referer(referer);
    }
    crate::proto::http::cookies::load(cx)?;
    read_resolve(cx)?;
    // The URL is a pattern if the options say so as each request starts;
    // the debug test build says so on request too (`Curl_pretransfer`).
    run.wildcard_match = cx.easy().options().line.ftp.wildcard
        || (cfg!(feature = "debug-hooks") && curl_os::env::is_set(b"CURL_DBG_FTP_WILDCARD"));
    if run.wildcard_match && run.wildcard.is_none() {
        let made = curl_alloc::try_box(crate::proto::ftp::Wildcard::new());
        run.wildcard = Some(made.map_err(|_| ErrorKind::OutOfMemory)?);
    }
    crate::proto::http::hsts::load(cx)?;
    // Taken as it is parsed, its text not read again.
    if let Some(copy) = shared {
        return copy.map_err(url_error);
    }
    let options = cx.easy().options();
    match parse_url(options.url().expect("checked above"), options, false) {
        Ok(url) => Ok(url),
        Err(UrlRefused::Rejected(e)) => {
            // Reported as C's `state.url` holds it, the text given.
            let (given, path_as_is) = (
                options.url().expect("checked above"),
                options.url_rules.path_as_is,
            );
            let mut kept = Vec::new();
            kept.try_extend_from_slice(given)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            cx.report_mut()
                .set_url_given(&kept, path_as_is)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            Err(trace::fail(
                cx,
                url_error(e),
                format_args!("URL rejected: {e}"),
            ))
        }
        Err(UrlRefused::Failed(kind)) => Err(kind),
    }
}

/// The transfer asks nothing of TLS its library cannot do, or none
/// where the handle has no TLS library: else it is not built in. C
/// refuses such an option as it is set (`Curl_ssl_supports` in
/// `curl_easy_setopt`), and so do the shim and the tool; the options
/// here have no setter to refuse them, so the transfer fails before it
/// does anything, whatever its URL, as C's would have done without it.
/// Checked here, once per transfer, it holds for every connection the
/// transfer makes or reuses, STARTTLS and QUIC too.
fn tls_supported<H: Host>(cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    let options = cx.easy().options();
    let asked = crate::tls::TlsSupport::asked_by(
        &options.tls,
        &options.proxy.tls,
        options.doh.verify_status,
    );
    let has = cx
        .easy()
        .libraries()
        .tls
        .as_deref()
        .map_or(crate::tls::TlsSupport::NONE, |tls| tls.support());
    match has.lacking(&asked) {
        None => Ok(()),
        Some(what) => Err(trace::fail(
            cx,
            ErrorKind::NotBuiltIn,
            format_args!("The TLS library has no support for {what}"),
        )),
    }
}

/// Read the application's resolve list into the multi's cache, once for
/// each time it is set (`Curl_loadhostpairs`): a list the cache cannot
/// take is read again by the next transfer.
fn read_resolve<H: Host>(cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    if cx.easy().options().resolve.stamp() == cx.easy().resolve_read {
        return Ok(());
    }
    // The entries are read from a handle on them, which shares them, or
    // on the source that gives them, as the cache and the trace are
    // reached while they are: the debug handler may set the list, and the
    // options keep what it sets. Read whole, the list is done with, and so
    // is one set meanwhile, as C clears `state.resolve` once it has read
    // the old one; one that failed is read again.
    let entries = cx.easy().options().resolve.shared();
    let read = read_entries(cx, &entries);
    if read.is_ok() {
        cx.easy_mut().resolve_read = cx.easy().options().resolve.stamp();
    }
    read
}

/// Put `addrs` in a random order, with the handle's random bytes, if the
/// transfer asks for it (`CURLOPT_DNS_SHUFFLE_ADDRESSES`,
/// `dnsc_entry_assign_addr`); whether they were shuffled.
pub(crate) fn shuffle<H: Host>(
    cx: &mut StepCx<'_, H>,
    addrs: &mut [IpAddr],
) -> Result<bool, OutOfMemory> {
    if !cx.easy().options().dns_shuffle {
        return Ok(false);
    }
    let libraries = cx.easy().libraries();
    crate::conn::shuffle(addrs, &mut |bytes| libraries.random(bytes).is_ok())
}

/// The list's entries read into the cache, in order, as C walks the
/// application's list in place: an entry reaches the trace, and the debug
/// handler, before the next is read.
fn read_entries<H: Host>(cx: &mut StepCx<'_, H>, list: &ResolveList) -> Result<(), ErrorKind> {
    if !list.is_set() {
        return Ok(());
    }
    cx.easy_mut().wildcard_resolve = false;
    list.try_each(|line| read_entry(cx, line))
}

fn read_entry<H: Host>(cx: &mut StepCx<'_, H>, line: &[u8]) -> Result<(), ErrorKind> {
    {
        let (name, port, addrs, permanent) = match parse_entry(line) {
            Ok(None) => return Ok(()),
            Ok(Some(ListEntry::Remove { name, port })) => {
                let kept = cx.rest.kept(cx.me, Kind::Names);
                let (_, mut names) = cx.rest.net_names(cx.me, kept.as_ref());
                names.section(|dns| dns.remove(name, port));
                return Ok(());
            }
            Ok(Some(ListEntry::Add {
                name,
                port,
                addrs,
                permanent,
            })) => (name, port, addrs, permanent),
            Err(BadEntry::Syntax { illegal }) => {
                if let Some(ip) = illegal {
                    trace::info_with(cx, &[b"Resolve IP address '", ip, b"' found is illegal"]);
                }
                let kind = ErrorKind::SetoptOptionSyntax;
                let why: [&[u8]; 3] = [b"Could not parse CURLOPT_RESOLVE entry '", line, b"'"];
                return Err(trace::fail_with(cx, kind, &why));
            }
        };
        let oom = |OutOfMemory| ErrorKind::OutOfMemory;
        let shuffling = cx.easy().options().dns_shuffle && addrs.iter().nth(1).is_some();
        // Shuffled as the entry is made, which C does with the old one
        // discarded: what a shuffle that fails leaves is nothing kept.
        let made = if shuffling {
            let mut shuffled = addrs.to_vec().map_err(oom)?;
            let drawn = shuffle(cx, &mut shuffled);
            let answer = TryArc::try_new(Answer::new(name, shuffled).map_err(oom)?).map_err(oom)?;
            Some((answer, drawn))
        } else {
            None
        };
        // One use of the names, the old answer discarded and the new kept
        // (`Curl_loadhostpairs`). An answer kept that is the one this
        // would make, as each transfer of a handle set the same list finds
        // its last, is kept again from now, as C's in its place would be.
        let kept = cx.rest.kept(cx.me, Kind::Names);
        let (_, mut names) = cx.rest.net_names(cx.me, kept.as_ref());
        let (discarded, put) = names.section(|dns| match &made {
            Some((answer, drawn)) => {
                let discarded = dns.remove(name, port);
                let put = match drawn {
                    Ok(_) => dns.add(answer.clone(), port, permanent),
                    Err(OutOfMemory) => Err(OutOfMemory),
                };
                (discarded, put)
            }
            None if dns.renew((name, port), addrs.iter(), permanent) => (true, Ok(())),
            None => match addrs
                .to_vec()
                .and_then(|a| TryArc::try_new(Answer::new(name, a)?))
            {
                Ok(answer) => {
                    let discarded = dns.remove(name, port);
                    (discarded, dns.add(answer, port, permanent))
                }
                Err(OutOfMemory) => (false, Err(OutOfMemory)),
            },
        });
        // The port is said only to be traced (`infof`'s check first).
        let at = cx
            .verbose()
            .then(|| Text::<8>::clipped(format_args!(":{port}")).0);
        let at = at.as_ref().map_or(&b""[..], Text::bytes);
        if discarded {
            trace::info_with(cx, &[b"RESOLVE ", name, at, b" - old addresses discarded"]);
        }
        if let Some((answer, Ok(true))) = &made {
            let n = answer.addrs().len();
            trace::of(cx, Component::Dns, format_args!("Shuffling {n} addresses"));
        }
        put.map_err(oom)?;
        let given = addrs.given();
        let kept: &[u8] = if permanent { b"" } else { b" (non-permanent)" };
        trace::info_with(
            cx,
            &[b"[DNS] added ", name, at, b":", given, b" to cache", kept],
        );
        if name == b"*" {
            trace::info(cx, format_args!("RESOLVE *:{port} using wildcard"));
            cx.easy_mut().wildcard_resolve = true;
        }
    }
    Ok(())
}

/// What follows a complete exchange, as its protocol decides; a
/// `Location:` not followed has where it would have led kept for the
/// application, as C's `FOLLOW_FAKE` keeps it at the end of the
/// exchange.
pub(super) fn exchanged<H: Host>(
    run: &mut Run,
    x: &mut Attached,
    cx: &mut StepCx<'_, H>,
) -> Result<AfterRequest, ErrorKind> {
    match x
        .proto
        .exchanged(cx, &run.url, x.origin.as_deref(), &mut run.http)?
    {
        Ended::Then(next) => Ok(next),
        Ended::Unfollowed(location) => {
            keep_redirect_url(run, cx, location)?;
            Ok(AfterRequest::Complete)
        }
    }
}

/// The URL of the request just made, as it was parsed for it (C's
/// `state.uh`).
fn request_url<H: Host>(run: &Run, cx: &StepCx<'_, H>) -> Result<Url, ErrorKind> {
    let mut url = match parse_url(&run.url, cx.easy().options(), true) {
        Ok(url) => url,
        Err(UrlRefused::Rejected(e)) => return Err(url_error(e)),
        Err(UrlRefused::Failed(kind)) => return Err(kind),
    };
    apply_port(&mut url, run, cx);
    Ok(url)
}

/// The application's port set over `url`'s, unless a redirect took it
/// away (`Curl_peer_from_url`'s `port_override`).
fn apply_port<H: Host>(url: &mut Url, run: &Run, cx: &StepCx<'_, H>) {
    if let Some(port) = cx
        .easy()
        .options()
        .port
        .filter(|_| run.course.allows_port())
    {
        url.set_port(port);
    }
}

/// Where `location` would have led from the request, kept for the
/// application (`follow_fake`).
fn keep_redirect_url<H: Host>(
    run: &Run,
    cx: &mut StepCx<'_, H>,
    location: &[u8],
) -> Result<(), ErrorKind> {
    let base = request_url(run, cx)?;
    let path_as_is = cx.easy().options().url_rules.path_as_is;
    let url = follow::would_redirect(base, location, path_as_is)?;
    cx.report_mut().set_redirect_url(url);
    Ok(())
}

/// A redirect is followed (`Curl_http_follow`, `FOLLOW_REDIR`): counted,
/// `location` resolved against the request's URL, and a leg started for
/// it. Past the limit, where it leads is kept and the transfer fails.
pub(super) fn follow_leg<H: Host>(
    run: &mut Run,
    cx: &mut StepCx<'_, H>,
    proto: &mut ProtoState,
    location: &[u8],
    code: u16,
    reload: bool,
) -> TransferState {
    let options = cx.easy().options();
    let path_as_is = options.url_rules.path_as_is;
    let max = options.http.max_redirects.get();
    let mut base = match request_url(run, cx) {
        Ok(base) => base,
        Err(e) => return TransferState::Init.fail(e),
    };
    // A `.netrc` file's credentials are the URL's from here, so that a
    // redirect on the same origin carries them as its own.
    if let Some(found) = proto.netrc_login() {
        let encoded = crate::url::SetOptions {
            parse: crate::url::ParseOptions {
                url_encode: true,
                ..crate::url::ParseOptions::NONE
            },
            ..crate::url::SetOptions::NONE
        };
        let secret = found.secret();
        let set = base
            .set(Part::User, Some(secret.user()), encoded)
            .and_then(|()| base.set(Part::Password, Some(secret.password()), encoded));
        if let Err(e) = set {
            return TransferState::Init.fail(url_error(e));
        }
    }
    if let Some(max) = max
        && cx.report_mut().redirects() >= u32::from(max)
    {
        if let Err(e) = keep_redirect_url(run, cx, location) {
            return TransferState::Init.fail(e);
        }
        let why = format_args!("Maximum ({max}) redirects followed");
        return TransferState::Init.fail(trace::fail(cx, ErrorKind::TooManyRedirects, why));
    }
    cx.report_mut().count_redirect();
    if cx.easy().options().http.auto_referer {
        match referer_of(&run.url) {
            Ok(referer) => cx.report_mut().set_referer(referer),
            Err(e) => return TransferState::Init.fail(e),
        }
    }
    let url = match follow::resolve(base, location, path_as_is) {
        Ok(url) => url,
        Err(e) => {
            let kind = url_error(e);
            let why = format_args!("The redirect target URL could not be parsed: {e}");
            return TransferState::Init.fail(trace::fail(cx, kind, why));
        }
    };
    // An absolute URL is reached on its own port, unless the code asks
    // for credentials.
    if !matches!(code, 401 | 407) && url::is_absolute(location) {
        run.course.drop_port();
    }
    let text = match url.get(Part::Url, GetOptions::NONE) {
        Ok(text) => text,
        Err(e) => return TransferState::Init.fail(url_error(e)),
    };
    // The body is started over before anything else is said of the next
    // request (`Curl_req_soft_reset`); a failure stands only if the next
    // request would send it.
    if proto.rewinds_upload() {
        client_start(cx);
    }
    let rewound = proto.rewind_upload(cx);
    trace::info_with(cx, &[b"Issue another request to this URL: '", &text, b"'"]);
    let switched = proto.redirected(cx, code, &mut run.method, &mut run.http);
    if let Err(e) = rewound
        && !switched
    {
        return TransferState::Init.fail(e);
    }
    // Parsed again for its leg, as every request's URL is: a location
    // followed from its text, spaces refused, a reload from the URL as
    // it was (`this_is_a_follow`).
    let url = match parse_url(&text, cx.easy().options(), reload) {
        Ok(url) => url,
        Err(UrlRefused::Rejected(e)) => {
            let why = format_args!("URL rejected: {e}");
            return TransferState::Init.fail(trace::fail(cx, url_error(e), why));
        }
        Err(UrlRefused::Failed(kind)) => return TransferState::Init.fail(kind),
    };
    next_leg(run, cx, url)
}

/// A request is to be made again: its URL parsed anew, as the follow of a
/// retry does (`Curl_http_follow`, `FOLLOW_RETRY`), and a leg started. A
/// protocol without HTTP's follow is simply connected for again, its URL
/// as it was, nothing said and nothing counted (`multi_follow`).
pub(super) fn retry_leg<H: Host>(
    run: &mut Run,
    cx: &mut StepCx<'_, H>,
    proto: &mut ProtoState,
) -> TransferState {
    let url = match parse_url(&run.url, cx.easy().options(), true) {
        Ok(url) => url,
        Err(UrlRefused::Rejected(e)) => {
            let kind = url_error(e);
            let why = format_args!("The redirect target URL could not be parsed: {e}");
            return TransferState::Init.fail(trace::fail(cx, kind, why));
        }
        Err(UrlRefused::Failed(kind)) => return TransferState::Init.fail(kind),
    };
    if !proto.follows() {
        mstate::enter(cx, MState::Setup);
        return start_leg(run, cx, url, true);
    }
    let shown = match url.get(Part::Url, GetOptions::NONE) {
        Ok(shown) => shown,
        Err(e) => return TransferState::Init.fail(url_error(e)),
    };
    // As for a redirect, which never switches to GET here. A retry always
    // rewinds (`Curl_retry_request`).
    client_start(cx);
    let rewound = proto.rewind_upload(cx);
    trace::info_with(cx, &[b"Issue another request to this URL: '", &shown, b"'"]);
    if let Err(e) = rewound {
        return TransferState::Init.fail(e);
    }
    next_leg(run, cx, url)
}

/// `url`, a request's, without credentials or fragment, as the referer
/// of the redirect it got (`set_auto_referer`); C takes any failure for
/// a lack of memory.
fn referer_of(url: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let none = SetOptions::NONE;
    let mut url = Url::parse(url, ParseOptions::NONE).map_err(|_| ErrorKind::OutOfMemory)?;
    url.set(Part::Fragment, None, none)
        .and_then(|()| url.set(Part::User, None, none))
        .and_then(|()| url.set(Part::Password, None, none))
        .and_then(|()| url.get(Part::Url, GetOptions::NONE))
        .map_err(|_| ErrorKind::OutOfMemory)
}

/// The next request of a transfer, made again or redirected, for `url`:
/// counted in the header store, timed, and its leg started.
fn next_leg<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>, url: Url) -> TransferState {
    cx.report_mut().headers_mut().next_request();
    cx.mark(Timer::Redirect);
    // The sizes to come are the new request's (`Curl_pgrsResetTransferSizes`).
    let sizes = cx.report_mut().sizes_mut();
    sizes.download_expected = None;
    sizes.upload_expected = None;
    mstate::enter(cx, MState::Setup);
    start_leg(run, cx, url, false)
}

/// An `http` URL to a host the HSTS cache says to reach only over HTTPS
/// is switched to `https` (`hsts_upgrade`), after the application's port
/// is applied: the URL read back, port and all, is the transfer's and the
/// report's from then on.
fn hsts_upgrade<H: Host>(
    url: &mut Url,
    run: &mut Run,
    cx: &mut StepCx<'_, H>,
) -> Result<(), ErrorKind> {
    if !cx.easy().hsts_enabled() {
        return Ok(());
    }
    let scheme = url.scheme_name(false).map_err(url_error)?;
    if !scheme.eq_ignore_ascii_case(b"http") {
        return Ok(());
    }
    // The host as it is looked up: an IPv6 address without its brackets,
    // a name in Unicode in its ASCII form (the origin's `hostname`).
    let host = url.get(Part::Host, GetOptions::NONE).map_err(url_error)?;
    let bare = host
        .strip_prefix(b"[")
        .and_then(|h| h.strip_suffix(b"]"))
        .unwrap_or(&host);
    let idn = cx.easy().libraries().idn;
    let ascii = crate::idn::lookup_name(idn, bare).map_err(crate::idn::IdnFailure::kind)?;
    let name = ascii.as_deref().unwrap_or(bare);
    if crate::proto::http::hsts::upgrade(url, name, cx)? {
        run.url = url.get(Part::Url, GetOptions::NONE).map_err(url_error)?;
        cx.report_mut()
            .set_url(url)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    }
    Ok(())
}

/// Whether a request that got nothing back over a reused connection is
/// made again on a fresh one (`Curl_retry_request`): the connection may
/// have closed as it was reused. The fifth retry fails the transfer.
pub(super) fn retry_request<H: Host>(
    run: &mut Run,
    x: &mut Attached,
    cx: &mut StepCx<'_, H>,
    ended: bool,
) -> Result<bool, ErrorKind> {
    let uploads = cx.easy().options().method == Method::Upload;
    let reused = x.proto.retryable(ended, uploads) && x.lease.conn().reused();
    // A stream HTTP/2 refused is safe to make again, on any connection,
    // if nothing came on it.
    let refused = x.proto.take_refused() && x.proto.retryable(ended, uploads);
    if !reused && !refused {
        return Ok(false);
    }
    if !reused {
        trace::info(cx, format_args!("REFUSED_STREAM, retrying a fresh connect"));
    }
    if run.retries >= MAX_RETRIES {
        run.retries = 0;
        return Err(trace::fail(
            cx,
            ErrorKind::SendError,
            format_args!("Connection died, tried {MAX_RETRIES} times before giving up"),
        ));
    }
    run.retries += 1;
    let count = run.retries;
    trace::info(
        cx,
        format_args!("Connection died, retrying a fresh connect (retry count: {count})"),
    );
    x.lease.get().mark_close();
    Ok(true)
}

/// C's SETUP and CONNECT, which always run in one pass, for each request
/// of a transfer: the leg's timers, the protocol and a connection for
/// `url`, then the protocol connects over it. `rewinding` says a retry
/// asked for the readers to be rewound and nothing since did, as C's
/// `rewind_read` is left by a retry no follow handles.
pub(super) fn start_leg<H: Host>(
    run: &mut Run,
    cx: &mut StepCx<'_, H>,
    mut url: Url,
    rewinding: bool,
) -> TransferState {
    // Cookies are counted from nothing for each request
    // (`Curl_req_hard_reset`).
    cx.easy_mut().set_cookies = 0;
    // The connect-to entries as the application's source has them now,
    // as C walks them for each connection it sets up; the header lists
    // are read as the request is built.
    if let Err(OutOfMemory) = cx.easy_mut().options_mut().connect_to.refill() {
        return TransferState::Init.fail(ErrorKind::OutOfMemory);
    }
    cx.report_mut().set_method(run.method);
    cx.mark(Timer::StartSingle);
    for (kind, at) in run.deadlines.start_leg(cx.rest.now).into_iter().flatten() {
        trace_set(cx, kind, at);
    }
    mstate::enter(cx, MState::Connect);
    // The request starts from nothing (`Curl_req_hard_reset`).
    upload::trace_reset(cx, rewinding);
    super::names::asyncs_let_go(cx);
    // Counted from nothing for each request (`Curl_init_do`).
    let (speedometer, report) = cx.progress_parts();
    report.sizes_mut().new_request();
    speedometer.start_over();
    // Read back once parsed, credentials and all, as C reads it back
    // (`url.c`, `CURLUPART_URL` into `state.url`): one that cannot be,
    // grown past the limit, fails the transfer without a word. It is read
    // before the application's port is applied, so the URL traced,
    // reported and sent as a referer is the one asked for; were HSTS to
    // upgrade it, C would read it back again, port and all.
    let get = GetOptions {
        get_empty: true,
        ..GetOptions::NONE
    };
    match url.get(Part::Url, get) {
        Ok(whole) => run.url = whole,
        Err(e) => return TransferState::Init.fail(url_error(e)),
    }
    // The transfer's URL from here on is the report's, whatever fails.
    if let Err(OutOfMemory) = cx.report_mut().set_url(&url) {
        return TransferState::Init.fail(ErrorKind::OutOfMemory);
    }
    // The application's port over the URL's, where the request goes and
    // what a relative redirect resolves against (`Curl_peer_from_url`
    // sets it in `state.uh`).
    apply_port(&mut url, run, cx);
    if let Err(kind) = hsts_upgrade(&mut url, run, cx) {
        return TransferState::Init.fail(kind);
    }
    let scheme = match url.scheme_name(false) {
        Ok(s) => s,
        Err(e) => return TransferState::Init.fail(url_error(e)),
    };
    // Known before the protocol opens anything, as C records it.
    cx.report_mut().set_protocol(Protocol::of_scheme(scheme));
    // A URL, and a redirect the more so, goes only where the application
    // lets it (`url_set_conn_scheme`).
    let redirected = run.course.followed();
    let refused = !cx.easy().options().schemes.permit(scheme, redirected);
    let follow: &[u8] = if redirected { b" (in redirect)" } else { b"" };
    // A scheme libcurl does not know is refused first, as the URL is
    // read (`Curl_peer_from_url`).
    if !ProtoState::knows(scheme) {
        let kind = ErrorKind::UnsupportedProtocol;
        let why = [&b"Protocol \""[..], scheme, b"\" not supported", follow];
        return TransferState::Init.fail(trace::fail_with(cx, kind, &why));
    }
    // A host name may be no longer than C lets a URL be (`MAX_URL_LEN`,
    // `Curl_peer_from_url`): the origin is made before anything is read
    // for it.
    if url.host_held().is_some_and(|host| host.len() > MAX_HOST) {
        let kind = ErrorKind::UrlMalformat;
        let kind = trace::fail_with(cx, kind, &[b"Too long hostname (maximum is 65535)"]);
        return TransferState::Init.fail(kind);
    }
    let started = if refused {
        Ok(None)
    } else {
        let before = Before {
            first: run.first.as_deref(),
            method: run.method,
            http: &run.http,
        };
        ProtoState::start(scheme, &url, before, cx)
    };
    // A request made has read the `.netrc`, once. With none to make, C has
    // read it all the same, before it checks the protocol is built and
    // allowed.
    let started = match started {
        Ok(None) => crate::proto::netrc_unkept(&url, run.first.as_deref(), cx).map(|()| None),
        started => started,
    };
    // Out of the queue once the request knows its origin and its
    // credentials, before its protocol is checked and a connection looked
    // for (`Curl_connect`, after `url_set_data_origin_and_creds`).
    if started.is_ok() {
        cx.mark_now(Timer::PostQueue);
    }
    if let Ok(Some(proto)) = &started {
        proto.set_up_said(cx);
    }
    let proto = match started {
        Ok(Some(proto)) => proto,
        Ok(None) => {
            // A scheme libcurl knows that this build leaves out, or that
            // the options do not allow, or that names a proxy and carries
            // no transfer (`url_set_conn_scheme`).
            let carries = crate::conn::Scheme::named(scheme).is_none_or(|s| !s.no_transfer());
            let tail: [&[u8]; 2] = if carries {
                [b"\" is disabled", follow]
            } else {
                [b"\" is not for transfers", b""]
            };
            let why = [&b"Protocol \""[..], scheme, tail[0], tail[1]];
            let kind = trace::fail_with(cx, ErrorKind::UnsupportedProtocol, &why);
            return TransferState::Init.fail(kind);
        }
        Err(e) => return TransferState::Init.fail(e),
    };
    let target = proto.network(
        &url,
        cx.easy().options().address_scope,
        cx.easy().libraries().idn,
    );
    let target = match target {
        Ok(Some(target)) => target,
        Ok(None) => {
            let lease = match acquire(cx, &proto, Route::Local, Dial::Stream) {
                Ok(Acquired::New(lease)) => lease,
                Ok(Acquired::Reused(_)) => {
                    unreachable!("a connection without a network is never kept")
                }
                Ok(Acquired::Wait(_)) => {
                    unreachable!("a connection without a network has no limits")
                }
                Err(OutOfMemory) => return TransferState::Init.fail(ErrorKind::OutOfMemory),
            };
            // It moves nothing over a socket (`Curl_xfer_setup_nop`), and
            // has its name at once.
            mstate::xfer_setup(cx, Directions::default());
            cx.mark(Timer::NameLookup);
            return TransferState::ProtoConnect(Attached {
                lease,
                proto,
                origin: None,
            });
        }
        Err(e) => return TransferState::Init.fail(e),
    };
    let Ok(origin) = TryArc::try_new(target) else {
        return TransferState::Init.fail(ErrorKind::OutOfMemory);
    };
    if run.first.is_none() {
        run.first = Some(origin.clone());
    }
    // Only the origin the transfer started at is given the client's own
    // TLS identity, whatever the application lets credentials follow
    // (`Curl_peer_equal(initial_origin, origin)`).
    let tls_origin = match run.first.as_deref() {
        Some(first) if *first == *origin => TlsOrigin::First,
        _ => TlsOrigin::Other,
    };
    // A Unix socket is connected to in place of the origin's host, and
    // of any connect-to entry, and no proxy is gone through
    // (`url_set_conn_origin_etc`).
    let unix = match unix_peer(cx, &origin) {
        Ok(unix) => unix,
        Err(e) => return TransferState::Init.fail(e),
    };
    let over_unix = unix.is_some();
    let mut alt_used = None;
    let mut preferred = None;
    let via = match unix {
        Some(peer) => Some(peer),
        None => match connect_to(cx, &origin) {
            Ok(Some(via)) => Some(via),
            // No connect-to entry: an alternative service, then.
            Ok(None) => {
                let neg = proto.negotiation();
                match alt_svc(cx, &origin, scheme, neg) {
                    Ok(Some(AltSvc::Elsewhere { via, speaks })) => {
                        alt_used = Some(speaks);
                        Some(via)
                    }
                    Ok(Some(AltSvc::Here(alpn))) => {
                        preferred = Some(alpn);
                        None
                    }
                    Ok(None) => None,
                    Err(e) => return TransferState::Init.fail(e),
                }
            }
            Err(e) => return TransferState::Init.fail(e),
        },
    };
    let secured = proto.secured();
    let proxy = if over_unix {
        None
    } else {
        // A scheme not of HTTP's family, nor one a proxy takes as HTTP,
        // cannot be handed to an HTTP proxy (`PROTOPT_PROXY_AS_HTTP`).
        let handed = origin.scheme().proxies_as_http();
        match choose_proxy(cx, &origin, scheme, via.is_some() || secured || !handed) {
            Ok(proxy) => proxy,
            Err(e) => return TransferState::Init.fail(e),
        }
    };
    // A request a proxy sends on names the whole URL, and the connection
    // is the proxy's (`origin_is_proxy`).
    let mut proto = proto;
    // The origin speaks another version too: it is wanted, and preferred.
    if let (Some(alpn), Some(neg)) = (preferred, proto.negotiation_mut()) {
        match alpn {
            crate::altsvc::Alpn::H1 => neg.wanted.h1 = true,
            crate::altsvc::Alpn::H2 => neg.wanted.h2 = true,
            crate::altsvc::Alpn::H3 => neg.wanted.h3 = true,
        }
        neg.alt_svc = Some(crate::proto::http::AltSvcSaid::Prefers(alpn));
    }
    if let Some(speaks) = alt_used {
        let via = via.as_deref().expect("an alternative is the peer");
        if let Err(OutOfMemory) = proto.alt_used(via, speaks) {
            return TransferState::Init.fail(ErrorKind::OutOfMemory);
        }
    }
    let origin = match &proxy {
        Some(p) if p.forward => {
            // A scheme a proxy takes as HTTP is asked of it in HTTP: the
            // connection's protocol is the proxy's (`conn->scheme`).
            let ftp = matches!(proto, ProtoState::Ftp(_));
            // `;type=` as the application's transfer text option says.
            let ftp_type = (ftp && cx.easy().options().proxy.transfer_mode).then(|| {
                if cx.easy().options().line.ftp.ascii {
                    b'a'
                } else {
                    b'i'
                }
            });
            if ftp {
                let before = Before {
                    first: run.first.as_deref(),
                    method: run.method,
                    http: &run.http,
                };
                if let Err(e) = proto.forward_ftp(&url, before, cx) {
                    return TransferState::Init.fail(e);
                }
            }
            if let Err(e) = proto.forward(&url, ftp_type) {
                return TransferState::Init.fail(e);
            }
            // What the transfer says it spoke is the proxy's scheme
            // (`info.conn_scheme`, from `conn->scheme`).
            let spoken = Protocol::of_scheme(p.peer.scheme().name().as_bytes());
            cx.report_mut().set_protocol(spoken);
            p.peer.clone()
        }
        _ => origin,
    };
    // Its TLS, wanted: from the start for a secured scheme; else the TLS
    // a connection not over it is upgraded to, or may be, for a scheme
    // that may reuse TLS or where TLS is asked for. The settings it is
    // made with stay in the transfer's options, which a connection must
    // share to serve it (`Curl_ssl_filter_config_tmp_init`), until one is
    // set up with them (`NetRoute::made`).
    let has_tls = cx.easy().libraries().tls.is_some();
    assert!(
        has_tls || !secured,
        "a secured scheme is one a TLS library speaks"
    );
    let reuses_tls = proto.scheme().is_some_and(crate::conn::Scheme::reuses_tls);
    let tls = if secured {
        Some(OriginTls::Start(RouteTls::Wanted(tls_origin)))
    } else if has_tls && (reuses_tls || cx.easy().options().line.use_ssl.may()) {
        Some(OriginTls::Upgrade(RouteTls::Wanted(tls_origin)))
    } else {
        None
    };
    // What few routes have: the local end each socket binds, which a
    // connection must share to serve it (`conn->interface_opts`,
    // `localport`, `localportrange`); the credentials a scheme that logs
    // in once per connection logs in with; and how far TLS is asked for.
    let cold = match route_cold(cx, &mut proto) {
        Ok(cold) => cold,
        Err(OutOfMemory) => return TransferState::Init.fail(ErrorKind::OutOfMemory),
    };
    let route = NetRoute {
        origin,
        via,
        proxy,
        tls,
        cold,
    };
    let mut dial = Dial::Stream;
    // HTTP/3 alone must be possible (`Curl_http_setup_conn`). It is
    // dialed over QUIC only as the HTTPS connect's attempt: without that
    // filter (ALPN off, or a proxy) C's connection keeps the TCP it
    // wants, and speaks HTTP/1.1 over TLS.
    let versions = proto.http_versions();
    if versions.h3_only()
        && let Err(kind) = may_http3(cx, &route, secured)
    {
        return TransferState::Init.fail(kind);
    }
    if https::HttpsConnect::heading(&route, cx.easy().options().tls.options.alpn).is_some()
        && https::Choosing::of(&proto, &route, cx)
            .first()
            .is_some_and(|(alpn, _)| alpn == https::Alpn::H3)
    {
        // The HTTPS connect filter's first attempt is HTTP/3's
        // (`cf_hc_set_baller1`).
        dial = Dial::Quic;
    }
    // TFTP sends its own datagrams, straight to its peer; through a
    // proxy, the tunnel refuses it (`TRNSPRT_UDP`, `tunnel_init`).
    if proto.sends_datagrams() && route.proxy.is_none() {
        dial = Dial::Udp;
    }
    if run.wildcard_match {
        proto.give_wildcard(&mut run.wildcard);
    }
    setup(cx, Plan { proto, route, dial })
}

/// What of the route for `proto` few routes have (`RouteCold`), or none
/// if none of it is there. The credentials of a scheme that logs in once
/// per connection move from the request to it, their one owner
/// (`url_set_conn_login`).
fn route_cold<H: Host>(
    cx: &mut StepCx<'_, H>,
    proto: &mut ProtoState,
) -> Result<Option<TryArc<crate::conn::RouteCold>>, OutOfMemory> {
    let options = cx.easy().options();
    let local = options.sockets.local.try_clone()?;
    let use_ssl = options.line.use_ssl;
    let ftp = match proto {
        ProtoState::Ftp(_) => {
            // Every option by name, so that one added does not compile
            // until it is said to set the connection up, and is copied
            // here to be compared (`Curl_ftp_conns_match`), or to be the
            // transfer's alone.
            let crate::options::Ftp {
                account,
                alternative_to_user,
                ssl_ccc,
                // Each transfer's own: how it opens its data connection,
                // what it sends to get or put its file, and the
                // application's handlers for a wildcard download.
                method: _,
                use_epsv: _,
                use_eprt: _,
                use_pret: _,
                skip_pasv_ip: _,
                port: _,
                create_dirs: _,
                accept_timeout: _,
                append: _,
                ascii: _,
                wildcard: _,
                chunk_begin: _,
                chunk_end: _,
                fnmatch: _,
                // Read as TLS is asked for with `AUTH`, which the
                // connection's TLS settings and `use_ssl` decide; C
                // matches no connection by it either.
                ssl_auth: _,
            } = &options.line.ftp;
            Some(crate::conn::FtpSetup {
                account: account.as_deref().map(copy_bytes).transpose()?,
                alternative_to_user: alternative_to_user.as_deref().map(copy_bytes).transpose()?,
                ccc: *ssl_ccc,
            })
        }
        _ => None,
    };
    let cold = crate::conn::RouteCold {
        ip: options.ip_version,
        delegation: options.login.delegation,
        local,
        login: proto.take_login()?,
        use_ssl,
        ftp,
        ssh: proto.take_ssh_keys(),
    };
    if cold.is_empty() {
        return Ok(None);
    }
    TryArc::try_new(cold).map(Some)
}

/// A copy of `bytes`.
fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_extend_from_slice(bytes)?;
    Ok(v)
}

/// Whether HTTP/3 may be spoken over `route`, to an origin `secured` or
/// not (`Curl_conn_may_http3`): failed as C fails it if not.
fn may_http3<H: Host>(
    cx: &mut StepCx<'_, H>,
    route: &NetRoute,
    secured: bool,
) -> Result<(), ErrorKind> {
    match quic_refused(route, secured) {
        None => Ok(()),
        Some((kind, why)) => Err(trace::fail(cx, kind, format_args!("{why}"))),
    }
}

/// Whether the HTTPS connect filter of a setup over `route` may make an
/// attempt in HTTP/3: with a QUIC library, where HTTP/3 may be spoken
/// (`cf_hc_may_h3`), through an HTTP proxy over its CONNECT-UDP.
pub(super) fn may_quic<H: Host>(cx: &StepCx<'_, H>, route: &NetRoute) -> bool {
    cx.easy().libraries().h3.is_some() && quic_refused(route, true).is_none()
}

/// Why HTTP/3 may not be spoken over `route`, to an origin `secured` or
/// not, if it may not (`Curl_conn_may_http3`).
pub(super) fn quic_refused(route: &NetRoute, secured: bool) -> Option<(ErrorKind, &'static str)> {
    Some(if route.destination().is_unix() {
        let why = "HTTP/3 cannot be used over UNIX domain sockets";
        (ErrorKind::QuicConnectError, why)
    } else if !secured {
        (
            ErrorKind::UrlMalformat,
            "HTTP/3 requested for non-HTTPS URL",
        )
    } else if route.socks().is_some() {
        (
            ErrorKind::UrlMalformat,
            "HTTP/3 is not supported over a SOCKS proxy",
        )
    } else {
        return None;
    })
}

/// The peer at the Unix socket the options name, if they name one,
/// spoken to as `origin` is (`Curl_peer_uds_create`): an empty path
/// fails the transfer, unsaid.
fn unix_peer<H: Host>(
    cx: &mut StepCx<'_, H>,
    origin: &Peer,
) -> Result<Option<TryArc<Peer>>, ErrorKind> {
    let Some(unix) = cx.easy().options().sockets.unix.as_ref() else {
        return Ok(None);
    };
    if unix.path.is_empty() {
        return Err(ErrorKind::FailedInit);
    }
    let oom = |OutOfMemory| ErrorKind::OutOfMemory;
    let mut path = Vec::new();
    path.try_extend_from_slice(&unix.path).map_err(oom)?;
    let peer = Peer::unix(origin.scheme(), path, 0, unix.abstract_name);
    TryArc::try_new(peer).map(Some).map_err(oom)
}

/// The proxy the transfer to `origin` goes through, if any
/// (`Curl_proxy_init_conn`): the options', or else the one the
/// environment names for `scheme`, unless the no-proxy list names the
/// origin's host; behind the SOCKS pre-proxy if one is set, which alone
/// is the proxy. Through a connect-to peer, or to a secured origin
/// (`tunnels`), an HTTP proxy would tunnel.
fn choose_proxy<H: Host>(
    cx: &mut StepCx<'_, H>,
    origin: &Peer,
    scheme: &[u8],
    tunnels: bool,
) -> Result<Option<ProxyRoute>, ErrorKind> {
    let options = &cx.easy().options().proxy;
    let no_proxy = match &options.no_proxy {
        Some(list) => Some(copied(list)?),
        None => env_named(cx, &[b"no_proxy", b"NO_PROXY"])?,
    };
    if no_proxy.is_some_and(|list| proxy::excluded(origin.name(), &list)) {
        return Ok(None);
    }
    let options = &cx.easy().options().proxy;
    // An empty one is none, and turns the environment's off too.
    let given = |text: Option<&[u8]>| text.filter(|t| !t.is_empty()).map(copied).transpose();
    let detect =
        !matches!(options.url(), Some([])) && !matches!(options.pre_proxy.as_deref(), Some([]));
    let pre = given(options.pre_proxy.as_deref())?;
    let text = match given(options.url())? {
        Some(text) => Some(text),
        None if pre.is_some() || !detect => None,
        None => match proxy::detect(scheme, &mut getenv).map_err(|_| ErrorKind::OutOfMemory)? {
            Some(found) => {
                let name = found.name();
                let said: [&[u8]; 5] = [
                    b"Uses proxy env variable ",
                    name,
                    b" == '",
                    &found.value,
                    b"'",
                ];
                trace::info_with(cx, &said);
                Some(found.value)
            }
            None => None,
        },
    };
    let pre = match pre {
        Some(pre) => Some(parse_proxy(cx, &pre, true)?),
        None => None,
    };
    let auth_only = cx.easy().options().proxy.socks5_auth.only;
    let Some(text) = text else {
        // The pre-proxy alone is the SOCKS proxy.
        return Ok(
            pre.map(|(kind, peer, creds)| ProxyRoute::new(kind, peer, creds, false, auth_only))
        );
    };
    let (kind, peer, creds) = parse_proxy(cx, &text, false)?;
    // Through a SOCKS proxy, the request goes as to the origin.
    if crate::conn::socks::Version::of(kind).is_some() {
        if pre.is_some() {
            return Err(trace::fail_with(
                cx,
                ErrorKind::CouldntResolveProxy,
                &[
                    b"Having a SOCKS pre-proxy and proxy is not supported with '",
                    &text,
                    b"'",
                ],
            ));
        }
        return Ok(Some(ProxyRoute::new(kind, peer, creds, false, auth_only)));
    }
    // A request goes to an HTTP proxy whole, unless it is asked to
    // tunnel, or reaches the origin through another peer, or is secured,
    // or is of a scheme an HTTP proxy cannot be handed (`tunnels`).
    let tunnel = cx.easy().options().proxy.tunnel || tunnels;
    let route = ProxyRoute::new(kind, peer, creds, !tunnel, auth_only);
    let route = match pre {
        Some((kind, peer, creds)) => route
            .behind(PreProxy { kind, peer, creds })
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?,
        None => route,
    };
    // An HTTPS proxy's TLS is wanted, as its type says: its settings stay
    // in the transfer's options, which a connection must share to serve
    // the transfer (`Curl_ssl_filter_config_tmp_init`'s `ssl_proxy`),
    // until one is set up with them (`NetRoute::made`).
    assert!(
        !route.https() || cx.easy().libraries().tls.is_some(),
        "an HTTPS proxy is one only with a TLS library"
    );
    Ok(Some(route))
}

/// A proxy's URL, `text`, as its type, its peer and its credentials
/// (`parse_proxy`): a pre-proxy is SOCKS4 unless its scheme says
/// otherwise, never HTTP, and has only the credentials its URL gives.
#[expect(clippy::type_complexity, reason = "the route's own parts")]
fn parse_proxy<H: Host>(
    cx: &mut StepCx<'_, H>,
    text: &[u8],
    pre: bool,
) -> Result<(ProxyType, TryArc<Peer>, Option<TryArc<ProxyCreds>>), ErrorKind> {
    let options = &cx.easy().options().proxy;
    let kind = if pre { ProxyType::Socks4 } else { options.kind };
    let tls = cx
        .easy()
        .libraries()
        .tls
        .as_deref()
        .is_some_and(|tls| tls.support().https_proxy);
    let parsed = match proxy::parse(text, kind, options.port(), tls) {
        Ok(parsed) => parsed,
        Err(Refused::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        Err(Refused::Syntax(e)) => {
            let e = Text::<256>::clipped(format_args!("': {e}")).0;
            return Err(trace::fail_with(
                cx,
                ErrorKind::CouldntResolveProxy,
                &[b"Unsupported proxy syntax in '", text, e.bytes()],
            ));
        }
        Err(Refused::Scheme) => {
            return Err(trace::fail_with(
                cx,
                ErrorKind::CouldntConnect,
                &[b"Unsupported proxy scheme for '", text, b"'"],
            ));
        }
        Err(Refused::Credentials(e)) => return Err(url_error(e)),
        Err(Refused::Https) => {
            return Err(trace::fail_with(
                cx,
                ErrorKind::NotBuiltIn,
                &[
                    b"Unsupported proxy '",
                    text,
                    b"', libcurl is built without the HTTPS-proxy support.",
                ],
            ));
        }
    };
    if pre && crate::conn::socks::Version::of(parsed.kind).is_none() {
        return Err(trace::fail_with(
            cx,
            ErrorKind::CouldntResolveProxy,
            &[b"Unsupported pre-proxy type for '", text, b"'"],
        ));
    }
    // A name in Unicode is looked up by its ASCII form, as the origin's
    // (`Curl_peer_from_proxy_url`).
    let mut parsed = parsed;
    parsed.peer = parsed
        .peer
        .idn(cx.easy().libraries().idn)
        .map_err(crate::idn::IdnFailure::kind)?;
    // The URL's user and password, else the options' (`proxy_parse`);
    // either goes with the service the options name, which makes
    // credentials alone for a proxy that is not a pre-proxy.
    let options = &cx.easy().options().proxy;
    let from_url = parsed.user.is_some() || parsed.password.is_some();
    let (user, password) = if from_url || pre {
        (parsed.user, parsed.password)
    } else {
        (
            options.user.as_deref().map(copied).transpose()?,
            options.password.as_deref().map(copied).transpose()?,
        )
    };
    let service = match options.service.as_deref() {
        Some(service) if from_url || !pre => copied(service)?,
        _ => Vec::new(),
    };
    let creds = match (user, password) {
        (None, None) if service.is_empty() => None,
        (user, password) => Some(
            TryArc::try_new(ProxyCreds {
                user: user.unwrap_or_default(),
                password: password.unwrap_or_default(),
                service,
            })
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?,
        ),
    };
    let peer = TryArc::try_new(parsed.peer).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    Ok((parsed.kind, peer, creds))
}

/// The first of the environment variables `names` set, traced as C
/// traces it.
fn env_named<H: Host>(
    cx: &mut StepCx<'_, H>,
    names: &[&[u8]],
) -> Result<Option<Vec<u8>>, ErrorKind> {
    for name in names {
        if let Some(value) = getenv(name).map_err(|_| ErrorKind::OutOfMemory)? {
            trace::info_with(
                cx,
                &[b"Uses proxy env variable ", name, b" == '", &value, b"'"],
            );
            return Ok(Some(value));
        }
    }
    Ok(None)
}

/// The environment variable `name`, unless unset or empty
/// (`curl_getenv`); `Err` when its copy cannot be allocated, where C's
/// reads as unset.
fn getenv(name: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
    Ok(curl_os::env::var(name)?.filter(|value| !value.is_empty()))
}

pub(super) fn copied(bytes: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut copy = Vec::new();
    copy.try_extend_from_slice(bytes)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    Ok(copy)
}

/// A connection for the request (`Curl_connect`): one to set up, or an
/// idle one to reuse, or none while the multi's limits allow none, the
/// request waiting for one (`multistate_connect`).
pub(super) fn setup<H: Host>(cx: &mut StepCx<'_, H>, plan: Plan) -> TransferState {
    let acquired = acquire(cx, &plan.proto, Route::Net(plan.route.clone()), plan.dial);
    if !matches!(acquired, Ok(Acquired::Wait(_))) {
        // One waiting may now find room too.
        schedule_pending(&mut cx.rest);
    }
    // A new connection's route, its TLS made as the pool set it up, is
    // the one its setup reads its TLS identities from; one reused is up,
    // and the plan's, wanting TLS, names what it reaches.
    let mut made = None;
    let lease = match acquired {
        Ok(Acquired::New(lease)) => {
            made = lease.setup().map(|setup| setup.route().clone());
            lease
        }
        Ok(Acquired::Reused(lease)) => {
            let route = &plan.route;
            let name = route.origin.scheme().name();
            let (to, host): (&[u8], _) = match &route.proxy {
                Some(proxy) => (b": connection with proxy ", proxy.peer.shown()),
                None => (b": connection with host ", route.origin.name()),
            };
            // Attached as it is found, its TLS objects the handlers' from
            // the line that says so (`url_find_or_create_conn`).
            let slot = cx.rest.caches.pool.slot_of(&lease);
            cx.lent = native_of(slot.and_then(|s| s.query(LayerQuery::TlsNative)));
            trace::info_with(cx, &[b"Reusing existing ", name.as_bytes(), to, host]);
            plan.proto.reused(cx);
            lease
        }
        Ok(Acquired::Wait(reason)) => {
            match reason {
                WaitReason::HostLimit => {
                    trace::info(cx, format_args!("No more connections allowed to host"));
                }
                WaitReason::TotalLimit(max) => trace::info(
                    cx,
                    format_args!("No connections available, total of {max} reached."),
                ),
                WaitReason::Multiplex => trace::info(
                    cx,
                    format_args!("Waiting on connection to negotiate possible multiplexing."),
                ),
            }
            mstate::enter(cx, MState::Pending);
            cx.rest.pending.enter(cx.me, plan);
            return TransferState::Pending;
        }
        Err(OutOfMemory) => return TransferState::Init.fail(ErrorKind::OutOfMemory),
    };
    cx.report_mut().set_used_proxy(plan.route.proxy.is_some());
    let Plan {
        proto,
        route,
        dial: _,
    } = plan;
    let new = made.is_some();
    let route = made.unwrap_or(route);
    // One joined as another transfer is on it is connected at once, its
    // ends the transfer's as it is found: on to PROTOCONNECT without
    // CONNECTING (`Curl_connect`'s `attached_xfers > 1`,
    // `Curl_conn_ev_data_setup`).
    if let Some(conn) = cx.rest.caches.pool.joined(&lease) {
        let ends = conn.remote().cloned().map(|remote| crate::report::Ends {
            remote,
            local: conn.local(),
        });
        if let Some(ends) = ends {
            cx.report_mut().set_primary(ends);
        }
        return TransferState::ProtoConnect(Attached {
            lease,
            proto,
            origin: Some(route.origin),
        });
    }
    let mut https = None;
    let mut record_ask = None;
    assert!(new || lease.is_up(), "a connection reused is up");
    if !lease.is_up() {
        // The HTTPS connect filter starts the chain, which puts the setup
        // filter below it as its attempt starts; or the setup filter does
        // (`Curl_cf_https_setup`, `Curl_cf_setup_insert_after`).
        https = https::HttpsConnect::heading(&route, cx.easy().options().tls.options.alpn);
        let first = match https {
            Some(_) => Component::HttpsConnect,
            None => Component::Setup,
        };
        trace::of(cx, first, format_args!("added"));
        // It asks for the origin's record (`cf_hc_add`).
        record_ask = https.and_then(|_| https::RecordAsk::heading(&route));
        let wants_quic = proto.negotiation().is_some_and(|n| n.wants_quic());
        names::chain_set_up(cx, &route, record_ask.is_some(), wants_quic);
        mstate::trace(cx, format_args!("Curl_conn_setup() -> 0"));
    }
    TransferState::Connecting(Connecting {
        lease,
        proto,
        route,
        https,
        record_ask,
        record: None,
        record_lookup: None,
        name: crate::conn::Late::default(),
        race: None,
        negotiate: None,
    })
}

/// Let the next transfer waiting for a connection, after the last one
/// let, look for one again (`multi_schedule_pending`): one at a time, as
/// a connection freed most often makes room for one.
pub(crate) fn schedule_pending<H: Host>(rest: &mut EngineRest<'_, H>) {
    if let Some(id) = wake_pending(rest.tell.slots, rest.dirty, rest.pending) {
        let mut cx = StepCx::new(id, rest.reborrow());
        mstate::enter(&mut cx, MState::Connect);
    }
}

/// As `schedule_pending`, on the multi's tables: the transfer let out,
/// which the caller traces entering CONNECT at once, as C's
/// `move_pending_to_connect` does, so that it is in the multi's process
/// set, and its pollset traced, before it next runs.
pub(in crate::multi) fn wake_pending<H: Host>(
    slots: &mut Slots<H>,
    dirty: &mut RowSet,
    pending: &mut PendingQueue,
) -> Option<TransferId> {
    let (id, plan) = pending.next()?;
    let_out(slots, dirty, id, plan);
    Some(id)
}

/// As `schedule_pending`, from the step of `run`, which may be the one
/// let out: a transfer whose step made it wait looks again at once if a
/// connection changed meanwhile, as it is the first waiting
/// (`multi_runsingle`'s `multi_schedule_pending` in PENDING).
pub(crate) fn schedule_pending_from<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) {
    let Some((id, plan)) = cx.rest.pending.next() else {
        return;
    };
    if id == cx.me {
        assert!(
            matches!(run.state, TransferState::Pending),
            "{id:?}, let out of the queue, does not wait"
        );
        run.state = TransferState::Setup(plan);
        mstate::enter(cx, MState::Connect);
    } else {
        let_out(cx.rest.tell.slots, cx.rest.dirty, id, plan);
        let mut other = StepCx::new(id, cx.rest.reborrow());
        mstate::enter(&mut other, MState::Connect);
    }
}

/// Transfer `id`, waiting, with its `plan`, taken out of the queue: it
/// looks for a connection again as it next runs.
fn let_out<H: Host>(slots: &mut Slots<H>, dirty: &mut RowSet, id: TransferId, plan: Plan) {
    let run = slots
        .get_mut(id)
        .and_then(|slot| slot.run.as_mut())
        .filter(|run| matches!(run.state, TransferState::Pending))
        .unwrap_or_else(|| panic!("{id:?}, let out of the queue, does not wait"));
    run.state = TransferState::Setup(plan);
    dirty.insert(id.index());
}

/// The peer the connect-to entries send a connection for `origin` to, if
/// not `origin` itself (`url_set_conn_peer`).
fn connect_to<H: Host>(
    cx: &mut StepCx<'_, H>,
    origin: &Peer,
) -> Result<Option<TryArc<Peer>>, ErrorKind> {
    // The reason formatted while the entries are borrowed, and given once
    // they are not: the debug handler may set them.
    let (kind, reason) = match crate::conn::via(origin, cx.easy().options().connect_to.iter()) {
        Ok(None) => return Ok(None),
        Ok(Some(via)) => {
            // A name in Unicode is looked up by its ASCII form, as the
            // origin's (`Curl_peer_from_connect_to`).
            let via = via.idn(cx.easy().libraries().idn);
            let via = via.map_err(crate::idn::IdnFailure::kind)?;
            return TryArc::try_new(via)
                .map(Some)
                .map_err(|OutOfMemory| ErrorKind::OutOfMemory);
        }
        Err(BadVia::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        Err(BadVia::Syntax { kind, why, text }) => {
            let why = why.as_bytes();
            (kind, trace::reason_with(&[why, b" in '", text, b"'"]))
        }
    };
    Err(trace::fail_for(cx, kind, reason))
}

/// What an alternative service for the origin says.
enum AltSvc {
    /// A connection goes to another peer, `via`, switching the request to
    /// `speaks` if that is another version than the one looked up.
    Elsewhere {
        via: TryArc<Peer>,
        speaks: Option<crate::altsvc::Alpn>,
    },
    /// The origin itself speaks this version too, which is preferred.
    Here(crate::altsvc::Alpn),
}

/// What an alternative service says of `origin`, if the cache is on and
/// knows one, for an `https` URL, or any in a debug build told
/// `CURL_ALTSVC_HTTP` (`url_set_conn_peer`). HTTP/3's alternative is
/// looked for first, then HTTP/2's, then HTTP/1's, as the request wants
/// them and the cache allows, those of HTTP/3 where a library speaks it.
fn alt_svc<H: Host>(
    cx: &mut StepCx<'_, H>,
    origin: &Peer,
    scheme: &[u8],
    neg: Option<crate::proto::http::Negotiation>,
) -> Result<Option<AltSvc>, ErrorKind> {
    use crate::altsvc::{Alpn, Versions};
    use crate::proto::http::Negotiation;
    let (Some(alt_svc), Some(neg)) = (cx.easy().alt_svc(), neg) else {
        return Ok(None);
    };
    let ctrl = alt_svc.ctrl().versions;
    let secured = scheme == b"https";
    #[cfg(feature = "debug-hooks")]
    let secured = secured || curl_os::env::is_set(b"CURL_ALTSVC_HTTP");
    if !secured {
        return Ok(None);
    }
    let (wanted, allowed) = (
        Negotiation::bits(neg.wanted),
        Negotiation::bits(neg.allowed),
    );
    trace::debug_info(
        cx,
        format_args!("Alt-svc check wanted={wanted:x}, allowed={allowed:x}"),
    );
    let h2 = cx.easy().libraries().h2.is_some();
    let h3 = cx.easy().libraries().h3.is_some();
    let allowed = Versions {
        h1: neg.allowed.h1 && ctrl.h1,
        h2: neg.allowed.h2 && h2 && ctrl.h2,
        h3: neg.allowed.h3 && h3 && ctrl.h3,
    };
    trace::debug_info_with(cx, &[b"check Alt-Svc for host '", origin.name(), b"'"]);
    let now = crate::date::cache_now(cx.unix_time());
    let alt_svc = cx.easy_mut().alt_svc_mut().expect("on, as above");
    let mut sources = [
        (neg.wanted.h3 && h3).then_some(Alpn::H3),
        (neg.wanted.h2 && h2 && !neg.prior).then_some(Alpn::H2),
        (neg.wanted.h1 && !neg.only_10).then_some(Alpn::H1),
    ]
    .into_iter()
    .flatten();
    let (src, found) = loop {
        let Some(src) = sources.next() else {
            return Ok(None);
        };
        if let Some(found) = alt_svc.lookup((origin.name(), origin.port(), src), allowed, now) {
            break (src, found);
        }
    };
    if found.same {
        return Ok(Some(AltSvc::Here(found.alpn)));
    }
    let oom = |OutOfMemory| ErrorKind::OutOfMemory;
    let (dst_alpn, port) = (found.alpn, found.port);
    // An IPv6 address and its zone told apart from a name as C tells
    // them (`Curl_peer_create`).
    let via = Peer::create(origin.scheme(), found.host, port)
        .map_err(oom)?
        .ok_or(ErrorKind::UrlMalformat)?;
    // A name in Unicode is looked up by its ASCII form, as the origin's
    // (`Curl_peer_create`).
    let via = via.idn(cx.easy().libraries().idn);
    let via = via.map_err(crate::idn::IdnFailure::kind)?;
    let mut line = trace::Line::new();
    line.text(format_args!("Alt-svc connecting from [{}]", src.name()));
    line.raw(origin.name());
    line.text(format_args!(":{} to [{}]", origin.port(), dst_alpn.name()));
    line.raw(via.name());
    line.text(format_args!(":{}", via.port()));
    trace::info_with(cx, &[line.bytes()]);
    let speaks = (src != dst_alpn).then_some(dst_alpn);
    let via = TryArc::try_new(via).map_err(oom)?;
    Ok(Some(AltSvc::Elsewhere { via, speaks }))
}

/// The search passed over connection `number`, as it speaks `version`,
/// which the transfer does not allow: the C debug build's line.
fn unwanted<H: Host>(
    cx: &mut StepCx<'_, H>,
    number: crate::conn::ConnNumber,
    version: crate::report::ResponseVersion,
) {
    use crate::report::ResponseVersion;
    let not = match version {
        ResponseVersion::Http3 => "h3",
        ResponseVersion::Http2 => "h2",
        ResponseVersion::Http10 | ResponseVersion::Http11 => "h1",
    };
    if cfg!(feature = "debug-hooks") {
        trace::info(
            cx,
            format_args!("not reusing conn {number}, we do not want {not}"),
        );
    }
}

/// A connection for the transfer making `proto`, and the trace of what
/// the search for one did.
/// `last` is the transfer's last connection, tried first and then
/// replaced by the one it gets.
fn acquire<H: Host>(
    cx: &mut StepCx<'_, H>,
    proto: &ProtoState,
    route: Route,
    dial: Dial,
) -> Result<Acquired, OutOfMemory> {
    let auth = &cx.easy().auth;
    let wants = match (proto, &route) {
        (ProtoState::Http(request), Route::Net(tcp)) => {
            request.reuse_wants(auth.host_want(), auth.proxy_want(), tcp)
        }
        _ => AuthWants::NONE,
    };
    let limits = cx.easy().options().limits.reuse;
    let rules = ReuseRules {
        max_idle: limits.max_idle.map(TimeLimit::duration),
        max_age: limits.max_age.map(TimeLimit::duration),
        // A redirect's request would reuse one anyway; one that only
        // connects never does (`url_attach_existing`).
        fresh: limits.fresh || cx.easy().options().connect_only.reserves(),
    };
    let mut notes = Vec::new();
    let now = cx.rest.now;
    let add = cx.rest.tell.limits.add();
    // The search and the addition, each a use of the pool of its own
    // (`Curl_cpool_find`, `Curl_cpool_add`).
    let home = match cx.rest.kept(cx.me, Kind::Connections) {
        Some(kept) => Home::Share(kept.share),
        None => Home::Multi,
    };
    let last = cx.easy().last_conn.map(|l| l.id);
    // What it allows, not only what it wants: a connection in HTTP/3 serves
    // one that asked for no version (`url_match_http_version`).
    let versions = proto.allowed_versions();
    // An HTTP transfer that may speak HTTP/2 or HTTP/3 shares a
    // connection that multiplexes, as the multi lets it
    // (`xfer_may_multiplex`).
    let http = matches!(proto, ProtoState::Http(_));
    let multiplex = (cx.rest.tell.limits.multiplex && http && (versions.h2 || versions.h3))
        .then_some(cx.rest.tell.limits.max_streams);
    let pipewait = cx.easy().options().http.pipewait;
    let found = if pool::searches(&route, rules) {
        let wanted = pool::Wanted {
            route: &route,
            auth: wants,
            last,
            versions,
            multiplex,
            pipewait,
            lending: pool::Lending::NONE,
        };
        // A share's connections lent to the multi are judged as the
        // multi's own, in the share's order.
        let lent = match &home {
            Home::Share(share) => {
                let tls = crate::conn::TlsWants::of(cx.easy());
                Some(cx.rest.caches.pool.lending(share, &wanted, tls)?)
            }
            _ => None,
        };
        let wanted = pool::Wanted {
            lending: lent.as_ref().map_or(pool::Lending::NONE, |l| l.lending()),
            ..wanted
        };
        cx.rest.pool_search(cx.me, &home, |pool, exits, here| {
            pool.find(here, wanted, rules, exits, now, &mut notes)
        })?
    } else {
        pool::Found::Nothing
    };
    // Said as the search passes them over, before a connection is made or
    // attached, as C's debug build says it in `url_match_http_version`.
    notes.retain(|note| match *note {
        PoolNote::Unwanted { number, version } => {
            unwanted(cx, number, version);
            false
        }
        _ => true,
    });
    // The rest are said as the search found them too, before a connection
    // is made or attached: of no connection yet (`url_match_conn`).
    for note in notes {
        match note {
            PoolNote::IdleTooLong { idle_ms, max_ms } => trace::info(
                cx,
                format_args!(
                    "Too old connection ({idle_ms} ms idle, max idle is {max_ms} ms), disconnect it"
                ),
            ),
            PoolNote::Dead(n) => {
                let n = n.get();
                trace::info(
                    cx,
                    format_args!("Connection {n} seems to be dead, terminating"),
                );
            }
            PoolNote::InputPending => trace::debug_info(
                cx,
                format_args!("connection has no transfer but input, not healthy"),
            ),
            PoolNote::Closed(n) => trace::info(cx, format_args!("shutting down connection {n}")),
            PoolNote::Unwanted { .. } => unreachable!("said as the search returns"),
            // The server's limit is said with no space before "reached",
            // as C says it.
            PoolNote::Full {
                number,
                users,
                peer,
            } => trace::info(
                cx,
                format_args!(
                    "connection {number}{}reached MAX_CONCURRENT_STREAMS({users}), skip",
                    if peer { "" } else { " " }
                ),
            ),
            PoolNote::Multiplexed => trace::info(cx, format_args!("Multiplexed connection found")),
            PoolNote::MaxConcurrent {
                number,
                max,
                in_use,
            } => trace_max_concurrent(cx, number, max, in_use),
            PoolNote::NotOpenEnough(n) => trace::info(
                cx,
                format_args!("Connection {n} is not open enough, cannot reuse"),
            ),
            PoolNote::PendingCandidate => trace::info(
                cx,
                format_args!("Found pending candidate for reuse and CURLOPT_PIPEWAIT is set"),
            ),
        }
    }
    let acquired = match found {
        pool::Found::Lease(lease) => Acquired::Reused(lease),
        pool::Found::Lent(id) => {
            let Home::Share(share) = &home else {
                unreachable!("only a share lends");
            };
            Acquired::Reused(cx.rest.caches.pool.join_lent(share, id))
        }
        pool::Found::Wait => Acquired::Wait(pool::WaitReason::Multiplex),
        pool::Found::Nothing => {
            // The connection closes its sockets as the transfer making it
            // says, whoever closes them (url.c's `fclosesocket`).
            let closer = match &cx.easy().options().sockets.close {
                Some(close) => Closer::Hook(close.clone()),
                None => Closer::System,
            };
            // What the connection keeps of the transfer's settings: C's
            // defaults, as no option sets them.
            let settings = ConnSettings::DEFAULT;
            let (added, members) = cx.rest.pool_search(cx.me, &home, |pool, exits, here| {
                pool.add(here, route, dial, closer, settings, add, exits, now)
                    .map(|added| (added, pool.len()))
            })?;
            if let Acquired::New(lease) = &added {
                let n = lease.number().get();
                mstate::trace(
                    cx,
                    format_args!(
                        "[CPOOL] added connection {n}. The cache now contains {members} members"
                    ),
                );
            }
            added
        }
    };
    // The transfer's connection from now on (`Curl_attach_connection`).
    if let Acquired::Reused(lease) | Acquired::New(lease) = &acquired {
        cx.report_mut().set_conn(Some(lease.number()));
        cx.easy_mut().last_conn = Some(crate::easy::LastConn {
            id: lease.id(),
            used: false,
        });
    }
    Ok(acquired)
}

/// Why a transfer's URL was not taken.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum UrlRefused {
    /// The parser's reason, which the transfer gives.
    Rejected(UrlErrorKind),
    /// Something else, without a reason given.
    Failed(ErrorKind),
}

/// A request's URL, parsed by the options' rules, given the default
/// scheme where it has none (`parseurlandfillconn`). The transfer's
/// `own` URL, read back from one parsed already, keeps any space the
/// application's URL handle allowed, as C goes on from that handle
/// (`state.uh`, `follow_parse_url`'s `CURLU_ALLOW_SPACE`); a location
/// followed is not its own, and C parses its text without
/// (`url_set_data_origin_and_creds` with `this_is_a_follow`).
pub(super) fn parse_url(url: &[u8], options: &Options, own: bool) -> Result<Url, UrlRefused> {
    let parse = ParseOptions {
        guess_scheme: true,
        non_support_scheme: true,
        disallow_user: options.url_rules.disallow_user,
        path_as_is: options.url_rules.path_as_is,
        allow_space: own,
        ..ParseOptions::NONE
    };
    let Some(default) = options.default_protocol() else {
        return Url::parse(url, parse).map_err(UrlRefused::Rejected);
    };
    // A path is no URL without `file:`, so for `file` the scheme is looked
    // for before parsing.
    if !default.eq_ignore_ascii_case(b"file") || url::has_scheme(url) {
        let parsed = Url::parse(url, parse).map_err(UrlRefused::Rejected)?;
        let no_guess = GetOptions {
            no_guess_scheme: true,
            ..GetOptions::NONE
        };
        match parsed.get(Part::Scheme, no_guess) {
            Ok(_) => return Ok(parsed),
            Err(UrlErrorKind::NoScheme) => {}
            Err(e) => return Err(UrlRefused::Failed(url_error(e))),
        }
    }
    let mut with_scheme = Vec::new();
    for part in [default, b"://", url] {
        with_scheme
            .try_extend_from_slice(part)
            .map_err(|_| UrlRefused::Failed(ErrorKind::OutOfMemory))?;
    }
    Url::parse(&with_scheme, parse).map_err(UrlRefused::Rejected)
}
