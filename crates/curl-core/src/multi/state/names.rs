//! C's DNS filters' own lines (`lib/vdns/cf-dns.c`): each made as the
//! setup's chain is (`cf_dns_create`), started as its first connect
//! reaches it (`cf_dns_start`), and connected once the chain below it is
//! (`cf_dns_connect`). The engine resolves without filters; these say
//! what C's would, where they would.

use super::{ConnRank, StepCx};
use crate::components::Component;
use crate::conn::asyncs::Holder;
use crate::conn::asyncs::ResolveNumber;
use crate::conn::{NetRoute, Peer};
use crate::multi::Host;
use crate::options::IpVersion;
use crate::text::Text;
use crate::trace;
use curl_alloc::OutOfMemory;

/// The address queries a DNS filter asks for a name, from the IP version
/// alone (`Curl_resolv_dns_queries`): an address's own family is no
/// part of it.
fn queries(ip: IpVersion, ipv6_works: bool) -> &'static str {
    match ip {
        IpVersion::V4 => "A",
        IpVersion::V6 => "AAAA",
        IpVersion::Any if ipv6_works => "A+AAAA",
        IpVersion::Any => "A",
    }
}

/// `:port`, as the filters' lines show it after a name.
fn at(peer: &Peer) -> Text<8> {
    Text::clipped(format_args!(":{}", peer.port())).0
}

/// A DNS filter for `peer` asking `queries` is made, and `added` at the
/// chain's end when it is its first (`cf_dns_add`), not put after
/// another (`cf_dns_insert_after`).
fn created<H: Host>(
    cx: &mut StepCx<'_, H>,
    queries: &str,
    peer: &Peer,
    transport: u8,
    added: bool,
) {
    let head = Text::<48>::clipped(format_args!("[{queries}] created DNS filter for ")).0;
    let tail = Text::<24>::clipped(format_args!(", transport={transport:x}")).0;
    trace::of_with(
        cx,
        Component::Dns,
        &[head.bytes(), peer.name(), at(peer).bytes(), tail.bytes()],
    );
    if added {
        trace::of(cx, Component::DnsFilter, format_args!("added"));
    }
}

/// The chain is set up over `route` (`Curl_conn_setup`): the filter
/// asking for the origin's HTTPS record first, if one is asked for
/// (`Curl_conn_dns_add_https_resolve`), then the one for the addresses
/// of the peer connected to, put after it. The transport is what the
/// connection wants (`transport_wanted`): a Unix socket's, QUIC's where
/// an alternative service switched the origin to HTTP/3, else TCP's.
pub(super) fn chain_set_up<H: Host>(
    cx: &mut StepCx<'_, H>,
    route: &NetRoute,
    record: bool,
    wants_quic: bool,
) {
    let first = route.destination();
    let transport = if first.is_unix() {
        6
    } else if wants_quic {
        5
    } else {
        3
    };
    if record {
        created(cx, "HTTPS", route.target(), transport, true);
    }
    let queries = queries(route.ip, cx.rest.ipv6_works);
    created(cx, queries, first, transport, !record);
}

/// The HTTPS record's filter starts, for the origin (`cf_dns_start`).
/// Over a Unix socket it asks for no record: the socket's path is made its
/// address at once, as the addresses' filter makes it (`resolv_unix`).
pub(super) fn record_started<H: Host>(cx: &mut StepCx<'_, H>, route: &NetRoute) {
    let peer = route.target();
    let unix = peer.is_unix();
    let head: &[u8] = if unix {
        b"[HTTPS] cf_dns_start unix-domain-socket "
    } else {
        b"[HTTPS] cf_dns_start host "
    };
    trace::of_with(
        cx,
        Component::DnsFilter,
        &[head, peer.name(), at(peer).bytes()],
    );
    resolved_unix(cx, peer);
}

/// The addresses' filter starts, for the peer connected to
/// (`cf_dns_start`): a Unix socket's path is its address, made at once
/// and reported (`resolv_unix`, `cf_dns_report`) unless it is too long
/// for one.
pub(super) fn started<H: Host>(cx: &mut StepCx<'_, H>, route: &NetRoute) {
    let peer = route.destination();
    let queries = queries(route.ip, cx.rest.ipv6_works);
    let unix = peer.is_unix();
    let kind = if unix { "unix-domain-socket" } else { "host" };
    let head = Text::<48>::clipped(format_args!("[{queries}] cf_dns_start {kind} ")).0;
    let dns = Component::DnsFilter;
    trace::of_with(cx, dns, &[head.bytes(), peer.name(), at(peer).bytes()]);
    resolved_unix(cx, peer);
}

/// A Unix socket's path made its address, reported unless it is too long
/// for one (`resolv_unix`, `cf_dns_report`); nothing for a name.
fn resolved_unix<H: Host>(cx: &mut StepCx<'_, H>, peer: &Peer) {
    let unix = peer.is_unix();
    if unix && peer.name().len() < curl_os::net::UNIX_PATH_ROOM {
        trace::of_with(
            cx,
            Component::DnsFilter,
            &[b"resolved unix://", peer.name()],
        );
    }
}

/// The chain below each of the DNS filters of the chain set up for
/// `rank` is connected, the lowest first: the SOCKS proxy's target's if it
/// is resolved here, the first hop's, and the origin's HTTPS record's if
/// one is asked for. Each lets go of its resolve's record
/// (`cf_dns_connect`'s `Curl_resolv_destroy`).
pub(super) fn connected<H: Host>(
    cx: &mut StepCx<'_, H>,
    rank: ConnRank,
    target: bool,
    record: bool,
) {
    let filters = [
        target.then_some(Holder::Target),
        Some(Holder::Addresses(rank)),
        record.then_some(Holder::Record),
    ];
    for holder in filters.into_iter().flatten() {
        trace::of(
            cx,
            Component::DnsFilter,
            format_args!("connected filter chain below"),
        );
        let gone = cx.easy_mut().asyncs.take(holder);
        if let Some(id) = gone {
            said(cx, id, "destroy");
        }
    }
}

/// A record of a resolve that answers later kept for `holder`, numbered
/// by the multi (`hostip_async_new`).
pub(crate) fn async_kept<H: Host>(
    cx: &mut StepCx<'_, H>,
    holder: Holder,
) -> Result<(), OutOfMemory> {
    let id = cx.rest.caches.resolves.next();
    cx.easy_mut().asyncs.keep(id, holder)
}

/// The newest of `holder`'s told it is no longer needed, its answer found
/// in the cache meanwhile (`Curl_resolv_take_result`'s
/// `Curl_async_shutdown`).
pub(crate) fn async_shut<H: Host>(cx: &mut StepCx<'_, H>, holder: Holder) {
    if let Some(id) = cx.easy().asyncs.newest(holder) {
        said(cx, id, "shutdown");
    }
}

/// The newest of `holder`'s let go of (`Curl_async_destroy`).
pub(crate) fn async_gone<H: Host>(cx: &mut StepCx<'_, H>, holder: Holder) {
    if let Some(id) = cx.easy_mut().asyncs.take(holder) {
        said(cx, id, "destroy");
    }
}

/// The transfer is done: each record still kept told so, the newest
/// first, and kept until the handle lets go of them (`multi_done`'s
/// `Curl_resolv_shutdown_all`).
pub(crate) fn asyncs_done<H: Host>(cx: &mut StepCx<'_, H>) {
    let mut n = 0;
    while let Some(id) = cx.easy().asyncs.nth_newest(n) {
        said(cx, id, "shutdown");
        n += 1;
    }
}

/// The request starts from nothing: each record still kept let go of, the
/// newest first (`Curl_req_hard_reset`'s `Curl_resolv_destroy_all`).
pub(crate) fn asyncs_let_go<H: Host>(cx: &mut StepCx<'_, H>) {
    while let Some(id) = cx.easy_mut().asyncs.pop_newest() {
        said(cx, id, "destroy");
    }
}

/// `[N] shutdown async` or `[N] destroy async`.
fn said<H: Host>(cx: &mut StepCx<'_, H>, id: ResolveNumber, what: &str) {
    let id = id.get();
    trace::of(cx, Component::Dns, format_args!("[{id}] {what} async"));
}

/// The SOCKS proxy's target, resolved here, has a DNS filter of its own,
/// asking in the families `ip` allows, put after the others
/// (`socks_proxy_cf_insert_after`).
pub(super) fn target_created<H: Host>(cx: &mut StepCx<'_, H>, target: &Peer, ip: IpVersion) {
    let queries = queries(ip, cx.rest.ipv6_works);
    created(cx, queries, target, 3, false);
}

/// The SOCKS proxy's target's filter starts as the handshake does
/// (`cf_dns_start`).
pub(super) fn target_started<H: Host>(cx: &mut StepCx<'_, H>, target: &Peer, ip: IpVersion) {
    let queries = queries(ip, cx.rest.ipv6_works);
    let head = Text::<32>::clipped(format_args!("[{queries}] cf_dns_start host ")).0;
    trace::of_with(
        cx,
        Component::DnsFilter,
        &[head.bytes(), target.name(), at(target).bytes()],
    );
}
