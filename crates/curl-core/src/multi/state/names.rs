//! C's DNS filters' own lines (`lib/vdns/cf-dns.c`): each made as the
//! setup's chain is (`cf_dns_create`), started as its first connect
//! reaches it (`cf_dns_start`), and connected once the chain below it is
//! (`cf_dns_connect`). The engine resolves without filters; these say
//! what C's would, where they would.

use super::StepCx;
use crate::components::Component;
use crate::conn::{NetRoute, Peer};
use crate::multi::Host;
use crate::options::IpVersion;
use crate::text::Text;
use crate::trace;

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
    let dns = Component::Dns;
    trace::of_with(
        cx,
        dns,
        &[head.bytes(), peer.name(), at(peer).bytes(), tail.bytes()],
    );
    if added {
        trace::of(cx, dns, format_args!("added"));
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
pub(super) fn record_started<H: Host>(cx: &mut StepCx<'_, H>, route: &NetRoute) {
    let peer = route.target();
    trace::of_with(
        cx,
        Component::Dns,
        &[b"[HTTPS] cf_dns_start host ", peer.name(), at(peer).bytes()],
    );
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
    let dns = Component::Dns;
    trace::of_with(cx, dns, &[head.bytes(), peer.name(), at(peer).bytes()]);
    if unix && peer.name().len() < curl_os::net::UNIX_PATH_ROOM {
        trace::of_with(cx, dns, &[b"resolved unix://", peer.name()]);
    }
}

/// The chain below each of the `filters` DNS filters is connected, the
/// lowest first (`cf_dns_connect`).
pub(super) fn connected<H: Host>(cx: &mut StepCx<'_, H>, filters: usize) {
    for _ in 0..filters {
        trace::of(
            cx,
            Component::Dns,
            format_args!("connected filter chain below"),
        );
    }
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
        Component::Dns,
        &[head.bytes(), target.name(), at(target).bytes()],
    );
}
