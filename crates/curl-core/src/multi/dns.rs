//! A transfer's resolves by its resolver library.

use super::{Host, StepCx};
use crate::components::Component;
use crate::conn::io::{DnsAsk, DnsRefused, DnsResolve, Family};
use crate::options::DnsOptions;

/// A resolve of `name` on `port` by the transfer's library if it has one:
/// the addresses of `family`, or with none its HTTPS record. The settings
/// are the transfer's, unless DoH's own transfers inherit them.
pub(crate) fn start<H: Host>(
    cx: &mut StepCx<'_, H>,
    name: &[u8],
    port: u16,
    family: Option<Family>,
) -> Option<Result<Box<dyn DnsResolve>, DnsRefused>> {
    let library = cx.easy().libraries().dns?;
    let dns = cx.easy().options().dns.try_clone_for_resolve();
    let dns: DnsOptions = match dns {
        Ok(dns) => dns,
        Err(_) => return Some(Err(DnsRefused::OutOfMemory)),
    };
    let ask = DnsAsk {
        name,
        port,
        family,
        stream: true,
        options: &dns,
    };
    let mut say = |parts: &[&[u8]]| crate::trace::of_with(cx, Component::Dns, parts);
    Some(library.resolve(ask, &mut say))
}
