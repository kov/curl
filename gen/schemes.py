#!/usr/bin/env python3
"""
Generate the table of URL schemes libcurl knows, and the protocols they
are of.

From the `Curl_scheme_*` structs of lib/protocol.c, the `PORT_*`,
`PROTOPT_*` and `CURLPROTO_*` values of lib/protocol.h, and the public
`CURLPROTO_*` bits of include/curl/curl.h:

  crates/curl-core/src/url/schemes.rs: each protocol a scheme is of (a
  `Protocol`, without C's bit), and each scheme's name, protocol, family
  (the protocol without TLS), default port, flags (C's `PROTOPT_*`, each
  a named bool) and whether the reference build implements it
  (inventory/baseline.json's protocols).

  crates/curl-sys-abi/src/protocols.rs: each protocol's `CURLPROTO_*` bit
  and the name C's `CURLINFO_SCHEME` and `curl_version_info` give it.

A scheme is known whether or not a build implements it: the URL API
parses `ldap://` in a build without LDAP, as C's does, and only setting
the scheme alone asks for one implemented (C's `run`).
"""

import json
import pathlib
import re

import genlib
from genlib import ROOT, check

HERE = pathlib.Path(__file__).resolve()
PROTOCOL_C = ROOT / "lib" / "protocol.c"
PROTOCOL_H = ROOT / "lib" / "protocol.h"
CURL_H = ROOT / "include" / "curl" / "curl.h"
OUT = ROOT / "crates" / "curl-core" / "src" / "url" / "schemes.rs"
SHIM_OUT = ROOT / "crates" / "curl-sys-abi" / "src" / "protocols.rs"
BASELINE = ROOT / "inventory" / "baseline.json"

# Each of C's flags by the name the Rust table gives it, and what it says.
FLAGS = {
    "SSL": ("ssl", "Over TLS from the start."),
    "DUAL": ("dual", "Uses two connections."),
    "CLOSEACTION": ("close_action", "Says something before its connection closes."),
    "DIRLOCK": ("dir_lock", "Sends and receives as its own state says, not as the socket does."),
    "NONETWORK": ("no_network", "Does not use the network."),
    "NEEDSPWD": ("needs_password", "Needs a password, given a default if none is set."),
    "NOURLQUERY": ("no_url_query", "Cannot take a URL's query."),
    "CREDSPERREQUEST": ("creds_per_request",
                        "Takes credentials per request, not per connection."),
    "ALPN": ("alpn", "Offers ALPN."),
    "URLOPTIONS": ("url_options", "Its URLs may carry `;options` after the user name."),
    "PROXY_AS_HTTP": ("proxy_as_http",
                      "May go through an HTTP proxy that speaks it as a gateway."),
    "WILDCARD": ("wildcard", "Matches wildcards."),
    "USERPWDCTRL": ("user_password_ctrl",
                    "Takes control bytes in its user name and password."),
    "NOTCPPROXY": ("no_tcp_proxy", "Cannot go through a proxy over TCP."),
    "SSL_REUSE": ("ssl_reuse",
                  "May reuse a TLS connection of its family, not being over TLS itself."),
    "CONN_REUSE": ("conn_reuse", "Keeps its connections for another transfer."),
    "NO_TRANSFER": ("no_transfer", "Is not for transfers."),
    "HTTP_PROXY_TUNNEL": ("http_proxy_tunnel", "Tunnels through an HTTP proxy."),
}


def variant(proto):
    """`POP3S` as a Rust variant, `Pop3s`."""
    return proto[0] + proto[1:].lower()


def main():
    built = set(json.loads(BASELINE.read_text())["data"]["protocols"])
    header_text = PROTOCOL_H.read_text()
    ports = {m[1]: int(m[2]) for m in
             re.finditer(r"#define (PORT_\w+)\s+(\d+)", header_text)}
    defined = set(re.findall(r"#define PROTOPT_(\w+)\s", header_text)) - {"NONE"}
    check(defined == set(FLAGS),
          f"PROTOPT_* in protocol.h and FLAGS differ: {sorted(defined ^ set(FLAGS))}")
    bits = {}
    for text in (CURL_H.read_text(), header_text):
        for m in re.finditer(r"#define CURLPROTO_(\w+)\s+\((?:\(\w+\))?1L{0,2}\s*<<\s*(\d+)\)",
                             text):
            bits[m[1]] = int(m[2])
    src = re.sub(r"/\*.*?\*/", "", PROTOCOL_C.read_text(), flags=re.DOTALL)
    blocks = re.findall(r"const struct Curl_scheme Curl_scheme_(\w+) = \{(.*?)\};",
                        src, flags=re.DOTALL)
    check(len(blocks) >= 30, f"only {len(blocks)} schemes in protocol.c")
    looked_up = set(re.findall(r"&Curl_scheme_(\w+)", src))
    rows = []
    for ident, body in blocks:
        check(ident in looked_up, f"Curl_scheme_{ident} is not looked up")
        name = re.search(r'"([a-z0-9]+)"', body)[1]
        defport = body.strip().rstrip(",").split()[-1]
        port = ports.get(defport, None) if defport != "0" else 0
        check(port is not None, f"unknown default port {defport} of {name}")
        protos = re.findall(r"\bCURLPROTO_(\w+)", body)
        check(len(protos) == 2, f"{name} names {protos}, not its protocol and family")
        for p in protos:
            check(p in bits, f"no bit for CURLPROTO_{p} of {name}")
        flags = set(re.findall(r"\bPROTOPT_(\w+)", body)) - {"NONE"}
        check(flags <= set(FLAGS), f"unknown flags {sorted(flags - set(FLAGS))} of {name}")
        rows.append((name, protos[0], protos[1], port, flags, name in built))
    check(len({r[0] for r in rows}) == len(rows), "duplicate scheme names")
    check(all(2 <= len(r[0]) <= 7 for r in rows),
          "Curl_getn_scheme looks up names of 2 to 7 letters only")
    rows.sort()
    protocols = sorted({r[1] for r in rows} | {r[2] for r in rows}, key=lambda p: bits[p])
    # A protocol is named as its first scheme (`socks` for SOCKS's five).
    names = {}
    for name, proto, *_ in rows:
        names.setdefault(proto, name)
    check(set(names) == set(protocols), "a family no scheme is of")

    variants = "".join(f"    {variant(p)},\n" for p in protocols)
    all_list = "".join(f"        Protocol::{variant(p)},\n" for p in protocols)
    name_arms = "".join(f'            Protocol::{variant(p)} => "{names[p]}",\n'
                        for p in protocols)
    no_flags = "".join(f"        {field}: false,\n" for field, _ in FLAGS.values())
    flag_fields = "".join(f"    /// {doc}\n    pub(crate) {field}: bool,\n"
                          for field, doc in FLAGS.values())

    def row(name, proto, family, port, flags, b):
        set_flags = "".join(
            f"            {field}: {str(c in flags).lower()},\n"
            for c, (field, _) in FLAGS.items())
        return (f"    Known {{\n"
                f'        name: "{name}",\n'
                f"        protocol: Some(Protocol::{variant(proto)}),\n"
                f"        family: Some(Protocol::{variant(family)}),\n"
                f"        default_port: {port},\n"
                f"        flags: Flags {{\n{set_flags}        }},\n"
                f"        built: {str(b).lower()},\n"
                f"    }},\n")

    table = "".join(row(*r) for r in rows)
    inputs = [PROTOCOL_C, PROTOCOL_H, BASELINE, ROOT / 'gen' / 'genlib.py', HERE]
    genlib.write(OUT, f"""{genlib.header(HERE, inputs)}\
//! The schemes `Curl_getn_scheme` in lib/protocol.c knows, and the
//! protocols they are of.

/// A protocol libcurl knows, implemented in this build or not (C's
/// `CURLPROTO_*`): one or more schemes are of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Protocol {{
{variants}}}

impl Protocol {{
    /// Every protocol, each at its `index`.
    pub const ALL: [Protocol; {len(protocols)}] = [
{all_list}    ];

    /// Its place in `ALL`.
    pub const fn index(self) -> usize {{
        self as usize
    }}

    /// Its name: its scheme's, the first of them for SOCKS.
    pub const fn name(self) -> &'static str {{
        match self {{
{name_arms}        }}
    }}
}}

/// What C's flags say of a scheme (`PROTOPT_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "C's flags, read as each protocol comes")]
pub(crate) struct Flags {{
{flag_fields}}}

impl Flags {{
    /// None of them, as the tests' own schemes start from.
    #[cfg(any(test, feature = "test-util"))]
    pub(crate) const NONE: Flags = Flags {{
{no_flags}    }};
}}

/// A scheme libcurl knows, implemented in this build or not.
#[derive(Debug)]
pub(crate) struct Known {{
    pub(crate) name: &'static str,
    /// The protocol it is of; none for the tests' own schemes, which C's
    /// table does not have.
    pub(crate) protocol: Option<Protocol>,
    /// Its protocol without TLS (C's `family`): an `imaps` connection
    /// may serve `imap`.
    pub(crate) family: Option<Protocol>,
    pub(crate) default_port: u16,
    pub(crate) flags: Flags,
    /// The reference build implements it (C's `run`).
    pub(crate) built: bool,
}}

/// Every known scheme, sorted by name.
pub(crate) static KNOWN: &[Known] = &[
{table}];
""")

    bit_list = "".join(f"    1 << {bits[p]},\n" for p in protocols)
    name_list = "".join(f'    c"{names[p]}",\n' for p in protocols)
    genlib.write(SHIM_OUT, f"""\
{genlib.header(HERE, [PROTOCOL_C, PROTOCOL_H, CURL_H, ROOT / 'gen' / 'genlib.py', HERE])}\
//! Each protocol libcurl knows as C names it: its `CURLPROTO_*` bit and
//! its scheme's name, at the protocol's `index`.

use std::ffi::CStr;

use curl_core::version::Protocol;

/// Each protocol's bit (`CURLPROTO_*`), at its `index`.
#[rustfmt::skip]
pub(crate) static BITS: [i64; Protocol::ALL.len()] = [
{bit_list}];

/// Each protocol's scheme name, as C's scheme table spells it: one
/// string for the process, as the application may compare its address.
#[rustfmt::skip]
pub(crate) static NAMES: [&CStr; Protocol::ALL.len()] = [
{name_list}];
""")


if __name__ == "__main__":
    main()
