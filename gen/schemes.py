#!/usr/bin/env python3
"""
Generate the table of URL schemes libcurl knows, for the URL parser.

From the `Curl_scheme_*` structs of lib/protocol.c and the `PORT_*`
values of lib/protocol.h:

  crates/curl-core/src/url/schemes.rs: each scheme's name, default port,
  and whether its URLs carry `;options` after the user name.

A scheme is known whether or not this build implements it: the URL API
accepts `ldap://` in a build without LDAP, as C's does.
"""

import pathlib
import re

import genlib
from genlib import ROOT, check

HERE = pathlib.Path(__file__).resolve()
PROTOCOL_C = ROOT / "lib" / "protocol.c"
PROTOCOL_H = ROOT / "lib" / "protocol.h"
OUT = ROOT / "crates" / "curl-core" / "src" / "url" / "schemes.rs"


def main():
    ports = {m[1]: int(m[2]) for m in
             re.finditer(r"#define (PORT_\w+)\s+(\d+)", PROTOCOL_H.read_text())}
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
        options = "PROTOPT_URLOPTIONS" in body
        rows.append((name, port, options))
    check(len({r[0] for r in rows}) == len(rows), "duplicate scheme names")
    check(all(2 <= len(r[0]) <= 7 for r in rows),
          "Curl_getn_scheme looks up names of 2 to 7 letters only")
    table = "".join(
        f'    Known {{ name: "{n}", default_port: {p}, url_options: {str(o).lower()} }},\n'
        for n, p, o in sorted(rows))
    genlib.write(OUT, f"""{genlib.header(HERE, [PROTOCOL_C, PROTOCOL_H, ROOT / 'gen' / 'genlib.py', HERE])}\
//! The schemes `Curl_getn_scheme` in lib/protocol.c knows.

/// A scheme libcurl knows, implemented in this build or not.
pub(super) struct Known {{
    pub(super) name: &'static str,
    pub(super) default_port: u16,
    /// Its URLs may carry `;options` after the user name.
    pub(super) url_options: bool,
}}

/// Every known scheme, sorted by name.
pub(super) static KNOWN: &[Known] = &[
{table}];
""")


if __name__ == "__main__":
    main()
