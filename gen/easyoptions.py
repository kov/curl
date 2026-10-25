#!/usr/bin/env python3
"""
Generate the table `curl_easy_option_by_name`, `curl_easy_option_by_id`
and `curl_easy_option_next` walk (C's `Curl_easyopts`).

The rows are C's, from lib/easyoptions.c (which lib/optiontable.pl makes
from curl.h): each option by its name without `CURLOPT_`, in that file's
order, with its id, its type and whether it is an alias. Each row is
checked against the option inventory (options.json, "easy"): the id is
the option's, or for an alias its target's, and the type is the one the
inventory gives.
"""

import json
import re

import genlib
from genlib import ROOT, check

OPTIONS = ROOT / "inventory" / "options.json"
TABLE = ROOT / "lib" / "easyoptions.c"
OUT = ROOT / "crates" / "curl-sys-abi" / "src" / "easyoptions.rs"

ROW = re.compile(r'\{ "([A-Z0-9_]+)",\s+(CURLOPT_[A-Z0-9_]+),\s+(CURLOT_[A-Z_]+),\s+'
                 r'(0|CURLOT_FLAG_ALIAS) \},')


def main():
    easy = json.loads(OPTIONS.read_text())["data"]["easy"]
    by_name = {o["name"]: o for o in easy["options"]}
    aliases = {a["name"]: a for a in easy["aliases"]}
    rows = []
    for m in ROW.finditer(TABLE.read_text()):
        name, symbol, curlot, flags = m.groups()
        alias = flags == "CURLOT_FLAG_ALIAS"
        check(symbol == f"CURLOPT_{name}" or alias, f"{name} names {symbol}")
        if alias:
            a = aliases.get(f"CURLOPT_{name}")
            check(a is not None, f"alias {name} is not in the inventory")
            check(a["target"] == symbol, f"alias {name} targets {a['target']}, not {symbol}")
        o = by_name.get(symbol)
        check(o is not None, f"{symbol} is not in the inventory")
        check(o["curlot"] == curlot, f"{name} is {curlot}, the inventory says {o['curlot']}")
        rows.append((name, o["id"], curlot, alias))
    check(len(rows) == easy["easyoptions_c"]["rows"],
          f"{len(rows)} rows, the inventory counts {easy['easyoptions_c']['rows']}")
    here = __import__("pathlib").Path(__file__)
    out = [genlib.header(here, [OPTIONS, TABLE, ROOT / "gen" / "genlib.py", here])]
    out.append("//! The easy options, as `curl_easy_option_*` walk them (`Curl_easyopts`):\n")
    out.append("//! C's rows, in C's order, ended by a row of nothing.\n\n")
    out.append("use crate::easyoption::Row;\n")
    out.append("#[rustfmt::skip]\nuse crate::ffi::{")
    out.append(", ".join(["CURLoption"] + sorted({c for _, _, c, _ in rows})))
    out.append("};\n\n")
    out.append("/// The options, then a row with no name.\n#[rustfmt::skip]\n")
    out.append(f"pub(crate) static ROWS: [Row; {len(rows) + 1}] = [\n")
    for name, oid, curlot, alias in rows:
        flags = 1 if alias else 0
        out.append(f'    Row::new(c"{name}", CURLoption({oid}), {curlot}, {flags}),\n')
    out.append("    Row::END,\n")
    out.append("];\n")
    genlib.write(OUT, "".join(out))


if __name__ == "__main__":
    main()
