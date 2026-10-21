#!/usr/bin/env python3
"""
Generate the list of `CURLoption` ids libcurl knows.

`curl_easy_setopt` tells an option nobody knows (`CURLE_UNKNOWN_OPTION`)
from one this build does not have (`CURLE_NOT_BUILT_IN`); the options the
shim implements are matched by hand, and every other id is looked up
here. The ids come from the option inventory (options.json, "easy");
aliases share their target's id.
"""

import json
import pathlib

import genlib
from genlib import ROOT, check

OPTIONS = ROOT / "inventory" / "options.json"
OUT = ROOT / "crates" / "curl-sys-abi" / "src" / "setopt" / "known.rs"


def main():
    easy = json.loads(OPTIONS.read_text())["data"]["easy"]
    ids = {}
    for o in easy["options"]:
        check(o["id"] not in ids, f"{o['name']} shares id {o['id']}")
        ids[o["id"]] = o["name"]
    for a in easy["aliases"]:
        check(a["id"] in ids, f"alias {a['name']} has no target")
    here = pathlib.Path(__file__)
    out = [genlib.header(here, [OPTIONS, ROOT / "gen" / "genlib.py", here])]
    out.append("//! The `CURLoption` ids libcurl knows, sorted.\n\n")
    out.append("use core::ffi::c_int;\n\n")
    out.append("pub(super) static KNOWN: &[c_int] = &[\n")
    for i in sorted(ids):
        out.append(f"    {i}, // {ids[i]}\n")
    out.append("];\n")
    genlib.write(OUT, "".join(out))


if __name__ == "__main__":
    main()
