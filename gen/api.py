#!/usr/bin/env python3
"""
Generate the shim's table of calls made while another call runs.

`lib/api.c` lists, for each easy and multi API function, whether it may
be called while another API call on the same handle is in progress,
whether it is refused inside the multi's event callbacks (socket, timer)
and whether it is allowed inside a notify callback; lib/api.h sets how
deep calls may nest. The inventory carries these tables (abi.json,
"api-calls"); this writes them as Rust for the shim's gate.
"""

import json
import pathlib

import genlib
from genlib import ROOT, check

OUT = ROOT / "crates" / "curl-sys-abi" / "src" / "gate" / "table.rs"


def camel(name):
    return "".join(part.capitalize() for part in name.split("_"))


def main():
    calls = json.loads(genlib.ABI.read_text())["data"]["api-calls"]
    eapi, mapi, cbapi = calls["eapi"], calls["mapi"], calls["cbapi"]
    check(eapi["columns"] == ["data_is_killed", "recurse", "no_event_cb",
                              "no_scache_lock"],
          f"eapi columns changed: {eapi['columns']}")
    check(mapi["columns"] == ["multi_is_killed", "recurse", "allow_ntfy_cb",
                              "no_scache_lock"],
          f"mapi columns changed: {mapi['columns']}")
    check(cbapi["columns"] == ["is_event_cb"],
          f"cbapi columns changed: {cbapi['columns']}")
    event = [r["name"] for r in cbapi["rows"] if r["is_event_cb"]]
    check(event == ["multi_socket_cb", "multi_timer_cb"],
          f"the event callbacks changed: {event}")

    out = [genlib.header(pathlib.Path(__file__), [genlib.ABI])]
    out.append("//! What may be called while another API call runs "
               "(`lib/api.c`).\n\n")
    out.append("use super::{EasyRules, MultiRules};\n\n")
    for kind, enum, rules, table in (
            ("easy", "EasyCall", "EasyRules", eapi),
            ("multi", "MultiCall", "MultiRules", mapi)):
        out.append(f"/// An {kind} API function the gate admits.\n")
        out.append("#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n")
        out.append(f"pub(crate) enum {enum} {{\n")
        for r in table["rows"]:
            out.append(f"    {camel(r['name'].removeprefix(kind + '_'))},\n")
        out.append("}\n\n")
        out.append(f"/// How deep {kind} calls nest.\n")
        out.append(f"pub(crate) const {kind.upper()}_MAX_DEPTH: u8 = "
                   f"{table['max-recursion']};\n\n")
        out.append(f"impl {enum} {{\n")
        out.append(f"    pub(crate) const fn rules(self) -> {rules} {{\n")
        out.append("        match self {\n")
        for r in table["rows"]:
            variant = camel(r["name"].removeprefix(kind + "_"))
            if kind == "easy":
                fields = (f"kills: {bool(r['data_is_killed'])}".lower(),
                          f"recurse: {bool(r['recurse'])}".lower(),
                          f"not_in_event: {bool(r['no_event_cb'])}".lower())
            else:
                fields = (f"kills: {bool(r['multi_is_killed'])}".lower(),
                          f"recurse: {bool(r['recurse'])}".lower(),
                          f"in_notify: {bool(r['allow_ntfy_cb'])}".lower())
            out.append(f"            {enum}::{variant} => {rules} {{ "
                       f"{', '.join(fields)} }},\n")
        out.append("        }\n    }\n}\n\n")
    genlib.write(OUT, "".join(out).rstrip("\n") + "\n")


if __name__ == "__main__":
    main()
