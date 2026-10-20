#!/usr/bin/env python3
"""
Generate the curl tool's option table and its argument errors.

From inventory/cli.json (the `aliases[]` table of src/tool_getparam.c
and the texts of `param2text` in src/tool_helpers.c) and the CURLcode
values in inventory/abi.json:

  crates/curl-tool/src/options/table.rs: an `Opt` per option, its
  `Spec` (long name, short letter, argument kind, flags) in the C
  table's order, which is sorted for binary search, and the short-letter
  lookup;

  crates/curl-tool/src/options/errors.rs: `ParamError`, a kind per
  `PARAM_*` error with its text, the library error each exits with, and
  `exit_code`, the exit status of each library error (the CURLcode value,
  as docs/cmdline-opts/_EXITCODES.md documents).
"""

import json
import pathlib

import genlib
from genlib import ABI, ROOT, check

HERE = pathlib.Path(__file__).resolve()
CLI = ROOT / "inventory" / "cli.json"
TABLE_OUT = ROOT / "crates" / "curl-tool" / "src" / "options" / "table.rs"
ERRORS_OUT = ROOT / "crates" / "curl-tool" / "src" / "options" / "errors.rs"

# What each guard in the C table means for the Rust tool.
GUARDS = {
    None: "",
    # Both are on in the reference build; until implemented, the options
    # are recognised and exit as unimplemented.
    "!defined(CURL_DISABLE_HTTPSIG)": "",
    "!defined(CURL_DISABLE_IPFS)": "",
    "defined(DEBUGBUILD)": '#[cfg(feature = "debug-hooks")]',
    # Windows with the Watt-32 TCP/IP stack: out of scope.
    "defined(USE_WATT32)": None,
}

KINDS = {
    "ARG_NONE": "None",
    "ARG_BOOL": "Bool",
    "ARG_STRG": "String",
    "ARG_FILE": "File",
    "ARG_SECS": "Seconds",
    "ARG_UNUM": "Unsigned",
}

FLAGS = {
    "ARG_NO": "short_negates",
    "ARG_TLS": "needs_tls",
    "ARG_CLEAR": "secret",
    "ARG_DEPR": "deprecated",
}


def camel(name, prefix):
    check(name.startswith(prefix), f"{name} lacks {prefix}")
    return "".join(w.capitalize() for w in name[len(prefix):].split("_"))


def table(cli):
    entries = cli["option_table"]["entries"]
    for e in entries:
        check(e["guard"] in GUARDS, f"unknown guard {e['guard']}")
        check(e["type"] in KINDS, f"unknown type {e['type']}")
        check(set(e["flags"]) <= set(FLAGS), f"unknown flags {e['flags']}")
    longs = [e["long"].encode() for e in entries]
    check(longs == sorted(longs), "the C table is not sorted by long name")
    check(len(set(longs)) == len(longs), "duplicate long names")
    kept = [e for e in entries if GUARDS[e["guard"]] is not None]
    max_len = max(len(e["long"]) for e in entries)
    check(max_len == cli["option_table"]["max_option_len_in_getparameter"],
          "MAX_OPTION_LEN differs from the longest option name")

    variants = []
    specs = []
    for e in kept:
        cfg = GUARDS[e["guard"]]
        attr = f"    {cfg}\n" if cfg else ""
        name = camel(e["cmd"], "C_")
        variants.append(f"{attr}    /// `--{e['long']}`\n    {name},\n")
        short = f"Some(b'{e['short']}')" if e["short"] else "None"
        flags = "".join(f"\n        {FLAGS[f]}: {'true' if f in e['flags'] else 'false'},"
                        for f in FLAGS)
        specs.append(f"""{attr}    Spec {{
        long: "{e['long']}",
        short: {short},
        opt: Opt::{name},
        kind: ArgKind::{KINDS[e['type']]},{flags}
    }},
""")
    check(len(set(variants)) == len(variants), "duplicate commands")
    return f"""{genlib.header(HERE, [CLI, ROOT / 'gen' / 'genlib.py', HERE])}\
//! The options of `src/tool_getparam.c`'s `aliases[]` table.

use super::{{ArgKind, Spec}};

/// The longest long option name, without its `--`.
pub(crate) const MAX_OPTION_LEN: usize = {max_len};

/// An option, by what it does rather than how it is spelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Opt {{
{"".join(variants)}}}

/// Every option, sorted by long name, as `findlongopt` searches them.
pub(crate) static OPTIONS: &[Spec] = &[
{"".join(specs)}];
"""


def errors(cli, abi):
    texts = cli["exit_codes"]["param2text"]["messages"]
    mapping = cli["exit_codes"]["parse_args_error_to_exit"]
    exits = {m["param"]: m["result"] for m in mapping["specific"]}
    check(set(exits) <= {t["param"] for t in texts},
          f"exit mapping for errors without text: {exits}")
    kinds = []
    arms = []
    exit_arms = []
    for t in texts:
        name = camel(t["param"], "PARAM_")
        kinds.append(f"    /// {t['text']}\n    {name},\n")
        arms.append(f"            ParamError::{name} => {json.dumps(t['text'])},\n")
        result = exits.get(t["param"], mapping["default"])
        exit_arms.append(f"            ParamError::{name} => "
                         f"ErrorKind::{camel(result, 'CURLE_')},\n")
    codes = {c["name"]: int(c["value"]) for c in abi["constants"]
             if c.get("enum") == "CURLcode"}
    members = next(e["members"] for e in abi["enums"]
                   if e["typedef"] == "CURLcode")
    messages = abi["strerror"]["curl_easy_strerror"]["messages"]
    code_arms = []
    for m in members:
        if m in messages and m != "CURLE_OK":
            check(0 < codes[m] < 256, f"{m} does not fit an exit status")
            code_arms.append(f"        ErrorKind::{camel(m, 'CURLE_')} => "
                             f"{codes[m]},\n")
    return f"""{genlib.header(HERE, [CLI, ABI, ROOT / 'gen' / 'genlib.py', HERE])}\
//! Why the command line was rejected, and the exit status of each error.

use std::fmt;

use curl_core::error::ErrorKind;

/// Why an option or its argument was rejected, as `param2text` words it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParamError {{
{"".join(kinds)}}}

impl ParamError {{
    pub(crate) fn text(self) -> &'static str {{
        match self {{
{"".join(arms)}        }}
    }}

    /// The library error the tool exits with.
    pub(crate) fn kind(self) -> ErrorKind {{
        match self {{
{"".join(exit_arms)}        }}
    }}
}}

impl fmt::Display for ParamError {{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {{
        f.write_str(self.text())
    }}
}}

/// The exit status for an error: its CURLcode value.
pub(crate) fn exit_code(kind: ErrorKind) -> u8 {{
    match kind {{
{"".join(code_arms)}    }}
}}
"""


def main():
    cli = json.loads(CLI.read_text())["data"]
    abi = json.loads(ABI.read_text())["data"]
    TABLE_OUT.parent.mkdir(exist_ok=True)
    genlib.write(TABLE_OUT, table(cli))
    genlib.write(ERRORS_OUT, errors(cli, abi))


if __name__ == "__main__":
    main()
