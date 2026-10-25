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

  crates/curl-tool/src/options/help.rs: the lines of `--help`, from
  src/tool_listhelp.c, and its categories, from src/tool_help.c;

  crates/curl-tool/src/options/errors.rs: `ParamError`, a kind per
  `PARAM_*` error with its text, the library error each exits with, and
  `exit_code`, the exit status of each library error (the CURLcode value,
  as docs/cmdline-opts/_EXITCODES.md documents);

and from the `setopt_nv_*` tables of src/tool_setopt.c, with their
values from inventory/abi.json:

  crates/curl-tool/src/easysrc/names.rs: the names `--libcurl` writes
  for an option's values, and the curl.h constants the tool's encoders
  pass.
"""

import json
import pathlib
import re

import genlib
from errors import SHIM_ONLY
from genlib import ABI, ROOT, check

HERE = pathlib.Path(__file__).resolve()
CLI = ROOT / "inventory" / "cli.json"
TABLE_OUT = ROOT / "crates" / "curl-tool" / "src" / "options" / "table.rs"
ERRORS_OUT = ROOT / "crates" / "curl-tool" / "src" / "options" / "errors.rs"
HELP_OUT = ROOT / "crates" / "curl-tool" / "src" / "options" / "help.rs"
TOOL_SETOPT = ROOT / "src" / "tool_setopt.c"
NAMES_OUT = ROOT / "crates" / "curl-tool" / "src" / "easysrc" / "names.rs"

# Each `setopt_nv_*` table of src/tool_setopt.c: the Rust name the tool
# reads it by, or None where the tool sets no option it names yet. A
# table missing here fails the generator.
NV_TABLES = {
    "CURLPROXY": "PROXY_TYPES",
    "CURL_SOCKS_PROXY": None,
    "CURLHSTS": None,
    "CURLAUTH": "AUTH",
    "CURL_HTTP_VERSION": "HTTP_VERSIONS",
    "CURL_SSLVERSION": "SSL_VERSIONS",
    "CURL_SSLVERSION_MAX": "SSL_VERSIONS_MAX",
    "CURL_TIMECOND": "TIME_CONDITIONS",
    "CURLFTPSSL_CCC": None,
    "CURLUSESSL": None,
    "CURLSSLOPT": "SSL_OPTIONS",
    "CURL_NETRC": "NETRC",
    "CURLOPT_FOLLOWLOCATION": None,
    "CURLNONZERODEFAULTS": "NONZERO_DEFAULTS",
}

# The curl.h constants the tool's encoders pass by name.
NV_CONSTANTS = [
    "CURLPROXY_HTTP", "CURLPROXY_HTTP_1_0", "CURLPROXY_HTTPS", "CURLPROXY_HTTPS2",
    "CURLPROXY_SOCKS4", "CURLPROXY_SOCKS5", "CURLPROXY_SOCKS4A",
    "CURLPROXY_SOCKS5_HOSTNAME", "CURLPROXY_HTTPS3",
    "CURL_HTTP_VERSION_1_0", "CURL_HTTP_VERSION_1_1", "CURL_HTTP_VERSION_2_0",
    "CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE",
    "CURL_SSLVERSION_TLSv1_0", "CURL_SSLVERSION_TLSv1_1", "CURL_SSLVERSION_TLSv1_2",
    "CURL_SSLVERSION_TLSv1_3",
    "CURL_SSLVERSION_MAX_NONE", "CURL_SSLVERSION_MAX_TLSv1_0",
    "CURL_SSLVERSION_MAX_TLSv1_1", "CURL_SSLVERSION_MAX_TLSv1_2",
    "CURL_SSLVERSION_MAX_TLSv1_3",
    "CURLAUTH_BASIC", "CURLAUTH_DIGEST", "CURLAUTH_GSSAPI", "CURLAUTH_BEARER",
    "CURLAUTH_AWS_SIGV4", "CURLAUTH_HTTPSIG", "CURLAUTH_ONLY", "CURLAUTH_ANY",
]

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
        # The tool uses the Rust API, which never gives the codes only
        # libcurl's C API produces.
        if (m in messages and m != "CURLE_OK"
                and m not in SHIM_ONLY["CURLcode"]):
            check(0 < codes[m] < 256, f"{m} does not fit an exit status")
            code_arms.append(f"        ErrorKind::{camel(m, 'CURLE_')} => "
                             f"{codes[m]},\n")
    inputs = [CLI, ABI, ROOT / 'gen' / 'genlib.py', ROOT / 'gen' / 'errors.py',
              HERE]
    return f"""{genlib.header(HERE, inputs)}\
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


def help_table(cli):
    lines = []
    for e in cli["tool_listhelp_entries"]:
        check(GUARDS.get(e["guard"]) == "", f"unexpected help guard {e['guard']}")
        cats = ", ".join(json.dumps(c) for c in e["categories"])
        lines.append(f"    HelpLine {{\n        opt: {json.dumps(e['opt'])},\n"
                     f"        desc: {json.dumps(e['desc'])},\n"
                     f"        categories: &[{cats}],\n    }},\n")
    names = {c for e in cli["tool_listhelp_entries"] for c in e["categories"]}
    cats = cli["help_categories"]
    check(names == {c["name"] for c in cats} | {"important"},
          "help lines use categories the table lacks")
    categories = "".join(f"    ({json.dumps(c['name'])}, {json.dumps(c['desc'])}),\n"
                         for c in cats)
    return f"""{genlib.header(HERE, [CLI, ROOT / 'gen' / 'genlib.py', HERE])}\
//! What `--help` shows: `src/tool_listhelp.c` and the categories of
//! `src/tool_help.c`.

/// One option's line in `--help`.
pub(crate) struct HelpLine {{
    /// The option as shown, such as `-o, --output <file>`.
    pub(crate) opt: &'static str,
    pub(crate) desc: &'static str,
    /// The categories it is listed under.
    pub(crate) categories: &'static [&'static str],
}}

/// Every option's line, in the order shown.
pub(crate) static HELP: &[HelpLine] = &[
{"".join(lines)}];

/// The categories `--help category` lists, with their descriptions; the
/// default page, `important`, is not among them.
pub(crate) static CATEGORIES: &[(&str, &str)] = &[
{categories}];
"""


def nv_value(name, consts):
    """The value of `name` in a `setopt_nv_*` entry: a curl.h constant or
    a literal."""
    if re.fullmatch(r"\d+L?", name):
        return int(name.rstrip("L"))
    check(name in consts, f"{name} of tool_setopt.c is not in abi.json")
    check(consts[name]["value"] is not None, f"{name} has no value in abi.json")
    return int(consts[name]["value"])


def rust_int(c):
    """The Rust type of a curl.h constant's C type."""
    return {"long": "i64", "unsigned long": "u64"}[c["c-type"]]


def names(abi):
    consts = {c["name"]: c for c in abi["constants"]}
    src = re.sub(r"/\*.*?\*/", "", TOOL_SETOPT.read_text(), flags=re.DOTALL)
    tables = re.findall(
        r"const struct (NameValue|NameValueUnsigned) setopt_nv_(\w+)\[\] = \{(.*?)\};",
        src, flags=re.DOTALL)
    found = [name for _, name, _ in tables]
    check(sorted(found) == sorted(NV_TABLES),
          f"tool_setopt.c's tables {sorted(found)} are not NV_TABLES")
    out = []
    for kind, name, body in tables:
        rust = NV_TABLES[name]
        if rust is None:
            continue
        rows = []
        for entry in re.findall(r"(NV1?\([^)]*\)|\{ \"\", \w+ \}|NVEND)", body):
            if entry == "NVEND":
                break
            if m := re.fullmatch(r"NV\((\w+)\)", entry):
                label, value = m[1], nv_value(m[1], consts)
            elif m := re.fullmatch(r"NV1\((\w+), (\w+)\)", entry):
                label, value = m[1], nv_value(m[2], consts)
            else:
                label, value = "", nv_value(re.search(r"(\w+) \}", entry)[1], consts)
            rows.append(f'    ("{label}", {value}),\n')
        check(rows, f"setopt_nv_{name} is empty")
        ty = "Bits" if kind == "NameValueUnsigned" else "Names"
        out.append(f"/// `setopt_nv_{name}`.\npub(crate) const {rust}: {ty} = &[\n"
                   + "".join(rows) + "];\n")
    constants = ["/// The curl.h constants the tool's encoders pass.\n"]
    for name in NV_CONSTANTS:
        check(name in consts, f"{name} is not in abi.json")
        c = consts[name]
        constants.append(f"pub(crate) const {name}: {rust_int(c)} = {c['value']};\n")
    out.append("".join(constants))
    inputs = [TOOL_SETOPT, ABI, ROOT / "gen" / "genlib.py", HERE]
    return (genlib.header(HERE, inputs)
            + "//! The names `--libcurl` writes for option values, and the curl.h\n"
            + "//! constants the tool passes, as src/tool_setopt.c and curl.h have them.\n\n"
            + "#![allow(non_upper_case_globals)]\n\n"
            + "use super::{Bits, Names};\n\n"
            + "\n".join(out))


def main():
    cli = json.loads(CLI.read_text())["data"]
    abi = json.loads(ABI.read_text())["data"]
    TABLE_OUT.parent.mkdir(exist_ok=True)
    genlib.write(TABLE_OUT, table(cli))
    genlib.write(ERRORS_OUT, errors(cli, abi))
    genlib.write(HELP_OUT, help_table(cli))
    NAMES_OUT.parent.mkdir(exist_ok=True)
    genlib.write(NAMES_OUT, names(abi))


if __name__ == "__main__":
    main()
