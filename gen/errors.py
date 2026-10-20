#!/usr/bin/env python3
"""
Generate the error kinds of the Rust API and their C codes and strings.

The strerror tables of inventory/abi.json, read from lib/strerror.c and
checked against test 1538, give every code of CURLcode, CURLMcode,
CURLSHcode and CURLUcode with its message. From them:

  crates/curl-core/src/error/kinds.rs: one enum per API, a variant per
  code that is an error, its message as `Display`;

  crates/curl-sys-abi/src/error_codes.rs: each variant's code, with a
  `match` that has no wildcard, and each code's string for `*_strerror`,
  including the codes that are not errors (`CURLE_OK`, ...).
"""

import json
import pathlib

import genlib
from genlib import ABI, ROOT, check

HERE = pathlib.Path(__file__).resolve()
CORE_OUT = ROOT / "crates" / "curl-core" / "src" / "error" / "kinds.rs"
SHIM_OUT = ROOT / "crates" / "curl-sys-abi" / "src" / "error_codes.rs"

# (strerror function, C enum, member prefix, Rust enum, Rust prefix,
#  codes that are not errors)
TABLES = [
    ("curl_easy_strerror", "CURLcode", "CURLE_", "ErrorKind", "easy",
     {"CURLE_OK"}),
    ("curl_multi_strerror", "CURLMcode", "CURLM_", "MultiErrorKind", "multi",
     {"CURLM_OK", "CURLM_CALL_MULTI_PERFORM"}),
    ("curl_share_strerror", "CURLSHcode", "CURLSHE_", "ShareErrorKind",
     "share", {"CURLSHE_OK"}),
    ("curl_url_strerror", "CURLUcode", "CURLUE_", "UrlErrorKind", "url",
     {"CURLUE_OK"}),
]

DOCS = {
    "ErrorKind": "Why a transfer or an easy-handle call failed.",
    "MultiErrorKind": "Why a multi-handle call failed.",
    "ShareErrorKind": "Why a share-handle call failed.",
    "UrlErrorKind": "Why a URL could not be parsed, built or read.",
}


CORE_TEMPLATE = """\
/// {doc}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum {rust} {{
{variants}}}

impl {rust} {{
    /// Every kind, in the order of their C codes.
    pub const ALL: &[{rust}] = &[
{all}    ];

    /// The message, as libcurl's `*_strerror` gives it.
    pub fn message(self) -> &'static str {{
        match self {{
{messages}        }}
    }}
}}

impl fmt::Display for {rust} {{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {{
        f.write_str(self.message())
    }}
}}

impl std::error::Error for {rust} {{}}
"""

SHIM_TEMPLATE = """\
/// The `{cenum}` of an error kind.
pub(crate) fn {short}_code(kind: {rust}) -> {cenum} {{
    match kind {{
{codes}    }}
}}

/// What `{func}` returns for `code`.
pub(crate) fn {short}_strerror(code: {cenum}) -> &'static CStr {{
    match code {{
{strings}        _ => c{unknown},
    }}
}}
"""


def camel(name, prefix):
    check(name.startswith(prefix), f"{name} lacks {prefix}")
    return "".join(w.capitalize() for w in name[len(prefix):].split("_"))


def literal(text):
    check(text.isascii() and "\n" not in text, f"unexpected message {text!r}")
    return json.dumps(text)


def generate():
    abi = json.loads(ABI.read_text())["data"]
    inputs = [ABI, ROOT / "gen" / "genlib.py", HERE]
    core = [genlib.header(HERE, inputs),
            "//! The error kinds of each API, one per C error code.\n",
            "use std::fmt;\n"]
    shim = [genlib.header(HERE, inputs),
            "//! The C codes and `*_strerror` strings of the error kinds.\n",
            "use core::ffi::CStr;\n",
            ("use curl_core::error::{ErrorKind, MultiErrorKind, "
             "ShareErrorKind, UrlErrorKind};\n"),
            "use crate::ffi::*;\n"]
    for func, cenum, prefix, rust, short, ok in TABLES:
        table = abi["strerror"][func]
        check(table["enum"] == cenum, f"{func} is not for {cenum}")
        members = next(e["members"] for e in abi["enums"]
                       if e["typedef"] == cenum)
        # The JSON is sorted by name; the C order is the enum's.
        messages = {m: table["messages"][m] for m in members
                    if m in table["messages"]}
        check(len(messages) == len(table["messages"]),
              f"{func} has messages for codes outside {cenum}")
        errors = [m for m in messages if m not in ok]
        check(ok <= set(messages), f"{func}: no message for {ok}")
        variants = [(m, camel(m, prefix), messages[m]) for m in errors]

        doc_variants = "".join(f"    /// {msg}\n    {v},\n"
                               for _, v, msg in variants)
        all_variants = "".join(f"        {rust}::{v},\n"
                               for _, v, _ in variants)
        message_arms = "".join(f"            {rust}::{v} => {literal(msg)},\n"
                               for _, v, msg in variants)
        core.append(CORE_TEMPLATE.format(
            doc=DOCS[rust], rust=rust, variants=doc_variants,
            all=all_variants, messages=message_arms))
        code_arms = "".join(f"        {rust}::{v} => {m},\n"
                            for m, v, _ in variants)
        str_arms = "".join(f"        {m} => c{literal(msg)},\n"
                           for m, msg in messages.items())
        shim.append(SHIM_TEMPLATE.format(
            func=func, cenum=cenum, short=short, rust=rust, codes=code_arms,
            strings=str_arms, unknown=literal(table["unknown"])))
    genlib.write(CORE_OUT, "\n".join(core))
    genlib.write(SHIM_OUT, "\n".join(shim))


if __name__ == "__main__":
    generate()
