#!/usr/bin/env python3
"""
Generate the error kinds of the Rust API and their C codes and strings.

The strerror tables of inventory/abi.json, read from lib/strerror.c and
checked against test 1538, give every code of CURLcode, CURLMcode,
CURLSHcode and CURLUcode with its message. Each error code is either the
core's, a way the Rust API fails, or one only the C API produces
(`SHIM_ONLY`). From them:

  crates/curl-core/src/error/kinds.rs: one enum per API that fails in
  the core, a variant per core code, its message as `Display`; for
  `ErrorKind`, also the code's number, which trace lines print as C's
  do, and the numbers of the codes only the shim returns that the core
  still traces (`TRACED`);

  crates/curl-sys-abi/src/error_codes.rs: per API with codes only the
  shim produces, an enum of those beside the core's kind; each variant's
  code, with a `match` that has no wildcard, and each code's string for
  `*_strerror`, including the codes that are not errors (`CURLE_OK`,
  ...).
"""

import json
import pathlib

import genlib
from genlib import ABI, ROOT, check

HERE = pathlib.Path(__file__).resolve()
CORE_OUT = ROOT / "crates" / "curl-core" / "src" / "error" / "kinds.rs"
SHIM_OUT = ROOT / "crates" / "curl-sys-abi" / "src" / "error_codes.rs"

# (strerror function, C enum, member prefix, core enum, shim enum,
#  Rust prefix, codes that are not errors)
TABLES = [
    ("curl_easy_strerror", "CURLcode", "CURLE_", "ErrorKind", "EasyError",
     "easy", {"CURLE_OK"}),
    ("curl_multi_strerror", "CURLMcode", "CURLM_", "MultiErrorKind",
     "MultiError", "multi", {"CURLM_OK", "CURLM_CALL_MULTI_PERFORM"}),
    ("curl_share_strerror", "CURLSHcode", "CURLSHE_", None, "ShareError",
     "share", {"CURLSHE_OK"}),
    ("curl_url_strerror", "CURLUcode", "CURLUE_", "UrlErrorKind", None,
     "url", {"CURLUE_OK"}),
]

# The codes only the shim produces: the Rust API has no option ids, no
# handles to be invalid and no re-entrant calls to refuse, and the core
# shares nothing it can be refused. A Rust caller never meets these; the
# shim's enums hold them. TLS's codes stay in the core, which will
# produce them.
SHIM_ONLY = {
    "CURLcode": {
        # The core's would-block, "not yet" and "no connection now" are
        # distinct types, not errors.
        "CURLE_AGAIN",
        "CURLE_NO_CONNECTION_AVAILABLE",
        "CURLE_RECURSIVE_API_CALL",
        "CURLE_UNKNOWN_OPTION",
    },
    "CURLMcode": {
        "CURLM_BAD_HANDLE",
        "CURLM_INTERNAL_ERROR",
        "CURLM_BAD_SOCKET",
        "CURLM_UNKNOWN_OPTION",
        "CURLM_ADDED_ALREADY",
        "CURLM_RECURSIVE_API_CALL",
        "CURLM_WAKEUP_FAILURE",
        "CURLM_BAD_FUNCTION_ARGUMENT",
    },
    "CURLSHcode": {
        "CURLSHE_BAD_OPTION",
        "CURLSHE_IN_USE",
        "CURLSHE_INVALID",
        "CURLSHE_NOMEM",
        "CURLSHE_NOT_BUILT_IN",
    },
}

# The codes only the shim returns whose numbers the core still traces as
# C does (`-> %d`), and the name of the number's constant.
TRACED = {
    "CURLE_AGAIN": ("AGAIN_NUMBER", "would-block and not-yet (`CURLE_AGAIN`)"),
}

DOCS = {
    "ErrorKind": "Why a transfer or an easy-handle call failed.",
    "MultiErrorKind": "Why a multi-handle call failed.",
    "UrlErrorKind": "Why a URL could not be parsed, built or read.",
    "EasyError": ("Why a libcurl easy call failed: the core's kind, or a "
                  "code only the\n/// C API produces."),
    "MultiError": ("Why a libcurl multi call failed: the core's kind, or a "
                   "code only the\n/// C API produces."),
    "ShareError": ("Why a libcurl share call failed: the core's share "
                   "never fails, so\n/// every code is the C API's."),
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

NUMBER_TEMPLATE = """\
impl {rust} {{
    /// The number of its C code, as trace lines print it (`-> %d`):
    /// its place in the C enum, which counts from 0 for success.
    pub(crate) fn number(self) -> u16 {{
        match self {{
{numbers}        }}
    }}
}}
"""

TRACED_TEMPLATE = """\
/// The number trace lines print for {doc}:
/// the core traces it as C does but never returns it.
pub(crate) const {name}: u16 = {number};
"""

SHIM_ENUM_TEMPLATE = """\
/// {doc}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum {shim} {{
{variants}}}

impl {shim} {{
    /// Every code only the shim produces, in the order of their C codes.
    pub(crate) const SHIM_ONLY: &[{shim}] = &[
{all}    ];

    /// The message, as `{func}` gives it.
    pub(crate) fn message(self) -> &'static str {{
        match self {{
{messages}        }}
    }}
}}
"""

FROM_TEMPLATE = """\
impl From<{rust}> for {shim} {{
    fn from(kind: {rust}) -> {shim} {{
        {shim}::Core(kind)
    }}
}}
"""

CODE_TEMPLATE = """\
/// The `{cenum}` of an error.
pub(crate) fn {short}_code(error: {arg}) -> {cenum} {{
    match {scrutinee} {{
{codes}    }}
}}
"""

STRERROR_TEMPLATE = """\
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


def shim_only(cenum):
    """The codes of `cenum` only the shim produces."""
    return SHIM_ONLY.get(cenum, set())


def generate():
    abi = json.loads(ABI.read_text())["data"]
    inputs = [ABI, ROOT / "gen" / "genlib.py", HERE]
    core_names = [t[3] for t in TABLES if t[3]]
    core = [genlib.header(HERE, inputs),
            "//! The error kinds of each API, one per C error code the core\n"
            "//! produces.\n",
            "use std::fmt;\n"]
    shim = [genlib.header(HERE, inputs),
            "//! The errors of the C API, their C codes and `*_strerror` "
            "strings.\n",
            "use core::ffi::CStr;\n",
            f"use curl_core::error::{{{', '.join(core_names)}}};\n",
            "use crate::ffi::*;\n"]
    for func, cenum, prefix, rust, shim_enum, short, ok in TABLES:
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
        only = shim_only(cenum)
        check(only <= set(errors),
              f"{cenum}: shim-only codes that are not errors: "
              f"{sorted(only - set(errors))}")
        variants = [(m, camel(m, prefix), messages[m]) for m in errors]
        core_vs = [v for v in variants if v[0] not in only]
        shim_vs = [v for v in variants if v[0] in only]
        check(bool(core_vs) == bool(rust), f"{cenum}: core enum {rust}")
        check(bool(shim_vs) == bool(shim_enum), f"{cenum}: shim enum {shim_enum}")

        if rust:
            core.append(CORE_TEMPLATE.format(
                doc=DOCS[rust], rust=rust,
                variants="".join(f"    /// {msg}\n    {v},\n"
                                 for _, v, msg in core_vs),
                all="".join(f"        {rust}::{v},\n" for _, v, _ in core_vs),
                messages="".join(f"            {rust}::{v} => {literal(msg)},\n"
                                 for _, v, msg in core_vs)))
        if rust == "ErrorKind":
            # The enum declares no values: each member's is its place.
            check(members[0] == "CURLE_OK", "CURLcode starts at CURLE_OK")
            number_arms = "".join(
                f"            {rust}::{v} => {members.index(m)},\n"
                for m, v, _ in core_vs)
            core.append(NUMBER_TEMPLATE.format(rust=rust, numbers=number_arms))
            for m, (name, doc) in TRACED.items():
                check(m in only, f"{m} is traced but not shim-only")
                core.append(TRACED_TEMPLATE.format(
                    doc=doc, name=name, number=members.index(m)))

        if shim_enum:
            enum_variants = ""
            if rust:
                enum_variants += (f"    /// The core's.\n"
                                  f"    Core({rust}),\n")
            enum_variants += "".join(f"    /// {msg}\n    {v},\n"
                                     for _, v, msg in shim_vs)
            msg_arms = ""
            if rust:
                msg_arms += f"            {shim_enum}::Core(kind) => kind.message(),\n"
            msg_arms += "".join(
                f"            {shim_enum}::{v} => {literal(msg)},\n"
                for _, v, msg in shim_vs)
            shim.append(SHIM_ENUM_TEMPLATE.format(
                doc=DOCS[shim_enum], shim=shim_enum, func=func,
                variants=enum_variants,
                all="".join(f"        {shim_enum}::{v},\n"
                            for _, v, _ in shim_vs),
                messages=msg_arms))
            if rust:
                shim.append(FROM_TEMPLATE.format(rust=rust, shim=shim_enum))

        if rust and shim_enum:
            core_arms = "".join(f"            {rust}::{v} => {m},\n"
                                for m, v, _ in core_vs)
            codes = (f"        {shim_enum}::Core(kind) => match kind {{\n"
                     f"{core_arms}        }},\n")
            codes += "".join(f"        {shim_enum}::{v} => {m},\n"
                             for m, v, _ in shim_vs)
            arg, scrutinee = f"impl Into<{shim_enum}>", "error.into()"
        elif shim_enum:
            codes = "".join(f"        {shim_enum}::{v} => {m},\n"
                            for m, v, _ in shim_vs)
            arg, scrutinee = shim_enum, "error"
        else:
            codes = "".join(f"        {rust}::{v} => {m},\n"
                            for m, v, _ in core_vs)
            arg, scrutinee = rust, "error"
        shim.append(CODE_TEMPLATE.format(
            cenum=cenum, short=short, arg=arg, scrutinee=scrutinee,
            codes=codes))
        str_arms = "".join(f"        {m} => c{literal(msg)},\n"
                           for m, msg in messages.items())
        shim.append(STRERROR_TEMPLATE.format(
            func=func, cenum=cenum, short=short, strings=str_arms,
            unknown=literal(table["unknown"])))
    genlib.write(CORE_OUT, "\n".join(core))
    genlib.write(SHIM_OUT, "\n".join(shim))


if __name__ == "__main__":
    generate()
